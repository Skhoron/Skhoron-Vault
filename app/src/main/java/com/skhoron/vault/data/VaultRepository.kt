package com.skhoron.vault.data

import android.content.Context
import android.net.Uri
import android.os.SystemClock
import android.util.Base64
import androidx.room.withTransaction
import com.skhoron.vault.crypto.Argon2Params
import com.skhoron.vault.crypto.DerivedKey
import com.skhoron.vault.crypto.EncryptedBlob
import com.skhoron.vault.crypto.Hkdf
import com.skhoron.vault.crypto.KeyContext
import com.skhoron.vault.crypto.SealedField
import com.skhoron.vault.crypto.VaultCrypto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.util.Locale
import java.util.UUID

sealed class UnlockResult {
    object Success : UnlockResult()
    object NoVaultYet : UnlockResult()
    data class WrongPassword(val attemptsLeft: Int) : UnlockResult()
    object WipedOut : UnlockResult()
    object VaultAlreadyExists : UnlockResult()

    /**
     * Пароль верный (или не проверялся), но БД не открылась или миграция
     * упала. В счётчик panic wipe такая попытка не входит.
     */
    data class StorageError(val reason: String) : UnlockResult()
}

/** Домены сравниваются без учёта регистра и завершающей точки. */
internal fun normalizeDomain(domain: String): String =
    domain.trim().trimEnd('.').lowercase(Locale.ROOT)

private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

private fun SealedField.toRow(entryId: String, kind: String) =
    EntryFieldRow(entryId, kind, ciphertext, nonce, wrappedKey, wrapNonce)

private fun EntryFieldRow.toSealed() = SealedField(ciphertext, nonce, wrappedKey, wrapNonce)

private fun charArrayToUtf8Bytes(chars: CharArray): ByteArray {
    val byteBuffer = Charsets.UTF_8.encode(CharBuffer.wrap(chars))
    val bytes = ByteArray(byteBuffer.remaining())
    byteBuffer.get(bytes)

    if (byteBuffer.hasArray()) {
        byteBuffer.array().fill(0)
    }

    return bytes
}

private fun java.io.InputStream.readFully(buffer: ByteArray): Int {
    var offset = 0

    while (offset < buffer.size) {
        val read = read(buffer, offset, buffer.size - offset)

        if (read < 0) break
        if (read == 0) continue

        offset += read
    }

    return offset
}

private fun java.io.InputStream.readExact(n: Int, what: String): ByteArray {
    val bytes = ByteArray(n)
    if (readFully(bytes) != n) {
        bytes.fill(0)
        throw IllegalStateException("Повреждённый файл бэкапа ($what)")
    }
    return bytes
}

private fun java.io.InputStream.readIntBE(what: String): Int =
    ByteBuffer.wrap(readExact(4, what)).int

private fun intToBytes(value: Int): ByteArray =
    ByteBuffer.allocate(4).putInt(value).array()

private fun java.io.InputStream.copyToLimited(
    out: java.io.OutputStream,
    maxBytes: Long,
    bufferSize: Int = 64 * 1024
): Long {
    val buffer = ByteArray(bufferSize)
    var total = 0L

    try {
        while (total < maxBytes) {
            val remaining = maxBytes - total
            val readSize = minOf(buffer.size.toLong(), remaining).toInt()
            val read = read(buffer, 0, readSize)

            if (read < 0) break
            if (read == 0) continue

            out.write(buffer, 0, read)
            total += read
        }
    } finally {
        buffer.fill(0)
    }

    return total
}

/**
 * Иерархия ключей (схема v2):
 *
 *   мастер-пароль --Argon2id--> root
 *     root --HKDF(SQLCIPHER)-->  ключ SQLCipher (файл БД целиком)
 *     root --HKDF(KEK_LOGIN)-->  KEK; в памяти только на время сессии
 *       KEK оборачивает случайный ключ каждого секретного поля (пока это пароль)
 *
 * Формат резервной копии:
 *   v2:     "SKVB" | 0x02 | saltLen(4) | salt | verifierLen(4) | verifier | БД
 *   legacy: saltLen(4) | salt | БД   (импортируется; проверочного блока нет)
 */
class VaultRepository(
    private val appContext: Context
) {

    companion object {
        private const val MAX_BACKUP_DB_BYTES = 128L * 1024 * 1024
        private const val MAX_VERIFIER_LEN = 256
        private const val BACKUP_FORMAT_VERSION = 2
        private val BACKUP_MAGIC = "SKVB".toByteArray(Charsets.US_ASCII)
        private val EMPTY = ByteArray(0)
    }

    private val crypto = VaultCrypto()
    private val prefs by lazy { PreferencesStore.get(appContext) }

    /** create/unlock не должны идти параллельно (двойной тап, два Argon2 сразу). */
    private val unlockMutex = Mutex()

    @Volatile
    private var kek: DerivedKey? = null

    @Volatile
    private var database: VaultDatabase? = null

    private val _unlocked = MutableStateFlow(false)

    /** UI подписывается на это, чтобы уйти на экран разблокировки при автоблокировке. */
    val unlocked: StateFlow<Boolean> = _unlocked.asStateFlow()

    val isUnlocked: Boolean
        get() = kek != null && database != null

    val hasVault: Boolean
        get() = prefs.contains(PreferencesStore.KEY_SALT)

    // ---- создание и разблокировка -------------------------------------

    suspend fun createVault(password: CharArray): UnlockResult =
        withContext(Dispatchers.Default) {
            unlockMutex.withLock { createVaultBlocking(password) }
        }

    private fun createVaultBlocking(password: CharArray): UnlockResult {
        if (hasVault) {
            password.fill('\u0000')
            return UnlockResult.VaultAlreadyExists
        }

        val passwordBytes = charArrayToUtf8Bytes(password)
        var root: DerivedKey? = null
        var sqlCipherKey: ByteArray? = null
        var kekBytes: ByteArray? = null
        var pendingDb: VaultDatabase? = null
        var transferred = false

        try {
            // Соли в настройках нет, значит прежнего хранилища нет: остатки
            // от оборвавшегося создания открылись бы другим ключом и упали.
            deleteDbFiles()

            val salt = crypto.generateSalt()
            root = crypto.deriveMasterKey(passwordBytes, salt)
            sqlCipherKey = Hkdf.expand(root.keyBytes, KeyContext.SQLCIPHER)
            kekBytes = Hkdf.expand(root.keyBytes, KeyContext.KEK_LOGIN)
            val newKek = DerivedKey(kekBytes)

            val newDb = VaultDatabase.build(appContext, sqlCipherKey)
            pendingDb = newDb
            newDb.openHelper.writableDatabase

            val verifier = crypto.sealVerifier(newKek).toBytes()
            val committed = prefs.edit()
                .putString(PreferencesStore.KEY_SALT, b64(salt))
                .putString(PreferencesStore.KEY_VERIFIER, b64(verifier))
                .putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0)
                .commit()

            if (!committed) {
                newDb.close()
                pendingDb = null
                deleteDbFiles()
                throw IllegalStateException("Не удалось сохранить настройки vault")
            }

            database = newDb
            pendingDb = null
            kek = newKek
            transferred = true
            _unlocked.value = true
            return UnlockResult.Success
        } finally {
            pendingDb?.close()
            sqlCipherKey?.fill(0)
            if (!transferred) kekBytes?.fill(0)
            passwordBytes.fill(0)
            password.fill('\u0000')
            root?.zeroize()
        }
    }

    suspend fun unlock(password: CharArray): UnlockResult =
        withContext(Dispatchers.Default) {
            unlockMutex.withLock { unlockBlocking(password) }
        }

    /**
     * Счётчик неудач увеличивается ДО вывода ключа и сбрасывается при успехе:
     * если оборвать процесс посреди Argon2id, попытка всё равно засчитана.
     * Запись через commit(), а не apply(), чтобы счётчик пережил kill процесса.
     * Сбой хранилища (не пароль) в счётчик не входит — попытка откатывается.
     */
    private suspend fun unlockBlocking(password: CharArray): UnlockResult {
        val saltB64 = prefs.getString(PreferencesStore.KEY_SALT, null)
        if (saltB64 == null) {
            password.fill('\u0000')
            return UnlockResult.NoVaultYet
        }

        val verifier = prefs.getString(PreferencesStore.KEY_VERIFIER, null)?.let {
            try {
                EncryptedBlob.fromBytes(Base64.decode(it, Base64.NO_WRAP))
            } catch (e: Exception) {
                null
            }
        }

        val pending = prefs.getInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0) + 1
        prefs.edit().putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, pending).commit()

        val passwordBytes = charArrayToUtf8Bytes(password)
        val salt = Base64.decode(saltB64, Base64.NO_WRAP)
        var root: DerivedKey? = null
        var sqlCipherKey: ByteArray? = null
        var kekBytes: ByteArray? = null
        var transferred = false

        try {
            root = crypto.deriveMasterKey(passwordBytes, salt)
            kekBytes = Hkdf.expand(root.keyBytes, KeyContext.KEK_LOGIN)
            val candidateKek = DerivedKey(kekBytes)

            if (verifier != null && !crypto.checkVerifier(candidateKek, verifier)) {
                return wrongPassword(pending)
            }

            sqlCipherKey = Hkdf.expand(root.keyBytes, KeyContext.SQLCIPHER)
            val candidate = VaultDatabase.build(appContext, sqlCipherKey)

            try {
                candidate.openHelper.writableDatabase
            } catch (e: Exception) {
                candidate.close()
                // Без проверочного блока (хранилище до v0.5) SQLCipher остаётся
                // единственным способом проверить пароль.
                return if (verifier == null) wrongPassword(pending) else storageError(pending, e)
            }

            try {
                migrateLegacyPasswords(candidate, candidateKek, root)
                if (verifier == null) writeVerifier(candidateKek)
            } catch (e: Exception) {
                candidate.close()
                return storageError(pending, e)
            }

            database?.close()
            kek?.zeroize()
            database = candidate
            kek = candidateKek
            transferred = true

            prefs.edit().putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0).commit()
            _unlocked.value = true
            return UnlockResult.Success
        } finally {
            sqlCipherKey?.fill(0)
            if (!transferred) kekBytes?.fill(0)
            passwordBytes.fill(0)
            password.fill('\u0000')
            root?.zeroize()
            salt.fill(0)
        }
    }

    private fun wrongPassword(attemptNumber: Int): UnlockResult {
        if (attemptNumber >= PreferencesStore.PANIC_WIPE_THRESHOLD) {
            panicWipe()
            return UnlockResult.WipedOut
        }
        return UnlockResult.WrongPassword(PreferencesStore.PANIC_WIPE_THRESHOLD - attemptNumber)
    }

    private fun storageError(attemptNumber: Int, e: Exception): UnlockResult {
        prefs.edit()
            .putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, (attemptNumber - 1).coerceAtLeast(0))
            .commit()
        return UnlockResult.StorageError(e.localizedMessage ?: e::class.java.simpleName)
    }

    private fun writeVerifier(key: DerivedKey) {
        val committed = prefs.edit()
            .putString(PreferencesStore.KEY_VERIFIER, b64(crypto.sealVerifier(key).toBytes()))
            .commit()
        if (!committed) throw IllegalStateException("Не удалось сохранить проверочный блок")
    }

    /**
     * Схема 1→2: пароли v1 лежат под одним общим ключом. Здесь каждый
     * перешифровывается в собственное поле со своим ключом. Всё в одной
     * транзакции: либо перенесены все записи, либо ни одной.
     */
    private suspend fun migrateLegacyPasswords(
        db: VaultDatabase,
        newKek: DerivedKey,
        root: DerivedKey
    ) {
        val rows = db.vaultEntryDao().findUnmigrated()
        if (rows.isEmpty()) return

        val legacyKey = DerivedKey(Hkdf.expand(root.keyBytes, KeyContext.FIELD_ENCRYPTION))
        try {
            db.withTransaction {
                for (row in rows) {
                    val plaintext = crypto.decryptEntry(
                        legacyKey,
                        EncryptedBlob(row.passwordCiphertext, row.passwordNonce),
                        aad = row.id.toByteArray()
                    )
                    try {
                        val sealed = crypto.sealField(newKek, row.id, FieldKind.PASSWORD, plaintext)
                        db.entryFieldDao().upsert(sealed.toRow(row.id, FieldKind.PASSWORD))
                        db.vaultEntryDao().markMigrated(row.id, EMPTY)
                    } finally {
                        plaintext.fill(0)
                    }
                }
            }
        } finally {
            legacyKey.zeroize()
        }
    }

    fun lock() {
        kek?.zeroize()
        kek = null

        database?.close()
        database = null

        _unlocked.value = false
    }

    fun panicWipe() {
        lock()
        deleteDbFiles()
        PreferencesStore.wipe(appContext)
    }

    private fun deleteDbFiles() {
        for (suffix in listOf("", "-wal", "-shm", "-journal")) {
            appContext.getDatabasePath(VaultDatabase.FILE_NAME + suffix).delete()
        }
    }

    // ---- записи -------------------------------------------------------

    fun observeEntries(): Flow<List<VaultEntryRow>> {
        val db = database
            ?: throw IllegalStateException("Vault заблокирован")

        return db.vaultEntryDao().observeAll()
    }

    suspend fun getEntry(id: String): VaultEntryRow? =
        database?.vaultEntryDao()?.getById(id)

    suspend fun addEntry(
        label: String,
        username: String?,
        password: String,
        domainHint: String?
    ) {
        val key = kek
            ?: throw IllegalStateException("Vault заблокирован")

        val db = database
            ?: throw IllegalStateException("Vault заблокирован")

        val id = UUID.randomUUID().toString()
        val passwordField = sealString(key, id, FieldKind.PASSWORD, password)

        db.withTransaction {
            db.vaultEntryDao().insert(
                VaultEntryRow(
                    id = id,
                    label = label,
                    username = username,
                    passwordCiphertext = EMPTY,
                    passwordNonce = EMPTY,
                    domainHint = domainHint?.let(::normalizeDomain),
                    createdAt = System.currentTimeMillis(),
                    passwordMigrated = true
                )
            )
            db.entryFieldDao().upsert(passwordField.toRow(id, FieldKind.PASSWORD))
        }
    }

    private fun sealString(key: DerivedKey, id: String, kind: String, value: String): SealedField {
        val bytes = value.toByteArray(Charsets.UTF_8)
        try {
            return crypto.sealField(key, id, kind, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    suspend fun deleteEntry(id: String) {
        val db = database ?: return
        db.withTransaction {
            db.entryFieldDao().deleteFor(id)
            db.vaultEntryDao().deleteById(id)
        }
    }

    /** Расшифровывает одно поле, разворачивая ключ только этого поля. */
    suspend fun decryptField(entryId: String, kind: String): String? {
        val key = kek
            ?: throw IllegalStateException("Vault заблокирован")

        val db = database
            ?: throw IllegalStateException("Vault заблокирован")

        val field = db.entryFieldDao().get(entryId, kind) ?: return null
        val plaintext = crypto.openField(key, entryId, kind, field.toSealed())

        return try {
            String(plaintext, Charsets.UTF_8)
        } finally {
            plaintext.fill(0)
        }
    }

    suspend fun decryptPassword(row: VaultEntryRow): String? =
        decryptField(row.id, FieldKind.PASSWORD)

    suspend fun findByExactDomain(domain: String): List<VaultEntryRow> {
        val db = database ?: return emptyList()
        return db.vaultEntryDao().findByDomain(normalizeDomain(domain))
    }

    // ---- автоблокировка -----------------------------------------------

    fun getAutolockMinutes(): Int =
        prefs.getInt(
            PreferencesStore.KEY_AUTOLOCK_MINUTES,
            PreferencesStore.DEFAULT_AUTOLOCK_MINUTES
        )

    fun getAutolockMillis(): Long = getAutolockMinutes() * 60_000L

    fun setAutolockMinutes(minutes: Int) {
        val clamped = minutes.coerceIn(
            PreferencesStore.MIN_AUTOLOCK_MINUTES,
            PreferencesStore.MAX_AUTOLOCK_MINUTES
        )

        prefs.edit()
            .putInt(
                PreferencesStore.KEY_AUTOLOCK_MINUTES,
                clamped
            )
            .apply()
    }

    fun onAppBackgrounded() {
        prefs.edit()
            .putLong(
                PreferencesStore.KEY_LAST_BACKGROUND_TS,
                SystemClock.elapsedRealtime()
            )
            .apply()
    }

    fun checkAutolockOnForeground() {
        val lastBg = prefs.getLong(
            PreferencesStore.KEY_LAST_BACKGROUND_TS,
            0L
        )

        if (lastBg == 0L) return

        val elapsed = SystemClock.elapsedRealtime() - lastBg

        // elapsed < 0: часы обнулились после перезагрузки — блокируем.
        if (elapsed < 0 || elapsed >= getAutolockMillis()) {
            lock()
        }
    }

    // ---- резервные копии ----------------------------------------------

    suspend fun exportBackup(destinationUri: Uri) =
        withContext(Dispatchers.IO) { exportBackupBlocking(destinationUri) }

    private fun exportBackupBlocking(destinationUri: Uri) {
        val db = database
            ?: throw IllegalStateException("Vault заблокирован")

        val saltB64 = prefs.getString(PreferencesStore.KEY_SALT, null)
            ?: throw IllegalStateException("Vault ещё не создан")

        val verifierB64 = prefs.getString(PreferencesStore.KEY_VERIFIER, null)
            ?: throw IllegalStateException("Нет проверочного блока — разблокируйте vault заново")

        val salt = Base64.decode(saltB64, Base64.NO_WRAP)
        val verifier = Base64.decode(verifierB64, Base64.NO_WRAP)

        try {
            // Без checkpoint транзакции из -wal не попали бы в копию.
            db.openHelper.writableDatabase
                .query("PRAGMA wal_checkpoint(FULL)")
                .close()

            val dbFile = appContext.getDatabasePath(VaultDatabase.FILE_NAME)

            appContext.contentResolver
                .openOutputStream(destinationUri)
                ?.use { out ->
                    out.write(BACKUP_MAGIC)
                    out.write(BACKUP_FORMAT_VERSION)
                    out.write(intToBytes(salt.size))
                    out.write(salt)
                    out.write(intToBytes(verifier.size))
                    out.write(verifier)

                    dbFile.inputStream().use { input ->
                        input.copyTo(out)
                    }
                }
                ?: throw IllegalStateException(
                    "Не удалось открыть файл назначения"
                )
        } finally {
            salt.fill(0)
        }
    }

    suspend fun importBackup(sourceUri: Uri) =
        withContext(Dispatchers.IO) { importBackupBlocking(sourceUri) }

    private fun importBackupBlocking(sourceUri: Uri) {
        lock()

        val dbFile = appContext.getDatabasePath(VaultDatabase.FILE_NAME)
        val walFile = appContext.getDatabasePath(VaultDatabase.FILE_NAME + "-wal")
        val shmFile = appContext.getDatabasePath(VaultDatabase.FILE_NAME + "-shm")

        val tempFile = File(
            appContext.cacheDir,
            "import_tmp_${System.nanoTime()}.db"
        )

        val rollbackFile = File(
            appContext.cacheDir,
            "import_rollback_${System.nanoTime()}.db"
        )

        var salt: ByteArray? = null
        var verifier: ByteArray? = null
        var replacementApplied = false
        var hadOriginalDb = false

        try {
            appContext.contentResolver
                .openInputStream(sourceUri)
                ?.use { input ->

                    val head = input.readExact(4, "нет заголовка")

                    val saltLen: Int
                    if (head.contentEquals(BACKUP_MAGIC)) {
                        val version = input.read()
                        if (version != BACKUP_FORMAT_VERSION) {
                            throw IllegalStateException(
                                "Неподдерживаемая версия формата бэкапа: $version"
                            )
                        }
                        saltLen = input.readIntBE("длина соли")
                    } else {
                        // Формат до v0.5: первые 4 байта — длина соли.
                        saltLen = ByteBuffer.wrap(head).int
                    }

                    if (saltLen != Argon2Params.SALT_LEN) {
                        throw IllegalStateException(
                            "Некорректный формат бэкапа " +
                                "(ожидалась длина соли " +
                                "${Argon2Params.SALT_LEN}, получено $saltLen)"
                        )
                    }

                    salt = input.readExact(saltLen, "неполная соль")

                    if (head.contentEquals(BACKUP_MAGIC)) {
                        val verifierLen = input.readIntBE("длина проверочного блока")
                        if (verifierLen !in 1..MAX_VERIFIER_LEN) {
                            throw IllegalStateException(
                                "Некорректный формат бэкапа (проверочный блок: $verifierLen байт)"
                            )
                        }
                        verifier = input.readExact(verifierLen, "неполный проверочный блок")
                    }

                    tempFile.outputStream().use { out ->
                        val copied = input.copyToLimited(
                            out = out,
                            maxBytes = MAX_BACKUP_DB_BYTES + 1L
                        )

                        out.fd.sync()

                        if (copied > MAX_BACKUP_DB_BYTES) {
                            throw IllegalStateException(
                                "Файл бэкапа слишком большой"
                            )
                        }
                    }
                }
                ?: throw IllegalStateException(
                    "Не удалось открыть файл источника"
                )

            val validatedSalt =
                salt ?: throw IllegalStateException(
                    "Не удалось прочитать соль из бэкапа"
                )

            if (tempFile.length() <= 0L) {
                throw IllegalStateException(
                    "Повреждённый файл бэкапа (пустая БД)"
                )
            }

            if (tempFile.length() > MAX_BACKUP_DB_BYTES) {
                throw IllegalStateException(
                    "Файл бэкапа слишком большой"
                )
            }

            walFile.delete()
            shmFile.delete()

            hadOriginalDb = dbFile.exists()

            if (hadOriginalDb) {
                try {
                    dbFile.copyTo(
                        rollbackFile,
                        overwrite = true
                    )
                } catch (e: Exception) {
                    throw IllegalStateException(
                        "Не удалось создать резервную копию текущей БД",
                        e
                    )
                }
            }

            if (dbFile.exists() && !dbFile.delete()) {
                throw IllegalStateException(
                    "Не удалось заменить текущую БД"
                )
            }

            if (!tempFile.renameTo(dbFile)) {
                if (hadOriginalDb && rollbackFile.exists()) {
                    rollbackFile.copyTo(
                        dbFile,
                        overwrite = true
                    )
                }

                throw IllegalStateException(
                    "Не удалось применить импортированный файл БД"
                )
            }

            replacementApplied = true

            val editor = prefs.edit()
                .putString(PreferencesStore.KEY_SALT, b64(validatedSalt))
                .putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0)

            val importedVerifier = verifier
            if (importedVerifier != null) {
                editor.putString(PreferencesStore.KEY_VERIFIER, b64(importedVerifier))
            } else {
                // Бэкап в старом формате: проверочный блок появится при первой
                // разблокировке. Старый блок к новой соли не подходит.
                editor.remove(PreferencesStore.KEY_VERIFIER)
            }

            if (!editor.commit()) {
                throw IllegalStateException(
                    "Не удалось сохранить настройки после импорта"
                )
            }
        } catch (e: Exception) {
            if (replacementApplied) {
                dbFile.delete()
                walFile.delete()
                shmFile.delete()

                if (hadOriginalDb && rollbackFile.exists()) {
                    rollbackFile.copyTo(
                        dbFile,
                        overwrite = true
                    )
                }
            }

            throw e
        } finally {
            salt?.fill(0)
            verifier?.fill(0)

            if (tempFile.exists()) {
                tempFile.delete()
            }

            if (rollbackFile.exists()) {
                rollbackFile.delete()
            }
        }
    }
}