package com.skhoron.vault.data

import android.content.Context
import android.net.Uri
import android.os.SystemClock
import android.util.Base64
import com.skhoron.vault.crypto.Argon2Params
import com.skhoron.vault.crypto.DerivedKey
import com.skhoron.vault.crypto.EncryptedBlob
import com.skhoron.vault.crypto.VaultCrypto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.io.File
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.util.UUID

sealed class UnlockResult {
    object Success : UnlockResult()
    object NoVaultYet : UnlockResult()
    data class WrongPassword(val attemptsLeft: Int) : UnlockResult()
    object WipedOut : UnlockResult()
    object VaultAlreadyExists : UnlockResult()
}

/**
 * Разделение ключей через HKDF (доменное разделение по контексту).
 * Компрометация одного подключа не даёт автоматически второй — хотя оба
 * выводятся из одного master key, так что на практике тот, кто знает
 * master password, может вывести оба; разделение защищает от случайного
 * использования одного и того же сырого байтового ключа сразу в двух
 * разных крипто-примитивах (SQLCipher AES и ChaCha20-Poly1305), что было
 * бы плохой практикой само по себе, независимо от источника ключа.
 */
private object KeyContext {
    val SQLCIPHER = "skhoron-vault-sqlcipher-v1".toByteArray()
    val FIELD_ENCRYPTION = "skhoron-vault-field-encryption-v1".toByteArray()
}

private fun hkdfExpand(masterKeyBytes: ByteArray, context: ByteArray, outLen: Int = 32): ByteArray {
    val hkdf = HKDFBytesGenerator(SHA256Digest())
    hkdf.init(HKDFParameters(masterKeyBytes, null, context))
    val out = ByteArray(outLen)
    hkdf.generateBytes(out, 0, outLen)
    return out
}

/** Кодирует CharArray в UTF-8 ByteArray напрямую, без промежуточного String,
 *  который иначе жил бы в куче JVM неопределённо долго до сборки мусора.
 *  Это единственный путь превращения мастер-пароля в байты во всём классе —
 *  String(password) намеренно нигде не используется. */
private fun charArrayToUtf8Bytes(chars: CharArray): ByteArray {
    val byteBuffer = Charsets.UTF_8.encode(CharBuffer.wrap(chars))
    val bytes = ByteArray(byteBuffer.remaining())
    byteBuffer.get(bytes)
    if (byteBuffer.hasArray()) byteBuffer.array().fill(0)
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


class VaultRepository(private val appContext: Context) {

    companion object {
        private const val MAX_BACKUP_DB_BYTES = 128L * 1024 * 1024
    }

    private val crypto = VaultCrypto()
    private val prefs by lazy { PreferencesStore.get(appContext) }

    @Volatile private var masterKey: DerivedKey? = null
    @Volatile private var database: VaultDatabase? = null

    val isUnlocked: Boolean get() = masterKey != null && database != null
    val hasVault: Boolean get() = prefs.contains(PreferencesStore.KEY_SALT)

    // ---------- Создание / разблокировка / блокировка ----------

    suspend fun createVault(password: CharArray): UnlockResult = withContext(Dispatchers.Default) {
        if (hasVault) return@withContext UnlockResult.VaultAlreadyExists

        val passwordBytes = charArrayToUtf8Bytes(password)
        var derived: DerivedKey? = null
        try {
            val salt = crypto.generateSalt()
            derived = crypto.deriveMasterKey(passwordBytes, salt)

            var sqlCipherKey: ByteArray? = null
            var fieldKey: ByteArray? = null
            var db: VaultDatabase? = null
            var fieldKeyTransferred = false
            try {
                sqlCipherKey = hkdfExpand(derived.keyBytes, KeyContext.SQLCIPHER)
                fieldKey = hkdfExpand(derived.keyBytes, KeyContext.FIELD_ENCRYPTION)

                db = VaultDatabase.build(appContext, sqlCipherKey)
                db.openHelper.writableDatabase

                val committed = prefs.edit()
                    .putString(PreferencesStore.KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                    .putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0)
                    .commit()
                if (!committed) {
                    db.close()
                    db = null
                    appContext.getDatabasePath("skhoron_vault.db").delete()
                    appContext.getDatabasePath("skhoron_vault.db-wal").delete()
                    appContext.getDatabasePath("skhoron_vault.db-shm").delete()
                    throw IllegalStateException("Не удалось сохранить настройки vault")
                }

                database = db
                db = null
                masterKey = DerivedKey(fieldKey)
                fieldKeyTransferred = true
                UnlockResult.Success
            } finally {
                if (!fieldKeyTransferred) db?.close()
                sqlCipherKey?.fill(0)
                if (!fieldKeyTransferred) fieldKey?.fill(0)
            }
        } finally {
            passwordBytes.fill(0)
            password.fill('\u0000')
            derived?.keyBytes?.fill(0)
        }
    }

    suspend fun unlock(password: CharArray): UnlockResult = withContext(Dispatchers.Default) {
        val saltB64 = prefs.getString(PreferencesStore.KEY_SALT, null)
            ?: return@withContext UnlockResult.NoVaultYet

        val passwordBytes = charArrayToUtf8Bytes(password)
        val salt = Base64.decode(saltB64, Base64.NO_WRAP)
        var derived: DerivedKey? = null

        try {
            derived = crypto.deriveMasterKey(passwordBytes, salt)
            var sqlCipherKey: ByteArray? = null
            var fieldKey: ByteArray? = null
            var fieldKeyTransferred = false

            return@withContext try {
                sqlCipherKey = hkdfExpand(derived.keyBytes, KeyContext.SQLCIPHER)
                fieldKey = hkdfExpand(derived.keyBytes, KeyContext.FIELD_ENCRYPTION)
                val candidate = VaultDatabase.build(appContext, sqlCipherKey)
                try {
                    candidate.openHelper.writableDatabase
                } catch (e: Exception) {
                    candidate.close()
                    throw e
                }

                database?.close()
                database = candidate
                masterKey = DerivedKey(fieldKey)
                fieldKeyTransferred = true
                prefs.edit().putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0).apply()
                UnlockResult.Success
            } catch (e: Exception) {
                val attempts = prefs.getInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0) + 1
                if (attempts >= PreferencesStore.PANIC_WIPE_THRESHOLD) {
                    panicWipe()
                    UnlockResult.WipedOut
                } else {
                    prefs.edit().putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, attempts).apply()
                    UnlockResult.WrongPassword(PreferencesStore.PANIC_WIPE_THRESHOLD - attempts)
                } finally {
                    sqlCipherKey?.fill(0)
                    if (!fieldKeyTransferred) fieldKey?.fill(0)
                }
            }
        } finally {
            passwordBytes.fill(0)
            password.fill('\u0000')
            derived?.keyBytes?.fill(0)
        }
    }

    fun lock() {
        masterKey?.zeroize()
        masterKey = null
        database?.close()
        database = null
    }

    fun panicWipe() {
        lock()
        appContext.getDatabasePath("skhoron_vault.db").delete()
        appContext.getDatabasePath("skhoron_vault.db-wal").delete()
        appContext.getDatabasePath("skhoron_vault.db-shm").delete()
        PreferencesStore.wipe(appContext)
    }

    // ---------- Работа с записями ----------

    fun observeEntries(): Flow<List<VaultEntryRow>> {
        val db = database ?: throw IllegalStateException("Vault заблокирован")
        return db.vaultEntryDao().observeAll()
    }

    suspend fun addEntry(label: String, username: String?, password: String, domainHint: String?) {
        val key = masterKey ?: throw IllegalStateException("Vault заблокирован")
        val db = database ?: throw IllegalStateException("Vault заблокирован")
        val id = UUID.randomUUID().toString()
        val passwordBytes = password.toByteArray(Charsets.UTF_8)
        val blob = try {
            crypto.encryptEntry(key, passwordBytes, aad = id.toByteArray())
        } finally {
            passwordBytes.fill(0)
        }
        db.vaultEntryDao().insert(
            VaultEntryRow(
                id = id,
                label = label,
                username = username,
                passwordCiphertext = blob.ciphertext,
                passwordNonce = blob.nonce,
                domainHint = domainHint,
                createdAt = System.currentTimeMillis()
            )
        )
    }

    suspend fun deleteEntry(row: VaultEntryRow) {
        database?.vaultEntryDao()?.delete(row)
    }

    /** Расшифровывает пароль записи. ByteArray-plaintext затирается сразу после
     *  копирования в String — сам String всё равно останется в памяти до GC,
     *  это ограничение платформы: Compose TextField работает только со String,
     *  без кастомного буфера над CharArray это неустранимо штатными средствами. */
    fun decryptPassword(row: VaultEntryRow): String {
        val key = masterKey ?: throw IllegalStateException("Vault заблокирован")
        val plaintext = crypto.decryptEntry(
            key,
            EncryptedBlob(row.passwordCiphertext, row.passwordNonce),
            aad = row.id.toByteArray()
        )
        val result = String(plaintext, Charsets.UTF_8)
        plaintext.fill(0)
        return result
    }

    /** Anti-phishing invariant: совпадение ТОЛЬКО по точному domainHint. */
    suspend fun findByExactDomain(domain: String): List<VaultEntryRow> {
        val db = database ?: return emptyList()
        return db.vaultEntryDao().findByDomain(domain)
    }

    // ---------- Auto-lock ----------
    // Используется SystemClock.elapsedRealtime() (монотонные часы), а не
    // System.currentTimeMillis() (wall clock) — последние можно перевести
    // вперёд/назад вручную или через сеть, что ломало бы логику таймаута.

    fun getAutolockMinutes(): Int =
        prefs.getInt(PreferencesStore.KEY_AUTOLOCK_MINUTES, PreferencesStore.DEFAULT_AUTOLOCK_MINUTES)

    fun setAutolockMinutes(minutes: Int) {
        val clamped = minutes.coerceIn(PreferencesStore.MIN_AUTOLOCK_MINUTES, PreferencesStore.MAX_AUTOLOCK_MINUTES)
        prefs.edit().putInt(PreferencesStore.KEY_AUTOLOCK_MINUTES, clamped).apply()
    }

    fun onAppBackgrounded() {
        prefs.edit().putLong(PreferencesStore.KEY_LAST_BACKGROUND_TS, SystemClock.elapsedRealtime()).apply()
    }

    fun checkAutolockOnForeground() {
        val lastBg = prefs.getLong(PreferencesStore.KEY_LAST_BACKGROUND_TS, 0L)
        if (lastBg == 0L) return
        val elapsedMinutes = (SystemClock.elapsedRealtime() - lastBg) / 60_000
        if (elapsedMinutes >= getAutolockMinutes()) {
            lock()
        }
    }

    // ---------- Локальный зашифрованный бэкап (без сети, без облака) ----------

    /**
     * Экспорт. Перед копированием выполняется WAL checkpoint — без него
     * несохранённые в основной .db-файл транзакции (лежащие в -wal) не
     * попали бы в бэкап, и восстановление могло бы оказаться неактуальным.
     *
     * Формат: [4 байта: длина соли][соль][содержимое db-файла].
     */
    fun exportBackup(destinationUri: Uri) {
        val saltB64 = prefs.getString(PreferencesStore.KEY_SALT, null)
            ?: throw IllegalStateException("Vault ещё не создан")
        val salt = Base64.decode(saltB64, Base64.NO_WRAP)

        database?.openHelper?.writableDatabase?.query("PRAGMA wal_checkpoint(FULL)")?.close()

        val dbFile = appContext.getDatabasePath("skhoron_vault.db")
        appContext.contentResolver.openOutputStream(destinationUri)?.use { out ->
            val lenBytes = ByteBuffer.allocate(4).putInt(salt.size).array()
            out.write(lenBytes)
            out.write(salt)
            dbFile.inputStream().use { input -> input.copyTo(out) }
        } ?: throw IllegalStateException("Не удалось открыть файл назначения")
    }

    /**
     * Импорт. Порядок операций важен для атомарности:
     * 1. Читаем и полностью валидируем файл бэкапа
     * 2. Пишем содержимое БД во временный файл (не трогая текущий рабочий .db)
     * 3. Только при полном успехе — атомарно переименовываем временный файл
     *    поверх рабочего и лишь ПОСЛЕ этого обновляем соль в настройках
     *
     * Если что-то оборвётся на шаге 1–2, рабочий vault остаётся нетронутым.
     * Раньше соль обновлялась ДО записи БД — при обрыве середины записи
     * можно было получить несовместимую пару (новая соль + старая/битая БД).
     */
    fun importBackup(sourceUri: Uri) {
        lock()

        val dbFile = appContext.getDatabasePath("skhoron_vault.db")
        val walFile = appContext.getDatabasePath("skhoron_vault.db-wal")
        val shmFile = appContext.getDatabasePath("skhoron_vault.db-shm")
        val tempFile = File(appContext.cacheDir, "import_tmp_${System.nanoTime()}.db")
        val rollbackFile = File(appContext.cacheDir, "import_rollback_${System.nanoTime()}.db")
        var salt: ByteArray? = null
        var replacementApplied = false
        var hadOriginalDb = false

        try {
            appContext.contentResolver.openInputStream(sourceUri)?.use { input ->
                val lenBytes = ByteArray(4)
                if (input.readFully(lenBytes) != 4) {
                    throw IllegalStateException("Повреждённый файл бэкапа (нет заголовка)")
                }
                val saltLen = ByteBuffer.wrap(lenBytes).int
                if (saltLen != Argon2Params.SALT_LEN) {
                    throw IllegalStateException("Некорректный формат бэкапа (ожидалась длина соли ${Argon2Params.SALT_LEN}, получено $saltLen)")
                }

                val saltBytes = ByteArray(saltLen)
                if (input.readFully(saltBytes) != saltLen) {
                    throw IllegalStateException("Повреждённый файл бэкапа (неполная соль)")
                }
                salt = saltBytes

                tempFile.outputStream().use { out ->
                    input.copyTo(out, bufferSize = 64 * 1024, limit = MAX_BACKUP_DB_BYTES + 1)
                    out.fd.sync()
                }
            } ?: throw IllegalStateException("Не удалось открыть файл источника")

            val validatedSalt = salt ?: throw IllegalStateException("Не удалось прочитать соль из бэкапа")
            if (tempFile.length() <= 0L) {
                throw IllegalStateException("Повреждённый файл бэкапа (пустая БД)")
            }
            if (tempFile.length() > MAX_BACKUP_DB_BYTES) {
                throw IllegalStateException("Файл бэкапа слишком большой")
            }

            walFile.delete()
            shmFile.delete()

            hadOriginalDb = dbFile.exists()
            if (hadOriginalDb) {
                try {
                    dbFile.copyTo(rollbackFile, overwrite = true)
                } catch (e: Exception) {
                    throw IllegalStateException("Не удалось создать резервную копию текущей БД", e)
                }
            }

            if (dbFile.exists() && !dbFile.delete()) {
                throw IllegalStateException("Не удалось заменить текущую БД")
            }
            if (!tempFile.renameTo(dbFile)) {
                if (hadOriginalDb && rollbackFile.exists()) {
                    rollbackFile.copyTo(dbFile, overwrite = true)
                }
                throw IllegalStateException("Не удалось применить импортированный файл БД")
            }
            replacementApplied = true

            val committed = prefs.edit()
                .putString(PreferencesStore.KEY_SALT, Base64.encodeToString(validatedSalt, Base64.NO_WRAP))
                .putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0)
                .commit()
            if (!committed) {
                throw IllegalStateException("Не удалось сохранить настройки после импорта")
            }
        } catch (e: Exception) {
            if (replacementApplied) {
                dbFile.delete()
                walFile.delete()
                shmFile.delete()
                if (hadOriginalDb && rollbackFile.exists()) {
                    rollbackFile.copyTo(dbFile, overwrite = true)
                }
            }
            throw e
        } finally {
            salt?.fill(0)
            if (tempFile.exists()) tempFile.delete()
            if (rollbackFile.exists()) rollbackFile.delete()
        }
    }
}