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

private object KeyContext {
    val SQLCIPHER = "skhoron-vault-sqlcipher-v1".toByteArray()
    val FIELD_ENCRYPTION = "skhoron-vault-field-encryption-v1".toByteArray()
}

private fun hkdfExpand(
    masterKeyBytes: ByteArray,
    context: ByteArray,
    outLen: Int = 32
): ByteArray {
    val hkdf = HKDFBytesGenerator(SHA256Digest())
    hkdf.init(HKDFParameters(masterKeyBytes, null, context))

    val out = ByteArray(outLen)
    hkdf.generateBytes(out, 0, outLen)
    return out
}

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

class VaultRepository(
    private val appContext: Context
) {

    companion object {
        private const val MAX_BACKUP_DB_BYTES = 128L * 1024 * 1024
    }

    private val crypto = VaultCrypto()
    private val prefs by lazy { PreferencesStore.get(appContext) }

    @Volatile
    private var masterKey: DerivedKey? = null

    @Volatile
    private var database: VaultDatabase? = null

    val isUnlocked: Boolean
        get() = masterKey != null && database != null

    val hasVault: Boolean
        get() = prefs.contains(PreferencesStore.KEY_SALT)

    suspend fun createVault(password: CharArray): UnlockResult =
        withContext(Dispatchers.Default) {
            if (hasVault) {
                return@withContext UnlockResult.VaultAlreadyExists
            }

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
                    sqlCipherKey = hkdfExpand(
                        derived.keyBytes,
                        KeyContext.SQLCIPHER
                    )

                    fieldKey = hkdfExpand(
                        derived.keyBytes,
                        KeyContext.FIELD_ENCRYPTION
                    )

                    db = VaultDatabase.build(appContext, sqlCipherKey)
                    db.openHelper.writableDatabase

                    val committed = prefs.edit()
                        .putString(
                            PreferencesStore.KEY_SALT,
                            Base64.encodeToString(salt, Base64.NO_WRAP)
                        )
                        .putInt(
                            PreferencesStore.KEY_FAILED_ATTEMPTS,
                            0
                        )
                        .commit()

                    if (!committed) {
                        db.close()
                        db = null

                        appContext.getDatabasePath("skhoron_vault.db").delete()
                        appContext.getDatabasePath("skhoron_vault.db-wal").delete()
                        appContext.getDatabasePath("skhoron_vault.db-shm").delete()

                        throw IllegalStateException(
                            "Не удалось сохранить настройки vault"
                        )
                    }

                    database = db
                    db = null

                    masterKey = DerivedKey(fieldKey)
                    fieldKeyTransferred = true

                    UnlockResult.Success
                } finally {
                    if (!fieldKeyTransferred) {
                        db?.close()
                    }

                    sqlCipherKey?.fill(0)

                    if (!fieldKeyTransferred) {
                        fieldKey?.fill(0)
                    }
                }
            } finally {
                passwordBytes.fill(0)
                password.fill('\u0000')
                derived?.keyBytes?.fill(0)
            }
        }

    suspend fun unlock(password: CharArray): UnlockResult =
        withContext(Dispatchers.Default) {
            val saltB64 = prefs.getString(
                PreferencesStore.KEY_SALT,
                null
            ) ?: return@withContext UnlockResult.NoVaultYet

            val passwordBytes = charArrayToUtf8Bytes(password)
            val salt = Base64.decode(saltB64, Base64.NO_WRAP)
            var derived: DerivedKey? = null

            try {
                derived = crypto.deriveMasterKey(passwordBytes, salt)

                var sqlCipherKey: ByteArray? = null
                var fieldKey: ByteArray? = null
                var fieldKeyTransferred = false

                try {
                    sqlCipherKey = hkdfExpand(
                        derived.keyBytes,
                        KeyContext.SQLCIPHER
                    )

                    fieldKey = hkdfExpand(
                        derived.keyBytes,
                        KeyContext.FIELD_ENCRYPTION
                    )

                    val candidate = VaultDatabase.build(
                        appContext,
                        sqlCipherKey
                    )

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

                    prefs.edit()
                        .putInt(
                            PreferencesStore.KEY_FAILED_ATTEMPTS,
                            0
                        )
                        .apply()

                    UnlockResult.Success
                } catch (e: Exception) {
                    val attempts = prefs.getInt(
                        PreferencesStore.KEY_FAILED_ATTEMPTS,
                        0
                    ) + 1

                    if (attempts >= PreferencesStore.PANIC_WIPE_THRESHOLD) {
                        panicWipe()
                        UnlockResult.WipedOut
                    } else {
                        prefs.edit()
                            .putInt(
                                PreferencesStore.KEY_FAILED_ATTEMPTS,
                                attempts
                            )
                            .apply()

                        UnlockResult.WrongPassword(
                            PreferencesStore.PANIC_WIPE_THRESHOLD - attempts
                        )
                    }
                } finally {
                    sqlCipherKey?.fill(0)

                    if (!fieldKeyTransferred) {
                        fieldKey?.fill(0)
                    }
                }
            } finally {
                passwordBytes.fill(0)
                password.fill('\u0000')
                derived?.keyBytes?.fill(0)
                salt.fill(0)
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

    fun observeEntries(): Flow<List<VaultEntryRow>> {
        val db = database
            ?: throw IllegalStateException("Vault заблокирован")

        return db.vaultEntryDao().observeAll()
    }

    suspend fun addEntry(
        label: String,
        username: String?,
        password: String,
        domainHint: String?
    ) {
        val key = masterKey
            ?: throw IllegalStateException("Vault заблокирован")

        val db = database
            ?: throw IllegalStateException("Vault заблокирован")

        val id = UUID.randomUUID().toString()
        val passwordBytes = password.toByteArray(Charsets.UTF_8)

        val blob = try {
            crypto.encryptEntry(
                key,
                passwordBytes,
                aad = id.toByteArray()
            )
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

    fun decryptPassword(row: VaultEntryRow): String {
        val key = masterKey
            ?: throw IllegalStateException("Vault заблокирован")

        val plaintext = crypto.decryptEntry(
            key,
            EncryptedBlob(
                row.passwordCiphertext,
                row.passwordNonce
            ),
            aad = row.id.toByteArray()
        )

        return try {
            String(plaintext, Charsets.UTF_8)
        } finally {
            plaintext.fill(0)
        }
    }

    suspend fun findByExactDomain(
        domain: String
    ): List<VaultEntryRow> {
        val db = database ?: return emptyList()
        return db.vaultEntryDao().findByDomain(domain)
    }

    fun getAutolockMinutes(): Int =
        prefs.getInt(
            PreferencesStore.KEY_AUTOLOCK_MINUTES,
            PreferencesStore.DEFAULT_AUTOLOCK_MINUTES
        )

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

        val elapsedMinutes =
            (SystemClock.elapsedRealtime() - lastBg) / 60_000

        if (elapsedMinutes >= getAutolockMinutes()) {
            lock()
        }
    }

    fun exportBackup(destinationUri: Uri) {
        val saltB64 = prefs.getString(
            PreferencesStore.KEY_SALT,
            null
        ) ?: throw IllegalStateException("Vault ещё не создан")

        val salt = Base64.decode(
            saltB64,
            Base64.NO_WRAP
        )

        try {
            database
                ?.openHelper
                ?.writableDatabase
                ?.query("PRAGMA wal_checkpoint(FULL)")
                ?.close()

            val dbFile =
                appContext.getDatabasePath("skhoron_vault.db")

            appContext.contentResolver
                .openOutputStream(destinationUri)
                ?.use { out ->
                    val lenBytes = ByteBuffer
                        .allocate(4)
                        .putInt(salt.size)
                        .array()

                    out.write(lenBytes)
                    out.write(salt)

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

    fun importBackup(sourceUri: Uri) {
        lock()

        val dbFile =
            appContext.getDatabasePath("skhoron_vault.db")

        val walFile =
            appContext.getDatabasePath("skhoron_vault.db-wal")

        val shmFile =
            appContext.getDatabasePath("skhoron_vault.db-shm")

        val tempFile = File(
            appContext.cacheDir,
            "import_tmp_${System.nanoTime()}.db"
        )

        val rollbackFile = File(
            appContext.cacheDir,
            "import_rollback_${System.nanoTime()}.db"
        )

        var salt: ByteArray? = null
        var replacementApplied = false
        var hadOriginalDb = false

        try {
            appContext.contentResolver
                .openInputStream(sourceUri)
                ?.use { input ->

                    val lenBytes = ByteArray(4)

                    if (input.readFully(lenBytes) != 4) {
                        throw IllegalStateException(
                            "Повреждённый файл бэкапа (нет заголовка)"
                        )
                    }

                    val saltLen =
                        ByteBuffer.wrap(lenBytes).int

                    if (saltLen != Argon2Params.SALT_LEN) {
                        throw IllegalStateException(
                            "Некорректный формат бэкапа " +
                                "(ожидалась длина соли " +
                                "${Argon2Params.SALT_LEN}, получено $saltLen)"
                        )
                    }

                    val saltBytes = ByteArray(saltLen)

                    if (input.readFully(saltBytes) != saltLen) {
                        saltBytes.fill(0)

                        throw IllegalStateException(
                            "Повреждённый файл бэкапа (неполная соль)"
                        )
                    }

                    salt = saltBytes

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

            val committed = prefs.edit()
                .putString(
                    PreferencesStore.KEY_SALT,
                    Base64.encodeToString(
                        validatedSalt,
                        Base64.NO_WRAP
                    )
                )
                .putInt(
                    PreferencesStore.KEY_FAILED_ATTEMPTS,
                    0
                )
                .commit()

            if (!committed) {
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

            if (tempFile.exists()) {
                tempFile.delete()
            }

            if (rollbackFile.exists()) {
                rollbackFile.delete()
            }
        }
    }
}