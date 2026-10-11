package com.skhoron.vault.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.KeyParameter
import java.security.SecureRandom

/**
 * VaultCrypto — ядро шифрования Skhoron Vault.
 *
 * АРХИТЕКТУРНЫЙ ИНВАРИАНТ: этот пакет (vault.crypto) не содержит и не должен
 * содержать сетевых вызовов.
 *
 * ВАЖНО — честное название примитива: используется ChaCha20-Poly1305
 * (RFC 7539, 96-бит/12-байтный nonce), а НЕ XChaCha20-Poly1305 (192-бит
 * nonce, требует HChaCha20 subkey derivation). Более раннее название в
 * коде/README было неточным — это фиксирует несоответствие.
 *
 * Почему 96-битного nonce достаточно здесь: nonce генерируется случайно
 * (SecureRandom) для каждой записи. Риск коллизии двух nonce для одного
 * ключа пренебрежимо мал для объёма записей одного личного vault'а —
 * по birthday bound нужно ~2^48 записей для 50%-й вероятности коллизии.
 * Если в будущем понадобится гарантия, не зависящая от объёма записей
 * (честный XChaCha20 с расширенным nonce) — это отдельная реализация
 * поверх HChaCha20 subkey derivation, которой сейчас нет.
 *
 * Схема v2 (ключи по полям): каждое секретное поле шифруется собственным
 * случайным 256-бит ключом; этот ключ хранится рядом, завёрнутый в KEK.
 * AAD = «id записи | тип поля», поэтому блок нельзя перенести в другую
 * запись или подставить вместо другого поля. Утечка ключа одного поля не
 * открывает остальные.
 *
 * KEK существует только в оперативной памяти на время разблокированной
 * сессии, никогда не сериализуется на диск.
 */

object Argon2Params {
    const val MEMORY_KB = 65536   // 64 MB
    const val ITERATIONS = 3
    const val PARALLELISM = 4
    const val SALT_LEN = 16
    const val KEY_LEN = 32        // 256 бит
    const val NONCE_LEN = 12      // ChaCha20-Poly1305 (RFC 7539) — 96-бит nonce
}

/**
 * Ключ для шифрования/расшифровки. Соль здесь намеренно НЕ хранится —
 * она нужна только на этапе вывода ключа (Argon2id) и не является частью
 * материала ключа; хранение её здесь было избыточным и создавало риск,
 * что метод zeroize() создаёт ложное впечатление полной очистки, тогда
 * как соль (не секрет, но лишняя ссылка) продолжала бы жить в памяти.
 */
class DerivedKey(val keyBytes: ByteArray) {
    fun zeroize() { keyBytes.fill(0) }
}

/** Зашифрованный блок: ciphertext (с тегом Poly1305) и nonce. */
class EncryptedBlob(val ciphertext: ByteArray, val nonce: ByteArray) {
    /** nonce (12 байт) || ciphertext — для хранения в одной строке/поле. */
    fun toBytes(): ByteArray = nonce + ciphertext

    companion object {
        fun fromBytes(bytes: ByteArray): EncryptedBlob {
            if (bytes.size <= Argon2Params.NONCE_LEN) {
                throw VaultCryptoException("Повреждённый блок: слишком короткий")
            }
            return EncryptedBlob(
                ciphertext = bytes.copyOfRange(Argon2Params.NONCE_LEN, bytes.size),
                nonce = bytes.copyOfRange(0, Argon2Params.NONCE_LEN)
            )
        }
    }
}

/**
 * Секретное поле записи в схеме v2: данные под собственным ключом
 * (ciphertext/nonce) и этот ключ, завёрнутый в KEK (wrappedKey/wrapNonce).
 */
class SealedField(
    val ciphertext: ByteArray,
    val nonce: ByteArray,
    val wrappedKey: ByteArray,
    val wrapNonce: ByteArray
)

class VaultCryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)

class VaultCrypto {

    private val secureRandom = SecureRandom()

    fun generateSalt(): ByteArray = ByteArray(Argon2Params.SALT_LEN).also { secureRandom.nextBytes(it) }

    fun generateNonce(): ByteArray = ByteArray(Argon2Params.NONCE_LEN).also { secureRandom.nextBytes(it) }

    /** Новый случайный 256-битный ключ (ключ поля). */
    fun newFieldKey(): ByteArray = ByteArray(Argon2Params.KEY_LEN).also { secureRandom.nextBytes(it) }

    /** Argon2id: пароль (уже как ByteArray, без промежуточного String на
     *  вызывающей стороне) + соль -> 256-битный ключ. Тяжёлая операция
     *  (~0.5–1.5 сек) — вызывающая сторона должна использовать
     *  Dispatchers.Default, а не запускать на UI-потоке. */
    fun deriveMasterKey(password: ByteArray, salt: ByteArray): DerivedKey {
        val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(Argon2Params.ITERATIONS)
            .withMemoryAsKB(Argon2Params.MEMORY_KB)
            .withParallelism(Argon2Params.PARALLELISM)
            .withSalt(salt)

        val generator = Argon2BytesGenerator()
        generator.init(builder.build())

        val out = ByteArray(Argon2Params.KEY_LEN)
        generator.generateBytes(password, out)
        return DerivedKey(out)
    }

    // ---- примитив AEAD ------------------------------------------------

    fun encryptEntry(key: DerivedKey, plaintext: ByteArray, aad: ByteArray? = null): EncryptedBlob {
        val nonce = generateNonce()
        try {
            val cipher = ChaCha20Poly1305()
            cipher.init(true, AEADParameters(KeyParameter(key.keyBytes), 128, nonce, aad))

            val out = ByteArray(cipher.getOutputSize(plaintext.size))
            var len = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
            len += cipher.doFinal(out, len)
            return EncryptedBlob(out.copyOf(len), nonce)
        } catch (e: Exception) {
            throw VaultCryptoException("Ошибка шифрования записи", e)
        }
    }

    fun decryptEntry(key: DerivedKey, blob: EncryptedBlob, aad: ByteArray? = null): ByteArray {
        try {
            val cipher = ChaCha20Poly1305()
            cipher.init(false, AEADParameters(KeyParameter(key.keyBytes), 128, blob.nonce, aad))

            val out = ByteArray(cipher.getOutputSize(blob.ciphertext.size))
            var len = cipher.processBytes(blob.ciphertext, 0, blob.ciphertext.size, out, 0)
            len += cipher.doFinal(out, len)
            return out.copyOf(len)
        } catch (e: Exception) {
            throw VaultCryptoException("Неверный ключ или повреждённые данные", e)
        }
    }

    // ---- схема v2: ключи по полям -------------------------------------

    private fun dataAad(entryId: String, kind: String): ByteArray =
        "v2|$entryId|$kind".toByteArray(Charsets.UTF_8)

    private fun wrapAad(entryId: String, kind: String): ByteArray =
        "v2|$entryId|$kind|wrap".toByteArray(Charsets.UTF_8)

    /** Шифрует поле собственным случайным ключом и заворачивает этот ключ в [kek]. */
    fun sealField(kek: DerivedKey, entryId: String, kind: String, plaintext: ByteArray): SealedField {
        val fieldKeyBytes = newFieldKey()
        try {
            val data = encryptEntry(DerivedKey(fieldKeyBytes), plaintext, dataAad(entryId, kind))
            val wrapped = encryptEntry(kek, fieldKeyBytes, wrapAad(entryId, kind))
            return SealedField(data.ciphertext, data.nonce, wrapped.ciphertext, wrapped.nonce)
        } finally {
            fieldKeyBytes.fill(0)
        }
    }

    /** Разворачивает ключ одного поля. Вызывающий обязан вызвать zeroize(). */
    fun unwrapFieldKey(kek: DerivedKey, entryId: String, kind: String, sealed: SealedField): DerivedKey {
        val keyBytes = decryptEntry(
            kek,
            EncryptedBlob(sealed.wrappedKey, sealed.wrapNonce),
            wrapAad(entryId, kind)
        )
        return DerivedKey(keyBytes)
    }

    /** Расшифровывает поле уже развёрнутым ключом поля. */
    fun openWithFieldKey(fieldKey: DerivedKey, entryId: String, kind: String, sealed: SealedField): ByteArray =
        decryptEntry(
            fieldKey,
            EncryptedBlob(sealed.ciphertext, sealed.nonce),
            dataAad(entryId, kind)
        )

    /** Разворачивает ключ только этого поля и расшифровывает его. */
    fun openField(kek: DerivedKey, entryId: String, kind: String, sealed: SealedField): ByteArray {
        val fieldKey = unwrapFieldKey(kek, entryId, kind, sealed)
        try {
            return openWithFieldKey(fieldKey, entryId, kind, sealed)
        } finally {
            fieldKey.zeroize()
        }
    }

    /** Меняет только обёртку ключа поля; сами данные не перешифровываются. */
    fun rewrapFieldKey(
        oldKek: DerivedKey,
        newKek: DerivedKey,
        entryId: String,
        kind: String,
        sealed: SealedField
    ): SealedField {
        val fieldKey = unwrapFieldKey(oldKek, entryId, kind, sealed)
        try {
            val wrapped = encryptEntry(newKek, fieldKey.keyBytes, wrapAad(entryId, kind))
            return SealedField(sealed.ciphertext, sealed.nonce, wrapped.ciphertext, wrapped.nonce)
        } finally {
            fieldKey.zeroize()
        }
    }

    // ---- проверочный блок --------------------------------------------

    private val verifierPlaintext = "skhoron-vault-verifier-v2".toByteArray(Charsets.UTF_8)
    private val verifierAad = "v2|verifier".toByteArray(Charsets.UTF_8)

    /**
     * Блок, расшифровка которого подтверждает, что KEK верный. Позволяет
     * отличить неверный мастер-пароль от сбоя БД или миграции.
     */
    fun sealVerifier(kek: DerivedKey): EncryptedBlob =
        encryptEntry(kek, verifierPlaintext, verifierAad)

    fun checkVerifier(kek: DerivedKey, blob: EncryptedBlob): Boolean =
        try {
            decryptEntry(kek, blob, verifierAad).contentEquals(verifierPlaintext)
        } catch (e: VaultCryptoException) {
            false
        }
}