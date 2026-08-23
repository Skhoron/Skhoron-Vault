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
 * masterKey существует только в оперативной памяти на время разблокированной
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

data class EncryptedBlob(val ciphertext: ByteArray, val nonce: ByteArray)

class VaultCryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)

class VaultCrypto {

    private val secureRandom = SecureRandom()

    fun generateSalt(): ByteArray = ByteArray(Argon2Params.SALT_LEN).also { secureRandom.nextBytes(it) }

    fun generateNonce(): ByteArray = ByteArray(Argon2Params.NONCE_LEN).also { secureRandom.nextBytes(it) }

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

    fun encryptEntry(masterKey: DerivedKey, plaintext: ByteArray, aad: ByteArray? = null): EncryptedBlob {
        val nonce = generateNonce()
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(masterKey.keyBytes), 128, nonce, aad))

        val out = ByteArray(cipher.getOutputSize(plaintext.size))
        var len = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        try {
            len += cipher.doFinal(out, len)
        } catch (e: Exception) {
            throw VaultCryptoException("Ошибка шифрования записи", e)
        }
        return EncryptedBlob(out.copyOf(len), nonce)
    }

    fun decryptEntry(masterKey: DerivedKey, blob: EncryptedBlob, aad: ByteArray? = null): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(masterKey.keyBytes), 128, blob.nonce, aad))

        val out = ByteArray(cipher.getOutputSize(blob.ciphertext.size))
        var len = cipher.processBytes(blob.ciphertext, 0, blob.ciphertext.size, out, 0)
        try {
            len += cipher.doFinal(out, len)
        } catch (e: Exception) {
            throw VaultCryptoException("Неверный мастер-пароль или повреждённые данные", e)
        }
        return out.copyOf(len)
    }
}