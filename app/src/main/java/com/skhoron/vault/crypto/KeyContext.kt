package com.skhoron.vault.crypto

/**
 * Контексты HKDF. Из одного корня (Argon2id) выводятся независимые ключи;
 * компрометация одного не раскрывает остальные.
 */
object KeyContext {
    /** Ключ SQLCipher (шифрование файла БД целиком). */
    val SQLCIPHER = "skhoron-vault-sqlcipher-v1".toByteArray()

    /**
     * Только для миграции схемы 1→2: единый ключ, которым v1 шифровал все
     * пароли. В схеме v2 не используется для новых данных.
     */
    val FIELD_ENCRYPTION = "skhoron-vault-field-encryption-v1".toByteArray()

    /** KEK, оборачивающий ключи полей записей «Login» и проверочный блок. */
    val KEK_LOGIN = "skhoron-vault-kek-login-v2".toByteArray()
}