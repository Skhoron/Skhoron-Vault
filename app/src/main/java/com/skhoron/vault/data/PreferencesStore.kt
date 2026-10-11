package com.skhoron.vault.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Хранит только несекретные-но-чувствительные данные: соль Argon2id (не секрет
 * сама по себе, но лучше не светить лишний раз), проверочный блок мастер-пароля
 * (под KEK, не секрет), счётчик неудачных попыток разблокировки, и настройку auto-lock таймаута. НИКОГДА не хранит сам
 * мастер-пароль или производный ключ.
 *
 * Шифруется через Android Keystore (EncryptedSharedPreferences) — ключ
 * привязан к устройству, не экспортируется.
 */
object PreferencesStore {
    private const val FILE_NAME = "skhoron_vault_prefs"
    const val KEY_SALT = "salt_b64"
    const val KEY_VERIFIER = "verifier_b64"
    const val KEY_FAILED_ATTEMPTS = "failed_attempts"
    const val KEY_AUTOLOCK_MINUTES = "autolock_minutes"
    const val KEY_LAST_BACKGROUND_TS = "last_background_ts"

    const val DEFAULT_AUTOLOCK_MINUTES = 2
    const val MIN_AUTOLOCK_MINUTES = 1
    const val MAX_AUTOLOCK_MINUTES = 30
    const val PANIC_WIPE_THRESHOLD = 10

    @Volatile
    private var instance: SharedPreferences? = null

    @Synchronized
    fun get(context: Context): SharedPreferences {
        instance?.let { return it }
        val masterKey = MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        val prefs = EncryptedSharedPreferences.create(
            context.applicationContext,
            FILE_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        instance = prefs
        return prefs
    }

    /** Полное локальное стирание настроек — часть panic wipe. */
    fun wipe(context: Context) {
        get(context).edit().clear().commit()
    }
}