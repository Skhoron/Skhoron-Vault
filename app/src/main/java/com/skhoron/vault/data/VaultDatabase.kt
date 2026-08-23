package com.skhoron.vault.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SupportFactory

/**
 * VaultDatabase — SQLCipher-зашифрованный файл БД + шифрование каждого поля
 * на уровне приложения (VaultCrypto).
 *
 * Намеренно НЕТ fallbackToDestructiveMigration(): при несовместимой схеме
 * (например, после апдейта приложения без написанной миграции) приложение
 * упадёт с понятным исключением вместо того, чтобы молча стереть все
 * данные пользователя. Падать громко — осознанное решение для password
 * manager, пока не появятся отдельные migration-тесты.
 */
@Database(entities = [VaultEntryRow::class], version = 1, exportSchema = false)
abstract class VaultDatabase : RoomDatabase() {
    abstract fun vaultEntryDao(): VaultEntryDao

    companion object {
        fun build(context: Context, sqlCipherPassphrase: ByteArray): VaultDatabase {
            SQLiteDatabase.loadLibs(context)
            val factory = SupportFactory(sqlCipherPassphrase)
            return Room.databaseBuilder(
                context.applicationContext,
                VaultDatabase::class.java,
                "skhoron_vault.db"
            )
                .openHelperFactory(factory)
                .build()
        }
    }
}