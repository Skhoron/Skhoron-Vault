package com.skhoron.vault.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SupportFactory

/**
 * VaultDatabase — SQLCipher-зашифрованный файл БД + шифрование каждого
 * секретного поля на уровне приложения (VaultCrypto, ключ на каждое поле).
 *
 * Намеренно НЕТ fallbackToDestructiveMigration(): при несовместимой схеме
 * приложение упадёт с понятным исключением вместо того, чтобы молча стереть
 * все данные пользователя. Падать громко — осознанное решение для password
 * manager.
 *
 * exportSchema = true: JSON схемы пишется в app/schemas (см. kapt в
 * build.gradle.kts) и коммитится — по нему пишутся тесты миграций.
 */
@Database(
    entities = [VaultEntryRow::class, EntryFieldRow::class],
    version = 2,
    exportSchema = true
)
abstract class VaultDatabase : RoomDatabase() {
    abstract fun vaultEntryDao(): VaultEntryDao
    abstract fun entryFieldDao(): EntryFieldDao

    companion object {
        const val FILE_NAME = "skhoron_vault.db"

        /**
         * 1→2: добавляет флаг миграции и таблицу entry_fields. Сами пароли
         * переносятся при первой разблокировке — нужен ключ, которого в
         * миграции нет (см. VaultRepository.migrateLegacyPasswords).
         */
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE `vault_entries` ADD COLUMN `password_migrated` " +
                        "INTEGER NOT NULL DEFAULT 0"
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS `entry_fields` (" +
                        "`entry_id` TEXT NOT NULL, " +
                        "`kind` TEXT NOT NULL, " +
                        "`ciphertext` BLOB NOT NULL, " +
                        "`nonce` BLOB NOT NULL, " +
                        "`wrapped_key` BLOB NOT NULL, " +
                        "`wrap_nonce` BLOB NOT NULL, " +
                        "PRIMARY KEY(`entry_id`, `kind`), " +
                        "FOREIGN KEY(`entry_id`) REFERENCES `vault_entries`(`id`) " +
                        "ON UPDATE NO ACTION ON DELETE CASCADE )"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS `index_entry_fields_entry_id` " +
                        "ON `entry_fields` (`entry_id`)"
                )
            }
        }

        fun build(context: Context, sqlCipherPassphrase: ByteArray): VaultDatabase {
            SQLiteDatabase.loadLibs(context)
            val factory = SupportFactory(sqlCipherPassphrase)
            return Room.databaseBuilder(
                context.applicationContext,
                VaultDatabase::class.java,
                FILE_NAME
            )
                .openHelperFactory(factory)
                .addMigrations(MIGRATION_1_2)
                .build()
        }
    }
}