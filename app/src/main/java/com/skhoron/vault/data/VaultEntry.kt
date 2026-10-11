package com.skhoron.vault.data

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/** Тип секретного поля входит в AAD, менять значение нельзя. */
object FieldKind {
    const val PASSWORD = "password"
}

/**
 * Одна запись vault'а. Несекретные метаданные (label, username, domain_hint)
 * лежат в таблице как есть — файл БД целиком зашифрован SQLCipher. Секретные
 * поля живут в [EntryFieldRow], каждое под своим ключом.
 *
 * Колонки password_ciphertext/password_nonce остались от схемы v1: у записей
 * схемы v2 они пустые, пароль лежит в entry_fields. Room не умеет безопасно
 * удалять колонки, поэтому они оставлены намеренно.
 */
@Entity(tableName = "vault_entries")
data class VaultEntryRow(
    @PrimaryKey val id: String, // UUID, генерируется локально
    @ColumnInfo(name = "label") val label: String, // "github.com" — видно в списке
    @ColumnInfo(name = "username") val username: String?,
    @ColumnInfo(name = "password_ciphertext") val passwordCiphertext: ByteArray,
    @ColumnInfo(name = "password_nonce") val passwordNonce: ByteArray,
    @ColumnInfo(name = "domain_hint") val domainHint: String?, // для автоподстановки при след. визите
    @ColumnInfo(name = "created_at") val createdAt: Long,
    @ColumnInfo(name = "notes") val notes: String? = null, // legacy v1, не используется
    @ColumnInfo(name = "password_migrated", defaultValue = "0") val passwordMigrated: Boolean = false
)

/** Секретное поле записи: данные под собственным ключом + ключ, завёрнутый в KEK. */
@Entity(
    tableName = "entry_fields",
    primaryKeys = ["entry_id", "kind"],
    foreignKeys = [
        ForeignKey(
            entity = VaultEntryRow::class,
            parentColumns = ["id"],
            childColumns = ["entry_id"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [Index(value = ["entry_id"])]
)
class EntryFieldRow(
    @ColumnInfo(name = "entry_id") val entryId: String,
    @ColumnInfo(name = "kind") val kind: String,
    @ColumnInfo(name = "ciphertext") val ciphertext: ByteArray,
    @ColumnInfo(name = "nonce") val nonce: ByteArray,
    @ColumnInfo(name = "wrapped_key") val wrappedKey: ByteArray,
    @ColumnInfo(name = "wrap_nonce") val wrapNonce: ByteArray
)

@Dao
interface VaultEntryDao {
    @Query("SELECT * FROM vault_entries ORDER BY label ASC")
    fun observeAll(): Flow<List<VaultEntryRow>>

    @Query("SELECT * FROM vault_entries WHERE lower(domain_hint) = :domain LIMIT 5")
    suspend fun findByDomain(domain: String): List<VaultEntryRow>

    @Query("SELECT * FROM vault_entries WHERE id = :id")
    suspend fun getById(id: String): VaultEntryRow?

    @Query("SELECT * FROM vault_entries WHERE password_migrated = 0")
    suspend fun findUnmigrated(): List<VaultEntryRow>

    @Query(
        "UPDATE vault_entries SET password_ciphertext = :empty, password_nonce = :empty, " +
            "password_migrated = 1 WHERE id = :id"
    )
    suspend fun markMigrated(id: String, empty: ByteArray)

    @Insert
    suspend fun insert(entry: VaultEntryRow)

    @Delete
    suspend fun delete(entry: VaultEntryRow)

    @Query("DELETE FROM vault_entries WHERE id = :id")
    suspend fun deleteById(id: String)
}

@Dao
interface EntryFieldDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(field: EntryFieldRow)

    @Query("SELECT * FROM entry_fields WHERE entry_id = :entryId AND kind = :kind")
    suspend fun get(entryId: String, kind: String): EntryFieldRow?

    @Query("DELETE FROM entry_fields WHERE entry_id = :entryId")
    suspend fun deleteFor(entryId: String)
}