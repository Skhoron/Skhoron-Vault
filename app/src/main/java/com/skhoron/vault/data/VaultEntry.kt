package com.skhoron.vault.data

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * Одна запись vault'а. Пароль хранится только в зашифрованном виде (ciphertext+nonce),
 * расшифровка происходит на лету в момент показа юзеру или автозаполнения — никогда
 * не пишется в открытом виде на диск, даже во временный кэш.
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
    @ColumnInfo(name = "notes") val notes: String? = null
)

@Dao
interface VaultEntryDao {
    @Query("SELECT * FROM vault_entries ORDER BY label ASC")
    fun observeAll(): Flow<List<VaultEntryRow>>

    @Query("SELECT * FROM vault_entries WHERE domain_hint = :domain LIMIT 5")
    suspend fun findByDomain(domain: String): List<VaultEntryRow>

    @Insert
    suspend fun insert(entry: VaultEntryRow)

    @Delete
    suspend fun delete(entry: VaultEntryRow)
}