# Skhoron Vault

A local password manager for Android, part of the Skhoron ecosystem.

No Network

There is no "INTERNET" permission in "AndroidManifest.xml"; without it, the OS blocks the app's sockets. Library manifests are merged with ours, so "INTERNET" is explicitly removed using "tools:node="remove"", and CI checks both the source and merged manifests (".github/scripts/check_network_invariant.py") as well as the source files for network classes.

How Storage Works

- Master password → Argon2id (64 MB, 3 iterations, 4 threads) → root key.
- The SQLCipher key and KEK are derived from the root using HKDF-SHA256.
- Each entry's password is encrypted with ChaCha20-Poly1305 (BouncyCastle, 96-bit nonce) using its own random key. This key is stored in the "entry_fields" table, wrapped in the KEK. The AAD contains the entry ID and field type, so the block cannot be moved to another entry.
- Entry metadata (name, username, domain) is stored in the database as plaintext; only SQLCipher protects it.
- A verification block under the KEK (stored in settings and in the backup) distinguishes an incorrect password from a database failure. Database or migration failures do not count toward the attempt counter.
- 10 consecutive incorrect passwords delete the database and settings. The counter is incremented before key derivation and written using "commit()", so killing the process does not cancel the attempt.
- Vaults before v0.5 do not have a verification block: until one exists, a failed SQLCipher opening is treated as an incorrect password. The block is written on the first successful unlock.

Database Schema and Backup

Room, version 2; JSON schemas are written to "app/schemas". Migration 1→2 creates
"entry_fields"; passwords are moved during the first unlock in a single transaction.
Make a backup before upgrading from v0.5.

Backup format: ""SKVB" | 0x02 | salt length | salt | verification block length | verification block | database". The old format ("salt length | salt | database") is also
imported. The database contents cannot be checked before unlocking, so during
import, the header, size (up to 128 MB), and non-empty file contents are checked.

Auto-Lock

A timer locks the vault 1–30 minutes after the app goes into the background. When returning to
the app, monotonic time is also checked.

Generator

- Password of 8–128 characters from selected character classes, with an option to exclude similar characters.
  Each selected class is present in the password. Entropy is calculated exactly.
- PIN of 4–12 digits.
- Passphrase of 4–12 words. Requires "app/src/main/assets/wordlist.txt" (at least 1024
  words, one per line; the EFF format is supported). The file is not in the repository,
  so this mode is hidden without it.

Autofill

Fills in credentials only when the domain matches exactly. If a page contains two different
domains (for example, an iframe), the form is not filled. Duplicates (same domain and
username) are skipped when saving.

Limitations

- Compose "TextField" works only with "String", so the master password on
  the unlock screen and the displayed password remain in the heap as "String" for some time.
- The attempt counter is stored in "EncryptedSharedPreferences"; with root access
  to the device, it can be reset.
- Import replaces the current vault and requires the backup password.

Not Implemented

Changing the master password ("rewrapFieldKey" is ready, but SQLCipher rekeying and a new
salt are still needed), editing entries, returning the unlock result to
autofill, a save confirmation dialog, and binding native apps by package name and signature.

Build and Tests

Android Studio Koala or newer, JDK 17. Open the root folder, wait for
Gradle Sync, then select "Build → Build APK(s)". Tests: "./gradlew testDebugUnitTest".
Then enable autofill: Settings → System → Languages & input →
Autofill → Skhoron Vault.