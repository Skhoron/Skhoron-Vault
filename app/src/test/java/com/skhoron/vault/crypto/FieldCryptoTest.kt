package com.skhoron.vault.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class FieldCryptoTest {

    private val crypto = VaultCrypto()
    private val secret = "correct horse battery staple".toByteArray()

    private fun kek() = DerivedKey(crypto.newFieldKey())

    private fun assertRejected(block: () -> Unit) {
        try {
            block()
            fail("ожидалось VaultCryptoException")
        } catch (e: VaultCryptoException) {
            // ok
        }
    }

    @Test
    fun roundTrip() {
        val kek = kek()
        val sealed = crypto.sealField(kek, "e1", "password", secret)
        assertArrayEquals(secret, crypto.openField(kek, "e1", "password", sealed))
    }

    @Test
    fun blockIsBoundToEntryAndKind() {
        val kek = kek()
        val sealed = crypto.sealField(kek, "e1", "password", secret)
        assertRejected { crypto.openField(kek, "e2", "password", sealed) }
        assertRejected { crypto.openField(kek, "e1", "notes", sealed) }
    }

    @Test
    fun everyFieldGetsItsOwnKey() {
        val kek = kek()
        val a = crypto.sealField(kek, "e1", "password", secret)
        val b = crypto.sealField(kek, "e1", "notes", secret)
        val keyA = crypto.unwrapFieldKey(kek, "e1", "password", a)
        val keyB = crypto.unwrapFieldKey(kek, "e1", "notes", b)
        assertFalse(keyA.keyBytes.contentEquals(keyB.keyBytes))
    }

    @Test
    fun leakedFieldKeyOpensOnlyItsOwnField() {
        val kek = kek()
        val a = crypto.sealField(kek, "e1", "password", secret)
        val b = crypto.sealField(kek, "e1", "notes", secret)
        val keyA = crypto.unwrapFieldKey(kek, "e1", "password", a)

        assertArrayEquals(secret, crypto.openWithFieldKey(keyA, "e1", "password", a))
        assertRejected { crypto.openWithFieldKey(keyA, "e1", "notes", b) }
    }

    @Test
    fun wrongKekCannotUnwrap() {
        val sealed = crypto.sealField(kek(), "e1", "password", secret)
        assertRejected { crypto.unwrapFieldKey(kek(), "e1", "password", sealed) }
    }

    @Test
    fun rewrapChangesOnlyTheWrapper() {
        val oldKek = kek()
        val newKek = kek()
        val sealed = crypto.sealField(oldKek, "e1", "password", secret)
        val rewrapped = crypto.rewrapFieldKey(oldKek, newKek, "e1", "password", sealed)

        assertArrayEquals(sealed.ciphertext, rewrapped.ciphertext)
        assertArrayEquals(secret, crypto.openField(newKek, "e1", "password", rewrapped))
        assertRejected { crypto.openField(oldKek, "e1", "password", rewrapped) }
    }

    @Test
    fun hkdfContextsGiveDifferentKeys() {
        val root = ByteArray(32) { it.toByte() }
        val a = Hkdf.expand(root, KeyContext.SQLCIPHER)
        val b = Hkdf.expand(root, KeyContext.KEK_LOGIN)
        val c = Hkdf.expand(root, KeyContext.FIELD_ENCRYPTION)
        assertTrue(!a.contentEquals(b) && !b.contentEquals(c) && !a.contentEquals(c))
    }
}