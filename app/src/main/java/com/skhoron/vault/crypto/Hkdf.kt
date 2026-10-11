package com.skhoron.vault.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

/** HKDF-SHA256 (RFC 5869) без соли: ikm у нас уже равномерный ключ после Argon2id. */
object Hkdf {
    fun expand(ikm: ByteArray, context: ByteArray, outLen: Int = 32): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, null, context))
        val out = ByteArray(outLen)
        hkdf.generateBytes(out, 0, outLen)
        return out
    }
}