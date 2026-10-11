package com.skhoron.vault.generator

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import kotlin.math.log2

class PasswordGeneratorTest {

    private val generator = PasswordGenerator()

    private fun assertRejected(block: () -> Unit) {
        try {
            block()
            fail("ожидалось IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // ok
        }
    }

    @Test
    fun everySelectedClassIsPresentEvenForShortPasswords() {
        repeat(300) {
            val p = generator.generate(GeneratorOptions(length = 8)).value
            assertEquals(8, p.length)
            assertTrue(p.any { it in CharsetPool.LOWER })
            assertTrue(p.any { it in CharsetPool.UPPER })
            assertTrue(p.any { it in CharsetPool.DIGITS })
            assertTrue(p.any { it in CharsetPool.SYMBOLS })
        }
    }

    @Test
    fun onlySelectedClassesAreUsed() {
        repeat(50) {
            val p = generator.generate(
                GeneratorOptions(length = 32, useUpper = false, useSymbols = false)
            ).value
            assertTrue(p.all { it in CharsetPool.LOWER || it in CharsetPool.DIGITS })
        }
    }

    @Test
    fun ambiguousCharactersAreExcludedOnRequest() {
        repeat(100) {
            val p = generator.generate(GeneratorOptions(length = 64, excludeAmbiguous = true)).value
            assertTrue(p.none { it in CharsetPool.AMBIGUOUS })
        }
    }

    @Test
    fun defaultEntropyMatchesFullPool() {
        val bits = generator.generate().entropyBits
        // Требование «есть символ каждого класса» при 64 символах почти ничего не отнимает.
        assertEquals(64 * log2(94.0), bits, 0.01)
    }

    @Test
    fun entropyFormulaMatchesBruteForce() {
        // Пул из 5 символов: классы по 2, 2 и 1. Строки длины 3, где есть все три класса.
        val classOf = intArrayOf(0, 0, 1, 1, 2)
        var count = 0
        for (a in 0 until 5) for (b in 0 until 5) for (c in 0 until 5) {
            if (setOf(classOf[a], classOf[b], classOf[c]).size == 3) count++
        }
        assertEquals(log2(count.toDouble()), PasswordGenerator.entropyBits(3, listOf(2, 2, 1)), 1e-9)
    }

    @Test
    fun invalidOptionsAreRejected() {
        assertRejected { generator.generate(GeneratorOptions(length = 7)) }
        assertRejected { generator.generate(GeneratorOptions(length = 129)) }
        assertRejected {
            generator.generate(
                GeneratorOptions(useLower = false, useUpper = false, useDigits = false, useSymbols = false)
            )
        }
    }

    @Test
    fun pinIsDigitsOfRequestedLength() {
        val pin = generator.generatePin(8)
        assertEquals(8, pin.value.length)
        assertTrue(pin.value.all { it.isDigit() })
        assertEquals(8 * log2(10.0), pin.entropyBits, 1e-9)
        assertRejected { generator.generatePin(3) }
    }

    @Test
    fun passphraseUsesWordListAndCountsEntropy() {
        val words = List(2048) { "w$it" }
        val phrase = generator.generatePassphrase(words, words = 5, separator = "-")
        val parts = phrase.value.split("-")
        assertEquals(5, parts.size)
        assertTrue(parts.all { it in words })
        assertEquals(5 * 11.0, phrase.entropyBits, 1e-9) // log2(2048) = 11
    }

    @Test
    fun shortWordListIsRejected() {
        assertRejected { generator.generatePassphrase(List(100) { "w$it" }) }
    }
}