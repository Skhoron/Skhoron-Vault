package com.skhoron.vault.generator

import java.security.SecureRandom
import kotlin.math.log2

/**
 * Генератор паролей. Дефолт — 64 символа из полного printable-ASCII набора (94 символа),
 * что даёт ~419 бит энтропии. Поскольку пароль вставляется через AutofillService и
 * никогда не набирается руками, нет смысла жертвовать стойкостью ради "запоминаемости".
 */

object CharsetPool {
    const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    const val DIGITS = "0123456789"
    const val SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
}

data class GeneratorOptions(
    val length: Int = 64,
    val useLower: Boolean = true,
    val useUpper: Boolean = true,
    val useDigits: Boolean = true,
    val useSymbols: Boolean = true
)

data class GeneratedPassword(val value: String, val entropyBits: Double) {
    /** Человекочитаемое сравнение энтропии — наглядно и по делу. */
    fun comparisonLabel(): String = when {
        entropyBits >= 266 -> "сильнее, чем протонов в наблюдаемой Вселенной"
        entropyBits >= 230 -> "сильнее, чем протонов в галактике Млечный Путь"
        entropyBits >= 128 -> "надёжный уровень для любых современных атак"
        else -> "ниже рекомендуемого минимума — увеличь длину"
    }
}

class PasswordGenerator {

    private val secureRandom = SecureRandom() // криптостойкий ГПСЧ, не java.util.Random

    fun generate(options: GeneratorOptions = GeneratorOptions()): GeneratedPassword {
        val pool = buildString {
            if (options.useLower) append(CharsetPool.LOWER)
            if (options.useUpper) append(CharsetPool.UPPER)
            if (options.useDigits) append(CharsetPool.DIGITS)
            if (options.useSymbols) append(CharsetPool.SYMBOLS)
        }
        require(pool.isNotEmpty()) { "Нужно выбрать хотя бы один набор символов" }
        require(options.length in 8..128) { "Длина пароля должна быть от 8 до 128 символов" }

        val password = buildString(options.length) {
            repeat(options.length) {
                append(pool[secureRandom.nextInt(pool.length)])
            }
        }

        val entropy = options.length * log2(pool.length.toDouble())
        return GeneratedPassword(password, entropy)
    }
}