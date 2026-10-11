package com.skhoron.vault.generator

import android.content.Context
import java.math.BigInteger
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

    /** Символы, которые легко спутать при чтении с экрана. */
    const val AMBIGUOUS = "Il1|O0o"
}

data class GeneratorOptions(
    val length: Int = 64,
    val useLower: Boolean = true,
    val useUpper: Boolean = true,
    val useDigits: Boolean = true,
    val useSymbols: Boolean = true,
    val excludeAmbiguous: Boolean = false
)

data class GeneratedPassword(val value: String, val entropyBits: Double)

class PasswordGenerator {

    companion object {
        const val MIN_LENGTH = 8
        const val MAX_LENGTH = 128
        const val MIN_PIN = 4
        const val MAX_PIN = 12
        const val MIN_WORDS = 4
        const val MAX_WORDS = 12

        /** Короткий список даёт слишком мало бит на слово. EFF large — 7776. */
        const val MIN_WORDLIST_SIZE = 1024

        private const val MAX_ATTEMPTS = 100_000

        /**
         * Точная энтропия: log2 числа строк длины [length] над пулом, где
         * каждый из классов [classSizes] встречается хотя бы раз
         * (включение–исключение). Совпадает с тем, что даёт rejection
         * sampling в [generate], потому что принятые строки равновероятны.
         */
        fun entropyBits(length: Int, classSizes: List<Int>): Double {
            val pool = classSizes.sum()
            var total = BigInteger.ZERO
            for (mask in 0 until (1 shl classSizes.size)) {
                var removed = 0
                var bits = 0
                for (i in classSizes.indices) {
                    if (mask and (1 shl i) != 0) {
                        removed += classSizes[i]
                        bits++
                    }
                }
                val term = BigInteger.valueOf((pool - removed).toLong()).pow(length)
                total = if (bits % 2 == 0) total + term else total - term
            }
            return log2(total.toDouble())
        }
    }

    private val secureRandom = SecureRandom() // криптостойкий ГПСЧ, не java.util.Random

    /**
     * В пароле гарантированно есть символ каждого выбранного класса. Это
     * делается отбраковкой (генерируем равномерно и повторяем, пока не
     * сойдётся), а не подстановкой по одному символу из класса: подстановка
     * смещает распределение, отбраковка нет.
     */
    fun generate(options: GeneratorOptions = GeneratorOptions()): GeneratedPassword {
        val classes = buildList {
            if (options.useLower) add(CharsetPool.LOWER)
            if (options.useUpper) add(CharsetPool.UPPER)
            if (options.useDigits) add(CharsetPool.DIGITS)
            if (options.useSymbols) add(CharsetPool.SYMBOLS)
        }.map { cls ->
            if (options.excludeAmbiguous) cls.filter { it !in CharsetPool.AMBIGUOUS } else cls
        }

        require(classes.isNotEmpty()) { "Нужно выбрать хотя бы один набор символов" }
        require(options.length in MIN_LENGTH..MAX_LENGTH) {
            "Длина пароля должна быть от $MIN_LENGTH до $MAX_LENGTH символов"
        }

        val pool = classes.joinToString("")
        val buffer = CharArray(options.length)

        try {
            repeat(MAX_ATTEMPTS) {
                for (i in buffer.indices) {
                    buffer[i] = pool[secureRandom.nextInt(pool.length)]
                }
                if (classes.all { cls -> buffer.any { it in cls } }) {
                    return GeneratedPassword(
                        value = String(buffer),
                        entropyBits = entropyBits(options.length, classes.map { it.length })
                    )
                }
            }
            throw IllegalStateException("Не удалось сгенерировать пароль с заданными классами")
        } finally {
            buffer.fill('\u0000')
        }
    }

    fun generatePin(length: Int = 6): GeneratedPassword {
        require(length in MIN_PIN..MAX_PIN) { "PIN: от $MIN_PIN до $MAX_PIN цифр" }
        val pin = buildString(length) {
            repeat(length) { append(CharsetPool.DIGITS[secureRandom.nextInt(10)]) }
        }
        return GeneratedPassword(pin, length * log2(10.0))
    }

    /** Слова выбираются независимо и равновероятно: entropy = words * log2(размер списка). */
    fun generatePassphrase(
        wordList: List<String>,
        words: Int = 6,
        separator: String = "-"
    ): GeneratedPassword {
        require(wordList.size >= MIN_WORDLIST_SIZE) {
            "Список слов слишком короткий (${wordList.size}); нужно не меньше $MIN_WORDLIST_SIZE"
        }
        require(words in MIN_WORDS..MAX_WORDS) { "Слов: от $MIN_WORDS до $MAX_WORDS" }

        val phrase = List(words) { wordList[secureRandom.nextInt(wordList.size)] }
            .joinToString(separator)
        return GeneratedPassword(phrase, words * log2(wordList.size.toDouble()))
    }
}

/** Список слов для passphrase: app/src/main/assets/wordlist.txt, по слову в строке. */
object WordList {
    const val ASSET_NAME = "wordlist.txt"

    /** Пусто, если файла нет или он слишком короткий — тогда passphrase недоступна. */
    fun load(context: Context): List<String> =
        try {
            context.assets.open(ASSET_NAME).bufferedReader(Charsets.UTF_8).use { reader ->
                reader.lineSequence()
                    .map { it.trim() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .map { line -> line.substringAfterLast('\t').trim() } // формат EFF: "11111<TAB>слово"
                    .distinct()
                    .toList()
            }.takeIf { it.size >= PasswordGenerator.MIN_WORDLIST_SIZE } ?: emptyList()
        } catch (e: java.io.IOException) {
            emptyList()
        }
}