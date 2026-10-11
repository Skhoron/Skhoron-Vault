package com.skhoron.vault.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Копирование секретов в буфер обмена: помечаем содержимое как sensitive
 * (Android 13+ скрывает его в превью) и очищаем буфер через [CLEAR_DELAY_MS].
 * Очистка срабатывает только для последнего копирования — более ранний таймер
 * не сотрёт то, что пользователь скопировал позже.
 */
object ClipboardHelper {
    const val CLEAR_DELAY_MS = 30_000L

    private val handler = Handler(Looper.getMainLooper())
    private var clearTask: Runnable? = null

    fun copySecret(context: Context, label: String, value: String) {
        val clipboard = context.applicationContext
            .getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

        val clip = ClipData.newPlainText(label, value)
        if (Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        clipboard.setPrimaryClip(clip)

        clearTask?.let { handler.removeCallbacks(it) }
        val task = Runnable { clear(clipboard) }
        clearTask = task
        handler.postDelayed(task, CLEAR_DELAY_MS)
    }

    private fun clear(clipboard: ClipboardManager) {
        if (Build.VERSION.SDK_INT >= 28) {
            clipboard.clearPrimaryClip()
        } else {
            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
        clearTask = null
    }
}