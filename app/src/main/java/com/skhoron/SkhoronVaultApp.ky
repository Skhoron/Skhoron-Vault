package com.skhoron.vault

import android.app.Application
import android.os.Handler
import android.os.Looper
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.skhoron.vault.data.VaultRepository

/**
 * SkhoronVaultApp — держит единственный на процесс инстанс VaultRepository.
 * MainActivity и SkhoronAutofillService объявлены в одном процессе (":vault",
 * см. AndroidManifest), поэтому оба видят один и тот же разблокированный
 * vault в рамках сессии — не нужно повторно вводить пароль для автозаполнения
 * сразу после того, как разблокировал через основной экран.
 *
 * Автоблокировка двухуровневая: таймер на главном потоке блокирует vault
 * сразу по истечении таймаута, пока приложение в фоне, а проверка по
 * монотонным часам при возврате на передний план — страховка на случай, если
 * процесс был заморожен и таймер не отработал.
 */
class SkhoronVaultApp : Application() {

    lateinit var repository: VaultRepository
        private set

    private val handler = Handler(Looper.getMainLooper())
    private val lockRunnable = Runnable { repository.lock() }

    override fun onCreate() {
        super.onCreate()
        repository = VaultRepository(applicationContext)

        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStop(owner: LifecycleOwner) {
                // Приложение ушло в фон (свёрнуто/экран заблокирован) — фиксируем момент
                // и ставим таймер блокировки.
                if (repository.isUnlocked) {
                    repository.onAppBackgrounded()
                    handler.removeCallbacks(lockRunnable)
                    handler.postDelayed(lockRunnable, repository.getAutolockMillis())
                }
            }

            override fun onStart(owner: LifecycleOwner) {
                // Вернулись на передний план — таймер больше не нужен, а истёкший
                // таймаут проверяем по монотонным часам.
                handler.removeCallbacks(lockRunnable)
                repository.checkAutolockOnForeground()
            }
        })
    }
}