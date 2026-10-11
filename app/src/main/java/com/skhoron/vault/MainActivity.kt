package com.skhoron.vault

import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.skhoron.vault.data.FieldKind
import com.skhoron.vault.data.UnlockResult
import com.skhoron.vault.data.VaultEntryRow
import com.skhoron.vault.ui.ClipboardHelper
import com.skhoron.vault.ui.EntryScreen
import com.skhoron.vault.ui.GeneratorScreen
import com.skhoron.vault.ui.SettingsScreen
import com.skhoron.vault.ui.UnlockScreen
import com.skhoron.vault.ui.VaultListItem
import com.skhoron.vault.ui.VaultListScreen
import com.skhoron.vault.ui.theme.SkhoronVaultTheme
import kotlinx.coroutines.launch

private enum class Screen { UNLOCK, LIST, GENERATOR, SETTINGS, ENTRY }

class MainActivity : ComponentActivity() {

    private val repository by lazy { (application as SkhoronVaultApp).repository }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // FLAG_SECURE: без этого список паролей и сгенерированный пароль попадали бы
        // в скриншоты, screen recording поверх экрана и превью в панели "Недавние".
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            SkhoronVaultTheme {
                val scope = rememberCoroutineScope()
                var screen by remember {
                    mutableStateOf(if (repository.isUnlocked) Screen.LIST else Screen.UNLOCK)
                }
                var selectedEntryId by remember { mutableStateOf<String?>(null) }

                // Автоблокировка (таймер или возврат из фона) закрывает БД, пока
                // экран списка ещё в композиции. Без этого observeEntries() на
                // закрытой БД бросал исключение — теперь блокировка всегда уводит
                // на экран разблокировки.
                val unlocked by repository.unlocked.collectAsStateWithLifecycle()
                val currentScreen = if (unlocked) screen else Screen.UNLOCK

                // Один snackbar на все экраны: раньше сообщения, выставленные на
                // экране разблокировки (стирание данных, сбой хранилища), нигде
                // не показывались.
                val snackbarHostState = remember { SnackbarHostState() }
                LaunchedEffect(statusMessage) {
                    statusMessage?.let {
                        snackbarHostState.showSnackbar(it)
                        statusMessage = null
                    }
                }
                var failedAttemptsShown by remember { mutableStateOf(0) }
                var statusMessage by remember { mutableStateOf<String?>(null) }

                val exportLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.CreateDocument("application/octet-stream")
                ) { uri: Uri? ->
                    uri?.let {
                        scope.launch {
                            try {
                                repository.exportBackup(it)
                                statusMessage = "Экспорт успешно завершён."
                            } catch (e: Exception) {
                                statusMessage = "Ошибка экспорта: ${e.localizedMessage ?: e::class.simpleName}"
                            }
                        }
                    }
                }

                val importLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocument()
                ) { uri: Uri? ->
                    uri?.let {
                        scope.launch {
                            try {
                                repository.importBackup(it)
                                statusMessage = "Импорт выполнен. Введите пароль от бэкапа."
                                screen = Screen.UNLOCK
                            } catch (e: Exception) {
                                statusMessage = "Ошибка импорта: ${e.localizedMessage ?: e::class.simpleName}"
                            }
                        }
                    }
                }

                Box(Modifier.fillMaxSize()) {
                when (currentScreen) {
                    Screen.UNLOCK -> UnlockScreen(
                        isFirstRun = !repository.hasVault,
                        failedAttempts = failedAttemptsShown,
                        onUnlock = { passwordStr ->
                            val password = passwordStr.toCharArray()
                            scope.launch {
                                try {
                                    val result = if (!repository.hasVault) {
                                        repository.createVault(password)
                                    } else {
                                        repository.unlock(password)
                                    }
                                    when (result) {
                                        is UnlockResult.Success -> {
                                            failedAttemptsShown = 0
                                            screen = Screen.LIST
                                        }
                                        is UnlockResult.WrongPassword -> {
                                            failedAttemptsShown++
                                        }
                                        is UnlockResult.WipedOut -> {
                                            statusMessage = "Слишком много неверных попыток. Данные удалены."
                                            failedAttemptsShown = 0
                                        }
                                        is UnlockResult.StorageError -> {
                                            // Пароль не виноват, счётчик попыток не тронут.
                                            statusMessage = "Не удалось открыть хранилище: ${result.reason}"
                                        }
                                        is UnlockResult.NoVaultYet -> { /* не должно происходить */ }
                                        is UnlockResult.VaultAlreadyExists -> { /* не должно происходить */ }
                                    }
                                } catch (e: Exception) {
                                    statusMessage = "Ошибка при разблокировке/создании: ${e.localizedMessage ?: e::class.simpleName}"
                                }
                                // password.toCharArray() уже скопирован и затёрт внутри repository —
                                // здесь дополнительно затираем локальную копию на всякий случай.
                                password.fill('0')
                            }
                        }
                    )

                    Screen.LIST -> {
                        val entriesFlow = remember { repository.observeEntries() }
                        val entries by entriesFlow
                            .collectAsStateWithLifecycle(initialValue = emptyList())

                        VaultListScreen(
                            entries = entries.map { VaultListItem(it.id, it.label, it.username) },
                            onEntryClick = { id ->
                                selectedEntryId = id
                                screen = Screen.ENTRY
                            },
                            onAddClick = { screen = Screen.GENERATOR },
                            onSettingsClick = { screen = Screen.SETTINGS },
                            snackbarHostState = null
                        )
                    }

                    Screen.ENTRY -> {
                        val entryId = selectedEntryId
                        val entry by produceState<VaultEntryRow?>(initialValue = null, entryId) {
                            value = entryId?.let { repository.getEntry(it) }
                        }
                        val row = entry
                        if (row != null) {
                            EntryScreen(
                                label = row.label,
                                username = row.username,
                                loadPassword = {
                                    try {
                                        repository.decryptField(row.id, FieldKind.PASSWORD)
                                    } catch (e: kotlinx.coroutines.CancellationException) {
                                        throw e
                                    } catch (e: Exception) {
                                        null // vault заблокирован или поле повреждено
                                    }
                                },
                                onCopyUsername = { ClipboardHelper.copySecret(this@MainActivity, "login", it) },
                                onCopyPassword = { ClipboardHelper.copySecret(this@MainActivity, "password", it) },
                                onDelete = {
                                    scope.launch {
                                        try {
                                            repository.deleteEntry(row.id)
                                            screen = Screen.LIST
                                        } catch (e: Exception) {
                                            statusMessage = "Не удалось удалить запись: ${e.localizedMessage ?: e::class.java.simpleName}"
                                        }
                                    }
                                },
                                onBack = { screen = Screen.LIST }
                            )
                        }
                    }

                    Screen.GENERATOR -> GeneratorScreen(
                        suggestedLabel = null,
                        onSave = { label, username, password ->
                            scope.launch {
                                try {
                                    repository.addEntry(label, username, password, domainHint = null)
                                    screen = Screen.LIST
                                } catch (e: Exception) {
                                    statusMessage = "Не удалось сохранить запись: ${e.localizedMessage ?: e::class.java.simpleName}"
                                }
                            }
                        },
                        onCancel = { screen = Screen.LIST }
                    )

                    Screen.SETTINGS -> SettingsScreen(
                        autolockMinutes = repository.getAutolockMinutes(),
                        onAutolockChange = { repository.setAutolockMinutes(it) },
                        onExportBackup = { exportLauncher.launch("skhoron-vault-backup.bin") },
                        onImportBackup = { importLauncher.launch(arrayOf("application/octet-stream")) },
                        onLockNow = {
                            repository.lock()
                            screen = Screen.UNLOCK
                        },
                        onPanicWipe = {
                            repository.panicWipe()
                            screen = Screen.UNLOCK
                        },
                        onBack = { screen = Screen.LIST }
                    )
                }
                SnackbarHost(snackbarHostState, Modifier.align(Alignment.BottomCenter))
                }
            }
        }
    }
}