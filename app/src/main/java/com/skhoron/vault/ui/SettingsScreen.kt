package com.skhoron.vault.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.skhoron.vault.ui.theme.SkhoronDanger
import com.skhoron.vault.ui.theme.SkhoronTextDim

@Composable
fun SettingsScreen(
    autolockMinutes: Int,
    onAutolockChange: (Int) -> Unit,
    onExportBackup: () -> Unit,
    onImportBackup: () -> Unit,
    onLockNow: () -> Unit,
    onPanicWipe: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    var showWipeConfirm by remember {
        mutableStateOf(false)
    }

    var sliderValue by remember(autolockMinutes) {
        mutableStateOf(autolockMinutes.toFloat())
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = {
                    Text("Настройки")
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Filled.ArrowBack,
                            contentDescription = "Назад"
                        )
                    }
                }
            )
        }
    ) { paddingValues ->

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(24.dp)
        ) {
            Text(
                text = "Автоблокировка",
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "Vault заблокируется, если приложение было в фоне дольше этого времени.",
                fontSize = 13.sp,
                color = SkhoronTextDim
            )

            Spacer(modifier = Modifier.height(8.dp))

            Slider(
                value = sliderValue,
                onValueChange = {
                    sliderValue = it
                },
                onValueChangeFinished = {
                    onAutolockChange(sliderValue.toInt())
                },
                valueRange = 1f..30f,
                steps = 28
            )

            Text(
                text = "${sliderValue.toInt()} мин.",
                fontSize = 13.sp,
                color = SkhoronTextDim
            )

            Spacer(modifier = Modifier.height(32.dp))

            Divider()

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "Локальный бэкап",
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "Файл уже зашифрован тем же мастер-паролем. Никакого облака — ты сам выбираешь, куда сохранить.",
                fontSize = 13.sp,
                color = SkhoronTextDim
            )

            Spacer(modifier = Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth()
            ) {
                OutlinedButton(
                    onClick = onExportBackup,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Экспорт")
                }

                Spacer(modifier = Modifier.width(12.dp))

                OutlinedButton(
                    onClick = onImportBackup,
                    modifier = Modifier.weight(1f)
                ) {
                    Text("Импорт")
                }
            }

            Spacer(modifier = Modifier.height(32.dp))

            Divider()

            Spacer(modifier = Modifier.height(24.dp))

            Button(
                onClick = onLockNow,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Заблокировать сейчас")
            }

            Spacer(modifier = Modifier.height(32.dp))

            Text(
                text = "Опасная зона",
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = SkhoronDanger
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "Полностью и необратимо удаляет все записи и настройки с этого устройства.",
                fontSize = 13.sp,
                color = SkhoronTextDim
            )

            Spacer(modifier = Modifier.height(12.dp))

            OutlinedButton(
                onClick = {
                    showWipeConfirm = true
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = SkhoronDanger
                )
            ) {
                Text("Стереть всё (panic wipe)")
            }
        }
    }

    if (showWipeConfirm) {
        AlertDialog(
            onDismissRequest = {
                showWipeConfirm = false
            },
            title = {
                Text("Стереть всё?")
            },
            text = {
                Text(
                    "Это необратимо удалит все пароли и настройки с этого устройства. Отменить нельзя."
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showWipeConfirm = false
                        onPanicWipe()
                    }
                ) {
                    Text(
                        text = "Стереть",
                        color = SkhoronDanger
                    )
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showWipeConfirm = false
                    }
                ) {
                    Text("Отмена")
                }
            }
        )
    }
}