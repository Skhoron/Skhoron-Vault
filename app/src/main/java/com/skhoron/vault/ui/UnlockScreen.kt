package com.skhoron.vault.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.skhoron.vault.R
import com.skhoron.vault.ui.theme.SkhoronAccent
import com.skhoron.vault.ui.theme.SkhoronTextDim

/**
 * Экран разблокировки. isFirstRun=true — создание нового vault'а (нужно
 * подтверждение пароля), false — обычная разблокировка существующего.
 *
 * failedAttempts прокидывается извне (из ViewModel) — при достижении порога
 * (например, 10 попыток) вызывающая сторона должна триггернуть panic wipe.
 */
@Composable
fun UnlockScreen(
    isFirstRun: Boolean,
    failedAttempts: Int,
    onUnlock: (password: String) -> Unit,
    modifier: Modifier = Modifier
) {
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }

    val passwordsMatch = !isFirstRun || (password.isNotEmpty() && password == confirmPassword)

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Filled.Lock,
            contentDescription = null,
            tint = SkhoronAccent,
            modifier = Modifier.size(56.dp)
        )
        Spacer(Modifier.height(24.dp))
        Text(
            text = stringResource(R.string.unlock_title),
            fontSize = 28.sp,
            fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.unlock_subtitle),
            fontSize = 14.sp,
            color = SkhoronTextDim
        )
        Spacer(Modifier.height(40.dp))

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text(stringResource(R.string.master_password_hint)) },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        if (isFirstRun) {
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = confirmPassword,
                onValueChange = { confirmPassword = it },
                label = { Text("Повторите мастер-пароль") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
        }

        if (!isFirstRun && failedAttempts > 0) {
            Spacer(Modifier.height(12.dp))
            Text(
                text = "Неверный пароль. Попыток: $failedAttempts",
                color = MaterialTheme.colorScheme.error,
                fontSize = 13.sp
            )
        }

        Spacer(Modifier.height(24.dp))
        Button(
            onClick = { onUnlock(password) },
            enabled = password.isNotEmpty() && passwordsMatch,
            modifier = Modifier.fillMaxWidth().height(52.dp)
        ) {
            Text(
                if (isFirstRun) stringResource(R.string.create_vault_button)
                else stringResource(R.string.unlock_button)
            )
        }
    }
}