package com.skhoron.vault.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val SkhoronBg = Color(0xFF0A0A0C)
val SkhoronSurface = Color(0xFF151518)
val SkhoronAccent = Color(0xFF5B8CFF)
val SkhoronText = Color(0xFFF2F2F4)
val SkhoronTextDim = Color(0xFF8A8A92)
val SkhoronDanger = Color(0xFFFF5B6E)

private val SkhoronDarkScheme = darkColorScheme(
    background = SkhoronBg,
    surface = SkhoronSurface,
    primary = SkhoronAccent,
    onBackground = SkhoronText,
    onSurface = SkhoronText,
    error = SkhoronDanger
)

@Composable
fun SkhoronVaultTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = SkhoronDarkScheme,
        content = content
    )
}