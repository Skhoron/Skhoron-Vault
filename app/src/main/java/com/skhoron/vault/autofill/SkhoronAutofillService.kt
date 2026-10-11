package com.skhoron.vault.autofill

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.content.IntentSender
import android.os.Bundle
import android.os.CancellationSignal
import android.service.autofill.*
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.skhoron.vault.MainActivity
import com.skhoron.vault.R
import com.skhoron.vault.SkhoronVaultApp
import com.skhoron.vault.data.VaultEntryRow
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * SkhoronAutofillService — системный Android Autofill Framework.
 *
 * Anti-phishing invariant: датасет предлагается ТОЛЬКО при точном совпадении
 * webDomain с сохранённым domainHint (см. VaultRepository.findByExactDomain).
 * Никакого сопоставления по похожести названия/label — это единственное, что
 * реально защищает от автозаполнения на поддельном домене.
 */
class SkhoronAutofillService : AutofillService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val repository by lazy { (application as SkhoronVaultApp).repository }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }

        val fields = findRelevantFields(structure)
        if (fields.usernameId == null && fields.passwordId == null) {
            callback.onSuccess(null)
            return
        }

        if (!repository.isUnlocked) {
            // Vault заблокирован — предлагаем один "датасет-заглушку", который
            // при выборе открывает MainActivity для разблокировки. Сами
            // значения полей при этом не раскрываются до успешного unlock.
            callback.onSuccess(buildAuthRequiredResponse(fields))
            return
        }

        val domain = fields.webDomain
        if (domain == null) {
            // Нет надёжного домена (например, нативное приложение без webDomain) —
            // не предлагаем ничего, чтобы не гадать и не подставить не туда.
            callback.onSuccess(null)
            return
        }

        val job = scope.launch {
            try {
                val matches = repository.findByExactDomain(domain)
                val response = FillResponse.Builder()
                var datasets = 0
                matches.forEach { entry ->
                    // Запись без читаемого пароля не предлагаем: пустой датасет
                    // только сбивает с толку.
                    buildDataset(entry, fields)?.let {
                        response.addDataset(it)
                        datasets++
                    }
                }
                callback.onSuccess(if (datasets == 0) null else response.build())
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                // Без onFailure система ждёт ответа до таймаута.
                callback.onFailure("Skhoron Vault: не удалось подготовить автозаполнение")
            }
        }
        cancellationSignal.setOnCancelListener { job.cancel() }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        val fields = structure?.let { findRelevantFields(it) }

        if (fields == null || (fields.usernameValue == null && fields.passwordValue == null)) {
            callback.onSuccess()
            return
        }

        val label = fields.webDomain ?: "Без названия"
        val username = fields.usernameValue
        val password = fields.passwordValue

        if (password != null && repository.isUnlocked) {
            scope.launch {
                try {
                    val domain = fields.webDomain
                    // Тот же домен и логин уже сохранены — не плодим дубликаты.
                    val duplicate = domain != null &&
                        repository.findByExactDomain(domain).any { it.username == username }
                    if (!duplicate) {
                        repository.addEntry(label, username, password, domainHint = domain)
                    }
                    callback.onSuccess()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    callback.onFailure("Skhoron Vault: не удалось сохранить запись")
                }
            }
        } else {
            // Vault заблокирован в момент сохранения — теряем возможность
            // сохранить эту конкретную форму (осознанный компромисс: не храним
            // пароль во внешнем состоянии сервиса, только в памяти разблокированной сессии).
            callback.onSuccess()
        }
    }

    private fun buildAuthRequiredResponse(fields: RelevantFields): FillResponse {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, "Разблокировать Skhoron Vault")
        }
        val ids = listOfNotNull(fields.usernameId, fields.passwordId).toTypedArray()
        return FillResponse.Builder()
            .setAuthentication(ids, pendingIntent.intentSender, presentation)
            .build()
    }

    /** null — пароль не расшифровался (повреждённое поле), датасет не строим. */
    private suspend fun buildDataset(entry: VaultEntryRow, fields: RelevantFields): Dataset? {
        val password = try {
            repository.decryptPassword(entry)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            null
        } ?: return null

        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, entry.label)
        }

        val builder = Dataset.Builder(presentation)
        fields.usernameId?.let { id ->
            entry.username?.let { builder.setValue(id, AutofillValue.forText(it), presentation) }
        }
        fields.passwordId?.let { id ->
            builder.setValue(id, AutofillValue.forText(password), presentation)
        }
        return builder.build()
    }

    private data class RelevantFields(
        val usernameId: AutofillId?,
        val passwordId: AutofillId?,
        val usernameValue: String?,
        val passwordValue: String?,
        val webDomain: String?
    )

    private fun findRelevantFields(structure: AssistStructure): RelevantFields {
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        var usernameValue: String? = null
        var passwordValue: String? = null
        var webDomain: String? = null
        var domainConflict = false

        fun walk(node: AssistStructure.ViewNode) {
            node.webDomain?.let {
                // Два разных домена в одной структуре (например, iframe с чужого
                // сайта): не угадываем, какому из них принадлежит форма.
                val domain = it.trim().lowercase()
                if (webDomain != null && webDomain != domain) domainConflict = true
                webDomain = domain
            }
            val hints = node.autofillHints
            if (hints != null) {
                if (hints.contains(View.AUTOFILL_HINT_USERNAME) || hints.contains(View.AUTOFILL_HINT_EMAIL_ADDRESS)) {
                    usernameId = node.autofillId
                    usernameValue = node.autofillValue?.takeIf { it.isText }?.textValue?.toString()
                }
                if (hints.contains(View.AUTOFILL_HINT_PASSWORD)) {
                    passwordId = node.autofillId
                    passwordValue = node.autofillValue?.takeIf { it.isText }?.textValue?.toString()
                }
            }
            for (i in 0 until node.childCount) walk(node.getChildAt(i))
        }

        for (i in 0 until structure.windowNodeCount) {
            walk(structure.getWindowNodeAt(i).rootViewNode)
        }

        return RelevantFields(
            usernameId, passwordId, usernameValue, passwordValue,
            webDomain = if (domainConflict) null else webDomain
        )
    }
}