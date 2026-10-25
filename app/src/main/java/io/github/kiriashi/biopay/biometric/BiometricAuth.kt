/*
 * BioPay - biometric payment assistance for supported payment apps.
 * Copyright (C) 2026 kiriashi
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package io.github.kiriashi.biopay.biometric

import android.app.Activity
import android.hardware.biometrics.BiometricPrompt
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import io.github.kiriashi.biopay.BuildConfig
import io.github.kiriashi.biopay.core.log.ModuleLog
import io.github.kiriashi.biopay.core.util.MainTasks
import io.github.kiriashi.biopay.core.util.findActivity
import io.github.kiriashi.biopay.payment.PasswordAutoInput
import io.github.kiriashi.biopay.runtime.AppRuntime
import io.github.kiriashi.biopay.storage.PasswordCipher
import io.github.kiriashi.biopay.storage.PaymentConfig
import java.lang.ref.WeakReference

object BiometricAuth {
    fun triggerBiometricAuth(
        keyboardView: ViewGroup,
        encodedPassword: String,
        state: AppRuntime,
        sessionId: Long
    ): Boolean {
        val config = state.session.currentConfig() ?: return false
        if (state.isClosed || !state.session.isCurrentSession(sessionId) ||
            config.encryptedPassword != encodedPassword || !state.prefs.isCurrent(config)) {
            ModuleLog.d { "biometric auth skipped: payment session expired or settings changed, app=${state.adapter.app}" }
            return false
        }
        // Plugin payment views can carry a different Activity from their host window.
        val activity = state.session.getHostActivity() ?: keyboardView.context.findActivity()
        if (activity == null || activity.isFinishing || activity.isDestroyed) {
            ModuleLog.w { "biometric auth skipped: keypad context has no live Activity, app=${state.adapter.app}, context=${keyboardView.context.javaClass.name}" }
            return false
        }
        if (PasswordAutoInput.isInProgress(sessionId)) return false
        val biometricType = config.biometricType
        if (biometricType !in BiometricType.BOTH..BiometricType.FACE) {
            ModuleLog.d { "biometric auth skipped: no biometric method enabled, app=${state.adapter.app}" }
            return false
        }
        val attempt = state.session.beginAuthentication() ?: return false
        try {
            state.session.suppressInputMethod()
            return state.paymentWorker.submit(
                work = {
                    if (!state.isClosed && state.session.isCurrentSession(sessionId) &&
                        state.session.isCurrentAuthentication(attempt.id)) {
                        measureCrypto("prepare") {
                            PasswordCipher.createDecryptOperation(encodedPassword, state.adapter.app.packageName)
                        }
                    } else null
                },
                discard = { it?.ciphertext?.fill(0) }
            ) { result ->
                val operation = result.getOrNull()
                val preparationFailure = currentFailure(state, config, sessionId, attempt.id, activity)
                    ?: when {
                        state.session.getCurrentKeyboardView() !== keyboardView -> "keyboard replaced"
                        !keyboardView.isAttachedToWindow -> "keyboard detached"
                        keyboardView.windowVisibility != View.VISIBLE || !keyboardView.isShown -> "keyboard hidden"
                        keyboardView.rootView.context.findActivity()?.let { it !== activity } == true -> "window owner changed"
                        else -> null
                    }
                if (preparationFailure != null) {
                    ModuleLog.d { "authentication preparation discarded: reason=$preparationFailure, app=${state.adapter.app}, session=$sessionId, attempt=${attempt.id}" }
                    operation?.ciphertext?.fill(0)
                    restoreKeyboard(state, sessionId, attempt.id)
                    return@submit
                }
                if (operation == null) {
                    result.exceptionOrNull()?.let { ModuleLog.w(it) { "password decryption preparation failed" } }
                    restoreKeyboard(state, sessionId, attempt.id)
                    return@submit
                }
                val callback = BiometricAuthCallback(
                    activity, keyboardView, operation, config, state, sessionId, attempt.id
                )
                if (!state.session.onAuthenticationEnded(attempt.id, callback::dispose)) {
                    callback.dispose()
                    restoreKeyboard(state, sessionId, attempt.id)
                    return@submit
                }
                try {
                    val executor = activity.mainExecutor
                    val builder = BiometricPrompt.Builder(activity)
                        .setTitle(BioPayPrompt.TITLE)
                    if (BiometricPromptPolicy.negativeButtonAllowed(config.pinFallback)) {
                        builder.setNegativeButton("取消", executor) { _, _ -> callback.cancel() }
                    }
                    BiometricPromptPolicy.configure(builder, biometricType, config.pinFallback).build()
                        .authenticate(attempt.signal, executor, callback)
                    if (state.session.isCurrentAuthentication(attempt.id)) {
                        // INVISIBLE preserves external payment keyboard attachment and the active prompt.
                        keyboardView.visibility = View.INVISIBLE
                        ModuleLog.d { "trigger: type=$biometricType, session=$sessionId, attempt=${attempt.id}" }
                    }
                } catch (error: Exception) {
                    callback.cancel()
                    ModuleLog.w(error) { "biometric auth failed" }
                }
            }.also { submitted ->
                if (!submitted) restoreKeyboard(state, sessionId, attempt.id)
            }
        } catch (e: Throwable) {
            restoreKeyboard(state, sessionId, attempt.id)
            ModuleLog.w(e) { "biometric auth failed" }
            return false
        }
    }

    private fun <T> measureCrypto(phase: String, work: () -> T): T {
        val start = if (BuildConfig.DEBUG) SystemClock.elapsedRealtime() else 0L
        return try { work() } finally {
            if (BuildConfig.DEBUG) ModuleLog.d { "payment crypto: phase=$phase, duration=${SystemClock.elapsedRealtime() - start}ms" }
        }
    }

    private fun currentFailure(
        state: AppRuntime, config: PaymentConfig, sessionId: Long, attemptId: Long,
        activity: Activity
    ): String? = when {
        state.isClosed -> "runtime closed"
        !state.session.isCurrentSession(sessionId) -> "payment session expired"
        !state.session.isCurrentAuthentication(attemptId) -> "authentication expired"
        state.session.currentConfig() != config || !state.prefs.isCurrent(config) -> "settings changed"
        state.session.getHostActivity() !== activity -> "payment host changed"
        activity.isFinishing || activity.isDestroyed -> "payment host closed"
        // Plugin hosts may expose a separate Application instance for the same package.
        activity.packageName != state.app.packageName -> "payment owner changed"
        else -> null
    }

    private fun restoreKeyboard(state: AppRuntime, sessionId: Long, attemptId: Long) {
        if (state.session.isCurrentSession(sessionId) && state.session.finishAuthentication(attemptId)) {
            state.session.restoreKeyboard(sessionId)
        }
    }

    private class BiometricAuthCallback(
        private val activity: Activity,
        keyboard: ViewGroup,
        operation: PasswordCipher.DecryptOperation,
        private val config: PaymentConfig,
        private val state: AppRuntime,
        private val sessionId: Long,
        private val attemptId: Long
    ) : BiometricPrompt.AuthenticationCallback() {
        private val window = WeakReference(keyboard.rootView as? ViewGroup)
        private val tasks = MainTasks()
        private val startedAt = SystemClock.uptimeMillis()
        private var operation: PasswordCipher.DecryptOperation? = operation
        private var password: CharArray? = null
        @Volatile private var ended = false
        private var authenticated = false
        private var decrypting = false
        private var deadline = 0L
        private var lastWaitReason: String? = null
        private val retry = Runnable { continueInput() }

        fun dispose() {
            ended = true
            tasks.close()
            tasks.onMain {
                operation?.ciphertext?.fill(0)
                operation = null
                password?.fill('\u0000')
                password = null
            }
        }

        fun cancel() {
            if (authenticated || ended) return
            stop("authentication cancelled")
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
            if (authenticated || ended) return
            stop("authentication error")
            ModuleLog.d { "onAuthError: code=$errorCode, attempt=$attemptId" }
        }

        override fun onAuthenticationFailed() {
            if (!ended && state.session.isCurrentSession(sessionId) && state.session.isCurrentAuthentication(attemptId)) {
                ModuleLog.d { "onAuthFailed: attempt=$attemptId" }
            }
        }

        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
            ModuleLog.d { "onAuthSucceeded received: attempt=$attemptId, elapsed=${SystemClock.uptimeMillis() - startedAt}ms" }
            if (authenticated || ended) return
            currentFailure(state, config, sessionId, attemptId, activity)?.let {
                stop(it)
                return
            }
            if (operation == null) {
                stop("decryption operation unavailable")
                return
            }
            authenticated = true
            state.session.holdInputMethodForInput()
            deadline = SystemClock.uptimeMillis() + INPUT_READY_TIMEOUT_MS
            continueInput()
        }

        private fun continueInput() {
            if (ended || decrypting) return
            try {
                currentFailure(state, config, sessionId, attemptId, activity)?.let {
                    stop(it)
                    return
                }
                val root = window.get() ?: run { stop("payment window released"); return }
                if (root.context.findActivity()?.let { it !== activity } == true) {
                    stop("payment window owner changed")
                    return
                }
                val keyboard = state.session.getCurrentKeyboardView()
                if (keyboard == null || !keyboard.isAttachedToWindow || !root.isAttachedToWindow) {
                    waitForInput("keyboard not attached")
                    return
                }
                // Authentication authorizes only the original payment window, even if its keypad is rebuilt.
                if (keyboard.rootView !== root) {
                    stop("payment window replaced")
                    return
                }
                keyboard.visibility = View.VISIBLE
                // Non-focusable keypad popups use the Activity window's focus.
                val hostWindow = activity.window?.decorView
                val hasFocus = root.hasWindowFocus() ||
                    (hostWindow?.isAttachedToWindow == true && hostWindow.hasWindowFocus())
                if (root.windowVisibility != View.VISIBLE || !hasFocus || !keyboard.isShown) {
                    waitForInput("payment window not ready")
                    return
                }
                when (val preparation = PasswordAutoInput.prepareInput(keyboard, state)) {
                    is PasswordAutoInput.Preparation.Waiting -> waitForInput(preparation.reason)
                    is PasswordAutoInput.Preparation.Rejected -> stop(preparation.reason)
                    is PasswordAutoInput.Preparation.Ready -> {
                        preparation.input.keyboardMode?.let(state.session::updateKeyboardMode)
                        if (password == null) decrypt() else enterPassword(keyboard, preparation.input)
                    }
                }
            } catch (error: Exception) {
                ModuleLog.w(error) { "post-authentication input preparation failed" }
                stop("input preparation failed")
            }
        }

        private fun waitForInput(reason: String) {
            val remaining = deadline - SystemClock.uptimeMillis()
            if (remaining <= 0L) {
                ModuleLog.w { "payment input readiness timed out: app=${state.adapter.app}, reason=$reason" }
                stop("input readiness timeout")
                return
            }
            if (reason != lastWaitReason) {
                lastWaitReason = reason
                ModuleLog.d { "payment input waiting: app=${state.adapter.app}, attempt=$attemptId, reason=$reason" }
            }
            tasks.post(retry, minOf(INPUT_READY_RETRY_MS, remaining))
        }

        private fun decrypt() {
            val pending = operation ?: run { stop("decryption operation unavailable"); return }
            operation = null
            decrypting = true
            val submitted = state.paymentWorker.submit(
                work = {
                    if (!ended && currentFailure(state, config, sessionId, attemptId, activity) == null) {
                        measureCrypto("decrypt") { PasswordCipher.decryptToCharArray(pending) }
                    } else null
                },
                cleanup = { pending.ciphertext.fill(0) },
                discard = { it?.fill('\u0000') }
            ) { result ->
                decrypting = false
                val decrypted = result.getOrNull()
                if (ended) {
                    decrypted?.fill('\u0000')
                    return@submit
                }
                if (decrypted == null) {
                    result.exceptionOrNull()?.let { ModuleLog.w(it) { "password decryption failed" } }
                    stop("password decryption unavailable")
                    return@submit
                }
                password = decrypted
                continueInput()
            }
            if (!submitted) stop("payment worker unavailable")
        }

        private fun enterPassword(keyboard: ViewGroup, input: PasswordAutoInput.PreparedInput) {
            val plaintext = password ?: return
            // Hand ownership to the input path before finishAuthentication invokes attempt cleanup.
            password = null
            try {
                if (!state.session.finishAuthentication(attemptId)) {
                    dispose()
                    return
                }
                ModuleLog.d { "payment input ready: app=${state.adapter.app}, attempt=$attemptId, elapsed=${SystemClock.uptimeMillis() - startedAt}ms" }
                if (!PasswordAutoInput.autoInputPassword(keyboard, plaintext, state, sessionId, config, input)) {
                    state.session.restoreKeyboard(sessionId)
                }
            } catch (error: Exception) {
                ModuleLog.w(error) { "post-authentication input failed" }
                state.session.restoreKeyboard(sessionId)
            } finally {
                plaintext.fill('\u0000')
            }
        }

        private fun stop(reason: String) {
            ModuleLog.d { "payment authentication ended: app=${state.adapter.app}, attempt=$attemptId, reason=$reason" }
            dispose()
            restoreKeyboard(state, sessionId, attemptId)
        }
    }

    private const val INPUT_READY_TIMEOUT_MS = 2_000L
    private const val INPUT_READY_RETRY_MS = 50L
}
