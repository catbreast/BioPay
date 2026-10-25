/*
 * BioPay - biometric payment assistance for supported payment apps.
 * Copyright (C) 2026 kiriashi
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package io.github.kiriashi.biopay.settings

import android.content.Context
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.widget.Toast
import io.github.kiriashi.biopay.biometric.BioPayPrompt
import io.github.kiriashi.biopay.biometric.BiometricPromptPolicy
import io.github.kiriashi.biopay.biometric.BiometricType
import io.github.kiriashi.biopay.core.log.LogCapture
import io.github.kiriashi.biopay.core.log.ModuleLog
import io.github.kiriashi.biopay.core.util.isValidActivity
import io.github.kiriashi.biopay.runtime.AppRuntime
import io.github.kiriashi.biopay.settings.ui.M3Field
import io.github.kiriashi.biopay.storage.PasswordCipher
import io.github.kiriashi.biopay.storage.PasswordVersionPolicy

object SettingsActions {
    fun loadSavedPassword(pwdInput: M3Field, state: AppRuntime) {
        pwdInput.hint = when {
            state.prefs.needsPasswordReentry() -> "请重新录入该应用的支付密码"
            !state.prefs.getEncodedPassword().isNullOrEmpty() -> "密码已设置"
            else -> "未设置密码"
        }
    }

    fun handleSave(context: Context, host: DialogHost, input: M3Field, state: AppRuntime, type: Int, pinFallback: Boolean) {
        if (state.isClosed || !host.isOpen || host.isBusy) return
        if (type == BiometricType.DISABLED) {
            save(context, host, state, "生物支付已关闭") {
                state.prefs.setBiometricMode(type, pinFallback)
            }
            return
        }
        val password = input.text?.trim() ?: ""
        if (password.isEmpty()) {
            if (state.prefs.needsPasswordReentry() ||
                PasswordVersionPolicy.requiresReentry(state.prefs.getEncodedPassword(), state.prefs.getPasswordVersion())) {
                showToast(context, "请重新录入该应用的支付密码")
            } else if (!state.prefs.getEncodedPassword().isNullOrEmpty()) {
                authenticateWithBiometric(context, host, state, biometricType = type, pinFallback = pinFallback) {
                    state.prefs.setBiometricMode(type, pinFallback)
                }
            } else showToast(context, "请输入支付密码")
            return
        }
        if (password.length != PasswordCipher.PASSWORD_LENGTH || password.any { it !in '0'..'9' }) {
            showToast(context, "密码必须是6位数字")
            return
        }
        val chars = CharArray(password.length) { password[it] }
        authenticateWithBiometric(context, host, state, biometricType = type, pinFallback = pinFallback, cleanup = { chars.fill('\u0000') }) {
            val cipher = PasswordCipher.createEncryptionCipher(state.app, state.adapter.app.packageName)
            state.prefs.savePassword(chars, cipher, PasswordVersionPolicy.current, type, pinFallback).isSuccess
        }
    }

    fun handleClearPassword(state: AppRuntime): Boolean =
        !state.isClosed && state.prefs.clearPassword()

    fun dismissDialog(dialogHost: DialogHost) {
        dialogHost.dismiss()
    }

    private fun save(
        context: Context,
        host: DialogHost,
        state: AppRuntime,
        successMsg: String,
        cleanup: () -> Unit = {},
        expectedRevision: Long = state.prefs.revision(),
        work: () -> Boolean
    ) {
        if (state.isClosed || !context.isValidActivity() || !host.beginWork()) { cleanup(); return }
        state.prefs.update(
            work = { !state.isClosed && host.isOpen && state.prefs.revision() == expectedRevision && work() },
            cleanup = cleanup
        ) { saved ->
            if (!host.finishWork() || state.isClosed || !context.isValidActivity()) return@update
            showToast(context, if (saved) successMsg else "保存失败，请重试")
            if (saved) host.dismiss()
        }
    }

    fun authenticateWithBiometric(
        context: Context,
        dialogHost: DialogHost,
        state: AppRuntime,
        successMsg: String = "生物支付已启用",
        biometricType: Int = state.prefs.getBiometricType(),
        pinFallback: Boolean = state.prefs.getPinFallback(),
        cleanup: () -> Unit = {},
        onSuccess: () -> Boolean
    ) {
        if (state.isClosed || !context.isValidActivity() || !dialogHost.isOpen || dialogHost.isBusy) {
            cleanup()
            return
        }
        val expectedRevision = state.prefs.revision()
        val signal = CancellationSignal()
        val attemptId = dialogHost.beginAuthentication(signal, cleanup)
        try {
            val builder = BiometricPrompt.Builder(context)
                .setTitle(BioPayPrompt.TITLE)
            if (BiometricPromptPolicy.negativeButtonAllowed(pinFallback)) {
                builder.setNegativeButton("取消", context.mainExecutor) { _, _ ->
                    if (dialogHost.finishAuthentication(attemptId)) cleanup()
                }
            }
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                    if (!dialogHost.finishAuthentication(attemptId)) return
                    save(context, dialogHost, state, successMsg, cleanup, expectedRevision, onSuccess)
                }
                override fun onAuthenticationError(code: Int, message: CharSequence?) {
                    if (!dialogHost.finishAuthentication(attemptId)) return
                    ModuleLog.d { "settings authentication ended: code=$code" }
                    cleanup()
                    if (!state.isClosed && dialogHost.isOpen && context.isValidActivity() && message != null) {
                        showToast(context, message.toString())
                    }
                }
            }
            BiometricPromptPolicy.configure(builder, biometricType, pinFallback).build()
                .authenticate(signal, context.mainExecutor, callback)
        } catch (error: Exception) {
            ModuleLog.d(error) { "settings authentication startup failed" }
            if (dialogHost.finishAuthentication(attemptId)) {
                cleanup()
                showToast(context, "无法启动身份验证，请重试")
            }
        }
    }

    fun showToast(context: Context, msg: String) {
        if (msg.isNotEmpty()) Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
    }

    fun exportDiagnostics(
        context: Context, host: DialogHost, state: AppRuntime, onComplete: () -> Unit
    ) {
        if (state.isClosed || !host.isOpen || !host.beginWork()) { onComplete(); return }
        LogCapture.export(context) { paths ->
            val active = host.finishWork()
            onComplete()
            if (!active || state.isClosed || !context.isValidActivity()) return@export
            showToast(context, if (paths.isEmpty()) "日志导出失败，请重试"
                else "已导出 ${paths.size} 份日志至下载/BioPay")
        }
    }
}
