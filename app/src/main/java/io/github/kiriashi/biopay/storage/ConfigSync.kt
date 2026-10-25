/*
 * BioPay - biometric payment assistance for supported payment apps.
 * Copyright (C) 2026 kiriashi
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package io.github.kiriashi.biopay.storage

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import io.github.kiriashi.biopay.apps.PaymentApp
import io.github.kiriashi.biopay.biometric.BiometricType
import io.github.kiriashi.biopay.core.log.ModuleLog
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

internal const val KEY_PASSWORD_VERSION = "password_version"
internal const val KEY_BIOMETRIC_TYPE = "bt"
internal const val KEY_PIN_FALLBACK = "pin_fb"
internal const val KEY_PASSWORD_OWNER = "password_owner_package"
internal const val KEY_SETTINGS_REVISION = "payment_settings_revision"
private const val ACTION_SETTINGS_CHANGED = "io.github.kiriashi.biopay.PAYMENT_SETTINGS_CHANGED"
private const val ACTION_SETTINGS_REQUEST = "io.github.kiriashi.biopay.PAYMENT_SETTINGS_REQUEST"
private const val EXTRA_SIGNATURE = "io.github.kiriashi.biopay.SETTINGS_SIGNATURE"
private const val EXTRA_REQUEST = "io.github.kiriashi.biopay.SETTINGS_REQUEST"

/** Signed snapshots repair QQ's process-local preference caches, including missed updates. */
internal class ConfigSync(
    private val context: Context,
    private val app: PaymentApp,
    private val local: () -> PaymentSettings,
    private val dispatch: (() -> Unit, () -> Unit) -> Unit
) {
    private val lock = Any()
    @Volatile private var remote: PaymentSettings? = null
    @Volatile private var closed = false
    private val primary = Application.getProcessName() == app.packageName
    private var lastRequest = -500L
    private val receiverRegistered = AtomicBoolean(false)
    private val receiver: BroadcastReceiver? = if (app == PaymentApp.QQ) {
        object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (closed) return
                // Copy and validate the small payload before leaving the receiver callback.
                runCatching {
                    when (intent.action) {
                        ACTION_SETTINGS_CHANGED -> {
                            val incoming = intent.extras?.readSettings() ?: return
                            if (incoming.encryptedPassword?.length?.let { it > 4096 } == true || incoming.revision < 0) return
                            if (incoming.owner != null && incoming.owner != app.packageName) return
                            if (incoming.revision <= current().revision) return
                            val signature = intent.getStringExtra(EXTRA_SIGNATURE)
                            val pending = goAsync()
                            enqueue(cleanup = pending::finish) {
                                if (!closed && SettingsBroadcastAuth.verifies(context, incoming, signature)) accept(incoming)
                            }
                        }
                        ACTION_SETTINGS_REQUEST -> {
                            if (!primary) return
                            val request = intent.getStringExtra(EXTRA_REQUEST) ?: return
                            if (request.length != 36) return
                            val signature = intent.getStringExtra(EXTRA_SIGNATURE)
                            val pending = goAsync()
                            enqueue(cleanup = pending::finish) {
                                if (!closed && SettingsBroadcastAuth.verifiesRequest(context, app.packageName, request, signature)) {
                                    publish(current())
                                }
                            }
                        }
                    }
                }.onFailure { ModuleLog.w(it) { "QQ settings message rejected" } }
            }
        }.also { registered ->
            val filter = IntentFilter(ACTION_SETTINGS_CHANGED).apply { addAction(ACTION_SETTINGS_REQUEST) }
            if (Build.VERSION.SDK_INT >= 33) {
                context.registerReceiver(registered, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                context.registerReceiver(registered, filter)
            }
            receiverRegistered.set(true)
        }
    } else null

    init {
        if (app == PaymentApp.QQ) {
            if (primary) enqueue { if (!closed) publish(current()) }
            else refresh()
        }
    }

    fun current(): PaymentSettings = local().let { remote?.latest(it) ?: it }

    fun saveState(): Bundle? = if (app == PaymentApp.QQ) current().toBundle() else null

    fun restoreState(saved: Bundle?) {
        if (app != PaymentApp.QQ || saved == null || closed) return
        val incoming = saved.readSettings()
        if (incoming.owner != null && incoming.owner != app.packageName) return
        accept(incoming)
    }

    fun afterWrite(updated: PaymentSettings) {
        if (app != PaymentApp.QQ || closed) return
        accept(updated)
        runCatching { publish(current()) }.onFailure {
            // Persistence succeeded; a later snapshot request can repair missed delivery.
            ModuleLog.w(it) { "QQ settings snapshot could not be published" }
        }
    }

    private fun enqueue(cleanup: () -> Unit = {}, work: () -> Unit) = dispatch(work, cleanup)

    private fun accept(incoming: PaymentSettings) = synchronized(lock) {
        if (!closed && incoming.revision > current().revision) remote = incoming
    }

    fun refresh() {
        if (app != PaymentApp.QQ || primary || closed) return
        synchronized(this) {
            val now = SystemClock.elapsedRealtime()
            if (now - lastRequest < 500) return
            lastRequest = now
        }
        enqueue {
            if (!closed) {
                val request = UUID.randomUUID().toString()
                val signature = SettingsBroadcastAuth.signRequest(context, app.packageName, request)
                send(Intent(ACTION_SETTINGS_REQUEST).apply {
                    putExtra(EXTRA_REQUEST, request)
                    putExtra(EXTRA_SIGNATURE, signature)
                })
            }
        }
    }

    private fun publish(settings: PaymentSettings) {
        val signature = SettingsBroadcastAuth.sign(context, settings)
        send(Intent(ACTION_SETTINGS_CHANGED).apply {
            putExtras(settings.toBundle())
            putExtra(EXTRA_SIGNATURE, signature)
        })
    }

    private fun send(intent: Intent) {
        if (closed) return
        runCatching { context.sendBroadcast(intent.setPackage(app.packageName)) }
            .onFailure { ModuleLog.w(it) { "QQ settings message could not be sent" } }
    }

    fun close() {
        closed = true
        val registered = receiver ?: return
        if (!receiverRegistered.compareAndSet(true, false)) return
        try {
            context.unregisterReceiver(registered)
        } catch (error: IllegalArgumentException) {
            ModuleLog.d(error) { "QQ settings receiver was already unregistered" }
        }
    }
}

private fun PaymentSettings.toBundle(): Bundle = Bundle().apply {
    putString(PrefKeys.prefKeyPwd, encryptedPassword)
    putString(KEY_PASSWORD_OWNER, owner)
    putBoolean(PrefKeys.prefKeyOn, enabled)
    putInt(KEY_PASSWORD_VERSION, passwordVersion)
    putInt(KEY_BIOMETRIC_TYPE, biometricType)
    putLong(KEY_SETTINGS_REVISION, revision)
    putBoolean(KEY_PIN_FALLBACK, pinFallback)
}

private fun Bundle.readSettings(): PaymentSettings = PaymentSettings(
    getString(PrefKeys.prefKeyPwd),
    getString(KEY_PASSWORD_OWNER),
    getBoolean(PrefKeys.prefKeyOn, false),
    getInt(KEY_PASSWORD_VERSION, 0),
    getInt(KEY_BIOMETRIC_TYPE, BiometricType.DISABLED),
    getLong(KEY_SETTINGS_REVISION, 0L),
    getBoolean(KEY_PIN_FALLBACK, false)
)
