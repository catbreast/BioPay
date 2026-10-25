/*
 * BioPay - biometric payment assistance for supported payment apps.
 *
 * Copyright (C) 2026 kiriashi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package io.github.kiriashi.biopay.storage

import io.github.kiriashi.biopay.core.log.ModuleLog
import io.github.kiriashi.biopay.biometric.BiometricType
import io.github.kiriashi.biopay.apps.PaymentApp
import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle

class ConfigStore(
    context: Context,
    private val pref: SharedPreferences,
    private val app: PaymentApp
) {

    private val queueLock = Any()
    private val writeLock = Any()
    @Volatile private var closed = false
    @Volatile private var snapshot = readPreferences()
    private data class ActiveSnapshot(val settings: PaymentSettings, val config: PaymentConfig?)
    @Volatile private var active: ActiveSnapshot? = null
    private val executor = context.mainExecutor
    private val worker = lazy {
        java.util.concurrent.Executors.newSingleThreadExecutor { task ->
            Thread(task, "BioPaySettings")
        }
    }
    private val sync = ConfigSync(context, app, ::localSettings, ::background)

    fun close() {
        synchronized(queueLock) {
            closed = true
            if (worker.isInitialized()) worker.value.shutdown()
        }
        synchronized(writeLock) { sync.close() }
    }

    fun refresh() { if (!closed) sync.refresh() }

    private fun background(task: () -> Unit, cleanup: () -> Unit) = submit(
        fallback = Unit, failure = "settings synchronization failed", cleanup = cleanup, work = task
    )

    /** Serialized storage work; completion is delivered only to the live generation. */
    internal fun update(
        work: () -> Boolean,
        cleanup: () -> Unit = {},
        onComplete: (Boolean) -> Unit = {}
    ) = submit(false, "settings update failed", cleanup, work, onComplete)

    private fun <T> submit(
        fallback: T,
        failure: String,
        cleanup: () -> Unit,
        work: () -> T,
        onComplete: ((T) -> Unit)? = null
    ) = synchronized(queueLock) {
        if (closed) { cleanup(); return@synchronized }
        try {
            worker.value.execute {
                val result = try {
                    if (closed) fallback else work()
                } catch (error: Exception) {
                    ModuleLog.w(error) { failure }
                    fallback
                } finally { cleanup() }
                if (onComplete != null && !closed) executor.execute { if (!closed) onComplete(result) }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) { cleanup() }
        Unit
    }

    internal fun saveState(): Bundle? = sync.saveState()

    internal fun restoreState(saved: Bundle?) = sync.restoreState(saved)

    private fun localSettings(): PaymentSettings = snapshot

    private fun readPreferences(): PaymentSettings {
        // Read one coherent preference snapshot instead of locking each field separately.
        val values = pref.all
        return PaymentSettings(
            values[PrefKeys.prefKeyPwd] as? String,
            values[KEY_PASSWORD_OWNER] as? String,
            values[PrefKeys.prefKeyOn] as? Boolean ?: false,
            values[KEY_PASSWORD_VERSION] as? Int ?: 0,
            values[KEY_BIOMETRIC_TYPE] as? Int ?: BiometricType.DISABLED,
            values[KEY_SETTINGS_REVISION] as? Long ?: 0L,
            values[KEY_PIN_FALLBACK] as? Boolean ?: false
        )
    }

    private fun settings(): PaymentSettings = sync.current()

    private fun writeSettings(change: SharedPreferences.Editor.() -> Unit): Boolean {
        val updated = synchronized(writeLock) {
            if (closed) return false
            val base = settings()
            val editor = pref.edit()
                .putString(PrefKeys.prefKeyPwd, base.encryptedPassword)
                .putString(KEY_PASSWORD_OWNER, base.owner)
                .putBoolean(PrefKeys.prefKeyOn, base.enabled)
                .putInt(KEY_PASSWORD_VERSION, base.passwordVersion)
                .putInt(KEY_BIOMETRIC_TYPE, base.biometricType)
                .putBoolean(KEY_PIN_FALLBACK, base.pinFallback)
            change(editor)
            editor.putLong(KEY_SETTINGS_REVISION, base.revision + 1L)
            if (!editor.commit()) return false
            readPreferences().also { snapshot = it }
        }
        if (!closed) sync.afterWrite(updated)
        return true
    }

    fun isBioPayEnabled(): Boolean = activeConfig() != null

    internal fun activeConfig(): PaymentConfig? {
        if (closed) return null
        val current = settings()
        val cached = active
        if (cached?.settings === current) return cached.config
        val config = current.activeFor(app)?.takeUnless {
            PasswordVersionPolicy.requiresReentry(it.encryptedPassword, it.passwordVersion)
        }
        active = ActiveSnapshot(current, config)
        return config
    }

    internal fun revision(): Long = settings().revision

    internal fun isCurrent(config: PaymentConfig): Boolean = activeConfig() == config

    /** Returns a password only when it belongs to this app and payment is enabled. */
    fun activePassword(): String? = activeConfig()?.encryptedPassword

    fun getEncodedPassword(): String? = encodedPassword(settings())

    private fun encodedPassword(current: PaymentSettings): String? = current.encodedPasswordFor(app)

    fun needsPasswordReentry(): Boolean = settings().let {
        !it.encryptedPassword.isNullOrEmpty() && (encodedPassword(it) == null ||
            PasswordVersionPolicy.requiresReentry(it.encryptedPassword, it.passwordVersion))
    }

    internal fun savePassword(password: CharArray, cipher: javax.crypto.Cipher, passwordVersion: Int, biometricType: Int = getBiometricType(), pinFallback: Boolean = getPinFallback()): Result<Unit> {
        return try {
            val encrypted = PasswordCipher.encrypt(password, cipher)
            if (!writeSettings {
                putString(PrefKeys.prefKeyPwd, encrypted)
                putBoolean(PrefKeys.prefKeyOn, true)
                putInt(KEY_PASSWORD_VERSION, passwordVersion)
                putInt(KEY_BIOMETRIC_TYPE, biometricType)
                putBoolean(KEY_PIN_FALLBACK, pinFallback)
                putString(KEY_PASSWORD_OWNER, app.packageName)
            }) error("payment settings could not be saved")
            Result.success(Unit)
        } catch (e: Exception) {
            ModuleLog.e(e) { "savePassword failed" }
            Result.failure(e)
        }
    }

    internal fun clearPassword(): Boolean {
        return writeSettings {
            putBoolean(PrefKeys.prefKeyOn, false)
            putString(PrefKeys.prefKeyPwd, "")
            putInt(KEY_PASSWORD_VERSION, 0)
            putInt(KEY_BIOMETRIC_TYPE, BiometricType.DISABLED)
            putBoolean(KEY_PIN_FALLBACK, false)
            remove(KEY_PASSWORD_OWNER)
        }
    }

    internal fun setBiometricMode(type: Int, pinFallback: Boolean = getPinFallback()): Boolean {
        require(type in BiometricType.DISABLED..BiometricType.FACE)
        return writeSettings {
            putBoolean(PrefKeys.prefKeyOn, type != BiometricType.DISABLED)
            putInt(KEY_BIOMETRIC_TYPE, type)
            putBoolean(KEY_PIN_FALLBACK, pinFallback)
        }
    }

    fun getPinFallback(): Boolean = settings().pinFallback

    fun getBiometricType(): Int = settings().let {
        if (encodedPassword(it) == null) BiometricType.DISABLED else it.biometricType
    }

    fun getPasswordVersion(): Int = settings().let {
        if (encodedPassword(it) == null) 0 else it.passwordVersion
    }
}
