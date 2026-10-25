/*
 * BioPay - biometric payment assistance for supported payment apps.
 * Copyright (C) 2026 kiriashi
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package io.github.kiriashi.biopay.storage

import io.github.kiriashi.biopay.apps.PaymentApp
import io.github.kiriashi.biopay.biometric.BiometricType

/** The exact settings authorized by one authentication attempt. Contains no plaintext. */
internal data class PaymentConfig(
    val app: PaymentApp,
    val encryptedPassword: String,
    val passwordVersion: Int,
    val biometricType: Int,
    val revision: Long,
    val pinFallback: Boolean = false
)

internal data class PaymentSettings(
    val encryptedPassword: String?,
    val owner: String?,
    val enabled: Boolean,
    val passwordVersion: Int,
    val biometricType: Int,
    val revision: Long,
    val pinFallback: Boolean = false
) {
    fun latest(other: PaymentSettings): PaymentSettings =
        if (revision > other.revision) this else other

    fun encodedPasswordFor(app: PaymentApp): String? {
        val encoded = encryptedPassword.takeUnless { it.isNullOrEmpty() } ?: return null
        val bound = PasswordCipher.isAppBoundCiphertext(encoded)
        return when {
            owner == app.packageName && bound -> encoded
            owner == null && app == PaymentApp.WECHAT && !bound -> encoded
            else -> null
        }
    }

    fun activeFor(app: PaymentApp): PaymentConfig? {
        if (!enabled || biometricType !in BiometricType.BOTH..BiometricType.FACE) return null
        val password = encodedPasswordFor(app) ?: return null
        return PaymentConfig(app, password, passwordVersion, biometricType, revision, pinFallback)
    }
}
