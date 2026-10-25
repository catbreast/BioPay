/*
 * Copyright (C) 2026 kiriashi
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package io.github.kiriashi.biopay.storage

import io.github.kiriashi.biopay.apps.PaymentApp
import io.github.kiriashi.biopay.biometric.BiometricType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

class PaymentSettingsTest {
    private fun settings(app: PaymentApp = PaymentApp.QQ, revision: Long = 1L) = PaymentSettings(
        encryptedPassword = "bp-app-v1:encrypted",
        owner = app.packageName,
        enabled = true,
        passwordVersion = 3,
        biometricType = BiometricType.FACE,
        revision = revision
    )

    @Test
    fun paymentConfigRejectsEveryOtherApp() {
        for (owner in PaymentApp.entries) {
            for (target in PaymentApp.entries) {
                val config = settings(owner).activeFor(target)
                if (owner == target) assertEquals(owner, config?.app) else assertNull(config)
            }
        }
    }

    @Test
    fun unownedLegacyPasswordCanOnlyBelongToWechat() {
        val legacy = settings().copy(encryptedPassword = "legacy", owner = null)
        for (app in PaymentApp.entries) {
            if (app == PaymentApp.WECHAT) assertEquals("legacy", legacy.activeFor(app)?.encryptedPassword)
            else assertNull(legacy.activeFor(app))
        }
        assertNull(settings().copy(owner = null).activeFor(PaymentApp.QQ))
        assertNull(settings().copy(encryptedPassword = "legacy").activeFor(PaymentApp.QQ))
    }

    @Test
    fun pinFallbackDefaultsOffAndPropagatesToPaymentConfig() {
        val original = settings()
        assertEquals(false, original.pinFallback)
        assertEquals(false, original.activeFor(PaymentApp.QQ)?.pinFallback)
        assertEquals(true, original.copy(pinFallback = true).activeFor(PaymentApp.QQ)?.pinFallback)
    }

    @Test
    fun disabledOrInvalidSettingsCannotAuthorizePayment() {
        val original = settings()
        assertNull(original.copy(enabled = false).activeFor(PaymentApp.QQ))
        for (mode in listOf(-2, BiometricType.DISABLED, 99)) {
            assertNull(original.copy(biometricType = mode).activeFor(PaymentApp.QQ))
        }
        assertNull(original.copy(encryptedPassword = null).activeFor(PaymentApp.QQ))
        assertNull(original.copy(encryptedPassword = "").activeFor(PaymentApp.QQ))
    }

    @Test
    fun restoredRemoteSettingsNeverOverrideNewerLocalSettings() {
        val local = settings(revision = 5L)
        val remote = settings(revision = 8L).copy(biometricType = BiometricType.FINGERPRINT)
        assertSame(remote, remote.latest(local))
        assertSame(local, settings(revision = 4L).latest(local))
        assertSame(local, settings(revision = 5L).latest(local))
        assertEquals(BiometricType.FINGERPRINT, remote.latest(local).activeFor(PaymentApp.QQ)?.biometricType)
    }

    @Test
    fun changingAndRestoringSettingsStillInvalidatesPreviousAuthorization() {
        val original = settings()
        val authorized = original.activeFor(PaymentApp.QQ)
        val changed = original.copy(revision = 2L, biometricType = BiometricType.FINGERPRINT)
        assertNotEquals(authorized, changed.activeFor(PaymentApp.QQ))
        assertNotEquals(authorized, original.copy(revision = 3L).activeFor(PaymentApp.QQ))
        assertNotEquals(authorized, original.copy(passwordVersion = 4).activeFor(PaymentApp.QQ))
        assertNotEquals(authorized, original.copy(encryptedPassword = "bp-app-v1:new").activeFor(PaymentApp.QQ))
    }
}
