/*
 * BioPay - biometric payment assistance for supported payment apps.
 * Copyright (C) 2026 kiriashi
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package io.github.kiriashi.biopay.biometric

import android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
import android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_WEAK
import android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BiometricPromptPolicyTest {
    @Test
    fun fingerprintOnlyRequiresStrongBiometrics() {
        assertEquals(
            BIOMETRIC_STRONG,
            BiometricPromptPolicy.authenticatorsFor(BiometricType.FINGERPRINT, pinFallback = false)
        )
    }

    @Test
    fun faceOnlyAcceptsWeakBiometrics() {
        assertEquals(
            BIOMETRIC_WEAK,
            BiometricPromptPolicy.authenticatorsFor(BiometricType.FACE, pinFallback = false)
        )
    }

    @Test
    fun bothAcceptsStrongAndWeakBiometrics() {
        val authenticators = BiometricPromptPolicy.authenticatorsFor(BiometricType.BOTH, pinFallback = false)
        assertEquals(BIOMETRIC_STRONG or BIOMETRIC_WEAK, authenticators)
        assertEquals(BIOMETRIC_STRONG, authenticators and BIOMETRIC_STRONG)
    }

    @Test
    fun pinFallbackAddsDeviceCredentialWithoutDroppingBiometrics() {
        for (type in listOf(BiometricType.BOTH, BiometricType.FINGERPRINT, BiometricType.FACE)) {
            val authenticators = BiometricPromptPolicy.authenticatorsFor(type, pinFallback = true)
            assertEquals(DEVICE_CREDENTIAL, authenticators and DEVICE_CREDENTIAL)
            assertEquals(
                BiometricPromptPolicy.authenticatorsFor(type, pinFallback = false),
                authenticators and DEVICE_CREDENTIAL.inv()
            )
        }
    }

    @Test
    fun negativeButtonIsOnlyAllowedWithoutPinFallback() {
        assertTrue(BiometricPromptPolicy.negativeButtonAllowed(pinFallback = false))
        assertFalse(BiometricPromptPolicy.negativeButtonAllowed(pinFallback = true))
    }
}
