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
package io.github.kiriashi.biopay.biometric

import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build

/** Keep settings verification and payment verification on the same authentication policy. */
internal object BiometricPromptPolicy {
    /**
     * Allowed authenticators for one prompt. BOTH accepts strong and weak biometrics so an
     * enrolled fingerprint and face can each satisfy the same prompt; the optional device
     * credential fallback adds the lockscreen PIN/pattern/password as a last resort.
     */
    fun authenticatorsFor(biometricType: Int, pinFallback: Boolean): Int {
        var authenticators = when (biometricType) {
            BiometricType.FINGERPRINT -> BiometricManager.Authenticators.BIOMETRIC_STRONG
            BiometricType.FACE -> BiometricManager.Authenticators.BIOMETRIC_WEAK
            else -> BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.BIOMETRIC_WEAK
        }
        if (pinFallback) {
            authenticators = authenticators or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        }
        return authenticators
    }

    /** A prompt that allows the device credential must not also set a negative button. */
    fun negativeButtonAllowed(pinFallback: Boolean): Boolean = !pinFallback

    fun configure(
        builder: BiometricPrompt.Builder,
        biometricType: Int,
        pinFallback: Boolean = false
    ): BiometricPrompt.Builder {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setAllowedAuthenticators(authenticatorsFor(biometricType, pinFallback))
        } else if (pinFallback) {
            @Suppress("DEPRECATION")
            builder.setDeviceCredentialAllowed(true)
        }
        if (biometricType == BiometricType.FACE || biometricType == BiometricType.BOTH) {
            builder.setConfirmationRequired(false)
        }
        return builder
    }
}
