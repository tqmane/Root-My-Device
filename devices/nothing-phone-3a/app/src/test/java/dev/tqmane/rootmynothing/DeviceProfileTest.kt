package dev.tqmane.rootmynothing

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceProfileTest {
    private val exact = DeviceSnapshot(
        model = AsteroidsTarget.MODEL,
        device = AsteroidsTarget.DEVICE,
        display = AsteroidsTarget.DISPLAY,
        fingerprint = AsteroidsTarget.FINGERPRINT,
        kernelRelease = AsteroidsTarget.KERNEL,
        sdk = AsteroidsTarget.SDK,
        securityPatch = AsteroidsTarget.SECURITY_PATCH,
        pageSize = AsteroidsTarget.PAGE_SIZE,
        abi = "arm64-v8a",
    )

    @Test
    fun exactProfileIsAccepted() {
        val result = AsteroidsTarget.validate(exact)

        assertTrue(result.mismatches.joinToString("\n"), result.compatible)
        assertTrue(result.mismatches.isEmpty())
    }

    @Test
    fun everyExactGuardDimensionIsEnforced() {
        val mismatches = listOf(
            exact.copy(model = "other") to "MODEL=",
            exact.copy(device = "other") to "DEVICE=",
            exact.copy(display = "other") to "BUILD=",
            exact.copy(fingerprint = "other") to "FINGERPRINT mismatch",
            exact.copy(kernelRelease = "other") to "KERNEL=",
            exact.copy(sdk = AsteroidsTarget.SDK - 1) to "SDK=",
            exact.copy(securityPatch = "2026-05-01") to "SECURITY_PATCH=",
            exact.copy(pageSize = 16_384) to "PAGE=",
            exact.copy(abi = "x86_64") to "ABI=",
        )

        mismatches.forEach { (snapshot, expectedMessage) ->
            val result = AsteroidsTarget.validate(snapshot)
            assertFalse("Unexpected match for $expectedMessage", result.compatible)
            assertTrue(
                result.mismatches.joinToString("\n"),
                result.mismatches.any { it.startsWith(expectedMessage) },
            )
        }
    }

    @Test
    fun disabledChecksAcceptRegionalFingerprintVariant() {
        val regional = exact.copy(
            fingerprint = exact.fingerprint.replace("AsteroidsJPN", "AsteroidsEEA"),
        )

        val result = AsteroidsTarget.validate(regional, checksEnabled = false)

        assertTrue(result.compatible)
        assertTrue(result.mismatches.isEmpty())
    }

    @Test
    fun disabledChecksAreExplicitAndDoNotChangeDefault() {
        val regional = exact.copy(
            fingerprint = exact.fingerprint.replace("AsteroidsJPN", "AsteroidsEEA"),
        )

        assertFalse(AsteroidsTarget.validate(regional).compatible)
    }
}
