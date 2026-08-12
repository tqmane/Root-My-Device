package dev.tqmane.rootmyonepluspad3

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceProfileTest {
    private val exact = DeviceSnapshot(
        model = OnePlusPad3Target.MODEL,
        device = OnePlusPad3Target.DEVICE,
        product = OnePlusPad3Target.PRODUCT,
        display = OnePlusPad3Target.DISPLAY,
        fingerprint = OnePlusPad3Target.FINGERPRINT,
        kernelRelease = OnePlusPad3Target.KERNEL,
        sdk = OnePlusPad3Target.SDK,
        securityPatch = OnePlusPad3Target.SECURITY_PATCH,
        pageSize = OnePlusPad3Target.PAGE_SIZE,
        abi = "arm64-v8a",
    )

    @Test
    fun exactProfileIsAccepted() {
        val result = OnePlusPad3Target.validate(exact)

        assertTrue(result.mismatches.joinToString("\n"), result.compatible)
        assertTrue(result.mismatches.isEmpty())
    }

    @Test
    fun everyExactGuardDimensionIsEnforced() {
        val mismatches = listOf(
            exact.copy(model = "other") to "MODEL=",
            exact.copy(device = "other") to "DEVICE=",
            exact.copy(product = "other") to "PRODUCT=",
            exact.copy(display = "other") to "BUILD=",
            exact.copy(fingerprint = "other") to "FINGERPRINT mismatch",
            exact.copy(kernelRelease = "other") to "KERNEL=",
            exact.copy(sdk = OnePlusPad3Target.SDK - 1) to "SDK=",
            exact.copy(securityPatch = "2026-06-01") to "SECURITY_PATCH=",
            exact.copy(pageSize = 16_384) to "PAGE=",
            exact.copy(abi = "x86_64") to "ABI=",
        )

        mismatches.forEach { (snapshot, expectedMessage) ->
            val result = OnePlusPad3Target.validate(snapshot)
            assertFalse("Unexpected match for $expectedMessage", result.compatible)
            assertTrue(
                result.mismatches.joinToString("\n"),
                result.mismatches.any { it.startsWith(expectedMessage) },
            )
        }
    }
}
