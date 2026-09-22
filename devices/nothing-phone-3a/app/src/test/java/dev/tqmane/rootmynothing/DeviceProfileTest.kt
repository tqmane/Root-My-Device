package dev.tqmane.rootmynothing

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceProfileTest {
    private fun snapshotFor(build: AsteroidsTarget.SupportedBuild) = DeviceSnapshot(
        model = AsteroidsTarget.MODEL,
        device = AsteroidsTarget.DEVICE,
        display = build.display,
        fingerprint = build.fingerprint,
        kernelRelease = AsteroidsTarget.KERNEL,
        sdk = build.sdk,
        securityPatch = build.securityPatch,
        pageSize = AsteroidsTarget.PAGE_SIZE,
        abi = "arm64-v8a",
    )

    private val exact = snapshotFor(AsteroidsTarget.SUPPORTED_BUILDS.first())

    @Test
    fun everySupportedBuildIsAccepted() {
        AsteroidsTarget.SUPPORTED_BUILDS.forEach { build ->
            val result = AsteroidsTarget.validate(snapshotFor(build))

            assertTrue(result.mismatches.joinToString("\n"), result.compatible)
            assertTrue(result.mismatches.isEmpty())
        }
    }

    @Test
    fun everyExactGuardDimensionIsEnforced() {
        val mismatches = listOf(
            exact.copy(model = "other") to "MODEL=",
            exact.copy(device = "other") to "DEVICE=",
            exact.copy(display = "other") to "BUILD=",
            exact.copy(fingerprint = "other") to "FINGERPRINT mismatch",
            exact.copy(kernelRelease = "other") to "KERNEL=",
            exact.copy(sdk = 35) to "SDK=",
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
    fun mixedBuildIdentityIsRejected() {
        val first = AsteroidsTarget.SUPPORTED_BUILDS[0]
        val second = AsteroidsTarget.SUPPORTED_BUILDS[1]
        // Display/fingerprint/patch from different builds must not combine.
        val mixed = snapshotFor(first).copy(
            display = second.display,
            fingerprint = second.fingerprint,
        )
        val result = AsteroidsTarget.validate(mixed)

        assertFalse(result.compatible)
        assertTrue(
            result.mismatches.joinToString("\n"),
            result.mismatches.any { it.startsWith("BUILD/FINGERPRINT/") },
        )
    }
}
