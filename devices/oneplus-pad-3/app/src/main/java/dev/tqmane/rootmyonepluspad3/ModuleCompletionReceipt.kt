package dev.tqmane.rootmyonepluspad3

/**
 * Strict parser for the public, read-only mirror of KernelSU's root-private
 * late-load receipt.  The mirror is recovery evidence only: callers must also
 * verify that KernelSU is live and that [expectedRunId] came from the app's
 * private, current-boot request receipt.
 */
object ModuleCompletionReceipt {
    private const val PUBLIC_RECEIPT_PATH =
        "/data/local/tmp/.ksu-late-load-modules-ok"
    const val PROBE_ABSENT = "__RMOP_MODULE_RECEIPT_ABSENT__"
    const val PROBE_UNSAFE = "__RMOP_MODULE_RECEIPT_UNSAFE__"
    const val PROBE_REGULAR = "__RMOP_MODULE_RECEIPT_REGULAR__"

    private val lowerHex32 = Regex("[0-9a-f]{32}")
    private val lowerHex64 = Regex("[0-9a-f]{64}")
    private val lowerUuid = Regex(
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    )

    fun isRunId(value: String): Boolean = lowerHex32.matches(value)

    fun isSha256(value: String): Boolean = lowerHex64.matches(value)

    /**
     * Open the marker once, then validate and read that same pinned inode.
     *
     * `/proc/self` cannot be used here: `stat` is an external process, so its
     * `self` does not refer to the shell that owns descriptor 3.  `$$` is
     * expanded by that shell before `stat` starts and therefore identifies the
     * process whose descriptor remains pinned across both operations.
     */
    internal fun probeCommand(): String =
        "if [ -L '$PUBLIC_RECEIPT_PATH' ]; then " +
            "echo '$PROBE_UNSAFE'; " +
            "elif [ ! -e '$PUBLIC_RECEIPT_PATH' ]; then " +
            "echo '$PROBE_ABSENT'; " +
            "elif exec 3< '$PUBLIC_RECEIPT_PATH'; then " +
            "printf '$PROBE_REGULAR '; " +
            "/system/bin/stat -L -c 'uid=%u gid=%g mode=%a nlink=%h' " +
            "\"/proc/\$\$/fd/3\" || exit 1; " +
            "/system/bin/cat <&3; " +
            "else echo '$PROBE_UNSAFE'; fi"

    fun matches(
        probe: String,
        currentBootId: String,
        expectedRunId: String,
        expectedKsudSha256: String,
    ): Boolean {
        if (
            !lowerUuid.matches(currentBootId) || !isRunId(expectedRunId) ||
            !isSha256(expectedKsudSha256)
        ) return false
        val normalized = probe.replace("\r", "").trimEnd('\n')
        val expected = buildString {
            append(PROBE_REGULAR)
            append(" uid=0 gid=0 mode=644 nlink=1\n")
            append("version=1\n")
            append("boot_id=").append(currentBootId).append('\n')
            append("run_id=").append(expectedRunId).append('\n')
            append("ksud_sha256=").append(expectedKsudSha256)
        }
        return normalized == expected
    }
}
