package dev.tqmane.rootmynothing

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

data class RuntimeArtifacts(
    val payload: File,
    val ksud: File,
    val helper: File,
)

object ArtifactStore {
    private data class Asset(
        val source: String,
        val destination: String,
        val size: Long,
        val sha256: String,
    )

    private val payload = Asset(
        source = "cve-2026-43499-standalone",
        destination = "cve-2026-43499-standalone",
        size = 96_464,
        sha256 = "958568eb13a5d21900f568fe1cb3e3e775b946362054a261313d9cc8b80bf72c",
    )
    private val ksud = Asset(
        source = "ksud-asteroids",
        destination = "ksud-asteroids",
        size = 4_767_584,
        sha256 = "c0e3be4a928668a5f58ea32564f2faf8b7d1dc5899fdafc51b3036bb877acc0f",
    )
    private const val HELPER_SIZE = 29_968L
    private const val HELPER_SHA256 =
        "180294a5fa34b84ae48a71a8e08f940d6b587d9c3d933601aae0c07f51f99531"

    fun prepare(context: Context, log: (String) -> Unit): RuntimeArtifacts {
        val directory = File(context.filesDir, "runtime").apply {
            require(mkdirs() || isDirectory) { "Unable to create runtime directory" }
        }
        val payloadFile = extract(context, payload, directory, log)
        val ksudFile = extract(context, ksud, directory, log)
        val helper = File(context.applicationInfo.nativeLibraryDir, "libcve43499root.so")
        verify(helper, HELPER_SIZE, HELPER_SHA256, "bootstrap helper")
        require(helper.canExecute()) { "Bootstrap helper is not executable" }
        log("[+] bootstrap helper verified")
        return RuntimeArtifacts(payloadFile, ksudFile, helper)
    }

    private fun extract(
        context: Context,
        asset: Asset,
        directory: File,
        log: (String) -> Unit,
    ): File {
        val destination = File(directory, asset.destination)
        if (runCatching {
                verify(destination, asset.size, asset.sha256, asset.source)
            }.isSuccess
        ) {
            log("[+] ${asset.source} verified (cached)")
            return destination
        }

        val temporary = File.createTempFile("${asset.destination}.", ".tmp", directory)
        try {
            context.assets.open(asset.source).use { input ->
                FileOutputStream(temporary).use { output -> input.copyTo(output) }
            }
            verify(temporary, asset.size, asset.sha256, asset.source)
            try {
                Files.move(
                    temporary.toPath(),
                    destination.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(
                    temporary.toPath(),
                    destination.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                )
            }
        } finally {
            temporary.delete()
        }
        destination.setReadable(true, true)
        log("[+] ${asset.source} extracted and verified")
        return destination
    }

    private fun verify(file: File, size: Long, expectedSha256: String, label: String) {
        require(file.isFile) { "$label is missing" }
        require(file.length() == size) {
            "$label size mismatch: ${file.length()} != $size"
        }
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count <= 0) break
                digest.update(buffer, 0, count)
            }
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }
        require(actual == expectedSha256) { "$label SHA-256 mismatch" }
    }
}
