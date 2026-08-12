package dev.tqmane.rootmyonepluspad3

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
    val ksudSha256: String,
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
        size = 177_840,
        sha256 = "62f1573e8cdf150059c412769f67467e9ac55623220f3fa4007a7adb1943b855",
    )
    private val ksud = Asset(
        source = "ksud-oneplus-pad3",
        destination = "ksud-oneplus-pad3",
        size = 4_902_304,
        sha256 = "591a59b86c636e6063f8b3dc57574477caddcc47d1a1774ce828e8846698d9a9",
    )
    private const val HELPER_SIZE = 60_824L
    private const val HELPER_SHA256 =
        "5c208d302784e92611d0408e70409657566e2d739335688a3cff68c088957151"

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
        return RuntimeArtifacts(payloadFile, ksudFile, helper, ksud.sha256)
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
