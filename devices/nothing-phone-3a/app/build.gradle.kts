import java.io.File
import java.security.MessageDigest

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.tqmane.rootmynothing"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.tqmane.rootmynothing"
        minSdk = 33
        targetSdk = 36
        versionCode = 3
        versionName = "1.2.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += "arm64-v8a"
        }

    }

    val releaseKeystore = providers.environmentVariable("RMN_KEYSTORE").orNull
    val releaseAlias = providers.environmentVariable("RMN_KEY_ALIAS").orNull
    val releaseStorePassword = providers.environmentVariable("RMN_STORE_PASSWORD").orNull
    val releaseKeyPassword = providers.environmentVariable("RMN_KEY_PASSWORD").orNull

    signingConfigs {
        if (
            releaseKeystore != null && releaseAlias != null &&
            releaseStorePassword != null && releaseKeyPassword != null
        ) {
            create("releaseFromEnvironment") {
                storeFile = file(releaseKeystore)
                storePassword = releaseStorePassword
                keyAlias = releaseAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("releaseFromEnvironment")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    androidResources {
        noCompress += listOf("so", "ksud")
    }

    packaging {
        jniLibs.useLegacyPackaging = true
        jniLibs.keepDebugSymbols += "**/libcve43499root.so"
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.05.01"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3:1.5.0-alpha24")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")

    debugImplementation("androidx.compose.ui:ui-tooling")
    androidTestImplementation("androidx.test:core-ktx:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    testImplementation("junit:junit:4.13.2")
}

val verifyNothingPhone3aReleaseSigning = tasks.register("verifyNothingPhone3aReleaseSigning") {
    doLast {
        val required = mapOf(
            "RMN_KEYSTORE" to providers.environmentVariable("RMN_KEYSTORE").orNull,
            "RMN_KEY_ALIAS" to providers.environmentVariable("RMN_KEY_ALIAS").orNull,
            "RMN_STORE_PASSWORD" to providers.environmentVariable("RMN_STORE_PASSWORD").orNull,
            "RMN_KEY_PASSWORD" to providers.environmentVariable("RMN_KEY_PASSWORD").orNull,
        )
        val missing = required.filterValues { it.isNullOrBlank() }.keys
        require(missing.isEmpty()) {
            "Release signing is not fully configured; missing ${missing.joinToString()}"
        }
        require(file(required.getValue("RMN_KEYSTORE")!!).isFile) {
            "RMN_KEYSTORE does not name a regular file"
        }
    }
}

tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    dependsOn(verifyNothingPhone3aReleaseSigning)
}

val nothingPhone3aKernelRelease =
    "6.1.157-android14-11-g82d681c9b06b-ab14634535"

val verifyAsteroidsArtifactsSynced = tasks.register("verifyAsteroidsArtifactsSynced") {
    val stamp = layout.projectDirectory.file("src/main/assets/.asteroids-artifacts-synced")
    val payload = layout.projectDirectory.file("src/main/assets/cve-2026-43499-standalone")
    val ksud = layout.projectDirectory.file("src/main/assets/ksud-asteroids")
    val helper = layout.projectDirectory.file("src/main/jniLibs/arm64-v8a/libcve43499root.so")
    val artifactStore = layout.projectDirectory.file(
        "src/main/java/dev/tqmane/rootmynothing/ArtifactStore.kt",
    )
    inputs.files(stamp, payload, ksud, helper, artifactStore)

    doLast {
        fun sha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count <= 0) break
                    digest.update(buffer, 0, count)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        fun actual(file: File, label: String): Pair<Long, String> {
            require(file.isFile) { "$label artifact is missing: $file" }
            return file.length() to sha256(file)
        }

        val stampFile = stamp.asFile
        val stampLines = if (stampFile.isFile) stampFile.readLines() else emptyList()
        fun stampValue(key: String): String =
            stampLines.singleOrNull { it.startsWith("$key=") }
                ?.substringAfter('=')
                ?: error("Artifact stamp is missing exactly one $key entry")

        require(
            stampValue("target") == "asteroids" &&
                stampValue("kernel_release") == nothingPhone3aKernelRelease &&
                stampValue("source_fix") == "1.2.0",
        ) {
            "Nothing Phone (3a) native artifacts are missing, stale, or built for another " +
                "kernel. Run tools/build-asteroids-fixed.sh so the exact payload/helper/ksud " +
                "artifacts and their hashes are synchronized before assembling the APK."
        }

        val identityPattern = Regex("""([0-9]+) ([0-9a-f]{64})""")
        fun stampIdentity(key: String): Pair<Long, String> {
            val match = identityPattern.matchEntire(stampValue(key))
                ?: error("Artifact stamp has malformed $key size/SHA-256")
            return match.groupValues[1].toLong() to match.groupValues[2]
        }

        val stampIdentities = mapOf(
            "payload" to stampIdentity("payload"),
            "ksud" to stampIdentity("ksud"),
            "helper" to stampIdentity("helper"),
        )
        val actualIdentities = mapOf(
            "payload" to actual(payload.asFile, "payload"),
            "ksud" to actual(ksud.asFile, "ksud"),
            "helper" to actual(helper.asFile, "helper"),
        )
        actualIdentities.forEach { (label, identity) ->
            require(stampIdentities.getValue(label) == identity) {
                "$label artifact does not match .asteroids-artifacts-synced"
            }
        }

        val storeFile = artifactStore.asFile
        require(storeFile.isFile) { "ArtifactStore.kt is missing" }
        val storeText = storeFile.readText()
        fun assetPin(source: String): Pair<Long, String> {
            val escaped = Regex.escape(source)
            val match = Regex(
                """source\s*=\s*\"$escaped\",[\s\S]*?size\s*=\s*([0-9_]+),""" +
                    """\s*sha256\s*=\s*\"([0-9a-f]{64})\"""",
            ).find(storeText) ?: error("ArtifactStore.kt has no complete pin for $source")
            return match.groupValues[1].replace("_", "").toLong() to match.groupValues[2]
        }

        val helperPinMatch = Regex(
            """HELPER_SIZE\s*=\s*([0-9_]+)L[\s\S]*?""" +
                """HELPER_SHA256\s*=\s*\"([0-9a-f]{64})\"""",
        ).find(storeText) ?: error("ArtifactStore.kt has no complete helper pin")
        val storeIdentities = mapOf(
            "payload" to assetPin("cve-2026-43499-standalone"),
            "ksud" to assetPin("ksud-asteroids"),
            "helper" to Pair(
                helperPinMatch.groupValues[1].replace("_", "").toLong(),
                helperPinMatch.groupValues[2],
            ),
        )
        actualIdentities.forEach { (label, identity) ->
            require(storeIdentities.getValue(label) == identity) {
                "$label artifact does not match its ArtifactStore.kt size/SHA-256 pin"
            }
        }
    }
}

tasks.named("preBuild").configure {
    dependsOn(verifyAsteroidsArtifactsSynced)
}
