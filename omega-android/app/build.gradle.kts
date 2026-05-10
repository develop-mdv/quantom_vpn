import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val localProperties = Properties().apply {
    val localFile = rootProject.file("local.properties")
    if (localFile.isFile) {
        localFile.inputStream().use(::load)
    }
}

val sdkDirPath = localProperties.getProperty("sdk.dir")
    ?: System.getenv("ANDROID_HOME")
    ?: System.getenv("ANDROID_SDK_ROOT")
    ?: error("Android SDK path is missing. Set sdk.dir in omega-android/local.properties or ANDROID_HOME.")

val androidNdkVersion = "27.1.12297006"
val workspaceRoot = rootProject.projectDir.parentFile
val isWindowsHost = System.getProperty("os.name").lowercase().contains("windows")
val hostTag = when {
    isWindowsHost -> "windows-x86_64"
    System.getProperty("os.name").lowercase().contains("mac") -> "darwin-x86_64"
    else -> "linux-x86_64"
}
val ndkToolchainBin = file("$sdkDirPath/ndk/$androidNdkVersion/toolchains/llvm/prebuilt/$hostTag/bin")
val androidAr = ndkToolchainBin.resolve("llvm-ar${if (isWindowsHost) ".exe" else ""}")

data class AndroidRustAbi(
    val taskSuffix: String,
    val rustTarget: String,
    val androidAbi: String,
    val clangPrefix: String,
)

val androidRustAbis = listOf(
    AndroidRustAbi("Arm64", "aarch64-linux-android", "arm64-v8a", "aarch64-linux-android"),
    AndroidRustAbi("X64", "x86_64-linux-android", "x86_64", "x86_64-linux-android"),
)
val androidRustFlags = "-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384"

android {
    namespace = "vpn.myboroda.omega"
    compileSdk = 35
    ndkVersion = androidNdkVersion

    defaultConfig {
        applicationId = "vpn.myboroda.omega"
        minSdk = 23
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += androidRustAbis.map { it.androidAbi }
        }
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs", "build/generated/omega/jniLibs")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        jvmToolchain(17)
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}

val copyOmegaBridgeTasks = androidRustAbis.map { abi ->
    val envTarget = abi.rustTarget.replace('-', '_')
    val cargoTargetEnv = abi.rustTarget.replace('-', '_').uppercase()
    val androidClang = ndkToolchainBin.resolve("${abi.clangPrefix}24-clang${if (isWindowsHost) ".cmd" else ""}")
    val omegaBridgeSo = file("$workspaceRoot/target/${abi.rustTarget}/release/libomega_android_bridge.so")

    val cargoBuild = tasks.register<Exec>("cargoBuildOmegaBridge${abi.taskSuffix}") {
        group = "build"
        description = "Builds the Omega Rust JNI bridge for Android ${abi.androidAbi}."
        workingDir = workspaceRoot

        environment("ANDROID_HOME", sdkDirPath)
        environment("ANDROID_NDK_HOME", file("$sdkDirPath/ndk/$androidNdkVersion").absolutePath)
        environment("CC_$envTarget", androidClang.absolutePath)
        environment("AR_$envTarget", androidAr.absolutePath)
        environment("CARGO_TARGET_${cargoTargetEnv}_LINKER", androidClang.absolutePath)
        environment("RUSTFLAGS", androidRustFlags)

        commandLine(
            "cargo",
            "build",
            "-p",
            "omega-android-bridge",
            "--target",
            abi.rustTarget,
            "--release",
        )

        inputs.file(file("$workspaceRoot/Cargo.toml"))
        inputs.file(file("$workspaceRoot/Cargo.lock"))
        inputs.file(file("$workspaceRoot/omega-android-bridge/Cargo.toml"))
        inputs.dir(file("$workspaceRoot/omega-android-bridge/src"))
        inputs.dir(file("$workspaceRoot/omega-core/src"))
        inputs.property("rustflags", androidRustFlags)
        outputs.file(omegaBridgeSo)
    }

    tasks.register<Copy>("copyOmegaBridge${abi.taskSuffix}") {
        dependsOn(cargoBuild)
        from(omegaBridgeSo)
        into(layout.buildDirectory.dir("generated/omega/jniLibs/${abi.androidAbi}"))
    }
}

tasks.named("preBuild") {
    dependsOn(copyOmegaBridgeTasks)
}
