# Omega Android Native Bridge

The Android app expects native libraries named `libomega_android_bridge.so` in:

```text
omega-android/app/src/main/jniLibs/arm64-v8a/
omega-android/app/src/main/jniLibs/armeabi-v7a/
omega-android/app/src/main/jniLibs/x86/
omega-android/app/src/main/jniLibs/x86_64/
```

Install Android Rust targets:

```powershell
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

Build examples:

```powershell
cargo build -p omega-android-bridge --target aarch64-linux-android --release
cargo build -p omega-android-bridge --target armv7-linux-androideabi --release
cargo build -p omega-android-bridge --target i686-linux-android --release
cargo build -p omega-android-bridge --target x86_64-linux-android --release
```

Copy each output to the matching Android ABI directory:

```text
target/aarch64-linux-android/release/libomega_android_bridge.so -> arm64-v8a/
target/armv7-linux-androideabi/release/libomega_android_bridge.so -> armeabi-v7a/
target/i686-linux-android/release/libomega_android_bridge.so -> x86/
target/x86_64-linux-android/release/libomega_android_bridge.so -> x86_64/
```

The bridge uses a two-phase Omega client flow:

1. native handshake returns assigned Android TUN parameters;
2. Kotlin creates the `VpnService.Builder` interface and app routing rules;
3. Kotlin passes the TUN fd to native code;
4. native code continues the encrypted Omega datapath with `AsyncDevice::from_fd`.

The Kotlin service creates a UDP socket, calls `VpnService.protect(socket)`, and
passes the detached fd to native code. This is required: if the native transport
socket is not protected, Android can route Omega's own control connection back
into the VPN after `establish()`.

If `cargo check --target aarch64-linux-android` fails with
`aarch64-linux-android-clang: program not found`, install Android NDK and set the
toolchain environment, for example:

```powershell
$env:ANDROID_NDK_HOME="C:\Users\dima_\AppData\Local\Android\Sdk\ndk\<version>"
$env:CC_aarch64_linux_android="$env:ANDROID_NDK_HOME\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android24-clang.cmd"
```
