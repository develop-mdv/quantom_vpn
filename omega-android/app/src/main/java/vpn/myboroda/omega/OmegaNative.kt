package vpn.myboroda.omega

import android.os.ParcelFileDescriptor
import org.json.JSONObject

data class NativeResult(
    val ok: Boolean,
    val message: String,
) {
    companion object {
        fun fromJson(json: String): NativeResult {
            return runCatching {
                val root = JSONObject(json)
                NativeResult(root.optBoolean("ok", false), root.optString("message", ""))
            }.getOrElse {
                NativeResult(false, "Native response was invalid: ${it.message}")
            }
        }
    }
}

data class NativeHandshakeResult(
    val ok: Boolean,
    val config: NativeHandshakeConfig?,
    val message: String,
)

object OmegaNative {
    private val loaded: Boolean = runCatching {
        System.loadLibrary("omega_android_bridge")
        true
    }.getOrDefault(false)

    private external fun nativeBridgeVersion(): Int
    private external fun nativeStartHandshake(
        server: String,
        deviceId: String,
        deviceToken: String,
        deviceName: String,
        transport: String,
        protectedUdpFd: Int,
    ): String
    private external fun nativeStartRealityHandshake(
        server: String,
        deviceId: String,
        deviceToken: String,
        deviceName: String,
        realitySni: String,
        realityServerPubkey: String,
        realityShortId: String,
        realityFingerprint: String,
        protectedTcpFd: Int,
    ): String
    private external fun nativeContinueWithTunFd(handle: Long, tunFd: Int): String
    private external fun nativeStop(handle: Long): String

    fun bridgeStatus(): String {
        if (!loaded) return "Native library is not packaged."
        return runCatching { "Native bridge v${nativeBridgeVersion()}" }
            .getOrElse { "Native bridge entrypoint is unavailable: ${it.message}" }
    }

    fun validateProfile(profile: OmegaProfile): NativeResult {
        val error = profile.validationError()
        if (error != null) return NativeResult(false, error)
        return NativeResult(true, bridgeStatus())
    }

    fun startHandshake(profile: OmegaProfile, protectedUdpFd: Int): NativeHandshakeResult {
        val validation = validateProfile(profile)
        if (!validation.ok) {
            closeDetachedFd(protectedUdpFd)
            return NativeHandshakeResult(false, null, validation.message)
        }
        if (!loaded) {
            closeDetachedFd(protectedUdpFd)
            return NativeHandshakeResult(
                false,
                null,
                "Native Omega runtime is not packaged yet. Build libomega_android_bridge.so and place it in jniLibs.",
            )
        }
        return NativeHandshakeConfig.fromJson(
            nativeStartHandshake(
                profile.server,
                profile.deviceId,
                profile.deviceToken,
                profile.deviceName,
                profile.transport,
                protectedUdpFd,
            )
        )
    }

    /// Drive the REALITY handshake natively. `protectedTcpFd` must be a TCP
    /// socket file descriptor that has already been (a) connected to
    /// `profile.realityServer` and (b) added to the VPN bypass via
    /// `VpnService.protect(socket)` — otherwise the handshake will loop back
    /// through the VPN itself.
    fun startRealityHandshake(profile: OmegaProfile, protectedTcpFd: Int): NativeHandshakeResult {
        val validation = validateProfile(profile)
        if (!validation.ok) {
            closeDetachedFd(protectedTcpFd)
            return NativeHandshakeResult(false, null, validation.message)
        }
        if (!loaded) {
            closeDetachedFd(protectedTcpFd)
            return NativeHandshakeResult(
                false,
                null,
                "Native Omega runtime is not packaged yet. Build libomega_android_bridge.so and place it in jniLibs.",
            )
        }
        val realityServer = if (profile.realityServer.isNotBlank()) profile.realityServer else profile.server
        return NativeHandshakeConfig.fromJson(
            nativeStartRealityHandshake(
                realityServer,
                profile.deviceId,
                profile.deviceToken,
                profile.deviceName,
                profile.realitySni,
                profile.realityServerPubkey,
                profile.realityShortId,
                profile.realityFingerprint,
                protectedTcpFd,
            )
        )
    }

    fun continueWithTunFd(handle: Long, fd: Int): NativeResult {
        if (fd < 0) return NativeResult(false, "Invalid TUN file descriptor.")
        if (!loaded) return NativeResult(false, "Native library is not packaged.")
        return NativeResult.fromJson(nativeContinueWithTunFd(handle, fd))
    }

    fun stop(handle: Long): NativeResult {
        if (!loaded) return NativeResult(true, "Stopped.")
        return NativeResult.fromJson(nativeStop(handle))
    }

    private fun closeDetachedFd(fd: Int) {
        if (fd < 0) return
        runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
    }
}
