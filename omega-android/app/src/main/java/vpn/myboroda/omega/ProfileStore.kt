package vpn.myboroda.omega

import android.content.Context

class ProfileStore(context: Context) {
    private val prefs = context.getSharedPreferences("omega_android_profile", Context.MODE_PRIVATE)

    fun loadProfile(): OmegaProfile {
        return OmegaProfile(
            server = prefs.getString(KEY_SERVER, "").orEmpty(),
            deviceId = prefs.getString(KEY_DEVICE_ID, "").orEmpty(),
            deviceToken = prefs.getString(KEY_DEVICE_TOKEN, "").orEmpty(),
            deviceName = prefs.getString(KEY_DEVICE_NAME, "android").orEmpty(),
            transport = prefs.getString(KEY_TRANSPORT, "auto").orEmpty(),
            realityServer = prefs.getString(KEY_REALITY_SERVER, "").orEmpty(),
            realitySni = prefs.getString(KEY_REALITY_SNI, "").orEmpty(),
            realityServerPubkey = prefs.getString(KEY_REALITY_PUBKEY, "").orEmpty(),
            realityShortId = prefs.getString(KEY_REALITY_SHORT_ID, "").orEmpty(),
            realityFingerprint = prefs.getString(KEY_REALITY_FP, "chrome_131").orEmpty(),
        ).normalized()
    }

    fun saveProfile(profile: OmegaProfile) {
        val normalized = profile.normalized()
        prefs.edit()
            .putString(KEY_SERVER, normalized.server)
            .putString(KEY_DEVICE_ID, normalized.deviceId)
            .putString(KEY_DEVICE_TOKEN, normalized.deviceToken)
            .putString(KEY_DEVICE_NAME, normalized.deviceName)
            .putString(KEY_TRANSPORT, normalized.transport)
            .putString(KEY_REALITY_SERVER, normalized.realityServer)
            .putString(KEY_REALITY_SNI, normalized.realitySni)
            .putString(KEY_REALITY_PUBKEY, normalized.realityServerPubkey)
            .putString(KEY_REALITY_SHORT_ID, normalized.realityShortId)
            .putString(KEY_REALITY_FP, normalized.realityFingerprint)
            .apply()
    }

    fun loadSplitSettings(): SplitSettings {
        val mode = SplitMode.fromStored(prefs.getString(KEY_SPLIT_MODE, null))
        val packages = prefs.getStringSet(KEY_SELECTED_PACKAGES, emptySet()).orEmpty()
        return SplitSettings(mode, packages)
    }

    fun saveSplitMode(mode: SplitMode) {
        prefs.edit().putString(KEY_SPLIT_MODE, mode.name).apply()
    }

    fun saveSelectedPackages(packages: Set<String>) {
        prefs.edit().putStringSet(KEY_SELECTED_PACKAGES, packages.toSet()).apply()
    }

    companion object {
        private const val KEY_SERVER = "server"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_DEVICE_TOKEN = "device_token"
        private const val KEY_DEVICE_NAME = "device_name"
        private const val KEY_TRANSPORT = "transport"
        private const val KEY_SPLIT_MODE = "split_mode"
        private const val KEY_SELECTED_PACKAGES = "selected_packages"
        private const val KEY_REALITY_SERVER = "reality_server"
        private const val KEY_REALITY_SNI = "reality_sni"
        private const val KEY_REALITY_PUBKEY = "reality_server_pubkey"
        private const val KEY_REALITY_SHORT_ID = "reality_short_id"
        private const val KEY_REALITY_FP = "reality_fingerprint"
    }
}
