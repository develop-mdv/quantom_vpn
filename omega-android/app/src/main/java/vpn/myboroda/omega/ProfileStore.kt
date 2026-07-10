package vpn.myboroda.omega

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/// A saved connection profile with a user-visible name. Several can coexist;
/// exactly one (the "active" profile) feeds the VPN service.
data class StoredProfile(
    val id: String,
    val name: String,
    val profile: OmegaProfile,
)

class ProfileStore(context: Context) {
    private val prefs = context.getSharedPreferences("omega_android_profile", Context.MODE_PRIVATE)

    // -------------------------------------------------------------------
    // Profiles (multiple, with a single active selection)
    // -------------------------------------------------------------------

    fun loadProfiles(): List<StoredProfile> {
        migrateLegacyProfileIfNeeded()
        return parseProfiles(prefs.getString(KEY_PROFILES, null).orEmpty())
    }

    /// The active profile, falling back to the first one if the stored id
    /// no longer exists (e.g. after a delete).
    fun activeProfile(): StoredProfile? {
        val profiles = loadProfiles()
        val id = prefs.getString(KEY_ACTIVE_PROFILE, null)
        return profiles.firstOrNull { it.id == id } ?: profiles.firstOrNull()
    }

    fun setActiveProfileId(id: String) {
        prefs.edit().putString(KEY_ACTIVE_PROFILE, id).apply()
    }

    /// Insert or replace by id. The first saved profile becomes active.
    fun upsertProfile(entry: StoredProfile) {
        val normalized = entry.copy(profile = entry.profile.normalized())
        val profiles = loadProfiles().toMutableList()
        val index = profiles.indexOfFirst { it.id == normalized.id }
        if (index >= 0) profiles[index] = normalized else profiles.add(normalized)
        persistProfiles(profiles)
        if (prefs.getString(KEY_ACTIVE_PROFILE, null) == null) {
            setActiveProfileId(normalized.id)
        }
    }

    fun deleteProfile(id: String) {
        val remaining = loadProfiles().filterNot { it.id == id }
        persistProfiles(remaining)
        if (prefs.getString(KEY_ACTIVE_PROFILE, null) == id) {
            val next = remaining.firstOrNull()?.id
            if (next != null) {
                setActiveProfileId(next)
            } else {
                prefs.edit().remove(KEY_ACTIVE_PROFILE).apply()
            }
        }
    }

    /// Applies a change (e.g. the REALITY toggle) to the active profile.
    fun updateActiveProfile(transform: (OmegaProfile) -> OmegaProfile) {
        val active = activeProfile() ?: return
        upsertProfile(active.copy(profile = transform(active.profile)))
    }

    /// The profile the VPN service actually connects with.
    fun loadProfile(): OmegaProfile = activeProfile()?.profile ?: OmegaProfile()

    private fun persistProfiles(profiles: List<StoredProfile>) {
        prefs.edit().putString(KEY_PROFILES, serializeProfiles(profiles)).apply()
    }

    /// Pre-multi-profile versions stored a single profile as flat keys; fold
    /// it into the list once so nobody loses a working setup on update.
    private fun migrateLegacyProfileIfNeeded() {
        if (prefs.contains(KEY_PROFILES)) return
        val legacy = OmegaProfile(
            server = prefs.getString(KEY_LEGACY_SERVER, "").orEmpty(),
            deviceId = prefs.getString(KEY_LEGACY_DEVICE_ID, "").orEmpty(),
            deviceToken = prefs.getString(KEY_LEGACY_DEVICE_TOKEN, "").orEmpty(),
            deviceName = prefs.getString(KEY_LEGACY_DEVICE_NAME, "android").orEmpty(),
            transport = prefs.getString(KEY_LEGACY_TRANSPORT, "auto").orEmpty(),
            realityCode = prefs.getString(KEY_LEGACY_REALITY_CODE, "").orEmpty(),
            realityEnabled = prefs.getBoolean(KEY_LEGACY_REALITY_ENABLED, false),
        ).normalized()
        if (legacy.server.isBlank() && legacy.deviceId.isBlank()) {
            prefs.edit().putString(KEY_PROFILES, "[]").apply()
            return
        }
        val entry = StoredProfile(
            id = UUID.randomUUID().toString(),
            name = defaultProfileName(legacy, fallback = "Мой профиль"),
            profile = legacy,
        )
        prefs.edit()
            .putString(KEY_PROFILES, serializeProfiles(listOf(entry)))
            .putString(KEY_ACTIVE_PROFILE, entry.id)
            .apply()
    }

    // -------------------------------------------------------------------
    // Split tunneling (global, not per profile)
    // -------------------------------------------------------------------

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
        private const val KEY_PROFILES = "profiles"
        private const val KEY_ACTIVE_PROFILE = "active_profile_id"
        private const val KEY_SPLIT_MODE = "split_mode"
        private const val KEY_SELECTED_PACKAGES = "selected_packages"

        // Flat keys of the old single-profile format, read only for migration.
        private const val KEY_LEGACY_SERVER = "server"
        private const val KEY_LEGACY_DEVICE_ID = "device_id"
        private const val KEY_LEGACY_DEVICE_TOKEN = "device_token"
        private const val KEY_LEGACY_DEVICE_NAME = "device_name"
        private const val KEY_LEGACY_TRANSPORT = "transport"
        private const val KEY_LEGACY_REALITY_CODE = "reality_code"
        private const val KEY_LEGACY_REALITY_ENABLED = "reality_enabled"

        fun defaultProfileName(profile: OmegaProfile, fallback: String): String {
            val deviceName = profile.deviceName.takeIf { it.isNotBlank() && it != "android" }
            return deviceName
                ?: profile.server.substringBeforeLast(':').takeIf { it.isNotBlank() }
                ?: fallback
        }

        private fun serializeProfiles(profiles: List<StoredProfile>): String {
            val array = JSONArray()
            profiles.forEach { entry ->
                array.put(
                    JSONObject().apply {
                        put("id", entry.id)
                        put("name", entry.name)
                        put("server", entry.profile.server)
                        put("device_id", entry.profile.deviceId)
                        put("device_token", entry.profile.deviceToken)
                        put("device_name", entry.profile.deviceName)
                        put("transport", entry.profile.transport)
                        put("reality_code", entry.profile.realityCode)
                        put("reality_enabled", entry.profile.realityEnabled)
                    }
                )
            }
            return array.toString()
        }

        private fun parseProfiles(json: String): List<StoredProfile> {
            if (json.isBlank()) return emptyList()
            return runCatching {
                val array = JSONArray(json)
                buildList {
                    for (index in 0 until array.length()) {
                        val obj = array.optJSONObject(index) ?: continue
                        val id = obj.optString("id").trim()
                        if (id.isEmpty()) continue
                        add(
                            StoredProfile(
                                id = id,
                                name = obj.optString("name").trim().ifEmpty { "Профиль" },
                                profile = OmegaProfile(
                                    server = obj.optString("server"),
                                    deviceId = obj.optString("device_id"),
                                    deviceToken = obj.optString("device_token"),
                                    deviceName = obj.optString("device_name"),
                                    transport = obj.optString("transport"),
                                    realityCode = obj.optString("reality_code"),
                                    realityEnabled = obj.optBoolean("reality_enabled", false),
                                ).normalized(),
                            )
                        )
                    }
                }
            }.getOrDefault(emptyList())
        }
    }
}
