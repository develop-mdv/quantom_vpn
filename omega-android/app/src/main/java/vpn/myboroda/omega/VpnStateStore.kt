package vpn.myboroda.omega

import android.content.Context

enum class VpnConnectionState {
    DISCONNECTED,
    CONNECTING,
    RECONNECTING,
    CONNECTED;

    companion object {
        fun fromStored(value: String?): VpnConnectionState {
            return entries.firstOrNull { it.name == value } ?: DISCONNECTED
        }
    }
}

class VpnStateStore(context: Context) {
    private val prefs = context.getSharedPreferences("omega_vpn_state", Context.MODE_PRIVATE)

    fun loadState(): VpnConnectionState {
        return VpnConnectionState.fromStored(prefs.getString(KEY_STATE, null))
    }

    fun saveState(state: VpnConnectionState) {
        prefs.edit().putString(KEY_STATE, state.name).apply()
    }

    /// Whether the user wants the tunnel up. Survives process death so the
    /// service can tell an intentional disconnect from a system-triggered
    /// restart (START_STICKY) and decide whether to auto-reconnect.
    fun isDesiredConnected(): Boolean = prefs.getBoolean(KEY_DESIRED, false)

    fun setDesiredConnected(value: Boolean) {
        prefs.edit().putBoolean(KEY_DESIRED, value).apply()
    }

    companion object {
        private const val KEY_STATE = "state"
        private const val KEY_DESIRED = "desired_connected"
    }
}
