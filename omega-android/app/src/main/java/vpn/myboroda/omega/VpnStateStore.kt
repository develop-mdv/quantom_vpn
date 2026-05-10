package vpn.myboroda.omega

import android.content.Context

enum class VpnConnectionState {
    DISCONNECTED,
    CONNECTING,
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

    companion object {
        private const val KEY_STATE = "state"
    }
}
