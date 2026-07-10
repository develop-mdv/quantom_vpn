package vpn.myboroda.omega

import android.content.Context
import android.content.SharedPreferences

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
        val stored = VpnConnectionState.fromStored(prefs.getString(KEY_STATE, null))
        // Prefs survive a process kill or reboot, the tunnel does not: an
        // "active" state without a live service instance is stale, so report
        // the truth instead of a phantom connection.
        if (stored != VpnConnectionState.DISCONNECTED && !OmegaVpnService.isRunning) {
            return VpnConnectionState.DISCONNECTED
        }
        return stored
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

    /// Live state updates for the UI: the service writes every transition
    /// through saveState(), so a prefs listener is a cheap in-process event
    /// bus. Callers must hold a strong reference to the listener —
    /// SharedPreferences only keeps weak ones.
    fun registerListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) {
        prefs.registerOnSharedPreferenceChangeListener(listener)
    }

    fun unregisterListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) {
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
    }

    companion object {
        private const val KEY_STATE = "state"
        private const val KEY_DESIRED = "desired_connected"
    }
}
