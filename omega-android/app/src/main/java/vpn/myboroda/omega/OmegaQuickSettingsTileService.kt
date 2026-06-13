package vpn.myboroda.omega

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class OmegaQuickSettingsTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        when (VpnStateStore(this).loadState()) {
            VpnConnectionState.CONNECTING,
            VpnConnectionState.RECONNECTING,
            VpnConnectionState.CONNECTED,
            -> {
                OmegaVpnService.disconnect(this)
                updateTile(VpnConnectionState.DISCONNECTED)
            }
            VpnConnectionState.DISCONNECTED -> connectFromTile()
        }
    }

    private fun connectFromTile() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent == null) {
            VpnStateStore(this).saveState(VpnConnectionState.CONNECTING)
            OmegaVpnService.start(this)
            updateTile(VpnConnectionState.CONNECTING)
            return
        }

        val intent = Intent(this, MainActivity::class.java)
            .setAction(MainActivity.ACTION_CONNECT)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pendingIntent = PendingIntent.getActivity(
                this,
                2,
                intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            startActivityAndCollapse(pendingIntent)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    private fun updateTile(state: VpnConnectionState = VpnStateStore(this).loadState()) {
        qsTile?.apply {
            label = "Omega VPN"
            this.state = when (state) {
                VpnConnectionState.CONNECTED,
                VpnConnectionState.CONNECTING,
                VpnConnectionState.RECONNECTING,
                -> Tile.STATE_ACTIVE
                VpnConnectionState.DISCONNECTED -> Tile.STATE_INACTIVE
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                subtitle = when (state) {
                    VpnConnectionState.CONNECTING -> "Connecting"
                    VpnConnectionState.RECONNECTING -> "Reconnecting"
                    VpnConnectionState.CONNECTED -> "Connected"
                    VpnConnectionState.DISCONNECTED -> "Disconnected"
                }
            }
            updateTile()
        }
    }
}
