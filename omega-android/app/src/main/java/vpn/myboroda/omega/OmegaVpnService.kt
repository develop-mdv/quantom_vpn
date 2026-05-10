package vpn.myboroda.omega

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import android.util.Log
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class OmegaVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var nativeHandle: Long = 0L
    private lateinit var stateStore: VpnStateStore
    private val mainHandler = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private val connecting = AtomicBoolean(false)

    override fun onCreate() {
        super.onCreate()
        stateStore = VpnStateStore(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                worker.execute { stopTunnel() }
                return START_NOT_STICKY
            }
            else -> {
                updateConnectionState(VpnConnectionState.CONNECTING)
                startForeground(NOTIFICATION_ID, buildNotification("Connecting"))
                if (connecting.compareAndSet(false, true)) {
                    worker.execute { startTunnel() }
                } else {
                    Log.i(TAG, "Connection request ignored because a tunnel start is already running")
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        worker.execute { stopTunnel() }
        worker.shutdown()
        super.onDestroy()
    }

    private fun startTunnel() {
        val store = ProfileStore(this)
        val profile = store.loadProfile()
        val splitSettings = store.loadSplitSettings()
        Log.i(TAG, "Starting tunnel to ${profile.server} via ${profile.transport}")
        val protectedUdpFd = createProtectedUdpFd(profile.server)
        if (protectedUdpFd < 0) {
            stopTunnel()
            return
        }
        Log.i(TAG, "Protected UDP socket is ready; starting native handshake")
        val handshake = OmegaNative.startHandshake(profile, protectedUdpFd)
        if (!handshake.ok || handshake.config == null) {
            Log.e(TAG, handshake.message)
            stopTunnel()
            return
        }
        nativeHandle = handshake.config.handle
        Log.i(
            TAG,
            "Handshake ok: handle=${handshake.config.handle}, ipv4=${handshake.config.tunnelIpv4}, " +
                "ipv6=${handshake.config.tunnelIpv6}, mtu=${handshake.config.mtu}",
        )

        val established = runCatching {
            establishTunnel(handshake.config, splitSettings)
        }.getOrElse {
            Log.e(TAG, "TUN setup failed", it)
            null
        }

        if (established == null) {
            stopTunnel()
            return
        }
        Log.i(TAG, "Android TUN interface established")

        val tunFd = established.detachFd()
        tun = null
        val native = OmegaNative.continueWithTunFd(handshake.config.handle, tunFd)
        if (!native.ok) {
            Log.e(TAG, native.message)
            stopTunnel()
            return
        }
        Log.i(TAG, native.message)

        updateConnectionState(VpnConnectionState.CONNECTED)
        postToMain { startForeground(NOTIFICATION_ID, buildNotification("Connected")) }
        connecting.set(false)
    }

    private fun establishTunnel(
        config: NativeHandshakeConfig,
        splitSettings: SplitSettings,
    ): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("Omega VPN")
            .setMtu(config.mtu.coerceIn(1200, 1420))
            .addAddress(config.tunnelIpv4, 16)
            .addRoute("0.0.0.0", 0)

        config.tunnelIpv6?.takeIf { it.isNotBlank() }?.let {
            builder.addAddress(it, 64)
            builder.addRoute("::", 0)
        }

        val dnsServers = config.dnsServers.ifEmpty { listOf("1.1.1.1", "8.8.8.8") }
        dnsServers.forEach(builder::addDnsServer)

        applyAppRules(builder, splitSettings)
        return builder.establish()
    }

    private fun applyAppRules(builder: Builder, settings: SplitSettings) {
        when (settings.mode) {
            SplitMode.EXCLUDE_SELECTED -> {
                (settings.selectedPackages + packageName)
                    .filter { it.isNotBlank() }
                    .distinct()
                    .forEach { builder.addDisallowedApplication(it) }
            }
            SplitMode.ONLY_SELECTED -> {
                val allowed = settings.selectedPackages
                    .filter { it.isNotBlank() && it != packageName }
                    .distinct()
                require(allowed.isNotEmpty()) { "Choose at least one app for VPN-only mode." }
                allowed.forEach { builder.addAllowedApplication(it) }
            }
        }
    }

    private fun stopTunnel() {
        OmegaNative.stop(nativeHandle)
        nativeHandle = 0L
        runCatching { tun?.close() }
        tun = null
        connecting.set(false)
        updateConnectionState(VpnConnectionState.DISCONNECTED)
        postToMain {
            stopForegroundCompat()
            stopSelf()
        }
    }

    private fun createProtectedUdpFd(server: String): Int {
        val host = server.substringBeforeLast(':', missingDelimiterValue = "")
            .trim()
            .removePrefix("[")
            .removeSuffix("]")
        val port = server.substringAfterLast(':', missingDelimiterValue = "").toIntOrNull()
        if (host.isBlank() || port == null || port !in 1..65535) {
            Log.e(TAG, "Invalid server endpoint: $server")
            return -1
        }

        val socket = DatagramSocket(null)
        return runCatching {
            socket.reuseAddress = false
            socket.bind(InetSocketAddress(0))
            if (!protect(socket)) {
                socket.close()
                Log.e(TAG, "VpnService.protect failed for Omega UDP socket")
                return -1
            }
            socket.connect(InetSocketAddress(host, port))
            val pfd = ParcelFileDescriptor.fromDatagramSocket(socket)
            val fd = pfd.detachFd()
            socket.close()
            fd
        }.getOrElse {
            socket.close()
            Log.e(TAG, "Failed to create protected UDP socket", it)
            -1
        }
    }

    private fun buildNotification(state: String): Notification {
        ensureNotificationChannel()
        val activityIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            activityIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disconnectIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, OmegaVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("Omega VPN")
            .setContentText(state)
            .setSmallIcon(R.drawable.ic_vpn_status)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .addAction(R.drawable.ic_vpn_status, "Disconnect", disconnectIntent)
            .build()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    private fun postToMain(block: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            block()
        } else {
            mainHandler.post(block)
        }
    }

    private fun updateConnectionState(state: VpnConnectionState) {
        stateStore.saveState(state)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            TileService.requestListeningState(
                this,
                ComponentName(this, OmegaQuickSettingsTileService::class.java),
            )
        }
    }

    companion object {
        private const val TAG = "OmegaVpnService"
        private const val CHANNEL_ID = "omega_vpn"
        private const val NOTIFICATION_ID = 7007
        private const val ACTION_DISCONNECT = "vpn.myboroda.omega.DISCONNECT"

        fun start(context: Context) {
            val intent = Intent(context, OmegaVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun disconnect(context: Context) {
            val intent = Intent(context, OmegaVpnService::class.java).setAction(ACTION_DISCONNECT)
            context.startService(intent)
        }
    }
}
