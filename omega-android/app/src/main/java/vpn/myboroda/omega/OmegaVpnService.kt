package vpn.myboroda.omega

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import android.util.Log
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class OmegaVpnService : VpnService() {
    @Volatile private var nativeHandle: Long = 0L
    private lateinit var stateStore: VpnStateStore
    private var connectivityManager: ConnectivityManager? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    // All datapath setup/teardown runs here, serialized, so connect, disconnect
    // and reconnect can never race each other.
    private val worker = Executors.newSingleThreadExecutor()

    // Guards against overlapping connect attempts (watchdog + network callback
    // + retry timer can all fire at once).
    private val reconnecting = AtomicBoolean(false)
    // Bumped on every user connect/disconnect; stale tasks captured from an
    // older generation no-op when they finally run.
    private val generation = AtomicInteger(0)

    @Volatile private var currentState = VpnConnectionState.DISCONNECTED
    // The current usable *underlying* (non-VPN) network, tracked from the
    // connectivity callback. Never the VPN itself — that's the whole point: the
    // VPN coming up must not look like a network change.
    @Volatile private var currentUnderlying: Network? = null
    // The underlying network the live datapath was actually built on; a switch
    // away from it (Wi-Fi <-> cellular) means we must rebuild on the new one.
    @Volatile private var boundNetwork: Network? = null
    private var retryAttempt = 0

    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var watchdogRunnable: Runnable? = null
    private var pendingRetry: Runnable? = null

    private sealed interface ConnectResult {
        object Success : ConnectResult
        // Configuration / permission problem — retrying won't help, so stop and
        // let the user fix it and reconnect manually.
        data class Fatal(val message: String) : ConnectResult
        // Network blip / timeout — retry with backoff.
        data class Transient(val message: String) : ConnectResult
    }

    override fun onCreate() {
        super.onCreate()
        stateStore = VpnStateStore(this)
        connectivityManager = getSystemService(ConnectivityManager::class.java)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                worker.execute { userDisconnect() }
                return START_NOT_STICKY
            }
            else -> {
                // A null intent means the system restarted us (START_STICKY).
                // Only resume if the user actually wanted the tunnel up.
                if (intent == null && !stateStore.isDesiredConnected()) {
                    stopSelf()
                    return START_NOT_STICKY
                }
                stateStore.setDesiredConnected(true)
                generation.incrementAndGet()
                setState(VpnConnectionState.CONNECTING)
                // Must enter the foreground promptly when launched via
                // startForegroundService(), so do it synchronously here.
                startForeground(NOTIFICATION_ID, buildNotification(VpnConnectionState.CONNECTING))
                registerNetworkCallback()
                attemptConnect("start")
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        // Another VPN took over or the user revoked our consent.
        worker.execute { userDisconnect() }
        super.onRevoke()
    }

    override fun onDestroy() {
        stopWatchdog()
        unregisterNetworkCallback()
        stopDatapath()
        worker.shutdown()
        super.onDestroy()
    }

    // -------------------------------------------------------------------------
    // Connect / reconnect / disconnect (all datapath work on the worker thread)
    // -------------------------------------------------------------------------

    /// Single entry point for (re)establishing the tunnel. Coalesced by the
    /// [reconnecting] flag and serialized on the worker, so the many triggers
    /// (start, network change, watchdog, retry timer) can never pile up.
    private fun attemptConnect(reason: String) {
        if (!stateStore.isDesiredConnected()) return
        if (!reconnecting.compareAndSet(false, true)) return
        val gen = generation.get()
        worker.execute {
            try {
                if (gen != generation.get() || !stateStore.isDesiredConnected()) return@execute
                // Already healthy — nothing to do (e.g. a stale retry fired).
                if (currentState == VpnConnectionState.CONNECTED &&
                    nativeHandle != 0L && OmegaNative.sessionAlive(nativeHandle)
                ) {
                    return@execute
                }
                stopWatchdog()
                if (currentUnderlying == null) {
                    // No usable network right now; wait for onAvailable to call
                    // us back once one appears (no busy retry, easy on battery).
                    stopDatapath()
                    showConnecting()
                    return@execute
                }
                showConnecting()
                Log.i(TAG, "Connecting ($reason)")
                when (val result = establishDatapath()) {
                    is ConnectResult.Success -> {
                        if (gen != generation.get() || !stateStore.isDesiredConnected()) {
                            stopDatapath()
                        } else {
                            onConnected(gen)
                        }
                    }
                    is ConnectResult.Fatal -> {
                        Log.e(TAG, "Fatal connect error: ${result.message}")
                        onFatal(result.message)
                    }
                    is ConnectResult.Transient -> {
                        Log.w(TAG, "Transient connect error: ${result.message}")
                        scheduleRetry(gen)
                    }
                }
            } finally {
                reconnecting.set(false)
            }
        }
    }

    private fun onConnected(gen: Int) {
        retryAttempt = 0
        boundNetwork = currentUnderlying
        applyUnderlyingNetworks(currentUnderlying)
        setState(VpnConnectionState.CONNECTED)
        setForegroundNotification(buildNotification(VpnConnectionState.CONNECTED))
        postToMain {
            pendingRetry?.let { mainHandler.removeCallbacks(it) }
            pendingRetry = null
        }
        startWatchdog(gen)
        Log.i(TAG, "Tunnel connected (handle=$nativeHandle, net=$boundNetwork)")
    }

    private fun scheduleRetry(gen: Int) {
        if (gen != generation.get() || !stateStore.isDesiredConnected()) return
        stopDatapath()
        showConnecting()
        if (currentUnderlying == null) return // wait for onAvailable instead
        val delay = backoffMs(retryAttempt)
        retryAttempt += 1
        postToMain {
            pendingRetry?.let { mainHandler.removeCallbacks(it) }
            val runnable = Runnable { attemptConnect("retry") }
            pendingRetry = runnable
            mainHandler.postDelayed(runnable, delay)
        }
        Log.i(TAG, "Retry scheduled in ${delay}ms")
    }

    private fun onFatal(message: String) {
        // Stop cleanly instead of thrashing. Leave a persistent notification with
        // the reason and a "Connect" action so the user can retry after fixing.
        stateStore.setDesiredConnected(false)
        generation.incrementAndGet()
        boundNetwork = null
        postToMain {
            stopWatchdogInternal()
            pendingRetry?.let { mainHandler.removeCallbacks(it) }
            pendingRetry = null
            unregisterNetworkCallback()
            applyUnderlyingNetworks(null)
        }
        stopDatapath()
        setState(VpnConnectionState.DISCONNECTED)
        postToMain {
            applyTerminalNotification(
                buildNotification(VpnConnectionState.DISCONNECTED, detail = message),
            )
            stopSelf()
        }
    }

    private fun userDisconnect() {
        stateStore.setDesiredConnected(false)
        generation.incrementAndGet()
        boundNetwork = null
        postToMain {
            stopWatchdogInternal()
            pendingRetry?.let { mainHandler.removeCallbacks(it) }
            pendingRetry = null
            unregisterNetworkCallback()
            applyUnderlyingNetworks(null)
        }
        stopDatapath()
        setState(VpnConnectionState.DISCONNECTED)
        postToMain {
            // Keep a persistent, swipeable notification with a "Connect" action
            // so the user can re-arm the tunnel straight from the shade. Setting
            // it as the foreground notification before detaching guarantees it
            // shows "Disconnected" and never stays stuck on "Connected".
            applyTerminalNotification(buildNotification(VpnConnectionState.DISCONNECTED))
            stopSelf()
        }
    }

    /// Shows "Connecting…" for the very first attempt and "Reconnecting…" for
    /// every attempt after we've already been connected, without flapping.
    private fun showConnecting() {
        val state = if (currentState == VpnConnectionState.CONNECTING) {
            VpnConnectionState.CONNECTING
        } else {
            VpnConnectionState.RECONNECTING
        }
        if (state != currentState) {
            setState(state)
        }
        setForegroundNotification(buildNotification(state))
    }

    // -------------------------------------------------------------------------
    // Datapath build / teardown
    // -------------------------------------------------------------------------

    /// Runs the handshake, builds the TUN interface and hands its fd to the
    /// native datapath. Any previously running datapath is torn down first, so
    /// at most one native session ever exists.
    private fun establishDatapath(): ConnectResult {
        stopDatapath()
        val store = ProfileStore(this)
        val profile = store.loadProfile()
        profile.validationError()?.let { return ConnectResult.Fatal(it) }
        val splitSettings = store.loadSplitSettings()
        Log.i(TAG, "Starting tunnel to ${profile.server} via ${profile.effectiveTransport()}")

        val handshake = when (profile.effectiveTransport()) {
            "reality" -> startRealityHandshake(profile)
            else -> startUdpHandshake(profile)
        }
        if (!handshake.ok || handshake.config == null) {
            return classifyHandshakeError(handshake.message)
        }
        val config = handshake.config
        Log.i(
            TAG,
            "Handshake ok: handle=${config.handle}, ipv4=${config.tunnelIpv4}, " +
                "ipv6=${config.tunnelIpv6}, mtu=${config.mtu}",
        )

        val established = try {
            establishTunnel(config, splitSettings)
        } catch (se: SecurityException) {
            OmegaNative.stop(config.handle)
            return ConnectResult.Fatal("Нет разрешения на VPN. Откройте приложение и подключитесь один раз.")
        } catch (ia: IllegalArgumentException) {
            OmegaNative.stop(config.handle)
            return ConnectResult.Fatal("Ошибка конфигурации туннеля: ${ia.message}")
        } catch (e: Exception) {
            Log.e(TAG, "TUN setup failed", e)
            OmegaNative.stop(config.handle)
            return ConnectResult.Transient("TUN setup failed: ${e.message}")
        }
        if (established == null) {
            OmegaNative.stop(config.handle)
            return ConnectResult.Transient("TUN setup returned no interface.")
        }

        val tunFd = established.detachFd()
        val native = OmegaNative.continueWithTunFd(config.handle, tunFd)
        if (!native.ok) {
            OmegaNative.stop(config.handle)
            return ConnectResult.Transient(native.message)
        }
        nativeHandle = config.handle
        Log.i(TAG, native.message)
        return ConnectResult.Success
    }

    /// Classify a handshake failure so we know whether to give up (bad auth /
    /// config) or retry (network blip / timeout).
    private fun classifyHandshakeError(message: String): ConnectResult {
        val m = message.lowercase()
        val fatalMarkers = listOf(
            "rejected", "token", "uuid", "device id", "validation",
            "required", "must be", "reality", "не распознан", "некоррект",
        )
        return if (fatalMarkers.any { m.contains(it) }) {
            ConnectResult.Fatal(message)
        } else {
            ConnectResult.Transient(message)
        }
    }

    private fun stopDatapath() {
        val handle = nativeHandle
        nativeHandle = 0L
        if (handle != 0L) {
            OmegaNative.stop(handle)
        }
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

        // Pin the tunnel to the current underlying network for correct routing
        // and accounting.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            builder.setUnderlyingNetworks(currentUnderlying?.let { arrayOf(it) })
        }

        applyAppRules(builder, splitSettings)
        return builder.establish()
    }

    private fun applyAppRules(builder: Builder, settings: SplitSettings) {
        when (settings.mode) {
            SplitMode.EXCLUDE_SELECTED -> {
                (settings.selectedPackages + packageName)
                    .filter { it.isNotBlank() }
                    .distinct()
                    .forEach { runCatching { builder.addDisallowedApplication(it) } }
            }
            SplitMode.ONLY_SELECTED -> {
                val allowed = settings.selectedPackages
                    .filter { it.isNotBlank() && it != packageName }
                    .distinct()
                require(allowed.isNotEmpty()) { "Выберите хотя бы одно приложение для режима «только выбранные»." }
                allowed.forEach { runCatching { builder.addAllowedApplication(it) } }
            }
        }
    }

    private fun startUdpHandshake(profile: OmegaProfile): NativeHandshakeResult {
        val protectedUdpFd = createProtectedUdpFd(profile.server)
        if (protectedUdpFd < 0) {
            return NativeHandshakeResult(false, null, "Failed to create protected UDP socket.")
        }
        Log.i(TAG, "Protected UDP socket is ready; starting native handshake")
        return OmegaNative.startHandshake(profile, protectedUdpFd)
    }

    private fun startRealityHandshake(profile: OmegaProfile): NativeHandshakeResult {
        val rf = profile.realityFields()
            ?: return NativeHandshakeResult(false, null, "REALITY-код не распознан.")
        val protectedTcpFd = createProtectedTcpFd(rf.server)
        if (protectedTcpFd < 0) {
            return NativeHandshakeResult(false, null, "Failed to create protected TCP socket for REALITY.")
        }
        Log.i(TAG, "Protected TCP socket is ready; starting REALITY handshake to ${rf.server} (SNI=${rf.sni})")
        return OmegaNative.startRealityHandshake(profile, protectedTcpFd)
    }

    private fun createProtectedTcpFd(server: String): Int {
        val host = server.substringBeforeLast(':', missingDelimiterValue = "")
            .trim()
            .removePrefix("[")
            .removeSuffix("]")
        val port = server.substringAfterLast(':', missingDelimiterValue = "").toIntOrNull()
        if (host.isBlank() || port == null || port !in 1..65535) {
            Log.e(TAG, "Invalid REALITY server endpoint: $server")
            return -1
        }
        val socket = Socket()
        return runCatching {
            socket.reuseAddress = false
            socket.tcpNoDelay = true
            // Step 1: protect the OS-level fd from the VPN itself.
            if (!protect(socket)) {
                socket.close()
                Log.e(TAG, "VpnService.protect failed for REALITY TCP socket")
                return -1
            }
            // Step 2: pin the socket to the chosen underlying network so it
            // actually leaves over (e.g.) Wi-Fi instead of whatever the default
            // route happens to be mid-handover — otherwise the old radio stays
            // busy and both the Wi-Fi and mobile icons keep showing.
            bindToUnderlying(socket)
            // Step 3: connect through the underlying (non-VPN) network.
            socket.connect(InetSocketAddress(host, port), 10_000)
            // Step 3: hand the connected fd to native land. Use
            // ParcelFileDescriptor.fromSocket to detach the fd cleanly.
            val pfd = ParcelFileDescriptor.fromSocket(socket)
            val fd = pfd.detachFd()
            // socket.close() at this point would close the dup'd fd we kept
            // — leave the Socket alive to keep the original handle until GC.
            // The pfd has detached; native side owns the fd now.
            fd
        }.getOrElse {
            runCatching { socket.close() }
            Log.e(TAG, "Failed to create protected TCP socket", it)
            -1
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
            // Pin to the chosen underlying network (see the TCP path for why).
            bindToUnderlying(socket)
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

    // -------------------------------------------------------------------------
    // Network monitoring + watchdog
    // -------------------------------------------------------------------------

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val cm = connectivityManager ?: return
        // Seed from the current default before our VPN exists (first connect).
        currentUnderlying = pickInitialUnderlying(cm)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                postToMain { onUnderlyingAvailable(network) }
            }

            override fun onLost(network: Network) {
                postToMain { onUnderlyingLost(network) }
            }
        }
        networkCallback = callback
        // IMPORTANT: filter to non-VPN networks. Watching the default network
        // would report our own VPN interface once it comes up, which looked like
        // an endless "network changed -> reconnect" loop.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // Best-matching = the single best underlying network. It re-fires
                // onAvailable when the winner changes (e.g. Wi-Fi beats cellular)
                // and only fires onLost when there's no replacement, so we never
                // juggle several networks or get stuck on a dead one.
                cm.registerBestMatchingNetworkCallback(request, callback, mainHandler)
            } else {
                cm.registerNetworkCallback(request, callback)
            }
        }.onFailure {
            Log.e(TAG, "Failed to register network callback", it)
            networkCallback = null
        }
    }

    private fun onUnderlyingAvailable(network: Network) {
        currentUnderlying = network
        applyUnderlyingNetworks(network)
        if (!stateStore.isDesiredConnected()) return
        when {
            // (Re)connect now that a usable underlying network exists.
            currentState != VpnConnectionState.CONNECTED ->
                attemptConnect("network available")
            // The best underlying network actually changed (Wi-Fi <-> cellular).
            network != boundNetwork ->
                attemptConnect("underlying network changed")
        }
    }

    private fun onUnderlyingLost(network: Network) {
        if (currentUnderlying == network) {
            // Best-matching delivers a replacement via onAvailable; the legacy
            // (pre-S) callback does not, so look for another non-VPN network.
            currentUnderlying = fallbackUnderlying(network)
        }
        if (!stateStore.isDesiredConnected()) return
        val replacement = currentUnderlying
        if (replacement == null) {
            // No network at all — tear down the dead datapath and wait.
            applyUnderlyingNetworks(null)
            showConnecting()
            worker.execute { if (stateStore.isDesiredConnected()) stopDatapath() }
        } else if (replacement != boundNetwork) {
            applyUnderlyingNetworks(replacement)
            attemptConnect("underlying network lost, switching")
        }
    }

    /// First non-VPN network with internet (used to seed, and to fall back on
    /// the legacy callback). Prefers the active default when it qualifies.
    private fun pickInitialUnderlying(cm: ConnectivityManager): Network? {
        val active = cm.activeNetwork
        if (active != null && isUsableUnderlying(cm, active)) return active
        return fallbackUnderlying(null)
    }

    private fun fallbackUnderlying(exclude: Network?): Network? {
        val cm = connectivityManager ?: return null
        @Suppress("DEPRECATION")
        return cm.allNetworks.firstOrNull { it != exclude && isUsableUnderlying(cm, it) }
    }

    private fun isUsableUnderlying(cm: ConnectivityManager, network: Network): Boolean {
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    }

    private fun unregisterNetworkCallback() {
        val cm = connectivityManager
        networkCallback?.let { cb -> runCatching { cm?.unregisterNetworkCallback(cb) } }
        networkCallback = null
    }

    private fun applyUnderlyingNetworks(network: Network?) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) return
        runCatching {
            setUnderlyingNetworks(if (network == null) null else arrayOf(network))
        }
    }

    private fun bindToUnderlying(socket: Socket) {
        currentUnderlying?.let { runCatching { it.bindSocket(socket) } }
    }

    private fun bindToUnderlying(socket: DatagramSocket) {
        currentUnderlying?.let { runCatching { it.bindSocket(socket) } }
    }

    private fun startWatchdog(gen: Int) {
        // Confine all watchdog handler/field access to the main thread so the
        // self-rescheduling runnable can't race with start/stop from the worker.
        postToMain {
            stopWatchdogInternal()
            val runnable = object : Runnable {
                override fun run() {
                    if (this !== watchdogRunnable) return // superseded
                    if (gen != generation.get() || !stateStore.isDesiredConnected()) return
                    if (currentState == VpnConnectionState.CONNECTED) {
                        val handle = nativeHandle
                        if (handle == 0L || !OmegaNative.sessionAlive(handle)) {
                            Log.w(TAG, "Watchdog: datapath is not alive — reconnecting")
                            attemptConnect("watchdog")
                            return // reconnect restarts the watchdog on success
                        }
                    }
                    mainHandler.postDelayed(this, WATCHDOG_INTERVAL_MS)
                }
            }
            watchdogRunnable = runnable
            mainHandler.postDelayed(runnable, WATCHDOG_INTERVAL_MS)
        }
    }

    private fun stopWatchdog() {
        postToMain { stopWatchdogInternal() }
    }

    private fun stopWatchdogInternal() {
        watchdogRunnable?.let { mainHandler.removeCallbacks(it) }
        watchdogRunnable = null
    }

    private fun backoffMs(attempt: Int): Long {
        // 1s, 2s, 4s, 8s, 16s, then capped at 30s — fast recovery without
        // hammering a server that's genuinely down.
        val shifted = 1000L shl attempt.coerceIn(0, 5)
        return shifted.coerceAtMost(MAX_BACKOFF_MS)
    }

    // -------------------------------------------------------------------------
    // Notification + state
    // -------------------------------------------------------------------------

    private fun buildNotification(state: VpnConnectionState, detail: String? = null): Notification {
        ensureNotificationChannel()
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        builder
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(detail ?: stateText(state))
            .setSmallIcon(R.drawable.ic_vpn_status)
            .setContentIntent(contentIntent)
            .setOnlyAlertOnce(true)

        if (state == VpnConnectionState.DISCONNECTED) {
            // Persistent but dismissible: stays in the shade as a one-tap
            // "Connect" toggle after the user disconnects.
            builder.setOngoing(false)
            @Suppress("DEPRECATION")
            builder.addAction(
                R.drawable.ic_vpn_status,
                getString(R.string.action_connect),
                connectActionIntent(),
            )
        } else {
            builder.setOngoing(true)
            @Suppress("DEPRECATION")
            builder.addAction(
                R.drawable.ic_vpn_status,
                getString(R.string.action_disconnect),
                disconnectActionIntent(),
            )
        }
        return builder.build()
    }

    private fun stateText(state: VpnConnectionState): String = when (state) {
        VpnConnectionState.CONNECTING -> getString(R.string.notif_connecting)
        VpnConnectionState.CONNECTED -> getString(R.string.notif_connected)
        VpnConnectionState.RECONNECTING -> getString(R.string.notif_reconnecting)
        VpnConnectionState.DISCONNECTED -> getString(R.string.notif_disconnected)
    }

    private fun connectActionIntent(): PendingIntent {
        val intent = Intent(this, OmegaVpnService::class.java).setAction(ACTION_CONNECT)
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        // The service is stopped when this action is shown, so start it fresh.
        // A notification action is an allowed foreground-service start trigger.
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            PendingIntent.getForegroundService(this, 2, intent, flags)
        } else {
            PendingIntent.getService(this, 2, intent, flags)
        }
    }

    private fun disconnectActionIntent(): PendingIntent {
        // The service is already running and foreground here, so a plain
        // startService delivery is correct (and must NOT promise a new
        // foreground start that we won't fulfil).
        return PendingIntent.getService(
            this,
            1,
            Intent(this, OmegaVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = notificationManager() ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        manager.createNotificationChannel(channel)
    }

    /// Update the foreground-service notification. We use startForeground rather
    /// than NotificationManager.notify() because notify() is rate-limited per app
    /// (~a few updates/sec) and, during rapid connect/disconnect cycling, the
    /// system can silently drop an update — leaving the banner stuck on a stale
    /// state (e.g. "Connected" after a disconnect). startForeground bypasses that
    /// limiter and keeps the system's cached foreground notification in sync.
    private fun setForegroundNotification(notification: Notification) {
        postToMain { runCatching { startForeground(NOTIFICATION_ID, notification) } }
    }

    /// Post the final notification as the service shuts down. Setting it as the
    /// foreground notification first (then detaching) guarantees this content
    /// survives — otherwise a detach could re-assert the previous foreground
    /// snapshot and freeze the banner on the old state. Must run on the main
    /// thread; falls back to notify() if foregrounding is no longer permitted.
    private fun applyTerminalNotification(notification: Notification) {
        val ok = runCatching {
            startForeground(NOTIFICATION_ID, notification)
            detachForegroundKeepNotification()
        }.isSuccess
        if (!ok) {
            notificationManager()?.notify(NOTIFICATION_ID, notification)
        }
    }

    private fun detachForegroundKeepNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_DETACH)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(false)
        }
    }

    private fun notificationManager(): NotificationManager? =
        getSystemService(NotificationManager::class.java)

    private fun postToMain(block: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            block()
        } else {
            mainHandler.post(block)
        }
    }

    private fun setState(state: VpnConnectionState) {
        currentState = state
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
        private const val ACTION_CONNECT = "vpn.myboroda.omega.CONNECT_SERVICE"
        private const val ACTION_DISCONNECT = "vpn.myboroda.omega.DISCONNECT"
        private const val WATCHDOG_INTERVAL_MS = 7_000L
        private const val MAX_BACKOFF_MS = 30_000L

        fun start(context: Context) {
            val intent = Intent(context, OmegaVpnService::class.java).setAction(ACTION_CONNECT)
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
