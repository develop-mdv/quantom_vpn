package vpn.myboroda.omega

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView

/// Home screen: pick a profile, add new ones and toggle the tunnel — nothing
/// else. All configuration lives on separate screens (ProfileEditorActivity
/// for profile data, SettingsActivity for REALITY and split tunneling) so
/// this screen stays glanceable.
class MainActivity : Activity() {
    private lateinit var store: ProfileStore
    private lateinit var stateStore: VpnStateStore

    private lateinit var toggleButton: TextView
    private lateinit var statusDot: View
    private lateinit var statusText: TextView
    private lateinit var activeProfileText: TextView
    private lateinit var hintText: TextView
    private lateinit var profileList: LinearLayout

    // Field, not a local: SharedPreferences only holds listeners weakly.
    private val stateListener =
        SharedPreferences.OnSharedPreferenceChangeListener { _, _ -> renderState() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = ProfileStore(this)
        stateStore = VpnStateStore(this)
        setContentView(buildContent())
        requestNotificationPermission()
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onStart() {
        super.onStart()
        stateStore.registerListener(stateListener)
    }

    override fun onStop() {
        stateStore.unregisterListener(stateListener)
        super.onStop()
    }

    override fun onResume() {
        super.onResume()
        // Profiles may have been added/edited on the editor screen, and the
        // tunnel state may have changed from the notification or QS tile.
        renderProfiles()
        renderState()
    }

    // ------------------------------------------------------------------ UI --

    private fun buildContent(): View {
        val root = uiScreenRoot()
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(16), dp(20), dp(24))
        }
        root.addView(column)
        column.addView(header())
        column.addView(statusCard())
        column.addView(profilesPanel())
        return root
    }

    private fun header(): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(16))
        }
        row.addView(
            ImageView(this).apply { setImageResource(R.drawable.ic_omega_mark) },
            LinearLayout.LayoutParams(dp(44), dp(44)),
        )
        row.addView(
            TextView(this).apply {
                text = "Omega VPN"
                textSize = 24f
                setTextColor(Palette.TEXT)
                typeface = Typeface.DEFAULT_BOLD
                setPadding(dp(12), 0, 0, 0)
            },
            weightParams(),
        )
        row.addView(
            uiIconButton("⚙", tint = Palette.TEXT) {
                startActivity(Intent(this, SettingsActivity::class.java))
            }
        )
        return row
    }

    private fun statusCard(): View {
        toggleButton = TextView(this).apply {
            gravity = Gravity.CENTER
            textSize = 18f
            typeface = Typeface.DEFAULT_BOLD
            setOnClickListener { onToggle() }
        }
        statusDot = View(this)
        statusText = TextView(this).apply {
            textSize = 16f
            typeface = Typeface.DEFAULT_BOLD
        }
        activeProfileText = TextView(this).apply {
            textSize = 13f
            setTextColor(Palette.MUTED)
            gravity = Gravity.CENTER
            setPadding(0, dp(4), 0, 0)
        }
        hintText = TextView(this).apply {
            textSize = 13f
            setTextColor(Palette.AMBER)
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(10), dp(8), 0)
            visibility = View.GONE
        }

        val statusRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(18), 0, 0)
        }
        statusRow.addView(
            statusDot,
            LinearLayout.LayoutParams(dp(10), dp(10)).apply { rightMargin = dp(8) },
        )
        statusRow.addView(statusText)

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(16), dp(26), dp(16), dp(20))
            background = roundedRect(Palette.PANEL, 14, Palette.BORDER)
        }
        card.addView(toggleButton, LinearLayout.LayoutParams(dp(150), dp(150)))
        card.addView(statusRow)
        card.addView(activeProfileText)
        card.addView(hintText)

        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, dp(14))
            addView(card)
        }
    }

    private fun profilesPanel(): View {
        profileList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val titleRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        titleRow.addView(
            TextView(this).apply {
                text = "Профили"
                textSize = 17f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(Palette.TEXT)
            },
            weightParams(),
        )
        titleRow.addView(uiGhostButton("+ Добавить", Palette.ACCENT) { openEditor(null) })
        return uiPanel(null, titleRow, uiSpace(1, dp(10)), profileList)
    }

    // ------------------------------------------------------------ Profiles --

    private fun renderProfiles() {
        profileList.removeAllViews()
        val profiles = store.loadProfiles()
        if (profiles.isEmpty()) {
            profileList.addView(
                uiLabel("Пока нет ни одного профиля. Нажмите «Добавить» и вставьте код подключения из админки."),
            )
            return
        }
        val activeId = store.activeProfile()?.id
        profiles.forEach { entry ->
            profileList.addView(profileRow(entry, entry.id == activeId))
        }
    }

    private fun profileRow(entry: StoredProfile, active: Boolean): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(10), dp(6), dp(10))
            background = roundedRect(
                if (active) Palette.PANEL_SOFT else Color.TRANSPARENT,
                10,
                if (active) Palette.ACCENT else Palette.BORDER,
            )
            setOnClickListener { selectProfile(entry) }
        }
        row.addView(
            View(this).apply {
                background = circle(
                    if (active) Palette.ACCENT else Color.TRANSPARENT,
                    if (active) Palette.ACCENT else Palette.MUTED,
                )
            },
            LinearLayout.LayoutParams(dp(12), dp(12)).apply { rightMargin = dp(10) },
        )
        val texts = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        texts.addView(
            TextView(this).apply {
                text = entry.name
                textSize = 15f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(Palette.TEXT)
            }
        )
        texts.addView(
            TextView(this).apply {
                text = profileSubtitle(entry.profile)
                textSize = 12f
                setTextColor(Palette.MUTED)
            }
        )
        row.addView(texts, weightParams())
        row.addView(uiIconButton("✎", sizeDp = 36) { openEditor(entry.id) })
        row.addView(uiSpace(dp(6), 1))
        row.addView(uiIconButton("✕", tint = Palette.DANGER, sizeDp = 36) { confirmDelete(entry) })
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, dp(8))
            addView(row)
        }
    }

    private fun profileSubtitle(profile: OmegaProfile): String {
        val extras = buildList {
            if (profile.transport != "auto") add(profile.transport.uppercase())
            if (profile.realityEnabled) add("REALITY")
        }
        val server = profile.server.ifBlank { "сервер не задан" }
        return if (extras.isEmpty()) server else "$server · ${extras.joinToString(" · ")}"
    }

    private fun selectProfile(entry: StoredProfile) {
        if (store.activeProfile()?.id == entry.id) return
        store.setActiveProfileId(entry.id)
        renderProfiles()
        renderState()
        if (stateStore.loadState() != VpnConnectionState.DISCONNECTED) {
            // The service always rebuilds the datapath on a fresh start
            // request, picking up the newly active profile.
            hint("Переподключение с профилем «${entry.name}»…")
            OmegaVpnService.start(this)
        }
    }

    private fun confirmDelete(entry: StoredProfile) {
        AlertDialog.Builder(this)
            .setTitle("Удалить профиль?")
            .setMessage("Профиль «${entry.name}» будет удалён без возможности восстановления.")
            .setPositiveButton("Удалить") { _, _ -> deleteProfile(entry) }
            .setNegativeButton("Отмена", null)
            .show()
    }

    private fun deleteProfile(entry: StoredProfile) {
        val wasActive = store.activeProfile()?.id == entry.id
        store.deleteProfile(entry.id)
        if (wasActive && stateStore.loadState() != VpnConnectionState.DISCONNECTED) {
            OmegaVpnService.disconnect(this)
        }
        renderProfiles()
        renderState()
    }

    private fun openEditor(profileId: String?) {
        val intent = Intent(this, ProfileEditorActivity::class.java)
        if (profileId != null) {
            intent.putExtra(ProfileEditorActivity.EXTRA_PROFILE_ID, profileId)
        }
        startActivity(intent)
    }

    // --------------------------------------------------------------- State --

    private fun renderState() {
        val state = stateStore.loadState()
        val stateColor = when (state) {
            VpnConnectionState.DISCONNECTED -> Palette.MUTED
            VpnConnectionState.CONNECTING, VpnConnectionState.RECONNECTING -> Palette.AMBER
            VpnConnectionState.CONNECTED -> Palette.ACCENT
        }
        statusText.text = when (state) {
            VpnConnectionState.DISCONNECTED -> "Отключено"
            VpnConnectionState.CONNECTING -> "Подключение…"
            VpnConnectionState.RECONNECTING -> "Переподключение…"
            VpnConnectionState.CONNECTED -> "Подключено"
        }
        statusText.setTextColor(stateColor)
        statusDot.background = circle(stateColor, stateColor)
        when (state) {
            VpnConnectionState.DISCONNECTED -> {
                toggleButton.text = "Подключить"
                toggleButton.setTextColor(Palette.ACCENT)
                toggleButton.background = circle(Palette.BG, Palette.ACCENT, strokeDp = 3)
            }
            VpnConnectionState.CONNECTING, VpnConnectionState.RECONNECTING -> {
                toggleButton.text = "Отмена"
                toggleButton.setTextColor(Palette.AMBER)
                toggleButton.background = circle(Palette.BG, Palette.AMBER, strokeDp = 3)
            }
            VpnConnectionState.CONNECTED -> {
                toggleButton.text = "Отключить"
                toggleButton.setTextColor(Palette.BG)
                toggleButton.background = circle(Palette.ACCENT, Palette.ACCENT, strokeDp = 3)
            }
        }
        if (state == VpnConnectionState.CONNECTED) {
            hint(null)
        }
        activeProfileText.text = store.activeProfile()
            ?.let { "Профиль: ${it.name}" }
            ?: "Профиль не выбран"
    }

    private fun hint(message: String?) {
        if (message.isNullOrBlank()) {
            hintText.visibility = View.GONE
        } else {
            hintText.text = message
            hintText.visibility = View.VISIBLE
        }
    }

    // ------------------------------------------------------------- Connect --

    private fun onToggle() {
        when (stateStore.loadState()) {
            VpnConnectionState.DISCONNECTED -> connect()
            else -> {
                hint(null)
                OmegaVpnService.disconnect(this)
            }
        }
    }

    private fun connect() {
        val active = store.activeProfile()
        if (active == null) {
            hint("Сначала добавьте профиль с кодом подключения.")
            openEditor(null)
            return
        }
        val error = active.profile.validationError()
        if (error != null) {
            hint(error)
            return
        }
        hint(null)
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            startActivityForResult(prepareIntent, VPN_REQUEST)
        } else {
            OmegaVpnService.start(this)
        }
    }

    @Deprecated("Deprecated by platform API; kept to avoid AndroidX dependency.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST) {
            if (resultCode == RESULT_OK) {
                OmegaVpnService.start(this)
            } else {
                hint("Нет разрешения на VPN — подключение невозможно.")
            }
        }
    }

    private fun handleIntent(intent: Intent?) {
        if (intent?.action == ACTION_CONNECT) {
            toggleButton.post { connect() }
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < 33) return
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_REQUEST)
    }

    companion object {
        private const val VPN_REQUEST = 42
        private const val NOTIFICATION_REQUEST = 43
        const val ACTION_CONNECT = "vpn.myboroda.omega.CONNECT"
    }
}
