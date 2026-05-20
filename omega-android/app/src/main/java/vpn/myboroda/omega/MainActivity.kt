package vpn.myboroda.omega

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var store: ProfileStore
    private lateinit var appRepository: AppSplitRepository
    private lateinit var statusView: TextView
    private lateinit var codeInput: EditText
    private lateinit var serverInput: EditText
    private lateinit var deviceIdInput: EditText
    private lateinit var tokenInput: EditText
    private lateinit var deviceNameInput: EditText
    private lateinit var transportSpinner: Spinner
    private lateinit var realityCodeInput: EditText
    private lateinit var realityEnabledBox: android.widget.CheckBox
    private lateinit var splitSpinner: Spinner
    private lateinit var splitSummaryView: TextView
    private lateinit var searchInput: EditText
    private lateinit var appList: LinearLayout

    private var selectedPackages: MutableSet<String> = linkedSetOf()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = ProfileStore(this)
        appRepository = AppSplitRepository(this)
        selectedPackages = store.loadSplitSettings().selectedPackages.toMutableSet()

        setContentView(buildContent())
        loadProfileIntoFields()
        requestNotificationPermission()
        refreshAppList()
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun buildContent(): View {
        val root = ScrollView(this).apply {
            setBackgroundColor(COLOR_BG)
            isFillViewport = true
        }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(18), dp(20), dp(24))
        }
        root.addView(column)

        column.addView(header())

        codeInput = input("Paste omega://connect code")
        column.addView(panel("Connection code", codeInput, button("Apply code") { applyConnectionCode() }))

        serverInput = input("Server, for example 72.56.88.224:51820")
        deviceIdInput = input("Device ID")
        tokenInput = input("Device token")
        deviceNameInput = input("Device name")
        transportSpinner = spinner(listOf("auto", "udp", "tcp"))
        column.addView(
            panel(
                "Profile",
                label("Server"),
                serverInput,
                label("Device ID"),
                deviceIdInput,
                label("Device token"),
                tokenInput,
                label("Device name"),
                deviceNameInput,
                label("Transport"),
                transportSpinner,
            )
        )

        realityEnabledBox = android.widget.CheckBox(this).apply {
            text = "Включить обход (REALITY)"
            setTextColor(COLOR_TEXT)
        }
        realityCodeInput = input("Вставьте REALITY-код (omega-reality://...)")
        column.addView(
            panel(
                "Обход блокировок (REALITY)",
                realityEnabledBox,
                label("REALITY-код из админки"),
                realityCodeInput,
                label("Включите переключатель только если в сети режут всё кроме TLS к доверенным сайтам. Один код заменяет все ручные настройки."),
            )
        )

        val actions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            addView(button("Connect") { connect() }, weightParams())
            addView(space(dp(10), 1))
            addView(button("Disconnect") { OmegaVpnService.disconnect(this@MainActivity) }, weightParams())
        }
        column.addView(actions)

        splitSpinner = spinner(listOf("VPN for all except selected", "VPN only for selected"))
        val settings = store.loadSplitSettings()
        splitSpinner.setSelection(if (settings.mode == SplitMode.ONLY_SELECTED) 1 else 0)
        splitSpinner.onItemSelectedListener = SimpleItemSelectedListener {
            store.saveSplitMode(currentSplitMode())
            updateSplitSummary()
        }
        splitSummaryView = label("")
        searchInput = input("Search apps")
        appList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        column.addView(
            panel(
                "Split tunneling",
                label("Mode"),
                splitSpinner,
                splitSummaryView,
                searchInput,
                appList,
            )
        )
        searchInput.addTextChangedListener(simpleTextWatcher { refreshAppList() })

        return root
    }

    private fun header(): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 0, 0, dp(18))
        }
        row.addView(ImageView(this).apply {
            setImageResource(R.drawable.ic_omega_mark)
        }, LinearLayout.LayoutParams(dp(54), dp(54)))
        val texts = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(14), 0, 0, 0)
        }
        texts.addView(TextView(this).apply {
            text = "Omega VPN"
            textSize = 28f
            setTextColor(COLOR_TEXT)
            typeface = Typeface.DEFAULT_BOLD
        })
        statusView = TextView(this).apply {
            text = OmegaNative.bridgeStatus()
            textSize = 14f
            setTextColor(COLOR_MUTED)
        }
        texts.addView(statusView)
        row.addView(texts, weightParams())
        return row
    }

    private fun applyConnectionCode() {
        val result = ConnectionCodeParser.parse(codeInput.text.toString())
        result
            .onSuccess {
                val error = it.validationError()
                if (error != null) {
                    status(error)
                } else {
                    putProfileIntoFields(it)
                    saveProfileFromFields()
                    status("Connection code applied.")
                }
            }
            .onFailure { status(it.message ?: "Connection code is invalid.") }
    }

    private fun connect() {
        val profile = readProfileFromFields()
        val error = profile.validationError()
        if (error != null) {
            status(error)
            return
        }
        saveProfileFromFields()

        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            startActivityForResult(prepareIntent, VPN_REQUEST)
        } else {
            startVpnService()
        }
    }

    @Deprecated("Deprecated by platform API; kept to avoid AndroidX dependency.")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST) {
            if (resultCode == RESULT_OK) {
                startVpnService()
            } else {
                status("VPN permission was denied.")
            }
        }
    }

    private fun startVpnService() {
        status("Connecting...")
        OmegaVpnService.start(this)
    }

    private fun handleIntent(intent: Intent?) {
        if (intent?.action == ACTION_CONNECT) {
            statusView.post { connect() }
        }
    }

    private fun saveProfileFromFields() {
        store.saveProfile(readProfileFromFields())
        store.saveSplitMode(currentSplitMode())
        store.saveSelectedPackages(selectedPackages)
    }

    private fun loadProfileIntoFields() {
        putProfileIntoFields(store.loadProfile())
    }

    private fun putProfileIntoFields(profile: OmegaProfile) {
        serverInput.setText(profile.server)
        deviceIdInput.setText(profile.deviceId)
        tokenInput.setText(profile.deviceToken)
        deviceNameInput.setText(profile.deviceName)
        transportSpinner.setSelection(
            listOf("auto", "udp", "tcp").indexOf(profile.transport).coerceAtLeast(0)
        )
        realityCodeInput.setText(profile.realityCode)
        realityEnabledBox.isChecked = profile.realityEnabled
    }

    private fun readProfileFromFields(): OmegaProfile {
        return OmegaProfile(
            server = serverInput.text.toString(),
            deviceId = deviceIdInput.text.toString(),
            deviceToken = tokenInput.text.toString(),
            deviceName = deviceNameInput.text.toString(),
            transport = transportSpinner.selectedItem?.toString() ?: "auto",
            realityCode = realityCodeInput.text.toString(),
            realityEnabled = realityEnabledBox.isChecked,
        ).normalized()
    }

    private fun currentSplitMode(): SplitMode {
        return if (splitSpinner.selectedItemPosition == 1) SplitMode.ONLY_SELECTED else SplitMode.EXCLUDE_SELECTED
    }

    private fun refreshAppList() {
        appList.removeAllViews()
        val apps = appRepository.loadInternetApps(selectedPackages, searchInput.text.toString())
        updateSplitSummary()
        if (apps.isEmpty()) {
            appList.addView(label("No apps found."))
            return
        }

        apps.forEach { app ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding(0, dp(8), 0, dp(8))
            }
            val checkBox = CheckBox(this).apply {
                isChecked = app.selected
                isEnabled = app.selectable
                buttonTintList = android.content.res.ColorStateList.valueOf(COLOR_ACCENT)
                setOnCheckedChangeListener { _, checked ->
                    if (checked) selectedPackages.add(app.packageName) else selectedPackages.remove(app.packageName)
                    store.saveSelectedPackages(selectedPackages)
                    updateSplitSummary()
                }
            }
            row.addView(checkBox)
            val text = TextView(this).apply {
                val markers = buildList {
                    if (app.system) add("system")
                    if (!app.launchable) add("background")
                    if (!app.selectable) add("Omega")
                }
                val suffix = markers.takeIf { it.isNotEmpty() }?.joinToString(" · ", " (", ")").orEmpty()
                text = "${app.label}$suffix\n${app.packageName}"
                textSize = 14f
                setTextColor(if (app.selectable) COLOR_TEXT else COLOR_MUTED)
            }
            row.addView(text, weightParams())
            appList.addView(row)
        }
    }

    private fun updateSplitSummary() {
        val count = selectedPackages.count { it != packageName }
        splitSummaryView.text = when (currentSplitMode()) {
            SplitMode.EXCLUDE_SELECTED -> "$count app(s) bypass VPN when it is connected."
            SplitMode.ONLY_SELECTED -> "$count app(s) are allowed to use VPN."
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < 33) return
        if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
        requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_REQUEST)
    }

    private fun panel(title: String, vararg children: View): View {
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(14), dp(16), dp(16))
            background = rounded(COLOR_PANEL, dp(8), COLOR_BORDER)
        }
        box.addView(TextView(this).apply {
            text = title
            textSize = 17f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(COLOR_TEXT)
        })
        box.addView(space(1, dp(10)))
        children.forEach { box.addView(it) }
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, 0, 0, dp(14))
            addView(box)
        }
    }

    private fun input(hintText: String): EditText {
        return EditText(this).apply {
            hint = hintText
            textSize = 15f
            setSingleLine(false)
            minLines = 1
            maxLines = 3
            setTextColor(COLOR_TEXT)
            setHintTextColor(COLOR_MUTED)
            setPadding(dp(12), dp(10), dp(12), dp(10))
            background = rounded(Color.TRANSPARENT, dp(8), COLOR_BORDER)
        }
    }

    private fun spinner(items: List<String>): Spinner {
        return Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, items)
            background = rounded(Color.TRANSPARENT, dp(8), COLOR_BORDER)
            setPadding(dp(8), dp(6), dp(8), dp(6))
        }
    }

    private fun button(textValue: String, onClick: () -> Unit): Button {
        return Button(this).apply {
            text = textValue
            textSize = 14f
            setTextColor(COLOR_BG)
            typeface = Typeface.DEFAULT_BOLD
            background = rounded(COLOR_ACCENT, dp(8), COLOR_ACCENT)
            setOnClickListener { onClick() }
        }
    }

    private fun label(textValue: String): TextView {
        return TextView(this).apply {
            text = textValue
            textSize = 13f
            setTextColor(COLOR_MUTED)
            setPadding(0, dp(8), 0, dp(5))
        }
    }

    private fun status(message: String) {
        statusView.text = message
    }

    private fun rounded(color: Int, radius: Int, strokeColor: Int): GradientDrawable {
        return GradientDrawable().apply {
            setColor(color)
            cornerRadius = radius.toFloat()
            setStroke(dp(1), strokeColor)
        }
    }

    private fun space(width: Int, height: Int): View {
        return View(this).apply {
            layoutParams = LinearLayout.LayoutParams(width, height)
        }
    }

    private fun weightParams(): LinearLayout.LayoutParams {
        return LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun simpleTextWatcher(onChange: () -> Unit): TextWatcher {
        return object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = onChange()
            override fun afterTextChanged(s: Editable?) = Unit
        }
    }

    companion object {
        private const val VPN_REQUEST = 42
        private const val NOTIFICATION_REQUEST = 43
        const val ACTION_CONNECT = "vpn.myboroda.omega.CONNECT"
        private val COLOR_BG = Color.rgb(17, 20, 24)
        private val COLOR_PANEL = Color.rgb(26, 32, 39)
        private val COLOR_BORDER = Color.rgb(43, 52, 64)
        private val COLOR_TEXT = Color.rgb(238, 244, 247)
        private val COLOR_MUTED = Color.rgb(152, 167, 179)
        private val COLOR_ACCENT = Color.rgb(54, 211, 153)
    }
}

private class SimpleItemSelectedListener(private val onSelected: () -> Unit) :
    android.widget.AdapterView.OnItemSelectedListener {
    override fun onItemSelected(
        parent: android.widget.AdapterView<*>?,
        view: View?,
        position: Int,
        id: Long,
    ) = onSelected()

    override fun onNothingSelected(parent: android.widget.AdapterView<*>?) = Unit
}
