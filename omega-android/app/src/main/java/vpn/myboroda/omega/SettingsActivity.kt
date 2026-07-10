package vpn.myboroda.omega

import android.app.Activity
import android.content.res.ColorStateList
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView

/// Everything that is not "pick a profile and connect": the REALITY bypass
/// (stored on the active profile) and split tunneling (global).
class SettingsActivity : Activity() {
    private lateinit var store: ProfileStore
    private lateinit var appRepository: AppSplitRepository

    @Suppress("DEPRECATION")
    private lateinit var realitySwitch: android.widget.Switch
    private lateinit var realityCodeInput: EditText
    private lateinit var realityHint: TextView

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
        loadReality()
        refreshAppList()
    }

    override fun onPause() {
        // Covers back navigation and app switches — the code field has no
        // explicit save button.
        saveReality()
        super.onPause()
    }

    private fun buildContent(): View {
        val root = uiScreenRoot()
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(16), dp(20), dp(24))
        }
        root.addView(column)

        column.addView(screenHeader("Настройки"))

        @Suppress("DEPRECATION") // platform Switch keeps the app androidx-free (min SDK 23).
        realitySwitch = android.widget.Switch(this).apply {
            text = "Включить обход (REALITY)"
            setTextColor(Palette.TEXT)
            textSize = 16f
            showText = false
            setOnCheckedChangeListener { _, _ -> saveReality() }
        }
        realityCodeInput = uiInput("Вставьте REALITY-код (omega-reality://…)")
        realityHint = TextView(this).apply {
            textSize = 13f
            setTextColor(Palette.DANGER)
            setPadding(0, dp(6), 0, 0)
            visibility = View.GONE
        }
        column.addView(
            uiPanel(
                "Обход блокировок (REALITY)",
                realitySwitch,
                uiLabel("REALITY-код из админки"),
                realityCodeInput,
                uiLabel(
                    "Настройка хранится в активном профиле. Включайте, только если в сети режут всё, " +
                        "кроме TLS к доверенным сайтам. Изменения применяются при следующем подключении.",
                ),
                realityHint,
            )
        )

        splitSpinner = uiSpinner(listOf("VPN для всех, кроме выбранных", "VPN только для выбранных"))
        val settings = store.loadSplitSettings()
        splitSpinner.setSelection(if (settings.mode == SplitMode.ONLY_SELECTED) 1 else 0)
        splitSpinner.onItemSelectedListener = SimpleItemSelectedListener {
            store.saveSplitMode(currentSplitMode())
            updateSplitSummary()
        }
        splitSummaryView = uiLabel("")
        searchInput = uiInput("Поиск приложений")
        appList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        column.addView(
            uiPanel(
                "Раздельный туннель",
                uiLabel("Режим"),
                splitSpinner,
                splitSummaryView,
                searchInput,
                appList,
            )
        )
        searchInput.addTextChangedListener(simpleTextWatcher { refreshAppList() })
        return root
    }

    // -------------------------------------------------------------- REALITY --

    private fun loadReality() {
        val active = store.activeProfile()
        if (active == null) {
            realitySwitch.isEnabled = false
            realityCodeInput.isEnabled = false
            realityHint.text = "Сначала добавьте профиль на главном экране."
            realityHint.visibility = View.VISIBLE
            return
        }
        realitySwitch.isChecked = active.profile.realityEnabled
        realityCodeInput.setText(active.profile.realityCode)
    }

    private fun saveReality() {
        if (store.activeProfile() == null) return
        val code = realityCodeInput.text.toString().trim()
        val enabled = realitySwitch.isChecked
        store.updateActiveProfile { it.copy(realityEnabled = enabled, realityCode = code) }
        val problem = when {
            !enabled -> null
            code.isEmpty() -> "Вставьте REALITY-код из админки — без него обход не включится."
            OmegaProfile(realityCode = code).realityFields() == null ->
                "REALITY-код некорректен. Скопируйте свежий код из админки заново."
            else -> null
        }
        if (problem == null) {
            realityHint.visibility = View.GONE
        } else {
            realityHint.text = problem
            realityHint.visibility = View.VISIBLE
        }
    }

    // ----------------------------------------------------- Split tunneling --

    private fun currentSplitMode(): SplitMode {
        return if (splitSpinner.selectedItemPosition == 1) SplitMode.ONLY_SELECTED else SplitMode.EXCLUDE_SELECTED
    }

    private fun refreshAppList() {
        appList.removeAllViews()
        val apps = appRepository.loadInternetApps(selectedPackages, searchInput.text.toString())
        updateSplitSummary()
        if (apps.isEmpty()) {
            appList.addView(uiLabel("Приложения не найдены."))
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
                buttonTintList = ColorStateList.valueOf(Palette.ACCENT)
                setOnCheckedChangeListener { _, checked ->
                    if (checked) selectedPackages.add(app.packageName) else selectedPackages.remove(app.packageName)
                    store.saveSelectedPackages(selectedPackages)
                    updateSplitSummary()
                }
            }
            row.addView(checkBox)
            val text = TextView(this).apply {
                val markers = buildList {
                    if (app.system) add("системное")
                    if (!app.launchable) add("фоновое")
                    if (!app.selectable) add("Omega")
                }
                val suffix = markers.takeIf { it.isNotEmpty() }?.joinToString(" · ", " (", ")").orEmpty()
                text = "${app.label}$suffix\n${app.packageName}"
                textSize = 14f
                setTextColor(if (app.selectable) Palette.TEXT else Palette.MUTED)
            }
            row.addView(text, weightParams())
            appList.addView(row)
        }
    }

    private fun updateSplitSummary() {
        val count = selectedPackages.count { it != packageName }
        splitSummaryView.text = when (currentSplitMode()) {
            SplitMode.EXCLUDE_SELECTED -> "Приложений в обход VPN: $count"
            SplitMode.ONLY_SELECTED -> "Приложений через VPN: $count"
        }
    }
}
