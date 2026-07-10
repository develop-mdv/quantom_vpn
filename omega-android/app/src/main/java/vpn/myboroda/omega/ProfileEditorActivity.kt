package vpn.myboroda.omega

import android.app.Activity
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import java.util.UUID

/// Add/edit screen for a single profile. The quickest path is pasting an
/// omega:// connection code — it fills every field; manual entry stays
/// available below for unusual setups.
class ProfileEditorActivity : Activity() {
    private lateinit var store: ProfileStore
    private var existing: StoredProfile? = null

    // REALITY data rides along with connection codes but is edited on the
    // settings screen; carry it through so saving doesn't drop it.
    private var realityCode: String = ""
    private var realityEnabled: Boolean = false

    private lateinit var nameInput: EditText
    private lateinit var codeInput: EditText
    private lateinit var serverInput: EditText
    private lateinit var deviceIdInput: EditText
    private lateinit var tokenInput: EditText
    private lateinit var deviceNameInput: EditText
    private lateinit var transportSpinner: Spinner
    private lateinit var hintText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = ProfileStore(this)
        existing = intent.getStringExtra(EXTRA_PROFILE_ID)
            ?.let { id -> store.loadProfiles().firstOrNull { it.id == id } }
        setContentView(buildContent())
        existing?.let(::fillFrom)
    }

    private fun buildContent(): View {
        val root = uiScreenRoot()
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(16), dp(20), dp(24))
        }
        root.addView(column)

        column.addView(screenHeader(if (existing == null) "Новый профиль" else "Профиль"))

        codeInput = uiInput("Вставьте код omega://…")
        column.addView(
            uiPanel(
                "Код подключения",
                codeInput,
                uiLabel("Код из админки заполняет все поля ниже автоматически."),
                uiSpace(1, dp(6)),
                uiButton("Применить код") { applyCode() },
            )
        )

        nameInput = uiInput("Например: Дом или Работа")
        column.addView(uiPanel("Название профиля", nameInput))

        serverInput = uiInput("Сервер, например 72.56.88.224:51820")
        deviceIdInput = uiInput("Device ID")
        tokenInput = uiInput("Токен устройства")
        deviceNameInput = uiInput("Имя устройства")
        transportSpinner = uiSpinner(TRANSPORTS)
        column.addView(
            uiPanel(
                "Параметры подключения",
                uiLabel("Сервер"),
                serverInput,
                uiLabel("Device ID"),
                deviceIdInput,
                uiLabel("Токен устройства"),
                tokenInput,
                uiLabel("Имя устройства"),
                deviceNameInput,
                uiLabel("Транспорт"),
                transportSpinner,
            )
        )

        hintText = TextView(this).apply {
            textSize = 13f
            setTextColor(Palette.DANGER)
            setPadding(dp(4), 0, dp(4), dp(10))
            visibility = View.GONE
        }
        column.addView(hintText)
        column.addView(
            uiButton("Сохранить профиль") { save() },
            LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ),
        )
        return root
    }

    private fun fillFrom(entry: StoredProfile) {
        nameInput.setText(entry.name)
        putProfileIntoFields(entry.profile)
        realityCode = entry.profile.realityCode
        realityEnabled = entry.profile.realityEnabled
    }

    private fun putProfileIntoFields(profile: OmegaProfile) {
        serverInput.setText(profile.server)
        deviceIdInput.setText(profile.deviceId)
        tokenInput.setText(profile.deviceToken)
        deviceNameInput.setText(profile.deviceName)
        transportSpinner.setSelection(TRANSPORTS.indexOf(profile.transport).coerceAtLeast(0))
    }

    private fun applyCode() {
        ConnectionCodeParser.parse(codeInput.text.toString())
            .onSuccess { profile ->
                // Fill what we got even if incomplete, so the user can fix
                // the remaining fields by hand.
                putProfileIntoFields(profile)
                if (profile.realityCode.isNotBlank()) {
                    realityCode = profile.realityCode
                }
                if (nameInput.text.toString().isBlank()) {
                    nameInput.setText(ProfileStore.defaultProfileName(profile, fallback = suggestedName()))
                }
                val error = profile.validationError()
                if (error != null) {
                    hint(error, Palette.DANGER)
                } else {
                    hint("Код применён — проверьте поля и сохраните.", Palette.ACCENT)
                }
            }
            .onFailure { hint(it.message ?: "Код не распознан.", Palette.DANGER) }
    }

    private fun save() {
        val profile = OmegaProfile(
            server = serverInput.text.toString(),
            deviceId = deviceIdInput.text.toString(),
            deviceToken = tokenInput.text.toString(),
            deviceName = deviceNameInput.text.toString(),
            transport = transportSpinner.selectedItem?.toString() ?: "auto",
            realityCode = realityCode,
            realityEnabled = realityEnabled,
        ).normalized()
        val error = profile.validationError()
        if (error != null) {
            hint(error, Palette.DANGER)
            return
        }
        val id = existing?.id ?: UUID.randomUUID().toString()
        val name = nameInput.text.toString().trim()
            .ifEmpty { ProfileStore.defaultProfileName(profile, fallback = suggestedName()) }
        store.upsertProfile(StoredProfile(id, name, profile))
        // A profile added while the tunnel is down is what the user wants to
        // connect to next — make it active right away. Never steal the
        // selection from a live connection though.
        if (existing == null && VpnStateStore(this).loadState() == VpnConnectionState.DISCONNECTED) {
            store.setActiveProfileId(id)
        }
        finish()
    }

    private fun suggestedName(): String = "Профиль ${store.loadProfiles().size + 1}"

    private fun hint(message: String?, color: Int) {
        if (message.isNullOrBlank()) {
            hintText.visibility = View.GONE
        } else {
            hintText.text = message
            hintText.setTextColor(color)
            hintText.visibility = View.VISIBLE
        }
    }

    companion object {
        const val EXTRA_PROFILE_ID = "profile_id"
        private val TRANSPORTS = listOf("auto", "udp", "tcp")
    }
}
