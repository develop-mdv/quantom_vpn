package vpn.myboroda.omega

import android.net.Uri
import android.util.Base64
import org.json.JSONObject

enum class SplitMode {
    EXCLUDE_SELECTED,
    ONLY_SELECTED;

    companion object {
        fun fromStored(value: String?): SplitMode {
            return entries.firstOrNull { it.name == value } ?: EXCLUDE_SELECTED
        }
    }
}

data class OmegaProfile(
    val server: String = "",
    val deviceId: String = "",
    val deviceToken: String = "",
    val deviceName: String = "android",
    val transport: String = "auto",
    // REALITY (TLS masquerade) — single self-contained code from the admin UI,
    // plus a user toggle. When realityEnabled is true the client uses
    // transport="reality" internally regardless of the UDP/TCP setting.
    val realityCode: String = "",
    val realityEnabled: Boolean = false,
) {
    fun normalized(): OmegaProfile {
        return copy(
            server = server.trim(),
            deviceId = deviceId.trim(),
            deviceToken = deviceToken.trim(),
            deviceName = deviceName.trim().ifEmpty { "android" },
            transport = normalizeTransport(transport),
            realityCode = realityCode.trim(),
        )
    }

    fun validationError(): String? {
        val normalized = normalized()
        if (normalized.server.isBlank()) return "Server is required."
        if (normalized.deviceId.isBlank()) return "Device ID is required."
        if (!UUID_RE.matches(normalized.deviceId)) return "Device ID must be a UUID."
        if (!TOKEN_RE.matches(normalized.deviceToken)) {
            return "Device token must be 64 hex characters."
        }
        if (normalized.realityEnabled) {
            if (normalized.realityCode.isBlank()) {
                return "Вставьте REALITY-код из админки — без него обход не включится."
            }
            if (!isValidRealityCode(normalized.realityCode)) {
                return "REALITY-код некорректен. Скопируйте свежий код из админки заново."
            }
        }
        return null
    }

    /// Effective transport that the native bridge actually consumes:
    /// "reality" overrides whatever the user selected when the toggle is on.
    fun effectiveTransport(): String = if (realityEnabled) "reality" else transport

    /// Parsed pieces of the REALITY-код (for the native side which still
    /// takes 5 explicit fields). Returns null if no code is present or
    /// parsing failed.
    fun realityFields(): RealityFields? {
        if (realityCode.isBlank()) return null
        return runCatching { parseRealityCode(realityCode) }.getOrNull()
    }

    companion object {
        private val UUID_RE =
            Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        private val TOKEN_RE = Regex("^[0-9a-fA-F]{64}$")
    }
}

data class RealityFields(
    val server: String,
    val sni: String,
    val pubkey: String,
    val shortId: String,
    val fingerprint: String,
)

private fun isValidRealityCode(code: String): Boolean {
    return runCatching { parseRealityCode(code) }.isSuccess
}

private fun parseRealityCode(code: String): RealityFields {
    val trimmed = code.trim()
    require(trimmed.startsWith("omega-reality://", ignoreCase = true)) {
        "REALITY code must start with omega-reality://"
    }
    val payload = trimmed.substring("omega-reality://".length)
    var b64 = payload.replace('-', '+').replace('_', '/')
    when (b64.length % 4) {
        2 -> b64 += "=="
        3 -> b64 += "="
    }
    val bytes = android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
    val json = JSONObject(String(bytes, Charsets.UTF_8))
    val server = json.optString("server").trim()
    val sni = json.optString("sni").trim()
    val pubkey = json.optString("pubkey").trim()
    val shortId = json.optString("short_id").trim()
    val fp = json.optString("fp").ifBlank { "chrome_131" }
    require(server.isNotBlank()) { "REALITY code: server missing" }
    require(sni.isNotBlank()) { "REALITY code: sni missing" }
    require(pubkey.isNotBlank()) { "REALITY code: pubkey missing" }
    val pkBytes = android.util.Base64.decode(pubkey, android.util.Base64.DEFAULT)
    require(pkBytes.size == 32) { "REALITY code: pubkey must be 32 bytes" }
    return RealityFields(server, sni, pubkey, shortId, fp)
}

data class SplitSettings(
    val mode: SplitMode = SplitMode.EXCLUDE_SELECTED,
    val selectedPackages: Set<String> = emptySet(),
)

data class NativeHandshakeConfig(
    val handle: Long,
    val tunnelIpv4: String,
    val tunnelIpv6: String?,
    val mtu: Int,
    val dnsServers: List<String>,
) {
    companion object {
        fun fromJson(json: String): NativeHandshakeResult {
            return runCatching {
                val root = JSONObject(json)
                val ok = root.optBoolean("ok", false)
                val message = root.optString("message", "")
                if (!ok) {
                    return@runCatching NativeHandshakeResult(false, null, message.ifBlank { "Native handshake failed." })
                }
                val dns = root.optJSONArray("dnsServers")
                val dnsServers = buildList {
                    if (dns != null) {
                        for (index in 0 until dns.length()) {
                            val value = dns.optString(index).trim()
                            if (value.isNotEmpty()) add(value)
                        }
                    }
                }
                NativeHandshakeResult(
                    ok = true,
                    config = NativeHandshakeConfig(
                        handle = root.optLong("handle", 0L),
                        tunnelIpv4 = root.optString("tunnelIpv4"),
                        tunnelIpv6 = root.optString("tunnelIpv6").takeIf { it.isNotBlank() && it != "null" },
                        mtu = root.optInt("mtu", 1280),
                        dnsServers = dnsServers.ifEmpty { listOf("1.1.1.1", "8.8.8.8") },
                    ),
                    message = message,
                )
            }.getOrElse {
                NativeHandshakeResult(false, null, "Native response was invalid: ${it.message}")
            }
        }
    }
}

object ConnectionCodeParser {
    fun parse(input: String): Result<OmegaProfile> {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return Result.failure(IllegalArgumentException("Connection code is empty."))

        return when {
            trimmed.contains("OMEGA_", ignoreCase = true) -> parseEnv(trimmed)
            trimmed.startsWith("{") -> parseJson(trimmed)
            trimmed.startsWith("omega://", ignoreCase = true) -> parseOmegaUri(trimmed)
            trimmed.startsWith("omega:", ignoreCase = true) -> parseCompact(trimmed.removePrefix("omega:"))
            else -> parseCompact(trimmed)
        }.map { it.normalized() }
    }

    private fun parseOmegaUri(value: String): Result<OmegaProfile> {
        val uri = Uri.parse(value)
        val server = uri.getQueryParameter("server")
        if (server != null) {
            return Result.success(
                OmegaProfile(
                    server = server,
                    deviceId = uri.firstQuery("device_id", "id", "omega_device_id"),
                    deviceToken = uri.firstQuery("token", "device_token", "omega_device_token"),
                    deviceName = uri.firstQuery("device_name", "name", fallback = "android"),
                    transport = uri.firstQuery("transport", "omega_transport", fallback = "auto"),
                    realityCode = uri.firstQuery("reality_code", "omega_reality_code"),
                )
            )
        }

        val payload = uri.pathSegments.firstOrNull().orEmpty()
        return parseCompact(payload)
    }

    private fun parseCompact(payload: String): Result<OmegaProfile> {
        return runCatching {
            val clean = payload.substringBefore('?').substringBefore('#')
            val padded = clean.padEnd(clean.length + ((4 - clean.length % 4) % 4), '=')
            val bytes = Base64.decode(padded, Base64.URL_SAFE or Base64.NO_WRAP)
            parseJson(String(bytes, Charsets.UTF_8)).getOrThrow()
        }.recoverCatching {
            throw IllegalArgumentException("Connection code is not recognized.")
        }
    }

    private fun parseJson(json: String): Result<OmegaProfile> {
        return runCatching {
            val root = JSONObject(json)
            OmegaProfile(
                server = root.firstString("server", "server_endpoint", "omega_server"),
                deviceId = root.firstString("device_id", "id", "omega_device_id"),
                deviceToken = root.firstString("token", "device_token", "omega_device_token"),
                deviceName = root.firstString("device_name", "name", "omega_device_name", fallback = "android"),
                transport = root.firstString("transport", "omega_transport", fallback = "auto"),
                realityCode = root.firstString("reality_code", "omega_reality_code"),
            )
        }
    }

    private fun parseEnv(text: String): Result<OmegaProfile> {
        return runCatching {
            val values = text
                .replace("\r\n", "\n")
                .lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") && it.contains("=") }
                .associate {
                    val key = it.substringBefore('=').trim().uppercase()
                    val value = it.substringAfter('=').trim().trim('"', '\'')
                    key to value
                }

            OmegaProfile(
                server = values["OMEGA_SERVER"].orEmpty(),
                deviceId = values["OMEGA_DEVICE_ID"].orEmpty(),
                deviceToken = values["OMEGA_DEVICE_TOKEN"].orEmpty(),
                deviceName = values["OMEGA_DEVICE_NAME"] ?: "android",
                transport = values["OMEGA_TRANSPORT"] ?: "auto",
                realityCode = values["OMEGA_REALITY_CODE"].orEmpty(),
            )
        }
    }
}

private fun normalizeTransport(value: String): String {
    return when (value.trim().lowercase()) {
        "udp" -> "udp"
        "tcp" -> "tcp"
        else -> "auto"
    }
}

private fun Uri.firstQuery(vararg names: String, fallback: String = ""): String {
    for (name in names) {
        val value = getQueryParameter(name)
        if (!value.isNullOrBlank()) return value.trim()
    }
    return fallback
}

private fun JSONObject.firstString(vararg names: String, fallback: String = ""): String {
    for (name in names) {
        if (has(name) && !isNull(name)) {
            val value = optString(name).trim()
            if (value.isNotEmpty()) return value
        }
    }
    return fallback
}
