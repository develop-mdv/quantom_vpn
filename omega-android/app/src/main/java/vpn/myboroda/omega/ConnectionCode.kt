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
    // REALITY (XTLS-style TLS masquerade). Only consumed when transport == "reality".
    val realityServer: String = "",
    val realitySni: String = "",
    val realityServerPubkey: String = "",
    val realityShortId: String = "",
    val realityFingerprint: String = "chrome_131",
) {
    fun normalized(): OmegaProfile {
        return copy(
            server = server.trim(),
            deviceId = deviceId.trim(),
            deviceToken = deviceToken.trim(),
            deviceName = deviceName.trim().ifEmpty { "android" },
            transport = normalizeTransport(transport),
            realityServer = realityServer.trim(),
            realitySni = realitySni.trim(),
            realityServerPubkey = realityServerPubkey.trim(),
            realityShortId = realityShortId.trim(),
            realityFingerprint = realityFingerprint.trim().ifEmpty { "chrome_131" },
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
        if (normalized.transport == "reality") {
            if (normalized.realitySni.isBlank()) {
                return "REALITY SNI is required when transport=reality."
            }
            if (normalized.realityServerPubkey.isBlank()) {
                return "REALITY server pubkey is required when transport=reality."
            }
            if (!PUBKEY_B64_RE.matches(normalized.realityServerPubkey)) {
                return "REALITY server pubkey must be base64 (32 bytes = 44 chars)."
            }
            if (normalized.realityShortId.isNotBlank() && !SHORT_ID_RE.matches(normalized.realityShortId)) {
                return "REALITY short_id must be 16 hex chars (or empty)."
            }
        }
        return null
    }

    companion object {
        private val UUID_RE =
            Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        private val TOKEN_RE = Regex("^[0-9a-fA-F]{64}$")
        private val PUBKEY_B64_RE = Regex("^[A-Za-z0-9+/]{43}=$")
        private val SHORT_ID_RE = Regex("^[0-9a-fA-F]{16}$")
    }
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
                    realityServer = uri.firstQuery("reality_server", "omega_reality_server"),
                    realitySni = uri.firstQuery("reality_sni", "omega_reality_sni"),
                    realityServerPubkey = uri.firstQuery("reality_server_pubkey", "omega_reality_server_pubkey"),
                    realityShortId = uri.firstQuery("reality_short_id", "omega_reality_short_id"),
                    realityFingerprint = uri.firstQuery("reality_fingerprint", "omega_reality_fingerprint", fallback = "chrome_131"),
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
                realityServer = root.firstString("reality_server", "omega_reality_server"),
                realitySni = root.firstString("reality_sni", "omega_reality_sni"),
                realityServerPubkey = root.firstString("reality_server_pubkey", "omega_reality_server_pubkey"),
                realityShortId = root.firstString("reality_short_id", "omega_reality_short_id"),
                realityFingerprint = root.firstString("reality_fingerprint", "omega_reality_fingerprint", fallback = "chrome_131"),
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
                realityServer = values["OMEGA_REALITY_SERVER"].orEmpty(),
                realitySni = values["OMEGA_REALITY_SNI"].orEmpty(),
                realityServerPubkey = values["OMEGA_REALITY_SERVER_PUBKEY"].orEmpty(),
                realityShortId = values["OMEGA_REALITY_SHORT_ID"].orEmpty(),
                realityFingerprint = values["OMEGA_REALITY_FINGERPRINT"] ?: "chrome_131",
            )
        }
    }
}

private fun normalizeTransport(value: String): String {
    return when (value.trim().lowercase()) {
        "udp" -> "udp"
        "tcp" -> "tcp"
        "reality", "xtls" -> "reality"
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
