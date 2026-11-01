#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REPO_ROOT/deploy/setup_admin.sh"
BINARY="$(realpath "${1:?Pass the built omega-server binary}")"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEST_DIR"' EXIT
export OMEGA_PUBLIC_HOST=203.0.113.10 OMEGA_ADMIN_TLS_MODE=letsencrypt
export OMEGA_CERTBOT_HOME="$TEST_DIR/certbot" OMEGA_ACME_STATE_DIR="$TEST_DIR/state/acme"
export CERTBOT_PROBE_DIR="$TEST_DIR" SSL_CERT_FILE="$TEST_DIR/ca.pem"
mkdir -p "$OMEGA_CERTBOT_HOME/bin" "$TEST_DIR/fixture"
touch "$TEST_DIR/server.env"

openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=Omega-Test-CA \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$TEST_DIR/ca-key.pem" -out "$SSL_CERT_FILE" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$OMEGA_PUBLIC_HOST" \
    -addext "subjectAltName=IP:$OMEGA_PUBLIC_HOST" -keyout "$TEST_DIR/leaf-key.pem" -out "$TEST_DIR/leaf.csr" 2>/dev/null
openssl x509 -req -in "$TEST_DIR/leaf.csr" -CA "$SSL_CERT_FILE" -CAkey "$TEST_DIR/ca-key.pem" \
    -CAcreateserial -days 6 -sha256 -copy_extensions copy -out "$TEST_DIR/leaf.pem" 2>/dev/null
cat "$TEST_DIR/leaf.pem" "$SSL_CERT_FILE" > "$TEST_DIR/fixture/fullchain.pem"
openssl ec -in "$TEST_DIR/leaf-key.pem" -out "$TEST_DIR/fixture/privkey.pem" 2>/dev/null

cat > "$OMEGA_CERTBOT_HOME/bin/certbot" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == --version ]]; then echo 'certbot 5.9.0'; exit 0; fi
config=""; profile=""; ip=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config-dir) config="$2"; shift ;;
        --required-profile) profile="$2"; shift ;;
        --ip-address) ip="$2"; shift ;;
    esac
    shift
done
[[ "$profile" == shortlived && "$ip" == "$OMEGA_PUBLIC_HOST" && -n "$config" ]]
printf 'issue\n' >> "$CERTBOT_PROBE_DIR/certbot.calls"
mkdir -p "$config/live/omega-admin"
cp "$CERTBOT_PROBE_DIR/fixture/"*.pem "$config/live/omega-admin/"
STUB
chmod +x "$OMEGA_CERTBOT_HOME/bin/certbot"

configure_admin "$TEST_DIR/server.env" "$TEST_DIR/state" "$BINARY" "$TEST_DIR/credentials.json"
[[ "$(wc -l < "$TEST_DIR/certbot.calls")" == 1 ]]
[[ "$ADMIN_CERT_FILE" == "$TEST_DIR/state/admin-tls/fullchain.pem" ]]
[[ "$ADMIN_KEY_FILE" == "$TEST_DIR/state/admin-tls/privkey.pem" ]]
[[ "$(stat -c %a "$ADMIN_KEY_FILE")" == 600 ]]
result="$(OMEGA_ADMIN_TLS_CERT="$ADMIN_CERT_FILE" OMEGA_ADMIN_TLS_KEY="$ADMIN_KEY_FILE" "$BINARY" admin check_web_tls)"
python3 -c 'import json,sys; assert json.loads(sys.argv[1])["certificate_chain_length"] == 2' "$result"
sha256sum "$TEST_DIR/state/admin-auth.json" > "$TEST_DIR/auth-before"
configure_admin "$TEST_DIR/server.env" "$TEST_DIR/state" "$BINARY" "$TEST_DIR/reinstall.json"
[[ "$(wc -l < "$TEST_DIR/certbot.calls")" == 1 ]]
sha256sum --check "$TEST_DIR/auth-before" >/dev/null
grep -q '^OMEGA_ADMIN_TLS_HOT_RELOAD=1$' "$TEST_DIR/server.env"
echo 'PASS: trusted IP chain, EC private key, automatic configuration and reinstall preservation'

openssl x509 -req -in "$TEST_DIR/leaf.csr" -CA "$SSL_CERT_FILE" -CAkey "$TEST_DIR/ca-key.pem" \
    -CAcreateserial -days 1 -sha256 -copy_extensions copy -out "$TEST_DIR/short.pem" 2>/dev/null
cat "$TEST_DIR/short.pem" "$SSL_CERT_FILE" > "$ADMIN_CERT_FILE"
ensure_admin_certificate "$TEST_DIR/state/admin-tls" "$OMEGA_PUBLIC_HOST"
[[ "$CERT_RENEWED" == 1 && "$(wc -l < "$TEST_DIR/certbot.calls")" == 2 ]]
pem_certificate_ready "$ADMIN_CERT_FILE" "$ADMIN_KEY_FILE" "$OMEGA_PUBLIC_HOST"
ensure_admin_certificate "$TEST_DIR/state/admin-tls" "$OMEGA_PUBLIC_HOST"
[[ "$CERT_RENEWED" == 0 && "$(wc -l < "$TEST_DIR/certbot.calls")" == 2 ]]
echo 'PASS: short-lived certificate renewed before expiry; fresh certificate is reused'

# A valid chain for another IP must be rejected without replacing the current pair.
openssl req -new -key "$TEST_DIR/leaf-key.pem" -subj /CN=203.0.113.11 \
    -addext subjectAltName=IP:203.0.113.11 -out "$TEST_DIR/wrong.csr" 2>/dev/null
openssl x509 -req -in "$TEST_DIR/wrong.csr" -CA "$SSL_CERT_FILE" -CAkey "$TEST_DIR/ca-key.pem" \
    -CAcreateserial -days 6 -sha256 -copy_extensions copy -out "$TEST_DIR/wrong.pem" 2>/dev/null
cat "$TEST_DIR/wrong.pem" "$SSL_CERT_FILE" > "$TEST_DIR/fixture/fullchain.pem"
cat "$TEST_DIR/short.pem" "$SSL_CERT_FILE" > "$ADMIN_CERT_FILE"
sha256sum "$ADMIN_CERT_FILE" "$ADMIN_KEY_FILE" > "$TEST_DIR/tls-before-failure"
if (ensure_admin_certificate "$TEST_DIR/state/admin-tls" "$OMEGA_PUBLIC_HOST") >/dev/null 2>&1; then
    echo 'FAIL: certificate for another IP was accepted' >&2
    exit 1
fi
sha256sum --check "$TEST_DIR/tls-before-failure" >/dev/null
echo 'PASS: wrong-IP issuance rejected and existing certificate/key preserved'
