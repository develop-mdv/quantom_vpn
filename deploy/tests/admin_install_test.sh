#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REPO_ROOT/install.sh"
source "$REPO_ROOT/deploy/setup_admin.sh"
BINARY="$(realpath "${1:?Pass the built omega-server binary}")"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEST_DIR"' EXIT
touch "$TEST_DIR/server.env"
export OMEGA_PUBLIC_HOST=203.0.113.10 OMEGA_VPN_PORT=443 OMEGA_TCP_PORT=443
configure_admin "$TEST_DIR/server.env" "$TEST_DIR/state" "$BINARY" "$TEST_DIR/credentials.json"
python3 - "$TEST_DIR" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
initial = json.loads((root / 'credentials.json').read_text())
stored = (root / 'state/admin-auth.json').read_text()
assert initial['created'] and len(initial['password']) >= 32
assert initial['password'] not in stored
assert 'OMEGA_CLIENT_SERVER=203.0.113.10:443' in (root / 'server.env').read_text()
assert 'OMEGA_ADMIN_WEB_BIND=[::]:8443' in (root / 'server.env').read_text()
assert (root / 'state/admin-auth.json').stat().st_mode & 0o777 == 0o600
assert (root / 'state/admin-tls/key.der').stat().st_mode & 0o777 == 0o600
PY
openssl x509 -inform DER -in "$TEST_DIR/state/admin-tls/cert.der" -checkip "$OMEGA_PUBLIC_HOST" -noout >/dev/null
sha256sum "$TEST_DIR/state/admin-auth.json" "$TEST_DIR/state/admin-tls/cert.der" > "$TEST_DIR/before"
configure_admin "$TEST_DIR/server.env" "$TEST_DIR/state" "$BINARY" "$TEST_DIR/reinstall.json"
sha256sum --check "$TEST_DIR/before" >/dev/null
python3 - "$TEST_DIR/reinstall.json" <<'PY'
import json, sys
output = json.load(open(sys.argv[1]))
assert output['created'] is False and 'password' not in output
PY
[[ "$(grep -c '^OMEGA_ADMIN_WEB_BIND=' "$TEST_DIR/server.env")" == 1 ]]
echo "PASS: HTTPS certificate, initial credentials, private permissions and reinstall preservation"

# A certificate with one day left must be replaced immediately, before expiry.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$OMEGA_PUBLIC_HOST" \
    -addext "subjectAltName=IP:$OMEGA_PUBLIC_HOST" -keyout "$TEST_DIR/short-key.pem" -out "$TEST_DIR/short-cert.pem" 2>/dev/null
openssl x509 -in "$TEST_DIR/short-cert.pem" -outform DER -out "$TEST_DIR/state/admin-tls/cert.der"
openssl pkcs8 -topk8 -nocrypt -in "$TEST_DIR/short-key.pem" -outform DER -out "$TEST_DIR/state/admin-tls/key.der"
ensure_admin_certificate "$TEST_DIR/state/admin-tls" "$OMEGA_PUBLIC_HOST"
[[ "$CERT_RENEWED" == 1 ]]
openssl x509 -inform DER -in "$TEST_DIR/state/admin-tls/cert.der" -checkend 2592000 -noout >/dev/null
ensure_admin_certificate "$TEST_DIR/state/admin-tls" "$OMEGA_PUBLIC_HOST"
[[ "$CERT_RENEWED" == 0 ]]
echo "PASS: certificate nearing expiry renewed, fresh certificate preserved"

if command -v systemd-analyze >/dev/null; then
    cp "$REPO_ROOT/deploy/setup_admin.sh" "$REPO_ROOT/deploy/renew_admin_tls.sh" "$TEST_DIR/"
    chmod +x "$TEST_DIR/"*.sh
    ln -s "$BINARY" "$TEST_DIR/omega-server"
    for unit in omega-server.service omega-admin-tls-renew.service omega-admin-tls-renew.timer; do
        sed "s|/opt/omega|$TEST_DIR|g" "$REPO_ROOT/deploy/$unit" > "$TEST_DIR/$unit"
    done
    systemd-analyze verify "$TEST_DIR/omega-server.service" "$TEST_DIR/omega-admin-tls-renew.service" "$TEST_DIR/omega-admin-tls-renew.timer"
    echo "PASS: server and persistent renewal timer unit definitions"
fi
