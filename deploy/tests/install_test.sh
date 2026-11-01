#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$REPO_ROOT/install.sh"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEST_DIR"' EXIT

expect_failure() {
    if (set -e; "$@") > "$TEST_DIR/error.log" 2>&1; then
        echo "FAIL: expected failure: $*" >&2
        exit 1
    fi
}

bash "$REPO_ROOT/install.sh" --help > "$TEST_DIR/help"
grep -q 'v0.1.0' "$TEST_DIR/help"
expect_failure bash "$REPO_ROOT/install.sh" invalid-tag
expect_failure bash "$REPO_ROOT/install.sh" v0.1.0 extra
echo "PASS: help and invalid arguments need no installation"

ASSET="omega-server-linux-x86_64.tar.gz"
printf 'release bundle\n' > "$TEST_DIR/$ASSET"
(
    cd "$TEST_DIR"
    sha256sum "$ASSET" > SHA256SUMS
    printf '%064d  unrelated.apk\n' 0 >> SHA256SUMS
)
verify_download "$TEST_DIR" "$ASSET"
cp "$TEST_DIR/SHA256SUMS" "$TEST_DIR/good-checksums"
printf 'corrupted\n' >> "$TEST_DIR/$ASSET"
expect_failure verify_download "$TEST_DIR" "$ASSET"
echo "PASS: corrupted download rejected"
printf 'release bundle\n' > "$TEST_DIR/$ASSET"
printf '%064d  unrelated.apk\n' 0 > "$TEST_DIR/SHA256SUMS"
expect_failure verify_download "$TEST_DIR" "$ASSET"
cat "$TEST_DIR/good-checksums" "$TEST_DIR/good-checksums" > "$TEST_DIR/SHA256SUMS"
expect_failure verify_download "$TEST_DIR" "$ASSET"
echo "PASS: missing and duplicate checksums rejected"

unset OMEGA_VPN_IPV6_MODE
write_default_config "$TEST_DIR/server.env"
(
    source "$TEST_DIR/server.env"
    [[ "$OMEGA_ADMIN_WEB_BIND" == "127.0.0.1:8081" ]]
    [[ "$OMEGA_ADMIN_WEB_PUBLIC" == 0 ]]
    [[ "$OMEGA_IPV6_MODE" == disabled ]]
    [[ "$OMEGA_VPN_PORT" == 443 ]]
)
echo "PASS: new installation uses local admin UI and matching VPN ports"
printf 'OMEGA_BIND=[::]:5443\nOMEGA_CUSTOM=preserved\n' > "$TEST_DIR/server.env"
cp "$TEST_DIR/server.env" "$TEST_DIR/original.env"
write_default_config "$TEST_DIR/server.env"
cmp "$TEST_DIR/server.env" "$TEST_DIR/original.env"
echo "PASS: existing settings preserved byte-for-byte"

OMEGA_VPN_IPV6_MODE=nat66 write_default_config "$TEST_DIR/ipv6.env"
grep -q '^OMEGA_IPV6_MODE=nat66$' "$TEST_DIR/ipv6.env"
echo "PASS: explicit IPv6 mode applied"
