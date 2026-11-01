#!/usr/bin/env python3
"""Check the live admin over loopback while verifying its public TLS identity.

Credentials and authenticated HTML stay in this process and are never logged.
"""

import argparse
import http.client
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


class LocalHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        try:
            raw = socket.create_connection(("127.0.0.1", self.port), self.timeout)
        except OSError:
            raw = socket.create_connection(("::1", self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class LocalHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request):
        return self.do_open(LocalHTTPSConnection, request, context=self._context)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=os.environ.get("OMEGA_ENV_FILE", "/etc/default/omega-server"))
    parser.add_argument("--credentials")
    args = parser.parse_args()
    config = {}
    for line in Path(args.config).read_text().splitlines():
        if line.startswith("OMEGA_") and "=" in line:
            key, value = line.split("=", 1)
            parts = shlex.split(value, comments=True)
            config[key] = parts[0] if parts else ""
    host = str(ipaddress.ip_address(config["OMEGA_PUBLIC_HOST"]))
    public_host = f"[{host}]" if ":" in host else host
    base = f"https://{public_host}:{int(config.get('OMEGA_ADMIN_WEB_PORT', '8443'))}"
    context = ssl.create_default_context()
    if config.get("OMEGA_ADMIN_TLS_MODE") == "self-signed":
        cert = Path(config["OMEGA_ADMIN_TLS_CERT"]).read_bytes()
        context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(cert))
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), LocalHTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(cookies),
    )

    def get(path):
        with opener.open(base + path, timeout=10) as response:
            return response.status, response.read(2 * 1024 * 1024).decode("utf-8")

    def post(path, fields):
        request = urllib.request.Request(base + path, data=urllib.parse.urlencode(fields).encode())
        with opener.open(request, timeout=10) as response:
            return response.status, response.read(2 * 1024 * 1024).decode("utf-8")

    def nonce(html):
        found = re.search(r'name="csrf" value="([^"]+)"', html)
        if not found:
            raise RuntimeError("Admin form has no CSRF token")
        return found.group(1)

    for attempt in range(10):
        try:
            status, login = get("/login")
            break
        except urllib.error.URLError:
            if attempt == 9:
                raise
            time.sleep(1)
    if status != 200 or 'action="/login"' not in login:
        raise RuntimeError("HTTPS login page is unavailable")
    token = nonce(login)
    if get("/favicon.ico")[0] != 204:
        raise RuntimeError("Favicon must not redirect to the login form")
    if nonce(get("/login")[1]) != token:
        raise RuntimeError("Another login request invalidates the form token")
    print("PASS: HTTPS identity, full chain, login page and stable CSRF nonce")

    auth_db = Path(config.get("OMEGA_ADMIN_AUTH_DB", "/opt/omega/state/admin-auth.json"))
    credentials_file = Path(args.credentials) if args.credentials else auth_db.with_name("admin-bootstrap.json")
    if not credentials_file.exists():
        print("Authenticated check skipped: initial credentials already consumed; existing login is preserved")
        return
    credentials = json.loads(credentials_file.read_text())
    if not credentials.get("password"):
        print("Authenticated check skipped: existing password is preserved")
        return
    status, dashboard = post("/login", {"csrf": token, "username": credentials["login"], "password": credentials["password"]})
    if status != 200 or 'action="/auth/logout"' not in dashboard:
        raise RuntimeError("Initial admin credentials did not open the authenticated dashboard")
    status, logged_out = post("/auth/logout", {"csrf": nonce(dashboard)})
    if status != 200 or 'action="/login"' not in logged_out:
        raise RuntimeError("Admin logout did not complete")
    try:
        get("/api/reality/status")
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise RuntimeError("Unexpected unauthenticated API status") from None
    else:
        raise RuntimeError("Admin API accepted a logged-out session")
    print("PASS: initial admin login, session cookie, CSRF validation and logout (credentials not logged)")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Admin HTTPS check failed: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1) from None
