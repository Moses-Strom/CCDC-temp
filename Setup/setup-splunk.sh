#!/usr/bin/env bash
# CCDC Splunk Enterprise Server Setup
# Debian 12 / Splunk Enterprise 10.0.2
# Intended VM: 172.20.240.20
# Run from NETLAB+ console: sudo bash setup-splunk-server.sh

set -euo pipefail
umask 022

SPLUNK_HOME="/opt/splunk"
SPLUNK_BIN="$SPLUNK_HOME/bin/splunk"
INPUTS="$SPLUNK_HOME/etc/system/local/inputs.conf"

# Check permissions and dependencies BEFORE changing anything.
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run with sudo."
    exit 1
fi
if [[ ! -x "$SPLUNK_BIN" ]]; then
    echo "ERROR: Splunk not found at $SPLUNK_BIN"
    exit 1
fi
for cmd in python3 ss; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $cmd"
        exit 1
    fi
done

echo "=== CCDC Splunk Server Setup ==="
echo "Existing listening ports:"
ss -lntup

echo ""
read -r -p "Check for Debian package updates? [y/N]: " CHECK_UPDATES
if [[ "$CHECK_UPDATES" =~ ^[Yy]$ ]]; then
    if apt-get update; then
        apt list --upgradable 2>/dev/null || true
        read -r -p "Install available upgrades? May disrupt services. [y/N]: " UPGRADE
        if [[ "$UPGRADE" =~ ^[Yy]$ ]]; then
            apt-get upgrade -y
        fi
    else
        echo "WARNING: Package list update failed. Continuing without upgrades."
    fi
fi

echo ""
echo "=== Change Splunk admin password ==="
read -r -p "Change Splunk admin password? [y/N]: " CHANGE_PASSWORD
if [[ "$CHANGE_PASSWORD" =~ ^[Yy]$ ]]; then
    python3 - <<'PY'
import base64
import getpass
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

old_password = getpass.getpass("Current Splunk admin password: ")
new_password = getpass.getpass("New Splunk admin password: ")
confirm = getpass.getpass("Confirm new password: ")
if not new_password or new_password != confirm:
    sys.exit("ERROR: New passwords do not match or are empty.")

credentials = base64.b64encode(("admin:" + old_password).encode()).decode()
data = urllib.parse.urlencode({
    "password": new_password,
    "oldpassword": old_password,
}).encode()
request = urllib.request.Request(
    "https://127.0.0.1:8089/services/authentication/users/admin",
    data=data,
    headers={"Authorization": "Basic " + credentials},
    method="POST",
)
# Only connects to this VM's loopback interface. Splunk may use a self-signed cert.
context = ssl._create_unverified_context()
try:
    with urllib.request.urlopen(request, context=context, timeout=15) as response:
        response.read()
except urllib.error.HTTPError as exc:
    sys.exit(f"ERROR: Password change failed (HTTP {exc.code}).")
except urllib.error.URLError as exc:
    sys.exit(f"ERROR: Cannot reach local Splunk API: {exc.reason}")
print("[+] Admin password updated.")
PY
fi

echo ""
echo "=== Configure receiving port 9997 ==="
mkdir -p "$(dirname "$INPUTS")"
if [[ -f "$INPUTS" ]]; then
    cp -p "$INPUTS" "${INPUTS}.bak.$(date +%Y%m%d-%H%M%S)"
fi

# Preserve other inputs.conf stanzas; enable an existing receiver if disabled.
python3 - "$INPUTS" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
lines = path.read_text().splitlines() if path.exists() else []
receiver = re.compile(r"^\[splunktcp://:?9997\]$")
starts = [i for i, line in enumerate(lines) if receiver.fullmatch(line.strip())]
if not starts:
    if lines and lines[-1].strip():
        lines.append("")
    lines += ["[splunktcp://9997]", "disabled = 0"]
    print("[+] Added TCP receiver 9997.")
else:
    # Work backwards to avoid shifting indices when adding a setting.
    for start in reversed(starts):
        end = next((i for i in range(start + 1, len(lines))
                    if re.match(r"^\s*\[", lines[i])), len(lines))
        disabled = [i for i in range(start + 1, end)
                    if re.match(r"^\s*disabled\s*=", lines[i])]
        if disabled:
            for i in disabled:
                lines[i] = "disabled = 0"
        else:
            lines.insert(start + 1, "disabled = 0")
    print("[+] Existing TCP receiver 9997 enabled.")
path.write_text("\n".join(lines) + "\n")
PY
