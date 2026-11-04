
#!/bin/bash

# CCDC Splunk Enterprise Server Setup
# Debian 12 / Splunk Enterprise 10.0.2
# Server: 172.20.240.20
# sudo bash setup-splunk-server.sh

set -euo pipefail

SPLUNK_HOME="/opt/splunk"
SPLUNK_BIN="$SPLUNK_HOME/bin/splunk"
INPUTS="$SPLUNK_HOME/etc/system/local/inputs.conf"
RECEIVER_PORT="9997"

echo "=================================="
echo " CCDC Splunk Server Setup"
echo "=================================="

# Check root privileges
if [[ $EUID -ne 0 ]]; then
    echo "Run using sudo."
    exit 1
fi

# Check installation
if [[ ! -x "$SPLUNK_BIN" ]]; then
    echo "ERROR: Splunk Enterprise not found."
    exit 1
fi

# Check Python (used for secure password prompt)
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: Python 3 is required."
    exit 1
fi

# Step 1: Change admin password
echo "[1/4] Changing Splunk admin password..."

python3 - <<'PY'
import base64
import getpass
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

old_password = getpass.getpass("Current admin password: ")
new_password = getpass.getpass("New admin password: ")
confirm = getpass.getpass("Confirm new password: ")

if not new_password or new_password != confirm:
    sys.exit("ERROR: Passwords do not match or are empty.")

credentials = base64.b64encode(
    f"admin:{old_password}".encode()
).decode()

data = urllib.parse.urlencode({
    "password": new_password,
    "oldpassword": old_password
}).encode()

request = urllib.request.Request(
    "https://127.0.0.1:8089/services/authentication/users/admin",
    data=data,
    headers={
        "Authorization": f"Basic {credentials}"
    },
    method="POST"
)

# Localhost only; Splunk commonly uses a self-signed certificate
context = ssl._create_unverified_context()

try:
    with urllib.request.urlopen(
        request, context=context, timeout=15
    ) as response:
        response.read()
except urllib.error.HTTPError as error:
    sys.exit(f"Password change failed: HTTP {error.code}")
except urllib.error.URLError as error:
    sys.exit(f"Cannot reach Splunk management API: {error.reason}")

print("[+] Admin password changed successfully.")
PY

# Step 2: Back up configuration
echo "[2/4] Checking receiving configuration..."

mkdir -p "$(dirname "$INPUTS")"

if [[ -f "$INPUTS" ]]; then
    cp -p "$INPUTS" "${INPUTS}.bak.$(date +%Y%m%d-%H%M%S)"
fi

# Add receiving port without overwriting existing inputs
if [[ -f "$INPUTS" ]] &&
   grep -Eq '^\[splunktcp://(:)?9997\][[:space:]]*$' "$INPUTS"; then
    echo "[!] Receiver stanza already exists."
    echo "[!] Verify it is enabled before proceeding."
else
    cat >> "$INPUTS" <<EOF

[splunktcp://${RECEIVER_PORT}]
disabled = 0
EOF

    echo "[+] Receiver configured on TCP $RECEIVER_PORT"
fi

# Step 3: Restart Splunk
echo "[3/4] Restart required to apply receiver settings."

read -r -p "Restart Splunk now? [y/N]: " RESTART

if [[ "$RESTART" =~ ^[Yy]$ ]]; then
    "$SPLUNK_BIN" restart
else
    echo "[!] Restart Splunk using its existing service manager."
fi

# Step 4: Verify ports
echo "[4/4] Checking listening ports..."

ss -lnt | grep -E ':(8000|8089|9997)[[:space:]]' || true

echo ""
echo "=================================="
echo " Setup finished"
echo "=================================="
echo "Splunk Web:        Port 8000"
echo "Splunk Management: Port 8089"
echo "Forwarder Receiver: Port 9997"
echo ""
echo "Verify that TCP 9997 is listening"
echo "after Splunk has restarted."
