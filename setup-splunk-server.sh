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

echo ""
echo "=== Configure UFW firewall ==="
if ! command -v ufw >/dev/null 2>&1; then
    echo "WARNING: UFW is not installed; skipping firewall setup."
    echo "After reviewing current rules, you may install it: sudo apt-get install ufw"
else
    ufw status verbose
    echo ""
    echo "Optional RESET will remove existing UFW rules."
    echo "New incoming allows: TCP 22, 8000, 8089, 9997."
    echo "Default: deny other incoming; allow outgoing."
    echo "Only reset after checking any additional scored services."
    if [[ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}" ]]; then
        echo "WARNING: SSH session detected. Firewall reset skipped. Use NETLAB+ console."
    else
        read -r -p "Type RESET to replace UFW rules, or Enter to skip: " CONFIRM
        if [[ "$CONFIRM" == "RESET" ]]; then
            BACKUP="/root/ufw-backup-$(date +%Y%m%d-%H%M%S)"
            cp -a /etc/ufw "$BACKUP"
            echo "[+] Saved UFW backup: $BACKUP"
            ufw --force reset
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow 22/tcp comment 'CCDC SSH'
            ufw allow 8000/tcp comment 'Splunk Web'
            ufw allow 8089/tcp comment 'Splunk Management'
            ufw allow 9997/tcp comment 'Splunk Receiver'
            ufw logging low
            ufw --force enable
            echo "[+] New firewall rules (persistent):"
            ufw status verbose
        else
            echo "[+] Existing UFW rules unchanged."
        fi
    fi
fi

echo ""
echo "=== Apply Splunk configuration ==="
read -r -p "Restart Splunk now? This briefly interrupts scoring. [y/N]: " RESTART
if [[ "$RESTART" =~ ^[Yy]$ ]]; then
    if systemctl cat Splunkd.service >/dev/null 2>&1; then
        systemctl restart Splunkd.service
    elif systemctl cat splunkd.service >/dev/null 2>&1; then
        systemctl restart splunkd.service
    else
        echo "WARNING: No standard Splunk systemd service found."
        echo "Restart Splunk using its existing service manager and OS account."
    fi
else
    echo "[!] Restart deferred. Receiver change may not be active yet."
fi

echo ""
echo "=== Verify ==="
"$SPLUNK_BIN" status || true
"$SPLUNK_BIN" cmd btool inputs list | grep -EA 3 '^\[splunktcp://:?9997\]' || true
ss -lntp | grep -E ':(22|8000|8089|9997)[[:space:]]' || true
df -h "$SPLUNK_HOME"
echo ""
echo "Check that 9997 is listening and forwarder events arrive in Splunk."
echo "Do not assume that an open port means scoring is working."
