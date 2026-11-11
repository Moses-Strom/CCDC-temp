#!/usr/bin/env bash
# CCDC Splunk Enterprise Server Setup + Optional Suricata IDS
# Debian 12 / Splunk Enterprise 10.0.2
# Intended VM: 172.20.240.20
# Run from NETLAB+ console: sudo bash setup-splunk-with-suricata.sh

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
echo "=== Debian root password (Splunk admin password is unchanged) ==="
echo "This changes the Linux root password only, not the Splunk Web admin account."
read -r -p "Change Debian root password interactively? [y/N]: " CHANGE_ROOT_PASSWORD
if [[ "$CHANGE_ROOT_PASSWORD" =~ ^[Yy]$ ]]; then
    # passwd prompts interactively; do not put passwords in this script or arguments.
    if ! passwd root; then
        echo "ERROR: Could not change the Debian root password."
        exit 1
    fi
    echo "[+] Debian root password changed."
fi

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
echo "=== Configure Splunk brute-force protection ==="

AUTH_CONF="$SPLUNK_HOME/etc/system/local/authentication.conf"
# Back up existing authentication configuration.
if [[ -f "$AUTH_CONF" ]]; then
    cp -p "$AUTH_CONF" \
        "${AUTH_CONF}.bak.$(date +%Y%m%d-%H%M%S)"
fi
# Enable account lockouts without overwriting other settings.
python3 - "$AUTH_CONF" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
lines = path.read_text().splitlines() if path.exists() else []

settings = {
    "lockoutUsers": "true",
    "lockoutAttempts": "5",
    "lockoutThresholdMins": "5",
    "lockoutMins": "30",
}

output = []
in_section = False
found_section = False
seen = set()
def add_missing():
    for key, value in settings.items():
        if key not in seen:
            output.append(f"{key} = {value}")

for line in lines:
    match = re.match(r"^\s*\[([^\]]+)\]", line)

    if match:
        if in_section:
            add_missing()
        in_section = match.group(1) == "splunk_auth"
        if in_section:
            found_section = True
        output.append(line)
        continue

    key_match = re.match(r"^\s*([^#;\s=]+)\s*=", line)
    if in_section and key_match:
        key = key_match.group(1)
        if key in settings:
            if key not in seen:
                output.append(f"{key} = {settings[key]}")
                seen.add(key)
            continue

    output.append(line)

if in_section:
    add_missing()

if not found_section:
    output.append("")
    output.append("[splunk_auth]")
    for key, value in settings.items():
        output.append(f"{key} = {value}")

path.write_text("\n".join(output) + "\n")
PY
echo "[+] Splunk brute-force protection configured."
echo "[+] Failed login threshold: 5 attempts"
echo "[+] Detection window: 5 minutes"
echo "[+] Lockout duration: 30 minutes"
echo "[+] Existing remote access settings preserved."

echo ""
echo "=== Restart Splunk ==="
"$SPLUNK_BIN" restart

echo ""
echo "=== Verify authentication settings ==="
"$SPLUNK_BIN" btool authentication list splunk_auth --debug \
    | grep -E 'lockoutUsers|lockoutAttempts|lockoutThresholdMins|lockoutMins'
echo ""
echo "=== Verify Splunk listening ports ==="
ss -lntp | grep -E ':(8000|8089|9997)\b' || true

# Optional standalone IDS setup; does not alter Splunk's ports or rules.
# A Suricata sensor on this VM sees only packets delivered to this VM
# unless traffic mirroring or forwarding is separately configured.
setup_suricata() {
    local iface detected_iface iface_input conf backup
    conf="/etc/suricata/suricata.yaml"

    if ! command -v ip >/dev/null 2>&1; then
        echo "ERROR: iproute2 (ip command) is required for interface detection."
        return 1
    fi

    if ! command -v suricata >/dev/null 2>&1 || \
       ! command -v suricata-update >/dev/null 2>&1; then
        echo "[+] Installing Suricata and suricata-update ..."
        if ! apt-get update; then
            echo "ERROR: Could not refresh package lists."
            return 1
        fi

        # Debian 12 can require backports for Suricata 7.
        # Only add it when Suricata is missing from available package candidates.
        if ! apt-cache show suricata >/dev/null 2>&1; then
            . /etc/os-release
            if [[ "${VERSION_CODENAME:-}" == "bookworm" ]]; then
                echo "[!] No Suricata package found. Adding Debian 12 Backports."
                echo "deb http://deb.debian.org/debian bookworm-backports main" \
                    > /etc/apt/sources.list.d/ccdc-bookworm-backports.list
                if ! apt-get update; then
                    echo "ERROR: Could not reach Debian 12 Backports."
                    return 1
                fi
            fi
        fi

        if ! apt-get install -y suricata suricata-update; then
            echo "ERROR: Suricata installation failed. Check available repositories."
            return 1
        fi
    fi

    if [[ ! -f "$conf" ]]; then
        echo "ERROR: Suricata config missing: $conf"
        return 1
    fi

    echo ""
    echo "=== Available IPv4 interfaces ==="
    ip -br -4 addr

    # Prefer the CCDC Splunk LAN interface, then default-route interface,
    # then the first interface with a global IPv4 address.
    detected_iface="$(ip -o -4 addr show scope global | awk '$4 ~ /^172\.20\.240\.20\// {print $2; exit}')"
    if [[ -z "$detected_iface" ]]; then
        detected_iface="$(ip -4 route show default | awk '$1 == "default" {for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')"
    fi
    if [[ -z "$detected_iface" ]]; then
        detected_iface="$(ip -o -4 addr show scope global | awk 'NR==1 {print $2}')"
    fi

    if [[ -z "$detected_iface" ]]; then
        echo "ERROR: Could not detect a suitable network interface."
        return 1
    fi

    read -r -p "Suricata capture interface [$detected_iface]: " iface_input || true
    iface="${iface_input:-$detected_iface}"
    if ! ip link show dev "$iface" >/dev/null 2>&1; then
        echo "ERROR: Network interface '$iface' does not exist."
        return 1
    fi

    backup="${conf}.bak.$(date +%Y%m%d-%H%M%S)"
    if ! cp -p "$conf" "$backup"; then
        echo "ERROR: Could not back up Suricata configuration."
        return 1
    fi

    # Change ONLY the first interface under the top-level af-packet section.
    # Preserve the remainder of the user's Suricata configuration.
    if ! python3 - "$conf" "$iface" <<'PY'
from pathlib import Path
import re
import sys

config_path, iface = Path(sys.argv[1]), sys.argv[2]
lines = config_path.read_text().splitlines(keepends=True)
in_af_packet = False
changed = False
for idx, line in enumerate(lines):
    if re.match(r"^af-packet:\s*(?:#.*)?$", line.rstrip('\n')):
        in_af_packet = True
        continue
    if in_af_packet and re.match(r"^[A-Za-z_][A-Za-z0-9_-]*:\s*", line):
        break
    if in_af_packet:
        m = re.match(r"^(\s*-\s*interface:\s*)([^\s#]+)(.*)$", line)
        if m:
            lines[idx] = m.group(1) + iface + m.group(3)
            changed = True
            break
if not changed:
    sys.exit("ERROR: No interface entry found in the af-packet section.")
config_path.write_text(''.join(lines))
print(f"[+] Configured Suricata AF_PACKET capture on {iface}")
PY
    then
        cp -p "$backup" "$conf"
        return 1
    fi

    echo "[+] Enabling Emerging Threats Open detection rules ..."
    if ! suricata-update enable-source et/open; then
        echo "ERROR: Could not enable ET Open rule source."
        cp -p "$backup" "$conf"
        return 1
    fi
    if ! suricata-update; then
        echo "ERROR: Could not download/update detection rules."
        cp -p "$backup" "$conf"
        return 1
    fi

    if [[ ! -s /var/lib/suricata/rules/suricata.rules ]]; then
        echo "ERROR: Suricata rules file missing or empty."
        cp -p "$backup" "$conf"
        return 1
    fi

    echo "[+] Testing Suricata configuration ..."
    if ! suricata -T -c "$conf"; then
        echo "ERROR: Suricata configuration check failed; restoring backup."
        cp -p "$backup" "$conf"
        return 1
    fi

    systemctl reset-failed suricata 2>/dev/null || true
    if ! systemctl enable suricata; then
        echo "ERROR: Could not enable Suricata service."
        return 1
    fi
    if ! systemctl restart suricata; then
        echo "ERROR: Suricata failed to start. Recent errors:"
        journalctl -u suricata -n 25 --no-pager || true
        return 1
    fi
    if ! systemctl is-active --quiet suricata; then
        echo "ERROR: Suricata service is not active."
        journalctl -u suricata -n 25 --no-pager || true
        return 1
    fi

    echo "[+] Suricata is active on interface: $iface"
    echo "[+] Rules file: /var/lib/suricata/rules/suricata.rules"
    echo "[+] Alerts: /var/log/suricata/fast.log"
    echo "[+] JSON events: /var/log/suricata/eve.json"
    echo "[+] Previous configuration backup: $backup"
    return 0
}

echo ""
read -r -p "Install/configure Suricata IDS on this VM? [y/N]: " CONFIGURE_SURICATA
if [[ "$CONFIGURE_SURICATA" =~ ^[Yy]$ ]]; then
    if setup_suricata; then
        echo "[+] Suricata setup complete."
    else
        echo "WARNING: Suricata setup did not complete. Splunk setup remains intact."
    fi
else
    echo "[+] Skipped optional Suricata setup."
fi

# Debian privilege audit and optional ACCOUNT EXPIRATION (not password locking).
# The Splunk admin account is separate and is not changed or expired here.
# We list both sudo-group members and sudoers-based grants such as limited sudo.
audit_and_optionally_expire_users() {
    local username password_field uid gid gecos home shell groups sudo_result reason
    local -a privileged_users=()
    local -a findings=()
    local active_users=""
    local choice confirmation old_expiry
    local sudo_supported=1

    echo ""
    echo "=== Audit local Debian privileged accounts ==="
    if ! command -v sudo >/dev/null 2>&1; then
        echo "WARNING: sudo is unavailable; cannot reliably audit sudoers grants."
        sudo_supported=0
    fi

    if command -v who >/dev/null 2>&1; then
        active_users="$(who 2>/dev/null | awk '{print $1}' | sort -u || true)"
    fi

    # Read local accounts only; usermod modifies local /etc/passwd accounts.
    while IFS=: read -r username password_field uid gid gecos home shell; do
        [[ "$username" == "root" ]] && continue
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        findings=()

        if (( uid == 0 )); then
            findings+=("UID 0 (root-equivalent)")
        fi
        groups="$(id -nG "$username" 2>/dev/null || true)"
        if [[ " $groups " =~ [[:space:]](sudo|admin|wheel)[[:space:]] ]]; then
            findings+=("administrative group")
        fi

        # sudo -l -U finds direct sudoers grants (including limited sudo) that
        # simple group membership checks miss. Locale fixed for output parsing.
        if (( sudo_supported )); then
            sudo_result="$(LC_ALL=C sudo -l -U "$username" 2>&1)" || true
            if grep -q 'may run the following commands' <<<"$sudo_result"; then
                findings+=("sudoers permission")
            fi
        fi

        if (( ${#findings[@]} > 0 )); then
            privileged_users+=("$username")
            reason="$(IFS=', '; echo "${findings[*]}")"
            printf '[AUDIT] %-22s UID=%-6s %s\n' "$username" "$uid" "$reason"
            if (( sudo_supported )); then
                echo "        Inspect exact rights: sudo -l -U $username"
            fi
        fi
    done < /etc/passwd

    if (( ${#privileged_users[@]} == 0 )); then
        echo "No non-root privileged accounts identified by this audit."
        return 0
    fi

    echo ""
    echo "Account expiration prevents new account logins after the expiry date."
    echo "It does NOT terminate existing sessions or remove files, processes,"
    echo "sudoers entries, SSH keys, or other persistence mechanisms."
    echo "IMPORTANT: Verify an independent administrator login BEFORE expiring users."
    echo "The script will not expire root or the account that invoked sudo."
    echo "It will also skip users currently reported as logged in by 'who'."
    if (( ! sudo_supported )); then
        echo "WARNING: Privilege audit was incomplete; expiration is disabled."
        return 0
    fi

    read -r -p "Review accounts for optional expiration? [y/N]: " choice
    if [[ ! "$choice" =~ ^[Yy]$ ]]; then
        echo "[+] Audit completed; no accounts expired."
        return 0
    fi
    read -r -p "Confirm independent admin/root console access: type VERIFIED: " confirmation
    if [[ "$confirmation" != "VERIFIED" ]]; then
        echo "[+] Access not confirmed; no accounts expired."
        return 0
    fi

    for username in "${privileged_users[@]}"; do
        # Never break the account currently granting this sudo session.
        if [[ -n "${SUDO_USER:-}" && "$username" == "$SUDO_USER" ]]; then
            echo "[SKIP] $username: current sudo account (expire later from a separately verified root session)."
            continue
        fi
        # Also avoid expiring a user who is actively logged into another session.
        if grep -Fxq "$username" <<<"$active_users"; then
            echo "[SKIP] $username: an active login session was detected."
            continue
        fi

        echo ""
        echo "Privileges for $username:"
        LC_ALL=C sudo -l -U "$username" 2>&1 || true
        read -r -p "Expire Debian account '$username' (YES to confirm)? " choice
        if [[ "$choice" == "YES" ]]; then
            # Jan 2 1970 is definitively in the past; this EXPIRES the account.
            if usermod --expiredate 1970-01-02 "$username"; then
                old_expiry="$(getent shadow "$username" 2>/dev/null | cut -d: -f8 || true)"
                if [[ "$old_expiry" == "1" ]]; then
                    echo "[+] Account $username expired; shadow expiry day = 1."
                else
                    echo "[!] Expiry command succeeded; verify with: chage -l $username"
                fi
            else
                echo "WARNING: Unable to expire $username."
            fi
        else
            echo "[SKIP] Left $username unchanged."
        fi
    done
    echo ""
    echo "Verify any account expiration with: sudo chage -l USERNAME"
}

audit_and_optionally_expire_users

echo ""
echo "======================================="
echo " CCDC Splunk Server Setup Complete"
echo "======================================="
echo "Web GUI: http://172.20.240.20:8000"
echo "Management API: TCP 8089"
echo "Forwarder Receiver: TCP 9997"
echo "Brute-force lockout policy: Enabled"
echo "Debian account expiration: audited; any changes confirmed individually"
echo "Splunk admin password: unchanged"
echo ""
echo "IMPORTANT: Verify all scored services."
