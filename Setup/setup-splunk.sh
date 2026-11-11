#!/usr/bin/env bash
# CCDC | Debian 12 / Splunk Enterprise 10.0.2 server setup
# Intended VM: 172.20.240.20 (verify in your actual CCDC pod)
# Includes Splunk receiver/auth protection + SSH restriction + interactive Linux root
# password rotation + optional administrator account audit/expiry
# + ClamAV notify-only real-time scanning + passive Suricata IDS
# + opt-in UFW inbound default-deny with ONLY 22/8000/8089/9997 TCP allowed.
# Run from NETLAB VM console: sudo bash setup-splunk.sh
# Read-only review: sudo bash setup-splunk.sh --verify
set -euo pipefail
umask 022

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SPLUNK_BIN="$SPLUNK_HOME/bin/splunk"
INPUTS="$SPLUNK_HOME/etc/system/local/inputs.conf"
AUTH_CONF="$SPLUNK_HOME/etc/system/local/authentication.conf"
EXPECTED_IP="172.20.240.20"
CCDC_CAPTURE_IFACE=''
CCDC_BASELINE_PORTS=''
CCDC_SETUP_ERRORS=0
CCDC_CHANGED_SPLUNK=0
CCDC_CHANGED_INPUTS=0
CCDC_RESTARTED=0
CCDC_UFW_APPLIED=0

say() { printf '%s\n' "$*"; }
warn() { printf 'WARN | %s\n' "$*" >&2; }
fail() { printf 'FAIL | %s\n' "$*" >&2; CCDC_SETUP_ERRORS=$((CCDC_SETUP_ERRORS+1)); }
yesno() { local answer=''; read -r -p "$1 [y/N]: " answer || true; [[ "$answer" =~ ^[Yy]$ ]]; }

ccdc_ssh_session() {
    [[ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-}" ]] && return 0
    local pid="$$" parent process hop
    for ((hop=0;hop<40 && pid>1;hop++)); do
        process="$(ps -o comm= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
        case "$process" in sshd|sshd-session) return 0 ;; esac
        parent="$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
        [[ "$parent" =~ ^[0-9]+$ ]] || break
        pid="$parent"
    done
    return 1
}

port_listening() {
    ss -H -lnt 2>/dev/null | awk -v port="$1" '$4 ~ (":" port "$") {found=1} END {exit !found}'
}
snapshot_ports() {
    local p
    for p in 8000 8089 9997; do
        if port_listening "$p"; then CCDC_BASELINE_PORTS+=" $p "; fi
    done
}

ccdc_configure_receiver() {
    say '=== Configure Splunk TCP receiver 9997 ==='
    mkdir -p "$(dirname "$INPUTS")"
    [[ ! -f "$INPUTS" ]] || cp -p "$INPUTS" "${INPUTS}.bak.$(date +%Y%m%d-%H%M%S).$$"
    python3 - "$INPUTS" <<'PY_RECEIVER'
from pathlib import Path
import re, sys
path=Path(sys.argv[1]); lines=path.read_text().splitlines() if path.exists() else []
pat=re.compile(r'^\[splunktcp://:?9997\]$')
starts=[i for i,line in enumerate(lines) if pat.fullmatch(line.strip())]
if not starts:
    if lines and lines[-1].strip(): lines.append('')
    lines+=['[splunktcp://9997]','disabled = 0']
    print('Added Splunk receiver stanza for TCP 9997.')
else:
    for start in reversed(starts):
        end=next((i for i in range(start+1,len(lines)) if re.match(r'^\s*\[',lines[i])),len(lines))
        disabled=[i for i in range(start+1,end) if re.match(r'^\s*disabled\s*=',lines[i])]
        if disabled:
            for i in disabled: lines[i]='disabled = 0'
        else: lines.insert(start+1,'disabled = 0')
    print('Enabled existing TCP 9997 receiver.')
path.write_text('\n'.join(lines)+'\n')
PY_RECEIVER
    CCDC_CHANGED_SPLUNK=1
}

ccdc_configure_lockout() {
    say '=== Configure Splunk brute-force protection ==='
    [[ ! -f "$AUTH_CONF" ]] || cp -p "$AUTH_CONF" "${AUTH_CONF}.bak.$(date +%Y%m%d-%H%M%S).$$"
    python3 - "$AUTH_CONF" <<'PY_AUTH'
from pathlib import Path
import re, sys
p=Path(sys.argv[1]); lines=p.read_text().splitlines() if p.exists() else []
settings={'lockoutUsers':'true','lockoutAttempts':'5','lockoutThresholdMins':'5','lockoutMins':'30'}
output=[]; inside=False; section=False; seen=set()
def missing():
    for k,v in settings.items():
        if k not in seen: output.append(f'{k} = {v}')
for line in lines:
    match=re.match(r'^\s*\[([^]]+)\]',line)
    if match:
        if inside: missing()
        inside=match.group(1)=='splunk_auth'
        section|=inside
        output.append(line);continue
    m=re.match(r'^\s*([^#;\s=]+)\s*=',line)
    if inside and m and m.group(1) in settings:
        k=m.group(1)
        if k not in seen: output.append(f'{k} = {settings[k]}');seen.add(k)
        continue
    output.append(line)
if inside: missing()
if not section:
    output.extend(['','[splunk_auth]']+[f'{k} = {v}' for k,v in settings.items()])
p.write_text('\n'.join(output)+'\n')
PY_AUTH
    CCDC_CHANGED_SPLUNK=1
    say 'Splunk lockout: 5 failed attempts / 5 minutes -> 30 minute lockout (effective after restart).'
}

ccdc_change_root_password() {
    say '=== Change Linux root password (NOT Splunk Web admin) ==='
    say 'The system passwd utility prompts securely; no password is stored by this script.'
    say 'This does NOT enable root SSH login (root SSH stays denied).'
    if passwd root; then
        say 'PASS | Linux root password change completed.'
    else
        warn 'Linux root password change failed; no automatic account expirations will run.'
        return 1
    fi
}

# Sudo permissions can come from individual sudoers entries as well as groups.
# Audit is best-effort on local/NSS users: sudo -l -U is more precise than
# simply listing the sudo group. Polkit and other privilege channels may exist.
ccdc_sudo_granted() {
    local output
    command -v sudo >/dev/null 2>&1 || return 1
    # Some sudo builds return exit code 0 even for "not allowed" users.
    # Therefore inspect the English (C-locale) privilege summary itself.
    output="$(LC_ALL=C sudo -n -l -U "$1" 2>&1 || true)"
    grep -Eqi 'may run the following commands?' <<< "$output"
}

ccdc_is_privileged_account() {
    local name="$1" uid
    uid="$(id -u "$name" 2>/dev/null || true)"
    [[ "$uid" == 0 ]] && return 0
    ccdc_sudo_granted "$name"
}

ccdc_account_expiry() {
    local name="$1" expiry
    expiry="$(getent shadow "$name" 2>/dev/null | awk -F: '{print $8}' || true)"
    if [[ "$expiry" =~ ^[0-9]+$ ]] && ((expiry > 0 && expiry <= $(date +%s)/86400)); then
        printf 'expired'
    elif [[ -z "$expiry" ]]; then
        printf 'not-expired/unknown'
    else
        printf 'active'
    fi
}

ccdc_audit_admins() {
    local name uid group shell pwd_status state count=0 source
    say ''
    say '=== Linux local/NSS administrator privilege review (read-only) ==='
    if ! command -v sudo >/dev/null 2>&1; then
        warn 'sudo utility not available. Only UID 0 / sudo and wheel group hints can be reported.'
    fi
    printf '%-23s %-7s %-21s %-14s %s\n' 'USER' 'UID' 'SOURCE' 'EXPIRY' 'SHELL'
    while IFS=: read -r name _ uid group _ _ shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        if [[ "$uid" == 0 ]]; then
            source='UID0/root'
        elif ccdc_sudo_granted "$name"; then
            source='effective sudoers'
        elif [[ " $(id -nG "$name" 2>/dev/null || true) " == *' sudo '* ||
                " $(id -nG "$name" 2>/dev/null || true) " == *' wheel '* ]]; then
            source='group hint only'
        else
            continue
        fi
        state="$(ccdc_account_expiry "$name")"
        printf '%-23s %-7s %-21s %-14s %s\n' "$name" "$uid" "$source" "$state" "$shell"
        count=$((count+1))
    done < <(getent passwd)
    say "Reviewed $count potentially privileged account(s)."
    say 'For actual allowed sudo commands: sudo -l -U USERNAME'
    say 'Group hints alone do not prove permission; only accounts with confirmed sudo privilege are eligible for the optional expiry step.'
    say 'Also review /etc/sudoers, /etc/sudoers.d/ and any external IAM/polkit rules.'
    say 'Account expiration does not revoke active sessions or previously launched processes.'
}

ccdc_protected_account() {
    local target="$1" uid service_user current_login
    uid="$(id -u "$target" 2>/dev/null || true)"
    if [[ ! "$uid" =~ ^[0-9]+$ || "$uid" -lt 1000 ]]; then
        warn 'Refusing: system/service accounts and UID 0 must not be expired by this script.'
        return 0
    fi
    if [[ -n "${SUDO_USER:-}" && "$target" == "$SUDO_USER" ]]; then
        warn 'Refusing: this is the user who invoked sudo.'
        return 0
    fi
    current_login="$(logname 2>/dev/null || true)"
    if [[ -n "$current_login" && "$target" == "$current_login" ]]; then
        warn 'Refusing: this is the detected console login user.'
        return 0
    fi
    if who 2>/dev/null | awk '{print $1}' | grep -Fxq -- "$target"; then
        warn 'Refusing: user has an active terminal session; review it manually.'
        return 0
    fi
    service_user="$(ps -eo user=,comm= | awk '$2=="splunkd" {print $1;exit}' || true)"
    if [[ -n "$service_user" && "$target" == "$service_user" ]]; then
        warn 'Refusing: this account is running Splunk.'
        return 0
    fi
    case "$target" in splunk|splunkfwd|clamav|suricata|daemon|nobody|_apt)
        warn 'Refusing: known service account.';return 0;;
    esac
    # Require a local entry: usermod generally does not manage remote NSS/LDAP identities.
    if ! awk -F: -v u="$target" '$1==u {found=1} END{exit !found}' /etc/passwd; then
        warn 'Refusing: account is not local to /etc/passwd; handle directory-managed users separately.'
        return 0
    fi
    return 1
}

ccdc_expire_selected_admins() {
    local target confirm console_ok='' root_pw
    say ''
    say '=== OPTIONAL: expire selected privileged Linux accounts ==='
    say 'Never expire every sudo account: preserve a tested administrative recovery path.'
    say 'This disables new console AND SSH logins for the selected user; it does not end active sessions.'
    if ! yesno 'Review and optionally expire a specific privileged Linux user?'; then
        say 'No account expiration requested.'
        return 0
    fi
    ccdc_audit_admins
    root_pw="$(passwd -S root 2>/dev/null | awk '{print $2}' || true)"
    if [[ "$root_pw" != 'P' ]]; then
        warn 'Root does not have a usable password (passwd -S root != P). Account expiration is disabled.'
        return 0
    fi
    read -r -p 'Have you personally tested a NEW root login via NETLAB console? Type ROOT-CONSOLE-VERIFIED: ' console_ok || true
    if [[ "$console_ok" != 'ROOT-CONSOLE-VERIFIED' ]]; then
        warn 'Skipping account expiration: a tested console recovery path was not confirmed.'
        return 0
    fi
    while true; do
        say ''
        read -r -p 'Exact Linux username to expire (Enter to finish): ' target || break
        [[ -n "$target" ]] || break
        if [[ ! "$target" =~ ^[a-z_][a-z0-9_.-]*\$?$ ]]; then
            warn 'Invalid local account name; skipped.';continue
        fi
        if ! id "$target" >/dev/null 2>&1; then
            warn 'Unknown account; skipped.';continue
        fi
        if ccdc_protected_account "$target"; then
            continue
        fi
        if ! ccdc_is_privileged_account "$target"; then
            warn 'Not listed as sudo/UID0/wheel privileged; account unchanged.';continue
        fi
        if [[ "$(ccdc_account_expiry "$target")" == 'expired' ]]; then
            warn 'This account already appears expired.';continue
        fi
        say "You are about to expire $target. This blocks NEW interactive/SSH logins for the account."
        read -r -p "To confirm, type exactly 'EXPIRE $target': " confirm || true
        if [[ "$confirm" != "EXPIRE $target" ]]; then
            say 'Skipped.';continue
        fi
        if usermod --expiredate 1970-01-02 "$target"; then
            if [[ "$(getent shadow "$target" 2>/dev/null | awk -F: '{print $8}')" == '1' ]]; then
                say "PASS | Account expired: $target"
                say "Undo: sudo usermod --expiredate '' $target"
            else
                warn "Expiration was requested but /etc/shadow verification was inconclusive for $target"
                CCDC_SETUP_ERRORS=$((CCDC_SETUP_ERRORS+1))
            fi
        else
            fail "Failed to expire $target"
        fi
    done
}

# UFW is separate from SSH authentication: port 22 remains available for
# other authorized users, while root and sysadmin are denied by sshd.
# Preserve scored Splunk Web (8000), API (8089), and UF receiver (9997).
# Always run this function from NETLAB VM CONSOLE, never over SSH.
ccdc_configure_firewall() {
    local confirm backup_dir status
    say ''
    say '=== Optional CCDC UFW host firewall ==='
    say 'New inbound connections: DENY by default.'
    say 'Explicit inbound TCP allows: 22/SSH, 8000/Web, 8089/management, 9997/forwarders.'
    say 'Outbound connections: ALLOW by default (required for packages, DNS, clocks and other dependencies).'
    say 'Standard UFW ICMP handling is retained; verify CCDC ping scoring afterward.'
    say 'This changes ONLY the Debian VM firewall, not the Palo Alto firewall.'
    say 'WARNING: Replacing existing UFW user rules could interrupt additional scored services.'
    if ! yesno 'Reset UFW rules to ONLY these inbound TCP allowances and ENABLE default-deny'; then
        say 'SKIP | UFW rules unchanged by operator choice.'
        return 0
    fi
    read -r -p 'From the NETLAB console, type APPLY-UFW to confirm replacement of existing UFW user rules: ' confirm || true
    if [[ "$confirm" != 'APPLY-UFW' ]]; then
        warn 'No UFW changes made (confirmation missing).'
        return 0
    fi
    if ccdc_ssh_session; then
        warn 'Refusing firewall reset from an SSH session.'
        return 1
    fi
    if ! command -v ufw >/dev/null 2>&1; then
        say 'Installing ufw ...'
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ufw; then
            warn 'Could not install UFW; no rules changed.'
            return 1
        fi
    fi
    backup_dir="/root/ccdc-firewall-backup-$(date +%Y%m%d-%H%M%S)-$$"
    mkdir -p "$backup_dir"
    ufw status verbose > "$backup_dir/ufw-status-before.txt" 2>&1 || true
    ufw show added > "$backup_dir/ufw-added-before.txt" 2>&1 || true
    if [[ -d /etc/ufw ]]; then
        if ! tar -czf "$backup_dir/etc-ufw-before.tar.gz" -C /etc ufw; then
            warn 'UFW backup failed; refusing to change firewall.'
            return 1
        fi
    fi
    say "Previous UFW configuration backup: $backup_dir"
    # Deliberately reset the UFW user rules, so old broad allows cannot linger.
    # UFW's stock before.rules still handles standard established/ICMP traffic.
    if ! ufw --force reset; then warn 'UFW reset failed';return 1; fi
    if ! ufw default deny incoming || ! ufw default allow outgoing ||
       ! ufw allow 22/tcp comment 'CCDC SSH: not root/sysadmin' ||
       ! ufw allow 8000/tcp comment 'CCDC Splunk Web/scoring' ||
       ! ufw allow 8089/tcp comment 'CCDC Splunk API/scoring' ||
       ! ufw allow 9997/tcp comment 'CCDC Splunk forwarders'; then
        warn 'Failed while staging UFW rules; check status BEFORE enabling.'
        return 1
    fi
    say 'Staged UFW rules:'
    ufw show added || true
    if ! ufw --force enable; then
        warn 'UFW enable failed; inspect firewall immediately.'
        return 1
    fi
    status="$(ufw status verbose 2>&1)"
    printf '%s\n' "$status"
    if ! grep -q '^Status: active' <<< "$status" ||
       ! grep -Eq '^Default: deny \(incoming\), allow \(outgoing\)' <<< "$status"; then
        warn 'UFW activation or defaults not confirmed.'
        return 1
    fi
    CCDC_UFW_APPLIED=1
    say 'PASS | UFW active: deny incoming; allow outgoing; required inbound TCP ports allowed.'
    say 'Verify remote scoring, forwarding and ping from other CCDC machines.'
}

ccdc_apply_ssh_restriction() {
    say '=== Restrict NEW SSH logins for root and sysadmin ==='
    local conf='/etc/ssh/sshd_config.d/00-ccdc-deny-root-sysadmin.conf' temp backup='' effective
    local sshbin='/usr/sbin/sshd'
    if [[ ! -x "$sshbin" ]]; then
        sshbin="$(command -v sshd 2>/dev/null || true)"
    fi
    if [[ -z "$sshbin" || ! -f /etc/ssh/sshd_config ]]; then
        warn 'OpenSSH server not found; no SSH configuration changed.'; return 0
    fi
    if ! grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
        warn 'sshd_config does not include Debian drop-in files. SSH change skipped.'; return 1
    fi
    mkdir -p /etc/ssh/sshd_config.d
    if [[ -f "$conf" ]]; then
        backup="${conf}.bak.$(date +%Y%m%d-%H%M%S).$$"; cp -p "$conf" "$backup"
    fi
    temp="$(mktemp /etc/ssh/sshd_config.d/.ccdc.XXXXXX)"
    cat > "$temp" <<'EOF_SSH'
# Only denies SSH authentication for these identities. Does not affect VM console access.
DenyUsers root sysadmin
PermitRootLogin no
EOF_SSH
    chmod 0644 "$temp"
    mv -f "$temp" "$conf"
    if ! "$sshbin" -t -f /etc/ssh/sshd_config ||
       ! effective="$($sshbin -T -C user=sysadmin,host=localhost,addr=127.0.0.1 2>/dev/null)" ||
       ! grep -Eq '^denyusers .*root([[:space:]]|$)' <<< "$effective" ||
       ! grep -Eq '^denyusers .*sysadmin([[:space:]]|$)' <<< "$effective"; then
        warn 'SSH config did not validate. Restoring previous drop-in.'
        if [[ -n "$backup" ]]; then cp -p "$backup" "$conf"; else rm -f "$conf"; fi
        return 1
    fi
    if systemctl is-active --quiet ssh.service; then
        if ! systemctl reload ssh.service; then
            warn 'SSH reload failed; reverting drop-in.'
            if [[ -n "$backup" ]]; then cp -p "$backup" "$conf"; else rm -f "$conf"; fi
            systemctl reload ssh.service || true
            return 1
        fi
    else
        warn 'ssh.service is not running. Rules will apply next time sshd is started.'
    fi
    say 'SSH restricted for root/sysadmin; other SSH identities are unaffected. Existing sessions stay open.'
}

ccdc_install_clamav() {
    say '=== Install/configure ClamAV on-access notify-only ==='
    if ! command -v clamonacc >/dev/null 2>&1 || ! command -v clamd >/dev/null 2>&1; then
        say 'Installing ClamAV packages (no full system upgrade).'
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends clamav clamav-daemon clamav-freshclam || return 1
    fi
    local config='/etc/clamav/clamd.conf' backup dropdir
    [[ -f "$config" ]] || { warn 'No /etc/clamav/clamd.conf found'; return 1; }
    backup="${config}.bak.ccdc.$(date +%Y%m%d-%H%M%S).$$"
    cp -p "$config" "$backup"
    python3 - "$config" "$SPLUNK_HOME" <<'PY_CLAM'
from pathlib import Path
import sys
p=Path(sys.argv[1]); root=Path(sys.argv[2]); lines=p.read_text().splitlines()
keys={'OnAccessIncludePath','OnAccessExcludePath','OnAccessExcludeUname','OnAccessPrevention','OnAccessDenyOnError','OnAccessExtraScanning','OnAccessMaxFileSize','OnAccessMaxThreads','OnAccessDisableDDD','OnAccessMountPath'}
lines=[s for s in lines if not (s.split()[0] in keys if s.split() else False)]
lines.extend(['','# CCDC: detect/log; NEVER prevent access or auto quarantine',
              'OnAccessPrevention no','OnAccessDenyOnError no',
              'OnAccessExtraScanning yes','OnAccessMaxFileSize 10M',
              'OnAccessMaxThreads 2','OnAccessExcludeUname clamav'])
for directory in [Path('/home'),Path('/tmp'),Path('/var/tmp'),root/'etc/apps',root/'etc/system/local']:
    if directory.is_dir():lines.append(f'OnAccessIncludePath {directory}')
p.write_text('\n'.join(lines)+'\n')
PY_CLAM
    dropdir='/etc/systemd/system/clamav-clamonacc.service.d'
    mkdir -p "$dropdir" /var/log/clamav
    # Debian's packaged on-access unit can include --move=/root/quarantine.
    # Override it: never move/delete, only log.
    if [[ -f "$dropdir/90-ccdc-notify-only.conf" ]]; then
        cp -p "$dropdir/90-ccdc-notify-only.conf" "$dropdir/90-ccdc-notify-only.conf.bak.$(date +%Y%m%d-%H%M%S).$$"
    fi
    cat > "$dropdir/90-ccdc-notify-only.conf" <<'EOF_CLAM_UNIT'
[Service]
ExecStart=
ExecStart=/usr/sbin/clamonacc -F --fdpass --log=/var/log/clamav/clamonacc.log
Restart=on-failure
RestartSec=5s
EOF_CLAM_UNIT
    touch /var/log/clamav/clamonacc.log
    chmod 0640 /var/log/clamav/clamonacc.log
    if getent group adm >/dev/null 2>&1; then chown root:adm /var/log/clamav/clamonacc.log; fi
    systemctl daemon-reload
    systemctl enable --now clamav-freshclam.service || warn 'ClamAV updates unavailable; inspect signatures.'
    systemctl enable clamav-daemon.service >/dev/null 2>&1 || true
    if ! systemctl restart clamav-daemon.service; then
        warn 'clamav-daemon failed. Restoring original clamd.conf.'
        cp -p "$backup" "$config"
        systemctl restart clamav-daemon.service || true
        return 1
    fi
    systemctl enable clamav-clamonacc.service >/dev/null 2>&1 || true
    if ! systemctl restart clamav-clamonacc.service; then
        warn 'ClamAV on-access watcher failed; check journalctl -u clamav-clamonacc.'
        return 1
    fi
    say 'ClamAV on-access scanner enabled: notify-only; no removal, quarantine or network filtering.'
}

ccdc_choose_iface() {
    local suggested='' source='' typed='' active_ip_iface=''
    say 'Available IPv4 network interfaces:'
    ip -br -4 addr || true
    if [[ -n "${CCDC_SURICATA_IFACE:-}" ]]; then
        suggested="$CCDC_SURICATA_IFACE"
        source='explicit environment override'
    else
        active_ip_iface="$(ip -o -4 addr show scope global 2>/dev/null | awk '$4 ~ /^172\.20\.240\.20\// {print $2;exit}')"
        if [[ -n "$active_ip_iface" ]]; then
            suggested="$active_ip_iface"
            source='interface with exact CCDC Splunk IP 172.20.240.20'
        else
            suggested="$(ip -4 route show default 2>/dev/null | awk 'NR==1 {for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')"
            source='default-route GUESS (scored IP was not found)'
        fi
    fi
    say "Suggested capture interface: ${suggested:-none} ($source)"
    read -r -p "Suricata capture interface [${suggested:-enter name}]: " typed || true
    CCDC_CAPTURE_IFACE="${typed:-$suggested}"
    if [[ -z "$CCDC_CAPTURE_IFACE" || ! "$CCDC_CAPTURE_IFACE" =~ ^[A-Za-z0-9_.:-]+$ || "$CCDC_CAPTURE_IFACE" == 'lo' ]] ||
       ! ip link show dev "$CCDC_CAPTURE_IFACE" >/dev/null 2>&1; then
        warn "Capture interface '${CCDC_CAPTURE_IFACE:-none}' does not exist or is unusable. Aborting Suricata setup."
        return 1
    fi
    if [[ -z "$active_ip_iface" && -z "${CCDC_SURICATA_IFACE:-}" ]]; then
        warn 'The exact scored IP 172.20.240.20 was not found. Default route is NOT proof of correct capture.'
        local confirm=''
        read -r -p "To approve $CCDC_CAPTURE_IFACE, type 'USE $CCDC_CAPTURE_IFACE': " confirm || true
        if [[ "$confirm" != "USE $CCDC_CAPTURE_IFACE" ]]; then
            warn 'Could not confirm capture network; leaving Suricata unchanged.'
            return 1
        fi
    elif [[ -n "$active_ip_iface" && "$CCDC_CAPTURE_IFACE" != "$active_ip_iface" ]]; then
        warn "You chose $CCDC_CAPTURE_IFACE instead of the interface with scored IP ($active_ip_iface)."
        local confirm=''
        read -r -p "To approve $CCDC_CAPTURE_IFACE, type 'USE $CCDC_CAPTURE_IFACE': " confirm || true
        [[ "$confirm" == "USE $CCDC_CAPTURE_IFACE" ]] || return 1
    fi
    local operational=''
    operational="$(cat "/sys/class/net/$CCDC_CAPTURE_IFACE/operstate" 2>/dev/null || true)"
    if [[ "$operational" == 'down' ]]; then
        warn "$CCDC_CAPTURE_IFACE is DOWN: Suricata cannot reliably capture until the NIC is up."
        return 1
    fi
    say "Selected Suricata interface: $CCDC_CAPTURE_IFACE (operstate=${operational:-unknown})"
    say 'Note: interface existence does NOT prove mirrored inter-VM traffic is visible.'
}

ccdc_install_suricata_packages() {
    local codename candidate policy
    if command -v suricata >/dev/null 2>&1 && command -v suricata-update >/dev/null 2>&1; then
        say 'Suricata and suricata-update already installed.'
        return 0
    fi
    if ! apt-get update; then warn 'apt update failed; cannot install Suricata.'; return 1; fi
    codename="$(. /etc/os-release; echo "${VERSION_CODENAME:-}")"
    policy="$(apt-cache policy suricata 2>/dev/null || true)"
    candidate="$(awk '/Candidate:/ {print $2;exit}' <<< "$policy")"
    if [[ "$codename" == bookworm ]]; then
        # Suricata was removed from the regular Bookworm package channel.
        # Debian 12 Backports provides the Debian-packaged Suricata 7 line.
        if ! grep -q 'bookworm-backports' <<< "$policy"; then
            say 'Adding Debian Bookworm Backports (not security-maintained after August 2026).'
            printf '%s\n' 'deb http://deb.debian.org/debian bookworm-backports main' \
                > /etc/apt/sources.list.d/ccdc-bookworm-backports.list
            if ! apt-get update; then
                warn 'Backports update failed. Check DNS/network and repository availability.'
                return 1
            fi
        fi
        if ! apt-cache policy suricata | grep -q 'bookworm-backports'; then
            warn 'Suricata is not available from configured Bookworm Backports.'
            return 1
        fi
        DEBIAN_FRONTEND=noninteractive apt-get install -y -t bookworm-backports --no-install-recommends suricata suricata-update || return 1
    else
        [[ "$candidate" != '(none)' && -n "$candidate" ]] || { warn 'Suricata package candidate unavailable.'; return 1; }
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends suricata suricata-update || return 1
    fi
    command -v suricata >/dev/null 2>&1 && command -v suricata-update >/dev/null 2>&1
}

ccdc_install_suricata() {
    say '=== Install/configure passive Suricata IDS ==='
    command -v ip >/dev/null 2>&1 || { warn 'iproute2 utility unavailable'; return 1; }
    ccdc_choose_iface || return 1
    ccdc_install_suricata_packages || return 1
    local config='/etc/suricata/suricata.yaml' dropdir='/etc/systemd/system/suricata.service.d'
    [[ -f "$config" ]] || { warn 'Suricata YAML configuration missing'; return 1; }
    mkdir -p "$dropdir" /var/log/suricata
    # Change Suricata YAML's AF_PACKET interface as well as the unit override.
    # This fixes the original eth0 crash instead of merely replacing it on CLI.
    local yaml_backup="${config}.bak.ccdc.$(date +%Y%m%d-%H%M%S).$$"
    cp -p "$config" "$yaml_backup"
    if ! python3 - "$config" "$CCDC_CAPTURE_IFACE" <<'PY_IFACE'
from pathlib import Path
import re, sys
p=Path(sys.argv[1]); iface=sys.argv[2]
lines=p.read_text().splitlines(keepends=True)
in_af=False; changed=False
for i,line in enumerate(lines):
    if re.match(r'^af-packet:\s*(?:#.*)?$', line.rstrip('\n')):
        in_af=True
        continue
    if in_af and re.match(r'^[A-Za-z_][\w-]*:\s*',line):
        break
    if in_af:
        m=re.match(r'^(\s*-\s*interface:\s*)([^\s#]+)(.*)$',line)
        if m:
            lines[i]=m.group(1)+iface+m.group(3)
            changed=True
            break
if not changed: raise SystemExit('ERROR: cannot locate AF_PACKET interface in YAML')
p.write_text(''.join(lines))
PY_IFACE
    then
        cp -p "$yaml_backup" "$config"
        return 1
    fi
    if [[ -f "$dropdir/90-ccdc-passive-ids.conf" ]]; then
        cp -p "$dropdir/90-ccdc-passive-ids.conf" "$dropdir/90-ccdc-passive-ids.conf.bak.$(date +%Y%m%d-%H%M%S).$$"
    fi
    cat > "$dropdir/90-ccdc-passive-ids.conf" <<EOF_SUR_UNIT
[Service]
ExecStart=
ExecStart=$(command -v suricata) -D --af-packet=$CCDC_CAPTURE_IFACE -c $config --pidfile /run/suricata.pid
EOF_SUR_UNIT
    say 'Updating Suricata rules (Emerging Threats Open) ...'
    if ! suricata-update enable-source et/open; then
        warn 'Could not explicitly enable ET Open (it may be the default source).'
    fi
    if ! suricata-update; then
        warn 'Rule download failed; using existing rules only if present.'
    fi
    if [[ ! -s /var/lib/suricata/rules/suricata.rules ]]; then
        warn 'Suricata rules missing/empty. Cannot claim IDS detection is configured.'
        return 1
    fi
    if ! suricata -T -c "$config" --af-packet="$CCDC_CAPTURE_IFACE" >/var/log/suricata/ccdc-config-test.log 2>&1; then
        warn 'Suricata configuration/rule test failed; see /var/log/suricata/ccdc-config-test.log.'
        cp -p "$yaml_backup" "$config"
        return 1
    fi
    if grep -Eqi '0 (rules|signatures) (successfully )?loaded|0 signatures processed' /var/log/suricata/ccdc-config-test.log; then
        warn 'Suricata reported zero loaded signatures; IDS detection is not ready.'
        return 1
    fi
    systemctl daemon-reload
    if ! systemctl enable suricata.service || ! systemctl restart suricata.service; then
        warn 'suricata.service could not start; inspect journalctl -u suricata.'
        return 1
    fi
    if ! systemctl is-active --quiet suricata.service; then
        warn 'Suricata service failed its active-state check.'
        return 1
    fi
    say "PASS | Suricata started on interface $CCDC_CAPTURE_IFACE, with a nonempty rule file."
    say "Backup: $yaml_backup"
    say 'Suricata passive IDS active: AF_PACKET only, never NFQUEUE, no firewall changes.'
}

ccdc_setup_monitoring_input() {
    say '=== Configure Splunk local monitoring for ClamAV and Suricata logs ==='
    local app="$SPLUNK_HOME/etc/apps/ccdc_endpoint_ids_inputs" owner group
    mkdir -p "$app/default" "$app/local"
    cat > "$app/default/app.conf" <<'EOF_APP'
[install]
is_configured = 1
[ui]
is_visible = 0
[launcher]
author = CCDC
description = Local Suricata IDS and ClamAV monitoring
EOF_APP
    cat > "$app/local/inputs.conf" <<'EOF_MON'
# Both inputs are disabled automatically if no matching file is present.
[monitor:///var/log/suricata/eve.json]
disabled = 0
sourcetype = suricata:eve

[monitor:///var/log/clamav/clamonacc.log]
disabled = 0
sourcetype = clamav:clamonacc
EOF_MON
    cat > "$app/local/props.conf" <<'EOF_PROPS'
[suricata:eve]
SHOULD_LINEMERGE = false
KV_MODE = json
TRUNCATE = 20000
EOF_PROPS
    owner="$(ps -eo user=,comm= | awk '$2=="splunkd" {print $1;exit}' || true)"
    if [[ -z "$owner" && -d "$SPLUNK_HOME/var/log/splunk" ]]; then
        owner="$(stat -c %U "$SPLUNK_HOME/var/log/splunk")"
    fi
    if [[ -n "$owner" && "$owner" != UNKNOWN ]] && id "$owner" >/dev/null 2>&1; then
        group="$(id -gn "$owner")"
        chown -R -- "$owner:$group" "$app"
        if command -v setfacl >/dev/null 2>&1; then
            for directory in /var/log/suricata /var/log/clamav; do
                if [[ -d "$directory" ]]; then
                    setfacl -m "u:$owner:rx" "$directory" || warn "ACL failed for $directory"
                    setfacl -m "d:u:$owner:rX" "$directory" || warn "Default ACL failed for $directory"
                fi
            done
            for logfile in /var/log/suricata/eve.json /var/log/clamav/clamonacc.log; do
                if [[ -f "$logfile" ]]; then
                    setfacl -m "u:$owner:r" "$logfile" || warn "Log file ACL failed for $logfile"
                fi
            done
        else
            warn 'setfacl not installed. Check Splunk OS account read access before relying on log ingestion.'
        fi
    else
        warn 'Could not determine Splunk daemon OS user. Verify log file permissions.'
    fi
    CCDC_CHANGED_INPUTS=1
    if [[ -f "$SPLUNK_HOME/etc/apps/ccdc_suricata_inputs/local/inputs.conf" ]]; then
        warn 'An older ccdc_suricata_inputs app also exists; check for duplicate Suricata monitor definitions.'
    fi
    say "Splunk EVE + ClamAV monitors saved under $app (requires a safe Splunk restart to activate)."
}

ccdc_verification() {
    local failed=0 effective p unit
    say ''
    say '==========================================================='
    say ' CCDC FINAL VERIFICATION: Splunk / SSH / AV / IDS'
    say '==========================================================='
    if [[ -x "$SPLUNK_BIN" ]] && "$SPLUNK_BIN" status >/dev/null 2>&1; then
        say 'PASS | Splunk process reports running'
    else warn 'Splunk not running or status unavailable'; failed=1; fi
    if [[ -x "$SPLUNK_BIN" ]] && "$SPLUNK_BIN" cmd btool inputs list --debug 2>/dev/null | grep -q -F 'splunktcp://9997'; then
        say 'PASS | Splunk TCP 9997 receiver stanza configured'
    else warn 'Splunk TCP 9997 receiver not found by btool'; failed=1; fi
    if [[ -x "$SPLUNK_BIN" ]] && "$SPLUNK_BIN" cmd btool authentication list splunk_auth 2>/dev/null | grep -Eq 'lockoutUsers[[:space:]]*=[[:space:]]*true'; then
        say 'PASS | Splunk lockoutUsers configured (not proof of runtime activation)'
    else warn 'Splunk lockout configuration not found'; failed=1; fi
    for p in 8000 8089 9997; do
        if port_listening "$p"; then
            say "PASS | TCP $p listening"
        else
            warn "TCP $p is not currently listening"
            if [[ " $CCDC_BASELINE_PORTS " == *" $p "* ]]; then
                warn "Previously listening TCP $p stopped listening"; failed=1
            elif [[ $CCDC_RESTARTED -eq 0 ]]; then
                say "INFO | TCP $p might require a planned Splunk restart"
            else
                failed=1
            fi
        fi
    done
    if [[ -x /usr/sbin/sshd ]]; then
        effective="$(/usr/sbin/sshd -T -C user=sysadmin,host=localhost,addr=127.0.0.1 2>/dev/null || true)"
        if /usr/sbin/sshd -t >/dev/null 2>&1 &&
           grep -Eq '^denyusers .*root([[:space:]]|$)' <<< "$effective" &&
           grep -Eq '^denyusers .*sysadmin([[:space:]]|$)' <<< "$effective"; then
            say 'PASS | root and sysadmin denied NEW SSH logins'
        else warn 'SSH restrictions not confirmed'; failed=1; fi
    else say 'SKIP | OpenSSH server is not installed'; fi
    if command -v ufw >/dev/null 2>&1; then
        local ufw_status
        ufw_status="$(ufw status verbose 2>&1 || true)"
        if grep -q '^Status: active' <<< "$ufw_status" &&
           grep -Eq '^Default: deny \(incoming\), allow \(outgoing\)' <<< "$ufw_status"; then
            say 'PASS | UFW active: incoming denied by default, outgoing allowed'
            for p in 22 8000 8089 9997; do
                if grep -Eq "^${p}/tcp[[:space:]]+ALLOW IN" <<< "$ufw_status"; then
                    say "PASS | UFW TCP $p inbound allowance shown"
                else
                    warn "UFW TCP $p allowance not confirmed"; failed=1
                fi
            done
        else
            warn 'UFW not active with expected defaults; inbound isolation NOT verified.'
            failed=1
        fi
    else
        warn 'UFW not installed: default-deny inbound NOT active.'
        failed=1
    fi
    for unit in clamav-daemon clamav-clamonacc clamav-freshclam suricata; do
        if systemctl is-active --quiet "${unit}.service"; then
            say "PASS | ${unit}.service active"
        else warn "${unit}.service is not active (may be intentionally uninstalled or skipped)"; fi
    done
    if [[ -f /etc/clamav/clamd.conf ]] && grep -q '^OnAccessPrevention no$' /etc/clamav/clamd.conf; then
        say 'PASS | ClamAV configured not to block file access'
    else warn 'ClamAV notify-only configuration not confirmed'; fi
    if [[ -n "$CCDC_CAPTURE_IFACE" ]] && ip link show dev "$CCDC_CAPTURE_IFACE" >/dev/null 2>&1; then
        say "PASS | Suricata monitored network interface exists: $CCDC_CAPTURE_IFACE"
    else
        say 'INFO | Suricata interface not set in this run; check service arguments if installed.'
    fi
    if command -v suricata >/dev/null 2>&1 && [[ -f /etc/suricata/suricata.yaml ]]; then
        local suricata_test=(suricata -T -c /etc/suricata/suricata.yaml)
        if [[ -n "$CCDC_CAPTURE_IFACE" ]]; then suricata_test+=("--af-packet=$CCDC_CAPTURE_IFACE"); fi
        if "${suricata_test[@]}" >/dev/null 2>&1; then
            say 'PASS | Suricata configuration parses'
        else warn 'Suricata config test failed'; failed=1; fi
    fi
    if [[ -s /var/lib/suricata/rules/suricata.rules ]]; then
        say 'PASS | Suricata detection rules exist'
    else
        warn 'Suricata detection rules missing; alerts may be limited'
    fi
    if [[ -f /etc/systemd/system/suricata.service.d/90-ccdc-passive-ids.conf ]]; then
        if grep -Eq '^ExecStart=.*--af-packet=' /etc/systemd/system/suricata.service.d/90-ccdc-passive-ids.conf; then
            say 'PASS | Suricata systemd override explicitly uses passive AF_PACKET'
        else
            warn 'Suricata passive AF_PACKET override not confirmed'; failed=1
        fi
    fi
    [[ ! -f /var/log/suricata/eve.json ]] || say 'PASS | Suricata EVE JSON file exists'
    [[ ! -f /var/log/clamav/clamonacc.log ]] || say 'PASS | ClamAV on-access log file exists'
    [[ ! -f "$SPLUNK_HOME/etc/apps/ccdc_endpoint_ids_inputs/local/inputs.conf" ]] || say 'PASS | Splunk Suricata/ClamAV monitor input files exist'
    df -h "$SPLUNK_HOME" | tail -n 1 || true
    if [[ $CCDC_SETUP_ERRORS -gt 0 ]]; then
        warn "$CCDC_SETUP_ERRORS setup operation(s) failed; review output above."
        failed=1
    fi
    say 'INFO | UFW was changed only if the operator approved APPLY-UFW.'
    say 'INFO | This script does not confirm scored-service reachability from NETLAB judges.'
    say 'INFO | Suricata only sees traffic visible to the Debian VM interface.'
    say 'INFO | Confirm actual EVE/ClamAV indexing by searching Splunk after it reloads.'
    if command -v passwd >/dev/null 2>&1; then
        say "INFO | Linux root password status: $(passwd -S root 2>/dev/null | awk '{print $2}' || echo unknown) (P=usable, L=locked, NP=no password)"
    fi
    say 'INFO | Review privileged Linux accounts separately with: sudo bash setup-splunk.sh --audit-admins'
    if ((failed)); then say 'RESULT | WARNINGS/FAILURES — investigate before relying on this setup';return 1;fi
    say 'RESULT | Static service/configuration checks passed (live detections not proven).'
}

case "${1:-}" in
    --help|-h) say 'Usage: sudo bash setup-splunk.sh [--verify|--audit-admins|--help]'; exit 0;;
    --audit-admins)
        [[ $EUID -eq 0 ]] || { say 'Run --audit-admins with sudo';exit 1; }
        ccdc_audit_admins
        exit 0;;
    --verify)
        [[ $EUID -eq 0 ]] || { say 'Run --verify with sudo';exit 1; }
        command -v ss >/dev/null 2>&1 || { say 'ss is required for verification';exit 1; }
        ccdc_verification
        exit $?;;
    '') ;;
    *) say 'Unknown argument; use --help.';exit 2;;
esac

[[ $EUID -eq 0 ]] || { say 'ERROR: Run with sudo.';exit 1; }
for command in python3 ss systemctl ps; do
    command -v "$command" >/dev/null 2>&1 || { say "ERROR: Required command missing: $command";exit 1; }
done
[[ -x "$SPLUNK_BIN" ]] || { say "ERROR: Splunk not found at $SPLUNK_BIN";exit 1; }

# Important: this check occurs before ANY configuration, unlike an add-on appended
# after the old script's unconditional Splunk restart.
if ccdc_ssh_session; then
    say 'STOP: This appears to be an SSH session. No setup changes made.' >&2
    say 'Run from a confirmed NETLAB VM console (not SSH).' >&2
    exit 3
fi

say '=== CCDC Splunk Enterprise Setup (Debian 12) ==='
say 'Current listening services:'
ss -lntup
snapshot_ports
if ! ip -o -4 addr show 2>/dev/null | grep -q "$EXPECTED_IP"; then
    warn "This VM may not currently hold the expected IP $EXPECTED_IP. Confirm the actual NETLAB topology."
fi
if yesno 'Refresh Debian package list (no upgrade unless separately approved)?'; then
    if apt-get update; then
        apt list --upgradable 2>/dev/null || true
        if yesno 'Install available Debian upgrades? Potential scoring disruption'; then
            apt-get upgrade -y || fail 'Debian package upgrade failed'
        fi
    else warn 'Package list refresh failed.'; fi
fi
if yesno 'Change Debian Linux root password interactively? (does not change Splunk Web admin)'; then
    ccdc_change_root_password || fail 'Linux root password update failed'
fi
ccdc_expire_selected_admins
ccdc_configure_receiver || fail 'Splunk receiver setup failed'
ccdc_configure_lockout || fail 'Splunk lockout setup failed'
ccdc_apply_ssh_restriction || fail 'SSH restriction failed'
ccdc_configure_firewall || fail 'UFW configuration failed'

say ''
say 'NOTE: ClamAV and Suricata are OPTIONAL because they use RAM, CPU and storage.'
say '      Both are detection-only; they do not block ports or alter firewall rules.'
if yesno 'Install/enable ClamAV REAL-TIME on-access notify-only monitoring?'; then
    ccdc_install_clamav || fail 'ClamAV configuration failed'
fi
if yesno 'Install/enable Suricata passive IDS (AF_PACKET)?'; then
    ccdc_install_suricata || fail 'Suricata configuration failed'
fi
if command -v clamonacc >/dev/null 2>&1 || command -v suricata >/dev/null 2>&1; then
    ccdc_setup_monitoring_input || fail 'Splunk AV/IDS log input setup failed'
fi

if yesno 'Restart Splunk now to activate pending configuration changes?'; then
    if "$SPLUNK_BIN" restart; then CCDC_RESTARTED=1; else fail 'Splunk restart failed'; fi
else
    warn 'Splunk not restarted: receiver/auth settings and new log monitors may remain pending.'
fi

ccdc_verification
