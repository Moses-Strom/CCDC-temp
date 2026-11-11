#!/usr/bin/env bash
# CCDC | Debian 12 / Splunk Enterprise 10.0.2 server setup
# Intended VM: 172.20.240.20 (verify in your actual CCDC pod)
# Includes Splunk receiver/auth protection + console-only SSH restriction
# + ClamAV notify-only real-time scanning + passive Suricata IDS.
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

ccdc_change_admin_password() {
    python3 - <<'PY_PASSWORD'
import base64, getpass, ssl, sys, urllib.error, urllib.parse, urllib.request
old=getpass.getpass('Current Splunk admin password: ')
new=getpass.getpass('New Splunk admin password: ')
confirm=getpass.getpass('Confirm new password: ')
if not new or new!=confirm: sys.exit('ERROR: Passwords do not match or are empty.')
auth=base64.b64encode(('admin:'+old).encode()).decode()
data=urllib.parse.urlencode({'password':new,'oldpassword':old}).encode()
req=urllib.request.Request('https://127.0.0.1:8089/services/authentication/users/admin',data=data,headers={'Authorization':'Basic '+auth},method='POST')
# Loopback only. The local Splunk management API may use a self-signed cert.
try:
    with urllib.request.urlopen(req,context=ssl._create_unverified_context(),timeout=15) as response: response.read()
except urllib.error.HTTPError as exc: sys.exit(f'ERROR: Password update returned HTTP {exc.code}')
except urllib.error.URLError as exc: sys.exit(f'ERROR: Local Splunk API unreachable: {exc.reason}')
print('Splunk admin password updated.')
PY_PASSWORD
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
    local candidate="${CCDC_SURICATA_IFACE:-}"
    if [[ -z "$candidate" ]]; then
        candidate="$(ip -o -4 addr show scope global 2>/dev/null | awk '$4 ~ /^172\.20\.240\.20\// {print $2; exit}')"
    fi
    if [[ -z "$candidate" ]]; then
        candidate="$(ip -4 route show default 2>/dev/null | awk 'NR==1 {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1);exit}}')"
    fi
    if [[ -z "$candidate" ]]; then
        candidate="$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2}' | sort -u)"
        [[ $(wc -w <<< "$candidate") -eq 1 ]] || candidate=''
    fi
    if [[ -z "$candidate" || ! "$candidate" =~ ^[A-Za-z0-9_.:-]+$ || "$candidate" == lo ]] ||
       ! ip link show dev "$candidate" >/dev/null 2>&1; then
        warn 'Capture interface ambiguous/unavailable. Run: ip -br addr; specify CCDC_SURICATA_IFACE=ens18 (actual interface).'
        return 1
    fi
    CCDC_CAPTURE_IFACE="$candidate"
    say "Suricata passive capture interface: $CCDC_CAPTURE_IFACE"
}

ccdc_install_suricata() {
    say '=== Install/configure passive Suricata IDS ==='
    command -v ip >/dev/null 2>&1 || { warn 'iproute2 utility unavailable'; return 1; }
    ccdc_choose_iface || return 1
    if ! command -v suricata >/dev/null 2>&1 || ! command -v suricata-update >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends suricata suricata-update || return 1
    fi
    local config='/etc/suricata/suricata.yaml' dropdir='/etc/systemd/system/suricata.service.d'
    [[ -f "$config" ]] || { warn 'Suricata YAML configuration missing'; return 1; }
    mkdir -p "$dropdir" /var/log/suricata
    # Debian Suricata's default unit is an AF_PACKET forking service. Override ONLY
    # its capture interface, not the detection/packet path; no NFQUEUE/IPS mode.
    if [[ -f "$dropdir/90-ccdc-passive-ids.conf" ]]; then
        cp -p "$dropdir/90-ccdc-passive-ids.conf" "$dropdir/90-ccdc-passive-ids.conf.bak.$(date +%Y%m%d-%H%M%S).$$"
    fi
    cat > "$dropdir/90-ccdc-passive-ids.conf" <<EOF_SUR_UNIT
[Service]
ExecStart=
ExecStart=$(command -v suricata) -D --af-packet=$CCDC_CAPTURE_IFACE -c $config --pidfile /run/suricata.pid
EOF_SUR_UNIT
    if [[ ! -s /var/lib/suricata/rules/suricata.rules ]]; then
        suricata-update enable-source et/open || warn 'Could not enable ET Open rules (possibly offline).'
        suricata-update || warn 'Rule download unavailable; passive capture may run with limited detections.'
    fi
    if ! suricata -T -c "$config" --af-packet="$CCDC_CAPTURE_IFACE" >/var/log/suricata/ccdc-config-test.log 2>&1; then
        warn 'Suricata configuration failed; see /var/log/suricata/ccdc-config-test.log.'
        return 1
    fi
    systemctl daemon-reload
    if ! systemctl enable suricata.service || ! systemctl restart suricata.service; then
        warn 'suricata.service could not start; inspect journalctl -u suricata.'
        return 1
    fi
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
    say 'INFO | No host/network firewall settings were changed by this script.'
    say 'INFO | This script does not confirm scored-service reachability from NETLAB judges.'
    say 'INFO | Suricata only sees traffic visible to the Debian VM interface.'
    say 'INFO | Confirm actual EVE/ClamAV indexing by searching Splunk after it reloads.'
    if ((failed)); then say 'RESULT | WARNINGS/FAILURES — investigate before relying on this setup';return 1;fi
    say 'RESULT | Static service/configuration checks passed (live detections not proven).'
}

case "${1:-}" in
    --help|-h) say 'Usage: sudo bash setup-splunk.sh [--verify|--help]'; exit 0;;
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
if yesno 'Change existing Splunk admin password?'; then
    ccdc_change_admin_password || fail 'Splunk admin password update failed'
fi
ccdc_configure_receiver || fail 'Splunk receiver setup failed'
ccdc_configure_lockout || fail 'Splunk lockout setup failed'
ccdc_apply_ssh_restriction || fail 'SSH restriction failed'

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
