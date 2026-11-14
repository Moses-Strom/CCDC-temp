#!/usr/bin/env bash
# CCDC | Debian 12 / Splunk Enterprise 10.0.x server setup
# Intended VM: 172.20.240.20 (verify in your actual CCDC pod)
# Includes Splunk receiver/auth protection + SSH restriction + interactive Linux root
# password rotation + optional administrator account audit/expiry
# + ClamAV notify-only real-time scanning + passive Suricata IDS
# + opt-in UFW inbound default-deny with TCP 22/8000/8089/9997 and UDP 9997 (if syslog configured).
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
CCDC_IPV6_UFW_SET=0
# Verification-only bookkeeping for operations performed in this invocation.
CCDC_ROOT_PASSWORD_CHANGED=0
CCDC_ROOT_PASSWORD_REQUESTED=0
CCDC_CLAMAV_REQUESTED=0
CCDC_SURICATA_REQUESTED=0
CCDC_SPLUNK_RESTART_REQUESTED=0
CCDC_EXPIRED_ACCOUNTS=()
CCDC_SPLUNK_CREDENTIALS_BEFORE=''
# Status for optional GitHub-hosted hardening features during THIS invocation.
# Standalone --verify reports independently observable settings instead.
CCDC_UPGRADE_STATUS=SKIP
# Retry bookkeeping is separate from CCDC_SETUP_ERRORS: if an initial failure
# recovers, the final PASS/FAIL status must reflect the actual final state.
CCDC_UPGRADE_FIRST_FAILED=0
CCDC_UPGRADE_RETRY_SUCCEEDED=0
CCDC_POSTUPGRADE_RESTARTED=0
CCDC_POSTUPGRADE_RESTART_PENDING=0
CCDC_SECURITY_AUDIT_STATUS=SKIP
CCDC_POSTGRES_STATUS=SKIP
CCDC_LOOKUP_STATUS=SKIP
CCDC_GATEWAY_STATUS=SKIP
CCDC_AUDITD_STATUS=SKIP
CCDC_LOGCOVERAGE_STATUS=SKIP
CCDC_SYSLOG_STATUS=SKIP
CCDC_SYSLOG_REQUESTED=0
CCDC_SYSLOG_CONF=/etc/rsyslog.d/25-ccdc-udp9997.conf
CCDC_SYSLOG_DIR=/var/log/remote-syslog
CCDC_SYSLOG_LOG=$CCDC_SYSLOG_DIR/udp9997.log

say() { printf '%s\n' "$*"; }
warn() { printf 'WARN | %s\n' "$*" >&2; }
fail() { printf 'FAIL | %s\n' "$*" >&2; CCDC_SETUP_ERRORS=$((CCDC_SETUP_ERRORS+1)); }
yesno() { local answer=''; read -r -p "$1 [y/N]: " answer || true; [[ "$answer" =~ ^[Yy]$ ]]; }

# Run a reviewed security helper, downloaded from a specific GitHub ref or
# copied from a local offline checkout. Use a pinned commit in CCDC_REPO_REF
# after validating the final script set. No script is executed on download error.
ccdc_run_github_helper() {
    local interpreter="$1" relative="$2" temp='' url='' rc=0
    shift 2
    case "$interpreter" in bash|python3) ;; *) warn "Unsupported helper: $interpreter"; return 2 ;; esac
    temp="$(mktemp /root/ccdc-helper.XXXXXXXX)" || return 1
    if [[ -n "${CCDC_OFFLINE_ROOT:-}" ]]; then
        if ! cp -- "${CCDC_OFFLINE_ROOT%/}/$relative" "$temp"; then
            warn "Offline helper missing: $relative"
            rm -f -- "$temp"; return 1
        fi
    else
        if ! command -v wget >/dev/null 2>&1; then
            warn 'wget unavailable for helper download'
            rm -f -- "$temp"; return 1
        fi
        url="https://raw.githubusercontent.com/Moses-Strom/CCDC-temp/${CCDC_REPO_REF:-main}/$relative"
        if ! wget --https-only -q --tries=2 --timeout=20 -O "$temp" "$url"; then
            warn "Failed downloading $relative"
            rm -f -- "$temp"; return 1
        fi
    fi
    if [[ ! -s "$temp" ]]; then warn "Downloaded helper empty: $relative";rm -f -- "$temp";return 1;fi
    if [[ "$interpreter" == bash ]]; then
        if ! bash -n "$temp"; then warn "Invalid Bash syntax: $relative";rm -f -- "$temp";return 1;fi
    fi
    if "$interpreter" "$temp" "$@"; then rc=0; else rc=$?; fi
    rm -f -- "$temp"
    return "$rc"
}

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

# A UDP socket and a TCP socket with the same port number are distinct.
# Splunk forwarders retain TCP 9997; rsyslog accepts raw UDP syslog on 9997.
ccdc_udp9997_listening() {
    ss -H -lnu 2>/dev/null | awk '$4 ~ /:9997$/ {found=1} END {exit !found}'
}

ccdc_syslog_udp_configured() {
    [[ -f "$CCDC_SYSLOG_CONF" && ! -L "$CCDC_SYSLOG_CONF" ]] &&
        grep -Fqx 'input(type="imudp" port="9997" ruleset="ccdc_udp9997")' "$CCDC_SYSLOG_CONF"
}

# Detect missing rsyslog main configuration BEFORE installing the UDP drop-in.
# Error -2104 means a referenced configuration file/directory could not be found.
# Never invent a substitute rsyslog.conf or silently replace customized settings.
ccdc_rsyslog_preflight() {
    local main_conf='/etc/rsyslog.conf' saved='' confirm='' diagnostic=''

    if [[ -L "$main_conf" ]]; then
        warn "$main_conf is a symlink; review its target manually before enabling UDP syslog."
        return 1
    fi
    if [[ ! -f "$main_conf" ]]; then
        warn "Missing $main_conf (possible rsyslog -2104 cause)."
        if ! dpkg-query -W -f='${Status}' rsyslog 2>/dev/null | grep -Fq 'install ok installed' ||
           ! dpkg -S "$main_conf" >/dev/null 2>&1; then
            warn 'Rsyslog package ownership is not confirmed; refusing automatic repair.'
            return 1
        fi
        read -r -p 'Restore missing Debian-packaged rsyslog.conf using apt reinstall? Type RESTORE-RSYSLOG-CONF: ' confirm || true
        if [[ "$confirm" != RESTORE-RSYSLOG-CONF ]]; then
            warn 'Rsyslog main configuration not restored; UDP syslog setup skipped.'
            return 1
        fi
        # --force-confmiss restores missing Debian conffiles, not existing edited ones.
        if ! DEBIAN_FRONTEND=noninteractive apt-get -o 'Dpkg::Options::=--force-confmiss' \
             install --reinstall -y --no-install-recommends rsyslog; then
            warn 'Package restoration failed; review apt output and package sources.'
            return 1
        fi
    fi
    if [[ ! -s "$main_conf" || ! -r "$main_conf" ]]; then
        warn "Rsyslog main configuration is empty/unreadable: $main_conf"
        return 1
    fi

    # The stock Debian include may error -2104 if this optional directory is absent.
    # Refuse an unsafe symlink/path and create ONLY the missing directory.
    if [[ -L /etc/rsyslog.d || ( -e /etc/rsyslog.d && ! -d /etc/rsyslog.d ) ]]; then
        warn '/etc/rsyslog.d is not a normal directory; inspect before installing the UDP receiver.'
        return 1
    fi
    if [[ ! -d /etc/rsyslog.d ]]; then
        install -d -m 0755 -o root -g root /etc/rsyslog.d || return 1
        say 'INFO | Created missing /etc/rsyslog.d directory.'
    fi

    # Debian normally includes /etc/rsyslog.d/*.conf. Without that directive,
    # a valid drop-in is ignored and no UDP socket will be opened.
    if ! grep -Eq '^[[:space:]]*(\$IncludeConfig[[:space:]]+|include\([[:space:]]*file[[:space:]]*=[[:space:]]*"?)/etc/rsyslog\.d/' "$main_conf"; then
        warn "$main_conf does not visibly include /etc/rsyslog.d/; UDP listener drop-in may be ignored."
        read -r -p 'Back up main config and add the standard optional rsyslog.d include? Type ADD-RSYSLOG-INCLUDE: ' confirm || true
        if [[ "$confirm" != ADD-RSYSLOG-INCLUDE ]]; then
            warn 'Rsyslog include not approved; stopping before creating a nonfunctional UDP listener.'
            return 1
        fi
        saved="${main_conf}.bak.ccdc.$(date +%Y%m%d-%H%M%S).$$"
        cp -p -- "$main_conf" "$saved" || return 1
        if ! printf '\n# CCDC: load Debian rsyslog drop-ins\ninclude(file="/etc/rsyslog.d/*.conf" mode="optional")\n' >> "$main_conf"; then
            cp -p -- "$saved" "$main_conf" || true
            warn "Unable to add rsyslog include; restored backup $saved"
            return 1
        fi
        say "INFO | Main rsyslog config backup: $saved"
    fi

    diagnostic="$(mktemp /root/ccdc-rsyslog-preflight.XXXXXXXX)" || return 1
    chmod 0600 "$diagnostic"
    if ! rsyslogd -N1 -f "$main_conf" >"$diagnostic" 2>&1; then
        warn "Existing rsyslog configuration is invalid. Validation output ($diagnostic):"
        tail -n 30 "$diagnostic" >&2 || true
        if [[ -n "$saved" ]]; then
            cp -p -- "$saved" "$main_conf" || warn "Could not restore $main_conf from $saved"
        fi
        return 1
    fi
    rm -f -- "$diagnostic"
    say "PASS | Existing rsyslog config preflight passed: $main_conf"
}

ccdc_rsyslog_failure_diagnostics() {
    warn 'Rsyslog details (look for a file/path named near error -2104):'
    systemctl status rsyslog.service --no-pager -l 2>&1 | tail -n 18 >&2 || true
    journalctl -u rsyslog.service -n 25 --no-pager 2>&1 | tail -n 25 >&2 || true
    ss -H -lunp 2>/dev/null | grep -E '(:9997[[:space:]]|:9997$)' >&2 || true
}

ccdc_setup_syslog_udp_9997() {
    say '=== Configure rsyslog raw syslog receiver on UDP 9997 ==='
    say 'Splunk Universal Forwarders keep using TCP 9997; this uses a separate UDP socket.'
    local backup='' temp='' was_present=0 attempt
    if ! command -v rsyslogd >/dev/null 2>&1; then
        say 'Installing Debian rsyslog package (no broad package upgrade) ...'
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rsyslog || return 1
    fi
    command -v rsyslogd >/dev/null 2>&1 || { warn 'rsyslogd unavailable after installation'; return 1; }
    # Splunk's daemon user needs read ACLs for the protected syslog file.
    if ! command -v setfacl >/dev/null 2>&1; then
        say 'Installing acl package so Splunk can read the protected remote syslog file ...'
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends acl || return 1
    fi
    command -v setfacl >/dev/null 2>&1 || { warn 'setfacl unavailable; cannot configure Splunk read ACL'; return 1; }
    if ! getent passwd syslog >/dev/null || ! getent group adm >/dev/null; then
        warn 'Expected Debian syslog account or adm group missing; refusing to configure log directory.'
        return 1
    fi
    if [[ -L "$CCDC_SYSLOG_CONF" || -L "$CCDC_SYSLOG_DIR" || -L "$CCDC_SYSLOG_LOG" ]]; then
        warn 'Syslog config/log path is a symlink; inspect manually before writing.'
        return 1
    fi
    if ccdc_udp9997_listening && ! ccdc_syslog_udp_configured; then
        warn 'UDP 9997 is already bound without the CCDC config; refusing to claim an unknown listener.'
        return 1
    fi
    # Do this before creating the drop-in; prevents -2104 and silent include failures.
    ccdc_rsyslog_preflight || return 1
    install -d -m 0750 -o syslog -g adm "$CCDC_SYSLOG_DIR" || return 1
    if [[ ! -e "$CCDC_SYSLOG_LOG" ]]; then
        install -m 0640 -o syslog -g adm /dev/null "$CCDC_SYSLOG_LOG" || return 1
    fi
    mkdir -p /etc/rsyslog.d || return 1
    if [[ -f "$CCDC_SYSLOG_CONF" ]]; then
        was_present=1
        backup="${CCDC_SYSLOG_CONF}.bak.$(date +%Y%m%d-%H%M%S).$$"
        cp -p -- "$CCDC_SYSLOG_CONF" "$backup" || return 1
    fi
    temp="$(mktemp /etc/rsyslog.d/.ccdc-udp9997.XXXXXXXX)" || return 1
    cat > "$temp" <<'EOF_CCDC_SYSLOG'
# CCDC: remote syslog only. Existing local syslog routing remains intact.
module(load="imudp")
ruleset(name="ccdc_udp9997") {
    action(type="omfile" file="/var/log/remote-syslog/udp9997.log"
           fileOwner="syslog" fileGroup="adm" fileCreateMode="0640")
    stop
}
input(type="imudp" port="9997" ruleset="ccdc_udp9997")
EOF_CCDC_SYSLOG
    chmod 0644 "$temp"
    mv -f -- "$temp" "$CCDC_SYSLOG_CONF" || return 1
    if ! rsyslogd -N1 -f /etc/rsyslog.conf; then
        warn 'Rsyslog validation failed after adding UDP 9997; restoring previous config.'
        ccdc_rsyslog_failure_diagnostics
        if ((was_present)); then cp -p -- "$backup" "$CCDC_SYSLOG_CONF"; else rm -f -- "$CCDC_SYSLOG_CONF"; fi
        return 1
    fi
    if ! systemctl enable rsyslog.service || ! systemctl restart rsyslog.service; then
        warn 'Rsyslog failed to enable/restart; restoring prior config.'
        ccdc_rsyslog_failure_diagnostics
        if ((was_present)); then cp -p -- "$backup" "$CCDC_SYSLOG_CONF"; else rm -f -- "$CCDC_SYSLOG_CONF"; fi
        systemctl restart rsyslog.service || true
        return 1
    fi
    for attempt in 1 2 3 4 5; do
        if systemctl is-active --quiet rsyslog.service && ccdc_udp9997_listening; then break; fi
        sleep 1
    done
    if ! systemctl is-active --quiet rsyslog.service || ! ccdc_udp9997_listening; then
        warn 'rsyslog.service is not active or UDP 9997 does not listen; restoring config.'
        ccdc_rsyslog_failure_diagnostics
        if ((was_present)); then cp -p -- "$backup" "$CCDC_SYSLOG_CONF"; else rm -f -- "$CCDC_SYSLOG_CONF"; fi
        systemctl restart rsyslog.service || true
        return 1
    fi
    # Prevent unbounded syslog growth. No service restart is needed for this file.
    if command -v logrotate >/dev/null 2>&1; then
        cat > /etc/logrotate.d/ccdc-remote-syslog <<'EOF_CCDC_ROTATE'
/var/log/remote-syslog/udp9997.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0640 syslog adm
    sharedscripts
    postrotate
        /bin/systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
EOF_CCDC_ROTATE
    else
        warn 'logrotate is absent; configure log rotation before accepting sustained syslog volumes.'
    fi
    say 'PASS | rsyslog is receiving on UDP 9997; file is ready for Splunk monitoring.'
    say 'REVIEW | Remote sender/firewall and live Splunk ingestion must be tested separately.'
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
        CCDC_ROOT_PASSWORD_CHANGED=1
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
                CCDC_EXPIRED_ACCOUNTS+=("$target")
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
    say 'Inbound TCP: 22/SSH, 8000/Web, 8089/management, 9997/forwarders.'
    say 'If the CCDC rsyslog receiver is configured: also allow UDP 9997 for remote syslog.'
    say 'Outbound connections: ALLOW by default (required for packages, DNS, clocks and other dependencies).'
    say 'Standard UFW ICMP handling is retained; verify CCDC ping scoring afterward.'
    say 'This changes ONLY the Debian VM firewall, not the Palo Alto firewall.'
    say 'NOTE: Palo Alto/VyOS or upstream ACLs must also allow UDP 9997 from authorized senders.'
    say 'WARNING: Replacing existing UFW user rules could interrupt additional scored services.'
    if ! yesno 'Reset UFW rules to the listed inbound TCP allowances (and UDP 9997 if rsyslog is configured) and ENABLE default-deny'; then
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
    # Only expose UDP when the CCDC rsyslog listener was installed/configured.
    # This is a separate protocol, not the Splunk-to-Splunk TCP 9997 receiver.
    if ccdc_syslog_udp_configured; then
        if ! ufw allow 9997/udp comment 'CCDC remote syslog'; then
            warn 'Could not stage UDP 9997; do not assume remote syslog will arrive.'
            return 1
        fi
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
    say 'PASS | UFW active: deny incoming; allow outgoing; TCP allowances and configured UDP syslog rule staged.'
    say 'Verify remote scoring, forwarding and ping from other CCDC machines.'
}

# Optional UFW IPv6 restriction. Requires active UFW; preserves existing IPv4 rules.
# UFW's IPV6=no filters non-loopback IPv6 traffic in both directions while UFW is active.
ccdc_optional_ufw_ipv6_block() {
    if ! yesno 'Block non-loopback IPv6 with UFW? (may block inbound AND outbound IPv6)'; then
        say 'SKIP | IPv6 block not selected'
        return 0
    fi
    if ccdc_ssh_session; then warn 'IPv6 change requires local VM console'; return 1; fi
    if ! command -v ufw >/dev/null 2>&1 ||
       ! LC_ALL=C ufw status 2>/dev/null | grep -Eq '^Status: active$'; then
        warn 'UFW not active; refusing to change IPv6 or activate firewall automatically'
        return 1
    fi
    if [[ ! -f /etc/default/ufw || -L /etc/default/ufw ]]; then
        warn 'Expected regular /etc/default/ufw file not found; no changes made'
        return 1
    fi
    local matches backup confirm=''
    matches="$(grep -Ec '^[[:space:]]*IPV6[[:space:]]*=' /etc/default/ufw || true)"
    if [[ "$matches" != 1 ]]; then
        warn "Expected one IPV6= setting in /etc/default/ufw, found $matches"
        return 1
    fi
    say 'IPv6 global addresses:'; ip -6 addr show scope global || true
    say 'IPv6 default routes:'; ip -6 route show default || true
    say 'Confirm DNS, monitoring and scoring do not use IPv6 before proceeding.'
    read -r -p 'Type BLOCK-IPV6 to confirm: ' confirm || true
    if [[ "$confirm" != BLOCK-IPV6 ]]; then
        say 'SKIP | IPv6 block not confirmed'
        return 0
    fi
    if grep -Eq '^[[:space:]]*IPV6[[:space:]]*=[[:space:]]*no[[:space:]]*$' /etc/default/ufw; then
        say 'PASS | UFW already configured IPV6=no'
        CCDC_IPV6_UFW_SET=1
        return 0
    fi
    backup="/root/ccdc-ufw-before-ipv6.$(date +%Y%m%d-%H%M%S).$$"
    cp -p -- /etc/default/ufw "$backup" || { warn 'IPv6 config backup failed';return 1; }
    if ! python3 - /etc/default/ufw <<'PY_UFW_IPV6'
from pathlib import Path
import re, sys
p=Path(sys.argv[1]); s=p.read_text()
s,n=re.subn(r'(?m)^[ \t]*IPV6[ \t]*=.*$', 'IPV6=no', s)
if n != 1: raise SystemExit('Unexpected IPV6 setting count')
p.write_text(s)
PY_UFW_IPV6
    then
        cp -p -- "$backup" /etc/default/ufw || true
        warn 'Could not set IPV6=no; restored backup'
        return 1
    fi
    if ! ufw reload; then
        warn 'UFW reload failed; restoring backup and attempting reload'
        cp -p -- "$backup" /etc/default/ufw || true
        ufw reload || warn 'Rollback reload also failed; inspect via console'
        return 1
    fi
    CCDC_IPV6_UFW_SET=1
    say "PASS | UFW IPV6=no; backup $backup"
    say 'INFO | Verify scoring and host IPv6 reachability externally; a config check alone cannot prove filtering.'
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


# Deny privilege elevation in SSH sessions, including NOPASSWD sudo and su.
# Applies only to the PAM entry points listed below. Console administration is preserved.
# Does not claim to stop non-PAM privilege mechanisms or already-root processes.
ccdc_block_ssh_elevation() {
    say '=== Restrict sudo/su and other PAM-mediated administration over SSH ==='
    local gate='/usr/local/sbin/ccdc-deny-ssh-elevation'
    local pam_dir='/etc/pam.d' service target backup_dir backup tmp line
    local services=(sudo sudo-i su su-l runuser runuser-l polkit-1)
    local sshd_rule="account requisite pam_exec.so quiet type=account $gate"
    local rules=(
        "auth requisite pam_exec.so quiet type=auth $gate"
        "account requisite pam_exec.so quiet type=account $gate"
        "session requisite pam_exec.so quiet type=open_session $gate"
    )

    if ccdc_ssh_session; then warn 'SSH elevation policy cannot be installed from SSH.'; return 1; fi
    if [[ ! -f "$pam_dir/sudo" || ! -f "$pam_dir/su" ]]; then
        warn 'Required sudo/su PAM definitions missing; restriction NOT installed.'; return 1
    fi
    if ! find /lib /usr/lib -name pam_exec.so -print -quit 2>/dev/null | grep -q .; then
        warn 'pam_exec.so missing: cannot safely enforce SSH elevation restrictions.'; return 1
    fi
    # Securely keep copies of all edited PAM definitions for manual recovery.
    backup_dir="/root/ccdc-ssh-pam-backup-$(date +%Y%m%d-%H%M%S)-$$"
    mkdir -m 0700 -p "$backup_dir"
    install -d -m 0755 /usr/local/sbin
    tmp="$(mktemp /usr/local/sbin/.ccdc-ssh-elev.XXXXXX)"
    cat > "$tmp" <<'EOF_ELEVATION_GATE'
#!/bin/sh
# PAM runs this from the privilege-elevating process; deny when SSH is an ancestor.
# SSHD account check: reject ANY UID 0 login, even an unexpected alias for root.
if [ "${PAM_SERVICE:-}" = sshd ]; then
    [ -n "${PAM_USER:-}" ] || exit 1
    user_uid=$(id -u -- "$PAM_USER" 2>/dev/null) || exit 1
    [ "$user_uid" -ne 0 ]
    exit $?
fi
# sudo/su checks: inherited SSH variables are a conservative denial signal.
[ -z "${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-}" ] || exit 1
pid="$PPID"
hops=0
while [ "$pid" -gt 1 ] 2>/dev/null && [ "$hops" -lt 60 ]; do
    [ -r "/proc/$pid/comm" ] || break
    IFS= read -r name < "/proc/$pid/comm" || break
    case "$name" in sshd|sshd-session) exit 1;; esac
    parent=$(awk '/^PPid:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null)
    case "$parent" in ''|*[!0-9]*) break;; esac
    pid="$parent"
    hops=$((hops + 1))
done
exit 0
EOF_ELEVATION_GATE
    chmod 0755 "$tmp"
    chown root:root "$tmp"
    if ! /bin/sh -n "$tmp"; then
        rm -f "$tmp"
        warn 'SSH PAM helper syntax invalid; nothing installed.'
        return 1
    fi
    # A test executed from the required local NETLAB console should succeed.
    if ! /bin/sh "$tmp"; then
        rm -f "$tmp"
        warn 'SSH PAM helper rejected local console; nothing installed.'
        return 1
    fi
    mv -f "$tmp" "$gate"

    for service in "${services[@]}"; do
        target="$pam_dir/$service"
        [[ -f "$target" ]] || continue
        if ! cp -p -- "$target" "$backup_dir/$service"; then
            warn "Could not back up PAM $service; refusing to modify it."
            return 1
        fi
        tmp="$(mktemp "$pam_dir/.ccdc-pam.XXXXXX")"
        # Do not duplicate exact rules when running setup again.
        {
            for line in "${rules[@]}"; do
                if ! grep -Fqx -- "$line" "$target"; then printf '%s\n' "$line"; fi
            done
            cat -- "$target"
        } > "$tmp"
        if ! chmod --reference="$target" "$tmp" || ! chown --reference="$target" "$tmp"; then
            rm -f -- "$tmp"
            warn "Could not preserve PAM $service permissions; config unchanged."
            return 1
        fi
        if ! mv -f -- "$tmp" "$target"; then
            rm -f -- "$tmp"
            warn "Cannot update PAM $service; restore configuration from $backup_dir"
            return 1
        fi
    done
    # Also block unexpected UID 0 aliases from authenticating through SSHD PAM.
    target="$pam_dir/sshd"
    if [[ -f "$target" ]]; then
        if ! cp -p -- "$target" "$backup_dir/sshd"; then
            warn 'Cannot back up sshd PAM policy; UID 0 SSH account restriction not installed.'
            return 1
        fi
        if ! grep -Fqx -- "$sshd_rule" "$target"; then
            tmp="$(mktemp "$pam_dir/.ccdc-pam-sshd.XXXXXX")"
            { printf '%s\n' "$sshd_rule"; cat -- "$target"; } > "$tmp"
            if ! chmod --reference="$target" "$tmp" || ! chown --reference="$target" "$tmp" ||
               ! mv -f -- "$tmp" "$target"; then
                rm -f -- "$tmp"
                warn 'Could not safely install sshd UID 0 PAM guard.'
                return 1
            fi
        fi
    else
        warn 'sshd PAM policy is missing; cannot protect unexpected UID 0 SSH aliases.'
        return 1
    fi
    say "PAM configuration backups: $backup_dir"
    say 'SSH-initiated sudo, sudo -i, su and other available PAM elevation services are now restricted.'
    say 'NOTE: PAM policy cannot guarantee blocking all possible non-PAM privilege mechanisms.'
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
            lines[i]=m.group(1)+iface+m.group(3)+("\n" if line.endswith("\n") else "")
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
    if grep -Eqi '(^|[^0-9])0 (rules|signatures) (successfully )?loaded|(^|[^0-9])0 signatures processed' /var/log/suricata/ccdc-config-test.log; then
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
    say '=== Configure Splunk local monitoring for ClamAV, Suricata, auditd and remote syslog ==='
    local app="$SPLUNK_HOME/etc/apps/ccdc_endpoint_ids_inputs" owner group
    mkdir -p "$app/default" "$app/local"
    cat > "$app/default/app.conf" <<'EOF_APP'
[install]
is_configured = 1
[ui]
is_visible = 0
[launcher]
author = CCDC
description = Local Suricata IDS, ClamAV, auditd and remote syslog monitoring
EOF_APP
    cat > "$app/local/inputs.conf" <<'EOF_MON'
# Monitors only have events once their source log exists and is readable.
[monitor:///var/log/suricata/eve.json]
disabled = 0
sourcetype = suricata:eve

[monitor:///var/log/clamav/clamonacc.log]
disabled = 0
sourcetype = clamav:clamonacc

[monitor:///var/log/audit/audit.log]
disabled = 0
sourcetype = linux:audit
index = main

[monitor:///var/log/remote-syslog/udp9997.log]
disabled = 0
sourcetype = ccdc:remote_syslog
index = main
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
            for directory in /var/log/suricata /var/log/clamav /var/log/audit /var/log/remote-syslog; do
                if [[ -d "$directory" ]]; then
                    setfacl -m "u:$owner:rx" "$directory" || warn "ACL failed for $directory"
                    setfacl -m "d:u:$owner:rX" "$directory" || warn "Default ACL failed for $directory"
                fi
            done
            for logfile in /var/log/suricata/eve.json /var/log/clamav/clamonacc.log /var/log/audit/audit.log /var/log/remote-syslog/udp9997.log; do
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
    say "Splunk Suricata + ClamAV + auditd + remote syslog monitors saved under $app (requires a safe Splunk restart to activate)."
}

# Verification below is read-only: it never installs or reconfigures services.
# PASS means the specific check succeeded, not that live CCDC scoring was tested.
ccdc_verification() {
    local failed=0 warnings=0 checks=0 effective p unit result
    local ufw_status gate='/usr/local/sbin/ccdc-deny-ssh-elevation'
    local files=(sudo sudo-i su su-l runuser runuser-l polkit-1)
    local auth_output inputs_output
    local credential_now='' account
    say ''
    say '==========================================================='
    if [[ "${1:-}" == 'final' ]]; then
        say ' CCDC Splunk Server Setup Complete'
    else
        say ' CCDC Splunk Server Read-Only Verification'
    fi
    say '==========================================================='
    say ' PASS / FAIL / SKIP verification of each setup area'
    say '-----------------------------------------------------------'
    # Password rotation can only be proven for this invocation. Root remains protected.
    if [[ "$CCDC_ROOT_PASSWORD_REQUESTED" -eq 1 ]]; then
        if [[ "$CCDC_ROOT_PASSWORD_CHANGED" -eq 1 && "$(passwd -S root 2>/dev/null | awk '{print $2}')" == P ]]; then
            say 'PASS | Interactive Linux root password rotation completed; root remains enabled'
        else say 'FAIL | Root password rotation not confirmed'; failed=1; fi
    elif [[ "${1:-}" == 'final' ]]; then
        say 'SKIP | Root password change was not requested'
    else
        say 'SKIP | Root password-change history cannot be verified read-only'
    fi
    if [[ "$(id -u root 2>/dev/null || true)" == 0 ]] &&
       [[ "$(ccdc_account_expiry root)" != expired ]]; then
        say 'PASS | Linux root account exists and is not expired'
    else say 'FAIL | Linux root account missing or expired'; failed=1; fi
    if [[ -n "$CCDC_SPLUNK_CREDENTIALS_BEFORE" ]]; then
        credential_now="$(sha256sum "$SPLUNK_HOME/etc/passwd" 2>/dev/null | awk '{print $1}' || true)"
        if [[ -n "$credential_now" && "$credential_now" == "$CCDC_SPLUNK_CREDENTIALS_BEFORE" ]]; then
            say 'PASS | Splunk credential store unchanged during this setup run'
        else say 'FAIL | Splunk credential store changed during setup; inspect account state'; failed=1; fi
    else
        say 'SKIP | Splunk admin credential integrity: no before/after baseline available'
    fi
    # Account expiration is checked for each account changed in this run.
    if (( ${#CCDC_EXPIRED_ACCOUNTS[@]} )); then
        for account in "${CCDC_EXPIRED_ACCOUNTS[@]}"; do
            if [[ "$(ccdc_account_expiry "$account")" == expired ]]; then
                say "PASS | Requested privileged account remains expired: $account"
            else say "FAIL | Requested account not expired: $account"; failed=1; fi
        done
    else
        say 'SKIP | No privileged accounts were expired during this invocation'
    fi
    if [[ -x "$SPLUNK_BIN" ]] && "$SPLUNK_BIN" status >/dev/null 2>&1; then
        say 'PASS | Splunk reports running'
    else say 'FAIL | Splunk not running or status unavailable'; failed=1; fi
    if [[ "$CCDC_SPLUNK_RESTART_REQUESTED" -eq 1 ]]; then
        if [[ "$CCDC_RESTARTED" -eq 1 ]]; then say 'PASS | Requested Splunk restart command succeeded'
        else say 'FAIL | Requested Splunk restart failed'; failed=1; fi
    else
        say 'SKIP | Splunk restart was not requested (or not measurable in --verify mode)'
    fi
    # Splunk supports both [splunktcp://9997] and [splunktcp://:9997].
    # Examine the merged btool stanza rather than relying on one spelling
    # or an arbitrary fixed number of lines after the header.
    if inputs_output="$("$SPLUNK_BIN" btool inputs list --debug 2>&1)"; then
        if awk '
            /\[splunktcp:\/\/:?9997\]/ { inside=1; found=1; next }
            inside && /\[[^]]+\]/ { inside=0 }
            inside && /(^|[[:space:]])disabled[[:space:]]*=[[:space:]]*0([[:space:]]|$)/ { enabled=1 }
            END { exit !(found && enabled) }
        ' <<< "$inputs_output"; then
            say 'PASS | Splunk receiving enabled on TCP 9997 in effective configuration'
        else
            say 'FAIL | btool did not show an enabled TCP 9997 receiver (check inputs.conf and port listener)'
            failed=1
        fi
    else
        say 'FAIL | Splunk btool inputs verification command failed'
        warn "btool reported: $(tail -n 2 <<< "$inputs_output")"
        failed=1
    fi
    auth_output="$("$SPLUNK_BIN" cmd btool authentication list splunk_auth 2>/dev/null || true)"
    for result in 'lockoutUsers=true' 'lockoutAttempts=5' 'lockoutThresholdMins=5' 'lockoutMins=30'; do
        p="${result%%=*}"
        unit="${result#*=}"
        if grep -Eiq "^[[:space:]]*$p[[:space:]]*=[[:space:]]*$unit([[:space:]]|$)" <<< "$auth_output"; then
            say "PASS | Splunk auth setting $p=$unit"
        else say "FAIL | Splunk auth setting $p=$unit not effective"; failed=1; fi
    done
    for p in 22 8000 8089 9997; do
        if port_listening "$p"; then say "PASS | TCP $p service listening"
        else say "FAIL | TCP $p service not listening (UFW allowance alone does not start a service)"; failed=1; fi
    done
    if [[ -x /usr/sbin/sshd ]]; then
        effective="$(/usr/sbin/sshd -T -C user=sysadmin,host=localhost,addr=127.0.0.1 2>/dev/null || true)"
        if /usr/sbin/sshd -t >/dev/null 2>&1 &&
           grep -Eq '^denyusers .*root([[:space:]]|$)' <<< "$effective" &&
           grep -Eq '^denyusers .*sysadmin([[:space:]]|$)' <<< "$effective" &&
           grep -Eq '^permitrootlogin no$' <<< "$effective"; then
            say 'PASS | sshd config denies new root/sysadmin SSH logins'
        else say 'FAIL | sshd root/sysadmin login restrictions not confirmed'; failed=1; fi
    else
        say 'FAIL | OpenSSH daemon unavailable; SSH authorization not verifiable'; failed=1
    fi
    # Verify local SSH privilege elevation guard, including sudo NOPASSWD.
    if [[ -f "$gate" && -x "$gate" && "$(stat -c '%U' "$gate" 2>/dev/null)" == root ]] &&
       /bin/sh -n "$gate" && /bin/sh "$gate"; then
        say 'PASS | Console-side PAM SSH elevation helper installed and runs locally'
        for unit in "${files[@]}"; do
            [[ -f "/etc/pam.d/$unit" ]] || continue
            checks=$((checks+1))
            if grep -Fqx "auth requisite pam_exec.so quiet type=auth $gate" "/etc/pam.d/$unit" &&
               grep -Fqx "account requisite pam_exec.so quiet type=account $gate" "/etc/pam.d/$unit" &&
               grep -Fqx "session requisite pam_exec.so quiet type=open_session $gate" "/etc/pam.d/$unit"; then
                say "PASS | PAM $unit configured to deny SSH-ancestry privilege elevation"
            else say "FAIL | PAM $unit SSH restriction missing or incomplete"; failed=1; fi
        done
        if [[ "$checks" -eq 0 ]]; then say 'FAIL | No monitored PAM elevation services found'; failed=1; fi
        if [[ -f /etc/pam.d/sshd ]] &&
           grep -Fqx "account requisite pam_exec.so quiet type=account $gate" /etc/pam.d/sshd &&
           [[ "$effective" == *$'usepam yes'* ]]; then
            say 'PASS | sshd PAM policy blocks UID 0 aliases (UsePAM enabled)'
        else say 'FAIL | sshd PAM UID 0 restriction absent or UsePAM disabled'; failed=1; fi
        say 'INFO | Test an actual sudo attempt over SSH to validate runtime policy'
    else say 'FAIL | SSH sudo/su elevation guard missing or cannot run from console'; failed=1; fi
    if command -v ufw >/dev/null 2>&1; then
        ufw_status="$(ufw status verbose 2>&1 || true)"
        if grep -q '^Status: active' <<< "$ufw_status" &&
           grep -Eq '^Default: deny \(incoming\), allow \(outgoing\)' <<< "$ufw_status"; then
            say 'PASS | UFW active with default deny incoming / allow outgoing'
        else say 'FAIL | UFW inactive or wrong default policy'; failed=1; fi
        for p in 22 8000 8089 9997; do
            if grep -Eq "^${p}/tcp[[:space:]]+ALLOW IN" <<< "$ufw_status"; then
                say "PASS | UFW inbound TCP $p allowed"
            else say "FAIL | UFW inbound TCP $p missing"; failed=1; fi
        done
        # Reject unknown inbound exceptions, but permit UDP 9997 only for configured rsyslog.
        local allowed_syslog_udp=0
        if ccdc_syslog_udp_configured; then allowed_syslog_udp=1; fi
        if awk -v allow_udp="$allowed_syslog_udp" '
          $2 == "ALLOW" && $3 == "IN" &&
          $1 !~ /^(22|8000|8089|9997)\/tcp$/ &&
          !(allow_udp == 1 && $1 == "9997/udp") {found=1}
          END {exit !found}
        ' <<< "$ufw_status"; then
            say 'FAIL | UFW contains an unexpected additional inbound ALLOW rule'
            failed=1
        else say 'PASS | No additional UFW user inbound ALLOW rules found'; fi
    else say 'FAIL | UFW not installed'; failed=1; fi

    if [[ "$CCDC_IPV6_UFW_SET" -eq 1 ]]; then
        if grep -Eq '^[[:space:]]*IPV6[[:space:]]*=[[:space:]]*no[[:space:]]*$' /etc/default/ufw 2>/dev/null &&
           LC_ALL=C ufw status 2>/dev/null | grep -Eq '^Status: active$'; then
            say 'PASS | UFW active and configured IPV6=no (external reachability not tested)'
        else
            say 'FAIL | Requested UFW IPv6 block not confirmed';failed=1
        fi
    elif [[ -f /etc/default/ufw ]]; then
        say 'INFO | UFW IPv6 configuration was not changed by this invocation'
    fi

    # Local UDP syslog checks are static; a real remote test is still necessary.
    if [[ "$CCDC_SYSLOG_STATUS" == FAIL ]]; then
        say 'FAIL | UDP 9997 rsyslog setup failed during this run'; failed=1
    elif ccdc_syslog_udp_configured; then
        if command -v rsyslogd >/dev/null 2>&1 &&
           rsyslogd -N1 -f /etc/rsyslog.conf >/dev/null 2>&1 &&
           systemctl is-active --quiet rsyslog.service && ccdc_udp9997_listening; then
            say 'PASS | rsyslog configuration valid, service active, UDP 9997 listening'
        else
            say 'FAIL | rsyslog UDP 9997 listener invalid or inactive'; failed=1
        fi
        if [[ -f "$CCDC_SYSLOG_LOG" && ! -L "$CCDC_SYSLOG_LOG" ]]; then
            say 'PASS | Remote syslog output file exists'
        else
            say 'FAIL | Remote syslog output file absent or unsafe';failed=1
        fi
        local remote_input="$SPLUNK_HOME/etc/apps/ccdc_endpoint_ids_inputs/local/inputs.conf"
        if [[ -f "$remote_input" ]] && grep -Fqx '[monitor:///var/log/remote-syslog/udp9997.log]' "$remote_input" &&
           grep -Fq 'sourcetype = ccdc:remote_syslog' "$remote_input"; then
            say 'PASS | Splunk remote syslog file monitor configured (ingestion unverified)'
        else
            say 'FAIL | Splunk remote syslog input not configured';failed=1
        fi
        if command -v ufw >/dev/null 2>&1 &&
           LC_ALL=C ufw status 2>/dev/null | grep -Eq '^Status: active$'; then
            if grep -Eq '^9997/udp[[:space:]]+ALLOW IN' <<< "$ufw_status"; then
                say 'PASS | UFW has inbound UDP 9997 rule for syslog'
            else
                say 'FAIL | rsyslog configured but UFW inbound UDP 9997 rule absent';failed=1
            fi
        else
            say 'SKIP | UFW inactive/unavailable; remote UDP 9997 reachability cannot be confirmed'
        fi
        say 'REVIEW | Live remote syslog delivery and Splunk indexing need separate tests'
    elif [[ "$CCDC_SYSLOG_REQUESTED" -eq 1 ]]; then
        say 'FAIL | UDP 9997 syslog requested but not configured';failed=1
    else
        say 'SKIP | UDP 9997 rsyslog receiver not configured/requested'
    fi

    if [[ "${1:-}" == final && "$CCDC_CLAMAV_REQUESTED" -eq 0 && ! -f /etc/clamav/clamd.conf ]]; then
        say 'SKIP | ClamAV not selected and not installed'
    elif [[ -f /etc/clamav/clamd.conf ]] || command -v clamonacc >/dev/null 2>&1; then
        for unit in clamav-daemon clamav-clamonacc clamav-freshclam; do
            if systemctl is-active --quiet "$unit.service"; then say "PASS | $unit.service active"
            else say "FAIL | $unit.service inactive"; failed=1; fi
        done
        if grep -Fxq 'OnAccessPrevention no' /etc/clamav/clamd.conf 2>/dev/null &&
           systemctl cat clamav-clamonacc 2>/dev/null | grep -Fq -- '--fdpass --log=/var/log/clamav/clamonacc.log'; then
            say 'PASS | ClamAV configured notify-only without automatic quarantine'
        else say 'FAIL | ClamAV notify-only mode not confirmed'; failed=1; fi
        if [[ -f /var/log/clamav/clamonacc.log ]]; then say 'PASS | ClamAV on-access log file exists'
        else say 'FAIL | ClamAV on-access log file missing'; failed=1; fi
    elif [[ "$CCDC_CLAMAV_REQUESTED" -eq 1 ]]; then
        say 'FAIL | ClamAV installation requested but not present'; failed=1
    else
        say 'SKIP | ClamAV not installed / not requested'
    fi

    if [[ "${1:-}" == final && "$CCDC_SURICATA_REQUESTED" -eq 0 ]] && ! command -v suricata >/dev/null 2>&1; then
        say 'SKIP | Suricata not selected and not installed'
    elif command -v suricata >/dev/null 2>&1; then
        if systemctl is-active --quiet suricata.service; then say 'PASS | suricata.service active'
        else say 'FAIL | suricata.service inactive'; failed=1; fi
        if [[ -s /var/lib/suricata/rules/suricata.rules ]]; then say 'PASS | Suricata nonempty signature rules file exists'
        else say 'FAIL | Suricata signature rules file missing'; failed=1; fi
        if [[ -f /etc/suricata/suricata.yaml ]] && suricata -T -c /etc/suricata/suricata.yaml >/dev/null 2>&1; then
            say 'PASS | Suricata YAML and rules validate'
        else say 'FAIL | Suricata YAML/rule test failed'; failed=1; fi
        if [[ -f /etc/systemd/system/suricata.service.d/90-ccdc-passive-ids.conf ]] &&
           grep -Eq '^ExecStart=.*--af-packet=' /etc/systemd/system/suricata.service.d/90-ccdc-passive-ids.conf; then
            say 'PASS | Suricata configured for passive AF_PACKET capture'
        else say 'FAIL | Suricata passive capture override missing'; failed=1; fi
        # Read the configured AF_PACKET interface, even during standalone --verify.
        local iface=''
        iface="${CCDC_CAPTURE_IFACE:-$(sed -n 's/.*--af-packet=\([^ ]*\).*/\1/p' /etc/systemd/system/suricata.service.d/90-ccdc-passive-ids.conf 2>/dev/null | head -n 1)}"
        if [[ -n "$iface" ]] && ip link show dev "$iface" >/dev/null 2>&1; then
            say "PASS | Suricata capture interface exists: $iface"
        else say 'FAIL | Suricata capture interface unavailable'; failed=1; fi
        if [[ -f /var/log/suricata/eve.json ]]; then say 'PASS | Suricata EVE JSON log file exists'
        else say 'FAIL | Suricata EVE JSON log file missing'; failed=1; fi
    elif [[ "$CCDC_SURICATA_REQUESTED" -eq 1 ]]; then
        say 'FAIL | Suricata was requested but not installed'; failed=1
    else say 'SKIP | Suricata not installed / not requested'; fi

    if [[ -f "$SPLUNK_HOME/etc/apps/ccdc_endpoint_ids_inputs/local/inputs.conf" ]]; then
        local monitoring_file="$SPLUNK_HOME/etc/apps/ccdc_endpoint_ids_inputs/local/inputs.conf"
        if grep -Fq '[monitor:///var/log/suricata/eve.json]' "$monitoring_file" &&
           grep -Fq '[monitor:///var/log/clamav/clamonacc.log]' "$monitoring_file" &&
           grep -Fq '[monitor:///var/log/audit/audit.log]' "$monitoring_file"; then
            say 'PASS | Splunk local Suricata/ClamAV/auditd monitoring inputs configured'
        else say 'FAIL | Splunk monitoring inputs incomplete'; failed=1; fi
    elif command -v suricata >/dev/null 2>&1 || command -v clamonacc >/dev/null 2>&1; then
        say 'FAIL | AV/IDS installed but Splunk log monitoring inputs missing'; failed=1
    else say 'SKIP | No optional AV/IDS monitoring inputs required'; fi
    if command -v auditctl >/dev/null 2>&1; then
        if systemctl is-active --quiet auditd.service &&
           auditctl -l 2>/dev/null | grep -Eq -- '(-k[[:space:]]+|key=)ccdc_'; then
            say 'PASS | auditd running and CCDC file-change watch rules active'
            say 'REVIEW | Confirm audit.log readable and fresh audit events searchable in Splunk'
        else
            say 'FAIL | auditd installed but service/rules not confirmed'
            failed=1
        fi
    else
        say 'SKIP | auditd file-change watches not installed'
    fi
    say '-----------------------------------------------------------'
    say ' CCDC Additional Hardening Verification (PASS/FAIL/SKIP/REVIEW)'
    say '-----------------------------------------------------------'
    local upgrade_version='' selected_target="${CCDC_SPLUNK_TARGET_VERSION:-10.0.12}"
    upgrade_version="$(dpkg-query -W -f='${Version}' splunk 2>/dev/null || true)"
    if [[ "$CCDC_UPGRADE_STATUS" == FAIL ]]; then
        say 'FAIL | Optional Splunk upgrade helper failed'; failed=1
    elif [[ -n "$upgrade_version" ]] && dpkg --compare-versions "$upgrade_version" ge "$selected_target"; then
        say "PASS | Splunk installed version $upgrade_version meets approved target $selected_target"
        if [[ "$CCDC_UPGRADE_RETRY_SUCCEEDED" -eq 1 ]]; then
            say 'PASS | First upgrade failed; second upgrade invocation recovered and live Splunk status passed'
        fi
    elif [[ "$CCDC_UPGRADE_STATUS" == SKIP ]]; then
        say "SKIP | Splunk upgrade not completed/selected; installed ${upgrade_version:-unknown}"
        say "REVIEW | Upgrade to at least $selected_target to address known 10.0.x security issues"
    else
        say "FAIL | Installed Splunk version ${upgrade_version:-unknown} remains below requested $selected_target"
        failed=1
    fi
    case "$CCDC_SECURITY_AUDIT_STATUS" in
        PASS) say 'PASS | Pre-setup read-only security inventory executed (results require review)' ;;
        FAIL) say 'FAIL | Pre-setup audit helper failed'; failed=1 ;;
        *) say 'SKIP | Pre-setup security audit not executed in this invocation' ;;
    esac
    local server_effective='' sidecar_off=0
    server_effective="$("$SPLUNK_BIN" cmd btool server list postgres 2>/dev/null || true)"
    if grep -Eiq '^[[:space:]]*disabled[[:space:]]*=[[:space:]]*(true|1)([[:space:]]|$)' <<< "$server_effective"; then sidecar_off=1; fi
    if [[ "$CCDC_POSTGRES_STATUS" == FAIL ]]; then
        say 'FAIL | Requested PostgreSQL-sidecar mitigation did not complete'; failed=1
    elif ((sidecar_off)); then
        say 'PASS | Effective Splunk PostgreSQL sidecar configuration reports disabled (restart still relevant)'
    elif [[ "$CCDC_POSTGRES_STATUS" == PASS ]]; then
        say 'FAIL | PostgreSQL helper returned success, but effective disabled setting is absent';failed=1
    elif [[ -n "$upgrade_version" ]] && dpkg --compare-versions "$upgrade_version" ge 10.0.7; then
        say 'SKIP | PostgreSQL sidecar workaround not required for CVE-2026-20253 at this fixed version'
    else
        say 'REVIEW | Vulnerable Splunk version; PostgreSQL sidecar workaround not confirmed'
    fi
    local lookup_effective=''
    lookup_effective="$("$SPLUNK_BIN" cmd btool limits list lookup 2>/dev/null || true)"
    if [[ "$CCDC_LOOKUP_STATUS" == FAIL ]]; then
        say 'FAIL | Requested post-upgrade lookup-write hardening failed';failed=1
    elif grep -Eiq '^[[:space:]]*scripted_lookup_raw_write_enforcement[[:space:]]*=[[:space:]]*block([[:space:]]|$)' <<< "$lookup_effective"; then
        if [[ "$CCDC_LOOKUP_STATUS" == PASS && "$CCDC_POSTUPGRADE_RESTARTED" -eq 1 ]]; then
            say 'PASS | Lookup raw-write enforcement configured and post-change Splunk restart succeeded'
        elif [[ "$CCDC_LOOKUP_STATUS" == PASS && "$CCDC_POSTUPGRADE_RESTART_PENDING" -eq 1 ]]; then
            say 'REVIEW | Lookup raw-write setting is configured but service restart was declined/pending'
        else
            say 'PASS | Effective lookup raw-write setting present in config (loaded service state requires validation)'
        fi
    elif [[ "$CCDC_LOOKUP_STATUS" == PASS ]]; then
        say 'FAIL | Lookup helper completed but effective required setting absent';failed=1
    elif [[ -n "$upgrade_version" ]] && dpkg --compare-versions "$upgrade_version" ge 10.0.10; then
        say 'REVIEW | Post-upgrade CVE-2026-76264 lookup setting is not confirmed'
    else
        say 'SKIP | Lookup configuration remediation requires upgrading Splunk first'
    fi
    local gw="$SPLUNK_HOME/etc/apps/splunk_secure_gateway" gw_conf="$SPLUNK_HOME/etc/apps/splunk_secure_gateway/local/app.conf"
    if [[ "$CCDC_GATEWAY_STATUS" == FAIL ]]; then
        say 'FAIL | Requested Secure Gateway mitigation failed';failed=1
    elif [[ ! -d "$gw" ]]; then
        say 'SKIP | Secure Gateway not found at the expected app path (check for alternate paths)'
    elif [[ -f "$gw_conf" ]] && awk '
        /^\[/{in_install=(tolower($0)=="[install]");next}
        in_install && tolower($0) ~ /^[[:space:]]*state[[:space:]]*=[[:space:]]*disabled([[:space:]]|$)/{ok=1}
        END{exit !ok}
    ' "$gw_conf"; then
        if [[ "$CCDC_GATEWAY_STATUS" == PASS && "$CCDC_POSTUPGRADE_RESTART_PENDING" -eq 1 ]]; then
            say 'REVIEW | Secure Gateway locally disabled, but Splunk restart is still pending'
        else
            say 'PASS | Secure Gateway local app state set to disabled; verify effective state after restart'
        fi
    elif [[ "$CCDC_GATEWAY_STATUS" == PASS ]]; then
        say 'FAIL | Gateway helper returned success, but app local state not disabled';failed=1
    else
        say 'REVIEW | Secure Gateway app present; verify app is updated to advisory-fixed release or unused'
    fi
    if [[ "$CCDC_AUDITD_STATUS" == FAIL ]]; then
        say 'FAIL | Requested auditd installation/ACL work failed'; failed=1
    elif command -v auditctl >/dev/null 2>&1 && systemctl is-active --quiet auditd.service &&
         auditctl -l 2>/dev/null | grep -Eq -- '(-k[[:space:]]+|key=)ccdc_'; then
        say 'PASS | auditd service active and CCDC watch rules loaded'
        if [[ -f /var/log/audit/audit.log && -r /var/log/audit/audit.log ]]; then
            say 'PASS | Local audit.log exists and is root-readable'
        else say 'REVIEW | audit.log absent/unreadable; investigate before claiming ingestion'; fi
        say 'REVIEW | Verify that a harmless monitored change appears in Splunk (not provable offline)'
    elif [[ "$CCDC_AUDITD_STATUS" == PASS ]]; then
        say 'FAIL | auditd helper returned success, but watch rules/service not confirmed'; failed=1
    else
        say 'SKIP | auditd CCDC watch rules not present/active'
    fi
    case "$CCDC_LOGCOVERAGE_STATUS" in
        PASS) say 'PASS | Local Linux log coverage diagnostic ran; indexed coverage still unverified' ;;
        FAIL) say 'FAIL | Local Linux logging diagnostic failed'; failed=1 ;;
        *) say 'SKIP | Local Linux logging diagnostic not run in this invocation' ;;
    esac
    if [[ "$CCDC_IPV6_UFW_SET" -eq 0 ]]; then
        say 'SKIP | IPv6 UFW block not newly requested this invocation (existing UFW evaluated above)'
    fi
    df -h "$SPLUNK_HOME" | tail -n 1 || true
    if [[ "$CCDC_SETUP_ERRORS" -gt 0 ]]; then
        say "FAIL | $CCDC_SETUP_ERRORS setup operation(s) reported errors"
        failed=1
    elif [[ "$CCDC_UPGRADE_FIRST_FAILED" -eq 1 && "$CCDC_UPGRADE_RETRY_SUCCEEDED" -ne 1 ]]; then
        say 'FAIL | First upgrade failure was not recovered by the late retry'
        failed=1
    else say 'PASS | No unresolved setup operations reported errors'; fi
    say 'INFO | These checks are local; CCDC scoring reachability, actual SSH denial and live IDS/AV alerts require separate remote tests.'
    say 'INFO | PAM restrictions cover standard escalation paths; no mechanism can promise to block all possible privilege-escalation paths.'
    if ((failed)); then say 'RESULT | FAIL: One or more checks need investigation.';return 1;fi
    say 'RESULT | PASS: All applicable static/local checks succeeded (live remote behavior unproven).'
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

# Optional pre-setup inspection before dashboard execution, firewall or auth edits.
if yesno 'Run read-only security audit before changing this host?'; then
    if ccdc_run_github_helper bash Setup/ccdc-readonly-security-audit.sh --pre-restart; then
        CCDC_SECURITY_AUDIT_STATUS=PASS
    else
        CCDC_SECURITY_AUDIT_STATUS=FAIL
        warn 'Pre-setup security audit failed or is unavailable.'
        if ! yesno 'Continue setup despite the audit failure?'; then
            say 'STOP | Review audit failure before continuing.'
            exit 1
        fi
    fi
fi

# Optional Splunk maintenance upgrade at the START of setup, AFTER an opportunity
# for pre-setup inspection and BEFORE any dashboards/config/credential baselines.
# The helper fetches Splunk's official Debian package and SHA512, verifies them,
# saves a LOCAL config archive, and requires explicit downtime confirmation.
# Downtime can affect scored Web, management and query services: test in a VM.
if yesno 'Upgrade installed Splunk Enterprise to the approved 10.0.x maintenance release now? (downtime / large download)'; then
    if ccdc_run_github_helper bash Setup/ccdc-upgrade-splunk.sh --upgrade; then
        CCDC_UPGRADE_STATUS=PASS
        say 'PASS | Upgrade helper completed; verify installed version and scored services'
    else
        ccdc_upgrade_rc=$?
        if [[ "$ccdc_upgrade_rc" -eq 3 ]]; then
            CCDC_UPGRADE_STATUS=SKIP
            say 'SKIP | Upgrade canceled before the package installation'
        else
            CCDC_UPGRADE_STATUS=FAIL
            CCDC_UPGRADE_FIRST_FAILED=1
            warn 'First Splunk upgrade attempt failed; ONE optional retry will be offered near the end.'
            warn 'Review the failure before proceeding; do not assume Splunk is running or the package is intact.'
            if ! yesno 'Continue setup after the first failure and offer one upgrade retry near the end? (practice VM only)'; then
                say 'STOP | Investigate upgrade failure, service and config before running more scripts'
                exit 1
            fi
        fi
    fi
fi

# Set credential baseline after any authorized Splunk package migration.
if [[ -f "$SPLUNK_HOME/etc/passwd" ]] && command -v sha256sum >/dev/null 2>&1; then
    CCDC_SPLUNK_CREDENTIALS_BEFORE="$(sha256sum "$SPLUNK_HOME/etc/passwd" | awk '{print $1}')"
fi

# ==========================================================
# Dashboard installation FIRST; the installer itself does not restart Splunk.
# Run only after the root and local-NETLAB-console preflight above.
# ==========================================================
say '=== Download and install CCDC Splunk dashboards ==='
DASHBOARD_URL="https://raw.githubusercontent.com/Moses-Strom/CCDC-temp/${CCDC_REPO_REF:-main}/Dashboards/setup-dashboards-main.sh"
if ! command -v wget >/dev/null 2>&1; then
    say 'FAIL | wget is missing; dashboard installation not attempted.' >&2
    exit 1
fi
DASHBOARD_SCRIPT="$(mktemp /tmp/ccdc-dashboards.XXXXXXXX.sh)"
if ! wget --https-only -q --tries=2 --timeout=20 -O "$DASHBOARD_SCRIPT" "$DASHBOARD_URL"; then
    rm -f -- "$DASHBOARD_SCRIPT"
    say 'FAIL | Could not download CCDC dashboard installer.' >&2
    exit 1
fi
say 'PASS | Dashboard installer downloaded from GitHub'
if ! bash "$DASHBOARD_SCRIPT"; then
    rm -f -- "$DASHBOARD_SCRIPT"
    say 'FAIL | Dashboard installer failed; stopping before server changes.' >&2
    exit 1
fi
if ! bash "$DASHBOARD_SCRIPT" --verify; then
    rm -f -- "$DASHBOARD_SCRIPT"
    say 'FAIL | Dashboard static verification failed; stopping before server changes.' >&2
    exit 1
fi
rm -f -- "$DASHBOARD_SCRIPT"
say 'PASS | CCDC dashboards installed and statically verified'

# ==========================================================
# Configure Splunk and network/security access BEFORE its restart.
# This includes the required inbound ports 22, 8000, 8089, 9997.
# ==========================================================
say '=== CCDC Splunk Enterprise Setup (Debian 12) ==='
say 'Current listening services:'
ss -lntup
snapshot_ports
if ! ip -o -4 addr show 2>/dev/null | grep -q "$EXPECTED_IP"; then
    warn "This VM may not currently hold the expected IP $EXPECTED_IP. Confirm the actual NETLAB topology."
fi

ccdc_configure_receiver || fail 'Splunk receiver setup failed'
ccdc_configure_lockout || fail 'Splunk lockout setup failed'
ccdc_apply_ssh_restriction || fail 'SSH restriction failed'
ccdc_block_ssh_elevation || fail 'SSH sudo/su elevation restriction failed'
# Configure UDP listener before UFW is reset so the associated rule is retained.
# If skipped on a later run, a preexisting CCDC listener still receives its rule.
if yesno 'Install/enable rsyslog receiver for remote syslog on UDP 9997?'; then
    CCDC_SYSLOG_REQUESTED=1
    if ccdc_setup_syslog_udp_9997; then
        CCDC_SYSLOG_STATUS=PASS
    else
        CCDC_SYSLOG_STATUS=FAIL
        fail 'UDP 9997 rsyslog receiver setup failed'
    fi
fi
ccdc_configure_firewall || fail 'UFW configuration failed'
ccdc_optional_ufw_ipv6_block || fail 'Optional UFW IPv6 change failed'

# Pre-configure Splunk monitoring inputs before restarting, even if optional
# IDS/AV logs do not exist yet. Refresh their ACLs after optional installs.
ccdc_setup_monitoring_input || fail 'Splunk AV/IDS input setup failed'

# Optional vendor workaround for vulnerable Splunk PostgreSQL sidecar.
# Helper edits server.conf only when confirmed; intended early restart follows.
if yesno 'Review/apply PostgreSQL sidecar mitigation before Splunk restart?'; then
    if ccdc_run_github_helper bash Setup/ccdc-mitigate-postgres.sh --apply; then
        CCDC_POSTGRES_STATUS=PASS
        say 'PASS | Sidecar mitigation helper completed'
    else
        CCDC_POSTGRES_STATUS=FAIL
        fail 'Sidecar mitigation failed or was declined; review exposure and dependency requirements'
    fi
fi

# Defer post-upgrade lookup enforcement and Secure Gateway decisions until
# AFTER the one permitted late upgrade retry (at the bottom of setup).
# Changes applied then will need a subsequent Splunk restart to take effect.

# ==========================================================
# Restart NOW, before slower apt upgrades, ClamAV and Suricata downloads.
# Splunk Web and the dashboards can be used while remaining steps run.
# ==========================================================
say '=== Restart Splunk to activate dashboards and configured ports ==='
CCDC_SPLUNK_RESTART_REQUESTED=1
if "$SPLUNK_BIN" restart; then
    CCDC_RESTARTED=1
    say 'PASS | Splunk restart succeeded; dashboards should now be available through Splunk Web.'
else
    fail 'Splunk restart failed: fix service before continuing with optional installs'
    exit 1
fi
if port_listening 8000; then
    say 'PASS | TCP 8000 listening; open Splunk Web in another browser tab.'
else
    warn 'TCP 8000 not yet listening; check Splunk Web after startup finishes.'
fi

# ==========================================================
# Create Splunk Analyst Account
# ==========================================================

echo "=== Setting Up Splunk Analyst Account ==="

ANALYST_URL="https://raw.githubusercontent.com/Moses-Strom/CCDC-temp/refs/heads/main/Dashboards/create-splunk-analyst.py"

ANALYST_SCRIPT="$(mktemp /tmp/ccdc-analyst.XXXXXXXX.py)"
ANALYST_LOG="$(mktemp /tmp/ccdc-analyst-output.XXXXXXXX)"

# Download analyst account creation script
if ! wget -q -O "$ANALYST_SCRIPT" "$ANALYST_URL"; then
    echo "FAIL | Could not download analyst setup script"
    rm -f "$ANALYST_SCRIPT" "$ANALYST_LOG"
    exit 1
fi

echo "PASS | Analyst setup script downloaded"

# Run Python script interactively
if python3 -u "$ANALYST_SCRIPT" | tee "$ANALYST_LOG"; then
    if grep -q "^SUCCESS: Splunk Web account " "$ANALYST_LOG"; then
        echo "PASS | Splunk Analyst account created successfully"
    else
        echo "SKIP | Analyst account creation was not completed"
    fi
else
    echo "FAIL | Splunk Analyst account setup failed"
    rm -f "$ANALYST_SCRIPT" "$ANALYST_LOG"
    exit 1
fi

# Cleanup
rm -f "$ANALYST_SCRIPT" "$ANALYST_LOG"

echo "=== Splunk Analyst Setup Complete ==="
echo ""

# ==========================================================
# Remaining original configuration, package updates and optional downloads.
# Splunk can remain available while these execute in the NETLAB console.
# ==========================================================
if yesno 'Refresh Debian package list (no upgrade unless separately approved)?'; then
    if apt-get update; then
        apt list --upgradable 2>/dev/null || true
        if yesno 'Install available Debian upgrades? Potential scoring disruption'; then
            apt-get upgrade -y || fail 'Debian package upgrade failed'
        fi
    else warn 'Package list refresh failed.'; fi
fi
if yesno 'Change Debian Linux root password interactively? (does not change Splunk Web admin)'; then
    CCDC_ROOT_PASSWORD_REQUESTED=1
    ccdc_change_root_password || fail 'Linux root password update failed'
fi
ccdc_expire_selected_admins

say ''
say 'NOTE: ClamAV and Suricata are OPTIONAL because they use RAM, CPU and storage.'
say '      Both are detection-only; they do not block ports or alter firewall rules.'
if yesno 'Install/enable ClamAV REAL-TIME on-access notify-only monitoring?'; then
    CCDC_CLAMAV_REQUESTED=1
    ccdc_install_clamav || fail 'ClamAV configuration failed'
fi
if yesno 'Install/enable Suricata passive IDS (AF_PACKET)?'; then
    CCDC_SURICATA_REQUESTED=1
    ccdc_install_suricata || fail 'Suricata configuration failed'
fi
if command -v clamonacc >/dev/null 2>&1 || command -v suricata >/dev/null 2>&1; then
    # Update ACLs now that the IDS/AV log files may exist. Inputs were already
    # installed and activated by the earlier Splunk restart.
    ccdc_setup_monitoring_input || fail 'Splunk AV/IDS log input ACL refresh failed'
fi

# Optional persistent file-change auditing. Executed AFTER the early Splunk
# restart so an APT package install cannot delay initial Web availability.
# audit.log monitor was installed BEFORE the restart; refresh permissions below.
if yesno 'Install auditd file-change monitoring on this Debian Splunk VM?'; then
    if ccdc_run_github_helper bash Setup/ccdc-install-auditd.sh --install; then
        CCDC_AUDITD_STATUS=PASS
        say 'PASS | auditd helper completed; verify event ingestion'
        ccdc_setup_monitoring_input || { CCDC_AUDITD_STATUS=FAIL; fail 'auditd/Splunk audit.log ACL refresh failed'; }
    else
        CCDC_AUDITD_STATUS=FAIL
        fail 'auditd setup failed or was declined; inspect auditd report'
    fi
fi

# Local host diagnosis only; other Linux VMs need this check on their own hosts.
if yesno 'Run local Linux logging/forwarder coverage diagnostic?'; then
    if ccdc_run_github_helper bash Setup/check-linux-log-coverage.sh; then
        CCDC_LOGCOVERAGE_STATUS=PASS
    else
        CCDC_LOGCOVERAGE_STATUS=FAIL
        fail 'Linux logging diagnostic could not complete'
    fi
fi

# ==========================================================
# LAST upgrade attempt: only retry if the FIRST upgrade actually FAILED.
# A successful first attempt does not re-download or re-install the package.
# This late retry still requires all confirmations in ccdc-upgrade-splunk.sh.
# ==========================================================
if [[ "$CCDC_UPGRADE_FIRST_FAILED" -eq 1 ]]; then
    say '=== Late Splunk upgrade retry (maximum one additional invocation) ==='
    warn 'The first upgrade failed; this is not proof of a harmless/transient failure.'
    if yesno 'Retry the Splunk upgrade helper ONCE now? (may stop/restart Splunk; practice VM)'; then
        if ccdc_run_github_helper bash Setup/ccdc-upgrade-splunk.sh --upgrade; then
            # IMPORTANT: helpers may report an already-installed version as PASS.
            # Require both the actual dpkg version and a live Splunk status check.
            ccdc_retry_version="$(dpkg-query -W -f='${Version}' splunk 2>/dev/null || true)"
            ccdc_retry_target="${CCDC_SPLUNK_TARGET_VERSION:-10.0.12}"
            if [[ -n "$ccdc_retry_version" ]] &&
               dpkg --compare-versions "$ccdc_retry_version" ge "$ccdc_retry_target" &&
               "$SPLUNK_BIN" status >/dev/null 2>&1; then
                CCDC_UPGRADE_STATUS=PASS
                CCDC_UPGRADE_RETRY_SUCCEEDED=1
                say "PASS | Late upgrade retry completed; Splunk $ccdc_retry_version is installed and running"
            else
                CCDC_UPGRADE_STATUS=FAIL
                fail 'Late upgrade helper returned success, but target package version or running Splunk was not verified'
            fi
        else
            ccdc_retry_rc=$?
            CCDC_UPGRADE_STATUS=FAIL
            fail "Late upgrade attempt failed or was canceled (helper exit code $ccdc_retry_rc)"
        fi
    else
        CCDC_UPGRADE_STATUS=FAIL
        warn 'Late retry declined; first upgrade failure remains unresolved.'
    fi
fi

# ==========================================================
# Post-upgrade CVE helper LAST: the version gate can now evaluate the result
# of the second upgrade invocation, rather than failing prematurely.
# Both opt-ins deliberately remain separate to preserve user choice.
# ==========================================================
say '=== Post-upgrade Splunk CVE hardening (after any late upgrade retry) ==='
ccdc_final_splunk_version="$(dpkg-query -W -f='${Version}' splunk 2>/dev/null || true)"
ccdc_postupgrade_restart_needed=0
if [[ -n "$ccdc_final_splunk_version" ]] &&
   dpkg --compare-versions "$ccdc_final_splunk_version" ge 10.0.10; then
    if yesno 'Apply post-upgrade scripted-lookup raw-write enforcement? (requires Splunk restart)'; then
        ccdc_limits_file="$SPLUNK_HOME/etc/system/local/limits.conf"
        ccdc_limits_before="$(sha256sum "$ccdc_limits_file" 2>/dev/null | awk '{print $1}' || true)"
        if ccdc_run_github_helper bash Setup/ccdc-post-upgrade-cve-hardening.sh --apply; then
            CCDC_LOOKUP_STATUS=PASS
            say 'PASS | Post-upgrade lookup enforcement configuration completed'
            ccdc_limits_after="$(sha256sum "$ccdc_limits_file" 2>/dev/null | awk '{print $1}' || true)"
            if [[ "$ccdc_limits_before" != "$ccdc_limits_after" ]]; then
                ccdc_postupgrade_restart_needed=1
            fi
        else
            CCDC_LOOKUP_STATUS=FAIL
            fail 'Post-upgrade lookup enforcement failed/declined; investigate before claiming mitigation'
        fi
    fi
else
    say "SKIP | Post-upgrade lookup enforcement requires Splunk >=10.0.10; current ${ccdc_final_splunk_version:-unknown}"
fi

# The Secure Gateway app workaround is independent of the Splunk version gate.
# Disabling the app can break Mobile/Spacebridge/Mission Control integrations.
if yesno 'Disable Splunk Secure Gateway app if unused? (requires Splunk restart)'; then
    ccdc_gateway_file="$SPLUNK_HOME/etc/apps/splunk_secure_gateway/local/app.conf"
    ccdc_gateway_before="$(sha256sum "$ccdc_gateway_file" 2>/dev/null | awk '{print $1}' || true)"
    if ccdc_run_github_helper bash Setup/ccdc-post-upgrade-cve-hardening.sh --disable-secure-gateway; then
        CCDC_GATEWAY_STATUS=PASS
        say 'PASS | Secure Gateway disable configuration completed'
        ccdc_gateway_after="$(sha256sum "$ccdc_gateway_file" 2>/dev/null | awk '{print $1}' || true)"
        if [[ "$ccdc_gateway_before" != "$ccdc_gateway_after" ]]; then
            ccdc_postupgrade_restart_needed=1
        fi
    else
        CCDC_GATEWAY_STATUS=FAIL
        fail 'Secure Gateway change failed/declined; review actual app version and advisory'
    fi
fi

# The early restart happened BEFORE these optional config changes. If the
# configuration changed, restart again ONLY with explicit operator consent.
if [[ "$ccdc_postupgrade_restart_needed" -eq 1 ]]; then
    warn 'CVE hardening modified Splunk config after the early restart; a second restart is required.'
    if yesno 'Restart Splunk now to activate the late CVE changes? (interrupts Web/query/management)'; then
        CCDC_SPLUNK_RESTART_REQUESTED=1
        ccdc_late_restart_healthy=0
        if "$SPLUNK_BIN" restart; then
            # Initial service startup can take several seconds. Avoid a false FAIL.
            for ((ccdc_restart_attempt=0; ccdc_restart_attempt<10; ccdc_restart_attempt++)); do
                if "$SPLUNK_BIN" status >/dev/null 2>&1; then
                    ccdc_late_restart_healthy=1
                    break
                fi
                sleep 3
            done
        fi
        if [[ "$ccdc_late_restart_healthy" -eq 1 ]]; then
            CCDC_RESTARTED=1
            CCDC_POSTUPGRADE_RESTARTED=1
            say 'PASS | Splunk restarted and running after late CVE configuration changes'
        else
            CCDC_RESTARTED=0
            CCDC_POSTUPGRADE_RESTART_PENDING=1
            fail 'Splunk restart/status after late CVE changes failed; check scored ports immediately'
        fi
    else
        CCDC_POSTUPGRADE_RESTART_PENDING=1
        warn 'CVE configuration written but service restart declined: effective mitigation NOT yet verified'
    fi
fi

ccdc_verification final
