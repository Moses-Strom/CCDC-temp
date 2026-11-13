#!/usr/bin/env bash
# Read-only host/Splunk exposure and persistence triage for a competition VM.
# No scanning of other hosts, no exploits, no state changes, no password contents.
# Intended BEFORE the operator's early Splunk restart; may also run afterwards.
# Review results manually; this is not a trusted malware scanner or FIM baseline.
set -uo pipefail
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
EXPECTED_IP="${EXPECTED_IP:-172.20.240.20}"
WARNINGS=0
say() { printf '%s\n' "$*"; }
section() { say '';say "=== $* ==="; }
warn() { say "REVIEW | $*"; WARNINGS=$((WARNINGS+1)); }
pass() { say "INFO | $*"; }
command_exists() { command -v "$1" >/dev/null 2>&1; }
print_file_list() {
    local root="$1" depth="${2:-2}"
    if [[ -d "$root" ]]; then
        find "$root" -maxdepth "$depth" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort | tail -n 35 || true
    fi
}
case "${1:---review}" in
  --review|--pre-restart) ;;
  *) say 'Usage: bash ccdc-readonly-security-audit.sh [--review|--pre-restart]';exit 2;;
esac
say 'CCDC Debian + Splunk READ-ONLY security exposure / persistence audit'
say "Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "Expected Splunk IP: $EXPECTED_IP | Expected ports: 22/8000/8089/9997 TCP + ICMP"
say 'No configuration changes, privileged login attempts, remote scans, or service restarts.'
if [[ "${EUID:-$(id -u)}" -ne 0 ]];then warn 'Run with sudo/NETLAB console for complete read-only inventory';fi

section 'Operating system, updates, kernel, vulnerable component versions'
if [[ -r /etc/os-release ]]; then
  # Do not *source* a potentially tampered file into this privileged shell.
  os_name="$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n 1 | tr -d '"')"
  pass "OS: ${os_name:-unknown}"
fi
uname -r 2>/dev/null || true
# Never run the installed Splunk binary during a pre-restart compromise review.
# A tampered executable itself can be the persistence mechanism under review.
if [[ -x "$SPLUNK_HOME/bin/splunk" ]];then
  pass "Splunk executable present (NOT executed): $SPLUNK_HOME/bin/splunk"
  if command_exists dpkg-query;then dpkg-query -W -f='${Package} ${Version}\n' splunk 2>/dev/null || true;fi
else warn "Splunk executable absent: $SPLUNK_HOME/bin/splunk";fi
if command_exists apt;then
  say 'Installed package updates (first 30, only if apt cache exists):'
  apt list --upgradable 2>/dev/null | head -n 31 || true
  pass 'Package version and CVE impact require Debian Security Tracker/LTS correlation; banners alone are not proof.'
fi
pass 'Splunk 10.0.2 has known vendor advisories: CVE-2026-20253 (exploited), SVD-2026-1001/1002/1007/1008.'
pass 'A patch/upgrade to an approved fixed release is needed for vulnerabilities without workarounds.'

section 'Host addresses, exposed listeners, IPv6 and UFW'
if command_exists ip;then ip -brief -4 addr 2>/dev/null || true;ip -brief -6 addr 2>/dev/null || true;ip -6 route 2>/dev/null | head -n 12 || true;else warn 'ip command missing';fi
if command_exists ss;then
  ss -H -lntup 2>/dev/null || warn 'Unable to enumerate TCP/UDP listening processes'
  for p in 22 8000 8089 9997;do
    if ss -H -lnt 2>/dev/null | awk -v p="$p" '$4 ~ (":" p "$") {yes=1} END{exit !yes}';then
       pass "Local TCP:$p listener present (NOT proof of scoring reachability)"
    else warn "No local TCP:$p listener (could be expected before startup)";fi
  done
else warn 'ss command missing';fi
if command_exists ufw;then
  ufw status verbose 2>/dev/null || warn 'Could not read UFW status'
else warn 'UFW not installed; investigate effective nftables/iptables policy';fi
if [[ -r /etc/default/ufw ]];then
  grep -E '^\s*IPV6\s*=' /etc/default/ufw || pass 'No IPV6= declaration found'
fi
if command_exists nft;then
  pass 'nftables detected: review effective rules with sudo nft list ruleset (can contain sensitive details).'
fi

section 'Splunk sidecar CVE exposure (read-only)'
postgres_status='unknown'
# Inspect on-disk local settings only. Do NOT execute Splunk btool from a host
# whose binary/app integrity has not yet been reviewed.
local_server_conf="$SPLUNK_HOME/etc/system/local/server.conf"
if [[ -r "$local_server_conf" ]];then
  say 'Local server.conf [postgres] setting (NOT effective cross-app precedence):'
  awk 'tolower($0)~/^\[postgres\]/{inside=1;next} /^\[/{inside=0} inside && tolower($0)~/^[[:space:]]*disabled[[:space:]]*=/{print $0;found=1} END{if(!found)print "UNSET"}' "$local_server_conf"
  if awk 'tolower($0)~/^\[postgres\]/{inside=1;next} /^\[/{inside=0} inside && tolower($0)~/^[[:space:]]*disabled[[:space:]]*=[[:space:]]*true([[:space:]]|$)/{good=1} END {exit !good}' "$local_server_conf";then
    postgres_status='local-disabled'
  fi
fi
if [[ "$postgres_status" != local-disabled ]];then
  warn 'PostgreSQL sidecar NOT CONFIRMED disabled in local file. On Splunk 10.0.2, review CVE-2026-20253.'
else
  pass 'Local postgres stanza says disabled=true; effective precedence, loaded config and runtime remain UNKNOWN.'
fi
pass 'Vendor workaround [postgres] disabled = true requires restart and may disrupt Edge Processor/OpAmp/SPL2 pipeline features.'

section 'Splunk runtime identity, app execution mechanisms and sensitive permissions'
if command_exists ps;then
  ps -eo user,pid,ppid,comm,args | awk '$4 ~ /^splunkd$/ {print $0}' | head -n 12
  if ps -eo user=,comm= | awk '$2=="splunkd" && $1=="root"{bad=1} END{exit !bad}';then
     warn 'splunkd appears to run as ROOT; review Splunk service account isolation.'
  fi
fi
for target in "$SPLUNK_HOME/etc" "$SPLUNK_HOME/bin/splunk" /etc/ssh/sshd_config /etc/sudoers;do
  [[ -e "$target" ]] && stat -c '%a %U:%G %n' "$target" 2>/dev/null || true
done
if [[ -d "$SPLUNK_HOME/etc/apps" ]];then
  pass 'Splunk potentially executable app entrypoints (inspect legitimacy, max 65 paths):'
  find "$SPLUNK_HOME/etc/apps" -maxdepth 7 -type f \( -name 'commands.conf' -o -name 'alert_actions.conf' -o -name 'inputs.conf' -o -name '*.py' -o -name '*.sh' -o -name '*.ps1' \) -print 2>/dev/null | head -n 65
fi
for root in "$SPLUNK_HOME/etc/system/local" "$SPLUNK_HOME/etc/apps";do
  if [[ -d "$root" ]];then
    pass "Recently modified Splunk config candidates under $root (48h, max 40):"
    find "$root" -maxdepth 5 -type f -mmin -2880 \( -name '*.conf' -o -name '*.py' -o -name '*.sh' -o -name '*.xml' \) -print 2>/dev/null | head -n 40
  fi
done
if [[ -r "$SPLUNK_HOME/var/log/splunk/audit.log" ]];then
  pass 'Splunk audit.log exists; correlate users/roles/config changes with approved changes in index=_audit.'
else warn 'Splunk audit.log inaccessible or missing; confirm index=_audit and log continuity.';fi

section 'Linux identity, authentication, SSH policy and privilege sources'
if [[ -r /etc/passwd ]];then
  say 'UID 0 account names (investigate any beyond the expected root):'
  awk -F: '$3==0{print $1" (UID=" $3 ")"}' /etc/passwd
fi
for group in sudo adm;do getent group "$group" 2>/dev/null || true;done
if command_exists sshd;then
  sshd -t 2>/dev/null || warn 'sshd configuration validation failed'
  sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|denyusers) ' || true
  pass 'This effective-configuration sample is NOT proof of all SSH Match/address contexts.'
fi
for p in /etc/sudoers.d /etc/ssh/sshd_config.d /root/.ssh;do
  if [[ -d "$p" ]];then
    say "Listing relevant file names/ownership, not secret file contents ($p):"
    find "$p" -maxdepth 2 -type f -printf '%m %u:%g %p\n' 2>/dev/null | head -n 35
  fi
done

section 'Startup persistence: enabled systemd units, custom units, cron and login hooks'
if command_exists systemctl;then
  say 'Enabled unit files (up to 90 lines):'
  systemctl list-unit-files --state=enabled --no-pager --no-legend 2>/dev/null | head -n 90 || true
  say 'Failed systemd units:'
  systemctl --failed --no-pager --no-legend 2>/dev/null | head -n 30 || true
fi
for p in /etc/systemd/system /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /var/spool/cron /etc/profile.d;do
  if [[ -d "$p" ]];then
    say "File inventory: $p (most recent 35 by lexical file-date listing):"
    print_file_list "$p" 3
  fi
done
if [[ -d /usr/local/bin || -d /usr/local/sbin ]];then
  say 'Local elevated-permission executables (max 35):'
  find /usr/local/bin /usr/local/sbin -maxdepth 2 -type f \( -perm /4000 -o -perm /2000 \) -printf '%m %u:%g %p\n' 2>/dev/null | head -n 35 || true
fi

section 'Monitoring and service availability'
for svc in splunk splunkd ssh sshd ufw fail2ban auditd suricata clamav-daemon clamav-clamonacc clamav-freshclam;do
  if command_exists systemctl;then
    state="$(systemctl is-active "$svc" 2>/dev/null || true)"
    [[ -n "$state" && "$state" != unknown ]] && say "Service $svc: $state"
  fi
done
if command_exists auditctl;then
  auditctl -s 2>/dev/null | head -n 12 || true
  say 'Audit rules (first 30):'
  auditctl -l 2>/dev/null | head -n 30 || true
else warn 'auditd rule inspection unavailable: OS-level change attribution may be missing';fi
if [[ -r /var/log/suricata/eve.json ]];then pass 'Suricata EVE JSON present; validate fresh alerts + actual Splunk ingestion';fi
if [[ -r /var/log/clamav/clamonacc.log ]];then pass 'ClamAV on-access log present; validate meaningful detection events + ingestion';fi
df -P "$SPLUNK_HOME" 2>/dev/null || true
say ''
say "COMPLETE | Read-only inspection finished. ${WARNINGS} item(s) need operator review (not a count of compromises)."
say 'Important: no trusted baseline was compared, no remote scorer was queried, and no malware was proven absent.'
say 'Do not automatically remove anything flagged: verify owner, hash, package provenance and scoring dependency first.'
