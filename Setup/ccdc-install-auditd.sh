#!/usr/bin/env bash
# CCDC Debian 12 - optional and idempotent file-change auditd rules.
# This is defensive configuration, not a malware-cleaning or trust guarantee.
# Usage: sudo bash ccdc-install-auditd.sh --check | --install
set -euo pipefail
umask 077
MODE="${1:---check}"
RULES="/etc/audit/rules.d/50-ccdc-fim.rules"
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
MARKER='# Managed by CCDC ccdc-install-auditd.sh v1'
log(){ printf '%s\n' "$*"; }
err(){ printf 'FAIL | %s\n' "$*" >&2; }
[[ "$MODE" == --check || "$MODE" == --install ]] || { err 'Usage: --check or --install';exit 2; }

check(){
  log '=== auditd/FIM status (read-only) ==='
  if command -v auditctl >/dev/null 2>&1; then
    auditctl -s 2>&1 || true
    log 'Installed CCDC rules:'
    auditctl -l 2>/dev/null | grep -E '(-k[[:space:]]+|key=)ccdc_' || log 'REVIEW | No active ccdc_ rules found'
  else
    log 'REVIEW | auditctl not installed'
  fi
  if command -v systemctl >/dev/null 2>&1; then
    log "auditd.service: $(systemctl is-active auditd.service 2>/dev/null || true)"
  fi
  if [[ -f "$RULES" ]]; then
    if grep -Fqx "$MARKER" "$RULES"; then
      log "PASS | CCDC rules installed in $RULES"
    else
      log "REVIEW | $RULES exists but not managed by this helper"
    fi
  else log "INFO | No $RULES"; fi
  [[ -f /var/log/audit/audit.log ]] && log 'INFO | /var/log/audit/audit.log exists' || log 'INFO | audit.log not yet present'
  log 'NOTE | auditd events are not searchable in Splunk until monitored, readable and verified.'
}
if [[ "$MODE" == --check ]]; then check; exit 0; fi
[[ $EUID -eq 0 ]] || { err 'Installation requires root';exit 1; }
[[ ! -L "$RULES" ]] || { err 'Refusing symlinked audit rules path';exit 1; }
if [[ -e "$RULES" ]] && ! grep -Fqx "$MARKER" "$RULES"; then
  err "Existing unmanaged rule file $RULES; review manually";exit 1
fi
log 'auditd tracks changes to specified config paths; it cannot prove a root-compromised host is trusted.'
log 'It does not delete files, deny access, stop services or change the network firewall.'
read -r -p 'To install auditd and apply reviewed CCDC watches, type INSTALL-AUDITD: ' confirm || true
[[ "${confirm:-}" == INSTALL-AUDITD ]] || { log 'SKIP | No changes made';exit 3; }
if ! command -v auditctl >/dev/null 2>&1 || ! command -v augenrules >/dev/null 2>&1; then
  log 'Installing auditd and ACL support from configured Debian repositories...'
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends auditd acl || { err 'apt install failed';exit 1; }
fi
if ! command -v auditctl >/dev/null 2>&1 || ! command -v augenrules >/dev/null 2>&1; then
  err 'auditd utilities still missing';exit 1
fi
# Avoid modifying settings while audit rules are immutable (until reboot).
if auditctl -s 2>/dev/null | grep -Eq '^enabled[[:space:]]+2$'; then
  err 'Kernel audit is immutable (enabled=2); do not force a reload';exit 1
fi
mkdir -p -m 0750 /etc/audit/rules.d
if [[ -f "$RULES" ]]; then
  backup="${RULES}.bak.$(date +%Y%m%d-%H%M%S).$$"
  cp -p -- "$RULES" "$backup"
  log "Previous rules backed up: $backup"
fi
# Generate only watches whose paths currently exist; avoid monitoring Splunk hot indexes.
# These audits may be noisy when installing apps or changing configuration.
new="$(mktemp /etc/audit/rules.d/.ccdc-fim.XXXXXXXX)"
trap 'rm -f -- "${new:-}"' EXIT
printf '%s\n' "$MARKER" '# write/attribute watches; do not clear or lock other rules.' > "$new"
count=0
while IFS='|' read -r path key; do
  [[ -n "$path" ]] || continue
  if [[ -e "$path" && ! -L "$path" ]]; then
    printf -- '-w %s -p wa -k %s\n' "$path" "$key" >> "$new"
    count=$((count+1))
  else log "SKIP | Watch path absent/symlink: $path"; fi
done <<EOF_WATCH
/etc/passwd|ccdc_identity
/etc/group|ccdc_identity
/etc/shadow|ccdc_identity
/etc/gshadow|ccdc_identity
/etc/sudoers|ccdc_privilege
/etc/sudoers.d|ccdc_privilege
/etc/ssh|ccdc_ssh
/etc/systemd/system|ccdc_startup
/etc/cron.d|ccdc_startup
/etc/crontab|ccdc_startup
/usr/local/sbin|ccdc_startup
/etc/audit/rules.d|ccdc_audit_config
$SPLUNK_HOME/etc/system/local|ccdc_splunk_conf
$SPLUNK_HOME/etc/apps|ccdc_splunk_apps
EOF_WATCH
[[ "$count" -gt 0 ]] || { err 'No existing watch paths; aborting';exit 1; }
chmod 0640 "$new"
chown root:root "$new"
mv -f -- "$new" "$RULES"
trap - EXIT
# Service may already be active. Do not stop or restart the audit daemon.
if ! systemctl enable --now auditd.service; then
  err 'Unable to enable/start auditd';exit 1
fi
if ! augenrules --load; then
  err 'Failed to load audit rules; check auditd journal and existing rules';exit 1
fi
if ! auditctl -l | grep -Eq -- '(-k[[:space:]]+|key=)ccdc_'; then
  err 'CCDC rules not seen in active kernel rules';exit 1
fi
log "PASS | Loaded CCDC audit watches on $count existing paths"
log 'INFO | Audit log monitoring is preconfigured by master setup BEFORE its first Splunk restart.'
# Only grant the operating-system Splunk daemon account read access, when detectable.
owner="$(ps -eo user=,comm= 2>/dev/null | awk '$2=="splunkd"{print $1;exit}' || true)"
if [[ -z "$owner" && -d "$SPLUNK_HOME/var/log/splunk" ]]; then
  owner="$(stat -c '%U' "$SPLUNK_HOME/var/log/splunk" 2>/dev/null || true)"
fi
if [[ -n "$owner" && "$owner" != UNKNOWN ]] && id "$owner" >/dev/null 2>&1; then
  if command -v setfacl >/dev/null 2>&1 && [[ -d /var/log/audit ]]; then
    setfacl -m "u:$owner:rx" /var/log/audit || log 'REVIEW | Audit dir ACL failed'
    setfacl -m "d:u:$owner:rX" /var/log/audit || log 'REVIEW | Default ACL failed (rotation risk)'
    if [[ -f /var/log/audit/audit.log ]]; then
      setfacl -m "u:$owner:r" /var/log/audit/audit.log || log 'REVIEW | Audit log ACL failed'
    fi
    log "INFO | Splunk OS account '$owner' granted read access to local audit log."
  else log 'REVIEW | setfacl or /var/log/audit unavailable; check Splunk ingest permissions';fi
else log 'REVIEW | Could not identify Splunk daemon owner for audit.log ACL';fi
log 'NEXT | Run: sudo ausearch -k ccdc_identity -ts recent'
log 'NEXT | Check in Splunk Web: index=main sourcetype=linux:audit earliest=-30m'
log 'NEXT | Ensure auditctl -s lost=0 and verify with harmless authorized config change.'
