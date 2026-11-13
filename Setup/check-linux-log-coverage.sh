#!/usr/bin/env bash
# Read-only Linux logging diagnosis for CCDC Universal Forwarder hosts.
# Does NOT install, alter permissions, restart anything, or show log contents.
set -u
say() { printf '%s\n' "$*"; }
say "CCDC Linux logging diagnostic | $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
say "Host: $(hostname 2>/dev/null || printf unknown)"
say "OS: $(. /etc/os-release 2>/dev/null; printf '%s %s' "${NAME:-unknown}" "${VERSION_ID:-unknown}")"
say ''
for svc in systemd-journald rsyslog auditd SplunkForwarder; do
  if command -v systemctl >/dev/null 2>&1; then
    active=$(systemctl is-active "$svc" 2>/dev/null || true)
    say "Service $svc: ${active:-unknown}"
  fi
done
say ''
if command -v journalctl >/dev/null 2>&1; then
  if journalctl -n 1 --no-pager -q >/dev/null 2>&1; then
    say 'Journal: readable by current user'
  else
    say 'Journal: unavailable or not readable by current user'
  fi
  if command -v du >/dev/null 2>&1; then
    if [[ -d /var/log/journal ]]; then
      say 'Persistent journal directory: /var/log/journal present'
    else
      say 'Persistent journal directory: /var/log/journal absent (persistence still depends on journald config)'
    fi
  fi
fi
say ''
files=(/var/log/syslog /var/log/messages /var/log/auth.log /var/log/secure \
       /var/log/audit/audit.log /var/log/audit.log /var/log/cron \
       /var/log/mail.log /var/log/maillog \
       /var/log/apache2/access.log /var/log/apache2/error.log \
       /var/log/httpd/access_log /var/log/httpd/error_log)
for file in "${files[@]}"; do
  if [[ -f "$file" ]]; then
    if [[ -r "$file" ]]; then readability='current-user-readable'; else readability='not-current-user-readable'; fi
    if id splunkfwd >/dev/null 2>&1 && command -v runuser >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
      if runuser -u splunkfwd -- test -r "$file"; then forwarder='forwarder-readable'; else forwarder='NOT-forwarder-readable'; fi
    else forwarder='forwarder-permission-unverified'; fi
    say "FILE $file | exists | $readability | $forwarder"
  else
    say "FILE $file | MISSING (not a monitored file under the current installer)"
  fi
done
say ''
if [[ -x /opt/splunkforwarder/bin/splunk ]]; then
  say 'Splunk Universal Forwarder binary: present'
  if [[ -f /opt/splunkforwarder/etc/system/local/inputs.conf ]]; then
    say 'Configured local inputs stanza headers (no log content):'
    grep -E '^\[(monitor|journald)://' /opt/splunkforwarder/etc/system/local/inputs.conf || true
  else
    say 'Local UF inputs.conf: absent'
  fi
  if [[ -d /opt/splunkforwarder/etc/apps ]]; then
    count=$(grep -rEl '^\[journald://' /opt/splunkforwarder/etc/apps/*/{default,local}/inputs.conf 2>/dev/null | wc -l || true)
    say "Journald input config files found in apps: ${count//[[:space:]]/}"
  fi
else
  say 'Splunk Universal Forwarder binary: not found at /opt/splunkforwarder'
fi
say ''
say 'Next: verify real events in Splunk Web before claiming full log coverage.'
say 'Suggested SPL: index=main earliest=-30m | stats count by host source sourcetype'
say 'This diagnostic is an inventory only, NOT a data ingestion test.'
