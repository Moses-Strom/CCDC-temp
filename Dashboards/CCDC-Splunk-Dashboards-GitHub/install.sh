#!/usr/bin/env bash
# CCDC Defense Monitor - readable source installer
# Run in the folder containing the ccdc_defense/ directory.
set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ccdc_defense"
TARGET="$SPLUNK_HOME/etc/apps/ccdc_defense"
MODE="${1:-install}"

usage() {
  echo "Usage: sudo bash install.sh [install|--update|--verify]"
}

verify() {
  if [[ ! -d "$TARGET/default/data/ui/views" ]]; then
    echo "ERROR: app is not installed in $TARGET"
    return 1
  fi
  local dashboard_count report_count enabled_count
  dashboard_count=$(find "$TARGET/default/data/ui/views" -maxdepth 1 -type f -name '*.xml' | wc -l)
  report_count=$(grep -c '^\[' "$TARGET/default/savedsearches.conf" || true)
  enabled_count=$(grep -Ec '^enableSched[[:space:]]*=[[:space:]]*1$' "$TARGET/default/savedsearches.conf" || true)
  echo "Dashboards: $dashboard_count (expected 12)"
  echo "Saved reports: $report_count (expected 71)"
  echo "Scheduled searches: $enabled_count (expected 0)"
  [[ $dashboard_count -eq 12 && $report_count -eq 71 && $enabled_count -eq 0 ]]
}

case "$MODE" in
  -h|--help) usage; exit 0 ;;
  --verify) verify; exit $? ;;
  install|--update) ;;
  *) usage; exit 2 ;;
esac

if [[ $(id -u) -ne 0 ]]; then
  echo "ERROR: run with sudo on the Splunk server."
  exit 1
fi
if [[ ! -x "$SPLUNK_HOME/bin/splunk" || ! -d "$SPLUNK_HOME/etc/apps" ]]; then
  echo "ERROR: existing Splunk Enterprise not found at $SPLUNK_HOME"
  exit 1
fi
if [[ ! -f "$SOURCE/default/app.conf" ]]; then
  echo "ERROR: source app folder missing: $SOURCE"
  exit 1
fi
if [[ -d "$TARGET" && "$MODE" == install ]]; then
  echo "Already installed. Use --update to back it up and replace."
  exit 1
fi

backup=""
if [[ -d "$TARGET" ]]; then
  backup_dir="$SPLUNK_HOME/var/ccdc_defense_backups"
  mkdir -p "$backup_dir"
  backup="$backup_dir/ccdc_defense.$(date +%Y%m%d-%H%M%S).$$"
  mv "$TARGET" "$backup"
  echo "Previous app backed up: $backup"
fi

if ! cp -a "$SOURCE" "$TARGET"; then
  echo "ERROR: copying app failed."
  rm -rf "$TARGET"
  if [[ -n "$backup" ]]; then mv "$backup" "$TARGET"; fi
  exit 1
fi

# Match the existing running Splunk OS account when known.
splunk_user=$(ps -eo user=,comm= | awk '$2=="splunkd" {print $1;exit}' || true)
if [[ -z "$splunk_user" && -d "$SPLUNK_HOME/var/log/splunk" ]]; then
  splunk_user=$(stat -c %U "$SPLUNK_HOME/var/log/splunk")
fi
if [[ -n "$splunk_user" ]] && id "$splunk_user" >/dev/null 2>&1; then
  chown -R "$splunk_user:$(id -gn "$splunk_user")" "$TARGET"
else
  echo "WARNING: check file ownership before restarting Splunk."
fi

if ! verify; then
  echo "ERROR: file verification failed."
  rm -rf "$TARGET"
  if [[ -n "$backup" ]]; then mv "$backup" "$TARGET"; fi
  exit 1
fi

echo "Source app installed at $TARGET"
echo "Restart Splunk using its existing service manager during an acceptable window."
echo "Open Apps > CCDC Defense Monitor, then start with Log Coverage."
echo "No listening ports, passwords, indexes, forwarders or firewall rules were changed."
