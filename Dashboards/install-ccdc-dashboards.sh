#!/usr/bin/env bash
# CCDC Splunk dashboards + detections installer (self-contained, offline)
# Installs the app into the existing Splunk Enterprise instance without
# touching existing listeners, accounts, service configuration, or indexes.
set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
APPS_DIR="$SPLUNK_HOME/etc/apps"
TARGET="$APPS_DIR/ccdc_defense"
MODE="${1:-install}"
EXPECTED_SHA256="ef807c2c91885df891abbfa5a357033b7d0c0f8a0bdddc7082129ca368901845"

usage() {
  echo "Usage: sudo bash $0 [install|--update|--verify]"
  echo "  install    Install dashboards on a fresh Splunk server (default)"
  echo "  --update  Back up and update an existing CCDC dashboard app"
  echo "  --verify  Check dashboard/report files already installed"
  echo "Does not restart Splunk or modify its receiving ports."
}

verify() {
  if [[ ! -d "$TARGET" ]]; then
    echo "Not installed: $TARGET"
    exit 1
  fi
  local viewdir="$TARGET/default/data/ui/views"
  local dashboards reports
  dashboards=$(find "$viewdir" -maxdepth 1 -type f -name '*.xml' | wc -l)
  reports=$(grep -c '^\[' "$TARGET/default/savedsearches.conf" || true)
  echo "Location: $TARGET"
  echo "Dashboard XML files: $dashboards (expected 12)"
  echo "Saved reports: $reports (expected 71)"
  echo "Scheduled searches enabled by this app: $(grep -Ec '^enableSched[[:space:]]*=[[:space:]]*1$' "$TARGET/default/savedsearches.conf" || true)"
  if [[ "$dashboards" -ne 12 || "$reports" -ne 71 ]]; then
    echo "ERROR: Unexpected app file counts."
    exit 1
  fi
  echo "Static file counts look correct (not a live Splunk test)."
}

case "$MODE" in
  -h|--help) usage; exit 0 ;;
  --verify) verify; exit 0 ;;
  install|--update) ;;
  *) usage; exit 2 ;;
esac

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run with sudo on the Splunk server."
  exit 1
fi
if [[ ! -x "$SPLUNK_HOME/bin/splunk" || ! -d "$APPS_DIR" ]]; then
  echo "ERROR: Splunk Enterprise not found at $SPLUNK_HOME"
  echo "Set SPLUNK_HOME only if your Enterprise installation uses a different directory."
  exit 1
fi
if [[ -d "$TARGET" && "$MODE" == 'install' ]]; then
  echo "Already installed. To update safely: sudo bash $0 --update"
  exit 1
fi

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT
PAYLOAD_START=$(awk '/^__CCDC_PAYLOAD_BELOW__$/ {print NR + 1; exit}' "$0")
if [[ -z "$PAYLOAD_START" ]]; then
  echo "ERROR: Built-in app payload missing."
  exit 1
fi
tail -n +"$PAYLOAD_START" "$0" | base64 -d > "$WORKDIR/ccdc_defense_app.tar.gz"
ACTUAL_SHA256=$(sha256sum "$WORKDIR/ccdc_defense_app.tar.gz" | awk '{print $1}')
if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
  echo "ERROR: Installer package integrity check failed."
  exit 1
fi

# Backups live OUTSIDE etc/apps so Splunk won't treat them as additional apps.
if [[ -d "$TARGET" && "$MODE" == '--update' ]]; then
  BACKUP_ROOT="$SPLUNK_HOME/var/ccdc_defense_backups"
  mkdir -p "$BACKUP_ROOT"
  BACKUP="$BACKUP_ROOT/ccdc_defense.$(date +%Y%m%d-%H%M%S)"
  cp -a "$TARGET" "$BACKUP"
  echo "Existing app backed up at: $BACKUP"
fi

# Extract the packaged app (only contains files in ccdc_defense/).
tar -xzf "$WORKDIR/ccdc_defense_app.tar.gz" -C "$APPS_DIR"

# Use the running splunkd OS identity if possible, without rewriting
# ownership of any unrelated Splunk installation directories.
SPLUNK_USER=$(ps -eo user=,comm= | awk '$2 == "splunkd" { print $1; exit }' || true)
# When Splunk is stopped, its log directory can identify the usual owner.
if [[ -z "$SPLUNK_USER" && -d "$SPLUNK_HOME/var/log/splunk" ]]; then
  SPLUNK_USER=$(stat -c '%U' "$SPLUNK_HOME/var/log/splunk")
fi
if [[ -n "$SPLUNK_USER" ]] && id "$SPLUNK_USER" >/dev/null 2>&1; then
  SPLUNK_GROUP=$(id -gn "$SPLUNK_USER")
  chown -R "$SPLUNK_USER:$SPLUNK_GROUP" "$TARGET"
  echo "Installed app owned by $SPLUNK_USER:$SPLUNK_GROUP"
else
  echo "No running splunkd user detected; verify app file ownership before restart."
fi

verify
cat <<'NEXT'

INSTALLATION COMPLETE. Existing Splunk settings were not changed.

To make the new dashboards appear:
  1. During an acceptable maintenance window, restart Splunk using its
     CURRENT service-management method. Never restart blindly during scoring.
  2. In Splunk Web, open Apps -> CCDC Defense Monitor.
  3. Start with Log Coverage, then select the real hostname per device.
  4. If menus don't refresh, visit /en-US/debug/refresh in Splunk Web.
  5. All 71 saved searches are reports; scheduled alerts are OFF.

This app does not configure TCP 9997, forwarders, Sysmon, Palo Alto or VyOS.
Panels that need those log sources stay empty until they are configured.
NEXT
exit 0
__CCDC_PAYLOAD_BELOW__
H4sICFGq62oC/2NjZGNfZGVmZW5zZV9hcHAudGFyAO1d63bbOJLuv+unwNH0nrbTtiTqaidxehVZ
6XjHF7WkJD3bnaNDkbDFMUWyCVK2dmbffasA8CJKiizHlmUbnGlHBMELqoBCfYWqQr6QL/xXW7/5
SHWT+j88yFEUx6J/i8VyJfmN5VqxpJV+IDc/rOEIWaD78PofXuZR2iejwBrRQ61+UN4v7R8Uy3mt
XtsvFatbP6jj2R+GYRp9k15Qh9HCDw82/kv1ajU97rV6VZsa81q1VIf/VYqVOoz/crlS+4FU1zn+
fdcNvlXP1a0+G+o+NZ8V//NK/iv5n5X/+1UYrmUl/1+a/Id/9dAOCvc//leU/5V6vaTk/8uR/+VZ
+a8p+b8W+V+fkv8HlWo9r9WK9YoS/y9X/uuelzdc5+Iex3+tUlko/0taLP+rWgnKtVqlCPK/uM7x
/0Ll/x+WAwSw7a9bFusjz63LENpIDom2tfVHaPHyscWsgU15oa0PqA2/ms2jJjkSHYecuo4VuD7c
YeuhYwyp/3VrTH1muQ5ULeZL+SJc83TjSr+k8Eh8frrnbSlho/Cfwn+bgv/qpf1SsabG5Eud/009
