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
0Av3Ov5XxH/VerGs8J+S/0r+K/mvjseR/6FVuL/xv6L8r5VLRSX/lfxX8v8x5H+pWKmU6nUl/1+6
/Hf0ceF+xv+K8r+uFStK/iv5r+T/I8n/g3pRU/Jfyf9xVJa/GdnfM/6/tf5TL9Wm5T+Mfpgu1PrP
Go63vwBjiVyrOfxJyxd/ItQxXNNyLg9/CoOLvf2ffnm39Ra6AmFU941hf2zR68OcOMm92yLkLZYQ
RwcpkuP9yYXnYVmOyN5zmAv8kOZIYW51273sG3iPfrmwjkkDagTwjf3At75RTzcXXRkx9pe96OK1
5Wjaoou+a1xNFl2kI91a+Fjm2aFztehqOAidIOxfu/4VdEJs3KKanm67fd0O3EUVxhOX8WtvcdC+
U/O/mv+/a/7XylWF/178/I9ShhXuY/yviv8qOP8r/Kfwn5L/a5X/wv+vWi0W9/eV/FfyH+W/1Kvv
jgCX4L9quVqe9v8raVCm8N8m4b8L1x/F1XJaXhPIj3sDvuO+gP8mDQBoY0qOLB+gmutP3hbEZaxo
Umb4locg590XyzHda0a6gBKpT0rFUok0jogeEK1eAu0zD2pAXisW81DDhkcRK2BEN4JQt0mXIyoy
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
CKsAkAEA
