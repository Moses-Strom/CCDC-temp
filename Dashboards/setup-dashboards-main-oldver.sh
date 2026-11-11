#!/usr/bin/env bash
# CCDC Splunk dashboards + detections installer (self-contained, offline)
# Installs the app into the existing Splunk Enterprise instance without
# touching existing listeners, accounts, service configuration, or indexes.
set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
APPS_DIR="$SPLUNK_HOME/etc/apps"
TARGET="$APPS_DIR/ccdc_defense"
MODE="${1:-install}"
EXPECTED_SHA256="6c0e0385615c087ca1688b0e42336e7a1ea2dac55c53245add1b5f5ab90ad983"

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
  local dashboards reports scheduled
  dashboards=$(find "$viewdir" -maxdepth 1 -type f -name '*.xml' | wc -l)
  reports=$(grep -c '^\[' "$TARGET/default/savedsearches.conf" || true)
  scheduled=$(grep -Ec '^enableSched[[:space:]]*=[[:space:]]*1$' "$TARGET/default/savedsearches.conf" || true)
  echo "Location: $TARGET"
  echo "Dashboard XML files: $dashboards (expected 12)"
  echo "Saved searches: $reports (71 original reports + 5 alerts = 76)"
  echo "Scheduled searches enabled by this app: $(grep -Ec '^enableSched[[:space:]]*=[[:space:]]*1$' "$TARGET/default/savedsearches.conf" || true)"
  if [[ "$dashboards" -ne 12 || "$reports" -ne 76 || "$scheduled" -ne 5 ]]; then
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
  # Preserve configured critical hostnames when updating the app.
  if [[ -f "$TARGET/lookups/ccdc_critical_hosts.csv" ]]; then
    cp -a "$TARGET/lookups/ccdc_critical_hosts.csv" "$WORKDIR/critical_hosts.saved.csv"
  fi
fi

# Extract the packaged app (only contains files in ccdc_defense/).
tar -xzf "$WORKDIR/ccdc_defense_app.tar.gz" -C "$APPS_DIR"
# Restore verified local critical host values after upgrading bundled templates.
if [[ -f "$WORKDIR/critical_hosts.saved.csv" ]]; then
  cp -a "$WORKDIR/critical_hosts.saved.csv" "$TARGET/lookups/ccdc_critical_hosts.csv"
fi

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
  5. 71 original reports stay unscheduled; 5 new alerts run every 5 minutes.
  6. Go to Activity -> Triggered Alerts for findings (no email actions).
  7. CONFIGURE lookups/ccdc_critical_hosts.csv for the log-silence alert.

This app does not configure TCP 9997, forwarders, Sysmon, Palo Alto or VyOS.
Panels and alerts that need those log sources stay empty until configured.
NEXT
exit 0
__CCDC_PAYLOAD_BELOW__
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
2IXpHHec0HuL26OyjSxM8569LvuUm6xSqBWzRtJBElJKEnytm0iDmSxMCT0l21LPs5mf/pX7aZD7
yWY/7b766eDVT510RreENlQYcvqbc8e3tvZCX4905Qv5wn8cm1e73LR58DDfKMpr0d9isVxJfmM5
mKdG6QW7WgYARkClAXz+meK/tMkGyOLbRn2rvFUqVrcq+UqpVq1VK5orn8GV1hkK0eLN/fN/qV6t
pvneqFeNCZ43qqV6uVSsG6US8H+1WDZesOoy+R8Plv5aPd90unSSmq3l/73L//Ks/De0/F+K/K/P
lf91o6rF/7OV/wuMxG/h/1qlslD+w+QwKf9LRrVce8GKy+T/Zyr/KaQIrbWssvzXmruNww+t7kGr
2z5q/vKvrNpVm8MkcjyweLaYqtI6aOztZz+ejrxwJENwJx53jvc/Hv6S3eGnjumpOMaJCo2dbLIT
jYKU4hPTJurRcTdxVXlX1BJK2396/r9H+2+ztLlVLOeNzcpWbauu2eu5zf+R37Zw7/x/I/sP/qsU
K3W0/4xSTdt/Wv5r+f848r8K7FrW8v/Zyn91rmMeC+6H/79m/1WMypT8r1eMurb/lnH9/ueayoy0
jcGuNnvFfmcv2Z9Zdgn2P6dbirhlf65havcghIqC4vDW1n6/cPil+KYWaPOCXKvm39aScl58Qxta
GuhLX/rSl770pS996Utf+tKXvvSlL33pS1/60pe+9KUvfelLX/rSl770pS996Utf+tKXvvSlr6dw
/X91lHKMAOABAA==
