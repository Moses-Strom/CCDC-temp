#!/usr/bin/env bash
# CCDC | optional Splunk Enterprise 10.0 maintenance upgrade for a trusted Debian VM.
# Downloads only official vendor .deb / .sha512, verifies hash, backs up local config,
# and preserves the existing Splunk service user/launch mechanism where supported.
# Usage: sudo bash ccdc-upgrade-splunk.sh --check | --upgrade
# Target: 10.0.12 by default; set CCDC_SPLUNK_TARGET_VERSION=10.0.11 if required.
set -euo pipefail
umask 077
mode="${1:---check}"
[[ "$mode" == --check || "$mode" == --upgrade ]] || { echo 'FAIL | Usage: --check or --upgrade' >&2; exit 2; }
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
TARGET="${CCDC_SPLUNK_TARGET_VERSION:-10.0.12}"
case "$TARGET" in
  10.0.12) build='e3ec63dc1d02' ;;
  10.0.11) build='c1c0c3ccd7cb' ;;
  *) echo 'FAIL | Supported targets: 10.0.12 (default), 10.0.11' >&2; exit 2 ;;
esac
pkg_name="splunk-${TARGET}-${build}-linux-amd64.deb"
base_url="https://download.splunk.com/products/splunk/releases/${TARGET}/linux"
package_url="$base_url/$pkg_name"
checksum_url="${package_url}.sha512"
log(){ printf '%s\n' "$*"; }
fail(){ printf 'FAIL | %s\n' "$*" >&2; exit 1; }
command -v dpkg-query >/dev/null 2>&1 || fail 'dpkg-query missing (is this Debian?)'
current="$(dpkg-query -W -f='${Version}' splunk 2>/dev/null || true)"
log "INFO | Installed splunk package: ${current:-NOT FOUND}"
log "INFO | Target Splunk Enterprise: $TARGET"
[[ "$mode" == --upgrade ]] || exit 0
[[ $EUID -eq 0 ]] || fail 'Upgrade requires root (console only)'
[[ -n "$current" ]] || fail 'No dpkg-installed splunk package; tar/rpm installs need a separate upgrade method'
if dpkg --compare-versions "$current" ge "$TARGET"; then
  log "PASS | Splunk package $current already meets target $TARGET; no upgrade needed"
  exit 0
fi
[[ "$SPLUNK_HOME" == /opt/splunk ]] || fail 'Debian package upgrade requires SPLUNK_HOME=/opt/splunk'
[[ -d "$SPLUNK_HOME" && ! -L "$SPLUNK_HOME" ]] || fail 'Splunk installation must be a real /opt/splunk directory'
[[ $(uname -m) == x86_64 ]] || fail 'Official package selected here is x86_64 only'
[[ -f /etc/os-release ]] || fail 'Cannot verify operating system'
. /etc/os-release
[[ "${ID:-}" == debian && "${VERSION_ID:-}" == 12* ]] || fail 'This helper is limited to Debian 12 practice/CCDC VMs'
[[ "$current" == 10.0.* ]] || fail "Unexpected source version $current; review vendor-supported upgrade path"
[[ -x "$SPLUNK_HOME/bin/splunk" ]] || fail 'Splunk binary absent or not executable'
# Do not blindly upgrade a potentially compromised host: this is for a verified practice/CCDC image.
log 'WARN | Upgrade is destructive/not easily reversible; do not use in-place on a host suspected of root-level compromise.'
log 'WARN | Stop/service migration causes downtime and can affect scored query, management and Web services.'
log 'WARN | Local configuration backup is on this same VM and cannot survive full disk loss or root compromise.'
log 'INFO | Official package and matching SHA512 will be obtained from Splunk download host (or verified from a local cache).'
read -r -p "To authorize PREPARING the Splunk $TARGET upgrade, type PREPARE-UPGRADE: " confirm || true
[[ "${confirm:-}" == PREPARE-UPGRADE ]] || { log 'SKIP | Upgrade not approved'; exit 3; }
for c in wget sha512sum dpkg-deb df tar stat awk; do command -v "$c" >/dev/null 2>&1 || fail "Missing prerequisite: $c"; done
cache="${CCDC_SPLUNK_PACKAGE_CACHE:-/root/ccdc-splunk-upgrade-cache}"
[[ ! -L "$cache" ]] || fail 'Refusing symlinked package cache directory'
mkdir -p -m 0700 "$cache"
chmod 0700 "$cache"
package="$cache/$pkg_name"
checksum="$cache/${pkg_name}.sha512"
# The operator can pre-stage the exact file on the VM; no off-machine backups assumed.
if [[ ! -s "$package" ]]; then
  log "INFO | Downloading the official Splunk .deb to $package (approximately 1.26 GB)."
  wget --https-only --tries=2 --timeout=60 -O "$package.part" "$package_url" || fail 'Package download failed; Splunk has not been stopped'
  mv -f -- "$package.part" "$package"
else
  log "INFO | Found cached package $package (will verify before trusting)."
fi
# Always refresh vendor checksum from the same official HTTPS endpoint unless manually pinned.
if [[ -n "${CCDC_SPLUNK_EXPECTED_SHA512:-}" ]]; then
  expected="${CCDC_SPLUNK_EXPECTED_SHA512,,}"
  log 'INFO | Using SHA512 provided explicitly in CCDC_SPLUNK_EXPECTED_SHA512.'
else
  wget --https-only --tries=2 --timeout=30 -O "$checksum.part" "$checksum_url" || fail 'Vendor SHA512 download failed; package NOT installed'
  mv -f -- "$checksum.part" "$checksum"
  # Supports SHA512 checksum lines as a hash alone, hash + filename, or SHA512(name)=hash.
  expected="$(python3 - "$checksum" "$pkg_name" <<'PY'
import pathlib,re,sys
raw=pathlib.Path(sys.argv[1]).read_text(encoding='utf-8').strip()
name=sys.argv[2]
if '\n' in raw: raise SystemExit('FAIL | Multiple checksum entries; review manually')
hexes=re.findall(r'(?<![0-9a-fA-F])[0-9a-fA-F]{128}(?![0-9a-fA-F])',raw)
if len(hexes)!=1: raise SystemExit('FAIL | Cannot parse one vendor SHA512 digest')
# If the vendor file names a package, ensure it is the package we requested.
if '.deb' in raw and name not in raw: raise SystemExit('FAIL | Vendor checksum names another package')
print(hexes[0].lower())
PY
)" || fail 'Vendor SHA512 parsing failed'
fi
[[ "$expected" =~ ^[a-f0-9]{128}$ ]] || fail 'Expected SHA512 must be exactly 128 hex characters'
actual="$(sha512sum "$package" | awk '{print $1}')"
[[ "$actual" == "$expected" ]] || fail 'SHA512 mismatch: refusing to install the package'
log 'PASS | Official package SHA512 matches vendor hash'
name_field="$(dpkg-deb -f "$package" Package 2>/dev/null || true)"
version_field="$(dpkg-deb -f "$package" Version 2>/dev/null || true)"
[[ "$name_field" == splunk && "$version_field" == "$TARGET"* ]] || fail "Package metadata mismatch ($name_field $version_field)"
log 'PASS | Package metadata matches requested Splunk version'
# Avoid a full-system backup; keep config and account database locally for recovery investigation.
backup_root="${CCDC_SPLUNK_BACKUP_DIR:-/root/ccdc-splunk-upgrade-backups}"
[[ ! -L "$backup_root" ]] || fail 'Refusing symlinked backup destination'
mkdir -p -m 0700 "$backup_root"
chmod 0700 "$backup_root"
# Require a meaningful disk margin beyond the downloaded .deb and a likely config archive.
free_mb="$(df -Pm "$backup_root" | awk 'END{print $4}')"
[[ "$free_mb" =~ ^[0-9]+$ ]] || fail 'Cannot determine backup filesystem free space'
(( free_mb >= 1024 )) || fail 'Less than 1 GB free for backup and package migration'
backup="$backup_root/splunk-etc-pre-${TARGET}-$(date +%Y%m%d-%H%M%S)-$$.tar.gz"
log "INFO | Backing up /opt/splunk/etc locally to $backup (contains sensitive configuration)."
tar -czpf "$backup" -C "$SPLUNK_HOME" etc || fail 'Configuration backup failed: refusing upgrade'
chmod 0600 "$backup"
[[ -s "$backup" ]] || fail 'Configuration backup is empty'
log 'PASS | Local configuration backup created (not a VM snapshot)'
# Recognize the existing service launcher before stopping anything.
service=''
for candidate in Splunkd.service splunkd.service splunk.service; do
  if systemctl is-active --quiet "$candidate"; then service="$candidate"; break; fi
done
owner="$(ps -eo user=,comm= 2>/dev/null | awk '$2=="splunkd" {print $1;exit}' || true)"
launcher='systemd'
if [[ -z "$service" ]]; then
  launcher='cli'
  [[ -n "$owner" ]] || fail 'No running Splunk service and no recognizable systemd service; manual upgrade required'
  [[ "$owner" == root ]] || { command -v runuser >/dev/null 2>&1 || fail 'runuser not available for preserving service account'; }
fi
log "INFO | Existing launcher: $launcher; service=${service:-none}; owner=${owner:-unknown}"
read -r -p "Type UPGRADE-$TARGET to STOP Splunk and install the verified package: " confirm || true
[[ "${confirm:-}" == "UPGRADE-$TARGET" ]] || { log 'SKIP | Upgrade canceled before service interruption'; exit 3; }
# Stop using its current launch mechanism; do not switch daemon ownership inadvertently.
if [[ "$launcher" == systemd ]]; then
  systemctl stop "$service" || fail 'Could not stop existing systemd service; package not installed'
else
  if [[ "$owner" == root ]]; then "$SPLUNK_HOME/bin/splunk" stop || fail 'Could not stop Splunk';
  else runuser -u "$owner" -- "$SPLUNK_HOME/bin/splunk" stop || fail 'Could not stop Splunk'; fi
fi
if ! DEBIAN_FRONTEND=noninteractive dpkg -i "$package"; then
  log 'FAIL | Package installation failed; do not blindly downgrade. Investigate dpkg and migration before restarting.' >&2
  exit 1
fi
# Vendor migration must occur on first start; preserve original systemd arrangement.
if [[ "$launcher" == systemd ]]; then
  systemctl start "$service" || fail 'Package upgraded but systemd restart failed; investigate migration and service logs'
else
  if [[ "$owner" == root ]]; then "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes || fail 'Package upgraded but CLI restart failed';
  else runuser -u "$owner" -- "$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes || fail 'Package upgraded but CLI restart failed'; fi
fi
installed="$(dpkg-query -W -f='${Version}' splunk 2>/dev/null || true)"
if ! dpkg --compare-versions "$installed" ge "$TARGET"; then fail "Installed version $installed below target $TARGET"; fi
log "PASS | Splunk package upgraded to $installed; service startup attempted"
log 'REVIEW | Validate Web, management API, authenticated searches, receiving on 9997 and indexed events from an approved peer.'
log 'REVIEW | Apply post-upgrade lookup-write enforcement and review Secure Gateway update separately.'
