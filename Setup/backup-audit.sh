#!/usr/bin/env bash
# CCDC Debian guest-only backup and startup integrity audit.
# Read-only for scan/audit; backup/baseline write only to chosen output directory.
# Does NOT restart services, restore an OS, or claim to prove a machine is clean.
set -Eeuo pipefail
umask 077
export LC_ALL=C

usage() {
  cat <<'EOF'
CCDC Debian Guest Backup + Startup Audit
Usage:
  sudo bash ccdc-debian-backup-audit.sh scan REPORT_DIR
  sudo bash ccdc-debian-backup-audit.sh baseline BASELINE_DIR
  sudo bash ccdc-debian-backup-audit.sh audit BASELINE_DIR REPORT_DIR
  sudo bash ccdc-debian-backup-audit.sh backup BACKUP_DIR
  sudo bash ccdc-debian-backup-audit.sh verify BACKUP_FILE.tar.gz

scan:     Read-only survey of startup jobs, Splunk scripted inputs, services,
          local accounts, listening ports, and potentially harmful commands.
baseline: Capture a *trusted, pre-competition* file-hash/metadata inventory.
audit:    Compare current startup-related files to the trusted baseline.
backup:   Make a root-filesystem tar archive (ACLs, xattrs, owners, permissions).
verify:   Check SHA-256 and the archive's readable tar listing.

IMPORTANT:
* Keep the archive and baseline OFF the VM in an approved, trusted location.
* Backup while running is NOT an atomic/consistent VM snapshot.
* --one-file-system covers / only. Separately mounted persistent /boot,/var,
  /home,/opt/etc. require separate backups (see mounts text in output).
* Never restore a full filesystem archive over a running compromised OS.
* A malicious root user can tamper with an in-guest audit or local backup.
EOF
}

fail() { echo "ERROR: $*" >&2; exit 1; }
need_root() { [[ $EUID -eq 0 ]] || fail "Please run with sudo/root."; }
need_dir() {
  local d="$1"; [[ -n "$d" && "$d" = /* ]] || fail "Use an absolute output directory path.";
  [[ "$d" != "/" ]] || fail "Output cannot be /.";
  mkdir -p -- "$d"
  chmod 700 -- "$d" || true
}
timestamp() { date -u +%Y%m%dT%H%M%SZ; }

# A narrow list of locations that typically contain persistence and security config.
# This is intentionally NOT a complete malware scan.
watch_paths=(
  /etc
  /usr/local/bin /usr/local/sbin /usr/lib/systemd/system /lib/systemd/system
  /opt/splunk/etc /opt/splunk/bin/scripts /var/spool/cron
  /root/.ssh
)

hash_manifest() {
  local dest="$1"
  : > "$dest/hashes.sha256"
  : > "$dest/file-metadata.tsv"
  local p
  for p in "${watch_paths[@]}"; do
    if [[ -d "$p" ]]; then
      # Paths are sorted deterministically. Escape handling is GNU sha256sum's default.
      find "$p" -xdev -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum >> "$dest/hashes.sha256" || true
      find "$p" -xdev \( -type f -o -type l \) -printf '%p\t%y\t%m\t%u:%g\t%l\n' 2>/dev/null >> "$dest/file-metadata.tsv" || true
    fi
  done
  sort -u -o "$dest/hashes.sha256" "$dest/hashes.sha256"
  sort -u -o "$dest/file-metadata.tsv" "$dest/file-metadata.tsv"
}

snapshot_commands() {
  local dest="$1"
  {
    echo '=== Installed service unit files ==='
    systemctl list-unit-files --type=service --all --no-pager 2>&1 || true
    echo '=== Enabled and installed timer unit files ==='
    systemctl list-unit-files --type=timer --all --no-pager 2>&1 || true
    echo '=== Active timers (current runtime view) ==='
    systemctl list-timers --all --no-pager 2>&1 || true
    echo '=== Splunk unit definitions (if present) ==='
    systemctl list-unit-files --type=service --all --no-pager --no-legend 2>/dev/null \
      | awk 'tolower($1) ~ /splunk/ {print $1}' \
      | while IFS= read -r unit; do
          echo "--- $unit ---"
          systemctl cat "$unit" --no-pager 2>&1 || true
          systemctl show "$unit" -p ExecStart -p ExecStartPre -p ExecStartPost -p ExecStop -p FragmentPath -p DropInPaths 2>&1 || true
        done
    echo '=== /etc/rc.local (if present) ==='
    [[ ! -e /etc/rc.local ]] || sed -n '1,200p' /etc/rc.local
    echo '=== SysV startup links ==='
    find /etc/rc?.d -maxdepth 1 -type l -printf '%p -> %l\n' 2>/dev/null || true
  } > "$dest/startup-services.txt"

  {
    echo '=== System crontab and cron configuration ==='
    for d in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron; do
      if [[ -e "$d" ]]; then find "$d" -maxdepth 2 -printf '%p %y %m %u:%g\n' 2>/dev/null || true; fi
    done
    echo '=== Root crontab, when present ==='
    crontab -l -u root 2>&1 || true
  } > "$dest/cron-summary.txt"

  {
    echo '=== Splunk scripted-input definitions (DO NOT EXECUTE THESE) ==='
    if [[ -d /opt/splunk/etc ]]; then
      grep -RInE --include='inputs.conf' '^[[:space:]]*\[script://' /opt/splunk/etc 2>/dev/null || true
    fi
    echo '=== Splunk app scripts / scripts folder ==='
    find /opt/splunk/etc/apps /opt/splunk/etc/system/bin /opt/splunk/bin/scripts \
      -type f \( -path '*/bin/*' -o -path '*/scripts/*' \) \
      -printf '%p\t%m\t%u:%g\n' 2>/dev/null | head -n 1000 || true
  } > "$dest/splunk-scripted-inputs.txt"

  {
    echo '=== Potential destructive commands in startup-related scripts and configs ==='
    echo '(Pattern matches are NOT proof of malicious activity; manually review.)'
    for p in /etc/systemd /etc/cron.d /etc/rc.local /usr/local/bin /usr/local/sbin \
             /opt/splunk/etc /opt/splunk/bin/scripts; do
      if [[ -d "$p" ]]; then
        grep -RInE --binary-files=without-match \
          --include='*.service' --include='*.timer' --include='*.sh' \
          --include='inputs.conf' --include='*.path' --include='*.py' \
          '(systemctl[[:space:]]+(poweroff|halt|reboot)|shutdown[[:space:]]|poweroff|reboot|rm[[:space:]]+-rf)' "$p" 2>/dev/null || true
      elif [[ -f "$p" ]]; then
        grep -nE '(shutdown[[:space:]]|poweroff|reboot|rm[[:space:]]+-rf)' "$p" 2>/dev/null || true
      fi
    done
  } > "$dest/review-possible-destructive-commands.txt"

  { getent passwd || true; echo; getent group || true; } > "$dest/accounts-and-groups.txt"
  { ss -lntup 2>&1 || true; } > "$dest/listening-ports.txt"
  { ip -brief address 2>&1 || true; ip route 2>&1 || true; } > "$dest/network.txt"
  { ufw status verbose 2>&1 || true; } > "$dest/ufw.txt"
  { findmnt -rno TARGET,SOURCE,FSTYPE,OPTIONS 2>&1 || true; } > "$dest/mounts.txt"
  { dpkg-query -W -f='${Package}\t${Version}\n' 2>&1 || true; } > "$dest/packages.txt"
  printf 'Generated UTC: %s\nHost: %s\n' "$(date -u --iso-8601=seconds)" "$(hostname)" > "$dest/about.txt"
}

scan() {
  local dest="$1"; need_dir "$dest"
  snapshot_commands "$dest"
  echo "Read-only scan report: $dest"
  echo "Review startup-services.txt, splunk-scripted-inputs.txt, review-possible-destructive-commands.txt."
  echo "Nothing was executed from startup configs, and no service was restarted."
}

baseline() {
  local dest="$1"; need_dir "$dest"
  [[ ! -e "$dest/hashes.sha256" ]] || fail "Baseline already exists; choose another directory."
  snapshot_commands "$dest"
  hash_manifest "$dest"
  echo "Created TRUSTED baseline: $dest"
  echo "Copy baseline outside this VM immediately; it is not trustworthy if created after compromise."
}

audit() {
  local base="$1" dest="$2"
  [[ -f "$base/hashes.sha256" && -f "$base/file-metadata.tsv" ]] || fail "Invalid baseline directory."
  [[ "$(readlink -f "$base")" != "$(readlink -m "$dest")" ]] || fail "Audit output cannot overwrite baseline."
  need_dir "$dest"
  snapshot_commands "$dest"
  hash_manifest "$dest"
  diff -u -- "$base/hashes.sha256" "$dest/hashes.sha256" > "$dest/changed-file-hashes.diff" || true
  diff -u -- "$base/file-metadata.tsv" "$dest/file-metadata.tsv" > "$dest/changed-file-metadata.diff" || true
  for f in startup-services.txt splunk-scripted-inputs.txt cron-summary.txt; do
    if [[ -f "$base/$f" ]]; then
      diff -u -- "$base/$f" "$dest/$f" > "$dest/changed-$f.diff" || true
    fi
  done
  echo "Audit results: $dest"
  echo "Review changed-file-hashes.diff and changed-startup-services.txt.diff first."
  echo "Changes are suspicious only when unexplained; no change does NOT prove the VM is safe."
}

backup() {
  local dest="$1"; need_dir "$dest"
  command -v tar >/dev/null || fail 'GNU tar not installed'
  command -v sha256sum >/dev/null || fail 'sha256sum not installed'
  local name="ccdc-debian-root-$(hostname -s)-$(timestamp).tar.gz"
  local file="$dest/$name" temp="$dest/.${name}.partial"
  [[ ! -e "$file" && ! -e "$temp" ]] || fail 'Backup already exists; retry later.'
  local rootdevice destdevice
  rootdevice=$(stat -c '%d' /)
  destdevice=$(stat -c '%d' "$dest")
  if [[ "$rootdevice" == "$destdevice" ]]; then
    echo 'WARNING: Backup destination is on the SAME filesystem as Debian.' >&2
    echo 'Writing a whole-root backup here could fill the filesystem and stop scored services.' >&2
    if [[ "${CCDC_ALLOW_LOCAL_BACKUP:-0}" != "1" ]]; then
      fail 'Refusing local full backup by default. Use an approved off-VM mount, or explicitly set CCDC_ALLOW_LOCAL_BACKUP=1 before scoring (at your own risk).'
    fi
    echo 'OVERRIDE ACCEPTED: You must move the archive OFF the VM immediately.' >&2
  fi
  echo 'Disk space available at destination:'
  df -h -- "$dest"
  echo 'Persistent mountpoints (separate filesystems are NOT included by --one-file-system):'
  findmnt -rno TARGET,SOURCE,FSTYPE | grep -E '^(/ |/boot |/home |/var |/opt |/srv )' || true
  echo 'Creating live root filesystem archive; this may be large and non-atomic.'
  # GNU tar recursively backs up the root filesystem, excluding pseudo filesystems,
  # transient data, external mount points, and the archive directory itself.
  # A live OS can change while the archive is being created; we do not hide errors.
  local tarout="${dest%/}/backup-messages-$(timestamp).txt"
  local rel=".${dest}"
  if ! tar --create --gzip --file="$temp" --directory=/ \
       --acls --xattrs --xattrs-include='*' --numeric-owner --one-file-system \
       --exclude='./proc' --exclude='./sys' --exclude='./dev' --exclude='./run' \
       --exclude='./tmp' --exclude='./mnt' --exclude='./media' --exclude='./lost+found' \
       --exclude='./swapfile' --exclude="$rel" \
       . 2>"$tarout"; then
    echo "Backup could not be verified as successful. Review $tarout" >&2
    echo "Partial archive kept for inspection at $temp (DO NOT use as a trusted backup)." >&2
    exit 2
  fi
  mv -- "$temp" "$file"
  ( cd "$dest" && sha256sum "$name" > "$name.sha256" )
  {
    date -u --iso-8601=seconds
    uname -a
    findmnt -rno TARGET,SOURCE,FSTYPE,OPTIONS
    lsblk -f
  } > "$dest/$name.system-info.txt"
  chmod 600 "$file" "$file.sha256" "$dest/$name.system-info.txt"
  echo "Backup created: $file"
  echo "Checksum: $file.sha256"
  echo "NEXT: sudo bash $0 verify '$file'"
  echo 'Then transfer archive, checksum, and system-info off the VM.'
  echo 'Restore requires an offline/rescue environment and validation, not extraction over a live server.'
}

verify() {
  local f="$1"; [[ -f "$f" && -f "$f.sha256" ]] || fail 'Archive or checksum not found.'
  local d b; d=$(dirname -- "$f"); b=$(basename -- "$f")
  ( cd "$d" && sha256sum --check -- "$b.sha256" )
  tar -tzf "$f" >/dev/null
  echo 'Checksum and archive listing verified. This does not prove the live backup is fully consistent.'
}

main() {
  need_root
  (($# >= 1)) || { usage; exit 1; }
  local cmd="$1"; shift
  case "$cmd" in
    -h|--help|help) usage ;;
    scan) (($# == 1)) || fail 'scan needs REPORT_DIR'; scan "$1" ;;
    baseline) (($# == 1)) || fail 'baseline needs BASELINE_DIR'; baseline "$1" ;;
    audit) (($# == 2)) || fail 'audit needs BASELINE_DIR REPORT_DIR'; audit "$1" "$2" ;;
    backup) (($# == 1)) || fail 'backup needs BACKUP_DIR'; backup "$1" ;;
    verify) (($# == 1)) || fail 'verify needs BACKUP_FILE.tar.gz'; verify "$1" ;;
    *) usage; fail "Unknown command: $cmd" ;;
  esac
}
main "$@"
