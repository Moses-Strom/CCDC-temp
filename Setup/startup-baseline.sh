#!/usr/bin/env bash
# CCDC: snapshot, compare and selectively restore startup/persistence configuration.
# --baseline records hashes and copies of selected configuration files.
# --check is read-only. --restore requires explicit console confirmation.
# Does not automatically restart services, alter users, or remove unknown files.
set -euo pipefail
umask 077

BASE="/root/ccdc-known-good-startup"
REPORT_ROOT="/root/ccdc-startup-audits"
SPLUNK="/opt/splunk/bin/splunk"

usage() {
  cat <<'HELP'
Usage: sudo bash ccdc-startup-baseline.sh --baseline|--check|--restore [--dry-run]
  --baseline          Capture a trusted startup state ONCE, with restorable copies
                      of selected configuration files (never overwrite an existing baseline).
  --check             Compare current state to baseline; do not modify services.
  --restore           Preview changed/deleted baselined configuration files and
                      ask for explicit confirmation before restoring their content,
                      owner and permissions. Backs up current versions first.
  --restore --dry-run Preview without prompting or modifying files.
Restore does NOT delete unknown added files, restore account databases, alter
firewall runtime state, or restart/reload services. Inspect unknown persistence
entries before restarting anything. Older hash-only baselines cannot restore.
Keep baselines and audit reports root-only; local storage is NOT trusted after
a root compromise. Never create a baseline on an untrusted host.
HELP
}
[[ ${1:-} == --help || ${1:-} == -h ]] && { usage; exit 0; }
[[ ${EUID} -eq 0 ]] || { echo 'ERROR: Run via sudo or root.' >&2; exit 2; }
if ! { [[ $# -eq 1 ]] || { [[ $# -eq 2 && $1 == --restore && $2 == --dry-run ]]; }; }; then
  usage; exit 2
fi

capture() {
  local dest="$1" directory path f unit
  mkdir -p "$dest"
  # Collect known persistence areas, plus executable/configuration files in Splunk.
  # Store hashes + metadata, not raw file contents.
  {
    for path in \
      /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
      /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly \
      /etc/cron.monthly /etc/init.d /var/spool/cron/crontabs \
      /etc/ssh /etc/sudoers.d /etc/profile.d /etc/udev/rules.d \
      /etc/network/if-up.d /etc/network/if-pre-up.d /var/spool/cron/atjobs \
      /usr/local/bin /usr/local/sbin; do
      [[ -d "$path" ]] && find "$path" -type f -print0
    done
    for f in /etc/crontab /etc/rc.local /etc/passwd /etc/group /etc/shadow \
             /etc/sudoers /etc/ld.so.preload; do
      [[ -f "$f" ]] && printf '%s\0' "$f"
    done
    if [[ -d /opt/splunk/etc ]]; then
      find /opt/splunk/etc -type f \
        \( -name '*.conf' -o -name '*.path' -o -name '*.py' \
           -o -name '*.sh' -o -name '*.service' -o -name '*.js' \
           -o -name '*.pl' -o -name '*.ps1' -o -name '*.xml' \
           -o -name '*.html' -o -name '*.css' -o -name '*.json' \
           -o -name '*.yml' -o -name '*.yaml' -o -perm /111 \) -print0
    fi
    for path in /opt/splunk/bin/scripts /opt/splunk/etc/system/bin; do
      [[ -d "$path" ]] && find "$path" -type f -print0
    done
    : # Always succeed when the last optional path is absent.
  } | LC_ALL=C sort -zu > "$dest/files.nul"

  : > "$dest/file-hashes.txt"
  : > "$dest/file-permissions.txt"
  while IFS= read -r -d '' f; do
    if [[ -f "$f" ]]; then
      sha256sum -- "$f" >> "$dest/file-hashes.txt" \
        || printf 'UNREADABLE %s\n' "$f" >> "$dest/file-hashes.txt"
      stat -c '%a %u %g %n' -- "$f" >> "$dest/file-permissions.txt" \
        || printf 'UNSTATABLE %s\n' "$f" >> "$dest/file-permissions.txt"
    fi
  done < "$dest/files.nul"
  cp -- "$dest/files.nul" "$dest/file-paths.nul"
  rm -f "$dest/files.nul"
  # Track symlink targets separately: changes to startup symlinks can matter.
  {
    for path in /etc/systemd/system /etc/cron.d /etc/ssh \
                /opt/splunk/etc /opt/splunk/bin/scripts; do
      [[ -d "$path" ]] || continue
      find "$path" -type l -print0
    done
  } | LC_ALL=C sort -zu | while IFS= read -r -d '' f; do
    printf '%s -> %s\n' "$f" "$(readlink -- "$f")"
  done > "$dest/symlink-targets.txt"

  systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager \
      2>&1 | LC_ALL=C sort > "$dest/enabled-services.txt" || true
  systemctl list-unit-files --type=timer --no-legend --no-pager \
      2>&1 | LC_ALL=C sort > "$dest/timer-units.txt" || true
  systemctl list-timers --all --no-pager > "$dest/timer-schedule-current.txt" 2>&1 || true
  ss -H -lntup 2>&1 | LC_ALL=C sort > "$dest/listening-sockets.txt" || true
  if command -v atq >/dev/null 2>&1; then
    atq > "$dest/at-jobs.txt" 2>&1 || true
  else
    echo 'at command not installed' > "$dest/at-jobs.txt"
  fi
  if command -v ufw >/dev/null 2>&1; then
    ufw status verbose > "$dest/ufw-status.txt" 2>&1 || true
  else
    echo 'ufw not installed' > "$dest/ufw-status.txt"
  fi
  if command -v crontab >/dev/null 2>&1; then
    {
      while IFS=: read -r user _; do
        entries="$(crontab -u "$user" -l 2>/dev/null || true)"
        if [[ -n "$entries" ]]; then
          printf '\n--- %s ---\n%s\n' "$user" "$entries"
        fi
      done < /etc/passwd
    } > "$dest/user-crontabs.txt"
  else
    echo 'crontab command not installed' > "$dest/user-crontabs.txt"
  fi
  {
    while read -r unit _; do
      if [[ "$unit" == *splunk*.service || "$unit" == *Splunk*.service ]]; then
        echo "--- $unit ---"
        systemctl cat "$unit" 2>&1 || true
        systemctl show "$unit" \
          -p ExecStart -p ExecStartPre -p ExecStartPost -p ExecStop -p ExecStopPost \
          -p FragmentPath -p DropInPaths 2>&1 || true
      fi
    done < <(systemctl list-unit-files --type=service --all --no-legend --no-pager 2>/dev/null)
  } > "$dest/splunk-systemd-units.txt"
  if [[ -x "$SPLUNK" ]]; then
    for conf in inputs savedsearches commands alert_actions; do
      "$SPLUNK" btool "$conf" list --debug \
        > "$dest/splunk-${conf}.txt" 2>&1 \
        || echo "WARNING: btool $conf could not be evaluated" >> "$dest/splunk-${conf}.txt"
    done
  else
    echo 'Splunk binary not found' > "$dest/splunk-inputs.txt"
    echo 'Splunk binary not found' > "$dest/splunk-savedsearches.txt"
    echo 'Splunk binary not found' > "$dest/splunk-commands.txt"
    echo 'Splunk binary not found' > "$dest/splunk-alert_actions.txt"
  fi
  getent group sudo > "$dest/sudo-group.txt" 2>&1 || true
  date -u '+Snapshot timestamp: %Y-%m-%dT%H:%M:%SZ' > "$dest/readme.txt"
}

# Only copies files from these approved, primarily startup-related paths.
# Sensitive account databases, vendor binaries, and arbitrary files are audited
# by --check but are intentionally NOT automatically rolled back.
restorable_path() {
  case "$1" in
    /etc/systemd/system/*|/etc/cron.d/*|/etc/cron.daily/*|/etc/cron.hourly/*|\
    /etc/cron.weekly/*|/etc/cron.monthly/*|/etc/init.d/*|\
    /var/spool/cron/crontabs/*|/etc/crontab|/etc/rc.local|\
    /etc/ssh/sshd_config|/etc/ssh/sshd_config.d/*.conf|\
    /etc/sudoers|/etc/sudoers.d/*|/etc/profile.d/*|\
    /etc/udev/rules.d/*|/etc/network/if-up.d/*|/etc/network/if-pre-up.d/*|\
    /usr/local/bin/*|/usr/local/sbin/*|/etc/ld.so.preload|\
    /opt/splunk/etc/*|/opt/splunk/bin/scripts/*) return 0 ;;
    *) return 1 ;;
  esac
}

make_restorable_snapshot() {
  local dest="$1" f size saved=0 skipped=0
  mkdir -p "$dest/restorable/files"
  : > "$dest/restorable/paths.nul"
  : > "$dest/restorable/skipped.txt"
  while IFS= read -r -d '' f; do
    restorable_path "$f" || continue
    [[ -f "$f" && ! -L "$f" ]] || continue
    size="$(stat -c %s -- "$f" 2>/dev/null || printf 0)"
    # Avoid snapshots of unexpectedly huge files; hash-only audit still covers them.
    if ((size > 5 * 1024 * 1024)); then
      printf 'Too large to copy (hash-only): %s\n' "$f" >> "$dest/restorable/skipped.txt"
      skipped=$((skipped + 1))
      continue
    fi
    mkdir -p -- "$dest/restorable/files$(dirname -- "$f")"
    cp -p -- "$f" "$dest/restorable/files$f"
    printf '%s\0' "$f" >> "$dest/restorable/paths.nul"
    saved=$((saved + 1))
  done < "$dest/file-paths.nul"
  # Parent directories are private; keep original file modes (e.g. sudoers 0440).
  chmod 0700 "$dest/restorable" "$dest/restorable/files"
  echo "Restorable configuration files saved: $saved (oversized skipped: $skipped)"
}

is_ssh_session() {
  [[ -n "${SSH_CONNECTION:-}${SSH_CLIENT:-}${SSH_TTY:-}" ]] && return 0
  local pid=$$ comm ppid hops=0
  while ((pid > 1 && hops < 40)); do
    comm="$(ps -o comm= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
    case "$comm" in sshd|sshd-session) return 0 ;; esac
    ppid="$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
    [[ "$ppid" =~ ^[0-9]+$ ]] || break
    pid="$ppid"
    hops=$((hops + 1))
  done
  return 1
}

# Refuse to traverse symlinked path components when writing as root.
no_symlink_components() {
  local path="$1" item prefix=''
  local -a parts
  [[ "$path" == /* ]] || return 1
  IFS='/' read -r -a parts <<< "${path#/}"
  for item in "${parts[@]}"; do
    [[ -n "$item" && "$item" != '.' && "$item" != '..' ]] || return 1
    prefix+="/$item"
    [[ ! -L "$prefix" ]] || return 1
  done
  return 0
}

# Config restoration never implies it is safe to restart Splunk or the VM.
restore_baseline() {
  [[ -f "$BASE/restorable/paths.nul" && -d "$BASE/restorable/files" ]] || {
    echo 'ERROR: This baseline has hashes only; it has no restorable file contents.' >&2
    echo 'Create a NEW baseline on a verified clean VM using this updated script.' >&2
    return 2
  }
  if is_ssh_session; then
    echo 'ERROR: Restore requires the NETLAB/VM local console, not SSH.' >&2
    return 2
  fi
  local f original mode_orig mode_current
  local -a changed=() unsafe=()
  # Also report previously unknown startup-related files: restoring known files
  # alone does NOT neutralize newly installed persistence.
  mkdir -p "$REPORT_ROOT"
  chmod 0700 "$REPORT_ROOT"
  local audit
  audit="$(mktemp -d "$REPORT_ROOT/restore-preview-XXXXXXXX")"
  capture "$audit"
  local -A baseline_seen=()
  local new_count=0
  if [[ -f "$BASE/file-paths.nul" ]]; then
    while IFS= read -r -d '' f; do baseline_seen["$f"]=1; done < "$BASE/file-paths.nul"
  fi
  echo '=== NEW STARTUP / CONFIG FILES SINCE BASELINE ==='
  : > "$audit/new-files.txt"
  while IFS= read -r -d '' f; do
    if [[ ! -v baseline_seen["$f"] ]]; then
      printf 'REVIEW NEW | %s\n' "$f" >> "$audit/new-files.txt"
      if ((new_count < 20)); then printf 'REVIEW NEW | %s\n' "$f"; fi
      new_count=$((new_count + 1))
    fi
  done < "$audit/file-paths.nul"
  printf 'New files requiring review: %d\n' "$new_count"
  if ((new_count > 20)); then echo "Full list: $audit/new-files.txt"; fi
  if ! cmp -s "$BASE/symlink-targets.txt" "$audit/symlink-targets.txt"; then
    echo 'REVIEW | Startup/configuration symlink changes detected.'
    echo "         Compare: diff -u '$BASE/symlink-targets.txt' '$audit/symlink-targets.txt'"
  fi
  if ! cmp -s "$BASE/enabled-services.txt" "$audit/enabled-services.txt"; then
    echo 'REVIEW | Enabled systemd services differ from baseline.'
  fi
  while IFS= read -r -d '' f; do
    restorable_path "$f" || { unsafe+=("$f"); continue; }
    original="$BASE/restorable/files$f"
    if [[ ! -f "$original" || -L "$original" ]] || ! no_symlink_components "$f"; then
      unsafe+=("$f")
      continue
    fi
    mode_orig="$(stat -c '%a:%u:%g' -- "$original" 2>/dev/null || true)"
    mode_current="$(stat -c '%a:%u:%g' -- "$f" 2>/dev/null || true)"
    if [[ ! -f "$f" ]] || ! cmp -s -- "$original" "$f" || [[ "$mode_orig" != "$mode_current" ]]; then
      changed+=("$f")
    fi
  done < "$BASE/restorable/paths.nul"

  printf '\n=== BASELINE RESTORE PREVIEW (no changes yet) ===\n'
  printf 'Baselined files requiring restoration: %d\n' "${#changed[@]}"
  for f in "${changed[@]}"; do printf 'RESTORE | %s\n' "$f"; done
  for f in "${unsafe[@]}"; do printf 'SKIP UNSAFE | %s\n' "$f"; done
  echo 'NOT INCLUDED: account databases, vendor-managed service files, runtime UFW state.'
  echo 'NOT REMOVED: newly added scripts, files, services, timers, or symlinks.'
  echo 'IMPORTANT: Inspect added persistence entries and modified privileged accounts.'
  echo 'No service restarts/reloads or automatic account changes are performed.'
  if [[ ${2:-} == --dry-run ]]; then echo 'DRY RUN: no files changed.'; return 0; fi
  if ((${#changed[@]} == 0)); then
    echo 'Nothing to restore from the saved file copies.'
    return 0
  fi

  local answer
  read -r -p 'Type RESTORE BASELINE to overwrite those files: ' answer || true
  if [[ "$answer" != 'RESTORE BASELINE' ]]; then
    echo 'CANCELLED: no files changed.'
    return 0
  fi

  mkdir -p "$REPORT_ROOT"
  chmod 0700 "$REPORT_ROOT"
  local rollback count=0 failed=0 dest parent tmp
  rollback="$(mktemp -d "$REPORT_ROOT/pre-restore-XXXXXXXX")"
  mkdir -p "$rollback/before"
  chmod 0700 "$rollback" "$rollback/before"
  printf 'Pre-restore copies, when existing, live under before/; read report.txt.\n' > "$rollback/report.txt"
  for f in "${changed[@]}"; do
    original="$BASE/restorable/files$f"
    if ! no_symlink_components "$f" || [[ ! -f "$original" || -L "$original" ]]; then
      printf 'FAIL | Unsafe or missing baseline file: %s\n' "$f" | tee -a "$rollback/report.txt"
      failed=$((failed + 1))
      continue
    fi
    parent="$(dirname -- "$f")"
    # Do not create arbitrary parent dirs that might have been removed/hijacked.
    if [[ ! -d "$parent" ]]; then
      printf 'FAIL | Parent directory missing: %s\n' "$f" | tee -a "$rollback/report.txt"
      failed=$((failed + 1))
      continue
    fi
    if [[ -e "$f" ]]; then
      mkdir -p "$rollback/before$parent"
      if ! cp -p -- "$f" "$rollback/before$f"; then
        printf 'FAIL | Could not preserve current version: %s\n' "$f" | tee -a "$rollback/report.txt"
        failed=$((failed + 1)); continue
      fi
    fi
    # Create temp in same destination directory; atomically replace final file.
    tmp="$(mktemp "$parent/.ccdc-restore-XXXXXXXX")" || { failed=$((failed + 1)); continue; }
    if cp -p -- "$original" "$tmp" && mv -fT -- "$tmp" "$f"; then
      if cmp -s -- "$original" "$f" && \
        [[ "$(stat -c '%a:%u:%g' -- "$original")" == "$(stat -c '%a:%u:%g' -- "$f")" ]]; then
        printf 'PASS | Restored: %s\n' "$f" | tee -a "$rollback/report.txt"
        count=$((count + 1))
      else
        printf 'FAIL | Post-restore mismatch: %s\n' "$f" | tee -a "$rollback/report.txt"
        failed=$((failed + 1))
      fi
    else
      rm -f -- "$tmp"
      printf 'FAIL | Could not restore: %s\n' "$f" | tee -a "$rollback/report.txt"
      failed=$((failed + 1))
    fi
  done
  printf '\nRestored: %d | Failed: %d | Pre-restore copies: %s\n' "$count" "$failed" "$rollback"
  if command -v visudo >/dev/null 2>&1; then
    visudo -c >/dev/null 2>&1 && echo 'PASS | sudoers syntax' || echo 'WARN | sudoers syntax check failed'
  fi
  if [[ -x /usr/sbin/sshd ]]; then
    /usr/sbin/sshd -t && echo 'PASS | OpenSSH configuration syntax' || echo 'WARN | OpenSSH configuration syntax check failed'
  fi
  echo 'REVIEW REQUIRED: Recheck changed systemd units, cron, Splunk scripted inputs,'
  echo 'new files/symlinks and sudo accounts before any reboot or Splunk restart.'
  echo 'Restored configuration is NOT automatically activated. It does NOT prove the host is clean.'
  ((failed == 0))
}

case "$1" in
  --baseline)
    if [[ -e "$BASE" ]]; then
      echo "ERROR: Baseline exists at $BASE. Refusing to overwrite it." >&2
      exit 2
    fi
    mkdir -p "$BASE"
    chmod 0700 "$BASE"
    capture "$BASE"
    make_restorable_snapshot "$BASE"
    echo "BASELINE CREATED: $BASE"
    echo 'Only do this after a trusted build and manual verification.'
    ;;
  --restore)
    [[ -d "$BASE" ]] || { echo "ERROR: No baseline at $BASE." >&2; exit 2; }
    restore_baseline "$@"
    ;;
  --check)
    [[ -d "$BASE" ]] || { echo "ERROR: No baseline at $BASE. Create one first." >&2; exit 2; }
    mkdir -p "$REPORT_ROOT"
    chmod 0700 "$REPORT_ROOT"
    REPORT="$(mktemp -d "$REPORT_ROOT/scan-XXXXXXXX")"
    capture "$REPORT"
    echo "Current-state audit: $REPORT"
    echo '==== BASELINE DIFFERENCES ===='
    changed=0
    for name in file-hashes.txt file-permissions.txt symlink-targets.txt enabled-services.txt \
                timer-units.txt user-crontabs.txt at-jobs.txt splunk-systemd-units.txt \
                splunk-inputs.txt splunk-savedsearches.txt splunk-commands.txt \
                splunk-alert_actions.txt sudo-group.txt ufw-status.txt; do
      if diff -u "$BASE/$name" "$REPORT/$name" > "$REPORT/diff-${name}"; then
        printf 'UNCHANGED | %s\n' "$name"
      else
        printf 'REVIEW    | %s (see diff-%s)\n' "$name" "$name"
        changed=$((changed + 1))
      fi
    done
    echo "Total categories needing review: $changed"
    echo 'A changed file is NOT automatically malicious; review each difference.'
    echo 'Live listening sockets and timer schedule are saved but not compared (transient).'
    ;;
  *) usage; exit 2 ;;
esac
