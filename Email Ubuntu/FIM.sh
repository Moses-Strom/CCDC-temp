#!/usr/bin/env bash
# =============================================================================
# fim.sh - live file integrity monitor for a CCDC Ubuntu 22.04 mail server
#
#   sudo ./fim.sh install     install inotify-tools + auditd, audit rules, start the service
#   sudo ./fim.sh live        live feed in this terminal (Ctrl+C closes the view only)
#   sudo ./fim.sh live quiet  same, without the beep on HIGH alerts
#   sudo ./fim.sh alerts [N]  the last N HIGH/MEDIUM events (default 40)
#   sudo ./fim.sh status      service, watches, audit rules, last heartbeat
#   sudo ./fim.sh stop        pause monitoring (while YOU make lots of changes)
#   sudo ./fim.sh start       resume
#   sudo ./fim.sh run         run in this terminal without the service (testing)
#   sudo ./fim.sh uninstall   remove the service and audit rules (keeps the logs)
#
# How it works:
#   - inotify (the kernel's file-change notifications) reports every create,
#     write, rename, permission change and delete in the watched folders.
#   - auditd records WHO did it (user, program, PID): shown under HIGH alerts.
#   - New or changed suspicious files are copied with their SHA-256 to
#     /root/ccdc/fim/evidence/, and their first lines are shown.
#   - Every event goes to the journal (journalctl -u ccdc-fim) and to
#     /root/ccdc/fim/events.log for incident reports.
#
# Severity:
#   HIGH    accounts, sudo, cron, systemd, PAM, SSH, shell startup files, mail/web/
#           PHP config, /usr/local/bin, replaced programs, .ssh folders, PHP/.htaccess
#           in web folders, executable or hidden files in temp folders, SUID bits
#   MEDIUM  other web files, deletions in sensitive folders, packages installed
#   Ignored mail landing in Maildir, Roundcube's own temp/log files, editor and
#           sed temp files, ordinary temp files, its own output in /root/ccdc
#
# Start it AFTER dropflag.sh and baseline.sh save, or your own hardening floods it.
# =============================================================================

set -o pipefail
MODE="${1:-}"
DIR=/root/ccdc/fim
EVID=$DIR/evidence
EVENTS=$DIR/events.log
SELF=$DIR/fim.sh
UNIT=/etc/systemd/system/ccdc-fim.service
AUDIT_RULES=/etc/audit/rules.d/ccdc-fim.rules
KEY=ccdc_fim
WEBROOTS=(/opt/roundcube /var/www /usr/share/roundcube /srv/www)
HEARTBEAT=300

# Folders watched with all their subfolders
REC_DIRS=(/etc/sudoers.d /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
  /var/spool/cron /etc/systemd /lib/systemd/system /etc/pam.d /etc/ssh /etc/profile.d /etc/update-motd.d
  /etc/apt/apt.conf.d /etc/ld.so.conf.d /etc/postfix /etc/dovecot /etc/apache2 /etc/php
  /usr/local/bin /usr/local/sbin /root /home /tmp /var/tmp /dev/shm)
# Folders watched without subfolders (big or busy trees)
FLAT_DIRS=(/etc /usr/bin /usr/sbin /usr/lib/x86_64-linux-gnu/security /var/lib/dpkg/info)
# Never watched or reported: mail delivery, caches, our own output, systemd's private temp
EXCLUDE='(/Maildir/|/\.cache/|/\.local/share/|/root/ccdc/|/systemd-private-|/\.bash_history$|/snap/|/\.npm/|/node_modules/|/\.git/objects/)'

if [[ -t 1 ]]; then RED=$'\e[1;31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; DIM=$'\e[2m'; BLU=$'\e[1;34m'; RST=$'\e[0m'
else RED=""; YEL=""; GRN=""; DIM=""; BLU=""; RST=""; fi
ok()   { printf '  %s[OK]%s %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '  %s[WARN]%s %s\n' "$YEL" "$RST" "$1"; }
fail() { printf '  %s[FAIL]%s %s\n' "$RED" "$RST" "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
need_root() { [[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo $0 $MODE" >&2; exit 1; }; }

# =============================================================================
# Classification: what an event means
# =============================================================================
webroot_of() {
  local r
  for r in "${WEBROOTS[@]}"; do [[ $1 == "$r"/* ]] && { echo "$r"; return 0; }; done
  return 1
}

classify() {
  # classify EVENTS PATH -> prints "SEVERITY|why" or nothing (ignore)
  local ev=$1 p=$2 name=${2##*/} r rel isdir=0 del=0
  [[ $ev == *ISDIR* ]] && isdir=1
  [[ $ev == *DELETE* || $ev == *MOVED_FROM* ]] && del=1

  # Editor, sed, dpkg and ucf temp files: the real change shows up as its own event.
  [[ $name =~ ^(sed[[:alnum:]]{6}|\.#.*|.*~|4913|.*\.sw[a-p]|.*\.dpkg-(new|tmp|old|dist|bak)|.*\.ucf-(new|old|dist)|.*\.tmp[[:alnum:]]*|.*\.lock|.*\+|.*-)$ ]] && return
  [[ $p =~ $EXCLUDE ]] && return

  # Permission changes: only interesting if a SUID/SGID bit appeared, or a temp/web file became executable.
  if [[ $ev == *ATTRIB* && $ev != *CREATE* ]]; then
    [[ -f $p && ( -u $p || -g $p ) ]] && { echo "HIGH|SUID/SGID bit set (runs as its owner)"; return; }
    if [[ $p =~ ^/(tmp|var/tmp|dev/shm)/ || -n $(webroot_of "$p") ]] && [[ -f $p && -x $p ]]; then
      echo "HIGH|made executable"; return
    fi
    return
  fi

  # /etc itself is watched without subfolders: only these files matter there.
  if [[ $p =~ ^/etc/[^/]+$ ]]; then
    case $name in
      passwd|shadow|group|gshadow) echo "HIGH|account file changed"; return ;;
      sudoers)                     echo "HIGH|sudo rules changed"; return ;;
      crontab)                     echo "HIGH|system cron table"; return ;;
      ld.so.preload)               echo "HIGH|library forced into every program (rootkit)"; return ;;
      rc.local)                    echo "HIGH|runs at boot"; return ;;
      environment|profile|bash.bashrc) echo "HIGH|runs at every login"; return ;;
      aliases|aliases.db)          echo "HIGH|mail aliases (can pipe mail to a program)"; return ;;
      hosts|resolv.conf|nsswitch.conf) echo "HIGH|name resolution changed"; return ;;
      *) return ;;
    esac
  fi

  case $p in
    /var/lib/dpkg/info/*.list) ((del)) || echo "MEDIUM|package installed: ${name%.list}"; return ;;
    /var/lib/dpkg/info/*) return ;;
    /usr/bin/*|/usr/sbin/*) echo "HIGH|system program added or replaced"; return ;;
    /usr/local/bin/*|/usr/local/sbin/*) echo "HIGH|program in /usr/local (runs before system programs)"; return ;;
    /usr/lib/x86_64-linux-gnu/security/*) echo "HIGH|PAM module (login code)"; return ;;
    /etc/sudoers.d/*) echo "HIGH|sudo rules"; return ;;
    /etc/cron.*|/var/spool/cron/*) echo "HIGH|scheduled job (cron)"; return ;;
    /etc/systemd/*|/lib/systemd/system/*)
      [[ $p == *.wants/* ]] && ! ((del)) && { echo "HIGH|service ENABLED at boot"; return; }
      echo "HIGH|systemd service/timer"; return ;;
    /etc/pam.d/*) echo "HIGH|PAM login config"; return ;;
    /etc/ssh/*) echo "HIGH|SSH server config"; return ;;
    /etc/profile.d/*|/etc/update-motd.d/*) echo "HIGH|runs at every login"; return ;;
    /etc/apt/apt.conf.d/*) echo "HIGH|apt hook (runs as root on apt commands)"; return ;;
    /etc/ld.so.conf.d/*) echo "HIGH|library search path"; return ;;
    /etc/postfix/*) echo "HIGH|Postfix config"; return ;;
    /etc/dovecot/*) echo "HIGH|Dovecot config"; return ;;
    /etc/apache2/*) echo "HIGH|Apache config"; return ;;
    /etc/php/*) echo "HIGH|PHP config"; return ;;
  esac

  # Homes: keys, startup files, mail forwarding, per-user services
  if [[ $p =~ ^/(root|home/[^/]+)/\.ssh(/|$) ]]; then echo "HIGH|SSH keys/config"; return; fi
  if [[ $p =~ ^/(root|home/[^/]+)/\.(bashrc|profile|bash_profile|bash_login|bash_logout|zshrc|zprofile)$ ]]; then echo "HIGH|runs when this user logs in"; return; fi
  if [[ $p =~ ^/(root|home/[^/]+)/\.(forward|dovecot\.sieve)$ || $p =~ ^/(root|home/[^/]+)/sieve/ ]]; then echo "HIGH|forwards this user's mail"; return; fi
  if [[ $p =~ ^/(root|home/[^/]+)/\.config/(systemd|autostart)/ ]]; then echo "HIGH|per-user service"; return; fi
  if [[ $p =~ ^/(root|home)/ ]]; then
    ((isdir)) && [[ $p =~ ^/home/[^/]+$ ]] && ! ((del)) && { echo "MEDIUM|new home folder (new account, or first AD login)"; return; }
    return
  fi

  # Temp folders: only executables, hidden files and scripts
  if [[ $p =~ ^/(tmp|var/tmp|dev/shm)/ ]]; then
    ((del || isdir)) && { [[ $name == .* ]] && ((isdir)) && ! ((del)) && echo "HIGH|hidden folder in a temp folder"; return; }
    [[ -f $p ]] || return
    if [[ -x $p ]]; then echo "HIGH|executable file in a temp folder"; return; fi
    [[ $name == .* ]] && { echo "HIGH|hidden file in a temp folder"; return; }
    [[ $(head -c 4 "$p" 2>/dev/null) == $'\x7fELF' ]] && { echo "HIGH|compiled program in a temp folder"; return; }
    [[ $(head -c 2 "$p" 2>/dev/null) == '#!' ]] && { echo "MEDIUM|script in a temp folder"; return; }
    [[ $name =~ \.(php[0-9]?|phtml|phar|sh|py|pl|elf|so)$ ]] && { echo "HIGH|script or library in a temp folder"; return; }
    return
  fi

  # Web folders
  if r=$(webroot_of "$p"); then
    rel=${p#"$r"/}
    if [[ $name =~ \.(php[0-9]?|phtml|pht|phar|inc)$ || $name == .htaccess || $name == .user.ini ]]; then
      ((del)) && { echo "MEDIUM|web code file deleted"; return; }
      echo "HIGH|web code file (webshell?)"; return
    fi
    # Roundcube writes its own temp, log and SQLite files all the time.
    [[ $rel =~ ^(temp|logs|db)/ ]] && return
    ((isdir)) && ! ((del)) && { echo "MEDIUM|new folder in the web root"; return; }
    [[ $name =~ \.(jpg|jpeg|png|gif|ico|txt|svg|css|js)$ ]] && [[ -f $p ]] && grep -q '<?php' "$p" 2>/dev/null && { echo "HIGH|PHP code hidden in a ${name##*.} file"; return; }
    echo "MEDIUM|web file changed"; return
  fi
}

# =============================================================================
# Daemon: watch, classify, report
# =============================================================================
emit() {
  # emit SEV LINE: journald priority prefix (<3> err, <4> warning, <6> info) + events.log
  local pri=6
  case $1 in HIGH) pri=3 ;; MEDIUM) pri=4 ;; esac
  printf '<%d>%s\n' "$pri" "$2"
  printf '%s\n' "$2" >> "$EVENTS"
}

who_did_it() {
  # Ask auditd who touched this path in the last minute. Runs in the background.
  local p=$1 t line
  have ausearch || return
  sleep 1
  line="$(ausearch --input-logs -k "$KEY" -f "$p" -ts recent --format text 2>/dev/null </dev/null | tail -n 1)"
  [[ -n $line ]] || line="$(ausearch --input-logs -k "$KEY" -f "${p##*/}" -ts recent --format text 2>/dev/null </dev/null | tail -n 1)"
  if [[ -n $line ]]; then
    emit INFO "           who: $line"
  else
    t="$(ausearch --input-logs -k "$KEY" -f "$p" -ts recent -i 2>/dev/null </dev/null | grep -m1 -oE 'type=SYSCALL.*' | grep -oE ' (auid|uid|pid|comm|exe)=[^ ]+' | tr -d '\n')"
    [[ -n $t ]] && emit INFO "           who: $t"
  fi
}

save_evidence() {
  local p=$1 dst
  [[ -f $p ]] || return
  (( $(stat -c %s "$p" 2>/dev/null || echo 0) <= 5242880 )) || return
  dst="$EVID/$(date +%H%M%S)_$(tr '/' '_' <<< "${p#/}")"
  cp -p -- "$p" "$dst" 2>/dev/null || return
  emit INFO "           saved: $dst  sha256 $(sha256sum "$p" | cut -c1-16)..."
  if [[ $p =~ ^/etc/g?shadow$ ]]; then
    return                                  # never print password hashes into the logs
  elif [[ $p =~ ^/etc/(passwd|group)$ ]]; then
    emit INFO "           | last line: $(tail -n 1 "$p" | cut -c1-150)"
  elif grep -Iq . "$p" 2>/dev/null; then
    grep -vE '^[[:space:]]*(#|//|;|$)' "$p" 2>/dev/null | head -n 2 | cut -c1-150 | sed 's/^/           | /' | while IFS= read -r l; do emit INFO "$l"; done
  else
    emit INFO "           (binary file: $(file -b "$p" 2>/dev/null | cut -c1-60))"
  fi
}

do_daemon() {
  local d rec=() flat=() ev p res sev why now burst=0 burst_dir="" last_sec=0 count=0
  declare -A lastseen=()
  mkdir -p "$EVID" && chmod 700 /root/ccdc "$DIR" 2>/dev/null
  for d in "${REC_DIRS[@]}" "${WEBROOTS[@]}"; do [[ -e $d ]] && rec+=("$d"); done
  for d in "${FLAT_DIRS[@]}"; do [[ -d $d ]] && flat+=("$d"); done
  sysctl -qw fs.inotify.max_user_watches=524288 2>/dev/null
  emit INFO "$(date '+%F %T') INFO   FIM started: ${#rec[@]} folder trees + ${#flat[@]} single folders. Who-did-it: $(have ausearch && auditctl -l 2>/dev/null | grep -q "$KEY" && echo on || echo 'off (auditd rules not loaded)')"

  {
    inotifywait -m -q -r --format '%e|%w%f' -e close_write,create,moved_to,attrib,delete,moved_from --exclude "$EXCLUDE" "${rec[@]}" 2>&1 &
    inotifywait -m -q --format '%e|%w%f' -e close_write,create,moved_to,attrib,delete,moved_from "${flat[@]}" 2>&1 &
    while sleep "$HEARTBEAT"; do echo "HEARTBEAT|"; done &
    wait
  } | while IFS='|' read -r ev p; do
    printf -v now '%(%s)T' -1
    if [[ $ev == HEARTBEAT ]]; then
      emit INFO "$(date '+%F %T') INFO   heartbeat: still watching"
      continue
    fi
    [[ -n $p ]] || { emit MEDIUM "$(date '+%F %T') MEDIUM inotify: $ev"; continue; }
    res="$(classify "$ev" "$p")"
    [[ -n $res ]] || continue
    sev=${res%%|*}; why=${res#*|}
    # The same file often fires CREATE + CLOSE_WRITE (+ ATTRIB): report it once per 3 seconds.
    [[ -n ${lastseen[$p|$why]:-} ]] && (( now - ${lastseen[$p|$why]} < 3 )) && continue
    lastseen[$p|$why]=$now
    # Bursts of MEDIUM events (a big copy into the web root): after 15 in one
    # second, summarize the rest. HIGH events are never held back.
    if (( now != last_sec )); then
      ((burst)) && emit MEDIUM "$(date '+%F %T') MEDIUM ...and $burst more MEDIUM changes in that second (last: $burst_dir)"
      burst=0; count=0; last_sec=$now
    fi
    if [[ $sev == MEDIUM ]]; then
      count=$((count + 1))
      if (( count > 15 )); then burst=$((burst + 1)); burst_dir=$p; continue; fi
    fi

    case $ev in
      *DELETE*|*MOVED_FROM*) ev=DELETED ;; *MOVED_TO*) ev=MOVED-IN ;; *CREATE*) ev=CREATED ;;
      *CLOSE_WRITE*) ev=WRITTEN ;; *ATTRIB*) ev=PERMS ;;
    esac
    emit "$sev" "$(date '+%F %T') $(printf '%-6s %-8s' "$sev" "$ev") $p   [$why]"
    if [[ $sev == HIGH && $ev != DELETED ]]; then
      save_evidence "$p"
      who_did_it "$p" </dev/null &
    elif [[ $sev == HIGH ]]; then
      who_did_it "$p" </dev/null &
    fi
  done
}

# =============================================================================
# install / service control
# =============================================================================
write_audit_rules() {
  local d
  {
    echo "# Written by fim.sh: record who changes the folders the FIM watches (key $KEY)."
    echo "# Roundcube's own temp/log folders are skipped (they change on every page load)."
    for d in "${WEBROOTS[@]}"; do
      [[ -d $d/temp ]] && echo "-a never,exit -S all -F dir=$d/temp -k ${KEY}_skip"
      [[ -d $d/logs ]] && echo "-a never,exit -S all -F dir=$d/logs -k ${KEY}_skip"
    done
    for d in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d /etc/crontab /etc/cron.d \
             /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /etc/systemd/system \
             /lib/systemd/system /etc/pam.d /etc/ssh /etc/profile.d /etc/update-motd.d /etc/apt/apt.conf.d \
             /etc/ld.so.preload /etc/ld.so.conf.d /etc/rc.local /etc/environment /etc/profile /etc/bash.bashrc \
             /etc/aliases /etc/hosts /etc/postfix /etc/dovecot /etc/apache2 /etc/php /usr/local/bin /usr/local/sbin \
             /usr/bin /usr/sbin /usr/lib/x86_64-linux-gnu/security /root /home /tmp /var/tmp /dev/shm "${WEBROOTS[@]}"; do
      [[ -e $d ]] && echo "-w $d -p wa -k $KEY"
    done
  } > "$AUDIT_RULES"
}

do_install() {
  need_root
  printf '\n%s== Install ==%s\n' "$BLU" "$RST"
  if ! have inotifywait || ! have auditctl; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o DPkg::Lock::Timeout=120 inotify-tools auditd >/dev/null 2>&1 \
      || warn "apt install failed (no internet, or apt busy)."
  fi
  have inotifywait || { fail "inotifywait is missing: sudo apt install inotify-tools"; exit 1; }
  ok "inotify-tools $(inotifywait --help 2>/dev/null | head -n1 | awk '{print $2}')"

  printf '\n%s== Who-did-it (auditd) ==%s\n' "$BLU" "$RST"
  if have auditctl; then
    systemctl enable --now auditd >/dev/null 2>&1
    write_audit_rules
    if auditctl -s 2>/dev/null | grep -q 'enabled 2'; then
      warn "Audit rules are locked until reboot (enabled 2). Who-did-it lines will be missing."
    elif auditctl -R "$AUDIT_RULES" >/dev/null 2>&1; then
      ok "$(auditctl -l 2>/dev/null | grep -c "$KEY") audit rules loaded (key $KEY), also saved in $AUDIT_RULES"
    else
      warn "Couldn't load the audit rules: who-did-it lines will be missing. Check: sudo auditctl -s"
    fi
  else
    warn "auditd not installed: alerts will work, but without who-did-it."
  fi

  printf '\n%s== Service ==%s\n' "$BLU" "$RST"
  mkdir -p "$EVID" && chmod 700 /root/ccdc "$DIR" 2>/dev/null
  install -m 700 "$0" "$SELF"
  cat > "$UNIT" <<EOF
# Written by fim.sh. Live view: sudo $SELF live
[Unit]
Description=CCDC file integrity monitor (fim.sh)
After=local-fs.target auditd.service

[Service]
ExecStart=/bin/bash $SELF daemon
Restart=always
RestartSec=2
SyslogIdentifier=ccdc-fim
Nice=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now ccdc-fim >/dev/null 2>&1
  sleep 2
  if systemctl is-active --quiet ccdc-fim; then
    ok "ccdc-fim service running (restarts itself if killed)"
  else
    fail "The service didn't start: sudo journalctl -u ccdc-fim -n 20"; exit 1
  fi
  echo
  echo "  Live feed:      sudo $0 live"
  echo "  Missed events:  sudo $0 alerts"
  echo "  Note: hunt.sh and baseline.sh will now list ccdc-fim.service and the audit rules."
  echo "        That's this tool. Run 'sudo ./baseline.sh save' again."
}

do_live() {
  need_root
  local quiet=${1:-} bell=$'\a' wd
  [[ $quiet == quiet ]] && bell=""
  if ! systemctl is-active --quiet ccdc-fim 2>/dev/null; then
    fail "The ccdc-fim service isn't running. Start it: sudo $0 start   (or install it first)"
    exit 1
  fi
  printf '%s== FIM live feed (%s) ==%s\n' "$BLU" "$(hostname)" "$RST"
  echo "  Red = HIGH (beeps), yellow = MEDIUM. Ctrl+C closes this view; monitoring keeps running."
  echo "  Evidence: $EVID   History: sudo $0 alerts"
  echo
  # Warn if the service stops while you're watching.
  ( while sleep 15; do
      systemctl is-active --quiet ccdc-fim || printf '\n%s!!! ccdc-fim STOPPED at %s: changes are NOT being watched. sudo %s start%s\n%s' "$RED" "$(date +%T)" "$0" "$RST" "$bell"
    done ) &
  wd=$!
  trap 'kill $wd 2>/dev/null; echo; exit 0' INT TERM
  journalctl -u ccdc-fim -n 20 -f -o cat 2>/dev/null | while IFS= read -r line; do
    case $line in
      *" HIGH "*)   printf '%s%s%s%s\n' "$RED" "$line" "$RST" "$bell" ;;
      *" MEDIUM "*) printf '%s%s%s\n' "$YEL" "$line" "$RST" ;;
      *"heartbeat"*|*"FIM started"*) printf '%s%s%s\n' "$DIM" "$line" "$RST" ;;
      *)            printf '%s\n' "$line" ;;
    esac
  done
}

do_alerts() {
  need_root
  local n=${1:-40}
  [[ -f $EVENTS ]] || { echo "No events yet ($EVENTS)."; exit 0; }
  # Each HIGH/MEDIUM line plus its indented detail lines (who, saved, preview)
  awk -v n="$n" '
    / (HIGH|MEDIUM) / {blk[++c]=$0; keep=1; next}
    /^           / && keep {blk[c]=blk[c] "\n" $0; next}
    {keep=0}
    END {for (i = (c > n ? c - n + 1 : 1); i <= c; i++) print blk[i]}
  ' "$EVENTS" | while IFS= read -r line; do
        case $line in
          *" HIGH "*)   printf '%s%s%s\n' "$RED" "$line" "$RST" ;;
          *" MEDIUM "*) printf '%s%s%s\n' "$YEL" "$line" "$RST" ;;
          *)            printf '%s\n' "$line" ;;
        esac
      done
  echo
  echo "  Totals in $EVENTS: $(grep -c ' HIGH ' "$EVENTS") HIGH, $(grep -c ' MEDIUM ' "$EVENTS") MEDIUM"
}

do_status() {
  need_root
  echo "Service:    $(systemctl is-active ccdc-fim 2>/dev/null) ($(systemctl is-enabled ccdc-fim 2>/dev/null) at boot)"
  echo "Watchers:   $(pgrep -c -x inotifywait 2>/dev/null) inotifywait processes"
  echo "Audit:      $(auditctl -l 2>/dev/null | grep -c "$KEY") rules with key $KEY   ($(auditctl -s 2>/dev/null | awk '/^enabled/ {print "enabled="$2}'))"
  echo "Heartbeat:  $(grep -E 'heartbeat|FIM started' "$EVENTS" 2>/dev/null | tail -n1 | cut -c1-19)"
  echo "Events:     $(grep -c ' HIGH ' "$EVENTS" 2>/dev/null) HIGH, $(grep -c ' MEDIUM ' "$EVENTS" 2>/dev/null) MEDIUM in $EVENTS"
  echo "Evidence:   $(find "$EVID" -type f 2>/dev/null | wc -l) files in $EVID"
}

do_uninstall() {
  need_root
  systemctl disable --now ccdc-fim >/dev/null 2>&1
  rm -f "$UNIT"; systemctl daemon-reload
  auditctl -D -k "$KEY" >/dev/null 2>&1
  auditctl -D -k "${KEY}_skip" >/dev/null 2>&1
  rm -f "$AUDIT_RULES"
  ok "Service and audit rules removed. Logs and evidence kept in $DIR"
}

case $MODE in
  install)   do_install ;;
  live)      do_live "${2:-}" ;;
  alerts)    do_alerts "${2:-40}" ;;
  status)    do_status ;;
  start)     need_root; systemctl start ccdc-fim && ok "Monitoring resumed. Check what changed while paused: sudo ./baseline.sh check" ;;
  stop)      need_root; systemctl stop ccdc-fim && warn "Monitoring PAUSED. Resume with: sudo $0 start" ;;
  uninstall) do_uninstall ;;
  daemon)    need_root; do_daemon ;;
  run)       need_root; mkdir -p "$EVID"; do_daemon | sed -u -E 's/^<[0-9]>//' | while IFS= read -r line; do
               case $line in *" HIGH "*) printf '%s%s%s\n' "$RED" "$line" "$RST" ;; *" MEDIUM "*) printf '%s%s%s\n' "$YEL" "$line" "$RST" ;; *) printf '%s\n' "$line" ;; esac
             done ;;
  *) sed -n '3,/^# ====/p' "$0"; exit 1 ;;
esac
