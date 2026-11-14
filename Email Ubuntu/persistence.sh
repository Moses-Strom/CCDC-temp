#!/usr/bin/env bash
# =============================================================================
# hunt.sh - read-only threat hunt for a CCDC Ubuntu 22.04 mail server
#
# Looks for what red team (or anyone) planted before you logged in:
#   1. Accounts      extra UID 0, service shells, empty passwords, sudo, SSH keys,
#                    account changes in the journal
#   2. Persistence   cron, at, systemd units/timers, rc.local, shell startup
#                    files, motd, apt hooks, ld.so.preload, PAM, kernel modules, sshd
#   3. Tampering     dpkg --verify, SUID/SGID, capabilities, fake commands in
#                    /usr/local/bin, programs in /tmp /var/tmp /dev/shm
#   4. Packages      .debs installed by hand, recent installs
#   5. Processes     running from temp or deleted files, reverse shells, odd
#                    children of www-data/postfix/dovecot, fake kernel threads
#   6. Network       unexpected listeners, outbound connections, sniffers, /etc/hosts
#   7. Web           webshell code, PHP in writable folders or images, recent PHP,
#                    .htaccess/.user.ini tricks, PHP-FPM pools, Apache modules
#   8. Mail          Postfix copies/filters/redirects, aliases, .forward, Dovecot
#                    master users, sieve redirects, Roundcube installer/version
#   9. Logs          journal persistence, log wiping, sudo commands, SSH logins,
#                    shell histories
#
# It NEVER changes the system. Every finding gets a severity and a fix command:
#   HIGH    almost certainly malicious: act now
#   MEDIUM  needs a look
#   INFO    context
# Suspicious files and running malware are copied (with SHA-256) to evidence/.
#
# Usage:
#   sudo ./hunt.sh           full hunt (1-3 minutes)
#   sudo ./hunt.sh --quick   skips full dpkg --verify and the web content scan
#
# Output: /root/ccdc/hunt-<time>/  report.txt (findings), full.log, evidence/
# Exit code: 2 = HIGH found, 1 = MEDIUM found, 0 = nothing above INFO
# Order at drop flag: change your password -> hunt.sh -> dropflag.sh -> hunt.sh -> baseline.sh save
# =============================================================================

set -o pipefail

QUICK=0
case ${1:-} in
  --quick) QUICK=1 ;;
  -h|--help) sed -n '3,/^# ====/p' "$0"; exit 0 ;;
  "") ;;
  *) echo "Usage: sudo $0 [--quick]"; exit 1 ;;
esac
[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo $0 $*" >&2; exit 1; }

# ---- what "normal" looks like on this box -----------------------------------
EXPECTED_TCP=(22 25 80 110 143 443 587 993 995)
WEBROOTS=(/opt/roundcube /var/www /usr/share/roundcube /srv/www)
RECENT_DAYS=2
# Attacker command patterns (cron lines, startup files, histories, unit files)
BAD='(curl|wget)[^|;]*\|[[:space:]]*(ba|da|z)?sh|/dev/(tcp|udp)/|(^|[^[:alnum:]_])nc(at)?[[:space:]].*-[[:alnum:]]*[ec]([[:space:]]|$)|(^|[^[:alnum:]_])socat[[:space:]]|bash -i|sh -i|python[0-9.]* -c|perl -e|ruby -e|php -r|base64 (-d|--decode)|mkfifo|/tmp/|/var/tmp/|/dev/shm/|chmod [ugoa]*\+s|chmod [0-7]?[4-7][0-7]{3}|LD_PRELOAD|alias (sudo|su|ps|ss|netstat|who|w|last|lsof|top|kill|crontab|passwd|ssh)='
# History and startup tricks that hide activity
HIDE='HISTFILE=/dev/null|unset HISTFILE|HISTSIZE=0|HISTFILESIZE=0|set \+o history|PROMPT_COMMAND=|trap .* DEBUG'
SHELLS='^(sh|bash|dash|zsh|ksh|python[0-9.]*|perl|ruby|php[0-9.]*|nc|ncat|netcat|socat|curl|wget|busybox|telnet)$'

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="/root/ccdc/hunt-$STAMP"
REPORT="$OUT/report.txt"
EVID="$OUT/evidence"
# Colors only on a terminal (decided before output is copied into full.log)
if [[ -t 1 ]]; then RED=$'\e[1;31m'; YEL=$'\e[33m'; CYN=$'\e[36m'; GRN=$'\e[32m'; BLU=$'\e[1;34m'; RST=$'\e[0m'
else RED=""; YEL=""; CYN=""; GRN=""; BLU=""; RST=""; fi
mkdir -p "$OUT" && chmod 700 /root/ccdc "$OUT"
: > "$REPORT"
exec > >(tee -a "$OUT/full.log") 2>&1

NH=0; NM=0; NI=0; HIGHS=()
section() { printf '\n%s==== %s ====%s\n' "$BLU" "$1" "$RST"; }
ok()      { printf '  %s[OK]%s %s\n' "$GRN" "$RST" "$1"; }
show()    { sed 's/^/           /' | head -n "${1:-5}"; }
hit() {
  # hit SEVERITY "what was found" ["how to fix it"]
  local sev=$1 msg=$2 fix=${3:-} c
  case $sev in
    HIGH)   NH=$((NH + 1)); HIGHS+=("$msg"); c=$RED ;;
    MEDIUM) NM=$((NM + 1)); c=$YEL ;;
    *)      NI=$((NI + 1)); c=$CYN ;;
  esac
  printf '  %s[%s]%s %s\n' "$c" "$sev" "$RST" "$msg"
  [[ -n $fix ]] && printf '           fix: %s\n' "$fix"
  printf '%s %-6s %s%s\n' "$(date +%T)" "$sev" "$msg" "${fix:+   | fix: $fix}" >> "$REPORT"
}
have() { command -v "$1" >/dev/null 2>&1; }

evidence() {
  # Copy a suspicious file (up to 10 MB) and record its hash. Never moves it.
  local f=$1 dst
  [[ -f $f ]] || return 0
  (( $(stat -c %s "$f" 2>/dev/null || echo 0) <= 10485760 )) || return 0
  mkdir -p "$EVID"
  dst="$EVID/$(tr '/' '_' <<< "${f#/}")"
  [[ -e $dst ]] && return 0
  cp -p -- "$f" "$dst" 2>/dev/null && sha256sum -- "$f" >> "$EVID/sha256.txt"
}

# ---- which files came from a package ------------------------------------------
declare -A PKG=()
build_pkg_index() {
  local f
  while IFS= read -r f; do PKG[$f]=1; done < <(cat /var/lib/dpkg/info/*.list 2>/dev/null)
}
owned() {
  # True if a package installed this path. /bin, /sbin and /lib are links to
  # /usr/... on 22.04, so either spelling counts.
  local f=$1 alt=""
  [[ -n ${PKG[$f]:-} ]] && return 0
  case $f in
    /usr/lib/*|/usr/lib64/*|/usr/bin/*|/usr/sbin/*) alt=${f#/usr} ;;
    /lib/*|/lib64/*|/bin/*|/sbin/*) alt=/usr$f ;;
  esac
  [[ -n $alt && -n ${PKG[$alt]:-} ]]
}

homes() {
  # Every home folder: local accounts, AD accounts (/home/user or /home/user@domain), root.
  { getent passwd | cut -d: -f6; printf '%s\n' /root /home/*/ /home/*/*/; } \
    | sed 's#/$##' | sort -u | while read -r h; do [[ -d $h && $h != / ]] && echo "$h"; done
}

lan_prefix() {
  # First three octets of this box's address, e.g. 172.20.240.
  local ip
  ip="$(ip -o -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[0-9.]+')"
  [[ -z $ip ]] && ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "${ip%.*}."
}

# =============================================================================
sec_accounts() {
  section "1. Accounts"
  local u uid shell f line n h hits

  while read -r u; do
    hit HIGH "Account '$u' has UID 0 (a second root account)" "sudo usermod -L -e 1 -s /usr/sbin/nologin $u"
  done < <(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd)
  while read -r uid; do
    hit HIGH "UID $uid is shared by: $(awk -F: -v i="$uid" '$3==i {printf "%s ", $1}' /etc/passwd)"
  done < <(cut -d: -f3 /etc/passwd | sort | uniq -d)
  while IFS=: read -r u uid shell; do
    hit HIGH "Service account '$u' (UID $uid) can log in: shell $shell" "sudo usermod -s /usr/sbin/nologin $u"
  done < <(awk -F: '$3>0 && $3<1000 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1":"$3":"$7}' /etc/passwd)
  while read -r u; do
    hit HIGH "Account '$u' has an empty password (logs in with no password)" "sudo passwd -l $u"
  done < <(awk -F: '$2=="" {print $1}' /etc/shadow)

  line=""
  while IFS=: read -r u uid h; do
    line+="$u(home made $(date -d @"$(stat -c %Z "$h" 2>/dev/null || echo 0)" +%F 2>/dev/null)) "
  done < <(awk -F: '$3>=1000 && $3<65534 && $7 !~ /(nologin|false)$/ {print $1":"$3":"$6}' /etc/passwd)
  [[ -n $line ]] && hit INFO "Local accounts that can log in: $line"

  hit INFO "Full sudo through groups: $(getent group sudo admin wheel 2>/dev/null | cut -d: -f4 | tr ',' ' ' | xargs)"
  while IFS= read -r line; do
    hit MEDIUM "sudo without a password: $line" "sudo visudo  (or edit the file in /etc/sudoers.d)"
  done < <(grep -rnsE '^[^#]*(NOPASSWD|!authenticate)' /etc/sudoers /etc/sudoers.d/)
  while IFS= read -r line; do
    hit MEDIUM "Account given sudo directly in /etc/sudoers: $line" "sudo visudo"
  done < <(awk '$1 !~ /^(#|%|@|Defaults|root|Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias)/ && NF && /=/' /etc/sudoers 2>/dev/null)
  for f in /etc/sudoers.d/*; do
    [[ -f $f && $(basename "$f") != README ]] || continue
    hit INFO "sudoers.d file: $f -> $(grep -vE '^[[:space:]]*(#|$)' "$f" | head -n1)"
  done
  grep -qE '^sudoers:.*sss' /etc/nsswitch.conf 2>/dev/null && hit INFO "sudo rules can also come from AD (sudoers: sss). Check one user: sudo -l -U <user>"

  n=0
  while read -r h; do
    for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
      [[ -f $f ]] || continue
      while IFS= read -r line; do
        [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
        n=1
        hit MEDIUM "SSH key in $f: $(awk '{print $1, "..."substr($2,length($2)-11), ($3==""?"(no label)":$3)}' <<< "$line")" "remove that line from $f"
        [[ $line == *command=* ]] && hit HIGH "That key forces a command when used: $(grep -oE 'command="[^"]*"' <<< "$line")"
        evidence "$f"
      done < "$f"
    done
  done < <(homes)
  ((n)) || ok "No SSH keys in any home folder"
  line="$(sshd -T 2>/dev/null | awk '$1=="authorizedkeysfile" {$1=""; print substr($0,2)}')"
  [[ -n $line && $line != ".ssh/authorized_keys .ssh/authorized_keys2" ]] && hit HIGH "sshd reads keys from a non-default place: $line" "check /etc/ssh/sshd_config and sshd_config.d/"
  line="$(sshd -T 2>/dev/null | awk '$1=="authorizedkeyscommand" {$1=""; print substr($0,2)}')"
  [[ -n $line && $line != none ]] && hit HIGH "sshd runs a program to fetch keys (AuthorizedKeysCommand $line)" "remove it from /etc/ssh/sshd_config*"

  if have journalctl; then
    hits="$(journalctl -q --no-pager -o short-iso --since -30d _COMM=useradd _COMM=usermod _COMM=userdel _COMM=groupadd _COMM=gpasswd _COMM=chpasswd _COMM=passwd 2>/dev/null)"
    if [[ -n $hits ]]; then
      hit MEDIUM "$(wc -l <<< "$hits") account changes in the journal (last 30 days). Were they all you?" "sudo journalctl _COMM=useradd _COMM=usermod _COMM=passwd"
      tail -n 8 <<< "$hits" | show 8
    fi
  fi
}

# =============================================================================
check_file_bad() {
  # check_file_bad FILE LABEL: HIGH for each line with an attacker pattern
  local f=$1 label=$2 line
  while IFS= read -r line; do
    hit HIGH "$label with attacker pattern: $f:${line%%:*}: $(cut -c1-160 <<< "${line#*:}")" "read it, then remove the line or the file"
    evidence "$f"
  done < <(grep -nE "$BAD" "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#')
}

sec_persistence() {
  section "2. Persistence"
  local f line u d m p dirs real n
  declare -A seen=() pamseen=()

  # cron
  for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* \
           /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/crontabs/*; do
    [[ -f $f && $(basename "$f") != .placeholder ]] || continue
    if [[ $f == /var/spool/cron/crontabs/* ]]; then
      u="$(basename "$f")"
      hit MEDIUM "User crontab for '$u':" "sudo crontab -l -u $u   remove all: sudo crontab -r -u $u"
      grep -vE '^[[:space:]]*(#|$)' "$f" | show 6
      evidence "$f"
    elif ! owned "$f"; then
      hit MEDIUM "Cron file not installed by any package: $f" "read it, then: sudo mv $f $OUT/"
      grep -vE '^[[:space:]]*(#|$)' "$f" | show 6
      evidence "$f"
    fi
    check_file_bad "$f" "Cron job"
    while IFS= read -r line; do
      hit MEDIUM "Cron job runs at every boot: $f: $line"
    done < <(grep -E '^[[:space:]]*@reboot' "$f" 2>/dev/null)
  done
  for f in /var/spool/cron/atjobs/*; do
    [[ -f $f ]] || continue
    hit MEDIUM "Scheduled 'at' job: $f" "atq   remove: sudo atrm <job number>"
    tail -n 5 "$f" | show 5; evidence "$f"
  done

  # systemd units, timers, sockets, paths and drop-ins not from a package
  dirs=(/etc/systemd/system /lib/systemd/system /usr/lib/systemd/system /run/systemd/system
        /etc/systemd/user /usr/lib/systemd/user /usr/local/lib/systemd/system)
  n=0
  while IFS= read -r f; do
    real="$(readlink -f "$f")"
    [[ -n ${seen[$real]:-} ]] && continue
    seen[$real]=1
    [[ $(basename "$f") == snap[.-]* ]] && continue
    owned "$f" || owned "$real" && continue
    n=1
    line="$(grep -hE '^[[:space:]]*Exec(Start|StartPre|StartPost|Stop)=' "$f" | head -n1 | cut -c1-150)"
    if [[ $f == *.d/*.conf ]]; then
      hit MEDIUM "systemd drop-in not from any package: $f ${line:+($line)}" "if you didn't create it: sudo mv $f $OUT/ && sudo systemctl daemon-reload"
    else
      hit MEDIUM "systemd unit not from any package: $f ${line:+($line)}" "systemctl status $(basename "$f")   then: sudo systemctl disable --now $(basename "$f")"
    fi
    check_file_bad "$f" "systemd unit"
    evidence "$f"
  done < <(find "${dirs[@]}" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.conf' \) 2>/dev/null | sort)
  while read -r d; do
    for f in "$d"/.config/systemd/user/*; do
      [[ -f $f ]] || continue
      n=1
      hit MEDIUM "Per-user systemd unit: $f" "read it, then remove it"
      check_file_bad "$f" "user systemd unit"; evidence "$f"
    done
  done < <(homes)
  ((n)) || ok "All systemd units and drop-ins come from packages"
  have systemctl && hit INFO "Timers: $(systemctl list-timers --all --no-legend 2>/dev/null | grep -oE '[^ ]+\.timer' | sort -u | tr '\n' ' ')"

  # rc.local
  if [[ -f /etc/rc.local ]]; then
    hit MEDIUM "/etc/rc.local exists (runs at boot):" "read it; empty it with: sudo truncate -s0 /etc/rc.local"
    grep -vE '^[[:space:]]*(#|$)' /etc/rc.local | show 6
    check_file_bad /etc/rc.local "rc.local"; evidence /etc/rc.local
  fi

  # shell startup files, system and per user
  for f in /etc/profile /etc/bash.bashrc /etc/environment /etc/profile.d/* /etc/zsh/zshrc /etc/zsh/zprofile; do
    [[ -f $f ]] || continue
    [[ $f == /etc/profile.d/* ]] && ! owned "$f" && { hit MEDIUM "Login script not from any package: $f" "read it, then: sudo mv $f $OUT/"; evidence "$f"; }
    check_file_bad "$f" "Login script"
    while IFS= read -r line; do hit MEDIUM "Login script hides or hooks shell activity: $f:$line"; done < <(grep -nE "$HIDE" "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#')
  done
  while read -r d; do
    for f in "$d"/.bashrc "$d"/.profile "$d"/.bash_profile "$d"/.bash_login "$d"/.bash_logout "$d"/.zshrc; do
      [[ -f $f ]] || continue
      check_file_bad "$f" "Shell startup file"
      while IFS= read -r line; do hit MEDIUM "Shell startup file hides or hooks activity: $f:$line"; done < <(grep -nE "$HIDE" "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#')
    done
  done < <(homes)

  # message of the day scripts (run as root at every SSH login)
  for f in /etc/update-motd.d/*; do
    [[ -e $f ]] || continue
    owned "$f" || owned "$(readlink -f "$f")" || { hit MEDIUM "Login message script not from any package (runs as root at every login): $f" "sudo mv $f $OUT/"; evidence "$f"; }
    check_file_bad "$f" "motd script"
  done

  # apt hooks (run as root on every apt command)
  for f in /etc/apt/apt.conf.d/*; do
    [[ -f $f ]] || continue
    if grep -qE 'Invoke' "$f" && ! owned "$f"; then
      hit HIGH "apt hook not from any package (runs as root on every apt command): $f" "sudo mv $f $OUT/"
      grep -E 'Invoke' "$f" | show 4; evidence "$f"
    fi
    check_file_bad "$f" "apt config"
  done

  # library preloading
  if [[ -s /etc/ld.so.preload ]]; then
    hit HIGH "/etc/ld.so.preload loads a library into EVERY program (classic rootkit): $(tr '\n' ' ' < /etc/ld.so.preload)" "sudo mv /etc/ld.so.preload $OUT/  (then re-run this hunt)"
    evidence /etc/ld.so.preload
  fi
  for f in /etc/ld.so.conf.d/*; do
    [[ -f $f ]] && ! owned "$f" && hit MEDIUM "Library search path not from any package: $f -> $(tr '\n' ' ' < "$f")"
  done

  # PAM: config files and modules not from a package
  for f in /etc/pam.d/*; do
    [[ -f $f ]] || continue
    [[ $(basename "$f") == common-* ]] && continue   # written by pam-auth-update, not a package
    owned "$f" || hit MEDIUM "PAM file not from any package: $f"
  done
  while read -r m; do
    if [[ $m == /* ]]; then p=$m; else
      p=""
      for d in /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security /lib/security /usr/lib/security; do
        [[ -f $d/$m ]] && { p=$d/$m; break; }
      done
    fi
    [[ -n $p ]] || continue
    pamseen[$(readlink -f "$p")]=1
    owned "$p" || owned "$(readlink -f "$p")" || { hit HIGH "PAM module not from any package, used in /etc/pam.d (can steal passwords or let anyone in): $p" "find it: grep -rn $(basename "$p") /etc/pam.d/"; evidence "$p"; }
  done < <(grep -hvE '^[[:space:]]*#' /etc/pam.d/* 2>/dev/null | grep -oE '[^[:space:]]+\.so' | sort -u)
  for p in /usr/lib/x86_64-linux-gnu/security/*.so; do
    [[ -f $p && -z ${pamseen[$(readlink -f "$p")]:-} ]] || continue
    owned "$p" || { hit HIGH "Unknown file in the PAM module folder: $p"; evidence "$p"; }
  done
  while IFS= read -r line; do hit MEDIUM "PAM runs a program at login: $line"; done < <(grep -rnE '^[^#]*pam_exec\.so' /etc/pam.d/ 2>/dev/null)

  # kernel modules
  if have lsmod && have modinfo; then
    while read -r m; do
      p="$(modinfo -n "$m" 2>/dev/null)"
      [[ $p == /* ]] || continue
      owned "$p" || hit HIGH "Loaded kernel module not from any package: $m ($p). Unless 'dkms status' lists it, treat it as a rootkit." "tell your captain; don't rmmod blindly"
    done < <(lsmod 2>/dev/null | awk 'NR>1 {print $1}')
  fi

  # sshd settings
  if have sshd; then
    line="$(sshd -T 2>/dev/null)"
    grep -q '^permitemptypasswords yes' <<< "$line" && hit HIGH "sshd allows empty passwords" "dropflag.sh step 5"
    grep -q '^permitrootlogin yes' <<< "$line" && hit MEDIUM "sshd allows root login" "dropflag.sh step 5"
    while IFS= read -r line; do hit MEDIUM "sshd Match block (can change rules for one user or IP): $line"; done \
      < <(grep -rnisE '^[[:space:]]*match[[:space:]]' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null)
  fi
}

# =============================================================================
sec_tamper() {
  section "3. Tampered files"
  local line f p pkg n cmd
  if ((QUICK)); then
    pkg="openssh-server openssh-client sudo login passwd coreutils procps iproute2 util-linux bash findutils grep libpam-modules libpam-runtime postfix dovecot-core apache2 apache2-bin cron"
    # shellcheck disable=SC2086
    line="$(dpkg -V $pkg 2>/dev/null)"
    hit INFO "Quick mode: checked only key packages with dpkg --verify"
  else
    echo "  Checking every installed file against its package (dpkg --verify, ~1 minute)..."
    line="$(dpkg -V 2>/dev/null)"
  fi
  n=0
  while read -r f; do
    n=$((n + 1))
    ((n <= 25)) || continue
    pkg="$(dpkg -S "$f" 2>/dev/null | head -n1 | cut -d: -f1)"
    hit HIGH "Changed since its package installed it: $f (package ${pkg:-?})" "sudo apt-get install --reinstall ${pkg:-<package>}"
    evidence "$f"
  done < <(awk '$1 ~ /^..5/ && $2 != "c" {print $NF}' <<< "$line")
  ((n > 25)) && hit HIGH "...and $((n - 25)) more changed files (see: sudo dpkg -V)"
  ((n)) || ok "No program differs from its package"

  n=0
  while read -r f; do
    n=1
    if [[ $(basename "$f") =~ $SHELLS || $(basename "$f") =~ ^(find|vim?|nano|cp|mv|less|more|awk|gawk|mawk|env|tar|nmap|bash.*)$ ]]; then
      hit HIGH "SUID/SGID on a program that gives a root shell: $f ($(stat -c %A "$f"))" "sudo chmod ug-s $f"
    elif ! owned "$f"; then
      hit HIGH "SUID/SGID program not from any package: $f ($(stat -c '%A %U' "$f"))" "sudo chmod ug-s $f"
    else
      continue
    fi
    evidence "$f"
  done < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
  ((n)) || ok "Every SUID/SGID program comes from a package"

  if have getcap; then
    while IFS= read -r line; do
      hit HIGH "File capability that grants root powers: $line" "sudo setcap -r ${line%% *}"
    done < <(getcap -r /usr /bin /sbin /opt /home /root /tmp /var /srv /etc 2>/dev/null | grep -E 'cap_(setuid|setgid|sys_admin|dac_override|dac_read_search|sys_ptrace|sys_module|chown|fowner)')
  fi

  line=""
  for f in /usr/local/bin/* /usr/local/sbin/*; do
    [[ -f $f ]] || continue
    cmd="$(basename "$f")"
    if [[ -e /usr/bin/$cmd || -e /usr/sbin/$cmd || -e /bin/$cmd || -e /sbin/$cmd ]]; then
      hit HIGH "$f has the same name as a system command and runs INSTEAD of it (comes first in PATH)" "read it: cat $f   then: sudo mv $f $OUT/"
      evidence "$f"
    else
      line+="$cmd "
    fi
  done
  [[ -n $line ]] && hit INFO "Programs in /usr/local/bin and sbin (not from packages; check any you don't recognize): $line"

  n=0
  declare -A flagged=()
  while read -r f; do
    n=1; flagged[$f]=1
    [[ $(head -c4 "$f" 2>/dev/null | od -An -c | tr -d ' ') == 177ELF ]] && p="compiled program" || p="script"
    hit HIGH "Executable $p in a temp folder: $f (owner $(stat -c %U "$f"), changed $(stat -c %y "$f" | cut -d. -f1))" "sudo mv $f $OUT/"
    evidence "$f"
  done < <(find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 ! -path '*/systemd-private-*' 2>/dev/null)
  while read -r f; do
    [[ -n ${flagged[$f]:-} ]] && continue
    n=1
    hit MEDIUM "Hidden file or folder in a temp folder: $f" "ls -la $f"
  done < <(find /tmp /var/tmp /dev/shm -xdev -mindepth 1 -maxdepth 2 -name '.*' ! -name '.X11-unix' ! -name '.ICE-unix' ! -name '.font-unix' ! -name '.XIM-unix' ! -name '.Test-unix' ! -path '*/systemd-private-*' 2>/dev/null)
  ((n)) || ok "Nothing executable or hidden in /tmp, /var/tmp, /dev/shm"
}

# =============================================================================
sec_packages() {
  section "4. Packages"
  local line pkg hist f n=0
  hist="$( { cat /var/log/apt/history.log 2>/dev/null; zcat /var/log/apt/history.log.*.gz 2>/dev/null; } | grep -E '^(Install|Upgrade|Reinstall):')"
  while read -r pkg; do
    [[ -n $pkg ]] || continue
    n=1
    if grep -q "[[:space:]]$pkg:" <<< " $hist"; then
      hit INFO "Package not in any repository (installed from a .deb, or an old version): $pkg"
    else
      hit HIGH "Package installed by hand from a .deb (not through apt): $pkg" "dpkg -L $pkg; read /var/lib/dpkg/info/$pkg.postinst; remove: sudo dpkg -r $pkg"
    fi
    for f in /var/lib/dpkg/info/"$pkg".postinst /var/lib/dpkg/info/"$pkg":*.postinst; do
      [[ -f $f ]] && check_file_bad "$f" "Install script"
    done
  done < <(apt list --installed 2>/dev/null | grep -F '[installed,local]' | cut -d/ -f1)
  ((n)) || ok "Every installed package comes from a repository"
  line="$(grep ' install ' /var/log/dpkg.log 2>/dev/null | tail -n 8)"
  [[ -n $line ]] && { hit INFO "Most recent package installs (/var/log/dpkg.log):"; show 8 <<< "$line"; }
}

# =============================================================================
sec_processes() {
  section "5. Processes"
  local pid ppid user comm exe cmd cg n=0
  while read -r pid ppid user comm; do
    [[ $pid == "$$" || $ppid == "$$" ]] && continue
    [[ -r /proc/$pid/cmdline ]] || continue
    cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-200)"
    [[ -z $cmd || $cmd == *hunt.sh* ]] && continue      # kernel threads, and this script
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"

    if [[ $exe =~ ^/(tmp|var/tmp|dev/shm|run/user|home)/ ]]; then
      n=1; hit HIGH "Process running from a writable folder: PID $pid ($user) $exe :: $cmd" "save it: sudo cp /proc/$pid/exe $OUT/   then: sudo kill -9 $pid"
      cp "/proc/$pid/exe" "$EVID/pid$pid-$(basename "${exe%% (deleted)}")" 2>/dev/null || { mkdir -p "$EVID" && cp "/proc/$pid/exe" "$EVID/pid$pid-$(basename "${exe%% (deleted)}")" 2>/dev/null; }
    elif [[ $exe == *" (deleted)" ]]; then
      n=1
      if [[ $exe =~ ^/(usr|lib|bin|sbin)/ ]]; then
        hit MEDIUM "PID $pid ($comm) runs a program that was replaced on disk: $exe (normal right after an upgrade: restart that service)"
      else
        hit HIGH "PID $pid runs a program that deleted itself: $exe :: $cmd" "save it: sudo cp /proc/$pid/exe $OUT/   then: sudo kill -9 $pid"
        mkdir -p "$EVID"; cp "/proc/$pid/exe" "$EVID/pid$pid-deleted" 2>/dev/null
      fi
    fi
    if [[ $cmd == \[* && -n $exe ]]; then
      n=1; hit HIGH "Fake kernel thread: PID $pid shows '$cmd' but runs $exe" "sudo kill -9 $pid"
    fi
    if [[ $cmd =~ /dev/(tcp|udp)/|bash\ -i|sh\ -i|(^|[ /])(nc|ncat|netcat)\ .*-[[:alnum:]]*[ec]( |$)|(^|[ /])socat\ |python[0-9.]*\ -c\ .*(socket|pty)|perl\ -e\ .*[Ss]ocket|php\ -r\ .*(fsockopen|exec|system)|mkfifo ]]; then
      n=1; hit HIGH "Reverse-shell command line: PID $pid ($user) :: $cmd" "sudo ss -tnp | grep pid=$pid   then: sudo kill -9 $pid"
    elif [[ $comm =~ ^(nc|ncat|netcat|socat)$ ]]; then
      n=1; hit HIGH "Netcat/socat running: PID $pid ($user) :: $cmd" "sudo kill -9 $pid"
    fi
    if [[ $user == www-data && ! $comm =~ ^(apache2|php-fpm.*|php-cgi.*|fcgid.*|httpd)$ ]]; then
      n=1; hit HIGH "The web server's account is running '$comm' (webshell activity?): PID $pid :: $cmd" "sudo ps -o pid,ppid,cmd --forest -u www-data   then: sudo kill -9 $pid"
    elif [[ $user =~ ^(postfix|dovecot|dovenull|vmail)$ && $comm =~ $SHELLS ]]; then
      n=1; hit HIGH "Mail service account '$user' is running '$comm': PID $pid :: $cmd" "sudo kill -9 $pid"
    fi
    if grep -qa 'LD_PRELOAD=' "/proc/$pid/environ" 2>/dev/null; then
      n=1; hit HIGH "PID $pid ($comm) has LD_PRELOAD set: $(tr '\0' '\n' < "/proc/$pid/environ" | grep LD_PRELOAD)"
    fi
    if [[ $ppid == 1 ]]; then
      cg="$(head -n1 "/proc/$pid/cgroup" 2>/dev/null)"
      if [[ $cg == */user.slice/* && ! $comm =~ ^(systemd|\(sd-pam\)|tmux.*|screen|SCREEN|gpg-agent|dbus-daemon|ssh-agent)$ ]]; then
        n=1; hit MEDIUM "Process detached from its login session (backgrounded with nohup/setsid?): PID $pid ($user) :: $cmd" "ls -l /proc/$pid/exe; sudo kill $pid if it's not yours"
      fi
    fi
  done < <(ps -eo pid=,ppid=,user:32=,comm= 2>/dev/null)
  ((n)) || ok "No suspicious processes"
}

# =============================================================================
sec_network() {
  section "6. Network"
  local netid laddr peer rest port pname pid exe ip lp lan n=0
  declare -A listen=() seen=()
  lan="$(lan_prefix)"

  while read -r netid _ _ _ laddr _ rest; do
    port=${laddr##*:}; ip=${laddr%:*}
    [[ $netid == tcp ]] && listen[$port]=1
    [[ $ip =~ ^(127\.|\[::1\]|\[::ffff:127\.) ]] && continue
    pname="$(grep -oP 'users:\(\("\K[^"]+' <<< "$rest" | head -n1)"
    pid="$(grep -oP 'pid=\K[0-9]+' <<< "$rest" | head -n1)"
    exe="$(readlink "/proc/${pid:-0}/exe" 2>/dev/null)"
    if [[ $netid == tcp ]] && printf '%s\n' "${EXPECTED_TCP[@]}" | grep -qx "$port"; then
      [[ $pname =~ $SHELLS || $exe =~ ^/(tmp|var/tmp|dev/shm|home)/ ]] && { n=1; hit HIGH "Backdoor on a scored port: $netid/$port is held by $pname ($exe)" "sudo kill -9 $pid"; }
      continue
    fi
    if [[ $netid == udp && ( ($port == 68 && $pname =~ ^(dhclient|systemd-network)) || ($port =~ ^(123|323)$ && $pname =~ ^(chronyd|ntpd|systemd-timesyn)) ) ]]; then
      continue
    fi
    n=1
    if [[ $pname =~ $SHELLS || $exe =~ ^/(tmp|var/tmp|dev/shm|home)/ ]]; then
      hit HIGH "Listening backdoor: $netid $laddr held by $pname (PID ${pid:-?}, $exe)" "sudo kill -9 ${pid:-<pid>}"
    elif [[ -z $pname ]]; then
      hit MEDIUM "Listener with no process behind it (kernel service, or hidden by a rootkit): $netid $laddr" "sudo ss -tulpne | grep ':${port} '"
    else
      hit MEDIUM "Unexpected listener: $netid $laddr ($pname, PID $pid, $exe)" "find out what it is: systemctl status $pid"
    fi
  done < <(ss -H -tulpn 2>/dev/null)

  while read -r laddr peer rest; do
    lp=${laddr##*:}
    [[ -n ${listen[$lp]:-} ]] && continue                 # someone connected IN to us
    ip=${peer%:*}; ip=${ip#[}; ip=${ip%]}; ip=${ip#::ffff:}
    [[ $ip =~ ^127\. || $ip == ::1 ]] && continue
    pname="$(grep -oP 'users:\(\("\K[^"]+' <<< "$rest" | head -n1)"
    pid="$(grep -oP 'pid=\K[0-9]+' <<< "$rest" | head -n1)"
    exe="$(readlink "/proc/${pid:-0}/exe" 2>/dev/null)"
    [[ -n ${seen[$pname$peer]:-} ]] && continue
    seen[$pname$peer]=1
    if [[ $pname =~ $SHELLS || $exe =~ ^/(tmp|var/tmp|dev/shm|home)/ ]]; then
      n=1; hit HIGH "Outbound connection from ${pname:-?} (PID ${pid:-?}) to $peer: reverse shell?" "sudo kill -9 ${pid:-<pid>}; block: sudo ufw insert 1 deny out to $ip"
    elif [[ $ip != "$lan"* ]]; then
      n=1; hit MEDIUM "Outbound connection leaving your LAN: ${pname:-?} (PID ${pid:-?}) -> $peer" "is this expected? If not: sudo kill ${pid:-<pid>}"
    else
      hit INFO "Outbound to your LAN: ${pname:-?} -> $peer"
    fi
  done < <(ss -H -tnp state established 2>/dev/null | awk '{print $3, $4, $5}')

  while IFS= read -r rest; do
    pname="$(grep -oP 'users:\(\("\K[^"]+' <<< "$rest" | head -n1)"
    [[ $pname =~ ^(dhclient|systemd-network|NetworkManager|suricata|Suricata-Main|W#.*|tcpdump|ping|wpa_supplicant)$ ]] && continue
    n=1; hit HIGH "Raw/packet socket (sniffer or port-knock backdoor): ${pname:-unknown} :: $(cut -c1-120 <<< "$rest")" "sudo ss -0p; sudo kill <pid>"
  done < <(ss -H -wp 2>/dev/null; ss -H -0p 2>/dev/null)

  while IFS= read -r rest; do
    hit MEDIUM "/etc/hosts entry (can redirect names to an attacker): $rest" "sudo nano /etc/hosts"
  done < <(grep -vE '^[[:space:]]*(#|$)' /etc/hosts | grep -vE 'localhost|ip6-|ff0[0-9]::|fe00::' | grep -vw "$(hostname)")
  ((n)) || ok "Only expected listeners, no outbound connections leaving your LAN"
}

# =============================================================================
sec_web() {
  section "7. Web"
  local roots=() r f line n=0 p
  for r in "${WEBROOTS[@]}"; do [[ -d $r ]] && roots+=("$(readlink -f "$r")"); done
  mapfile -t roots < <(printf '%s\n' "${roots[@]}" | sort -u)
  if ((${#roots[@]} == 0)); then ok "No web folders found"; return; fi
  echo "  Web folders: ${roots[*]}"
  local exts=(--include='*.php' --include='*.php[0-9]' --include='*.phtml' --include='*.pht' --include='*.phar' --include='*.inc')

  if ((QUICK)); then
    hit INFO "Quick mode: skipped the webshell content scan"
  else
    while read -r f; do
      n=1; hit HIGH "Webshell code in $f: $(grep -m1 -noE '(eval|assert|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|hex2bin)|\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\(' "$f" | cut -c1-100)" "sudo mv $f $OUT/   (dropflag.sh quarantines these too)"
      evidence "$f"
    done < <(grep -rlE "${exts[@]}" '(eval|assert|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)|eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|hex2bin)|\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\(' "${roots[@]}" 2>/dev/null)
    while read -r f; do
      n=1; hit HIGH "PHP code hidden in a non-PHP file: $f" "sudo mv $f $OUT/"
      evidence "$f"
    done < <(grep -rlE --include='*.jpg' --include='*.jpeg' --include='*.png' --include='*.gif' --include='*.ico' --include='*.txt' --include='*.svg' --include='*.css' --include='*.js' '<\?php' "${roots[@]}" 2>/dev/null)
  fi

  while read -r f; do
    n=1; hit HIGH "PHP file in a folder the web server writes to: $f (owner $(stat -c %U "$f"), changed $(stat -c %y "$f" | cut -d. -f1))" "sudo mv $f $OUT/"
    evidence "$f"
  done < <(for r in "${roots[@]}"; do
             find "$r" -type f \( -path "$r/temp/*" -o -path "$r/logs/*" -o -path "$r/tmp/*" -o -path "$r/db/*" -o -path '*/upload/*' -o -path '*/uploads/*' \) \
               \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.pht' -o -iname '*.phar' \) 2>/dev/null
           done)

  mapfile -t p < <(find "${roots[@]}" -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '.htaccess' -o -iname '.user.ini' \) -mtime -"$RECENT_DAYS" 2>/dev/null)
  if ((${#p[@]})); then
    hit MEDIUM "${#p[@]} PHP/.htaccess files changed in the last $RECENT_DAYS days (yours, or red team's?):" "diff against a clean copy, or check: ls -la --time-style=full-iso <file>"
    printf '%s\n' "${p[@]}" | show 10
  fi

  while IFS= read -r line; do
    n=1; hit HIGH "Web config runs other files as PHP or adds code to every page: $line" "remove that line"
  done < <(
    grep -rnisE '^[[:space:]]*(AddHandler|SetHandler|AddType|ForceType)\b.*(php|x-httpd)|php_value[[:space:]]+auto_(prepend|append)_file' "${roots[@]}" --include='.htaccess' 2>/dev/null
    grep -rnisE '^[[:space:]]*(AddHandler|AddType|ForceType)\b.*(php|x-httpd)' /etc/apache2/sites-enabled /etc/apache2/conf-enabled 2>/dev/null
  )
  while read -r f; do
    n=1; hit HIGH "PHP per-folder config file: $f -> $(grep -vE '^[[:space:]]*(;|$)' "$f" | head -n2 | tr '\n' ' ')" "sudo mv $f $OUT/"
    evidence "$f"
  done < <(find "${roots[@]}" -name '.user.ini' -type f 2>/dev/null)
  while IFS= read -r line; do
    n=1; hit HIGH "PHP adds a file to EVERY page (auto_prepend/append): $line" "set it back to empty and restart PHP-FPM"
  done < <(grep -rnE '^[[:space:]]*(php_admin_value\[|php_value\[)?auto_(prepend|append)_file\]?[[:space:]]*=[[:space:]]*[^[:space:];]+' /etc/php 2>/dev/null | grep -viE '=[[:space:]]*(none|"")[[:space:]]*$')

  for f in /etc/php/*/fpm/pool.d/*.conf; do
    [[ -f $f ]] || continue
    [[ $(basename "$f") == www.conf ]] || { n=1; hit MEDIUM "Extra PHP-FPM pool: $f (user $(grep -E '^[[:space:]]*user' "$f" | head -n1 | awk -F= '{print $2}' | xargs), listen $(grep -E '^[[:space:]]*listen[[:space:]]*=' "$f" | head -n1 | awk -F= '{print $2}' | xargs))"; evidence "$f"; }
    grep -qE '^[[:space:]]*user[[:space:]]*=[[:space:]]*root' "$f" && { n=1; hit HIGH "PHP-FPM pool runs PHP as ROOT: $f" "set user = www-data, then restart php-fpm"; }
  done

  if [[ -d /etc/apache2/mods-enabled ]]; then
    while read -r f; do
      [[ -f $f ]] || continue
      owned "$f" || { n=1; hit HIGH "Apache module not from any package: $f" "find the LoadModule line in /etc/apache2/mods-enabled/ and disable it"; evidence "$f"; }
    done < <(grep -hoE '^[[:space:]]*LoadModule[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+' /etc/apache2/mods-enabled/*.load 2>/dev/null | awk '{print $3}' | sed 's#^\([^/]\)#/usr/lib/apache2/\1#')
  fi
  ((n)) || ok "No webshell signs found"
}

# =============================================================================
sec_mail() {
  section "8. Mail"
  local v key f line n=0 svc conf
  if have postconf; then
    v="$(postconf -h smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null | tr '\n' ' ')"
    [[ $v =~ (reject|defer)_unauth_destination ]] || { n=1; hit HIGH "Postfix may be an OPEN RELAY (no reject_unauth_destination)" "dropflag.sh step 8"; }
    v="$(postconf -h mynetworks 2>/dev/null)"
    [[ " $v " =~ [[:space:],](0\.0\.0\.0/0|0/0|::/0|\[::\]/0)[[:space:],] ]] && { n=1; hit HIGH "mynetworks trusts every IP: $v" "dropflag.sh step 8"; }
    [[ $(postconf -h disable_vrfy_command 2>/dev/null) == yes ]] || hit INFO "SMTP VRFY is on (username checks). dropflag.sh step 8 turns it off."
    for key in always_bcc sender_bcc_maps recipient_bcc_maps content_filter smtpd_proxy_filter smtpd_milters non_smtpd_milters; do
      v="$(postconf -n 2>/dev/null | awk -F' = ' -v k="$key" '$1==k {print $2}')"
      [[ -n $v ]] && { n=1; hit HIGH "Postfix sends mail somewhere extra: $key = $v" "sudo postconf -X $key && sudo postfix reload"; }
    done
    while IFS= read -r line; do n=1; hit HIGH "master.cf adds a filter or copy for one service: $line" "sudo postconf -P to review; edit /etc/postfix/master.cf"; done \
      < <(postconf -P 2>/dev/null | grep -E 'content_filter|proxy_filter|milters|bcc')
    for key in canonical_maps sender_canonical_maps recipient_canonical_maps virtual_alias_maps transport_maps; do
      v="$(postconf -n 2>/dev/null | awk -F' = ' -v k="$key" '$1==k {print $2}')"
      [[ -n $v ]] || continue
      hit MEDIUM "Postfix rewrites or reroutes addresses: $key = $v" "read the file it points to"
      for f in $(grep -oE '/[^ ,]+' <<< "$v"); do [[ -f $f ]] && grep -vE '^[[:space:]]*(#|$)' "$f" | show 4; done
    done
    for key in header_checks body_checks mime_header_checks nested_header_checks smtp_header_checks; do
      v="$(postconf -n 2>/dev/null | awk -F' = ' -v k="$key" '$1==k {print $2}')"
      for f in $(grep -oE '/[^ ,]+' <<< "$v"); do
        [[ -f $f ]] || continue
        while IFS= read -r line; do n=1; hit HIGH "Postfix $key copies or redirects matching mail: $f: $line" "remove the line, then: sudo postfix reload"; done \
          < <(grep -niE '[[:space:]](REDIRECT|BCC|FILTER|PREPEND)[[:space:]]' "$f")
      done
    done
    while IFS= read -r line; do n=1; hit MEDIUM "Extra network service in master.cf: $line"; done \
      < <(postconf -M 2>/dev/null | awk '$2=="inet" && $1 !~ /^(smtp|submission|submissions|smtps|25|465|587)$/')
    while read -r svc; do n=1; hit HIGH "Postfix service '$svc' pipes mail to a program: $(grep -A2 -E "^${svc}[[:space:]]" /etc/postfix/master.cf | grep -oE 'argv=.*' | head -n1)"; done \
      < <(postconf -M 2>/dev/null | awk '$8=="pipe" && $1 !~ /^(maildrop|uucp|ifmail|bsmtp|scalemail-backend|mailman)$/ {print $1}')
    while IFS= read -r line; do n=1; hit HIGH "/etc/aliases runs a command or writes a file: $line" "remove it, then: sudo newaliases"; done \
      < <(grep -vE '^[[:space:]]*(#|$)' /etc/aliases 2>/dev/null | grep -E '\||:include:|:[[:space:]]*/|,[[:space:]]*/')
    while read -r f; do n=1; hit HIGH "$f forwards this user's mail: $(tr '\n' ' ' < "$f" | cut -c1-100)" "sudo mv $f $OUT/"; evidence "$f"; done \
      < <(find /home /root -maxdepth 3 -name .forward -type f 2>/dev/null)
    hit INFO "Mail queue: $(postqueue -j 2>/dev/null | wc -l) message(s)"
  fi

  if have doveconf; then
    if conf="$(doveconf -n 2>&1)"; then
      { grep -qE '^[[:space:]]+master = yes' <<< "$conf" || grep -qE '^auth_master_user_separator' <<< "$conf"; } && { n=1; hit HIGH "Dovecot master user: one password opens every mailbox" "edit /etc/dovecot/conf.d, then: sudo systemctl reload dovecot"; }
      awk '/^passdb[[:space:]]/ {b=1} b && /driver = static/ {f=1} END {exit !f}' <<< "$conf" && { n=1; hit HIGH "Dovecot 'static' passdb: everyone logs in with one fixed password"; }
      grep -qE 'driver = passwd-file' <<< "$conf" && hit MEDIUM "Dovecot reads passwords from a file: $(grep -oE 'args = [^ ]+' <<< "$conf" | head -n1)"
      grep -qE '^auth_(debug_passwords = yes|verbose_passwords = (plain|sha1|yes))' <<< "$conf" && { n=1; hit HIGH "Dovecot writes users' passwords into the logs" "remove auth_debug_passwords / auth_verbose_passwords"; }
      while IFS= read -r line; do n=1; hit HIGH "Dovecot runs a custom program: $line"; done \
        < <(grep -E '^[[:space:]]+executable = ' <<< "$conf" | grep -vE 'executable = (imap|pop3|lmtp|imap-login|pop3-login|managesieve|managesieve-login|auth|config|anvil|log|dict|stats)$')
      grep -E '^[[:space:]]*sieve_(before|after|global)' <<< "$conf" | while IFS= read -r line; do echo "  global sieve: $line"; done
    else
      hit MEDIUM "Dovecot's config has errors: $(head -n1 <<< "$conf")"
    fi
    while read -r f; do
      if grep -qiE '^[^#]*\b(redirect|vnd\.dovecot\.execute|execute)\b' "$f"; then
        n=1; hit HIGH "Sieve filter forwards or runs something: $f: $(grep -m1 -iE 'redirect|execute' "$f")" "sudo mv $f $OUT/"
      else
        hit INFO "Sieve filter: $f"
      fi
      evidence "$f"
    done < <(find /home /root /var/lib/dovecot /etc/dovecot -maxdepth 4 \( -name '*.sieve' -o -name '.dovecot.sieve' \) -type f 2>/dev/null)
  fi

  for f in /opt/roundcube /var/www/roundcube /var/www/html/roundcube /usr/share/roundcube; do
    [[ -f $f/program/include/iniset.php ]] || continue
    v="$(grep -m1 -oE "RCMAIL_VERSION', '[^']+" "$f/program/include/iniset.php" | cut -d"'" -f3)"
    if [[ $v =~ ^1\.6\. && $(printf '%s\n' "$v" 1.6.11 | sort -V | head -n1) != 1.6.11 ]] || [[ $v =~ ^1\.5\. && $(printf '%s\n' "$v" 1.5.10 | sort -V | head -n1) != 1.5.10 ]] || [[ $v =~ ^1\.[0-4]\. ]]; then
      n=1; hit HIGH "Roundcube $v is vulnerable to CVE-2025-49113 (logged-in user runs code)"
    else
      hit INFO "Roundcube $v in $f"
    fi
    [[ -d $f/installer ]] && hit MEDIUM "Roundcube installer folder present: $f/installer" "dropflag.sh step 8 moves it out"
    line="$(stat -c '%a' "$f/config/config.inc.php" 2>/dev/null)"
    [[ -n $line && ${line: -1} != 0 ]] && hit MEDIUM "Roundcube config (DB password, des_key) is readable by everyone: $f/config/config.inc.php ($line)" "dropflag.sh step 8"
    while read -r line; do hit MEDIUM "Roundcube plugin folder changed in the last $RECENT_DAYS days: $line"; done \
      < <(find "$f/plugins" -mindepth 1 -maxdepth 1 -type d -mtime -"$RECENT_DAYS" 2>/dev/null)
  done
  ((n)) || ok "No mail backdoors found"
}

# =============================================================================
sec_logs() {
  section "9. Logs and history"
  local line d f n=0
  have rsyslogd || hit INFO "No rsyslog: there's no /var/log/auth.log, syslog or mail.log. Everything is in journalctl."
  if [[ -d /var/log/journal ]]; then
    ok "The journal is saved to disk (survives reboots)"
  else
    hit MEDIUM "The journal is in memory only: a reboot wipes the evidence" "sudo mkdir -p /var/log/journal && sudo journalctl --flush"
  fi
  if have journalctl; then
    line="$(journalctl --list-boots --no-pager 2>/dev/null | wc -l)"
    hit INFO "Boots recorded in the journal: $line   oldest entry: $(journalctl -q --no-pager -o short-iso 2>/dev/null | head -n1 | cut -c1-25)"
    line="$(journalctl -q --no-pager -o short-iso --since -3d _COMM=sudo 2>/dev/null | grep 'COMMAND=')"
    if [[ -n $line ]]; then
      while IFS= read -r d; do n=1; hit HIGH "Someone wiped logs or history with sudo: $d"; done \
        < <(grep -E 'journalctl .*--(vacuum|rotate)|rm .*(/var/log|journal|history)|truncate .*(log|history)|shred .*(log|history)|history -c' <<< "$line")
      hit INFO "Last sudo commands:"; tail -n 10 <<< "$line" | sed -E 's/.*sudo\[[0-9]+\]: //' | show 10
    fi
    line="$(journalctl -q --no-pager --since -3d -u ssh -u sshd 2>/dev/null)"
    if [[ -n $line ]]; then
      d="$(grep -oE 'Accepted [a-z-]+ for [^ ]+ from [^ ]+' <<< "$line" | awk '{print $4"@"$6}' | sort | uniq -c | sort -rn | head -n 8)"
      [[ -n $d ]] && { hit INFO "Successful SSH logins (last 3 days), count user@IP:"; show 8 <<< "$d"; }
      d="$(grep -oE 'Failed password for (invalid user )?[^ ]+ from [^ ]+' <<< "$line" | awk '{print $NF}' | sort | uniq -c | sort -rn | head -n 5)"
      [[ -n $d ]] && { hit INFO "Failed SSH logins by IP (last 3 days):"; show 5 <<< "$d"; }
    fi
  fi
  [[ -f /var/log/wtmp && ! -s /var/log/wtmp ]] && hit MEDIUM "/var/log/wtmp (login history) is empty: wiped?"
  have last && { hit INFO "Recent logins (last):"; last -n 8 -i 2>/dev/null | grep -vE '^(wtmp|$)' | show 8; }

  while read -r d; do
    for f in "$d"/.bash_history "$d"/.zsh_history "$d"/.sh_history; do
      [[ -e $f || -L $f ]] || continue
      if [[ -L $f ]]; then
        n=1; hit MEDIUM "$f is a link to $(readlink "$f"): history is being hidden"
        continue
      fi
      while IFS= read -r line; do
        n=1; hit HIGH "Attacker command in $f:${line%%:*}: $(cut -c1-150 <<< "${line#*:}")"
        evidence "$f"
      done < <(grep -nE "$BAD" "$f" 2>/dev/null | head -n 8)
      while IFS= read -r line; do
        n=1; hit MEDIUM "History-hiding command in $f:${line%%:*}: ${line#*:}"
      done < <(grep -nE 'history -c|unset HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|set \+o history' "$f" 2>/dev/null | head -n 3)
    done
  done < <(homes)
  ((n)) || ok "No signs of log wiping or attacker commands in shell histories"
}

# =============================================================================
main() {
  local h
  section "hunt.sh  host=$(hostname)  $(date)$( ((QUICK)) && echo '  QUICK MODE')"
  [[ -r /etc/os-release ]] && { . /etc/os-release; echo "  OS: ${PRETTY_NAME:-unknown}"; }
  echo "  Read-only: nothing on this box is changed. Report: $OUT"
  echo "  Indexing which files came from packages..."
  build_pkg_index
  sec_accounts
  sec_persistence
  sec_tamper
  sec_packages
  sec_processes
  sec_network
  sec_web
  sec_mail
  sec_logs

  section "Summary"
  if ((NH)); then
    printf '  %s%d HIGH%s, %d MEDIUM, %d INFO. Deal with these first:\n' "$RED" "$NH" "$RST" "$NM" "$NI"
    for h in "${HIGHS[@]:0:20}"; do printf '    %s-%s %s\n' "$RED" "$RST" "$h"; done
    ((NH > 20)) && echo "    ... $((NH - 20)) more in the report"
  else
    printf '  %s0 HIGH%s, %d MEDIUM, %d INFO.\n' "$GRN" "$RST" "$NM" "$NI"
  fi
  echo "  Findings:  $REPORT"
  echo "  Full log:  $OUT/full.log"
  [[ -d $EVID ]] && echo "  Evidence:  $EVID  ($(find "$EVID" -type f ! -name sha256.txt | wc -l) files, hashes in sha256.txt)"
  echo "  Next: fix the HIGHs (or run dropflag.sh), write down times for your incident report, then run this again."
  sleep 0.3
  ((NH)) && exit 2
  ((NM)) && exit 1
  exit 0
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main; fi
