#!/usr/bin/env bash
# =============================================================================
# dropflag.sh - first-15-minutes hardening for a CCDC Ubuntu 22.04 server
#
# Steps, in order:
#   0. Baseline + backup   record which scored ports answer, back up /etc, /home, /root
#   1. Sessions            show who is logged in, end sessions you don't recognize
#   2. Passwords           your account, other admins, other local users
#   3. Root                lock root's password (sudo keeps working) or change it
#   4. User security       extra UID 0, empty passwords, service accounts with
#                          shells, sudo members, sudoers rules, SSH keys, file perms
#   5. SSH                 root login off; password logins stay on (scorer logs in)
#   6. Ports               UDP first, then TCP: stop services and kill processes
#                          that listen outside localhost and aren't needed
#   7. Firewall            ufw: deny inbound except scored ports, ping kept,
#                          22, 80 and 443 always open (the packet requires them),
#                          plus 25 587 110 143 993 995 when a mail server is here,
#                          on at boot, hidden iptables/nftables/legacy rules removed
#   8. Mail stack + logs   Postfix (open relay, VRFY, hidden bcc copies, forwards),
#                          Dovecot backdoors (report only), Roundcube (installer,
#                          config perms, code ownership, PHP in writable folders),
#                          unused Apache modules, logs kept across reboots.
#                          Mail parts run only if Postfix/Dovecot/Roundcube is found.
#
# Packet rules it follows: ping stays on, SSH stays up with password logins,
# usernames are never changed or deleted (accounts get locked instead), AD
# passwords change only through Quotient's PCR tab.
# After every risky change it re-checks the scored ports and undoes the change
# if one stopped answering.
#
# Usage:
#   sudo ./dropflag.sh          interactive: asks before every change
#   sudo ./dropflag.sh check    read-only: shows what it would flag, changes nothing
#
# Output: /root/ccdc/dropflag-<time>/  run.log, findings.txt (timestamped, for
# incident reports), backup.tgz, rollback copies of every file it changed.
# =============================================================================

set -o pipefail

MODE="${1:-run}"

# TCP ports that may be scored here. Only the ones actually answering get a
# firewall opening. 21 is included because FTP is scored somewhere in the
# topology: if an FTP server runs on this box, treat it as scored until
# Quotient says otherwise.
SCORED_TCP=(21 22 25 80 110 143 443 465 587 993 995)

# Opened in step 7 even if nothing answers at that moment, so a service that's
# down at drop flag isn't firewalled once you fix it. Mail ports are added only
# when a mail server is installed on this box.
ALWAYS_TCP=(22 80 443)
MAIL_TCP=(25 587 110 143 993 995)

# Services re-checked after every risky change, if they were running at the start.
WATCH_UNITS='^(postfix@-|dovecot|apache2|nginx|php[0-9.]*-fpm|sssd|ssh)\.service$'

# System services the box needs. Reported, never stopped. Whatever holds a
# scored port is also left alone (see review_listener), so application
# software doesn't need to be listed here.
PROTECTED='^(sshd|master|dovecot|apache2|httpd|nginx|php-fpm.*|docker-proxy|dockerd|containerd|vsftpd|proftpd|pure-ftpd.*|systemd|systemd-resolve|systemd-network|systemd-timesyn|chronyd|ntpd|sssd.*|winbindd|rsyslogd|auditd|splunkd|mysqld|mariadbd|postgres|redis-server|dhclient)$'

# Programs that should never hold a listening socket on a server.
SUSPICIOUS='^(nc|ncat|netcat|nc\.openbsd|nc\.traditional|socat|python[0-9.]*|perl|ruby|php|bash|sh|dash|zsh|ksh|busybox|node|telnetd|cryptcat)$'

# Services that are safe to turn off on this server (default answer: yes).
UNNEEDED_UNITS=(avahi-daemon.service cups.service cups-browsed.service snmpd.service
  rpcbind.service nmbd.service smbd.service xinetd.service openbsd-inetd.service
  inetutils-inetd.service tftpd-hpa.service nfs-server.service rsync.service
  minissdpd.service)
# dnsmasq is left out on purpose: on some servers it is the box's own DNS
# forwarder, and stopping it would break name lookups. It is still reported.

STAMP="$(date +%Y%m%d-%H%M%S)"
BASE_DIR="/root/ccdc"
RUN_DIR="$BASE_DIR/dropflag-$STAMP"
LOG="$RUN_DIR/run.log"
FINDINGS="$RUN_DIR/findings.txt"
PCR_FILE="$RUN_DIR/pcr.csv"
ADMIN="${SUDO_USER:-$(logname 2>/dev/null)}"
[[ $ADMIN == root ]] && ADMIN=""
MY_TTY="$(tty 2>/dev/null | sed 's#^/dev/##')"
FINDING_COUNT=0
BASE_PORTS=()
BASE_UNITS=()
WEB_MARKER=""
STEP_DIR="$RUN_DIR"
LAST_PW=""
declare -A SEEN=()

# ---- output ------------------------------------------------------------------
if [[ -t 1 ]]; then
  RED=$'\e[31m'; YEL=$'\e[33m'; GRN=$'\e[32m'; BLU=$'\e[1;34m'; RST=$'\e[0m'
else
  RED=""; YEL=""; GRN=""; BLU=""; RST=""
fi

now()     { date '+%Y-%m-%d %H:%M:%S'; }
section() { printf '\n%s==== %s ====%s\n' "$BLU" "$1" "$RST"; }
sub()     { printf '\n  %s-- %s --%s\n' "$BLU" "$1" "$RST"; }
info()    { printf '  %s\n' "$1"; }
ok()      { printf '  %s[OK]%s %s\n' "$GRN" "$RST" "$1"; }
warn()    { printf '  %s[WARN]%s %s\n' "$YEL" "$RST" "$1"; }
finding() {
  # Something suspicious. Timestamped into findings.txt for the incident report.
  FINDING_COUNT=$((FINDING_COUNT + 1))
  printf '  %s[FINDING]%s %s\n' "$RED" "$RST" "$1"
  printf '%s %s FINDING | %s\n' "$(now)" "$(hostname)" "$1" >> "$FINDINGS"
}
action() {
  # A change this script made. Also timestamped, so the report has a timeline.
  printf '  %s[DONE]%s %s\n' "$GRN" "$RST" "$1"
  printf '%s %s ACTION  | %s\n' "$(now)" "$(hostname)" "$1" >> "$FINDINGS"
}
have()    { command -v "$1" >/dev/null 2>&1; }
in_list() { local x=$1 y; shift; for y in "$@"; do [[ $x == "$y" ]] && return 0; done; return 1; }
is_local() { [[ $1 == 127.* || $1 == "[::1]" || $1 == "::1" || $1 == "[::ffff:127."* ]]; }

ask() {
  # ask "question" [Y|N]. The capital letter is what Enter picks.
  # Answers come from the keyboard (/dev/tty), so loops reading files still work.
  local q=$1 def=${2:-N} ans hint="[y/N]"
  [[ $def == Y ]] && hint="[Y/n]"
  if [[ $MODE == check ]]; then
    info "(check mode, would ask) $q"
    return 1
  fi
  read -r -p "  >> $q $hint " ans < /dev/tty || return 1
  ans=${ans:-$def}
  [[ $ans =~ ^[Yy] ]]
}

begin_step() {
  # Each step gets its own folder for copies of what it changes.
  STEP_DIR="$RUN_DIR/rollback/step$1"
  mkdir -p "$STEP_DIR"
  section "$1. $2"
}

save() {
  # Copy files or folders into the step's rollback folder before changing them.
  local p
  for p in "$@"; do
    [[ -e $p ]] && cp -a --parents "$p" "$STEP_DIR/" 2>/dev/null
  done
}

# ---- scored-service health (the safety net) -----------------------------------
listening_tcp() { ss -Hltn "( sport = :$1 )" 2>/dev/null | grep -q .; }

probe() {
  # Connect to localhost:PORT and check the greeting starts with EXPECT.
  # The braces keep 2>/dev/null temporary; a bare exec would silence stderr for good.
  local port=$1 expect=$2 line=""
  { exec 3<>"/dev/tcp/127.0.0.1/$port"; } 2>/dev/null || return 1
  read -r -t 5 line <&3
  exec 3>&- 3<&-
  [[ $line == "$expect"* ]]
}

tls_probe() {
  # TLS handshake, then check the greeting. The command makes the server hang up
  # right away instead of waiting for a timeout.
  local port=$1 expect=$2 cmd=$3 line
  have openssl || { listening_tcp "$port"; return; }
  line="$(printf '%s\r\n' "$cmd" | timeout 8 openssl s_client -connect "127.0.0.1:$port" -quiet 2>/dev/null | head -n1)"
  [[ $line == "$expect"* ]]
}

web_page() {
  # Body of the page on http or https, following redirects.
  curl -skL -m 10 "$1://127.0.0.1/" 2>/dev/null
}

web_ok() {
  # The page has to load (2xx/3xx). If it showed the Roundcube login form at the
  # start, it still has to: a dead PHP-FPM leaves Apache listening but broken.
  local scheme=$1 port=80 code
  [[ $scheme == https ]] && port=443
  have curl || { listening_tcp "$port"; return; }
  code="$(curl -sk -o /dev/null -m 10 -w '%{http_code}' "$scheme://127.0.0.1/" 2>/dev/null)"
  [[ $code =~ ^[23] ]] || return 1
  [[ -z $WEB_MARKER ]] || [[ $(web_page "$scheme") == *"$WEB_MARKER"* ]]
}

check_port() {
  case $1 in
    22)        probe 22 "SSH-" ;;
    21|25|587) probe "$1" "220" ;;
    110)       probe 110 "+OK" ;;
    143)       probe 143 "* OK" ;;
    993)       tls_probe 993 "* OK" "a1 LOGOUT" ;;
    995)       tls_probe 995 "+OK" "QUIT" ;;
    465)       tls_probe 465 "220" "QUIT" ;;
    80)        web_ok http ;;
    443)       web_ok https ;;
    *)         listening_tcp "$1" ;;
  esac
}

watched_units() {
  have systemctl || return 0
  systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null \
    | awk '{print $1}' | grep -E "$WATCH_UNITS"
}

record_baseline() {
  # Only ports that answer now are re-checked later, so a service bound to the
  # external IP only doesn't cause false rollbacks.
  local p
  BASE_PORTS=()
  WEB_MARKER=""
  # (a variable, not 'curl | grep -q': with pipefail, grep quitting early fails the pipe)
  if have curl && [[ "$(web_page http)$(web_page https)" == *rcmloginuser* ]]; then WEB_MARKER=rcmloginuser; fi
  for p in "${SCORED_TCP[@]}"; do check_port "$p" && BASE_PORTS+=("$p"); done
  mapfile -t BASE_UNITS < <(watched_units)
  if ((${#BASE_PORTS[@]})); then
    ok "Answering now, re-checked after every risky change: ${BASE_PORTS[*]}"
  else
    warn "No scored port answers on localhost. Are the services running?"
  fi
  [[ -n $WEB_MARKER ]] && ok "Webmail login page loads; it must still load after every change"
  ((${#BASE_UNITS[@]})) && ok "Services watched: ${BASE_UNITS[*]}"
}

health_check() {
  local p u bad=0
  for p in "${BASE_PORTS[@]}"; do
    check_port "$p" || { warn "Port $p stopped answering"; bad=1; }
  done
  for u in "${BASE_UNITS[@]}"; do
    systemctl is-active --quiet "$u" || { warn "Service $u stopped"; bad=1; }
  done
  return $bad
}

mail_stack_present() {
  have postconf || have doveconf || [[ -n $(find_roundcube) ]]
}

# ---- helpers -------------------------------------------------------------------
admin_users() {
  # Members of the groups that grant full sudo on Ubuntu.
  getent group sudo admin 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -v '^$' | sort -u
}

is_admin() {
  # Loaded into an array first: 'admin_users | grep -q' fails under pipefail when
  # grep exits early, which made admins look like regular users.
  local -a admins
  mapfile -t admins < <(admin_users)
  in_list "$1" "${admins[@]}"
}

is_local_account() { grep -q "^$1:" /etc/passwd; }

gen_password() {
  local p
  p="$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-14)"
  printf '%s-%s' "${p:0:7}" "${p:7:7}"
}

set_password() {
  # set_password USER. Asks twice; pressing Enter at the first prompt generates one.
  # Typed passwords never reach the log. A generated one is printed straight to the
  # screen (not the log) so you can write it down.
  local u=$1 p1 p2
  while true; do
    read -r -s -p "  New password for $u (Enter = generate one): " p1 < /dev/tty; echo
    if [[ -z $p1 ]]; then
      p1="$(gen_password)"
      sleep 0.2
      printf '  %sGenerated password for %s:  %s   <- write it down now%s\n' \
        "$YEL" "$u" "$p1" "$RST" > /dev/tty
      break
    fi
    read -r -s -p "  Repeat it: " p2 < /dev/tty; echo
    [[ $p1 == "$p2" ]] || { warn "They didn't match. Try again."; continue; }
    [[ $p1 == *:* ]]   && { warn "A ':' breaks chpasswd. Try again."; continue; }
    ((${#p1} >= 12))   || { warn "Use at least 12 characters."; continue; }
    break
  done
  if printf '%s:%s\n' "$u" "$p1" | chpasswd; then
    LAST_PW=$p1
    action "Changed password for $u"
    return 0
  fi
  warn "chpasswd failed for $u"
  return 1
}

lock_account() {
  # Lock instead of delete: rule 11 forbids changing usernames, and the
  # account is evidence. -L locks the password, -e 1 expires the account
  # (this also blocks SSH keys), nologin removes the shell.
  local u=$1 uid line
  uid="$(id -u "$u" 2>/dev/null)"
  usermod -L -e 1 -s /usr/sbin/nologin "$u" || { warn "usermod failed for $u"; return 1; }
  action "Locked account $u (UID $uid)"
  # End their sessions. Never 'pkill -u' when the UID is 0 or shared: pkill
  # matches the number, so it would kill root's (or the other account's)
  # processes too. Use their terminals instead.
  if [[ $uid != 0 ]] && (( $(awk -F: -v id="$uid" '$3==id' /etc/passwd | wc -l) == 1 )); then
    pkill -KILL -u "$uid" 2>/dev/null
  else
    for line in $(who | awk -v n="$u" '$1==n {print $2}'); do
      pkill -KILL -t "$line" 2>/dev/null
    done
  fi
}

key_files() {
  # sshd reads keys from each account's home, so check every account, service
  # accounts included (www-data's home is /var/www). AD users don't show up in
  # 'getent passwd' (SSSD doesn't list the whole domain), so every folder under
  # /home is checked too, including /home/user@domain. A non-default
  # AuthorizedKeysFile setting is flagged separately.
  local home f
  { getent passwd | cut -d: -f6; printf '%s\n' /home/*/ /home/*/*/; } | sed 's#/$##' | sort -u | while read -r home; do
    [[ -n $home && -d $home ]] || continue
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [[ -f $f ]] && echo "$f"
    done
  done
}

fix_perm() {
  local f=$1 mode=$2 own=$3
  [[ -e $f ]] || return 0
  if [[ $(stat -c %a "$f") != "$mode" || $(stat -c %U:%G "$f") != "$own" ]]; then
    finding "$f is $(stat -c '%a %U:%G' "$f"), expected $mode $own"
    if ask "Fix it?" Y; then
      chown "$own" "$f" && chmod "$mode" "$f" && action "Set $f to $mode $own"
    fi
  fi
}

list_listeners() {
  # One line per listening socket: proto|address|port|process|pid
  local netid laddr rest
  ss -H -tulpn 2>/dev/null | while read -r netid _ _ _ laddr _ rest; do
    printf '%s|%s|%s|%s|%s\n' "$netid" "${laddr%:*}" "${laddr##*:}" \
      "$(grep -oP 'users:\(\("\K[^"]+' <<< "$rest" | head -n1)" \
      "$(grep -oP 'pid=\K[0-9]+' <<< "$rest" | head -n1)"
  done | sort -u
}

listening_external() {
  # listening_external tcp|udp PORT -> true if it listens beyond localhost
  list_listeners | awk -F'|' -v p="$1" -v port="$2" '$1==p && $3==port {print $2}' \
    | grep -qvE '^(127\.|\[::1\]|::1|\[::ffff:127\.)'
}

unit_of() {
  # System service a process belongs to, read from its cgroup. Empty for
  # anything a user started by hand (those live in a session scope).
  local cg
  cg="$(head -n1 "/proc/$1/cgroup" 2>/dev/null)"
  if [[ $cg == *"/system.slice/"* ]]; then
    cg="${cg##*/}"
    [[ $cg == *.service ]] && echo "$cg"
  fi
}

is_suspicious() {
  # is_suspicious NAME EXE
  [[ $1 =~ $SUSPICIOUS ]] && return 0
  [[ $2 =~ ^/(tmp|var/tmp|dev/shm|home|run/user)/ ]] && return 0
  [[ $2 == *"(deleted)"* ]] && return 0
  return 1
}

read_ports() {
  # Prompts for extra ports; prints the valid ones space-separated.
  local ans p out=()
  [[ $MODE == check ]] && return 0
  read -r -p "  >> $1 " ans < /dev/tty || return 0
  for p in ${ans//,/ }; do
    if [[ $p =~ ^[0-9]+$ ]] && ((p >= 1 && p <= 65535)); then
      out+=("$p")
    else
      warn "Ignoring '$p' (not a port number)" >&2
    fi
  done
  echo "${out[*]}"
}

# =============================================================================
# STEPS
# =============================================================================

step_baseline() {
  begin_step 0 "Baseline and backup"
  record_baseline
  ((${#BASE_PORTS[@]})) && { health_check >/dev/null && ok "All of them answer correctly."; }
  if ask "Back up /etc, /home and /root now? (your only undo: no snapshots in competition)" Y; then
    local bk="$RUN_DIR/backup.tgz" paths=() p
    for p in /etc /home /root; do
      [[ -e $p ]] && paths+=("$p")
    done
    info "Backing up ${paths[*]} (free space: $(df -h / | awk 'NR==2{print $4}'))"
    tar --exclude="$BASE_DIR" --exclude='*/.cache' -czpf "$bk" "${paths[@]}" 2>/dev/null
    if [[ -s $bk ]]; then
      chmod 600 "$bk"
      action "Backup written: $bk ($(du -h "$bk" | cut -f1))"
      info "Restore one file later: tar -xzpf $bk -C / etc/ssh/sshd_config"
    else
      warn "Backup failed. Think hard before continuing without one."
    fi
  fi
}

step_sessions() {
  begin_step 1 "Logged-in sessions"
  local name line rest
  who -u | sed 's/^/    /'
  info "Yours: ${MY_TTY:-unknown}. Check the IP in brackets: is it yours or a teammate's?"
  while read -r name line rest; do
    [[ -z $line || $line == "$MY_TTY" ]] && continue
    if ask "End session $name on $line ($rest)?" N; then
      pkill -KILL -t "$line" && action "Ended session $name on $line ($rest)"
    fi
  done < <(who -u)
}

step_passwords() {
  begin_step 2 "Passwords"
  info "AD user passwords: change them only in Quotient's PCR tab, or scoring breaks."
  info "Root is handled in step 3."
  save /etc/shadow
  local u

  sub "Local accounts that can log in"
  passwd -S -a 2>/dev/null | while read -r u st _; do
    is_local_account "$u" || continue
    awk -F: -v n="$u" '$1==n && $7 !~ /(nologin|false|sync)$/ {f=1} END{exit !f}' /etc/passwd || continue
    case $st in
      P)  info "    $u  password set" ;;
      L)  info "    $u  locked" ;;
      NP) info "    $u  NO PASSWORD" ;;
    esac
  done

  sub "Your account"
  if [[ -z $ADMIN ]]; then
    warn "Can't tell which account you used. Run this with sudo from your admin account."
  elif ! is_local_account "$ADMIN"; then
    info "$ADMIN is not a local account (AD?). Change it on the DC or through Quotient PCR."
  elif ask "Change YOUR password ($ADMIN)? The default is printed in the team packet, so red team knows it." Y; then
    set_password "$ADMIN"
  fi

  sub "Other admin accounts (sudo/admin group)"
  for u in $(admin_users); do
    [[ $u == "$ADMIN" ]] && continue
    is_local_account "$u" || { info "$u is not local (AD?), skipping"; continue; }
    if ask "Change password for admin account '$u'?" Y; then set_password "$u"; fi
  done

  sub "Other local users"
  for u in $(awk -F: '$3>=1000 && $3<65534 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd); do
    [[ $u == "$ADMIN" ]] && continue
    is_admin "$u" && continue
    if ask "Change password for local user '$u'? If the scoring engine logs in as this user, scoring breaks until you submit it in Quotient PCR." N; then
      if set_password "$u"; then
        printf '%s,%s\n' "$u" "$LAST_PW" >> "$PCR_FILE"
        chmod 600 "$PCR_FILE"
        info "Saved to $PCR_FILE for Quotient PCR. After submitting: shred -u $PCR_FILE"
      fi
    fi
  done
}

can_lock_root() {
  # Locking root is safe only if your own sudo access is solid.
  if [[ -z $ADMIN ]] || ! is_local_account "$ADMIN"; then
    warn "Run this with sudo from a local admin account before locking root."; return 1
  fi
  if [[ $(passwd -S "$ADMIN" | awk '{print $2}') != P ]]; then
    warn "$ADMIN has no usable password."; return 1
  fi
  if ! sudo -l -U "$ADMIN" 2>/dev/null | grep -qE '\(ALL( : ALL)?\) (NOPASSWD: )?ALL$'; then
    warn "$ADMIN does not have full sudo."; return 1
  fi
  if ! visudo -c >/dev/null 2>&1; then
    warn "sudoers has errors, so sudo could break."; return 1
  fi
  return 0
}

step_root() {
  begin_step 3 "Root account"
  save /etc/shadow
  local st
  st="$(passwd -S root | awk '{print $2}')"
  case $st in
    L)  ok "Root's password is already locked (Ubuntu's default). sudo still works."; return 0 ;;
    NP) finding "Root has NO password" ;;
    P)  info "Root has a usable password. Anyone who knows it can 'su root' or log in at the console." ;;
  esac
  if can_lock_root; then
    ok "$ADMIN has a password and full sudo, so locking root is safe."
    if ask "Lock root's password? Blocks root logins and 'su root'. 'sudo' from $ADMIN keeps working." Y; then
      passwd -l root >/dev/null && action "Locked root's password"
      return 0
    fi
  else
    warn "Not offering to lock root (reason above)."
  fi
  if ask "Change root's password instead?" Y; then set_password root; fi
}

step_users() {
  begin_step 4 "User security"
  save /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d
  local u uid shell f line n

  sub "Accounts with UID 0 (full root)"
  n=0
  while IFS=: read -r u uid; do
    n=1
    finding "Account '$u' has UID 0, which makes it root"
    if ask "Lock '$u'? Keeps it as evidence, blocks password and key logins." Y; then lock_account "$u"; fi
  done < <(awk -F: '$3==0 && $1!="root" {print $1":"$3}' /etc/passwd)
  ((n)) || ok "Only root has UID 0"
  for uid in $(cut -d: -f3 /etc/passwd | sort | uniq -d); do
    finding "UID $uid is shared by: $(awk -F: -v id="$uid" '$3==id {printf "%s ", $1}' /etc/passwd)"
  done

  sub "Accounts with an empty password"
  n=0
  while read -r u; do
    [[ $u == root ]] && continue
    n=1
    finding "Account '$u' has an empty password (logs in with no password)"
    if ask "Lock '$u'?" Y; then lock_account "$u"; fi
  done < <(awk -F: '$2=="" {print $1}' /etc/shadow)
  ((n)) || ok "None"

  sub "Service accounts with a login shell"
  n=0
  while IFS=: read -r u uid shell; do
    n=1
    finding "Service account '$u' (UID $uid) has a login shell: $shell"
    if ask "Set '$u' to /usr/sbin/nologin? (say N for postgres or anything your team logs in as)" N; then
      usermod -s /usr/sbin/nologin "$u" && action "Set $u's shell to nologin"
    fi
  done < <(awk -F: '$3>0 && $3<1000 && $7 !~ /(nologin|false|sync)$/ {print $1":"$3":"$7}' /etc/passwd)
  ((n)) || ok "None (Ubuntu's default)"

  sub "Members of the sudo and admin groups"
  for u in $(admin_users); do
    if [[ $u == "$ADMIN" ]]; then ok "$u (you)"; continue; fi
    warn "$u has full sudo"
    if ask "Remove '$u' from the sudo and admin groups? Only if you don't recognize it." N; then
      gpasswd -d "$u" sudo >/dev/null 2>&1
      gpasswd -d "$u" admin >/dev/null 2>&1
      action "Removed $u from the sudo/admin groups"
    fi
  done

  sub "sudo rules"
  while IFS= read -r line; do
    finding "sudo without a password: $line"
  done < <(grep -rnsE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/)
  while IFS= read -r line; do
    finding "sudo authentication turned off: $line"
  done < <(grep -rnsE '^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d/)
  # Users given sudo by name instead of through a group
  while IFS= read -r line; do
    finding "Account given sudo directly in /etc/sudoers: $line"
  done < <(awk '$1 !~ /^(#|%|@|Defaults|root|Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias)/ && NF && /=/' /etc/sudoers)
  grep -qE 'NOPASSWD|!authenticate' /etc/sudoers 2>/dev/null && info "Fix rules in the main file with: sudo visudo"
  for f in /etc/sudoers.d/*; do
    [[ -f $f && $(basename "$f") != README ]] || continue
    finding "Extra sudoers file: $f"
    sed 's/^/      /' "$f"
    if ask "Disable $f? (moved into the rollback folder)" N; then
      mv "$f" "$STEP_DIR/"
      if visudo -c >/dev/null 2>&1; then
        action "Disabled sudoers file $f"
      else
        warn "sudo config broke without it. Putting it back."
        mv "$STEP_DIR/$(basename "$f")" "$f"
      fi
    fi
  done
  visudo -c >/dev/null 2>&1 && ok "sudoers syntax is valid" || finding "sudoers has syntax errors (sudo may be broken): run sudo visudo -c"

  sub "SSH authorized_keys"
  info "At drop flag you haven't added any keys, so every key found is someone else's."
  n=0
  while read -r f; do
    local count owner
    count="$(grep -cvE '^[[:space:]]*(#|$)' "$f")"
    ((count)) || continue
    n=1
    owner="$(stat -c %U "$f")"
    finding "$count SSH key(s) in $f (owner $owner), labels: $(awk '!/^[[:space:]]*(#|$)/ {printf "%s ", (NF>=3 ? $NF : "(none)")}' "$f")"
    awk '!/^[[:space:]]*(#|$)/ {print "      " substr($0,1,40) " ... " substr($0, length($0)-30)}' "$f"
    if grep -qiE 'cyberrange|ansible' "$f"; then
      info "    Looks like the organizers' setup key (it came with the box). Removing it is fine;"
      info "    it's logged in findings.txt in case White Team asks about it."
    fi
    if ask "Empty $f? (If you added a key yourself in this lab, say N.)" Y; then
      save "$f"
      : > "$f" && action "Removed $count SSH key(s) from $f"
    fi
  done < <(key_files)
  ((n)) || ok "No SSH keys in any account's home folder"
  line="$(sshd -T 2>/dev/null | awk '/^authorizedkeysfile / {$1=""; print substr($0,2)}')"
  if [[ -n $line && $line != ".ssh/authorized_keys .ssh/authorized_keys2" ]]; then
    finding "sshd reads keys from a non-default location: $line"
  fi

  sub "Who can log in through AD (report only)"
  if have realm && [[ -n $(realm list 2>/dev/null) ]]; then
    realm list 2>/dev/null | grep -E '^[^[:space:]]|login-policy|permitted-(logins|groups)' | sed 's/^/      /'
    if realm list 2>/dev/null | grep -q 'allow-realm-logins'; then
      finding "Any AD account can log in to this box (login-policy: allow-realm-logins): one weak AD password gives a shell here"
      info "Don't change it: the scorer logs in through AD. Tell your AD teammate to reset weak AD passwords."
    fi
  elif [[ -f /etc/sssd/sssd.conf ]]; then
    grep -E '^[[:space:]]*(domains|access_provider|simple_allow_(users|groups)|ad_access_filter|ldap_access_filter)[[:space:]]*=' /etc/sssd/sssd.conf | sed 's/^[[:space:]]*/      /'
    if grep -qE '^[[:space:]]*access_provider[[:space:]]*=[[:space:]]*permit' /etc/sssd/sssd.conf; then
      finding "SSSD lets every AD account log in (access_provider = permit)"
    fi
  else
    ok "Not joined to a domain (no realm or SSSD config)"
  fi
  if grep -qE '^sudoers:.*sss' /etc/nsswitch.conf 2>/dev/null; then
    info "sudo rules can also come from AD ('sudoers: ... sss' in /etc/nsswitch.conf)."
    info "Check an AD account's real sudo rights with: sudo -l -U <user>"
  fi

  sub "Permissions on account files"
  fix_perm /etc/passwd  644 root:root
  fix_perm /etc/group   644 root:root
  fix_perm /etc/shadow  640 root:shadow
  fix_perm /etc/gshadow 640 root:shadow
  fix_perm /etc/sudoers 440 root:root
  ok "Checked passwd, group, shadow, gshadow, sudoers"
}

step_ssh() {
  begin_step 5 "SSH"
  local cfg=/etc/ssh/sshd_config f tmp moved=()
  [[ -f $cfg ]] || { warn "No $cfg. Is openssh-server installed?"; return 0; }

  info "Settings sshd is using now:"
  sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|permitemptypasswords|maxauthtries) ' | sed 's/^/      /'

  # Override files are read before the rest of the main file (Include is at its top).
  # A Match block can turn root login back on for one IP, whatever comes first.
  grep -nisE '^[[:space:]]*(permitrootlogin[[:space:]]+yes|match[[:space:]])' "$cfg" | while IFS= read -r f; do
    finding "In $cfg: $f  (edit by hand: sudo nano $cfg)"
  done
  for f in /etc/ssh/sshd_config.d/*.conf; do
    [[ -f $f ]] || continue
    info "Override file: $f"
    if grep -qisE '^[[:space:]]*(permitrootlogin[[:space:]]+yes|match[[:space:]])' "$f"; then
      finding "$f turns root login on or has a Match block:"
      sed 's/^/      /' "$f"
      if ask "Disable $f? (moved into the rollback folder)" Y; then
        mv "$f" "$STEP_DIR/" && moved+=("$f")
      fi
    fi
  done

  if ! ask "Apply SSH hardening? Root login off, empty passwords off, 4 tries per connection. Password logins stay ON for the scorer." Y; then
    return 0
  fi
  save "$cfg"
  # sshd uses the FIRST value it reads for each setting, so this block goes at
  # the very top, ahead of the Include line and anything an attacker added.
  tmp="$(mktemp)"
  {
    echo "# BEGIN ccdc dropflag $STAMP (sshd uses the first value it reads, so this sits at the top)"
    echo "PermitRootLogin no"
    echo "PermitEmptyPasswords no"
    echo "MaxAuthTries 4"
    echo "LoginGraceTime 30"
    echo "X11Forwarding no"
    echo "# END ccdc dropflag"
    sed '/^# BEGIN ccdc dropflag/,/^# END ccdc dropflag/d' "$cfg"
  } > "$tmp" && cat "$tmp" > "$cfg"
  rm -f "$tmp"

  # Test before applying: a broken config would take SSH (a scored service) down.
  if ! sshd -t; then
    warn "sshd -t failed. Restoring the old config."
    cp -a "$STEP_DIR$cfg" "$cfg"
    for f in "${moved[@]}"; do mv "$STEP_DIR/$(basename "$f")" "$f"; done
    return 1
  fi
  systemctl reload ssh 2>/dev/null || systemctl restart ssh
  sleep 1
  for f in "${moved[@]}"; do action "Disabled sshd override $f"; done
  if sshd -T 2>/dev/null | grep -q '^permitrootlogin no'; then
    action "SSH root login disabled (permitrootlogin no)"
  else
    finding "permitrootlogin is still not 'no'. Check: sudo sshd -T | grep permitrootlogin"
  fi
  if health_check; then
    ok "SSH still answers."
  else
    warn "A scored port stopped answering. Restoring the old SSH config."
    cp -a "$STEP_DIR$cfg" "$cfg"
    for f in "${moved[@]}"; do mv "$STEP_DIR/$(basename "$f")" "$f"; done
    systemctl restart ssh
  fi
  warn "Keep this session open. Log in as ${ADMIN:-your admin} from a SECOND window before closing it."
}

review_listener() {
  local proto=$1 addr=$2 port=$3 pname=${4:--} pid=${5:--} unit exe cmd label def frag sock
  label="$proto $addr:$port  $pname (pid $pid)"
  if is_local "$addr"; then
    ok "$label  localhost only, unreachable from outside"; return
  fi
  exe=""
  [[ $pid != - ]] && exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
  # Whatever program holds a scored port is treated as the scored service, so
  # this works with any software. Exception: a shell or netcat sitting on
  # a scored port is a backdoor pretending to be the service.
  if [[ $proto == tcp ]] && in_list "$port" "${SCORED_TCP[@]}" && ! is_suspicious "$pname" "$exe"; then
    ok "$label  scored port"; return
  fi
  if [[ $pname =~ $PROTECTED ]]; then
    ok "$label  service the box needs; the firewall blocks it from outside"; return
  fi
  [[ $pid == - ]] && { finding "$label  listening with no process info"; return; }

  unit="$(unit_of "$pid")"
  cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-150)"
  [[ -n ${SEEN[${unit:-$pid}]:-} ]] && return      # IPv4 and IPv6 copies of one listener
  SEEN[${unit:-$pid}]=1

  if is_suspicious "$pname" "$exe"; then
    finding "Possible backdoor on $proto/$port: $cmd (program $exe)"
  elif [[ -n $unit ]] && in_list "$unit" "${UNNEEDED_UNITS[@]}"; then
    warn "$label  not needed on this server"
  else
    warn "$label  unknown: find out what it is before stopping it"
  fi
  info "    command: $cmd"
  info "    program: $exe"

  if [[ -n $unit ]]; then
    frag="$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)"
    info "    service: $unit  (unit file: ${frag:-unknown})"
    def=N; in_list "$unit" "${UNNEEDED_UNITS[@]}" && def=Y
    if ask "Stop and disable $unit?" "$def"; then
      sock="${unit%.service}.socket"
      if systemctl cat "$sock" >/dev/null 2>&1; then
        systemctl disable --now "$unit" "$sock" >/dev/null 2>&1   # the socket would restart it
      else
        systemctl disable --now "$unit" >/dev/null 2>&1
      fi
      action "Stopped and disabled $unit (was listening on $proto/$port)"
      sleep 1
      if ! health_check; then
        warn "A scored port stopped answering. Turning $unit back on."
        systemctl enable --now "$unit" >/dev/null 2>&1
        action "Re-enabled $unit after it broke a scored service"
      fi
    fi
  else
    info "    started by hand, not a service"
    def=N; is_suspicious "$pname" "$exe" && def=Y
    if ask "Kill PID $pid? (a copy of the program is saved as evidence first)" "$def"; then
      cp "/proc/$pid/exe" "$STEP_DIR/evidence-pid$pid.bin" 2>/dev/null \
        && sha256sum "$STEP_DIR/evidence-pid$pid.bin" >> "$STEP_DIR/evidence-hashes.txt"
      kill -9 "$pid" 2>/dev/null && action "Killed PID $pid ($cmd) listening on $proto/$port"
    fi
  fi
}

step_ports() {
  begin_step 6 "Listening ports (UDP first)"
  info "Nothing scored on this box uses UDP, so any UDP listener open to the network is"
  info "either a default service you can turn off or a backdoor. Outbound UDP (DNS,"
  info "Kerberos and NTP to the DC) isn't touched here."
  local proto p addr port pname pid
  for proto in udp tcp; do
    sub "${proto^^} listeners"
    while IFS='|' read -r p addr port pname pid; do
      [[ $p == "$proto" ]] && review_listener "$p" "$addr" "$port" "$pname" "$pid"
    done < <(list_listeners)
  done
  if have systemctl; then
    local socks
    socks="$(systemctl list-sockets --no-legend 2>/dev/null | awk '$1 ~ /:[0-9]+$/ && $1 !~ /^(127\.|\[::1\])/ {print "      " $1 "  " $2}')"
    [[ -n $socks ]] && { info "Ports systemd opens on demand (check these units too):"; echo "$socks"; }
  fi
}

check_ping() {
  local v
  v="$(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null)"
  if [[ $v == 1 ]]; then
    finding "Ping replies are turned off (net.ipv4.icmp_echo_ignore_all=1). The packet requires ping."
    grep -rns 'icmp_echo_ignore_all' /etc/sysctl.conf /etc/sysctl.d/ 2>/dev/null | sed 's/^/      set in: /'
    if ask "Turn ping replies back on now?" Y; then
      sysctl -qw net.ipv4.icmp_echo_ignore_all=0 && action "Turned ping replies back on (remove the line above so it survives a reboot)"
    fi
  fi
  if grep -qE 'ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT' /etc/ufw/before.rules 2>/dev/null; then
    ok "ufw allows ping"
  else
    finding "ufw's before.rules has no rule allowing ping. Reset ufw or restore /etc/ufw/before.rules."
  fi
}

check_hidden_rules() {
  local bin chain rule n dels t fam name
  # 1. Rules added straight into the built-in chains, outside ufw's own chains.
  #    Deleted by number, highest first, so the numbers don't shift.
  for bin in iptables ip6tables; do
    have "$bin" || continue
    for chain in INPUT OUTPUT FORWARD; do
      dels=(); n=0
      while read -r rule; do
        n=$((n + 1))
        [[ $rule == *" -j ufw"* || $rule == *DOCKER* ]] && continue   # ufw's own and Docker's rules stay
        finding "$bin rule added outside ufw ($chain #$n): $rule"
        if ask "Delete it?" Y; then dels=("$n" "${dels[@]}"); fi
      done < <("$bin" -S "$chain" 2>/dev/null | grep "^-A $chain ")
      for n in "${dels[@]}"; do
        "$bin" -D "$chain" "$n" && action "Deleted $bin $chain rule #$n"
      done
    done
    for t in nat mangle raw; do
      while read -r rule; do
        finding "$bin $t table rule (not needed unless this box forwards traffic): $rule   remove with: sudo $bin -t $t -F"
      done < <("$bin" -t "$t" -S 2>/dev/null | grep '^-A ' | grep -v DOCKER | grep -v NFQUEUE)   # NFQUEUE = your Suricata IPS
    done
  done

  # 2. nftables tables that ufw and the iptables commands didn't create.
  if have nft; then
    while read -r _ fam name; do
      case "$fam $name" in
        "ip filter"|"ip6 filter"|"ip nat"|"ip6 nat"|"ip mangle"|"ip6 mangle"|"ip raw"|"ip6 raw"|"ip security"|"ip6 security") continue ;;
      esac
      finding "nftables table not made by ufw/iptables: $fam $name (iptables -L and ufw status don't show it)"
      nft list table "$fam" "$name" 2>/dev/null | sed 's/^/      /'
      if ask "Delete table $fam $name? (say N if your team set up fail2ban)" N; then
        nft delete table "$fam" "$name" && action "Deleted nftables table $fam $name"
      fi
    done < <(nft list tables 2>/dev/null)
  fi

  # 3. The old legacy engine. On 22.04 iptables writes into nftables, so rules here
  #    were loaded on purpose with iptables-legacy, and they still filter traffic.
  if have iptables-legacy && iptables -V 2>/dev/null | grep -q nf_tables; then
    for bin in iptables-legacy ip6tables-legacy; do
      have "$bin" || continue
      if "${bin}-save" 2>/dev/null | grep -qE '^-A |^:[A-Z]+ (DROP|REJECT)'; then
        finding "Rules loaded in $bin (hidden from the normal iptables and ufw commands):"
        "${bin}-save" 2>/dev/null | grep -E '^-A |^:[A-Z]+ (DROP|REJECT)' | sed 's/^/      /'
        if ask "Flush all $bin rules?" Y; then
          for t in filter nat mangle raw; do "$bin" -t "$t" -F 2>/dev/null; "$bin" -t "$t" -X 2>/dev/null; done
          for chain in INPUT FORWARD OUTPUT; do "$bin" -P "$chain" ACCEPT 2>/dev/null; done
          action "Flushed $bin"
        fi
      fi
    done
  fi
}

step_firewall() {
  begin_step 7 "Firewall (ufw)"
  if ! have ufw; then
    warn "ufw is not installed."
    if ask "Install ufw now? (needs package access)" Y; then
      apt-get install -y ufw >/dev/null 2>&1 || { warn "Install failed"; return 1; }
    else
      return 0
    fi
  fi

  info "Now: $(ufw status | head -n1)   service at boot: $(systemctl is-enabled ufw 2>/dev/null)"
  [[ -d /var/lib/docker ]] && warn "Docker is installed: ports it publishes bypass ufw. Its own firewall rules are left alone."
  ufw status numbered 2>/dev/null | sed -n '4,$p' | sed 's/^/      /'

  # Template check: red team can hide ACCEPT rules in before.rules, which
  # 'ufw status' never shows.
  if [[ -f /usr/share/ufw/iptables/before.rules ]] && ! diff -q /usr/share/ufw/iptables/before.rules /etc/ufw/before.rules >/dev/null 2>&1; then
    finding "/etc/ufw/before.rules differs from Ubuntu's default:"
    diff /usr/share/ufw/iptables/before.rules /etc/ufw/before.rules | sed 's/^/      /' | head -n 30
  fi

  # SSH, HTTP and HTTPS (plus the mail ports on a mail server) are opened even
  # if nothing listens on them right now: a service that's down at drop flag
  # must still be reachable once it's back up. Other scored ports open if listening.
  local allow_tcp=("${ALWAYS_TCP[@]}") allow_udp=() p addr port pname pid extra
  if mail_stack_present; then
    allow_tcp+=("${MAIL_TCP[@]}")
    info "Mail server found: ${MAIL_TCP[*]} stay open even if a mail service is down right now."
  fi
  for p in "${SCORED_TCP[@]}"; do
    if listening_external tcp "$p" && ! in_list "$p" "${allow_tcp[@]}"; then allow_tcp+=("$p"); fi
  done
  while IFS='|' read -r p addr port pname pid; do
    [[ $p == tcp && $pname =~ $PROTECTED ]] || continue
    is_local "$addr" && continue
    in_list "$port" "${SCORED_TCP[@]}" && continue
    info "$pname also listens on tcp/$port. If Quotient scores that port, add it below."
  done < <(list_listeners)
  extra="$(read_ports 'Other scored TCP ports to allow? (space-separated, Enter for none)')"
  for p in $extra; do in_list "$p" "${allow_tcp[@]}" || allow_tcp+=("$p"); done
  extra="$(read_ports 'Any UDP ports to allow? (normally none; Enter for none)')"
  for p in $extra; do allow_udp+=("$p"); done

  info "Inbound TCP to allow: ${allow_tcp[*]}"
  info "Inbound UDP to allow: ${allow_udp[*]:-none}"
  info "Everything else inbound is blocked, TCP and UDP. Outbound stays open (DNS, AD logins, replies)."
  if ask "Apply these firewall rules?" Y; then
    save /etc/ufw
    if ask "Reset ufw first? Clears every rule anyone else added. ufw keeps dated backups in /etc/ufw/." Y; then
      ufw --force reset >/dev/null && action "Reset ufw to Ubuntu's default rules"
    fi
    ufw default deny incoming  >/dev/null
    ufw default allow outgoing >/dev/null
    ufw default deny routed    >/dev/null
    for p in "${allow_tcp[@]}"; do ufw allow "$p/tcp" >/dev/null; done
    for p in "${allow_udp[@]}"; do ufw allow "$p/udp" >/dev/null; done
    ufw logging low >/dev/null
    if [[ -f /var/log/ufw.log ]]; then
      info "Blocked packets are logged to /var/log/ufw.log"
    else
      info "Blocked packets are logged to the kernel journal: sudo journalctl -k | grep 'UFW BLOCK'"
    fi
    if ufw --force enable >/dev/null; then
      action "ufw on: inbound allowed only on tcp ${allow_tcp[*]}${allow_udp[*]:+ and udp ${allow_udp[*]}}"
    else
      warn "ufw enable failed"
    fi
    systemctl enable ufw >/dev/null 2>&1
    [[ $(systemctl is-enabled ufw 2>/dev/null) == enabled ]] && ok "ufw starts at boot" || warn "ufw is not enabled at boot"
    ufw status verbose | sed 's/^/      /'
  fi

  sub "Ping"
  check_ping
  sub "Rules hidden outside ufw"
  check_hidden_rules
  health_check && ok "Scored ports still answer locally."
  warn "These checks run on the box itself and can't see the firewall from outside. Watch Quotient."
}

# ---- step 8 helpers ------------------------------------------------------------
find_roundcube() {
  # Roundcube's folder, wherever it was installed (the competition box: /opt/roundcube).
  local d
  for d in /opt/roundcube /var/www/roundcube /var/www/html/roundcube /usr/share/roundcube \
           $(find /opt /var/www /srv -maxdepth 4 -path '*/program/include/iniset.php' 2>/dev/null | sed 's#/program/include/iniset.php$##'); do
    [[ -f $d/program/include/iniset.php ]] && { readlink -f "$d"; return 0; }
  done
}

web_user() {
  # The account PHP runs as: the PHP-FPM pool's user, else Apache's.
  local u
  u="$(grep -hE '^[[:space:]]*user[[:space:]]*=' /etc/php/*/fpm/pool.d/*.conf 2>/dev/null | head -n1 | sed -E 's/.*=[[:space:]]*//; s/[[:space:]]+$//')"
  [[ -z $u ]] && u="$( . /etc/apache2/envvars 2>/dev/null; echo "${APACHE_RUN_USER:-}")"
  echo "${u:-www-data}"
}

lan_net() {
  local iface
  iface="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')"
  [[ -n $iface ]] && ip -o -4 route show dev "$iface" scope link 2>/dev/null | awk '{print $1; exit}'
}

postfix_set() {
  # postfix_set "key = value" "what it does"
  postconf -e "$1" && PF_CHANGED=1 && action "Postfix: $1 ($2)"
}

mail_postfix() {
  sub "Postfix"
  local v key f line n svc lan
  PF_CHANGED=0
  save /etc/postfix /etc/aliases

  v="$(postconf -h smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null | tr '\n' ' ')"
  if [[ $v =~ (reject|defer)_unauth_destination ]]; then
    ok "Not an open relay (relay rules end in reject/defer_unauth_destination)"
  else
    finding "Postfix may be an OPEN RELAY: no reject_unauth_destination in smtpd_relay_restrictions or smtpd_recipient_restrictions"
    if ask "Set smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination?" Y; then
      postfix_set "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination" "only trusted hosts and logged-in users may relay"
    fi
  fi

  v="$(postconf -h mynetworks 2>/dev/null)"
  if [[ " $v " =~ [[:space:],](0\.0\.0\.0/0|0/0|::/0|\[::\]/0)[[:space:],] ]]; then
    finding "mynetworks trusts every IP address ($v): anyone can relay mail through this box"
    lan="$(lan_net)"
    if ask "Set mynetworks to localhost${lan:+ and $lan}?" Y; then
      postfix_set "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128${lan:+ $lan}" "trusted relay hosts"
    fi
  else
    info "Hosts trusted to relay without logging in (mynetworks): $v"
  fi

  if [[ $(postconf -h disable_vrfy_command 2>/dev/null) != yes ]]; then
    finding "SMTP VRFY is on: anyone can check which usernames exist"
    if ask "Turn VRFY off (disable_vrfy_command = yes)?" Y; then
      postfix_set "disable_vrfy_command = yes" "no username checks over SMTP"
    fi
  else
    ok "VRFY is off"
  fi

  # Settings that silently copy or reroute every message.
  for key in always_bcc sender_bcc_maps recipient_bcc_maps; do
    v="$(postconf -n 2>/dev/null | awk -F' = ' -v k="$key" '$1==k {print $2}')"
    [[ -n $v ]] || continue
    finding "Postfix copies mail silently: $key = $v"
    for f in $(grep -oE '/[^ ,]+' <<< "$v"); do
      [[ -f $f ]] && sed 's/^/      /' "$f" | head -n 10
    done
    if ask "Remove $key? (copy saved in the rollback folder)" Y; then
      postconf -X "$key" && PF_CHANGED=1 && action "Postfix: removed $key = $v"
    fi
  done
  for key in content_filter smtpd_proxy_filter smtpd_milters non_smtpd_milters; do
    v="$(postconf -n 2>/dev/null | awk -F' = ' -v k="$key" '$1==k {print $2}')"
    [[ -n $v ]] && finding "Mail passes through an outside program: $key = $v. Normal only if your team set up a filter. Remove with: sudo postconf -X $key && sudo postfix reload"
  done
  while IFS= read -r line; do
    finding "master.cf overrides a filter or copy setting for one service: $line"
  done < <(postconf -P 2>/dev/null | grep -E 'content_filter|proxy_filter|milters|bcc')

  # Extra SMTP listeners, or services that hand mail to a program.
  while IFS= read -r line; do
    finding "Extra network service in /etc/postfix/master.cf: $line"
  done < <(postconf -M 2>/dev/null | awk '$2=="inet" && $1 !~ /^(smtp|submission|submissions|smtps|25|465|587)$/')
  while read -r svc; do
    finding "Postfix service '$svc' pipes mail to a program (not one of Ubuntu's defaults):"
    grep -A3 -E "^${svc}[[:space:]]" /etc/postfix/master.cf | sed 's/^/      /'
  done < <(postconf -M 2>/dev/null | awk '$8=="pipe" && $1 !~ /^(maildrop|uucp|ifmail|bsmtp|scalemail-backend|mailman)$/ {print $1}')

  # Forwarding: aliases that run commands or write files, and .forward files.
  while IFS= read -r line; do
    finding "/etc/aliases runs a command or writes to a file: $line  (edit by hand, then: sudo newaliases)"
  done < <(grep -vE '^[[:space:]]*(#|$)' /etc/aliases 2>/dev/null | grep -E '\||:include:|:[[:space:]]*/|,[[:space:]]*/')
  n=0
  while read -r f; do
    n=1
    finding "$f forwards this user's mail: $(tr '\n' ' ' < "$f" | cut -c1-120)"
    if ask "Remove $f? (copy saved in the rollback folder)" Y; then
      save "$f"; rm -f "$f" && action "Removed mail forward $f"
    fi
  done < <(find /home /root -maxdepth 3 -name .forward -type f 2>/dev/null)
  ((n)) || ok "No .forward files"

  n="$(postqueue -j 2>/dev/null | wc -l)"
  if ((n > 50)); then
    warn "$n messages waiting in the mail queue. A growing queue means delivery is failing:"
    info "    sudo mailq | tail    and    sudo journalctl -u postfix@- -n 30"
  else
    ok "Mail queue: $n message(s)"
  fi

  if ((PF_CHANGED)); then
    if postfix check 2>/dev/null && postfix reload >/dev/null 2>&1 && sleep 1 && health_check; then
      ok "Postfix reloaded, scored services still answer"
    else
      warn "Postfix broke after the changes. Restoring /etc/postfix."
      cp -a "$STEP_DIR/etc/postfix/." /etc/postfix/ && postfix reload >/dev/null 2>&1
      action "Restored /etc/postfix from the rollback copy"
    fi
  fi
}

mail_dovecot() {
  sub "Dovecot (report only: edit /etc/dovecot by hand, then 'sudo doveconf -n && sudo systemctl reload dovecot')"
  local conf line
  if ! conf="$(doveconf -n 2>&1)"; then
    finding "Dovecot's config has errors: $(head -n1 <<< "$conf")"; return
  fi
  info "Password and user sources: $(awk '/^(passdb|userdb)[[:space:]]/ {b=$1} b && /^[[:space:]]+driver = / {printf "%s=%s  ", b, $3; b=""}' <<< "$conf")"
  if grep -qE '^[[:space:]]+master = yes' <<< "$conf" || grep -qE '^auth_master_user_separator' <<< "$conf"; then
    finding "Dovecot has a master user: one password opens every mailbox"
  fi
  if awk '/^passdb[[:space:]]/ {b=1} b && /driver = static/ {f=1} END {exit !f}' <<< "$conf"; then
    finding "Dovecot has a 'static' password source: everyone can log in with one fixed password"
  fi
  grep -qE 'driver = passwd-file' <<< "$conf" && finding "Dovecot reads passwords from a file (passwd-file). Check that file: $(grep -oE 'args = [^ ]+' <<< "$conf" | head -n1)"
  grep -qE '^auth_(debug_passwords = yes|verbose_passwords = (plain|sha1|yes))' <<< "$conf" && finding "Dovecot writes passwords into the logs (auth_debug_passwords / auth_verbose_passwords)"
  while IFS= read -r line; do
    finding "Dovecot runs a custom program: $line"
  done < <(grep -E '^[[:space:]]+executable = ' <<< "$conf" | grep -vE 'executable = (imap|pop3|lmtp|imap-login|pop3-login|managesieve|managesieve-login|auth|config|anvil|log|dict|stats)$')
  ok "Dovecot checks done"
}

mail_roundcube() {
  local rc=$1 wu wg ver cfg f n line keep=() prune=() own
  sub "Roundcube ($rc)"
  wu="$(web_user)"; wg="$(id -gn "$wu" 2>/dev/null || echo "$wu")"
  ver="$(grep -m1 -oE "RCMAIL_VERSION', '[^']+" "$rc/program/include/iniset.php" | cut -d"'" -f3)"
  info "Version ${ver:-unknown}. PHP runs as $wu."
  if [[ $ver =~ ^1\.6\. && $(printf '%s\n' "$ver" 1.6.11 | sort -V | head -n1) != 1.6.11 ]] ||
     [[ $ver =~ ^1\.5\. && $(printf '%s\n' "$ver" 1.5.10 | sort -V | head -n1) != 1.5.10 ]] ||
     [[ $ver =~ ^1\.[0-4]\. ]]; then
    finding "Roundcube $ver is vulnerable to CVE-2025-49113 (any logged-in user can run code). Fixed in 1.6.11 / 1.5.10."
  fi

  if [[ -d $rc/installer ]]; then
    finding "Roundcube's installer folder is still here: $rc/installer (it can show or rewrite the config)"
    if ask "Move it out of Roundcube (into the rollback folder)?" Y; then
      mv "$rc/installer" "$STEP_DIR/roundcube-installer" && action "Moved $rc/installer to $STEP_DIR/roundcube-installer"
      if ! health_check; then
        mv "$STEP_DIR/roundcube-installer" "$rc/installer" && action "Put the installer folder back: webmail broke without it"
      fi
    fi
  else
    ok "No installer folder"
  fi
  cfg="$(readlink -f "$rc/config/config.inc.php")"
  grep -qE "^[[:space:]]*\\\$config\[.enable_installer.\][[:space:]]*=[[:space:]]*true" "$cfg" 2>/dev/null \
    && finding "enable_installer is true in $cfg (set it to false by hand)"

  # Folders Roundcube writes to: temp/, logs/, and any folder holding a SQLite database.
  keep=("$rc/temp" "$rc/logs")
  while read -r f; do in_list "$(dirname "$f")" "${keep[@]}" || keep+=("$(dirname "$f")"); done \
    < <(find "$rc" -maxdepth 3 -type f \( -name '*.db' -o -name '*.sqlite*' \) 2>/dev/null)
  for f in "${keep[@]}"; do prune+=(-path "$f" -o); done
  unset 'prune[${#prune[@]}-1]'

  mapfile -t own < <(find "$rc" \( "${prune[@]}" \) -prune -o \( -user "$wu" -o \( -group "$wg" -perm -g+w \) -o -perm -o+w \) -print 2>/dev/null)
  if ((${#own[@]})); then
    finding "${#own[@]} files or folders in $rc can be changed by $wu (a webshell could rewrite Roundcube)"
    printf '      %s\n' "${own[@]:0:5}"
    ((${#own[@]} > 5)) && info "      ... and $((${#own[@]} - 5)) more"
    if ask "Make root own Roundcube's code? ${keep[*]#"$rc/"} stay writable by $wu." Y; then
      find "$rc" -printf '%u:%g %m %p\n' > "$STEP_DIR/roundcube-ownership.txt"
      chown -R root:root "$rc" && chmod -R go-w "$rc"
      for f in "${keep[@]}"; do [[ -d $f ]] && chown -R "$wu:$wg" "$f"; done
      [[ -f $cfg ]] && chown "root:$wg" "$cfg" && chmod 640 "$cfg"
      action "Roundcube code now owned by root; writable by $wu: ${keep[*]}"
      if ! health_check; then
        while read -r line f; do
          chown -h "${line%% *}" "$f" 2>/dev/null
        done < <(awk '{print $1, substr($0, index($0,$3))}' "$STEP_DIR/roundcube-ownership.txt")
        while read -r line f; do
          [[ -L $f ]] || chmod "$line" "$f" 2>/dev/null
        done < <(awk '{print $2, substr($0, index($0,$3))}' "$STEP_DIR/roundcube-ownership.txt")
        action "Restored Roundcube's original owners and permissions: webmail broke"
      fi
    fi
  else
    ok "$wu can only write to: ${keep[*]}"
  fi

  if [[ -f $cfg ]]; then
    if [[ $(stat -c '%a %U:%G' "$cfg") != "640 root:$wg" ]]; then
      finding "$cfg (database password, des_key) is $(stat -c '%a %U:%G' "$cfg"), expected 640 root:$wg"
      if ask "Fix it?" Y; then
        line="$(stat -c '%a %U:%G' "$cfg")"
        chown "root:$wg" "$cfg" && chmod 640 "$cfg" && action "Set $cfg to 640 root:$wg"
        if ! health_check; then
          chown "${line#* }" "$cfg"; chmod "${line%% *}" "$cfg"
          action "Restored $cfg to $line: webmail broke"
        fi
      fi
    else
      ok "config.inc.php is 640 root:$wg"
    fi
  fi

  n=0
  while read -r f; do
    n=1
    finding "PHP file in a folder the web server writes to: $f (owner $(stat -c %U "$f"), changed $(stat -c %y "$f" | cut -d. -f1))"
    if ask "Quarantine it? (moved to the rollback folder, hash recorded)" Y; then
      mkdir -p "$STEP_DIR/quarantine"
      sha256sum "$f" >> "$STEP_DIR/quarantine/hashes.txt"
      line="$STEP_DIR/quarantine/$(date +%s)-$(basename "$f")"
      mv "$f" "$line" && chmod 000 "$line" && action "Quarantined $f (now $line)"
    fi
  done < <(find "${keep[@]}" -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.pht' \) 2>/dev/null)
  ((n)) || ok "No PHP files in ${keep[*]}"

  while IFS= read -r line; do
    finding "Apache is told to run other files as PHP (report only): $line"
  done < <(
    grep -rnisE '^[[:space:]]*(AddHandler|SetHandler|AddType|ForceType)\b.*(php|x-httpd)' "$rc" /var/www --include='.htaccess' 2>/dev/null
    grep -rnisE '^[[:space:]]*(AddHandler|AddType|ForceType)\b.*(php|x-httpd)' /etc/apache2/sites-enabled /etc/apache2/conf-enabled 2>/dev/null
  )
}

apache_reload() {
  if [[ -d /run/systemd/system ]]; then systemctl reload apache2; else apache2ctl graceful; fi
}

mail_apache() {
  local mods m n
  have apache2ctl || return 0
  sub "Apache modules"
  mods="$(apache2ctl -M 2>/dev/null)"
  n=0
  for m in passenger fcgid; do
    grep -q "${m}_module" <<< "$mods" || continue
    n=1
    finding "Apache module $m is loaded but nothing on a Roundcube box uses it (extra attack surface)"
    if ask "Disable it (a2dismod $m)? Webmail is re-checked and it's turned back on if anything breaks." N; then
      a2dismod -q "$m" >/dev/null 2>&1
      if apache2ctl configtest >/dev/null 2>&1 && apache_reload >/dev/null 2>&1 && sleep 2 && health_check; then
        action "Disabled Apache module $m"
      else
        a2enmod -q "$m" >/dev/null 2>&1; apache_reload >/dev/null 2>&1
        action "Re-enabled Apache module $m: disabling it broke something"
      fi
    fi
  done
  ((n)) || ok "No unused passenger/fcgid modules loaded"
}

check_logs() {
  sub "Logs"
  local storage
  have rsyslogd || info "No rsyslog: there is no /var/log/syslog, auth.log or mail.log here. Use journalctl."
  storage="$(grep -hE '^[[:space:]]*Storage=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null | tail -n1 | cut -d= -f2)"
  if [[ $storage == volatile || $storage == none ]]; then
    finding "journald is set to Storage=$storage: logs are lost on reboot (or never kept). Fix by hand in /etc/systemd/journald.conf"
  elif [[ -d /var/log/journal ]]; then
    ok "Logs are saved to disk and survive a reboot (/var/log/journal)"
  else
    finding "Logs are kept in memory only: a reboot wipes all evidence"
    if ask "Keep logs on disk from now on (create /var/log/journal)?" Y; then
      mkdir -p /var/log/journal
      systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1
      journalctl --flush >/dev/null 2>&1
      action "Created /var/log/journal: logs now survive reboots"
    fi
  fi
}

step_mail() {
  begin_step 8 "Mail stack and logs"
  local rc
  rc="$(find_roundcube)"
  if ! have postconf && ! have doveconf && [[ -z $rc ]]; then
    ok "No Postfix, Dovecot or Roundcube on this box. Skipping the mail checks."
  else
    have postconf && mail_postfix
    have doveconf && mail_dovecot
    [[ -n $rc ]] && mail_roundcube "$rc"
    mail_apache
  fi
  check_logs
  health_check && ok "Scored services still answer."
}

step_summary() {
  section "Summary"
  if [[ $MODE == run ]]; then
    { getent passwd; getent group; } > "$BASE_DIR/accounts-baseline.txt"
    chmod 600 "$BASE_DIR/accounts-baseline.txt"
    info "Account baseline saved. Every 30 minutes run:"
    info "  sudo diff $BASE_DIR/accounts-baseline.txt <({ getent passwd; getent group; })"
  fi
  info "Took $((SECONDS / 60))m $((SECONDS % 60))s. $FINDING_COUNT findings."
  info "Findings and actions, timestamped: $FINDINGS"
  info "Full log: $LOG"
  info "Copies of everything changed: $RUN_DIR/rollback/"
  [[ -f $PCR_FILE ]] && warn "Submit $PCR_FILE in Quotient PCR, then: sudo shred -u $PCR_FILE"
  info "Blocked packets: sudo journalctl -k | grep 'UFW BLOCK'"
  info "Next: log in from a second window, check Quotient, then hunt persistence"
  info "(cron, systemd timers, webshells, planted packages), then: sudo ./baseline.sh save"
}

main() {
  case $MODE in
    run|check) ;;
    -h|--help|help) sed -n '3,/^# ====/p' "$0"; exit 0 ;;
    *) echo "Usage: sudo $0 [run|check]"; exit 1 ;;
  esac
  if [[ $EUID -ne 0 ]]; then echo "Run with sudo: sudo $0 $MODE" >&2; exit 1; fi
  mkdir -p "$RUN_DIR" && chmod 700 "$BASE_DIR" "$RUN_DIR"
  touch "$FINDINGS" && chmod 600 "$FINDINGS"
  exec > >(tee -a "$LOG") 2>&1

  section "dropflag.sh  mode=$MODE  host=$(hostname)  $(date)"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    info "OS: ${PRETTY_NAME:-unknown}"
    [[ ${VERSION_ID:-} == 22.04 ]] || warn "Written for Ubuntu 22.04. Read each prompt carefully on other versions."
  fi
  info "Admin account: ${ADMIN:-unknown (logged in as root?)}   your terminal: ${MY_TTY:-unknown}"
  [[ $MODE == check ]] && info "CHECK MODE: nothing will be changed."

  step_baseline
  step_sessions
  step_passwords
  step_root
  step_users
  step_ssh
  step_ports
  step_firewall
  step_mail
  step_summary
  sleep 0.3   # let the log finish writing before the prompt returns
}

# Run main only when executed, so the functions can be loaded for testing.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
