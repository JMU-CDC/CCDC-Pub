#!/usr/bin/env bash
# =============================================================================
#  webmail-5min.sh - MACCDC first-5-minutes script for a Fedora webmail box
#                    (Postfix + Dovecot + Apache/PHP webmail such as Roundcube)
#
#  Run as root:   bash webmail-5min.sh              scan, then hardening menu
#                 bash webmail-5min.sh --scan-only  read-only scan + flag list
#
#  Ground rules this script keeps:
#    * The scan is read-only. It only writes its own report folder
#      ($CCDC_DIR, default /root/.ccdc/<timestamp>).
#    * Nothing on the system changes unless you answer "y". Prompts default to No.
#    * You type every password into passwd / chpasswd / mysql's own prompts.
#      The script never sees, stores or prints them.
#    * Nothing is deleted. "Removed" files are moved to a quarantine folder.
#    * Firewall changes roll back on their own after ROLLBACK_SECS (default 60)
#      unless you type "keep". The rollback survives a dropped SSH session.
#
#  THE 5-MINUTE PLAN
#    0:00  Log in on the console. Run the script. Accept the backup prompt.
#    0:30  Scan runs (about 1 min). Read the FLAG SUMMARY.
#    1:30  [1] Passwords: root and your admin first. Change scored mail users
#              only with a Password Change Request (PCR) to the White Team.
#    2:00  [2] Kill flagged shells/sessions   [3] Accounts, sudo, SSH keys
#    2:45  [4] Firewall allowlist (auto-rollback)
#    3:30  [5] Postfix relay/BCC/forwards     [6] Dovecot auth backdoors
#    4:15  [7] Webmail installer/webshells    [8] Cron/systemd persistence
#    4:45  [v] Verify SMTP/POP3/IMAP/HTTP still answer. Copy the report
#              folder off the box. Then work the rest of the menu.
# =============================================================================

VERSION=1.0
BASE_DIR=${CCDC_DIR:-/root/.ccdc}
ROLLBACK_SECS=${ROLLBACK_SECS:-60}
[[ $ROLLBACK_SECS =~ ^[0-9]+$ ]] && (( ROLLBACK_SECS >= 30 )) || ROLLBACK_SECS=60
TS=$(date +%Y%m%d-%H%M%S)
OUT=$BASE_DIR/$TS
REPORT=$OUT/scan-report.txt
FLAGFILE=$OUT/flags.txt
ACTLOG=$OUT/actions.log
QUAR=$OUT/quarantine
BACKUP=$OUT/backup
TTY=/dev/tty
EDITOR_CMD=${EDITOR:-vi}

# TCP ports a webmail box is expected to serve. Any other port listening on a
# non-loopback address gets flagged.
MAIL_PORTS="22 25 80 110 143 443 465 587 993 995 4190"
UDP_OK="68 123 323 546"
CORE_SVCS="postfix dovecot httpd"

# Strings that show up in PHP webshells, not in normal webmail code.
WEBSHELL_RE='eval *\( *(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|\$_(GET|POST|REQUEST|COOKIE|SERVER))|(system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec|assert|create_function) *\( *\$_(GET|POST|REQUEST|COOKIE|SERVER)|\$_(GET|POST|REQUEST|COOKIE)\[[^]]{0,40}\] *\(|base64_decode *\( *\$_(GET|POST|REQUEST|COOKIE)|` *\$_(GET|POST|REQUEST|COOKIE)|gzinflate *\( *base64_decode|move_uploaded_file *\( *\$_FILES|FilesMan|b374k|weevely|p0wny|c99shell|r57shell'

if [[ -t 1 ]]; then
  R=$'\e[1;31m'; Y=$'\e[1;33m'; G=$'\e[1;32m'; B=$'\e[1;36m'; N=$'\e[0m'
else
  R=; Y=; G=; B=; N=
fi

# ---- state collected by the scan, used by the menu ---------------------------
FLAGS=(); SECTION=""
declare -A EXE
UID0_USERS=(); EMPTY_PW_USERS=(); SHELL_USERS=(); SYS_SHELL_USERS=(); HUMAN_USERS=()
SUDO_FLAG_FILES=(); AUTH_KEYS=(); SUS_PROCS=(); LISTEN_PORTS=(); SUID_FLAG_FILES=()
CRON_FLAG_FILES=(); UNIT_FLAG_FILES=(); SHELLRC_FLAG_FILES=(); IMMUTABLE_FILES=(); TMP_FLAG_FILES=()
FORWARD_FILES=(); SIEVE_FLAG_FILES=(); PF_MAP_FLAG_FILES=(); DC_HITS=(); WEBSHELLS=()
UNNEEDED_SVCS=(); WEBROOTS=()
FW=none; SSHD_T=""
RC_DIR=""; RC_CONF=""; RC_DBUSER=""
RC_INSTALLER_ON=0; RC_DESKEY_DEFAULT=0; RC_CONF_WORLD=0; SQM_FOUND=0
ALIAS_FLAG=0; PRELOAD_FLAG=0; CRONTAB_FLAG=0; RCLOCAL_FLAG=0; RCLOCAL_FILE=""
SSH_AKF_FLAG=0; SSH_AKC_FLAG=0; DC_PWLOG=0

# ---- output helpers ------------------------------------------------------------
rep()     { printf '%s\n' "$*" >>"$REPORT"; }
section() { SECTION=$1; printf '\n%s=== %s ===%s\n' "$B" "$1" "$N"; rep ""; rep "=== $1 ==="; }
hdr()     { printf '\n%s--- %s ---%s\n' "$B" "$1" "$N"; rep ""; rep "--- $1 ---"; }
info()    { printf '  %s\n' "$*"; rep "  $*"; }
good()    { printf '  %s[ok]%s %s\n' "$G" "$N" "$*"; rep "  [ok] $*"; }
note()    { printf '  %s[i]%s %s\n' "$Y" "$N" "$*"; rep "  [i] $*"; }
flag()    { FLAGS+=("[$SECTION] $*"); printf '  %s[!]%s %s\n' "$R" "$N" "$*"; rep "  [!] $*"; }
warn()    { printf '  %s[!]%s %s\n' "$R" "$N" "$*"; rep "  [!] $*"; }
show()    { sed 's/^/      /' | cut -c1-220 | tee -a "$REPORT"; }    # indent stdin to screen + report
act()     { printf '%s  %s\n' "$(date '+%F %T')" "$*" >>"$ACTLOG"; }   # every change lands here
have()    { command -v "$1" >/dev/null 2>&1; }

# ---- prompts (always read the terminal, never stdin) --------------------------
confirm() {          # y/N, default No
  local a
  read -r -p "  ${Y}?${N} $1 [y/N] " a <"$TTY" || { echo; return 1; }
  [[ $a == [yY]* ]]
}
confirm_yes() {      # Y/n, only for non-invasive steps (backups)
  local a
  read -r -p "  ${Y}?${N} $1 [Y/n] " a <"$TTY" || { echo; return 1; }
  [[ -z $a || $a == [yY]* ]]
}
EACH_ALL=0; EACH_STOP=0
each_reset() { EACH_ALL=0; EACH_STOP=0; }
each() {             # per-item prompt for lists: y / N / a = yes to the rest / q = skip the rest
  (( EACH_ALL )) && return 0
  (( EACH_STOP )) && return 1
  local a
  read -r -p "  ${Y}?${N} $1 [y/N/a=all/q=skip rest] " a <"$TTY" || { echo; return 1; }
  case $a in
    [yY]*) return 0 ;;
    [aA]*) EACH_ALL=1; return 0 ;;
    [qQ]*) EACH_STOP=1; return 1 ;;
  esac
  return 1
}
ask() {              # ask "prompt" -> prints the answer
  local a
  read -r -p "$1" a <"$TTY" || return 1
  printf '%s' "$a"
}
on_tty() { "$@" <"$TTY" >"$TTY" 2>&1; }      # passwd, vi, visudo, curl -u ...
edit() {             # edit <file>; returns 0 only if the file changed
  local f=$1 before
  before=$(md5sum <"$f" 2>/dev/null)
  # shellcheck disable=SC2086  # EDITOR may carry flags
  on_tty $EDITOR_CMD "$f"
  if [[ $(md5sum <"$f" 2>/dev/null) != "$before" ]]; then act "EDITED $f"; return 0; fi
  return 1
}
quarantine() {       # move a file/dir into $QUAR keeping its full path; never deletes
  local f=$1 dest=$QUAR$1
  mkdir -p "$(dirname "$dest")"
  if mv -f -- "$f" "$dest" 2>/dev/null; then
    act "QUARANTINED $f -> $dest"; good "moved $f -> $dest"
  else
    warn "could not move $f (immutable? check: lsattr -d '$f')"
  fi
}

# ---- small utilities -----------------------------------------------------------
unowned() {          # print the arguments that no RPM package owns
  (( $# )) || return 0
  printf '%s\0' "$@" | xargs -0 rpm -qf 2>&1 | sed -n 's/^file \(.*\) is not owned by any package$/\1/p'
}
real_dirs()   { local d; for d in "$@"; do [[ -d $d ]] && readlink -f "$d"; done | sort -u; }
unit_exists() { systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1\.service"; }
svc_state() {        # systemd state, or a process check where systemd isn't running
  local s
  if [[ -d /run/systemd/system ]]; then s=$(systemctl is-active "$1" 2>/dev/null); echo "${s:-unknown}"; return; fi
  case $1 in postfix) s=master ;; mariadb|mysqld|mysql) s='mariadbd|mysqld' ;; *) s=$1 ;; esac
  if pgrep -x "$s" >/dev/null 2>&1; then echo active; else echo inactive; fi
}
ver_lt()      { [[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1) == "$1" ]]; }
sshv()        { awk -v k="$1" 'tolower($1)==k { $1=""; sub(/^ +/, ""); print; exit }' <<<"$SSHD_T"; }
pcn()         { postconf -n "$1" 2>/dev/null | sed 's/^[^=]*= *//'; }   # only explicitly-set postfix params
pch()         { postconf -xh "$1" 2>/dev/null || postconf -h "$1" 2>/dev/null; }  # value with $vars expanded (-x: postfix 2.10+)
pfmaps()      { grep -oE '(hash|lmdb|btree|cdb|dbm|texthash|regexp|pcre|cidr):/[^ ,]+' <<<"$1"; }
relay_ok() {         # does a restriction list reach *_unauth_destination before a bare "permit"?
  local t
  for t in ${1//,/ }; do
    [[ $t == permit ]] && return 1
    [[ $t == *_unauth_destination ]] && return 0
  done
  return 1
}
keys_summary() {
  awk '/^[[:space:]]*(#|$)/ { next }
       { for (i = 1; i <= NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) {
           c = ""; for (j = i + 2; j <= NF; j++) c = c " " $j
           print $i c ((i > 1) ? "   [options: " $1 "]" : ""); next }
         print "unparsed: " substr($0, 1, 80) }' "$1"
}

# ---- auto-rollback for firewall changes ---------------------------------------
RB_CMD=""; RB_PIDFILE=""
arm_rollback() {     # run "$1" after ROLLBACK_SECS unless disarmed; detached from this terminal
  RB_CMD=$1; RB_PIDFILE=$OUT/rollback.pid
  rm -f "$RB_PIDFILE"
  nohup setsid bash -c 'echo $$ >"$1"; sleep "$2"; eval "$3"; echo "$(date "+%F %T")  AUTO-ROLLBACK ran: $3" >>"$4"' \
    _ "$RB_PIDFILE" "$ROLLBACK_SECS" "$RB_CMD" "$ACTLOG" >/dev/null 2>&1 </dev/null &
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do [[ -s $RB_PIDFILE ]] && break; sleep 0.2; done
  note "auto-rollback armed: it runs in ${ROLLBACK_SECS}s unless you type 'keep'"
}
disarm_rollback() {
  local p
  p=$(cat "$RB_PIDFILE" 2>/dev/null)
  [[ -n $p ]] && { kill -TERM -- "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null; }
  rm -f "$RB_PIDFILE"
}
keep_or_rollback() { # $1 = command that makes the change permanent
  local a t=$(( ROLLBACK_SECS - 10 ))
  printf '\n  %sCheck from another machine now: does SSH still work? is scoring still green?%s\n' "$Y" "$N"
  if read -r -t "$t" -p "  Type 'keep' within ${t}s to keep it (anything else or timeout = roll back): " a <"$TTY" && [[ $a == keep ]]; then
    disarm_rollback
    if [[ $1 == true ]]; then good "kept (runtime only)"; act "FIREWALL kept (runtime only)"
    elif eval "$1"; then good "kept and saved"; act "FIREWALL kept and saved ($1)"
    else warn "kept for now, but saving failed: $1"; act "FIREWALL kept, save failed ($1)"; fi
  else
    echo; disarm_rollback; eval "$RB_CMD"; warn "rolled back"; act "FIREWALL rolled back"
  fi
}

# =============================================================================
#  SCAN (read-only)
# =============================================================================
scan_system() {
  section "System"
  local os h
  os=$( . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" )
  [[ -z $os ]] && os=$(cat /etc/redhat-release 2>/dev/null)
  info "Host: $(hostname)   OS: ${os:-unknown}   Kernel: $(uname -r)"
  info "Up: $(uptime | sed 's/^ *//')"
  info "IPv4: $(ip -4 -o addr show 2>/dev/null | awk '$2!="lo"{printf "%s=%s  ", $2, $4}')"
  info "Default route: $(ip route show default 2>/dev/null | head -n1)"
  info "DNS servers: $(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf 2>/dev/null)"
  h=$(grep -vE '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null | grep -vE '^[[:space:]]*(127\.|::1|fe00::|ff0[0-9]::)')
  if [[ -n $h ]]; then note "/etc/hosts has custom entries (check for hijacked names):"; show <<<"$h"; fi
}

scan_accounts() {
  section "Accounts & authentication"
  local u pw uid shell lc st line f body norm table="" files=() pdirs=()

  mapfile -t UID0_USERS < <(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
  if (( ${#UID0_USERS[@]} )); then flag "UID 0 accounts besides root: ${UID0_USERS[*]}"; else good "only root has UID 0"; fi

  line=$(cut -d: -f3 /etc/passwd | sort | uniq -d | grep -vx 0 | tr '\n' ' ')
  [[ -n ${line// } ]] && flag "duplicate UIDs: $line"

  mapfile -t EMPTY_PW_USERS < <(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null)
  (( ${#EMPTY_PW_USERS[@]} )) && flag "EMPTY password (no password needed to log in): ${EMPTY_PW_USERS[*]}"

  line=$( { find /etc/shadow /etc/gshadow -perm /o+r; find /etc/passwd /etc/group /etc/shadow /etc/sudoers -perm /go+w; } 2>/dev/null | sort -u | tr '\n' ' ')
  [[ -n ${line// } ]] && flag "bad permissions on: $line"

  SHELL_USERS=(); SYS_SHELL_USERS=(); HUMAN_USERS=()
  while IFS=: read -r u _ uid _ _ _ shell; do
    local has_shell=1
    case $shell in */nologin|*/false|*/sync|*/shutdown|*/halt|"") has_shell=0 ;; esac
    (( has_shell )) && SHELL_USERS+=("$u")
    (( has_shell && uid > 0 && uid < 1000 )) && SYS_SHELL_USERS+=("$u")
    (( uid >= 1000 && uid < 60000 )) && HUMAN_USERS+=("$u")
    if (( has_shell || (uid >= 1000 && uid < 60000) )); then
      pw=$(awk -F: -v u="$u" '$1==u{print $2; exit}' /etc/shadow 2>/dev/null)
      lc=$(awk -F: -v u="$u" '$1==u{print $3; exit}' /etc/shadow 2>/dev/null)
      case $pw in "") st="EMPTY" ;; '!'*|'*'*) st="locked/none" ;; *) st="set" ;; esac
      [[ $lc =~ ^[0-9]+$ ]] && lc=$(date -d "@$((lc * 86400))" +%F 2>/dev/null)
      table+=$(printf '%-16s uid=%-6s shell=%-15s pw=%-11s changed=%-10s groups=%s' \
        "$u" "$uid" "$shell" "$st" "${lc:--}" "$(id -nG "$u" 2>/dev/null | tr ' ' ',')")$'\n'
    fi
  done </etc/passwd
  info "Users that can log in (shell) or are regular users (UID>=1000):"
  show <<<"${table%$'\n'}"
  for u in "${SYS_SHELL_USERS[@]}"; do flag "system account '$u' (UID<1000) has a login shell"; done
  for u in wheel adm sudo; do
    line=$(getent group "$u" | cut -d: -f4)
    [[ -n $line ]] && info "group $u: $line"
  done

  # sudo: anything beyond the stock root/%wheel rules
  SUDO_FLAG_FILES=()
  while IFS= read -r line; do
    f=${line%%:*}; body=${line#*:*:}
    norm=$(tr -s ' \t' ' ' <<<"$body" | sed 's/^ //; s/ $//')
    case $norm in
      "root ALL=(ALL) ALL"|"root ALL=(ALL:ALL) ALL"|"%wheel ALL=(ALL) ALL"|"%wheel ALL=(ALL:ALL) ALL") continue ;;
    esac
    if [[ $norm == *NOPASSWD* ]]; then flag "sudo NOPASSWD rule: $line"; else flag "non-default sudo rule: $line"; fi
    [[ $f == /etc/sudoers.d/* && " ${SUDO_FLAG_FILES[*]} " != *" $f "* ]] && SUDO_FLAG_FILES+=("$f")
  done < <(grep -HnvE '^[[:space:]]*(#|$)|^[[:space:]]*(Defaults|@include)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null)
  while IFS= read -r f; do
    flag "sudoers file not from any package: $f"
    [[ " ${SUDO_FLAG_FILES[*]} " != *" $f "* ]] && SUDO_FLAG_FILES+=("$f")
  done < <(unowned /etc/sudoers.d/*)

  # PAM backdoors
  line=$(grep -HnE '^[[:space:]]*-?auth[[:space:]]+[^#]*pam_permit\.so' /etc/pam.d/* 2>/dev/null)
  [[ -n $line ]] && { flag "PAM auth line uses pam_permit (accepts ANY password):"; show <<<"$line"; }
  line=$(grep -HnE '^[^#]*pam_exec\.so' /etc/pam.d/* 2>/dev/null)
  [[ -n $line ]] && { flag "PAM pam_exec runs a program at login (can capture passwords):"; show <<<"$line"; }
  mapfile -t files < <(find /etc/pam.d -maxdepth 1 -type f 2>/dev/null)
  line=$(unowned "${files[@]}" | tr '\n' ' ')
  [[ -n ${line// } ]] && flag "PAM config files not from any package: $line"
  mapfile -t pdirs < <(real_dirs /usr/lib64/security /lib64/security /usr/lib/security /lib/security)
  if (( ${#pdirs[@]} )); then
    mapfile -t files < <(find "${pdirs[@]}" -maxdepth 1 -type f -name '*.so' 2>/dev/null)
    line=$(unowned "${files[@]}" | tr '\n' ' ')
    [[ -n ${line// } ]] && flag "PAM modules not from any package (backdoor?): $line"
  fi
}

scan_ssh() {
  section "SSH"
  local v f u home
  if have sshd; then
    SSHD_T=$(sshd -T 2>/dev/null)
    if [[ -z $SSHD_T ]]; then
      note "sshd -T failed; reading sshd_config directly (first match wins)"
      SSHD_T=$(grep -hvE '^[[:space:]]*(#|$)' /etc/ssh/sshd_config 2>/dev/null)
    fi
    v=$(sshv permitrootlogin)
    case $v in
      yes) flag "PermitRootLogin yes" ;;
      no)  good "PermitRootLogin no" ;;
      "")  note "PermitRootLogin not set (old OpenSSH defaults to yes)" ;;
      *)   note "PermitRootLogin $v" ;;
    esac
    [[ $(sshv permitemptypasswords) == yes ]] && flag "PermitEmptyPasswords yes"
    [[ $(sshv permituserenvironment) == yes ]] && flag "PermitUserEnvironment yes"
    v=$(sshv authorizedkeysfile)
    if [[ -n $v && $v != ".ssh/authorized_keys .ssh/authorized_keys2" && $v != ".ssh/authorized_keys" ]]; then
      flag "AuthorizedKeysFile is non-default: $v"; SSH_AKF_FLAG=1
    fi
    v=$(sshv authorizedkeyscommand)
    [[ -n $v && $v != none ]] && { flag "AuthorizedKeysCommand set: $v"; SSH_AKC_FLAG=1; }
    info "Port $(sshv port) | PasswordAuthentication $(sshv passwordauthentication) | PubkeyAuthentication $(sshv pubkeyauthentication) | X11Forwarding $(sshv x11forwarding) | AllowUsers $(sshv allowusers)"
    v=$(grep -nE '^[[:space:]]*Match' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null)
    [[ -n $v ]] && { note "sshd Match blocks (override settings for some users/hosts):"; show <<<"$v"; }
    v=$(unowned /etc/ssh/sshd_config.d/*.conf | tr '\n' ' ')
    [[ -n ${v// } ]] && note "sshd_config.d files not from a package: $v"
  else
    note "sshd not installed"
  fi

  AUTH_KEYS=()
  while IFS=: read -r u _ _ _ _ home _; do
    [[ -n $home ]] || continue
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [[ -s $f && " ${AUTH_KEYS[*]} " != *" $f "* ]] && AUTH_KEYS+=("$f")
    done
  done < <(getent passwd)
  (( ${#AUTH_KEYS[@]} )) || good "no authorized_keys files"
  for f in "${AUTH_KEYS[@]}"; do
    flag "SSH keys in $f ($(grep -cvE '^[[:space:]]*(#|$)' "$f") key(s)): whoever holds them gets in"
    keys_summary "$f" | show
  done
}

scan_network() {
  section "Listening ports"
  LISTEN_PORTS=()
  local proto laddr proc port addr pname pid desc line est
  while read -r proto _ _ _ laddr _ proc; do
    [[ $proto == tcp || $proto == udp ]] || continue
    port=${laddr##*:}; addr=${laddr%:*}
    pname=$(grep -o '"[^"]*"' <<<"$proc" | head -n1 | tr -d '"')
    pid=$(grep -o 'pid=[0-9]*' <<<"$proc" | head -n1 | cut -d= -f2)
    desc=$(printf '%-3s %-26s %s[%s]' "$proto" "$laddr" "${pname:-?}" "${pid:-?}")
    if [[ $addr =~ ^(127\.|\[?::1\]?$|\[::ffff:127\.) ]]; then info "local-only  $desc"; continue; fi
    if [[ $proto == tcp ]]; then
      if [[ " $MAIL_PORTS " == *" $port "* ]]; then info "expected    $desc"; LISTEN_PORTS+=("$port")
      else flag "unexpected TCP listener: $desc"; fi
    else
      if [[ " $UDP_OK " == *" $port "* ]]; then info "expected    $desc"
      else flag "unexpected UDP listener: $desc"; fi
    fi
  done < <(ss -tulpn 2>/dev/null)
  mapfile -t LISTEN_PORTS < <(printf '%s\n' "${LISTEN_PORTS[@]}" | sed '/^$/d' | sort -nu)

  section "Established connections"
  est=$(ss -tunp state established 2>/dev/null | tail -n +2)
  if [[ -z $est ]]; then info "none"; else show <<<"$est"; fi
  while IFS= read -r line; do
    [[ -z $line ]] && continue
    pname=$(grep -o '(("[^"]*"' <<<"$line" | head -n1 | tr -d '("')
    case $pname in
      bash|sh|dash|zsh|ksh|nc|ncat|netcat|socat|python*|perl|php|ruby|telnet|openssl|awk|gawk|lua)
        flag "shell/interpreter holds a network connection: $(tr -s ' ' <<<"$line")" ;;
    esac
  done <<<"$est"

  section "Firewall"
  local z zones v
  if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    FW=firewalld
    good "firewalld running, default zone $(firewall-cmd --get-default-zone 2>/dev/null)"
    zones=$(firewall-cmd --get-active-zones 2>/dev/null | awk '!/^[[:space:]]/{print $1}')
    for z in $zones; do
      firewall-cmd --zone="$z" --list-all 2>/dev/null | show
      v=$(firewall-cmd --zone="$z" --list-rich-rules 2>/dev/null)
      [[ -n $v ]] && { flag "rich rules in zone $z (review):"; show <<<"$v"; }
      v=$(firewall-cmd --zone="$z" --list-forward-ports 2>/dev/null)
      [[ -n $v ]] && { flag "port forwards in zone $z:"; show <<<"$v"; }
      [[ $(firewall-cmd --permanent --zone="$z" --get-target 2>/dev/null) == ACCEPT ]] && \
        flag "zone $z accepts everything (target ACCEPT), interfaces: $(firewall-cmd --zone="$z" --list-interfaces 2>/dev/null)"
    done
    v=$(firewall-cmd --zone=trusted --list-sources 2>/dev/null)
    [[ -n ${v//[[:space:]]} ]] && flag "firewalld 'trusted' zone sources bypass the firewall: $v"
  elif have iptables; then
    FW=iptables
    local pol n
    pol=$(iptables -S INPUT 2>/dev/null | awk '$1=="-P"{print $3}')
    n=$(iptables -S INPUT 2>/dev/null | grep -c '^-A')
    if [[ $pol == ACCEPT && $n == 0 ]]; then flag "NO host firewall (iptables INPUT policy ACCEPT, no rules)"
    else info "iptables INPUT policy $pol, $n rules:"; iptables -S INPUT 2>/dev/null | show; fi
    have firewall-cmd && note "firewalld is installed but stopped; the menu uses iptables so nothing blocks scoring by surprise"
  else
    FW=none; flag "no firewall tool found (firewall-cmd / iptables)"
  fi
}

scan_procs() {
  section "Processes"
  SUS_PROCS=()
  EXE=()
  local d exe pid user args comm why
  local re_tcp='/dev/(tcp|udp)/'
  local re_nc='(^|[/[:space:]])(nc|ncat|netcat)([[:space:]]|$)'
  local re_socat='(^|[/[:space:]])socat([[:space:]]|$)'
  local re_fifo='mkfifo|mknod[[:space:]].*[[:space:]]p([[:space:]]|$)'
  local re_inline='(^|[/[:space:]])(python[0-9.]*|perl|ruby|php|lua)[[:space:]]+-[a-zA-Z]*[ecr]([[:space:]]|$)'
  local re_dl='(curl|wget)[^|]*\|[[:space:]]*(ba|z|da)?sh'
  local re_b64='base64[[:space:]]+(-d|--decode)'
  local re_rtun='(^|[/[:space:]])ssh[[:space:]].*-[a-zA-Z]*R[[:space:]]'
  local re_tools='msfconsole|meterpreter|sliver|chisel|ligolo|gs-netcat|gsocket|frpc|xmrig|minerd|pspy|linpeas|reptile'

  while IFS=$'\t' read -r d exe; do EXE[${d#/proc/}]=$exe; done \
    < <(find /proc -mindepth 2 -maxdepth 2 -name exe -printf '%h\t%l\n' 2>/dev/null)

  while read -r pid user args; do
    [[ $pid == "$$" || $pid == "$BASHPID" ]] && continue
    exe=${EXE[$pid]}
    [[ -z $exe ]] && continue                      # kernel thread
    comm=""; read -r comm 2>/dev/null <"/proc/$pid/comm"
    why=""
    case $exe in
      *" (deleted)") why="binary was deleted from disk" ;;
      /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*|*/.*/*) why="runs from $(dirname "$exe")" ;;
    esac
    [[ -z $why && $args == "["* ]] && why="user process disguised as a kernel thread"
    if [[ -z $why ]]; then
      if   [[ $args =~ $re_tcp ]];    then why="bash /dev/tcp reverse shell"
      elif [[ $args =~ $re_nc ]];     then why="netcat"
      elif [[ $args =~ $re_socat ]];  then why="socat"
      elif [[ $args =~ $re_fifo ]];   then why="named-pipe shell"
      elif [[ $args =~ $re_inline ]]; then why="inline interpreter one-liner"
      elif [[ $args =~ $re_dl ]];     then why="download piped into a shell"
      elif [[ $args =~ $re_b64 ]];    then why="base64 decoding"
      elif [[ $args =~ $re_rtun ]];   then why="SSH reverse tunnel"
      elif [[ $args =~ $re_tools ]];  then why="known offensive tool name"
      fi
    fi
    if [[ -z $why ]]; then
      case $user in
        apache|nginx|www-data|http|postfix|dovecot|dovenull|mail|nobody|mysql|named|ftp)
          case $comm in
            bash|sh|dash|zsh|ksh|tcsh|csh|python*|perl|ruby|nc|ncat|socat|telnet|php)
              why="service account '$user' running $comm (webshell?)" ;;
          esac ;;
      esac
    fi
    if [[ -n $why ]]; then
      SUS_PROCS+=("$pid")
      flag "PID $pid ($user) $why: ${args:0:150}"
    fi
  done < <(ps -eo pid=,user:32=,args= 2>/dev/null)
  (( ${#SUS_PROCS[@]} )) || good "no suspicious processes matched"

  section "Logged-in sessions"
  local w
  w=$(who 2>/dev/null)
  if [[ -n $w ]]; then show <<<"$w"; else info "none"; fi
  info "this script is on terminal: $(ps -o tty= -p $$ 2>/dev/null | tr -d ' ')"
}

scan_persistence() {
  section "Persistence: cron / at / systemd / startup files"
  local f line files=() dirs=() u home re

  CRON_FLAG_FILES=()
  for f in /var/spool/cron/* /var/spool/cron/crontabs/*; do
    [[ -f $f ]] || continue
    flag "user crontab $f:"; grep -vE '^[[:space:]]*(#|$)' "$f" | show
    CRON_FLAG_FILES+=("$f")
  done
  line=$(grep -vE '^[[:space:]]*(#|$)|^[[:space:]]*(SHELL|PATH|MAILTO|HOME)=' /etc/crontab 2>/dev/null)
  if [[ -n $line ]]; then flag "/etc/crontab has jobs:"; show <<<"$line"; CRONTAB_FLAG=1; fi
  mapfile -t files < <(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f 2>/dev/null)
  while IFS= read -r f; do
    flag "cron file not from any package: $f"
    grep -vE '^[[:space:]]*(#|$)' "$f" | head -n 5 | show
    CRON_FLAG_FILES+=("$f")
  done < <(unowned "${files[@]}")
  if have atq; then
    line=$(atq 2>/dev/null)
    [[ -n $line ]] && { flag "queued 'at' jobs:"; show <<<"$line"; }
  fi

  UNIT_FLAG_FILES=()
  mapfile -t dirs < <(real_dirs /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system \
                                /etc/systemd/user /usr/lib/systemd/user /root/.config/systemd/user /home/*/.config/systemd/user)
  if (( ${#dirs[@]} )); then
    mapfile -t files < <(find "${dirs[@]}" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \
                           -o -name '*.path' -o -name '*.conf' \) 2>/dev/null | sort -u)
    while IFS= read -r f; do
      flag "systemd unit not from any package: $f"
      grep -E '^[[:space:]]*(ExecStart|ExecStartPre|ExecStartPost|ExecStop|OnCalendar|OnBootSec|OnUnitActiveSec)=' "$f" | head -n 4 | show
      UNIT_FLAG_FILES+=("$f")
    done < <(unowned "${files[@]}")
  fi
  systemctl list-timers --all --no-pager >>"$REPORT" 2>/dev/null

  for f in /etc/rc.d/rc.local /etc/rc.local; do
    [[ -f $f && ! -L $f ]] || continue
    line=$(grep -vE '^[[:space:]]*(#|$)|^[[:space:]]*(touch /var/lock/subsys/local|exit 0)[[:space:]]*$' "$f")
    [[ -n $line ]] && { flag "$f runs commands at boot:"; show <<<"$line"; RCLOCAL_FLAG=1; RCLOCAL_FILE=$f; }
  done

  if [[ -s /etc/ld.so.preload ]]; then
    flag "/etc/ld.so.preload is set (classic userland rootkit):"; show </etc/ld.so.preload; PRELOAD_FLAG=1
  else
    good "/etc/ld.so.preload empty/absent"
  fi

  # shell startup files: trojan aliases, callbacks, keyloggers
  SHELLRC_FLAG_FILES=()
  re='alias[[:space:]]+(sudo|su|ls|ps|ss|netstat|passwd|cat|top|lsof|who|w|kill|id|grep|find|systemctl)=|/dev/tcp|(^|[;&|[:space:]])(nc|ncat|socat)[[:space:]]|curl[[:space:]]|wget[[:space:]]|base64[[:space:]]+-d|PROMPT_COMMAND|trap[[:space:]].*DEBUG|LD_PRELOAD'
  for f in /etc/profile /etc/bashrc /etc/environment /etc/profile.d/*.sh /root/.bashrc /root/.bash_profile \
           /root/.profile /root/.bash_logout /home/*/.bashrc /home/*/.bash_profile /home/*/.profile /home/*/.bash_logout; do
    [[ -f $f ]] || continue
    line=$(grep -nE "$re" "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#')
    [[ -z $line ]] && continue
    # a stock, unmodified package file (e.g. Fedora's /etc/bashrc PROMPT_COMMAND) is fine
    if rpm -qf "$f" >/dev/null 2>&1 && ! rpm -Vf "$f" 2>/dev/null | grep -q " $f\$"; then continue; fi
    flag "suspicious line(s) in $f:"; show <<<"$line"; SHELLRC_FLAG_FILES+=("$f")
  done
  mapfile -t files < <(find /etc/profile.d -maxdepth 1 -type f 2>/dev/null)
  line=$(unowned "${files[@]}" | tr '\n' ' ')
  [[ -n ${line// } ]] && flag "/etc/profile.d files not from any package: $line"

  # chattr +i is how red team makes your fixes fail
  mapfile -t IMMUTABLE_FILES < <(
    { lsattr -Ra /etc /root /var/spool/cron 2>/dev/null; lsattr -a /usr/bin /usr/sbin /tmp /var/tmp 2>/dev/null; } |
      awk '$1 ~ /^[-a-zA-Z]+$/ && $1 ~ /i/ { $1 = ""; sub(/^ /, ""); print }' | grep -vE '/\.\.?$')
  if (( ${#IMMUTABLE_FILES[@]} )); then
    flag "immutable (chattr +i) files; edits and password changes on them will fail:"
    printf '%s\n' "${IMMUTABLE_FILES[@]}" | show
  fi

  mapfile -t TMP_FLAG_FILES < <(find /tmp /var/tmp /dev/shm -xdev -type f \( -perm /111 -o -name '.*' -o -name '*.sh' \
      -o -name '*.py' -o -name '*.pl' -o -name '*.php' -o -name '*.elf' -o -name '*.so' \) 2>/dev/null |
      grep -vE '^/tmp/\.X[0-9]+-lock$' | head -n 50)
  if (( ${#TMP_FLAG_FILES[@]} )); then
    flag "executable / hidden / script files in temp dirs:"
    for f in "${TMP_FLAG_FILES[@]}"; do ls -la "$f" 2>/dev/null; done | show
  fi
}

scan_integrity() {
  section "Integrity of key packages (rpm -V)"
  local p pkgs=() v line files=() dirs=() f m nomod=() tainted gtfo
  for p in openssh-server openssh openssh-clients pam sudo shadow-utils passwd coreutils procps-ng procps util-linux \
           iproute net-tools findutils grep sed gawk bash systemd cronie which lsof psmisc postfix dovecot httpd \
           php-cli php-common mod_ssl roundcubemail; do
    rpm -q --quiet "$p" 2>/dev/null && pkgs+=("$p")
  done
  v=$(rpm -V "${pkgs[@]}" 2>/dev/null)
  # (a quarantined Roundcube installer/ shows up as "missing"; that one is expected)
  line=$(awk '($1 ~ /5/ || $1 == "missing") && $2 !~ /^[cdglr]$/ && !($1 == "missing" && $NF ~ /roundcubemail\/installer/)' <<<"$v")
  if [[ -n $line ]]; then flag "package files whose content changed (possible trojans):"; show <<<"$line"
  else good "no changed binaries in: ${pkgs[*]}"; fi
  line=$(awk '$2 == "c" {print $NF}' <<<"$v" | tr '\n' ' ')
  [[ -n ${line// } ]] && note "changed config files (normal on a set-up box, still review): $line"

  section "Executables not owned by any package"
  mapfile -t dirs < <(real_dirs /usr/bin /usr/sbin /bin /sbin /usr/libexec/dovecot /usr/libexec/postfix)
  mapfile -t files < <(find "${dirs[@]}" -maxdepth 1 -type f 2>/dev/null)
  line=$(unowned "${files[@]}")
  if [[ -n $line ]]; then flag "files in system bin dirs that no package installed:"; show <<<"$line"
  else good "every file in ${dirs[*]} belongs to a package"; fi
  line=$(find /usr/local/bin /usr/local/sbin /usr/local/lib /usr/local/lib64 -maxdepth 1 -type f 2>/dev/null)
  [[ -n $line ]] && { flag "files in /usr/local (not from RPM):"; show <<<"$line"; }

  section "SUID/SGID files"
  dirs=(/)
  for f in /home /var /tmp /opt /srv /usr; do
    [[ -d $f && $(stat -c %d "$f") != "$(stat -c %d /)" ]] && dirs+=("$f")
  done
  mapfile -t files < <(find "${dirs[@]}" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort -u)
  SUID_FLAG_FILES=()
  line=$(unowned "${files[@]}")
  if [[ -n $line ]]; then
    flag "SUID/SGID files not from any package:"; show <<<"$line"
    mapfile -t SUID_FLAG_FILES <<<"$line"
  fi
  gtfo='^(bash|sh|dash|zsh|ksh|find|vim?|nano|less|more|python[0-9.]*|perl|ruby|php[0-9.]*|lua|node|awk|gawk|nawk|cp|mv|tar|zip|env|tee|dd|base64|xxd|socat|nc|ncat|wget|curl|git|nmap|gdb|strace|taskset|cpulimit|docker|busybox|openssl|rsync|timeout|xargs|sed|ed|cat|head|tail|chmod|chown)$'
  for f in "${files[@]}"; do
    [[ $(basename "$f") =~ $gtfo ]] || continue
    flag "SUID/SGID on $f: any user can become root with it"
    [[ " ${SUID_FLAG_FILES[*]} " == *" $f "* ]] || SUID_FLAG_FILES+=("$f")
  done
  info "${#files[@]} SUID/SGID files in total (full list in the report)"
  printf '%s\n' "${files[@]}" >>"$REPORT"

  section "Kernel modules"
  if [[ -d /lib/modules/$(uname -r) ]]; then
    while read -r m _; do
      [[ $m == Module || -z $m ]] && continue
      if [[ $m =~ diamorph|reptile|suterusu|adore|knark|kovid|nuk3|azazel|jynx|bdvl|puszek|singularity|caraxes|rootkit ]]; then
        flag "known rootkit module loaded: $m"; continue
      fi
      modinfo -F filename "$m" >/dev/null 2>&1 || nomod+=("$m")
    done < <(lsmod 2>/dev/null)
    (( ${#nomod[@]} )) && flag "loaded modules with no file in the module tree (insmod'ed from elsewhere?): ${nomod[*]}"
  else
    note "no /lib/modules/$(uname -r) (kernel updated without reboot?) - module check skipped"
  fi
  tainted=$(cat /proc/sys/kernel/tainted 2>/dev/null)
  [[ -n $tainted && $tainted != 0 ]] && note "kernel taint flag = $tainted (out-of-tree/unsigned module or other taint)"
}

scan_postfix() {
  section "Postfix"
  if ! have postconf; then note "postfix not installed"; return; fi
  local v p f t m line mn tok qre='in ([0-9]+) Request' seen=" " u home rr rc

  info "version $(postconf -h mail_version 2>/dev/null) | service $(svc_state postfix) | inet_interfaces $(postconf -h inet_interfaces 2>/dev/null)"
  mn=$(pch mynetworks)
  info "mynetworks = $mn"
  for tok in ${mn//,/ }; do
    tok=${tok//[\[\]]/}
    case $tok in
      0.0.0.0*|::/0|*/0) flag "mynetworks contains $tok: OPEN RELAY (anyone can send mail through you)" ;;
      127.*|::1|::1/128|::ffff:127.0.0.0/104) ;;
      */*) [[ ${tok##*/} =~ ^[0-9]+$ && $tok == *.* ]] && (( ${tok##*/} < 24 )) && \
             flag "mynetworks contains wide range $tok (every host in it can relay)" ;;
    esac
  done
  rr=$(pch smtpd_relay_restrictions)
  rc=$(pch smtpd_recipient_restrictions)
  info "smtpd_relay_restrictions = ${rr:-(not set / old postfix)}"
  info "smtpd_recipient_restrictions = ${rc:-(empty)}"
  if relay_ok "$rr" || relay_ok "$rc"; then good "relay restrictions end in *_unauth_destination"
  else flag "neither relay nor recipient restrictions reach reject_unauth_destination: OPEN RELAY risk"; fi

  for p in always_bcc sender_bcc_maps recipient_bcc_maps; do
    v=$(pcn "$p")
    [[ -n $v ]] && flag "$p = $v  (silently copies mail somewhere)"
  done
  for p in relayhost content_filter smtpd_proxy_filter smtpd_milters non_smtpd_milters virtual_alias_maps \
           transport_maps canonical_maps sender_canonical_maps recipient_canonical_maps header_checks body_checks; do
    v=$(pcn "$p")
    [[ -n $v ]] && note "$p = $v"
  done
  PF_MAP_FLAG_FILES=()
  for p in sender_bcc_maps recipient_bcc_maps header_checks body_checks virtual_alias_maps transport_maps; do
    for m in $(pfmaps "$(pcn "$p")"); do
      t=${m%%:*}; f=${m#*:}
      [[ -f $f ]] || continue
      line=$(grep -vE '^[[:space:]]*(#|$)' "$f" | head -n 15)
      [[ -z $line ]] && continue
      info "$p -> $f:"; show <<<"$line"
      if [[ $p == *bcc* ]] || grep -qiE '[[:space:]](REDIRECT|BCC|FILTER)[[:space:]]' "$f"; then
        flag "$f redirects or copies mail"; PF_MAP_FLAG_FILES+=("$p|$t|$f")
      fi
    done
  done

  if [[ -f /etc/postfix/master.cf ]]; then
    for v in $(awk '/^[^#[:space:]]/ && $2 == "inet" {print $1}' /etc/postfix/master.cf); do
      case $v in
        smtp|submission|smtps|submissions|25|465|587|127.0.0.1:*|localhost:*|\[::1\]:*) ;;
        *) flag "extra Postfix SMTP listener in master.cf: $v" ;;
      esac
    done
    line=$(grep -nE 'argv=' /etc/postfix/master.cf | grep -vE '^[0-9]+:[[:space:]]*#')
    if [[ -n $line ]]; then
      info "master.cf pipe commands:"; show <<<"$line"
      grep -qE 'argv=(/tmp|/var/tmp|/dev/shm|/home|/root)|argv=[^ ]*/(bash|sh|python[0-9.]*|perl|nc|ncat|socat)( |$)' <<<"$line" && \
        flag "master.cf pipes mail into a script or shell; review the argv= lines above"
    fi
  fi

  for m in $( { pfmaps "$(postconf -h alias_maps 2>/dev/null)"; echo hash:/etc/aliases; } | sort -u); do
    f=${m#*:}
    [[ -f $f && $seen != *" $f "* ]] || continue
    seen+="$f "
    line=$(grep -nE '^[^#]*(\||:include:)' "$f")
    [[ -n $line ]] && { flag "$f pipes mail into commands/includes:"; show <<<"$line"; ALIAS_FLAG=1; }
    line=$(grep -nE '^[^#]*:.*@' "$f")
    [[ -n $line ]] && { flag "$f forwards mail to other addresses:"; show <<<"$line"; ALIAS_FLAG=1; }
  done

  FORWARD_FILES=(); SIEVE_FLAG_FILES=(); seen=" "
  while IFS=: read -r u _ _ _ _ home _; do
    [[ -d $home && $home != / && $seen != *" $home "* ]] || continue
    seen+="$home "
    for f in "$home/.forward" "$home/.procmailrc" "$home/.mailfilter"; do
      [[ -f $f ]] && { flag "mail forwarding/filter file $f:"; head -n 5 "$f" | show; FORWARD_FILES+=("$f"); }
    done
    for f in "$home/.dovecot.sieve" "$home"/sieve/*.sieve "$home"/Maildir/sieve/*.sieve; do
      [[ -f $f ]] || continue
      if grep -qiE 'redirect|vnd\.dovecot\.(execute|pipe|filter)|"(execute|pipe)"' "$f"; then
        flag "Sieve script $f redirects or pipes mail:"; grep -niE 'redirect|execute|pipe' "$f" | head -n 5 | show
        SIEVE_FLAG_FILES+=("$f")
      fi
    done
  done < <(getent passwd)

  line=$(postqueue -p 2>/dev/null | tail -n1)
  info "queue: ${line:-?}"
  [[ $line =~ $qre ]] && (( BASH_REMATCH[1] > 50 )) && flag "mail queue holds ${BASH_REMATCH[1]} messages (being used to spam?)"
  [[ $(postconf -h disable_vrfy_command 2>/dev/null) == no ]] && note "VRFY is on (lets attackers list usernames); menu 5 can turn it off"
  [[ $(postconf -h smtpd_banner 2>/dev/null) == *mail_version* ]] && note "SMTP banner shows the Postfix version"
}

scan_dovecot() {
  section "Dovecot"
  if ! have doveconf; then note "dovecot not installed"; return; fi
  local dc pb v line f re patterns=()
  dc=$(doveconf -n 2>&1)
  printf '%s\n' "$dc" >"$OUT/doveconf-n.txt"
  info "version $(dovecot --version 2>/dev/null) | service $(svc_state dovecot) | protocols: $(doveconf -h protocols 2>/dev/null)"
  pb=$(awk '/^passdb/,/^}/' <<<"$dc")
  info "passdb / userdb:"; awk '/^(passdb|userdb)/,/^}/' <<<"$dc" | show

  if grep -qE 'driver = static|^passdb static' <<<"$pb"; then
    flag "STATIC passdb: logins succeed with one fixed password (or none)"; patterns+=('static')
  fi
  grep -qi 'nopassword' <<<"$dc" && { flag "'nopassword' in dovecot auth: login without a password"; patterns+=('nopassword'); }
  grep -q 'checkpassword' <<<"$pb" && { flag "checkpassword passdb runs an external program to decide logins"; patterns+=('checkpassword'); }
  grep -qE 'master = yes' <<<"$pb" && { flag "master passdb: a master user can log in as anyone"; patterns+=('master *= *yes'); }
  line=$(grep -E '^auth_master_user_separator' <<<"$dc")
  [[ -n $line ]] && note "$line (master-user logins enabled)"
  grep -qE '^auth_mechanisms.*anonymous' <<<"$dc" && { flag "anonymous auth mechanism enabled"; patterns+=('anonymous'); }
  grep -qE '^auth_debug_passwords = yes' <<<"$dc" && { flag "auth_debug_passwords = yes (passwords go to the log)"; patterns+=('auth_debug_passwords'); DC_PWLOG=1; }
  grep -qE '^auth_verbose_passwords = (plain|yes|sha1)' <<<"$dc" && { flag "auth_verbose_passwords logs passwords"; patterns+=('auth_verbose_passwords'); DC_PWLOG=1; }
  line=$(grep -E '^[[:space:]]*executable = ' <<<"$dc")
  [[ -n $line ]] && { flag "dovecot service 'executable' overridden (post-login script?):"; show <<<"$line"; patterns+=('executable'); }

  for f in $(grep -E '^[[:space:]]*(args|passwd_file_path) = ' <<<"$pb" | grep -oE '/[^ ]+'); do
    [[ -f $f ]] || continue
    info "passwd-file $f: $(grep -cvE '^[[:space:]]*(#|$)' "$f") users, mode $(stat -c '%a %U:%G' "$f")"
    [[ $(stat -c %a "$f") =~ [4-7]$ ]] && flag "$f is world-readable (password hashes)"
  done

  v=$(doveconf -h disable_plaintext_auth 2>/dev/null)
  [[ -z $v ]] && v=$(doveconf -h auth_allow_cleartext 2>/dev/null)
  info "disable_plaintext_auth/auth_allow_cleartext = ${v:-?} (leave it if scoring logs in over plain POP3/IMAP) | ssl = $(doveconf -h ssl 2>/dev/null)"
  for v in sieve_before sieve_after sieve_global sieve_global_path sieve_extensions mail_plugins login_trusted_networks; do
    line=$(grep -E "^[[:space:]]*$v = " <<<"$dc" | head -n1)
    [[ -n $line ]] && note "$line"
  done

  DC_HITS=()
  if (( ${#patterns[@]} )); then
    re=$(IFS='|'; echo "${patterns[*]}")
    mapfile -t DC_HITS < <(grep -rnE "^[^#]*($re)" /etc/dovecot 2>/dev/null)
    (( ${#DC_HITS[@]} )) && { info "where (file:line):"; printf '%s\n' "${DC_HITS[@]}" | show; }
  fi
  line=$(grep -vE '^[[:space:]]*(#|$)' /etc/pam.d/dovecot 2>/dev/null)
  [[ -n $line ]] && { info "/etc/pam.d/dovecot:"; show <<<"$line"; }
}

detect_web() {
  local cand=() d p keep
  for d in /var/www /usr/share/roundcubemail /usr/share/squirrelmail /usr/share/rainloop /usr/share/snappymail \
           /srv/www /var/lib/roundcubemail; do
    [[ -d $d ]] && cand+=("$d")
  done
  if [[ -d /etc/httpd ]]; then
    while read -r d; do
      d=${d//\"/}; [[ -d $d ]] && cand+=("$d")
    done < <(grep -rhiE '^[[:space:]]*(DocumentRoot|Alias|ScriptAlias)[[:space:]]' /etc/httpd/conf /etc/httpd/conf.d 2>/dev/null | awk '{print $NF}')
  fi
  if have nginx && [[ -d /etc/nginx ]]; then
    while read -r d; do
      d=${d%;}; [[ -d $d ]] && cand+=("$d")
    done < <(grep -rhE '^[[:space:]]*root[[:space:]]' /etc/nginx 2>/dev/null | awk '{print $2}')
  fi
  WEBROOTS=()
  while read -r p; do
    case $p in ""|/|/usr|/usr/share|/var|/etc|/opt|/srv|/home) continue ;; esac
    keep=1
    for d in "${WEBROOTS[@]}"; do [[ $p == "$d"/* ]] && keep=0; done
    (( keep )) && WEBROOTS+=("$p")
  done < <(printf '%s\n' "${cand[@]}" | sed 's:/*$::' | sort -u)
}

scan_web() {
  section "Web server & webmail"
  detect_web
  local s v f d line pi files=()
  for s in httpd nginx php-fpm; do unit_exists "$s" && info "$s: $(svc_state "$s")"; done
  info "web roots: ${WEBROOTS[*]:-none found}"
  if have httpd; then
    info "$(httpd -v 2>/dev/null | head -n1)"
    info "Listen: $(grep -rhE '^[[:space:]]*Listen[[:space:]]' /etc/httpd/conf /etc/httpd/conf.d 2>/dev/null | tr -s ' \t' ' ' | tr '\n' ';')"
    line=$(grep -rnE '^[[:space:]]*Options[[:space:]].*([[:space:]]|\+)Indexes' /etc/httpd/conf /etc/httpd/conf.d 2>/dev/null)
    [[ -n $line ]] && { note "directory listing enabled:"; show <<<"$line"; }
    line=$(grep -rnE 'SetHandler[[:space:]]+server-(status|info)' /etc/httpd/conf /etc/httpd/conf.d 2>/dev/null | grep -vE ':[[:space:]]*#')
    [[ -n $line ]] && { note "server-status/info handler configured:"; show <<<"$line"; }
    mapfile -t files < <(find /etc/httpd/conf /etc/httpd/conf.d /etc/httpd/conf.modules.d -maxdepth 1 -type f 2>/dev/null)
    line=$(unowned "${files[@]}" | tr '\n' ' ')
    [[ -n ${line// } ]] && note "httpd config files not from a package (review): $line"
  fi

  # Roundcube
  RC_DIR=""; RC_CONF=""; RC_DBUSER=""
  for d in "${WEBROOTS[@]}"; do
    f=$(find "$d" -maxdepth 4 -path '*/program/include/iniset.php' 2>/dev/null | head -n1)
    [[ -n $f ]] && { RC_DIR=${f%/program/include/iniset.php}; break; }
  done
  if [[ -n $RC_DIR ]]; then
    v=$(grep -oE "RCMAIL_VERSION'[[:space:]]*,[[:space:]]*'[^']+'" "$RC_DIR/program/include/iniset.php" | sed -E "s/.*'([^']+)'$/\1/")
    info "Roundcube ${v:-?} at $RC_DIR"
    if [[ -n $v ]] && { ver_lt "$v" 1.5.10 || { ! ver_lt "$v" 1.6.0 && ver_lt "$v" 1.6.11; }; }; then
      flag "Roundcube $v is older than 1.5.10/1.6.11: CVE-2025-49113 (any logged-in user -> code execution) plus older XSS bugs. Update if the rules allow."
    fi
    for f in /etc/roundcubemail/config.inc.php "$RC_DIR/config/config.inc.php"; do
      [[ -f $f ]] && { RC_CONF=$(readlink -f "$f"); break; }
    done
    if [[ -n $RC_CONF ]]; then
      info "config: $RC_CONF (mode $(stat -c '%a %U:%G' "$RC_CONF"))"
      [[ $(stat -c %a "$RC_CONF") =~ [4-7]$ ]] && { flag "Roundcube config is world-readable (it holds the DB password)"; RC_CONF_WORLD=1; }
      grep -qE "^[[:space:]]*\\\$(config|rcmail_config)\['enable_installer'\][[:space:]]*=[[:space:]]*true" "$RC_CONF" && \
        { flag "Roundcube enable_installer = true (the installer can rewrite config and leak secrets)"; RC_INSTALLER_ON=1; }
      grep -q "rcmail-!24ByteDESkey\*Str" "$RC_CONF" && { flag "Roundcube des_key is the public default"; RC_DESKEY_DEFAULT=1; }
      line=$(grep -E "\['db_dsnw'\]" "$RC_CONF" | grep -vE '^[[:space:]]*(//|#)' | head -n1)
      if [[ -n $line ]]; then
        info "DB: $(sed -E 's#(://[^:/@]+:)[^@]*@#\1****@#' <<<"$line" | tr -s ' ')"
        RC_DBUSER=$(sed -nE 's#.*://([^:/@]+)[:@].*#\1#p' <<<"$line")
      fi
      line=$(grep -E "\['(default_host|imap_host|smtp_server|smtp_host)'\]" "$RC_CONF" | grep -vE '^[[:space:]]*(//|#)' | tr -s ' ')
      [[ -n $line ]] && show <<<"$line"
    fi
    [[ -d $RC_DIR/installer ]] && note "installer/ directory is still present at $RC_DIR/installer"
  fi

  # SquirrelMail
  for d in "${WEBROOTS[@]}"; do
    f=$(find "$d" -maxdepth 3 -path '*/functions/strings.php' 2>/dev/null | head -n1)
    if [[ -n $f ]] && grep -qi squirrelmail "$f" 2>/dev/null; then
      v=$(grep -oE "version = '[^']+'" "$f" | head -n1)
      flag "SquirrelMail at $(dirname "$(dirname "$f")") ($v): end-of-life, known RCE (CVE-2017-7692) when it sends via sendmail"
      SQM_FOUND=1
    fi
  done

  # webshells and PHP in places PHP doesn't belong
  WEBSHELLS=()
  if (( ${#WEBROOTS[@]} )); then
    mapfile -t WEBSHELLS < <(
      {
        find "${WEBROOTS[@]}" -xdev -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.pht' \
             -o -iname '*.phar' -o -iname '*.inc' \) -size -3M -print0 2>/dev/null | xargs -0 -r grep -lIiE "$WEBSHELL_RE" 2>/dev/null
        find "${WEBROOTS[@]}" -xdev -type f \( -path '*/temp/*' -o -path '*/tmp/*' -o -path '*/logs/*' -o -path '*/upload*/*' \) \
             -iname '*.ph*' 2>/dev/null
        find "${WEBROOTS[@]}" -xdev -type f \( -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.ico' \) \
             -size -2M -print0 2>/dev/null | xargs -0 -r grep -l '<?php' 2>/dev/null
        find "${WEBROOTS[@]}" -xdev -type f -name '.htaccess' -print0 2>/dev/null | \
             xargs -0 -r grep -liE 'Add(Type|Handler)[^#]*(php|phtml|x-httpd)|SetHandler[^#]*php|auto_(prepend|append)_file' 2>/dev/null
      } | sed '/^$/d' | sort -u)
    if (( ${#WEBSHELLS[@]} )); then
      flag "possible webshells / PHP in odd places (${#WEBSHELLS[@]}):"
      for f in "${WEBSHELLS[@]}"; do printf '%s  [%s %s]\n' "$f" "$(stat -c %U "$f" 2>/dev/null)" "$(date -r "$f" '+%F %R' 2>/dev/null)"; done | show
    else
      good "no webshell patterns in web roots"
    fi
    info "most recently modified files in web roots:"
    find "${WEBROOTS[@]}" -xdev -type f -printf '%TY-%Tm-%Td %TH:%TM  %u  %p\n' 2>/dev/null | sort -r | head -n 10 | show
    line=$(find /var/www/cgi-bin -type f 2>/dev/null)
    [[ -n $line ]] && { flag "CGI scripts present:"; show <<<"$line"; }
  fi

  if have php; then
    pi=$(php -i 2>/dev/null)
    info "PHP $(php -r 'echo PHP_VERSION;' 2>/dev/null) | ini: $(awk -F' => ' '$1=="Loaded Configuration File"{print $2; exit}' <<<"$pi")"
    v=$(awk -F' => ' '$1=="disable_functions"{print $2; exit}' <<<"$pi")
    [[ -z $v || $v == "no value" ]] && note "PHP disable_functions is empty (a webshell can run any command)"
    [[ $(awk -F' => ' '$1=="allow_url_include"{print $2; exit}' <<<"$pi") == On ]] && flag "PHP allow_url_include = On (remote file inclusion)"
    [[ $(awk -F' => ' '$1=="expose_php"{print $2; exit}' <<<"$pi") == On ]] && note "PHP expose_php = On"
  fi
}

scan_db() {
  section "Database"
  local s svc="" line
  for s in mariadb mysqld mysql postgresql; do [[ $(svc_state "$s") == active ]] && svc+="$s "; done
  if [[ -z $svc ]] && ! have mysql; then info "no database service running"; return; fi
  info "running: ${svc:-none}"
  have mysql || return
  [[ -f /root/.my.cnf ]] && note "/root/.my.cnf exists (it may hold the DB root password)"
  if timeout 5 mysql --connect-timeout=3 --protocol=TCP -h 127.0.0.1 -u root --password= -e 'select 1' </dev/null >/dev/null 2>&1; then
    flag "MySQL root logs in over TCP with an EMPTY password"
  fi
  line=$(timeout 5 mysql --connect-timeout=3 -N -B -e "SELECT CONCAT(user,'@',host) FROM mysql.user" </dev/null 2>/dev/null)
  if [[ -n $line ]]; then
    info "DB accounts (root got in over the socket without a password; normal only with unix_socket auth on MariaDB 10.4+):"
    show <<<"$line"
    grep -qE '^@' <<<"$line" && flag "anonymous MySQL accounts exist"
    grep -qE '^root@%$' <<<"$line" && flag "MySQL root can log in from any host"
  else
    info "socket login as root needs a password (good)"
  fi
  [[ -n $RC_DBUSER ]] && info "Roundcube uses DB user '$RC_DBUSER'"
  [[ $RC_DBUSER == root ]] && flag "Roundcube connects to the DB as root"
}

scan_services() {
  section "Services"
  local s st running skip_re
  for s in $CORE_SVCS; do
    unit_exists "$s" || { note "$s is not installed"; continue; }
    st=$(svc_state "$s")
    if [[ $st == active ]]; then good "$s is active"; else flag "$s is $st (scored service down?)"; fi
  done
  for s in php-fpm mariadb mysqld nginx sshd firewalld; do unit_exists "$s" && info "$s: $(svc_state "$s")"; done
  running=$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//')
  UNNEEDED_SVCS=()
  skip_re='^(telnet.*|vsftpd|proftpd|pure-ftpd|tftp.*|rsh.*|rlogin.*|rexec.*|xinetd|nfs-server|rpcbind|smb|nmb|winbind|snmpd|cups|avahi-daemon|bluetooth|sendmail|exim|vncserver.*|x11vnc|squid|named|dnsmasq|cockpit|docker|containerd|lighttpd|tomcat|webmin|ncat|socat|teamviewerd|anydesk)$'
  for s in $running; do
    [[ $s =~ $skip_re ]] && { flag "service probably not needed on a mail box: $s"; UNNEEDED_SVCS+=("$s"); }
  done
  info "running services: $(tr '\n' ' ' <<<"$running")"

  section "SELinux"
  if have getenforce; then
    st=$(getenforce 2>/dev/null)
    case $st in
      Enforcing)  good "SELinux Enforcing" ;;
      Permissive) flag "SELinux Permissive (logs but blocks nothing)" ;;
      *)          flag "SELinux ${st:-unknown}" ;;
    esac
    have getsebool && info "$(getsebool httpd_can_network_connect httpd_can_sendmail httpd_enable_cgi httpd_execmem 2>/dev/null | tr '\n' ';')"
  else
    note "SELinux tools not installed"
  fi
}

scan_logins() {
  section "Recent logins & shell history"
  local line f u home
  last -n 15 -a 2>/dev/null | grep -vE '^[[:space:]]*$|^wtmp begins' | show
  line=$(lastb -n 10 -a 2>/dev/null | grep -vE '^$|^btmp begins')
  [[ -n $line ]] && { info "failed logins:"; show <<<"$line"; }
  line=$(grep -hE 'Accepted (password|publickey)' /var/log/secure 2>/dev/null | tail -n 8)
  [[ -z $line ]] && have journalctl && line=$(journalctl -u sshd --since yesterday --no-pager -q 2>/dev/null | grep 'Accepted' | tail -n 8)
  [[ -n $line ]] && { info "recent SSH logins:"; show <<<"$line"; }
  while IFS=: read -r u _ _ _ _ home _; do
    f=$home/.bash_history
    [[ -f $f ]] || continue
    line=$(grep -nE '(wget|curl)[[:space:]].*http|/dev/tcp|nc[[:space:]]+-[a-z]*e|ncat|socat|chattr|base64[[:space:]]+-d|useradd|usermod|passwd[[:space:]]+[a-z]|authorized_keys|crontab|history[[:space:]]+-c|unset[[:space:]]+HISTFILE' "$f" | tail -n 8)
    [[ -n $line ]] && { note "interesting commands in $f:"; show <<<"$line"; }
  done < <(getent passwd | sort -t: -k6,6 -u)
}

run_scan() {
  FLAGS=()
  scan_system; scan_accounts; scan_ssh; scan_network; scan_procs; scan_persistence
  scan_integrity; scan_postfix; scan_dovecot; scan_web; scan_db; scan_services; scan_logins
}

summary() {
  section "FLAG SUMMARY: ${#FLAGS[@]} item(s) to look at"
  printf '%s\n' "${FLAGS[@]}" >"$FLAGFILE"
  local i=0 f
  for f in "${FLAGS[@]}"; do i=$((i + 1)); printf '  %s%3d%s %s\n' "$R" "$i" "$N" "$f"; done
  rep "(flag list: $FLAGFILE)"
}

# =============================================================================
#  BACKUP (asks first)
# =============================================================================
do_backup() {
  mkdir -p "$BACKUP"
  info "backing up to $BACKUP ..."
  local p size inc=() u ex
  ex=$(basename "$BASE_DIR")
  for p in /etc /root /var/spool/cron /var/spool/at "${WEBROOTS[@]}"; do
    [[ -e $p ]] || continue
    if [[ $p != /etc ]]; then
      size=$(du -sm --exclude="$ex" "$p" 2>/dev/null | cut -f1)
      if (( ${size:-0} > 500 )); then note "skipping $p (${size} MB); back it up separately"; continue; fi
    fi
    inc+=("$p")
  done
  tar czf "$BACKUP/files.tgz" --exclude="$ex" --ignore-failed-read "${inc[@]}" 2>"$BACKUP/tar-errors.txt"
  {
    ps auxfww >"$BACKUP/ps.txt"
    ss -tulpna >"$BACKUP/ss.txt"
    iptables-save >"$BACKUP/iptables.rules"
    ip6tables-save >"$BACKUP/ip6tables.rules"
    have firewall-cmd && firewall-cmd --list-all-zones >"$BACKUP/firewalld-zones.txt"
    have nft && nft list ruleset >"$BACKUP/nft.txt"
    rpm -qa --last >"$BACKUP/rpm-qa-last.txt"
    systemctl list-unit-files --no-pager >"$BACKUP/unit-files.txt"
    have postconf && postconf -n >"$BACKUP/postconf-n.txt"
    have doveconf && doveconf -n >"$BACKUP/doveconf-n.txt"
    have crontab && for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s|^|$u: |"; done >"$BACKUP/crontabs.txt"
  } 2>/dev/null
  if have mysqldump && timeout 5 mysql --connect-timeout=3 -e 'select 1' </dev/null >/dev/null 2>&1; then
    timeout 120 mysqldump --all-databases --single-transaction 2>/dev/null | gzip >"$BACKUP/mysql-all.sql.gz" && info "MySQL dumped"
  elif have mysql; then
    note "MySQL not dumped (needs a password). Later: mysqldump -u root -p --all-databases | gzip > $BACKUP/mysql-all.sql.gz"
  fi
  act "BACKUP written to $BACKUP"
  good "backup done ($(du -sh "$BACKUP" 2>/dev/null | cut -f1)). Copy $OUT off this box: red team can wipe it."
}

# =============================================================================
#  MENU STEPS (each change asks first)
# =============================================================================
disable_user() {
  usermod -L -e 1 -s /sbin/nologin "$1" && { good "disabled $1"; act "DISABLED user $1 (locked, expired, nologin)"; }
}

step_passwords() {
  hdr "1) Passwords"
  note "MACCDC: change a SCORED user's password only with a PCR to the White Team, or the service check fails."
  note "You type every password at passwd's own prompt. Nothing is stored."
  confirm "Change the root password now?" && on_tty passwd root && act "PASSWORD changed: root"
  local admins u others=() c
  admins=$(getent group wheel | cut -d: -f4 | tr ',' ' ')
  for u in $admins; do
    [[ $u == root ]] && continue
    confirm "Change password for admin (wheel) user '$u'?" && on_tty passwd "$u" && act "PASSWORD changed: $u"
  done
  for u in "${SHELL_USERS[@]}" "${HUMAN_USERS[@]}"; do
    [[ $u == root || " $admins " == *" $u "* || " ${others[*]} " == *" $u "* ]] && continue
    others+=("$u")
  done
  (( ${#others[@]} )) || return 0
  info "Other users (${#others[@]}): ${others[*]}"
  c=$(ask "  [o]ne at a time / [b]ulk from a user:password file you write / [s]kip (default): ")
  case $c in
    o*) each_reset
        for u in "${others[@]}"; do each "Change password for '$u'?" && on_tty passwd "$u" && act "PASSWORD changed: $u"; done ;;
    b*) bulk_passwords ;;
  esac
}

bulk_passwords() {
  local f u bad=()
  note "Write one 'user:newpassword' per line (e.g. vi /root/pw.txt). Keep a copy for your PCR."
  f=$(ask "  Path to that file: ")
  [[ -f $f ]] || { warn "no such file: $f"; return; }
  while IFS=: read -r u _; do
    [[ -z $u ]] && continue
    id "$u" >/dev/null 2>&1 || bad+=("$u")
  done <"$f"
  (( ${#bad[@]} )) && { warn "these users don't exist, fix the file first: ${bad[*]}"; return; }
  info "will change: $(cut -d: -f1 "$f" | sed '/^$/d' | tr '\n' ' ')"
  confirm "Apply with chpasswd?" || return
  if chpasswd <"$f"; then
    good "passwords changed"; act "PASSWORD changed (bulk chpasswd): $(cut -d: -f1 "$f" | tr '\n' ' ')"
  else
    warn "chpasswd failed"
  fi
  confirm "Shred $f now? (only after you've copied it for the PCR)" && shred -u "$f" 2>/dev/null && act "SHREDDED $f"
}

step_procs() {
  hdr "2) Suspicious processes & other sessions"
  local pid exe my_tty tty line
  (( ${#SUS_PROCS[@]} )) || good "no processes were flagged"
  for pid in "${SUS_PROCS[@]}"; do
    [[ -d /proc/$pid ]] || continue
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    echo
    ps -o pid,ppid,user,lstart,args -p "$pid" 2>/dev/null | show
    info "exe: $exe   cwd: $(readlink "/proc/$pid/cwd" 2>/dev/null)"
    ss -tunp 2>/dev/null | grep "pid=$pid," | show
    if confirm "Kill PID $pid? (its binary + cmdline are copied to quarantine first, for your incident report)"; then
      mkdir -p "$QUAR/proc"
      cp "/proc/$pid/exe" "$QUAR/proc/$pid-$(basename "${exe% (deleted)}")" 2>/dev/null
      tr '\0' ' ' <"/proc/$pid/cmdline" >"$QUAR/proc/$pid.cmdline" 2>/dev/null
      if kill -9 "$pid" 2>/dev/null; then
        good "killed $pid"; act "KILLED pid $pid: $(cat "$QUAR/proc/$pid.cmdline" 2>/dev/null)"
      else
        warn "could not kill $pid"
      fi
      exe=${exe% (deleted)}
      [[ -f $exe && $exe =~ ^(/tmp|/var/tmp|/dev/shm)/ ]] && confirm "Quarantine its file $exe too?" && quarantine "$exe"
    fi
  done
  note "Killed shells that come back are being respawned: run step 8 (persistence)."

  echo
  my_tty=$(ps -o tty= -p $$ 2>/dev/null | tr -d ' ')
  info "Your terminal: ${my_tty:-unknown}. Other sessions:"
  while IFS= read -r line; do
    tty=$(awk '{print $2}' <<<"$line")
    [[ -z $tty || $tty == "$my_tty" ]] && continue
    printf '      %s\n' "$line"
    confirm "Kill every process on $tty? (make sure it isn't a teammate)" && pkill -KILL -t "$tty" && \
      { good "killed session $tty"; act "KILLED session $tty: $line"; }
  done < <(who 2>/dev/null)
}

step_accounts() {
  hdr "3) Accounts, sudo, SSH keys"
  local u f line before
  for u in "${UID0_USERS[@]}"; do
    confirm "Disable UID-0 account '$u' (lock, expire, nologin shell)?" && disable_user "$u"
  done
  for u in "${EMPTY_PW_USERS[@]}"; do
    confirm "Lock '$u' (it has an EMPTY password)?" && passwd -l "$u" >/dev/null && { good "locked $u"; act "LOCKED (empty password) $u"; }
  done
  each_reset
  for u in "${SYS_SHELL_USERS[@]}"; do
    each "Set system account '$u' shell to /sbin/nologin?" && usermod -s /sbin/nologin "$u" && { good "$u -> nologin"; act "SHELL nologin: $u"; }
  done

  info "Users with a login shell: ${SHELL_USERS[*]}"
  note "Disabling a mail user also blocks their POP3/IMAP/webmail login (scoring!). 'nologin only' keeps mail working."
  line=$(ask "  Users to fully disable (lock + expire + nologin), space-separated, blank = none: ")
  for u in $line; do
    id "$u" >/dev/null 2>&1 || { warn "no user $u"; continue; }
    [[ $u == root ]] && { warn "skipping root"; continue; }
    confirm "Disable '$u'?" && disable_user "$u"
  done
  line=$(ask "  Users to set to nologin shell only (keeps mail working), blank = none: ")
  for u in $line; do
    id "$u" >/dev/null 2>&1 || { warn "no user $u"; continue; }
    confirm "Set '$u' shell to /sbin/nologin?" && usermod -s /sbin/nologin "$u" && { good "$u -> nologin"; act "SHELL nologin: $u"; }
  done

  for u in $(getent group wheel | cut -d: -f4 | tr ',' ' '); do
    confirm "Remove '$u' from wheel (no more sudo)? Say no for your own admin account." && \
      gpasswd -d "$u" wheel >/dev/null && { good "removed $u from wheel"; act "WHEEL removed $u"; }
  done

  each_reset
  for f in "${SUDO_FLAG_FILES[@]}"; do
    [[ -f $f ]] || continue
    info "$f:"; grep -vE '^[[:space:]]*(#|$)' "$f" | show
    each "Quarantine $f?" && quarantine "$f"
  done
  if confirm "Open /etc/sudoers in visudo to review/remove rules?"; then
    before=$(md5sum </etc/sudoers)
    on_tty visudo
    [[ $(md5sum </etc/sudoers) != "$before" ]] && act "EDITED /etc/sudoers (visudo)"
  fi
  if visudo -c >/dev/null 2>&1; then good "sudoers syntax OK"; else warn "visudo -c reports a problem: fix it now with visudo"; fi

  each_reset
  for f in "${AUTH_KEYS[@]}"; do
    [[ -f $f ]] || continue
    echo; info "$f:"; keys_summary "$f" | show
    each "Quarantine $f (these keys stop working)?" && quarantine "$f"
  done
}

step_firewall() {
  hdr "4) Firewall: inbound allowlist"
  local def="" p ports badport=0
  for p in $MAIL_PORTS; do [[ " ${LISTEN_PORTS[*]} " == *" $p "* ]] && def+="$p "; done
  def=${def% }
  [[ -z $def ]] && def="22 25 80 110 143 443"
  info "firewall tool: $FW"
  info "ssh/mail/web ports listening right now: $def"
  note "Every scored port must stay open. Loopback, ICMP and replies to this box's own connections stay allowed."
  ports=$(ask "  TCP ports to allow inbound [$def]: ") || return
  ports=${ports:-$def}; ports=${ports//,/ }
  for p in $ports; do
    [[ $p =~ ^[0-9]+$ ]] && (( p > 0 && p < 65536 )) || { warn "bad port: $p"; badport=1; }
  done
  (( badport )) && return
  [[ " $ports " == *" 22 "* ]] || warn "22 is not in the list: remote SSH (yours too) will be blocked"
  case $FW in
    firewalld) fw_firewalld "$ports" ;;
    iptables)  fw_iptables "$ports" ;;
    *)         warn "no firewall tool available" ;;
  esac
}

fw_firewalld() {
  local ports=$1 z zones s p r i rm_rich=() rm_fwd=() rm_src=() mv_if=()
  zones=$(firewall-cmd --get-active-zones 2>/dev/null | awk '!/^[[:space:]]/{print $1}')
  [[ -z $zones ]] && zones=$(firewall-cmd --get-default-zone)
  # decide on the extras first, so the rollback timer isn't running while you read
  for z in $zones; do
    while IFS= read -r r; do
      [[ -z $r ]] && continue
      info "zone $z rich rule: $r"
      confirm "Remove this rich rule?" && rm_rich+=("$z|$r")
    done < <(firewall-cmd --zone="$z" --list-rich-rules 2>/dev/null)
    for r in $(firewall-cmd --zone="$z" --list-forward-ports 2>/dev/null); do
      confirm "Remove port forward '$r' from zone $z?" && rm_fwd+=("$z|$r")
    done
    if [[ $(firewall-cmd --permanent --zone="$z" --get-target 2>/dev/null) == ACCEPT ]]; then
      for i in $(firewall-cmd --zone="$z" --list-interfaces 2>/dev/null); do
        confirm "Interface $i is in zone '$z', which accepts everything. Move it to 'public'?" && mv_if+=("$i")
      done
    fi
  done
  for s in $(firewall-cmd --zone=trusted --list-sources 2>/dev/null); do
    confirm "Remove source $s from the 'trusted' zone (it bypasses the firewall)?" && rm_src+=("$s")
  done
  (( ${#mv_if[@]} )) && [[ " $zones " != *" public "* ]] && zones+=" public"
  info "Plan for zone(s) $zones: allow TCP $ports (+ dhcpv6-client), remove every other service/port."
  confirm "Apply now (runtime only, auto-rollback in ${ROLLBACK_SECS}s)?" || return

  arm_rollback "firewall-cmd --reload"
  for i in "${mv_if[@]}"; do firewall-cmd -q --zone=public --change-interface="$i"; done
  for z in $zones; do
    [[ $(firewall-cmd --permanent --zone="$z" --get-target 2>/dev/null) == ACCEPT ]] && continue
    for p in $ports; do firewall-cmd -q --zone="$z" --add-port="$p/tcp"; done
    for s in $(firewall-cmd --zone="$z" --list-services 2>/dev/null); do
      [[ $s == dhcpv6-client ]] || firewall-cmd -q --zone="$z" --remove-service="$s"
    done
    for p in $(firewall-cmd --zone="$z" --list-ports 2>/dev/null); do
      [[ $p == */tcp && " $ports " == *" ${p%/tcp} "* ]] || firewall-cmd -q --zone="$z" --remove-port="$p"
    done
  done
  for r in "${rm_rich[@]}"; do firewall-cmd -q --zone="${r%%|*}" --remove-rich-rule="${r#*|}"; done
  for r in "${rm_fwd[@]}"; do firewall-cmd -q --zone="${r%%|*}" --remove-forward-port="${r#*|}"; done
  for s in "${rm_src[@]}"; do firewall-cmd -q --zone=trusted --remove-source="$s"; done
  for z in $zones; do firewall-cmd --zone="$z" --list-all 2>/dev/null | show; done
  keep_or_rollback "firewall-cmd --runtime-to-permanent"
}

fw_iptables() {
  local ports=$1 v p persist="" rb
  info "Plan: chain CCDC_IN at the top of INPUT: allow lo, established, ICMP, DHCP, TCP $ports; drop the rest (IPv4 + IPv6)."
  confirm "Apply now (auto-rollback in ${ROLLBACK_SECS}s)?" || return
  iptables-save >"$OUT/iptables.before" 2>/dev/null
  have ip6tables-save && ip6tables-save >"$OUT/ip6tables.before" 2>/dev/null
  rb="iptables-restore <'$OUT/iptables.before'"
  [[ -s $OUT/ip6tables.before ]] && rb+="; ip6tables-restore <'$OUT/ip6tables.before'"
  arm_rollback "$rb"
  for v in iptables ip6tables; do
    have "$v" || continue
    "$v" -N CCDC_IN 2>/dev/null || "$v" -F CCDC_IN
    "$v" -A CCDC_IN -i lo -j ACCEPT
    "$v" -A CCDC_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
      "$v" -A CCDC_IN -m state --state ESTABLISHED,RELATED -j ACCEPT
    if [[ $v == iptables ]]; then
      "$v" -A CCDC_IN -p icmp -j ACCEPT; "$v" -A CCDC_IN -p udp --dport 68 -j ACCEPT
    else
      "$v" -A CCDC_IN -p ipv6-icmp -j ACCEPT; "$v" -A CCDC_IN -p udp --dport 546 -j ACCEPT
    fi
    for p in $ports; do "$v" -A CCDC_IN -p tcp --dport "$p" -j ACCEPT; done
    "$v" -A CCDC_IN -j DROP
    while "$v" -D INPUT -j CCDC_IN 2>/dev/null; do :; done
    "$v" -I INPUT 1 -j CCDC_IN
  done
  iptables -S CCDC_IN | show
  if [[ -f /etc/sysconfig/iptables ]] || systemctl is-enabled -q iptables 2>/dev/null; then
    persist="iptables-save >/etc/sysconfig/iptables; ip6tables-save >/etc/sysconfig/ip6tables 2>/dev/null; true"
    note "'keep' also saves the rules to /etc/sysconfig/iptables"
  else
    note "no iptables-services: these rules last until reboot (re-run this step after one)"
  fi
  keep_or_rollback "${persist:-true}"
}

step_postfix() {
  hdr "5) Postfix"
  have postconf || { info "postfix not installed"; return; }
  local cur new p e t f changed=0 err want="permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"
  [[ -f $OUT/main.cf.before ]] || cp -a /etc/postfix/main.cf "$OUT/main.cf.before"
  pset() { postconf -e "$1" && { act "POSTFIX $1   (was: $2)"; good "$1"; changed=1; }; }

  cur=$(pch mynetworks)
  info "mynetworks = $cur"
  note "Hosts in mynetworks can send mail anywhere without logging in. Webmail on this box only needs 127.0.0.0/8."
  if confirm "Change mynetworks?"; then
    new=$(ask "  new mynetworks [127.0.0.0/8 [::1]/128]: "); new=${new:-127.0.0.0/8 [::1]/128}
    pset "mynetworks = $new" "$cur"
  fi

  if [[ -n $(postconf -dh smtpd_relay_restrictions 2>/dev/null) ]]; then p=smtpd_relay_restrictions; else p=smtpd_recipient_restrictions; fi
  cur=$(pch "$p")
  if relay_ok "$(pch smtpd_relay_restrictions)" || relay_ok "$(pch smtpd_recipient_restrictions)"; then
    good "relay restrictions OK ($p = $cur)"
  else
    warn "$p = $cur  (open relay risk)"
    confirm "Set $p = $want ?" && pset "$p = $want" "$cur"
  fi

  for p in always_bcc sender_bcc_maps recipient_bcc_maps; do
    cur=$(pcn "$p"); [[ -z $cur ]] && continue
    warn "$p = $cur"
    confirm "Clear $p (stops silent copies of every mail)?" && pset "$p =" "$cur"
  done
  for p in relayhost content_filter smtpd_proxy_filter smtpd_milters non_smtpd_milters; do
    cur=$(pcn "$p"); [[ -z $cur ]] && continue
    info "$p = $cur"
    confirm "Clear $p? (only if you don't recognize it)" && pset "$p =" "$cur"
  done
  [[ $(postconf -h disable_vrfy_command) == no ]] && confirm "Disable VRFY (stops username probing)?" && \
    pset "disable_vrfy_command = yes" no
  cur=$(postconf -h smtpd_banner)
  # shellcheck disable=SC2016  # $myhostname is a postfix variable, not a shell one
  [[ $cur == *mail_version* ]] && confirm "Hide the Postfix version in the SMTP banner?" && \
    pset 'smtpd_banner = $myhostname ESMTP' "$cur"

  each_reset
  for e in "${PF_MAP_FLAG_FILES[@]}"; do
    p=${e%%|*}; e=${e#*|}; t=${e%%|*}; f=${e#*|}
    info "$p -> $f"
    if each "Open $f in the editor?" && edit "$f"; then
      [[ $t =~ ^(hash|lmdb|btree|cdb|dbm)$ ]] && postmap "$t:$f" && act "postmap $t:$f"
      changed=1
    fi
  done
  if (( ALIAS_FLAG )) && confirm "Edit /etc/aliases (pipes / forwards were flagged)?" && edit /etc/aliases; then
    newaliases && act "newaliases"
  fi
  each_reset
  for f in "${FORWARD_FILES[@]}"; do
    [[ -f $f ]] || continue
    info "$f: $(head -c 200 "$f" | tr '\n' ' ')"
    each "Quarantine $f?" && quarantine "$f"
  done
  each_reset
  for f in "${SIEVE_FLAG_FILES[@]}"; do
    [[ -e $f ]] || continue
    info "$f"
    each "Quarantine sieve script $f?" && quarantine "$f"
  done

  if (( changed )); then
    err=$(postconf -n 2>&1 >/dev/null)
    [[ -n $err ]] && { warn "postconf says:"; show <<<"$err"; }
    postfix check 2>&1 | show
    if systemctl reload postfix 2>/dev/null || postfix reload 2>/dev/null; then
      good "postfix reloaded"; act "postfix reloaded"
    else
      warn "postfix reload failed"
      if confirm "Restore main.cf from before this step and reload?"; then
        cp -a "$OUT/main.cf.before" /etc/postfix/main.cf && act "RESTORED /etc/postfix/main.cf"
        systemctl reload postfix 2>/dev/null || postfix reload
      fi
    fi
    check_port 25 '^220' SMTP
  fi
}

step_dovecot() {
  hdr "6) Dovecot"
  have doveconf || { info "dovecot not installed"; return; }
  local f files=() changed=0 err dropin=/etc/dovecot/conf.d/99-ccdc.conf
  [[ -d $OUT/dovecot.before ]] || cp -a /etc/dovecot "$OUT/dovecot.before"
  if (( ${#DC_HITS[@]} )); then
    warn "flagged dovecot settings:"; printf '%s\n' "${DC_HITS[@]}" | show
    note "Fix: comment out the static / nopassword / master / checkpassword passdb or the post-login 'executable'. Keep the normal pam or passwd-file passdb (and a static USERdb is normal)."
    mapfile -t files < <(printf '%s\n' "${DC_HITS[@]}" | cut -d: -f1 | sort -u)
    each_reset
    for f in "${files[@]}"; do each "Open $f in the editor?" && edit "$f" && changed=1; done
  else
    good "no dovecot auth backdoors were flagged"
  fi
  if (( DC_PWLOG )) && grep -qE '^[[:space:]]*!include[[:space:]]+conf\.d/\*\.conf' /etc/dovecot/dovecot.conf 2>/dev/null; then
    if confirm "Write $dropin to stop logging passwords (auth_debug_passwords = no, auth_verbose_passwords = no)?"; then
      printf '# added by webmail-5min.sh %s\nauth_debug_passwords = no\nauth_verbose_passwords = no\n' "$TS" >"$dropin"
      chmod 644 "$dropin"
      if doveconf -n >/dev/null 2>&1; then act "WROTE $dropin"; changed=1; else warn "dovecot rejected it; removing it"; rm -f "$dropin"; fi
    fi
  fi
  if (( changed )); then
    err=$(doveconf -n 2>&1 >/dev/null | grep -iE 'fatal|error')
    if [[ -n $err ]]; then
      warn "doveconf errors:"; show <<<"$err"
      confirm "Restore /etc/dovecot from before this step?" && cp -a "$OUT/dovecot.before/." /etc/dovecot/ && act "RESTORED /etc/dovecot"
    fi
    if systemctl reload dovecot 2>/dev/null || doveadm reload 2>/dev/null; then good "dovecot reloaded"; act "dovecot reloaded"
    else warn "dovecot reload failed: check 'systemctl status dovecot'"; fi
    check_port 110 '^\+OK' POP3
    check_port 143 '^\* OK' IMAP
  fi
}

step_web() {
  hdr "7) Webmail & PHP"
  local f key line reload=0 ini=/etc/php.d/99-ccdc.ini cur_df df bk
  if [[ -n $RC_DIR && -d $RC_DIR/installer ]] && confirm "Move the Roundcube installer ($RC_DIR/installer) to quarantine?"; then
    quarantine "$RC_DIR/installer"
  fi
  if [[ -n $RC_CONF ]]; then
    bk="$OUT/$(basename "$RC_CONF").before"
    [[ -f $bk ]] || cp -a "$RC_CONF" "$bk"
    if (( RC_INSTALLER_ON )) && confirm "Set enable_installer = false in $RC_CONF?"; then
      sed -i -E "s/(\['enable_installer'\][[:space:]]*=[[:space:]]*)true/\1false/" "$RC_CONF" && act "ROUNDCUBE enable_installer = false"
    fi
    if (( RC_CONF_WORLD )) && confirm "Remove world access to $RC_CONF (chmod o-rwx)?"; then
      chmod o-rwx "$RC_CONF" && act "CHMOD o-rwx $RC_CONF"
    fi
    if (( RC_DESKEY_DEFAULT )) && confirm "Replace the default des_key? (logs everyone out of webmail once)"; then
      key=$(ask "  New des_key, exactly 24 letters/digits (blank = random): ")
      [[ -z $key ]] && key=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)
      if [[ $key =~ ^[A-Za-z0-9]{24}$ ]]; then
        sed -i -E "s/(\['des_key'\][[:space:]]*=[[:space:]]*)'[^']*'/\1'$key'/" "$RC_CONF" && act "ROUNDCUBE des_key replaced"
      else
        warn "need exactly 24 letters/digits; skipped"
      fi
    fi
    if have php && ! php -l "$RC_CONF" >/dev/null 2>&1; then
      warn "$RC_CONF no longer parses; restoring it"; cp -a "$bk" "$RC_CONF"; act "RESTORED $RC_CONF"
    fi
  fi

  each_reset
  for f in "${WEBSHELLS[@]}"; do
    [[ -f $f ]] || continue
    echo; warn "$f  [$(stat -c %U "$f" 2>/dev/null) $(date -r "$f" '+%F %R' 2>/dev/null)]"
    line=$(grep -noiE ".{0,40}($WEBSHELL_RE).{0,40}" "$f" 2>/dev/null | head -n 3)
    [[ -z $line ]] && line=$(head -c 300 "$f" | tr -c '[:print:]\n' '.' | head -n 4)
    show <<<"$line"
    each "Quarantine it? (if it's really part of the webmail app, re-check webmail after)" && quarantine "$f"
  done

  if [[ -d /etc/php.d ]]; then
    if confirm "Write $ini: expose_php = Off, allow_url_include = Off, display_errors = Off?"; then
      printf '; added by webmail-5min.sh %s\nexpose_php = Off\nallow_url_include = Off\ndisplay_errors = Off\n' "$TS" >"$ini" && \
        { chmod 644 "$ini"; good "wrote $ini"; act "WROTE $ini"; reload=1; }
    fi
    note "disable_functions stops webshells from running commands. Roundcube doesn't need these functions."
    (( SQM_FOUND )) && note "SquirrelMail in 'sendmail' delivery mode needs popen: switch it to SMTP or skip this."
    if have php && confirm "Block exec, passthru, shell_exec, system, proc_open, popen, pcntl_exec in PHP?"; then
      cur_df=$(php -r 'echo ini_get("disable_functions");' 2>/dev/null)
      df="exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec"
      [[ -n $cur_df ]] && df="$cur_df,$df"
      printf 'disable_functions = %s\n' "$df" >>"$ini" && \
        { chmod 644 "$ini"; good "disable_functions added to $ini"; act "PHP disable_functions = $df ($ini)"; reload=1; }
    fi
  fi
  if (( reload )); then
    if have apachectl && ! apachectl configtest >/dev/null 2>&1; then
      warn "apachectl configtest already fails (not from this script); not reloading. Run: apachectl configtest"
    else
      if systemctl reload httpd 2>/dev/null || apachectl graceful 2>/dev/null; then good "httpd reloaded"; act "httpd reloaded"
      else warn "httpd reload failed: systemctl status httpd"; fi
      if [[ $(svc_state php-fpm) == active ]]; then
        if systemctl reload php-fpm 2>/dev/null; then good "php-fpm reloaded"; act "php-fpm reloaded"; else warn "php-fpm reload failed"; fi
      fi
    fi
    http_check
  fi
}

step_persist() {
  hdr "8) Persistence"
  local f c job unit parent reload=0
  for f in "${CRON_FLAG_FILES[@]}"; do
    [[ -f $f ]] || continue
    echo; info "$f:"; grep -vE '^[[:space:]]*(#|$)' "$f" | head -n 10 | show
    c=$(ask "  [q]uarantine / [e]dit / [s]kip (default): ")
    case $c in q*) quarantine "$f" ;; e*) edit "$f" ;; esac
  done
  (( CRONTAB_FLAG )) && confirm "Edit /etc/crontab?" && edit /etc/crontab
  if have atq; then
    for job in $(atq 2>/dev/null | awk '{print $1}'); do
      info "at job $job:"; at -c "$job" 2>/dev/null | tail -n 5 | show
      confirm "Remove at job $job?" && atrm "$job" && act "ATRM $job"
    done
  fi
  for f in "${UNIT_FLAG_FILES[@]}"; do
    [[ -f $f ]] || continue
    unit=$(basename "$f")
    echo; info "$f:"; grep -vE '^[[:space:]]*(#|$)' "$f" | head -n 12 | show
    if [[ $f == *.d/*.conf ]]; then
      parent=$(basename "${f%/*}" .d)
      confirm "Quarantine this drop-in (it changes $parent)?" && { quarantine "$f"; reload=1; note "restart $parent afterwards to drop the override"; }
    else
      confirm "Stop + disable $unit and quarantine the file?" && \
        { systemctl disable --now "$unit" 2>/dev/null; act "DISABLED unit $unit"; quarantine "$f"; reload=1; }
    fi
  done
  (( reload )) && systemctl daemon-reload 2>/dev/null && act "systemctl daemon-reload"
  if (( PRELOAD_FLAG )) && [[ -f /etc/ld.so.preload ]]; then
    show </etc/ld.so.preload
    confirm "Quarantine /etc/ld.so.preload?" && quarantine /etc/ld.so.preload
  fi
  (( RCLOCAL_FLAG )) && confirm "Edit $RCLOCAL_FILE?" && edit "$RCLOCAL_FILE"
  each_reset
  for f in "${SHELLRC_FLAG_FILES[@]}"; do each "Edit $f (the scan showed the suspicious lines)?" && edit "$f"; done
  if (( ${#IMMUTABLE_FILES[@]} )); then
    printf '%s\n' "${IMMUTABLE_FILES[@]}" | show
    each_reset
    for f in "${IMMUTABLE_FILES[@]}"; do each "chattr -i $f?" && chattr -i "$f" && act "CHATTR -i $f"; done
  fi
  each_reset
  for f in "${SUID_FLAG_FILES[@]}"; do
    [[ -f $f ]] || continue
    info "$(ls -la "$f" 2>/dev/null)"
    each "Remove the SUID/SGID bit from $f (chmod u-s,g-s)?" && chmod u-s,g-s "$f" && { good "fixed $f"; act "CHMOD u-s,g-s $f"; }
  done
  each_reset
  for f in "${TMP_FLAG_FILES[@]}"; do
    [[ -f $f ]] || continue
    info "$(ls -la "$f" 2>/dev/null)  [$(file -b "$f" 2>/dev/null | cut -c1-50)]"
    each "Quarantine $f?" && quarantine "$f"
  done
}

step_ssh() {
  hdr "9) SSH daemon"
  have sshd || { info "sshd not installed"; return; }
  local block="" c au
  SSHD_T=$(sshd -T 2>/dev/null)
  info "now: PermitRootLogin $(sshv permitrootlogin) | PasswordAuthentication $(sshv passwordauthentication) | MaxAuthTries $(sshv maxauthtries) | AllowUsers $(sshv allowusers)"
  note "Keep console access or a sudo admin before turning root login off. Open sessions stay up."
  c=$(ask "  PermitRootLogin: [n]o / [k]eys only / [l]eave as is (default): ")
  case $c in
    n*) block+=$'PermitRootLogin no\n' ;;
    k*) block+=$'PermitRootLogin without-password\n' ;;
  esac
  confirm "Add PermitEmptyPasswords no, MaxAuthTries 3, X11Forwarding no, PermitUserEnvironment no, AllowTcpForwarding no (no pivoting through this box)?" && \
    block+=$'PermitEmptyPasswords no\nMaxAuthTries 3\nX11Forwarding no\nPermitUserEnvironment no\nAllowTcpForwarding no\n'
  (( SSH_AKF_FLAG )) && confirm "Reset AuthorizedKeysFile to .ssh/authorized_keys?" && block+=$'AuthorizedKeysFile .ssh/authorized_keys\n'
  (( SSH_AKC_FLAG )) && confirm "Turn off AuthorizedKeysCommand?" && block+=$'AuthorizedKeysCommand none\n'
  au=$(ask "  AllowUsers (only these may SSH in), space-separated, blank = no change: ")
  [[ -n $au ]] && block+="AllowUsers $au"$'\n'
  [[ -z $block ]] && { info "no SSH changes"; return; }
  info "This goes at the top of /etc/ssh/sshd_config (sshd uses the first value it sees):"
  show <<<"${block%$'\n'}"
  confirm "Apply, test with sshd -t, then reload sshd?" || return
  cp -a /etc/ssh/sshd_config "$OUT/sshd_config.before"
  { printf '# --- added by webmail-5min.sh %s ---\n%s# --- end webmail-5min.sh ---\n\n' "$TS" "$block"
    cat "$OUT/sshd_config.before"; } >/etc/ssh/sshd_config
  if sshd -t 2>"$OUT/sshd-t.txt"; then
    if systemctl reload sshd 2>/dev/null; then good "sshd reloaded"; else warn "sshd reload failed: systemctl status sshd"; fi
    act "SSHD settings: $(tr '\n' ';' <<<"$block")"
  else
    warn "sshd -t failed, putting the original sshd_config back:"; show <"$OUT/sshd-t.txt"
    cat "$OUT/sshd_config.before" >/etc/ssh/sshd_config
  fi
}

step_services() {
  hdr "10) Unneeded services"
  note "Leave alone: postfix, dovecot, httpd/php-fpm, mariadb/mysqld (webmail DB), sshd if it's scored."
  local s extra
  each_reset
  for s in "${UNNEEDED_SVCS[@]}"; do
    each "Stop and disable $s?" && systemctl disable --now "$s" 2>/dev/null && { good "$s stopped"; act "DISABLED service $s"; }
  done
  extra=$(ask "  Other services to stop + disable, space-separated, blank = none: ")
  for s in $extra; do
    if [[ $s =~ ^(postfix|dovecot|httpd|php-fpm|mariadb|mysqld|sshd)$ ]]; then confirm "$s is probably SCORED. Really stop it?" || continue; fi
    systemctl disable --now "$s" && { good "$s stopped"; act "DISABLED service $s"; }
  done
}

step_selinux() {
  hdr "11) SELinux"
  have getenforce || { info "SELinux tools not installed"; return; }
  local m
  m=$(getenforce)
  info "mode: $m"
  case $m in
    Enforcing) good "already enforcing" ;;
    Permissive)
      note "Enforcing can break webmail if file labels/booleans are wrong. Undo instantly with: setenforce 0"
      if confirm "setenforce 1 now (lasts until reboot)?"; then
        setenforce 1 && act "SETENFORCE 1"
        verify_services
        if confirm "Everything still up? Make Enforcing permanent in /etc/selinux/config?"; then
          sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config && act "SELINUX=enforcing in /etc/selinux/config"
        elif confirm "Go back to Permissive now?"; then
          setenforce 0 && act "SETENFORCE 0"
        fi
      fi ;;
    *) note "Disabled: turning it on needs a relabel and reboot. Not mid-competition." ;;
  esac
  have getsebool && getsebool httpd_can_network_connect httpd_can_sendmail httpd_execmem httpd_enable_cgi 2>/dev/null | show
  note "If webmail breaks under Enforcing: ausearch -m avc -ts recent; then e.g. setsebool -P httpd_can_network_connect on"
}

step_mysql() {
  hdr "12) MySQL / MariaDB"
  have mysql || { info "no MySQL/MariaDB client installed"; return; }
  local tool=""
  [[ -n $RC_DBUSER ]] && info "Roundcube logs in as DB user '$RC_DBUSER' (config: $RC_CONF)"
  [[ $RC_DBUSER == root ]] && warn "Roundcube uses DB root: if you change root's DB password, update db_dsnw in $RC_CONF too or webmail breaks"
  have mariadb-secure-installation && tool=mariadb-secure-installation
  have mysql_secure_installation && tool=mysql_secure_installation
  if [[ -n $tool ]] && confirm "Run $tool (you type the passwords; it removes anonymous users, test DB and remote root)?"; then
    on_tty "$tool" && act "RAN $tool"
  fi
}

# ---- verification -------------------------------------------------------------
check_port() {       # check_port <port> <greeting regex> <name>
  local line
  line=$(timeout 4 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1 && head -n1 <&3" 2>/dev/null | tr -d '\r')
  if [[ $line =~ $2 ]]; then good "$3 :$1 answers: ${line:0:70}"
  else warn "$3 :$1 did not answer as expected: '${line:0:70}'"; fi
}
check_tls() {        # check_tls <port> <greeting regex> <name>
  local line
  line=$(timeout 5 openssl s_client -connect "127.0.0.1:$1" -quiet -ign_eof </dev/null 2>/dev/null | head -n1 | tr -d '\r')
  if [[ $line =~ $2 ]]; then good "$3 :$1 answers: ${line:0:70}"
  else warn "$3 :$1 did not answer as expected: '${line:0:70}'"; fi
}
http_check() {
  have curl || { warn "curl not installed; open the webmail in a browser instead"; return; }
  local url code
  for url in http://127.0.0.1/ https://127.0.0.1/; do
    code=$(curl -sk -o /dev/null -m 5 -w '%{http_code}' "$url" 2>/dev/null)
    case $code in 2*|3*) good "$url -> $code" ;; *) warn "$url -> ${code:-no answer}" ;; esac
  done
  for url in roundcubemail roundcube webmail mail squirrelmail; do
    for p in http https; do
      code=$(curl -sk -o /dev/null -m 5 -w '%{http_code}' "$p://127.0.0.1/$url/" 2>/dev/null)
      case $code in 2*|3*) good "$p://127.0.0.1/$url/ -> $code" ;; 401|403|5*) warn "$p://127.0.0.1/$url/ -> $code" ;; esac
    done
  done
}
verify_services() {
  hdr "Service check (from this box)"
  local s open u
  for s in postfix dovecot httpd nginx php-fpm mariadb mysqld sshd; do
    unit_exists "$s" || continue
    if [[ $(svc_state "$s") == active ]]; then good "$s active"; else warn "$s: $(svc_state "$s")"; fi
  done
  open=" $(ss -ltn 2>/dev/null | awk 'NR>1{print $4}' | sed 's/.*://' | sort -u | tr '\n' ' ') "
  check_port 25 '^220' SMTP
  [[ $open == *" 587 "* ]] && check_port 587 '^220' Submission
  check_port 110 '^\+OK' POP3
  check_port 143 '^\* OK' IMAP
  if have openssl; then
    [[ $open == *" 995 "* ]] && check_tls 995 '^\+OK' POP3S
    [[ $open == *" 993 "* ]] && check_tls 993 '^\* OK' IMAPS
  fi
  http_check
  if have curl && confirm "Test a real mailbox login over IMAP (you type the password at curl's prompt)?"; then
    u=$(ask "  mail username: ")
    if [[ -n $u ]]; then
      if on_tty curl -s -m 10 -u "$u" imap://127.0.0.1/; then good "IMAP login works for $u"; else warn "IMAP login FAILED for $u"; fi
    fi
  fi
}

# =============================================================================
#  MAIN
# =============================================================================
STEP_FUNCS=(step_passwords step_procs step_accounts step_firewall step_postfix step_dovecot
            step_web step_persist step_ssh step_services step_selinux step_mysql)

menu() {
  local c s
  REPORT=$OUT/menu-session.txt
  while true; do
    printf '\n%s=== MENU (nothing changes unless you answer y) ===%s\n' "$B" "$N"
    cat <<EOF
   1) Passwords (you type them)           7) Webmail installer / webshells / PHP
   2) Kill flagged processes & sessions   8) Persistence: cron, systemd, preload, SUID
   3) Accounts, sudo, SSH keys            9) SSH daemon settings
   4) Firewall allowlist (auto-rollback) 10) Unneeded services
   5) Postfix relay / BCC / forwards     11) SELinux
   6) Dovecot auth backdoors             12) MySQL / MariaDB
   a) walk 1-12 in order   v) verify services   f) show flags   r) re-scan   q) quit
EOF
    c=$(ask "  choice: ") || break
    case $c in
      [1-9]|1[0-2]) "${STEP_FUNCS[c-1]}" ;;
      a) for s in "${STEP_FUNCS[@]}"; do
           "$s"
           c=$(ask "  [enter] next step / [s]top walking: ") || break
           [[ $c == s* ]] && break
         done
         verify_services ;;
      v) verify_services ;;
      f) cat "$FLAGFILE" ;;
      r) REPORT=$OUT/scan-report-$(date +%H%M%S).txt; FLAGFILE=${REPORT%.txt}-flags.txt
         run_scan; summary; REPORT=$OUT/menu-session.txt ;;
      q) break ;;
    esac
  done
}

finish() {
  echo
  printf '  Scan report : %s\n  Flags       : %s\n  Changes log : %s (use it for incident reports)\n  Quarantine  : %s\n' \
    "$OUT/scan-report.txt" "$FLAGFILE" "$ACTLOG" "$QUAR"
  printf '  %sCopy %s off this box now (e.g. scp -r %s you@jumpbox:).%s\n' "$Y" "$OUT" "$OUT" "$N"
}

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

main() {
  local scan_only=0
  case ${1:-} in
    -s|--scan-only) scan_only=1 ;;
    -h|--help)      usage; exit 0 ;;
    "") ;;
    *)              echo "unknown option: $1"; usage; exit 1 ;;
  esac
  [[ $EUID -eq 0 ]] || { echo "Run this as root."; exit 1; }
  if (( ! scan_only )) && ! { : <"$TTY"; } 2>/dev/null; then
    echo "No terminal for prompts. Run it interactively, or use --scan-only."; exit 1
  fi
  mkdir -p "$OUT" || exit 1
  chmod 700 "$BASE_DIR" "$OUT"
  : >"$REPORT"; : >"$ACTLOG"

  cat <<EOF
${B}
  MACCDC webmail: first 5 minutes  (v$VERSION)   $(hostname)   $(date '+%F %T')${N}
  The scan is read-only. Every change asks first (default No). You type all passwords.
  Output: $OUT

  0:00 backup > 0:30 scan > 1:30 [1] passwords > 2:00 [2] kill shells, [3] accounts/keys
  2:45 [4] firewall > 3:30 [5] postfix, [6] dovecot > 4:15 [7] webmail, [8] persistence > 4:45 [v] verify
EOF
  trap 'echo; finish; exit 130' INT

  detect_web
  if (( ! scan_only )) && confirm_yes "Back up /etc, /root, cron spools, web roots, mail + firewall state to $BACKUP first?"; then
    do_backup
  fi
  nohup nice -n 19 rpm -Va >"$OUT/rpm-Va.txt" 2>&1 </dev/null &
  note "full 'rpm -Va' running in the background -> $OUT/rpm-Va.txt (look for '5' on non-config files later)"

  run_scan
  summary
  (( scan_only )) || menu
  finish
}

main "$@"

