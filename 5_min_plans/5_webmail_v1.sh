#!/usr/bin/env bash
# =============================================================================
#  5_Min_Plan_Debian_Webmail.sh - first-5-minutes script for a Debian/Ubuntu
#        webmail box (Postfix + Dovecot + Apache2/PHP webmail such as Roundcube)
#
#  Debian port of 5_Min_Plan_Fedora_Webmail.sh. Same flow, same ground rules,
#  plus the fixes listed in Linux_5_Min_Plan_Review.md.
#
#  Run as root:   bash 5_Min_Plan_Debian_Webmail.sh              scan, then menu
#                 bash 5_Min_Plan_Debian_Webmail.sh --scan-only  read-only scan
#                 add --no-pager (first) to turn off the screen-by-screen pauses
#
#  NO SCROLLBACK NEEDED: output stops at every full screen ("-- more --"), each
#  menu step starts on a clean screen, and menu keys f / s / l / m open the
#  flags, full report, changes log or session output in a full-screen viewer
#  (space = down, b = up, / = search, q = back to the menu).
#
#  Ground rules this script keeps:
#    * NO NETWORK. Nothing is downloaded or installed. Only tools from a base
#      Debian install are required; optional ones (ufw, nft, iptables, getcap,
#      aa-status, mysql, openssl) are used only if already there, with
#      pure-bash fallbacks (HTTP / IMAP checks use bash's /dev/tcp, no curl).
#    * The scan is read-only. It only writes its own report folder
#      ($CCDC_DIR, default /root/.ccdc/<timestamp>).
#    * Nothing on the system changes unless you answer "y". Prompts default to No.
#    * You type every password into passwd / chpasswd / mysql's own prompts.
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

# ---- don't trust the environment we were started from ---------------------------
# A planted /usr/local/bin/ps or an LD_PRELOAD in root's shell would make the
# scan lie. Use only the system directories and a predictable locale.
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV CDPATH GREP_OPTIONS
umask 077

VERSION=1.0-debian
ME_NAME=5_Min_Plan_Debian_Webmail.sh
BASE_DIR=${CCDC_DIR:-/root/.ccdc}
ROLLBACK_SECS=${ROLLBACK_SECS:-60}
[[ $ROLLBACK_SECS =~ ^[0-9]+$ ]] && (( ROLLBACK_SECS >= 30 )) || ROLLBACK_SECS=60
TS=$(date +%Y%m%d-%H%M%S)
OUT=$BASE_DIR/$TS
REPORT=$OUT/scan-report.txt
SCAN_REPORT=$REPORT
FLAGFILE=$OUT/flags.txt
ACTLOG=$OUT/actions.log
QUAR=$OUT/quarantine
BACKUP=$OUT/backup
TTY=/dev/tty
EDITOR_CMD=${EDITOR:-}
[[ -z $EDITOR_CMD ]] && for e in vim.tiny vi nano; do command -v "$e" >/dev/null 2>&1 && { EDITOR_CMD=$e; break; }; done
EDITOR_CMD=${EDITOR_CMD:-vi}
NOLOGIN=/usr/sbin/nologin; [[ -x $NOLOGIN ]] || NOLOGIN=/sbin/nologin

# TCP ports a webmail box is expected to serve. Any other port listening on a
# non-loopback address gets flagged.
MAIL_PORTS="22 25 80 110 143 443 465 587 993 995 4190"
UDP_OK="68 123 323 546"
CORE_SVCS="postfix dovecot apache2"
ADMIN_GROUPS="sudo admin wheel"            # Debian: sudo; Ubuntu (old): admin
ROOTEQ_GROUPS="docker lxd disk libvirt"    # membership = root without sudo

# The account YOU logged in with (never locked, kicked or removed from sudo).
ME="${SUDO_USER:-$(logname 2>/dev/null)}"
[[ $ME == root ]] && ME=""

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
UID0_USERS=(); EMPTY_PW_USERS=(); SHELL_USERS=(); SYS_SHELL_USERS=(); HUMAN_USERS=(); SYS_PW_USERS=()
SUDO_FLAG_FILES=(); AUTH_KEYS=(); SSH_RC_FILES=(); SUS_PROCS=(); LISTEN_PORTS=(); SUID_FLAG_FILES=(); CAP_FLAG_FILES=()
CRON_FLAG_FILES=(); UNIT_FLAG_FILES=(); MISC_FLAG_FILES=(); SHELLRC_FLAG_FILES=(); IMMUTABLE_FILES=(); TMP_FLAG_FILES=()
FORWARD_FILES=(); SIEVE_FLAG_FILES=(); PF_MAP_FLAG_FILES=(); DC_HITS=(); WEBSHELLS=(); PAM_FLAG_FILES=()
UNNEEDED_SVCS=(); WEBROOTS=(); AA_COMPLAIN=(); SSH_MATCH_FILES=(); PHP_SAPI_DIRS=(); PHPFPM_UNITS=()
FW=none; SSHD_T=""
RC_DIR=""; RC_CONF=""; RC_DBFILE=""; RC_DBUSER=""; RC_PKG=0
RC_INSTALLER_ON=0; RC_DESKEY_DEFAULT=0; RC_CONF_WORLD=0; SQM_FOUND=0
ALIAS_FLAG=0; PRELOAD_FLAG=0; CRONTAB_FLAG=0; RCLOCAL_FLAG=0; RCLOCAL_FILE=""
SSH_AKF_FLAG=0; SSH_AKC_FLAG=0; DC_PWLOG=0

# ---- output helpers ------------------------------------------------------------
rep()     { printf '%s\n' "$*" >>"$REPORT"; }
section() { SECTION=$1; pg_line ""; pg_line "$B=== $1 ===$N"; rep ""; rep "=== $1 ==="; }
hdr()     { (( PG_ON )) && printf '\e[H\e[2J'; pg_reset; pg_line "$B--- $1 ---$N"; rep ""; rep "--- $1 ---"; }
info()    { pg_line "  $*"; rep "  $*"; }
good()    { pg_line "  ${G}[ok]${N} $*"; rep "  [ok] $*"; }
note()    { pg_line "  ${Y}[i]${N} $*"; rep "  [i] $*"; }
flag()    { FLAGS+=("[$SECTION] $*"); pg_line "  ${R}[!]${N} $*"; rep "  [!] $*"; }
warn()    { pg_line "  ${R}[!]${N} $*"; rep "  [!] $*"; }
show()    { local l; while IFS= read -r l; do l="      ${l:0:214}"; printf '%s\n' "$l" >>"$REPORT"; pg_line "$l"; done; }
act()     { printf '%s  %s\n' "$(date '+%F %T')" "$*" >>"$ACTLOG"; }
have()    { command -v "$1" >/dev/null 2>&1; }
inlist()  { [[ " $2 " == *" $1 "* ]]; }          # inlist word "space separated list"

# ---- built-in pager (for consoles with NO scrollback) -------------------------
# Every line printed to the terminal is counted. When the screen is full the
# script stops with "-- more --" until you press a key. Answering a question
# starts a fresh screen. view_file opens a saved file full-screen with paging
# and search. Pure bash: no less/more needed. Turn off: NOPAGER=1 or --no-pager.
shopt -s lastpipe extglob                # "cmd | show" runs show in this shell, so the count is kept
PG_ON=0; PG_N=0; PG_ROWS=24; PG_COLS=80; PG_FILE=""
pg_init() {          # pg_init <dir for the reset marker>
  [[ -t 1 && -z ${NOPAGER:-} ]] && { : <"$TTY"; } 2>/dev/null || return 0
  local s; s=$(stty size <"$TTY" 2>/dev/null)
  [[ ${s% *} =~ ^[0-9]+$ ]] && (( ${s% *} > 5 )) && PG_ROWS=${s% *}
  [[ ${s#* } =~ ^[0-9]+$ ]] && (( ${s#* } > 20 )) && PG_COLS=${s#* }
  PG_FILE=$1/.pager-reset; PG_ON=1
}
pg_reset() { PG_N=0; [[ -n $PG_FILE ]] && : >"$PG_FILE" 2>/dev/null; }   # marker works from $(subshells) too
pg_line() {          # print one line; pause when the screen is full
  printf '%s\n' "$1"
  (( PG_ON )) || return 0
  [[ -e $PG_FILE ]] && { rm -f "$PG_FILE"; PG_N=0; }
  local plain=${1//$'\e'\[*([0-9;])m/}
  (( PG_N += 1 + ${#plain} / PG_COLS ))
  (( PG_N < PG_ROWS - 1 )) && return 0
  local k
  printf '\e[7m-- more --  [Enter/space] next page   [s] skip to next question   [q] stop paging \e[0m' >"$TTY"
  read -rsn1 k <"$TTY"
  printf '\r\e[K' >"$TTY"
  case $k in s|S) PG_N=-100000 ;; q|Q) PG_ON=0 ;; *) PG_N=0 ;; esac
}
view_file() {        # full-screen viewer: space/Enter down, b up, g/G top/end, / search, n next, q quit
  local f=$1 lines=() top=0 h k pat="" i n
  [[ -s $f ]] || { pg_line "  (empty: $f)"; return; }
  if [[ ! -t 1 ]] || ! { : <"$TTY"; } 2>/dev/null; then cat "$f"; return; fi
  mapfile -t lines < <(sed 's/\t/    /g' "$f" | fold -w "$PG_COLS")
  n=${#lines[@]}; h=$(( PG_ROWS - 1 ))
  while true; do
    printf '\e[H\e[2J' >"$TTY"
    for (( i = top; i < top + h && i < n; i++ )); do printf '%s\n' "${lines[i]}"; done >"$TTY"
    printf '\e[7m %s  %d-%d/%d  [space]down [b]up [g]top [G]end [/]find [n]next [q]uit \e[0m' \
      "${f##*/}" $(( top + 1 )) "$i" "$n" >"$TTY"
    read -rsn1 k <"$TTY"
    case $k in
      ""|" "|j|f) (( top + h < n )) && (( top += h )) ;;
      b|k|u)      (( top -= h )); (( top < 0 )) && top=0 ;;
      g)          top=0 ;;
      G)          top=$(( n > h ? n - h : 0 )) ;;
      /|n)        if [[ $k == / ]]; then printf '\r\e[K' >"$TTY"; read -r -p "find: " pat <"$TTY"; fi
                  [[ -z $pat ]] && continue
                  for (( i = top + 1; i < n; i++ )); do [[ ${lines[i],,} == *"${pat,,}"* ]] && { top=$i; break; }; done ;;
      q|Q)        break ;;
    esac
  done
  printf '\e[H\e[2J' >"$TTY"; pg_reset
}

# ---- prompts (always read the terminal, never stdin) --------------------------
confirm() {
  local a
  read -r -p "  ${Y}?${N} $1 [y/N] " a <"$TTY" || { echo; return 1; }
  pg_reset; [[ $a == [yY]* ]]
}
confirm_yes() {
  local a
  read -r -p "  ${Y}?${N} $1 [Y/n] " a <"$TTY" || { echo; return 1; }
  pg_reset; [[ -z $a || $a == [yY]* ]]
}
EACH_ALL=0; EACH_STOP=0
each_reset() { EACH_ALL=0; EACH_STOP=0; }
each() {
  (( EACH_ALL )) && return 0
  (( EACH_STOP )) && return 1
  local a
  read -r -p "  ${Y}?${N} $1 [y/N/a=all/q=skip rest] " a <"$TTY" || { echo; return 1; }
  pg_reset
  case $a in
    [yY]*) return 0 ;;
    [aA]*) EACH_ALL=1; return 0 ;;
    [qQ]*) EACH_STOP=1; return 1 ;;
  esac
  return 1
}
ask() {
  local a
  read -r -p "$1" a <"$TTY" || return 1
  pg_reset; printf '%s' "$a"
}
on_tty() { "$@" <"$TTY" >"$TTY" 2>&1; pg_reset; }
edit() {
  local f=$1 before
  before=$(md5sum <"$f" 2>/dev/null)
  # shellcheck disable=SC2086
  on_tty $EDITOR_CMD "$f"
  if [[ $(md5sum <"$f" 2>/dev/null) != "$before" ]]; then act "EDITED $f"; return 0; fi
  return 1
}
quarantine() {
  local f=$1 dest=$QUAR$1
  mkdir -p "$(dirname "$dest")"
  if mv -f -- "$f" "$dest" 2>/dev/null; then
    act "QUARANTINED $f -> $dest"; good "moved $f -> $dest"
  else
    warn "could not move $f (immutable? check: lsattr -d '$f')"; return 1
  fi
}

# ---- package database (dpkg) ---------------------------------------------------
# Built once from /var/lib/dpkg/info/*.list. Paths are folded so /usr/bin/x and
# /bin/x compare equal (merged-/usr systems list either form).
PKG_DB=""; CONF_DB=""
canon_awk='{ p=$0; if (p ~ /^\/usr\/(bin|sbin|lib|lib32|lib64|libx32)\//) p=substr(p,5); print p }'
build_pkgdb() {
  [[ -n $PKG_DB && -s $PKG_DB ]] && return
  PKG_DB=$OUT/pkg-files.txt
  {
    cat /var/lib/dpkg/info/*.list 2>/dev/null
    # files a package moved aside with dpkg-divert are still package files
    dpkg-divert --list 2>/dev/null | sed -nE 's/^diversion of [^ ]+ to ([^ ]+) by .*/\1/p'
  } | awk "$canon_awk" | sort -u >"$PKG_DB"
}
unowned() {          # print the arguments that no Debian package installed
  (( $# )) || return 0
  build_pkgdb
  printf '%s\n' "$@" | awk -v db="$PKG_DB" '
    BEGIN { while ((getline l < db) > 0) own[l] = 1 }
    { p = $0; if (p ~ /^\/usr\/(bin|sbin|lib|lib32|lib64|libx32)\//) p = substr(p, 5)
      if (!(p in own)) print $0 }'
}
build_confdb() {
  [[ -n $CONF_DB && -s $CONF_DB ]] && return
  CONF_DB=$OUT/conffiles.txt
  dpkg-query -W -f='${Conffiles}\n' 2>/dev/null | awk 'NF >= 2 && $3 != "obsolete" { print $1, $2 }' >"$CONF_DB"
}
is_conffile()    { build_confdb; awk -v f="$1" '$1 == f { found = 1; exit } END { exit !found }' "$CONF_DB"; }
stock_conffile() {   # 0 if $1 is a package conffile whose content is unchanged
  local want
  build_confdb
  want=$(awk -v f="$1" '$1 == f { print $2; exit }' "$CONF_DB")
  [[ -n $want && $(md5sum <"$1" 2>/dev/null | cut -d' ' -f1) == "$want" ]]
}
stock_or_unowned_check() {   # print files that are unowned OR modified conffiles
  local f
  unowned "$@"
  for f in "$@"; do is_conffile "$f" && ! stock_conffile "$f" && echo "$f"; done
}

# ---- small utilities -----------------------------------------------------------
real_dirs()   { local d; for d in "$@"; do [[ -d $d ]] && readlink -f "$d"; done | sort -u; }
unit_exists() { systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1\.service"; }
svc_state() {
  local s
  case $1 in
    # Debian's postfix.service is a oneshot wrapper that reads "active" even when
    # the real daemon (postfix@-) is dead. Ask postfix itself.
    postfix) if postfix status >/dev/null 2>&1; then echo active; else echo inactive; fi; return ;;
  esac
  if [[ -d /run/systemd/system ]]; then s=$(systemctl is-active "$1" 2>/dev/null); echo "${s:-unknown}"; return; fi
  case $1 in mariadb|mysql) s='mariadbd|mysqld' ;; apache2) s=apache2 ;; *) s=$1 ;; esac
  if pgrep -x "$s" >/dev/null 2>&1; then echo active; else echo inactive; fi
}
ver_lt()      { [[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1) == "$1" ]]; }
sshv()        { awk -v k="$1" 'tolower($1)==k { $1=""; sub(/^ +/, ""); print; exit }' <<<"$SSHD_T"; }
pcn()         { postconf -n "$1" 2>/dev/null | sed 's/^[^=]*= *//'; }
pch()         { postconf -xh "$1" 2>/dev/null || postconf -h "$1" 2>/dev/null; }
pfmaps()      { grep -oE '(hash|lmdb|btree|cdb|dbm|texthash|regexp|pcre|cidr):/[^ ,]+' <<<"$1"; }
relay_ok() {
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
php_ini_val() {      # php_ini_val <sapi dir> <key>: last value set in php.ini + conf.d/*.ini
  cat "$1/php.ini" "$1"/conf.d/*.ini 2>/dev/null |
    sed -nE "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*//p" | tail -n1 | tr -d '"'
}

# Processes that are this script or its ancestors (your own SSH session).
MY_PIDS=" "
p=$$; while [[ $p =~ ^[0-9]+$ ]] && (( p > 1 )); do MY_PIDS+="$p "; p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' '); done
unset p
ssh_sessions() {     # "pid user@tty" for every SSH login, including ones with no terminal (notty)
  ps -eo pid=,args= 2>/dev/null | awk '$2 ~ /^sshd(-session)?:$/ && $3 ~ /@/ { print $1, $3 }'
}
end_sessions() {     # log a user out everywhere. Never "kill all root processes" for a UID-0 alias.
  local u=$1 pid s
  while read -r pid s; do
    [[ ${s%@*} == "$u" ]] || continue
    inlist "$pid" "$MY_PIDS" && continue
    kill -KILL "$pid" 2>/dev/null
  done < <(ssh_sessions)
  [[ $(id -u "$u" 2>/dev/null) != 0 ]] && pkill -KILL -u "$u" 2>/dev/null
}

# ---- pure-bash network checks (no curl) ---------------------------------------
tcp_banner() {       # tcp_banner <port>: first line the service sends
  timeout 4 bash -c 'exec 3<>/dev/tcp/127.0.0.1/"$1" && head -n1 <&3' _ "$1" 2>/dev/null | tr -d '\r'
}
http_code() {        # http_code <port> <path>
  timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/"$1" || exit 1
    printf "GET %s HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n" "$2" >&3
    head -n1 <&3' _ "$1" "$2" 2>/dev/null | awk '{print $2}'
}
https_code() {       # https_code <path>   (needs openssl; skipped if absent)
  have openssl || return 0
  printf 'GET %s HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n' "$1" |
    timeout 6 openssl s_client -connect 127.0.0.1:443 -quiet 2>/dev/null | head -n1 | awk '{print $2}'
}
imap_login() {       # imap_login <user> <password>. Runs in a subshell, so the password
  local u=$1 p=$2     # never shows up in any process's command line.
  p=${p//\\/\\\\}; p=${p//\"/\\\"}; u=${u//\\/\\\\}; u=${u//\"/\\\"}
  ( exec 3<>/dev/tcp/127.0.0.1/143 || exit 2
    read -r -t 5 line <&3 || exit 2
    printf 'a1 LOGIN "%s" "%s"\r\n' "$u" "$p" >&3
    while read -r -t 8 line <&3; do
      if [[ $line == "a1 "* ]]; then printf 'a2 LOGOUT\r\n' >&3; [[ $line == "a1 OK"* ]]; exit; fi
    done
    exit 3 )
}

# ---- auto-rollback for firewall changes ---------------------------------------
RB_CMD=""; RB_PIDFILE=""
arm_rollback() {
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
keep_or_rollback() { # $1 = command that makes the change permanent ("true" = nothing to do)
  local a t=$(( ROLLBACK_SECS - 10 ))
  printf '\n  %sCheck from another machine now: does SSH still work? is scoring still green?%s\n' "$Y" "$N"
  if read -r -t "$t" -p "  Type 'keep' within ${t}s to keep it (anything else or timeout = roll back): " a <"$TTY" && [[ $a == keep ]]; then
    disarm_rollback
    if [[ $1 == true ]]; then good "kept"; act "FIREWALL kept"
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
  info "Host: $(hostname)   OS: ${os:-unknown} (Debian $(cat /etc/debian_version 2>/dev/null))   Kernel: $(uname -r)"
  info "Up: $(uptime | sed 's/^ *//')"
  info "IPv4: $(ip -4 -o addr show 2>/dev/null | awk '$2!="lo"{printf "%s=%s  ", $2, $4}')"
  info "Default route: $(ip route show default 2>/dev/null | head -n1)"
  info "DNS servers: $(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf 2>/dev/null)"
  h=$(grep -vE '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null | grep -vE '^[[:space:]]*(127\.|::1|fe00::|ff0[0-9]::)')
  if [[ -n $h ]]; then note "/etc/hosts has custom entries (check for hijacked names):"; show <<<"$h"; fi
  h=$(grep -E '^[[:space:]]*(passwd|group|shadow|hosts):' /etc/nsswitch.conf 2>/dev/null | grep -vE ':[[:space:]]*(files|systemd|dns|mymachines|myhostname|resolve|\[[^]]*\]|[[:space:]])*$')
  [[ -n $h ]] && { note "/etc/nsswitch.conf uses extra sources (LDAP/SSSD/other: users may exist outside /etc/passwd):"; show <<<"$h"; }
  [[ -n $ME ]] && info "You are logged in as: $ME (protected from locking / sudo removal)" || \
    note "Couldn't tell which account is yours (logged in as root directly?). Answer N for your own account."
}

scan_accounts() {
  section "Accounts & authentication"
  local u pw uid shell lc st line f body norm table="" files=() pdirs=() g has_shell

  mapfile -t UID0_USERS < <(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
  if (( ${#UID0_USERS[@]} )); then flag "UID 0 accounts besides root: ${UID0_USERS[*]}"; else good "only root has UID 0"; fi

  line=$(cut -d: -f3 /etc/passwd | sort | uniq -d | grep -vx 0 | tr '\n' ' ')
  [[ -n ${line// } ]] && flag "duplicate UIDs: $line"
  line=$(awk -F: '$4==0 && $1!="root"{print $1}' /etc/passwd | tr '\n' ' ')
  [[ -n ${line// } ]] && note "accounts whose primary group is root (GID 0): $line"

  mapfile -t EMPTY_PW_USERS < <(awk -F: '$2==""{print $1}' /etc/shadow 2>/dev/null)
  (( ${#EMPTY_PW_USERS[@]} )) && flag "EMPTY password (no password needed to log in): ${EMPTY_PW_USERS[*]}"
  line=$(awk -F: '$2!="x" && $2!="*" && $2!~/^!/ {print $1}' /etc/passwd | tr '\n' ' ')
  [[ -n ${line// } ]] && flag "password hash stored in /etc/passwd (overrides /etc/shadow): $line"

  # Debian: /etc/shadow is 640 root:shadow; o+r or any write bit is wrong
  line=$( { find /etc/shadow /etc/gshadow -perm /o+r; find /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers -perm /go+w; } 2>/dev/null | sort -u | tr '\n' ' ')
  [[ -n ${line// } ]] && flag "bad permissions on: $line"

  SHELL_USERS=(); SYS_SHELL_USERS=(); HUMAN_USERS=(); SYS_PW_USERS=()
  while IFS=: read -r u _ uid _ _ _ shell; do
    has_shell=1
    case $shell in */nologin|*/false|*/sync|*/shutdown|*/halt|"") has_shell=0 ;; esac
    (( has_shell )) && SHELL_USERS+=("$u")
    (( has_shell && uid > 0 && uid < 1000 )) && SYS_SHELL_USERS+=("$u")
    (( uid >= 1000 && uid < 60000 )) && HUMAN_USERS+=("$u")
    pw=$(awk -F: -v u="$u" '$1==u{print $2; exit}' /etc/shadow 2>/dev/null)
    # a nologin shell does not stop PAM services (dovecot, ftp, su -s) from accepting a password
    case $pw in ""|'!'*|'*'*) ;; *) (( ! has_shell && uid > 0 && uid < 1000 )) && SYS_PW_USERS+=("$u") ;; esac
    if (( has_shell || (uid >= 1000 && uid < 60000) )); then
      lc=$(awk -F: -v u="$u" '$1==u{print $3; exit}' /etc/shadow 2>/dev/null)
      case $pw in "") st="EMPTY" ;; '!'*|'*'*) st="locked/none" ;; *) st="set" ;; esac
      [[ $lc =~ ^[0-9]+$ ]] && lc=$(date -d "@$((lc * 86400))" +%F 2>/dev/null)
      table+=$(printf '%-16s uid=%-6s shell=%-17s pw=%-11s changed=%-10s groups=%s' \
        "$u" "$uid" "$shell" "$st" "${lc:--}" "$(id -nG "$u" 2>/dev/null | tr ' ' ',')")$'\n'
    fi
  done </etc/passwd
  info "Users that can log in (shell) or are regular users (UID>=1000):"
  show <<<"${table%$'\n'}"
  for u in "${SYS_SHELL_USERS[@]}"; do flag "system account '$u' (UID<1000) has a login shell"; done
  (( ${#SYS_PW_USERS[@]} )) && flag "system accounts with a usable password (nologin doesn't stop IMAP/POP/su -s logins): ${SYS_PW_USERS[*]}"
  for g in $ADMIN_GROUPS adm; do
    line=$(getent group "$g" | cut -d: -f4)
    [[ -n $line ]] && info "group $g: $line"
  done
  for g in $ROOTEQ_GROUPS; do
    line=$(getent group "$g" | cut -d: -f4)
    [[ -n $line ]] && flag "group '$g' members are root-equivalent: $line"
  done

  # sudo: anything beyond the stock rules. Unlike a comment, '#include' and
  # '#includedir' ARE directives, so they are checked, not skipped. Defaults
  # lines are checked for the ones that hand out root.
  SUDO_FLAG_FILES=()
  while IFS= read -r line; do
    f=${line%%:*}; body=${line#*:}; body=${body#*:}
    norm=$(tr -s ' \t' ' ' <<<"$body" | sed 's/^ //; s/ $//')
    [[ -z $norm ]] && continue
    case $norm in
      [#@]include*)
        if [[ $norm =~ ^[#@]includedir\ /etc/sudoers.d$ ]]; then continue; fi
        flag "sudoers pulls in another file/dir: $f: $norm" ;;
      \#*) continue ;;
      "root ALL=(ALL) ALL"|"root ALL=(ALL:ALL) ALL"|"%sudo ALL=(ALL:ALL) ALL"|"%sudo ALL=(ALL) ALL"|\
      "%admin ALL=(ALL) ALL"|"%admin ALL=(ALL:ALL) ALL"|"%wheel ALL=(ALL) ALL"|"%wheel ALL=(ALL:ALL) ALL") continue ;;
      Defaults*)
        if [[ $norm =~ \!authenticate|LD_PRELOAD|LD_LIBRARY_PATH|BASH_ENV|PYTHONPATH|PERL5LIB ]]; then
          flag "dangerous sudo Defaults (root without a password / code injection): $f: $norm"
        elif [[ $norm =~ secure_path.*(/tmp|/var/tmp|/dev/shm|/home/|/root) ]]; then
          flag "sudo secure_path contains a writable directory: $f: $norm"
        else continue; fi ;;
      *NOPASSWD*) flag "sudo NOPASSWD rule: $f: $norm" ;;
      *)          flag "non-default sudo rule: $f: $norm" ;;
    esac
    [[ $f == /etc/sudoers.d/* ]] && ! inlist "$f" "${SUDO_FLAG_FILES[*]}" && SUDO_FLAG_FILES+=("$f")
  done < <(grep -HnE '' /etc/sudoers /etc/sudoers.d/* 2>/dev/null)
  while IFS= read -r f; do
    [[ -f $f ]] || continue
    flag "sudoers file not from any package: $f"
    inlist "$f" "${SUDO_FLAG_FILES[*]}" || SUDO_FLAG_FILES+=("$f")
  done < <(unowned /etc/sudoers.d/*)

  # PAM. Debian's stock common-auth DOES contain "auth required pam_permit.so"
  # (after a requisite pam_deny), so only other uses of pam_permit in auth are flagged.
  PAM_FLAG_FILES=()
  line=$(grep -HnE '^[[:space:]]*-?auth[[:space:]]+[^#]*pam_permit\.so' /etc/pam.d/* 2>/dev/null |
         grep -vE '^[^:]+:[0-9]+:[[:space:]]*-?auth[[:space:]]+required[[:space:]]+pam_permit\.so')
  [[ -n $line ]] && { flag "PAM auth line lets pam_permit decide (accepts ANY password):"; show <<<"$line"; mapfile -t -O "${#PAM_FLAG_FILES[@]}" PAM_FLAG_FILES < <(cut -d: -f1 <<<"$line" | sort -u); }
  if [[ -f /etc/pam.d/common-auth ]] && ! grep -qE '^[[:space:]]*auth[[:space:]]+requisite[[:space:]]+pam_deny\.so' /etc/pam.d/common-auth; then
    flag "/etc/pam.d/common-auth has no 'auth requisite pam_deny.so' (failed passwords may fall through to success)"
    PAM_FLAG_FILES+=(/etc/pam.d/common-auth)
  fi
  info "/etc/pam.d/common-auth (review: pam_unix, then requisite pam_deny, then required pam_permit is stock):"
  grep -vE '^[[:space:]]*(#|$)' /etc/pam.d/common-auth 2>/dev/null | show
  line=$(grep -HnE '^[^#]*pam_exec\.so' /etc/pam.d/* 2>/dev/null)
  [[ -n $line ]] && { flag "PAM pam_exec runs a program at login (can capture passwords):"; show <<<"$line"; mapfile -t -O "${#PAM_FLAG_FILES[@]}" PAM_FLAG_FILES < <(cut -d: -f1 <<<"$line" | sort -u); }
  # common-* are generated by pam-auth-update (never package-owned); judge them by content above
  mapfile -t files < <(find /etc/pam.d -maxdepth 1 -type f ! -name 'common-*' 2>/dev/null)
  line=$(stock_or_unowned_check "${files[@]}" | sort -u | tr '\n' ' ')
  [[ -n ${line// } ]] && note "PAM files not from a package or changed from the package version: $line"
  mapfile -t files < <(find /usr/share/pam-configs -maxdepth 1 -type f 2>/dev/null)
  line=$(unowned "${files[@]}" | tr '\n' ' ')
  [[ -n ${line// } ]] && flag "pam-auth-update profiles not from any package (they get written into common-*): $line"
  mapfile -t pdirs < <(real_dirs /lib/*/security /usr/lib/*/security /lib/security /usr/lib/security /lib64/security /usr/lib64/security)
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
      note "sshd -T failed (no /run/sshd?); reading sshd_config directly (first match wins)"
      SSHD_T=$(grep -hvE '^[[:space:]]*(#|$)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null)
    fi
    v=$(sshv permitrootlogin)
    case $v in
      yes) flag "PermitRootLogin yes" ;;
      no)  good "PermitRootLogin no" ;;
      "")  note "PermitRootLogin not set" ;;
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
    # Settings inside a Match block override the global ones for some users/hosts,
    # so a "PermitRootLogin yes" there survives our global "no".
    v=$(awk 'FNR==1{m=0} tolower($1)=="match"{m=1; h=$0; next}
             m && tolower($1) ~ /^(permitrootlogin|passwordauthentication|permitemptypasswords|authorizedkeysfile|authorizedkeyscommand|authorizedkeyscommanduser|forcecommand|permituserenvironment|permittunnel|allowtcpforwarding)$/ {
               print FILENAME ":" FNR ": [" h "] " $0 }' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null)
    if [[ -n $v ]]; then
      flag "sshd Match blocks override security settings:"; show <<<"$v"
      mapfile -t SSH_MATCH_FILES < <(cut -d: -f1 <<<"$v" | sort -u)
    fi
    v=$(unowned /etc/ssh/sshd_config.d/*.conf 2>/dev/null | grep -v '\*' | tr '\n' ' ')
    [[ -n ${v// } ]] && note "sshd_config.d files not from a package: $v"
  else
    note "sshd not installed"
  fi

  AUTH_KEYS=(); SSH_RC_FILES=()
  [[ -f /etc/ssh/sshrc ]] && SSH_RC_FILES+=(/etc/ssh/sshrc)
  while IFS=: read -r u _ _ _ _ home _; do
    [[ -n $home && $home != / ]] || continue
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [[ -s $f ]] && ! inlist "$f" "${AUTH_KEYS[*]}" && AUTH_KEYS+=("$f")
    done
    [[ -f $home/.ssh/rc ]] && ! inlist "$home/.ssh/rc" "${SSH_RC_FILES[*]}" && SSH_RC_FILES+=("$home/.ssh/rc")
  done < <(getent passwd)
  (( ${#AUTH_KEYS[@]} )) || good "no authorized_keys files"
  for f in "${AUTH_KEYS[@]}"; do
    flag "SSH keys in $f ($(grep -cvE '^[[:space:]]*(#|$)' "$f") key(s)): whoever holds them gets in"
    keys_summary "$f" | show
  done
  for f in "${SSH_RC_FILES[@]}"; do
    flag "$f runs on EVERY ssh login:"; head -n 5 "$f" | show
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
      if inlist "$port" "$MAIL_PORTS"; then info "expected    $desc"; LISTEN_PORTS+=("$port")
      else flag "unexpected TCP listener: $desc"; fi
    else
      if inlist "$port" "$UDP_OK"; then info "expected    $desc"
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
      bash|sh|dash|zsh|ksh|nc|ncat|netcat|nc.openbsd|nc.traditional|socat|python*|perl|php*|ruby|telnet|openssl|awk|gawk|mawk|lua*|busybox)
        flag "shell/interpreter holds a network connection: $(tr -s ' ' <<<"$line")" ;;
    esac
  done <<<"$est"

  section "Firewall"
  local z zones v rs
  if have ufw; then
    FW=ufw
    v=$(ufw status verbose 2>/dev/null)
    show <<<"$v"
    if grep -q 'Status: active' <<<"$v"; then
      good "ufw active"
      grep -qE 'Default:.*allow \(incoming\)' <<<"$v" && flag "ufw default policy ALLOWS incoming"
    else
      flag "ufw installed but INACTIVE"
    fi
    v=$(ufw show added 2>/dev/null | grep '^ufw')
    [[ -n $v ]] && { info "ufw rules on file (apply when active):"; show <<<"$v"; }
  elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
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
  elif have nft; then
    FW=nft
  elif have iptables; then
    FW=iptables
  else
    FW=none; flag "no firewall tool found (ufw / firewall-cmd / nft / iptables). Nothing can be installed offline: filter at the network edge."
  fi
  # Whatever the front end, the kernel ruleset decides. Is anything dropping inbound?
  if have nft; then
    rs=$(nft list ruleset 2>/dev/null)
    printf '%s\n' "$rs" >"$OUT/nft-ruleset.txt"
    if awk '/^[[:space:]]*chain /{i=0} /hook input/{i=1} i && (/policy drop/ || /(^|[[:space:]])(drop|reject)([[:space:]]|;|$)/){f=1} END{exit !f}' <<<"$rs"; then
      info "nftables: an input chain drops traffic (full ruleset: $OUT/nft-ruleset.txt)"
    else
      flag "NO inbound filtering in the kernel ruleset (no input chain drops anything)"
    fi
    grep -qE '^table inet ccdc' <<<"$rs" && note "table inet ccdc (from this script) is loaded"
  elif have iptables; then
    v=$(iptables -S INPUT 2>/dev/null)
    if [[ $(awk '$1=="-P"{print $3}' <<<"$v") == ACCEPT && $(grep -c '^-A' <<<"$v") == 0 ]]; then
      flag "NO host firewall (iptables INPUT policy ACCEPT, no rules)"
    else info "iptables INPUT:"; show <<<"$v"; fi
  fi
  info "firewall tool the menu will use: $FW"
}

scan_procs() {
  section "Processes"
  SUS_PROCS=()
  EXE=()
  local d exe pid user args comm why
  local re_tcp='/dev/(tcp|udp)/'
  local re_nc='(^|[/[:space:]])(nc|ncat|netcat|nc\.openbsd|nc\.traditional)([[:space:]]|$)'
  local re_socat='(^|[/[:space:]])socat([[:space:]]|$)'
  local re_fifo='mkfifo|mknod[[:space:]].*[[:space:]]p([[:space:]]|$)'
  local re_inline='(^|[/[:space:]])(python[0-9.]*|perl|ruby|php[0-9.]*|lua[0-9.]*)[[:space:]]+-[a-zA-Z]*[ecr]([[:space:]]|$)'
  local re_dl='(curl|wget)[^|]*\|[[:space:]]*(ba|z|da)?sh'
  local re_b64='base64[[:space:]]+(-d|--decode)'
  local re_rtun='(^|[/[:space:]])ssh[[:space:]].*-[a-zA-Z]*R[[:space:]]'
  local re_sshd='^(/usr/sbin/)?sshd[[:space:]].*[[:space:]]-[a-zA-Z]*[fpo]'
  local re_tools='msfconsole|meterpreter|sliver|chisel|ligolo|gs-netcat|gsocket|frpc|xmrig|minerd|pspy|linpeas|reptile'

  while IFS=$'\t' read -r d exe; do EXE[${d#/proc/}]=$exe; done \
    < <(find /proc -mindepth 2 -maxdepth 2 -name exe -printf '%h\t%l\n' 2>/dev/null)

  while read -r pid user args; do
    [[ $pid == "$$" || $pid == "$BASHPID" ]] && continue
    exe=${EXE[$pid]}
    [[ -z $exe ]] && continue
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
      elif [[ $args =~ $re_sshd ]];   then why="second sshd with its own config/port (backdoor sshd?)"
      elif [[ $args =~ $re_tools ]];  then why="known offensive tool name"
      fi
    fi
    if [[ -z $why ]]; then
      case $user in
        www-data|postfix|dovecot|dovenull|mail|nobody|mysql|bind|ftp|Debian-exim|_apt)
          case $comm in
            bash|sh|dash|zsh|ksh|tcsh|csh|python*|perl|ruby|nc|nc.*|ncat|socat|telnet|php*)
              # Debian's php-fpm master/worker processes are called php-fpm8.x: not a shell
              [[ $comm == php-fpm* ]] || why="service account '$user' running $comm (webshell?)" ;;
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
  local w pid s
  w=$(who 2>/dev/null)
  if [[ -n $w ]]; then show <<<"$w"; else info "none in utmp"; fi
  info "SSH sessions (includes ones with no terminal, which 'who' does not show):"
  while read -r pid s; do
    if inlist "$pid" "$MY_PIDS"; then info "    $s (pid $pid)  <- you"; else info "    $s (pid $pid)"; fi
  done < <(ssh_sessions)
}

scan_persistence() {
  section "Persistence: cron / at / systemd / startup files"
  local f line files=() dirs=() re t

  CRON_FLAG_FILES=()
  for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [[ -f $f ]] || continue
    flag "user crontab $f:"; grep -vE '^[[:space:]]*(#|$)' "$f" | show
    CRON_FLAG_FILES+=("$f")
  done
  # Debian's stock /etc/crontab has the run-parts jobs, so judge it by checksum, not by "has jobs"
  if [[ -f /etc/crontab ]]; then
    if stock_conffile /etc/crontab; then good "/etc/crontab is the stock package version"
    else
      line=$(grep -vE '^[[:space:]]*(#|$)|^[[:space:]]*(SHELL|PATH|MAILTO|HOME)=' /etc/crontab | grep -vE 'run-parts.*/etc/cron\.(hourly|daily|weekly|monthly)')
      if [[ -n $line ]]; then flag "/etc/crontab was changed and has extra jobs:"; show <<<"$line"; CRONTAB_FLAG=1
      else note "/etc/crontab differs from the package version (no extra jobs found)"; fi
    fi
  fi
  mapfile -t files < <(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.yearly -maxdepth 1 -type f ! -name .placeholder 2>/dev/null)
  while IFS= read -r f; do
    [[ -z $f ]] && continue
    flag "cron file not from a package (or changed from it): $f"
    grep -vE '^[[:space:]]*(#|$)' "$f" | head -n 5 | show
    inlist "$f" "${CRON_FLAG_FILES[*]}" || CRON_FLAG_FILES+=("$f")
  done < <(stock_or_unowned_check "${files[@]}" | sort -u)
  if have atq; then
    line=$(atq 2>/dev/null)
    [[ -n $line ]] && { flag "queued 'at' jobs:"; show <<<"$line"; }
  fi

  UNIT_FLAG_FILES=()
  mapfile -t dirs < <(real_dirs /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system \
                                /usr/local/lib/systemd/system /etc/systemd/user /usr/lib/systemd/user \
                                /etc/systemd/system-generators /usr/local/lib/systemd/system-generators \
                                /root/.config/systemd/user /home/*/.config/systemd/user)
  if (( ${#dirs[@]} )); then
    mapfile -t files < <(find "${dirs[@]}" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \
                           -o -name '*.path' -o -name '*.conf' -o -perm /111 \) 2>/dev/null | sort -u)
    while IFS= read -r f; do
      [[ $f == /run/systemd/* && $f != */transient/* ]] && continue   # generated at boot by systemd itself
      flag "systemd unit/drop-in/generator not from any package: $f"
      grep -E '^[[:space:]]*(ExecStart|ExecStartPre|ExecStartPost|ExecStop|OnCalendar|OnBootSec|OnUnitActiveSec)=' "$f" | head -n 4 | show
      UNIT_FLAG_FILES+=("$f")
    done < <(unowned "${files[@]}")
    # enabled-unit symlinks that point outside the unit directories
    while IFS= read -r f; do
      t=$(readlink -f "$f" 2>/dev/null)
      case $t in /dev/null|/usr/lib/systemd/*|/lib/systemd/*|/etc/systemd/*|/run/systemd/*) continue ;; esac
      flag "systemd symlink $f -> ${t:-$(readlink "$f")} (points outside the unit dirs)"
      MISC_FLAG_FILES+=("$f")
    done < <(find /etc/systemd/system /etc/systemd/user -type l 2>/dev/null)
  fi
  systemctl list-timers --all --no-pager >>"$REPORT" 2>/dev/null

  for f in /etc/rc.local /etc/rc.d/rc.local; do
    [[ -f $f && ! -L $f ]] || continue
    line=$(grep -vE '^[[:space:]]*(#|$)|^[[:space:]]*exit 0[[:space:]]*$' "$f")
    [[ -n $line ]] && { flag "$f runs commands at boot:"; show <<<"$line"; RCLOCAL_FLAG=1; RCLOCAL_FILE=$f; }
  done

  if [[ -s /etc/ld.so.preload ]]; then
    flag "/etc/ld.so.preload is set (classic userland rootkit):"; show </etc/ld.so.preload; PRELOAD_FLAG=1
  else
    good "/etc/ld.so.preload empty/absent"
  fi

  # Debian-specific places that run code as root without cron or systemd
  local -a extra=()
  mapfile -t files < <(find /etc/update-motd.d /etc/init.d /etc/network/if-up.d /etc/network/if-pre-up.d \
                            /etc/network/if-down.d /etc/NetworkManager/dispatcher.d /etc/dhcp/dhclient-enter-hooks.d \
                            /etc/dhcp/dhclient-exit-hooks.d /etc/ld.so.conf.d /etc/apt/apt.conf.d /etc/X11/Xsession.d \
                            /etc/udev/rules.d /etc/modprobe.d /etc/modules-load.d -maxdepth 1 -type f 2>/dev/null)
  mapfile -t extra < <(stock_or_unowned_check "${files[@]}" | sort -u)
  for f in "${extra[@]}"; do
    case $f in
      /etc/udev/rules.d/70-persistent-*) continue ;;           # written by udev itself
      /etc/apt/apt.conf.d/*)
        grep -qiE 'Invoke|::Pre-|::Post-' "$f" || continue
        flag "apt hook runs commands on every apt/dpkg call: $f"; grep -niE 'Invoke' "$f" | head -n 3 | show ;;
      /etc/udev/rules.d/*)
        grep -qE 'RUN\+?=' "$f" || continue
        flag "udev rule runs a program: $f"; grep -nE 'RUN\+?=' "$f" | head -n 3 | show ;;
      /etc/update-motd.d/*) flag "motd script (runs as root at every SSH login): $f"; grep -vE '^[[:space:]]*(#|$)' "$f" | head -n 4 | show ;;
      *) flag "not from a package / changed from it: $f"; grep -vE '^[[:space:]]*(#|$)' "$f" | head -n 3 | show ;;
    esac
    MISC_FLAG_FILES+=("$f")
  done

  # shell startup files: trojan aliases, callbacks, keyloggers
  SHELLRC_FLAG_FILES=()
  re='alias[[:space:]]+(sudo|su|ls|ps|ss|netstat|passwd|cat|top|lsof|who|w|kill|id|grep|find|systemctl)=|/dev/tcp|(^|[;&|[:space:]])(nc|ncat|socat)[[:space:]]|curl[[:space:]]|wget[[:space:]]|base64[[:space:]]+-d|PROMPT_COMMAND|trap[[:space:]].*DEBUG|LD_PRELOAD'
  for f in /etc/profile /etc/bash.bashrc /etc/environment /etc/profile.d/*.sh /etc/skel/.bashrc /etc/skel/.profile \
           /root/.bashrc /root/.bash_profile /root/.bash_login /root/.profile /root/.bash_logout \
           /home/*/.bashrc /home/*/.bash_profile /home/*/.bash_login /home/*/.profile /home/*/.bash_logout; do
    [[ -f $f ]] || continue
    stock_conffile "$f" && continue                                   # untouched package file
    case $f in /root/*|/home/*) [[ -f /etc/skel/${f##*/} ]] && cmp -s "$f" "/etc/skel/${f##*/}" && stock_conffile "/etc/skel/${f##*/}" && continue ;; esac
    line=$(grep -nE "$re" "$f" 2>/dev/null | grep -vE '^[0-9]+:[[:space:]]*#' |
           grep -vE "alias[[:space:]]+(ls|dir|vdir|grep|fgrep|egrep)=['\"]?(ls|dir|vdir|grep|fgrep|egrep) --color=auto['\"]?[[:space:]]*$")
    [[ -z $line ]] && continue
    flag "suspicious line(s) in $f:"; show <<<"$line"; SHELLRC_FLAG_FILES+=("$f")
  done
  mapfile -t files < <(find /etc/profile.d -maxdepth 1 -type f 2>/dev/null)
  line=$(unowned "${files[@]}" | tr '\n' ' ')
  [[ -n ${line// } ]] && flag "/etc/profile.d files not from any package: $line"

  mapfile -t IMMUTABLE_FILES < <(
    { lsattr -Ra /etc /root /var/spool/cron 2>/dev/null; lsattr -a /usr/bin /usr/sbin /tmp /var/tmp 2>/dev/null; } |
      awk '$1 ~ /^[-a-zA-Z]+$/ && $1 ~ /[ia]/ { $1 = ""; sub(/^ /, ""); print }' | grep -vE '/\.\.?$')
  if (( ${#IMMUTABLE_FILES[@]} )); then
    flag "immutable/append-only (chattr +i/+a) files; edits and password changes on them will fail:"
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

DEB_CORE_PKGS="openssh-server openssh-client openssh-sftp-server libpam-modules libpam-modules-bin libpam-runtime libpam0g
  sudo passwd login util-linux coreutils procps iproute2 net-tools findutils grep sed gawk mawk bash dash systemd
  systemd-sysv cron libc-bin libc6 dpkg apt kmod e2fsprogs postfix dovecot-core dovecot-imapd dovecot-pop3d
  apache2 apache2-bin roundcube-core"
verify_filter() {    # keep: changed non-config files, and missing files outside the docs dpkg may be told to skip
  awk '($1 ~ /5/ && $2 != "c") ||
       ($1 == "missing" && $NF !~ /^\/usr\/share\/(doc|man|locale|info|lintian|bug|doc-base|help|gtk-doc)\// && $NF !~ /^\/var\/(lib\/apt\/lists|cache)\// && $NF !~ /roundcube\/installer/)'
}
scan_integrity() {
  section "Integrity of key packages (dpkg --verify)"
  local p pkgs=() v line files=() dirs=() f m nomod=() tainted gtfo
  for p in $DEB_CORE_PKGS; do
    dpkg-query -W -f='${db:Status-Abbrev}' "$p" 2>/dev/null | grep -q '^ii' && pkgs+=("$p")
  done
  while read -r p; do pkgs+=("$p"); done < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'php*-cli' 'php*-common' 'libapache2-mod-php*' 2>/dev/null | awk '$1=="ii"{print $2}')
  v=$(dpkg --verify "${pkgs[@]}" 2>/dev/null)
  line=$(verify_filter <<<"$v")
  if [[ -n $line ]]; then flag "package files whose content changed or vanished (possible trojans):"; show <<<"$line"
  else good "no changed binaries in: ${pkgs[*]}"; fi
  line=$(awk '$2 == "c" {print $NF}' <<<"$v" | tr '\n' ' ')
  [[ -n ${line// } ]] && note "changed config files (normal on a set-up box, still review): $line"
  note "dpkg checks files against its own md5 list in /var/lib/dpkg/info, which root can rewrite. It catches lazy trojans, not careful ones."
  line=$(dpkg-divert --list 2>/dev/null | grep '^local diversion')
  [[ -n $line ]] && { flag "local dpkg diversions (a binary was swapped aside by hand):"; show <<<"$line"; }

  section "Executables not owned by any package"
  mapfile -t dirs < <(real_dirs /usr/bin /usr/sbin /bin /sbin /usr/lib/dovecot /usr/lib/postfix/sbin /usr/lib/apache2/modules)
  mapfile -t files < <(find "${dirs[@]}" -maxdepth 1 -type f 2>/dev/null)
  line=$(unowned "${files[@]}")
  if [[ -n $line ]]; then flag "files in system bin / module dirs that no package installed:"; show <<<"$line"
  else good "every file in ${dirs[*]} belongs to a package"; fi
  line=$(find /usr/local/bin /usr/local/sbin /usr/local/lib -maxdepth 1 -type f 2>/dev/null)
  [[ -n $line ]] && { flag "files in /usr/local (not from a package):"; show <<<"$line"; }

  section "SUID/SGID files and file capabilities"
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
  gtfo='^(bash|sh|dash|zsh|ksh|find|vim?|vim\.(basic|tiny)|nano|less|more|python[0-9.]*|perl|ruby|php[0-9.]*|lua|node|awk|gawk|mawk|nawk|cp|mv|tar|zip|env|tee|dd|base64|xxd|socat|nc|ncat|wget|curl|git|nmap|gdb|strace|taskset|cpulimit|docker|busybox|openssl|rsync|timeout|xargs|sed|ed|cat|head|tail|chmod|chown)$'
  for f in "${files[@]}"; do
    [[ $(basename "$f") =~ $gtfo ]] || continue
    flag "SUID/SGID on $f: any user can become root with it"
    inlist "$f" "${SUID_FLAG_FILES[*]}" || SUID_FLAG_FILES+=("$f")
  done
  info "${#files[@]} SUID/SGID files in total (full list in the report)"
  printf '%s\n' "${files[@]}" >>"$REPORT"
  CAP_FLAG_FILES=()
  if have getcap; then
    line=$(getcap -r /usr /opt /srv /home /var/www 2>/dev/null | grep -E 'cap_(setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|sys_module|chown|fowner)')
    if [[ -n $line ]]; then
      flag "files with root-equivalent capabilities (as dangerous as SUID root):"; show <<<"$line"
      mapfile -t CAP_FLAG_FILES < <(awk '{print $1}' <<<"$line")
    else good "no files with root-equivalent capabilities"; fi
  else
    note "getcap not installed (libcap2-bin): file capabilities not checked"
  fi

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
    note "no /lib/modules/$(uname -r) (kernel updated without reboot, or a container) - module check skipped"
  fi
  tainted=$(cat /proc/sys/kernel/tainted 2>/dev/null)
  [[ -n $tainted && $tainted != 0 ]] && note "kernel taint flag = $tainted (out-of-tree/unsigned module or other taint)"
}

scan_postfix() {
  section "Postfix"
  if ! have postconf; then note "postfix not installed"; return; fi
  local v p f t m line mn tok qre='in ([0-9]+) Request' seen=" " u home rr rc

  info "version $(postconf -h mail_version 2>/dev/null) | daemon $(svc_state postfix) | inet_interfaces $(postconf -h inet_interfaces 2>/dev/null)"
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
  else flag "neither relay nor recipient restrictions reach reject/defer_unauth_destination: OPEN RELAY risk"; fi

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
      grep -qE 'argv=(/tmp|/var/tmp|/dev/shm|/home|/root)|argv=[^ ]*/(bash|sh|dash|python[0-9.]*|perl|nc|ncat|socat)( |$)' <<<"$line" && \
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
  [[ -n $line ]] && { info "/etc/pam.d/dovecot (stock: @include common-auth / common-account / common-session):"; show <<<"$line"; }
}

detect_web() {
  local cand=() d p keep
  for d in /var/www /usr/share/roundcube /var/lib/roundcube /usr/share/squirrelmail /usr/share/rainloop \
           /usr/share/snappymail /srv/www; do
    [[ -d $d ]] && cand+=("$d")
  done
  if [[ -d /etc/apache2 ]]; then
    # -R, not -r: sites-enabled/conf-enabled are symlinks and -r skips them
    while read -r d; do
      d=${d//\"/}; [[ -d $d ]] && cand+=("$d")
    done < <(grep -RhiE '^[[:space:]]*(DocumentRoot|Alias|ScriptAlias)[[:space:]]' /etc/apache2/apache2.conf \
               /etc/apache2/sites-enabled /etc/apache2/conf-enabled 2>/dev/null | awk '{print $NF}')
  fi
  if [[ -d /etc/nginx ]]; then
    while read -r d; do
      d=${d%;}; [[ -d $d ]] && cand+=("$d")
    done < <(grep -RhE '^[[:space:]]*root[[:space:]]' /etc/nginx 2>/dev/null | awk '{print $2}')
  fi
  WEBROOTS=()
  while read -r p; do
    case $p in ""|/|/usr|/usr/share|/usr/lib|/var|/var/lib|/etc|/opt|/srv|/home) continue ;; esac
    keep=1
    for d in "${WEBROOTS[@]}"; do [[ $p == "$d"/* ]] && keep=0; done
    (( keep )) && WEBROOTS+=("$p")
  done < <(printf '%s\n' "${cand[@]}" | sed 's:/*$::' | sort -u)
  PHP_SAPI_DIRS=()
  for d in /etc/php/*/apache2 /etc/php/*/fpm; do [[ -d $d ]] && PHP_SAPI_DIRS+=("$d"); done
  mapfile -t PHPFPM_UNITS < <(systemctl list-unit-files 'php*-fpm.service' --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//')
}

scan_web() {
  section "Web server & webmail"
  detect_web
  local s v f d line files=() pkgv
  for s in apache2 nginx "${PHPFPM_UNITS[@]}"; do unit_exists "$s" && info "$s: $(svc_state "$s")"; done
  info "web roots: ${WEBROOTS[*]:-none found}"
  if have apache2ctl; then
    info "$(apache2ctl -v 2>/dev/null | head -n1)"
    info "Listen: $(grep -RhE '^[[:space:]]*Listen[[:space:]]' /etc/apache2/ports.conf /etc/apache2/sites-enabled 2>/dev/null | tr -s ' \t' ' ' | tr '\n' ';')"
    info "enabled modules: $(ls /etc/apache2/mods-enabled 2>/dev/null | sed -n 's/\.load$//p' | tr '\n' ' ')"
    line=$(grep -RnE '^[[:space:]]*Options[[:space:]].*([[:space:]]|\+)Indexes' /etc/apache2/apache2.conf /etc/apache2/sites-enabled /etc/apache2/conf-enabled 2>/dev/null)
    [[ -n $line ]] && { note "directory listing enabled (Debian's default for /var/www):"; show <<<"$line"; }
    line=$(grep -RnE 'SetHandler[[:space:]]+server-(status|info)' /etc/apache2/sites-enabled /etc/apache2/conf-enabled /etc/apache2/mods-enabled 2>/dev/null | grep -vE ':[[:space:]]*#')
    [[ -n $line ]] && { note "server-status/info handler configured (stock one is 'Require local'):"; show <<<"$line"; }
    mapfile -t files < <(find /etc/apache2 -type f 2>/dev/null)
    line=$(stock_or_unowned_check "${files[@]}" | sort -u | tr '\n' ' ')
    [[ -n ${line// } ]] && note "apache2 config files not from a package or changed (review): $line"
    line=$(find /etc/apache2/sites-enabled /etc/apache2/conf-enabled /etc/apache2/mods-enabled -type l 2>/dev/null |
           while read -r f; do t=$(readlink -f "$f"); [[ $t == /etc/apache2/* ]] || echo "$f -> $t"; done)
    [[ -n $line ]] && { flag "apache2 *-enabled links pointing outside /etc/apache2:"; show <<<"$line"; }
  fi

  # Roundcube
  RC_DIR=""; RC_CONF=""; RC_DBFILE=""; RC_DBUSER=""; RC_PKG=0
  for d in "${WEBROOTS[@]}"; do
    f=$(find "$d" -maxdepth 4 -path '*/program/include/iniset.php' 2>/dev/null | head -n1)
    [[ -n $f ]] && { RC_DIR=${f%/program/include/iniset.php}; break; }
  done
  if [[ -n $RC_DIR ]]; then
    v=$(grep -oE "RCMAIL_VERSION'[[:space:]]*,[[:space:]]*'[^']+'" "$RC_DIR/program/include/iniset.php" | sed -E "s/.*'([^']+)'$/\1/")
    pkgv=$(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' roundcube-core 2>/dev/null | awk '$1=="ii"{print $2}')
    [[ -n $pkgv ]] && [[ -z $(unowned "$RC_DIR/program/include/iniset.php") ]] && RC_PKG=1
    info "Roundcube ${v:-?} at $RC_DIR $( (( RC_PKG )) && echo "(Debian package roundcube-core $pkgv)")"
    if (( RC_PKG )); then
      # Debian backports security fixes without changing the upstream version number
      if zgrep -q 'CVE-2025-49113' /usr/share/doc/roundcube-core/changelog.Debian.gz 2>/dev/null; then
        good "Debian changelog lists the CVE-2025-49113 fix"
      elif [[ -f /usr/share/doc/roundcube-core/changelog.Debian.gz ]]; then
        flag "roundcube-core $pkgv: Debian changelog does not mention CVE-2025-49113 (logged-in user -> code execution). Patch if the rules allow."
      else
        note "can't read the Debian changelog; check roundcube-core $pkgv against the Debian security tracker for CVE-2025-49113 from another machine"
      fi
    elif [[ -n $v ]] && { ver_lt "$v" 1.5.10 || { ! ver_lt "$v" 1.6.0 && ver_lt "$v" 1.6.11; }; }; then
      flag "Roundcube $v is older than 1.5.10/1.6.11: CVE-2025-49113 (any logged-in user -> code execution) plus older XSS bugs."
    fi
    for f in /etc/roundcube/config.inc.php "$RC_DIR/config/config.inc.php"; do
      [[ -f $f ]] && { RC_CONF=$(readlink -f "$f"); break; }
    done
    [[ -f /etc/roundcube/debian-db.php ]] && RC_DBFILE=/etc/roundcube/debian-db.php
    if [[ -n $RC_CONF ]]; then
      info "config: $RC_CONF (mode $(stat -c '%a %U:%G' "$RC_CONF"))"
      for f in "$RC_CONF" $RC_DBFILE; do
        [[ $(stat -c %a "$f") =~ [4-7]$ ]] && { flag "$f is world-readable (it holds secrets / the DB password)"; RC_CONF_WORLD=1; }
      done
      grep -qE "^[[:space:]]*\\\$(config|rcmail_config)\['enable_installer'\][[:space:]]*=[[:space:]]*true" "$RC_CONF" && \
        { flag "Roundcube enable_installer = true (the installer can rewrite config and leak secrets)"; RC_INSTALLER_ON=1; }
      grep -q "rcmail-!24ByteDESkey\*Str" "$RC_CONF" && { flag "Roundcube des_key is the public default"; RC_DESKEY_DEFAULT=1; }
      line=$(grep -E "\['db_dsnw'\]" "$RC_CONF" | grep -vE '^[[:space:]]*(//|#)' | head -n1)
      if [[ -n $line ]]; then
        info "DB: $(sed -E 's#(://[^:/@]+:)[^@]*@#\1****@#' <<<"$line" | tr -s ' ')"
        RC_DBUSER=$(sed -nE 's#.*://([^:/@$]+)[:@].*#\1#p' <<<"$line")
      fi
      [[ -z $RC_DBUSER && -n $RC_DBFILE ]] && RC_DBUSER=$(sed -nE "s/^[[:space:]]*\\\$dbuser[[:space:]]*=[[:space:]]*['\"]([^'\"]*)['\"].*/\1/p" "$RC_DBFILE" | head -n1)
      [[ -n $RC_DBFILE ]] && info "DB settings from dbconfig-common: $RC_DBFILE (user ${RC_DBUSER:-?})"
      line=$(grep -E "\['(default_host|imap_host|smtp_server|smtp_host|plugins)'\]" "$RC_CONF" | grep -vE '^[[:space:]]*(//|#)' | tr -s ' ')
      [[ -n $line ]] && show <<<"$line"
    fi
    [[ -d $RC_DIR/installer ]] && note "installer/ directory is still present at $RC_DIR/installer"
    if (( RC_PKG )); then
      mapfile -t files < <(find -L "$RC_DIR/plugins" /var/lib/roundcube/plugins -maxdepth 2 -type f -name '*.php' 2>/dev/null)
      line=$(unowned "${files[@]}" | xargs -r -n1 dirname 2>/dev/null | sort -u | tr '\n' ' ')
      [[ -n ${line// } ]] && flag "Roundcube plugin code not from any package (planted plugin?): $line"
    fi
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
        # Apache on Debian runs with PrivateTmp: files dropped in "/tmp" by PHP land here
        find /tmp/systemd-private-*-apache2.service-*/tmp /tmp/systemd-private-*-php*-fpm.service-*/tmp -type f \
             \( -iname '*.ph*' -o -perm /111 \) 2>/dev/null
      } | sed '/^$/d' | sort -u)
    if (( ${#WEBSHELLS[@]} )); then
      flag "possible webshells / PHP in odd places (${#WEBSHELLS[@]}):"
      for f in "${WEBSHELLS[@]}"; do printf '%s  [%s %s]\n' "$f" "$(stat -c %U "$f" 2>/dev/null)" "$(date -r "$f" '+%F %R' 2>/dev/null)"; done | show
    else
      good "no webshell patterns in web roots"
    fi
    info "most recently modified files in web roots:"
    find "${WEBROOTS[@]}" -xdev -type f -printf '%TY-%Tm-%Td %TH:%TM  %u  %p\n' 2>/dev/null | sort -r | head -n 10 | show
    line=$(find /usr/lib/cgi-bin -type f 2>/dev/null)
    [[ -n $line ]] && { flag "CGI scripts present in /usr/lib/cgi-bin:"; show <<<"$line"; }
  fi

  # Debian keeps one php.ini per SAPI; the CLI one (php -i) is NOT what Apache uses.
  for d in "${PHP_SAPI_DIRS[@]}"; do
    v=$(php_ini_val "$d" disable_functions)
    info "PHP $d: disable_functions='${v:-}' allow_url_include=$(php_ini_val "$d" allow_url_include) expose_php=$(php_ini_val "$d" expose_php)"
    [[ $v != *exec* || $v != *system* ]] && note "$d: disable_functions doesn't block exec/system (a webshell can run any command)"
    [[ $(php_ini_val "$d" allow_url_include) =~ ^([Oo]n|1|[Tt]rue)$ ]] && flag "$d: PHP allow_url_include = On (remote file inclusion)"
  done
}

scan_db() {
  section "Database"
  local s svc="" line
  for s in mariadb mysql postgresql; do [[ $(svc_state "$s") == active ]] && svc+="$s "; done
  if [[ -z $svc ]] && ! have mysql; then info "no database service running"; return; fi
  info "running: ${svc:-none}"
  for s in /etc/mysql/debian.cnf /root/.my.cnf; do
    [[ -f $s ]] || continue
    note "$s exists (DB admin credentials), mode $(stat -c '%a %U:%G' "$s")"
    [[ $(stat -c %a "$s") =~ [1-7][0-7]$|[0-7][1-7]$ ]] && flag "$s is readable by non-root"
  done
  have mysql || return
  if timeout 5 mysql --connect-timeout=3 --protocol=TCP -h 127.0.0.1 -u root --password= -e 'select 1' </dev/null >/dev/null 2>&1; then
    flag "MySQL root logs in over TCP with an EMPTY password"
  fi
  line=$(timeout 5 mysql --connect-timeout=3 -N -B -e "SELECT CONCAT(user,'@',host) FROM mysql.user" </dev/null 2>/dev/null)
  if [[ -n $line ]]; then
    info "DB accounts (root got in over the socket: normal on Debian, where MariaDB root uses unix_socket auth):"
    show <<<"$line"
    grep -qE '^@' <<<"$line" && flag "anonymous MySQL accounts exist"
    grep -qE '^root@%$' <<<"$line" && flag "MySQL root can log in from any host"
  else
    info "socket login as root needs a password"
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
  for s in "${PHPFPM_UNITS[@]}" mariadb mysql nginx ssh ufw nftables firewalld cron apparmor; do unit_exists "$s" && info "$s: $(svc_state "$s")"; done
  running=$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//')
  UNNEEDED_SVCS=()
  skip_re='^(telnet.*|inetd|openbsd-inetd|xinetd|vsftpd|proftpd|pure-ftpd|tftpd-hpa|tftp.*|rsh.*|rlogin.*|rexec.*|nfs-server|nfs-kernel-server|rpcbind|smbd|nmbd|winbind|samba-ad-dc|snmpd|cups|cups-browsed|avahi-daemon|bluetooth|sendmail|exim4|vncserver.*|x11vnc|xrdp|squid|named|bind9|dnsmasq|cockpit|docker|containerd|lighttpd|tomcat[0-9]*|webmin|ncat|socat|teamviewerd|anydesk)$'
  for s in $running; do
    [[ $s =~ $skip_re ]] && { flag "service probably not needed on a mail box: $s"; UNNEEDED_SVCS+=("$s"); }
  done
  info "running services: $(tr '\n' ' ' <<<"$running")"

  section "AppArmor / SELinux"
  AA_COMPLAIN=()
  if have getenforce; then
    st=$(getenforce 2>/dev/null); info "SELinux: $st"
  elif [[ -r /sys/module/apparmor/parameters/enabled ]]; then
    if [[ $(cat /sys/module/apparmor/parameters/enabled) != Y ]]; then flag "AppArmor is disabled in the kernel"
    elif have aa-status; then
      st=$(aa-status 2>/dev/null)
      info "$(grep -E '^[0-9]+ (profiles are|processes)' <<<"$st" | tr '\n' ';')"
      mapfile -t AA_COMPLAIN < <(awk '/^[0-9]+ profiles are in complain mode/{f=1; next} /^[0-9]+ /{f=0} f{sub(/^[ \t]+/, ""); print}' <<<"$st")
      (( ${#AA_COMPLAIN[@]} )) && flag "AppArmor profiles in complain mode (log only, block nothing): ${AA_COMPLAIN[*]}"
      grep -qE '^[1-9][0-9]* processes are unconfined but have a profile defined' <<<"$st" && \
        flag "processes running unconfined although a profile exists (restarted around AppArmor?)"
      line=$(find /etc/apparmor.d/disable -type l 2>/dev/null | tr '\n' ' ')
      [[ -n ${line// } ]] && note "profiles disabled on purpose: $line"
    else
      info "AppArmor enabled (install-free check: aa-status not present)"
    fi
  else
    note "no AppArmor or SELinux"
  fi
}

scan_logins() {
  section "Recent logins & shell history"
  local line f u home
  if have last; then
    last -n 15 -a 2>/dev/null | grep -vE '^[[:space:]]*$|^wtmp begins' | show
    line=$(lastb -n 10 -a 2>/dev/null | grep -vE '^$|^btmp begins')
    [[ -n $line ]] && { info "failed logins:"; show <<<"$line"; }
  elif have wtmpdb; then
    wtmpdb last -n 15 2>/dev/null | show                  # Debian 13 replaced wtmp with wtmpdb
  fi
  line=$(grep -hE 'Accepted (password|publickey)' /var/log/auth.log 2>/dev/null | tail -n 8)
  [[ -z $line ]] && have journalctl && \
    line=$(journalctl --since yesterday --no-pager -q _COMM=sshd _COMM=sshd-session 2>/dev/null | grep 'Accepted' | tail -n 8)
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
  for f in "${FLAGS[@]}"; do i=$((i + 1)); pg_line "$(printf '  %s%3d%s %s' "$R" "$i" "$N" "$f")"; done
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
  for p in /etc /root /var/spool/cron "${WEBROOTS[@]}"; do
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
    have iptables-save && iptables-save >"$BACKUP/iptables.rules"
    have ip6tables-save && ip6tables-save >"$BACKUP/ip6tables.rules"
    have nft && nft list ruleset >"$BACKUP/nft.txt"
    have ufw && ufw status verbose >"$BACKUP/ufw.txt"
    have firewall-cmd && firewall-cmd --list-all-zones >"$BACKUP/firewalld-zones.txt"
    dpkg -l >"$BACKUP/dpkg-l.txt"
    systemctl list-unit-files --no-pager >"$BACKUP/unit-files.txt"
    have postconf && postconf -n >"$BACKUP/postconf-n.txt"
    have doveconf && doveconf -n >"$BACKUP/doveconf-n.txt"
    have apache2ctl && apache2ctl -S >"$BACKUP/apache2ctl-S.txt" 2>&1
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
disable_user() {     # lock + expire (blocks SSH keys too) + nologin, then log them out
  local u=$1
  [[ $u == root ]] && { warn "not disabling root"; return 1; }
  [[ -n $ME && $u == "$ME" ]] && { warn "'$u' is the account you logged in with; skipped"; return 1; }
  usermod -L -e 1 -s "$NOLOGIN" "$u" || return 1
  end_sessions "$u"
  good "disabled and logged out $u   (undo: usermod -U -e '' -s /bin/bash $u)"; act "DISABLED user $u (locked, expired, nologin, sessions killed)"
}
admin_members() {   # members of every admin group
  local g; for g in $ADMIN_GROUPS; do getent group "$g" | cut -d: -f4 | tr ',' '\n'; done | sed '/^$/d' | sort -u | tr '\n' ' '
}

step_passwords() {
  hdr "1) Passwords"
  note "MACCDC: change a SCORED user's password only with a PCR to the White Team, or the service check fails."
  note "You type every password at passwd's own prompt. Nothing is stored."
  local f
  for f in /etc/shadow /etc/passwd /etc/gshadow; do
    inlist "$f" "${IMMUTABLE_FILES[*]}" && { warn "$f is immutable: password changes will FAIL."; confirm "chattr -i $f now?" && chattr -i "$f" && act "CHATTR -i $f"; }
  done
  confirm "Change the root password now?" && on_tty passwd root && act "PASSWORD changed: root"
  local admins u others=() c
  admins=$(admin_members)
  for u in $admins; do
    [[ $u == root ]] && continue
    confirm "Change password for admin (sudo) user '$u'?" && on_tty passwd "$u" && act "PASSWORD changed: $u"
  done
  for u in "${SHELL_USERS[@]}" "${HUMAN_USERS[@]}"; do
    [[ $u == root ]] && continue
    inlist "$u" "$admins" && continue
    inlist "$u" "${others[*]}" && continue
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
  note "Change them AGAIN in 30-45 minutes: assume the first ones were watched."
}

bulk_passwords() {
  local f u bad=() empty
  note "Write one 'user:newpassword' per line. Put it in RAM, not on disk: e.g.  vi /dev/shm/pw.txt"
  note "(shred can't reliably wipe a file on ext4/XFS journals or SSDs; /dev/shm is never written to disk)"
  f=$(ask "  Path to that file: ")
  [[ -f $f ]] || { warn "no such file: $f"; return; }
  chmod 600 "$f"
  [[ $(stat -c %U "$f") == root ]] || { warn "$f is not owned by root; refusing"; return; }
  while IFS=: read -r u p; do
    [[ -z $u ]] && continue
    [[ -z $p ]] && empty+="$u "
    id "$u" >/dev/null 2>&1 || bad+=("$u")
  done <"$f"
  unset p
  (( ${#bad[@]} )) && { warn "these users don't exist, fix the file first: ${bad[*]}"; return; }
  [[ -n $empty ]] && { warn "empty password for: $empty- fix the file first"; return; }
  info "will change: $(cut -d: -f1 "$f" | sed '/^$/d' | tr '\n' ' ')"
  confirm "Apply with chpasswd?" || return
  if chpasswd <"$f"; then
    good "passwords changed"; act "PASSWORD changed (bulk chpasswd): $(cut -d: -f1 "$f" | tr '\n' ' ')"
  else
    warn "chpasswd failed"
  fi
  confirm "Remove $f now? (only after you've copied it for the PCR)" && shred -u "$f" 2>/dev/null && act "REMOVED $f"
}

step_procs() {
  hdr "2) Suspicious processes & other sessions"
  local pid exe my_tty tty line s
  (( ${#SUS_PROCS[@]} )) || good "no processes were flagged"
  for pid in "${SUS_PROCS[@]}"; do
    [[ -d /proc/$pid ]] || continue
    inlist "$pid" "$MY_PIDS" && continue
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
  info "SSH sessions (including no-terminal ones 'who' misses):"
  while read -r pid s; do
    if inlist "$pid" "$MY_PIDS"; then info "    $s  <- you"; continue; fi
    info "    $s (pid $pid)"
    confirm "End this SSH session? (N if it's a teammate)" && kill -KILL "$pid" 2>/dev/null && \
      { good "ended $s"; act "KILLED ssh session $s (pid $pid)"; }
  done < <(ssh_sessions)
  my_tty=$(ps -o tty= -p $$ 2>/dev/null | tr -d ' ')
  info "Your terminal: ${my_tty:-unknown}. Other terminal sessions:"
  while IFS= read -r line; do
    tty=$(awk '{print $2}' <<<"$line")
    [[ -z $tty || $tty == "$my_tty" ]] && continue
    pgrep -t "$tty" >/dev/null 2>&1 || continue
    pg_line "      $line"
    confirm "Kill every process on $tty? (make sure it isn't a teammate)" && pkill -KILL -t "$tty" && \
      { good "killed session $tty"; act "KILLED session $tty: $line"; }
  done < <(who 2>/dev/null)
}

quarantine_sudoers() {   # move a sudoers.d file, put it back if sudo breaks or you lose sudo
  local f=$1
  quarantine "$f" || return
  if ! visudo -c >/dev/null 2>&1; then
    mv -f "$QUAR$f" "$f"; warn "sudo config check failed without it; put back"; act "RESTORED $f (visudo -c failed)"
  elif [[ -n $ME ]] && sudo -l -U "$ME" 2>&1 | grep -q 'not allowed'; then
    mv -f "$QUAR$f" "$f"; warn "without $f YOUR account ($ME) would lose sudo; put back"; act "RESTORED $f (would lock out $ME)"
  fi
}

step_accounts() {
  hdr "3) Accounts, sudo, SSH keys"
  local u f line before g
  for u in "${UID0_USERS[@]}"; do
    confirm "Disable UID-0 account '$u' (lock, expire, nologin, end its SSH sessions)?" && disable_user "$u"
  done
  for u in "${EMPTY_PW_USERS[@]}"; do
    confirm "Lock '$u' (it has an EMPTY password)?" && passwd -l "$u" >/dev/null && { good "locked $u"; act "LOCKED (empty password) $u"; }
  done
  each_reset
  for u in "${SYS_SHELL_USERS[@]}"; do
    each "Set system account '$u' shell to $NOLOGIN?" && usermod -s "$NOLOGIN" "$u" && { good "$u -> nologin"; act "SHELL nologin: $u"; }
  done
  each_reset
  for u in "${SYS_PW_USERS[@]}"; do
    each "Lock the password of system account '$u' (it should not have one)?" && passwd -l "$u" >/dev/null && { good "locked $u"; act "LOCKED password of system account $u"; }
  done

  info "Users with a login shell: ${SHELL_USERS[*]}"
  note "Disabling a mail user also blocks their POP3/IMAP/webmail login (scoring!). 'nologin only' keeps mail working."
  line=$(ask "  Users to fully disable (lock + expire + nologin + log out), space-separated, blank = none: ")
  for u in $line; do
    id "$u" >/dev/null 2>&1 || { warn "no user $u"; continue; }
    confirm "Disable '$u'?" && disable_user "$u"
  done
  line=$(ask "  Users to set to nologin shell only (keeps mail working), blank = none: ")
  for u in $line; do
    id "$u" >/dev/null 2>&1 || { warn "no user $u"; continue; }
    confirm "Set '$u' shell to $NOLOGIN?" && usermod -s "$NOLOGIN" "$u" && { end_sessions "$u"; good "$u -> nologin, logged out"; act "SHELL nologin: $u"; }
  done

  for g in $ADMIN_GROUPS $ROOTEQ_GROUPS; do
    for u in $(getent group "$g" | cut -d: -f4 | tr ',' ' '); do
      [[ -n $ME && $u == "$ME" ]] && { info "$u in $g = you, keeping"; continue; }
      confirm "Remove '$u' from group '$g' (root access)?" && \
        gpasswd -d "$u" "$g" >/dev/null && { good "removed $u from $g"; act "GROUP $g removed $u"; }
    done
  done

  each_reset
  for f in "${SUDO_FLAG_FILES[@]}"; do
    [[ -f $f ]] || continue
    info "$f:"; grep -vE '^[[:space:]]*(#|$)' "$f" | show
    each "Quarantine $f?" && quarantine_sudoers "$f"
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
    note "judge keys by WHICH ACCOUNT they're on; the comment at the end is fakeable"
    each "Quarantine $f (these keys stop working)?" && quarantine "$f"
  done
  each_reset
  for f in "${SSH_RC_FILES[@]}"; do
    [[ -f $f ]] || continue
    info "$f:"; head -n 5 "$f" | show
    each "Quarantine $f (runs on every ssh login)?" && quarantine "$f"
  done
  each_reset
  for f in "${PAM_FLAG_FILES[@]}"; do
    [[ -f $f ]] || continue
    each "Edit $f (flagged PAM line)? Keep a root shell open while you test logins." && edit "$f"
  done
}

step_firewall() {
  hdr "4) Firewall: inbound allowlist"
  local def="" p ports badport=0 sp
  sp=$(sshv port); sp=${sp:-22}
  for p in $MAIL_PORTS; do inlist "$p" "${LISTEN_PORTS[*]}" && def+="$p "; done
  def=${def% }
  [[ -z $def ]] && def="22 25 80 110 143 443"
  inlist "$sp" "$def" || def="$sp $def"
  info "firewall tool: $FW"
  info "ssh/mail/web ports listening right now: $def"
  note "Every scored port must stay open. Loopback, ICMP and replies to this box's own connections stay allowed."
  note "Outbound is NOT filtered (reverse shells can still call out). Do egress by hand once you know what the box needs."
  ports=$(ask "  TCP ports to allow inbound [$def]: ") || return
  ports=${ports:-$def}; ports=${ports//,/ }
  for p in $ports; do
    [[ $p =~ ^[0-9]+$ ]] && (( p > 0 && p < 65536 )) || { warn "bad port: $p"; badport=1; }
  done
  (( badport )) && return
  inlist "$sp" "$ports" || warn "sshd's port $sp is not in the list: remote SSH (yours too) will be blocked"
  case $FW in
    ufw)       fw_ufw "$ports" ;;
    firewalld) fw_firewalld "$ports" ;;
    nft)       fw_nft "$ports" ;;
    iptables)  fw_iptables "$ports" ;;
    *)         warn "no firewall tool available, and nothing can be installed offline" ;;
  esac
}

fw_ufw() {
  local ports=$1 bk=$OUT/ufw.before r w port dels=() was_active=0 rb
  ufw status 2>/dev/null | grep -q 'Status: active' && was_active=1
  # decide which existing rules to drop BEFORE the rollback timer starts
  while IFS= read -r r; do
    r=${r#ufw }
    port=""
    for w in $r; do [[ $w =~ ^([0-9]+)(/(tcp|udp))?$ ]] && { port=${BASH_REMATCH[1]}; break; }; done
    [[ -n $port && $r == allow* ]] && inlist "$port" "$ports" && continue
    info "existing ufw rule: $r"
    confirm "Delete it (not in your allow list)?" && dels+=("$r")
  done < <(ufw show added 2>/dev/null | grep '^ufw ')
  info "Plan: ufw default deny incoming, allow TCP $ports, delete ${#dels[@]} rule(s)$( (( was_active )) || echo ', then ENABLE ufw')."
  confirm "Apply now (auto-rollback in ${ROLLBACK_SECS}s)?" || return
  mkdir -p "$bk"; cp -a /etc/ufw/user.rules /etc/ufw/user6.rules /etc/default/ufw "$bk"/ 2>/dev/null
  rb="cp -a '$bk/user.rules' '$bk/user6.rules' /etc/ufw/; cp -a '$bk/ufw' /etc/default/ufw"
  if (( was_active )); then rb+="; ufw reload"; else rb+="; ufw --force disable"; fi
  arm_rollback "$rb"
  for r in "${dels[@]}"; do
    read -ra w <<<"$r"
    ufw --force delete "${w[@]}" >/dev/null 2>&1 && act "UFW deleted: $r" || warn "couldn't delete: $r (delete it by number: ufw status numbered)"
  done
  ufw default deny incoming >/dev/null
  for p in $ports; do ufw allow "$p/tcp" >/dev/null; done
  if (( was_active )); then ufw reload >/dev/null; else ufw --force enable >/dev/null; fi
  ufw status verbose | show
  keep_or_rollback true    # ufw saves its rules as it goes; 'keep' just stops the timer
}

fw_firewalld() {
  local ports=$1 z zones s p r i rm_rich=() rm_fwd=() rm_src=() mv_if=()
  zones=$(firewall-cmd --get-active-zones 2>/dev/null | awk '!/^[[:space:]]/{print $1}')
  [[ -z $zones ]] && zones=$(firewall-cmd --get-default-zone)
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
  (( ${#mv_if[@]} )) && ! inlist public "$zones" && zones+=" public"
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
      [[ $p == */tcp ]] && inlist "${p%/tcp}" "$ports" || firewall-cmd -q --zone="$z" --remove-port="$p"
    done
  done
  for r in "${rm_rich[@]}"; do firewall-cmd -q --zone="${r%%|*}" --remove-rich-rule="${r#*|}"; done
  for r in "${rm_fwd[@]}"; do firewall-cmd -q --zone="${r%%|*}" --remove-forward-port="${r#*|}"; done
  for s in "${rm_src[@]}"; do firewall-cmd -q --zone=trusted --remove-source="$s"; done
  for z in $zones; do firewall-cmd --zone="$z" --list-all 2>/dev/null | show; done
  keep_or_rollback "firewall-cmd --runtime-to-permanent"
}

nft_persist() {      # save table inet ccdc so it loads at boot (asks before enabling nftables.service)
  local conf=/etc/nftables.conf saved=/etc/nftables-ccdc.nft
  nft list table inet ccdc >"$saved" || return 1
  chmod 600 "$saved"
  [[ -f $conf ]] || printf '#!/usr/sbin/nft -f\n' >"$conf"
  grep -qF "include \"$saved\"" "$conf" || printf '\ninclude "%s"\n' "$saved" >>"$conf"
  nft -c -f "$conf" || { warn "nft rejects $conf; rules stay loaded until reboot only"; return 1; }
  act "WROTE $saved and include in $conf"
  if ! systemctl is-enabled -q nftables 2>/dev/null; then
    note "nftables.service loads $conf at boot. Debian's stock $conf starts with 'flush ruleset', which"
    note "also wipes rules other tools (docker, fail2ban) add before it runs. Say N on a docker host."
    confirm "Enable nftables.service so this survives a reboot?" && systemctl enable nftables >/dev/null 2>&1 && act "ENABLED nftables.service"
  fi
  return 0
}

fw_nft() {
  local ports=$1 set before=$OUT/nft-ccdc.before rb
  info "Plan: nftables table 'inet ccdc' (IPv4+IPv6): allow lo, established, ICMP, DHCP, TCP $ports; drop the rest."
  note "Other tables are left alone. A drop in ANY table is final, so this blocks even if another table accepts."
  confirm "Apply now (auto-rollback in ${ROLLBACK_SECS}s)?" || return
  nft list table inet ccdc >"$before" 2>/dev/null || : >"$before"
  set=$(tr ' ' ',' <<<"$ports")
  rb="nft delete table inet ccdc 2>/dev/null; if [ -s '$before' ]; then nft -f '$before'; fi; true"
  arm_rollback "$rb"
  if ! nft -f - <<EOF
table inet ccdc
delete table inet ccdc
table inet ccdc {
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto { icmp, ipv6-icmp } accept
    udp dport { 68, 546 } accept
    tcp dport { $set } accept
  }
}
EOF
  then
    disarm_rollback; eval "$rb"; warn "nft rejected the rules; nothing changed"; return
  fi
  nft list table inet ccdc | show
  keep_or_rollback nft_persist
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
  if [[ -d /etc/iptables ]] && have netfilter-persistent; then
    persist="iptables-save >/etc/iptables/rules.v4; ip6tables-save >/etc/iptables/rules.v6 2>/dev/null; true"
    note "'keep' also saves the rules to /etc/iptables/rules.v4 (netfilter-persistent)"
  else
    note "no netfilter-persistent: these rules last until reboot (re-run this step after one)"
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
    new=$(ask "  new mynetworks [127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128]: "); new=${new:-127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128}
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
  # shellcheck disable=SC2016
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
    note "Fix: comment out the static / nopassword / master / checkpassword passdb or the post-login 'executable'. Keep the normal pam or passwd-file passdb (a static USERdb is normal)."
    mapfile -t files < <(printf '%s\n' "${DC_HITS[@]}" | cut -d: -f1 | sort -u)
    each_reset
    for f in "${files[@]}"; do each "Open $f in the editor?" && edit "$f" && changed=1; done
  else
    good "no dovecot auth backdoors were flagged"
  fi
  if (( DC_PWLOG )) && grep -qE '^[[:space:]]*!include(_try)?[[:space:]]+(/etc/dovecot/)?conf\.d/\*\.conf' /etc/dovecot/dovecot.conf 2>/dev/null; then
    if confirm "Write $dropin to stop logging passwords (auth_debug_passwords = no, auth_verbose_passwords = no)?"; then
      printf '# added by %s %s\nauth_debug_passwords = no\nauth_verbose_passwords = no\n' "$ME_NAME" "$TS" >"$dropin"
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
  local f key line reload=0 ini cur_df df bk d
  if [[ -n $RC_DIR && -d $RC_DIR/installer ]] && confirm "Move the Roundcube installer ($RC_DIR/installer) to quarantine?"; then
    quarantine "$RC_DIR/installer"
  fi
  if [[ -n $RC_CONF ]]; then
    bk="$OUT/$(basename "$RC_CONF").before"
    [[ -f $bk ]] || cp -a "$RC_CONF" "$bk"
    if (( RC_INSTALLER_ON )) && confirm "Set enable_installer = false in $RC_CONF?"; then
      sed -i -E "s/(\['enable_installer'\][[:space:]]*=[[:space:]]*)true/\1false/" "$RC_CONF" && act "ROUNDCUBE enable_installer = false"
    fi
    if (( RC_CONF_WORLD )) && confirm "Remove world access to $RC_CONF ${RC_DBFILE} (chmod o-rwx; Debian wants root:www-data 640)?"; then
      chmod o-rwx "$RC_CONF" $RC_DBFILE && act "CHMOD o-rwx $RC_CONF $RC_DBFILE"
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

  if (( ${#PHP_SAPI_DIRS[@]} )); then
    note "PHP settings go into 99-ccdc.ini in each web SAPI's conf.d (${PHP_SAPI_DIRS[*]}). The CLI is left alone."
    local want_basic=0 want_df=0
    confirm "Set expose_php = Off, allow_url_include = Off, display_errors = Off?" && want_basic=1
    note "disable_functions stops webshells from running commands. Roundcube doesn't need these functions."
    (( SQM_FOUND )) && note "SquirrelMail in 'sendmail' delivery mode needs popen: switch it to SMTP or skip this."
    confirm "Block exec, passthru, shell_exec, system, proc_open, popen, pcntl_exec?" && want_df=1
    for d in "${PHP_SAPI_DIRS[@]}"; do
      (( want_basic || want_df )) || break
      ini=$d/conf.d/99-ccdc.ini
      cur_df=$(php_ini_val "$d" disable_functions)
      [[ -f $ini ]] && cp -a "$ini" "$OUT/$(tr / _ <<<"$ini").before"
      {
        printf '; added by %s %s\n' "$ME_NAME" "$TS"
        (( want_basic )) && printf 'expose_php = Off\nallow_url_include = Off\ndisplay_errors = Off\n'
        if (( want_df )); then
          df="exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec"
          [[ -n $cur_df && $cur_df != *"$df"* ]] && df="$cur_df,$df"
          [[ $cur_df == *"$df"* ]] && df=$cur_df
          printf 'disable_functions = %s\n' "$df"
        fi
      } >"$ini" && { chmod 644 "$ini"; good "wrote $ini"; act "WROTE $ini"; reload=1; }
    done
  fi
  if (( reload )); then
    if have apache2ctl && ! apache2ctl configtest >/dev/null 2>&1; then
      warn "apache2ctl configtest already fails (not from this script); not reloading. Run: apache2ctl configtest"
    else
      if unit_exists apache2; then
        if systemctl reload apache2 2>/dev/null; then good "apache2 reloaded"; act "apache2 reloaded"
        else warn "apache2 reload failed: systemctl status apache2"; fi
      fi
      for d in "${PHPFPM_UNITS[@]}"; do
        [[ $(svc_state "$d") == active ]] || continue
        if systemctl reload "$d" 2>/dev/null; then good "$d reloaded"; act "$d reloaded"; else warn "$d reload failed"; fi
      done
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
    elif [[ $f == */*-generators/* ]]; then
      confirm "Quarantine this systemd generator (runs at every boot)?" && { quarantine "$f"; reload=1; }
    else
      confirm "Stop + disable $unit and quarantine the file?" && \
        { systemctl disable --now "$unit" 2>/dev/null; act "DISABLED unit $unit"; quarantine "$f"; reload=1; }
    fi
  done
  (( reload )) && systemctl daemon-reload 2>/dev/null && act "systemctl daemon-reload"
  for f in "${MISC_FLAG_FILES[@]}"; do
    [[ -e $f || -L $f ]] || continue
    echo; info "$f"
    [[ -f $f ]] && grep -vE '^[[:space:]]*(#|$)' "$f" | head -n 8 | show
    if is_conffile "$f"; then
      note "this is a package config file that was CHANGED: edit it back rather than removing it"
      c=$(ask "  [e]dit / [s]kip (default): ")
    else
      c=$(ask "  [q]uarantine / [e]dit / [s]kip (default): ")
    fi
    case $c in q*) is_conffile "$f" || quarantine "$f" ;; e*) [[ -f $f ]] && edit "$f" ;; esac
  done
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
    for f in "${IMMUTABLE_FILES[@]}"; do each "chattr -i -a $f?" && chattr -i -a "$f" && act "CHATTR -i -a $f"; done
  fi
  each_reset
  for f in "${SUID_FLAG_FILES[@]}"; do
    [[ -f $f ]] || continue
    info "$(ls -la "$f" 2>/dev/null)"
    each "Remove the SUID/SGID bit from $f (chmod u-s,g-s)?" && chmod u-s,g-s "$f" && { good "fixed $f"; act "CHMOD u-s,g-s $f"; }
  done
  each_reset
  for f in "${CAP_FLAG_FILES[@]}"; do
    [[ -f $f ]] || continue
    info "$(getcap "$f" 2>/dev/null)"
    each "Remove the capabilities from $f (setcap -r)?" && setcap -r "$f" && { good "fixed $f"; act "SETCAP -r $f"; }
  done
  each_reset
  for f in "${TMP_FLAG_FILES[@]}"; do
    [[ -f $f ]] || continue
    info "$(ls -la "$f" 2>/dev/null)  [$(head -c 64 "$f" | tr -c '[:print:]' '.' | cut -c1-40)]"
    each "Quarantine $f?" && quarantine "$f"
  done
}

step_ssh() {
  hdr "9) SSH daemon"
  have sshd || { info "sshd not installed"; return; }
  local block="" c au f
  SSHD_T=$(sshd -T 2>/dev/null)
  info "now: PermitRootLogin $(sshv permitrootlogin) | PasswordAuthentication $(sshv passwordauthentication) | MaxAuthTries $(sshv maxauthtries) | AllowUsers $(sshv allowusers)"
  note "Keep console access or a sudo admin before turning root login off. Open sessions stay up."
  c=$(ask "  PermitRootLogin: [n]o / [k]eys only / [l]eave as is (default): ")
  case $c in
    n*) block+=$'PermitRootLogin no\n' ;;
    k*) block+=$'PermitRootLogin prohibit-password\n' ;;
  esac
  confirm "Add PermitEmptyPasswords no, MaxAuthTries 3, X11Forwarding no, PermitUserEnvironment no, AllowTcpForwarding no, PermitTunnel no?" && \
    block+=$'PermitEmptyPasswords no\nMaxAuthTries 3\nX11Forwarding no\nPermitUserEnvironment no\nAllowTcpForwarding no\nPermitTunnel no\n'
  (( SSH_AKF_FLAG )) && confirm "Reset AuthorizedKeysFile to .ssh/authorized_keys?" && block+=$'AuthorizedKeysFile .ssh/authorized_keys\n'
  (( SSH_AKC_FLAG )) && confirm "Turn off AuthorizedKeysCommand?" && block+=$'AuthorizedKeysCommand none\n'
  au=$(ask "  AllowUsers (only these may SSH in), space-separated, blank = no change: ")
  if [[ -n $au ]]; then
    [[ -n $ME ]] && ! inlist "$ME" "$au" && { warn "your own account '$ME' is not in that list: you would be locked out of SSH"; confirm "Use it anyway?" || au=""; }
    [[ -n $au ]] && block+="AllowUsers $au"$'\n'
  fi
  if [[ -n $block ]]; then
    info "This goes at the top of /etc/ssh/sshd_config (sshd uses the first value it sees):"
    show <<<"${block%$'\n'}"
    if confirm "Apply, test with sshd -t, then reload ssh?"; then
      cp -a /etc/ssh/sshd_config "$OUT/sshd_config.before"
      { printf '# --- added by %s %s ---\n%s# --- end %s ---\n\n' "$ME_NAME" "$TS" "$block" "$ME_NAME"
        sed "/^# --- added by $ME_NAME/,/^# --- end $ME_NAME ---\$/d" "$OUT/sshd_config.before"; } >/etc/ssh/sshd_config
      mkdir -p /run/sshd 2>/dev/null
      if sshd -t 2>"$OUT/sshd-t.txt"; then
        if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then good "ssh reloaded"; else warn "ssh reload failed: systemctl status ssh"; fi
        act "SSHD settings: $(tr '\n' ';' <<<"$block")"
        warn "TEST NOW: open a NEW ssh session before closing this one."
      else
        warn "sshd -t failed, putting the original sshd_config back:"; show <"$OUT/sshd-t.txt"
        cat "$OUT/sshd_config.before" >/etc/ssh/sshd_config
      fi
    fi
  else
    info "no global SSH changes"
  fi
  if (( ${#SSH_MATCH_FILES[@]} )); then
    note "Match blocks still override the global settings for some users/hosts:"
    each_reset
    for f in "${SSH_MATCH_FILES[@]}"; do
      each "Edit $f?" && edit "$f" && { sshd -t && { systemctl reload ssh 2>/dev/null || systemctl reload sshd; } || warn "sshd -t fails: fix $f before logging out"; }
    done
  fi
}

step_services() {
  hdr "10) Unneeded services"
  note "Leave alone: postfix, dovecot, apache2/php-fpm, mariadb/mysql (webmail DB), ssh if it's scored."
  local s extra
  each_reset
  for s in "${UNNEEDED_SVCS[@]}"; do
    each "Stop and disable $s?" && systemctl disable --now "$s" 2>/dev/null && { good "$s stopped"; act "DISABLED service $s"; }
  done
  extra=$(ask "  Other services to stop + disable, space-separated, blank = none: ")
  for s in $extra; do
    if [[ $s =~ ^(postfix|postfix@-|dovecot|apache2|php.*-fpm|mariadb|mysql|ssh|sshd)$ ]]; then confirm "$s is probably SCORED. Really stop it?" || continue; fi
    systemctl disable --now "$s" && { good "$s stopped"; act "DISABLED service $s"; }
  done
}

step_mac() {
  hdr "11) AppArmor"
  if have getenforce; then info "SELinux mode: $(getenforce). Use the Fedora script's SELinux step logic by hand."; return; fi
  [[ -r /sys/module/apparmor/parameters/enabled ]] || { info "AppArmor not available"; return; }
  [[ $(cat /sys/module/apparmor/parameters/enabled) == Y ]] || { note "AppArmor is disabled in the kernel: enabling it needs a reboot. Not mid-competition."; return; }
  (( ${#AA_COMPLAIN[@]} )) || { good "no profiles in complain mode"; return; }
  have aa-enforce || { note "aa-enforce (apparmor-utils) isn't installed and can't be fetched offline. By hand: apparmor_parser -r /etc/apparmor.d/<profile> after removing 'flags=(complain)'."; return; }
  note "Enforcing a profile can break the service it confines. Undo: aa-complain <profile>"
  local p done_list=()
  each_reset
  for p in "${AA_COMPLAIN[@]}"; do
    each "aa-enforce $p?" && aa-enforce "$p" >/dev/null 2>&1 && { done_list+=("$p"); act "AA-ENFORCE $p"; good "$p enforced"; }
  done
  (( ${#done_list[@]} )) || return
  verify_services
  if ! confirm "Everything still up? (N puts them back in complain mode)"; then
    for p in "${done_list[@]}"; do aa-complain "$p" >/dev/null 2>&1 && act "AA-COMPLAIN $p (rollback)"; done
    warn "put back in complain mode"
  fi
}

step_mysql() {
  hdr "12) MySQL / MariaDB"
  have mysql || { info "no MySQL/MariaDB client installed"; return; }
  local tool=""
  [[ -n $RC_DBUSER ]] && info "Roundcube logs in as DB user '$RC_DBUSER' (config: ${RC_DBFILE:-$RC_CONF})"
  [[ $RC_DBUSER == root ]] && warn "Roundcube uses DB root: if you change root's DB password, update ${RC_DBFILE:-$RC_CONF} too or webmail breaks"
  note "If you change the roundcube DB user's password, update \$dbpass in ${RC_DBFILE:-the Roundcube config} the same minute."
  have mariadb-secure-installation && tool=mariadb-secure-installation
  have mysql_secure_installation && tool=mysql_secure_installation
  if [[ -n $tool ]] && confirm "Run $tool (you type the passwords; it removes anonymous users, test DB and remote root)?"; then
    on_tty "$tool" && act "RAN $tool"
  fi
}

# ---- verification (no curl: bash /dev/tcp, openssl only if present) ----------
check_port() {
  local line
  line=$(tcp_banner "$1")
  if [[ $line =~ $2 ]]; then good "$3 :$1 answers: ${line:0:70}"
  else warn "$3 :$1 did not answer as expected: '${line:0:70}'"; fi
}
check_tls() {
  local line
  line=$(timeout 5 openssl s_client -connect "127.0.0.1:$1" -quiet -ign_eof </dev/null 2>/dev/null | head -n1 | tr -d '\r')
  if [[ $line =~ $2 ]]; then good "$3 :$1 answers: ${line:0:70}"
  else warn "$3 :$1 did not answer as expected: '${line:0:70}'"; fi
}
http_check() {
  local url code p
  code=$(http_code 80 /); case $code in 2*|3*) good "http://127.0.0.1/ -> $code" ;; *) warn "http://127.0.0.1/ -> ${code:-no answer}" ;; esac
  if have openssl; then
    code=$(https_code /); case $code in 2*|3*) good "https://127.0.0.1/ -> $code" ;; "") ;; *) warn "https://127.0.0.1/ -> $code" ;; esac
  fi
  for url in roundcube roundcubemail webmail mail squirrelmail; do
    code=$(http_code 80 "/$url/")
    case $code in 2*|3*) good "http://127.0.0.1/$url/ -> $code" ;; 401|403|5*) warn "http://127.0.0.1/$url/ -> $code" ;; esac
    have openssl || continue
    code=$(https_code "/$url/")
    case $code in 2*|3*) good "https://127.0.0.1/$url/ -> $code" ;; 401|403|5*) warn "https://127.0.0.1/$url/ -> $code" ;; esac
  done
}
verify_services() {
  hdr "Service check (from this box)"
  local s open u pw
  for s in postfix dovecot apache2 nginx "${PHPFPM_UNITS[@]}" mariadb mysql ssh; do
    [[ $s == postfix ]] || unit_exists "$s" || continue
    [[ $s == postfix ]] && ! have postfix && continue
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
  if confirm "Test a real mailbox login over IMAP on 127.0.0.1:143 (password is typed hidden, never stored)?"; then
    u=$(ask "  mail username: ")
    if [[ -n $u ]]; then
      read -r -s -p "  password for $u: " pw <"$TTY"; echo
      if imap_login "$u" "$pw"; then good "IMAP login works for $u"; else warn "IMAP login FAILED for $u"; fi
      unset pw
    fi
  fi
}

# =============================================================================
#  MAIN
# =============================================================================
STEP_FUNCS=(step_passwords step_procs step_accounts step_firewall step_postfix step_dovecot
            step_web step_persist step_ssh step_services step_mac step_mysql)

menu() {
  local c s
  REPORT=$OUT/menu-session.txt
  while true; do
    pg_reset
    printf '\n%s=== MENU (nothing changes unless you answer y) ===%s\n' "$B" "$N"
    cat <<EOF
   1) Passwords (you type them)           7) Webmail installer / webshells / PHP
   2) Kill flagged processes & sessions   8) Persistence: cron, systemd, motd, apt hooks, SUID/caps
   3) Accounts, sudo, SSH keys, PAM       9) SSH daemon settings
   4) Firewall allowlist (auto-rollback) 10) Unneeded services
   5) Postfix relay / BCC / forwards     11) AppArmor
   6) Dovecot auth backdoors             12) MySQL / MariaDB
   a) walk 1-12 in order   v) verify services   r) re-scan   q) quit
   VIEW (page up/down + search):  f) flags   s) full scan report   l) changes log   m) this session's output
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
      f) view_file "$FLAGFILE" ;;
      s) view_file "$SCAN_REPORT" ;;
      l) view_file "$ACTLOG" ;;
      m) view_file "$OUT/menu-session.txt" ;;
      r) REPORT=$OUT/scan-report-$(date +%H%M%S).txt; FLAGFILE=${REPORT%.txt}-flags.txt; SCAN_REPORT=$REPORT
         run_scan; summary; REPORT=$OUT/menu-session.txt ;;
      q) break ;;
    esac
  done
}

finish() {
  echo
  printf '  Scan report : %s\n  Flags       : %s\n  Changes log : %s (use it for incident reports)\n  Quarantine  : %s\n  dpkg verify : %s\n' \
    "$OUT/scan-report.txt" "$FLAGFILE" "$ACTLOG" "$QUAR" "$OUT/dpkg-verify-all.txt"
  printf '  %sCopy %s off this box now (e.g. scp -r %s you@jumpbox:).%s\n' "$Y" "$OUT" "$OUT" "$N"
}

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; }

main() {
  local scan_only=0
  case ${1:-} in
    -s|--scan-only) scan_only=1 ;;
    --no-pager)     NOPAGER=1; shift; main "$@"; return ;;
    -h|--help)      usage; exit 0 ;;
    "") ;;
    *)              echo "unknown option: $1"; usage; exit 1 ;;
  esac
  [[ $EUID -eq 0 ]] || { echo "Run this as root."; exit 1; }
  have dpkg-query || { echo "No dpkg: this is the Debian/Ubuntu version. Use 5_Min_Plan_Fedora_Webmail.sh on Fedora/RHEL."; exit 1; }
  if (( ! scan_only )) && ! { : <"$TTY"; } 2>/dev/null; then
    echo "No terminal for prompts. Run it interactively, or use --scan-only."; exit 1
  fi
  mkdir -p "$OUT" || exit 1
  chmod 700 "$BASE_DIR" "$OUT"
  : >"$REPORT"; : >"$ACTLOG"
  pg_init "$OUT"

  cat <<EOF
${B}
  Debian webmail: first 5 minutes  (v$VERSION)   $(hostname)   $(date '+%F %T')${N}
  The scan is read-only. Every change asks first (default No). You type all passwords. No network used.
  Output: $OUT

  0:00 backup > 0:30 scan > 1:30 [1] passwords > 2:00 [2] kill shells, [3] accounts/keys
  2:45 [4] firewall > 3:30 [5] postfix, [6] dovecot > 4:15 [7] webmail, [8] persistence > 4:45 [v] verify
EOF
  trap 'echo; finish; exit 130' INT

  detect_web
  if (( ! scan_only )) && confirm_yes "Back up /etc, /root, cron spools, web roots, mail + firewall state to $BACKUP first?"; then
    do_backup
  fi
  nohup nice -n 19 bash -c 'dpkg --verify 2>&1 | awk '"'"'($1 ~ /5/) || ($1 == "missing" && $NF !~ /^\/usr\/share\/(doc|man|locale|info|lintian|bug|doc-base|help|gtk-doc)\// && $NF !~ /^\/var\/(lib\/apt\/lists|cache)\//)'"'"' >"$1"' \
    _ "$OUT/dpkg-verify-all.txt" >/dev/null 2>&1 </dev/null &
  note "full 'dpkg --verify' running in the background -> $OUT/dpkg-verify-all.txt (non-'c' lines with '5' = changed binaries)"

  run_scan
  summary
  if (( PG_ON )) && (( ! scan_only )); then
    note "The menu has viewers (f / s / l) to page back through the flags, the full report and the log."
  fi
  (( scan_only )) || menu
  finish
}

main "$@"
