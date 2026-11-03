#!/usr/bin/env bash
export PATH=/usr/sbin:/usr/bin:/sbin:/bin      
export LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV CDPATH
umask 077

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo:  sudo bash $0"; exit 1; }
CHECK=0
for a in "$@"; do case $a in --check) CHECK=1 ;; --no-pager) NOPAGER=1 ;; *) echo "unknown option: $a"; exit 1 ;; esac; done
TTY=/dev/tty
if (( ! CHECK )) && ! { : <"$TTY"; } 2>/dev/null; then echo "No terminal for prompts. Use --check."; exit 1; fi

TS=$(date +%Y%m%d-%H%M%S)
SAVE=/root/.bak-$TS
mkdir -p "$SAVE" && chmod 700 "$SAVE"
LOG=$SAVE/actions.log; : >"$LOG"
FW_WAIT=${FW_WAIT:-90}; [[ $FW_WAIT =~ ^[0-9]+$ ]] && (( FW_WAIT >= 30 )) || FW_WAIT=90

ME="${SUDO_USER:-$(logname 2>/dev/null)}"; [ "$ME" = root ] && ME=""
NOLOGIN=/usr/sbin/nologin; [ -x $NOLOGIN ] || NOLOGIN=/sbin/nologin
if command -v dpkg-query >/dev/null 2>&1; then PKG=dpkg
elif command -v rpm >/dev/null 2>&1; then PKG=rpm
else PKG=none; fi
ADMIN_GROUPS="sudo wheel admin"
ROOTEQ_GROUPS="docker lxd disk libvirt"


MY_PIDS=" "; p=$$
while [[ $p =~ ^[0-9]+$ ]] && (( p > 1 )); do MY_PIDS+="$p "; p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' '); done

ask()    { if (( CHECK )); then echo "  $1 [check mode: no]"; return 1; fi
           local a; read -r -p "$1 [y/N] " a <"$TTY" || return 1; pg_reset; [[ $a == [yY]* ]]; }
step()   { echo; echo "=== $1 ==="; }
warn()   { echo "  !! $*"; }
act()    { echo "$(date '+%F %T')  $*" >>"$LOG"; }
have()   { command -v "$1" >/dev/null 2>&1; }
inlist() { [[ " $2 " == *" $1 "* ]]; }



shopt -s lastpipe extglob                  
PG_ON=0; PG_N=0; PG_ROWS=24; PG_COLS=80; PG_FILE=""
pg_init() {          
  [[ -t 1 && -z ${NOPAGER:-} ]] && { : <"$TTY"; } 2>/dev/null || return 0
  local s; s=$(stty size <"$TTY" 2>/dev/null)
  [[ ${s% *} =~ ^[0-9]+$ ]] && (( ${s% *} > 5 )) && PG_ROWS=${s% *}
  [[ ${s#* } =~ ^[0-9]+$ ]] && (( ${s#* } > 20 )) && PG_COLS=${s#* }
  PG_FILE=$1/.pager-reset; PG_ON=1
}
pg_reset() { PG_N=0; [[ -n $PG_FILE ]] && : >"$PG_FILE" 2>/dev/null; }   
pg_line() {          
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
view_file() {        
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



echo() {
  if [[ -t 1 ]]; then local IFS=' '; printf '%s\n' "$*" >>"$SAVE/screen.txt"; pg_line "$*"
  else builtin echo "$@"; fi
}
pg_init "$SAVE"
indent() { local l; while IFS= read -r l; do l="    $l"; echo "${l:0:200}"; done; }
stash()  { local d=$SAVE/quarantine$1; mkdir -p "$(dirname "$d")"; mv -f -- "$1" "$d" && { echo "  Moved to $d"; act "QUARANTINED $1"; }; }


PKGDB=$SAVE/package-files.txt
build_pkgdb() {
  [ -s "$PKGDB" ] && return
  { case $PKG in
      dpkg) cat /var/lib/dpkg/info/*.list 2>/dev/null
            dpkg-divert --list 2>/dev/null | sed -nE 's/^diversion of [^ ]+ to ([^ ]+) by .*/\1/p' ;;
      rpm)  rpm -qal 2>/dev/null ;;
    esac; } | awk '{ p=$0; if (p ~ /^\/usr\/(bin|sbin|lib|lib32|lib64|libx32)\//) p=substr(p,5); print p }' | sort -u >"$PKGDB"
}
unowned() {   
  (( $# )) || return 0
  [ "$PKG" = none ] && { printf '%s\n' "$@"; return; }
  build_pkgdb
  printf '%s\n' "$@" | awk -v db="$PKGDB" 'BEGIN { while ((getline l < db) > 0) own[l] = 1 }
    { p = $0; if (p ~ /^\/usr\/(bin|sbin|lib|lib32|lib64|libx32)\//) p = substr(p, 5); if (!(p in own)) print $0 }'
}
pkg_changed() {   
  case $PKG in
    dpkg) local want; want=$(dpkg-query -W -f='${Conffiles}\n' 2>/dev/null | awk -v f="$1" '$1==f{print $2; exit}')
          [ -n "$want" ] && [ "$(md5sum <"$1" | cut -d' ' -f1)" != "$want" ] ;;
    rpm)  rpm -Vf "$1" 2>/dev/null | grep -qE "^..5.* $1\$" ;;
    *)    return 1 ;;
  esac
}
suspect_files() { unowned "$@"; local f; for f in "$@"; do pkg_changed "$f" && echo "$f"; done; }


ssh_sessions() { ps -eo pid=,args= 2>/dev/null | awk '$2 ~ /^sshd(-session)?:$/ && $3 ~ /@/ { print $1, $3 }'; }
end_sessions() {   
  local pid s
  while read -r pid s; do
    [ "${s%@*}" = "$1" ] && ! inlist "$pid" "$MY_PIDS" && kill -KILL "$pid" 2>/dev/null
  done < <(ssh_sessions)
  [ "$(id -u "$1" 2>/dev/null)" != 0 ] && pkill -KILL -u "$1" 2>/dev/null
}
lock_user() {   
  [ "$1" = root ] && { warn "not locking root"; return; }
  [ -n "$ME" ] && [ "$1" = "$ME" ] && { warn "'$1' is you; skipped"; return; }
  passwd -l "$1" >/dev/null 2>&1; chage -E 0 "$1"; end_sessions "$1"
  echo "  Locked and logged out: $1   (undo: passwd -u $1; chage -E -1 $1)"; act "LOCKED $1"
}
change_pw() {   
  local p1 p2
  while true; do
    read -r -s -p "  New password for $1: " p1 <"$TTY"; echo
    read -r -s -p "  Type it again: " p2 <"$TTY"; echo; pg_reset
    [ -n "$p1" ] && [ "$p1" = "$p2" ] && break
    echo "  Didn't match (or was empty). Try again."
  done
  if printf '%s:%s\n' "$1" "$p1" | chpasswd; then echo "  Done: $1"; act "PASSWORD changed: $1"; else warn "FAILED: $1 (immutable /etc/shadow? see step 11)"; fi
}

echo "General Linux 5-minute plan   $(hostname)   $(date '+%F %T')   package manager: $PKG"
(( CHECK )) && echo "CHECK MODE: nothing will be changed."
echo "Everything this script saves goes to $SAVE (copy it off the box!)"
[ -n "$ME" ] && echo "You are: $ME (never locked, kicked or removed from sudo)" || \
  echo "!! Couldn't tell which account is yours. Answer N whenever your own account comes up."


step "0. Back up /etc and system state (your undo button)"
BACKUP=""; UNDO=""
if have tar && have gzip; then
  tar czf "$SAVE/etc-backup.tgz" /etc 2>/dev/null
  if (( $? <= 1 )) && [ -s "$SAVE/etc-backup.tgz" ]; then
    BACKUP=$SAVE/etc-backup.tgz; UNDO="tar xzf $BACKUP -C / etc/PATH/TO/FILE"
    have restorecon && UNDO+="; restorecon -F /etc/PATH/TO/FILE"
  else
    rm -f "$SAVE/etc-backup.tgz"; warn "tar failed; falling back to a plain copy"
  fi
else
  echo "  tar or gzip not installed; using a plain copy of /etc"
fi
if [ -z "$BACKUP" ]; then
  cp -a /etc "$SAVE/etc" 2>/dev/null; rc=$?
  if [ -d "$SAVE/etc" ]; then
    BACKUP=$SAVE/etc; UNDO="cp -a $BACKUP/PATH/TO/FILE /etc/PATH/TO/FILE"
    (( rc )) && warn "copy of /etc is INCOMPLETE (disk full?): check $BACKUP before relying on it"
  fi
fi
{ ps auxfww; echo; ss -tulpna; } >"$SAVE/state-before.txt" 2>/dev/null
have nft && nft list ruleset >"$SAVE/nft-before.txt" 2>/dev/null
have iptables-save && iptables-save >"$SAVE/iptables-before.txt" 2>/dev/null
if [ -n "$BACKUP" ]; then echo "  Saved: $BACKUP and state-before.txt"
else warn "NO BACKUP OF /etc (disk full?). There is no undo for file changes: free space and re-run."; fi
case $PKG in
  dpkg) nohup nice -n 19 bash -c 'dpkg --verify 2>&1 | awk '"'"'$1 ~ /5/ || ($1=="missing" && $NF !~ /^\/usr\/share\/(doc|man|locale|info)\//)'"'"' >"$1"' _ "$SAVE/integrity.txt" >/dev/null 2>&1 </dev/null & ;;
  rpm)  nohup nice -n 19 bash -c 'rpm -Va 2>&1 | awk '"'"'$1 ~ /5/ || $1=="missing"'"'"' >"$1"' _ "$SAVE/integrity.txt" >/dev/null 2>&1 </dev/null & ;;
esac
echo "  Package integrity check running in the background -> $SAVE/integrity.txt"


step "1. Who is logged in right now"



who | indent
echo "  SSH sessions:"
while read -r pid sess; do
  if inlist "$pid" "$MY_PIDS"; then echo "    $sess  <- you"; continue; fi
  echo "    $sess (pid $pid)"
  ask "    End this session? (N if it's a teammate)" && kill -KILL "$pid" && { echo "    Ended."; act "KILLED ssh session $sess"; }
done < <(ssh_sessions)


step "2. Suspicious processes"

SUS=0
while read -r pid user args; do
  inlist "$pid" "$MY_PIDS" && continue
  exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
  why=""
  case $exe in
    *" (deleted)") why="binary deleted from disk" ;;
    /tmp/*|/var/tmp/*|/dev/shm/*|*/.*/*) why="runs from $(dirname "$exe")" ;;
  esac
  [ -z "$why" ] && [[ $args == "["* ]] && why="pretends to be a kernel thread"
  if [ -z "$why" ]; then
    if   [[ $args =~ /dev/(tcp|udp)/ ]]; then why="bash /dev/tcp reverse shell"
    elif [[ $args =~ (^|[/[:space:]])(nc|ncat|netcat|socat)([[:space:]]|$) ]]; then why="netcat/socat"
    elif [[ $args =~ (^|[/[:space:]])(python[0-9.]*|perl|ruby|php[0-9.]*)[[:space:]]+-[a-zA-Z]*[ecr]([[:space:]]|$) ]]; then why="interpreter one-liner"
    elif [[ $args =~ (curl|wget)[^|]*\|[[:space:]]*(ba|da|z)?sh ]]; then why="download piped into a shell"
    elif [[ $args =~ mkfifo ]]; then why="named-pipe shell"
    elif [[ $args =~ ^(/usr/sbin/)?sshd[[:space:]].*[[:space:]]-[a-zA-Z]*[fpo] ]]; then why="second sshd with its own config/port"
    elif [[ $args =~ (^|[/[:space:]])ssh[[:space:]].*-[a-zA-Z]*R[[:space:]] ]]; then why="SSH reverse tunnel"
    fi
  fi
  [ -z "$why" ] && continue
  SUS=1
  echo "  PID $pid ($user) $why:"; echo "    ${args:0:150}"
  ss -tunp 2>/dev/null | grep "pid=$pid," | indent
  if ask "  Kill it? (binary + command line copied to $SAVE/proc first)"; then
    mkdir -p "$SAVE/proc"; cp "/proc/$pid/exe" "$SAVE/proc/$pid.bin" 2>/dev/null
    tr '\0' ' ' <"/proc/$pid/cmdline" >"$SAVE/proc/$pid.cmdline" 2>/dev/null
    kill -9 "$pid" && { echo "  Killed."; act "KILLED $pid: ${args:0:150}"; }
  fi
done < <(ps -eo pid=,user:32=,args= 2>/dev/null)
[ $SUS = 0 ] && echo "  None matched. (Not proof: a rootkit can hide processes.)" || \
  echo "  If a killed shell comes back, it's being respawned: see step 8."


step "3. Change passwords"

for f in /etc/shadow /etc/passwd; do
  lsattr -d "$f" 2>/dev/null | awk '{exit !($1 ~ /i/)}' && {
    warn "$f is IMMUTABLE (chattr +i): every password change will fail."
    ask "  Remove the immutable flag (chattr -i $f)?" && chattr -i "$f" && act "CHATTR -i $f"; }
done
USERS=$(awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ && $7 != "" {print $1}' /etc/passwd)
ADMINS=$(for g in $ADMIN_GROUPS; do getent group "$g" | cut -d: -f4 | tr ',' '\n'; done | sed '/^$/d' | sort -u | tr '\n' ' ')
echo "  Accounts that can log in: $(echo $USERS)"
echo "  Admins (sudo/wheel/admin groups): ${ADMINS:-none}"
echo "  Order: root, then admins, then the rest. A SCORED service account needs a"
echo "  password-change ticket (PCR) or scoring fails. Strangers get locked in steps 4-5."
SEEN=" "
for u in root $ADMINS $USERS; do
  inlist "$u" "$SEEN" && continue; SEEN+="$u "
  ask "  Change password for '$u'?" && change_pw "$u"
done
echo "  NOTE: change them AGAIN in 30-45 minutes (assume they were watched)."


step "4. Root-level accounts"
EXTRA=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
for u in $EXTRA; do warn "'$u' has UID 0 (full root power)"; ask "  Lock '$u'?" && lock_user "$u"; done
[ -z "$EXTRA" ] && echo "  Only root has UID 0. Good."
for u in $(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null); do
  warn "'$u' has an EMPTY password (anyone can log in as it)"; ask "  Lock '$u'?" && lock_user "$u"
done
x=$(awk -F: '$2 != "x" && $2 != "*" && $2 !~ /^!/ {print $1}' /etc/passwd); [ -n "$x" ] && warn "password hash in /etc/passwd (overrides shadow): $x"
x=$(cut -d: -f3 /etc/passwd | sort | uniq -d | tr '\n' ' '); [ -n "${x// }" ] && warn "duplicate UIDs: $x"
x=$({ find /etc/shadow /etc/gshadow -perm /o+r; find /etc/passwd /etc/group /etc/shadow /etc/sudoers -perm /go+w; } 2>/dev/null | tr '\n' ' ')
[ -n "${x// }" ] && warn "bad permissions on: $x  (fix: chmod 640 shadow files, 644 passwd/group, 440 sudoers)"


step "5. Lock accounts you don't recognize"

echo "  Do NOT lock: yourself, root, or anything a scored service might use."
for u in $USERS; do
  [ "$u" = root ] && continue; [ -n "$ME" ] && [ "$u" = "$ME" ] && continue
  echo "$EXTRA" | grep -qx "$u" && continue
  ask "  Lock '$u'?" && lock_user "$u"
done

SYSPW=$(awk -F: 'NR==FNR { sh[$1]=$7; uid[$1]=$3; next }
  $2 !~ /^[!*]/ && $2 != "" && uid[$1] > 0 && uid[$1] < 1000 && sh[$1] ~ /(nologin|false)$/ {print $1}' /etc/passwd /etc/shadow 2>/dev/null)
for u in $SYSPW; do
  warn "system account '$u' has a usable password but no shell (still works for IMAP/FTP/su -s)"
  ask "  Lock its password?" && passwd -l "$u" >/dev/null && { echo "  Locked."; act "LOCKED password of $u"; }
done


step "6. Who has admin (root) rights"


for g in $ADMIN_GROUPS $ROOTEQ_GROUPS; do
  getent group "$g" >/dev/null || continue
  members=$(getent group "$g" | cut -d: -f4 | tr ',' ' ')
  echo "  Group '$g': ${members:-(nobody)}"
  for u in $members; do
    [ -n "$ME" ] && [ "$u" = "$ME" ] && { echo "    $u = you, keeping"; continue; }
    ask "  Remove '$u' from '$g'?" && gpasswd -d "$u" "$g" >/dev/null && { echo "  Removed."; act "GROUP $g removed $u"; }
  done
done


echo "  sudo rules that aren't stock:"
FOUND=no
while IFS= read -r line; do
  f=${line%%:*}; body=${line#*:}; body=${body#*:}
  norm=$(tr -s ' \t' ' ' <<<"$body" | sed 's/^ //; s/ $//')
  why=""
  case $norm in
    "") continue ;;
    [#@]includedir\ /etc/sudoers.d) continue ;;
    [#@]include*) why="pulls in another file/dir" ;;
    \#*) continue ;;
    "root ALL=(ALL) ALL"|"root ALL=(ALL:ALL) ALL"|%sudo\ ALL=\(ALL*\)\ ALL|%wheel\ ALL=\(ALL*\)\ ALL|%admin\ ALL=\(ALL*\)\ ALL) continue ;;
    Defaults*) [[ $norm =~ \!authenticate|LD_PRELOAD|LD_LIBRARY_PATH|BASH_ENV ]] && why="Defaults that skip the password / inject code" || continue ;;
    *NOPASSWD*) why="NOPASSWD (root without a password)" ;;
    *) why="extra grant" ;;
  esac
  FOUND=yes; echo "    $f: $norm   <- $why"
done < <(grep -HnE '' /etc/sudoers /etc/sudoers.d/* 2>/dev/null)
[ $FOUND = no ] && echo "    none. Good."


for f in /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  grep -vE '^[[:space:]]*(#[^i]|#$|$)' "$f" | grep -q . || continue
  [ -z "$(unowned "$f")" ] && ! grep -qE 'NOPASSWD|!authenticate' "$f" && continue
  echo "  File: $f"; grep -vE '^[[:space:]]*(#[^i]|#$|$)' "$f" | indent
  ask "  Move it out of sudoers.d?" || continue
  stash "$f"
  if ! visudo -c >/dev/null 2>&1; then mv -f "$SAVE/quarantine$f" "$f"; warn "sudo config check failed; put back"
  elif [ -n "$ME" ] && sudo -l -U "$ME" 2>&1 | grep -q 'not allowed'; then mv -f "$SAVE/quarantine$f" "$f"; warn "you would lose sudo; put back"; fi
done
echo "  Lines in /etc/sudoers itself: fix with 'sudo visudo'."


step "7. SSH keys and SSH login hooks"



FOUND=no
while IFS=: read -r u _ _ _ _ home _; do
  [ -n "$home" ] && [ "$home" != / ] || continue
  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2" "$home/.ssh/rc"; do
    [ -s "$f" ] || continue
    inlist "$f" "${SEEN_KEYS:-}" && continue; SEEN_KEYS="${SEEN_KEYS:-} $f"
    FOUND=yes; echo; echo "  $f  (account $u)"
    case $f in */rc) echo "    (runs on every ssh login as $u)"; head -n 5 "$f" | indent ;;
               *)    awk '!/^[[:space:]]*(#|$)/ {print substr($0, 1, 40) " ... " $NF}' "$f" | indent ;; esac
    ask "  Move it out (keys stop working)? N if any key is your team's" && stash "$f"
  done
done < <(getent passwd)
[ -f /etc/ssh/sshrc ] && { FOUND=yes; echo "  /etc/ssh/sshrc runs on EVERY ssh login:"; indent </etc/ssh/sshrc; ask "  Move it out?" && stash /etc/ssh/sshrc; }
[ $FOUND = no ] && echo "  No keys or login hooks found."
if have sshd; then
  T=$(sshd -T 2>/dev/null)
  x=$(awk 'tolower($1)=="authorizedkeysfile"{ $1=""; print }' <<<"$T")
  [[ -n $x && $x != " .ssh/authorized_keys .ssh/authorized_keys2" && $x != " .ssh/authorized_keys" ]] && warn "sshd reads keys from a non-default place:$x (fix in sshd_config)"
  x=$(awk 'tolower($1)=="authorizedkeyscommand" && $2!="none"{ $1=""; print }' <<<"$T")
  [ -n "$x" ] && warn "sshd runs a program to fetch keys:$x (backdoor? fix in sshd_config)"
fi


step "8. Persistence (things that bring the attacker back)"





mkdir -p "$SAVE/quarantine"; RELOAD=no
review() {   
  echo; echo "  $2: $1   (changed $(date -r "$1" '+%F %R' 2>/dev/null))"
  grep -vE '^[[:space:]]*(#|$)' "$1" 2>/dev/null | head -n 6 | indent
  ask "  Move it out?" && stash "$1"
}

for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do [ -f "$f" ] && review "$f" "user crontab"; done

mapfile -t L < <(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f ! -name .placeholder 2>/dev/null)
mapfile -t L < <(suspect_files "${L[@]}" | sort -u)
for f in "${L[@]}"; do
  review "$f" "cron file not from a package (or changed)"
done
if [ -f /etc/crontab ] && { [ -n "$(unowned /etc/crontab)" ] || pkg_changed /etc/crontab; }; then
  echo; echo "  /etc/crontab was changed. Jobs (Debian's stock run-parts lines are normal):"
  grep -vE '^[[:space:]]*(#|$)|^[A-Z]+=' /etc/crontab | indent; echo "  Edit by hand if needed."
fi
have atq && [ -n "$(atq 2>/dev/null)" ] && { echo "  'at' jobs queued (atq; at -c N to read, atrm N to remove):"; atq | indent; }


UDIRS=$(for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /usr/local/lib/systemd/system \
                 /etc/systemd/user /usr/lib/systemd/user /etc/systemd/system-generators /root/.config/systemd/user \
                 /home/*/.config/systemd/user; do [ -d "$d" ] && readlink -f "$d"; done | sort -u)
mapfile -t UD <<<"$UDIRS"
mapfile -t L < <(find "${UD[@]}" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.conf' -o -perm /111 \) 2>/dev/null)
mapfile -t L < <(unowned "${L[@]}")
for f in "${L[@]}"; do
  name=$(basename "$f")
  echo; echo "  systemd file not from a package: $f   (changed $(date -r "$f" '+%F %R'))"
  grep -E '^[[:space:]]*(Description|ExecStart|ExecStartPre|ExecStartPost|OnCalendar|OnBootSec|OnUnitActiveSec)=' "$f" | head -n 5 | indent
  if ask "  Stop it and move it out?"; then
    case $f in *.d/*.conf|*generators*|/home/*|/root/*) ;; *) systemctl disable --now "$name" >/dev/null 2>&1 ;; esac
    stash "$f"; RELOAD=yes
  fi
done
while read -r l; do
  t=$(readlink -f "$l" 2>/dev/null)
  case $t in /dev/null|/usr/lib/systemd/*|/lib/systemd/*|/etc/systemd/*|/run/systemd/*) continue ;; esac
  echo; echo "  systemd link $l -> ${t:-$(readlink "$l")}  (points outside the unit dirs)"
  ask "  Remove the link?" && { stash "$l"; RELOAD=yes; }
done < <(find /etc/systemd/system /etc/systemd/user -type l 2>/dev/null)
[ $RELOAD = yes ] && systemctl daemon-reload 2>/dev/null

for f in /etc/rc.local /etc/rc.d/rc.local; do
  [ -f "$f" ] && [ ! -L "$f" ] && grep -vE '^[[:space:]]*(#|$)|^[[:space:]]*(exit 0|touch /var/lock/subsys/local)[[:space:]]*$' "$f" | grep -q . && review "$f" "runs at boot"
done
[ -s /etc/ld.so.preload ] && review /etc/ld.so.preload "LOADED INTO EVERY PROGRAM (classic rootkit)"
mapfile -t L < <(find /etc/profile.d /etc/update-motd.d /etc/ld.so.conf.d /etc/init.d /etc/X11/Xsession.d -maxdepth 1 -type f 2>/dev/null)
mapfile -t L < <(suspect_files "${L[@]}" | sort -u)
for f in "${L[@]}"; do
  review "$f" "login/boot script not from a package (or changed)"
done
mapfile -t L < <(find /etc/apt/apt.conf.d -maxdepth 1 -type f 2>/dev/null)
mapfile -t L < <(suspect_files "${L[@]}")
for f in "${L[@]}"; do
  grep -qi invoke "$f" && review "$f" "apt hook (runs on every apt/dpkg call)"
done
for f in /etc/udev/rules.d/*.rules; do [ -f "$f" ] && grep -qE 'RUN\+?=' "$f" && review "$f" "udev rule that runs a program"; done

RE='alias[[:space:]]+(sudo|su|ls|ps|ss|netstat|passwd|cat|top|lsof|who|kill|id|grep|find|systemctl)=|/dev/tcp|(^|[;&|[:space:]])(nc|ncat|socat)[[:space:]]|curl[[:space:]]|wget[[:space:]]|base64[[:space:]]+-d|PROMPT_COMMAND|trap[[:space:]].*DEBUG|LD_PRELOAD'
for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment /root/.bashrc /root/.bash_profile /root/.profile \
         /home/*/.bashrc /home/*/.bash_profile /home/*/.profile; do
  [ -f "$f" ] || continue
  [ -z "$(unowned "$f")" ] && ! pkg_changed "$f" && continue            
  x=$(grep -nE "$RE" "$f" | grep -vE '^[0-9]+:[[:space:]]*#' | grep -vE "alias (ls|dir|vdir|grep|fgrep|egrep)='(ls|dir|vdir|grep|fgrep|egrep) --color=auto'")
  [ -n "$x" ] && { echo; echo "  Suspicious lines in $f (edit by hand):"; indent <<<"$x"; }
done



x=$(grep -HnE '^[[:space:]]*-?auth[[:space:]]+[^#]*pam_permit\.so' /etc/pam.d/* 2>/dev/null | grep -vE '^[^:]+:[0-9]+:[[:space:]]*-?auth[[:space:]]+required[[:space:]]+pam_permit')
[ -n "$x" ] && { echo; warn "PAM accepts ANY password here (fix by hand, keep a root shell open):"; indent <<<"$x"; }
x=$(grep -HnE '^[^#]*pam_exec\.so' /etc/pam.d/* 2>/dev/null)
[ -n "$x" ] && { echo; warn "PAM runs a program at login (can steal passwords):"; indent <<<"$x"; }
mapfile -t L < <(find /lib/*/security /usr/lib/*/security /lib64/security /usr/lib64/security -maxdepth 1 -name '*.so' 2>/dev/null)
x=$(unowned "${L[@]}" | tr '\n' ' ')
[ -n "${x// }" ] && warn "PAM modules no package installed (backdoor?): $x"


step "9. SSH server settings"




CFG=/etc/ssh/sshd_config
MARK="# --- 5_Min_Plan_Linux_General.sh ---"
if [ ! -f "$CFG" ]; then echo "  No SSH server config. Skipping."
else
  x=$(awk 'FNR==1{m=0} tolower($1)=="match"{m=1; h=$0; next}
           m && tolower($1) ~ /^(permitrootlogin|passwordauthentication|permitemptypasswords|authorizedkeysfile|authorizedkeyscommand|forcecommand)$/ {print FILENAME ":" FNR ": [" h "] " $0}' \
           "$CFG" /etc/ssh/sshd_config.d/*.conf 2>/dev/null)
  [ -n "$x" ] && { warn "Match blocks override these for some users/hosts (edit by hand):"; indent <<<"$x"; }
  if grep -qF "$MARK" "$CFG"; then echo "  Already done on an earlier run."
  else
    [ -z "$ME" ] && warn "You seem to be logged in as root directly. Make sure another sudo account works BEFORE saying yes."
    if ask "  Disable root login and empty passwords over SSH?"; then
      cp -a "$CFG" "$SAVE/sshd_config.before"
      { printf '%s\nPermitRootLogin no\nPermitEmptyPasswords no\n\n' "$MARK"; cat "$SAVE/sshd_config.before"; } >"$CFG"
      mkdir -p /run/sshd 2>/dev/null
      if sshd -t 2>/dev/null; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || service sshd reload
        echo "  Done. Your current session stays open."; act "SSHD PermitRootLogin no, PermitEmptyPasswords no"
        warn "TEST NOW: open a NEW ssh session before closing this one."
      else
        cat "$SAVE/sshd_config.before" >"$CFG"; warn "Config test FAILED, so nothing was changed."
      fi
    fi
  fi
fi


step "10. Firewall: incoming allowlist with a safety timer"








if have ufw; then FW=ufw
elif have firewall-cmd; then FW=firewalld
elif have nft; then FW=nft
else FW=none; fi
echo "  Tool: $FW"
PORTLIST=$(ss -tlnpH 2>/dev/null | awk '{ a=$4; if (a ~ /^(127\.|\[::1\]|\[::ffff:127\.)/) next
             n=split(a, x, ":"); port=x[n]; prog="?"; if (match($0, /\(\("[^"]+"/)) prog=substr($0, RSTART+3, RLENGTH-4)
             print port, prog }' | sort -un)
echo "  TCP ports open to the network now (port program):"; echo "${PORTLIST:-(none)}" | indent
SSHPORT=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}'); SSHPORT=${SSHPORT:-22}
SUGGEST=$(awk -v s="$SSHPORT" '$1 != s && $1 ~ /^(21|25|53|80|110|143|389|443|465|587|636|993|995|3306|5432|8080|8443)$/ {printf "%s ", $1}' <<<"$PORTLIST")
case $FW in
  ufw)       ufw status verbose | indent ;;
  firewalld) firewall-cmd --state >/dev/null 2>&1 && for z in $(firewall-cmd --get-active-zones | awk '!/^[[:space:]]/{print $1}'); do
               firewall-cmd --zone="$z" --list-all | indent
               [ "$(firewall-cmd --permanent --zone="$z" --get-target)" = ACCEPT ] && warn "zone $z accepts EVERYTHING"
             done
             x=$(firewall-cmd --zone=trusted --list-sources 2>/dev/null); [ -n "$x" ] && warn "trusted-zone sources bypass the firewall: $x" ;;
  nft)       nft list ruleset 2>/dev/null | grep -E 'hook input|policy' | indent ;;
  none)      warn "no ufw / firewalld / nft. Nothing can be installed offline: ask for edge filtering." ;;
esac
if [ "$FW" != none ] && ! (( CHECK )); then
  echo "  SSH port $SSHPORT is always allowed. Every OTHER incoming TCP port gets blocked unless listed."
  echo "  (scored service left out = lost points. Type 'none' for no extra ports. UDP: add by hand.)"
  read -r -p "  Ports to allow from anywhere [${SUGGEST:-none}]: " PORTS <"$TTY"; pg_reset
  PORTS=${PORTS:-$SUGGEST}; [ "$PORTS" = none ] && PORTS=""; PORTS=${PORTS//,/ }
  BAD=no; for p in $PORTS; do [[ $p =~ ^[0-9]+$ ]] && (( p > 0 && p < 65536 )) || { warn "bad port: $p"; BAD=yes; }; done
  if [ $BAD = no ] && ask "  Apply: allow TCP $SSHPORT ${PORTS}, drop other incoming?"; then
    KEEPFILE=$SAVE/firewall-keep; rm -f "$KEEPFILE"
    case $FW in
      ufw)
        mkdir -p "$SAVE/ufw"; cp -a /etc/ufw/user.rules /etc/ufw/user6.rules /etc/default/ufw "$SAVE/ufw/" 2>/dev/null
        if ufw status | grep -q 'Status: active'; then REVERT="cp -a $SAVE/ufw/user.rules $SAVE/ufw/user6.rules /etc/ufw/; cp -a $SAVE/ufw/ufw /etc/default/ufw; ufw reload"
        else REVERT="ufw --force disable; cp -a $SAVE/ufw/user.rules $SAVE/ufw/user6.rules /etc/ufw/; cp -a $SAVE/ufw/ufw /etc/default/ufw"; fi
        echo "  Existing ufw rules (delete any you don't recognize afterwards: ufw status numbered / ufw delete N):"
        ufw show added 2>/dev/null | grep '^ufw' | indent
        APPLY="ufw allow $SSHPORT/tcp >/dev/null; for p in $PORTS; do ufw allow \$p/tcp >/dev/null; done; ufw default deny incoming >/dev/null; ufw --force enable >/dev/null; ufw reload >/dev/null"
        SAVECMD=true ;;
      firewalld)
        if firewall-cmd --state >/dev/null 2>&1; then REVERT="firewall-cmd --reload"; WAS=on
        else REVERT="systemctl stop firewalld"; WAS=off; systemctl start firewalld; fi
        Z=$(firewall-cmd --get-default-zone)
        echo "  Zone $Z now:"; firewall-cmd --zone="$Z" --list-all | indent
        APPLY="firewall-cmd -q --zone=$Z --add-port=$SSHPORT/tcp; for p in $PORTS; do firewall-cmd -q --zone=$Z --add-port=\$p/tcp; done
               for s in \$(firewall-cmd --zone=$Z --list-services); do [ \$s = dhcpv6-client ] || firewall-cmd -q --zone=$Z --remove-service=\$s; done"
        SAVECMD="firewall-cmd --runtime-to-permanent"; [ $WAS = off ] && SAVECMD+=" && systemctl enable firewalld" ;;
      nft)
        nft list table inet ccdc >"$SAVE/nft-ccdc.before" 2>/dev/null || : >"$SAVE/nft-ccdc.before"
        REVERT="nft delete table inet ccdc 2>/dev/null; [ -s $SAVE/nft-ccdc.before ] && nft -f $SAVE/nft-ccdc.before; true"
        SET=$(echo $SSHPORT $PORTS | tr ' ' ',')
        printf '%s\n' 'table inet ccdc' 'delete table inet ccdc' 'table inet ccdc {' ' chain input {' \
          '  type filter hook input priority 0; policy drop;' '  iif "lo" accept' '  ct state established,related accept' \
          '  meta l4proto { icmp, ipv6-icmp } accept' '  udp dport { 68, 546 } accept' "  tcp dport { $SET } accept" ' }' '}' >"$SAVE/ccdc.nft"
        APPLY="nft -f $SAVE/ccdc.nft"
        SAVECMD="cp $SAVE/ccdc.nft /etc/nftables-ccdc.nft && echo '  Saved /etc/nftables-ccdc.nft. To load at boot, add: include \"/etc/nftables-ccdc.nft\" to your nftables config.'" ;;
    esac
    
    setsid bash -c "sleep $FW_WAIT; [ -f '$KEEPFILE' ] || { $REVERT; echo \"\$(date '+%F %T')  AUTO-ROLLBACK firewall\" >>'$LOG'; }" </dev/null >/dev/null 2>&1 &
    TIMER=$!
    eval "$APPLY" && act "FIREWALL applied ($FW): $SSHPORT $PORTS"
    echo; echo "  Firewall is ON. Before typing KEEP, from your laptop:"
    echo "    1. open a NEW ssh session to this box   2. check each scored service still works"
    pg_reset
    if read -r -t $((FW_WAIT - 10)) -p "  Type KEEP within $((FW_WAIT - 10))s (anything else puts it back): " k <"$TTY" && [ "$k" = KEEP ]; then
      touch "$KEEPFILE"; kill "$TIMER" 2>/dev/null
      eval "$SAVECMD"; echo "  Kept."; act "FIREWALL kept"
    else
      echo; kill "$TIMER" 2>/dev/null; eval "$REVERT" >/dev/null 2>&1
      echo "  Firewall put back the way it was."; act "FIREWALL rolled back"
    fi
  fi
fi


step "11. Report (read-only)"
R=$SAVE/report.txt
{
  echo "## IP addresses"; ip -br addr 2>/dev/null
  echo; echo "## Listening ports"; ss -tulpn 2>/dev/null
  echo; echo "## Established connections (shells/interpreters here = reverse shell)"; ss -tunp state established 2>/dev/null
  echo; echo "## SUID/SGID files no package installed (each one = possible root shell)"
  mapfile -t L < <(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null); unowned "${L[@]}"
  echo; echo "## Files with root-level capabilities (same danger as SUID)"
  have getcap && getcap -r /usr /opt /home 2>/dev/null | grep -E 'cap_(setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|sys_module)' || echo "(getcap not installed or none)"
  echo; echo "## Immutable files (chattr +i makes your fixes fail; chattr -i FILE)"
  lsattr -Ra /etc /root 2>/dev/null | awk '$1 ~ /^[-a-zA-Z]+$/ && $1 ~ /i/ {print $2}'
  echo; echo "## Files in system bin dirs no package installed"
  mapfile -t L < <(find /usr/bin /usr/sbin /bin /sbin -maxdepth 1 -type f 2>/dev/null | sort -u); unowned "${L[@]}"
  echo; echo "## /usr/local (never from a package)"; find /usr/local/bin /usr/local/sbin -maxdepth 1 -type f 2>/dev/null
  echo; echo "## /etc/ld.so.preload (should NOT exist)"; cat /etc/ld.so.preload 2>/dev/null || echo "not present - good"
  echo; echo "## Kernel taint (non-zero = out-of-tree module)"; cat /proc/sys/kernel/tainted
  echo; echo "## Systemd timers"; systemctl list-timers --all --no-pager 2>/dev/null
  echo; echo "## Package integrity (changed package files; written by the background job)"; echo "see $SAVE/integrity.txt"
} >"$R" 2>&1
echo "  Saved: $R   (read it: sudo less $R)"
echo "  Blind spots: a kernel rootkit or a trojaned ps/ss can hide from ALL of this."
echo "  Package checks trust the package database, which root can rewrite."

echo
echo "Finished. Everything saved in $SAVE  (actions: $LOG)"
echo "Copy it OFF this box now: red team can wipe it."
[ -n "$UNDO" ] && echo "Undo a file:  $UNDO" || warn "No /etc backup was made, so there is no undo."


if [[ -t 1 ]] && { : <"$TTY"; } 2>/dev/null; then
  while true; do
    pg_reset
    read -r -p "View: [r] report  [o] everything this run printed  [l] changes log  [q] quit: " v <"$TTY" || break
    case $v in
      r) view_file "$R" ;;
      o) view_file "$SAVE/screen.txt" ;;
      l) view_file "$LOG" ;;
      *) break ;;
    esac
  done
fi
