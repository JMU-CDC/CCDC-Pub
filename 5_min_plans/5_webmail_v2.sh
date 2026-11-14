#!/usr/bin/env bash
# mailstack-detect.sh: read-only inventory of a mail/webmail server.
#
# Finds which mail server (SMTP), IMAP/POP3 server, webmail, web server and
# database this box runs, and where logins are checked. For each program it
# reports whether it is installed, running and listening, and what it saw.
# When a tool is missing it falls back to another one:
#   services   systemctl -> upstart initctl -> /etc/init.d (scripts never run)
#   processes  ps -> /proc/*/cmdline
#   ports      ss -> netstat -> /proc/net/tcp{,6}
#   packages   dpkg-query -> /var/lib/dpkg/status -> rpm
#
# It is read-only: it starts, stops and edits nothing. The only file it
# writes is the one passed to --env (MS_*=value lines another script can
# source).
#
#   sudo ./mailstack-detect.sh
#   sudo ./mailstack-detect.sh --env /root/mailstack.env
#
# Run it as root. Without root, port owners and some configs stay hidden.

set -u
export LC_ALL=C
PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
MSD_VERSION="1.0.0"

usage() {
  cat <<'EOF'
Usage: mailstack-detect.sh [--env FILE] [--no-color] [-q] [-h]

  --env FILE   also write the results to FILE as MS_*=value lines
  --no-color   no ANSI colors
  -q           print only the one-line summary
  -h           show this help
EOF
}

ENV_FILE="" COLOR=auto QUIET=0
while [ $# -gt 0 ]; do
  case $1 in
    --env)      [ $# -ge 2 ] || { usage >&2; exit 2; }; ENV_FILE=$2; shift 2 ;;
    --env=*)    ENV_FILE=${1#--env=}; shift ;;
    --no-color) COLOR=never; shift ;;
    -q|--quiet) QUIET=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *)          echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ "$COLOR" = auto ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$'\e[1m' DIM=$'\e[2m' GRN=$'\e[32m' YEL=$'\e[33m' RED=$'\e[31m' CYN=$'\e[36m' RST=$'\e[0m'
else
  BOLD="" DIM="" GRN="" YEL="" RED="" CYN="" RST=""
fi
TAB=$'\t'

# ======================================================================
# helpers
# ======================================================================

have() { command -v "$1" >/dev/null 2>&1; }

TIMEOUT_BIN=$(command -v timeout 2>/dev/null || true)
# q CMD...: run a probe with stderr dropped, for at most 5 seconds.
q() {
  if [ -n "$TIMEOUT_BIN" ]; then "$TIMEOUT_BIN" 5 "$@" 2>/dev/null
  else "$@" 2>/dev/null; fi
}
# q2 CMD...: same, keeping stderr (some tools print their version there).
q2() {
  if [ -n "$TIMEOUT_BIN" ]; then "$TIMEOUT_BIN" 5 "$@" 2>&1
  else "$@" 2>&1; fi
}

declare -A RES=() ENVV=() PORT_OWNER=()
ENV_KEYS=() NOTES=() WM_IDX=()

setenv() {
  local k="MS_$1"
  [ -n "${ENVV[$k]+x}" ] || ENV_KEYS+=("$k")
  ENVV[$k]=$2
}
note() { NOTES+=("$*"); }

# join_words: split stdin on spaces/commas, drop duplicates, join with spaces.
join_words() { tr ', ' '\n\n' | awk 'NF && !seen[$0]++' | paste -sd' ' -; }

# first_existing PATH...: print the first path that exists.
first_existing() {
  local p
  for p in "$@"; do [ -e "$p" ] && { printf '%s' "$p"; return 0; }; done
  return 1
}

# upstream_ver "1:2.3.16+dfsg1-3ubuntu2" -> 2.3.16
upstream_ver() { local v=${1#*:}; printf '%s' "${v%%[-+~]*}"; }

# ======================================================================
# tools, packages, binaries, services
# ======================================================================

detect_tools() {
  SVC_MGR=none SVC_NOTE=""
  if have systemctl && [ -d /run/systemd/system ]; then
    SVC_MGR=systemd
  else
    if have systemctl; then
      SVC_NOTE="systemctl is installed but systemd is not running (container or chroot?), so running state comes from processes and ports"
    fi
    if have initctl && q initctl version | grep -q upstart; then SVC_MGR=upstart
    elif [ -d /etc/init.d ]; then SVC_MGR=sysv
    fi
  fi
  PROC_TOOL=proc
  have ps && PROC_TOOL="ps"
  PORT_TOOL=none           # set by snapshot_ports
  if have dpkg-query; then PKG_TOOL=dpkg-query
  elif [ -r /var/lib/dpkg/status ]; then PKG_TOOL=dpkg-status
  elif have rpm; then PKG_TOOL=rpm
  else PKG_TOOL=none; fi
  FW_TOOLS=""
  local t
  for t in ufw nft iptables firewall-cmd; do
    have "$t" && FW_TOOLS+="${FW_TOOLS:+ }$t"
  done
}

# find_bin NAME...: path of the first executable found. Bare names are looked
# up in PATH, /usr/local and /opt (source installs); absolute paths may be globs.
find_bin() {
  local n p
  for n in "$@"; do
    case $n in
      /*) for p in $n; do [ -f "$p" ] && [ -x "$p" ] && { printf '%s' "$p"; return 0; }; done ;;
      *)  p=$(command -v "$n" 2>/dev/null) && [ -n "$p" ] && { printf '%s' "$p"; return 0; }
          for p in /usr/local/sbin /usr/local/bin /opt/*/sbin /opt/*/bin; do
            [ -f "$p/$n" ] && [ -x "$p/$n" ] && { printf '%s' "$p/$n"; return 0; }
          done ;;
    esac
  done
  return 1
}

# pkg_version NAME...: "package version" of the first installed package.
# Names may be globs (mariadb-server*).
pkg_version() {
  local p out=""
  for p in "$@"; do
    case $PKG_TOOL in
      dpkg-query)
        # shellcheck disable=SC2016  # ${...} here is dpkg's format syntax
        out=$(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' "$p" 2>/dev/null |
              awk '$1 == "ii" { print $2, $3; exit }') ;;
      dpkg-status)
        out=$(awk -v pat="$p" '
          BEGIN { re = pat; gsub(/[.+]/, "[&]", re); gsub(/[*]/, ".*", re); re = "^" re "$" }
          /^Package: / { pk = $2; ok = 0; v = "" }
          /^Status: .* installed$/ { ok = 1 }
          /^Version: / { v = $2 }
          /^$/ { if (pk ~ re && ok && !done) { print pk, v; done = 1 } pk = "" }
          END { if (pk ~ re && ok && !done) print pk, v }' /var/lib/dpkg/status 2>/dev/null) ;;
      rpm)
        out=$(rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\n' "$p" 2>/dev/null | grep -v 'not installed' | head -1) ;;
      *) return 1 ;;
    esac
    [ -n "$out" ] && { printf '%s' "$out"; return 0; }
  done
  return 1
}

# svc_status NAME: prints "STATE ENABLED" and fails when there is no such
# service. STATE: active|inactive|failed|unknown, or not-queried for SysV
# init scripts. ENABLED: enabled|disabled|static|...|?
#
# SysV init scripts are never run, not even with "status": they are arbitrary
# root code that can have side effects (Cyrus's creates directories on every
# call) and an attacker may have edited them. Without systemd or upstart, a
# program counts as running from its processes and listening ports instead.
svc_status() {
  local s=$1 st="" en="?" out
  case $SVC_MGR in
    systemd)
      [ "$(q systemctl show -p LoadState "$s.service")" = "LoadState=loaded" ] || return 1
      st=$(q systemctl is-active "$s.service")
      en=$(q systemctl is-enabled "$s.service") ;;
    upstart)
      if [ -f "/etc/init/$s.conf" ]; then
        out=$(q initctl status "$s")
        case $out in *start/running*) st=active ;; *stop/waiting*) st=inactive ;; *) st=unknown ;; esac
      else
        [ -x "/etc/init.d/$s" ] || return 1
        st=not-queried
        if ls /etc/rc[2345].d/S[0-9][0-9]"$s" >/dev/null 2>&1; then en=enabled; else en=disabled; fi
      fi ;;
    sysv)
      [ -x "/etc/init.d/$s" ] || return 1
      st=not-queried
      if ls /etc/rc[2345].d/S[0-9][0-9]"$s" >/dev/null 2>&1; then en=enabled; else en=disabled; fi ;;
    *) return 1 ;;
  esac
  printf '%s %s' "${st:-unknown}" "${en:-?}"
}

# ======================================================================
# processes and listening ports (one snapshot each)
# ======================================================================

PROCS=""
snapshot_procs() {
  if [ "$PROC_TOOL" = ps ]; then
    PROCS=$(ps -eww -o pid=,args= 2>/dev/null)
  fi
  if [ -z "$PROCS" ]; then
    PROC_TOOL=proc
    local d a
    for d in /proc/[0-9]*; do
      a=$(tr '\0' ' ' 2>/dev/null <"$d/cmdline") || continue
      [ -n "$a" ] && PROCS+="${d#/proc/} $a"$'\n'
    done
  fi
}

# proc_pids REGEX: PIDs whose command line matches. The command line is
# padded with one space on each side, so "[ /]dovecot " matches the binary
# name whether or not it has a path.
proc_pids() {
  [ -n "$1" ] || return 0
  awk -v re="$1" -v self="$$" '
    { pid = $1; line = $0; sub(/^[ \t]*[0-9]+[ \t]+/, "", line)
      if (pid != self && (" " line " ") ~ re) printf "%s ", pid }' <<<"$PROCS" | sed 's/ $//'
}

parse_ss() {
  awk 'NR > 1 {
    la = ""; names = ""; pid = "?"
    for (i = 1; i <= NF; i++) {
      if (la == "" && $i ~ /:[0-9]+$/) la = $i
      if ($i ~ /^users:/) {
        u = $i
        if (match(u, /pid=[0-9]+/)) pid = substr(u, RSTART + 4, RLENGTH - 4)
        while (match(u, /"[^"]+"/)) {
          nm = substr(u, RSTART + 1, RLENGTH - 2)
          if (index("," names ",", "," nm ",") == 0) names = names (names == "" ? "" : ",") nm
          u = substr(u, RSTART + RLENGTH)
        }
      }
    }
    if (la == "") next
    n = split(la, a, ":"); port = a[n]
    print port "\t" (names == "" ? "?" : names) "\t" pid "\t" substr(la, 1, length(la) - length(port) - 1)
  }'
}

parse_netstat() {
  awk '$1 ~ /^tcp/ && $6 == "LISTEN" {
    la = $4; n = split(la, a, ":"); port = a[n]
    pid = "?"; nm = "?"
    if ($7 ~ /^[0-9]+\//) { pid = $7; sub(/\/.*/, "", pid); nm = $7; sub(/^[0-9]+\//, "", nm); sub(/:$/, "", nm) }
    print port "\t" nm "\t" pid "\t" substr(la, 1, length(la) - length(port) - 1)
  }'
}

hexaddr() {
  local h=$1
  if [ ${#h} -eq 8 ]; then
    printf '%d.%d.%d.%d' $((16#${h:6:2})) $((16#${h:4:2})) $((16#${h:2:2})) $((16#${h:0:2}))
  elif [ "$h" = 00000000000000000000000000000000 ]; then printf '[::]'
  elif [ "$h" = 00000000000000000000000001000000 ]; then printf '[::1]'
  else printf '[ipv6]'; fi
}

# Last resort: read /proc/net/tcp{,6} directly. Mapping a socket to its
# process means reading other processes' fd links, which needs root.
proc_listeners() {
  local lines p l ino hex addr port pid name
  lines=$(awk 'FNR > 1 && $4 == "0A" { split($2, a, ":"); print a[2], $10, a[1] }' \
          /proc/net/tcp /proc/net/tcp6 2>/dev/null)
  [ -n "$lines" ] || return 0
  declare -A ino_pid=()
  while read -r p l; do
    case $l in
      socket:\[*\])
        ino=${l#socket:[}; ino=${ino%]}; pid=${p#/proc/}; pid=${pid%%/*}
        [ -n "${ino_pid[$ino]+x}" ] || ino_pid[$ino]=$pid ;;
    esac
  done < <(find /proc/[0-9]*/fd -maxdepth 1 -lname 'socket:*' -printf '%p %l\n' 2>/dev/null)
  while read -r hex ino addr; do
    port=$((16#$hex)); pid=${ino_pid[$ino]:-?}; name="?"
    if [ "$pid" != "?" ]; then name=$(cat "/proc/$pid/comm" 2>/dev/null) || name="?"; fi
    printf '%s\t%s\t%s\t%s\n' "$port" "${name:-?}" "$pid" "$(hexaddr "$addr")"
  done <<<"$lines"
}

LISTEN_LINES=""   # port<TAB>owners<TAB>pid<TAB>addresses, owners comma-joined or "?"
snapshot_ports() {
  local raw="" t port owners pid addrs
  for t in ss netstat proc; do
    case $t in
      ss)      have ss || continue
               raw=$(q ss -ltnp) || continue
               raw=$(printf '%s\n' "$raw" | parse_ss) ;;
      netstat) have netstat || continue
               raw=$(q netstat -ltnp) || continue
               raw=$(printf '%s\n' "$raw" | parse_netstat) ;;
      proc)    [ -r /proc/net/tcp ] || continue
               raw=$(proc_listeners) ;;
    esac
    PORT_TOOL=$t
    break
  done
  # merge IPv4/IPv6 rows of the same port and program
  LISTEN_LINES=$(printf '%s\n' "$raw" | awk -F'\t' '
    NF >= 4 { k = $1 FS $2
      if (!(k in addr)) { ord[++n] = k; pid[k] = $3; addr[k] = $4 }
      else if (index("," addr[k] ",", "," $4 ",") == 0) addr[k] = addr[k] "," $4 }
    END { for (i = 1; i <= n; i++) print ord[i] FS pid[ord[i]] FS addr[ord[i]] }' |
    sort -t "$TAB" -k1,1n -k2,2)
  while IFS="$TAB" read -r port owners pid addrs; do
    [ -n "$port" ] || continue
    if [ -z "${PORT_OWNER[$port]:-}" ] || [ "${PORT_OWNER[$port]}" = "?" ]; then
      PORT_OWNER[$port]=$owners
    fi
  done <<<"$LISTEN_LINES"
}

# ports_owned REGEX: listening ports whose owner list matches. The list is
# padded with commas, so ",nginx," matches "nginx" and "php,nginx".
ports_owned() {
  awk -F'\t' -v re="$1" '("," $2 ",") ~ re { print $1 }' <<<"$LISTEN_LINES" | sort -un | paste -sd' ' -
}

# ======================================================================
# candidate programs
# ======================================================================
# One spec per program, fields separated by ';':
#   id;label;binaries;packages;services;process-regex;configs;port-owner-regex;usual-ports
# Order matters: it is the fallback order, and the first running program in
# a role is reported as that role's program.

MTA_SPECS=(
  "postfix;Postfix;postfix;postfix;postfix;postfix/(sbin/)?master ;/etc/postfix/main.cf;,(master|smtpd),;25 465 587"
  "exim4;Exim;exim4 exim;exim4-daemon-light exim4-daemon-heavy exim4-base exim;exim4 exim;[ /]exim4? ;/etc/exim4/update-exim4.conf.conf /etc/exim4/exim4.conf.template /etc/exim/exim.conf;,exim4?,;25 465 587"
  "sendmail;Sendmail;sendmail-mta /usr/lib/sm.bin/sendmail;sendmail-bin sendmail;sendmail;^ sendmail: |[ /]sendmail-mta |sm[.]bin/sendmail ;/etc/mail/sendmail.cf;,sendmail[^,]*,;25 465 587"
  "opensmtpd;OpenSMTPD;smtpd;opensmtpd;opensmtpd;^ smtpd: |^ /usr/s?bin/smtpd ;/etc/smtpd.conf /etc/opensmtpd/smtpd.conf /etc/smtpd/smtpd.conf;,smtpd,;25 465 587"
)
IMAP_SPECS=(
  "dovecot;Dovecot;dovecot;dovecot-core dovecot;dovecot;[ /]dovecot ;/etc/dovecot/dovecot.conf;,dovecot,;143 993 110 995 4190"
  "courier;Courier;couriertcpd;courier-imap courier-pop courier-base;courier-imap courier-pop courier-authdaemon;[ /]couriertcpd |[ /]authdaemond ;/etc/courier/imapd /etc/courier/pop3d;,couriertcpd,;143 993 110 995"
  "cyrus;Cyrus;/usr/lib/cyrus/bin/master /usr/sbin/cyrmaster;cyrus-imapd cyrus-common;cyrus-imapd;[ /]cyrmaster |cyrus/bin/master ;/etc/imapd.conf /etc/cyrus.conf;,(cyrmaster|imapd|pop3d),;143 993 110 995 4190"
)
WEB_SPECS=(
  "apache2;Apache;apache2 httpd;apache2 apache2-bin httpd;apache2 httpd;[ /](apache2|httpd) ;/etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf;,(apache2|httpd),;80 443"
  "nginx;Nginx;nginx;nginx nginx-core nginx-full nginx-light nginx-extras;nginx;^ nginx: master|[ /]nginx ;/etc/nginx/nginx.conf;,nginx,;80 443"
  "lighttpd;Lighttpd;lighttpd;lighttpd;lighttpd;[ /]lighttpd ;/etc/lighttpd/lighttpd.conf;,lighttpd,;80 443"
)
DB_SPECS=(
  "mysql;MariaDB/MySQL;mariadbd mysqld;mariadb-server* mysql-server* percona-server-server*;mariadb mysql mysqld;[ /](mariadbd|mysqld) ;/etc/mysql/mariadb.conf.d/50-server.cnf /etc/mysql/mysql.conf.d/mysqld.cnf /etc/my.cnf.d/mariadb-server.cnf;,(mariadbd|mysqld),;3306"
  "postgresql;PostgreSQL;/usr/lib/postgresql/*/bin/postgres /usr/pgsql-*/bin/postgres;postgresql-[0-9]* postgresql-server postgresql;postgresql;[ /]postgres |^ postgres: |[ /]postmaster ;/etc/postgresql /var/lib/pgsql/data/postgresql.conf;,(postgres|postmaster),;5432"
)

ver_postfix()    { local pc; pc=$(find_bin postconf) && q "$pc" -h mail_version; }
ver_exim4()      { q "$1" -bV | sed -n 's/^Exim version \([^ ]*\).*/\1/p'; }
ver_dovecot()    { q "$1" --version | awk '{ print $1; exit }'; }
ver_apache2()    { q "$1" -v | sed -n 's#.*Apache/\([^ ]*\).*#\1#p'; }
ver_nginx()      { q2 "$1" -v | sed -n 's#.*nginx/\([^ ]*\).*#\1#p'; }
ver_lighttpd()   { q "$1" -v | sed -n 's#^lighttpd/\([^ ]*\).*#\1#p'; }
ver_mysql()      { q "$1" --version | sed -n 's/.* Ver \([0-9][0-9.]*\).*/\1/p'; }
ver_postgresql() { q "$1" --version | sed -n 's/.*(PostgreSQL) \([0-9][0-9.]*\).*/\1/p'; }

probe() {
  local role=$1 spec=$2
  local id label bins pkgs svcs pre confs ore ports
  IFS=';' read -r id label bins pkgs svcs pre confs ore ports <<<"$spec"
  local k="$role:$id" a=() bin pkg conf="" svc="" st="" en="" out pids lp="" lpu="" state ver="" seen="" c p
  read -ra a <<<"$bins"; bin=$(find_bin ${a[@]+"${a[@]}"}) || bin=""
  read -ra a <<<"$pkgs"; pkg=$(pkg_version ${a[@]+"${a[@]}"}) || pkg=""
  read -ra a <<<"$confs"
  for c in ${a[@]+"${a[@]}"}; do [ -e "$c" ] && { conf=$c; break; }; done
  read -ra a <<<"$svcs"
  for c in ${a[@]+"${a[@]}"}; do
    out=$(svc_status "$c") || continue
    svc=$c st=${out%% *} en=${out#* }
    break
  done
  pids=$(proc_pids "$pre")
  [ -n "$ore" ] && lp=$(ports_owned "$ore")

  local installed="$bin$pkg$conf$svc"
  [ -n "$pids" ] && seen+=" process"
  [ "$st" = active ] && seen+=" service"
  [ -n "$installed" ] && [ -n "$lp" ] && seen+=" port-owner"
  if [ -n "$seen" ]; then state=running
  elif [ -n "$installed" ]; then state=installed
  else state=none; fi
  [ "$state" = running ] || lp=""
  # No port owners visible (not root)? Note what listens on the usual ports.
  if [ "$state" = running ] && [ -z "$lp" ]; then
    for p in $ports; do [ "${PORT_OWNER[$p]:-}" = "?" ] && lpu+="${lpu:+ }$p"; done
  fi
  if [ "$state" != none ]; then
    if [ -n "$bin" ] && declare -F "ver_$id" >/dev/null; then ver=$("ver_$id" "$bin" | head -1); fi
    [ -n "$ver" ] || ver=$(upstream_ver "${pkg#* }")
  fi
  RES[$k:label]=$label RES[$k:state]=$state RES[$k:seen]=${seen# } RES[$k:version]=$ver
  RES[$k:bin]=$bin RES[$k:pkg]=$pkg RES[$k:conf]=$conf RES[$k:svc]=$svc
  RES[$k:svcstate]="${st}${svc:+, $en}" RES[$k:pids]=$pids RES[$k:ports]=$lp
  RES[$k:ports_unconfirmed]=$lpu RES[$k:ore]=$ore RES[$k:usual]=$ports
}

# probe_role ROLE SPEC...: probe each program, pick the role's program: the
# first running one, else the first installed one.
probe_role() {
  local role=$1 spec id primary="" first_inst="" ids=""
  shift
  for spec in "$@"; do
    probe "$role" "$spec"
    id=${spec%%;*}
    ids+="$id "
    case ${RES[$role:$id:state]} in
      running)   [ -n "$primary" ] || primary=$id ;;
      installed) [ -n "$first_inst" ] || first_inst=$id ;;
    esac
  done
  RES[$role:ids]=$ids
  RES[$role:primary]=${primary:-$first_inst}
}

# ======================================================================
# webmail
# ======================================================================

WM_KINDS="roundcube squirrelmail rainloop snappymail horde"
declare -A WM_LABEL=([roundcube]=Roundcube [squirrelmail]=SquirrelMail [rainloop]=RainLoop
                     [snappymail]=SnappyMail [horde]=Horde)

# web_doc_paths: "server<TAB>config-file<TAB>directory<TAB>url" for every
# DocumentRoot/Alias/root in enabled web server configs. url is "/" for a
# document root and "?" when unknown.
web_doc_paths() {
  local f
  for f in /etc/apache2/sites-enabled/* /etc/apache2/conf-enabled/* /etc/apache2/apache2.conf \
           /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf; do
    [ -f "$f" ] || continue
    awk -v f="$f" -v OFS='\t' '
      { gsub(/"/, "") }
      tolower($1) == "documentroot" && NF >= 2 { print "apache2", f, $2, "/" }
      tolower($1) ~ /^(alias|scriptalias)$/ && NF >= 3 { print "apache2", f, $3, $2 }' "$f" 2>/dev/null
  done
  for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf /etc/nginx/nginx.conf; do
    [ -f "$f" ] || continue
    awk -v f="$f" -v OFS='\t' '
      $1 == "location" { loc = ($2 ~ /^[=~^]/ ? $3 : $2) }
      ($1 == "root" || $1 == "alias") && NF >= 2 {
        p = $2; sub(/;$/, "", p); gsub(/"/, "", p)
        print "nginx", f, p, ($1 == "root" ? "/" : (loc != "" ? loc : "?")) }' "$f" 2>/dev/null
  done
  for f in /etc/lighttpd/lighttpd.conf /etc/lighttpd/conf-enabled/*.conf; do
    [ -f "$f" ] || continue
    awk -v f="$f" -v OFS='\t' '
      /^[ \t]*server\.document-root/ && match($0, /"[^"]+"/) {
        print "lighttpd", f, substr($0, RSTART + 1, RLENGTH - 2), "/" }' "$f" 2>/dev/null
  done
}

# php_assign FILE PREFIX-REGEX: value of the last "<prefix> = value;" line.
# Quoted strings come back unquoted, numbers and booleans as they are; for
# arrays the first quoted item is returned; anything else as "(expr) ...".
php_assign() {
  awk -v pre="$2" -v sq="'" '
    $0 ~ pre {
      v = $0; sub(pre, "", v); q = substr(v, 1, 1)
      if (q == sq || q == "\"") { v = substr(v, 2); i = index(v, q); if (i) v = substr(v, 1, i - 1) }
      else if ((q == "[" || v ~ /^array[(]/) && match(v, "[" sq "\"][^" sq "\"]*[" sq "\"]")) v = substr(v, RSTART + 1, RLENGTH - 2)
      else { sub(/[ \t]*;.*$/, "", v); if (v !~ /^(-?[0-9.]+|true|false|TRUE|FALSE|null|NULL)$/) v = "(expr) " v }
      last = v
    }
    END { if (last != "") print last }' "$1" 2>/dev/null
}
# php_cfg FILE KEY: $config['KEY'] (Roundcube; $rcmail_config in old versions)
php_cfg() { php_assign "$1" "^[ \t]*[\$](config|rcmail_config)[[]['\"]$2['\"][]][ \t]*=[ \t]*"; }
# php_var FILE NAME: $NAME = ...;
php_var() { php_assign "$1" "^[ \t]*[\$]$2[ \t]*=[ \t]*"; }

# ini_get FILE SECTION KEY
ini_get() {
  awk -v s="$2" -v k="$3" '
    /^[ \t]*\[/ { sec = $0; gsub(/[][ \t]/, "", sec); next }
    sec == s && index($0, "=") {
      key = substr($0, 1, index($0, "=") - 1); gsub(/[ \t]/, "", key)
      if (key == k) { v = substr($0, index($0, "=") + 1); gsub(/^[ \t]+|[ \t]+$/, "", v); gsub(/"/, "", v); last = v } }
    END { print last }' "$1" 2>/dev/null
}

mask_dsn() { printf '%s' "$1" | sed -E 's#^([A-Za-z0-9+]+://[^:@/]*):[^@]*@#\1:****@#'; }

# db_kind DSN-or-type -> mysql|postgresql|sqlite|files|<other>
db_kind() {
  local s=${1%%:*}
  s=${s,,}
  case $s in
    "")              ;;
    mysql*|mariadb*) echo mysql ;;
    pgsql|postgres*) echo postgresql ;;
    sqlite*)         echo sqlite ;;
    *)               echo "$s" ;;
  esac
}

add_webmail() {
  local kind=$1 rp i
  rp=$(readlink -f "$2" 2>/dev/null) || rp=$2
  [ -n "$rp" ] || rp=$2
  for i in ${WM_IDX[@]+"${WM_IDX[@]}"}; do
    [ "${RES[wm:$i:path]}" = "$rp" ] && return 0
  done
  i=${#WM_IDX[@]}
  WM_IDX+=("$i")
  RES[wm:$i:kind]=$kind RES[wm:$i:path]=$rp
}

# Debian/Ubuntu's Roundcube package builds db_dsnw from $dbtype, $dbuser...
# set by dbconfig in debian-db.php (newer) or debian-db-roundcube.php (older).
rc_debian_dsn() {
  local f t=""
  for f in "$1/debian-db.php" "$1/debian-db-roundcube.php"; do
    [ -r "$f" ] || continue
    t=$(php_var "$f" dbtype)
    [ -n "$t" ] && break
  done
  case $t in
    "") ;;
    sqlite*) printf 'sqlite:///%s/%s' "$(php_var "$f" basepath)" "$(php_var "$f" dbname)" ;;
    *) printf '%s://%s:****@%s/%s' "$t" "$(php_var "$f" dbuser)" "$(php_var "$f" dbserver)" "$(php_var "$f" dbname)" ;;
  esac
}

wm_details() {
  local i=$1
  local kind=${RES[wm:$i:kind]} root=${RES[wm:$i:path]}
  local v="" cfg="" dsn="" db="" imap="" smtp="" data="" en t sp
  case $kind in
    roundcube)
      v=$(sed -n "s/.*RCMAIL_VERSION'[ ]*,[ ]*'\([^']*\)'.*/\1/p" "$root/program/include/iniset.php" 2>/dev/null | head -1)
      cfg=$(first_existing "$root/config/config.inc.php" /etc/roundcube/config.inc.php)
      if [ -n "$cfg" ] && [ -r "$cfg" ]; then
        dsn=$(php_cfg "$cfg" db_dsnw)
        case $dsn in ""|"(expr)"*) t=$(rc_debian_dsn "$(dirname "$cfg")"); [ -n "$t" ] && dsn=$t ;; esac
        if [ -z "$dsn" ]; then
          t=$(first_existing "$(dirname "$cfg")/defaults.inc.php" "$root/config/defaults.inc.php")
          [ -n "$t" ] && dsn=$(php_cfg "$t" db_dsnw)
          [ -n "$dsn" ] && dsn="$dsn (built-in default)"
        fi
        imap=$(php_cfg "$cfg" imap_host); [ -n "$imap" ] || imap=$(php_cfg "$cfg" default_host)
        smtp=$(php_cfg "$cfg" smtp_host)
        if [ -z "$smtp" ]; then
          smtp=$(php_cfg "$cfg" smtp_server); sp=$(php_cfg "$cfg" smtp_port)
          [ -n "$smtp" ] && [ -n "$sp" ] && smtp="$smtp:$sp"
        fi
        dsn=$(mask_dsn "$dsn")
        case $dsn in "(expr)"*) db=unknown ;; *) db=$(db_kind "$dsn") ;; esac
      elif [ -n "$cfg" ]; then
        db="unknown (config not readable)"
      fi ;;
    squirrelmail)
      v=$(php_var "$root/functions/strings.php" version)
      [ -n "$v" ] || v=$(sed -n "s/.*SM_VERSION'[ ]*,[ ]*'\([^']*\)'.*/\1/p" "$root/include/constants.php" 2>/dev/null | head -1)
      cfg=$(first_existing "$root/config/config.php" /etc/squirrelmail/config.php)
      if [ -n "$cfg" ] && [ -r "$cfg" ]; then
        imap="$(php_var "$cfg" imapServerAddress):$(php_var "$cfg" imapPort)"
        smtp="$(php_var "$cfg" smtpServerAddress):$(php_var "$cfg" smtpPort)"
        dsn=$(mask_dsn "$(php_var "$cfg" prefs_dsn)")
        if [ -n "$dsn" ]; then db=$(db_kind "$dsn"); else db=files; fi
      elif [ -n "$cfg" ]; then
        db="unknown (config not readable)"
      fi ;;
    rainloop|snappymail)
      v=$(find "$root/$kind/v" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -V | tail -1)
      data=$(first_existing "$root/data")
      cfg=$(first_existing "$data/_data_/_default_/configs/application.ini")
      if [ -n "$cfg" ] && [ -r "$cfg" ]; then
        en=$(ini_get "$cfg" contacts enable); t=$(ini_get "$cfg" contacts type)
        case ${en,,} in on|true|1|yes) db=$(db_kind "${t:-sqlite}") ;; *) db=files ;; esac
      fi ;;
    horde)
      v=$(sed -n "s/.*public \$version = '\([^']*\)'.*/\1/p" "$root/imp/lib/Application.php" 2>/dev/null | head -1)
      cfg=$(first_existing "$root/config/conf.php" /etc/horde/horde/conf.php)
      if [ -n "$cfg" ] && [ -r "$cfg" ]; then
        t=$(sed -n "s/.*\$conf\['sql'\]\['phptype'\] = '\([^']*\)'.*/\1/p" "$cfg" | tail -1)
        db=$(db_kind "$t")
      fi ;;
  esac
  RES[wm:$i:label]=${WM_LABEL[$kind]} RES[wm:$i:version]=$v RES[wm:$i:config]=$cfg
  RES[wm:$i:dsn]=$dsn RES[wm:$i:db]=$db RES[wm:$i:imap]=$imap RES[wm:$i:smtp]=$smtp RES[wm:$i:data]=$data
}

# wm_served_by INDEX: which enabled web server configs point at this webmail.
wm_served_by() {
  local i=$1
  local kind=${RES[wm:$i:kind]} rp=${RES[wm:$i:path]} srv f d url dr hits="" run=""
  while IFS="$TAB" read -r srv f d url; do
    [ -n "$d" ] || continue
    dr=$(readlink -f "$d" 2>/dev/null) || dr=$d
    [ -n "$dr" ] || dr=$d
    if [ "$url" = "/" ]; then
      # a document root that contains the webmail
      case "$rp/" in "$dr"/*) url=${rp#"$dr"}; url=${url:-/} ;; *) continue ;; esac
    else
      # an alias that points into the webmail, or whose target names it
      case "$dr/" in
        "$rp"/*) ;;
        *) case $dr in *"$kind"*) ;; *) continue ;; esac ;;
      esac
    fi
    # running web servers first, so the URL comes from one that is up
    if [ "${RES[web:$srv:state]:-}" = running ]; then run+="$srv$TAB$url$TAB$f"$'\n'
    else hits+="$srv$TAB$url$TAB$f"$'\n'; fi
  done <<<"$WEBDOCS"
  RES[wm:$i:served]=$(printf '%s%s' "$run" "$hits" | awk 'NF && !seen[$0]++')
  RES[wm:$i:served_running]=$(printf '%s' "$run" | cut -f1 | join_words)
  RES[wm:$i:url]=$(head -1 <<<"${RES[wm:$i:served]}" | cut -f2)
}

detect_webmail() {
  WEBDOCS=$(web_doc_paths)
  local roots=() d depth hits h i kind best=""
  for d in /var/www /srv /opt /usr/local/www /home /usr/share /var/lib /usr/local/share; do
    [ -d "$d" ] && roots+=("$d")
  done
  while IFS="$TAB" read -r _ _ d _; do
    [ -n "$d" ] && [ -d "$d" ] && roots+=("$d")
  done <<<"$WEBDOCS"
  hits=$(
    for d in ${roots[@]+"${roots[@]}"}; do
      case $d in /usr/share|/var/lib|/usr/local/share) depth=4 ;; *) depth=6 ;; esac
      find "$d" -maxdepth "$depth" \( -path '*/program/include/iniset.php' -o -path '*/functions/strings.php' \
        -o -path '*/imp/lib/Application.php' \
        -o \( -type d \( -path '*/rainloop/v' -o -path '*/snappymail/v' \) \) \) -print 2>/dev/null
    done | sort -u)
  while IFS= read -r h; do
    case $h in
      */program/include/iniset.php) add_webmail roundcube "${h%/program/include/iniset.php}" ;;
      */functions/strings.php)      grep -qi squirrelmail "$h" 2>/dev/null && add_webmail squirrelmail "${h%/functions/strings.php}" ;;
      */imp/lib/Application.php)    add_webmail horde "${h%/imp/lib/Application.php}" ;;
      */rainloop/v)                 add_webmail rainloop "${h%/rainloop/v}" ;;
      */snappymail/v)               add_webmail snappymail "${h%/snappymail/v}" ;;
    esac
  done <<<"$hits"
  for i in ${WM_IDX[@]+"${WM_IDX[@]}"}; do
    wm_details "$i"
    wm_served_by "$i"
  done
  # The webmail, in WM_KINDS order: first one a running web server points at,
  # else first one any enabled config points at, else first one found.
  local tier field
  for tier in served_running served any; do
    for kind in $WM_KINDS; do
      for i in ${WM_IDX[@]+"${WM_IDX[@]}"}; do
        [ "${RES[wm:$i:kind]}" = "$kind" ] || continue
        field=${RES[wm:$i:$tier]-x}
        [ -n "$field" ] && { best=$i; break 3; }
      done
    done
  done
  WM_PRIMARY=$best
}

# ======================================================================
# PHP
# ======================================================================

detect_php() {
  local v="" sapi="" ini="" m pv dir
  have php && v=$(upstream_ver "$(q php -r 'echo PHP_VERSION;')")   # drop "-1ubuntu2.28"
  for m in /etc/apache2/mods-enabled/php*.load; do
    [ -e "$m" ] || continue
    pv=${m##*/php}; pv=${pv%.load}
    sapi="apache2 module"
    ini=$(first_existing "/etc/php/$pv/apache2/php.ini" "/etc/php$pv/apache2/php.ini" /etc/php5/apache2/php.ini)
    break
  done
  if [ -z "$sapi" ] && [ -n "$(proc_pids 'php-fpm')" ]; then
    sapi=php-fpm
    dir=$(grep -o '/etc/php/[0-9.]*/fpm' <<<"$PROCS" | head -1)
    pv=$(sed -n 's#/etc/php/\([0-9.]*\)/fpm#\1#p' <<<"$dir")
    ini=$(first_existing "$dir/php.ini" /etc/php/*/fpm/php.ini)
  fi
  if [ -z "$sapi" ] && ls /etc/lighttpd/conf-enabled/*fastcgi-php* >/dev/null 2>&1; then
    sapi="cgi (lighttpd fastcgi)"
    ini=$(first_existing /etc/php/*/cgi/php.ini)
    pv=$(sed -n 's#/etc/php/\([0-9.]*\)/cgi/php.ini#\1#p' <<<"$ini")
  fi
  if [ -z "$v" ]; then
    v=${pv:-}
    [ -n "$v" ] || v=$(find /etc/php -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null | sort -V | tail -1)
  fi
  RES[php:version]=$v RES[php:sapi]=$sapi RES[php:ini]=$ini
}

# ======================================================================
# logins and mail layout
# ======================================================================

# dovecot_dbs passdb|userdb (config on stdin): "driver (detail), ..."
dovecot_dbs() {
  awk -v want="$1" '
    !inb && $1 == want && ($2 == "{" || $3 == "{") {
      inb = 1; depth = 1; name = ($2 == "{" ? "" : $2); drv = ""; args = ""; next }
    inb {
      if ($1 == "driver" && $2 == "=") drv = $3
      else if ($1 == "args" && $2 == "=") { a = $0; sub(/^[^=]*=[ \t]*/, "", a); args = a }
      else if (($1 == "passwd_file_path" || $1 == "sql_driver") && $2 == "=") args = $3
      if ($0 ~ /[{]/) depth++
      if ($0 ~ /[}]/ && --depth == 0) {
        d = (drv != "" ? drv : name)
        if (d !~ /^(passwd-file|sql|ldap|checkpassword|lua|dict)$/) args = ""
        gsub(/password=[^ ]*/, "password=****", args)
        out = out (out == "" ? "" : ", ") d (args != "" ? " (" args ")" : "")
        inb = 0
      }
    }
    END { print out }'
}

# Fallback when doveconf can't run: the config files themselves, plus the
# auth-*.conf.ext files that 10-auth.conf includes.
dovecot_conf_grep() {
  local f inc
  for f in /etc/dovecot/dovecot.conf /etc/dovecot/conf.d/*.conf /usr/share/dovecot/protocols.d/*.protocol; do
    [ -r "$f" ] && grep -v '^[[:space:]]*#' "$f"
  done
  while read -r _ inc; do
    [ -r "/etc/dovecot/conf.d/$inc" ] && grep -v '^[[:space:]]*#' "/etc/dovecot/conf.d/$inc"
  done < <(grep -hE '^[[:space:]]*!include(_try)?[[:space:]]+auth-[^ ]*[.]conf[.]ext' /etc/dovecot/conf.d/10-auth.conf 2>/dev/null)
}

conf_val() { awk -v k="$2" '$1 == k && $2 == "=" { v = $0; sub(/^[^=]*=[ \t]*/, "", v); last = v } END { print last }' <<<"$1"; }

dovecot_info() {
  local dc conf="" src ml pd sf drv t re='sql \(([^)]+)\)'
  dc=$(find_bin doveconf) || dc=""
  if [ -n "$dc" ] && conf=$(q "$dc" -n) && [ -n "$conf" ]; then
    src="doveconf -n"
  else
    conf=$(dovecot_conf_grep)
    src="dovecot config files (doveconf could not run; lower confidence)"
  fi
  [ -n "$conf" ] || return 0
  pd=$(dovecot_dbs passdb <<<"$conf")
  if [[ $pd =~ $re ]]; then
    sf=${BASH_REMATCH[1]}
    drv=$(awk '$1 == "driver" && $2 == "=" { print $3; exit }' "$sf" 2>/dev/null)
    [ -n "$drv" ] && pd=${pd/sql (/sql\/$drv (}
  fi
  RES[auth:passdb]=$pd
  RES[auth:userdb]=$(dovecot_dbs userdb <<<"$conf")
  RES[auth:source]=$src
  if [ "$src" = "doveconf -n" ]; then get() { q "$dc" -h "$1"; }; else get() { conf_val "$conf" "$1"; }; fi
  ml=$(get mail_location)
  [ -n "$ml" ] || { ml=$(get mail_driver); [ -n "$ml" ] && ml="$ml:$(get mail_path)"; }
  RES[imap:mail_location]=$ml
  RES[imap:protocols]=$(get protocols | join_words)
  t=$(get ssl_cert); [ -n "$t" ] || t=$(get ssl_server_cert_file)
  RES[imap:tls_cert]=${t#<}
}

courier_info() {
  local m
  m=$(sed -n 's/^authmodulelist="\(.*\)"/\1/p' /etc/courier/authdaemonrc 2>/dev/null | tail -1)
  if [ -n "$m" ]; then
    RES[auth:passdb]=$(tr ' ' '\n' <<<"$m" | sed 's/^auth//' | awk 'NF' | paste -sd' ' -)
    RES[auth:source]=/etc/courier/authdaemonrc
  fi
  m=$(sed -n 's/^MAILDIRPATH=//p' /etc/courier/imapd 2>/dev/null | tail -1)
  [ -n "$m" ] && RES[imap:mail_location]="maildir:~/$m"
  RES[imap:tls_cert]=$(sed -n 's/^TLS_CERTFILE=//p' /etc/courier/imapd-ssl 2>/dev/null | tail -1)
}

cyrus_info() {
  local m mech
  [ -r /etc/imapd.conf ] || return 0
  m=$(awk -F': *' '$1 == "sasl_pwcheck_method" { print $2 }' /etc/imapd.conf | tail -1)
  if [ "$m" = saslauthd ]; then
    mech=$(sed -n 's/^MECHANISMS="\(.*\)"/\1/p' /etc/default/saslauthd 2>/dev/null | tail -1)
    m="saslauthd${mech:+/$mech}"
  fi
  RES[auth:passdb]=${m:-auxprop (default)}
  RES[auth:source]=/etc/imapd.conf
  RES[imap:mail_location]=$(awk -F': *' '$1 == "partition-default" { print $2 }' /etc/imapd.conf | tail -1)
  RES[imap:tls_cert]=$(awk -F': *' '$1 == "tls_server_cert" { print $2 }' /etc/imapd.conf | tail -1)
}

PC=""
pcv() { awk -v k="$1" 'index($0, k " =") == 1 { v = $0; sub(/^[^=]*= ?/, "", v); print v; exit }' <<<"$PC"; }

postfix_info() {
  local pcb keys maps t sasl masters
  pcb=$(find_bin postconf) || return 0
  keys="mydestination virtual_mailbox_domains virtual_alias_domains virtual_mailbox_maps virtual_transport
        mailbox_transport mailbox_command home_mailbox smtpd_sasl_auth_enable smtpd_sasl_type smtpd_sasl_path
        smtpd_tls_cert_file"
  # shellcheck disable=SC2086  # one argument per parameter name
  PC=$(q "$pcb" -x $keys) || PC=""
  # shellcheck disable=SC2086
  [ -n "$PC" ] || PC=$(q "$pcb" $keys)
  [ -n "$PC" ] || return 0
  RES[mta:domains]=$(printf '%s %s %s' "$(pcv mydestination)" "$(pcv virtual_mailbox_domains)" "$(pcv virtual_alias_domains)" | join_words)
  maps=$(pcv virtual_mailbox_maps)
  if [ -n "$maps$(pcv virtual_mailbox_domains)" ]; then
    t=$(tr ', ' '\n\n' <<<"$maps" | awk -F: 'NF > 1 && !s[$1]++ { print $1 }' | paste -sd' ' -)
    RES[mta:users]="virtual${t:+ ($t maps)}"
    t=$(pcv virtual_transport); RES[mta:delivery]=${t:-virtual}
  else
    RES[mta:users]=system
    if   t=$(pcv mailbox_transport); [ -n "$t" ]; then RES[mta:delivery]=$t
    elif t=$(pcv mailbox_command);   [ -n "$t" ]; then RES[mta:delivery]="command: $t"
    elif t=$(pcv home_mailbox);      [ -n "$t" ]; then RES[mta:delivery]="local: ~/$t"
    else RES[mta:delivery]="local: mbox in /var/mail"; fi
  fi
  sasl="type $(pcv smtpd_sasl_type), path $(pcv smtpd_sasl_path)"
  masters=$(q "$pcb" -P | awk -F/ '/smtpd_sasl_auth_enable *= *yes/ { print $1 }' | paste -sd' ' -)
  if [ "$(pcv smtpd_sasl_auth_enable)" = yes ]; then RES[mta:sasl]="on ($sasl)"
  elif [ -n "$masters" ]; then RES[mta:sasl]="on for $masters ($sasl)"
  else RES[mta:sasl]=off; fi
  RES[mta:listeners]=$(q "$pcb" -M | awk '$2 == "inet" { print $1 }' | paste -sd' ' -)
  RES[mta:tls_cert]=$(pcv smtpd_tls_cert_file)
}

exim_info() {
  local f=/etc/exim4/update-exim4.conf.conf t
  if [ -r "$f" ]; then
    t=$(sed -n "s/^dc_eximconfig_configtype='\(.*\)'/\1/p" "$f")
    RES[mta:domains]=$(printf '%s %s' "$(cat /etc/mailname 2>/dev/null)" \
      "$(sed -n "s/^dc_other_hostnames='\(.*\)'/\1/p" "$f" | tr ':;' '  ')" | join_words)
    RES[mta:delivery]="debconf config type: ${t:-?}"
  fi
  if grep -rhsE '^[^#]*(mysql|pgsql|ldap)[a-z]*[{]' /etc/exim4 /etc/exim 2>/dev/null | grep -q .; then
    RES[mta:users]="virtual (SQL/LDAP lookups)"
  else
    RES[mta:users]=system
  fi
  if grep -rqsE '^[[:space:]]*driver[[:space:]]*=[[:space:]]*dovecot' /etc/exim4 /etc/exim 2>/dev/null; then
    RES[mta:sasl]="on (dovecot)"
  elif grep -rqsE '^[[:space:]]*server_condition.*saslauthd' /etc/exim4 /etc/exim 2>/dev/null; then
    RES[mta:sasl]="on (saslauthd)"
  else
    RES[mta:sasl]="off (no authenticator enabled)"
  fi
}

opensmtpd_info() {
  local f
  f=$(first_existing /etc/smtpd.conf /etc/opensmtpd/smtpd.conf /etc/smtpd/smtpd.conf) || return 0
  [ -r "$f" ] || return 0
  if grep -qsE '^[^#]*virtual' "$f"; then RES[mta:users]=virtual; else RES[mta:users]=system; fi
  RES[mta:delivery]=$(awk '$1 == "action" { print $3 }' "$f" | join_words)
  RES[mta:domains]=$(grep -oE 'for domain [^ ]+' "$f" | awk '{ print $3 }' | tr -d '"<>' | join_words)
  if grep -qsE '^[^#]*listen.* auth' "$f"; then RES[mta:sasl]="on (system logins)"; else RES[mta:sasl]=off; fi
}

# users_kind "drivers": system|virtual|system+virtual
users_kind() {
  local s=" ${1//,/ } " sys=0 virt=0
  local re_sys='[ /(](pam|shadow|passwd|bsdauth|pwd)[ /(]'
  local re_virt='(passwd-file|sql|ldap|dict|static|lua|userdb|mysql|pgsql|sqlite|checkpassword)'
  [[ $s =~ $re_sys ]] && sys=1
  [[ $s =~ $re_virt ]] && virt=1
  if [ $sys = 1 ] && [ $virt = 1 ]; then echo system+virtual
  elif [ $sys = 1 ]; then echo system
  elif [ $virt = 1 ]; then echo virtual
  fi
}

detect_auth() {
  case ${RES[imap:primary]:-} in
    dovecot) dovecot_info ;;
    courier) courier_info ;;
    cyrus)   cyrus_info ;;
  esac
  case ${RES[mta:primary]:-} in
    postfix)   postfix_info ;;
    exim4)     exim_info ;;
    opensmtpd) opensmtpd_info ;;
  esac
}

# ======================================================================
# notes (facts worth a second look; nothing here is a verdict)
# ======================================================================

declare -A ROLE_TITLE=([mta]="mail server" [imap]="IMAP/POP3 server" [web]="web server" [db]="database server")
declare -A ROLE_PORTS=([mta]="25 465 587" [imap]="110 143 993 995" [web]="80 443" [db]="")

collect_notes() {
  local role id running p owner ore known title ports prim
  [ "$IS_ROOT" = 1 ] || note "Not running as root: port owners, some configs and some service states may be missing. Re-run with sudo."
  [ -n "$SVC_NOTE" ] && note "$SVC_NOTE."
  [ "$PORT_TOOL" = proc ] && [ "$IS_ROOT" != 1 ] && note "Ports were read from /proc without root, so their owners are unknown."
  if [ "$IS_ROOT" = 1 ] && awk -F'\t' '$2 == "?" { f = 1 } END { exit !f }' <<<"$LISTEN_LINES"; then
    note "Some port owners are hidden even as root (no CAP_SYS_PTRACE, e.g. inside a container)."
  fi
  for role in mta imap web db; do
    title=${ROLE_TITLE[$role]}
    running=""
    for id in ${RES[$role:ids]}; do
      [ "${RES[$role:$id:state]}" = running ] && running+="${running:+, }${RES[$role:$id:label]}"
    done
    [[ $running == *,* ]] && note "More than one $title is running: $running."
    prim=${RES[$role:primary]:-}
    if [ -n "$prim" ] && [ "${RES[$role:$prim:state]}" = running ] && [ "$role" != db ] &&
       [ -z "${RES[$role:$prim:ports]}${RES[$role:$prim:ports_unconfirmed]}" ]; then
      note "${RES[$role:$prim:label]} is running but was not seen listening on any TCP port."
    fi
    ports=${ROLE_PORTS[$role]}
    for p in $ports; do
      owner=${PORT_OWNER[$p]:-}
      [ -n "$owner" ] && [ "$owner" != "?" ] || continue
      known=0
      for id in ${RES[$role:ids]}; do
        ore=${RES[$role:$id:ore]}
        [[ ",$owner," =~ $ore ]] && { known=1; break; }
      done
      [ "$role" = web ] && [[ ",$owner," =~ ,(php-fpm[^,]*|php-cgi), ]] && known=1
      [ $known = 1 ] || note "Port $p is held by '$owner', which is not one of the known ${title}s."
    done
  done
  if [ -n "$WM_PRIMARY" ] && [ -z "${RES[wm:$WM_PRIMARY:served]}" ]; then
    note "${RES[wm:$WM_PRIMARY:label]} was found at ${RES[wm:$WM_PRIMARY:path]}, but no enabled web server config points to it."
  fi
  if [ -n "$WM_PRIMARY" ]; then
    case ${RES[wm:$WM_PRIMARY:db]} in
      mysql|postgresql)
        id=${RES[wm:$WM_PRIMARY:db]}
        [ "${RES[db:$id:state]}" = running ] ||
          note "${RES[wm:$WM_PRIMARY:label]} is set to use $id, but no running $id server was found here (remote DB, or stopped)." ;;
    esac
  fi
}

# ======================================================================
# output
# ======================================================================

out()  { [ "$QUIET" = 1 ] || printf '%s\n' "$*"; }
hdr()  { out ""; out "${BOLD}${CYN}$1${RST}"; }
kv()   { [ "$QUIET" = 1 ] || [ -z "$2" ] || printf '      %-10s %s\n' "$1" "$2"; }
kv2()  { [ "$QUIET" = 1 ] || [ -z "$2" ] || printf '  %-12s %s\n' "$1" "$2"; }

port_name() {
  case $1 in
    22) echo ssh ;; 25) echo smtp ;; 53) echo dns ;; 80) echo http ;; 110) echo pop3 ;;
    143) echo imap ;; 443) echo https ;; 465) echo smtps ;; 587) echo submission ;;
    993) echo imaps ;; 995) echo pop3s ;; 3306) echo mysql ;; 4190) echo sieve ;;
    5432) echo postgres ;; 8080) echo http-alt ;; 10024|10025) echo filter ;; *) echo "" ;;
  esac
}

print_role() {
  local role=$1 title=$2 id k st found=0 nfound=0 missing="" listen n
  hdr "$title"
  for id in ${RES[$role:ids]}; do
    [ "${RES[$role:$id:state]}" = none ] || nfound=$((nfound + 1))
  done
  for id in ${RES[$role:ids]}; do
    k="$role:$id"
    st=${RES[$k:state]}
    if [ "$st" = none ]; then missing+="${missing:+, }${RES[$k:label]}"; continue; fi
    found=$((found + 1))
    if [ "$st" = running ]; then
      if [ -n "${RES[$k:ports]}" ]; then listen="listening on ${RES[$k:ports]}"
      elif [ -n "${RES[$k:ports_unconfirmed]}" ]; then listen="something listens on ${RES[$k:ports_unconfirmed]} (owner hidden)"
      else listen="${YEL}not seen listening${RST}"; fi
      out "  ${GRN}[+]${RST} ${BOLD}${RES[$k:label]} ${RES[$k:version]}${RST}  ${GRN}running${RST}, $listen"
    else
      out "  ${YEL}[.]${RST} ${BOLD}${RES[$k:label]} ${RES[$k:version]}${RST}  ${YEL}installed, not running${RST}"
    fi
    [ "${RES[$role:primary]}" = "$id" ] && [ "$nfound" -gt 1 ] && kv role "this is the one reported for this role"
    kv package "${RES[$k:pkg]}"
    if [ -n "${RES[$k:svc]}" ]; then
      case ${RES[$k:svcstate]} in
        not-queried*) kv service "${RES[$k:svc]} (init script, ${RES[$k:svcstate]#not-queried, }; not run)" ;;
        *)            kv service "${RES[$k:svc]} (${RES[$k:svcstate]})" ;;
      esac
    fi
    kv config "${RES[$k:conf]}"
    kv binary "${RES[$k:bin]}"
    if [ -n "${RES[$k:pids]}" ]; then
      n=$(wc -w <<<"${RES[$k:pids]}")
      if [ "$((n))" -gt 1 ]; then kv processes "$((n)) (first pid ${RES[$k:pids]%% *})"
      else kv processes "1 (pid ${RES[$k:pids]})"; fi
    fi
    [ "$st" = running ] && kv seen-by "${RES[$k:seen]// /, }"
    print_role_extra "$role" "$id"
  done
  if [ "$found" = 0 ]; then out "  ${RED}[-] none found${RST}"; fi
  [ -n "$missing" ] && out "  ${DIM}not found: $missing${RST}"
  return 0
}

print_role_extra() {
  local role=$1 id=$2
  [ "${RES[$role:primary]}" = "$id" ] || return 0
  case $role in
    mta)
      kv listeners "${RES[mta:listeners]:-}"
      kv domains "${RES[mta:domains]:-}"
      kv users "${RES[mta:users]:-}"
      kv delivery "${RES[mta:delivery]:-}"
      kv smtp-auth "${RES[mta:sasl]:-}"
      kv tls-cert "${RES[mta:tls_cert]:-}" ;;
    imap)
      kv protocols "${RES[imap:protocols]:-}"
      kv logins "${RES[auth:passdb]:-}"
      kv users-db "${RES[auth:userdb]:-}"
      kv mailboxes "${RES[imap:mail_location]:-}"
      kv tls-cert "${RES[imap:tls_cert]:-}"
      kv read-from "${RES[auth:source]:-}" ;;
  esac
}

print_webmail() {
  local i k served srv url f
  hdr "WEBMAIL"
  if [ ${#WM_IDX[@]} -eq 0 ]; then
    out "  ${RED}[-] none found${RST}  ${DIM}(looked for Roundcube, SquirrelMail, RainLoop, SnappyMail, Horde)${RST}"
    return 0
  fi
  local order=("$WM_PRIMARY")
  for i in "${WM_IDX[@]}"; do [ "$i" = "$WM_PRIMARY" ] || order+=("$i"); done
  for i in "${order[@]}"; do
    k="wm:$i"
    served=${RES[$k:served]}
    if [ -n "$served" ]; then out "  ${GRN}[+]${RST} ${BOLD}${RES[$k:label]} ${RES[$k:version]}${RST}  ${RES[$k:path]}"
    else out "  ${YEL}[.]${RST} ${BOLD}${RES[$k:label]} ${RES[$k:version]}${RST}  ${RES[$k:path]}  ${YEL}(no web server points here)${RST}"; fi
    [ "$i" = "$WM_PRIMARY" ] && [ ${#WM_IDX[@]} -gt 1 ] && kv role "this is the one reported as the webmail"
    kv config "${RES[$k:config]}"
    if [ -n "${RES[$k:dsn]}" ]; then kv database "${RES[$k:dsn]}"; else kv database "${RES[$k:db]}"; fi
    kv imap "${RES[$k:imap]}"
    kv smtp "${RES[$k:smtp]}"
    kv data-dir "${RES[$k:data]}"
    while IFS="$TAB" read -r srv url f; do
      [ -n "$srv" ] || continue
      if [ "${RES[web:$srv:state]:-}" = running ]; then kv served-by "$srv at URL $url ($f)"
      else kv served-by "$srv at URL $url ($f) ${YEL}[$srv not running]${RST}"; fi
    done <<<"$served"
  done
}

print_listen() {
  local port owners pid addrs
  hdr "LISTENING TCP PORTS  ${DIM}(via $PORT_TOOL)${RST}"
  if [ -z "$LISTEN_LINES" ]; then out "  none found"; return 0; fi
  [ "$QUIET" = 1 ] && return 0
  while IFS="$TAB" read -r port owners pid addrs; do
    [ "$pid" = "?" ] && pid="" || pid=" ($pid)"
    printf '  %-6s %-11s %-26s %s\n' "$port" "$(port_name "$port")" "$owners$pid" "$addrs"
  done <<<"$LISTEN_LINES"
}

summary_line() {
  local s="" role p st
  for role in mta imap; do
    p=${RES[$role:primary]:-}; st=${p:+${RES[$role:$p:state]}}
    s+="${role^^}=${p:-none}${st:+($st)} "
  done
  s+="WEBMAIL=${ENVV[MS_WEBMAIL]}${ENVV[MS_WEBMAIL_URL]:+@${ENVV[MS_WEBMAIL_URL]}} "
  p=${RES[web:primary]:-}; st=${p:+${RES[web:$p:state]}}
  s+="WEB=${p:-none}${st:+($st)} DB=${ENVV[MS_DB]} AUTH=${ENVV[MS_AUTH]:-unknown}"
  printf '%s' "$s"
}

# ======================================================================
# --env values
# ======================================================================

fill_env() {
  local role R p k o id other
  setenv DETECT_VERSION "$MSD_VERSION"; setenv DETECT_TIME "$NOW"
  setenv HOST "$HOST"; setenv OS "$OS_NAME"; setenv IS_ROOT "$IS_ROOT"
  setenv SVC_MGR "$SVC_MGR"; setenv PROC_TOOL "$PROC_TOOL"; setenv PORT_TOOL "$PORT_TOOL"
  setenv PKG_TOOL "$PKG_TOOL"; setenv FW_TOOLS "$FW_TOOLS"
  for role in mta imap web db; do
    case $role in db) R=DB_SERVER ;; *) R=${role^^} ;; esac
    p=${RES[$role:primary]:-}
    k="$role:$p"
    setenv "$R" "${p:-none}"
    setenv "${R}_STATE" "${p:+${RES[$k:state]}}"
    setenv "${R}_VERSION" "${p:+${RES[$k:version]}}"
    setenv "${R}_CONFIG" "${p:+${RES[$k:conf]}}"
    setenv "${R}_BIN" "${p:+${RES[$k:bin]}}"
    setenv "${R}_PACKAGE" "${p:+${RES[$k:pkg]% *}}"
    setenv "${R}_SERVICE" "${p:+${RES[$k:svc]}}"
    setenv "${R}_SERVICE_STATE" "${p:+${RES[$k:svcstate]}}"
    setenv "${R}_SEEN_BY" "${p:+${RES[$k:seen]}}"
    setenv "${R}_PORTS" "${p:+${RES[$k:ports]}}"
    setenv "${R}_PORTS_UNCONFIRMED" "${p:+${RES[$k:ports_unconfirmed]}}"
    o=""
    if [ "${p:+${RES[$k:state]}}" = running ]; then
      if [ -n "${RES[$k:ports]}" ]; then o=yes
      elif [ -n "${RES[$k:ports_unconfirmed]}" ]; then o=unconfirmed
      else o=no; fi
    fi
    setenv "${R}_LISTENING" "$o"
    other=""
    for id in ${RES[$role:ids]}; do
      [ "$id" = "$p" ] && continue
      [ "${RES[$role:$id:state]}" = none ] || other+="${other:+ }$id:${RES[$role:$id:state]}"
    done
    setenv "${R}_OTHERS" "$other"
  done
  if [ "${RES[db:primary]:-}" = mysql ]; then
    if [[ ${RES[db:mysql:bin]} == *mariadbd || ${RES[db:mysql:pkg]} == mariadb* ]] ||
       q "${RES[db:mysql:bin]:-false}" --version | grep -qi mariadb; then
      setenv DB_FLAVOR mariadb
    else
      setenv DB_FLAVOR mysql
    fi
  else
    setenv DB_FLAVOR ""
  fi

  # webmail
  local w=$WM_PRIMARY
  setenv WEBMAIL "${w:+${RES[wm:$w:kind]}}"
  [ -n "$w" ] || ENVV[MS_WEBMAIL]=none
  setenv WEBMAIL_VERSION "${w:+${RES[wm:$w:version]}}"
  setenv WEBMAIL_PATH "${w:+${RES[wm:$w:path]}}"
  setenv WEBMAIL_CONFIG "${w:+${RES[wm:$w:config]}}"
  setenv WEBMAIL_DB "${w:+${RES[wm:$w:db]}}"
  setenv WEBMAIL_DSN "${w:+${RES[wm:$w:dsn]}}"
  setenv WEBMAIL_IMAP "${w:+${RES[wm:$w:imap]}}"
  setenv WEBMAIL_SMTP "${w:+${RES[wm:$w:smtp]}}"
  setenv WEBMAIL_DATA_DIR "${w:+${RES[wm:$w:data]}}"
  setenv WEBMAIL_URL "${w:+${RES[wm:$w:url]}}"
  # running web servers whose config points here; if none runs, the configured ones
  local sb=""
  if [ -n "$w" ]; then
    sb=${RES[wm:$w:served_running]}
    [ -n "$sb" ] || sb=$(cut -f1 <<<"${RES[wm:$w:served]}" | join_words)
  fi
  setenv WEBMAIL_SERVED_BY "$sb"
  other=""
  for id in ${WM_IDX[@]+"${WM_IDX[@]}"}; do
    [ "$id" = "$w" ] || other+="${other:+ }${RES[wm:$id:kind]}:${RES[wm:$id:path]}"
  done
  setenv WEBMAIL_OTHERS "$other"

  # the database the webmail uses, else the database server found
  local db="" src=""
  case ${w:+${RES[wm:$w:db]}} in
    mysql|postgresql|sqlite) db=${RES[wm:$w:db]} src=webmail-config ;;
  esac
  if [ -z "$db" ] && [ -n "${RES[db:primary]:-}" ]; then db=${RES[db:primary]} src=server; fi
  setenv DB "${db:-none}"; setenv DB_SOURCE "$src"

  setenv PHP_VERSION "${RES[php:version]:-}"; setenv PHP_SAPI "${RES[php:sapi]:-}"; setenv PHP_INI "${RES[php:ini]:-}"

  local drivers=${RES[auth:passdb]:-}
  setenv AUTH "$(sed 's/ ([^)]*)//g; s/,//g' <<<"$drivers" | join_words)"
  setenv AUTH_PASSDB "$drivers"
  setenv AUTH_USERDB "${RES[auth:userdb]:-}"
  setenv AUTH_SOURCE "${RES[auth:source]:-}"
  local uk; uk=$(users_kind "$drivers")
  [ -n "$uk" ] || { uk=${RES[mta:users]:-}; uk=${uk%% *}; }
  setenv MAIL_USERS "${uk:-}"
  setenv MAIL_DOMAINS "${RES[mta:domains]:-}"
  setenv MAIL_DELIVERY "${RES[mta:delivery]:-}"
  setenv MAIL_LOCATION "${RES[imap:mail_location]:-}"
  setenv IMAP_PROTOCOLS "${RES[imap:protocols]:-}"
  setenv IMAP_TLS_CERT "${RES[imap:tls_cert]:-}"
  setenv MTA_LISTENERS "${RES[mta:listeners]:-}"
  setenv MTA_TLS_CERT "${RES[mta:tls_cert]:-}"
  setenv SMTP_AUTH "${RES[mta:sasl]:-}"

  local port owners pid addrs l=""
  while IFS="$TAB" read -r port owners pid addrs; do
    [ -n "$port" ] && l+="${l:+ }$port:$owners"
  done <<<"$LISTEN_LINES"
  setenv LISTEN "$l"
  setenv NOTES "$(printf '%s\n' ${NOTES[@]+"${NOTES[@]}"} | awk 'NF' | paste -sd'|' -)"
}

write_env() {
  local k
  (
    umask 077
    {
      printf '# mailstack-detect %s | %s | %s\n' "$MSD_VERSION" "$HOST" "$NOW"
      for k in "${ENV_KEYS[@]}"; do printf '%s=%q\n' "$k" "${ENVV[$k]}"; done
    } >"$ENV_FILE"
  ) 2>/dev/null || { printf 'mailstack-detect: could not write %s\n' "$ENV_FILE" >&2; return 1; }
}

# ======================================================================
# main
# ======================================================================

NOW=$(date '+%Y-%m-%d %H:%M:%S %Z')
HOST=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown)
OS_NAME=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | tr -d '"')
OS_NAME=${OS_NAME:-unknown}
IS_ROOT=0
[ "$(id -u)" = 0 ] && IS_ROOT=1
WM_PRIMARY=""

detect_tools
snapshot_procs
snapshot_ports
probe_role mta  "${MTA_SPECS[@]}"
probe_role imap "${IMAP_SPECS[@]}"
probe_role web  "${WEB_SPECS[@]}"
probe_role db   "${DB_SPECS[@]}"
if [ "${RES[db:primary]:-}" = mysql ]; then
  case ${RES[db:mysql:pkg]} in mariadb*) RES[db:mysql:label]=MariaDB ;; mysql*|percona*) RES[db:mysql:label]=MySQL ;; esac
  case ${RES[db:mysql:bin]} in *mariadbd) RES[db:mysql:label]=MariaDB ;; esac
fi
detect_webmail
detect_php
detect_auth
collect_notes
fill_env

if [ "$QUIET" = 0 ]; then
  out "${BOLD}mailstack-detect $MSD_VERSION${RST}  $HOST | $OS_NAME | $NOW"
  if [ "$IS_ROOT" = 1 ]; then out "${DIM}running as root, read-only${RST}"
  else out "${YEL}not root: some details will be missing (re-run with sudo)${RST}"; fi

  hdr "TOOLS USED"
  kv2 services "$SVC_MGR"
  kv2 processes "$PROC_TOOL"
  kv2 ports "$PORT_TOOL"
  kv2 packages "$PKG_TOOL"
  kv2 firewall "${FW_TOOLS:-none found}"

  print_role mta "MAIL SERVER (SMTP)"
  print_role imap "IMAP / POP3"
  print_webmail
  print_role web "WEB SERVER"
  if [ -n "${RES[php:version]}${RES[php:sapi]}" ]; then
    kv2 PHP "${RES[php:version]:-?}${RES[php:sapi]:+ via ${RES[php:sapi]}}${RES[php:ini]:+ | ${RES[php:ini]}}"
  fi
  print_role db "DATABASE SERVER"
  if [ "${ENVV[MS_DB_SOURCE]}" = webmail-config ]; then
    kv2 "webmail DB" "${ENVV[MS_DB]}"
  fi
  print_listen

  if [ ${#NOTES[@]} -gt 0 ]; then
    hdr "NOTES"
    for n in "${NOTES[@]}"; do out "  ${YEL}!${RST} $n"; done
  fi
  hdr "SUMMARY"
fi
printf '%s\n' "$(summary_line)"

if [ -n "$ENV_FILE" ]; then
  write_env && [ "$QUIET" = 0 ] && out "${DIM}wrote $ENV_FILE${RST}"
fi
exit 0
