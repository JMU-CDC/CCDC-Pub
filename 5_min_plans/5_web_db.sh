#!/usr/bin/env bash

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo:  sudo bash webdb.sh"; exit 1; }

ask() { read -r -p "$1 [y/N] " a; [ "$a" = y ] || [ "$a" = Y ]; }
step() { echo; echo "=== $1 ==="; }

TS=$(date +%Y%m%d-%H%M%S)
DEFAULT_BASE=/root/.cache/.$(tr -dc 'a-z0-9' </dev/urandom | head -c 6)
echo "Tip: type the same folder every time (written on paper), so everything is in one place."
read -r -p "Folder to save copies in (Enter = $DEFAULT_BASE): " BASE
case "$BASE" in
  "") BASE=$DEFAULT_BASE ;;
  /var/www*|/srv/*|/tmp*|/var/tmp*|/dev/shm*)
      echo "  Not there: the website, or a temporary folder that gets wiped. Using $DEFAULT_BASE"
      BASE=$DEFAULT_BASE ;;
  /*) ;;
  *)  echo "  Needs a full path starting with /. Using $DEFAULT_BASE"; BASE=$DEFAULT_BASE ;;
esac
SAVE="$BASE/$TS-w"
mkdir -p "$SAVE/moved" && chmod 700 "$BASE" "$SAVE"
UNDO="$SAVE/undo.txt"
echo "# Commands that undo what webdb.sh changed. Run as root (sudo -i)." > "$UNDO"
chmod 600 "$UNDO"
echo "  !! WRITE THIS DOWN: copies and undo commands are in  $SAVE"

step "0. Save copies first (your undo button)"
HAVE_TAR=no; command -v tar >/dev/null 2>&1 && HAVE_TAR=yes
TARSEL=""; [ $HAVE_TAR = yes ] && tar --help 2>/dev/null | grep -q -- '--selinux' && TARSEL="--selinux --xattrs"
[ $HAVE_TAR = no ] && echo "  (No 'tar' on this box: saving plain folder copies instead of .tgz files.)"
save_copy() {
  local name="$1"; shift
  if [ $HAVE_TAR = yes ]; then
    tar $TARSEL -czpf "$SAVE/$name.tgz" "$@" 2>/dev/null
    [ $? -le 1 ] && [ -s "$SAVE/$name.tgz" ] && echo "$SAVE/$name.tgz"
  else
    mkdir -p "$SAVE/$name" && cp -a --parents "$@" "$SAVE/$name/" 2>/dev/null && echo "$SAVE/$name"
  fi
}

WEBDIRS=""; [ -d /var/www ] && WEBDIRS="/var/www"
for d in $( { grep -rhiE '^[[:space:]]*DocumentRoot[[:space:]]' /etc/httpd /etc/apache2 2>/dev/null | awk '{print $2}'
              grep -rhE '^[[:space:]]*root[[:space:]]' /etc/nginx 2>/dev/null | awk '{print $2}'; } | tr -d '";' | sort -u ); do
  [ -d "$d" ] || continue
  case "$d" in /var/www|/var/www/*) continue;; esac
  WEBDIRS="$WEBDIRS $d"
done

P=$(save_copy etc /etc)
if [ -n "$P" ]; then echo "  Saved: $P"
else echo "  !! The /etc backup FAILED. Copy it by hand: sudo cp -a /etc $SAVE/"; fi

if [ -z "$WEBDIRS" ]; then
  echo "  No website folder found. Skipping the website copy."
else
  NEED=$(du -sk $WEBDIRS 2>/dev/null | awk '{s+=$1} END {print s+0}')
  FREE=$(df -Pk "$SAVE" | awk 'NR==2 {print $4}')
  if [ "$NEED" -gt $((FREE / 2)) ]; then
    echo "  !! Website folders are $((NEED/1024)) MB but only $((FREE/1024)) MB of disk is free."
    echo "     Skipping, so the disk doesn't fill up. Back up the important parts by hand."
  else
    P=$(save_copy www $WEBDIRS)
    if [ -n "$P" ]; then echo "  Saved: $P  ($WEBDIRS, $(du -sh "$P" | cut -f1))"
    else echo "  !! The website copy FAILED. Copy it by hand: sudo cp -a /var/www $SAVE/"; fi
  fi
fi
chmod -R go-rwx "$SAVE" 2>/dev/null
echo "  (The database is copied at the start of step 1, once we can sign in to it.)"

step "0b. How does the website answer right now?"
MYIP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
code() {
  if command -v curl >/dev/null 2>&1; then
    curl -sk -o /dev/null -w '%{http_code}' --max-time 8 "$1" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget --no-check-certificate -q -T 8 -t 1 --server-response -O /dev/null "$1" 2>&1 | awk '/HTTP\//{c=$2} END{print c+0}'
  fi
}
site() {
  local out="" u
  for u in http://127.0.0.1/ https://127.0.0.1/ ${MYIP:+http://$MYIP/ https://$MYIP/}; do
    out="$out ${u%/}=$(code "$u")"
  done
  echo "$out"
}
same() {
  local now; sleep 3; now=$(site)
  [ "$now" = "$BEFORE" ] && return 0
  echo "  !! The website's answer changed:"
  echo "       before:$BEFORE"
  echo "       now:   $now"
  return 1
}
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || \
  echo "  !! No curl or wget here, so the script can't check the site. Test it yourself after each change."
BEFORE=$(site)
echo "  Answers now:$BEFORE"
echo "  (200 = OK. Every later change must keep these exactly the same.)"

step "1. Database (MariaDB / MySQL)"
CLIENT=$(command -v mariadb || command -v mysql)
DUMPER=$(command -v mariadb-dump || command -v mysqldump)
DBARGS=()
q()   { timeout 30 "$CLIENT" "${DBARGS[@]}" -N -B -e "$1" 2>/dev/null; }
run() { timeout 30 "$CLIENT" "${DBARGS[@]}" -e "$1"; }
DB_OK=no

if [ -z "$CLIENT" ]; then
  echo "  No MariaDB or MySQL on this box. Skipping the database part."
else
  if timeout 15 "$CLIENT" -e "SELECT 1" >/dev/null 2>&1; then
    DB_OK=yes
  else
    echo "  Couldn't sign in to the database as root without a password."
    echo "  An admin account is needed for these changes. (The store's own"
    echo "  account usually isn't allowed to make them.)"
    if ask "  Sign in with a database admin account now?"; then
      read -r -p "  Database admin username: " DBU
      read -r -s -p "  Password (hidden): " MYSQL_PWD; echo
      export MYSQL_PWD
      DBARGS=(-u "$DBU")
      if q "SELECT 1" >/dev/null; then DB_OK=yes; else echo "  That didn't work. Skipping the database changes."; fi
    fi
  fi

  if [ "$DB_OK" = yes ]; then
    if [ -n "$DUMPER" ] && timeout 300 "$DUMPER" "${DBARGS[@]}" --all-databases --single-transaction > "$SAVE/db-before.dump" 2>/dev/null; then
      chmod 600 "$SAVE/db-before.dump"
      echo "  Saved a copy of every database first: $SAVE/db-before.dump"
      echo "# Put ALL databases back as they were before webdb.sh:" >> "$UNDO"
      echo "mysql < $SAVE/db-before.dump" >> "$UNDO"
    else
      rm -f "$SAVE/db-before.dump"
      echo "  !! Couldn't save a copy of the databases, so nothing will be changed."
      DB_OK=no
    fi
  fi

  if [ "$DB_OK" = yes ]; then
    echo
    echo "  Database accounts (name @ where it may log in from):"
    q "SELECT CONCAT(user,'|',host,'|',plugin,'|',IF(authentication_string='' OR authentication_string IS NULL,'none','set')) FROM mysql.user ORDER BY user, host" |
    while IFS='|' read -r u hst plug pw; do
      note=""
      case "$u" in mariadb.sys|mysql.sys|mysql.session|mysql.infoschema) note="built-in, can't log in";;
        "") note="ANONYMOUS: anyone can use it";; esac
      [ -z "$note" ] && case "$plug" in unix_socket|auth_socket) note="signs in through the local socket only";; esac
      [ -z "$note" ] && [ "$pw" = none ] && note="!! NO PASSWORD"
      [ "$hst" = "%" ] && note="${note:+$note, }!! from ANY machine"
      printf "    %-28s %s\n" "'$u'@'$hst'" "$note"
    done
    CHANGED=no

    while IFS= read -r acct <&3; do
      [ -n "$acct" ] || continue
      ask "  Remove anonymous account $acct?" && run "DROP USER $acct;" && { echo "  Removed."; CHANGED=yes; }
    done 3< <(q "SELECT CONCAT(QUOTE(user),'@',QUOTE(host)) FROM mysql.user WHERE user=''")

    if [ -n "$(q "SHOW DATABASES LIKE 'test'")" ]; then
      N=$(q "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='test'")
      echo "  Found a database named 'test' with ${N:-0} table(s)."
      [ "${N:-0}" -gt 0 ] && echo "  !! It has tables. Answer N unless you're sure the store doesn't use it."
      if ask "  Remove the 'test' database?"; then
        run "DROP DATABASE test; DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'; FLUSH PRIVILEGES;" && { echo "  Removed."; CHANGED=yes; }
      fi
    fi

    while IFS= read -r acct <&3; do
      [ -n "$acct" ] || continue
      echo "  !! $acct is root, signing in from another machine."
      ask "  Remove $acct? (root on localhost stays)" && run "DROP USER $acct;" && { echo "  Removed."; CHANGED=yes; }
    done 3< <(q "SELECT CONCAT(QUOTE(user),'@',QUOTE(host)) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')")

    ANY=$(q "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host='%' AND user NOT IN ('','root')")
    if [ -n "$ANY" ]; then
      echo "  These accounts can sign in from ANY machine (shown only, not changed):"
      echo "$ANY" | sed 's/^/    /'
      echo "  If the store's database host is localhost (see below), it doesn't need"
      echo "  that. Change the account's password, or remove it, by hand."
    fi

    if [ "$CHANGED" = yes ] && ! same; then
      if ask "  Put ALL databases back from the copy taken a minute ago?"; then
        timeout 300 "$CLIENT" "${DBARGS[@]}" < "$SAVE/db-before.dump" && echo "  Put back."
      fi
    elif [ "$CHANGED" = yes ]; then
      echo "  Website still answers the same."
    fi
  fi

  echo
  LST=$(ss -tlnH 2>/dev/null | awk '$4 ~ /:3306$/ {print $4}' | sort -u | tr '\n' ' ' | sed 's/ $//')
  if [ -z "$LST" ]; then
    echo "  Port 3306: not listening on the network at all. Good."
  elif [ -z "$(echo $LST | tr ' ' '\n' | grep -vE '^(127\.0\.0\.1|\[::1\]):3306$')" ]; then
    echo "  Port 3306: listening inside the box only ($LST). Good."
  else
    echo "  Port 3306 is listening on the network: $LST"
    if ufw status 2>/dev/null | grep -q 'Status: active'; then
      ufw status | grep -qE '(^| )3306' && echo "  !! ...and ufw ALLOWS it." || echo "  ufw is on and doesn't allow it, so the network can't reach it. OK."
    elif firewall-cmd --state >/dev/null 2>&1; then
      firewall-cmd --list-all | grep -qE '3306|mysql' && echo "  !! ...and firewalld ALLOWS it." || echo "  firewalld is on and doesn't allow it, so the network can't reach it. OK."
    else
      echo "  !! No firewall is on, so the network CAN reach it. basics.sh step 10 fixes that."
    fi
    echo "  To make the database listen inside the box only, see the Database panel on your map."
  fi

  if [ -n "$WEBDIRS" ]; then
    echo
    echo "  Store database settings (passwords hidden):"
    FOUNDCFG=no
    for f in $(grep -RlE --include='*.php' --include='*.env' --include='*.ini' "DB_HOST|DB_USER|database_host|database_user|db_hostname|db_username|'dbname'" $WEBDIRS 2>/dev/null | head -5); do
      FOUNDCFG=yes
      echo "    $f"
      grep -nE "DB_HOST|DB_USER|DB_NAME|database_host|database_user|database_name|db_hostname|db_username|db_database|'host'|'username'|'dbname'" "$f" 2>/dev/null \
        | grep -viE 'pass' | head -6 | cut -c1-120 | sed 's/^/      line /'
    done
    [ "$FOUNDCFG" = no ] && echo "    (none found)"
    echo "  If the host is localhost or 127.0.0.1, the database is on this box."
  fi
fi

step "2. Web server (Apache / nginx)"
KINDS=""
pgrep -x httpd   >/dev/null && KINDS="$KINDS apache-rh"
pgrep -x apache2 >/dev/null && KINDS="$KINDS apache-deb"
pgrep -x nginx   >/dev/null && KINDS="$KINDS nginx"

reload_web() {
  systemctl reload "$1" 2>/dev/null || service "$1" reload >/dev/null 2>&1 || {
    [ "$1" = nginx ] && nginx -s reload 2>/dev/null; } || apachectl -k graceful 2>/dev/null
  sleep 1
}

move_out() {
  local f="$1" dest; dest="$SAVE/moved/$(echo "$1" | tr / _)"
  mv "$f" "$dest" || return
  if same; then
    echo "  Moved (kept in $SAVE/moved). Website still answers the same."
    echo "mv '$dest' '$f'" >> "$UNDO"
  else
    mv "$dest" "$f"; echo "  Put back: the website needed it."
  fi
}

offer_list() { # $1 = list, one path per line
  while IFS= read -r f <&3; do
    [ -n "$f" ] && [ -e "$f" ] || continue
    echo "    $f   ($(du -sh "$f" 2>/dev/null | cut -f1), changed $(date -r "$f" '+%F %R'))"
    ask "    Move it out?" && move_out "$f"
  done 3< <(printf '%s\n' "$1")
}

if [ -z "$KINDS" ]; then
  echo "  No Apache or nginx running. Skipping the web server part."
else
  for k in $KINDS; do
    case $k in
      apache-rh)  S=httpd;   F=/etc/httpd/conf.d/zz-hide-version.conf;           TEST="apachectl -t" ;;
      apache-deb) S=apache2; F=/etc/apache2/conf-available/zz-hide-version.conf; TEST="apache2ctl -t" ;;
      nginx)      S=nginx;   F=/etc/nginx/conf.d/zz-hide-version.conf;           TEST="nginx -t" ;;
    esac
    echo; echo "  --- $S ---"

    HDR=$(curl -skI --max-time 8 http://127.0.0.1/ 2>/dev/null | grep -i '^server:' | tr -d '\r')
    [ -n "$HDR" ] || HDR="(no answer)"
    echo "  It announces itself as:  $HDR"
    if [ -f "$F" ]; then
      echo "  Version already hidden on an earlier run."
    elif [ "$k" = nginx ] && nginx -T 2>/dev/null | grep -qE '^[[:space:]]*server_tokens[[:space:]]+off'; then
      echo "  Version already hidden in its settings."
    elif ask "  Hide the $S version number?"; then
      if [ "$k" = nginx ]; then printf 'server_tokens off;\n' > "$F"
      else printf 'ServerTokens Prod\nServerSignature Off\nTraceEnable Off\n' > "$F"
           [ "$k" = apache-deb ] && a2enconf -q zz-hide-version >/dev/null 2>&1; fi
      if ! $TEST >/dev/null 2>&1; then
        [ "$k" = apache-deb ] && a2disconf -q zz-hide-version >/dev/null 2>&1
        rm -f "$F"; echo "  Settings test failed, so nothing was changed."
      else
        reload_web "$S"
        if same; then
          echo "  Done. Website still answers the same."
          echo "# Show the $S version again:" >> "$UNDO"
          if [ "$k" = apache-deb ]; then echo "a2disconf -q zz-hide-version; rm -f $F && systemctl reload $S" >> "$UNDO"
          else echo "rm -f $F && systemctl reload $S" >> "$UNDO"; fi
        else
          [ "$k" = apache-deb ] && a2disconf -q zz-hide-version >/dev/null 2>&1
          rm -f "$F"; reload_web "$S"; echo "  Undone."
        fi
      fi
    fi

    echo "  Ports it listens on (expect 80 and 443):"
    ss -tlnpH 2>/dev/null | grep -E "\"($S|apache2|httpd)\"" | awk '{print "    " $4}' | sort -u
    echo "  Sites in its settings:"
    if [ "$k" = nginx ]; then
      nginx -T 2>/dev/null | grep -E '^[[:space:]]*(listen|server_name|root)[[:space:]]' | sed -E 's/^[[:space:]]+/    /' | sort -u | head -20
    else
      ${TEST%% -t} -S 2>&1 | grep -E 'port|namevhost|Main DocumentRoot' | sed -E 's/^[[:space:]]*/    /' | head -20
    fi
  done

  if [ -z "$WEBDIRS" ]; then
    echo "  No website folder found, so no file checks."
  else
    echo
    echo "  Leftover files in the website ($WEBDIRS):"
    LEFT=$( { find $WEBDIRS -maxdepth 4 -type f \( -iname phpinfo.php -o -iname info.php -o -iname test.php -o -iname phptest.php -o -iname 'adminer*.php' \) 2>/dev/null
              find $WEBDIRS -maxdepth 3 -type d \( -iname install -o -iname installation -o -iname _install \) 2>/dev/null
              find $WEBDIRS -maxdepth 5 -type d \( -name .git -o -name .svn \) 2>/dev/null
              find $WEBDIRS -type f \( -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.zip' -o -iname '*.tar' -o -iname '*.tar.gz' \
                   -o -iname '*.tgz' -o -iname '*.bak' -o -iname '*.old' -o -iname '*.swp' -o -name '*~' \) 2>/dev/null; } | sort -u | head -40)
    if [ -z "$LEFT" ]; then echo "    None found. Good."; else offer_list "$LEFT"; fi

    PAT='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13)|(system|shell_exec|passthru|exec|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|assert[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST)|\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\('
    echo
    echo "  Likely webshells (look at each before answering):"
    SUS=$( { timeout 120 grep -rlE --include='*.php' --include='*.phtml' --include='*.php5' --include='*.phar' "$PAT" $WEBDIRS 2>/dev/null
             find $WEBDIRS -type f \( -iname '*.php*' -o -iname '*.phtml' -o -iname '*.phar' \) \
                  \( -ipath '*upload*' -o -ipath '*/images/*' -o -ipath '*/img/*' -o -ipath '*/media/*' \) ! -name index.php 2>/dev/null; } | sort -u | head -40)
    if [ -z "$SUS" ]; then
      echo "    None found."
    else
      while IFS= read -r f <&3; do
        [ -n "$f" ] && [ -f "$f" ] || continue
        echo; echo "    $f   ($(du -h "$f" | cut -f1), changed $(date -r "$f" '+%F %R'))"
        { grep -nE "$PAT" "$f" 2>/dev/null || head -3 "$f"; } | head -3 | cut -c1-150 | sed 's/^/      | /'
        ask "    Move it out (kept as evidence)?" && move_out "$f"
      done 3< <(printf '%s\n' "$SUS")
    fi

    RECENT=$(find $WEBDIRS -type f -name '*.php' -mmin -120 2>/dev/null | head -20)
    if [ -n "$RECENT" ]; then
      echo
      echo "  PHP files changed in the last 2 hours (look at these by hand):"
      echo "$RECENT" | sed 's/^/    /'
    fi
  fi
fi

step "3. Is the website allowed through the firewall?"
WEBPORTS=$(ss -tlnH 2>/dev/null | awk '{n=split($4,x,":"); p=x[n]} p==80 || p==443 {print p}' | sort -un | tr '\n' ' ')
if [ -z "$WEBPORTS" ]; then
  echo "  Nothing is listening on port 80 or 443, so there's nothing to allow."
  echo "  !! If the store should be up, check the web server: systemctl status httpd"
elif ufw status 2>/dev/null | grep -q 'Status: active'; then
  for p in $WEBPORTS; do
    if ufw status | grep -qE "^$p(/tcp)?[[:space:]].*ALLOW"; then
      echo "  Port $p: allowed. Good."
    else
      echo "  !! Port $p: the web server listens on it, but ufw doesn't allow it."
      ask "  Allow port $p from anywhere?" && ufw allow "$p/tcp" >/dev/null && {
        echo "  Allowed."; echo "ufw delete allow $p/tcp" >> "$UNDO"; }
    fi
  done
elif firewall-cmd --state >/dev/null 2>&1; then
  for p in $WEBPORTS; do
    svc=http; [ "$p" = 443 ] && svc=https
    if firewall-cmd -q --query-service=$svc 2>/dev/null || firewall-cmd -q --query-port=$p/tcp 2>/dev/null; then
      echo "  Port $p ($svc): allowed. Good."
    else
      echo "  !! Port $p ($svc): the web server listens on it, but firewalld doesn't allow it."
      ask "  Allow $svc from anywhere?" && firewall-cmd -q --add-service=$svc && firewall-cmd -q --permanent --add-service=$svc && {
        echo "  Allowed."; echo "firewall-cmd --remove-service=$svc; firewall-cmd --permanent --remove-service=$svc" >> "$UNDO"; }
    fi
  done
elif command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q 'hook input'; then
  echo "  The firewall is nftables. Check the web ports are in its allow list:"
  nft list ruleset 2>/dev/null | grep -E 'dport' | sed 's/^[[:space:]]*/    /'
else
  echo "  No firewall is on, so nothing blocks the website."
fi

U=${SUDO_USER:-YOURUSER}
if [ $HAVE_TAR = yes ]; then
  R_ALL="tar $TARSEL -xzpf $SAVE/www.tgz -C /"
  R_ONE="mkdir -p /tmp/r && tar -xzpf $SAVE/www.tgz -C /tmp/r var/www/html/index.php
  cp /tmp/r/var/www/html/index.php /var/www/html/index.php"
  R_ETC="mkdir -p /tmp/r && tar -xzpf $SAVE/etc.tgz -C /tmp/r etc/PATH/TO/FILE
  diff /tmp/r/etc/PATH/TO/FILE /etc/PATH/TO/FILE
  cp /tmp/r/etc/PATH/TO/FILE /etc/PATH/TO/FILE"
else
  R_ALL="cp -a $SAVE/www/var/www/. /var/www/"
  R_ONE="cp -a $SAVE/www/var/www/html/index.php /var/www/html/index.php"
  R_ETC="diff $SAVE/etc/etc/PATH/TO/FILE /etc/PATH/TO/FILE
  cp -a $SAVE/etc/etc/PATH/TO/FILE /etc/PATH/TO/FILE"
fi
cat > "$SAVE/notes.txt" <<EOF
HOW TO RESTORE  (become root first:  sudo -i)

WHOLE WEBSITE (puts back changed and deleted files):
  $R_ALL
  restorecon -Rv /var/www          <- Rocky/Red Hat only. Fixes SELinux labels,
                                      otherwise the site shows "403 Forbidden".

WHOLE WEBSITE, FULL RESET (also removes files the red team ADDED, e.g. webshells):
  mv /var/www /root/www-hacked-\$(date +%H%M)     <- keep it as evidence
  $R_ALL
  restorecon -Rv /var/www          <- Rocky/Red Hat only
  (The site is down for the few seconds between these commands.)

ONE WEBSITE FILE (e.g. a defaced home page):
  $R_ONE
  restorecon -v /var/www/html/index.php      <- Rocky/Red Hat only

DATABASE (as it was when webdb.sh started):
  mysql < $SAVE/db-before.dump
  NOTE: this also brings back the database's OLD account passwords.
        Change them again afterwards.

ONE FILE FROM /etc (look first, then copy):
  $R_ETC

UNDO ONLY WHAT webdb.sh CHANGED:
  cat $UNDO        (run its lines from the bottom up)

KEEP A SECOND COPY ON ANOTHER MACHINE (works with the internet closed):
  On this box:      cp -r $SAVE /home/$U/.c && chown -R $U: /home/$U/.c
  On the other box: scp -r $U@THIS_BOX_IP:.c ~/copy
  Then delete /home/$U/.c on this box.
EOF
chmod 600 "$SAVE/notes.txt"

step "Done"
NOW=$(site)
echo "  Website before:$BEFORE"
echo "  Website now:   $NOW"
if [ "$NOW" != "$BEFORE" ]; then
  echo
  echo "  !!!! THE WEBSITE IS NOT ANSWERING THE WAY IT DID AT THE START !!!!"
  echo "  Undo the most recent changes first (bottom of this file, upward):"
  echo "    sudo cat $UNDO"
fi
echo "  Moved files:   $SAVE/moved"
echo "  Restore:       sudo cat $SAVE/notes.txt"
echo "  Undo commands: sudo cat $UNDO"
echo
echo "  Next, by hand (see the Database and Web server panels on your map):"
echo "   - change the store's database password AND its config file together"
echo "   - change the store's admin passwords on its admin page"
echo "   - submit any scored passwords on Quotient's PCR tab"
echo "   - open the store in a browser and check it looks the same as before"
