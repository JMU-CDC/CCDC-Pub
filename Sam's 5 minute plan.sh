#!/usr/bin/env bash
# =============================================================================
#  basics.sh  --  the SIMPLE first-5-minutes script (any Linux distro)
# =============================================================================
#  What it does (asks y/n before EVERY change):
#    0. Backs up /etc so you can undo anything
#    1. Shows who is logged in right now, and lets you kick out strangers
#    2. Changes passwords (root + every account that can log in)
#    3. Finds extra "root" accounts (UID 0), locks them, kicks them out
#    4. Locks accounts you don't recognize, and kicks them out
#    5. Shows who has admin (sudo) rights, lets you remove strangers
#    6. Shows SSH keys and lets you remove ones you don't recognize
#    7. Removes sudo rules that skip the password (NOPASSWD)
#    8. Finds scheduled jobs no package installed (cron + systemd)
#    9. Turns off SSH login as root (checked before applying)
#   10. Turns on a basic firewall (SSH + ports you pick), with a safety timer
#   11. Saves a short "what's on this box" report for you to read
#
#  What it does NOT do on purpose: stop services, touch the database or web
#  app, or block OUTGOING traffic. Those depend on the environment, and a
#  wrong guess breaks scoring. Do them by hand once you know what the box is.
#
#  Run:  sudo bash basics.sh
# =============================================================================

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo:  sudo bash basics.sh"; exit 1; }

TS=$(date +%Y%m%d-%H%M%S)
SAVE=/root/basics-$TS          # everything this script saves goes here
mkdir -p "$SAVE" && chmod 700 "$SAVE"
# The account YOU logged in with (never locked, kicked, or removed from sudo).
# Works out the name automatically, whatever it is: first from sudo, and if
# you became root with 'sudo su -', from the account that logged in on this
# terminal.
ME="${SUDO_USER:-$(logname 2>/dev/null)}"
[ "$ME" = root ] && ME=""

ask() { read -r -p "$1 [y/N] " a; [ "$a" = y ] || [ "$a" = Y ]; }
step() { echo; echo "=== $1 ==="; }

# Change one user's password. Typed twice, hidden, never saved anywhere.
change_pw() {
  while true; do
    read -r -s -p "  New password for $1: " p1; echo
    read -r -s -p "  Type it again: " p2; echo
    [ -n "$p1" ] && [ "$p1" = "$p2" ] && break
    echo "  Didn't match (or was empty). Try again."
  done
  echo "$1:$p1" | chpasswd && echo "  Done: $1" || echo "  FAILED: $1"
  unset p1 p2
}

# End every SSH session and program of one user.
# WHY: locking an account or changing its password does NOT log out someone
# who is already logged in. This kicks them out.
# SAFETY: for a UID 0 account, "kill everything owned by this user" would mean
# "kill everything owned by root" and crash the box. So for UID 0 we only end
# that account's SSH sessions (found by name), never all root programs.
end_sessions() {
  pkill -KILL -f "^sshd(-session)?: $1([@ ]|$)" 2>/dev/null
  [ "$(id -u "$1" 2>/dev/null)" != 0 ] && pkill -KILL -u "$1" 2>/dev/null
}

# Lock an account so it can't log in by password OR by SSH key, then kick it out.
#   passwd -l   = password login stops working
#   chage -E 0  = account is "expired", which also blocks SSH key login
#                 (passwd -l alone does NOT block keys)
# Undo later with:  passwd -u USER ; chage -E -1 USER
lock_user() {
  passwd -l "$1" >/dev/null 2>&1
  chage -E 0 "$1"
  end_sessions "$1"
  echo "  Locked and logged out: $1   (undo: passwd -u $1; chage -E -1 $1)"
}

# -----------------------------------------------------------------------------
step "0. Back up /etc (your undo button)"
# WHY: if anything below goes wrong, the original files are in this tarball.
tar czf "$SAVE/etc-backup.tgz" /etc 2>/dev/null
echo "  Saved: $SAVE/etc-backup.tgz"

# -----------------------------------------------------------------------------
step "1. Who is logged in right now"
# WHY: the red team may already be logged in, often with the default password.
# Changing passwords later won't kick them out, so look first.
# The address in (brackets) is where each login came from. Compare it with
# your team's machines.
who | sed 's/^/  /'
MYTTY=$(tty 2>/dev/null) && MYTTY=${MYTTY#/dev/} || MYTTY=""
echo "  SSH sessions (yours is on ${MYTTY:-unknown}):"
while read -r pid rest <&3; do
  sess="${rest#*: }"                     # e.g. backdoor@pts/1 or backdoor@notty
  if [ "${sess#*@}" = "$MYTTY" ]; then echo "    $sess  <- you"; continue; fi
  echo "    $sess"
  ask "    End this session? (N if it's a teammate)" && kill -KILL "$pid" && echo "    Ended."
done 3< <(ps -eo pid=,args= | grep -E '^ *[0-9]+ sshd(-session)?: [^ ]+@')

# -----------------------------------------------------------------------------
step "2. Change passwords"
# WHY: the red team knows the default passwords (e.g. sysadmin:changeme) and
# tries them in the first minutes. This is the most important step.
# Accounts with a real shell are the ones that can log in.
USERS=$(awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd)
echo "  Accounts that can log in:"; for u in $USERS; do echo "    $u"; done
if [ -n "$ME" ]; then echo "  You are logged in as: $ME  (protected from locking)"
else echo "  !! Couldn't tell which account is yours. In steps 4-5, answer N for it."; fi
echo "  Only change accounts you KEEP. Strangers get locked in steps 3-4."
for u in $USERS; do
  ask "  Change password for '$u'?" && change_pw "$u"
done
echo "  NOTE: change them AGAIN in 30-45 minutes (assume they were watched)."
echo "  NOTE: root/admin changes need no ticket. If an account is used by a"
echo "        SCORED service, file a password-change ticket."

# -----------------------------------------------------------------------------
step "3. Extra root accounts (UID 0)"
# WHY: any account with UID 0 IS root, whatever its name. Only 'root' should.
EXTRA=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
if [ -z "$EXTRA" ]; then echo "  None found. Good."; else
  for u in $EXTRA; do
    echo "  !! '$u' has UID 0 (full root power)"
    ask "  Lock '$u'?" && lock_user "$u"
  done
fi

# -----------------------------------------------------------------------------
step "4. Lock accounts you don't recognize"
# WHY: leftover or planted accounts are easy ways back in. We LOCK, not
# delete, so you can undo it if a service turns out to need the account.
echo "  Do NOT lock: yourself, root, or anything a scored service might use."
for u in $USERS; do
  [ "$u" = root ] && continue
  [ "$u" = "$ME" ] && continue               # never offer to lock yourself
  echo "$EXTRA" | grep -qx "$u" && continue  # already handled in step 3
  ask "  Lock '$u'?" && lock_user "$u"
done

# -----------------------------------------------------------------------------
step "5. Who has admin (sudo) rights"
# WHY: anyone in these groups can become root with their own password.
# Remove anyone who isn't on your team. Keep yourself and your teammates.
for g in sudo wheel admin; do
  getent group "$g" >/dev/null || continue
  members=$(getent group "$g" | cut -d: -f4 | tr ',' ' ')
  echo "  Group '$g': ${members:-(nobody)}"
  for u in $members; do
    [ "$u" = "$ME" ] && { echo "    $u = you, keeping"; continue; }
    ask "  Remove '$u' from '$g'?" && gpasswd -d "$u" "$g" >/dev/null && echo "  Removed."
  done
done

# -----------------------------------------------------------------------------
step "6. SSH keys"
# WHY: an SSH key lets someone log in WITHOUT a password, so changing
# passwords doesn't stop them. Keys you don't recognize get moved (not
# deleted) into the save folder so you can show them in an incident report.
# Judge a key by WHICH ACCOUNT it's on, not by the label at the end (fakeable).
mkdir -p "$SAVE/ssh-keys"
FOUND=no
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] || continue
  FOUND=yes
  echo; echo "  File: $f"
  if [ -s "$f" ]; then sed 's/^/    /' "$f" | cut -c1-110; else echo "    (empty)"; continue; fi
  if ask "  Remove ALL keys in this file? (say N if any key is your team's)"; then
    mv "$f" "$SAVE/ssh-keys/$(echo "$f" | tr / _)" && echo "  Moved."
  fi
done
[ "$FOUND" = no ] && echo "  No authorized_keys files found."

# -----------------------------------------------------------------------------
step "7. Sudo without a password (NOPASSWD)"
# WHY: NOPASSWD lets someone become root without knowing any password.
# Files in /etc/sudoers.d with NOPASSWD can be moved to the save folder.
# After each move we check two things, and put the file BACK if either fails:
#   - 'visudo -c' : sudo's own config check (a broken config locks out sudo)
#   - you still have sudo (so you can't remove your own admin rights by mistake)
mkdir -p "$SAVE/sudoers.d"
FOUND=no
for f in /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  grep -v '^[[:space:]]*#' "$f" | grep -q NOPASSWD || continue
  FOUND=yes
  echo; echo "  File: $f"
  grep -v '^[[:space:]]*#' "$f" | grep -v '^[[:space:]]*$' | sed 's/^/    /'
  ask "  Remove this file?" || continue
  mv "$f" "$SAVE/sudoers.d/"
  if ! visudo -c >/dev/null 2>&1; then
    mv "$SAVE/sudoers.d/$(basename "$f")" "$f"; echo "  Sudo config check failed, so it was put back."
  elif [ -n "$ME" ] && sudo -l -U "$ME" 2>&1 | grep -q 'not allowed'; then
    mv "$SAVE/sudoers.d/$(basename "$f")" "$f"; echo "  Put back: without this file, YOU would lose sudo."
  else
    echo "  Moved."
  fi
done
# The main /etc/sudoers file is only shown, never edited automatically.
MAIN=$(grep -n NOPASSWD /etc/sudoers 2>/dev/null | grep -v '^[0-9]*:[[:space:]]*#')
if [ -n "$MAIN" ]; then
  FOUND=yes
  echo; echo "  In /etc/sudoers (fix by hand: 'sudo visudo', delete the line, save):"
  echo "$MAIN" | sed 's/^/    line /'
fi
[ "$FOUND" = no ] && echo "  None found. Good."

# -----------------------------------------------------------------------------
step "8. Scheduled jobs no package installed (cron + systemd)"
# WHY: attackers schedule a job that reconnects to them every few minutes,
# so even after you kick them out, they come back.
# HOW WE SPOT THEM: files that Ubuntu/Red Hat installed are recorded in the
# package database. A scheduled job that NO package installed was added by a
# person -- maybe the red team, maybe the competition's own setup. Look at
# each one and decide. Removed files are MOVED to the save folder.
# NOTE: if one looks like the web store, the database, or something your team
# made, answer N.
PKGFILES="$SAVE/package-files.txt"
{ cat /var/lib/dpkg/info/*.list 2>/dev/null; rpm -qal 2>/dev/null; } \
  | sed 's#^/usr/lib/#/lib/#' | sort -u > "$PKGFILES"
from_pkg() { grep -qxF "$(echo "$1" | sed 's#^/usr/lib/#/lib/#')" "$PKGFILES"; }
mkdir -p "$SAVE/scheduled"
stash() { mv "$1" "$SAVE/scheduled/$(echo "$1" | tr / _)" && echo "  Moved."; }
FOUND=no

# --- cron files ---
for f in /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* \
         /etc/cron.monthly/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [ -f "$f" ] || continue
  from_pkg "$f" && continue
  FOUND=yes
  echo; echo "  Cron file: $f   (last changed $(date -r "$f" '+%F %R'))"
  grep -v '^[[:space:]]*#' "$f" | grep -v '^[[:space:]]*$' | cut -c1-150 | sed 's/^/    /'
  ask "  Remove it?" && stash "$f"
done

# --- systemd services and timers ---
DIRS="/etc/systemd/system /usr/lib/systemd/system"
[ -L /lib ] || DIRS="$DIRS /lib/systemd/system"        # older systems
SNAPS=0; RELOAD=no
for d in $DIRS /root/.config/systemd/user /home/*/.config/systemd/user; do
  for f in "$d"/*.service "$d"/*.timer; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    from_pkg "$f" && continue
    name=$(basename "$f")
    case "$name" in snap[.-]*) SNAPS=$((SNAPS+1)); continue;; esac  # Ubuntu's app system
    FOUND=yes
    echo; echo "  Systemd unit: $f   (last changed $(date -r "$f" '+%F %R'))"
    grep -E '^(Description|ExecStart|OnCalendar|OnBootSec|OnUnitActiveSec)=' "$f" | cut -c1-150 | sed 's/^/    /'
    if ask "  Stop and remove it?"; then
      case "$f" in /home/*|/root/*) ;; *) systemctl disable --now "$name" >/dev/null 2>&1; RELOAD=yes;; esac
      stash "$f"
    fi
  done
done
[ "$RELOAD" = yes ] && systemctl daemon-reload 2>/dev/null
[ "$SNAPS" -gt 0 ] && echo "  (Skipped $SNAPS 'snap' units: those are Ubuntu's own app system.)"
[ "$FOUND" = no ] && echo "  None found. Good."

# -----------------------------------------------------------------------------
step "9. Turn off SSH login as root"
# WHY: makes attackers guess a username too, and forces root actions through
# sudo (which is logged). We put the setting at the TOP of sshd_config,
# because sshd uses the FIRST value it sees. That beats any other file.
# We test with 'sshd -t' and undo automatically if the test fails.
CFG=/etc/ssh/sshd_config
if [ ! -f "$CFG" ]; then
  echo "  No SSH server config found. Skipping."
elif grep -q '^# basics.sh' "$CFG"; then
  echo "  Already done on an earlier run. Skipping."
else
  [ -z "$ME" ] && echo "  !! You seem to be logged in as root directly. Make sure"\
                       "another account with sudo works BEFORE saying yes."
  if ask "  Disable root login and empty passwords over SSH?"; then
    cp -a "$CFG" "$SAVE/sshd_config.before"
    sed -i '1i # basics.sh\nPermitRootLogin no\nPermitEmptyPasswords no\n' "$CFG"
    if sshd -t 2>/dev/null || /usr/sbin/sshd -t 2>/dev/null; then
      systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || service sshd reload
      echo "  Done. Your current session stays open."
      echo "  !! TEST NOW: open a NEW ssh session before closing this one."
    else
      cp -a "$SAVE/sshd_config.before" "$CFG"
      echo "  Config test FAILED, so nothing was changed."
    fi
  fi
fi

# -----------------------------------------------------------------------------
step "10. Basic firewall"
# WHY: a firewall blocks every incoming connection except the ones you allow,
# so backdoors the red team starts on odd ports can't be reached.
# THE RULES THIS STEP FOLLOWS (they keep you from losing points):
#   - Incoming: blocked, EXCEPT SSH and the ports you list. The ports you list
#     are open to EVERYONE: the scoring engine has to reach them, and the
#     competition rules ban blocking whole networks.
#   - Outgoing: always allowed. Blocking it breaks DNS, updates and the app.
#   - SAFETY TIMER: after turning it on, you have FW_WAIT seconds to type KEEP.
#     If you don't (for example because the firewall cut you off), it turns
#     itself OFF again. That works even if your SSH session dies.
#   - If a firewall is ALREADY on, this step only shows its rules and changes
#     nothing, so it can't break a setup that already works.
FW_WAIT=${FW_WAIT:-90}
if command -v ufw >/dev/null 2>&1; then FW=ufw              # Ubuntu / Debian
elif command -v firewall-cmd >/dev/null 2>&1; then FW=firewalld  # Red Hat family
else FW=none; fi

if [ "$FW" = none ]; then
  echo "  No ufw or firewalld found. Skipping (set up the firewall by hand)."
elif { [ "$FW" = ufw ] && ufw status 2>/dev/null | grep -q 'Status: active'; } ||
     { [ "$FW" = firewalld ] && firewall-cmd --state >/dev/null 2>&1; }; then
  echo "  A firewall is already ON. Leaving it as is. Current rules:"
  if [ "$FW" = ufw ]; then ufw status numbered | sed 's/^/    /'
    echo "  To allow a port by hand:   sudo ufw allow PORT"
    echo "  To delete a rule by hand:  sudo ufw delete NUMBER"
  else firewall-cmd --list-all | sed 's/^/    /'
    echo "  To allow a port by hand:   sudo firewall-cmd --permanent --add-port=PORT/tcp && sudo firewall-cmd --reload"
  fi
else
  # What is listening for connections from the network right now?
  # (Programs listening only on 127.x / ::1 can't be reached from outside, so
  # they're left out.)
  echo "  Ports open to the network right now (port  program):"
  PORTLIST=$(ss -tlnpH 2>/dev/null | awk '{
      a=$4; if (a ~ /^(127\.|\[::1\])/) next
      n=split(a, x, ":"); port=x[n]
      prog="?"; if (match($0, /\(\("[^"]+"/)) prog=substr($0, RSTART+3, RLENGTH-4)
      print port, prog }' | sort -un)
  echo "${PORTLIST:-(none)}" | sed 's/^/    /'
  SUGGEST=$(echo "$PORTLIST" | awk '$1==80 || $1==443 {printf "%s ", $1}')
  SSHPORT=$(sshd -T 2>/dev/null | awk '$1=="port" {print $2; exit}')
  SSHPORT=${SSHPORT:-22}
  echo
  echo "  SSH (port $SSHPORT) is always allowed, so you can't lock yourself out."
  echo "  EVERY OTHER incoming port gets blocked unless you list it below."
  echo "  If a SCORED service uses a port and you leave it out, you lose points."
  echo "  (Add /udp for UDP ports, e.g. 53/udp. Type 'none' for no extra ports.)"
  read -r -p "  Ports to allow from anywhere [${SUGGEST:-none}]: " PORTS
  PORTS=${PORTS:-$SUGGEST}
  [ "$PORTS" = none ] && PORTS=""
  if ask "  Turn on the firewall allowing SSH + ${PORTS:-nothing else}?"; then
    if [ "$FW" = ufw ]; then
      REVERT="ufw disable"
      # Add the allow rules FIRST, then set "block by default", then turn it on.
      ufw allow "$SSHPORT/tcp" >/dev/null
      for p in $PORTS; do ufw allow "$p" >/dev/null && echo "  Allowed $p" || echo "  !! Couldn't add '$p'"; done
      ufw default allow outgoing >/dev/null
      ufw default deny incoming >/dev/null
    else
      REVERT="systemctl stop firewalld"
      systemctl enable --now firewalld >/dev/null 2>&1
      firewall-cmd --permanent --add-port="$SSHPORT/tcp" >/dev/null
      for p in $PORTS; do
        case "$p" in */*) ;; *) p="$p/tcp";; esac
        firewall-cmd --permanent --add-port="$p" >/dev/null && echo "  Allowed $p" || echo "  !! Couldn't add '$p'"
      done
    fi
    # Safety timer: runs on its own (setsid), so it survives your SSH session
    # dying. If the KEEP file doesn't exist when time is up, it turns the
    # firewall off.
    KEEPFILE="$SAVE/firewall-keep"
    setsid bash -c "sleep $FW_WAIT; [ -f '$KEEPFILE' ] || $REVERT" </dev/null >/dev/null 2>&1 &
    if [ "$FW" = ufw ]; then ufw --force enable >/dev/null; else firewall-cmd --reload >/dev/null; fi
    echo
    echo "  Firewall is ON. Before typing KEEP, from your laptop:"
    echo "    1. Open a NEW ssh session to this box and make sure it works."
    echo "    2. Check each scored service still works (e.g. open the website)."
    if read -r -t "$FW_WAIT" -p "  Type KEEP within $FW_WAIT seconds to keep it (anything else turns it off): " k && [ "$k" = KEEP ]; then
      touch "$KEEPFILE"
      echo "  Kept. It stays on after a reboot too."
    else
      echo
      $REVERT >/dev/null 2>&1
      echo "  Firewall turned OFF again. Nothing is being blocked."
    fi
  fi
fi

# -----------------------------------------------------------------------------
step "11. Quick report (read-only)"
# WHY: you need to know what's running so you know what's scored and what
# looks wrong. Read this after the script finishes.
R="$SAVE/report.txt"
{
  echo "## IP addresses";            ip -br addr 2>/dev/null
  echo; echo "## Listening ports (what's exposed)"; ss -tulpn 2>/dev/null
  echo; echo "## Main cron file (/etc/crontab), non-comment lines"; grep -v '^[[:space:]]*#' /etc/crontab 2>/dev/null
  echo; echo "## Systemd timers"; systemctl list-timers --all 2>/dev/null
  echo; echo "## Firewall"; ufw status verbose 2>/dev/null || firewall-cmd --list-all 2>/dev/null || echo "no ufw or firewalld"
  echo; echo "## /etc/ld.so.preload (should NOT exist)"; cat /etc/ld.so.preload 2>/dev/null || echo "not present - good"
} > "$R" 2>&1
echo "  Saved: $R   (read it with: sudo less $R)"

echo
echo "Finished. Everything saved in $SAVE"
echo "Undo a file:  tar xzf $SAVE/etc-backup.tgz -C / etc/PATH/TO/FILE"
