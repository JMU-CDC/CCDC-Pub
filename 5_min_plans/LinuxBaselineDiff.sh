#!/usr/bin/env bash
# Linux triage script: runs checks in order and writes everything to a text file.
# Usage: sudo ./triage.sh [output_file]

if [ "$EUID" -ne 0 ]; then
    echo "Warning: not running as root. Some commands (lastb, lsof, /proc, shadow, crontabs) will give partial results." >&2
fi

OUTFILE="${1:-triage_$(hostname)_$(date +%Y%m%d_%H%M%S).txt}"

THIN="--------------------------------------------------------------------------------"
THICK="================================================================================"

# Print a big separator and section title
section() {
    {
        echo
        echo "$THICK"
        echo "$THICK"
        echo "## $1"
        echo "$THICK"
        echo "$THICK"
    } >> "$OUTFILE"
}

# Read a command from stdin (heredoc), print a thin separator + the command, then its output.
run() {
    local cmd
    cmd="$(cat)"
    {
        echo
        echo "$THIN"
        echo "\$ $cmd"
        echo "$THIN"
        eval "$cmd" 2>&1
    } >> "$OUTFILE"
}

{
    echo "$THICK"
    echo "TRIAGE REPORT"
    echo "Host:  $(hostname)"
    echo "Date:  $(date)"
    echo "User:  $(whoami)"
    echo "$THICK"
} > "$OUTFILE"

# ============================================================================
section "0. Baseline & System Info"
run <<'EOF'
uname -a
EOF
run <<'EOF'
cat /etc/os-release
EOF
run <<'EOF'
uptime; date
EOF

# ============================================================================
section "1. Network & Active Connections"
run <<'EOF'
ss -tulpna
EOF
run <<'EOF'
lsof -i -P -n
EOF
run <<'EOF'
ss -tnp state established
EOF
run <<'EOF'
ip addr; ip route; ip neigh
EOF
run <<'EOF'
cat /etc/hosts /etc/resolv.conf
EOF
run <<'EOF'
if command -v iptables >/dev/null; then iptables -S; else echo "iptables not installed"; fi
EOF
run <<'EOF'
if command -v nft >/dev/null; then nft list ruleset; else echo "nft not installed"; fi
EOF

# ============================================================================
section "2. Running Processes, Hidden Binaries & Kernel Modules"
run <<'EOF'
ps auxf
EOF
run <<'EOF'
ls -la /proc/*/exe 2>/dev/null | grep -E "deleted|/tmp|/dev/shm|/var/tmp"
EOF
run <<'EOF'
lsof +L1
EOF
run <<'EOF'
for p in /proc/[0-9]*; do { tr '\0' '\n' < $p/environ; } 2>/dev/null | grep -H --label=$p LD_PRELOAD; done
EOF
run <<'EOF'
lsmod
EOF
run <<'EOF'
if command -v docker >/dev/null; then docker ps -a; else echo "docker not installed"; fi
EOF

# ============================================================================
section "3. Active Users & Login History"
run <<'EOF'
w
EOF
run <<'EOF'
last -a
EOF
run <<'EOF'
lastb -a
EOF
run <<'EOF'
for f in /var/log/auth.log /var/log/secure; do [ -f "$f" ] && { echo "=== $f (last 500 matches) ==="; grep -E "sshd|sudo|su:" "$f" | tail -500; }; done
EOF

# ============================================================================
section "4. Rogue Accounts, SSH Keys & Sudo"
run <<'EOF'
awk -F: '($3 == "0") {print}' /etc/passwd
EOF
run <<'EOF'
grep -vE "nologin|false" /etc/passwd
EOF
run <<'EOF'
awk -F: '($2 == "") {print $1}' /etc/shadow
EOF
run <<'EOF'
for h in $(cut -d: -f6 /etc/passwd | sort -u); do find "$h" -maxdepth 2 -name "authorized_keys*" -exec ls -la {} \; -exec cat {} \; 2>/dev/null; done
EOF
run <<'EOF'
cat /etc/sudoers; ls -la /etc/sudoers.d/; cat /etc/sudoers.d/*
EOF
run <<'EOF'
cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf
EOF
run <<'EOF'
ls -la /root /home/*/.bash_history
EOF
run <<'EOF'
for f in /root/.bash_history /home/*/.bash_history; do [ -f "$f" ] && { echo "=== $f ==="; cat "$f"; }; done
EOF

# ============================================================================
section "5. Persistence (Cron, Services & Startup)"
run <<'EOF'
for user in $(cut -f1 -d: /etc/passwd); do echo "=== $user ==="; crontab -u $user -l 2>/dev/null; done
EOF
run <<'EOF'
ls -la /etc/cron* /var/spool/cron/crontabs/
EOF
run <<'EOF'
cat /etc/crontab /etc/cron.d/*
EOF
run <<'EOF'
atq; ls -la /var/spool/at /var/spool/cron
EOF
run <<'EOF'
systemctl list-units --type=service --state=running
EOF
run <<'EOF'
systemctl list-unit-files --state=enabled
EOF
run <<'EOF'
systemctl list-timers --all
EOF
run <<'EOF'
find /etc/systemd /lib/systemd /usr/lib/systemd -name "*.service" -mtime -7 -ls 2>/dev/null
EOF
run <<'EOF'
cat /etc/profile /etc/bash.bashrc ~/.bashrc ~/.profile 2>/dev/null
EOF
run <<'EOF'
cat /etc/profile.d/* /etc/environment /etc/rc.local 2>/dev/null
EOF
run <<'EOF'
for h in $(cut -d: -f6 /etc/passwd | sort -u); do for f in .bashrc .profile .bash_profile; do [ -f "$h/$f" ] && { echo "=== $h/$f ==="; cat "$h/$f"; }; done; done
EOF

# ============================================================================
section "6. Privilege Escalation & Recent File Changes"
run <<'EOF'
find / -perm -4000 -type f 2>/dev/null
EOF
run <<'EOF'
find / -perm -2000 -type f 2>/dev/null
EOF
run <<'EOF'
if command -v getcap >/dev/null; then getcap -r / 2>/dev/null; else echo "getcap not installed"; fi
EOF
run <<'EOF'
find / -xdev -type f -perm -0002 2>/dev/null | head -100
EOF
run <<'EOF'
find /tmp /dev/shm /var/tmp -type f -ls
EOF
run <<'EOF'
find / -path /proc -prune -o -path /sys -prune -o -mmin -60 -type f -not -name "$(basename "$OUTFILE")" -ls 2>/dev/null
EOF
run <<'EOF'
find /tmp /dev/shm /var/tmp /etc /usr/bin /usr/sbin -mtime -7 -type f -ls 2>/dev/null
EOF
run <<'EOF'
cat /etc/ld.so.preload 2>/dev/null
EOF

# ============================================================================
section "7. Package Integrity (modified system binaries; can be slow)"
run <<'EOF'
if command -v debsums >/dev/null; then debsums -c
elif command -v dpkg >/dev/null; then dpkg -V
elif command -v rpm >/dev/null; then rpm -Va
else echo "no supported package verifier found"; fi
EOF

{
    echo
    echo "$THICK"
    echo "END OF REPORT"
    echo "$THICK"
} >> "$OUTFILE"

echo "Done. Output saved to: $OUTFILE"