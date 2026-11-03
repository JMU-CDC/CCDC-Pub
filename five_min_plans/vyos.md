# VyOS Opening-Minutes Lockdown (VyOS 1.4+)

Replace `eth1` with the inside interface (`show interfaces`), `LANIP` with the router's inside IP, `URL` with the script URL, and `NEWPW` with the new password. Tab-complete to confirm syntax on the competition version.

## Why firewall instead of wipe
- A wipe (`load config.boot.default`) removes WAN/LAN IPs, default route, and DNS, so curl and script hosting fail.
- A wipe resets the `vyos` password to default, and restoring the backup reverts it again.
- Config prebakes (users, SSH keys, task-scheduler, NAT port forwards) are in the backup and come back on restore. Filesystem prebakes (cron, `/config/scripts`, `authorized_keys`) survive a wipe anyway.
- Firewall-only: fewer characters, interfaces and NAT stay intact, restore = delete a few lines.

## Step 1: Backup (~2 sec)
```
conf
save /config/b
```
- `conf`: enter configuration mode.
- `save /config/b`: write the running config to `/config/b` as insurance.

## Step 2: Cut everything
```
delete firewall
set firewall ipv4 input filter default-action drop
set firewall ipv4 forward filter default-action drop
set firewall ipv4 output filter default-action drop
commit
run sudo conntrack -F
```
- `delete firewall`: remove existing rules, including planted accept rules that would match before the default drop.
- input drop: blocks all traffic addressed to the router.
- forward drop: blocks all traffic passing through the router, including NAT'd traffic.
- output drop: blocks traffic the router originates.
- `commit`: apply.
- `run sudo conntrack -F`: flush connection tracking so existing red team sessions die immediately.
- If IPv6 is in use, repeat the three drop lines with `ipv6` instead of `ipv4`.

## Step 3: Password, then open only what's needed
```
set system login user vyos authentication plaintext-password NEWPW
set firewall ipv4 output filter default-action accept
set firewall ipv4 input filter rule 1 action accept
set firewall ipv4 input filter rule 1 state established
set firewall ipv4 input filter rule 2 action accept
set firewall ipv4 input filter rule 2 inbound-interface name eth1
commit
exit
```
- Password change sticks because nothing gets wiped.
- Output accept: the router can start its own connections (curl).
- Rule 1: replies to the router's connections are allowed back in. It is on the input filter only, not global-options, so forwarded sessions stay dead.
- Rule 2: teammates can start connections to the router from the inside interface only.
- `exit`: return to op mode (normal bash shell).
- If curl fails on name resolution, use an IP in the URL.
- If local services act strangely, add `rule 3` accepting `inbound-interface name lo`.

## Steps 4 & 5: Get and host the scripts
```
mkdir s;cd s;curl -O URL
python3 -m http.server 80 -b LANIP &
```
- VyOS has Python 3 but no FTP server. This serves the current directory over HTTP, bound to the inside IP only.
- Teammates fetch with: `curl -O http://LANIP/file.sh`

## Step 6: Hunt for prebakes
```
show configuration commands | grep -e login -e task -e nat -e service
ls -la /config/scripts /etc/cron* /home/*/.ssh
ss -tlnp
```
- Config: extra users, SSH public keys, `system task-scheduler`, unexpected NAT port forwards, odd services.
- Filesystem: `/config/scripts` (especially `vyos-postconfig-bootup.script`, which runs every boot), `/etc/cron*`, `/home/*/.ssh/authorized_keys`, `/root/.ssh`.
- `ss -tlnp`: listening sockets. `ps aux`: running processes.
- Remove config items in conf mode with `delete ...`; remove planted files with `sudo rm`.
- Check whether `/config/b` had firewall rules that scoring depends on (see Step 8 alternative).

## Step 7: Close the door on the team
```
kill %1
conf
delete firewall ipv4 input filter rule 2
commit
```
- `kill %1`: stop the web server.
- Deleting rule 2 means nothing can start a new connection to the router.

## Step 8: Restore forwarding, keep router locked
```
delete firewall ipv4 forward
delete firewall ipv4 output
commit
save
```
- Removing the forward and output drops restores NAT and routing (never removed).
- Input drop + rule 1 stay: the router stays locked down.
- `save`: write to boot config so it survives a reboot.

### If the router serves DHCP/DNS to the inside network
Add before the commit:
```
set firewall ipv4 input filter rule 3 action accept
set firewall ipv4 input filter rule 3 inbound-interface name eth1
set firewall ipv4 input filter rule 3 protocol udp
set firewall ipv4 input filter rule 3 destination port 53,67
```

### Alternative: original config had firewall rules scoring needs
Run `load /config/b`, then redo before `commit`:
- password change
- `set firewall ipv4 input filter default-action drop`
- rule 1 (established)
- all prebake deletions from Step 6

(The load brings all of those back.)

## Final note
Practice the full run on a VyOS VM first. Syntax has shifted between 1.4 and 1.5 point releases.
