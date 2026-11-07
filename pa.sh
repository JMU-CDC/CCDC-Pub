#!/usr/bin/env bash

PA_IP="172.20.240.200"
PA_USER="admin"

echo "========================================================"
echo "   MWCCDC: LIVE HUNT & MONITOR TERMINAL                 "
echo "========================================================"

# Prompt for the new password you set in the hardening script
read -r -s -p "[?] Enter your updated Palo Alto Admin Password: " PA_PASS
echo ""

# Helper function to execute a single command cleanly
run_cmd() {
  echo -e "\n[*] Executing: $1"
  if command -v sshpass >/dev/null 2>&1; then
    sshpass -p "${PA_PASS}" ssh -t -q -o StrictHostKeyChecking=no "${PA_USER}@${PA_IP}" "$1"
  else
    ssh -t -q -o StrictHostKeyChecking=no "${PA_USER}@${PA_IP}" "$1"
  fi
  echo -e "\n--------------------------------------------------------"
}

PS3="Select an action (1-7): "
options=(
  "View Active Sessions (Filter by Source IP)"
  "View Active Sessions (Filter by Dest IP)"
  "Check Global Drop Counters"
  "Tail Live Traffic Logs"
  "Tail Live Threat Logs"
  "Kill Active Red Team Session (By Source IP)"
  "Exit"
)

select opt in "${options[@]}"; do
  case $REPLY in
    1)
      read -r -p "Enter Source IP to track: " SRC_IP
      run_cmd "show session all filter source ${SRC_IP}"
      ;;
    2)
      read -r -p "Enter Destination IP (e.g. Scored Server): " DST_IP
      run_cmd "show session all filter destination ${DST_IP}"
      ;;
    3)
      run_cmd "show counter global | match drop"
      ;;
    4)
      echo "[!] Press Ctrl+C to stop tailing logs."
      run_cmd "tail follow yes mp-log traffic.log"
      ;;
    5)
      echo "[!] Press Ctrl+C to stop tailing logs."
      run_cmd "tail follow yes mp-log threat.log"
      ;;
    6)
      read -r -p "Enter Malicious Source IP to Sever: " KILL_IP
      run_cmd "clear session all filter source ${KILL_IP}"
      echo "[+] All stateful sessions for ${KILL_IP} flushed."
      ;;
    7)
      echo "Exiting."
      break
      ;;
    *) echo "Invalid option $REPLY";;
  esac
done
