#!/bin/bash
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
# SOC - Linux Remediation & Containment
# Targeted actions to contain and remediate a compromise.
# *** ALWAYS document what you do and get change approval first. ***
# *** These actions modify the system - run only when authorized. ***
# Required: Run as root or with sudo.
#
# USAGE:
#   Kill process:          sudo ./08_Remediation.sh kill_pid 1234
#   Kill by name:          sudo ./08_Remediation.sh kill_name malware
#   Block IP:              sudo ./08_Remediation.sh block_ip 1.2.3.4
#   Disable service:       sudo ./08_Remediation.sh disable_service evil_svc
#   Remove cron entry:     sudo ./08_Remediation.sh remove_cron root "/tmp/evil.sh"
#   Lock user:             sudo ./08_Remediation.sh lock_user baduser
#   Delete user:           sudo ./08_Remediation.sh delete_user baduser
#   Remove SSH key:        sudo ./08_Remediation.sh remove_ssh_key username "key_comment"
#   Quarantine file:       sudo ./08_Remediation.sh quarantine /tmp/evil.elf
#   Isolate machine:       sudo ./08_Remediation.sh isolate

ACTION="$1"
ARG1="$2"
ARG2="$3"
LOGFILE="/var/log/soc_remediation_$(date +%Y%m%d).log"
QUARANTINE_DIR="/var/soc_quarantine"

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC LINUX REMEDIATION  |  $TS UTC"
echo "====================================================="
echo ""

log_action() {
    local entry="[$(date -u '+%H:%M:%S UTC')] $1 | $2"
    echo "$entry"
    echo "$entry" >> "$LOGFILE"
}

if [ "$(id -u)" -ne 0 ]; then
    echo "  ERROR: Must run as root."
    exit 1
fi

case "$ACTION" in

  # ------------------------------------------------------------
  kill_pid)
    # Kill a specific process by PID
    if [ -z "$ARG1" ]; then echo "Usage: $0 kill_pid <PID>"; exit 1; fi
    COMM=$(cat /proc/$ARG1/comm 2>/dev/null)
    EXE=$(readlink /proc/$ARG1/exe 2>/dev/null)
    echo "  Process: PID=$ARG1 Name=$COMM EXE=$EXE"
    read -rp "  Confirm kill? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        kill -9 "$ARG1"
        log_action "KILL_PROCESS" "PID=$ARG1 Name=$COMM EXE=$EXE"
    fi
    ;;

  # ------------------------------------------------------------
  kill_name)
    # Kill all processes matching a name
    if [ -z "$ARG1" ]; then echo "Usage: $0 kill_name <process_name>"; exit 1; fi
    PIDS=$(pgrep -x "$ARG1" 2>/dev/null)
    if [ -z "$PIDS" ]; then
        echo "  No process named '$ARG1' found."
    else
        echo "  Matching PIDs: $PIDS"
        ps -p $PIDS -o pid,ppid,user,cmd
        read -rp "  Kill all above? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            pkill -9 -x "$ARG1"
            log_action "KILL_PROCESS" "Name=$ARG1 PIDs=$PIDS"
        fi
    fi
    ;;

  # ------------------------------------------------------------
  block_ip)
    # Block an IP address inbound and outbound using iptables
    if [ -z "$ARG1" ]; then echo "Usage: $0 block_ip <IP>"; exit 1; fi
    echo "  Blocking IP: $ARG1"
    read -rp "  Confirm block (inbound+outbound)? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        iptables -I INPUT  -s "$ARG1" -j DROP
        iptables -I OUTPUT -d "$ARG1" -j DROP
        log_action "BLOCK_IP" "IP=$ARG1 Direction=inbound+outbound"
        echo "  To make persistent: iptables-save > /etc/iptables/rules.v4"
        echo "  To remove: iptables -D INPUT -s $ARG1 -j DROP && iptables -D OUTPUT -d $ARG1 -j DROP"
    fi
    ;;

  # ------------------------------------------------------------
  disable_service)
    # Stop and disable a systemd service
    if [ -z "$ARG1" ]; then echo "Usage: $0 disable_service <service_name>"; exit 1; fi
    echo "  Service: $ARG1 (Status: $(systemctl is-active "$ARG1" 2>/dev/null))"
    read -rp "  Stop and disable? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        systemctl stop "$ARG1" 2>/dev/null
        systemctl disable "$ARG1" 2>/dev/null
        systemctl mask "$ARG1" 2>/dev/null
        log_action "DISABLE_SERVICE" "Name=$ARG1"
    fi
    ;;

  # ------------------------------------------------------------
  remove_cron)
    # Remove a specific cron entry for a user
    # ARG1=username, ARG2=string to match in crontab
    if [ -z "$ARG1" ] || [ -z "$ARG2" ]; then
        echo "Usage: $0 remove_cron <username> <cron_string_to_remove>"
        exit 1
    fi
    echo "  Current crontab for $ARG1:"
    crontab -l -u "$ARG1" 2>/dev/null
    echo ""
    echo "  Will remove line matching: $ARG2"
    read -rp "  Confirm? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        crontab -l -u "$ARG1" 2>/dev/null | grep -v "$ARG2" | crontab -u "$ARG1" -
        log_action "REMOVE_CRON" "User=$ARG1 Removed=$ARG2"
    fi
    ;;

  # ------------------------------------------------------------
  lock_user)
    # Lock a user account (prevents login)
    if [ -z "$ARG1" ]; then echo "Usage: $0 lock_user <username>"; exit 1; fi
    echo "  Locking user: $ARG1"
    read -rp "  Confirm lock? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        usermod -L "$ARG1"
        # Also expire all current sessions
        pkill -KILL -u "$ARG1" 2>/dev/null
        log_action "LOCK_USER" "User=$ARG1"
        echo "  To unlock: usermod -U $ARG1"
    fi
    ;;

  # ------------------------------------------------------------
  delete_user)
    # Delete a user account and optionally their home directory
    if [ -z "$ARG1" ]; then echo "Usage: $0 delete_user <username>"; exit 1; fi
    echo "  About to delete user: $ARG1"
    id "$ARG1" 2>/dev/null
    read -rp "  Delete user AND home directory? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        pkill -KILL -u "$ARG1" 2>/dev/null
        userdel -r "$ARG1" 2>/dev/null
        log_action "DELETE_USER" "User=$ARG1"
    fi
    ;;

  # ------------------------------------------------------------
  remove_ssh_key)
    # Remove an authorized SSH key by comment from a user's authorized_keys
    if [ -z "$ARG1" ] || [ -z "$ARG2" ]; then
        echo "Usage: $0 remove_ssh_key <username> <key_comment>"
        exit 1
    fi
    KEYFILE="/home/$ARG1/.ssh/authorized_keys"
    [ "$ARG1" = "root" ] && KEYFILE="/root/.ssh/authorized_keys"
    if [ -f "$KEYFILE" ]; then
        echo "  Current keys in $KEYFILE:"
        cat "$KEYFILE"
        echo ""
        echo "  Will remove key with comment: $ARG2"
        read -rp "  Confirm? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            # Backup first
            cp "$KEYFILE" "${KEYFILE}.bak.$(date +%Y%m%d%H%M%S)"
            grep -v "$ARG2" "$KEYFILE" > "${KEYFILE}.tmp" && mv "${KEYFILE}.tmp" "$KEYFILE"
            log_action "REMOVE_SSH_KEY" "User=$ARG1 KeyComment=$ARG2"
        fi
    else
        echo "  No authorized_keys file found for $ARG1"
    fi
    ;;

  # ------------------------------------------------------------
  quarantine)
    # Move a suspicious file to quarantine with no-exec permissions
    if [ -z "$ARG1" ] || [ ! -f "$ARG1" ]; then
        echo "Usage: $0 quarantine /full/path/to/file"
        exit 1
    fi
    HASH=$(sha256sum "$ARG1" | awk '{print $1}')
    FNAME=$(basename "$ARG1")
    echo "  File    : $ARG1"
    echo "  SHA256  : $HASH"
    echo "  Type    : $(file "$ARG1")"
    read -rp "  Move to $QUARANTINE_DIR? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        mkdir -p "$QUARANTINE_DIR"
        chmod 700 "$QUARANTINE_DIR"
        DEST="$QUARANTINE_DIR/${HASH}_${FNAME}.quarantine"
        mv "$ARG1" "$DEST"
        chmod 000 "$DEST"
        chattr +i "$DEST" 2>/dev/null  # Make immutable
        log_action "QUARANTINE" "Source=$ARG1 Dest=$DEST SHA256=$HASH"
        echo "  VirusTotal: https://www.virustotal.com/gui/file/$HASH"
    fi
    ;;

  # ------------------------------------------------------------
  isolate)
    # Block ALL traffic except established sessions and loopback
    # Use only if you have out-of-band console access
    echo "  [ISOLATE] This will block ALL new inbound and outbound connections!"
    echo "  Ensure you have console/IPMI access before proceeding."
    read -rp "  Type ISOLATE to confirm: " confirm
    if [ "$confirm" = "ISOLATE" ]; then
        iptables -F
        iptables -P INPUT DROP
        iptables -P OUTPUT DROP
        iptables -P FORWARD DROP
        # Allow loopback
        iptables -A INPUT  -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        # Allow established sessions so current SSH doesn't drop
        iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
        iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        log_action "ISOLATE_MACHINE" "All new inbound+outbound blocked. Existing sessions kept."
        echo "  Machine isolated."
        echo "  To restore: iptables -F && iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT"
    fi
    ;;

  # ------------------------------------------------------------
  *)
    echo "  Available actions:"
    echo "    kill_pid <PID>"
    echo "    kill_name <process_name>"
    echo "    block_ip <IP>"
    echo "    disable_service <service_name>"
    echo "    remove_cron <username> <cron_string>"
    echo "    lock_user <username>"
    echo "    delete_user <username>"
    echo "    remove_ssh_key <username> <key_comment>"
    echo "    quarantine <file_path>"
    echo "    isolate"
    echo ""
    echo "  Action log: $LOGFILE"
    ;;
esac

echo ""
echo "  Action log: $LOGFILE"
echo "====================================================="
