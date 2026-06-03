#!/bin/bash
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
# SOC - macOS Remediation & Containment
# Targeted containment and remediation actions for macOS.
# *** ALWAYS document what you do and get change approval first. ***
# *** These actions modify the system - run only when authorized. ***
# Required: Run as root or with sudo.
#
# USAGE:
#   Kill process:           sudo ./08_Remediation.sh kill_pid 1234
#   Kill by name:           sudo ./08_Remediation.sh kill_name malware
#   Block IP:               sudo ./08_Remediation.sh block_ip 1.2.3.4
#   Remove LaunchAgent:     sudo ./08_Remediation.sh remove_launch "/Library/LaunchAgents/evil.plist"
#   Disable service:        sudo ./08_Remediation.sh disable_service com.evil.agent
#   Lock user:              sudo ./08_Remediation.sh lock_user baduser
#   Delete user:            sudo ./08_Remediation.sh delete_user baduser
#   Remove SSH key:         sudo ./08_Remediation.sh remove_ssh_key username "key_comment"
#   Quarantine file:        sudo ./08_Remediation.sh quarantine /tmp/evil.app
#   Disable network:        sudo ./08_Remediation.sh disable_network
#   Isolate machine:        sudo ./08_Remediation.sh isolate

ACTION="$1"
ARG1="$2"
ARG2="$3"
LOGFILE="/var/log/soc_remediation_$(date +%Y%m%d).log"
QUARANTINE_DIR="/private/var/soc_quarantine"

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC macOS REMEDIATION  |  $TS UTC"
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
    if [ -z "$ARG1" ]; then echo "Usage: $0 kill_pid <PID>"; exit 1; fi
    COMM=$(ps -p "$ARG1" -o comm= 2>/dev/null)
    PATH_EXE=$(lsof -p "$ARG1" -a -d txt 2>/dev/null | awk 'NR>1{print $9}' | head -1)
    echo "  Process: PID=$ARG1 Name=$COMM Path=$PATH_EXE"
    read -rp "  Confirm kill? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        kill -9 "$ARG1"
        log_action "KILL_PROCESS" "PID=$ARG1 Name=$COMM Path=$PATH_EXE"
    fi
    ;;

  # ------------------------------------------------------------
  kill_name)
    if [ -z "$ARG1" ]; then echo "Usage: $0 kill_name <process_name>"; exit 1; fi
    PIDS=$(pgrep -x "$ARG1" 2>/dev/null)
    if [ -z "$PIDS" ]; then
        echo "  No process named '$ARG1' found."
    else
        echo "  Matching processes:"
        ps -p $(echo $PIDS | tr ' ' ',') -o pid,user,comm,args 2>/dev/null
        read -rp "  Kill all? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            pkill -9 -x "$ARG1"
            log_action "KILL_PROCESS" "Name=$ARG1 PIDs=$PIDS"
        fi
    fi
    ;;

  # ------------------------------------------------------------
  block_ip)
    if [ -z "$ARG1" ]; then echo "Usage: $0 block_ip <IP>"; exit 1; fi
    echo "  Blocking IP: $ARG1 (inbound + outbound)"
    read -rp "  Confirm? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        # Use pf (Packet Filter) - the macOS firewall
        echo "block drop from $ARG1 to any" | pfctl -f - 2>/dev/null
        echo "block drop from any to $ARG1" | pfctl -f - 2>/dev/null
        pfctl -e 2>/dev/null
        log_action "BLOCK_IP" "IP=$ARG1 via pf"
        echo "  To verify: pfctl -sr"
        echo "  To remove: edit /etc/pf.conf and pfctl -f /etc/pf.conf"
    fi
    ;;

  # ------------------------------------------------------------
  remove_launch)
    # Remove a LaunchAgent or LaunchDaemon plist
    if [ -z "$ARG1" ] || [ ! -f "$ARG1" ]; then
        echo "Usage: $0 remove_launch /path/to/file.plist"
        exit 1
    fi
    echo "  LaunchAgent/Daemon plist: $ARG1"
    cat "$ARG1"
    echo ""
    read -rp "  Unload and delete this plist? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        # Get the label before deleting
        LABEL=$(/usr/libexec/PlistBuddy -c "Print :Label" "$ARG1" 2>/dev/null)
        launchctl unload "$ARG1" 2>/dev/null
        launchctl remove "$LABEL" 2>/dev/null
        # Backup before delete
        cp "$ARG1" "$QUARANTINE_DIR/$(basename $ARG1).bak" 2>/dev/null || true
        rm -f "$ARG1"
        log_action "REMOVE_LAUNCH_ITEM" "Path=$ARG1 Label=$LABEL"
    fi
    ;;

  # ------------------------------------------------------------
  disable_service)
    # Disable a launchd service by label
    if [ -z "$ARG1" ]; then echo "Usage: $0 disable_service <label>"; exit 1; fi
    echo "  Service label: $ARG1"
    launchctl list "$ARG1" 2>/dev/null
    read -rp "  Unload and disable? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        launchctl unload -w "$ARG1" 2>/dev/null || launchctl stop "$ARG1" 2>/dev/null
        launchctl disable "system/$ARG1" 2>/dev/null
        log_action "DISABLE_SERVICE" "Label=$ARG1"
    fi
    ;;

  # ------------------------------------------------------------
  lock_user)
    if [ -z "$ARG1" ]; then echo "Usage: $0 lock_user <username>"; exit 1; fi
    echo "  Locking user: $ARG1"
    dscl . read /Users/"$ARG1" 2>/dev/null | grep -E "UserShell|UniqueID|AuthenticationAuthority"
    read -rp "  Confirm lock (disable login shell)? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        # Set shell to /usr/bin/false to prevent login
        dscl . change /Users/"$ARG1" UserShell "$(dscl . read /Users/"$ARG1" UserShell | awk '{print $2}')" /usr/bin/false 2>/dev/null
        # Disable password authentication
        dscl . delete /Users/"$ARG1" AuthenticationAuthority 2>/dev/null
        # Kill any current sessions
        pkill -KILL -u "$ARG1" 2>/dev/null
        log_action "LOCK_USER" "User=$ARG1"
        echo "  To restore: dscl . change /Users/$ARG1 UserShell /usr/bin/false /bin/bash"
    fi
    ;;

  # ------------------------------------------------------------
  delete_user)
    if [ -z "$ARG1" ]; then echo "Usage: $0 delete_user <username>"; exit 1; fi
    echo "  About to delete user: $ARG1"
    dscl . read /Users/"$ARG1" 2>/dev/null
    read -rp "  Delete user AND home directory? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        pkill -KILL -u "$ARG1" 2>/dev/null
        dscl . delete /Users/"$ARG1" 2>/dev/null
        # Optionally remove home directory
        read -rp "  Also remove home directory /Users/$ARG1? (yes/no): " rmhome
        if [ "$rmhome" = "yes" ]; then
            rm -rf "/Users/$ARG1"
        fi
        log_action "DELETE_USER" "User=$ARG1"
    fi
    ;;

  # ------------------------------------------------------------
  remove_ssh_key)
    if [ -z "$ARG1" ] || [ -z "$ARG2" ]; then
        echo "Usage: $0 remove_ssh_key <username> <key_comment>"
        exit 1
    fi
    KEYFILE="/Users/$ARG1/.ssh/authorized_keys"
    [ "$ARG1" = "root" ] && KEYFILE="/var/root/.ssh/authorized_keys"
    if [ -f "$KEYFILE" ]; then
        echo "  Current keys:"
        cat "$KEYFILE"
        echo ""
        read -rp "  Remove key matching comment '$ARG2'? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            cp "$KEYFILE" "${KEYFILE}.bak.$(date +%Y%m%d%H%M%S)"
            grep -v "$ARG2" "$KEYFILE" > "${KEYFILE}.tmp" && mv "${KEYFILE}.tmp" "$KEYFILE"
            log_action "REMOVE_SSH_KEY" "User=$ARG1 KeyComment=$ARG2"
        fi
    else
        echo "  No authorized_keys for $ARG1"
    fi
    ;;

  # ------------------------------------------------------------
  quarantine)
    if [ -z "$ARG1" ] || [ ! -e "$ARG1" ]; then
        echo "Usage: $0 quarantine /path/to/file"
        exit 1
    fi
    SHA=$(shasum -a 256 "$ARG1" 2>/dev/null | awk '{print $1}')
    FNAME=$(basename "$ARG1")
    echo "  File   : $ARG1"
    echo "  SHA256 : $SHA"
    echo "  Type   : $(file "$ARG1")"
    read -rp "  Move to $QUARANTINE_DIR? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        mkdir -p "$QUARANTINE_DIR"
        chmod 700 "$QUARANTINE_DIR"
        DEST="$QUARANTINE_DIR/${SHA}_${FNAME}.quarantine"
        mv "$ARG1" "$DEST"
        chmod 000 "$DEST"
        chflags schg "$DEST" 2>/dev/null  # Make immutable (system immutable flag)
        log_action "QUARANTINE" "Source=$ARG1 Dest=$DEST SHA256=$SHA"
        echo "  VirusTotal: https://www.virustotal.com/gui/file/$SHA"
    fi
    ;;

  # ------------------------------------------------------------
  disable_network)
    # Turn off all network interfaces (less drastic than full isolation)
    echo "  Disabling all network interfaces..."
    read -rp "  This will cut ALL network connectivity. Confirm? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        networksetup -listallnetworkservices 2>/dev/null | grep -v "^An asterisk" | while read svc; do
            networksetup -setnetworkserviceenabled "$svc" off 2>/dev/null
            echo "  Disabled: $svc"
        done
        log_action "DISABLE_NETWORK" "All network services disabled"
        echo "  To re-enable: networksetup -setnetworkserviceenabled 'Wi-Fi' on"
    fi
    ;;

  # ------------------------------------------------------------
  isolate)
    echo "  [ISOLATE] Block ALL new connections via pf. Keep existing sessions."
    echo "  Ensure you have physical/console access before proceeding."
    read -rp "  Type ISOLATE to confirm: " confirm
    if [ "$confirm" = "ISOLATE" ]; then
        # Write a blocking pf ruleset that only allows established
        cat > /tmp/soc_pf.conf << 'EOF'
# SOC Isolation - blocks all new connections, keeps established
set skip on lo0
block all
pass out proto tcp keep state
pass in proto tcp established
EOF
        pfctl -f /tmp/soc_pf.conf 2>/dev/null
        pfctl -e 2>/dev/null
        log_action "ISOLATE_MACHINE" "pf ruleset applied - all new inbound blocked"
        echo "  Machine isolated."
        echo "  To restore: pfctl -F all && pfctl -d"
    fi
    ;;

  # ------------------------------------------------------------
  *)
    echo "  Available actions:"
    echo "    kill_pid <PID>"
    echo "    kill_name <process_name>"
    echo "    block_ip <IP>"
    echo "    remove_launch <plist_path>"
    echo "    disable_service <label>"
    echo "    lock_user <username>"
    echo "    delete_user <username>"
    echo "    remove_ssh_key <username> <key_comment>"
    echo "    quarantine <file_path>"
    echo "    disable_network"
    echo "    isolate"
    echo ""
    echo "  Action log: $LOGFILE"
    ;;
esac

echo ""
echo "  Action log: $LOGFILE"
echo "====================================================="
