#!/bin/bash
# =============================================================================
# VPS Hardening Script v3.0
# Supports: Ubuntu 20.04, 22.04, 24.04
# Providers: Oracle Cloud, AWS, DigitalOcean, Hetzner, Linode, Vultr, generic
# Usage: sudo ./harden.sh
# Repository: https://github.com/nrikmoh/vps-hardening
# =============================================================================

set -euo pipefail

# =============================================================================
# COLORS AND UI
# =============================================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
ITALIC='\033[3m'
NC='\033[0m'

# Spinner characters for background tasks
SPINNER='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

log_ok()      { echo -e "  ${GREEN}✓${NC}  $1"; }
log_warn()    { echo -e "  ${YELLOW}⚠${NC}  $1"; }
log_error()   { echo -e "  ${RED}✗${NC}  $1"; }
log_info()    { echo -e "  ${BLUE}ℹ${NC}  $1"; }
log_step()    { echo -e "  ${CYAN}→${NC}  $1"; }
log_tip()     { echo -e "  ${MAGENTA}💡${NC} $1"; }

# Animated spinner for background operations
spin() {
    local MSG="$1"
    local PID="$2"
    local i=0
    local LEN=${#SPINNER}

    echo -ne "  ${CYAN}${SPINNER:0:1}${NC}  $MSG"

    while kill -0 "$PID" 2>/dev/null; do
        i=$(( (i + 1) % LEN ))
        echo -ne "\r  ${CYAN}${SPINNER:$i:1}${NC}  $MSG"
        sleep 0.1
    done

    wait "$PID" 2>/dev/null
    local EXIT_CODE=$?
    echo -ne "\r"

    if [[ $EXIT_CODE -eq 0 ]]; then
        echo -e "  ${GREEN}✓${NC}  $MSG"
    else
        echo -e "  ${RED}✗${NC}  $MSG ${RED}(failed)${NC}"
    fi

    return $EXIT_CODE
}

# Run command silently in background with spinner
run_silent() {
    local MSG="$1"
    shift
    "$@" > /dev/null 2>&1 &
    local PID=$!
    spin "$MSG" "$PID"
}

print_banner() {
    clear
    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║                                                          ║"
    echo "  ║     🛡️   VPS HARDENING SCRIPT  v3.0                     ║"
    echo "  ║     Secure your server in minutes, not hours             ║"
    echo "  ║                                                          ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${DIM}Ubuntu 20.04 / 22.04 / 24.04${NC}"
    echo -e "  ${DIM}Oracle · AWS · DigitalOcean · Hetzner · Linode · Vultr · Generic${NC}"
    echo ""
}

print_phase() {
    local NUM="$1"
    local TITLE="$2"
    local DESC="${3:-}"
    echo ""
    echo -e "  ${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}${WHITE}  Phase $NUM${NC}  ${BOLD}$TITLE${NC}"
    if [[ -n "$DESC" ]]; then
        echo -e "  ${DIM}  $DESC${NC}"
    fi
    echo -e "  ${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_divider() {
    echo ""
    echo -e "  ${DIM}┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈${NC}"
    echo ""
}

print_box() {
    local TITLE="$1"
    local COLOR="${2:-$YELLOW}"
    echo ""
    echo -e "  ${BOLD}${COLOR}┌──────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}${COLOR}│${NC}  ${BOLD}$TITLE"
    echo -e "  ${BOLD}${COLOR}└──────────────────────────────────────────────────────┘${NC}"
    echo ""
}

pause() {
    echo ""
    echo -ne "  ${DIM}Press ENTER to continue ▶${NC} "
    read -r
}

# Root check
if [[ $EUID -ne 0 ]]; then
    echo ""
    echo -e "  ${RED}✗${NC}  This script requires ${BOLD}root privileges${NC}."
    echo -e "     Run with: ${CYAN}sudo ./harden.sh${NC}"
    echo ""
    exit 1
fi

# =============================================================================
# HELPERS
# =============================================================================

get_public_ip() {
    local IP
    if IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null) && [[ -n "$IP" ]]; then
        echo "$IP"
    elif IP=$(curl -s --max-time 5 icanhazip.com 2>/dev/null) && [[ -n "$IP" ]]; then
        echo "$IP"
    else
        echo "YOUR_SERVER_IP"
    fi
}

safe_find_suid() {
    find / -perm -4000 -type f 2>/dev/null | grep -v snap | sort || true
}

apply_ssh_socket_fix() {
    local SOCKET_EXISTS=false
    systemctl list-units --all 2>/dev/null | grep -q "ssh.socket"  && SOCKET_EXISTS=true || true
    systemctl list-unit-files 2>/dev/null | grep -q "ssh.socket"   && SOCKET_EXISTS=true || true
    [[ -f /lib/systemd/system/ssh.socket ]]                        && SOCKET_EXISTS=true || true
    [[ -f /usr/lib/systemd/system/ssh.socket ]]                    && SOCKET_EXISTS=true || true

    if [[ "$SOCKET_EXISTS" == "true" ]]; then
        log_step "Disabling SSH socket activation ${DIM}(Ubuntu 24.04 specific)${NC}"
        systemctl stop ssh.socket    2>/dev/null || true
        systemctl disable ssh.socket 2>/dev/null || true
        systemctl mask ssh.socket    2>/dev/null || true
        systemctl enable ssh.service 2>/dev/null || true
        log_ok "Socket activation disabled — sshd controls its own port now"
    fi

    if [[ ! -d /run/sshd ]]; then
        mkdir -p /run/sshd
        chmod 755 /run/sshd
    fi
}

# Calculate elapsed time
SCRIPT_START=$(date +%s)

# =============================================================================
# WELCOME SCREEN
# =============================================================================

print_banner

echo -e "  ${BOLD}Welcome!${NC} This script will:"
echo ""
echo -e "  ${CYAN}  1.${NC}  Update your system and set a custom hostname"
echo -e "  ${CYAN}  2.${NC}  Disable unnecessary services to reduce attack surface"
echo -e "  ${CYAN}  3.${NC}  Configure a strict firewall (UFW)"
echo -e "  ${CYAN}  4.${NC}  Move SSH to a custom port and harden its configuration"
echo -e "  ${CYAN}  5.${NC}  Install fail2ban to block brute-force attacks"
echo -e "  ${CYAN}  6.${NC}  Enable AppArmor mandatory access control"
echo -e "  ${CYAN}  7.${NC}  Set up persistent logging that survives reboots"
echo -e "  ${CYAN}  8.${NC}  Remove unnecessary packages"
echo -e "  ${CYAN}  9.${NC}  Create a personal admin account and lock down root"
echo -e "  ${CYAN} 10.${NC}  Install daily security monitoring scripts"
echo ""
echo -e "  ${DIM}The script will pause at two points to let you test${NC}"
echo -e "  ${DIM}SSH connections before applying restrictions.${NC}"
echo ""
echo -e "  ${DIM}Estimated time: 5–10 minutes${NC}"
echo ""

pause

# =============================================================================
# ENVIRONMENT DETECTION
# =============================================================================

print_phase "0" "Environment Detection" "Analyzing your server before making changes"

progress_items=(
    "Reading OS information"
    "Detecting cloud provider"
    "Checking firewall rules"
    "Checking cloud-init"
    "Scanning installed services"
)

# --- OS ---
echo -ne "  ${CYAN}⠋${NC}  ${progress_items[0]}"
OS_ID=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
OS_VERSION=$(grep "^VERSION_ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
OS_CODENAME=$(grep "^VERSION_CODENAME=" /etc/os-release \
    | cut -d= -f2 | tr -d '"' 2>/dev/null || echo "unknown")
sleep 0.3
echo -e "\r  ${GREEN}✓${NC}  ${progress_items[0]}"

if [[ "$OS_ID" != "ubuntu" ]]; then
    log_warn "This script is designed for Ubuntu. Detected: $OS_ID"
    read -rp "  Continue anyway? (yes/no): " CONTINUE_ANYWAY
    [[ "$CONTINUE_ANYWAY" != "yes" ]] && exit 1
fi

CURRENT_USER="${SUDO_USER:-root}"

# --- Cloud Provider ---
echo -ne "  ${CYAN}⠋${NC}  ${progress_items[1]}"
CLOUD_PROVIDER="generic"
DEFAULT_CLOUD_USER="$CURRENT_USER"

if systemctl list-units --all 2>/dev/null | grep -q "oracle" || \
   [[ -f /etc/oracle-cloud-agent/agent.yml ]] || \
   curl -sf --max-time 2 -H "Authorization: Bearer Oracle" \
       http://169.254.169.254/opc/v2/instance/ &>/dev/null; then
    CLOUD_PROVIDER="oracle"; DEFAULT_CLOUD_USER="ubuntu"
elif curl -sf --max-time 2 http://169.254.169.254/latest/meta-data/ami-id &>/dev/null; then
    CLOUD_PROVIDER="aws"; DEFAULT_CLOUD_USER="ubuntu"
elif [[ -f /etc/digitalocean ]] || \
     curl -sf --max-time 2 http://169.254.169.254/metadata/v1/id &>/dev/null; then
    CLOUD_PROVIDER="digitalocean"; DEFAULT_CLOUD_USER="root"
elif [[ -f /etc/hetzner-build ]] || \
     curl -sf --max-time 2 http://169.254.169.254/hetzner/v1/metadata &>/dev/null; then
    CLOUD_PROVIDER="hetzner"; DEFAULT_CLOUD_USER="root"
elif curl -sf --max-time 2 http://169.254.169.254/linode/v1/ &>/dev/null; then
    CLOUD_PROVIDER="linode"; DEFAULT_CLOUD_USER="root"
elif curl -sf --max-time 2 http://169.254.169.254/v1.json &>/dev/null; then
    CLOUD_PROVIDER="vultr"; DEFAULT_CLOUD_USER="root"
elif curl -sf --max-time 2 -H "Metadata-Flavor: Google" \
     http://169.254.169.254/computeMetadata/v1/ &>/dev/null; then
    CLOUD_PROVIDER="gcp"; DEFAULT_CLOUD_USER="ubuntu"
elif curl -sf --max-time 2 -H "Metadata: true" \
     "http://169.254.169.254/metadata/instance?api-version=2021-02-01" &>/dev/null; then
    CLOUD_PROVIDER="azure"; DEFAULT_CLOUD_USER="azureuser"
fi

if ! id "$DEFAULT_CLOUD_USER" &>/dev/null; then
    DEFAULT_CLOUD_USER="$CURRENT_USER"
fi
echo -e "\r  ${GREEN}✓${NC}  ${progress_items[1]}"

# --- iptables ---
echo -ne "  ${CYAN}⠋${NC}  ${progress_items[2]}"
CONFLICTING_IPTABLES=false
CONFLICTING_LINES=()
if command -v iptables &>/dev/null; then
    while IFS= read -r line; do
        if echo "$line" | grep -qE "REJECT|DROP" && \
           echo "$line" | grep -qE "^[0-9]"; then
            LINE_NUM=$(echo "$line" | awk '{print $1}')
            CONFLICTING_LINES+=("$LINE_NUM")
            CONFLICTING_IPTABLES=true
        fi
    done < <(iptables -L INPUT -n --line-numbers 2>/dev/null | tail -n +3)
fi
echo -e "\r  ${GREEN}✓${NC}  ${progress_items[2]}"

# --- cloud-init ---
echo -ne "  ${CYAN}⠋${NC}  ${progress_items[3]}"
HAS_CLOUD_INIT=false
command -v cloud-init &>/dev/null && HAS_CLOUD_INIT=true
echo -e "\r  ${GREEN}✓${NC}  ${progress_items[3]}"

# --- Services ---
echo -ne "  ${CYAN}⠋${NC}  ${progress_items[4]}"
HAS_RPCBIND=false; HAS_MODEMMANAGER=false; HAS_ISCSID=false
systemctl list-units --all 2>/dev/null | grep -q "rpcbind"      && HAS_RPCBIND=true      || true
systemctl list-units --all 2>/dev/null | grep -q "ModemManager" && HAS_MODEMMANAGER=true  || true
systemctl list-units --all 2>/dev/null | grep -q "iscsid"       && HAS_ISCSID=true        || true
echo -e "\r  ${GREEN}✓${NC}  ${progress_items[4]}"

# --- Results Table ---
print_divider

echo -e "  ${BOLD}Your Server:${NC}"
echo ""
echo -e "    ${DIM}Operating System${NC}    $OS_ID $OS_VERSION ($OS_CODENAME)"
echo -e "    ${DIM}Cloud Provider${NC}      $CLOUD_PROVIDER"
echo -e "    ${DIM}Logged in as${NC}        $CURRENT_USER"
echo -e "    ${DIM}Cloud default user${NC}  $DEFAULT_CLOUD_USER"
echo -e "    ${DIM}cloud-init${NC}          $(if [[ "$HAS_CLOUD_INIT" == "true" ]]; then echo "${GREEN}present${NC}"; else echo "${DIM}not found${NC}"; fi)"
echo -e "    ${DIM}iptables${NC}            $(if [[ "$CONFLICTING_IPTABLES" == "true" ]]; then echo "${YELLOW}conflicts found (will fix)${NC}"; else echo "${GREEN}clean${NC}"; fi)"

# Count services to remove
SVC_COUNT=0
[[ "$HAS_RPCBIND" == "true" ]] && SVC_COUNT=$((SVC_COUNT+1))
[[ "$HAS_MODEMMANAGER" == "true" ]] && SVC_COUNT=$((SVC_COUNT+1))
[[ "$HAS_ISCSID" == "true" ]] && SVC_COUNT=$((SVC_COUNT+1))
echo -e "    ${DIM}Services to remove${NC}  ${SVC_COUNT} found"

echo ""
log_ok "Environment scan complete"

# =============================================================================
# CONFIGURATION
# =============================================================================

print_phase "0" "Configuration" "Tell me how you want your server set up"

# --- Auth Method ---
print_divider
echo -e "  ${BOLD}🔐 Authentication Method${NC}"
echo ""
echo -e "    ${CYAN}1)${NC}  SSH key  ${DIM}(private key / identity file)${NC}"
echo -e "    ${CYAN}2)${NC}  Password"
echo ""
read -rp "  How are you logged in? (1/2): " AUTH_METHOD

while [[ "$AUTH_METHOD" != "1" && "$AUTH_METHOD" != "2" ]]; do
    log_warn "Please enter 1 or 2."
    read -rp "  Enter 1 or 2: " AUTH_METHOD
done

AUTH_TYPE=""
INPUT_PUBLIC_KEY=""

if [[ "$AUTH_METHOD" == "1" ]]; then
    AUTH_TYPE="key"
    echo ""
    log_ok "SSH key authentication"

    CURRENT_USER_HOME=$(eval echo "~${SUDO_USER:-$USER}")
    KEY_FOUND=false
    if [[ -f "$CURRENT_USER_HOME/.ssh/authorized_keys" ]] && \
       [[ -s "$CURRENT_USER_HOME/.ssh/authorized_keys" ]]; then
        log_ok "Found authorized_keys"
        KEY_FOUND=true
    elif [[ -f /root/.ssh/authorized_keys" ]] && \
         [[ -s "/root/.ssh/authorized_keys" ]]; then
        log_ok "Found authorized_keys"
        KEY_FOUND=true
    fi

    if [[ "$KEY_FOUND" == "false" ]]; then
        log_warn "No authorized_keys found"
        read -rp "  Continue anyway? (yes/no): " KEY_CONFIRM
        [[ "$KEY_CONFIRM" != "yes" ]] && exit 1
    fi

else
    print_box "SSH KEY RECOMMENDATION" "$YELLOW"
    echo -e "  SSH keys are ${BOLD}far more secure${NC} than passwords:"
    echo ""
    echo -e "    ${YELLOW}•${NC}  Passwords can be brute-forced — keys ${BOLD}cannot${NC}"
    echo -e "    ${YELLOW}•${NC}  Keys use 256+ bits of cryptographic randomness"
    echo -e "    ${YELLOW}•${NC}  Automated bots are trying passwords on your"
    echo -e "       server ${ITALIC}right now${NC}"
    echo -e "    ${YELLOW}•${NC}  fail2ban will be installed either way to limit attempts"
    echo ""
    print_divider
    echo -e "  ${BOLD}Would you like to set up an SSH key now?${NC}"
    echo ""
    echo -e "    ${CYAN}a)${NC}  ${GREEN}Yes${NC} — set up SSH key ${DIM}(recommended)${NC}"
    echo -e "    ${CYAN}b)${NC}  No  — keep using password"
    echo ""
    read -rp "  Enter a or b: " KEY_CHOICE

    while [[ "$KEY_CHOICE" != "a" && "$KEY_CHOICE" != "b" ]]; do
        log_warn "Please enter a or b."
        read -rp "  Enter a or b: " KEY_CHOICE
    done

    if [[ "$KEY_CHOICE" == "a" ]]; then
        AUTH_TYPE="key"
        echo ""
        echo -e "  ${BOLD}Step 1${NC} — Generate a key on your ${BOLD}LOCAL machine${NC}:"
        echo ""
        echo -e "    ${DIM}Mac / Linux:${NC}"
        echo -e "    ${CYAN}ssh-keygen -t ed25519 -C \"my-vps-key\"${NC}"
        echo -e "    ${CYAN}cat ~/.ssh/id_ed25519.pub${NC}"
        echo ""
        echo -e "    ${DIM}Windows PowerShell:${NC}"
        echo -e "    ${CYAN}ssh-keygen -t ed25519 -C \"my-vps-key\"${NC}"
        echo -e "    ${CYAN}type \$env:USERPROFILE\\.ssh\\id_ed25519.pub${NC}"
        echo ""
        echo -e "  ${BOLD}Step 2${NC} — Copy the output (starts with ${CYAN}ssh-ed25519 AAAA...${NC})"
        echo ""

        read -rp "  Have you generated the key? (yes/no): " KEY_GENERATED
        if [[ "$KEY_GENERATED" != "yes" ]]; then
            log_warn "Generate a key first, then re-run this script."
            exit 1
        fi

        echo ""
        echo -e "  ${BOLD}Step 3${NC} — Paste your ${BOLD}public key${NC} (.pub file):"
        echo ""
        read -rp "  > " INPUT_PUBLIC_KEY

        while [[ ! "$INPUT_PUBLIC_KEY" =~ ^ssh-(ed25519|rsa|ecdsa) ]]; do
            echo ""
            log_warn "Invalid format. Must start with ssh-ed25519, ssh-rsa, or ssh-ecdsa"
            log_warn "Make sure you copied the .pub file, not the private key"
            echo ""
            read -rp "  Paste your public key: " INPUT_PUBLIC_KEY
        done

        if [[ "$CURRENT_USER" == "root" ]]; then
            KEY_DIR="/root/.ssh"
        else
            KEY_DIR="/home/$CURRENT_USER/.ssh"
        fi

        mkdir -p "$KEY_DIR"
        chmod 700 "$KEY_DIR"
        echo "$INPUT_PUBLIC_KEY" >> "$KEY_DIR/authorized_keys"
        chmod 600 "$KEY_DIR/authorized_keys"
        [[ "$CURRENT_USER" != "root" ]] && chown -R "$CURRENT_USER:$CURRENT_USER" "$KEY_DIR"
        log_ok "Public key installed"

        PUBLIC_IP_EARLY=$(get_public_ip)
        print_box "TEST YOUR KEY LOGIN NOW" "$YELLOW"
        echo -e "  Open a ${BOLD}NEW terminal${NC} and run:"
        echo ""
        echo -e "    ${DIM}Mac / Linux:${NC}"
        echo -e "    ${CYAN}ssh -i ~/.ssh/id_ed25519 $CURRENT_USER@$PUBLIC_IP_EARLY${NC}"
        echo ""
        echo -e "    ${DIM}Windows:${NC}"
        echo -e "    ${CYAN}ssh -i \$env:USERPROFILE\\.ssh\\id_ed25519 $CURRENT_USER@$PUBLIC_IP_EARLY${NC}"
        echo ""
        echo -e "  If it connects ${GREEN}without a password${NC} — the key works."
        echo -e "  ${RED}Keep THIS session open!${NC}"
        echo ""
        read -rp "  Did the SSH key login succeed? (yes/no): " KEY_TEST

        if [[ "$KEY_TEST" != "yes" ]]; then
            echo ""
            log_warn "Key login failed. Tips:"
            echo -e "    ${CYAN}1)${NC} Confirm you copied the .pub file (public key)"
            echo -e "    ${CYAN}2)${NC} Check: ${CYAN}cat $KEY_DIR/authorized_keys${NC}"
            echo -e "    ${CYAN}3)${NC} Debug: ${CYAN}ssh -vvv -i ~/.ssh/id_ed25519 $CURRENT_USER@$PUBLIC_IP_EARLY${NC}"
            echo ""
            read -rp "  Continue with password-only instead? (yes/no): " FALLBACK
            if [[ "$FALLBACK" == "yes" ]]; then
                AUTH_TYPE="password"
                log_warn "Switching to password authentication"
            else
                log_error "Fix the key issue and re-run this script."
                exit 1
            fi
        else
            log_ok "Key login confirmed"
        fi
    else
        AUTH_TYPE="password"
        echo ""
        log_info "Continuing with password authentication"
        log_tip "You can add SSH keys later for stronger security"
    fi
fi

# --- Hostname ---
print_divider
echo -e "  ${BOLD}🏷️  Server Hostname${NC}"
echo -e "  ${DIM}A meaningful name for this server (letters, numbers, hyphens)${NC}"
echo ""
read -rp "  Hostname (e.g., web-01, vpn, myserver): " INPUT_HOSTNAME
while [[ -z "$INPUT_HOSTNAME" || ! "$INPUT_HOSTNAME" =~ ^[a-zA-Z0-9-]+$ ]]; do
    log_warn "Invalid. Use letters, numbers, and hyphens only."
    read -rp "  Hostname: " INPUT_HOSTNAME
done

# --- SSH Port ---
print_divider
echo -e "  ${BOLD}🔌 New SSH Port${NC}"
echo -e "  ${DIM}Moving SSH off port 22 blocks most automated scanners.${NC}"
echo -e "  ${DIM}Pick any number 1024–65535. Avoid 2222 (bots scan that too).${NC}"
echo ""
read -rp "  SSH port (e.g., 7022, 30044, 45678): " INPUT_SSH_PORT
while ! [[ "$INPUT_SSH_PORT" =~ ^[0-9]+$ ]] || \
      [[ "$INPUT_SSH_PORT" -lt 1024 ]] || \
      [[ "$INPUT_SSH_PORT" -gt 65535 ]]; do
    log_warn "Invalid. Must be 1024–65535."
    read -rp "  SSH port: " INPUT_SSH_PORT
done

# --- Admin Username ---
print_divider
echo -e "  ${BOLD}👤 Admin Username${NC}"
echo -e "  ${DIM}Your personal admin account. Avoid: ubuntu, admin, root, test, user${NC}"
echo ""
read -rp "  Username: " INPUT_USERNAME
while [[ -z "$INPUT_USERNAME" || \
         "$INPUT_USERNAME" =~ ^(ubuntu|admin|root|test|user)$ ]]; do
    log_warn "Too predictable. Choose something unique."
    read -rp "  Username: " INPUT_USERNAME
done

# --- Cloud User ---
INPUT_CLOUD_USER="$CURRENT_USER"
if [[ "$CURRENT_USER" != "root" ]]; then
    print_divider
    echo -e "  ${BOLD}Cloud Default User to Demote${NC}"
    echo ""
    read -rp "  Cloud username to demote [$CURRENT_USER]: " INPUT_CLOUD_USER
    INPUT_CLOUD_USER="${INPUT_CLOUD_USER:-$CURRENT_USER}"
fi

# --- Confirmation ---
echo ""
echo -e "  ${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "  ${BOLD}${CYAN}║${NC}  ${BOLD}${WHITE}CONFIGURATION SUMMARY${NC}"
echo -e "  ${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "    ${DIM}Hostname${NC}         ${BOLD}${GREEN}$INPUT_HOSTNAME${NC}"
echo -e "    ${DIM}SSH Port${NC}         ${BOLD}${GREEN}$INPUT_SSH_PORT${NC}"
echo -e "    ${DIM}Admin User${NC}       ${BOLD}${GREEN}$INPUT_USERNAME${NC}"
echo -e "    ${DIM}Current User${NC}     $INPUT_CLOUD_USER"
echo -e "    ${DIM}Auth Method${NC}      ${BOLD}${GREEN}$AUTH_TYPE${NC}"
echo -e "    ${DIM}Provider${NC}         $CLOUD_PROVIDER"
echo -e "    ${DIM}OS${NC}               $OS_ID $OS_VERSION"

if [[ "$AUTH_TYPE" == "password" ]]; then
    echo ""
    echo -e "    ${YELLOW}⚠  Password auth remains enabled.${NC}"
    echo -e "    ${DIM}   All other hardening still applies.${NC}"
fi

echo ""
read -rp "  Proceed with these settings? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo ""
    log_warn "Aborted. No changes were made."
    echo ""
    exit 1
fi

# =============================================================================
# LOGGING
# =============================================================================

LOGFILE="/var/log/harden-script.log"
exec > >(tee -a "$LOGFILE") 2>&1
{
    echo "════════════════════════════════════════"
    echo "Started: $(date)"
    echo "Provider: $CLOUD_PROVIDER | OS: $OS_ID $OS_VERSION | Auth: $AUTH_TYPE"
    echo "Host: $INPUT_HOSTNAME | Port: $INPUT_SSH_PORT | User: $INPUT_USERNAME"
    echo "════════════════════════════════════════"
} >> "$LOGFILE"

# =============================================================================
# PHASE 1 - ASSESSMENT
# =============================================================================

print_phase "1" "Initial Assessment" "Quick snapshot of your server's current state"

PUBLIC_IP=$(get_public_ip)

echo -e "  ${BOLD}System Overview:${NC}"
echo ""
echo -e "    ${DIM}Hostname${NC}     $(hostname)"
echo -e "    ${DIM}Public IP${NC}    ${BOLD}$PUBLIC_IP${NC}"
echo -e "    ${DIM}Kernel${NC}       $(uname -r)"
echo -e "    ${DIM}OS${NC}           $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
echo -e "    ${DIM}Uptime${NC}       $(uptime -p 2>/dev/null || echo 'unknown')"
echo -e "    ${DIM}Disk Used${NC}    $(df -h / | tail -1 | awk '{print $5 " of " $2}')"
echo -e "    ${DIM}Memory${NC}       $(free -h | grep Mem | awk '{print $3 " / " $2}')"

echo ""
echo -e "  ${BOLD}Open Ports:${NC}"
while IFS= read -r line; do
    PORT=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
    PROC=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")
    echo -e "    ${DIM}Port${NC} ${BOLD}$PORT${NC} ${DIM}— $PROC${NC}"
done < <(ss -tlnp | grep LISTEN)

echo ""
echo -e "  ${BOLD}Services Running:${NC} $(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | grep 'loaded units' | awk '{print $1}')"

# Kernel check
RUNNING_KERNEL=$(uname -r)
if [[ -f /var/run/reboot-required ]]; then
    echo ""
    log_warn "A system reboot is pending — will remind you at the end"
fi

echo ""
log_ok "Assessment complete"
pause

# =============================================================================
# PHASE 2 - SYSTEM PREP
# =============================================================================

print_phase "2" "System Preparation" "Updating packages and setting hostname"

run_silent "Updating package lists" apt update -qq
run_silent "Installing available upgrades" apt upgrade -y -qq
run_silent "Setting hostname to ${BOLD}$INPUT_HOSTNAME${NC}" hostnamectl set-hostname "$INPUT_HOSTNAME"

if [[ "$HAS_CLOUD_INIT" == "true" ]]; then
    echo "preserve_hostname: true" > /etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg 2>/dev/null
    log_ok "cloud-init hostname lock applied"
fi

if grep -q "127.0.1.1" /etc/hosts; then
    sed -i "s/^127\.0\.1\.1.*/127.0.1.1 $INPUT_HOSTNAME/" /etc/hosts
else
    echo "127.0.1.1 $INPUT_HOSTNAME" >> /etc/hosts
fi

echo ""
log_ok "System updated, hostname set to ${BOLD}$INPUT_HOSTNAME${NC}"

# =============================================================================
# PHASE 3 - SERVICES
# =============================================================================

print_phase "3" "Remove Unnecessary Services" "Each service is a potential attack target"

disable_and_mask() {
    local SERVICE="$1"
    if systemctl list-units --all 2>/dev/null | grep -q "$SERVICE"; then
        systemctl stop "$SERVICE"    2>/dev/null || true
        systemctl disable "$SERVICE" 2>/dev/null || true
        systemctl mask "$SERVICE"    2>/dev/null || true
        return 0
    fi
    return 1
}

REMOVED=0
if [[ "$HAS_RPCBIND" == "true" ]]; then
    run_silent "Removing rpcbind (NFS — not needed)" bash -c 'systemctl stop rpcbind.socket rpcbind.service 2>/dev/null; systemctl disable rpcbind.socket rpcbind.service 2>/dev/null; systemctl mask rpcbind.socket rpcbind.service 2>/dev/null; true'
    REMOVED=$((REMOVED+1))
fi
if [[ "$HAS_MODEMMANAGER" == "true" ]]; then
    run_silent "Removing ModemManager (cellular — useless on VPS)" bash -c 'systemctl stop ModemManager 2>/dev/null; systemctl disable ModemManager 2>/dev/null; systemctl mask ModemManager 2>/dev/null; true'
    REMOVED=$((REMOVED+1))
fi
if [[ "$HAS_ISCSID" == "true" ]]; then
    run_silent "Removing iSCSI (enterprise storage — not needed)" bash -c 'systemctl stop iscsid.socket iscsid.service 2>/dev/null; systemctl disable iscsid.socket iscsid.service 2>/dev/null; systemctl mask iscsid.socket iscsid.service 2>/dev/null; true'
    REMOVED=$((REMOVED+1))
fi

systemctl daemon-reload 2>/dev/null || true

echo ""
if [[ "$REMOVED" -eq 0 ]]; then
    log_ok "No unnecessary services found — already clean"
else
    log_ok "$REMOVED service(s) disabled and masked"
fi

# =============================================================================
# PHASE 4 - FIREWALL
# =============================================================================

print_phase "4" "Firewall Configuration" "Only allow what you explicitly permit"

run_silent "Installing UFW firewall" apt install ufw -y -qq

ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
log_ok "Default policy: ${BOLD}deny incoming${NC}, allow outgoing"

ufw allow 22/tcp comment "SSH default - temporary" > /dev/null 2>&1
ufw allow "$INPUT_SSH_PORT"/tcp comment "SSH hardened" > /dev/null 2>&1
log_ok "Opened ports: 22 ${DIM}(temporary)${NC} and ${BOLD}$INPUT_SSH_PORT${NC}"

echo "y" | ufw enable > /dev/null 2>&1
log_ok "UFW firewall ${BOLD}${GREEN}active${NC}"

if [[ "$CONFLICTING_IPTABLES" == "true" ]]; then
    mapfile -t SORTED_LINES < <(printf '%s\n' "${CONFLICTING_LINES[@]}" | sort -rn)
    for LINE_NUM in "${SORTED_LINES[@]}"; do
        iptables -D INPUT "$LINE_NUM" 2>/dev/null || true
    done
    mkdir -p /etc/iptables
    sh -c 'iptables-save > /etc/iptables/rules.v4' 2>/dev/null
    log_ok "Conflicting iptables rules cleaned"
fi

case "$CLOUD_PROVIDER" in
    oracle)
        echo ""
        log_warn "${BOLD}Oracle Cloud:${NC} Also open port $INPUT_SSH_PORT in your Security List"
        log_info "VCN → Subnet → Security List → Add Ingress Rule → Port $INPUT_SSH_PORT"
        pause ;;
    aws)
        echo ""
        log_warn "${BOLD}AWS:${NC} Also open port $INPUT_SSH_PORT in your EC2 Security Group"
        pause ;;
    azure)
        echo ""
        log_warn "${BOLD}Azure:${NC} Also open port $INPUT_SSH_PORT in your NSG"
        pause ;;
    gcp)
        echo ""
        log_warn "${BOLD}GCP:${NC} Also open port $INPUT_SSH_PORT in VPC Firewall Rules"
        pause ;;
esac

# =============================================================================
# PHASE 5 - SSH
# =============================================================================

print_phase "5" "SSH Hardening" "Port change + security settings (no lockout risk)"

echo -e "  ${DIM}This phase changes the port and applies hardening settings.${NC}"
echo -e "  ${DIM}User restrictions (AllowUsers, root login) are applied${NC}"
echo -e "  ${DIM}in Phase 10 — only after your new account is confirmed.${NC}"
echo ""
log_warn "Keep your current SSH session open"
pause

run_silent "Backing up SSH configuration" bash -c "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup; mkdir -p /etc/ssh/sshd_config.d"

# Build SSH config
if [[ "$AUTH_TYPE" == "key" ]]; then
    cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# Hardened SSH — Phase 5 (safe)
# AllowUsers + PermitRootLogin no applied in Phase 10
Port $INPUT_SSH_PORT
PermitRootLogin yes
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
EOF
else
    cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# Hardened SSH — Phase 5 (safe)
# AllowUsers + PermitRootLogin no applied in Phase 10
Port $INPUT_SSH_PORT
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
EOF
fi
log_ok "Hardened SSH config written"

[[ "$OS_VERSION" == "24.04" ]] && apply_ssh_socket_fix

if ! sshd -t 2>/dev/null; then
    log_error "SSH config has errors — restoring backup"
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/99-hardened.conf
    exit 1
fi

run_silent "Restarting SSH on port $INPUT_SSH_PORT" systemctl restart ssh
sleep 1

if ! ss -tlnp | grep -q ":$INPUT_SSH_PORT"; then
    log_error "SSH is NOT on port $INPUT_SSH_PORT — check journalctl -u ssh"
    exit 1
fi

log_ok "SSH listening on port ${BOLD}$INPUT_SSH_PORT${NC}"

print_box "TEST YOUR CONNECTION" "$YELLOW"
echo -e "  Open a ${BOLD}NEW terminal${NC} and run:"
echo ""
if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "    ${CYAN}ssh -i /path/to/key -p $INPUT_SSH_PORT $CURRENT_USER@$PUBLIC_IP${NC}"
else
    echo -e "    ${CYAN}ssh -p $INPUT_SSH_PORT $CURRENT_USER@$PUBLIC_IP${NC}"
fi
echo ""
echo -e "  ${RED}Keep THIS session open!${NC}"
echo ""
read -rp "  Connection on port $INPUT_SSH_PORT succeeded? (yes/no): " SSH_TEST

if [[ "$SSH_TEST" != "yes" ]]; then
    log_error "SSH test failed. Debug from this session:"
    log_info "  systemctl status ssh"
    log_info "  journalctl -u ssh -n 30"
    exit 1
fi

ufw delete allow 22/tcp > /dev/null 2>&1
log_ok "Port 22 closed — only ${BOLD}$INPUT_SSH_PORT${NC} is accessible"

# =============================================================================
# PHASE 6 - FAIL2BAN
# =============================================================================

print_phase "6" "Brute Force Protection" "fail2ban blocks attackers after 3 failures"

run_silent "Installing fail2ban" apt install fail2ban -y -qq

cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = 86400
findtime = 1200
maxretry = 3

[sshd]
enabled  = true
port     = $INPUT_SSH_PORT
logpath  = %(sshd_log)s
backend  = systemd
EOF

systemctl enable fail2ban -q 2>/dev/null || true
run_silent "Starting fail2ban" systemctl start fail2ban

BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0")
echo ""
log_ok "fail2ban active — 3 strikes = 24h ban"
if [[ "$BANNED" -gt 0 ]]; then
    log_info "Already banned: ${BOLD}$BANNED IP(s)${NC} from previous attacks"
fi

# =============================================================================
# PHASE 7 - APPARMOR
# =============================================================================

print_phase "7" "Mandatory Access Control" "AppArmor limits what programs can do, even as root"

if command -v aa-status &>/dev/null; then
    PROFILES_BEFORE=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}' || echo "0")
    run_silent "Installing additional AppArmor profiles" apt install apparmor-profiles apparmor-profiles-extra -y -qq
    PROFILES_AFTER=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}' || echo "0")
    ENFORCED=$(aa-status 2>/dev/null | grep "in enforce mode" | head -1 | awk '{print $1}' || echo "0")
    echo ""
    log_ok "AppArmor: ${BOLD}$PROFILES_AFTER${NC} profiles loaded, ${BOLD}$ENFORCED${NC} enforcing"
    if [[ "$PROFILES_AFTER" -gt "$PROFILES_BEFORE" ]]; then
        log_info "Added $((PROFILES_AFTER - PROFILES_BEFORE)) new security profiles"
    fi
else
    log_warn "AppArmor not available — skipping"
fi

# =============================================================================
# PHASE 8 - LOGGING
# =============================================================================

print_phase "8" "Persistent Logging" "Logs survive reboots — attackers can't erase evidence"

run_silent "Configuring persistent journal" bash -c '
    mkdir -p /var/log/journal
    systemd-tmpfiles --create --prefix /var/log/journal > /dev/null 2>&1 || true
    mkdir -p /etc/systemd/journald.conf.d
    cat > /etc/systemd/journald.conf.d/custom.conf << JEOF
[Journal]
Storage=persistent
SystemMaxUse=500M
SystemMaxFileSize=50M
JEOF
    systemctl restart systemd-journald
'

JOURNAL_SIZE=$(journalctl --disk-usage 2>/dev/null | grep -oP '[\d.]+\w+' | head -1 || echo "unknown")
BOOT_COUNT=$(journalctl --list-boots --no-pager 2>/dev/null | wc -l || echo "1")
echo ""
log_ok "Persistent logging enabled — ${BOLD}${JOURNAL_SIZE}${NC} stored, $BOOT_COUNT boot(s) recorded"

# =============================================================================
# PHASE 9 - PACKAGES
# =============================================================================

print_phase "9" "Package Cleanup" "Less software = fewer vulnerabilities"

PACKAGES_TO_REMOVE=()
for PKG in nfs-common open-iscsi ssh-import-id; do
    if dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        PACKAGES_TO_REMOVE+=("$PKG")
    fi
done

if [[ ${#PACKAGES_TO_REMOVE[@]} -gt 0 ]]; then
    run_silent "Removing: ${PACKAGES_TO_REMOVE[*]}" apt remove "${PACKAGES_TO_REMOVE[@]}" -y -qq
fi

run_silent "Cleaning up unused dependencies" apt autoremove -y -qq

echo ""
log_ok "Package cleanup complete — ${#PACKAGES_TO_REMOVE[@]} package(s) removed"

# =============================================================================
# PHASE 10 - ADMIN ACCOUNT + LOCKDOWN
# =============================================================================

print_phase "10" "Admin Account + Final Lockdown" "Create your account, then lock everything down"

echo -e "  ${DIM}Your personal admin account is created first.${NC}"
echo -e "  ${DIM}SSH restrictions are applied ONLY after you confirm it works.${NC}"
echo -e "  ${DIM}If something goes wrong, root access is preserved.${NC}"
echo ""

# Create account
if id "$INPUT_USERNAME" &>/dev/null; then
    log_warn "User $INPUT_USERNAME already exists — skipping creation"
else
    echo -e "  ${BOLD}Create password for ${GREEN}$INPUT_USERNAME${NC}${BOLD}:${NC}"
    echo ""
    adduser --gecos "" "$INPUT_USERNAME"
fi

echo ""
run_silent "Adding $INPUT_USERNAME to sudo and adm groups" bash -c "usermod -aG sudo $INPUT_USERNAME; usermod -aG adm $INPUT_USERNAME"

# SSH key setup for new account
mkdir -p "/home/$INPUT_USERNAME/.ssh"
chmod 700 "/home/$INPUT_USERNAME/.ssh"

if [[ "$AUTH_TYPE" == "key" ]]; then
    KEY_SOURCE=""
    [[ -f "/root/.ssh/authorized_keys" && -s "/root/.ssh/authorized_keys" ]] && KEY_SOURCE="/root/.ssh/authorized_keys"
    [[ -z "$KEY_SOURCE" && "$INPUT_CLOUD_USER" != "root" && -f "/home/$INPUT_CLOUD_USER/.ssh/authorized_keys" ]] && KEY_SOURCE="/home/$INPUT_CLOUD_USER/.ssh/authorized_keys"

    if [[ -n "$KEY_SOURCE" ]]; then
        cp "$KEY_SOURCE" "/home/$INPUT_USERNAME/.ssh/authorized_keys"
        chmod 600 "/home/$INPUT_USERNAME/.ssh/authorized_keys"
        log_ok "SSH key copied to new account"
    elif [[ -n "${INPUT_PUBLIC_KEY:-}" ]]; then
        echo "$INPUT_PUBLIC_KEY" > "/home/$INPUT_USERNAME/.ssh/authorized_keys"
        chmod 600 "/home/$INPUT_USERNAME/.ssh/authorized_keys"
        log_ok "SSH key installed for new account"
    fi
else
    log_info "Password mode — $INPUT_USERNAME will use password to login"
fi

chown -R "$INPUT_USERNAME:$INPUT_USERNAME" "/home/$INPUT_USERNAME/.ssh"

# --- TEST ---
print_box "TEST YOUR NEW ADMIN ACCOUNT" "$YELLOW"

if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "    ${CYAN}ssh -i /path/to/key -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
else
    echo -e "    ${CYAN}ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    echo -e "    ${DIM}Use the password you just set for $INPUT_USERNAME${NC}"
fi

echo ""
echo -e "  Then verify sudo works:"
echo -e "    ${CYAN}sudo -l${NC}"
echo -e "    ${CYAN}sudo id${NC}  ${DIM}(should show uid=0(root))${NC}"
echo ""
echo -e "  ${RED}Keep THIS session open!${NC}"
echo ""
read -rp "  Login and sudo both succeeded? (yes/no): " NEW_ACCT_TEST

if [[ "$NEW_ACCT_TEST" != "yes" ]]; then
    echo ""
    log_error "Test failed — SSH lockdown ${BOLD}NOT${NC} applied"
    log_error "Root access preserved. You are still connected."
    echo ""
    log_info "Diagnose:"
    echo -e "    ${CYAN}id $INPUT_USERNAME${NC}"
    echo -e "    ${CYAN}passwd $INPUT_USERNAME${NC}"
    echo -e "    ${CYAN}journalctl -u ssh -n 20${NC}"
    echo ""
    log_info "Once fixed, apply lockdown manually:"
    echo -e "    ${CYAN}sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "    ${CYAN}echo 'AllowUsers $INPUT_USERNAME' | sudo tee -a /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "    ${CYAN}sudo sshd -t && sudo systemctl restart ssh${NC}"
    echo ""
    log_warn "Continuing to Phase 11..."

else
    # Apply final lockdown
    if [[ "$AUTH_TYPE" == "key" ]]; then
        cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# Hardened SSH Configuration (FINAL)
# Generated: $(date)
Port $INPUT_SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
AllowUsers $INPUT_USERNAME
EOF
    else
        cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# Hardened SSH Configuration (FINAL)
# Generated: $(date)
# To switch to key-only later:
#   1. ssh-keygen -t ed25519
#   2. ssh-copy-id -p $INPUT_SSH_PORT $INPUT_USERNAME@server
#   3. Set PasswordAuthentication no
#   4. Add: AuthenticationMethods publickey
#   5. sudo sshd -t && sudo systemctl restart ssh
Port $INPUT_SSH_PORT
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
AllowUsers $INPUT_USERNAME
EOF
    fi

    if sshd -t 2>/dev/null; then
        run_silent "Applying final SSH lockdown" systemctl restart ssh
        log_ok "Root login ${BOLD}disabled${NC} — only ${BOLD}$INPUT_USERNAME${NC} can login"
    else
        log_error "Config error — keeping safe config"
    fi

    # Demote cloud user
    if [[ "$INPUT_CLOUD_USER" != "root" ]]; then
        deluser "$INPUT_CLOUD_USER" sudo  2>/dev/null || true
        deluser "$INPUT_CLOUD_USER" lxd   2>/dev/null || true
        deluser "$INPUT_CLOUD_USER" cdrom 2>/dev/null || true
        deluser "$INPUT_CLOUD_USER" dip   2>/dev/null || true
        passwd -l "$INPUT_CLOUD_USER" > /dev/null 2>&1 || true
        log_ok "$INPUT_CLOUD_USER demoted and locked"
    fi

    # Remove NOPASSWD
    SUDOERS_FILE=""
    for F in /etc/sudoers.d/*; do
        if grep -q "$INPUT_CLOUD_USER" "$F" 2>/dev/null; then
            SUDOERS_FILE="$F"
            break
        fi
    done
    if [[ -n "$SUDOERS_FILE" ]]; then
        cp "$SUDOERS_FILE" "${SUDOERS_FILE}.backup"
        sed -i "s|$INPUT_CLOUD_USER ALL=(ALL) NOPASSWD:ALL|$INPUT_CLOUD_USER ALL=(ALL) ALL|g" "$SUDOERS_FILE"
        sed -i "s|$INPUT_CLOUD_USER ALL=(ALL:ALL) NOPASSWD:ALL|$INPUT_CLOUD_USER ALL=(ALL:ALL) ALL|g" "$SUDOERS_FILE"
    fi
fi

# =============================================================================
# PHASE 11 - MONITORING
# =============================================================================

print_phase "11" "Security Monitoring" "Daily audits + on-demand health checks"

SCRIPTS_DIR="/opt/$INPUT_HOSTNAME/scripts"
BASELINE_DIR="/opt/$INPUT_HOSTNAME/baseline"
AUDIT_LOG="/var/log/${INPUT_HOSTNAME}-audit.log"

run_silent "Creating directory structure" mkdir -p "$SCRIPTS_DIR" "$BASELINE_DIR"

# SUID baseline
safe_find_suid > "$BASELINE_DIR/suid-baseline.txt"
chmod 600 "$BASELINE_DIR/suid-baseline.txt"
SUID_COUNT=$(wc -l < "$BASELINE_DIR/suid-baseline.txt")
log_ok "SUID baseline: ${BOLD}$SUID_COUNT${NC} privileged binaries tracked"

# --- Daily Audit ---
cat > "$SCRIPTS_DIR/daily-audit.sh" << AUDIT_EOF
#!/bin/bash
LOGFILE="$AUDIT_LOG"
DATE=\$(date '+%Y-%m-%d %H:%M:%S')

echo "========================================" >> \$LOGFILE
echo "Audit: \$DATE" >> \$LOGFILE
echo "========================================" >> \$LOGFILE

echo "--- System Health ---" >> \$LOGFILE
echo "Uptime: \$(uptime)" >> \$LOGFILE
df -h / >> \$LOGFILE
free -h >> \$LOGFILE
echo "CPU Load: \$(cat /proc/loadavg)" >> \$LOGFILE

echo "--- Failed SSH (24h) ---" >> \$LOGFILE
journalctl -u ssh --since "24 hours ago" 2>/dev/null \
    | grep -c "Invalid user\|Failed password" \
    | xargs echo "Failed:" >> \$LOGFILE
journalctl -u ssh --since "24 hours ago" 2>/dev/null \
    | grep -i "failed\|invalid" | tail -10 >> \$LOGFILE

echo "--- fail2ban (24h) ---" >> \$LOGFILE
journalctl -u fail2ban --since "24 hours ago" 2>/dev/null | grep "Ban" >> \$LOGFILE

echo "--- SUID Changes ---" >> \$LOGFILE
find / -perm -4000 -type f 2>/dev/null | grep -v snap | sort > /tmp/current-suid.txt || true
DIFF=\$(diff $BASELINE_DIR/suid-baseline.txt /tmp/current-suid.txt 2>/dev/null || true)
if [ -z "\$DIFF" ]; then echo "No changes." >> \$LOGFILE; else echo "WARNING: SUID changed!" >> \$LOGFILE; echo "\$DIFF" >> \$LOGFILE; fi
rm -f /tmp/current-suid.txt

echo "--- Ports ---" >> \$LOGFILE
ss -tlnp >> \$LOGFILE

echo "--- Users ---" >> \$LOGFILE
who >> \$LOGFILE; last | head -5 >> \$LOGFILE

echo "--- Sudo (24h) ---" >> \$LOGFILE
journalctl --since "24 hours ago" 2>/dev/null | grep "sudo" | grep -v "pam_unix" >> \$LOGFILE
echo "" >> \$LOGFILE
AUDIT_EOF

# --- Check Alerts ---
cat > "$SCRIPTS_DIR/check-alerts.sh" << 'ALERT_HEADER'
#!/bin/bash
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; WHITE='\033[1;37m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

HOST=$(hostname)
DATE=$(date '+%Y-%m-%d %H:%M:%S')
UPTIME=$(uptime -p 2>/dev/null || echo "unknown")

echo ""
echo -e "${BOLD}${CYAN}  ╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}  ║${NC}  ${BOLD}${WHITE}🛡️  Security Status — ${HOST}${NC}"
echo -e "${BOLD}${CYAN}  ║${NC}  ${DIM}${DATE} • ${UPTIME}${NC}"
echo -e "${BOLD}${CYAN}  ╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

ALERTS=0; WARNINGS=0

check() {
    local S="$1" M="$2"
    case "$S" in
        ok)   echo -e "  ${GREEN}✓${NC}  $M" ;;
        warn) echo -e "  ${YELLOW}⚠${NC}  $M"; WARNINGS=$((WARNINGS+1)) ;;
        crit) echo -e "  ${RED}✗${NC}  $M"; ALERTS=$((ALERTS+1)) ;;
        info) echo -e "  ${CYAN}ℹ${NC}  $M" ;;
    esac
}

ALERT_HEADER

cat >> "$SCRIPTS_DIR/check-alerts.sh" << ALERT_BODY

# Disk
DISK=\$(df / | tail -1 | awk '{print \$5}' | tr -d '%')
if [ "\$DISK" -gt 80 ]; then check "crit" "Disk: \${DISK}% — critically full"
elif [ "\$DISK" -gt 60 ]; then check "warn" "Disk: \${DISK}% — getting full"
else check "ok" "Disk: \${DISK}%"; fi

# Memory
MEM=\$(free | grep Mem | awk '{printf "%.0f", \$3/\$2*100}')
if [ "\$MEM" -gt 90 ]; then check "crit" "Memory: \${MEM}%"
elif [ "\$MEM" -gt 75 ]; then check "warn" "Memory: \${MEM}%"
else check "ok" "Memory: \${MEM}%"; fi

# SSH failures
FAILED=\$(journalctl -u ssh --since "24 hours ago" 2>/dev/null | grep -c "Invalid user\|Failed password" || echo 0)
if [ "\$FAILED" -gt 200 ]; then check "crit" "Failed SSH (24h): \${FAILED} — unusual volume"
elif [ "\$FAILED" -gt 50 ]; then check "warn" "Failed SSH (24h): \${FAILED}"
else check "ok" "Failed SSH (24h): \${FAILED}"; fi

# fail2ban
BANS=\$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print \$NF}')
BANS=\${BANS:-0}
TOTAL=\$(fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print \$NF}')
TOTAL=\${TOTAL:-0}
if [ "\$BANS" -gt 0 ]; then
    check "info" "fail2ban: \${BANS} currently banned (\${TOTAL} total)"
    BANNED_IPS=\$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP" | cut -d: -f2)
    echo -e "  \${DIM}  \$BANNED_IPS\${NC}"
else check "ok" "fail2ban: No IPs banned (\${TOTAL} total)"; fi

# SUID
find / -perm -4000 -type f 2>/dev/null | grep -v snap | sort > /tmp/suid-chk.txt || true
SDIFF=\$(diff $BASELINE_DIR/suid-baseline.txt /tmp/suid-chk.txt 2>/dev/null || true)
rm -f /tmp/suid-chk.txt
if [ -n "\$SDIFF" ]; then check "crit" "SUID files changed — investigate!"; echo "\$SDIFF"
else check "ok" "SUID files unchanged (\$(wc -l < $BASELINE_DIR/suid-baseline.txt) tracked)"; fi

# Services
for SVC in ssh fail2ban; do
    if systemctl is-active --quiet "\$SVC"; then check "ok" "\$SVC running"
    else check "crit" "\$SVC NOT running — investigate"; fi
done

# UFW
if ufw status | grep -q "Status: active"; then check "ok" "UFW firewall active"
else check "crit" "UFW firewall NOT active"; fi

# AppArmor
if command -v aa-status &>/dev/null; then
    ENF=\$(aa-status 2>/dev/null | grep "in enforce mode" | head -1 | awk '{print \$1}' || echo "0")
    check "ok" "AppArmor: \${ENF} profiles enforcing"
fi

# Ports
echo ""
echo -e "  \${BOLD}Listening Ports:\${NC}"
ss -tlnp | grep LISTEN | while read -r line; do
    PORT=\$(echo "\$line" | awk '{print \$4}' | rev | cut -d: -f1 | rev)
    PROC=\$(echo "\$line" | grep -oP 'users:\(\("\K[^"]+' || echo "?")
    echo -e "    \${DIM}:\$PORT\${NC} — \$PROC"
done

# Summary
echo ""
echo -e "  \${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\${NC}"
if [ "\$ALERTS" -gt 0 ]; then
    echo -e "  \${RED}✗  \${ALERTS} critical alert(s) — action required\${NC}"
elif [ "\$WARNINGS" -gt 0 ]; then
    echo -e "  \${YELLOW}⚠  \${WARNINGS} warning(s) — review when possible\${NC}"
else
    echo -e "  \${GREEN}✓  All systems healthy — no issues found\${NC}"
fi
echo ""
ALERT_BODY

# Permissions
chmod 750 "$SCRIPTS_DIR/daily-audit.sh" "$SCRIPTS_DIR/check-alerts.sh"
if id "$INPUT_USERNAME" &>/dev/null; then
    chown root:"$INPUT_USERNAME" "$SCRIPTS_DIR/daily-audit.sh" "$SCRIPTS_DIR/check-alerts.sh"
fi
ln -sf "$SCRIPTS_DIR/check-alerts.sh" /usr/local/bin/check-alerts

# Cron — FIXED: || true prevents exit when no crontab exists
(crontab -l 2>/dev/null || true; echo "0 4 * * * $SCRIPTS_DIR/daily-audit.sh") | crontab -
log_ok "Daily audit scheduled at ${BOLD}4:00 AM${NC}"

run_silent "Running initial audit" bash "$SCRIPTS_DIR/daily-audit.sh"
log_ok "Monitoring installed — run ${BOLD}${CYAN}sudo check-alerts${NC} anytime"

# =============================================================================
# FINAL SUMMARY
# =============================================================================

SCRIPT_END=$(date +%s)
ELAPSED=$(( SCRIPT_END - SCRIPT_START ))
MINUTES=$(( ELAPSED / 60 ))
SECONDS_REMAINING=$(( ELAPSED % 60 ))

echo ""
echo ""
echo -e "${BOLD}${GREEN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║                                                          ║"
echo "  ║    🛡️   VPS HARDENING COMPLETE                          ║"
echo "  ║                                                          ║"
echo "  ║    Your server is now secured and monitored.             ║"
echo "  ║                                                          ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "  ${DIM}Completed in ${MINUTES}m ${SECONDS_REMAINING}s${NC}"
echo ""

# Security Summary
echo -e "  ${BOLD}${WHITE}What was secured:${NC}"
echo ""
echo -e "  ${GREEN}✓${NC}  ${BOLD}Firewall${NC}         Only port $INPUT_SSH_PORT is open"
echo -e "  ${GREEN}✓${NC}  ${BOLD}SSH${NC}              Moved from 22 → $INPUT_SSH_PORT, root login disabled"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Admin Account${NC}    ${BOLD}$INPUT_USERNAME${NC} created with sudo access"

if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "  ${GREEN}✓${NC}  ${BOLD}Auth Method${NC}      SSH key only — passwords disabled"
else
    echo -e "  ${YELLOW}⚠${NC}  ${BOLD}Auth Method${NC}      Password ${DIM}(upgrade to SSH keys recommended)${NC}"
fi

echo -e "  ${GREEN}✓${NC}  ${BOLD}fail2ban${NC}         3 failed logins = 24 hour IP ban"
echo -e "  ${GREEN}✓${NC}  ${BOLD}AppArmor${NC}         Mandatory access control enforcing"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Logging${NC}          Persistent, reboot-safe, 500MB limit"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Monitoring${NC}       Daily audit at 4 AM + on-demand health check"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Cleanup${NC}          Unnecessary services and packages removed"

# Server Details
echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${WHITE}Your Server Details:${NC}"
echo ""
echo -e "    ${DIM}Hostname${NC}       ${BOLD}$INPUT_HOSTNAME${NC}"
echo -e "    ${DIM}Public IP${NC}      ${BOLD}$PUBLIC_IP${NC}"
echo -e "    ${DIM}SSH Port${NC}       ${BOLD}$INPUT_SSH_PORT${NC}"
echo -e "    ${DIM}Admin User${NC}     ${BOLD}$INPUT_USERNAME${NC}"
echo -e "    ${DIM}Auth${NC}           ${BOLD}$AUTH_TYPE${NC}"
echo -e "    ${DIM}Provider${NC}       $CLOUD_PROVIDER"
echo -e "    ${DIM}OS${NC}             $OS_ID $OS_VERSION"

# Connection Command
echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${WHITE}🔑 How to connect from now on:${NC}"
echo ""

if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "    ${DIM}Mac / Linux:${NC}"
    echo -e "    ${CYAN}ssh -i ~/.ssh/id_ed25519 -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    echo ""
    echo -e "    ${DIM}Windows PowerShell:${NC}"
    echo -e "    ${CYAN}ssh -i \$env:USERPROFILE\\.ssh\\id_ed25519 -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
else
    echo -e "    ${CYAN}ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
fi

# Daily Commands
echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${WHITE}📋 Useful Commands:${NC}"
echo ""
echo -e "    ${CYAN}sudo check-alerts${NC}                  ${DIM}Full security health check${NC}"
echo -e "    ${CYAN}sudo fail2ban-client status sshd${NC}   ${DIM}View banned attackers${NC}"
echo -e "    ${CYAN}sudo ufw status verbose${NC}             ${DIM}View firewall rules${NC}"
echo -e "    ${CYAN}sudo journalctl -u ssh -n 50${NC}        ${DIM}Recent SSH activity${NC}"
echo -e "    ${CYAN}sudo tail -f $AUDIT_LOG${NC}"
echo -e "                                          ${DIM}Live audit log${NC}"

# Next Steps
echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${WHITE}📝 Recommended Next Steps:${NC}"
echo ""

STEP=1

# Reboot if needed
if [[ -f /var/run/reboot-required ]]; then
    echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Reboot your server${NC} to load the new kernel"
    echo -e "       ${CYAN}sudo reboot${NC}"
    echo -e "       ${DIM}Then reconnect: ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    STEP=$((STEP+1))
    echo ""
fi

# SSH keys upgrade
if [[ "$AUTH_TYPE" == "password" ]]; then
    echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Upgrade to SSH keys${NC} for maximum security"
    echo -e "       ${DIM}On your local machine:${NC}"
    echo -e "       ${CYAN}ssh-keygen -t ed25519 -C \"$INPUT_HOSTNAME\"${NC}"
    echo -e "       ${CYAN}ssh-copy-id -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    echo ""
    echo -e "       ${DIM}Then on the server:${NC}"
    echo -e "       ${CYAN}sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' \\${NC}"
    echo -e "       ${CYAN}    /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "       ${CYAN}sudo sed -i '/PermitEmptyPasswords/i AuthenticationMethods publickey' \\${NC}"
    echo -e "       ${CYAN}    /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "       ${CYAN}sudo sshd -t && sudo systemctl restart ssh${NC}"
    STEP=$((STEP+1))
    echo ""
fi

# Cloud console
if [[ "$CLOUD_PROVIDER" =~ ^(oracle|aws|azure|gcp)$ ]]; then
    echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Cloud firewall${NC} — verify port $INPUT_SSH_PORT is open"
    echo -e "       ${DIM}in your ${CLOUD_PROVIDER} network security console${NC}"
    STEP=$((STEP+1))
    echo ""
fi

echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Run a health check${NC} after rebooting"
echo -e "       ${CYAN}sudo check-alerts${NC}"
echo ""

# Key Files
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${WHITE}📁 Key Files:${NC}"
echo ""
echo -e "    ${DIM}SSH Config${NC}      /etc/ssh/sshd_config.d/99-hardened.conf"
echo -e "    ${DIM}fail2ban${NC}        /etc/fail2ban/jail.local"
echo -e "    ${DIM}Audit Log${NC}       $AUDIT_LOG"
echo -e "    ${DIM}Scripts${NC}         $SCRIPTS_DIR/"
echo -e "    ${DIM}SUID Baseline${NC}   $BASELINE_DIR/suid-baseline.txt"
echo -e "    ${DIM}Script Log${NC}      $LOGFILE"
echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${CYAN}  Happy and secure hosting! 🚀${NC}"
echo ""
echo -e "  ${DIM}Full log saved to: $LOGFILE${NC}"
echo ""
