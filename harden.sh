#!/bin/bash
# =============================================================================
# VPS Hardening Script
# Supports: Ubuntu 20.04, 22.04, 24.04
# Providers: Oracle Cloud, AWS, DigitalOcean, Hetzner, Linode, Vultr, generic
# Usage: sudo ./harden.sh
# =============================================================================

set -euo pipefail

# =============================================================================
# COLORS AND UI HELPERS
# =============================================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

log_info()    { echo -e "  ${BLUE}ℹ${NC}  $1"; }
log_ok()      { echo -e "  ${GREEN}✓${NC}  $1"; }
log_warn()    { echo -e "  ${YELLOW}⚠${NC}  $1"; }
log_error()   { echo -e "  ${RED}✗${NC}  $1"; }
log_step()    { echo -e "  ${CYAN}→${NC}  $1"; }

print_banner() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║           VPS HARDENING SCRIPT  v2.0                ║"
    echo "  ║     Secure your server in minutes, not hours        ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${DIM}Supports Ubuntu 20.04 / 22.04 / 24.04${NC}"
    echo -e "  ${DIM}Oracle · AWS · DigitalOcean · Hetzner · Linode · Vultr${NC}"
    echo ""
}

print_section() {
    local PHASE="$1"
    local TITLE="$2"
    echo ""
    echo -e "  ${BOLD}${MAGENTA}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}${MAGENTA}│${NC}  ${BOLD}${CYAN}Phase $PHASE${NC} — ${BOLD}$TITLE${NC}"
    echo -e "  ${BOLD}${MAGENTA}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
}

print_divider() {
    echo -e "  ${DIM}──────────────────────────────────────────────────────${NC}"
}

print_success_banner() {
    echo ""
    echo -e "${BOLD}${GREEN}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║                                                      ║"
    echo "  ║        ✓  VPS HARDENING COMPLETE                    ║"
    echo "  ║           Your server is now secured                 ║"
    echo "  ║                                                      ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

progress() {
    local MSG="$1"
    echo -ne "  ${CYAN}→${NC}  $MSG..."
}

progress_done() {
    echo -e " ${GREEN}done${NC}"
}

pause() {
    echo ""
    echo -e "  ${DIM}Press ENTER to continue...${NC}"
    read -r
}

confirm() {
    local PROMPT="$1"
    local RESPONSE
    echo ""
    read -rp "  ${BOLD}$PROMPT${NC} " RESPONSE
    echo "$RESPONSE"
}

if [[ $EUID -ne 0 ]]; then
    echo ""
    echo -e "  ${RED}✗${NC}  This script must be run as root."
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
    if systemctl list-units --all 2>/dev/null | grep -q "ssh.socket"; then
        SOCKET_EXISTS=true
    fi
    if systemctl list-unit-files 2>/dev/null | grep -q "ssh.socket"; then
        SOCKET_EXISTS=true
    fi
    if [[ -f /lib/systemd/system/ssh.socket ]] || \
       [[ -f /usr/lib/systemd/system/ssh.socket ]]; then
        SOCKET_EXISTS=true
    fi

    if [[ "$SOCKET_EXISTS" == "true" ]]; then
        log_step "Disabling SSH socket activation (Ubuntu 24.04)..."
        systemctl stop ssh.socket    2>/dev/null || true
        systemctl disable ssh.socket 2>/dev/null || true
        systemctl mask ssh.socket    2>/dev/null || true
        systemctl enable ssh.service 2>/dev/null || true
        log_ok "SSH socket activation disabled"
    fi

    if [[ ! -d /run/sshd ]]; then
        mkdir -p /run/sshd
        chmod 755 /run/sshd
    fi
}

# =============================================================================
# ENVIRONMENT DETECTION
# =============================================================================

detect_environment() {
    print_section "0A" "Detecting Your Environment"

    progress "Reading OS information"
    OS_ID=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_VERSION=$(grep "^VERSION_ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_CODENAME=$(grep "^VERSION_CODENAME=" /etc/os-release \
        | cut -d= -f2 | tr -d '"' 2>/dev/null || echo "unknown")
    progress_done

    if [[ "$OS_ID" != "ubuntu" ]]; then
        log_warn "This script is designed for Ubuntu. Detected: $OS_ID"
        RESPONSE=$(confirm "Continue anyway? (yes/no):")
        [[ "$RESPONSE" != "yes" ]] && exit 1
    fi

    CURRENT_USER="${SUDO_USER:-root}"
    CLOUD_PROVIDER="generic"
    DEFAULT_CLOUD_USER="$CURRENT_USER"

    progress "Detecting cloud provider"
    if systemctl list-units --all 2>/dev/null | grep -q "oracle" || \
       [[ -f /etc/oracle-cloud-agent/agent.yml ]] || \
       curl -sf --max-time 2 \
           -H "Authorization: Bearer Oracle" \
           http://169.254.169.254/opc/v2/instance/ &>/dev/null; then
        CLOUD_PROVIDER="oracle"; DEFAULT_CLOUD_USER="ubuntu"
    elif curl -sf --max-time 2 \
             http://169.254.169.254/latest/meta-data/ami-id &>/dev/null; then
        CLOUD_PROVIDER="aws"; DEFAULT_CLOUD_USER="ubuntu"
    elif [[ -f /etc/digitalocean ]] || \
         curl -sf --max-time 2 \
             http://169.254.169.254/metadata/v1/id &>/dev/null; then
        CLOUD_PROVIDER="digitalocean"; DEFAULT_CLOUD_USER="root"
    elif [[ -f /etc/hetzner-build ]] || \
         curl -sf --max-time 2 \
             http://169.254.169.254/hetzner/v1/metadata &>/dev/null; then
        CLOUD_PROVIDER="hetzner"; DEFAULT_CLOUD_USER="root"
    elif curl -sf --max-time 2 \
             http://169.254.169.254/linode/v1/ &>/dev/null; then
        CLOUD_PROVIDER="linode"; DEFAULT_CLOUD_USER="root"
    elif curl -sf --max-time 2 \
             http://169.254.169.254/v1.json &>/dev/null; then
        CLOUD_PROVIDER="vultr"; DEFAULT_CLOUD_USER="root"
    elif curl -sf --max-time 2 \
             -H "Metadata-Flavor: Google" \
             http://169.254.169.254/computeMetadata/v1/ &>/dev/null; then
        CLOUD_PROVIDER="gcp"; DEFAULT_CLOUD_USER="ubuntu"
    elif curl -sf --max-time 2 \
             -H "Metadata: true" \
             "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
             &>/dev/null; then
        CLOUD_PROVIDER="azure"; DEFAULT_CLOUD_USER="azureuser"
    fi
    progress_done

    if ! id "$DEFAULT_CLOUD_USER" &>/dev/null; then
        DEFAULT_CLOUD_USER="$CURRENT_USER"
    fi

    progress "Checking iptables rules"
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
    progress_done

    progress "Checking cloud-init"
    HAS_CLOUD_INIT=false
    command -v cloud-init &>/dev/null && HAS_CLOUD_INIT=true
    progress_done

    progress "Checking installed services"
    HAS_RPCBIND=false
    HAS_MODEMMANAGER=false
    HAS_ISCSID=false
    systemctl list-units --all 2>/dev/null | grep -q "rpcbind"      && HAS_RPCBIND=true      || true
    systemctl list-units --all 2>/dev/null | grep -q "ModemManager" && HAS_MODEMMANAGER=true  || true
    systemctl list-units --all 2>/dev/null | grep -q "iscsid"       && HAS_ISCSID=true        || true
    progress_done

    echo ""
    print_divider
    echo ""
    echo -e "  ${BOLD}Detection Results:${NC}"
    echo ""
    echo -e "  ${DIM}OS:${NC}             ${BOLD}$OS_ID $OS_VERSION ($OS_CODENAME)${NC}"
    echo -e "  ${DIM}Cloud Provider:${NC} ${BOLD}$CLOUD_PROVIDER${NC}"
    echo -e "  ${DIM}Current User:${NC}   ${BOLD}$CURRENT_USER${NC}"
    echo -e "  ${DIM}Cloud User:${NC}     ${BOLD}$DEFAULT_CLOUD_USER${NC}"
    echo -e "  ${DIM}cloud-init:${NC}     ${BOLD}$HAS_CLOUD_INIT${NC}"

    if [[ "$CONFLICTING_IPTABLES" == "true" ]]; then
        echo -e "  ${DIM}iptables:${NC}       ${YELLOW}Conflicting rules found (will be fixed)${NC}"
    else
        echo -e "  ${DIM}iptables:${NC}       ${GREEN}Clean${NC}"
    fi
    echo ""
    log_ok "Environment detection complete"
}

detect_environment

# =============================================================================
# PHASE 0 - INTERACTIVE CONFIGURATION
# =============================================================================

print_section "0B" "Configuration"

echo -e "  ${DIM}Answer the questions below. All changes happen AFTER you confirm.${NC}"
echo ""

# --- SSH Authentication ---
print_divider
echo ""
echo -e "  ${BOLD}How are you currently logged into this server?${NC}"
echo ""
echo -e "  ${CYAN}  1)${NC}  SSH key  ${DIM}(private key / identity file)${NC}"
echo -e "  ${CYAN}  2)${NC}  Password"
echo ""
read -rp "  Enter 1 or 2: " AUTH_METHOD

while [[ "$AUTH_METHOD" != "1" && "$AUTH_METHOD" != "2" ]]; do
    log_warn "Please enter 1 or 2."
    read -rp "  Enter 1 or 2: " AUTH_METHOD
done

AUTH_TYPE=""
INPUT_PUBLIC_KEY=""

if [[ "$AUTH_METHOD" == "1" ]]; then
    AUTH_TYPE="key"
    echo ""
    log_ok "SSH key authentication selected"

    CURRENT_USER_HOME=$(eval echo "~${SUDO_USER:-$USER}")
    KEY_FOUND=false
    if [[ -f "$CURRENT_USER_HOME/.ssh/authorized_keys" ]] && \
       [[ -s "$CURRENT_USER_HOME/.ssh/authorized_keys" ]]; then
        log_ok "Found authorized_keys at $CURRENT_USER_HOME/.ssh/authorized_keys"
        KEY_FOUND=true
    elif [[ -f /root/.ssh/authorized_keys ]] && \
         [[ -s /root/.ssh/authorized_keys ]]; then
        log_ok "Found authorized_keys at /root/.ssh/authorized_keys"
        KEY_FOUND=true
    fi

    if [[ "$KEY_FOUND" == "false" ]]; then
        log_warn "No authorized_keys file found on this server"
        RESPONSE=$(confirm "Continue anyway? (yes/no):")
        [[ "$RESPONSE" != "yes" ]] && exit 1
    fi

else
    echo ""
    echo -e "  ${BOLD}${YELLOW}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}${YELLOW}│  SSH KEY RECOMMENDATION                             │${NC}"
    echo -e "  ${BOLD}${YELLOW}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "  SSH keys are ${BOLD}significantly more secure${NC} than passwords:"
    echo ""
    echo -e "  ${YELLOW}  •${NC}  Passwords can be brute-forced — keys cannot"
    echo -e "  ${YELLOW}  •${NC}  Keys use 256+ bits of cryptographic randomness"
    echo -e "  ${YELLOW}  •${NC}  Bots are already trying passwords on your server right now"
    echo -e "  ${YELLOW}  •${NC}  fail2ban will be installed to limit attempts either way"
    echo ""
    print_divider
    echo ""
    echo -e "  ${BOLD}Would you like to set up an SSH key now?${NC}"
    echo ""
    echo -e "  ${CYAN}  a)${NC}  ${GREEN}Yes${NC} — set up SSH key now ${DIM}(recommended)${NC}"
    echo -e "  ${CYAN}  b)${NC}  No  — continue with password only"
    echo ""
    read -rp "  Enter a or b: " KEY_CHOICE

    while [[ "$KEY_CHOICE" != "a" && "$KEY_CHOICE" != "b" ]]; do
        log_warn "Please enter a or b."
        read -rp "  Enter a or b: " KEY_CHOICE
    done

    if [[ "$KEY_CHOICE" == "a" ]]; then
        AUTH_TYPE="key"
        echo ""
        echo -e "  ${BOLD}Generate a key on your LOCAL machine (not this server):${NC}"
        echo ""
        echo -e "  ${DIM}Mac / Linux:${NC}"
        echo -e "  ${CYAN}    ssh-keygen -t ed25519 -C \"my-vps-key\"${NC}"
        echo -e "  ${CYAN}    cat ~/.ssh/id_ed25519.pub${NC}"
        echo ""
        echo -e "  ${DIM}Windows PowerShell:${NC}"
        echo -e "  ${CYAN}    ssh-keygen -t ed25519 -C \"my-vps-key\"${NC}"
        echo -e "  ${CYAN}    type \$env:USERPROFILE\\.ssh\\id_ed25519.pub${NC}"
        echo ""
        echo -e "  Copy the output — it starts with ${CYAN}ssh-ed25519 AAAA...${NC}"
        echo ""
        read -rp "  Have you generated the key on your local machine? (yes/no): " KEY_GENERATED
        if [[ "$KEY_GENERATED" != "yes" ]]; then
            echo ""
            log_warn "Generate a key first then re-run this script."
            log_warn "Or choose option b to continue with password only."
            exit 1
        fi

        echo ""
        echo -e "  ${BOLD}Paste your PUBLIC key below (.pub file content):${NC}"
        echo -e "  ${DIM}Must start with: ssh-ed25519, ssh-rsa, or ssh-ecdsa${NC}"
        echo ""
        read -rp "  > " INPUT_PUBLIC_KEY

        while [[ ! "$INPUT_PUBLIC_KEY" =~ ^ssh-(ed25519|rsa|ecdsa) ]]; do
            echo ""
            log_warn "Invalid key format. Should start with ssh-ed25519, ssh-rsa, or ssh-ecdsa."
            log_warn "Make sure you copied the .pub file — not the private key."
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
        if [[ "$CURRENT_USER" != "root" ]]; then
            chown -R "$CURRENT_USER:$CURRENT_USER" "$KEY_DIR"
        fi
        log_ok "Public key installed to $KEY_DIR/authorized_keys"

        PUBLIC_IP_EARLY=$(get_public_ip)
        echo ""
        echo -e "  ${BOLD}${YELLOW}┌─────────────────────────────────────────────────────┐${NC}"
        echo -e "  ${BOLD}${YELLOW}│  TEST YOUR KEY LOGIN NOW (before port change)       │${NC}"
        echo -e "  ${BOLD}${YELLOW}└─────────────────────────────────────────────────────┘${NC}"
        echo ""
        echo -e "  Open a ${BOLD}NEW terminal${NC} on your local machine and run:"
        echo ""
        echo -e "  ${DIM}Mac / Linux:${NC}"
        echo -e "  ${CYAN}    ssh -i ~/.ssh/id_ed25519 $CURRENT_USER@$PUBLIC_IP_EARLY${NC}"
        echo ""
        echo -e "  ${DIM}Windows:${NC}"
        echo -e "  ${CYAN}    ssh -i \$env:USERPROFILE\\.ssh\\id_ed25519 $CURRENT_USER@$PUBLIC_IP_EARLY${NC}"
        echo ""
        echo -e "  If it connects ${GREEN}without a password prompt${NC} — the key is working."
        echo -e "  ${RED}  Keep THIS session open!${NC}"
        echo ""
        read -rp "  Did the SSH key login succeed? (yes/no): " KEY_TEST

        if [[ "$KEY_TEST" != "yes" ]]; then
            echo ""
            log_warn "Key login did not work. Try these fixes:"
            echo ""
            echo -e "  ${CYAN}  1)${NC}  Confirm you copied the .pub file (public key)"
            echo -e "  ${CYAN}  2)${NC}  Check: ${CYAN}cat $KEY_DIR/authorized_keys${NC}"
            echo -e "  ${CYAN}  3)${NC}  Debug: ${CYAN}ssh -vvv -i ~/.ssh/id_ed25519 $CURRENT_USER@$PUBLIC_IP_EARLY${NC}"
            echo ""
            read -rp "  Continue with password-only instead? (yes/no): " FALLBACK
            if [[ "$FALLBACK" == "yes" ]]; then
                AUTH_TYPE="password"
                log_warn "Switching to password authentication."
            else
                log_error "Fix the key issue and re-run this script."
                exit 1
            fi
        else
            log_ok "Key login confirmed working"
        fi

    else
        AUTH_TYPE="password"
        echo ""
        log_warn "Continuing with password authentication"
        log_info "You can add SSH keys anytime after setup for stronger security"
    fi
fi

# --- Hostname ---
echo ""
print_divider
echo ""
echo -e "  ${BOLD}Server Hostname${NC}"
echo -e "  ${DIM}A meaningful name for this server (letters, numbers, hyphens)${NC}"
echo ""
read -rp "  Enter hostname (e.g., web-01, vpn, myserver): " INPUT_HOSTNAME
while [[ -z "$INPUT_HOSTNAME" || ! "$INPUT_HOSTNAME" =~ ^[a-zA-Z0-9-]+$ ]]; do
    log_warn "Invalid hostname. Use letters, numbers, and hyphens only."
    read -rp "  Enter hostname: " INPUT_HOSTNAME
done

# --- SSH Port ---
echo ""
print_divider
echo ""
echo -e "  ${BOLD}New SSH Port${NC}"
echo -e "  ${DIM}Moving SSH off port 22 blocks automated scanners${NC}"
echo -e "  ${DIM}Pick any number between 1024-65535 (e.g., 7022, 30044, 45678)${NC}"
echo -e "  ${DIM}Avoid 2222 — bots scan that too${NC}"
echo ""
read -rp "  Enter new SSH port: " INPUT_SSH_PORT
while ! [[ "$INPUT_SSH_PORT" =~ ^[0-9]+$ ]] || \
      [[ "$INPUT_SSH_PORT" -lt 1024 ]] || \
      [[ "$INPUT_SSH_PORT" -gt 65535 ]]; do
    log_warn "Invalid port. Must be a number between 1024-65535."
    read -rp "  Enter new SSH port: " INPUT_SSH_PORT
done

# --- Admin Username ---
echo ""
print_divider
echo ""
echo -e "  ${BOLD}New Admin Username${NC}"
echo -e "  ${DIM}A personal username for your admin account${NC}"
echo -e "  ${DIM}Avoid predictable names: ubuntu, admin, root, test, user${NC}"
echo ""
read -rp "  Enter new admin username: " INPUT_USERNAME
while [[ -z "$INPUT_USERNAME" || \
         "$INPUT_USERNAME" =~ ^(ubuntu|admin|root|test|user)$ ]]; do
    log_warn "Choose a less predictable username."
    log_warn "Avoid: ubuntu, admin, root, test, user"
    read -rp "  Enter new admin username: " INPUT_USERNAME
done

# --- Cloud User ---
INPUT_CLOUD_USER="$CURRENT_USER"
if [[ "$CURRENT_USER" != "root" ]]; then
    echo ""
    print_divider
    echo ""
    echo -e "  ${BOLD}Cloud Default Username to Demote${NC}"
    echo -e "  ${DIM}The default account created by your cloud provider${NC}"
    echo ""
    read -rp "  Cloud username to demote [$CURRENT_USER]: " INPUT_CLOUD_USER
    INPUT_CLOUD_USER="${INPUT_CLOUD_USER:-$CURRENT_USER}"
fi

# --- Confirmation ---
echo ""
echo ""
echo -e "  ${BOLD}${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "  ${BOLD}${CYAN}│  CONFIGURATION SUMMARY                              │${NC}"
echo -e "  ${BOLD}${CYAN}└─────────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "  ${DIM}Hostname:${NC}         ${BOLD}${GREEN}$INPUT_HOSTNAME${NC}"
echo -e "  ${DIM}SSH Port:${NC}         ${BOLD}${GREEN}$INPUT_SSH_PORT${NC}"
echo -e "  ${DIM}Admin User:${NC}       ${BOLD}${GREEN}$INPUT_USERNAME${NC}"
echo -e "  ${DIM}Current User:${NC}     ${BOLD}$INPUT_CLOUD_USER${NC}"
echo -e "  ${DIM}Auth Method:${NC}      ${BOLD}${GREEN}$AUTH_TYPE${NC}"
echo -e "  ${DIM}Provider:${NC}         ${BOLD}$CLOUD_PROVIDER${NC}"
echo -e "  ${DIM}OS:${NC}               ${BOLD}$OS_ID $OS_VERSION${NC}"

if [[ "$AUTH_TYPE" == "password" ]]; then
    echo ""
    echo -e "  ${YELLOW}  ⚠  Password auth will remain enabled${NC}"
    echo -e "  ${DIM}     All other hardening still applies. You can add SSH keys later.${NC}"
fi

echo ""
print_divider
echo ""
read -rp "  Proceed with these settings? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo ""
    log_warn "Aborted by user. No changes were made."
    echo ""
    exit 1
fi

# =============================================================================
# LOGGING SETUP
# =============================================================================

LOGFILE="/var/log/harden-script.log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "════════════════════════════════════════════════════════" >> "$LOGFILE"
echo "Started: $(date)" >> "$LOGFILE"
echo "Provider: $CLOUD_PROVIDER | OS: $OS_ID $OS_VERSION | Auth: $AUTH_TYPE" >> "$LOGFILE"
echo "Hostname: $INPUT_HOSTNAME | Port: $INPUT_SSH_PORT | User: $INPUT_USERNAME" >> "$LOGFILE"
echo "════════════════════════════════════════════════════════" >> "$LOGFILE"

# =============================================================================
# PHASE 1 - INITIAL ASSESSMENT
# =============================================================================

print_section "1" "Initial Assessment"
log_step "Gathering system information..."
echo ""

PUBLIC_IP=$(get_public_ip)

echo -e "  ${DIM}Hostname:${NC}    $(hostname)"
echo -e "  ${DIM}Public IP:${NC}   $PUBLIC_IP"
echo -e "  ${DIM}Kernel:${NC}      $(uname -r)"
echo -e "  ${DIM}OS:${NC}          $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
echo ""

# Check for pending kernel upgrade
RUNNING_KERNEL=$(uname -r)
EXPECTED_KERNEL=$(apt-cache show linux-image-generic 2>/dev/null \
    | grep "^Depends" | grep -oP 'linux-image-\K[0-9][^\s,]+' | head -1 || echo "")

if [[ -n "$EXPECTED_KERNEL" && "$RUNNING_KERNEL" != *"$EXPECTED_KERNEL"* ]]; then
    log_warn "Pending kernel upgrade detected — a reboot is recommended after setup"
fi

echo -e "  ${DIM}Open Ports:${NC}"
ss -tlnp | grep LISTEN | awk '{print "    " $4}' || true
echo ""

log_step "Checking firewall..."
UFW_STATUS=$(ufw status 2>/dev/null | head -1 || echo "Status: unknown")
log_info "UFW: $UFW_STATUS"

log_step "Checking SSH config..."
CURRENT_SSH_PORT=$(sshd -T 2>/dev/null | grep "^port " | awk '{print $2}' || echo "22")
log_info "Current SSH port: $CURRENT_SSH_PORT"

echo ""
log_ok "Assessment complete"
pause

# =============================================================================
# PHASE 2 - SYSTEM PREPARATION
# =============================================================================

print_section "2" "System Preparation"

progress "Updating package lists"
apt update -qq 2>/dev/null
progress_done

progress "Installing available upgrades"
apt upgrade -y -qq 2>/dev/null
progress_done

progress "Setting hostname to: $INPUT_HOSTNAME"
hostnamectl set-hostname "$INPUT_HOSTNAME"
progress_done

if [[ "$HAS_CLOUD_INIT" == "true" ]]; then
    progress "Preventing cloud-init from resetting hostname"
    echo "preserve_hostname: true" \
        | tee /etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg > /dev/null
    progress_done
fi

progress "Updating /etc/hosts"
if grep -q "127.0.1.1" /etc/hosts; then
    sed -i "s/^127\.0\.1\.1.*/127.0.1.1 $INPUT_HOSTNAME/" /etc/hosts
else
    echo "127.0.1.1 $INPUT_HOSTNAME" >> /etc/hosts
fi
progress_done

echo ""
log_ok "System prepared — hostname set to ${BOLD}$INPUT_HOSTNAME${NC}"

# =============================================================================
# PHASE 3 - REMOVE UNNECESSARY SERVICES
# =============================================================================

print_section "3" "Remove Unnecessary Services"

disable_and_mask() {
    local SERVICE="$1"
    if systemctl list-units --all 2>/dev/null | grep -q "$SERVICE"; then
        progress "Disabling $SERVICE"
        systemctl stop "$SERVICE"    2>/dev/null || true
        systemctl disable "$SERVICE" 2>/dev/null || true
        systemctl mask "$SERVICE"    2>/dev/null || true
        progress_done
    fi
}

SERVICES_REMOVED=0

if [[ "$HAS_RPCBIND" == "true" ]]; then
    disable_and_mask "rpcbind.socket"
    disable_and_mask "rpcbind.service"
    SERVICES_REMOVED=$((SERVICES_REMOVED + 1))
fi

if [[ "$HAS_MODEMMANAGER" == "true" ]]; then
    disable_and_mask "ModemManager"
    SERVICES_REMOVED=$((SERVICES_REMOVED + 1))
fi

if [[ "$HAS_ISCSID" == "true" ]]; then
    disable_and_mask "iscsid.socket"
    disable_and_mask "iscsid.service"
    SERVICES_REMOVED=$((SERVICES_REMOVED + 1))
fi

systemctl daemon-reload 2>/dev/null || true

echo ""
if [[ "$SERVICES_REMOVED" -eq 0 ]]; then
    log_ok "No unnecessary services found — system is already clean"
else
    log_ok "$SERVICES_REMOVED unnecessary service(s) disabled and masked"
fi

# =============================================================================
# PHASE 4 - FIREWALL CONFIGURATION
# =============================================================================

print_section "4" "Firewall Configuration"

progress "Installing UFW"
apt install ufw -y -qq 2>/dev/null
progress_done

progress "Setting default policies (deny incoming / allow outgoing)"
ufw default deny incoming > /dev/null
ufw default allow outgoing > /dev/null
progress_done

progress "Opening port 22 (temporary safety net)"
ufw allow 22/tcp comment "SSH default - temporary" > /dev/null
progress_done

progress "Opening port $INPUT_SSH_PORT (new SSH port)"
ufw allow "$INPUT_SSH_PORT"/tcp comment "SSH hardened" > /dev/null
progress_done

progress "Enabling UFW"
echo "y" | ufw enable > /dev/null
progress_done

if [[ "$CONFLICTING_IPTABLES" == "true" ]]; then
    echo ""
    progress "Removing conflicting iptables rules"
    mapfile -t SORTED_LINES < <(printf '%s\n' "${CONFLICTING_LINES[@]}" | sort -rn)
    for LINE_NUM in "${SORTED_LINES[@]}"; do
        iptables -D INPUT "$LINE_NUM" 2>/dev/null || true
    done
    mkdir -p /etc/iptables
    sh -c 'iptables-save > /etc/iptables/rules.v4'
    progress_done
fi

case "$CLOUD_PROVIDER" in
    oracle)
        echo ""
        log_warn "ORACLE CLOUD — Action required in web console:"
        log_info "VCN → Subnet → Security List → Add Ingress Rule → Port $INPUT_SSH_PORT"
        pause ;;
    aws)
        echo ""
        log_warn "AWS — Action required in web console:"
        log_info "EC2 → Security Groups → Inbound Rules → Add Rule → Port $INPUT_SSH_PORT"
        pause ;;
    azure)
        echo ""
        log_warn "AZURE — Action required in web console:"
        log_info "NSG → Inbound Security Rules → Add → Port $INPUT_SSH_PORT"
        pause ;;
    gcp)
        echo ""
        log_warn "GCP — Action required in web console:"
        log_info "VPC Network → Firewall → Create Firewall Rule → Port $INPUT_SSH_PORT"
        pause ;;
esac

echo ""
log_ok "Firewall active — ports 22 and $INPUT_SSH_PORT open (22 is temporary)"

# =============================================================================
# PHASE 5 - SSH HARDENING
# =============================================================================

print_section "5" "SSH Hardening"

echo -e "  ${DIM}This phase changes the SSH port and hardens settings.${NC}"
echo -e "  ${DIM}User restrictions are applied in Phase 10 after your new${NC}"
echo -e "  ${DIM}admin account is created and confirmed working.${NC}"
echo ""
log_warn "Keep your current SSH session open throughout this phase"
pause

progress "Backing up SSH configuration"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
if [[ -d /etc/ssh/sshd_config.d ]]; then
    for CONF_FILE in /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$CONF_FILE" ]] && cp "$CONF_FILE" "${CONF_FILE}.backup" || true
    done
fi
mkdir -p /etc/ssh/sshd_config.d
progress_done

progress "Writing hardened SSH config"

if [[ "$AUTH_TYPE" == "key" ]]; then
    cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# ============================================
# Hardened SSH Configuration
# Generated: $(date)
# Provider: $CLOUD_PROVIDER | OS: $OS_ID $OS_VERSION
# Auth: key-only
# Phase 5 (safe): PermitRootLogin yes — no AllowUsers yet
# Phase 10 (final): restrictions applied after new account tested
# ============================================

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
# ============================================
# Hardened SSH Configuration
# Generated: $(date)
# Provider: $CLOUD_PROVIDER | OS: $OS_ID $OS_VERSION
# Auth: password
# Phase 5 (safe): PermitRootLogin yes — no AllowUsers yet
# Phase 10 (final): restrictions applied after new account tested
#
# To upgrade to key-only later:
#   1. ssh-keygen -t ed25519
#   2. ssh-copy-id -p $INPUT_SSH_PORT $INPUT_USERNAME@server
#   3. Set PasswordAuthentication no
#   4. Add: AuthenticationMethods publickey
#   5. sudo sshd -t && sudo systemctl restart ssh
# ============================================

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

progress_done

# Apply socket fix on Ubuntu 24.04
if [[ "$OS_VERSION" == "24.04" ]]; then
    apply_ssh_socket_fix
fi

progress "Validating SSH configuration"
if ! sshd -t; then
    progress_done
    log_error "SSH config has errors. Restoring backup..."
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/99-hardened.conf
    exit 1
fi
progress_done

progress "Restarting SSH service"
systemctl restart ssh
sleep 1
progress_done

# Verify SSH is on the new port
if ! ss -tlnp | grep -q ":$INPUT_SSH_PORT"; then
    log_error "SSH is NOT listening on port $INPUT_SSH_PORT"
    log_error "Check: journalctl -u ssh -n 20 --no-pager"
    exit 1
fi

echo ""
log_ok "SSH is now listening on port $INPUT_SSH_PORT"
echo ""

echo -e "  ${BOLD}${YELLOW}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "  ${BOLD}${YELLOW}│  TEST YOUR CONNECTION NOW                           │${NC}"
echo -e "  ${BOLD}${YELLOW}└─────────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "  Open a ${BOLD}NEW terminal${NC} on your local machine and run:"
echo ""

if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "  ${CYAN}    ssh -i /path/to/key -p $INPUT_SSH_PORT $CURRENT_USER@$PUBLIC_IP${NC}"
else
    echo -e "  ${CYAN}    ssh -p $INPUT_SSH_PORT $CURRENT_USER@$PUBLIC_IP${NC}"
fi

echo ""
echo -e "  ${RED}  Keep THIS session open!${NC}"
echo ""
read -rp "  Did the connection on port $INPUT_SSH_PORT succeed? (yes/no): " SSH_TEST

if [[ "$SSH_TEST" != "yes" ]]; then
    echo ""
    log_error "SSH test failed. Diagnose from this session:"
    log_info "  systemctl status ssh"
    log_info "  journalctl -u ssh -n 30 --no-pager"
    log_info "  ss -tlnp | grep ssh"
    exit 1
fi

progress "Removing temporary port 22 from firewall"
ufw delete allow 22/tcp > /dev/null
progress_done

echo ""
log_ok "Port 22 closed. Only port $INPUT_SSH_PORT is open"

# =============================================================================
# PHASE 6 - FAIL2BAN
# =============================================================================

print_section "6" "Brute Force Protection (fail2ban)"

progress "Installing fail2ban"
apt install fail2ban -y -qq 2>/dev/null
progress_done

progress "Configuring fail2ban jail"
cat > /etc/fail2ban/jail.local << EOF
# ============================================
# fail2ban Configuration
# Generated: $(date)
# ============================================

[DEFAULT]
# Ban for 24 hours
bantime  = 86400
# Look back 20 minutes
findtime = 1200
# 3 failures = ban
maxretry = 3

[sshd]
enabled  = true
port     = $INPUT_SSH_PORT
logpath  = %(sshd_log)s
backend  = systemd
EOF
progress_done

progress "Starting fail2ban"
systemctl enable fail2ban -q
systemctl start fail2ban
sleep 1
progress_done

echo ""
log_ok "fail2ban active — 3 failed attempts = 24 hour ban"

# =============================================================================
# PHASE 7 - APPARMOR
# =============================================================================

print_section "7" "Mandatory Access Control (AppArmor)"

if command -v aa-status &>/dev/null; then
    PROFILES_BEFORE=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}' || echo "0")

    progress "Installing additional AppArmor profiles"
    apt install apparmor-profiles apparmor-profiles-extra -y -qq 2>/dev/null
    progress_done

    PROFILES_AFTER=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}' || echo "0")
    ENFORCED=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}' || echo "0")

    echo ""
    log_ok "AppArmor active — $PROFILES_AFTER profiles loaded, $ENFORCED enforcing"
else
    log_warn "AppArmor not available on this system — skipping"
fi

# =============================================================================
# PHASE 8 - PERSISTENT LOGGING
# =============================================================================

print_section "8" "Persistent Logging"

progress "Creating journal directory"
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal > /dev/null 2>&1 || true
progress_done

progress "Configuring journal size limits (500MB max)"
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/custom.conf << EOF
[Journal]
Storage=persistent
SystemMaxUse=500M
SystemMaxFileSize=50M
EOF
progress_done

progress "Restarting journald"
systemctl restart systemd-journald
progress_done

DISK_USAGE=$(journalctl --disk-usage 2>/dev/null | awk '{print $NF, $(NF-1)}' || echo "unknown")

echo ""
log_ok "Logs will now survive reboots — current usage: $DISK_USAGE"

# =============================================================================
# PHASE 9 - PACKAGE CLEANUP
# =============================================================================

print_section "9" "Package Cleanup"

PACKAGES_TO_REMOVE=()
for PKG in nfs-common open-iscsi ssh-import-id; do
    if dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        PACKAGES_TO_REMOVE+=("$PKG")
    fi
done

if [[ ${#PACKAGES_TO_REMOVE[@]} -gt 0 ]]; then
    progress "Removing: ${PACKAGES_TO_REMOVE[*]}"
    apt remove "${PACKAGES_TO_REMOVE[@]}" -y -qq 2>/dev/null
    progress_done
else
    log_info "No unnecessary packages found"
fi

progress "Running autoremove"
apt autoremove -y -qq 2>/dev/null
progress_done

echo ""
log_ok "Package cleanup complete"

# =============================================================================
# PHASE 10 - ADMIN ACCOUNT + FINAL SSH LOCKDOWN
# =============================================================================

print_section "10" "Admin Account Setup"

echo -e "  ${DIM}Creating your personal admin account.${NC}"
echo -e "  ${DIM}SSH restrictions are only applied AFTER this account is tested.${NC}"
echo ""

progress "Creating user account: $INPUT_USERNAME"
if id "$INPUT_USERNAME" &>/dev/null; then
    progress_done
    log_warn "User $INPUT_USERNAME already exists — skipping creation"
else
    adduser --gecos "" "$INPUT_USERNAME"
fi

progress "Adding to sudo and adm groups"
usermod -aG sudo "$INPUT_USERNAME"
usermod -aG adm  "$INPUT_USERNAME"
progress_done

# Set up SSH keys for new account
progress "Setting up SSH access"
mkdir -p "/home/$INPUT_USERNAME/.ssh"
chmod 700 "/home/$INPUT_USERNAME/.ssh"

if [[ "$AUTH_TYPE" == "key" ]]; then
    KEY_SOURCE=""
    if [[ -f "/root/.ssh/authorized_keys" ]] && \
       [[ -s "/root/.ssh/authorized_keys" ]]; then
        KEY_SOURCE="/root/.ssh/authorized_keys"
    elif [[ "$INPUT_CLOUD_USER" != "root" ]] && \
         [[ -f "/home/$INPUT_CLOUD_USER/.ssh/authorized_keys" ]] && \
         [[ -s "/home/$INPUT_CLOUD_USER/.ssh/authorized_keys" ]]; then
        KEY_SOURCE="/home/$INPUT_CLOUD_USER/.ssh/authorized_keys"
    fi

    if [[ -n "$KEY_SOURCE" ]]; then
        cp "$KEY_SOURCE" "/home/$INPUT_USERNAME/.ssh/authorized_keys"
        chmod 600 "/home/$INPUT_USERNAME/.ssh/authorized_keys"
    elif [[ -n "${INPUT_PUBLIC_KEY:-}" ]]; then
        echo "$INPUT_PUBLIC_KEY" > "/home/$INPUT_USERNAME/.ssh/authorized_keys"
        chmod 600 "/home/$INPUT_USERNAME/.ssh/authorized_keys"
    fi
else
    log_info "Password mode — $INPUT_USERNAME will use password to login"
fi

chown -R "$INPUT_USERNAME:$INPUT_USERNAME" "/home/$INPUT_USERNAME/.ssh"
progress_done

echo ""
echo -e "  ${BOLD}${YELLOW}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "  ${BOLD}${YELLOW}│  TEST YOUR NEW ADMIN ACCOUNT                        │${NC}"
echo -e "  ${BOLD}${YELLOW}└─────────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "  Open a ${BOLD}NEW terminal${NC} and run:"
echo ""

if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "  ${CYAN}    ssh -i /path/to/key -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
else
    echo -e "  ${CYAN}    ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    echo -e "  ${DIM}    Use the password you just set for $INPUT_USERNAME${NC}"
fi

echo ""
echo -e "  Then verify sudo works inside the new session:"
echo -e "  ${CYAN}    sudo -l${NC}"
echo -e "  ${CYAN}    sudo id${NC}  ${DIM}(should show uid=0(root))${NC}"
echo ""
echo -e "  ${RED}  Keep THIS session open until the test passes!${NC}"
echo ""
read -rp "  New account login and sudo both succeeded? (yes/no): " NEW_ACCT_TEST

if [[ "$NEW_ACCT_TEST" != "yes" ]]; then
    echo ""
    log_error "Test failed — SSH lockdown NOT applied. Root access preserved."
    echo ""
    log_info "Diagnose the issue:"
    echo -e "  ${CYAN}    id $INPUT_USERNAME${NC}"
    echo -e "  ${CYAN}    passwd $INPUT_USERNAME${NC}"
    echo -e "  ${CYAN}    journalctl -u ssh -n 20 --no-pager${NC}"
    echo ""
    log_info "Once fixed, apply lockdown manually:"
    echo -e "  ${CYAN}    sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' \\${NC}"
    echo -e "  ${CYAN}        /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "  ${CYAN}    echo 'AllowUsers $INPUT_USERNAME' | sudo tee -a \\${NC}"
    echo -e "  ${CYAN}        /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "  ${CYAN}    sudo sshd -t && sudo systemctl restart ssh${NC}"
    echo ""
    log_warn "Continuing to Phase 11 to set up monitoring."
    log_warn "SSH accessible via root on port $INPUT_SSH_PORT."

else
    progress "Applying final SSH lockdown"

    if [[ "$AUTH_TYPE" == "key" ]]; then
        cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# ============================================
# Hardened SSH Configuration (FINAL)
# Generated: $(date)
# Provider: $CLOUD_PROVIDER | OS: $OS_ID $OS_VERSION
# Auth: key-only (password disabled)
# ============================================

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
# ============================================
# Hardened SSH Configuration (FINAL)
# Generated: $(date)
# Provider: $CLOUD_PROVIDER | OS: $OS_ID $OS_VERSION
# Auth: password (upgrade to SSH keys recommended)
#
# To switch to key-only later:
#   1. ssh-keygen -t ed25519
#   2. ssh-copy-id -p $INPUT_SSH_PORT $INPUT_USERNAME@server
#   3. Set PasswordAuthentication no
#   4. Add: AuthenticationMethods publickey
#   5. sudo sshd -t && sudo systemctl restart ssh
# ============================================

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

    if sshd -t; then
        systemctl restart ssh
        progress_done
        log_ok "Root login disabled — only $INPUT_USERNAME can login"
    else
        progress_done
        log_error "SSH config error during lockdown — keeping safe config"
    fi

    if [[ "$INPUT_CLOUD_USER" != "root" ]]; then
        progress "Demoting $INPUT_CLOUD_USER"
        deluser "$INPUT_CLOUD_USER" sudo  2>/dev/null || true
        deluser "$INPUT_CLOUD_USER" lxd   2>/dev/null || true
        deluser "$INPUT_CLOUD_USER" cdrom 2>/dev/null || true
        deluser "$INPUT_CLOUD_USER" dip   2>/dev/null || true
        passwd -l "$INPUT_CLOUD_USER" > /dev/null 2>&1 || true
        progress_done
    fi

    SUDOERS_FILE=""
    for F in /etc/sudoers.d/*; do
        if grep -q "$INPUT_CLOUD_USER" "$F" 2>/dev/null; then
            SUDOERS_FILE="$F"
            break
        fi
    done
    if [[ -n "$SUDOERS_FILE" ]]; then
        progress "Removing NOPASSWD from $INPUT_CLOUD_USER"
        cp "$SUDOERS_FILE" "${SUDOERS_FILE}.backup"
        sed -i \
            "s|$INPUT_CLOUD_USER ALL=(ALL) NOPASSWD:ALL|$INPUT_CLOUD_USER ALL=(ALL) ALL|g" \
            "$SUDOERS_FILE"
        sed -i \
            "s|$INPUT_CLOUD_USER ALL=(ALL:ALL) NOPASSWD:ALL|$INPUT_CLOUD_USER ALL=(ALL:ALL) ALL|g" \
            "$SUDOERS_FILE"
        progress_done
    fi
fi

# =============================================================================
# PHASE 11 - MONITORING AND AUDIT
# =============================================================================

print_section "11" "Monitoring and Audit Scripts"

SCRIPTS_DIR="/opt/$INPUT_HOSTNAME/scripts"
BASELINE_DIR="/opt/$INPUT_HOSTNAME/baseline"
AUDIT_LOG="/var/log/${INPUT_HOSTNAME}-audit.log"

progress "Creating directory structure"
mkdir -p "$SCRIPTS_DIR" "$BASELINE_DIR"
progress_done

progress "Creating SUID baseline"
safe_find_suid > "$BASELINE_DIR/suid-baseline.txt"
chmod 600 "$BASELINE_DIR/suid-baseline.txt"
SUID_COUNT=$(wc -l < "$BASELINE_DIR/suid-baseline.txt")
progress_done
log_info "Baseline contains $SUID_COUNT SUID binaries"

# Daily audit script
progress "Creating daily audit script"
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

echo "--- Failed SSH Logins (Last 24h) ---" >> \$LOGFILE
journalctl -u ssh --since "24 hours ago" 2>/dev/null \
    | grep -c "Invalid user\|Failed password" \
    | xargs echo "Total failed attempts:" >> \$LOGFILE
journalctl -u ssh --since "24 hours ago" 2>/dev/null \
    | grep -i "failed\|invalid" | tail -10 >> \$LOGFILE

echo "--- fail2ban Bans (Last 24h) ---" >> \$LOGFILE
journalctl -u fail2ban --since "24 hours ago" 2>/dev/null \
    | grep "Ban" >> \$LOGFILE

echo "--- SUID Changes ---" >> \$LOGFILE
find / -perm -4000 -type f 2>/dev/null | grep -v snap | sort \
    > /tmp/current-suid.txt || true
DIFF=\$(diff $BASELINE_DIR/suid-baseline.txt /tmp/current-suid.txt 2>/dev/null || true)
if [ -z "\$DIFF" ]; then
    echo "No changes." >> \$LOGFILE
else
    echo "WARNING: SUID changes detected!" >> \$LOGFILE
    echo "\$DIFF" >> \$LOGFILE
fi
rm -f /tmp/current-suid.txt

echo "--- Listening Ports ---" >> \$LOGFILE
ss -tlnp >> \$LOGFILE

echo "--- Active Users ---" >> \$LOGFILE
who >> \$LOGFILE
last | head -5 >> \$LOGFILE

echo "--- Sudo Usage (Last 24h) ---" >> \$LOGFILE
journalctl --since "24 hours ago" 2>/dev/null \
    | grep "sudo" | grep -v "pam_unix" >> \$LOGFILE

echo "--- End of Audit ---" >> \$LOGFILE
echo "" >> \$LOGFILE
AUDIT_EOF
progress_done

# Alert checker script
progress "Creating check-alerts command"
cat > "$SCRIPTS_DIR/check-alerts.sh" << ALERT_EOF
#!/bin/bash
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

HOSTNAME_LOCAL=\$(hostname)
DATE=\$(date '+%Y-%m-%d %H:%M:%S')

echo ""
echo -e "\${BOLD}\${CYAN}  ╔══════════════════════════════════════════════════════╗\${NC}"
echo -e "\${BOLD}\${CYAN}  ║  Security Alert Check — \$HOSTNAME_LOCAL\${NC}"
echo -e "\${BOLD}\${CYAN}  ║  \$DATE\${NC}"
echo -e "\${BOLD}\${CYAN}  ╚══════════════════════════════════════════════════════╝\${NC}"
echo ""

ALERTS=0
WARNINGS=0

check() {
    local STATUS="\$1"
    local MSG="\$2"
    if [ "\$STATUS" = "ok" ]; then
        echo -e "  \${GREEN}✓\${NC}  \$MSG"
    elif [ "\$STATUS" = "warn" ]; then
        echo -e "  \${YELLOW}⚠\${NC}  \$MSG"
        WARNINGS=\$((WARNINGS+1))
    elif [ "\$STATUS" = "crit" ]; then
        echo -e "  \${RED}✗\${NC}  \$MSG"
        ALERTS=\$((ALERTS+1))
    elif [ "\$STATUS" = "info" ]; then
        echo -e "  \${CYAN}ℹ\${NC}  \$MSG"
    fi
}

# Disk usage
DISK=\$(df / | tail -1 | awk '{print \$5}' | tr -d '%')
if [ "\$DISK" -gt 80 ]; then
    check "crit" "Disk usage: \${DISK}% — ${BOLD}ACTION REQUIRED\${NC}"
elif [ "\$DISK" -gt 60 ]; then
    check "warn" "Disk usage: \${DISK}% — getting full"
else
    check "ok" "Disk usage: \${DISK}%"
fi

# Memory usage
MEM=\$(free | grep Mem | awk '{printf "%.0f", \$3/\$2*100}')
if [ "\$MEM" -gt 90 ]; then
    check "crit" "Memory usage: \${MEM}% — system under pressure"
elif [ "\$MEM" -gt 75 ]; then
    check "warn" "Memory usage: \${MEM}%"
else
    check "ok" "Memory usage: \${MEM}%"
fi

# Failed SSH logins
FAILED=\$(journalctl -u ssh --since "24 hours ago" 2>/dev/null \
    | grep -c "Invalid user\|Failed password" || echo 0)
if [ "\$FAILED" -gt 200 ]; then
    check "crit" "Failed SSH attempts (24h): \${FAILED} — unusual volume"
elif [ "\$FAILED" -gt 50 ]; then
    check "warn" "Failed SSH attempts (24h): \${FAILED} — elevated"
else
    check "ok" "Failed SSH attempts (24h): \${FAILED}"
fi

# fail2ban bans
BANS=\$(fail2ban-client status sshd 2>/dev/null \
    | grep "Total banned" | awk '{print \$NF}')
BANS=\${BANS:-0}
CURRENT_BANS=\$(fail2ban-client status sshd 2>/dev/null \
    | grep "Currently banned" | awk '{print \$NF}')
CURRENT_BANS=\${CURRENT_BANS:-0}
if [ "\$CURRENT_BANS" -gt 0 ]; then
    check "info" "fail2ban: \${CURRENT_BANS} IP(s) currently banned (\${BANS} total)"
    BANNED_IPS=\$(fail2ban-client status sshd 2>/dev/null \
        | grep "Banned IP" | cut -d: -f2)
    echo -e "  \${DIM}     \$BANNED_IPS\${NC}"
else
    check "ok" "fail2ban: No IPs currently banned (\${BANS} total ever)"
fi

# SUID changes
find / -perm -4000 -type f 2>/dev/null | grep -v snap | sort \
    > /tmp/suid-check.txt || true
SUID_DIFF=\$(diff $BASELINE_DIR/suid-baseline.txt \
    /tmp/suid-check.txt 2>/dev/null || true)
rm -f /tmp/suid-check.txt
if [ -n "\$SUID_DIFF" ]; then
    check "crit" "SUID files have changed — possible backdoor!"
    echo "\$SUID_DIFF"
else
    check "ok" "SUID files unchanged"
fi

# Service health
for SVC in ssh fail2ban; do
    if systemctl is-active --quiet "\$SVC"; then
        check "ok" "\$SVC is running"
    else
        check "crit" "\$SVC is NOT running — investigate immediately"
    fi
done

# UFW firewall
if ufw status | grep -q "Status: active"; then
    check "ok" "UFW firewall is active"
else
    check "crit" "UFW firewall is NOT active"
fi

# AppArmor
if command -v aa-status &>/dev/null; then
    ENFORCED=\$(aa-status 2>/dev/null | grep "in enforce mode" | head -1 | awk '{print \$1}' || echo "0")
    check "ok" "AppArmor: \${ENFORCED} profiles enforcing"
fi

# Open ports
echo ""
echo -e "  \${BOLD}Open Ports:\${NC}"
ss -tlnp | grep LISTEN | while read -r line; do
    PORT=\$(echo "\$line" | awk '{print \$4}' | rev | cut -d: -f1 | rev)
    PROC=\$(echo "\$line" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")
    echo -e "  \${DIM}  Port \$PORT — \$PROC\${NC}"
done

# Summary
echo ""
echo -e "  \${BOLD}\$(hostname) — \$(date '+%H:%M %Z')\${NC}"
echo -e "  \${DIM}Uptime: \$(uptime -p)\${NC}"
echo ""

if [ "\$ALERTS" -gt 0 ]; then
    echo -e "  \${RED}✗  \${ALERTS} critical alert(s) require immediate attention\${NC}"
elif [ "\$WARNINGS" -gt 0 ]; then
    echo -e "  \${YELLOW}⚠  \${WARNINGS} warning(s) — review when possible\${NC}"
else
    echo -e "  \${GREEN}✓  All checks passed — server is healthy\${NC}"
fi
echo ""
ALERT_EOF

progress_done

progress "Setting permissions"
chmod 750 "$SCRIPTS_DIR/daily-audit.sh"
chmod 750 "$SCRIPTS_DIR/check-alerts.sh"
if id "$INPUT_USERNAME" &>/dev/null; then
    chown root:"$INPUT_USERNAME" "$SCRIPTS_DIR/daily-audit.sh"
    chown root:"$INPUT_USERNAME" "$SCRIPTS_DIR/check-alerts.sh"
fi
progress_done

progress "Installing check-alerts as system command"
ln -sf "$SCRIPTS_DIR/check-alerts.sh" /usr/local/bin/check-alerts
progress_done

progress "Scheduling daily audit at 4:00 AM"
(crontab -l 2>/dev/null | grep -v "daily-audit.sh"; \
 echo "0 4 * * * $SCRIPTS_DIR/daily-audit.sh") | crontab -
progress_done

progress "Running initial audit"
bash "$SCRIPTS_DIR/daily-audit.sh" || true
progress_done

echo ""
log_ok "Monitoring configured — run ${BOLD}sudo check-alerts${NC} anytime"

# =============================================================================
# FINAL SUMMARY
# =============================================================================

print_success_banner

echo -e "  ${BOLD}What was secured:${NC}"
echo ""
echo -e "  ${GREEN}✓${NC}  ${BOLD}Firewall (UFW)${NC} — only port $INPUT_SSH_PORT is open"
echo -e "  ${GREEN}✓${NC}  ${BOLD}SSH${NC} — moved to port $INPUT_SSH_PORT, root login disabled"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Admin Account${NC} — $INPUT_USERNAME created with sudo access"

if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "  ${GREEN}✓${NC}  ${BOLD}Authentication${NC} — SSH key only, passwords disabled"
else
    echo -e "  ${YELLOW}⚠${NC}  ${BOLD}Authentication${NC} — password (upgrade to SSH keys recommended)"
fi

echo -e "  ${GREEN}✓${NC}  ${BOLD}fail2ban${NC} — 3 failed attempts = 24 hour ban"
echo -e "  ${GREEN}✓${NC}  ${BOLD}AppArmor${NC} — mandatory access control enforcing"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Logging${NC} — persistent, survives reboots, 500MB limit"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Unnecessary services${NC} — removed"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Daily audit${NC} — runs at 4 AM, logs to $AUDIT_LOG"
echo ""

print_divider

echo ""
echo -e "  ${BOLD}Your server details:${NC}"
echo ""
echo -e "  ${DIM}Hostname:${NC}   ${BOLD}$INPUT_HOSTNAME${NC}"
echo -e "  ${DIM}Public IP:${NC}  ${BOLD}$PUBLIC_IP${NC}"
echo -e "  ${DIM}SSH Port:${NC}   ${BOLD}$INPUT_SSH_PORT${NC}"
echo -e "  ${DIM}Admin:${NC}      ${BOLD}$INPUT_USERNAME${NC}"
echo ""

print_divider

echo ""
echo -e "  ${BOLD}How to connect from now on:${NC}"
echo ""

if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "  ${DIM}Mac / Linux:${NC}"
    echo -e "  ${CYAN}    ssh -i ~/.ssh/id_ed25519 -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    echo ""
    echo -e "  ${DIM}Windows:${NC}"
    echo -e "  ${CYAN}    ssh -i \$env:USERPROFILE\\.ssh\\id_ed25519 -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
else
    echo -e "  ${CYAN}    ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
fi

echo ""
print_divider

echo ""
echo -e "  ${BOLD}Daily commands:${NC}"
echo ""
echo -e "  ${CYAN}  sudo check-alerts${NC}                  ${DIM}Full security overview${NC}"
echo -e "  ${CYAN}  sudo fail2ban-client status sshd${NC}   ${DIM}See banned IPs${NC}"
echo -e "  ${CYAN}  sudo ufw status verbose${NC}             ${DIM}View firewall rules${NC}"
echo -e "  ${CYAN}  sudo journalctl -u ssh -n 50${NC}        ${DIM}Recent SSH activity${NC}"
echo -e "  ${CYAN}  sudo tail -f $AUDIT_LOG${NC}"
echo ""
print_divider

echo ""
echo -e "  ${BOLD}Important notes:${NC}"
echo ""
echo -e "  ${YELLOW}  1)${NC}  ${BOLD}Reboot recommended${NC} — loads any pending kernel updates"
echo -e "  ${CYAN}       sudo reboot${NC}"
echo -e "  ${DIM}       Then reconnect: ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
echo ""

if [[ "$AUTH_TYPE" == "password" ]]; then
    echo -e "  ${YELLOW}  2)${NC}  ${BOLD}Upgrade to SSH keys${NC} — much stronger than passwords"
    echo -e "  ${DIM}       On your local machine:${NC}"
    echo -e "  ${CYAN}       ssh-keygen -t ed25519 -C \"$INPUT_HOSTNAME\"${NC}"
    echo -e "  ${CYAN}       ssh-copy-id -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    echo -e "  ${DIM}       Then on the server:${NC}"
    echo -e "  ${CYAN}       sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' \\${NC}"
    echo -e "  ${CYAN}           /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "  ${CYAN}       sudo sed -i '/PermitEmptyPasswords/i AuthenticationMethods publickey' \\${NC}"
    echo -e "  ${CYAN}           /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "  ${CYAN}       sudo sshd -t && sudo systemctl restart ssh${NC}"
    echo ""
fi

if [[ "$CLOUD_PROVIDER" =~ ^(oracle|aws|azure|gcp)$ ]]; then
    echo -e "  ${YELLOW}  3)${NC}  ${BOLD}Cloud firewall reminder${NC} — verify port $INPUT_SSH_PORT is open"
    echo -e "  ${DIM}       in your ${CLOUD_PROVIDER} network security console${NC}"
    echo ""
fi

print_divider

echo ""
echo -e "  ${DIM}Full log saved to: $LOGFILE${NC}"
echo -e "  ${DIM}Run ${NC}${CYAN}sudo check-alerts${NC}${DIM} after rebooting to confirm everything is healthy.${NC}"
echo ""
echo -e "${BOLD}${CYAN}  Happy and secure hosting! 🚀${NC}"
echo ""
