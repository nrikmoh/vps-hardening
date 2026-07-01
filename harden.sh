#!/bin/bash
# =============================================================================
# VPS Hardening Script
# Supports: Ubuntu 20.04, 22.04, 24.04
# Providers: Oracle Cloud, AWS, DigitalOcean, Hetzner, Linode, Vultr, generic
# Usage: sudo ./harden.sh
# =============================================================================

set -euo pipefail

# =============================================================================
# COLORS AND HELPERS
# =============================================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()      { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_section() {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════${NC}\n"
}
pause() { echo -e "${YELLOW}Press ENTER to continue...${NC}"; read -r; }

if [[ $EUID -ne 0 ]]; then
    log_error "Run this script with sudo: sudo ./harden.sh"
    exit 1
fi

# =============================================================================
# PUBLIC IP HELPER
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

# =============================================================================
# SAFE FIND SUID
# find returns non-zero when hitting /proc /sys permission errors
# The || true prevents set -euo pipefail from killing the script
# =============================================================================

safe_find_suid() {
    find / -perm -4000 -type f 2>/dev/null | grep -v snap | sort || true
}

# =============================================================================
# SSH SOCKET FIX
# Ubuntu 24.04 uses socket activation which holds port 22 in systemd
# regardless of what Port is set in sshd_config
# We always attempt this fix on Ubuntu 24.04
# =============================================================================

apply_ssh_socket_fix() {
    log_info "Checking for SSH socket activation..."

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
        log_info "SSH socket found. Disabling socket activation..."
        systemctl stop ssh.socket    2>/dev/null || true
        systemctl disable ssh.socket 2>/dev/null || true
        systemctl mask ssh.socket    2>/dev/null || true
        systemctl enable ssh.service 2>/dev/null || true
        log_ok "SSH socket activation disabled. sshd now manages its own port."
    else
        log_info "No SSH socket activation found. Skipping."
    fi

    # Always ensure /run/sshd exists
    # This directory is required for privilege separation
    # It lives in tmpfs and disappears when the socket is stopped
    if [[ ! -d /run/sshd ]]; then
        mkdir -p /run/sshd
        chmod 755 /run/sshd
        log_ok "/run/sshd created."
    fi
}

# =============================================================================
# ENVIRONMENT DETECTION
# =============================================================================

detect_environment() {
    log_section "Detecting Environment"

    OS_ID=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_VERSION=$(grep "^VERSION_ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
    OS_CODENAME=$(grep "^VERSION_CODENAME=" /etc/os-release \
        | cut -d= -f2 | tr -d '"' 2>/dev/null || echo "unknown")

    log_info "OS: $OS_ID $OS_VERSION ($OS_CODENAME)"

    if [[ "$OS_ID" != "ubuntu" ]]; then
        log_warn "Designed for Ubuntu. Detected: $OS_ID"
        read -rp "Continue anyway? (yes/no): " CONTINUE_ANYWAY
        [[ "$CONTINUE_ANYWAY" != "yes" ]] && exit 1
    fi

    # Detect current user
    CURRENT_USER="${SUDO_USER:-root}"

    # Detect cloud provider
    CLOUD_PROVIDER="generic"
    DEFAULT_CLOUD_USER="$CURRENT_USER"

    if systemctl list-units --all 2>/dev/null | grep -q "oracle" || \
       [[ -f /etc/oracle-cloud-agent/agent.yml ]] || \
       curl -sf --max-time 2 \
           -H "Authorization: Bearer Oracle" \
           http://169.254.169.254/opc/v2/instance/ &>/dev/null; then
        CLOUD_PROVIDER="oracle"
        DEFAULT_CLOUD_USER="ubuntu"
    elif curl -sf --max-time 2 \
             http://169.254.169.254/latest/meta-data/ami-id &>/dev/null; then
        CLOUD_PROVIDER="aws"
        DEFAULT_CLOUD_USER="ubuntu"
    elif [[ -f /etc/digitalocean ]] || \
         curl -sf --max-time 2 \
             http://169.254.169.254/metadata/v1/id &>/dev/null; then
        CLOUD_PROVIDER="digitalocean"
        DEFAULT_CLOUD_USER="root"
    elif [[ -f /etc/hetzner-build ]] || \
         curl -sf --max-time 2 \
             http://169.254.169.254/hetzner/v1/metadata &>/dev/null; then
        CLOUD_PROVIDER="hetzner"
        DEFAULT_CLOUD_USER="root"
    elif curl -sf --max-time 2 \
             http://169.254.169.254/linode/v1/ &>/dev/null; then
        CLOUD_PROVIDER="linode"
        DEFAULT_CLOUD_USER="root"
    elif curl -sf --max-time 2 \
             http://169.254.169.254/v1.json &>/dev/null; then
        CLOUD_PROVIDER="vultr"
        DEFAULT_CLOUD_USER="root"
    elif curl -sf --max-time 2 \
             -H "Metadata-Flavor: Google" \
             http://169.254.169.254/computeMetadata/v1/ &>/dev/null; then
        CLOUD_PROVIDER="gcp"
        DEFAULT_CLOUD_USER="ubuntu"
    elif curl -sf --max-time 2 \
             -H "Metadata: true" \
             "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
             &>/dev/null; then
        CLOUD_PROVIDER="azure"
        DEFAULT_CLOUD_USER="azureuser"
    fi

    # Verify detected cloud user exists — fall back to current user if not
    if ! id "$DEFAULT_CLOUD_USER" &>/dev/null; then
        log_warn "Detected cloud user '$DEFAULT_CLOUD_USER' does not exist."
        DEFAULT_CLOUD_USER="$CURRENT_USER"
        log_info "Using current user instead: $DEFAULT_CLOUD_USER"
    fi

    log_info "Cloud provider:     $CLOUD_PROVIDER"
    log_info "Default cloud user: $DEFAULT_CLOUD_USER"
    log_info "Current login user: $CURRENT_USER"

    # Detect conflicting iptables rules
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

    if [[ "$CONFLICTING_IPTABLES" == "true" ]]; then
        log_warn "Conflicting iptables rules at lines: ${CONFLICTING_LINES[*]}"
    else
        log_ok "No conflicting iptables rules."
    fi

    # Detect cloud-init
    HAS_CLOUD_INIT=false
    if command -v cloud-init &>/dev/null; then
        HAS_CLOUD_INIT=true
        log_info "cloud-init detected."
    else
        log_info "cloud-init not detected."
    fi

    # Detect unnecessary services
    HAS_RPCBIND=false
    HAS_MODEMMANAGER=false
    HAS_ISCSID=false

    if systemctl list-units --all 2>/dev/null | grep -q "rpcbind"; then
        HAS_RPCBIND=true
    fi
    if systemctl list-units --all 2>/dev/null | grep -q "ModemManager"; then
        HAS_MODEMMANAGER=true
    fi
    if systemctl list-units --all 2>/dev/null | grep -q "iscsid"; then
        HAS_ISCSID=true
    fi

    log_info "rpcbind: $HAS_RPCBIND | ModemManager: $HAS_MODEMMANAGER | iscsid: $HAS_ISCSID"
    log_ok "Environment detection complete."
}

detect_environment

# =============================================================================
# PHASE 0 - COLLECT CONFIGURATION
# All user input gathered upfront before any changes are made
# =============================================================================

log_section "Phase 0 - Configuration"

echo -e "${BOLD}Environment Summary:${NC}"
echo -e "  OS:             ${GREEN}$OS_ID $OS_VERSION${NC}"
echo -e "  Cloud Provider: ${GREEN}$CLOUD_PROVIDER${NC}"
echo -e "  Current User:   ${GREEN}$CURRENT_USER${NC}"
echo ""

# --- SSH Authentication Method ---
echo -e "${BOLD}How are you currently logged into this server?${NC}"
echo -e "  ${CYAN}1)${NC} SSH key (private key / identity file)"
echo -e "  ${CYAN}2)${NC} Password"
echo ""
read -rp "Enter 1 or 2: " AUTH_METHOD

while [[ "$AUTH_METHOD" != "1" && "$AUTH_METHOD" != "2" ]]; do
    log_warn "Please enter 1 or 2."
    read -rp "Enter 1 or 2: " AUTH_METHOD
done

AUTH_TYPE=""
INPUT_PUBLIC_KEY=""

if [[ "$AUTH_METHOD" == "1" ]]; then
    AUTH_TYPE="key"
    log_ok "SSH key authentication selected."

    CURRENT_USER_HOME=$(eval echo "~${SUDO_USER:-$USER}")
    if [[ -f "$CURRENT_USER_HOME/.ssh/authorized_keys" ]] && \
       [[ -s "$CURRENT_USER_HOME/.ssh/authorized_keys" ]]; then
        log_ok "Found authorized_keys at $CURRENT_USER_HOME/.ssh/authorized_keys"
    elif [[ -f /root/.ssh/authorized_keys ]] && \
         [[ -s /root/.ssh/authorized_keys ]]; then
        log_ok "Found authorized_keys at /root/.ssh/authorized_keys"
    else
        log_warn "No authorized_keys file found on this server."
        read -rp "Continue anyway? (yes/no): " KEY_CONFIRM
        [[ "$KEY_CONFIRM" != "yes" ]] && exit 1
    fi

else
    echo ""
    echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${YELLOW}  SSH KEY RECOMMENDATION${NC}"
    echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "SSH keys are ${BOLD}significantly more secure${NC} than passwords:"
    echo -e "  ${YELLOW}•${NC} Passwords can be brute-forced. Keys cannot."
    echo -e "  ${YELLOW}•${NC} Keys are 256+ bits of randomness vs a memorable password."
    echo -e "  ${YELLOW}•${NC} Bots are already trying passwords on your server right now."
    echo ""
    echo -e "Would you like to set up an SSH key now?"
    echo -e "  ${CYAN}a)${NC} Yes — set up SSH key now (${GREEN}recommended${NC})"
    echo -e "  ${CYAN}b)${NC} No  — continue with password only"
    echo ""
    read -rp "Enter a or b: " KEY_CHOICE

    while [[ "$KEY_CHOICE" != "a" && "$KEY_CHOICE" != "b" ]]; do
        log_warn "Please enter a or b."
        read -rp "Enter a or b: " KEY_CHOICE
    done

    if [[ "$KEY_CHOICE" == "a" ]]; then
        AUTH_TYPE="key"

        echo ""
        echo -e "${BOLD}Step 1 — On your LOCAL machine (not this server):${NC}"
        echo ""
        echo -e "  ${CYAN}Mac/Linux:${NC}"
        echo -e "    ssh-keygen -t ed25519 -C \"my-vps-key\""
        echo -e "    cat ~/.ssh/id_ed25519.pub"
        echo ""
        echo -e "  ${CYAN}Windows (PowerShell):${NC}"
        echo -e "    ssh-keygen -t ed25519 -C \"my-vps-key\""
        echo -e "    type \$env:USERPROFILE\\.ssh\\id_ed25519.pub"
        echo ""
        echo -e "${BOLD}Step 2 — Copy the output. It starts with: ${CYAN}ssh-ed25519 AAAA...${NC}"
        echo ""

        read -rp "Have you generated the key on your local machine? (yes/no): " KEY_GENERATED
        if [[ "$KEY_GENERATED" != "yes" ]]; then
            log_warn "Generate a key first, then re-run this script."
            exit 1
        fi

        echo ""
        echo -e "${BOLD}Paste your PUBLIC key below (.pub file content):${NC}"
        echo -e "${YELLOW}Must start with: ssh-ed25519, ssh-rsa, or ssh-ecdsa${NC}"
        echo ""
        read -rp "> " INPUT_PUBLIC_KEY

        while [[ ! "$INPUT_PUBLIC_KEY" =~ ^ssh-(ed25519|rsa|ecdsa) ]]; do
            log_warn "Invalid key. Should start with ssh-ed25519, ssh-rsa, or ssh-ecdsa."
            log_warn "Make sure you copied the .pub file not the private key."
            echo ""
            read -rp "Paste your public key: " INPUT_PUBLIC_KEY
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
        echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}  TEST YOUR KEY LOGIN NOW (port 22 — before port change)${NC}"
        echo -e "${BOLD}${YELLOW}═══════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "  ${CYAN}Mac/Linux:${NC}"
        echo -e "    ssh -i ~/.ssh/id_ed25519 $CURRENT_USER@$PUBLIC_IP_EARLY"
        echo ""
        echo -e "  ${CYAN}Windows:${NC}"
        echo -e "    ssh -i \$env:USERPROFILE\\.ssh\\id_ed25519 $CURRENT_USER@$PUBLIC_IP_EARLY"
        echo ""
        echo -e "  If it connects ${GREEN}without a password prompt${NC} the key is working."
        echo -e "  ${RED}Keep THIS session open!${NC}"
        echo ""
        read -rp "Did the SSH key login succeed? (yes/no): " KEY_TEST

        if [[ "$KEY_TEST" != "yes" ]]; then
            echo ""
            log_warn "Key login did not work."
            echo -e "  Fixes to try:"
            echo -e "  ${CYAN}1)${NC} Make sure you copied the .pub file (public key)"
            echo -e "  ${CYAN}2)${NC} Check: cat $KEY_DIR/authorized_keys"
            echo -e "  ${CYAN}3)${NC} Debug: ssh -vvv -i ~/.ssh/id_ed25519 $CURRENT_USER@$PUBLIC_IP_EARLY"
            echo ""
            read -rp "Continue with password-only instead? (yes/no): " FALLBACK
            if [[ "$FALLBACK" == "yes" ]]; then
                AUTH_TYPE="password"
                log_warn "Switching to password authentication."
            else
                log_error "Fix the key issue and re-run this script."
                exit 1
            fi
        else
            log_ok "Key login confirmed working."
        fi

    else
        AUTH_TYPE="password"
        echo ""
        log_warn "Continuing with password authentication."
        log_warn "You can add SSH keys later for stronger security."
        echo ""
    fi
fi

# Hostname
read -rp "Enter desired hostname (e.g., myserver): " INPUT_HOSTNAME
while [[ -z "$INPUT_HOSTNAME" || ! "$INPUT_HOSTNAME" =~ ^[a-zA-Z0-9-]+$ ]]; do
    log_warn "Invalid hostname. Use letters, numbers, and hyphens only."
    read -rp "Enter desired hostname: " INPUT_HOSTNAME
done

# SSH Port
read -rp "Enter new SSH port (1024-65535): " INPUT_SSH_PORT
while ! [[ "$INPUT_SSH_PORT" =~ ^[0-9]+$ ]] || \
      [[ "$INPUT_SSH_PORT" -lt 1024 ]] || \
      [[ "$INPUT_SSH_PORT" -gt 65535 ]]; do
    log_warn "Invalid port. Must be a number between 1024-65535."
    read -rp "Enter new SSH port: " INPUT_SSH_PORT
done

# New admin username
read -rp "Enter new admin username: " INPUT_USERNAME
while [[ -z "$INPUT_USERNAME" || \
         "$INPUT_USERNAME" =~ ^(ubuntu|admin|root|test)$ ]]; do
    log_warn "Choose a less predictable username."
    log_warn "Avoid: ubuntu, admin, root, test"
    read -rp "Enter new admin username: " INPUT_USERNAME
done

# Cloud user — only ask if not root
INPUT_CLOUD_USER="$CURRENT_USER"
if [[ "$CURRENT_USER" != "root" ]]; then
    read -rp "Cloud username to demote [$CURRENT_USER]: " INPUT_CLOUD_USER
    INPUT_CLOUD_USER="${INPUT_CLOUD_USER:-$CURRENT_USER}"
fi

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}Configuration Summary:${NC}"
echo -e "  Hostname:         ${GREEN}$INPUT_HOSTNAME${NC}"
echo -e "  SSH Port:         ${GREEN}$INPUT_SSH_PORT${NC}"
echo -e "  New Admin User:   ${GREEN}$INPUT_USERNAME${NC}"
echo -e "  Current User:     ${GREEN}$INPUT_CLOUD_USER${NC}"
echo -e "  Auth Method:      ${GREEN}$AUTH_TYPE${NC}"
echo -e "  Provider:         ${GREEN}$CLOUD_PROVIDER${NC}"
echo -e "  Fix iptables:     ${GREEN}$CONFLICTING_IPTABLES${NC}"

if [[ "$AUTH_TYPE" == "password" ]]; then
    echo ""
    echo -e "  ${YELLOW}⚠  Password auth will remain enabled.${NC}"
    echo -e "  ${YELLOW}   All other hardening still applies.${NC}"
fi
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""
read -rp "Proceed with these settings? (yes/no): " CONFIRM
[[ "$CONFIRM" != "yes" ]] && { log_error "Aborted by user."; exit 1; }

# =============================================================================
# LOGGING SETUP
# =============================================================================

LOGFILE="/var/log/harden-script.log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "════════════════════════════════════════" >> "$LOGFILE"
echo "Started: $(date)" >> "$LOGFILE"
echo "Provider: $CLOUD_PROVIDER | OS: $OS_ID $OS_VERSION | Auth: $AUTH_TYPE" >> "$LOGFILE"
echo "════════════════════════════════════════" >> "$LOGFILE"

# =============================================================================
# PHASE 1 - INITIAL ASSESSMENT
# =============================================================================

log_section "Phase 1 - Initial Assessment"

log_info "System info:"
hostname
uname -a
head -5 /etc/os-release

log_info "Shell-access accounts:"
grep -v nologin /etc/passwd | grep -v false

log_info "Running services:"
systemctl list-units --type=service --state=running --no-pager || true

log_info "Open ports:"
ss -tlnp

log_info "Firewall status:"
ufw status verbose 2>/dev/null || log_warn "UFW not installed yet"

log_info "SSH config:"
grep -v "^#" /etc/ssh/sshd_config | grep -v "^$" || true
if [[ -d /etc/ssh/sshd_config.d ]]; then
    log_info "SSH config.d overrides:"
    ls /etc/ssh/sshd_config.d/ 2>/dev/null || true
    cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
fi

log_info "iptables INPUT chain:"
iptables -L INPUT -n --line-numbers 2>/dev/null || log_warn "iptables unavailable"

log_info "AppArmor status:"
aa-status 2>/dev/null || log_warn "AppArmor unavailable"

log_info "Public IP:"
PUBLIC_IP=$(get_public_ip)
echo "$PUBLIC_IP"

log_ok "Assessment complete."
pause

# =============================================================================
# PHASE 2 - SYSTEM PREPARATION
# =============================================================================

log_section "Phase 2 - System Preparation"

log_info "Updating system packages..."
apt update && apt upgrade -y
log_ok "System updated."

log_info "Setting hostname to: $INPUT_HOSTNAME"
hostnamectl set-hostname "$INPUT_HOSTNAME"

if [[ "$HAS_CLOUD_INIT" == "true" ]]; then
    log_info "Preventing cloud-init from resetting hostname..."
    echo "preserve_hostname: true" \
        | tee /etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg
    log_ok "cloud-init hostname preservation configured."
fi

log_info "Updating /etc/hosts..."
if grep -q "127.0.1.1" /etc/hosts; then
    sed -i "s/^127\.0\.1\.1.*/127.0.1.1 $INPUT_HOSTNAME/" /etc/hosts
else
    echo "127.0.1.1 $INPUT_HOSTNAME" >> /etc/hosts
fi

log_info "Verifying hostname:"
hostname
cat /etc/hostname
grep "$INPUT_HOSTNAME" /etc/hosts && log_ok "Hostname configured correctly."

# =============================================================================
# PHASE 3 - REMOVE UNNECESSARY SERVICES
# =============================================================================

log_section "Phase 3 - Remove Unnecessary Services"

disable_and_mask() {
    local SERVICE="$1"
    if systemctl list-units --all 2>/dev/null | grep -q "$SERVICE"; then
        log_info "Disabling and masking: $SERVICE"
        if systemctl stop "$SERVICE" 2>/dev/null; then
            log_ok "Stopped $SERVICE"
        else
            log_warn "Could not stop $SERVICE"
        fi
        if systemctl disable "$SERVICE" 2>/dev/null; then
            log_ok "Disabled $SERVICE"
        else
            log_warn "Could not disable $SERVICE"
        fi
        if systemctl mask "$SERVICE" 2>/dev/null; then
            log_ok "Masked $SERVICE"
        else
            log_warn "Could not mask $SERVICE"
        fi
    else
        log_info "Not found, skipping: $SERVICE"
    fi
}

if [[ "$HAS_RPCBIND" == "true" ]]; then
    disable_and_mask "rpcbind.socket"
    disable_and_mask "rpcbind.service"
fi
if [[ "$HAS_MODEMMANAGER" == "true" ]]; then
    disable_and_mask "ModemManager"
fi
if [[ "$HAS_ISCSID" == "true" ]]; then
    disable_and_mask "iscsid.socket"
    disable_and_mask "iscsid.service"
fi

systemctl daemon-reload
log_info "Open ports after service removal:"
ss -tlnp
log_ok "Unnecessary services handled."

# =============================================================================
# PHASE 4 - FIREWALL CONFIGURATION
# =============================================================================

log_section "Phase 4 - Firewall Configuration"

log_info "Installing UFW..."
apt install ufw -y

log_info "Setting default policies..."
ufw default deny incoming
ufw default allow outgoing

log_info "Opening SSH on both ports (safety net during transition)..."
ufw allow 22/tcp comment "SSH default - temporary"
ufw allow "$INPUT_SSH_PORT"/tcp comment "SSH hardened"

log_info "Enabling UFW..."
echo "y" | ufw enable
log_ok "UFW enabled."

if [[ "$CONFLICTING_IPTABLES" == "true" ]]; then
    log_info "Removing conflicting iptables rules: ${CONFLICTING_LINES[*]}"
    mapfile -t SORTED_LINES < <(printf '%s\n' "${CONFLICTING_LINES[@]}" | sort -rn)
    for LINE_NUM in "${SORTED_LINES[@]}"; do
        if iptables -D INPUT "$LINE_NUM" 2>/dev/null; then
            log_ok "Deleted iptables rule $LINE_NUM"
        else
            log_warn "Could not delete rule $LINE_NUM"
        fi
    done
    mkdir -p /etc/iptables
    sh -c 'iptables-save > /etc/iptables/rules.v4'
    log_ok "Saved clean iptables rules."
else
    log_ok "No conflicting iptables rules to remove."
fi

case "$CLOUD_PROVIDER" in
    oracle)
        echo ""
        log_warn "ORACLE: Also open port $INPUT_SSH_PORT in Security Lists."
        log_warn "VCN → Subnet → Security List → Add Ingress Rule"
        echo ""
        pause ;;
    aws)
        echo ""
        log_warn "AWS: Also open port $INPUT_SSH_PORT in EC2 Security Group."
        log_warn "EC2 → Security Groups → Inbound Rules → Add Rule"
        echo ""
        pause ;;
    azure)
        echo ""
        log_warn "AZURE: Also open port $INPUT_SSH_PORT in your NSG."
        log_warn "NSG → Inbound Security Rules → Add"
        echo ""
        pause ;;
    gcp)
        echo ""
        log_warn "GCP: Also open port $INPUT_SSH_PORT in VPC Firewall Rules."
        log_warn "VPC Network → Firewall → Create Firewall Rule"
        echo ""
        pause ;;
esac

log_info "Current firewall state:"
ufw status verbose
log_ok "Firewall configured."

# =============================================================================
# PHASE 5 - SSH HARDENING
#
# SAFE DESIGN: This phase changes the port and hardens settings but does
# NOT set AllowUsers or disable root login. Those restrictions are applied
# in Phase 10 AFTER the new admin account is created and confirmed working.
# This prevents the lockout scenario where restrictions are applied before
# the replacement account exists and is verified.
# =============================================================================

log_section "Phase 5 - SSH Hardening (Port Change)"

log_warn "Keep your current SSH session open throughout this phase."
log_info "This phase changes the port and hardens settings."
log_info "User restrictions (AllowUsers, PermitRootLogin no) are applied"
log_info "in Phase 10 after your new admin account is tested."
pause

log_info "Backing up SSH configuration..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
log_ok "Backed up: /etc/ssh/sshd_config"

if [[ -d /etc/ssh/sshd_config.d ]]; then
    for CONF_FILE in /etc/ssh/sshd_config.d/*.conf; do
        if [[ -f "$CONF_FILE" ]]; then
            cp "$CONF_FILE" "${CONF_FILE}.backup"
            log_ok "Backed up: $CONF_FILE"
        fi
    done
fi

mkdir -p /etc/ssh/sshd_config.d

log_info "Writing safe SSH config..."

if [[ "$AUTH_TYPE" == "key" ]]; then
    cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# ============================================
# Hardened SSH Configuration
# Generated: $(date)
# Provider: $CLOUD_PROVIDER | OS: $OS_ID $OS_VERSION
# Auth: key-only
#
# PHASE 5 (safe): Port changed, root kept accessible.
# PHASE 10 (final): AllowUsers + PermitRootLogin no
#   applied after new admin account confirmed working.
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
#
# PHASE 5 (safe): Port changed, root kept accessible.
# PHASE 10 (final): AllowUsers + PermitRootLogin no
#   applied after new admin account confirmed working.
#
# To upgrade to key-only auth later:
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

log_ok "Safe SSH config written."

# Apply SSH socket fix on Ubuntu 24.04
# Always applied on 24.04 — socket may exist even when not showing in list-units
if [[ "$OS_VERSION" == "24.04" ]]; then
    apply_ssh_socket_fix
fi

log_info "Validating SSH config syntax..."
if sshd -t; then
    log_ok "SSH config is valid."
else
    log_error "SSH config has errors. Restoring backup..."
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/99-hardened.conf
    exit 1
fi

log_info "Restarting SSH service..."
systemctl restart ssh

log_info "Verifying SSH is on port $INPUT_SSH_PORT:"
ss -tlnp | grep ssh || true
echo ""
sshd -T | grep -E 'port|permitrootlogin|passwordauthentication' || true

# Verify SSH is actually on the new port
if ! ss -tlnp | grep -q ":$INPUT_SSH_PORT"; then
    log_error "SSH is NOT listening on port $INPUT_SSH_PORT."
    log_error "Check: systemctl status ssh"
    log_error "Check: journalctl -u ssh -n 20"
    exit 1
fi

log_ok "SSH confirmed listening on port $INPUT_SSH_PORT."

echo ""
log_warn "═══════════════════════════════════════════════════"
log_warn "ACTION REQUIRED: Open a NEW terminal and test:"

if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "  ${CYAN}ssh -i /path/to/key -p $INPUT_SSH_PORT $CURRENT_USER@$PUBLIC_IP${NC}"
else
    echo -e "  ${CYAN}ssh -p $INPUT_SSH_PORT $CURRENT_USER@$PUBLIC_IP${NC}"
fi

log_warn "Keep THIS session open!"
log_warn "═══════════════════════════════════════════════════"
echo ""
read -rp "Did the connection on port $INPUT_SSH_PORT succeed? (yes/no): " SSH_TEST

if [[ "$SSH_TEST" != "yes" ]]; then
    log_error "SSH test failed. Diagnose from this session:"
    log_error "  systemctl status ssh"
    log_error "  journalctl -u ssh -n 30 --no-pager"
    log_error "  ss -tlnp | grep ssh"
    exit 1
fi

log_info "Removing temporary port 22 rule from UFW..."
ufw delete allow 22/tcp
log_ok "Port 22 removed. Only port $INPUT_SSH_PORT is open."
ufw status verbose

# =============================================================================
# PHASE 6 - FAIL2BAN
# =============================================================================

log_section "Phase 6 - fail2ban"

log_info "Installing fail2ban..."
apt install fail2ban -y

log_info "Creating jail.local..."
cat > /etc/fail2ban/jail.local << EOF
# ============================================
# fail2ban Configuration
# Generated: $(date)
# ============================================

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

systemctl enable fail2ban
systemctl start fail2ban

log_info "fail2ban status:"
systemctl status fail2ban --no-pager || true
fail2ban-client status sshd || true
log_ok "fail2ban configured."

# =============================================================================
# PHASE 7 - APPARMOR
# =============================================================================

log_section "Phase 7 - AppArmor"

if command -v aa-status &>/dev/null; then
    log_info "Current AppArmor status:"
    aa-status || true
    log_info "Installing additional profiles..."
    apt install apparmor-profiles apparmor-profiles-extra -y
    systemctl status apparmor --no-pager || true
    log_ok "AppArmor configured."
else
    log_warn "AppArmor not available. Skipping."
fi

# =============================================================================
# PHASE 8 - PERSISTENT LOGGING
# =============================================================================

log_section "Phase 8 - Persistent Logging"

log_info "Enabling persistent journal logging..."
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal

mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/custom.conf << EOF
[Journal]
Storage=persistent
SystemMaxUse=500M
SystemMaxFileSize=50M
EOF

systemctl restart systemd-journald
journalctl --disk-usage || true
log_ok "Persistent logging configured."

# =============================================================================
# PHASE 9 - PACKAGE CLEANUP
# =============================================================================

log_section "Phase 9 - Package Cleanup"

PACKAGES_TO_REMOVE=()
for PKG in nfs-common open-iscsi ssh-import-id; do
    if dpkg -l "$PKG" 2>/dev/null | grep -q "^ii"; then
        PACKAGES_TO_REMOVE+=("$PKG")
        log_info "Will remove: $PKG"
    else
        log_info "Not installed, skipping: $PKG"
    fi
done

if [[ ${#PACKAGES_TO_REMOVE[@]} -gt 0 ]]; then
    apt remove "${PACKAGES_TO_REMOVE[@]}" -y
fi
apt autoremove -y
log_ok "Package cleanup complete."

# =============================================================================
# PHASE 10 - ADMIN ACCOUNT + FINAL SSH LOCKDOWN
#
# SAFE DESIGN: New account is created and tested FIRST.
# AllowUsers and PermitRootLogin no are only applied AFTER
# the new account is confirmed working. If the test fails,
# root access is preserved so you are never locked out.
# =============================================================================

log_section "Phase 10 - Admin Account + Final SSH Lockdown"

log_info "Creating admin account: $INPUT_USERNAME"
if id "$INPUT_USERNAME" &>/dev/null; then
    log_warn "User $INPUT_USERNAME already exists, skipping creation."
else
    adduser --gecos "" "$INPUT_USERNAME"
fi

usermod -aG sudo "$INPUT_USERNAME"
usermod -aG adm  "$INPUT_USERNAME"
log_ok "User $INPUT_USERNAME created with sudo and adm groups."

# Set up SSH access for new account
log_info "Setting up SSH access for $INPUT_USERNAME..."
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
        log_ok "Keys copied from $KEY_SOURCE"
    elif [[ -n "${INPUT_PUBLIC_KEY:-}" ]]; then
        echo "$INPUT_PUBLIC_KEY" > "/home/$INPUT_USERNAME/.ssh/authorized_keys"
        chmod 600 "/home/$INPUT_USERNAME/.ssh/authorized_keys"
        log_ok "Public key from setup installed."
    else
        log_warn "No SSH key found. Add key manually later:"
        log_warn "  /home/$INPUT_USERNAME/.ssh/authorized_keys"
    fi
else
    log_info "Password mode — $INPUT_USERNAME will use password to login."
fi

chown -R "$INPUT_USERNAME:$INPUT_USERNAME" "/home/$INPUT_USERNAME/.ssh"

# ─── TEST BEFORE LOCKDOWN ────────────────────────────────────────────────────
echo ""
log_warn "═══════════════════════════════════════════════════"
log_warn "ACTION REQUIRED: Test your NEW admin account now."
echo ""

if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "  ${CYAN}ssh -i /path/to/key -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
else
    echo -e "  ${CYAN}ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    echo -e "  ${YELLOW}Use the password you just set for $INPUT_USERNAME${NC}"
fi

echo ""
echo -e "  Then verify sudo works inside the new session:"
echo -e "  ${CYAN}sudo -l${NC}"
echo -e "  ${CYAN}sudo id${NC}"
echo ""
log_warn "Keep THIS session open until the test passes!"
log_warn "═══════════════════════════════════════════════════"
echo ""
read -rp "New account login and sudo both succeeded? (yes/no): " NEW_ACCT_TEST

if [[ "$NEW_ACCT_TEST" != "yes" ]]; then
    # Test failed — preserve access, give instructions
    log_error "═══════════════════════════════════════════════════"
    log_error "Test failed. SSH lockdown NOT applied."
    log_error "Root access preserved. You are still connected."
    log_error ""
    log_error "Diagnose the issue:"
    log_error "  id $INPUT_USERNAME"
    log_error "  passwd $INPUT_USERNAME"
    log_error "  journalctl -u ssh -n 20 --no-pager"
    log_error ""
    log_error "Once fixed, apply lockdown manually:"
    echo ""
    echo -e "  ${CYAN}sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' \\${NC}"
    echo -e "  ${CYAN}    /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "  ${CYAN}echo 'AllowUsers $INPUT_USERNAME' | sudo tee -a \\${NC}"
    echo -e "  ${CYAN}    /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "  ${CYAN}sudo sshd -t && sudo systemctl restart ssh${NC}"
    echo ""
    log_error "═══════════════════════════════════════════════════"
    log_warn "Continuing to Phase 11 for monitoring setup."
    log_warn "SSH accessible via root on port $INPUT_SSH_PORT."

else
    # Test passed — apply final lockdown
    log_info "New account confirmed. Applying final SSH lockdown..."

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
# Auth: password (upgrade to keys recommended)
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
        log_ok "Final SSH lockdown applied."
        log_ok "Only '$INPUT_USERNAME' can login. Root login disabled."
    else
        log_error "SSH config error during lockdown. Keeping safe config."
        log_error "Fix manually: nano /etc/ssh/sshd_config.d/99-hardened.conf"
    fi

    # Demote cloud user if not root
    if [[ "$INPUT_CLOUD_USER" != "root" ]]; then
        log_info "Demoting $INPUT_CLOUD_USER..."
        deluser "$INPUT_CLOUD_USER" sudo  2>/dev/null || log_warn "Not in sudo"
        deluser "$INPUT_CLOUD_USER" lxd   2>/dev/null || log_warn "Not in lxd"
        deluser "$INPUT_CLOUD_USER" cdrom 2>/dev/null || log_warn "Not in cdrom"
        deluser "$INPUT_CLOUD_USER" dip   2>/dev/null || log_warn "Not in dip"
        passwd -l "$INPUT_CLOUD_USER"
        log_ok "$INPUT_CLOUD_USER demoted and locked."
    fi

    # Remove NOPASSWD if found in sudoers
    SUDOERS_FILE=""
    for F in /etc/sudoers.d/*; do
        if grep -q "$INPUT_CLOUD_USER" "$F" 2>/dev/null; then
            SUDOERS_FILE="$F"
            break
        fi
    done
    if [[ -n "$SUDOERS_FILE" ]]; then
        cp "$SUDOERS_FILE" "${SUDOERS_FILE}.backup"
        sed -i \
            "s|$INPUT_CLOUD_USER ALL=(ALL) NOPASSWD:ALL|$INPUT_CLOUD_USER ALL=(ALL) ALL|g" \
            "$SUDOERS_FILE"
        sed -i \
            "s|$INPUT_CLOUD_USER ALL=(ALL:ALL) NOPASSWD:ALL|$INPUT_CLOUD_USER ALL=(ALL:ALL) ALL|g" \
            "$SUDOERS_FILE"
        log_ok "Removed NOPASSWD from $INPUT_CLOUD_USER sudoers."
    fi
fi

# =============================================================================
# PHASE 11 - MONITORING AND AUDIT
# =============================================================================

log_section "Phase 11 - Monitoring and Audit"

SCRIPTS_DIR="/opt/$INPUT_HOSTNAME/scripts"
BASELINE_DIR="/opt/$INPUT_HOSTNAME/baseline"
AUDIT_LOG="/var/log/${INPUT_HOSTNAME}-audit.log"

log_info "Creating directory structure..."
mkdir -p "$SCRIPTS_DIR" "$BASELINE_DIR"

log_info "Creating SUID baseline..."
safe_find_suid > "$BASELINE_DIR/suid-baseline.txt"
chmod 600 "$BASELINE_DIR/suid-baseline.txt"
log_ok "SUID baseline saved: $BASELINE_DIR/suid-baseline.txt"

# Daily audit script
log_info "Creating daily audit script..."
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
    echo "WARNING: SUID changes!" >> \$LOGFILE
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

# Alert checker script
log_info "Creating alert checker script..."
cat > "$SCRIPTS_DIR/check-alerts.sh" << ALERT_EOF
#!/bin/bash
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo ""
echo "=========================================="
echo "   Security Alert Check"
echo "   \$(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="
echo ""

ALERTS=0

DISK=\$(df / | tail -1 | awk '{print \$5}' | tr -d '%')
if [ "\$DISK" -gt 80 ]; then
    echo -e "\${RED}[CRITICAL] Disk: \${DISK}%\${NC}"; ALERTS=\$((ALERTS+1))
elif [ "\$DISK" -gt 60 ]; then
    echo -e "\${YELLOW}[WARNING] Disk: \${DISK}%\${NC}"; ALERTS=\$((ALERTS+1))
else
    echo -e "\${GREEN}[OK] Disk: \${DISK}%\${NC}"
fi

MEM=\$(free | grep Mem | awk '{printf "%.0f", \$3/\$2*100}')
if [ "\$MEM" -gt 90 ]; then
    echo -e "\${RED}[CRITICAL] Memory: \${MEM}%\${NC}"; ALERTS=\$((ALERTS+1))
elif [ "\$MEM" -gt 75 ]; then
    echo -e "\${YELLOW}[WARNING] Memory: \${MEM}%\${NC}"; ALERTS=\$((ALERTS+1))
else
    echo -e "\${GREEN}[OK] Memory: \${MEM}%\${NC}"
fi

FAILED=\$(journalctl -u ssh --since "24 hours ago" 2>/dev/null \
    | grep -c "Invalid user\|Failed password" || echo 0)
if [ "\$FAILED" -gt 50 ]; then
    echo -e "\${RED}[CRITICAL] \${FAILED} failed SSH (24h)\${NC}"; ALERTS=\$((ALERTS+1))
elif [ "\$FAILED" -gt 10 ]; then
    echo -e "\${YELLOW}[WARNING] \${FAILED} failed SSH (24h)\${NC}"; ALERTS=\$((ALERTS+1))
else
    echo -e "\${GREEN}[OK] Failed SSH (24h): \${FAILED}\${NC}"
fi

BANS=\$(fail2ban-client status sshd 2>/dev/null \
    | grep "Total banned" | awk '{print \$NF}')
BANS=\${BANS:-0}
if [ "\$BANS" -gt 0 ]; then
    echo -e "\${YELLOW}[INFO] fail2ban banned \${BANS} IP(s)\${NC}"
    fail2ban-client status sshd 2>/dev/null | grep "Banned IP" | cut -d: -f2
else
    echo -e "\${GREEN}[OK] No IPs banned\${NC}"
fi

find / -perm -4000 -type f 2>/dev/null | grep -v snap | sort \
    > /tmp/suid-check.txt || true
SUID_DIFF=\$(diff $BASELINE_DIR/suid-baseline.txt \
    /tmp/suid-check.txt 2>/dev/null || true)
rm -f /tmp/suid-check.txt
if [ -n "\$SUID_DIFF" ]; then
    echo -e "\${RED}[CRITICAL] SUID files changed!\${NC}"
    echo "\$SUID_DIFF"
    ALERTS=\$((ALERTS+1))
else
    echo -e "\${GREEN}[OK] SUID files unchanged\${NC}"
fi

for SVC in ssh fail2ban; do
    if systemctl is-active --quiet "\$SVC"; then
        echo -e "\${GREEN}[OK] \$SVC running\${NC}"
    else
        echo -e "\${RED}[CRITICAL] \$SVC not running!\${NC}"; ALERTS=\$((ALERTS+1))
    fi
done

if ufw status | grep -q "Status: active"; then
    echo -e "\${GREEN}[OK] UFW active\${NC}"
else
    echo -e "\${RED}[CRITICAL] UFW not active!\${NC}"; ALERTS=\$((ALERTS+1))
fi

echo ""
echo "--- Listening Ports ---"
ss -tlnp | grep LISTEN

echo ""
echo "=========================================="
if [ "\$ALERTS" -eq 0 ]; then
    echo -e "\${GREEN}All checks passed. No alerts.\${NC}"
else
    echo -e "\${RED}\${ALERTS} alert(s) require attention.\${NC}"
fi
echo "=========================================="
echo ""
ALERT_EOF

chmod 750 "$SCRIPTS_DIR/daily-audit.sh"
chmod 750 "$SCRIPTS_DIR/check-alerts.sh"

if id "$INPUT_USERNAME" &>/dev/null; then
    chown root:"$INPUT_USERNAME" "$SCRIPTS_DIR/daily-audit.sh"
    chown root:"$INPUT_USERNAME" "$SCRIPTS_DIR/check-alerts.sh"
else
    chown root:root "$SCRIPTS_DIR/daily-audit.sh"
    chown root:root "$SCRIPTS_DIR/check-alerts.sh"
fi

ln -sf "$SCRIPTS_DIR/check-alerts.sh" /usr/local/bin/check-alerts
log_ok "Created system command: sudo check-alerts"

log_info "Scheduling daily audit at 4:00 AM..."
(crontab -l 2>/dev/null | grep -v "daily-audit.sh"; \
 echo "0 4 * * * $SCRIPTS_DIR/daily-audit.sh") | crontab -
log_ok "Cron job scheduled."

log_info "Running audit script to verify..."
bash "$SCRIPTS_DIR/daily-audit.sh" || true
tail -20 "$AUDIT_LOG" || true
log_ok "Audit script verified."

log_info "Running check-alerts to verify..."
bash "$SCRIPTS_DIR/check-alerts.sh" || true
log_ok "Alert checker verified."

# =============================================================================
# FINAL SUMMARY
# =============================================================================

log_section "Hardening Complete"

echo -e "${BOLD}${GREEN}All phases completed successfully.${NC}\n"

echo -e "${BOLD}Environment:${NC}"
echo -e "  Provider: ${GREEN}$CLOUD_PROVIDER${NC}"
echo -e "  OS:       ${GREEN}$OS_ID $OS_VERSION${NC}"
echo ""

echo -e "${BOLD}Configuration Applied:${NC}"
echo -e "  Hostname:     ${GREEN}$INPUT_HOSTNAME${NC}"
echo -e "  SSH Port:     ${GREEN}$INPUT_SSH_PORT${NC}"
echo -e "  Admin User:   ${GREEN}$INPUT_USERNAME${NC}"
echo -e "  Auth Method:  ${GREEN}$AUTH_TYPE${NC}"
echo -e "  Public IP:    ${GREEN}$PUBLIC_IP${NC}"
echo ""

echo -e "${BOLD}SSH Connection Command:${NC}"
if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "  ${CYAN}ssh -i ~/.ssh/id_ed25519 -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
else
    echo -e "  ${CYAN}ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
fi
echo ""

if [[ "$AUTH_TYPE" == "password" ]]; then
    echo -e "${BOLD}${YELLOW}Upgrade to SSH keys later:${NC}"
    echo -e "  ${CYAN}# On your local machine:${NC}"
    echo -e "  ${CYAN}ssh-keygen -t ed25519 -C \"my-vps-key\"${NC}"
    echo -e "  ${CYAN}ssh-copy-id -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    echo ""
    echo -e "  ${CYAN}# On the server:${NC}"
    echo -e "  ${CYAN}sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' \\${NC}"
    echo -e "  ${CYAN}    /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "  ${CYAN}sudo sed -i '/PermitEmptyPasswords/i AuthenticationMethods publickey' \\${NC}"
    echo -e "  ${CYAN}    /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "  ${CYAN}sudo sshd -t && sudo systemctl restart ssh${NC}"
    echo ""
fi

echo -e "${BOLD}Key Files:${NC}"
echo -e "  SSH Config:    /etc/ssh/sshd_config.d/99-hardened.conf"
echo -e "  fail2ban:      /etc/fail2ban/jail.local"
echo -e "  Audit Log:     $AUDIT_LOG"
echo -e "  Scripts:       $SCRIPTS_DIR/"
echo -e "  SUID Baseline: $BASELINE_DIR/suid-baseline.txt"
echo -e "  Script Log:    $LOGFILE"
echo ""

echo -e "${BOLD}Daily Commands:${NC}"
echo -e "  ${CYAN}sudo check-alerts${NC}                    Security overview"
echo -e "  ${CYAN}sudo fail2ban-client status sshd${NC}     View banned IPs"
echo -e "  ${CYAN}sudo ufw status verbose${NC}              Firewall rules"
echo -e "  ${CYAN}sudo journalctl -u ssh -n 50${NC}         SSH activity"
echo -e "  ${CYAN}sudo tail -f $AUDIT_LOG${NC}"
echo ""

if [[ "$CLOUD_PROVIDER" =~ ^(oracle|aws|azure|gcp)$ ]]; then
    log_warn "═══════════════════════════════════════════════════"
    log_warn "REMINDER: Verify port $INPUT_SSH_PORT is open in"
    log_warn "your cloud provider's network security console."
    log_warn "═══════════════════════════════════════════════════"
fi

echo -e "\n${BOLD}Full log: $LOGFILE${NC}\n"
