#!/usr/bin/env bash
################################################################################
#
#   VPS HARDENING SCRIPT - COMPLETE EDITION v3.0
#   Comprehensive Server Security Hardening + Interactive Telegram Bot
#
#   Compatible: Debian 10/11/12, Ubuntu 20.04/22.04/24.04
#
#   Features:
#     - Tier 0: Essential (SSH, UFW, Fail2ban, Kernel, Auto-Updates, User)
#     - Tier 1: High Impact (AppArmor, AIDE, auditd, /dev/shm, protocols)
#     - Tier 2: Advanced (Resource limits, DNS-over-TLS, Lynis, lockdown)
#     - Tier 3: Zero Trust (Tailscale, fwknop SPA)
#     - Interactive Telegram Bot (two-way, inline menus, remote management)
#     - Login security, user hardening, log forwarding, batch operations
#
#   Usage: sudo bash harden.sh
#
################################################################################

# ============================================================================
# STRICT ERROR HANDLING
# ============================================================================
set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# COLOR DEFINITIONS
# ============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;37m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly UNDERLINE='\033[4m'
readonly NC='\033[0m'

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================
readonly SCRIPT_VERSION="3.0.0-complete"
readonly SCRIPT_NAME="VPS Hardening Script"
readonly SCRIPT_DATE="$(date +%Y-%m-%d)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

readonly LOG_FILE="/var/log/vps-hardening.log"
readonly BACKUP_DIR="/root/.vps-hardening-backups/${TIMESTAMP}"
readonly STATE_FILE="/var/lib/vps-hardening/state.conf"
readonly REPORT_FILE="/root/vps-hardening-report-${TIMESTAMP}.txt"

# Global operational variables
SSH_PORT=""
TARGET_USER="${SUDO_USER:-$USER}"
USER_HOME="$(eval echo "~${TARGET_USER}")"
OS_ID=""
OS_VERSION=""
OS_NAME=""
OS_CODENAME=""
KERNEL_VERSION="$(uname -r)"
ARCH="$(uname -m)"

# Feature tracking
declare -A COMPLETED_TASKS
declare -A FAILED_TASKS

# APT non-interactive mode
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
export NEEDRESTART_MODE=a

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

init_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$STATE_FILE")"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    
    {
        echo "================================================================"
        echo "  VPS Hardening Script - Session Started"
        echo "  Version: ${SCRIPT_VERSION}"
        echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  User: ${TARGET_USER}"
        echo "  Host: $(hostname)"
        echo "================================================================"
    } >> "$LOG_FILE"
}

log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] ${message}" >> "$LOG_FILE"
}

log_info()    { log "INFO"    "$1"; }
log_warn()    { log "WARN"    "$1"; }
log_error()   { log "ERROR"   "$1"; }
log_success() { log "SUCCESS" "$1"; }
log_debug()   { log "DEBUG"   "$1"; }

# ============================================================================
# OUTPUT FORMATTING FUNCTIONS
# ============================================================================

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║          VPS HARDENING SCRIPT - COMPLETE EDITION v3.0            ║
    ║                                                                  ║
    ║       Comprehensive Server Security + Telegram Bot Control       ║
    ║                                                                  ║
    ║   ┌────────────────────────────────────────────────────────┐   ║
    ║   │  Tier 0: Essential Hardening                           │   ║
    ║   │  Tier 1: High Impact Defenses                          │   ║
    ║   │  Tier 2: Advanced Security Controls                    │   ║
    ║   │  Tier 3: Zero Trust Networking                         │   ║
    ║   │  Bonus:  Interactive Telegram Bot                      │   ║
    ║   └────────────────────────────────────────────────────────┘   ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "  ${YELLOW}${BOLD}⚠  IMPORTANT NOTICES:${NC}"
    echo -e "  ${YELLOW}• This script must be run as root or with sudo${NC}"
    echo -e "  ${YELLOW}• All configurations are backed up before modification${NC}"
    echo -e "  ${YELLOW}• Test SSH access in a NEW terminal before disconnecting${NC}"
    echo -e "  ${YELLOW}• Review the log file: ${LOG_FILE}${NC}"
    echo ""
}

print_section() {
    local title="$1"
    local width=68
    local title_len=${#title}
    local padding=$(( (width - title_len - 2) / 2 ))
    
    echo ""
    echo -e "${BLUE}${BOLD}$(printf '━%.0s' $(seq 1 $width))${NC}"
    echo -e "${BLUE}${BOLD}$(printf ' %.0s' $(seq 1 $padding))${WHITE}${title}${BLUE}$(printf ' %.0s' $(seq 1 $padding))${NC}"
    echo -e "${BLUE}${BOLD}$(printf '━%.0s' $(seq 1 $width))${NC}"
    echo ""
}

print_subsection() {
    echo ""
    echo -e "  ${CYAN}${BOLD}▸ $1${NC}"
    echo -e "  ${DIM}$(printf '─%.0s' $(seq 1 60))${NC}"
}

print_status() {
    echo -e "  ${GREEN}${BOLD}[✔]${NC} $1"
    log_success "$1"
}

print_warning() {
    echo -e "  ${YELLOW}${BOLD}[⚠]${NC} $1"
    log_warn "$1"
}

print_error() {
    echo -e "  ${RED}${BOLD}[✘]${NC} $1"
    log_error "$1"
}

print_info() {
    echo -e "  ${CYAN}${BOLD}[ℹ]${NC} $1"
    log_info "$1"
}

print_step() {
    echo -e "  ${MAGENTA}${BOLD}[→]${NC} $1"
    log_info "STEP: $1"
}

print_debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo -e "  ${GRAY}${DIM}[DEBUG]${NC} $1"
    fi
    log_debug "$1"
}

print_separator() {
    echo -e "  ${DIM}$(printf '─%.0s' $(seq 1 66))${NC}"
}

# ============================================================================
# INTERACTIVE PROMPTS
# ============================================================================

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    local response=""
    local hint=""
    
    if [[ "$default" == "y" ]]; then
        hint="[Y/n]"
    else
        hint="[y/N]"
    fi
    
    while true; do
        echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt} ${hint}: "
        read -r response
        response="${response:-$default}"
        
        case "${response,,}" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *) print_warning "Please answer yes or no." ;;
        esac
    done
}

prompt_input() {
    local prompt="$1"
    local default="${2:-}"
    local variable_name="$3"
    local response=""
    
    if [[ -n "$default" ]]; then
        echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt} [default: ${default}]: "
    else
        echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt}: "
    fi
    
    read -r response
    response="${response:-$default}"
    
    printf -v "$variable_name" '%s' "$response"
}

prompt_password() {
    local prompt="$1"
    local variable_name="$2"
    local response=""
    
    echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt}: "
    read -rs response
    echo ""
    
    printf -v "$variable_name" '%s' "$response"
}

prompt_menu() {
    local prompt="$1"
    shift
    local options=("$@")
    local choice=""
    
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} ${prompt}"
    for i in "${!options[@]}"; do
        echo -e "      ${CYAN}$((i+1)))${NC} ${options[$i]}"
    done
    
    while true; do
        echo -ne "  ${MAGENTA}${BOLD}[?]${NC} Select option [1-${#options[@]}]: "
        read -r choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
            echo "$((choice-1))"
            return 0
        else
            print_warning "Invalid selection. Please try again."
        fi
    done
}

pause() {
    echo ""
    echo -ne "  ${DIM}Press ${BOLD}Enter${NC}${DIM} to continue...${NC}"
    read -r
}

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        print_error "This script must be run as root."
        echo -e "  ${YELLOW}Please run with: ${BOLD}sudo bash $0${NC}"
        exit 1
    fi
}

check_internet() {
    print_step "Checking internet connectivity..."
    if ping -c 1 -W 3 8.8.8.8 &>/dev/null || ping -c 1 -W 3 1.1.1.1 &>/dev/null; then
        print_status "Internet connection is active"
        return 0
    else
        print_error "No internet connection detected"
        print_warning "Some operations require internet access"
        if ! confirm "Continue anyway?"; then
            exit 1
        fi
    fi
}

detect_os() {
    print_step "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
        OS_NAME="${PRETTY_NAME:-unknown}"
        OS_CODENAME="${VERSION_CODENAME:-unknown}"
    else
        print_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    
    case "$OS_ID" in
        ubuntu|debian)
            print_status "Detected: ${OS_NAME}"
            print_info "Codename: ${OS_CODENAME} | Kernel: ${KERNEL_VERSION} | Arch: ${ARCH}"
            ;;
        *)
            print_warning "OS '${OS_ID}' is not officially tested."
            print_warning "This script is optimized for Debian/Ubuntu."
            if ! confirm "Continue anyway?"; then
                exit 1
            fi
            ;;
    esac
}

validate_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra parts <<< "$ip"
        for part in "${parts[@]}"; do
            if [ "$part" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

validate_hostname() {
    local hostname="$1"
    if [[ "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$ ]]; then
        return 0
    else
        return 1
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

service_exists() {
    systemctl list-unit-files "$1.service" &>/dev/null 2>&1
}

service_active() {
    systemctl is-active --quiet "$1" 2>/dev/null
}

package_installed() {
    dpkg -l "$1" &>/dev/null 2>&1
}

# ============================================================================
# BACKUP & STATE MANAGEMENT
# ============================================================================

create_backup_dir() {
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"
        print_info "Backup directory: ${BACKUP_DIR}"
        log_info "Backup directory created: ${BACKUP_DIR}"
    fi
}

backup_file() {
    local file="$1"
    
    if [ -z "$file" ]; then
        return 1
    fi
    
    if [ -f "$file" ] || [ -d "$file" ]; then
        create_backup_dir
        local backup_path="${BACKUP_DIR}$(dirname "$file")"
        mkdir -p "$backup_path"
        cp -rp "$file" "$backup_path/" 2>/dev/null || true
        log_debug "Backed up: $file -> $backup_path/"
        return 0
    fi
    
    return 1
}

backup_directory() {
    local dir="$1"
    
    if [ -d "$dir" ]; then
        create_backup_dir
        local backup_path="${BACKUP_DIR}$(dirname "$dir")"
        mkdir -p "$backup_path"
        cp -rp "$dir" "$backup_path/" 2>/dev/null || true
        log_debug "Backed up directory: $dir"
        return 0
    fi
    
    return 1
}

save_state() {
    local key="$1"
    local value="$2"
    
    mkdir -p "$(dirname "$STATE_FILE")"
    touch "$STATE_FILE"
    
    sed -i "/^${key}=/d" "$STATE_FILE" 2>/dev/null || true
    echo "${key}=${value}" >> "$STATE_FILE"
    chmod 600 "$STATE_FILE"
}

load_state() {
    local key="$1"
    
    if [ -f "$STATE_FILE" ]; then
        grep "^${key}=" "$STATE_FILE" 2>/dev/null | cut -d'=' -f2- | tail -1
    fi
}

mark_completed() {
    local task="$1"
    COMPLETED_TASKS["$task"]="$(date '+%Y-%m-%d %H:%M:%S')"
    save_state "COMPLETED_${task}" "$(date '+%Y-%m-%d %H:%M:%S')"
}

mark_failed() {
    local task="$1"
    local reason="${2:-Unknown error}"
    FAILED_TASKS["$task"]="$reason"
    save_state "FAILED_${task}" "$reason"
}

is_completed() {
    local task="$1"
    [ -n "${COMPLETED_TASKS[$task]:-}" ] || [ -n "$(load_state "COMPLETED_${task}")" ]
}

# ============================================================================
# ERROR HANDLING & CLEANUP
# ============================================================================

cleanup_on_exit() {
    local exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        log_error "Script exited with code: $exit_code"
        echo ""
        print_error "Script exited unexpectedly (exit code: $exit_code)"
        print_info "Check the log file: ${LOG_FILE}"
        print_info "Backups are stored in: ${BACKUP_DIR}"
    fi
    
    echo -e "${NC}"
}

trap cleanup_on_exit EXIT
trap 'log_error "Interrupted by user"; exit 130' INT
trap 'log_error "Terminated"; exit 143' TERM

# ============================================================================
# TIER 0: ESSENTIAL HARDENING FUNCTIONS
# ============================================================================

# ----------------------------------------------------------------------------
# Function: system_update
# Purpose: Update system packages and install essential utilities
# ----------------------------------------------------------------------------
system_update() {
    print_section "SYSTEM UPDATE & CLEANUP"
    
    print_step "Updating package repository lists..."
    if apt-get update -y >> "$LOG_FILE" 2>&1; then
        print_status "Package lists updated successfully"
    else
        print_error "Failed to update package lists"
        mark_failed "system_update" "apt-get update failed"
        return 1
    fi
    
    print_step "Upgrading installed packages (this may take a while)..."
    if apt-get -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold" \
                upgrade -y >> "$LOG_FILE" 2>&1; then
        print_status "System packages upgraded successfully"
    else
        print_error "Failed to upgrade packages"
        mark_failed "system_update" "apt-get upgrade failed"
        return 1
    fi
    
    if confirm "Perform full distribution upgrade (dist-upgrade)?" "n"; then
        print_step "Performing distribution upgrade..."
        if apt-get -o Dpkg::Options::="--force-confdef" \
                    -o Dpkg::Options::="--force-confold" \
                    dist-upgrade -y >> "$LOG_FILE" 2>&1; then
            print_status "Distribution upgrade completed"
        else
            print_warning "Distribution upgrade had issues (see log)"
        fi
    fi
    
    print_step "Removing unnecessary packages..."
    apt-get autoremove -y >> "$LOG_FILE" 2>&1 || true
    apt-get autoclean -y >> "$LOG_FILE" 2>&1 || true
    apt-get clean >> "$LOG_FILE" 2>&1 || true
    print_status "System cleaned"
    
    # Install essential utilities (includes bot dependencies)
    print_step "Installing essential utility packages..."
    local essential_packages=(
        curl wget git vim nano htop
        net-tools dnsutils
        gnupg2 ca-certificates
        software-properties-common
        apt-transport-https
        unzip zip
        rsync bc jq
        python3 python3-minimal
    )
    
    for pkg in "${essential_packages[@]}"; do
        if ! package_installed "$pkg"; then
            apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 || \
                print_warning "Failed to install: $pkg"
        fi
    done
    print_status "Essential utilities installed"
    
    mark_completed "system_update"
}

# ----------------------------------------------------------------------------
# Function: harden_ssh
# Purpose: Comprehensive SSH hardening with lockout prevention
# ----------------------------------------------------------------------------
harden_ssh() {
    print_section "SSH HARDENING"
    
    # Install SSH server if not present
    if ! package_installed "openssh-server"; then
        print_step "Installing OpenSSH server..."
        apt-get install -y openssh-server >> "$LOG_FILE" 2>&1
    fi
    
    print_subsection "SSH Port Configuration"
    
    local current_port
    current_port=$(grep -h "^Port " /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | \
                   head -1 | awk '{print $2}' || echo "22")
    print_info "Current SSH port: ${current_port}"
    
    while true; do
        prompt_input "Enter desired SSH port" "2222" SSH_PORT
        if validate_port "$SSH_PORT"; then
            if [ "$SSH_PORT" -eq 22 ]; then
                print_warning "Port 22 is the default and frequently attacked."
                if ! confirm "Are you sure you want to use port 22?" "n"; then
                    continue
                fi
            fi
            break
        else
            print_error "Invalid port. Must be 1-65535."
        fi
    done
    
    save_state "SSH_PORT" "$SSH_PORT"
    
    print_subsection "SSH Key Validation"
    
    local AUTH_KEYS="${USER_HOME}/.ssh/authorized_keys"
    local disable_password="yes"
    local key_count=0
    
    if [ -f "$AUTH_KEYS" ] && [ -s "$AUTH_KEYS" ]; then
        key_count=$(grep -cve '^\s*$\|^\s*#' "$AUTH_KEYS" 2>/dev/null || echo "0")
        print_status "Found ${key_count} SSH key(s) for user: ${TARGET_USER}"
        
        if [ "$key_count" -gt 0 ]; then
            print_info "Key fingerprints:"
            while IFS= read -r key_line; do
                if [ -n "$key_line" ] && [[ ! "$key_line" =~ ^# ]]; then
                    local fingerprint
                    fingerprint=$(echo "$key_line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2, $NF}' || echo "invalid key")
                    echo -e "      ${GRAY}• ${fingerprint}${NC}"
                fi
            done < "$AUTH_KEYS"
        fi
    else
        print_warning "No SSH keys found in ${AUTH_KEYS}"
        print_warning "═══════════════════════════════════════════════════════════"
        print_warning "  CRITICAL: Disabling password authentication without SSH"
        print_warning "  keys will PERMANENTLY LOCK YOU OUT of this server!"
        print_warning "═══════════════════════════════════════════════════════════"
        
        if confirm "Do you want to add an SSH key now?" "y"; then
            add_ssh_key
            if [ -f "$AUTH_KEYS" ] && [ -s "$AUTH_KEYS" ]; then
                key_count=$(grep -cve '^\s*$\|^\s*#' "$AUTH_KEYS" 2>/dev/null || echo "0")
                if [ "$key_count" -eq 0 ]; then
                    disable_password="no"
                fi
            else
                disable_password="no"
            fi
        else
            disable_password="no"
            print_warning "Password authentication will remain ENABLED"
        fi
    fi
    
    print_subsection "Applying SSH Configuration"
    
    backup_file /etc/ssh/sshd_config
    backup_directory /etc/ssh/sshd_config.d
    
    mkdir -p /etc/ssh/sshd_config.d
    chmod 755 /etc/ssh/sshd_config.d
    
    local password_auth_value="no"
    [ "$disable_password" = "no" ] && password_auth_value="yes"
    
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << EOF
# ============================================================
# VPS Hardening - SSH Security Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# --- Network ---
Port ${SSH_PORT}
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# --- Protocol ---
Protocol 2

# --- Authentication ---
PermitRootLogin no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
StrictModes yes
PermitEmptyPasswords no

# --- Password Authentication ---
PasswordAuthentication ${password_auth_value}
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# --- Public Key Authentication ---
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# --- Host-Based Authentication ---
HostbasedAuthentication no
IgnoreRhosts yes
IgnoreUserKnownHosts yes

# --- Kerberos & GSSAPI ---
KerberosAuthentication no
GSSAPIAuthentication no

# --- Forwarding & Tunneling ---
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no

# --- User Environment ---
PermitUserEnvironment no
PermitUserRC no

# --- Session Timeouts ---
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# --- Logging ---
SyslogFacility AUTH
LogLevel VERBOSE

# --- Ciphers & Algorithms (Modern, Secure) ---
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# --- Banner ---
Banner /etc/issue.net

# --- DNS ---
UseDNS no

# --- Misc ---
Compression no
PrintMotd no
PrintLastLog yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
    
    chmod 600 /etc/ssh/sshd_config.d/99-hardening.conf
    print_status "SSH hardening configuration created"
    
    cat > /etc/issue.net << 'EOF'
################################################################
#                                                              #
#           AUTHORIZED ACCESS ONLY                             #
#                                                              #
#  This system is restricted to authorized users only.         #
#  All activities are monitored, logged, and audited.          #
#  Unauthorized access is strictly prohibited and will be      #
#  prosecuted to the fullest extent of the law.                #
#                                                              #
#  By accessing this system, you consent to monitoring.        #
#                                                              #
################################################################
EOF
    chmod 644 /etc/issue.net
    print_status "Login banner created"
    
    print_subsection "Systemd Socket Activation Check"
    
    if service_active "ssh.socket"; then
        print_info "Detected systemd socket activation (Ubuntu 24.04+ style)"
        print_step "Creating socket override for port ${SSH_PORT}..."
        
        mkdir -p /etc/systemd/system/ssh.socket.d
        cat > /etc/systemd/system/ssh.socket.d/override.conf << EOF
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF
        chmod 644 /etc/systemd/system/ssh.socket.d/override.conf
        systemctl daemon-reload
        print_status "SSH socket override configured"
    else
        print_info "Using traditional ssh.service (no socket activation)"
    fi
    
    print_subsection "Configuration Validation"
    
    print_step "Testing SSH configuration syntax..."
    if sshd -t 2>>"$LOG_FILE"; then
        print_status "SSH configuration syntax is valid"
        
        print_step "Restarting SSH service..."
        if service_active "ssh.socket"; then
            systemctl restart ssh.socket
            print_status "ssh.socket restarted"
        fi
        
        if service_active "ssh"; then
            systemctl restart ssh
            print_status "ssh service restarted"
        elif service_active "sshd"; then
            systemctl restart sshd
            print_status "sshd service restarted"
        fi
        
        sleep 2
        if ss -tlnp | grep -q ":${SSH_PORT} "; then
            print_status "SSH is now listening on port ${SSH_PORT}"
        else
            print_warning "SSH may not be listening on port ${SSH_PORT} yet"
            print_info "Verify with: ss -tlnp | grep ssh"
        fi
        
        mark_completed "harden_ssh"
    else
        print_error "SSH configuration test FAILED!"
        print_step "Reverting changes..."
        rm -f /etc/ssh/sshd_config.d/99-hardening.conf
        rm -rf /etc/systemd/system/ssh.socket.d
        systemctl daemon-reload 2>/dev/null || true
        print_error "Configuration reverted. Please check the log file."
        mark_failed "harden_ssh" "Configuration syntax error"
        return 1
    fi
    
    echo ""
    print_warning "═══════════════════════════════════════════════════════════"
    print_warning "  IMPORTANT: Test SSH access in a NEW terminal before"
    print_warning "  closing this session!"
    print_warning ""
    print_warning "  Command: ssh -p ${SSH_PORT} ${TARGET_USER}@$(hostname -I | awk '{print $1}')"
    print_warning "═══════════════════════════════════════════════════════════"
    
    if [ "$disable_password" = "no" ]; then
        echo ""
        print_warning "Password authentication is still ENABLED."
        print_warning "To disable it later:"
        print_warning "  1. Add your SSH public key to ~/.ssh/authorized_keys"
        print_warning "  2. Re-run SSH hardening (menu option 2)"
    fi
}

# ----------------------------------------------------------------------------
# Function: add_ssh_key
# Purpose: Helper function to add SSH keys interactively
# ----------------------------------------------------------------------------
add_ssh_key() {
    print_subsection "Add SSH Public Key"
    
    local ssh_dir="${USER_HOME}/.ssh"
    if [ ! -d "$ssh_dir" ]; then
        mkdir -p "$ssh_dir"
        chown "${TARGET_USER}:${TARGET_USER}" "$ssh_dir"
        chmod 700 "$ssh_dir"
        print_status "Created ${ssh_dir}"
    fi
    
    local auth_keys="${ssh_dir}/authorized_keys"
    if [ ! -f "$auth_keys" ]; then
        touch "$auth_keys"
        chown "${TARGET_USER}:${TARGET_USER}" "$auth_keys"
        chmod 600 "$auth_keys"
    fi
    
    print_info "Paste your SSH public key below (ssh-rsa, ssh-ed25519, ecdsa-*)"
    print_info "Press Enter twice when done, or type 'skip' to skip:"
    echo ""
    
    local ssh_key=""
    read -r ssh_key
    
    if [ "$ssh_key" = "skip" ] || [ -z "$ssh_key" ]; then
        print_warning "Skipped SSH key addition"
        return 1
    fi
    
    if echo "$ssh_key" | ssh-keygen -lf - &>/dev/null; then
        echo "$ssh_key" >> "$auth_keys"
        chown "${TARGET_USER}:${TARGET_USER}" "$auth_keys"
        chmod 600 "$auth_keys"
        
        local fingerprint
        fingerprint=$(echo "$ssh_key" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
        print_status "SSH key added successfully"
        print_info "Fingerprint: ${fingerprint}"
        return 0
    else
        print_error "Invalid SSH key format"
        return 1
    fi
}

# End of Section 1
# ============================================================================
# TIER 0 CONTINUED: FIREWALL, FAIL2BAN, KERNEL, AUTO-UPDATES, USER SETUP
# ============================================================================

# ----------------------------------------------------------------------------
# Function: configure_firewall
# Purpose: Configure UFW firewall with interactive port selection
# ----------------------------------------------------------------------------
configure_firewall() {
    print_section "FIREWALL CONFIGURATION (UFW)"
    
    if ! command_exists ufw; then
        print_step "Installing UFW..."
        apt-get install -y ufw >> "$LOG_FILE" 2>&1
        print_status "UFW installed"
    fi
    
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        if [ -z "$SSH_PORT" ]; then
            prompt_input "Enter your SSH port" "2222" SSH_PORT
        fi
    fi
    
    print_subsection "Current Firewall Status"
    ufw status verbose 2>/dev/null || print_info "UFW is not yet configured"
    
    print_subsection "Firewall Configuration"
    
    if confirm "Reset UFW to clean state before configuring?" "n"; then
        print_step "Resetting UFW..."
        ufw --force reset >> "$LOG_FILE" 2>&1
        print_status "UFW reset to defaults"
    fi
    
    print_step "Setting default policies..."
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1
    print_status "Default: DENY incoming, ALLOW outgoing"
    
    print_step "Configuring SSH access on port ${SSH_PORT}..."
    ufw limit "${SSH_PORT}/tcp" comment "SSH (rate-limited)" >> "$LOG_FILE" 2>&1
    print_status "SSH allowed on port ${SSH_PORT} with rate limiting"
    
    print_subsection "Common Service Ports"
    
    if confirm "Allow HTTP (port 80)?"; then
        ufw allow 80/tcp comment "HTTP" >> "$LOG_FILE" 2>&1
        print_status "Allowed HTTP (80)"
    fi
    
    if confirm "Allow HTTPS (port 443)?"; then
        ufw allow 443/tcp comment "HTTPS" >> "$LOG_FILE" 2>&1
        print_status "Allowed HTTPS (443)"
    fi
    
    print_subsection "Custom Port Configuration"
    
    if confirm "Add custom ports?"; then
        while true; do
            local custom_port=""
            prompt_input "Enter port number (or 'done' to finish)" "" custom_port
            
            if [ "$custom_port" = "done" ] || [ -z "$custom_port" ]; then
                break
            fi
            
            if ! validate_port "$custom_port"; then
                print_error "Invalid port: ${custom_port}. Must be 1-65535."
                continue
            fi
            
            local proto=""
            prompt_input "Protocol (tcp/udp/both)" "tcp" proto
            
            local comment=""
            prompt_input "Description/comment" "Custom" comment
            
            case "$proto" in
                both)
                    ufw allow "$custom_port" comment "$comment" >> "$LOG_FILE" 2>&1
                    print_status "Allowed ${custom_port} (tcp+udp) - ${comment}"
                    ;;
                tcp|udp)
                    ufw allow "${custom_port}/${proto}" comment "$comment" >> "$LOG_FILE" 2>&1
                    print_status "Allowed ${custom_port}/${proto} - ${comment}"
                    ;;
                *)
                    print_error "Invalid protocol. Skipping."
                    ;;
            esac
        done
    fi
    
    print_subsection "ICMP Configuration"
    
    if confirm "Allow ICMP (ping)?" "y"; then
        ufw allow proto icmp comment "ICMP" >> "$LOG_FILE" 2>&1
        print_status "ICMP allowed"
    fi
    
    if confirm "Enable IPv6 firewall rules?"; then
        backup_file /etc/default/ufw
        sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
        print_status "IPv6 firewall rules enabled"
    fi
    
    print_subsection "Activating Firewall"
    
    if confirm "Enable UFW now? (CRITICAL: ensure SSH port is correct!)" "y"; then
        ufw --force enable >> "$LOG_FILE" 2>&1
        print_status "UFW firewall is now ACTIVE"
    else
        print_warning "UFW is configured but NOT enabled"
        print_info "Enable manually with: ufw enable"
    fi
    
    echo ""
    print_info "Final firewall rules:"
    ufw status numbered
    
    mark_completed "configure_firewall"
}

# ----------------------------------------------------------------------------
# Function: setup_fail2ban
# Purpose: Install and configure Fail2ban with drop-in configuration
# ----------------------------------------------------------------------------
setup_fail2ban() {
    print_section "FAIL2BAN CONFIGURATION"
    
    if ! command_exists fail2ban-client; then
        print_step "Installing Fail2ban..."
        apt-get install -y fail2ban >> "$LOG_FILE" 2>&1
        print_status "Fail2ban installed"
    fi
    
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        if [ -z "$SSH_PORT" ]; then
            prompt_input "Enter your SSH port" "2222" SSH_PORT
        fi
    fi
    
    print_subsection "Fail2ban Parameters"
    
    local bantime="" findtime="" maxretry=""
    prompt_input "Ban duration in minutes" "60" bantime
    prompt_input "Detection window in minutes" "10" findtime
    prompt_input "Max failed attempts before ban" "4" maxretry
    
    local backend="auto"
    if service_active "systemd-journald"; then
        backend="systemd"
        print_info "Detected systemd journal backend"
    else
        print_info "Using auto-detect log backend"
    fi
    
    local banaction="ufw"
    if ! command_exists ufw; then
        banaction="iptables-multiport"
        print_info "UFW not found, using iptables ban action"
    fi
    
    print_subsection "Applying Configuration"
    
    backup_file /etc/fail2ban/jail.conf
    backup_directory /etc/fail2ban/jail.d
    
    mkdir -p /etc/fail2ban/jail.d
    
    cat > /etc/fail2ban/jail.d/00-hardening-defaults.local << EOF
# VPS Hardening - Fail2ban Default Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')

[DEFAULT]
bantime  = ${bantime}m
findtime = ${findtime}m
maxretry = ${maxretry}
banaction = ${banaction}
backend = ${backend}
destemail = root@localhost
sender = fail2ban@$(hostname)
action = %(action_mwl)s
ignoreip = 127.0.0.1/8 ::1
EOF
    
    chmod 644 /etc/fail2ban/jail.d/00-hardening-defaults.local
    print_status "Default parameters configured"
    
    cat > /etc/fail2ban/jail.d/10-sshd.local << EOF
# SSH Protection
[sshd]
enabled = true
port    = ${SSH_PORT}
filter  = sshd
logpath = %(sshd_log)s
maxretry = ${maxretry}
bantime  = ${bantime}m
EOF
    
    chmod 644 /etc/fail2ban/jail.d/10-sshd.local
    print_status "SSH jail configured for port ${SSH_PORT}"
    
    print_subsection "Additional Jails"
    
    if confirm "Enable web server protection (nginx/apache)?" "n"; then
        cat > /etc/fail2ban/jail.d/20-webserver.local << 'EOF'
[nginx-http-auth]
enabled = true
port    = http,https
filter  = nginx-http-auth
logpath = /var/log/nginx/error.log

[nginx-botsearch]
enabled = true
port    = http,https
filter  = nginx-botsearch
logpath = /var/log/nginx/access.log
maxretry = 2

[apache-auth]
enabled = true
port    = http,https
filter  = apache-auth
logpath = /var/log/apache2/error.log
EOF
        chmod 644 /etc/fail2ban/jail.d/20-webserver.local
        print_status "Web server jails configured"
    fi
    
    if confirm "Enable mail server protection (postfix/dovecot)?" "n"; then
        cat > /etc/fail2ban/jail.d/30-mail.local << 'EOF'
[postfix]
enabled = true
port    = smtp,465,submission
filter  = postfix
logpath = /var/log/mail.log

[dovecot]
enabled = true
port    = pop3,pop3s,imap,imaps
filter  = dovecot
logpath = /var/log/mail.log
EOF
        chmod 644 /etc/fail2ban/jail.d/30-mail.local
        print_status "Mail server jails configured"
    fi
    
    if confirm "Enable recidive jail (ban repeat offenders for 1 week)?" "y"; then
        cat > /etc/fail2ban/jail.d/90-recidive.local << 'EOF'
[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = %(banaction_allports)s
bantime  = 1w
findtime = 1d
maxretry = 3
EOF
        chmod 644 /etc/fail2ban/jail.d/90-recidive.local
        print_status "Recidive jail configured (1-week ban for repeat offenders)"
    fi
    
    print_subsection "Starting Fail2ban"
    
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    
    if systemctl restart fail2ban >> "$LOG_FILE" 2>&1; then
        print_status "Fail2ban started successfully"
    else
        print_error "Fail2ban failed to start. Check: journalctl -u fail2ban"
        mark_failed "setup_fail2ban" "Service failed to start"
        return 1
    fi
    
    sleep 2
    echo ""
    print_info "Fail2ban status:"
    fail2ban-client status 2>/dev/null || print_warning "Could not retrieve status"
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}fail2ban-client status sshd${NC}          # Check SSH jail"
    echo -e "    ${CYAN}fail2ban-client set sshd banip <IP>${NC}   # Manually ban IP"
    echo -e "    ${CYAN}fail2ban-client set sshd unbanip <IP>${NC} # Unban IP"
    
    mark_completed "setup_fail2ban"
}

# ----------------------------------------------------------------------------
# Function: kernel_hardening
# Purpose: Apply comprehensive kernel security parameters via sysctl
# ----------------------------------------------------------------------------
kernel_hardening() {
    print_section "KERNEL HARDENING (SYSCTL)"
    
    print_subsection "Backing Up Current Configuration"
    backup_file /etc/sysctl.conf
    backup_directory /etc/sysctl.d
    
    print_subsection "Applying Security Parameters"
    
    cat > /etc/sysctl.d/99-vps-hardening.conf << 'EOF'
# ============================================================
# VPS Hardening - Comprehensive Kernel Security Parameters
# ============================================================

# ---- IP Spoofing & Source Routing ----
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ---- ICMP Hardening ----
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ---- Redirect Attack Prevention (MITM) ----
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# ---- SYN Flood Protection ----
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_rfc1337 = 1

# ---- TCP Hardening ----
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_window_scaling = 1

# ---- IP Forwarding ----
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# ---- IPv6 Hardening ----
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# ---- Memory Protection (ASLR) ----
kernel.randomize_va_space = 2

# ---- Kernel Information Leak Prevention ----
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# ---- BPF & Tracing Restrictions ----
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 2

# ---- File System Protection ----
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# ---- Core Dump Restrictions ----
fs.suid_dumpable = 0

# ---- Network Misc ----
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ---- Performance Tuning ----
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 8192
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 5000
EOF
    
    chmod 644 /etc/sysctl.d/99-vps-hardening.conf
    print_status "Kernel parameters written"
    
    print_step "Applying kernel parameters..."
    if sysctl --system >> "$LOG_FILE" 2>&1; then
        print_status "All kernel parameters applied successfully"
    else
        print_warning "Some parameters may have failed (normal on restricted VPS kernels)"
    fi
    
    print_subsection "Verification"
    
    local checks=(
        "kernel.randomize_va_space:2:ASLR"
        "net.ipv4.tcp_syncookies:1:SYN Cookies"
        "net.ipv4.conf.all.rp_filter:1:Reverse Path Filter"
        "kernel.dmesg_restrict:1:dmesg Restriction"
        "fs.protected_symlinks:1:Symlink Protection"
    )
    
    for check in "${checks[@]}"; do
        IFS=':' read -r param expected label <<< "$check"
        local actual
        actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        if [ "$actual" = "$expected" ]; then
            print_status "${label}: ${actual} ✔"
        else
            print_warning "${label}: ${actual} (expected ${expected})"
        fi
    done
    
    mark_completed "kernel_hardening"
}

# ----------------------------------------------------------------------------
# Function: setup_auto_updates
# Purpose: Configure automatic security updates with optional reboot
# ----------------------------------------------------------------------------
setup_auto_updates() {
    print_section "AUTOMATIC SECURITY UPDATES"
    
    print_step "Installing unattended-upgrades..."
    apt-get install -y unattended-upgrades apt-listchanges >> "$LOG_FILE" 2>&1
    print_status "Packages installed"
    
    backup_file /etc/apt/apt.conf.d/20auto-upgrades
    backup_file /etc/apt/apt.conf.d/50unattended-upgrades
    
    print_subsection "Update Schedule Configuration"
    
    local update_interval="" download_interval="" autoclean_interval=""
    prompt_input "Package list update interval (days)" "1" update_interval
    prompt_input "Download upgradeable packages interval (days)" "1" download_interval
    prompt_input "Autoclean interval (days)" "7" autoclean_interval
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "${update_interval}";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "${download_interval}";
APT::Periodic::AutocleanInterval "${autoclean_interval}";
APT::Periodic::Verbose "1";
EOF
    
    chmod 644 /etc/apt/apt.conf.d/20auto-upgrades
    print_status "Update schedule configured"
    
    print_subsection "Upgrade Behavior"
    
    local auto_reboot="false"
    local reboot_time="03:30"
    
    if confirm "Enable automatic reboot after kernel updates?"; then
        auto_reboot="true"
        prompt_input "Reboot time (HH:MM, 24h format)" "03:30" reboot_time
        print_warning "System will automatically reboot at ${reboot_time} when needed"
    fi
    
    cat > /etc/apt/apt.conf.d/51unattended-upgrades-custom << EOF
Unattended-Upgrade::Automatic-Reboot "${auto_reboot}";
Unattended-Upgrade::Automatic-Reboot-Time "${reboot_time}";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Allow-downgrade "true";
EOF
    
    chmod 644 /etc/apt/apt.conf.d/51unattended-upgrades-custom
    print_status "Unattended-upgrades behavior configured"
    
    print_subsection "Activating Service"
    
    systemctl enable unattended-upgrades >> "$LOG_FILE" 2>&1
    systemctl restart unattended-upgrades >> "$LOG_FILE" 2>&1
    
    if service_active "unattended-upgrades"; then
        print_status "Unattended-upgrades service is active"
    else
        print_warning "Service may not be running"
    fi
    
    systemctl enable apt-daily.timer >> "$LOG_FILE" 2>&1
    systemctl enable apt-daily-upgrade.timer >> "$LOG_FILE" 2>&1
    systemctl start apt-daily.timer >> "$LOG_FILE" 2>&1
    systemctl start apt-daily-upgrade.timer >> "$LOG_FILE" 2>&1
    print_status "APT daily timers enabled"
    
    if confirm "Perform a dry-run test now?"; then
        print_step "Running dry-run (no actual changes)..."
        unattended-upgrades --dry-run --debug 2>&1 | tail -20
        print_status "Dry-run completed"
    fi
    
    echo ""
    print_info "Log location: /var/log/unattended-upgrades/"
    
    mark_completed "setup_auto_updates"
}

# ----------------------------------------------------------------------------
# Function: setup_user_account
# Purpose: Create hardened user account with restricted sudo
# ----------------------------------------------------------------------------
setup_user_account() {
    print_section "USER ACCOUNT & SUDO SETUP"
    
    print_info "Current user: ${TARGET_USER}"
    print_info "Home directory: ${USER_HOME}"
    
    print_subsection "Admin User Configuration"
    
    if confirm "Create a new dedicated admin user?" "n"; then
        local new_user=""
        while true; do
            prompt_input "Enter new admin username" "" new_user
            if [ -z "$new_user" ]; then
                print_error "Username cannot be empty"
                continue
            fi
            if [[ ! "$new_user" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
                print_error "Invalid username format"
                continue
            fi
            if id "$new_user" &>/dev/null; then
                print_warning "User '${new_user}' already exists"
                if ! confirm "Configure this existing user?" "n"; then
                    continue
                fi
            fi
            break
        done
        
        if ! id "$new_user" &>/dev/null; then
            print_step "Creating user: ${new_user}"
            useradd -m -s /bin/bash -G sudo "$new_user"
            print_status "User created"
            
            print_step "Setting password for ${new_user}..."
            passwd "$new_user"
        fi
        
        local new_home
        new_home=$(eval echo "~${new_user}")
        local new_ssh_dir="${new_home}/.ssh"
        
        mkdir -p "$new_ssh_dir"
        chown "${new_user}:${new_user}" "$new_ssh_dir"
        chmod 700 "$new_ssh_dir"
        
        if [ ! -f "${new_ssh_dir}/authorized_keys" ]; then
            touch "${new_ssh_dir}/authorized_keys"
            chown "${new_user}:${new_user}" "${new_ssh_dir}/authorized_keys"
            chmod 600 "${new_ssh_dir}/authorized_keys"
        fi
        
        if [ -f "${USER_HOME}/.ssh/authorized_keys" ] && [ -s "${USER_HOME}/.ssh/authorized_keys" ]; then
            if confirm "Copy SSH keys from ${TARGET_USER} to ${new_user}?"; then
                cp "${USER_HOME}/.ssh/authorized_keys" "${new_ssh_dir}/authorized_keys"
                chown "${new_user}:${new_user}" "${new_ssh_dir}/authorized_keys"
                chmod 600 "${new_ssh_dir}/authorized_keys"
                print_status "SSH keys copied to ${new_user}"
            fi
        fi
        
        TARGET_USER="$new_user"
        USER_HOME="$new_home"
        save_state "ADMIN_USER" "$new_user"
        print_status "Admin user configured: ${new_user}"
    fi
    
    print_subsection "Sudo Hardening"
    
    if confirm "Restrict sudo to require password every time (no caching)?" "n"; then
        mkdir -p /etc/sudoers.d
        cat > /etc/sudoers.d/99-hardening-timestamp << 'EOF'
Defaults timestamp_timeout=0
EOF
        chmod 440 /etc/sudoers.d/99-hardening-timestamp
        print_status "Sudo password caching disabled"
    fi
    
    if confirm "Log all sudo commands to a separate log file?"; then
        mkdir -p /etc/sudoers.d
        cat > /etc/sudoers.d/99-hardening-logging << 'EOF'
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
Defaults iolog_dir="/var/log/sudo-io"
EOF
        chmod 440 /etc/sudoers.d/99-hardening-logging
        mkdir -p /var/log/sudo-io
        chmod 700 /var/log/sudo-io
        print_status "Sudo command logging enabled"
    fi
    
    if confirm "Restrict 'su' command to sudo group members only?"; then
        backup_file /etc/pam.d/su
        if ! grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
            sed -i 's/^#\s*auth\s*required\s*pam_wheel.so/auth required pam_wheel.so/' /etc/pam.d/su
            if ! grep -q "pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
                echo "auth required pam_wheel.so" >> /etc/pam.d/su
            fi
            print_status "'su' restricted to sudo group"
        else
            print_info "'su' is already restricted"
        fi
    fi
    
    print_subsection "Root Account Security"
    
    if confirm "Lock the root account password? (sudo still works)"; then
        passwd -l root >> "$LOG_FILE" 2>&1
        print_status "Root password locked"
        print_info "Root login via SSH is already disabled"
        print_info "Use 'sudo -i' or 'sudo su -' for root shell"
    fi
    
    mark_completed "setup_user_account"
}

# End of Section 2
# ============================================================================
# TIER 1: HIGH IMPACT DEFENSES
# ============================================================================

# ----------------------------------------------------------------------------
# Function: secure_shared_memory
# Purpose: Secure /dev/shm to prevent in-memory malware execution
# ----------------------------------------------------------------------------
secure_shared_memory() {
    print_section "SECURE SHARED MEMORY (/dev/shm)"
    
    print_info "/dev/shm is a world-writable tmpfs used for shared memory."
    print_info "Attackers exploit it to execute malicious payloads in RAM."
    echo ""
    
    print_subsection "Current Status"
    if mount | grep -q " /dev/shm "; then
        local current_opts
        current_opts=$(mount | grep " /dev/shm " | sed 's/.*(\(.*\))/\1/')
        print_info "Current mount options: ${current_opts}"
    else
        print_info "/dev/shm is using default mount options"
    fi
    
    if grep -q " /dev/shm " /etc/fstab 2>/dev/null; then
        print_warning "/dev/shm already has an fstab entry"
        if ! confirm "Update the existing entry with hardened options?"; then
            return 0
        fi
        backup_file /etc/fstab
        sed -i '/ \/dev\/shm /d' /etc/fstab
    else
        backup_file /etc/fstab
    fi
    
    print_step "Adding hardened /dev/shm mount..."
    echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=1G 0 0" >> /etc/fstab
    chmod 644 /etc/fstab
    
    print_step "Remounting /dev/shm..."
    if mount -o remount /dev/shm 2>>"$LOG_FILE"; then
        print_status "/dev/shm remounted with noexec,nosuid,nodev"
    else
        print_warning "Remount failed. Changes will apply on next reboot."
    fi
    
    print_subsection "Verification"
    local verify_opts
    verify_opts=$(mount | grep " /dev/shm " | sed 's/.*(\(.*\))/\1/')
    print_info "Active mount options: ${verify_opts}"
    
    echo "$verify_opts" | grep -q "noexec" && print_status "noexec: active ✔" || print_warning "noexec: not active"
    echo "$verify_opts" | grep -q "nosuid" && print_status "nosuid: active ✔" || print_warning "nosuid: not active"
    echo "$verify_opts" | grep -q "nodev" && print_status "nodev: active ✔" || print_warning "nodev: not active"
    
    mark_completed "secure_shared_memory"
}

# ----------------------------------------------------------------------------
# Function: disable_unused_protocols
# Purpose: Disable unused and vulnerable kernel network modules
# ----------------------------------------------------------------------------
disable_unused_protocols() {
    print_section "DISABLE UNUSED NETWORK PROTOCOLS"
    
    print_info "Disabling rarely-used kernel protocols reduces the attack surface"
    print_info "for local privilege escalation and remote kernel exploits."
    echo ""
    
    backup_directory /etc/modprobe.d
    
    print_subsection "Core Protocol Disabling"
    
    cat > /etc/modprobe.d/99-vps-disable-protocols.conf << 'EOF'
# VPS Hardening - Disable Unused Network Protocols

# DCCP - CVE-2017-6074: heap out-of-bounds write
install dccp /bin/true
install dccp_ipv4 /bin/true
install dccp_ipv6 /bin/true

# SCTP - Multiple CVEs in kernel SCTP implementation
install sctp /bin/true
install sctp_diag /bin/true

# RDS - CVE-2010-3904: local privilege escalation
install rds /bin/true
install rds_tcp /bin/true
install rds_rdma /bin/true

# TIPC - CVE-2021-43267: heap overflow, remote code execution
install tipc /bin/true

# ATM - Asynchronous Transfer Mode (legacy)
install atm /bin/true

# AX.25 / NETROM / ROSE - Amateur Radio protocols
install ax25 /bin/true
install netrom /bin/true
install rose /bin/true

# X.25 - Legacy packet switching
install x25 /bin/true

# DECnet - Legacy DEC protocol
install decnet /bin/true

# Econet - Legacy Acorn protocol
install econet /bin/true

# AF_802154 - IEEE 802.15.4 (IoT, rarely needed on VPS)
install af_802154 /bin/true

# CAN - Controller Area Network (automotive)
install can /bin/true

# NFC - Near Field Communication
install nfc /bin/true
EOF
    
    chmod 644 /etc/modprobe.d/99-vps-disable-protocols.conf
    print_status "Core dangerous protocols disabled"
    
    print_subsection "Optional Module Disabling"
    
    local optional_modules=()
    
    if confirm "Disable USB storage? (recommended for remote VPS)" "y"; then
        optional_modules+=("install usb-storage /bin/true" "install uas /bin/true")
        print_status "USB storage modules disabled"
    fi
    
    if confirm "Disable FireWire? (DMA attack vector)" "y"; then
        optional_modules+=("install firewire-core /bin/true" "install firewire-ohci /bin/true" "install firewire-sbp2 /bin/true")
        print_status "FireWire modules disabled"
    fi
    
    if confirm "Disable Thunderbolt? (DMA attack vector)" "y"; then
        optional_modules+=("install thunderbolt /bin/true")
        print_status "Thunderbolt module disabled"
    fi
    
    if confirm "Disable Bluetooth? (not needed on VPS)" "y"; then
        optional_modules+=("install bluetooth /bin/true" "install btusb /bin/true")
        print_status "Bluetooth modules disabled"
    fi
    
    if confirm "Disable CIFS/SMB client? (unless mounting Windows shares)" "y"; then
        optional_modules+=("install cifs /bin/true")
        print_status "CIFS/SMB client disabled"
    fi
    
    if confirm "Disable NFS client? (unless mounting NFS shares)" "y"; then
        optional_modules+=("install nfs /bin/true" "install nfsv3 /bin/true" "install nfsv4 /bin/true")
        print_status "NFS client modules disabled"
    fi
    
    if [ ${#optional_modules[@]} -gt 0 ]; then
        echo "" >> /etc/modprobe.d/99-vps-disable-protocols.conf
        echo "# ---- Optional Disabled Modules ----" >> /etc/modprobe.d/99-vps-disable-protocols.conf
        for mod in "${optional_modules[@]}"; do
            echo "$mod" >> /etc/modprobe.d/99-vps-disable-protocols.conf
        done
    fi
    
    print_subsection "Unloading Active Modules"
    
    local modules_to_unload=("dccp" "sctp" "rds" "tipc")
    for mod in "${modules_to_unload[@]}"; do
        if lsmod | grep -q "^${mod} "; then
            if rmmod "$mod" 2>>"$LOG_FILE"; then
                print_status "Unloaded active module: ${mod}"
            else
                print_warning "Could not unload ${mod} (may be in use)"
            fi
        fi
    done
    
    echo ""
    print_info "Changes take full effect after reboot"
    print_info "Verify with: lsmod | grep -E 'dccp|sctp|rds|tipc'"
    
    mark_completed "disable_unused_protocols"
}

# ----------------------------------------------------------------------------
# Function: setup_apparmor
# Purpose: Enable and enforce AppArmor mandatory access control
# ----------------------------------------------------------------------------
setup_apparmor() {
    print_section "APPARMOR - MANDATORY ACCESS CONTROL"
    
    print_info "AppArmor confines programs to a limited set of resources,"
    print_info "preventing compromised services from accessing unauthorized files."
    echo ""
    
    if ! command_exists apparmor_status && ! command_exists aa-status; then
        print_step "Installing AppArmor..."
        apt-get install -y apparmor apparmor-utils >> "$LOG_FILE" 2>&1
        print_status "AppArmor base packages installed"
    fi
    
    print_step "Installing additional AppArmor profiles..."
    apt-get install -y apparmor-profiles apparmor-profiles-extra >> "$LOG_FILE" 2>&1 || \
        print_warning "Some extra profiles may not be available for your OS version"
    print_status "AppArmor profiles installed"
    
    print_subsection "Kernel Support Check"
    
    if [ -d /sys/kernel/security/apparmor ]; then
        print_status "AppArmor kernel module is loaded"
    else
        print_warning "AppArmor kernel module not detected"
        print_info "You may need to add 'apparmor=1 security=apparmor' to GRUB"
        
        if confirm "Add AppArmor to kernel boot parameters?"; then
            backup_file /etc/default/grub
            
            if ! grep -q "apparmor=1" /etc/default/grub; then
                sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 apparmor=1 security=apparmor"/' /etc/default/grub
                
                if command_exists update-grub; then
                    update-grub >> "$LOG_FILE" 2>&1
                elif command_exists grub2-mkconfig; then
                    grub2-mkconfig -o /boot/grub2/grub.cfg >> "$LOG_FILE" 2>&1
                fi
                
                print_status "AppArmor boot parameters added (active after reboot)"
            else
                print_info "AppArmor already in boot parameters"
            fi
        fi
    fi
    
    print_subsection "Profile Enforcement"
    
    local enforced_count=0
    local failed_count=0
    
    if command_exists aa-enforce; then
        print_step "Switching all profiles to enforce mode..."
        
        for profile in /etc/apparmor.d/*; do
            local basename
            basename=$(basename "$profile")
            
            if [ -d "$profile" ]; then continue; fi
            
            case "$basename" in
                local|abstractions|tunables|disable|force-complain|lxc|README|*.dpkg-*|*.rpmsave|*.rpmnew)
                    continue ;;
            esac
            
            if aa-enforce "$profile" >> "$LOG_FILE" 2>&1; then
                ((enforced_count++))
            else
                ((failed_count++))
            fi
        done
        
        print_status "Enforced: ${enforced_count} profiles"
        [ "$failed_count" -gt 0 ] && print_warning "Failed: ${failed_count} profiles (see log)"
    else
        print_warning "aa-enforce command not available"
    fi
    
    print_subsection "Service Activation"
    
    systemctl enable apparmor >> "$LOG_FILE" 2>&1
    systemctl restart apparmor >> "$LOG_FILE" 2>&1
    
    if service_active "apparmor"; then
        print_status "AppArmor service is active"
    else
        print_warning "AppArmor service may not be running"
    fi
    
    print_subsection "Current Status"
    if command_exists aa-status; then
        aa-status 2>/dev/null | head -15
    fi
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}aa-status${NC}                    # Show profile status"
    echo -e "    ${CYAN}aa-complain /path/to/bin${NC}     # Set to complain mode"
    echo -e "    ${CYAN}aa-enforce /path/to/bin${NC}      # Set to enforce mode"
    echo -e "    ${CYAN}aa-logprof${NC}                   # Review and update profiles"
    
    mark_completed "setup_apparmor"
}

# ----------------------------------------------------------------------------
# Function: setup_aide
# Purpose: Install and configure AIDE file integrity monitoring
# ----------------------------------------------------------------------------
setup_aide() {
    print_section "FILE INTEGRITY MONITORING (AIDE)"
    
    print_info "AIDE creates a database of file checksums and attributes."
    print_info "It detects unauthorized changes to system binaries and configs."
    echo ""
    
    if ! command_exists aide; then
        print_step "Installing AIDE..."
        apt-get install -y aide aide-common >> "$LOG_FILE" 2>&1
        print_status "AIDE installed"
    fi
    
    backup_file /etc/aide/aide.conf
    
    print_subsection "AIDE Configuration"
    
    cat > /etc/aide/aide.conf.d/99_vps_hardening << 'EOF'
# VPS Hardening - Custom AIDE Rules

/etc/ssh/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/sudoers$ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/sudoers.d/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/pam.d/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/systemd/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/cron.* p+i+n+u+g+s+b+acl+xattrs+sha512
/var/spool/cron/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/modprobe.d/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/ufw/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/fail2ban/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/apparmor/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/apparmor.d/ p+i+n+u+g+s+b+acl+xattrs+sha512

!/var/log/.*
!/var/cache/.*
!/var/tmp/.*
!/run/.*
!/dev/.*
!/proc/.*
!/sys/.*
!/tmp/.*
EOF
    
    chmod 644 /etc/aide/aide.conf.d/99_vps_hardening
    print_status "Custom AIDE rules created"
    
    print_subsection "Database Initialization"
    print_warning "This process may take 5-15 minutes depending on disk size..."
    
    if confirm "Initialize AIDE database now?"; then
        print_step "Initializing AIDE database (please wait)..."
        
        local start_time
        start_time=$(date +%s)
        
        if aideinit >> "$LOG_FILE" 2>&1; then
            local end_time
            end_time=$(date +%s)
            local duration=$(( end_time - start_time ))
            print_status "AIDE database initialized in ${duration} seconds"
        else
            print_warning "AIDE initialization had warnings (see log)"
        fi
        
        if [ -f /var/lib/aide/aide.db.new ]; then
            cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            chmod 600 /var/lib/aide/aide.db
            print_status "Database activated"
        elif [ -f /var/lib/aide/aide.db.new.gz ]; then
            cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
            chmod 600 /var/lib/aide/aide.db.gz
            print_status "Database activated (compressed)"
        else
            print_warning "Database file not found in expected location"
        fi
    else
        print_info "Skipping initialization. Run manually: aideinit"
    fi
    
    print_subsection "Automated Integrity Checks"
    
    cat > /etc/cron.daily/aide-integrity-check << 'CRONEOF'
#!/bin/bash
# VPS Hardening - Daily AIDE Integrity Check

REPORT_FILE="/var/log/aide/aide-check-$(date +%Y%m%d).log"
mkdir -p /var/log/aide

/usr/bin/aide --check > "$REPORT_FILE" 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    logger -t aide-check -p auth.warning "AIDE detected changes! See $REPORT_FILE"
    
    # Send Telegram alert if configured
    if [ -f /etc/vps-hardening/telegram.conf ]; then
        source /etc/vps-hardening/telegram.conf
        MSG="🚨 <b>AIDE Alert</b>%0AFile integrity changes detected on $(hostname)%0ASee: ${REPORT_FILE}"
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}" -d "text=${MSG}" \
            -d "parse_mode=HTML" > /dev/null 2>&1
    fi
else
    logger -t aide-check -p auth.info "AIDE check passed - no changes detected"
fi

find /var/log/aide/ -name "aide-check-*.log" -mtime +30 -delete 2>/dev/null
exit 0
CRONEOF
    
    chmod 755 /etc/cron.daily/aide-integrity-check
    mkdir -p /var/log/aide
    print_status "Daily AIDE integrity check scheduled"
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}aide --check${NC}              # Run integrity check"
    echo -e "    ${CYAN}aide --update${NC}             # Update database after changes"
    echo -e "    ${CYAN}cat /var/log/aide/*.log${NC}   # View check reports"
    
    mark_completed "setup_aide"
}

# ----------------------------------------------------------------------------
# Function: setup_auditd
# Purpose: Install and configure kernel audit daemon
# ----------------------------------------------------------------------------
setup_auditd() {
    print_section "KERNEL AUDIT DAEMON (auditd)"
    
    print_info "auditd logs security-relevant events at the kernel level."
    print_info "Attackers cannot easily hide from kernel-level auditing."
    echo ""
    
    if ! command_exists auditctl; then
        print_step "Installing auditd..."
        apt-get install -y auditd audispd-plugins >> "$LOG_FILE" 2>&1
        print_status "auditd installed"
    fi
    
    backup_directory /etc/audit
    backup_directory /etc/audit/rules.d
    
    print_subsection "Audit Rules Configuration"
    
    mkdir -p /etc/audit/rules.d
    
    cat > /etc/audit/rules.d/99-vps-hardening.rules << 'EOF'
# VPS Hardening - Comprehensive Audit Rules

-D
-b 8192
-f 1

# ---- Identity & Authentication ----
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# ---- Sudo & Privilege Escalation ----
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /usr/bin/sudo -p x -k sudo_exec
-w /usr/bin/su -p x -k su_exec

# ---- SSH Configuration & Keys ----
-w /etc/ssh/ -p wa -k sshd_config
-w /root/.ssh/ -p wa -k root_ssh_keys
-w /etc/ssh/sshd_config -p wa -k sshd_main_config

# ---- Cron Job Monitoring ----
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/at.allow -p wa -k cron
-w /etc/cron.allow -p wa -k cron

# ---- Kernel Module Operations ----
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules

# ---- Network Configuration ----
-w /etc/hosts -p wa -k network
-w /etc/resolv.conf -p wa -k network
-w /etc/hostname -p wa -k network
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/ufw/ -p wa -k firewall

# ---- System Time Changes ----
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b64 -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# ---- Login/Logout Events ----
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/run/utmp -p wa -k session

# ---- AppArmor & Fail2ban ----
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor
-w /etc/fail2ban/ -p wa -k fail2ban

# ---- File Deletion by Users ----
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k file_delete

# ---- Failed Access Attempts ----
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EPERM -k access_denied
-a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EPERM -k access_denied

# ---- Executable File Modifications ----
-w /usr/bin/ -p wa -k bin_modification
-w /usr/sbin/ -p wa -k sbin_modification
-w /usr/local/bin/ -p wa -k local_bin_modification

-e 2
EOF
    
    chmod 640 /etc/audit/rules.d/99-vps-hardening.rules
    print_status "Comprehensive audit rules created"
    
    print_subsection "Daemon Configuration"
    
    backup_file /etc/audit/auditd.conf
    
    cat > /etc/audit/auditd.conf << 'EOF'
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 50
num_logs = 10
priority_boost = 4
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 75
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
distribute_network = no
q_depth = 1200
overflow_action = SYSLOG
max_restarts = 10
plugin_dir = /etc/audit/plugins.d
EOF
    
    chmod 640 /etc/audit/auditd.conf
    print_status "Audit daemon configured"
    
    print_subsection "Service Activation"
    
    systemctl enable auditd >> "$LOG_FILE" 2>&1
    systemctl restart auditd >> "$LOG_FILE" 2>&1 || true
    
    if service_active "auditd"; then
        print_status "auditd is active and running"
    else
        print_warning "auditd may not be running (some VPS kernels restrict it)"
    fi
    
    local rule_count
    rule_count=$(auditctl -l 2>/dev/null | wc -l || echo "0")
    print_info "Loaded audit rules: ${rule_count}"
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}ausearch -k sudoers${NC}        # Search sudo events"
    echo -e "    ${CYAN}ausearch -k identity${NC}       # Search identity changes"
    echo -e "    ${CYAN}ausearch -k access_denied${NC}  # Search failed access"
    echo -e "    ${CYAN}aureport --auth${NC}            # Authentication report"
    echo -e "    ${CYAN}aureport --failed${NC}          # Failed events report"
    
    mark_completed "setup_auditd"
}

# ----------------------------------------------------------------------------
# Function: secure_tmp_directories
# Purpose: Secure /tmp and /var/tmp with restrictive mount options
# ----------------------------------------------------------------------------
secure_tmp_directories() {
    print_section "SECURE TEMPORARY DIRECTORIES"
    
    print_info "Attackers often use /tmp and /var/tmp to stage exploits."
    print_info "Mounting them with noexec,nosuid,nodev prevents execution."
    echo ""
    
    backup_file /etc/fstab
    
    print_subsection "Securing /tmp"
    
    if mount | grep -q " /tmp " && mount | grep " /tmp " | grep -q "noexec"; then
        print_info "/tmp is already mounted with noexec"
    else
        if confirm "Mount /tmp with noexec,nosuid,nodev?"; then
            if grep -q " /tmp " /etc/fstab; then
                sed -i '/ \/tmp /d' /etc/fstab
            fi
            
            echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab
            
            if mount -o remount /tmp 2>>"$LOG_FILE"; then
                print_status "/tmp secured and remounted"
            else
                print_warning "/tmp remount failed. Will apply on next reboot."
            fi
        fi
    fi
    
    print_subsection "Securing /var/tmp"
    
    if mount | grep -q " /var/tmp " && mount | grep " /var/tmp " | grep -q "noexec"; then
        print_info "/var/tmp is already mounted with noexec"
    else
        if confirm "Mount /var/tmp with noexec,nosuid,nodev?"; then
            if grep -q " /var/tmp " /etc/fstab; then
                sed -i '/ \/var\/tmp /d' /etc/fstab
            fi
            
            echo "tmpfs /var/tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=1G 0 0" >> /etc/fstab
            
            if mount -o remount /var/tmp 2>>"$LOG_FILE"; then
                print_status "/var/tmp secured and remounted"
            else
                print_warning "/var/tmp remount failed. Will apply on next reboot."
            fi
        fi
    fi
    
    print_subsection "Temporary File Cleanup"
    
    if confirm "Configure aggressive /tmp cleanup (files older than 7 days)?" "n"; then
        mkdir -p /etc/tmpfiles.d
        cat > /etc/tmpfiles.d/99-vps-hardening.conf << 'EOF'
q /tmp 1777 root root 7d
q /var/tmp 1777 root root 7d
EOF
        chmod 644 /etc/tmpfiles.d/99-vps-hardening.conf
        print_status "Temp file cleanup configured (7-day retention)"
    fi
    
    echo ""
    print_info "Verify mounts: mount | grep -E '/tmp|/var/tmp'"
    
    mark_completed "secure_tmp_directories"
}

# End of Section 3
# ============================================================================
# TIER 2: ADVANCED SECURITY CONTROLS (PART 1)
# ============================================================================

# ----------------------------------------------------------------------------
# Function: setup_resource_limits
# Purpose: Configure resource limits to prevent fork bombs and DoS
# ----------------------------------------------------------------------------
setup_resource_limits() {
    print_section "RESOURCE LIMITS & FORK BOMB PROTECTION"
    
    print_info "Resource limits prevent a single user or compromised process"
    print_info "from consuming all system resources (CPU, RAM, processes)."
    echo ""
    
    backup_directory /etc/security/limits.d
    backup_file /etc/security/limits.conf
    
    print_subsection "Process & Memory Limits"
    
    local nproc_hard="" nproc_soft="" nofile_hard=""
    prompt_input "Max processes per user (hard)" "512" nproc_hard
    prompt_input "Max processes per user (soft)" "256" nproc_soft
    prompt_input "Max open files per user (hard)" "65536" nofile_hard
    
    cat > /etc/security/limits.d/99-vps-hardening.conf << EOF
# ============================================================
# VPS Hardening - Resource Limits
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# ---- Fork Bomb Protection ----
*               hard    nproc           ${nproc_hard}
*               soft    nproc           ${nproc_soft}
root            hard    nproc           unlimited
root            soft    nproc           unlimited

# ---- File Descriptor Limits ----
*               hard    nofile          ${nofile_hard}
*               soft    nofile          8192
root            hard    nofile          1048576
root            soft    nofile          65536

# ---- Memory Lock Limits ----
*               hard    memlock         65536
*               soft    memlock         65536

# ---- Core Dump Prevention ----
*               hard    core            0
*               soft    core            0
root            hard    core            0

# ---- Stack Size Limits ----
*               hard    stack           8192
*               soft    stack           8192

# ---- Max Logins ----
*               hard    maxlogins       5
root            hard    maxlogins       unlimited
EOF
    
    chmod 644 /etc/security/limits.d/99-vps-hardening.conf
    print_status "Resource limits configured"
    
    print_subsection "PAM Integration"
    
    local pam_files=("/etc/pam.d/common-session" "/etc/pam.d/common-session-noninteractive")
    local pam_file
    for pam_file in "${pam_files[@]}"; do
        if [ -f "$pam_file" ]; then
            if ! grep -q "pam_limits.so" "$pam_file" 2>/dev/null; then
                echo "session required pam_limits.so" >> "$pam_file"
                print_status "pam_limits.so added to ${pam_file}"
            else
                print_info "pam_limits.so already in ${pam_file}"
            fi
        fi
    done
    
    print_subsection "Systemd Core Dump Control"
    
    mkdir -p /etc/systemd/coredump.conf.d
    cat > /etc/systemd/coredump.conf.d/99-vps-hardening.conf << 'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
ExternalSizeMax=0
JournalSizeMax=0
EOF
    
    chmod 644 /etc/systemd/coredump.conf.d/99-vps-hardening.conf
    systemctl daemon-reload 2>/dev/null || true
    print_status "Systemd core dumps disabled"
    
    cat > /etc/sysctl.d/98-coredump.conf << 'EOF'
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
EOF
    
    chmod 644 /etc/sysctl.d/98-coredump.conf
    sysctl --system >> "$LOG_FILE" 2>&1 || true
    print_status "Kernel core dump pattern disabled"
    
    echo ""
    print_info "Verify limits: ulimit -a"
    print_info "Verify for user: su - ${TARGET_USER} -c 'ulimit -a'"
    
    mark_completed "setup_resource_limits"
}

# ----------------------------------------------------------------------------
# Function: disable_unnecessary_services
# Purpose: Audit and disable unnecessary running services
# ----------------------------------------------------------------------------
disable_unnecessary_services() {
    print_section "DISABLE UNNECESSARY SERVICES"
    
    print_info "Every running service is a potential attack surface."
    print_info "This function helps identify and disable services you don't need."
    echo ""
    
    print_subsection "Currently Listening Services"
    ss -tlnp 2>/dev/null | grep LISTEN | awk '{printf "    %-30s %s\n", $4, $6}' || \
        print_warning "Could not list listening services"
    echo ""
    
    # Declare associative array explicitly
    declare -A service_descriptions
    service_descriptions=(
        ["rpcbind"]="RPC Bind (NFS/SUN-RPC, rarely needed on VPS)"
        ["rpc-statd"]="NFS Status Monitor"
        ["nfs-server"]="NFS File Server"
        ["nfs-kernel-server"]="NFS Kernel Server"
        ["cups"]="CUPS Print Server (not needed on VPS)"
        ["avahi-daemon"]="Avahi mDNS/DNS-SD (local network discovery)"
        ["bluetooth"]="Bluetooth Service"
        ["apache2"]="Apache HTTP Server"
        ["nginx"]="Nginx HTTP Server"
        ["postfix"]="Postfix Mail Transfer Agent"
        ["exim4"]="Exim Mail Transfer Agent"
        ["dovecot"]="Dovecot IMAP/POP3 Server"
        ["mysql"]="MySQL Database Server"
        ["mariadb"]="MariaDB Database Server"
        ["postgresql"]="PostgreSQL Database Server"
        ["redis-server"]="Redis In-Memory Database"
        ["memcached"]="Memcached Cache Server"
        ["mongodb"]="MongoDB Database"
        ["snapd"]="Snap Package Manager Daemon"
        ["multipathd"]="Multipath Device Mapper"
        ["lvm2-lvmpolld"]="LVM Poll Daemon"
        ["rsync"]="Rsync Daemon"
        ["telnetd"]="Telnet Server (INSECURE)"
        ["vsftpd"]="vsftpd FTP Server"
        ["proftpd"]="ProFTPD FTP Server"
        ["named"]="BIND DNS Server"
        ["dnsmasq"]="Dnsmasq DNS/DHCP"
        ["docker"]="Docker Container Engine"
        ["containerd"]="Containerd Runtime"
        ["libvirtd"]="Libvirt Virtualization"
        ["qemu-kvm"]="QEMU/KVM Virtualization"
        ["smbd"]="Samba SMB File Sharing"
        ["nmbd"]="Samba NetBIOS"
        ["atd"]="At Job Scheduler"
        ["rsyslog"]="Rsyslog System Logger"
        ["systemd-journal-remote"]="Remote Journal Receiver"
        ["systemd-journal-upload"]="Remote Journal Uploader"
    )
    
    # Sort services for display
    local sorted_services
    sorted_services=($(echo "${!service_descriptions[@]}" | tr ' ' '\n' | sort))
    
    print_subsection "Service Audit"
    print_info "Review each service. Only disable what you are sure you don't need."
    print_warning "Disabling the wrong service can break your applications!"
    echo ""
    
    local disabled_count=0
    local svc
    for svc in "${sorted_services[@]}"; do
        local desc="${service_descriptions[$svc]}"
        
        if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
            local state
            state=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
            local active
            active=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
            
            if [ "$state" != "not-found" ] && [ "$state" != "masked" ]; then
                local status_color="${GREEN}"
                [ "$active" = "active" ] && status_color="${RED}"
                
                echo -e "  ${status_color}[${active}]${NC} ${BOLD}${svc}${NC} - ${desc}"
                
                if confirm "  Disable and mask ${svc}?" "n"; then
                    systemctl stop "$svc" 2>>"$LOG_FILE" || true
                    systemctl disable "$svc" 2>>"$LOG_FILE" || true
                    systemctl mask "$svc" 2>>"$LOG_FILE" || true
                    print_status "Disabled and masked: ${svc}"
                    ((disabled_count++))
                fi
            fi
        fi
    done
    
    print_subsection "Systemd Socket Hardening"
    
    local sockets_to_mask=(
        "systemd-journal-remote.socket"
        "systemd-journal-upload.socket"
        "systemd-journal-gatewayd.socket"
    )
    
    local sock
    for sock in "${sockets_to_mask[@]}"; do
        if systemctl list-unit-files "$sock" &>/dev/null 2>&1; then
            local sock_state
            sock_state=$(systemctl is-enabled "$sock" 2>/dev/null || echo "not-found")
            if [ "$sock_state" != "not-found" ] && [ "$sock_state" != "masked" ]; then
                if confirm "Mask ${sock}?"; then
                    systemctl stop "$sock" 2>/dev/null || true
                    systemctl mask "$sock" 2>/dev/null || true
                    print_status "Masked: ${sock}"
                    ((disabled_count++))
                fi
            fi
        fi
    done
    
    echo ""
    print_status "Service audit complete. ${disabled_count} services disabled."
    print_info "To unmask a service: systemctl unmask <service>"
    
    mark_completed "disable_unnecessary_services"
}

# ----------------------------------------------------------------------------
# Function: restrict_cron_at
# Purpose: Restrict cron and at scheduler access
# ----------------------------------------------------------------------------
restrict_cron_at() {
    print_section "RESTRICT CRON & AT ACCESS"
    
    print_info "Limiting cron and at access prevents unauthorized scheduled tasks."
    echo ""
    
    print_subsection "Cron Access Control"
    
    local cron_users_input=""
    prompt_input "Users allowed to use cron (comma-separated)" "root" cron_users_input
    
    rm -f /etc/cron.deny
    
    : > /etc/cron.allow
    IFS=',' read -ra CRON_ARRAY <<< "$cron_users_input"
    local user
    for user in "${CRON_ARRAY[@]}"; do
        user=$(echo "$user" | xargs)
        if [ -n "$user" ]; then
            if id "$user" &>/dev/null; then
                echo "$user" >> /etc/cron.allow
                print_status "Cron access granted: ${user}"
            else
                print_warning "User '${user}' does not exist. Skipping."
            fi
        fi
    done
    
    chmod 640 /etc/cron.allow
    chown root:root /etc/cron.allow
    print_status "Cron allow list configured"
    
    print_subsection "Cron Directory Permissions"
    
    local cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
    local dir
    for dir in "${cron_dirs[@]}"; do
        if [ -d "$dir" ]; then
            chmod 700 "$dir" 2>/dev/null || true
            chown root:root "$dir" 2>/dev/null || true
        fi
    done
    
    if [ -f /etc/crontab ]; then
        chmod 600 /etc/crontab
        chown root:root /etc/crontab
    fi
    
    if [ -f /etc/anacrontab ]; then
        chmod 600 /etc/anacrontab
        chown root:root /etc/anacrontab
    fi
    
    print_status "Cron directories secured (700/600 permissions)"
    
    print_subsection "At Scheduler Control"
    
    if command_exists at; then
        if confirm "Remove 'at' scheduler entirely? (recommended for VPS)" "y"; then
            apt-get purge -y at >> "$LOG_FILE" 2>&1
            print_status "'at' scheduler removed"
        else
            rm -f /etc/at.deny
            : > /etc/at.allow
            echo "root" >> /etc/at.allow
            chmod 640 /etc/at.allow
            chown root:root /etc/at.allow
            print_status "'at' restricted to root only"
        fi
    else
        print_info "'at' scheduler is not installed"
    fi
    
    print_subsection "Existing Cron Jobs Audit"
    
    echo -e "  ${BOLD}System crontab:${NC}"
    if [ -f /etc/crontab ]; then
        grep -v '^#\|^$\|^SHELL\|^PATH\|^MAILTO' /etc/crontab 2>/dev/null | \
            while IFS= read -r line; do
                echo -e "    ${GRAY}${line}${NC}"
            done
    fi
    
    echo -e "  ${BOLD}User crontabs:${NC}"
    local cron_user
    for cron_user in $(cut -f1 -d: /etc/passwd 2>/dev/null); do
        local user_cron
        user_cron=$(crontab -l -u "$cron_user" 2>/dev/null | grep -v '^#\|^$' || true)
        if [ -n "$user_cron" ]; then
            echo -e "    ${CYAN}${cron_user}:${NC}"
            echo "$user_cron" | while IFS= read -r line; do
                echo -e "      ${GRAY}${line}${NC}"
            done
        fi
    done
    
    mark_completed "restrict_cron_at"
}

# ----------------------------------------------------------------------------
# Function: setup_dns_over_tls
# Purpose: Configure encrypted DNS to prevent DNS snooping
# ----------------------------------------------------------------------------
setup_dns_over_tls() {
    print_section "DNS OVER TLS (ENCRYPTED DNS)"
    
    print_info "Standard DNS queries are sent in plaintext."
    print_info "DNS over TLS encrypts queries to prevent snooping and manipulation."
    echo ""
    
    print_subsection "Current DNS Configuration"
    if [ -f /etc/resolv.conf ]; then
        grep "^nameserver" /etc/resolv.conf | while IFS= read -r line; do
            echo -e "    ${GRAY}${line}${NC}"
        done
    fi
    echo ""
    
    if ! service_exists "systemd-resolved"; then
        print_step "Installing systemd-resolved..."
        apt-get install -y systemd-resolved >> "$LOG_FILE" 2>&1
    fi
    
    backup_file /etc/systemd/resolved.conf
    
    print_subsection "DNS Provider Selection"
    
    local dns_choice=""
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Select DNS provider:"
    echo -e "      ${CYAN}1)${NC} Cloudflare (1.1.1.1) - Fast, privacy-focused"
    echo -e "      ${CYAN}2)${NC} Quad9 (9.9.9.9) - Security-focused, malware blocking"
    echo -e "      ${CYAN}3)${NC} Google (8.8.8.8) - Reliable, widely used"
    echo -e "      ${CYAN}4)${NC} Cloudflare + Quad9 (recommended, redundant)"
    echo -e "      ${CYAN}5)${NC} Custom DNS servers"
    echo ""
    prompt_input "Choice" "4" dns_choice
    
    local dns_servers="" fallback_dns=""
    
    case "$dns_choice" in
        1)
            dns_servers="1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com"
            fallback_dns="9.9.9.9#dns.quad9.net"
            ;;
        2)
            dns_servers="9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net"
            fallback_dns="1.1.1.1#cloudflare-dns.com"
            ;;
        3)
            dns_servers="8.8.8.8#dns.google 8.8.4.4#dns.google"
            fallback_dns="1.1.1.1#cloudflare-dns.com"
            ;;
        4)
            dns_servers="1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net"
            fallback_dns="1.0.0.1#cloudflare-dns.com 149.112.112.112#dns.quad9.net"
            ;;
        5)
            prompt_input "Primary DNS (IP#hostname)" "" dns_servers
            prompt_input "Fallback DNS (IP#hostname)" "" fallback_dns
            ;;
        *)
            dns_servers="1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net"
            fallback_dns="1.0.0.1#cloudflare-dns.com 149.112.112.112#dns.quad9.net"
            ;;
    esac
    
    print_subsection "Applying Configuration"
    
    cat > /etc/systemd/resolved.conf << EOF
# ============================================================
# VPS Hardening - DNS over TLS Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

[Resolve]
DNS=${dns_servers}
FallbackDNS=${fallback_dns}
DNSOverTLS=yes
DNSSEC=allow-downgrade
Cache=yes
CacheFromLocalhost=no
DNSStubListener=yes
MulticastDNS=no
LLMNR=no
EOF
    
    chmod 644 /etc/systemd/resolved.conf
    print_status "systemd-resolved configured"
    
    systemctl enable systemd-resolved >> "$LOG_FILE" 2>&1
    systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1
    
    if service_active "systemd-resolved"; then
        print_status "systemd-resolved is active"
    else
        print_warning "systemd-resolved failed to start"
    fi
    
    print_subsection "Resolv.conf Integration"
    
    local current_link=""
    if [ -L /etc/resolv.conf ]; then
        current_link=$(readlink /etc/resolv.conf)
    fi
    
    if [ "$current_link" != "/run/systemd/resolve/stub-resolv.conf" ]; then
        if confirm "Replace /etc/resolv.conf with systemd-resolved stub? (recommended)"; then
            backup_file /etc/resolv.conf
            rm -f /etc/resolv.conf
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            print_status "/etc/resolv.conf linked to systemd-resolved stub"
        else
            print_info "Keeping existing /etc/resolv.conf"
            print_warning "DNS over TLS may not be fully effective"
        fi
    else
        print_info "/etc/resolv.conf already linked correctly"
    fi
    
    print_subsection "Local Network Spoofing Prevention"
    print_status "LLMNR disabled (configured in resolved.conf)"
    print_status "MulticastDNS disabled (configured in resolved.conf)"
    
    echo ""
    print_info "Verify with: resolvectl status"
    print_info "Test DNS: resolvectl query example.com"
    
    mark_completed "setup_dns_over_tls"
}

# ----------------------------------------------------------------------------
# Function: setup_login_security
# Purpose: Configure login timeouts, password quality, and PAM hardening
# ----------------------------------------------------------------------------
setup_login_security() {
    print_section "LOGIN & PASSWORD SECURITY"
    
    print_subsection "Password Quality Requirements"
    
    if confirm "Install and configure password quality enforcement?"; then
        apt-get install -y libpam-pwquality >> "$LOG_FILE" 2>&1
        backup_file /etc/security/pwquality.conf
        
        local min_len="" min_class=""
        prompt_input "Minimum password length" "14" min_len
        prompt_input "Minimum character classes (upper,lower,digit,special)" "3" min_class
        
        cat > /etc/security/pwquality.conf << EOF
# ============================================================
# VPS Hardening - Password Quality Requirements
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================
minlen = ${min_len}
minclass = ${min_class}
maxrepeat = 3
maxclassrepeat = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
reject_username
enforce_for_root
difok = 4
palindrome
EOF
        
        chmod 644 /etc/security/pwquality.conf
        print_status "Password quality requirements configured"
    fi
    
    print_subsection "Login Failure Delay"
    
    if confirm "Add delay after failed login attempts? (anti-brute-force)"; then
        local delay_seconds=""
        prompt_input "Delay in seconds" "4" delay_seconds
        local delay_micro=$(( delay_seconds * 1000000 ))
        
        backup_file /etc/pam.d/common-auth
        
        if ! grep -q "pam_faildelay.so" /etc/pam.d/common-auth 2>/dev/null; then
            sed -i "1i auth optional pam_faildelay.so delay=${delay_micro}" /etc/pam.d/common-auth
            print_status "Login failure delay: ${delay_seconds} seconds"
        else
            sed -i "s/pam_faildelay.so delay=[0-9]*/pam_faildelay.so delay=${delay_micro}/" /etc/pam.d/common-auth
            print_status "Login failure delay updated: ${delay_seconds} seconds"
        fi
    fi
    
    print_subsection "Shell Session Timeout"
    
    local timeout_val=""
    prompt_input "Auto-logout after inactivity (seconds, 0 to skip)" "900" timeout_val
    
    if [ "$timeout_val" != "0" ] && [ -n "$timeout_val" ]; then
        cat > /etc/profile.d/99-vps-timeout.sh << EOF
# VPS Hardening - Shell Session Timeout
TMOUT=${timeout_val}
readonly TMOUT
export TMOUT
EOF
        chmod 644 /etc/profile.d/99-vps-timeout.sh
        print_status "Shell auto-logout: ${timeout_val} seconds ($(( timeout_val / 60 )) minutes)"
    fi
    
    print_subsection "Login History & MOTD"
    
    backup_file /etc/login.defs
    
    if confirm "Set minimum password age to 1 day? (prevents rapid cycling)"; then
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
        print_status "Minimum password age: 1 day"
    fi
    
    if confirm "Set maximum password age to 90 days?"; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
        print_status "Maximum password age: 90 days"
    fi
    
    if confirm "Set password warning period to 14 days?"; then
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
        print_status "Password expiry warning: 14 days"
    fi
    
    if confirm "Increase bash history size and add timestamps?"; then
        cat > /etc/profile.d/99-vps-history.sh << 'EOF'
HISTSIZE=10000
HISTFILESIZE=20000
HISTCONTROL=ignoredups:erasedups
HISTTIMEFORMAT="%F %T "
shopt -s histappend
PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"
readonly HISTFILE
EOF
        chmod 644 /etc/profile.d/99-vps-history.sh
        print_status "Bash history enhanced"
    fi
    
    mark_completed "setup_login_security"
}

# ----------------------------------------------------------------------------
# Function: setup_user_hardening
# Purpose: Lock unused accounts, restrict umask, harden user defaults
# ----------------------------------------------------------------------------
setup_user_hardening() {
    print_section "USER ACCOUNT HARDENING"
    
    print_subsection "Lock Unused System Accounts"
    
    if confirm "Lock default system accounts that should never log in?"; then
        local accounts_to_lock=(
            "daemon" "bin" "sys" "games" "man" "lp"
            "mail" "news" "uucp" "proxy" "www-data"
            "backup" "list" "irc" "gnats" "nobody"
            "systemd-network" "systemd-resolve" "messagebus"
            "syslog" "uuidd" "tcpdump" "sshd" "pollinate"
        )
        
        local locked_count=0
        local acct
        for acct in "${accounts_to_lock[@]}"; do
            if id "$acct" &>/dev/null; then
                if [ "$acct" != "$TARGET_USER" ] && [ "$acct" != "root" ]; then
                    usermod -L "$acct" 2>>"$LOG_FILE" || true
                    usermod -s /usr/sbin/nologin "$acct" 2>>"$LOG_FILE" || true
                    ((locked_count++))
                fi
            fi
        done
        
        print_status "Locked ${locked_count} unused system accounts"
    fi
    
    print_subsection "Default Umask"
    
    local umask_val=""
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Select default umask:"
    echo -e "      ${CYAN}1)${NC} 022 - Default (owner: rw, group: r, others: r)"
    echo -e "      ${CYAN}2)${NC} 027 - Restrictive (owner: rw, group: r, others: none) [recommended]"
    echo -e "      ${CYAN}3)${NC} 077 - Strict (owner: rw, group: none, others: none)"
    echo ""
    prompt_input "Choice" "2" umask_val
    
    case "$umask_val" in
        1) umask_val="022" ;;
        2) umask_val="027" ;;
        3) umask_val="077" ;;
        *) umask_val="027" ;;
    esac
    
    backup_file /etc/login.defs
    sed -i "s/^UMASK.*/UMASK           ${umask_val}/" /etc/login.defs
    
    cat > /etc/profile.d/99-vps-umask.sh << EOF
umask ${umask_val}
EOF
    chmod 644 /etc/profile.d/99-vps-umask.sh
    print_status "Default umask set to ${umask_val}"
    
    print_subsection "Home Directory Permissions"
    
    if confirm "Restrict home directory permissions to 750?"; then
        local username uid homedir shell
        while IFS=: read -r username _ uid _ _ homedir shell; do
            if [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ] && [ -d "$homedir" ]; then
                if [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
                    chmod 750 "$homedir" 2>/dev/null || true
                    print_status "Restricted: ${homedir} -> 750"
                fi
            fi
        done < /etc/passwd
        
        backup_file /etc/adduser.conf
        if [ -f /etc/adduser.conf ]; then
            sed -i 's/^DIR_MODE=.*/DIR_MODE=0750/' /etc/adduser.conf
        fi
        print_status "New user home directories will default to 750"
    fi
    
    print_subsection "Account Expiration Defaults"
    
    if confirm "Set default account inactivity lock to 30 days?"; then
        backup_file /etc/default/useradd
        if [ -f /etc/default/useradd ]; then
            sed -i 's/^INACTIVE=.*/INACTIVE=30/' /etc/default/useradd
        else
            echo "INACTIVE=30" > /etc/default/useradd
        fi
        print_status "Accounts locked after 30 days of inactivity"
    fi
    
    print_subsection "TTY Access Restriction"
    
    if confirm "Restrict root login to specific TTYs? (console only)"; then
        backup_file /etc/securetty
        cat > /etc/securetty << 'EOF'
console
tty1
tty2
EOF
        chmod 600 /etc/securetty
        print_status "Root TTY access restricted to console"
    fi
    
    mark_completed "setup_user_hardening"
}

# End of Section 4
# ============================================================================
# TIER 2 CONTINUED: AUDITING, LOG FORWARDING, KERNEL LOCKDOWN
# ============================================================================

# ----------------------------------------------------------------------------
# Function: install_lynis
# Purpose: Install Lynis security auditing tool with automated scans
# ----------------------------------------------------------------------------
install_lynis() {
    print_section "SECURITY AUDITING (LYNIS)"
    
    print_info "Lynis performs a comprehensive security audit based on"
    print_info "CIS benchmarks, checking hundreds of security controls."
    echo ""
    
    if ! command_exists lynis; then
        print_step "Installing Lynis..."
        apt-get install -y lynis >> "$LOG_FILE" 2>&1
        print_status "Lynis installed"
    else
        print_info "Lynis is already installed"
        local lynis_version
        lynis_version=$(lynis --version 2>/dev/null | head -1 || echo "unknown")
        print_info "Version: ${lynis_version}"
    fi
    
    print_subsection "Initial Security Audit"
    
    if confirm "Run a quick Lynis security audit now? (takes 2-5 minutes)"; then
        print_step "Running Lynis audit (this may take a few minutes)..."
        echo ""
        
        local audit_output
        audit_output=$(lynis audit system --quick --no-colors 2>&1) || true
        
        local hardening_index
        hardening_index=$(echo "$audit_output" | grep -i "Hardening index" | grep -oP '\d+' | head -1 || echo "N/A")
        
        local warnings_count
        warnings_count=$(echo "$audit_output" | grep -i "Warnings" | grep -oP '\d+' | head -1 || echo "N/A")
        
        local suggestions_count
        suggestions_count=$(echo "$audit_output" | grep -i "Suggestions" | grep -oP '\d+' | head -1 || echo "N/A")
        
        echo ""
        print_separator
        echo -e "  ${BOLD}Lynis Audit Summary:${NC}"
        echo -e "    Hardening Index: ${CYAN}${hardening_index}/100${NC}"
        echo -e "    Warnings:        ${YELLOW}${warnings_count}${NC}"
        echo -e "    Suggestions:     ${MAGENTA}${suggestions_count}${NC}"
        print_separator
        
        echo "$audit_output" > "/root/lynis-initial-audit-${TIMESTAMP}.txt"
        print_status "Full report saved: /root/lynis-initial-audit-${TIMESTAMP}.txt"
    fi
    
    print_subsection "Automated Weekly Audits"
    
    if confirm "Schedule weekly automated Lynis audits?"; then
        cat > /etc/cron.weekly/lynis-security-audit << 'CRONEOF'
#!/bin/bash
# VPS Hardening - Weekly Lynis Security Audit

REPORT_DIR="/var/log/lynis"
mkdir -p "$REPORT_DIR"

DATE=$(date +%Y%m%d)
REPORT_FILE="${REPORT_DIR}/lynis-report-${DATE}.txt"
LOG_FILE="${REPORT_DIR}/lynis-log-${DATE}.log"

/usr/bin/lynis audit system --cronjob --report-file "$REPORT_FILE" > "$LOG_FILE" 2>&1

HARDENING=$(grep -i "Hardening index" "$REPORT_FILE" 2>/dev/null | grep -oP '\d+' | head -1)

logger -t lynis-audit -p auth.info "Weekly audit complete. Hardening index: ${HARDENING:-unknown}"

THRESHOLD=65
if [ -n "$HARDENING" ] && [ "$HARDENING" -lt "$THRESHOLD" ]; then
    logger -t lynis-audit -p auth.warning "ALERT: Hardening index ${HARDENING} below threshold ${THRESHOLD}!"
    
    # Send Telegram alert if configured
    if [ -f /etc/vps-hardening/telegram.conf ]; then
        source /etc/vps-hardening/telegram.conf
        MSG="⚠️ <b>Lynis Alert</b>%0AHardening index dropped to ${HARDENING}/100 on $(hostname)"
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}" -d "text=${MSG}" \
            -d "parse_mode=HTML" > /dev/null 2>&1
    fi
fi

find "$REPORT_DIR" -name "lynis-*" -mtime +84 -delete 2>/dev/null
exit 0
CRONEOF
        
        chmod 755 /etc/cron.weekly/lynis-security-audit
        mkdir -p /var/log/lynis
        print_status "Weekly Lynis audit scheduled"
    fi
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}lynis audit system${NC}           # Full interactive audit"
    echo -e "    ${CYAN}lynis audit system --quick${NC}   # Quick audit"
    echo -e "    ${CYAN}lynis show details${NC}           # Show test details"
    
    mark_completed "install_lynis"
}

# ----------------------------------------------------------------------------
# Function: setup_log_forwarding
# Purpose: Configure remote log forwarding for anti-tampering
# ----------------------------------------------------------------------------
setup_log_forwarding() {
    print_section "LOG FORWARDING (ANTI-TAMPERING)"
    
    print_info "If an attacker gains root, their first move is deleting logs."
    print_info "Remote log forwarding sends copies to an external server"
    print_info "so evidence survives even if the VPS is fully compromised."
    echo ""
    
    print_subsection "Remote Syslog Server"
    
    local remote_server=""
    prompt_input "Remote syslog server address (e.g., logs.example.com)" "" remote_server
    
    if [ -z "$remote_server" ]; then
        print_warning "No server specified. Skipping log forwarding."
        print_info "You can configure this later by re-running this option."
        return 0
    fi
    
    local remote_port=""
    prompt_input "Remote syslog port" "514" remote_port
    
    local remote_proto=""
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Protocol:"
    echo -e "      ${CYAN}1)${NC} TCP (reliable, recommended)"
    echo -e "      ${CYAN}2)${NC} UDP (faster, may lose packets)"
    echo -e "      ${CYAN}3)${NC} TLS (encrypted, requires certificates)"
    echo ""
    prompt_input "Choice" "1" remote_proto
    
    if ! command_exists rsyslogd; then
        print_step "Installing rsyslog..."
        apt-get install -y rsyslog >> "$LOG_FILE" 2>&1
    fi
    
    backup_directory /etc/rsyslog.d
    
    print_subsection "Configuring Forwarding"
    
    local proto_prefix="@"
    local proto_label="UDP"
    
    case "$remote_proto" in
        1)
            proto_prefix="@@"
            proto_label="TCP"
            ;;
        2)
            proto_prefix="@"
            proto_label="UDP"
            ;;
        3)
            proto_prefix="@@"
            proto_label="TLS"
            apt-get install -y rsyslog-gnutls >> "$LOG_FILE" 2>&1
            
            cat > /etc/rsyslog.d/10-tls.conf << 'EOF'
global(
    DefaultNetstreamDriver="gtls"
    DefaultNetstreamDriverCAFile="/etc/ssl/certs/ca-certificates.crt"
)
EOF
            chmod 640 /etc/rsyslog.d/10-tls.conf
            print_status "TLS support configured"
            ;;
    esac
    
    cat > /etc/rsyslog.d/50-remote-forwarding.conf << EOF
# VPS Hardening - Remote Log Forwarding
# Target: ${remote_server}:${remote_port} (${proto_label})
*.* ${proto_prefix}${remote_server}:${remote_port}
EOF
    
    chmod 640 /etc/rsyslog.d/50-remote-forwarding.conf
    
    if rsyslogd -N1 >> "$LOG_FILE" 2>&1; then
        systemctl restart rsyslog >> "$LOG_FILE" 2>&1
        print_status "Log forwarding active: ${remote_server}:${remote_port} (${proto_label})"
    else
        print_error "Rsyslog configuration validation failed"
    fi
    
    print_subsection "Local Log Protection"
    
    if confirm "Make log files append-only with chattr?"; then
        local log_files=("/var/log/auth.log" "/var/log/syslog" "/var/log/kern.log" "/var/log/fail2ban.log")
        local log_file
        for log_file in "${log_files[@]}"; do
            if [ -f "$log_file" ]; then
                chattr +a "$log_file" 2>>"$LOG_FILE" || true
                print_status "Append-only: ${log_file}"
            fi
        done
        
        print_warning "Immutable logs may interfere with log rotation."
        print_info "To remove: chattr -a /var/log/auth.log"
    fi
    
    echo ""
    print_info "Verify forwarding: logger 'test message' && check remote server"
    
    mark_completed "setup_log_forwarding"
}

# ----------------------------------------------------------------------------
# Function: setup_kernel_lockdown
# Purpose: Enable kernel lockdown and module signing enforcement
# ----------------------------------------------------------------------------
setup_kernel_lockdown() {
    print_section "KERNEL LOCKDOWN & MODULE RESTRICTIONS"
    
    print_warning "═══════════════════════════════════════════════════════════"
    print_warning "  Kernel lockdown restricts even root from accessing raw"
    print_warning "  memory, loading unsigned modules, and modifying kernel"
    print_warning "  code. This may break some monitoring tools."
    print_warning "═══════════════════════════════════════════════════════════"
    echo ""
    
    print_subsection "Current Kernel Status"
    
    if [ -f /sys/kernel/security/lockdown ]; then
        local current_lockdown
        current_lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "unknown")
        print_info "Current lockdown: ${current_lockdown}"
    else
        print_info "Kernel lockdown not available (may need newer kernel)"
    fi
    
    print_info "Kernel: ${KERNEL_VERSION}"
    print_info "Secure Boot: $(mokutil --sb-state 2>/dev/null || echo 'unknown')"
    echo ""
    
    print_subsection "Kernel Lockdown Mode"
    
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Select lockdown mode:"
    echo -e "      ${CYAN}1)${NC} None - No lockdown (default)"
    echo -e "      ${CYAN}2)${NC} Integrity - Prevent kernel modification (recommended)"
    echo -e "      ${CYAN}3)${NC} Confidentiality - Prevent kernel data extraction (strict)"
    echo ""
    
    local lockdown_choice=""
    prompt_input "Choice" "2" lockdown_choice
    
    local lockdown_mode=""
    case "$lockdown_choice" in
        1) lockdown_mode="" ;;
        2) lockdown_mode="integrity" ;;
        3) lockdown_mode="confidentiality" ;;
        *) lockdown_mode="integrity" ;;
    esac
    
    if [ -n "$lockdown_mode" ]; then
        backup_file /etc/default/grub
        
        if grep -q "lockdown=" /etc/default/grub; then
            sed -i "s/lockdown=[a-z]*/lockdown=${lockdown_mode}/" /etc/default/grub
        else
            sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 lockdown=${lockdown_mode}\"/" /etc/default/grub
        fi
        
        if command_exists update-grub; then
            update-grub >> "$LOG_FILE" 2>&1
            print_status "Kernel lockdown '${lockdown_mode}' configured (active after reboot)"
        elif command_exists grub2-mkconfig; then
            grub2-mkconfig -o /boot/grub2/grub.cfg >> "$LOG_FILE" 2>&1
            print_status "Kernel lockdown '${lockdown_mode}' configured (active after reboot)"
        else
            print_warning "GRUB update command not found. Add manually."
        fi
    else
        print_info "No lockdown mode selected"
    fi
    
    print_subsection "Kernel Module Restrictions"
    
    if confirm "Prevent loading new kernel modules after boot?"; then
        print_warning "After reboot, NO new kernel modules can be loaded."
        
        if confirm "Are you sure? This is difficult to reverse without console access."; then
            cat > /etc/sysctl.d/97-module-lock.conf << 'EOF'
# WARNING: Irreversible until reboot
kernel.modules_disabled = 1
EOF
            chmod 644 /etc/sysctl.d/97-module-lock.conf
            print_status "Module loading will be disabled on next boot"
        fi
    fi
    
    if confirm "Enforce kernel module signature verification?"; then
        cat > /etc/modprobe.d/99-module-signing.conf << 'EOF'
options module.sig_enforce=1
EOF
        chmod 644 /etc/modprobe.d/99-module-signing.conf
        print_status "Module signature enforcement configured"
    fi
    
    print_subsection "Additional Kernel Protections"
    
    if confirm "Disable kernel profiling for non-root?"; then
        cat >> /etc/sysctl.d/99-vps-hardening.conf << 'EOF'

# Restrict perf events to root
kernel.perf_event_paranoid = 3
EOF
        sysctl --system >> "$LOG_FILE" 2>&1 || true
        print_status "Kernel profiling restricted"
    fi
    
    echo ""
    print_info "Most kernel lockdown features require a reboot to activate"
    
    mark_completed "setup_kernel_lockdown"
}

# ============================================================================
# TIER 3: ZERO TRUST NETWORKING
# ============================================================================

# ----------------------------------------------------------------------------
# Function: setup_tailscale
# Purpose: Install Tailscale VPN for zero-trust SSH access
# ----------------------------------------------------------------------------
setup_tailscale() {
    print_section "TAILSCALE VPN (ZERO TRUST NETWORK)"
    
    print_info "Tailscale creates an encrypted WireGuard mesh network."
    print_info "Once connected, you can remove SSH from the public internet"
    print_info "entirely, making your VPS invisible to port scanners."
    echo ""
    
    if command_exists tailscale; then
        print_info "Tailscale is already installed"
        local ts_status
        ts_status=$(tailscale status 2>/dev/null | head -3 || echo "not connected")
        echo -e "    ${GRAY}${ts_status}${NC}"
        echo ""
    else
        if ! confirm "Install Tailscale?"; then
            return 0
        fi
        
        print_step "Installing Tailscale..."
        if curl -fsSL https://tailscale.com/install.sh | sh >> "$LOG_FILE" 2>&1; then
            print_status "Tailscale installed"
        else
            print_error "Tailscale installation failed"
            return 1
        fi
    fi
    
    print_subsection "Tailscale Authentication"
    
    if ! tailscale status &>/dev/null 2>&1; then
        print_step "Starting Tailscale authentication..."
        print_info "You will need to open a URL in your browser to authenticate."
        echo ""
        tailscale up 2>&1 || true
        echo ""
    else
        print_info "Tailscale is already authenticated"
    fi
    
    print_subsection "Tailscale Network Info"
    
    local ts_ip
    ts_ip=$(tailscale ip -4 2>/dev/null || echo "pending...")
    print_info "Tailscale IP: ${ts_ip}"
    
    local ts_hostname
    ts_hostname=$(tailscale status 2>/dev/null | head -1 | awk '{print $1}' || echo "unknown")
    print_info "Tailscale hostname: ${ts_hostname}"
    
    print_subsection "SSH Access Restriction"
    
    if command_exists ufw; then
        if [ -z "$SSH_PORT" ]; then
            SSH_PORT=$(load_state "SSH_PORT")
            SSH_PORT="${SSH_PORT:-2222}"
        fi
        
        print_warning "This will remove public SSH access and only allow"
        print_warning "connections through the Tailscale network interface."
        echo ""
        
        if confirm "Restrict SSH to Tailscale interface ONLY?"; then
            ufw delete allow "${SSH_PORT}/tcp" 2>/dev/null || true
            ufw delete limit "${SSH_PORT}/tcp" 2>/dev/null || true
            
            ufw allow in on tailscale0 to any port "${SSH_PORT}" proto tcp \
                comment "SSH via Tailscale only" >> "$LOG_FILE" 2>&1
            
            ufw reload >> "$LOG_FILE" 2>&1
            print_status "SSH restricted to Tailscale interface"
            
            echo ""
            print_warning "═══════════════════════════════════════════════════════════"
            print_warning "  SSH is now ONLY accessible via Tailscale!"
            print_warning "  Connect with: ssh -p ${SSH_PORT} ${ts_ip}"
            print_warning "  Make sure Tailscale is running on your local machine!"
            print_warning "═══════════════════════════════════════════════════════════"
        fi
    else
        print_warning "UFW not found. Configure iptables manually."
    fi
    
    print_subsection "Tailscale SSH (Optional)"
    
    if confirm "Enable Tailscale SSH? (SSH through Tailscale without managing keys)"; then
        tailscale up --ssh >> "$LOG_FILE" 2>&1
        print_status "Tailscale SSH enabled"
    fi
    
    if confirm "Enable Tailscale auto-updates?"; then
        tailscale set --auto-update >> "$LOG_FILE" 2>&1 || true
        print_status "Tailscale auto-updates enabled"
    fi
    
    echo ""
    print_info "Useful commands:"
    echo -e "    ${CYAN}tailscale status${NC}          # Show network status"
    echo -e "    ${CYAN}tailscale ip${NC}              # Show Tailscale IPs"
    echo -e "    ${CYAN}tailscale ping <host>${NC}     # Test connectivity"
    
    mark_completed "setup_tailscale"
}

# ----------------------------------------------------------------------------
# Function: setup_fwknop
# Purpose: Configure Single Packet Authorization for invisible SSH
# ----------------------------------------------------------------------------
setup_fwknop() {
    print_section "SINGLE PACKET AUTHORIZATION (fwknop)"
    
    print_info "fwknop keeps your SSH port completely CLOSED and invisible."
    print_info "You send one encrypted UDP 'knock' packet from your device"
    print_info "to temporarily open the port for your IP only (30 seconds)."
    echo ""
    print_info "Workflow:"
    echo -e "    ${GRAY}1. Port is BLOCKED (invisible to scanners)${NC}"
    echo -e "    ${GRAY}2. You send encrypted knock from phone/laptop${NC}"
    echo -e "    ${GRAY}3. Port opens for YOUR IP for 30 seconds${NC}"
    echo -e "    ${GRAY}4. You SSH in during the window${NC}"
    echo -e "    ${GRAY}5. Port closes automatically${NC}"
    echo ""
    
    if ! confirm "Install and configure fwknop?"; then
        return 0
    fi
    
    if ! command_exists fwknopd; then
        print_step "Installing fwknop..."
        apt-get install -y fwknop-server >> "$LOG_FILE" 2>&1
        print_status "fwknop installed"
    fi
    
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        SSH_PORT="${SSH_PORT:-2222}"
    fi
    
    backup_file /etc/fwknop/fwknopd.conf
    backup_file /etc/fwknop/access.conf
    
    print_subsection "Key Generation"
    
    local spa_key
    spa_key=$(openssl rand -base64 32)
    local hmac_key
    hmac_key=$(openssl rand -base64 32)
    
    print_status "Encryption keys generated"
    
    print_subsection "Server Configuration"
    
    local primary_iface
    primary_iface=$(ip route | grep default | awk '{print $5}' | head -1)
    primary_iface="${primary_iface:-eth0}"
    
    cat > /etc/fwknop/access.conf << EOF
# VPS Hardening - fwknop Access Configuration
SOURCE                  ANY
OPEN_PORTS              tcp/${SSH_PORT}
FW_ACCESS_TIMEOUT       30
REQUIRE_SOURCE_ADDRESS  Y
KEY_BASE64              ${spa_key}
HMAC_KEY_BASE64         ${hmac_key}
EOF
    
    chmod 600 /etc/fwknop/access.conf
    
    if [ -f /etc/fwknop/fwknopd.conf ]; then
        sed -i "s/^#\?PCAP_INTF .*/PCAP_INTF             ${primary_iface};/" /etc/fwknop/fwknopd.conf 2>/dev/null || true
    fi
    
    systemctl enable fwknop-server >> "$LOG_FILE" 2>&1
    
    if systemctl restart fwknop-server >> "$LOG_FILE" 2>&1; then
        print_status "fwknop server started"
    else
        print_warning "fwknop failed to start. Check: journalctl -u fwknop-server"
    fi
    
    if command_exists ufw; then
        if confirm "Block SSH port in UFW (fwknop will open it on demand)?"; then
            ufw delete allow "${SSH_PORT}/tcp" 2>/dev/null || true
            ufw delete limit "${SSH_PORT}/tcp" 2>/dev/null || true
            print_status "SSH port blocked in UFW (fwknop manages access)"
        fi
    fi
    
    print_subsection "Client Configuration (SAVE THIS!)"
    
    echo ""
    print_warning "═══════════════════════════════════════════════════════════"
    print_warning "  SAVE THESE CREDENTIALS IN A SECURE LOCATION!"
    print_warning "═══════════════════════════════════════════════════════════"
    echo ""
    echo -e "  ${BOLD}SPA Key:${NC}     ${YELLOW}${spa_key}${NC}"
    echo -e "  ${BOLD}HMAC Key:${NC}    ${YELLOW}${hmac_key}${NC}"
    echo -e "  ${BOLD}SSH Port:${NC}    ${YELLOW}${SSH_PORT}${NC}"
    echo -e "  ${BOLD}Server IP:${NC}   ${YELLOW}$(hostname -I | awk '{print $1}')${NC}"
    echo ""
    echo -e "  ${BOLD}Client Command (Linux/macOS):${NC}"
    echo -e "    ${CYAN}fwknop -A tcp/${SSH_PORT} -D <SERVER_IP> \\${NC}"
    echo -e "    ${CYAN}  --key-base64 ${spa_key} \\${NC}"
    echo -e "    ${CYAN}  --hmac-base64 ${hmac_key}${NC}"
    echo ""
    echo -e "  ${BOLD}Mobile Apps:${NC}"
    echo -e "    ${GRAY}• Android: FWKnop2 (Play Store)${NC}"
    echo -e "    ${GRAY}• iOS: FWKnop (App Store)${NC}"
    echo ""
    
    local creds_file="/root/.fwknop-credentials-${TIMESTAMP}.txt"
    cat > "$creds_file" << EOF
fwknop Credentials - Generated $(date)
========================================
Server IP:  $(hostname -I | awk '{print $1}')
SSH Port:   ${SSH_PORT}
SPA Key:    ${spa_key}
HMAC Key:   ${hmac_key}

Client Command:
fwknop -A tcp/${SSH_PORT} -D <SERVER_IP> \
  --key-base64 ${spa_key} \
  --hmac-base64 ${hmac_key}
EOF
    chmod 600 "$creds_file"
    print_info "Credentials saved to: ${creds_file}"
    
    mark_completed "setup_fwknop"
}

# End of Section 5
# ============================================================================
# INTERACTIVE TELEGRAM BOT (TWO-WAY COMMUNICATION)
# ============================================================================
# Full interactive bot with inline menus, remote management, push alerts
# Uses only Python 3 standard library (no pip required)
# ============================================================================

readonly TG_CONFIG="/etc/vps-hardening/telegram.conf"
readonly TG_BOT_DIR="/opt/vps-telegram-bot"
readonly TG_BOT_SCRIPT="${TG_BOT_DIR}/bot.py"
readonly TG_BOT_SERVICE="vps-telegram-bot.service"

# ----------------------------------------------------------------------------
# Function: setup_telegram_interactive
# Purpose: Deploy the full interactive Telegram bot
# ----------------------------------------------------------------------------
setup_telegram_interactive() {
    print_section "INTERACTIVE TELEGRAM BOT"

    print_info "This creates a two-way Telegram bot that lets you:"
    echo -e "    ${GRAY}• Run commands from Telegram (/status, /health, /security)${NC}"
    echo -e "    ${GRAY}• Navigate with clickable inline button menus${NC}"
    echo -e "    ${GRAY}• Manage services, firewall, and users remotely${NC}"
    echo -e "    ${GRAY}• Receive real-time alerts with action buttons${NC}"
    echo -e "    ${GRAY}• Download log files and reports directly${NC}"
    echo ""

    print_subsection "Prerequisites"
    echo -e "  ${CYAN}1.${NC} Create a bot via ${BOLD}@BotFather${NC} on Telegram:"
    echo -e "     ${GRAY}/newbot → name it → copy the token${NC}"
    echo -e "  ${CYAN}2.${NC} Get your Chat ID via ${BOLD}@userinfobot${NC}:"
    echo -e "     ${GRAY}/start → copy numeric ID${NC}"
    echo -e "  ${CYAN}3.${NC} Start a chat with your bot and send ${BOLD}/start${NC}"
    echo ""

    if ! confirm "Ready with your Bot Token and Chat ID?"; then
        return 0
    fi

    print_subsection "Credentials"

    local bot_token="" chat_id=""
    while true; do
        prompt_input "Bot Token (from @BotFather)" "" bot_token
        [[ "$bot_token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] && break
        print_error "Invalid format. Example: 123456789:ABCdefGHIjklMNOpqrs"
    done

    while true; do
        prompt_input "Your Chat ID (numeric)" "" chat_id
        [[ "$chat_id" =~ ^-?[0-9]+$ ]] && break
        print_error "Must be numeric"
    done

    print_step "Testing connection..."
    local test_resp
    test_resp=$(curl -s "https://api.telegram.org/bot${bot_token}/getMe" 2>&1)
    if echo "$test_resp" | grep -q '"ok":true'; then
        local bot_name
        bot_name=$(echo "$test_resp" | grep -oP '"username":"[^"]*"' | cut -d'"' -f4)
        print_status "Connected to @${bot_name}"
    else
        print_error "Invalid token or network error"
        return 1
    fi

    mkdir -p /etc/vps-hardening
    chmod 700 /etc/vps-hardening

    cat > "$TG_CONFIG" << EOF
# VPS Hardening - Interactive Telegram Bot
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
TELEGRAM_BOT_TOKEN="${bot_token}"
TELEGRAM_CHAT_ID="${chat_id}"
TELEGRAM_HOSTNAME="$(hostname)"
TELEGRAM_SERVER_IP="$(hostname -I | awk '{print $1}')"
NOTIFY_SSH_LOGIN=true
NOTIFY_FAIL2BAN=true
NOTIFY_HIGH_LOAD=true
NOTIFY_DISK_FULL=true
NOTIFY_SECURITY_UPDATES=true
NOTIFY_ROOT_LOGIN=true
DISK_WARN_THRESHOLD=80
DISK_CRITICAL_THRESHOLD=90
MEMORY_WARN_THRESHOLD=85
LOAD_WARN_THRESHOLD=5.0
FAILED_LOGIN_THRESHOLD=10
BOT_POLL_INTERVAL=2
EOF

    chmod 600 "$TG_CONFIG"
    print_status "Configuration saved"

    print_step "Registering bot commands..."
    curl -s -X POST "https://api.telegram.org/bot${bot_token}/setMyCommands" \
        -H "Content-Type: application/json" \
        -d '{"commands":[
            {"command":"start","description":"Welcome & main menu"},
            {"command":"menu","description":"Interactive button menu"},
            {"command":"status","description":"Quick system status"},
            {"command":"health","description":"Full health report"},
            {"command":"security","description":"Security report"},
            {"command":"firewall","description":"Firewall status"},
            {"command":"services","description":"Service management"},
            {"command":"logs","description":"Recent system logs"},
            {"command":"users","description":"Logged-in users"},
            {"command":"updates","description":"Package updates"},
            {"command":"ban","description":"Ban IP (usage: /ban 1.2.3.4)"},
            {"command":"unban","description":"Unban an IP"},
            {"command":"reboot","description":"Reboot server"},
            {"command":"help","description":"Show all commands"}
        ]}' > /dev/null 2>&1
    print_status "Bot commands registered"

    deploy_interactive_bot
    setup_interactive_notifications

    print_subsection "Starting Bot"
    systemctl daemon-reload
    systemctl enable "$TG_BOT_SERVICE" >> "$LOG_FILE" 2>&1
    systemctl restart "$TG_BOT_SERVICE" >> "$LOG_FILE" 2>&1

    sleep 3
    if systemctl is-active --quiet "$TG_BOT_SERVICE"; then
        print_status "Interactive bot is running!"
    else
        print_error "Bot failed to start. Check: journalctl -u ${TG_BOT_SERVICE}"
    fi

    print_step "Sending welcome message..."
    local welcome="🎉 <b>Interactive Bot Activated!</b>%0A%0A"
    welcome+="Your VPS bot is now online.%0A%0A"
    welcome+="Try: /menu - Button menu%0A/status - Quick status%0A/help - All commands"
    curl -s -X POST "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -d "chat_id=${chat_id}" -d "text=${welcome}" \
        -d "parse_mode=HTML" > /dev/null 2>&1

    echo ""
    print_info "Open Telegram and try /menu on your bot!"
    print_info "Service: systemctl status ${TG_BOT_SERVICE}"
    print_info "Logs: journalctl -u ${TG_BOT_SERVICE} -f"

    mark_completed "setup_telegram_interactive"
}

# ----------------------------------------------------------------------------
# Function: deploy_interactive_bot
# Purpose: Deploy the Python bot daemon
# ----------------------------------------------------------------------------
deploy_interactive_bot() {
    print_step "Deploying interactive bot daemon..."

    mkdir -p "$TG_BOT_DIR"
    chmod 700 "$TG_BOT_DIR"

    cat > "$TG_BOT_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""VPS Hardening Interactive Telegram Bot - Python 3 stdlib only."""
import json, os, subprocess, time, urllib.request, urllib.error
import signal, sys, logging
from datetime import datetime

CONFIG_FILE = "/etc/vps-hardening/telegram.conf"
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("/var/log/vps-telegram-bot.log"),
              logging.StreamHandler()])
logger = logging.getLogger("vps-bot")

def load_config():
    c = {}
    try:
        with open(CONFIG_FILE) as f:
            for l in f:
                l = l.strip()
                if l and not l.startswith("#") and "=" in l:
                    k, v = l.split("=", 1)
                    c[k.strip()] = v.strip().strip('"').strip("'")
    except Exception as e:
        logger.error(f"Config error: {e}")
    return c

CFG = load_config()
TOKEN = CFG.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = CFG.get("TELEGRAM_CHAT_ID", "")
HOST = CFG.get("TELEGRAM_HOSTNAME", "unknown")
IP = CFG.get("TELEGRAM_SERVER_IP", "unknown")
API = f"https://api.telegram.org/bot{TOKEN}"

def tg(method, data=None):
    url = f"{API}/{method}"
    try:
        if data:
            req = urllib.request.Request(url, json.dumps(data).encode(),
                                         {"Content-Type": "application/json"})
        else:
            req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        logger.error(f"API error ({method}): {e}")
        return None

def send(text, cid=None, kb=None, pm="HTML"):
    d = {"chat_id": cid or CHAT_ID, "text": text[:4096], "parse_mode": pm}
    if kb: d["reply_markup"] = kb
    return tg("sendMessage", d)

def edit(mid, text, cid=None, kb=None):
    d = {"chat_id": cid or CHAT_ID, "message_id": mid,
         "text": text[:4096], "parse_mode": "HTML"}
    if kb: d["reply_markup"] = kb
    return tg("editMessageText", d)

def answer_cb(qid, text=""):
    tg("answerCallbackQuery", {"callback_query_id": qid, "text": text})

def kb(rows):
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in r] for r in rows]}

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() or r.stderr.strip() or "No output"
    except subprocess.TimeoutExpired:
        return "⏱ Timed out"
    except Exception as e:
        return f"❌ {e}"

def send_file(path, cid=None, caption=None):
    cid = cid or CHAT_ID
    boundary = "----VPSBot"
    try:
        with open(path, "rb") as f: fdata = f.read()
    except Exception as e:
        send(f"❌ Cannot read: {e}", cid); return
    body = f"--{boundary}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n{cid}\r\n"
    if caption:
        body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"caption\"\r\n\r\n{caption}\r\n"
    body += f"--{boundary}\r\nContent-Disposition: form-data; name=\"document\"; filename=\"{os.path.basename(path)}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    raw = body.encode() + fdata + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{API}/sendDocument", raw,
                                 {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try: urllib.request.urlopen(req, timeout=60)
    except Exception as e: logger.error(f"sendFile: {e}")

# ---- Commands ----
def cmd_start(c):
    send(f"👋 <b>Welcome to {HOST} VPS Bot!</b>\n\n🖥 <code>{HOST}</code>\n🌐 <code>{IP}</code>\n\n/menu for button menu\n/help for all commands", c)

def cmd_help(c):
    send("❓ <b>Commands</b>\n━━━━━━━━━━━━━━━━\n\n"
         "📊 /status - Quick overview\n🏥 /health - Full report\n🔒 /security - Security\n"
         "🔥 /firewall - UFW rules\n⚙️ /services - Manage services\n📦 /updates - Packages\n"
         "👤 /users - Active users\n📋 /logs - System logs\n\n"
         "🛡 /ban <ip> - Ban IP\n🛡 /unban <ip> - Unban IP\n"
         "⚠️ /reboot - Reboot server\n📱 /menu - Button menu", c)

def cmd_status(c):
    t = (f"📊 <b>System Status</b>\n━━━━━━━━━━━━━━━━\n\n"
         f"🖥 <code>{HOST}</code>\n⏱ <code>{run('uptime -p | sed \"s/up //\"')}</code>\n"
         f"⚡ CPU: <code>{run('top -bn1|grep \"Cpu(s)\"|awk \"{print $2+$4}\"')}% ({run('nproc')}c)</code>\n"
         f"📈 Load: <code>{run('uptime|awk -F\"load average:\" \"{print $2}\"|xargs')}</code>\n"
         f"🧠 RAM: <code>{run('free -m|awk \"NR==2{printf \\\"%dMB/%dMB (%.1f%%)\\\",$3,$2,$3/$2*100}\"')}</code>\n"
         f"💾 Disk: <code>{run('df -h /|awk \"NR==2{printf \\\"%s/%s (%s)\\\",$3,$2,$5}\"')}</code>\n"
         f"🌐 Ports: <code>{run('ss -tlnp 2>/dev/null|grep -c LISTEN')} listening</code>\n\n"
         f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>")
    send(t, c, kb([[("🔄 Refresh","cmd_status"),("🏥 Health","cmd_health")],[("🔙 Menu","cmd_menu")]]))

def cmd_health(c):
    t = (f"🏥 <b>Full Health Report</b>\n━━━━━━━━━━━━━━━━\n\n"
         f"🖥 <b>System</b>\n• Host: <code>{HOST}</code>\n• IP: <code>{IP}</code>\n"
         f"• Kernel: <code>{run('uname -r')}</code>\n• Uptime: <code>{run('uptime -p|sed \"s/up //\"')}</code>\n\n"
         f"⚡ <b>Performance</b>\n• CPU: <code>{run('top -bn1|grep \"Cpu(s)\"|awk \"{print $2+$4}\"')}%</code>\n"
         f"• Load: <code>{run('uptime|awk -F\"load average:\" \"{print $2}\"|xargs')}</code>\n"
         f"• RAM: <code>{run('free -m|awk \"NR==2{printf \\\"%dMB/%dMB (%.1f%%)\\\",$3,$2,$3/$2*100}\"')}</code>\n\n"
         f"💾 <b>Storage</b>\n• Root: <code>{run('df -h /|awk \"NR==2{printf \\\"%s/%s (%s)\\\",$3,$2,$5}\"')}</code>\n\n"
         f"🔧 <b>Top Processes</b>\n• CPU: <code>{run('ps aux --sort=-%cpu|awk \"NR==2{print $11,$3\\\"%\\\"}\"')}</code>\n"
         f"• RAM: <code>{run('ps aux --sort=-%mem|awk \"NR==2{print $11,$4\\\"%\\\"}\"')}</code>\n\n"
         f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>")
    send(t, c, kb([[("🔄 Refresh","cmd_health"),("📊 Quick","cmd_status")],[("🔒 Security","cmd_security"),("🔙 Menu","cmd_menu")]]))

def cmd_security(c):
    fl = run("grep 'Failed password' /var/log/auth.log 2>/dev/null|tail -200|wc -l")
    bn = run("fail2ban-client status 2>/dev/null|grep -oP '\\d+(?= currently banned)'|head -1") or "0"
    uf = run("ufw status 2>/dev/null|head -1|awk '{print $2}'")
    up = run("apt list --upgradable 2>/dev/null|grep -v Listing|wc -l")
    su = run("apt list --upgradable 2>/dev/null|grep -ic security") or "0"
    rb = "🔴 Yes" if os.path.exists("/var/run/reboot-required") else "✅ No"
    em = "🔒" if uf == "active" and int(fl or 0) < 50 else "⚠️"
    t = (f"{em} <b>Security Report</b>\n━━━━━━━━━━━━━━━━\n\n"
         f"🔐 <b>SSH (24h)</b>\n• Failed: <code>{fl}</code>\n• Banned: <code>{bn}</code>\n\n"
         f"🔥 <b>Firewall</b>\n• UFW: <code>{uf}</code>\n• Ports: <code>{run('ss -tlnp 2>/dev/null|grep -c LISTEN')}</code>\n\n"
         f"📦 <b>Updates</b>\n• Pending: <code>{up}</code>\n• Security: <code>{su}</code>\n• Reboot: {rb}\n\n"
         f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>")
    send(t, c, kb([[("🔄 Refresh","cmd_security"),("🔥 Firewall","cmd_firewall")],[("📦 Updates","cmd_updates"),("🔙 Menu","cmd_menu")]]))

def cmd_firewall(c):
    send(f"🔥 <b>Firewall</b>\n━━━━━━━━━━━━━━━━\n\n<code>{run('ufw status verbose 2>/dev/null')[:3500]}</code>",
         c, kb([[("🔄 Refresh","cmd_firewall")],[("🔒 Security","cmd_security"),("🔙 Menu","cmd_menu")]]))

def cmd_services(c):
    send("⚙️ <b>Service Management</b>\n━━━━━━━━━━━━━━━━\n\nSelect a service:",
         c, kb([[("SSH","svc_ssh"),("UFW","svc_ufw"),("F2B","svc_f2b")],
                [("Nginx","svc_nginx"),("Apache","svc_apache"),("Docker","svc_docker")],
                [("Cron","svc_cron"),("Auditd","svc_auditd"),("AppArmor","svc_apparmor")],
                [("🔙 Menu","cmd_menu")]]))

def handle_svc(c, name, action="status"):
    m = {"ssh":"ssh","ufw":"ufw","f2b":"fail2ban","nginx":"nginx","apache":"apache2",
         "docker":"docker","cron":"cron","auditd":"auditd","apparmor":"apparmor"}
    svc = m.get(name, name)
    if action == "status":
        st = run(f"systemctl is-active {svc} 2>/dev/null")
        en = run(f"systemctl is-enabled {svc} 2>/dev/null")
        em = "🟢" if st == "active" else "🔴"
        send(f"⚙️ <b>{svc.upper()}</b>\n\n• Status: {em} <code>{st}</code>\n• Enabled: <code>{en}</code>",
             c, kb([[("▶️ Start",f"svc_{name}_start"),("⏹ Stop",f"svc_{name}_stop")],
                    [("🔄 Restart",f"svc_{name}_restart")],
                    [("⚙️ Services","cmd_services"),("🔙 Menu","cmd_menu")]]))
    elif action in ("start","stop","restart"):
        r = run(f"systemctl {action} {svc} 2>&1")
        st = run(f"systemctl is-active {svc} 2>/dev/null")
        em = "🟢" if st == "active" else "🔴"
        send(f"⚙️ <b>{svc.upper()}</b> → {action}\n\n{em} <code>{st}</code>\n<code>{r[:500]}</code>",
             c, kb([[("🔄 Refresh",f"svc_{name}")],[("⚙️ Services","cmd_services"),("🔙 Menu","cmd_menu")]]))

def cmd_logs(c):
    send(f"📋 <b>Recent Logs</b>\n━━━━━━━━━━━━━━━━\n\n<code>{run('tail -30 /var/log/syslog 2>/dev/null||journalctl -n 30 --no-pager 2>/dev/null')[:3500]}</code>",
         c, kb([[("📋 Auth","logs_auth"),("📋 Syslog","logs_sys")],[("📄 Download","logs_dl")],[("🔄 Refresh","cmd_logs"),("🔙 Menu","cmd_menu")]]))

def cmd_users(c):
    send(f"👤 <b>Users</b>\n━━━━━━━━━━━━━━━━\n\n<b>Online:</b>\n<code>{run('who 2>/dev/null||echo None')}</code>\n\n<b>Recent:</b>\n<code>{run('last -n 5 -F 2>/dev/null|head -6')[:1500]}</code>",
         c, kb([[("🔄 Refresh","cmd_users"),("🔙 Menu","cmd_menu")]]))

def cmd_updates(c):
    run("apt-get update -qq 2>/dev/null", 30)
    u = run("apt list --upgradable 2>/dev/null|grep -v Listing|head -20")
    n = run("apt list --upgradable 2>/dev/null|grep -v Listing|wc -l")
    send(f"📦 <b>Updates</b>\n━━━━━━━━━━━━━━━━\n\nAvailable: <code>{n}</code>\n\n<code>{u[:3000]}</code>",
         c, kb([[("📦 Upgrade","confirm_upgrade"),("🔄 Refresh","cmd_updates")],[("🔙 Menu","cmd_menu")]]))

def cmd_ban(c, ip):
    if not ip: send("❌ Usage: /ban <ip>", c); return
    send(f"🚫 <b>Ban</b>\n\nIP: <code>{ip}</code>\n<code>{run(f'fail2ban-client set sshd banip {ip} 2>&1')}</code>", c)

def cmd_unban(c, ip):
    if not ip: send("❌ Usage: /unban <ip>", c); return
    send(f"✅ <b>Unban</b>\n\nIP: <code>{ip}</code>\n<code>{run(f'fail2ban-client set sshd unbanip {ip} 2>&1')}</code>", c)

def cmd_reboot(c):
    send("⚠️ <b>REBOOT SERVER?</b>\n\nThis will disconnect all users.", c,
         kb([[("✅ Yes, Reboot","confirm_reboot"),("❌ Cancel","cmd_menu")]]))

def cmd_menu(c):
    send(f"📱 <b>{HOST} Control Panel</b>\n━━━━━━━━━━━━━━━━\n<i>Select an option:</i>", c,
         kb([[("📊 Status","cmd_status"),("🏥 Health","cmd_health")],
             [("🔒 Security","cmd_security"),("🔥 Firewall","cmd_firewall")],
             [("⚙️ Services","cmd_services"),("📦 Updates","cmd_updates")],
             [("📋 Logs","cmd_logs"),("👤 Users","cmd_users")],
             [("🔄 Reboot","cmd_reboot"),("❓ Help","cmd_help")]]))

# ---- Callback Router ----
def handle_cb(q):
    d = q.get("data","")
    c = q["message"]["chat"]["id"]
    answer_cb(q["id"])
    cmds = {"cmd_menu":cmd_menu,"cmd_status":cmd_status,"cmd_health":cmd_health,
            "cmd_security":cmd_security,"cmd_firewall":cmd_firewall,"cmd_services":cmd_services,
            "cmd_logs":cmd_logs,"cmd_users":cmd_users,"cmd_updates":cmd_updates,
            "cmd_help":cmd_help,"cmd_reboot":cmd_reboot}
    if d in cmds: cmds[d](c)
    elif d.startswith("svc_"):
        p = d.split("_")
        handle_svc(c, p[1], p[2] if len(p)>2 else "status")
    elif d == "logs_auth":
        send(f"📋 <b>Auth Log</b>\n\n<code>{run('tail -30 /var/log/auth.log 2>/dev/null')[:3500]}</code>", c)
    elif d == "logs_sys": cmd_logs(c)
    elif d == "logs_dl": send_file("/var/log/syslog", c, "📄 System log")
    elif d == "confirm_reboot":
        send("🔄 <b>Rebooting...</b>", c); time.sleep(2); run("reboot")
    elif d == "confirm_upgrade":
        send("📦 <b>Upgrading...</b>", c)
        r = run("DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1|tail -20", 300)
        send(f"📦 <b>Done</b>\n\n<code>{r[:3500]}</code>", c)

# ---- Main Loop ----
def main():
    if not TOKEN: logger.error("No token!"); sys.exit(1)
    logger.info(f"Bot started for {HOST}")
    send(f"🟢 <b>Bot Online</b>\n\n{HOST} monitoring active.", CHAT_ID)
    offset = 0
    while True:
        try:
            resp = tg("getUpdates", {"offset": offset, "timeout": 30})
            if not resp or not resp.get("ok"): time.sleep(5); continue
            for u in resp.get("result", []):
                offset = u["update_id"] + 1
                if "message" in u:
                    m = u["message"]; c = m["chat"]["id"]
                    if str(c) != str(CHAT_ID): send("🚫 Unauthorized", c); continue
                    t = m.get("text","").strip()
                    if t == "/start": cmd_start(c)
                    elif t == "/menu": cmd_menu(c)
                    elif t == "/status": cmd_status(c)
                    elif t == "/health": cmd_health(c)
                    elif t == "/security": cmd_security(c)
                    elif t == "/firewall": cmd_firewall(c)
                    elif t == "/services": cmd_services(c)
                    elif t == "/logs": cmd_logs(c)
                    elif t == "/users": cmd_users(c)
                    elif t == "/updates": cmd_updates(c)
                    elif t.startswith("/ban"): cmd_ban(c, t.split(" ",1)[1] if " " in t else "")
                    elif t.startswith("/unban"): cmd_unban(c, t.split(" ",1)[1] if " " in t else "")
                    elif t == "/reboot": cmd_reboot(c)
                    elif t == "/help": cmd_help(c)
                elif "callback_query" in u:
                    q = u["callback_query"]
                    if str(q["message"]["chat"]["id"]) == str(CHAT_ID): handle_cb(q)
        except KeyboardInterrupt: break
        except Exception as e: logger.error(f"Poll error: {e}"); time.sleep(5)

if __name__ == "__main__": main()
PYEOF

    chmod 700 "$TG_BOT_SCRIPT"
    chown -R root:root "$TG_BOT_DIR"
    print_status "Bot daemon deployed"

    cat > "/etc/systemd/system/${TG_BOT_SERVICE}" << EOF
[Unit]
Description=VPS Hardening Interactive Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${TG_BOT_SCRIPT}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vps-telegram-bot
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log /tmp
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "/etc/systemd/system/${TG_BOT_SERVICE}"
    print_status "Systemd service created"
}

# ----------------------------------------------------------------------------
# Function: setup_interactive_notifications
# Purpose: Setup push notifications integrated with the bot
# ----------------------------------------------------------------------------
setup_interactive_notifications() {
    print_step "Setting up push notification hooks..."

    # SSH login PAM hook
    cat > /usr/local/bin/vps-tg-ssh-notify.sh << 'EOF'
#!/bin/bash
[ "$PAM_TYPE" != "open_session" ] && exit 0
source /etc/vps-hardening/telegram.conf 2>/dev/null || exit 0
[ "${NOTIFY_SSH_LOGIN:-true}" != "true" ] && exit 0
USER="${PAM_USER:-unknown}"; IP="${PAM_RHOST:-local}"; TIME=$(date '+%Y-%m-%d %H:%M:%S')
[ "$USER" = "root" ] && E="🚨" || E="🔐"
GEO=""
if [ "$IP" != "local" ] && [ "$IP" != "::1" ] && [ "$IP" != "127.0.0.1" ]; then
    C=$(curl -s --max-time 3 "https://ipapi.co/${IP}/country_name/" 2>/dev/null)
    [ -n "$C" ] && GEO=" | 🌍 ${C}"
fi
MSG="${E} <b>SSH Login</b>%0A👤 <code>${USER}</code> from <code>${IP}</code>${GEO}%0A⏰ <code>${TIME}</code>"
curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT_ID}" -d "text=${MSG}" -d "parse_mode=HTML" > /dev/null 2>&1 &
exit 0
EOF
    chmod 750 /usr/local/bin/vps-tg-ssh-notify.sh
    if ! grep -q "vps-tg-ssh-notify" /etc/pam.d/sshd 2>/dev/null; then
        echo "session optional pam_exec.so /usr/local/bin/vps-tg-ssh-notify.sh" >> /etc/pam.d/sshd
    fi
    print_status "SSH login alerts configured"

    # Resource monitor
    cat > /usr/local/bin/vps-tg-monitor.sh << 'MEOF'
#!/bin/bash
source /etc/vps-hardening/telegram.conf 2>/dev/null || exit 0
SD="/var/lib/vps-hardening"; mkdir -p "$SD"
cd_check() {
    local k="$1" m="${2:-60}" f="$SD/tg-$k.ts"
    [ -f "$f" ] && [ $(( $(date +%s) - $(cat "$f") )) -lt $((m*60)) ] && return 0
    date +%s > "$f"; return 1
}
sa() { curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT_ID}" -d "text=$1" -d "parse_mode=HTML" > /dev/null 2>&1; }

D=$(df / | awk 'NR==2{print $5}' | tr -d '%')
[ "$D" -ge "${DISK_CRITICAL_THRESHOLD:-90}" ] && ! cd_check dc 30 && sa "🚨 <b>CRITICAL: Disk ${D}%</b>"
[ "$D" -ge "${DISK_WARN_THRESHOLD:-80}" ] && [ "$D" -lt "${DISK_CRITICAL_THRESHOLD:-90}" ] && ! cd_check dw 240 && sa "⚠️ <b>Disk Warning: ${D}%</b>"

M=$(free | awk 'NR==2{printf "%.0f",$3/$2*100}')
[ "$M" -ge "${MEMORY_WARN_THRESHOLD:-85}" ] && ! cd_check mem 120 && \
    sa "⚠️ <b>High Memory: ${M}%</b>%0A$(ps aux --sort=-%mem | awk 'NR<=4{printf "• %s: %s%%\n",$11,$4}')"

F=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -100 | wc -l)
[ "$F" -ge "${FAILED_LOGIN_THRESHOLD:-10}" ] && ! cd_check brute 60 && \
    sa "🚨 <b>Brute Force: ${F} failures</b>%0A$(grep 'Failed password' /var/log/auth.log | grep -oP 'from \K[0-9.]+' | sort|uniq -c|sort -rn|head -3|awk '{printf "• %s (%s)\n",$2,$1}')%0AUse /ban to block"

S=$(apt list --upgradable 2>/dev/null | grep -ic security)
[ "$S" -gt 0 ] && ! cd_check su 1440 && sa "📦 <b>${S} Security Updates</b>%0AUse /updates"

[ -f /var/run/reboot-required ] && ! cd_check rb 1440 && sa "🔄 <b>Reboot Required</b>%0AUse /reboot"
MEOF
    chmod 750 /usr/local/bin/vps-tg-monitor.sh

    cat > /etc/cron.d/vps-telegram-monitor << 'EOF'
SHELL=/bin/bash
*/15 * * * * root /usr/local/bin/vps-tg-monitor.sh
EOF
    chmod 644 /etc/cron.d/vps-telegram-monitor
    print_status "Resource monitoring active (every 15 min)"

    # Daily report
    cat > /etc/cron.d/vps-telegram-daily << 'EOF'
SHELL=/bin/bash
0 8 * * * root /usr/bin/python3 -c "
import sys; sys.path.insert(0,'/opt/vps-telegram-bot')
from bot import cmd_health,cmd_security,CHAT_ID
cmd_health(CHAT_ID)
import time; time.sleep(3)
cmd_security(CHAT_ID)
"
EOF
    chmod 644 /etc/cron.d/vps-telegram-daily
    print_status "Daily reports scheduled at 08:00"
}

# ----------------------------------------------------------------------------
# Function: telegram_bot_manage
# Purpose: Manage the interactive bot
# ----------------------------------------------------------------------------
telegram_bot_manage() {
    print_section "TELEGRAM BOT MANAGEMENT"

    if [ ! -f "$TG_CONFIG" ]; then
        print_error "Bot not configured. Run 'Setup Interactive Bot' first."
        return 1
    fi

    local bot_status
    bot_status=$(systemctl is-active "$TG_BOT_SERVICE" 2>/dev/null || echo "inactive")
    local bot_emoji="🔴"
    [ "$bot_status" = "active" ] && bot_emoji="🟢"

    echo -e "  ${BOLD}Bot Status:${NC}  ${bot_emoji} ${bot_status}"
    echo -e "  ${BOLD}Service:${NC}     ${TG_BOT_SERVICE}"
    echo -e "  ${BOLD}Script:${NC}      ${TG_BOT_SCRIPT}"
    echo -e "  ${BOLD}Config:${NC}      ${TG_CONFIG}"
    echo -e "  ${BOLD}Logs:${NC}        journalctl -u ${TG_BOT_SERVICE}"
    echo ""
    echo -e "  ${CYAN}1)${NC} Start bot"
    echo -e "  ${CYAN}2)${NC} Stop bot"
    echo -e "  ${CYAN}3)${NC} Restart bot"
    echo -e "  ${CYAN}4)${NC} View live logs"
    echo -e "  ${CYAN}5)${NC} Edit configuration"
    echo -e "  ${CYAN}6)${NC} Remove bot completely"
    echo -e "  ${CYAN}7)${NC} Return to menu"
    echo ""

    local choice=""
    prompt_input "Choice" "7" choice

    case "$choice" in
        1) systemctl start "$TG_BOT_SERVICE"; print_status "Bot started" ;;
        2) systemctl stop "$TG_BOT_SERVICE"; print_status "Bot stopped" ;;
        3) systemctl restart "$TG_BOT_SERVICE"; print_status "Bot restarted" ;;
        4) journalctl -u "$TG_BOT_SERVICE" -f ;;
        5) ${EDITOR:-nano} "$TG_CONFIG"; systemctl restart "$TG_BOT_SERVICE" ;;
        6)
            if confirm "Remove everything?" "n"; then
                systemctl stop "$TG_BOT_SERVICE" 2>/dev/null
                systemctl disable "$TG_BOT_SERVICE" 2>/dev/null
                rm -f "/etc/systemd/system/${TG_BOT_SERVICE}"
                rm -rf "$TG_BOT_DIR"
                rm -f "$TG_CONFIG"
                rm -f /usr/local/bin/vps-tg-*.sh
                rm -f /etc/cron.d/vps-telegram-*
                sed -i '/vps-tg-ssh-notify/d' /etc/pam.d/sshd 2>/dev/null
                systemctl daemon-reload
                print_status "Bot completely removed"
            fi
            ;;
    esac
}

# End of Section 6
# ============================================================================
# SECURITY STATUS DASHBOARD
# ============================================================================

show_security_status() {
    print_section "CURRENT SECURITY STATUS DASHBOARD"

    print_subsection "System Information"
    echo -e "    ${BOLD}Hostname:${NC}      $(hostname)"
    echo -e "    ${BOLD}OS:${NC}            ${OS_NAME}"
    echo -e "    ${BOLD}Kernel:${NC}        ${KERNEL_VERSION}"
    echo -e "    ${BOLD}Architecture:${NC}  ${ARCH}"
    echo -e "    ${BOLD}Uptime:${NC}        $(uptime -p 2>/dev/null || uptime)"
    echo -e "    ${BOLD}Current User:${NC}  ${TARGET_USER}"
    echo ""

    print_subsection "SSH Configuration"
    local ssh_port_current
    ssh_port_current=$(grep -h "^Port " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}' || echo "22")
    echo -e "    ${BOLD}Port:${NC}                 ${CYAN}${ssh_port_current}${NC}"
    local pass_auth
    pass_auth=$(grep -h "^PasswordAuthentication " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    [ "$pass_auth" = "no" ] && echo -e "    ${BOLD}Password Auth:${NC}        ${GREEN}disabled ✔${NC}" || echo -e "    ${BOLD}Password Auth:${NC}        ${RED}enabled ✘${NC}"
    local root_login
    root_login=$(grep -h "^PermitRootLogin " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    [ "$root_login" = "no" ] && echo -e "    ${BOLD}Root Login:${NC}           ${GREEN}disabled ✔${NC}" || echo -e "    ${BOLD}Root Login:${NC}           ${RED}${root_login} ✘${NC}"
    echo ""

    print_subsection "Firewall (UFW)"
    if command_exists ufw; then
        local ufw_status
        ufw_status=$(ufw status | head -1 | awk '{print $2}')
        [ "$ufw_status" = "active" ] && echo -e "    ${BOLD}Status:${NC}               ${GREEN}active ✔${NC}" || echo -e "    ${BOLD}Status:${NC}               ${RED}inactive ✘${NC}"
    else
        echo -e "    ${BOLD}Status:${NC}               ${RED}not installed ✘${NC}"
    fi
    echo ""

    print_subsection "Intrusion Prevention (Fail2ban)"
    if command_exists fail2ban-client; then
        local f2b_status
        f2b_status=$(systemctl is-active fail2ban 2>/dev/null || echo "inactive")
        if [ "$f2b_status" = "active" ]; then
            echo -e "    ${BOLD}Status:${NC}               ${GREEN}active ✔${NC}"
            local jails
            jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/^\s*//' || echo "none")
            echo -e "    ${BOLD}Active Jails:${NC}         ${CYAN}${jails}${NC}"
        else
            echo -e "    ${BOLD}Status:${NC}               ${RED}inactive ✘${NC}"
        fi
    else
        echo -e "    ${BOLD}Status:${NC}               ${RED}not installed ✘${NC}"
    fi
    echo ""

    print_subsection "Mandatory Access Control (AppArmor)"
    if command_exists aa-status; then
        local aa_enforced
        aa_enforced=$(aa-status 2>/dev/null | grep -oP '\d+(?= profiles are in enforce mode)' | head -1 || echo "0")
        echo -e "    ${BOLD}Enforced Profiles:${NC}    ${GREEN}${aa_enforced}${NC}"
    else
        echo -e "    ${BOLD}Status:${NC}               ${RED}not installed ✘${NC}"
    fi
    echo ""

    print_subsection "Kernel Auditing (auditd)"
    if command_exists auditctl; then
        local audit_status
        audit_status=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
        local audit_rules
        audit_rules=$(auditctl -l 2>/dev/null | wc -l || echo "0")
        [ "$audit_status" = "active" ] && echo -e "    ${BOLD}Status:${NC}               ${GREEN}active (${audit_rules} rules) ✔${NC}" || echo -e "    ${BOLD}Status:${NC}               ${YELLOW}inactive${NC}"
    else
        echo -e "    ${BOLD}Status:${NC}               ${RED}not installed ✘${NC}"
    fi
    echo ""

    print_subsection "File Integrity (AIDE)"
    if command_exists aide; then
        [ -f /var/lib/aide/aide.db ] || [ -f /var/lib/aide/aide.db.gz ] && echo -e "    ${BOLD}Database:${NC}             ${GREEN}initialized ✔${NC}" || echo -e "    ${BOLD}Database:${NC}             ${YELLOW}not initialized${NC}"
    else
        echo -e "    ${BOLD}Status:${NC}               ${RED}not installed ✘${NC}"
    fi
    echo ""

    print_subsection "Kernel Security Parameters"
    echo -e "    ${BOLD}ASLR:${NC}                 $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo 'N/A')/2"
    echo -e "    ${BOLD}dmesg_restrict:${NC}       $(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo 'N/A')"
    echo -e "    ${BOLD}SYN Cookies:${NC}          $(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo 'N/A')"
    echo -e "    ${BOLD}ptrace_scope:${NC}         $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 'N/A')"
    echo ""

    print_subsection "Telegram Bot"
    if [ -f "$TG_CONFIG" ]; then
        local tg_status
        tg_status=$(systemctl is-active "$TG_BOT_SERVICE" 2>/dev/null || echo "inactive")
        [ "$tg_status" = "active" ] && echo -e "    ${BOLD}Status:${NC}               ${GREEN}active ✔${NC}" || echo -e "    ${BOLD}Status:${NC}               ${YELLOW}inactive${NC}"
    else
        echo -e "    ${BOLD}Status:${NC}               ${GRAY}not configured${NC}"
    fi
    echo ""

    print_subsection "Listening Network Ports"
    ss -tlnp 2>/dev/null | grep LISTEN | awk '{printf "    %-30s %s\n", $4, $6}' | head -15
    echo -e "    ${BOLD}Total:${NC} $(ss -tlnp 2>/dev/null | grep -c LISTEN || echo 0) ports"
    echo ""

    print_subsection "System Resources"
    echo -e "    ${BOLD}Disk (/):${NC}             $(df -h / 2>/dev/null | awk 'NR==2{print $5}')"
    echo -e "    ${BOLD}Memory:${NC}               $(free -h 2>/dev/null | awk 'NR==2{printf "%s / %s",$3,$2}')"
    echo -e "    ${BOLD}Load:${NC}                 $(uptime | awk -F'load average:' '{print $2}' | xargs)"
    echo ""
}

# ============================================================================
# REPORT GENERATION
# ============================================================================

generate_report() {
    print_step "Generating hardening report..."

    {
        echo "================================================================"
        echo "  VPS HARDENING REPORT"
        echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Script Version: ${SCRIPT_VERSION}"
        echo "================================================================"
        echo ""
        echo "System: $(hostname) | ${OS_NAME} | ${KERNEL_VERSION}"
        echo "IP: $(hostname -I 2>/dev/null | awk '{print $1}')"
        echo ""
        echo "Completed Tasks (${#COMPLETED_TASKS[@]}):"
        local task
        for task in "${!COMPLETED_TASKS[@]}"; do
            echo "  ✔ ${task} (${COMPLETED_TASKS[$task]})"
        done
        echo ""
        if [ ${#FAILED_TASKS[@]} -gt 0 ]; then
            echo "Failed Tasks (${#FAILED_TASKS[@]}):"
            for task in "${!FAILED_TASKS[@]}"; do
                echo "  ✘ ${task}: ${FAILED_TASKS[$task]}"
            done
            echo ""
        fi
        [ -n "$SSH_PORT" ] && echo "SSH Port: ${SSH_PORT}"
        echo "Backups: ${BACKUP_DIR}"
        echo "Log: ${LOG_FILE}"
        echo "================================================================"
    } > "$REPORT_FILE"

    chmod 600 "$REPORT_FILE"
    print_status "Report saved to: ${REPORT_FILE}"
}

# ============================================================================
# BATCH OPERATIONS
# ============================================================================

run_tier0_essential() {
    print_section "RUNNING ALL TIER 0 - ESSENTIAL HARDENING"
    if ! confirm "Run: System Update, SSH, Firewall, Fail2ban, Kernel, Auto-Updates, User Setup?"; then return 0; fi
    system_update; harden_ssh; configure_firewall; setup_fail2ban
    kernel_hardening; setup_auto_updates; setup_user_account
    print_section "TIER 0 COMPLETE"
}

run_tier0_plus_tier1() {
    print_section "RUNNING TIER 0 + TIER 1"
    if ! confirm "Run all Tier 0 + Tier 1 (13 tasks)?"; then return 0; fi
    system_update; harden_ssh; configure_firewall; setup_fail2ban
    kernel_hardening; setup_auto_updates; setup_user_account
    secure_shared_memory; disable_unused_protocols; setup_apparmor
    setup_aide; setup_auditd; secure_tmp_directories
    print_section "TIER 0 + TIER 1 COMPLETE"
}

run_full_hardening() {
    print_section "RUNNING FULL HARDENING (TIER 0 + 1 + 2)"
    print_warning "This runs 22 hardening tasks. May take 20-40 minutes."
    if ! confirm "Continue with full batch execution?"; then return 0; fi
    system_update; harden_ssh; configure_firewall; setup_fail2ban
    kernel_hardening; setup_auto_updates; setup_user_account
    secure_shared_memory; disable_unused_protocols; setup_apparmor
    setup_aide; setup_auditd; secure_tmp_directories
    setup_resource_limits; disable_unnecessary_services; restrict_cron_at
    setup_dns_over_tls; setup_login_security; setup_user_hardening
    install_lynis; setup_log_forwarding; setup_kernel_lockdown
    print_section "FULL HARDENING COMPLETE"
    print_info "For Zero Trust networking, run options 23 (Tailscale) or 24 (fwknop)"
}

# ============================================================================
# INTERACTIVE MENU
# ============================================================================

show_menu() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════════╗
    ║        VPS HARDENING - INTERACTIVE MENU v3.0                     ║
    ╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    echo -e "  ${GREEN}${BOLD}━━━ TIER 0: ESSENTIAL ━━━${NC}"
    echo -e "   ${WHITE} 1)${NC} System Update & Cleanup"
    echo -e "   ${WHITE} 2)${NC} SSH Hardening"
    echo -e "   ${WHITE} 3)${NC} Firewall (UFW)"
    echo -e "   ${WHITE} 4)${NC} Fail2ban Setup"
    echo -e "   ${WHITE} 5)${NC} Kernel Hardening (sysctl)"
    echo -e "   ${WHITE} 6)${NC} Automatic Security Updates"
    echo -e "   ${WHITE} 7)${NC} User Account & Sudo Setup"
    echo ""

    echo -e "  ${YELLOW}${BOLD}━━━ TIER 1: HIGH IMPACT ━━━${NC}"
    echo -e "   ${WHITE} 8)${NC} Secure Shared Memory (/dev/shm)"
    echo -e "   ${WHITE} 9)${NC} Disable Unused Protocols"
    echo -e "   ${WHITE}10)${NC} AppArmor (MAC)"
    echo -e "   ${WHITE}11)${NC} File Integrity (AIDE)"
    echo -e "   ${WHITE}12)${NC} Kernel Audit (auditd)"
    echo -e "   ${WHITE}13)${NC} Secure Temp Directories"
    echo ""

    echo -e "  ${MAGENTA}${BOLD}━━━ TIER 2: ADVANCED ━━━${NC}"
    echo -e "   ${WHITE}14)${NC} Resource Limits & Fork Bomb"
    echo -e "   ${WHITE}15)${NC} Disable Unnecessary Services"
    echo -e "   ${WHITE}16)${NC} Restrict Cron & At"
    echo -e "   ${WHITE}17)${NC} DNS over TLS"
    echo -e "   ${WHITE}18)${NC} Login & Password Security"
    echo -e "   ${WHITE}19)${NC} User Account Hardening"
    echo -e "   ${WHITE}20)${NC} Security Auditing (Lynis)"
    echo -e "   ${WHITE}21)${NC} Log Forwarding"
    echo -e "   ${WHITE}22)${NC} Kernel Lockdown"
    echo ""

    echo -e "  ${RED}${BOLD}━━━ TIER 3: ZERO TRUST ━━━${NC}"
    echo -e "   ${WHITE}23)${NC} Tailscale VPN"
    echo -e "   ${WHITE}24)${NC} Single Packet Auth (fwknop)"
    echo ""

    echo -e "  ${CYAN}${BOLD}━━━ TELEGRAM BOT ━━━${NC}"
    echo -e "   ${WHITE}40)${NC} Setup Interactive Telegram Bot"
    echo -e "   ${WHITE}41)${NC} Manage Telegram Bot"
    echo ""

    echo -e "  ${BLUE}${BOLD}━━━ BATCH OPERATIONS ━━━${NC}"
    echo -e "   ${WHITE}30)${NC} Run ALL Tier 0"
    echo -e "   ${WHITE}31)${NC} Run Tier 0 + Tier 1"
    echo -e "   ${WHITE}32)${NC} Run Full (Tier 0+1+2)"
    echo ""

    echo -e "  ${BLUE}${BOLD}━━━ UTILITIES ━━━${NC}"
    echo -e "   ${WHITE} s)${NC} Security Status Dashboard"
    echo -e "   ${WHITE} r)${NC} Generate Report"
    echo -e "   ${WHITE} l)${NC} View Log File"
    echo -e "   ${WHITE} b)${NC} List Backups"
    echo -e "   ${WHITE} q)${NC} Quit"
    echo ""
    print_separator
}

# ============================================================================
# MAIN EXECUTION LOOP
# ============================================================================

main() {
    check_root
    init_logging
    print_banner
    detect_os
    check_internet
    create_backup_dir

    if [ -f "$STATE_FILE" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        local saved_user
        saved_user=$(load_state "ADMIN_USER")
        [ -n "$saved_user" ] && TARGET_USER="$saved_user"
    fi

    echo ""
    print_info "Press Enter to continue..."
    read -r

    while true; do
        show_menu
        echo -ne "  ${BOLD}${MAGENTA}Select option: ${NC}"
        read -r choice
        echo ""

        case "$choice" in
            1)  system_update ;;
            2)  harden_ssh ;;
            3)  configure_firewall ;;
            4)  setup_fail2ban ;;
            5)  kernel_hardening ;;
            6)  setup_auto_updates ;;
            7)  setup_user_account ;;
            8)  secure_shared_memory ;;
            9)  disable_unused_protocols ;;
            10) setup_apparmor ;;
            11) setup_aide ;;
            12) setup_auditd ;;
            13) secure_tmp_directories ;;
            14) setup_resource_limits ;;
            15) disable_unnecessary_services ;;
            16) restrict_cron_at ;;
            17) setup_dns_over_tls ;;
            18) setup_login_security ;;
            19) setup_user_hardening ;;
            20) install_lynis ;;
            21) setup_log_forwarding ;;
            22) setup_kernel_lockdown ;;
            23) setup_tailscale ;;
            24) setup_fwknop ;;
            30) run_tier0_essential ;;
            31) run_tier0_plus_tier1 ;;
            32) run_full_hardening ;;
            40) setup_telegram_interactive ;;
            41) telegram_bot_manage ;;
            s|S) show_security_status ;;
            r|R)
                generate_report
                if confirm "View the report now?"; then less "$REPORT_FILE"; fi
                ;;
            l|L)
                [ -f "$LOG_FILE" ] && less "$LOG_FILE" || print_error "Log file not found"
                ;;
            b|B)
                print_section "CONFIGURATION BACKUPS"
                if [ -d "/root/.vps-hardening-backups" ]; then
                    ls -lah /root/.vps-hardening-backups/ 2>/dev/null | tail -20
                    print_info "Current session: ${BACKUP_DIR}"
                else
                    print_warning "No backups found"
                fi
                ;;
            q|Q|quit|exit)
                print_section "HARDENING SESSION COMPLETE"
                generate_report

                echo ""
                print_info "Session Summary:"
                echo -e "    ${BOLD}Completed:${NC} ${#COMPLETED_TASKS[@]} tasks"
                echo -e "    ${BOLD}Failed:${NC}    ${#FAILED_TASKS[@]} tasks"
                echo -e "    ${BOLD}Log:${NC}       ${LOG_FILE}"
                echo -e "    ${BOLD}Report:${NC}    ${REPORT_FILE}"
                echo -e "    ${BOLD}Backups:${NC}   ${BACKUP_DIR}"
                echo ""

                if [ -n "$SSH_PORT" ]; then
                    print_warning "═══════════════════════════════════════════════════════════"
                    print_warning "  SSH is now on port ${SSH_PORT}"
                    print_warning "  Test: ssh -p ${SSH_PORT} ${TARGET_USER}@$(hostname -I | awk '{print $1}')"
                    print_warning "═══════════════════════════════════════════════════════════"
                    echo ""
                fi

                print_info "Recommended Next Steps:"
                echo -e "    ${CYAN}1.${NC} Test SSH in a NEW terminal before closing"
                echo -e "    ${CYAN}2.${NC} Run: ${BOLD}lynis audit system${NC}"
                echo -e "    ${CYAN}3.${NC} Set up Telegram bot (option 40)"
                echo -e "    ${CYAN}4.${NC} Take a VPS snapshot"
                echo -e "    ${CYAN}5.${NC} Reboot when convenient"
                echo ""

                if [ -f /var/run/reboot-required ]; then
                    print_warning "REBOOT REQUIRED to apply all changes"
                fi

                echo -e "  ${GREEN}${BOLD}Thank you for using VPS Hardening Script v${SCRIPT_VERSION}! 🔒${NC}"
                echo ""
                exit 0
                ;;
            *)
                print_error "Invalid option: ${choice}"
                ;;
        esac

        pause
    done
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================
main "$@"
