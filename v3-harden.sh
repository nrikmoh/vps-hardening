#!/usr/bin/env bash
################################################################################
#
#   VPS HARDENING SCRIPT - FULLY ENHANCED EDITION v3.1
#   Comprehensive Server Security + Interactive Telegram Bot Management
#
#   Compatible: Debian 10/11/12, Ubuntu 20.04/22.04/24.04
#
#   Complete Feature Set:
#     ┌─ Tier 0: Essential (SSH, UFW, Fail2ban, Kernel, Updates, User)
#     ├─ Tier 1: High Impact (AppArmor, AIDE, auditd, /dev/shm, protocols)
#     ├─ Tier 2: Advanced (Limits, DNS-TLS, Lynis, Logs, Lockdown)
#     ├─ Tier 3: Zero Trust (Tailscale, fwknop SPA)
#     └─ Bonus: Interactive Telegram Bot with 15+ commands
#
#   Author: Enhanced by VPS Community
#   License: MIT
#   Documentation: See README.md
#
#   Usage:
#     sudo bash v3-harden.sh                    # Interactive mode
#     sudo DEBUG=1 bash v3-harden.sh            # Verbose debug output
#     sudo bash v3-harden.sh --version          # Show version
#
################################################################################

# ============================================================================
# STRICT ERROR HANDLING
# ============================================================================
set -euo pipefail
IFS=$'\n\t'

# Handle command line arguments early
case "${1:-}" in
    --version|-v)
        echo "VPS Hardening Script v3.1.0-enhanced"
        exit 0
        ;;
    --help|-h)
        echo "Usage: sudo bash $0 [options]"
        echo "Options:"
        echo "  --version, -v    Show version"
        echo "  --help, -h       Show this help"
        echo "Environment:"
        echo "  DEBUG=1          Enable verbose debug output"
        exit 0
        ;;
esac

# ============================================================================
# COLOR & FORMATTING DEFINITIONS
# ============================================================================
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly WHITE='\033[1;37m'
readonly GRAY='\033[0;37m'
readonly BLACK='\033[0;30m'
readonly ORANGE='\033[38;5;208m'
readonly PURPLE='\033[38;5;135m'
readonly PINK='\033[38;5;213m'
readonly TEAL='\033[38;5;51m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly ITALIC='\033[3m'
readonly UNDERLINE='\033[4m'
readonly BLINK='\033[5m'
readonly REVERSE='\033[7m'
readonly HIDDEN='\033[8m'
readonly STRIKE='\033[9m'
readonly NC='\033[0m'

# Background colors
readonly BG_RED='\033[41m'
readonly BG_GREEN='\033[42m'
readonly BG_YELLOW='\033[43m'
readonly BG_BLUE='\033[44m'
readonly BG_MAGENTA='\033[45m'
readonly BG_CYAN='\033[46m'

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================
readonly SCRIPT_VERSION="3.1.0-enhanced"
readonly SCRIPT_NAME="VPS Hardening Script"
readonly SCRIPT_AUTHOR="Enhanced Edition"
readonly SCRIPT_DATE="$(date +%Y-%m-%d)"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly SCRIPT_START_TIME="$(date +%s)"

# Paths
readonly LOG_FILE="/var/log/vps-hardening.log"
readonly BACKUP_DIR="/root/.vps-hardening-backups/${TIMESTAMP}"
readonly BACKUP_ROOT="/root/.vps-hardening-backups"
readonly STATE_DIR="/var/lib/vps-hardening"
readonly STATE_FILE="${STATE_DIR}/state.conf"
readonly REPORT_FILE="/root/vps-hardening-report-${TIMESTAMP}.txt"
readonly LOCK_FILE="/var/run/vps-hardening.lock"

# Session variables (mutable)
SSH_PORT=""
TARGET_USER="${SUDO_USER:-$USER}"
USER_HOME="$(eval echo "~${TARGET_USER}")"
OS_ID=""
OS_VERSION=""
OS_NAME=""
OS_CODENAME=""
KERNEL_VERSION="$(uname -r)"
ARCH="$(uname -m)"
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
PRIMARY_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

# Feature tracking
declare -A COMPLETED_TASKS=()
declare -A FAILED_TASKS=()
declare -A SKIPPED_TASKS=()
declare -A TASK_DURATIONS=()

# Counters
TOTAL_WARNINGS=0
TOTAL_ERRORS=0
TOTAL_ACTIONS=0

# APT non-interactive mode
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
export NEEDRESTART_MODE=a
export UCF_FORCE_CONFFOLD=1

# Terminal detection
readonly TERM_WIDTH="$(tput cols 2>/dev/null || echo 80)"
readonly TERM_HEIGHT="$(tput lines 2>/dev/null || echo 24)"

# ============================================================================
# LOCK FILE MANAGEMENT
# ============================================================================

acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local lock_pid
        lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "0")
        if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
            echo -e "${RED}Error: Another instance is already running (PID: ${lock_pid})${NC}"
            echo -e "${YELLOW}If you're sure no other instance is running, delete: ${LOCK_FILE}${NC}"
            exit 1
        else
            rm -f "$LOCK_FILE"
        fi
    fi
    echo "$$" > "$LOCK_FILE"
}

release_lock() {
    rm -f "$LOCK_FILE" 2>/dev/null || true
}

# ============================================================================
# LOGGING SYSTEM
# ============================================================================

init_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$STATE_DIR"
    mkdir -p "$BACKUP_ROOT"
    
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    chown root:adm "$LOG_FILE" 2>/dev/null || chown root:root "$LOG_FILE"
    
    {
        echo ""
        echo "################################################################"
        echo "# VPS Hardening Script - Session Started"
        echo "#"
        echo "# Version:    ${SCRIPT_VERSION}"
        echo "# Date:       $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "# User:       ${TARGET_USER} (from SUDO_USER=${SUDO_USER:-none})"
        echo "# Host:       ${HOSTNAME_FQDN}"
        echo "# IP:         ${PRIMARY_IP}"
        echo "# Kernel:     ${KERNEL_VERSION}"
        echo "# Arch:       ${ARCH}"
        echo "# PID:        $$"
        echo "# TTY:        $(tty 2>/dev/null || echo 'not-a-tty')"
        echo "# Terminal:   ${TERM:-unknown} (${TERM_WIDTH}x${TERM_HEIGHT})"
        echo "# Backup dir: ${BACKUP_DIR}"
        echo "################################################################"
        echo ""
    } >> "$LOG_FILE"
}

log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local caller="${FUNCNAME[2]:-main}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] [${caller}] ${message}" >> "$LOG_FILE"
}

log_info()    { log "INFO"    "$1"; }
log_warn()    { log "WARN"    "$1"; ((TOTAL_WARNINGS++)) || true; }
log_error()   { log "ERROR"   "$1"; ((TOTAL_ERRORS++)) || true; }
log_success() { log "SUCCESS" "$1"; }
log_debug()   { log "DEBUG"   "$1"; }
log_action()  { log "ACTION"  "$1"; ((TOTAL_ACTIONS++)) || true; }

log_command() {
    local cmd="$1"
    log "COMMAND" "Executing: ${cmd}"
}

log_separator() {
    echo "----------------------------------------------------------------" >> "$LOG_FILE"
}

# ============================================================================
# OUTPUT FORMATTING FUNCTIONS
# ============================================================================

print_banner() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║      █  █ ██▄ ▄▀▀   █▄█ ▄▀▄ █▀▄ █▀▄ █▀▀ █▄ █ █ █▄ █ ▄▀ ║
    ║      █▄▄█ █▄█ ▄██▄ █ █ █▀█ █▀▄ █▄▀ █▀▀ █ ▀█ █ █ ▀█ ▀▄█ ║
    ║                                                                  ║
    ║      ═══ FULLY ENHANCED EDITION v3.1.0 ═══                       ║
    ║                                                                  ║
    ║      Comprehensive Server Security + Telegram Bot Control       ║
    ║                                                                  ║
    ║   ┌────────────────────────────────────────────────────────┐   ║
    ║   │                                                         │   ║
    ║   │  🛡  Tier 0: Essential Hardening (7 modules)            │   ║
    ║   │  🔒  Tier 1: High Impact Defenses (6 modules)            │   ║
    ║   │  🔐  Tier 2: Advanced Security Controls (9 modules)      │   ║
    ║   │  🌐  Tier 3: Zero Trust Networking (2 modules)          │   ║
    ║   │  🤖  Bonus: Interactive Telegram Bot Control            │   ║
    ║   │                                                         │   ║
    ║   └────────────────────────────────────────────────────────┘   ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo ""
    echo -e "  ${YELLOW}${BOLD}⚠  IMPORTANT PRE-FLIGHT NOTICES:${NC}"
    echo -e "  ${YELLOW}  ├─ This script must be run as root or with sudo${NC}"
    echo -e "  ${YELLOW}  ├─ All configurations are backed up automatically${NC}"
    echo -e "  ${YELLOW}  ├─ Test SSH access in a NEW terminal before disconnecting${NC}"
    echo -e "  ${YELLOW}  ├─ Take a VPS snapshot before major changes${NC}"
    echo -e "  ${YELLOW}  ├─ Have console/rescue access ready as backup${NC}"
    echo -e "  ${YELLOW}  └─ Review log file: ${LOG_FILE}${NC}"
    echo ""
    echo -e "  ${DIM}Version: ${SCRIPT_VERSION} | Date: ${SCRIPT_DATE} | PID: $$${NC}"
    echo ""
}

print_section() {
    local title="$1"
    local width=68
    local title_len=${#title}
    local padding=$(( (width - title_len - 2) / 2 ))
    local extra_pad=$(( (width - title_len - 2) % 2 ))
    
    echo ""
    echo -e "${BLUE}${BOLD}$(printf '━%.0s' $(seq 1 $width))${NC}"
    echo -e "${BLUE}${BOLD}$(printf ' %.0s' $(seq 1 $padding))${WHITE}${BOLD}${title}${BLUE}$(printf ' %.0s' $(seq 1 $((padding + extra_pad))))${NC}"
    echo -e "${BLUE}${BOLD}$(printf '━%.0s' $(seq 1 $width))${NC}"
    echo ""
    log_separator
    log_info "═══ Section: ${title} ═══"
}

print_subsection() {
    echo ""
    echo -e "  ${CYAN}${BOLD}▸ $1${NC}"
    echo -e "  ${DIM}$(printf '─%.0s' $(seq 1 60))${NC}"
    log_info "── Subsection: $1 ──"
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
    log_action "$1"
}

print_debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo -e "  ${GRAY}${DIM}[DEBUG]${NC} $1"
    fi
    log_debug "$1"
}

print_critical() {
    echo -e "  ${BG_RED}${WHITE}${BOLD}[!! CRITICAL !!]${NC} ${RED}${BOLD}$1${NC}"
    log_error "CRITICAL: $1"
}

print_success_box() {
    local msg="$1"
    local width=68
    local msg_len=${#msg}
    local padding=$(( (width - msg_len - 4) / 2 ))
    
    echo ""
    echo -e "  ${GREEN}${BOLD}╔$(printf '═%.0s' $(seq 1 $((width - 2))))╗${NC}"
    echo -e "  ${GREEN}${BOLD}║$(printf ' %.0s' $(seq 1 $padding)) ${WHITE}✔ ${msg}${GREEN} $(printf ' %.0s' $(seq 1 $padding))║${NC}"
    echo -e "  ${GREEN}${BOLD}╚$(printf '═%.0s' $(seq 1 $((width - 2))))╝${NC}"
    echo ""
}

print_warning_box() {
    local msg="$1"
    echo ""
    echo -e "  ${YELLOW}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${YELLOW}${BOLD}║  ⚠  WARNING${NC}"
    echo -e "  ${YELLOW}${BOLD}║  ${msg}${NC}"
    echo -e "  ${YELLOW}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_error_box() {
    local msg="$1"
    echo ""
    echo -e "  ${RED}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${RED}${BOLD}║  ✘  ERROR${NC}"
    echo -e "  ${RED}${BOLD}║  ${msg}${NC}"
    echo -e "  ${RED}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_separator() {
    echo -e "  ${DIM}$(printf '─%.0s' $(seq 1 66))${NC}"
}

print_thick_separator() {
    echo -e "  ${BOLD}$(printf '═%.0s' $(seq 1 66))${NC}"
}

print_double_separator() {
    echo -e "  ${BOLD}${BLUE}$(printf '═%.0s' $(seq 1 66))${NC}"
}

print_progress() {
    local current="$1"
    local total="$2"
    local task="${3:-Processing}"
    local percent=$(( (current * 100) / total ))
    local filled=$(( (current * 40) / total ))
    local empty=$(( 40 - filled ))
    
    printf "\r  ${CYAN}${BOLD}[${task}]${NC} ["
    printf "${GREEN}%${filled}s${NC}" | tr ' ' '█'
    printf "${GRAY}%${empty}s${NC}" | tr ' ' '░'
    printf "] ${BOLD}%3d%%${NC} (%d/%d)" "$percent" "$current" "$total"
    
    if [ "$current" -eq "$total" ]; then
        echo ""
    fi
}

print_key_value() {
    local key="$1"
    local value="$2"
    local color="${3:-$CYAN}"
    printf "    ${BOLD}%-25s${NC} ${color}%s${NC}\n" "${key}:" "$value"
}

print_check() {
    local label="$1"
    local status="$2"  # ok, warn, fail, info
    local detail="${3:-}"
    
    case "$status" in
        ok)   echo -e "    ${GREEN}${BOLD}✔${NC} ${label} ${detail:+${DIM}(${detail})${NC}}" ;;
        warn) echo -e "    ${YELLOW}${BOLD}⚠${NC} ${label} ${detail:+${DIM}(${detail})${NC}}" ;;
        fail) echo -e "    ${RED}${BOLD}✘${NC} ${label} ${detail:+${DIM}(${detail})${NC}}" ;;
        info) echo -e "    ${CYAN}${BOLD}ℹ${NC} ${label} ${detail:+${DIM}(${detail})${NC}}" ;;
        *)    echo -e "    ${GRAY}${BOLD}?${NC} ${label} ${detail:+${DIM}(${detail})${NC}}" ;;
    esac
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
        hint="${GREEN}${BOLD}[Y${NC}${DIM}/n]${NC}"
    else
        hint="${DIM}[y/${NC}${RED}${BOLD}N${NC}${DIM}]${NC}"
    fi
    
    while true; do
        echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt} ${hint}: "
        read -r response
        response="${response:-$default}"
        
        case "${response,,}" in
            y|yes|1|true) 
                log_debug "User confirmed: ${prompt}"
                return 0 
                ;;
            n|no|0|false) 
                log_debug "User declined: ${prompt}"
                return 1 
                ;;
            *) 
                print_warning "Please answer 'yes' or 'no'" 
                ;;
        esac
    done
}

prompt_input() {
    local prompt="$1"
    local default="${2:-}"
    local variable_name="$3"
    local validator="${4:-}"
    local response=""
    
    while true; do
        if [[ -n "$default" ]]; then
            echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt} ${DIM}[default: ${default}]${NC}: "
        else
            echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt}: "
        fi
        
        read -r response
        response="${response:-$default}"
        
        # If validator function provided, validate the input
        if [ -n "$validator" ] && command -v "$validator" &>/dev/null; then
            if "$validator" "$response"; then
                break
            else
                print_error "Invalid input. Please try again."
                continue
            fi
        fi
        
        break
    done
    
    log_debug "Input received for ${variable_name}: ${response}"
    printf -v "$variable_name" '%s' "$response"
}

prompt_password() {
    local prompt="$1"
    local variable_name="$2"
    local min_length="${3:-8}"
    local response=""
    local response_confirm=""
    
    while true; do
        echo -ne "  ${MAGENTA}${BOLD}[?]${NC} ${prompt}: "
        read -rs response
        echo ""
        
        if [ "${#response}" -lt "$min_length" ]; then
            print_error "Password must be at least ${min_length} characters"
            continue
        fi
        
        echo -ne "  ${MAGENTA}${BOLD}[?]${NC} Confirm password: "
        read -rs response_confirm
        echo ""
        
        if [ "$response" = "$response_confirm" ]; then
            break
        else
            print_error "Passwords do not match. Please try again."
        fi
    done
    
    printf -v "$variable_name" '%s' "$response"
}

prompt_menu() {
    local prompt="$1"
    shift
    local options=("$@")
    local choice=""
    
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} ${prompt}"
    local i
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
            print_warning "Invalid selection. Please choose 1-${#options[@]}"
        fi
    done
}

pause() {
    echo ""
    echo -ne "  ${DIM}Press ${BOLD}Enter${NC}${DIM} to continue...${NC}"
    read -r
}

countdown() {
    local seconds="$1"
    local message="${2:-Continuing in}"
    
    local i
    for ((i=seconds; i>0; i--)); do
        printf "\r  ${YELLOW}${BOLD}[⏱]${NC} ${message} ${BOLD}%d${NC} seconds... (Ctrl+C to cancel)" "$i"
        sleep 1
    done
    echo ""
}

# End of Section 1
# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        print_error_box "This script must be run as root."
        echo -e "  ${YELLOW}Please run with: ${BOLD}sudo bash $0${NC}"
        echo -e "  ${DIM}Current user: $(whoami) (UID: $EUID)${NC}"
        echo ""
        exit 1
    fi
    log_info "Root privileges confirmed"
}

check_internet() {
    print_step "Checking internet connectivity..."
    
    local test_hosts=("8.8.8.8" "1.1.1.1" "9.9.9.9" "208.67.222.222")
    local connected=false
    local host
    
    for host in "${test_hosts[@]}"; do
        if ping -c 1 -W 3 "$host" &>/dev/null; then
            connected=true
            print_status "Internet connection active (verified via ${host})"
            break
        fi
    done
    
    if [ "$connected" = false ]; then
        # Try DNS resolution as fallback
        if host google.com &>/dev/null 2>&1 || nslookup google.com &>/dev/null 2>&1; then
            connected=true
            print_status "Internet connection active (verified via DNS)"
        fi
    fi
    
    if [ "$connected" = false ]; then
        print_error "No internet connection detected"
        print_warning "The following operations require internet access:"
        echo -e "    ${GRAY}• Package installation and updates${NC}"
        echo -e "    ${GRAY}• Tailscale installation${NC}"
        echo -e "    ${GRAY}• fwknop installation${NC}"
        echo -e "    ${GRAY}• Telegram bot communication${NC}"
        echo -e "    ${GRAY}• Lynis installation${NC}"
        echo ""
        if ! confirm "Continue anyway? (some features will be unavailable)"; then
            print_info "Exiting. Please restore internet connectivity and try again."
            exit 1
        fi
        log_warn "Continuing without internet connectivity"
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
    elif [ -f /etc/lsb-release ]; then
        # shellcheck source=/dev/null
        . /etc/lsb-release
        OS_ID="${DISTRIB_ID:-unknown}"
        OS_VERSION="${DISTRIB_RELEASE:-unknown}"
        OS_NAME="${DISTRIB_DESCRIPTION:-unknown}"
        OS_CODENAME="${DISTRIB_CODENAME:-unknown}"
    else
        print_error "Cannot detect OS. Neither /etc/os-release nor /etc/lsb-release found."
        print_info "Falling back to uname detection"
        OS_ID=$(uname -s | tr '[:upper:]' '[:lower:]')
        OS_VERSION=$(uname -r)
        OS_NAME="${OS_ID} ${OS_VERSION}"
        OS_CODENAME="unknown"
    fi
    
    # Detailed OS information
    print_subsection "Operating System Details"
    print_key_value "Distribution" "$OS_NAME"
    print_key_value "ID" "$OS_ID"
    print_key_value "Version" "$OS_VERSION"
    print_key_value "Codename" "$OS_CODENAME"
    print_key_value "Kernel" "$KERNEL_VERSION"
    print_key_value "Architecture" "$ARCH"
    print_key_value "Hostname" "$HOSTNAME_FQDN"
    print_key_value "Primary IP" "$PRIMARY_IP"
    echo ""
    
    # Check for supported OS
    case "$OS_ID" in
        ubuntu)
            print_status "Detected: ${OS_NAME} (Supported)"
            case "$OS_VERSION" in
                24.04) print_info "Ubuntu 24.04 detected - systemd socket activation will be handled" ;;
                22.04) print_info "Ubuntu 22.04 LTS detected - fully supported" ;;
                20.04) print_info "Ubuntu 20.04 LTS detected - fully supported" ;;
                *)     print_warning "Ubuntu ${OS_VERSION} is untested but should work" ;;
            esac
            ;;
        debian)
            print_status "Detected: ${OS_NAME} (Supported)"
            case "$OS_VERSION" in
                12) print_info "Debian 12 (Bookworm) detected - fully supported" ;;
                11) print_info "Debian 11 (Bullseye) detected - fully supported" ;;
                10) print_info "Debian 10 (Buster) detected - supported (EOL soon)" ;;
                *)  print_warning "Debian ${OS_VERSION} is untested but should work" ;;
            esac
            ;;
        *)
            print_warning "OS '${OS_ID}' is not officially tested."
            print_warning "This script is optimized for Debian/Ubuntu."
            print_info "Some features may not work correctly on ${OS_ID}."
            if ! confirm "Continue anyway?"; then
                print_info "Exiting."
                exit 1
            fi
            log_warn "Proceeding with unsupported OS: ${OS_ID}"
            ;;
    esac
    
    # Check virtualization type
    print_subsection "Virtualization Detection"
    local virt_type="unknown"
    if command_exists systemd-detect-virt; then
        virt_type=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    elif [ -f /proc/1/cgroup ]; then
        if grep -q "docker" /proc/1/cgroup 2>/dev/null; then
            virt_type="docker"
        elif grep -q "lxc" /proc/1/cgroup 2>/dev/null; then
            virt_type="lxc"
        fi
    elif [ -f /.dockerenv ]; then
        virt_type="docker"
    fi
    
    print_key_value "Virtualization" "$virt_type"
    
    case "$virt_type" in
        kvm|qemu)    print_info "KVM/QEMU VM detected - full kernel features available" ;;
        xen)         print_info "Xen VM detected - some kernel features may be restricted" ;;
        openvz|lxc)  print_warning "Container detected - kernel hardening may be limited" ;;
        docker)      print_warning "Docker container detected - many features will not work" ;;
        vmware)      print_info "VMware VM detected - full kernel features available" ;;
        microsoft)   print_info "Hyper-V VM detected - full kernel features available" ;;
        none)        print_info "Bare metal detected - all features available" ;;
        *)           print_info "Virtualization type: ${virt_type}" ;;
    esac
    
    log_info "OS Detection complete: ${OS_NAME} (${virt_type})"
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
        local part
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

service_enabled() {
    systemctl is-enabled --quiet "$1" 2>/dev/null
}

package_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
}

get_package_version() {
    dpkg -l "$1" 2>/dev/null | grep "^ii" | awk '{print $3}' || echo "not installed"
}

check_disk_space() {
    local path="${1:-/}"
    local required_mb="${2:-500}"
    local available_mb
    available_mb=$(df -BM "$path" 2>/dev/null | awk 'NR==2 {print $4}' | tr -d 'M')
    
    if [ -n "$available_mb" ] && [ "$available_mb" -lt "$required_mb" ]; then
        print_warning "Low disk space on ${path}: ${available_mb}MB available (need ${required_mb}MB)"
        return 1
    fi
    return 0
}

check_memory() {
    local required_mb="${1:-256}"
    local available_mb
    available_mb=$(free -m 2>/dev/null | awk 'NR==2 {print $7}')
    
    if [ -z "$available_mb" ]; then
        available_mb=$(free -m 2>/dev/null | awk 'NR==2 {print $4}')
    fi
    
    if [ -n "$available_mb" ] && [ "$available_mb" -lt "$required_mb" ]; then
        print_warning "Low memory: ${available_mb}MB available (need ${required_mb}MB)"
        return 1
    fi
    return 0
}

# ============================================================================
# BACKUP & STATE MANAGEMENT
# ============================================================================

create_backup_dir() {
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"
        print_info "Backup directory created: ${BACKUP_DIR}"
        log_info "Backup directory created: ${BACKUP_DIR}"
    fi
}

backup_file() {
    local file="$1"
    local description="${2:-}"
    
    if [ -z "$file" ]; then
        log_error "backup_file called with empty path"
        return 1
    fi
    
    if [ -f "$file" ]; then
        create_backup_dir
        local backup_path="${BACKUP_DIR}$(dirname "$file")"
        mkdir -p "$backup_path"
        cp -rp "$file" "$backup_path/" 2>/dev/null || true
        log_debug "Backed up file: $file -> $backup_path/ ${description:+($description)}"
        print_debug "Backup: ${file}"
        return 0
    elif [ -d "$file" ]; then
        backup_directory "$file" "$description"
        return $?
    else
        log_debug "backup_file: $file does not exist (skipping)"
        return 1
    fi
}

backup_directory() {
    local dir="$1"
    local description="${2:-}"
    
    if [ -d "$dir" ]; then
        create_backup_dir
        local backup_path="${BACKUP_DIR}$(dirname "$dir")"
        mkdir -p "$backup_path"
        cp -rp "$dir" "$backup_path/" 2>/dev/null || true
        log_debug "Backed up directory: $dir ${description:+($description)}"
        print_debug "Backup dir: ${dir}"
        return 0
    else
        log_debug "backup_directory: $dir does not exist (skipping)"
        return 1
    fi
}

backup_critical_configs() {
    print_step "Creating comprehensive backup of critical configurations..."
    
    local critical_files=(
        "/etc/ssh/sshd_config"
        "/etc/ssh/sshd_config.d"
        "/etc/ufw/ufw.conf"
        "/etc/ufw/before.rules"
        "/etc/ufw/after.rules"
        "/etc/default/ufw"
        "/etc/fail2ban/jail.conf"
        "/etc/fail2ban/jail.d"
        "/etc/sysctl.conf"
        "/etc/sysctl.d"
        "/etc/fstab"
        "/etc/hosts"
        "/etc/resolv.conf"
        "/etc/pam.d/sshd"
        "/etc/pam.d/su"
        "/etc/pam.d/common-auth"
        "/etc/pam.d/common-session"
        "/etc/security/limits.conf"
        "/etc/security/limits.d"
        "/etc/login.defs"
        "/etc/default/useradd"
        "/etc/crontab"
        "/etc/cron.d"
        "/etc/modprobe.d"
        "/etc/default/grub"
        "/etc/audit/auditd.conf"
        "/etc/audit/rules.d"
        "/etc/apparmor.d"
        "/etc/aide/aide.conf"
        "/etc/systemd/resolved.conf"
        "/etc/apt/apt.conf.d"
    )
    
    local backed_up=0
    local item
    for item in "${critical_files[@]}"; do
        if [ -e "$item" ]; then
            backup_file "$item" "pre-hardening"
            backed_up=$((backed_up + 1))
        fi
    done
    
    print_status "Backed up ${backed_up} critical configuration files/directories"
    print_info "All backups stored in: ${BACKUP_DIR}"
}

save_state() {
    local key="$1"
    local value="$2"
    
    mkdir -p "$STATE_DIR"
    touch "$STATE_FILE"
    chmod 600 "$STATE_FILE"
    
    # Remove existing entry if present
    if grep -q "^${key}=" "$STATE_FILE" 2>/dev/null; then
        sed -i "/^${key}=/d" "$STATE_FILE" 2>/dev/null || true
    fi
    
    # Add new entry with timestamp
    echo "${key}=${value} # $(date '+%Y-%m-%d %H:%M:%S')" >> "$STATE_FILE"
    log_debug "State saved: ${key}=${value}"
}

load_state() {
    local key="$1"
    
    if [ -f "$STATE_FILE" ]; then
        grep "^${key}=" "$STATE_FILE" 2>/dev/null | tail -1 | cut -d'=' -f2 | cut -d'#' -f1 | xargs
    fi
}

mark_completed() {
    local task="$1"
    local end_time
    end_time=$(date +%s)
    local start_time="${TASK_START_TIME:-$end_time}"
    local duration=$(( end_time - start_time ))
    
    COMPLETED_TASKS["$task"]="$(date '+%Y-%m-%d %H:%M:%S')"
    TASK_DURATIONS["$task"]="${duration}s"
    save_state "COMPLETED_${task}" "$(date '+%Y-%m-%d %H:%M:%S')"
    log_success "Task completed: ${task} (${duration}s)"
}

mark_failed() {
    local task="$1"
    local reason="${2:-Unknown error}"
    FAILED_TASKS["$task"]="$reason"
    save_state "FAILED_${task}" "$reason"
    log_error "Task failed: ${task} - ${reason}"
}

mark_skipped() {
    local task="$1"
    local reason="${2:-User skipped}"
    SKIPPED_TASKS["$task"]="$reason"
    log_info "Task skipped: ${task} - ${reason}"
}

is_completed() {
    local task="$1"
    set +u
    local res="false"
    if [ -n "${COMPLETED_TASKS[$task]:-}" ] || [ -n "$(load_state "COMPLETED_${task}")" ]; then
        res="true"
    fi
    set -u
    [ "$res" = "true" ]
}

start_task_timer() {
    TASK_START_TIME=$(date +%s)
}

# ============================================================================
# ERROR HANDLING & CLEANUP
# ============================================================================

cleanup_on_exit() {
    local exit_code=$?
    local end_time
    end_time=$(date +%s)
    local total_duration=$(( end_time - SCRIPT_START_TIME ))
    local minutes=$(( total_duration / 60 ))
    local seconds=$(( total_duration % 60 ))
    
    release_lock
    
    # Temporarily disable nounset to handle uninitialized/empty arrays safely
    set +u
    {
        echo ""
        echo "################################################################"
        echo "# Session Summary"
        echo "# Exit code:    ${exit_code}"
        echo "# Duration:     ${minutes}m ${seconds}s"
        echo "# Completed:    ${#COMPLETED_TASKS[@]} tasks"
        echo "# Failed:       ${#FAILED_TASKS[@]} tasks"
        echo "# Skipped:      ${#SKIPPED_TASKS[@]} tasks"
        echo "# Warnings:     ${TOTAL_WARNINGS}"
        echo "# Errors:       ${TOTAL_ERRORS}"
        echo "# Actions:      ${TOTAL_ACTIONS}"
        echo "################################################################"
    } >> "$LOG_FILE"
    
    if [ $exit_code -ne 0 ]; then
        echo ""
        print_error_box "Script exited unexpectedly (exit code: $exit_code)"
        echo -e "  ${YELLOW}Session duration: ${minutes}m ${seconds}s${NC}"
        echo -e "  ${YELLOW}Log file: ${LOG_FILE}${NC}"
        echo -e "  ${YELLOW}Backups: ${BACKUP_DIR}${NC}"
        echo ""
        print_info "To restore from backup:"
        echo -e "    ${CYAN}cp -rp ${BACKUP_DIR}/etc/ssh/* /etc/ssh/${NC}"
        echo -e "    ${CYAN}cp -rp ${BACKUP_DIR}/etc/sysctl.d/* /etc/sysctl.d/${NC}"
        echo ""
    fi
    set -u
    
    echo -e "${NC}"
}

handle_interrupt() {
    echo ""
    echo ""
    print_warning_box "Script interrupted by user (Ctrl+C)"
    print_info "Partial changes may have been applied."
    print_info "Check the log file: ${LOG_FILE}"
    print_info "Backups are stored in: ${BACKUP_DIR}"
    echo ""
    
    if confirm "Would you like to see the session summary?"; then
        echo ""
        print_info "Completed tasks: ${#COMPLETED_TASKS[@]}"
        local task
        for task in "${!COMPLETED_TASKS[@]}"; do
            echo -e "    ${GREEN}✔${NC} ${task}"
        done
        
        if [ ${#FAILED_TASKS[@]} -gt 0 ]; then
            print_info "Failed tasks: ${#FAILED_TASKS[@]}"
            for task in "${!FAILED_TASKS[@]}"; do
                echo -e "    ${RED}✘${NC} ${task}: ${FAILED_TASKS[$task]}"
            done
        fi
    fi
    
    release_lock
    exit 130
}

handle_terminate() {
    log_error "Script terminated by signal"
    release_lock
    exit 143
}

trap cleanup_on_exit EXIT
trap handle_interrupt INT
trap handle_terminate TERM

# ============================================================================
# TIER 0: ESSENTIAL HARDENING FUNCTIONS
# ============================================================================

# ----------------------------------------------------------------------------
# Function: system_update
# Purpose: Update system packages and install essential utilities
# ----------------------------------------------------------------------------
system_update() {
    start_task_timer
    print_section "SYSTEM UPDATE & CLEANUP"
    
    # Pre-flight checks
    print_subsection "Pre-Flight Checks"
    check_disk_space "/" 500 || print_warning "Low disk space may cause issues"
    check_memory 256 || print_warning "Low memory may slow down updates"
    
    # Update package lists
    print_subsection "Package Repository Update"
    print_step "Updating package repository lists..."
    print_info "This may take a minute depending on your connection..."
    
    if apt-get update -y >> "$LOG_FILE" 2>&1; then
        local pkg_count
        pkg_count=$(apt list --upgradable 2>/dev/null | grep -v "Listing" | wc -l)
        print_status "Package lists updated successfully"
        print_info "Upgradable packages available: ${pkg_count}"
    else
        print_error "Failed to update package lists"
        print_info "Check your network connection and /etc/apt/sources.list"
        print_info "Error details in: ${LOG_FILE}"
        mark_failed "system_update" "apt-get update failed"
        return 1
    fi
    
    # Upgrade installed packages
    print_subsection "System Package Upgrade"
    print_step "Upgrading installed packages..."
    print_info "Using --force-confdef to keep existing configurations"
    print_info "This may take several minutes..."
    echo ""
    
    if apt-get -o Dpkg::Options::="--force-confdef" \
                -o Dpkg::Options::="--force-confold" \
                upgrade -y >> "$LOG_FILE" 2>&1; then
        print_status "System packages upgraded successfully"
    else
        print_error "Failed to upgrade packages"
        print_info "Some packages may have been held back"
        print_info "Try running manually: apt-get upgrade"
        mark_failed "system_update" "apt-get upgrade failed"
        return 1
    fi
    
    # Optional dist-upgrade
    if confirm "Perform full distribution upgrade (dist-upgrade)?" "n"; then
        print_step "Performing distribution upgrade..."
        print_warning "This may install new packages and remove obsolete ones"
        
        if apt-get -o Dpkg::Options::="--force-confdef" \
                    -o Dpkg::Options::="--force-confold" \
                    dist-upgrade -y >> "$LOG_FILE" 2>&1; then
            print_status "Distribution upgrade completed"
        else
            print_warning "Distribution upgrade had issues (see log for details)"
        fi
    fi
    
    # Cleanup
    print_subsection "System Cleanup"
    print_step "Removing unnecessary packages and cached files..."
    
    local before_size
    before_size=$(du -sh /var/cache/apt 2>/dev/null | awk '{print $1}' || echo "unknown")
    
    apt-get autoremove -y >> "$LOG_FILE" 2>&1 || true
    apt-get autoclean -y >> "$LOG_FILE" 2>&1 || true
    apt-get clean >> "$LOG_FILE" 2>&1 || true
    
    local after_size
    after_size=$(du -sh /var/cache/apt 2>/dev/null | awk '{print $1}' || echo "unknown")
    
    print_status "System cleaned"
    print_info "APT cache: ${before_size} → ${after_size}"
    
    # Install essential utilities
    print_subsection "Essential Utility Installation"
    print_step "Installing essential utility packages..."
    
    local essential_packages=(
        curl wget git vim nano htop
        net-tools dnsutils iproute2
        gnupg2 ca-certificates
        software-properties-common
        apt-transport-https
        unzip zip tar
        rsync bc jq
        python3 python3-minimal
        lsof strace
        tree tmux
        logrotate
    )
    
    local installed_count=0
    local skipped_count=0
    local failed_count=0
    local pkg
    
    for pkg in "${essential_packages[@]}"; do
        if ! package_installed "$pkg"; then
            if apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1; then
                installed_count=$((installed_count + 1))
                print_debug "Installed: ${pkg}"
            else
                failed_count=$((failed_count + 1))
                print_warning "Failed to install: $pkg"
            fi
        else
            ((skipped_count++))
            print_debug "Already installed: ${pkg}"
        fi
    done
    
    print_status "Essential utilities: ${installed_count} installed, ${skipped_count} already present, ${failed_count} failed"
    
    # Check for reboot requirement
    if [ -f /var/run/reboot-required ]; then
        echo ""
        print_warning "A system reboot is required to complete the update"
        print_info "Reboot when convenient: sudo reboot"
        if [ -f /var/run/reboot-required.pkgs ]; then
            print_info "Packages requiring reboot:"
            cat /var/run/reboot-required.pkgs 2>/dev/null | while IFS= read -r line; do
                echo -e "    ${GRAY}• ${line}${NC}"
            done
        fi
    fi
    
    mark_completed "system_update"
}

# ----------------------------------------------------------------------------
# Function: harden_ssh
# Purpose: Comprehensive SSH hardening with lockout prevention
# ----------------------------------------------------------------------------
harden_ssh() {
    start_task_timer
    print_section "SSH HARDENING"
    
    # Install SSH server if not present
    if ! package_installed "openssh-server"; then
        print_step "Installing OpenSSH server..."
        apt-get install -y openssh-server >> "$LOG_FILE" 2>&1
        print_status "OpenSSH server installed"
    else
        local ssh_version
        ssh_version=$(ssh -V 2>&1 | awk '{print $1}' | tr -d ',')
        print_info "OpenSSH already installed: ${ssh_version}"
    fi
    
    # ---- Port Configuration ----
    print_subsection "SSH Port Configuration"
    
    local current_port
    current_port=$(grep -rh "^Port " /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | \
                   head -1 | awk '{print $2}' || echo "22")
    print_info "Current SSH port: ${current_port}"
    
    # Show common attack stats for port 22
    if [ "$current_port" = "22" ]; then
        print_warning "Port 22 is the default SSH port and is heavily targeted by bots"
        print_info "Changing to a non-standard port reduces noise by ~95%"
    fi
    
    while true; do
        prompt_input "Enter desired SSH port" "2222" SSH_PORT
        if validate_port "$SSH_PORT"; then
            if [ "$SSH_PORT" -eq 22 ]; then
                print_warning "Port 22 is the default and frequently attacked."
                if ! confirm "Are you sure you want to use port 22?" "n"; then
                    continue
                fi
            elif [ "$SSH_PORT" -lt 1024 ]; then
                print_info "Ports below 1024 require root privileges (this is fine for sshd)"
            fi
            
            # Check if port is already in use
            if ss -tlnp | grep -q ":${SSH_PORT} " 2>/dev/null; then
                local using_proc
                using_proc=$(ss -tlnp | grep ":${SSH_PORT} " | awk '{print $NF}' | head -1)
                print_warning "Port ${SSH_PORT} is currently in use by: ${using_proc}"
                if ! confirm "Use this port anyway?"; then
                    continue
                fi
            fi
            break
        else
            print_error "Invalid port. Must be a number between 1 and 65535."
        fi
    done
    
    save_state "SSH_PORT" "$SSH_PORT"
    print_status "SSH port will be changed to: ${SSH_PORT}"
    
    # ---- Key Validation ----
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
                    fingerprint=$(echo "$key_line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2, $NF}' || echo "invalid key format")
                    local key_type
                    key_type=$(echo "$key_line" | awk '{print $1}')
                    echo -e "      ${GRAY}• [${key_type}] ${fingerprint}${NC}"
                fi
            done < "$AUTH_KEYS"
        fi
    else
        print_warning "No SSH keys found in ${AUTH_KEYS}"
        echo ""
        print_warning_box "CRITICAL: Disabling password authentication without SSH keys will PERMANENTLY LOCK YOU OUT of this server!"
        echo ""
        
        if confirm "Do you want to add an SSH public key now?" "y"; then
            add_ssh_key
            # Re-check after adding
            if [ -f "$AUTH_KEYS" ] && [ -s "$AUTH_KEYS" ]; then
                key_count=$(grep -cve '^\s*$\|^\s*#' "$AUTH_KEYS" 2>/dev/null || echo "0")
                if [ "$key_count" -eq 0 ]; then
                    disable_password="no"
                    print_warning "Key addition failed. Password auth will remain enabled."
                else
                    print_status "SSH key verified. Safe to disable password auth."
                fi
            else
                disable_password="no"
                print_warning "No keys found after attempt. Password auth will remain enabled."
            fi
        else
            disable_password="no"
            print_warning "Password authentication will remain ENABLED"
            print_info "You can re-run SSH hardening later after adding your key"
        fi
    fi
    
    # ---- Apply Configuration ----
    print_subsection "Applying SSH Configuration"
    
    # Backup original configuration
    backup_file /etc/ssh/sshd_config "pre-SSH-hardening"
    backup_directory /etc/ssh/sshd_config.d "pre-SSH-hardening"
    
    # Create drop-in configuration directory
    mkdir -p /etc/ssh/sshd_config.d
    chmod 755 /etc/ssh/sshd_config.d
    
    local password_auth_value="no"
    [ "$disable_password" = "no" ] && password_auth_value="yes"
    
    # Write comprehensive SSH hardening configuration
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << EOF
# ============================================================
# VPS Hardening - SSH Security Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Script Version: ${SCRIPT_VERSION}
# ============================================================

# ---- Network ----
Port ${SSH_PORT}
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# ---- Protocol ----
Protocol 2

# ---- Host Keys (prefer Ed25519 and RSA-SHA2) ----
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key

# ---- Authentication ----
PermitRootLogin no
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
StrictModes yes
PermitEmptyPasswords no

# ---- Password Authentication ----
PasswordAuthentication ${password_auth_value}
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no

# ---- Public Key Authentication ----
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
AuthenticationMethods publickey

# ---- Host-Based Authentication ----
HostbasedAuthentication no
IgnoreRhosts yes
IgnoreUserKnownHosts yes

# ---- Kerberos & GSSAPI (disable if not used) ----
KerberosAuthentication no
GSSAPIAuthentication no

# ---- Forwarding & Tunneling ----
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no

# ---- User Environment ----
PermitUserEnvironment no
PermitUserRC no

# ---- Session Timeouts ----
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# ---- Logging ----
SyslogFacility AUTH
LogLevel VERBOSE

# ---- Ciphers & Algorithms (Modern, Secure Only) ----
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

# ---- Banner ----
Banner /etc/issue.net

# ---- DNS ----
UseDNS no

# ---- Miscellaneous ----
Compression no
PrintMotd no
PrintLastLog yes
AcceptEnv LANG LC_*
MaxStartups 10:30:60
PerSourceMaxStartups 3
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
    
    chmod 600 /etc/ssh/sshd_config.d/99-hardening.conf
    chown root:root /etc/ssh/sshd_config.d/99-hardening.conf
    print_status "SSH hardening configuration created"
    
    # Create warning banner
    cat > /etc/issue.net << 'EOF'
################################################################
#                                                              #
#           ⚠  AUTHORIZED ACCESS ONLY  ⚠                      #
#                                                              #
#  This system is restricted to authorized users only.         #
#  All activities are monitored, logged, and audited.          #
#  Unauthorized access is strictly prohibited and will be      #
#  prosecuted to the fullest extent of the law.                #
#                                                              #
#  By accessing this system, you consent to monitoring.        #
#  Disconnect NOW if you are not an authorized user.           #
#                                                              #
################################################################
EOF
    chmod 644 /etc/issue.net
    print_status "Login warning banner created"
    
    # ---- Ubuntu 24.04+ Socket Activation ----
    print_subsection "Systemd Socket Activation Check"
    
    if service_active "ssh.socket"; then
        print_info "Detected systemd socket activation (Ubuntu 24.04+ style)"
        print_info "The ssh.socket unit controls the listening port, not sshd_config"
        print_step "Creating socket override for port ${SSH_PORT}..."
        
        mkdir -p /etc/systemd/system/ssh.socket.d
        cat > /etc/systemd/system/ssh.socket.d/override.conf << EOF
# VPS Hardening - SSH Socket Override
# Redirects listening port from default 22 to ${SSH_PORT}
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF
        chmod 644 /etc/systemd/system/ssh.socket.d/override.conf
        systemctl daemon-reload
        print_status "SSH socket override configured for port ${SSH_PORT}"
        print_info "File: /etc/systemd/system/ssh.socket.d/override.conf"
    else
        print_info "Using traditional ssh.service (no socket activation detected)"
        print_info "Port change will be applied via sshd_config drop-in"
    fi
    
    # ---- Validate & Restart ----
    print_subsection "Configuration Validation & Restart"
    
    print_step "Testing SSH configuration syntax..."
    local sshd_test_output
    sshd_test_output=$(sshd -t 2>&1)
    
    if [ $? -eq 0 ]; then
        print_status "SSH configuration syntax is valid ✔"
        
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
        
        # Verify SSH is listening on new port
        sleep 2
        if ss -tlnp | grep -q ":${SSH_PORT} "; then
            print_status "SSH is now listening on port ${SSH_PORT} ✔"
            local ssh_proc
            ssh_proc=$(ss -tlnp | grep ":${SSH_PORT} " | awk '{print $NF}' | head -1)
            print_info "Process: ${ssh_proc}"
        else
            print_warning "SSH may not be listening on port ${SSH_PORT} yet"
            print_info "This can take a few seconds. Verify with: ss -tlnp | grep ${SSH_PORT}"
        fi
        
        mark_completed "harden_ssh"
    else
        print_error "SSH configuration test FAILED!"
        print_error "Output: ${sshd_test_output}"
        print_step "Reverting all SSH changes..."
        rm -f /etc/ssh/sshd_config.d/99-hardening.conf
        rm -rf /etc/systemd/system/ssh.socket.d
        systemctl daemon-reload 2>/dev/null || true
        print_error "Configuration reverted. Your SSH is unchanged."
        print_info "Check the log file for details: ${LOG_FILE}"
        mark_failed "harden_ssh" "Configuration syntax error: ${sshd_test_output}"
        return 1
    fi
    
    # ---- Final Warnings ----
    echo ""
    print_warning_box "IMPORTANT: Test SSH access in a NEW terminal before closing this session!"
    echo ""
    echo -e "  ${BOLD}Test command:${NC}"
    echo -e "    ${CYAN}ssh -p ${SSH_PORT} ${TARGET_USER}@${PRIMARY_IP}${NC}"
    echo ""
    
    if [ "$disable_password" = "no" ]; then
        echo ""
        print_warning "Password authentication is still ENABLED."
        print_info "To disable it later:"
        echo -e "    ${CYAN}1. Add your SSH public key to ~/.ssh/authorized_keys${NC}"
        echo -e "    ${CYAN}2. Re-run SSH hardening (menu option 2)${NC}"
    fi
    
    print_info "SSH configuration file: /etc/ssh/sshd_config.d/99-hardening.conf"
    print_info "To view active config: sshd -T | grep -E 'port|password|root|pubkey'"
}

# ----------------------------------------------------------------------------
# Function: add_ssh_key
# Purpose: Helper function to add SSH keys interactively
# ----------------------------------------------------------------------------
add_ssh_key() {
    print_subsection "Add SSH Public Key"
    
    # Ensure .ssh directory exists with correct permissions
    local ssh_dir="${USER_HOME}/.ssh"
    if [ ! -d "$ssh_dir" ]; then
        mkdir -p "$ssh_dir"
        chown "${TARGET_USER}:${TARGET_USER}" "$ssh_dir"
        chmod 700 "$ssh_dir"
        print_status "Created ${ssh_dir} with permissions 700"
    else
        # Fix permissions if needed
        chmod 700 "$ssh_dir"
        chown "${TARGET_USER}:${TARGET_USER}" "$ssh_dir"
        print_info "Using existing ${ssh_dir}"
    fi
    
    # Ensure authorized_keys exists with correct permissions
    local auth_keys="${ssh_dir}/authorized_keys"
    if [ ! -f "$auth_keys" ]; then
        touch "$auth_keys"
        chown "${TARGET_USER}:${TARGET_USER}" "$auth_keys"
        chmod 600 "$auth_keys"
        print_status "Created ${auth_keys} with permissions 600"
    fi
    
    echo ""
    print_info "Paste your SSH public key below."
    print_info "Supported formats: ssh-rsa, ssh-ed25519, ecdsa-sha2-*"
    print_info "Type 'skip' to skip, or paste your key:"
    echo ""
    echo -e "  ${DIM}Example: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host${NC}"
    echo ""
    
    local ssh_key=""
    read -r ssh_key
    
    if [ "$ssh_key" = "skip" ] || [ -z "$ssh_key" ]; then
        print_warning "Skipped SSH key addition"
        return 1
    fi
    
    # Validate key format
    if echo "$ssh_key" | ssh-keygen -lf - &>/dev/null; then
        # Check for duplicate
        local key_data
        key_data=$(echo "$ssh_key" | awk '{print $2}')
        if grep -q "$key_data" "$auth_keys" 2>/dev/null; then
            print_warning "This key already exists in authorized_keys"
            return 0
        fi
        
        echo "$ssh_key" >> "$auth_keys"
        chown "${TARGET_USER}:${TARGET_USER}" "$auth_keys"
        chmod 600 "$auth_keys"
        
        local fingerprint
        fingerprint=$(echo "$ssh_key" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')
        local key_bits
        key_bits=$(echo "$ssh_key" | ssh-keygen -lf - 2>/dev/null | awk '{print $1}')
        local key_type
        key_type=$(echo "$ssh_key" | ssh-keygen -lf - 2>/dev/null | awk '{print $NF}' | tr -d '()')
        
        print_status "SSH key added successfully"
        print_info "Fingerprint: ${fingerprint}"
        print_info "Key size: ${key_bits} bits"
        print_info "Key type: ${key_type}"
        return 0
    else
        print_error "Invalid SSH key format"
        print_info "Make sure you're pasting the PUBLIC key (not the private key)"
        print_info "Public keys start with: ssh-rsa, ssh-ed25519, or ecdsa-sha2-"
        return 1
    fi
}

# End of Section 2
# ============================================================================
# TIER 0 CONTINUED: FIREWALL, FAIL2BAN, KERNEL, AUTO-UPDATES, USER SETUP
# ============================================================================

# ----------------------------------------------------------------------------
# Function: configure_firewall
# Purpose: Configure UFW firewall with interactive port selection and ICMP mods
# ----------------------------------------------------------------------------
configure_firewall() {
    start_task_timer
    print_section "FIREWALL CONFIGURATION (UFW)"
    
    if ! command_exists ufw; then
        print_step "Installing UFW..."
        apt-get install -y ufw >> "$LOG_FILE" 2>&1
        print_status "UFW installed successfully"
    else
        print_info "UFW is already installed"
    fi
    
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        if [ -z "$SSH_PORT" ]; then
            prompt_input "Enter your SSH port" "2222" SSH_PORT
        fi
    fi
    
    print_subsection "Current Firewall Status"
    ufw status verbose 2>/dev/null || print_info "UFW is not yet configured or active"
    
    print_subsection "Firewall Rules Reset"
    if confirm "Reset UFW to clean state before configuring?" "n"; then
        print_step "Resetting UFW rules..."
        ufw --force reset >> "$LOG_FILE" 2>&1
        print_status "UFW reset to default factory state"
    fi
    
    # Default firewall policies
    print_step "Applying default traffic policies..."
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1
    ufw default deny routed >> "$LOG_FILE" 2>&1
    print_status "Default Policies: DENY incoming, ALLOW outgoing, DENY routed"
    
    # Rate limit SSH on the custom port
    print_step "Configuring SSH rule on port ${SSH_PORT}..."
    ufw limit "${SSH_PORT}/tcp" comment "SSH Port (rate-limited)" >> "$LOG_FILE" 2>&1
    print_status "SSH traffic allowed on port ${SSH_PORT} with brute-force rate-limiting"
    
    # Common services rules
    print_subsection "Common Application Ports"
    
    if confirm "Allow HTTP (port 80) traffic?" "n"; then
        ufw allow 80/tcp comment "HTTP Web Server" >> "$LOG_FILE" 2>&1
        print_status "Allowed: HTTP (80/tcp)"
    fi
    
    if confirm "Allow HTTPS (port 443) traffic?" "n"; then
        ufw allow 443/tcp comment "HTTPS Web Server" >> "$LOG_FILE" 2>&1
        print_status "Allowed: HTTPS (443/tcp)"
    fi

    if confirm "Allow DNS traffic (port 53)?" "n"; then
        ufw allow 53/tcp comment "DNS Server TCP" >> "$LOG_FILE" 2>&1
        ufw allow 53/udp comment "DNS Server UDP" >> "$LOG_FILE" 2>&1
        print_status "Allowed: DNS (53/tcp, 53/udp)"
    fi

    if confirm "Allow WireGuard VPN traffic (port 51820)?" "n"; then
        ufw allow 51820/udp comment "WireGuard VPN" >> "$LOG_FILE" 2>&1
        print_status "Allowed: WireGuard (51820/udp)"
    fi
    
    # Custom ports configuration loop
    print_subsection "Custom Service Rules"
    if confirm "Do you want to configure custom port rules?" "n"; then
        while true; do
            local custom_port=""
            prompt_input "Enter custom port number (or 'done' to finish)" "" custom_port
            
            if [ "$custom_port" = "done" ] || [ -z "$custom_port" ]; then
                break
            fi
            
            if ! validate_port "$custom_port"; then
                print_error "Invalid port: ${custom_port}. Please enter a number between 1 and 65535."
                continue
            fi
            
            local proto=""
            prompt_input "Choose protocol (tcp/udp/both)" "tcp" proto
            
            local desc=""
            prompt_input "Enter a brief rule description" "Custom User Service" desc
            
            case "$proto" in
                both)
                    ufw allow "$custom_port" comment "$desc" >> "$LOG_FILE" 2>&1
                    print_status "Allowed: ${custom_port}/tcp and ${custom_port}/udp - ${desc}"
                    ;;
                tcp|udp)
                    ufw allow "${custom_port}/${proto}" comment "$desc" >> "$LOG_FILE" 2>&1
                    print_status "Allowed: ${custom_port}/${proto} - ${desc}"
                    ;;
                *)
                    print_error "Invalid protocol selection. Skipping port."
                    ;;
            esac
        done
    fi
    
    # ICMP (Ping) configuration
    print_subsection "ICMP (Ping) Protection"
    if confirm "Configure ICMP (ping) rate-limiting to mitigate flood attacks?" "y"; then
        backup_file /etc/ufw/before.rules "pre-ICMP-hardening"
        
        # Inject rate limit rules for icmp into before.rules if not already present
        if [ -f /etc/ufw/before.rules ] && ! grep -q "ufw-before-input -p icmp" /etc/ufw/before.rules; then
            print_step "Modifying /etc/ufw/before.rules to rate limit ICMP..."
            # Find the line allowing icmp and replace/insert rate limiting rules
            sed -i '/-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT/i \
-A ufw-before-input -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT\n-A ufw-before-input -p icmp --icmp-type echo-request -j DROP' /etc/ufw/before.rules
            print_status "ICMP rate-limiting applied"
        else
            print_info "ICMP rules already rate-limited or configuration file not found"
        fi
    fi
    
    # IPv6 default configurations
    backup_file /etc/default/ufw "pre-IPv6-config"
    if confirm "Enable IPv6 firewall rules?" "y"; then
        sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
        print_status "IPv6 firewall support enabled in UFW"
    else
        sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
        print_status "IPv6 firewall support disabled in UFW"
    fi
    
    # Final activation
    print_subsection "Activating Firewall"
    print_warning "Review your current listening ports before continuing."
    print_info "SSH access will be active on port ${SSH_PORT}."
    
    if confirm "Are you ready to enable the UFW firewall now?" "y"; then
        ufw --force enable >> "$LOG_FILE" 2>&1
        print_status "UFW Firewall is now ENABLED and ACTIVE"
    else
        print_warning "UFW configurations saved, but firewall remains DISABLED"
        print_info "You can manually enable it using: ufw enable"
    fi
    
    # Logging status
    echo ""
    print_info "UFW active rules summary:"
    ufw status numbered
    
    mark_completed "configure_firewall"
}

# ----------------------------------------------------------------------------
# Function: setup_fail2ban
# Purpose: Install and configure Fail2ban with robust jail structures
# ----------------------------------------------------------------------------
setup_fail2ban() {
    start_task_timer
    print_section "FAIL2BAN CONFIGURATION"
    
    if ! command_exists fail2ban-client; then
        print_step "Installing Fail2ban..."
        apt-get install -y fail2ban >> "$LOG_FILE" 2>&1
        print_status "Fail2ban installed successfully"
    else
        local f2b_ver
        f2b_version=$(fail2ban-client --version | head -1 | awk '{print $2}')
        print_info "Fail2ban already installed: v${f2b_version}"
    fi
    
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        if [ -z "$SSH_PORT" ]; then
            prompt_input "Enter your SSH port" "2222" SSH_PORT
        fi
    fi
    
    print_subsection "Ban Threshold Configuration"
    local bantime="" findtime="" maxretry=""
    prompt_input "Enter default ban duration (minutes)" "60" bantime
    prompt_input "Enter detection window (minutes)" "10" findtime
    prompt_input "Enter maximum failed attempts before ban" "4" maxretry
    
    # Journald detection
    local backend="auto"
    if service_active "systemd-journald"; then
        backend="systemd"
        print_info "Systemd journald detected; configuring as default log backend"
    fi
    
    # Action determination
    local banaction="ufw"
    if ! command_exists ufw; then
        banaction="iptables-multiport"
        print_warning "UFW not found; falling back to iptables-multiport for ban execution"
    fi
    
    print_subsection "Applying Config Drop-ins"
    backup_file /etc/fail2ban/jail.conf "pre-f2b-hardening"
    backup_directory /etc/fail2ban/jail.d "pre-f2b-hardening"
    
    mkdir -p /etc/fail2ban/jail.d
    
    # Global parameters configuration
    cat > /etc/fail2ban/jail.d/00-hardening-defaults.local << EOF
# ============================================================
# VPS Hardening - Fail2ban Global Defaults
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

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
    print_status "Global defaults configured: /etc/fail2ban/jail.d/00-hardening-defaults.local"
    
    # Custom SSH Jail Configuration
    cat > /etc/fail2ban/jail.d/10-sshd.local << EOF
# ============================================================
# VPS Hardening - SSH Daemon Jail
# ============================================================
[sshd]
enabled = true
port    = ${SSH_PORT}
filter  = sshd
logpath = %(sshd_log)s
maxretry = ${maxretry}
bantime  = ${bantime}m
EOF
    chmod 644 /etc/fail2ban/jail.d/10-sshd.local
    print_status "SSH Daemon Jail configured on port ${SSH_PORT}"
    
    # Optional additional filters
    print_subsection "Optional Application Jails"
    
    if confirm "Enable monitoring and jails for Nginx/Apache servers?" "n"; then
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

[nginx-badbots]
enabled = true
port    = http,https
filter  = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[apache-auth]
enabled = true
port    = http,https
filter  = apache-auth
logpath = /var/log/apache2/error.log
EOF
        chmod 644 /etc/fail2ban/jail.d/20-webserver.local
        print_status "Nginx/Apache security jails configured"
    fi
    
    if confirm "Enable mail server protection jails (Postfix/Dovecot)?" "n"; then
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
        print_status "Mail server security jails configured"
    fi
    
    if confirm "Enable recidive jail (bans repeat offenders for 1 week)?" "y"; then
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
        print_status "Recidive jail enabled (long-term ban protection)"
    fi
    
    print_subsection "Enabling and Starting Service"
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    
    if systemctl restart fail2ban >> "$LOG_FILE" 2>&1; then
        print_status "Fail2ban service is active and running"
    else
        print_error "Fail2ban failed to restart. Review execution log: ${LOG_FILE}"
        mark_failed "setup_fail2ban" "Service failed to restart"
        return 1
    fi
    
    sleep 2
    echo ""
    print_info "Fail2ban operational status:"
    fail2ban-client status 2>/dev/null || print_warning "Could not gather active fail2ban status"
    
    mark_completed "setup_fail2ban"
}

# ----------------------------------------------------------------------------
# Function: kernel_hardening
# Purpose: Apply comprehensive system sysctl profiles to secure kernel space
# ----------------------------------------------------------------------------
kernel_hardening() {
    start_task_timer
    print_section "KERNEL HARDENING (SYSCTL)"
    
    print_subsection "Config Backups"
    backup_file /etc/sysctl.conf "pre-hardening-sysctl"
    backup_directory /etc/sysctl.d "pre-hardening-sysctl"
    
    print_subsection "Applying Hardened Kernel Parameters"
    
    # Writing detailed, modern 40+ parameter kernel security profiles
    cat > /etc/sysctl.d/99-vps-hardening.conf << 'EOF'
# ============================================================
# VPS Hardening - Core Kernel Parameters Drop-in
# ============================================================

# ---- IP Spoofing & Source Routing Protection ----
# Enable Reverse Path Filtering (prevents IP spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable Source Routing (blocks spoofed packet routing)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ---- ICMP Hardening ----
# Ignore ICMP Broadcast Requests (Smurf attack mitigation)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bad ICMP error messages
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ---- Redirect Attack Protection (MITM Mitigations) ----
# Do not accept ICMP redirects (prevents routing manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Do not send ICMP redirects (system is not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# ---- SYN Flood Protection ----
# Enable TCP SYN Cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Max TCP SYN backlog queue
net.ipv4.tcp_max_syn_backlog = 2048

# Reduce SYN-ACK retries to clear socket memory faster
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Enable RFC 1337 (protection against TCP TIME_WAIT attacks)
net.ipv4.tcp_rfc1337 = 1

# ---- TCP RFC Protections & Timestamps ----
# Disable TCP Timestamps to prevent system uptime leaks
net.ipv4.tcp_timestamps = 0

# Enable TCP Window Scaling
net.ipv4.tcp_window_scaling = 1

# ---- IP Forwarding ----
# Disable IP packet forwarding (system is not a gateway/router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# ---- IPv6 Hardening ----
# Ignore Router Advertisements (prevents IPv6 spoofing/MITM)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# ---- Memory Protections (Exploit Mitigations) ----
# Enforce Randomized Address Space Layout (ASLR)
kernel.randomize_va_space = 2

# ---- System Logs & Kernel Exposure ----
# Restrict dmesg execution to root only
kernel.dmesg_restrict = 1

# Restrict Kernel pointer access (mitigates privilege escalations)
kernel.kptr_restrict = 2

# ---- BPF & Tracing Hardening ----
# Disable unprivileged BPF access (blocks kernel memory extraction)
kernel.unprivileged_bpf_disabled = 1

# Restrict process tracing (ptrace) to parent processes
kernel.yama.ptrace_scope = 2

# ---- Filesystem Integrity Rules ----
# Prevent hardlink attacks
fs.protected_hardlinks = 1

# Prevent symlink attacks
fs.protected_symlinks = 1

# Secure write access in world-writable directories
fs.protected_fifos = 2
fs.protected_regular = 2

# ---- Memory Dump Protection ----
# Disable setuid core dumps (prevents sensitive environment leaks)
fs.suid_dumpable = 0

# ---- Martian Packet Auditing ----
# Log packets with impossible addresses
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ---- Performance & Buffer Hardening ----
# Optimize maximum file descriptors limit
fs.file-max = 2097152

# Limit max watch instances
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 8192

# Optimize network read/write buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 5000
EOF
    chmod 644 /etc/sysctl.d/99-vps-hardening.conf
    print_status "Hardened sysctl rules configuration deployed"
    
    print_step "Applying parameters into live kernel space..."
    if sysctl --system >> "$LOG_FILE" 2>&1; then
        print_status "Live kernel space parameterized successfully"
    else
        print_warning "Applying some parameters failed; this is normal on limited openvz/lxc containers"
    fi
    
    print_subsection "Runtime Hardening Verification"
    local checks=(
        "kernel.randomize_va_space:2:ASLR Configuration"
        "net.ipv4.tcp_syncookies:1:SYN Cookie Flooding Defenses"
        "net.ipv4.conf.all.rp_filter:1:Reverse Path Spoofing Filters"
        "kernel.dmesg_restrict:1:dmesg Restriction Profiles"
        "fs.protected_symlinks:1:Failsafe Symlink Protection"
    )
    
    local check
    for check in "${checks[@]}"; do
        IFS=':' read -r param expected label <<< "$check"
        local actual
        actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        if [ "$actual" = "$expected" ]; then
            print_status "${label}: [${actual}] OK ✔"
        else
            print_warning "${label}: [${actual}] expected [${expected}] (Possible restricted hypervisor environment)"
        fi
    done
    
    mark_completed "kernel_hardening"
}

# ----------------------------------------------------------------------------
# Function: setup_auto_updates
# Purpose: Configure automated unattended updates and notifications
# ----------------------------------------------------------------------------
setup_auto_updates() {
    start_task_timer
    print_section "AUTOMATIC SECURITY UPDATES"
    
    print_step "Installing unattended-upgrades tools..."
    apt-get install -y unattended-upgrades apt-listchanges >> "$LOG_FILE" 2>&1
    print_status "Unattended upgrading binaries deployed"
    
    backup_file /etc/apt/apt.conf.d/20auto-upgrades "pre-updates-config"
    backup_file /etc/apt/apt.conf.d/50unattended-upgrades "pre-updates-config"
    
    print_subsection "Schedule Frequency Configuration"
    local update_interval="" download_interval="" autoclean_interval=""
    prompt_input "Set package checklist update frequency (in days)" "1" update_interval
    prompt_input "Set background download frequency (in days)" "1" download_interval
    prompt_input "Set cache autoclean frequency (in days)" "7" autoclean_interval
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
// VPS Hardening - Automatic Updates Frequency Setup
APT::Periodic::Update-Package-Lists "${update_interval}";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "${download_interval}";
APT::Periodic::AutocleanInterval "${autoclean_interval}";
APT::Periodic::Verbose "1";
EOF
    chmod 644 /etc/apt/apt.conf.d/20auto-upgrades
    print_status "APT periodic updater schedule deployed"
    
    print_subsection "Automated Reboot Configuration"
    local auto_reboot="false"
    local reboot_time="03:30"
    
    if confirm "Enable automatic reboot when kernel security upgrades require it?" "n"; then
        auto_reboot="true"
        prompt_input "Specify automatic reboot time (HH:MM format)" "03:30" reboot_time
        print_warning "Attention: Server will reboot at ${reboot_time} when upgrades mandate it!"
    fi
    
    cat > /etc/apt/apt.conf.d/51unattended-upgrades-custom << EOF
// VPS Hardening - Custom Unattended Upgrade Handlers
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
    print_status "Automated update behaviors and rules modified"
    
    print_subsection "Timer Configurations Activation"
    systemctl enable unattended-upgrades >> "$LOG_FILE" 2>&1
    systemctl restart unattended-upgrades >> "$LOG_FILE" 2>&1
    
    if service_active "unattended-upgrades"; then
        print_status "Unattended-Upgrades service actively daemonized"
    else
        print_warning "Service failed default check; check with systemctl status unattended-upgrades"
    fi
    
    systemctl enable apt-daily.timer >> "$LOG_FILE" 2>&1
    systemctl enable apt-daily-upgrade.timer >> "$LOG_FILE" 2>&1
    systemctl start apt-daily.timer >> "$LOG_FILE" 2>&1
    systemctl start apt-daily-upgrade.timer >> "$LOG_FILE" 2>&1
    print_status "APT daily processing timers active"
    
    if confirm "Perform an immediate dry-run analysis test?" "n"; then
        print_step "Analyzing simulation upgrade dry-run..."
        unattended-upgrades --dry-run --debug 2>&1 | tail -20
        print_status "Simulation execution completed"
    fi
    
    mark_completed "setup_auto_updates"
}

# ----------------------------------------------------------------------------
# Function: setup_user_account
# Purpose: Create a separate administrative account and apply sudo rules
# ----------------------------------------------------------------------------
setup_user_account() {
    start_task_timer
    print_section "USER ACCOUNT & SUDO SETUP"
    
    print_info "Current active user: ${TARGET_USER}"
    print_info "Home directory: ${USER_HOME}"
    
    print_subsection "Interactive Admin Account Generation"
    if confirm "Create a new administrative user to manage this VPS?" "n"; then
        local new_user=""
        while true; do
            prompt_input "Enter the username for the new administrative user" "" new_user
            if [ -z "$new_user" ]; then
                print_error "Username cannot be empty"
                continue
            fi
            if [[ ! "$new_user" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
                print_error "Invalid format. Username must start with a letter and use only lowercase letters/numbers"
                continue
            fi
            if id "$new_user" &>/dev/null; then
                print_warning "Username '${new_user}' already exists on this system"
                if ! confirm "Configure this existing user?" "n"; then
                    continue
                fi
            fi
            break
        done
        
        # User initialization
        if ! id "$new_user" &>/dev/null; then
            print_step "Initializing system user: ${new_user}..."
            useradd -m -s /bin/bash -G sudo "$new_user"
            print_status "User added to system and associated with sudo group"
            
            print_step "Assigning credentials for ${new_user}..."
            passwd "$new_user"
        fi
        
        # Secure directory mapping
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
        
        # Ssh key inheritance checks
        if [ -f "${USER_HOME}/.ssh/authorized_keys" ] && [ -s "${USER_HOME}/.ssh/authorized_keys" ]; then
            if confirm "Copy authorized SSH keys from current account (${TARGET_USER}) to ${new_user}?" "y"; then
                cp "${USER_HOME}/.ssh/authorized_keys" "${new_ssh_dir}/authorized_keys"
                chown "${new_user}:${new_user}" "${new_ssh_dir}/authorized_keys"
                chmod 600 "${new_ssh_dir}/authorized_keys"
                print_status "SSH authorized profiles inherited successfully"
            fi
        fi
        
        TARGET_USER="$new_user"
        USER_HOME="$new_home"
        save_state "ADMIN_USER" "$new_user"
        print_status "Active administrative management target user set to: ${new_user}"
    fi
    
    print_subsection "Hardening sudoers Permissions Map"
    if confirm "Enforce password validation on EVERY sudo call (zero credential caching)?" "n"; then
        mkdir -p /etc/sudoers.d
        cat > /etc/sudoers.d/99-hardening-timestamp << 'EOF'
# Hardened Sudo Timestamp - zero duration
Defaults timestamp_timeout=0
EOF
        chmod 440 /etc/sudoers.d/99-hardening-timestamp
        print_status "Password validation caching policy hardened"
    fi
    
    if confirm "Configure detailed logging audit profiles for sudo usage?" "y"; then
        mkdir -p /etc/sudoers.d
        cat > /etc/sudoers.d/99-hardening-logging << 'EOF'
# Sudo Execution Audit Rules
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
Defaults iolog_dir="/var/log/sudo-io"
EOF
        chmod 440 /etc/sudoers.d/99-hardening-logging
        mkdir -p /var/log/sudo-io
        chmod 700 /var/log/sudo-io
        print_status "Comprehensive execution audit logging enabled (/var/log/sudo.log)"
    fi
    
    if confirm "Restrict 'su' access exclusively to accounts in the sudo group?" "y"; then
        backup_file /etc/pam.d/su "pre-su-restriction"
        if ! grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
            sed -i 's/^#\s*auth\s*required\s*pam_wheel.so/auth required pam_wheel.so/' /etc/pam.d/su
            if ! grep -q "pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
                echo "auth required pam_wheel.so" >> /etc/pam.d/su
            fi
            print_status "Access restriction enforced; only members of group 'sudo' may invoke 'su'"
        else
            print_info "'su' access is already restricted"
        fi
    fi
    
    print_subsection "Local Root Access Lockdown"
    if confirm "Lock default password access to root user account? (Admins use sudo)" "y"; then
        passwd -l root >> "$LOG_FILE" 2>&1
        print_status "Direct password access to root locked"
    fi
    
    mark_completed "setup_user_account"
}

# End of Section 3
# ============================================================================
# TIER 1: HIGH IMPACT DEFENSES (PART 1)
# ============================================================================

# ----------------------------------------------------------------------------
# Function: secure_shared_memory
# Purpose: Secure /dev/shm to prevent in-memory malware execution
# ----------------------------------------------------------------------------
secure_shared_memory() {
    start_task_timer
    print_section "SECURE SHARED MEMORY (/dev/shm)"
    
    print_info "/dev/shm is a world-writable tmpfs partition used for inter-process communication."
    print_info "Attackers frequently exploit default settings to download and execute binaries"
    print_info "directly in memory, bypassing standard disk-based anti-virus and auditing."
    echo ""
    
    print_subsection "Analyze Current Mount Status"
    local current_opts=""
    if mount | grep -q " /dev/shm "; then
        current_opts=$(mount | grep " /dev/shm " | sed 's/.*(\(.*\))/\1/')
        print_info "Current active mount options: ${current_opts}"
    else
        print_warning "/dev/shm is not currently mounted as a separate partition"
    fi
    
    # Check for existing fstab entry
    print_subsection "Configuring /etc/fstab"
    if grep -q " /dev/shm " /etc/fstab 2>/dev/null; then
        print_warning "/dev/shm already has a configured entry in /etc/fstab"
        if ! confirm "Would you like to overwrite this entry with hardened settings?" "y"; then
            print_info "Skipping /dev/shm configuration as requested."
            mark_skipped "secure_shared_memory" "User chose not to overwrite existing fstab entry"
            return 0
        fi
        backup_file /etc/fstab "pre-fstab-shm-hardening"
        print_step "Removing old /dev/shm entry from fstab..."
        sed -i '/ \/dev\/shm /d' /etc/fstab
    else
        backup_file /etc/fstab "pre-fstab-shm-hardening"
    fi
    
    # Add hardened mount options (noexec, nosuid, nodev)
    print_step "Writing hardened options to /etc/fstab..."
    echo -e "# VPS Hardening - Secure /dev/shm\ntmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=1G 0 0" >> /etc/fstab
    chmod 644 /etc/fstab
    print_status "/etc/fstab updated"
    
    # Remount immediately to apply changes
    print_subsection "Remounting /dev/shm"
    print_step "Attempting to remount /dev/shm with new parameters..."
    
    if mount -o remount /dev/shm 2>>"$LOG_FILE"; then
        print_status "/dev/shm remounted successfully"
    else
        print_warning "Failed to live-remount /dev/shm (this is common if services are currently utilizing it)."
        print_info "Hardened mount options will be applied automatically on the next system reboot."
        print_info "Command tried: mount -o remount /dev/shm"
    fi
    
    # Verify active options
    print_subsection "Mount Options Verification"
    local verify_opts=""
    verify_opts=$(mount | grep " /dev/shm " | sed 's/.*(\(.*\))/\1/' || echo "none")
    print_info "Current active parameters: ${verify_opts}"
    
    local verify_failed=0
    
    if echo "$verify_opts" | grep -q "noexec"; then
        print_status "noexec parameter is ACTIVE ✔"
    else
        print_warning "noexec parameter is INACTIVE (Reboot required)"
        verify_failed=1
    fi
    
    if echo "$verify_opts" | grep -q "nosuid"; then
        print_status "nosuid parameter is ACTIVE ✔"
    else
        print_warning "nosuid parameter is INACTIVE (Reboot required)"
        verify_failed=1
    fi
    
    if echo "$verify_opts" | grep -q "nodev"; then
        print_status "nodev parameter is ACTIVE ✔"
    else
        print_warning "nodev parameter is INACTIVE (Reboot required)"
        verify_failed=1
    fi
    
    if [ "$verify_failed" -eq 0 ]; then
        print_success_box "Shared memory secured successfully"
    else
        print_info "Changes have been written to /etc/fstab and will take full effect after reboot."
    fi
    
    mark_completed "secure_shared_memory"
}

# ----------------------------------------------------------------------------
# Function: disable_unused_protocols
# Purpose: Disable unused and vulnerable kernel network modules
# ----------------------------------------------------------------------------
disable_unused_protocols() {
    start_task_timer
    print_section "DISABLE UNUSED NETWORK PROTOCOLS"
    
    print_info "The Linux kernel supports a wide range of legacy, obscure, or niche protocols."
    print_info "Many of these are not needed for a standard VPS, but their drivers remain"
    print_info "available, presenting targets for local privilege escalation exploits."
    echo ""
    
    backup_directory /etc/modprobe.d "pre-modprobe-hardening"
    
    print_subsection "Disable Core High-Risk Protocols"
    print_step "Writing rules to block dangerous protocol drivers..."
    
    cat > /etc/modprobe.d/99-vps-disable-protocols.conf << 'EOF'
# ============================================================
# VPS Hardening - Block Unused Kernel Protocol Drivers
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# DCCP - Datagram Congestion Control Protocol (CVE-2017-6074)
install dccp /bin/true
install dccp_ipv4 /bin/true
install dccp_ipv6 /bin/true

# SCTP - Stream Control Transmission Protocol (Multiple CVEs)
install sctp /bin/true
install sctp_diag /bin/true

# RDS - Reliable Datagram Sockets (CVE-2010-3904)
install rds /bin/true
install rds_tcp /bin/true
install rds_rdma /bin/true

# TIPC - Transparent Inter-Process Communication (CVE-2021-43267)
install tipc /bin/true

# ATM - Legacy Asynchronous Transfer Mode
install atm /bin/true

# Legacy and Amateur Radio protocols
install ax25 /bin/true
install netrom /bin/true
install rose /bin/true
install x25 /bin/true
install decnet /bin/true
install econet /bin/true

# IoT and Hardware protocols (unnecessary on a VPS virtual environment)
install af_802154 /bin/true
install can /bin/true
install nfc /bin/true
EOF
    
    chmod 644 /etc/modprobe.d/99-vps-disable-protocols.conf
    chown root:root /etc/modprobe.d/99-vps-disable-protocols.conf
    print_status "Default vulnerable protocols blocked via modprobe install configurations"
    
    # Optional hardware/additional protocols
    print_subsection "Disable Optional Kernel Drivers"
    local optional_modules=()
    
    if confirm "Disable USB Storage and UAS drivers? (Highly recommended for remote servers)" "y"; then
        optional_modules+=("install usb-storage /bin/true" "install uas /bin/true")
        print_status "USB Storage and UAS drivers added to blacklist queue"
    fi
    
    if confirm "Disable FireWire (IEEE 1394) drivers? (Known direct memory access attack vector)" "y"; then
        optional_modules+=("install firewire-core /bin/true" "install firewire-ohci /bin/true" "install firewire-sbp2 /bin/true")
        print_status "FireWire drivers added to blacklist queue"
    fi
    
    if confirm "Disable Thunderbolt interfaces? (Direct memory access attack vector)" "y"; then
        optional_modules+=("install thunderbolt /bin/true")
        print_status "Thunderbolt interface driver added to blacklist queue"
    fi
    
    if confirm "Disable physical PC speaker beep driver?" "n"; then
        optional_modules+=("install pcspkr /bin/true" "blacklist pcspkr")
        print_status "PC speaker driver added to blacklist queue"
    fi
    
    if confirm "Disable Bluetooth stack drivers? (Unnecessary overhead on remote instances)" "y"; then
        optional_modules+=("install bluetooth /bin/true" "install btusb /bin/true")
        print_status "Bluetooth drivers added to blacklist queue"
    fi
    
    if confirm "Disable CIFS (Samba Client) module? (Unless mounting remote Windows shares)" "y"; then
        optional_modules+=("install cifs /bin/true")
        print_status "CIFS driver added to blacklist queue"
    fi
    
    if confirm "Disable NFS Client filesystem modules? (Unless mounting NFS storage exports)" "y"; then
        optional_modules+=("install nfs /bin/true" "install nfsv3 /bin/true" "install nfsv4 /bin/true")
        print_status "NFS Client drivers added to blacklist queue"
    fi
    
    # Append optional configurations if selected
    if [ ${#optional_modules[@]} -gt 0 ]; then
        echo -e "\n# ---- Optional Blocked Driver Modules ----" >> /etc/modprobe.d/99-vps-disable-protocols.conf
        local mod
        for mod in "${optional_modules[@]}"; do
            echo "$mod" >> /etc/modprobe.d/99-vps-disable-protocols.conf
        done
    fi
    
    # Try to unload currently active dangerous drivers
    print_subsection "Unload Active Vulnerable Kernel Modules"
    local modules_to_unload=("dccp" "sctp" "rds" "tipc")
    local active_unloaded=0
    
    for mod in "${modules_to_unload[@]}"; do
        if lsmod | grep -q "^${mod} "; then
            print_step "Active module detected: ${mod}. Attempting to unload..."
            if rmmod "$mod" 2>>"$LOG_FILE"; then
                print_status "Successfully unloaded: ${mod} ✔"
                ((active_unloaded++))
            else
                print_warning "Failed to unload active module: ${mod}. It may currently be locked by a running process."
                print_info "Driver is blacklisted and will not load on subsequent boots."
            fi
        fi
    done
    
    if [ "$active_unloaded" -gt 0 ]; then
        print_status "${active_unloaded} active modules unloaded live"
    fi
    
    print_info "Modprobe block config file: /etc/modprobe.d/99-vps-disable-protocols.conf"
    mark_completed "disable_unused_protocols"
}

# ----------------------------------------------------------------------------
# Function: setup_apparmor
# Purpose: Enable and enforce AppArmor mandatory access control
# ----------------------------------------------------------------------------
setup_apparmor() {
    start_task_timer
    print_section "APPARMOR - MANDATORY ACCESS CONTROL"
    
    print_info "AppArmor (Mandatory Access Control) restricts applications to a set of"
    print_info "defined capabilities, blocking unauthorized file writes, process executions,"
    print_info "and network bindings even if the application is compromised."
    echo ""
    
    if ! command_exists apparmor_status && ! command_exists aa-status; then
        print_step "Installing AppArmor user-space tools..."
        if apt-get install -y apparmor apparmor-utils >> "$LOG_FILE" 2>&1; then
            print_status "AppArmor binaries installed"
        else
            print_error "Failed to install AppArmor user-space tools"
            mark_failed "setup_apparmor" "Apt installation failed"
            return 1
        fi
    else
        print_info "AppArmor user-space tools are already present"
    fi
    
    print_step "Installing expanded security profiles..."
    if apt-get install -y apparmor-profiles apparmor-profiles-extra >> "$LOG_FILE" 2>&1; then
        print_status "Additional profile sets installed"
    else
        print_warning "Additional profiles failed to install or were not found on this OS version"
    fi
    
    print_subsection "Kernel Support Audit"
    if [ -d /sys/kernel/security/apparmor ]; then
        print_status "AppArmor kernel engine is loaded and operational"
    else
        print_critical "AppArmor kernel support is not active"
        print_info "This may require adding boot flags to your kernel command line."
        
        if confirm "Would you like to inject AppArmor activation parameters into GRUB config?" "y"; then
            backup_file /etc/default/grub "pre-apparmor-grub-inject"
            
            if ! grep -q "apparmor=1" /etc/default/grub; then
                print_step "Adding AppArmor parameters to GRUB_CMDLINE_LINUX_DEFAULT..."
                sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 apparmor=1 security=apparmor"/' /etc/default/grub
                
                print_step "Regenerating GRUB boot files..."
                if command_exists update-grub; then
                    update-grub >> "$LOG_FILE" 2>&1
                    print_status "GRUB updated successfully"
                elif command_exists grub2-mkconfig; then
                    grub2-mkconfig -o /boot/grub2/grub.cfg >> "$LOG_FILE" 2>&1
                    print_status "GRUB updated successfully"
                else
                    print_warning "No GRUB update command found. Please update GRUB configuration manually."
                fi
                print_info "Reboot is required to activate kernel AppArmor support"
            else
                print_info "AppArmor boot configuration parameters are already present"
            fi
        fi
    fi
    
    print_subsection "AppArmor Profiles Enforcement"
    local enforced_count=0
    local failed_count=0
    
    if command_exists aa-enforce; then
        print_step "Enforcing all available system security profiles..."
        
        # Enforce profiles loop with absolute safety filtering
        local profile
        for profile in /etc/apparmor.d/*; do
            [ -d "$profile" ] && continue
            local base_p
            base_p=$(basename "$profile")
            
            case "$base_p" in
                local|abstractions|tunables|disable|force-complain|lxc|README|*.dpkg-*|*.rpmsave|*.rpmnew)
                    continue ;;
            esac
            
            if aa-enforce "$profile" >> "$LOG_FILE" 2>&1; then
                ((enforced_count++))
                print_debug "Enforced: ${base_p}"
            else
                ((failed_count++))
                log_warn "Failed to enforce AppArmor profile: ${base_p}"
            fi
        done
        
        print_status "Enforcement completed: ${enforced_count} profiles active"
        if [ "$failed_count" -gt 0 ]; then
            print_warning "${failed_count} profiles could not be forced into enforce mode (see log)"
        fi
    else
        print_warning "aa-enforce tool not present on system. AppArmor profile modes left at defaults."
    fi
    
    print_subsection "Enabling and Starting Service"
    systemctl enable apparmor >> "$LOG_FILE" 2>&1
    
    if systemctl restart apparmor >> "$LOG_FILE" 2>&1; then
        print_status "AppArmor service successfully restarted and active"
    else
        print_warning "Failed to restart AppArmor service (AppArmor state may be inconsistent)"
    fi
    
    print_subsection "Active Enforcement Status"
    if command_exists aa-status; then
        aa-status 2>/dev/null | head -15
    fi
    
    mark_completed "setup_apparmor"
}

# ----------------------------------------------------------------------------
# Function: setup_aide
# Purpose: Install and configure AIDE file integrity monitoring
# ----------------------------------------------------------------------------
setup_aide() {
    start_task_timer
    print_section "FILE INTEGRITY MONITORING (AIDE)"
    
    print_info "AIDE (Advanced Intrusion Detection Environment) constructs a cryptographic"
    print_info "database of critical system files, binaries, permissions, and hashes."
    print_info "Daily audits detect if an intruder has modified root files or inserted rootkits."
    echo ""
    
    if ! command_exists aide; then
        print_step "Installing AIDE (This may take a moment to download)..."
        if apt-get install -y aide aide-common >> "$LOG_FILE" 2>&1; then
            print_status "AIDE software deployed successfully"
        else
            print_error "Failed to install AIDE packages"
            mark_failed "setup_aide" "Apt installation failed"
            return 1
        fi
    else
        print_info "AIDE is already installed on this machine"
    fi
    
    backup_file /etc/aide/aide.conf "pre-AIDE-rules"
    
    print_subsection "Writing Hardened File Monitoring Policy rules"
    print_step "Deploying custom security profile rules..."
    
    # Custom high-impact file integrity scanning filters
    cat > /etc/aide/aide.conf.d/99_vps_hardening << 'EOF'
# ============================================================
# VPS Hardening - Strict Cryptographic File Integrity Policy
# ============================================================

# Close audit monitoring for core authentication configs
/etc/ssh/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/sudoers$ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/sudoers.d/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/pam.d/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Watch service controller structures
/etc/systemd/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Audit tasks and cron engines closely
/etc/crontab p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/cron.* p+i+n+u+g+s+b+acl+xattrs+sha512
/var/spool/cron/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Watch system driver rules
/etc/modprobe.d/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Watch security components configurations
/etc/ufw/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/fail2ban/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/apparmor/ p+i+n+u+g+s+b+acl+xattrs+sha512
/etc/apparmor.d/ p+i+n+u+g+s+b+acl+xattrs+sha512

# Ignore highly volatile system directories
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
    chown root:root /etc/aide/aide.conf.d/99_vps_hardening
    print_status "Strict cryptographic profile rules written to configuration"
    
    print_subsection "Initialize Integrity Database"
    print_warning "Database initialization calculates SHA-512 hashes for all matching system files."
    print_warning "Depending on your CPU and disk speed, this can take 2-15 minutes."
    
    if confirm "Would you like to initialize the cryptographic database now?" "y"; then
        print_step "Running database initialization (AIDE hashing system files)..."
        
        local start_db_time
        start_db_time=$(date +%s)
        
        # Run initialization
        if aideinit >> "$LOG_FILE" 2>&1; then
            local end_db_time
            end_db_time=$(date +%s)
            local diff_db_time=$(( end_db_time - start_db_time ))
            print_status "AIDE database initialized successfully in ${diff_db_time} seconds ✔"
        else
            print_warning "AIDE database initialization compiled with warnings (Check log file: ${LOG_FILE})"
        fi
        
        # Copy newly initialized db to production search directory
        print_step "Activating integrity database..."
        if [ -f /var/lib/aide/aide.db.new ]; then
            cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
            chmod 600 /var/lib/aide/aide.db
            chown root:root /var/lib/aide/aide.db
            print_status "AIDE database successfully active and locked"
        elif [ -f /var/lib/aide/aide.db.new.gz ]; then
            cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
            chmod 600 /var/lib/aide/aide.db.gz
            chown root:root /var/lib/aide/aide.db.gz
            print_status "AIDE database successfully active and locked (Gzipped)"
        else
            print_error "AIDE database compiled file not found in directory. Manual replication required."
        fi
    else
        print_info "Skipping initialization. You must run 'aideinit' manually before audit checks will function."
    fi
    
    # Configure Daily Crontab Audits with Slack/Telegram Alert hooks
    print_subsection "Configure Automatic Daily Integrity Scans"
    
    cat > /etc/cron.daily/aide-integrity-check << 'CRONEOF'
#!/bin/bash
# VPS Hardening - Daily File Integrity Audit Check

REPORT_FILE="/var/log/aide/aide-check-$(date +%Y%m%d).log"
mkdir -p /var/log/aide
chmod 700 /var/log/aide

# Run checksum audit against baseline
/usr/bin/aide --check > "$REPORT_FILE" 2>&1
EXIT_CODE=$?

# Analyze results
if [ $EXIT_CODE -ne 0 ]; then
    logger -t aide-check -p auth.warning "AIDE integrity check FAILED: File alterations detected! Report: $REPORT_FILE"
    
    # If the interactive telegram config exists, send urgent broadcast warning
    if [ -f /etc/vps-hardening/telegram.conf ]; then
        source /etc/vps-hardening/telegram.conf
        MSG="🚨 <b>AIDE File Integrity Warning</b>%0A%0AChanges detected on host: <code>${TELEGRAM_HOSTNAME}</code>%0A%0A<b>Review log urgently:</b>%0A<code>cat ${REPORT_FILE}</code>"
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}" \
            -d "text=${MSG}" \
            -d "parse_mode=HTML" > /dev/null 2>&1
    fi
else
    logger -t aide-check -p auth.info "AIDE integrity check passed: system clean"
fi

# Rotate log files older than 30 days
find /var/log/aide/ -name "aide-check-*.log" -mtime +30 -delete 2>/dev/null
exit 0
CRONEOF
    
    chmod 755 /etc/cron.daily/aide-integrity-check
    chown root:root /etc/cron.daily/aide-integrity-check
    print_status "Daily automated AIDE cron check scheduled with alert integration"
    
    mark_completed "setup_aide"
}

# End of Section 4
# ============================================================================
# TIER 1 CONTINUED: KERNEL AUDITING & TEMPORARY DIRECTORIES
# ============================================================================

# ----------------------------------------------------------------------------
# Function: setup_auditd
# Purpose: Configure the Linux Audit Daemon for kernel-level security tracing
# ----------------------------------------------------------------------------
setup_auditd() {
    start_task_timer
    print_section "KERNEL AUDIT DAEMON (auditd)"
    
    print_info "auditd implements kernel-level logging for security events."
    print_info "It logs system calls, file access, privilege escalation, and network"
    print_info "parameter modifications directly from the kernel before userspace can alter them."
    echo ""
    
    if ! command_exists auditctl; then
        print_step "Installing auditd..."
        if apt-get install -y auditd audispd-plugins >> "$LOG_FILE" 2>&1; then
            print_status "Audit daemon packages installed successfully"
        else
            print_error "Failed to install auditd packages"
            mark_failed "setup_auditd" "Apt installation failed"
            return 1
        fi
    else
        print_info "Audit daemon is already installed on this machine"
    fi
    
    backup_directory /etc/audit "pre-auditd-hardening"
    
    print_subsection "Rules Configuration"
    print_step "Writing comprehensive security tracking rules..."
    
    mkdir -p /etc/audit/rules.d
    
    # 30+ highly-detailed, immutable-ready audit rules
    cat > /etc/audit/rules.d/99-vps-hardening.rules << 'EOF'
# ============================================================
# VPS Hardening - Comprehensive Linux Audit Daemon Rules
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# Delete all existing rules
-D

# Increase processing buffer size
-b 8192

# Failure mode: 1 = printk log, 2 = kernel panic
-f 1

# ---- Identity, Accounts & Authentication ----
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# ---- Sudo & Privilege Escalation Monitoring ----
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /usr/bin/sudo -p x -k sudo_exec
-w /usr/bin/su -p x -k su_exec
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k privilege_escalation

# ---- SSH Access & Keys ----
-w /etc/ssh/ -p wa -k sshd_config
-w /root/.ssh/ -p wa -k root_ssh_keys
-w /etc/ssh/sshd_config -p wa -k sshd_main_config

# ---- Scheduler & Cron Auditing ----
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/at.allow -p wa -k cron
-w /etc/cron.allow -p wa -k cron

# ---- Kernel Module Alterations ----
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules

# ---- Network Parameters & Configuration ----
-w /etc/hosts -p wa -k network
-w /etc/resolv.conf -p wa -k network
-w /etc/hostname -p wa -k network
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/ufw/ -p wa -k firewall

# ---- System Time Modifications ----
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b64 -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# ---- Session Logins & State Tracking ----
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /var/run/utmp -p wa -k session

# ---- Security Control Software Modifications ----
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor
-w /etc/fail2ban/ -p wa -k fail2ban

# ---- File Deletion by Interactive Users ----
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k file_delete

# ---- Failed System Call Access Attempts ----
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EPERM -k access_denied
-a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EPERM -k access_denied

# ---- Executable Binary Modifications ----
-w /usr/bin/ -p wa -k bin_modification
-w /usr/sbin/ -p wa -k sbin_modification
-w /usr/local/bin/ -p wa -k local_bin_modification

# ---- Make Configuration Immutable ----
# Requires reboot to delete or modify rules
-e 2
EOF
    
    chmod 640 /etc/audit/rules.d/99-vps-hardening.rules
    print_status "Audit security rules created: /etc/audit/rules.d/99-vps-hardening.rules"
    
    # Configure Daemon Log parameters
    print_subsection "Audit Daemon Settings Configuration"
    backup_file /etc/audit/auditd.conf "pre-auditd-hardening"
    
    cat > /etc/audit/auditd.conf << 'EOF'
# VPS Hardening - auditd daemon settings
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
    print_status "Daemon configuration applied"
    
    print_subsection "Starting Service"
    systemctl enable auditd >> "$LOG_FILE" 2>&1
    
    # auditd doesn't always support standard systemctl restart inside containers; handle carefully
    if systemctl restart auditd >> "$LOG_FILE" 2>&1 || service auditd restart >> "$LOG_FILE" 2>&1; then
        print_status "auditd service is active and monitoring"
    else
        print_warning "auditd service restart failed (common on openvz/lxc hypervisors with shared kernels)"
    fi
    
    local loaded_rules_count
    loaded_rules_count=$(auditctl -l 2>/dev/null | wc -l || echo "0")
    print_info "Currently loaded kernel audit rules count: ${loaded_rules_count}"
    
    mark_completed "setup_auditd"
}

# ----------------------------------------------------------------------------
# Function: secure_tmp_directories
# Purpose: Mount temporary execution spaces with strict safety bounds
# ----------------------------------------------------------------------------
secure_tmp_directories() {
    start_task_timer
    print_section "SECURE TEMPORARY DIRECTORIES"
    
    print_info "/tmp and /var/tmp are writable by all users, making them primary locations"
    print_info "for launching malicious scripts and executing pre-staged exploit binaries."
    echo ""
    
    backup_file /etc/fstab "pre-tmp-hardening"
    
    print_subsection "Securing /tmp"
    if mount | grep -q " /tmp " && mount | grep " /tmp " | grep -q "noexec"; then
        print_info "/tmp is already secured on a separate filesystem mount"
    else
        if confirm "Mount /tmp as a secured memory partition (noexec, nosuid, nodev)?" "y"; then
            if grep -q " /tmp " /etc/fstab; then
                sed -i '/ \/tmp /d' /etc/fstab
            fi
            
            # Mount as tmpfs with strict parameters
            echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab
            
            if mount -o remount /tmp 2>>"$LOG_FILE" || mount -a >> "$LOG_FILE" 2>&1; then
                print_status "/tmp partition mounted securely"
            else
                print_warning "Failed to live-remount /tmp partition. Hardening parameters will apply after next reboot."
            fi
        fi
    fi
    
    print_subsection "Securing /var/tmp"
    if mount | grep -q " /var/tmp " && mount | grep " /var/tmp " | grep -q "noexec"; then
        print_info "/var/tmp is already secured on a separate filesystem mount"
    else
        if confirm "Mount /var/tmp as a secured partition (noexec, nosuid, nodev)?" "y"; then
            if grep -q " /var/tmp " /etc/fstab; then
                sed -i '/ \/var\/tmp /d' /etc/fstab
            fi
            
            echo "tmpfs /var/tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=1G 0 0" >> /etc/fstab
            
            if mount -o remount /var/tmp 2>>"$LOG_FILE" || mount -a >> "$LOG_FILE" 2>&1; then
                print_status "/var/tmp partition mounted securely"
            else
                print_warning "Failed to live-remount /var/tmp partition. Hardening parameters will apply after next reboot."
            fi
        fi
    fi
    
    print_subsection "Configuring Automatic Cleanup Policies"
    if confirm "Enable automated systemd cleanup of temporary directories (7-day lifecycle)?" "y"; then
        mkdir -p /etc/tmpfiles.d
        cat > /etc/tmpfiles.d/99-vps-hardening.conf << 'EOF'
# VPS Hardening - Automatic Temporary Directories Purge Rules
# Deletes files older than 7 days from execution namespaces
q /tmp 1777 root root 7d
q /var/tmp 1777 root root 7d
EOF
        chmod 644 /etc/tmpfiles.d/99-vps-hardening.conf
        print_status "Systemd cleanup policies set: /etc/tmpfiles.d/99-vps-hardening.conf"
    fi
    
    mark_completed "secure_tmp_directories"
}

# ============================================================================
# TIER 2: ADVANCED SECURITY CONTROLS (PART 1)
# ============================================================================

# ----------------------------------------------------------------------------
# Function: setup_resource_limits
# Purpose: Mitigate resource exhausting DoS and fork bomb loops
# ----------------------------------------------------------------------------
setup_resource_limits() {
    start_task_timer
    print_section "RESOURCE LIMITS & FORK BOMB PROTECTION"
    
    print_info "Limiting resource profiles stops single compromised users"
    print_info "or web workers from taking down the entire VPS via system starvation loops."
    echo ""
    
    backup_directory /etc/security/limits.d "pre-limits-hardening"
    backup_file /etc/security/limits.conf "pre-limits-hardening"
    
    print_subsection "Configuring Resource Profiles limits"
    local nproc_hard="" nproc_soft="" nofile_hard=""
    prompt_input "Set maximum processes per user [Hard Limit]" "512" nproc_hard
    prompt_input "Set maximum processes per user [Soft Limit]" "256" nproc_soft
    prompt_input "Set maximum open files per process [Hard Limit]" "65536" nofile_hard
    
    cat > /etc/security/limits.d/99-vps-hardening.conf << EOF
# ============================================================
# VPS Hardening - Global System Limits Profile
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# ---- Fork Bomb & Process Mitigation ----
*               hard    nproc           ${nproc_hard}
*               soft    nproc           ${nproc_soft}
root            hard    nproc           unlimited
root            soft    nproc           unlimited

# ---- File Handle Limits ----
*               hard    nofile          ${nofile_hard}
*               soft    nofile          8192
root            hard    nofile          1048576
root            soft    nofile          65536

# ---- Memory Pinning Limits ----
*               hard    memlock         65536
*               soft    memlock         65536

# ---- Hardened Stack Space ----
*               hard    stack           8192
*               soft    stack           8192

# ---- Concurrent Sessions Limit ----
*               hard    maxlogins       5
root            hard    maxlogins       unlimited
EOF
    chmod 644 /etc/security/limits.d/99-vps-hardening.conf
    print_status "Resource limits profile written: /etc/security/limits.d/99-vps-hardening.conf"
    
    print_subsection "Enforcing Limits Integration via PAM"
    local pam_files=("/etc/pam.d/common-session" "/etc/pam.d/common-session-noninteractive")
    local pf
    for pf in "${pam_files[@]}"; do
        if [ -f "$pf" ]; then
            if ! grep -q "pam_limits.so" "$pf" 2>/dev/null; then
                echo "session required pam_limits.so" >> "$pf"
                print_status "Enforced rules inside PAM configuration file: ${pf}"
            else
                print_info "PAM configuration already enforces pam_limits.so on ${pf}"
            fi
        fi
    done
    
    print_subsection "Systemd Core Dump Control"
    mkdir -p /etc/systemd/coredump.conf.d
    cat > /etc/systemd/coredump.conf.d/99-vps-hardening.conf << 'EOF'
# VPS Hardening - Stop core dump memory logging
[Coredump]
Storage=none
ProcessSizeMax=0
ExternalSizeMax=0
JournalSizeMax=0
EOF
    chmod 644 /etc/systemd/coredump.conf.d/99-vps-hardening.conf
    systemctl daemon-reload 2>/dev/null || true
    print_status "Systemd execution core dumps disabled"
    
    # Kernel limits parameter fallback
    cat > /etc/sysctl.d/98-coredump.conf << 'EOF'
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
EOF
    chmod 644 /etc/sysctl.d/98-coredump.conf
    sysctl --system >> "$LOG_FILE" 2>&1 || true
    print_status "Kernel level dump profiles disabled"
    
    mark_completed "setup_resource_limits"
}

# ----------------------------------------------------------------------------
# Function: disable_unnecessary_services
# Purpose: Disable useless and risky networking daemon services
# ----------------------------------------------------------------------------
disable_unnecessary_services() {
    start_task_timer
    print_section "DISABLE UNNECESSARY SERVICES"
    
    print_info "Active networking services present potential entry points."
    print_info "Auditing and shutting down unneeded system daemons keeps system footprint clean."
    echo ""
    
    print_subsection "Active Listening Interfaces"
    ss -tlnp 2>/dev/null | grep LISTEN | awk '{printf "    %-30s %s\n", $4, $6}' || \
        print_warning "Failed to extract active listening interfaces"
    echo ""
    
    declare -A system_daemons
    system_daemons=(
        ["rpcbind"]="RPC Map (NFS connectivity, redundant on modern VPS structures)"
        ["rpc-statd"]="NFS status query protocol"
        ["nfs-server"]="Network File Sharing (NFS) Daemon"
        ["nfs-kernel-server"]="Kernel NFS file daemon"
        ["cups"]="CUPS (common UNIX printing system - completely useless on cloud servers)"
        ["avahi-daemon"]="mDNS resolution discovery daemon"
        ["bluetooth"]="Bluetooth wireless daemon stack"
        ["apache2"]="Apache Web Server engine"
        ["nginx"]="Nginx proxy engine"
        ["postfix"]="Postfix Mail Agent"
        ["exim4"]="Exim Mail Agent"
        ["dovecot"]="Dovecot IMAP stack"
        ["mysql"]="MySQL Database service"
        ["mariadb"]="MariaDB Database service"
        ["postgresql"]="PostgreSQL Database service"
        ["redis-server"]="Redis key cache store"
        ["memcached"]="Memcached cache daemon"
        ["mongodb"]="MongoDB document database"
        ["snapd"]="Canonical Snap application layer daemon"
        ["multipathd"]="Multipath IO device daemon mapper"
        ["lvm2-lvmpolld"]="LVM polling service daemon"
        ["rsync"]="Rsync server daemon"
        ["telnetd"]="Telnet server daemon (Unencrypted, highly INSECURE)"
        ["vsftpd"]="vsftpd FTP transfer daemon"
        ["proftpd"]="ProFTPD transfer daemon"
        ["named"]="BIND DNS routing daemon"
        ["dnsmasq"]="dnsmasq routing layer daemon"
        ["docker"]="Docker application container engine"
        ["containerd"]="containerd isolated executor daemon"
        ["libvirtd"]="libvirt management service daemon"
        ["qemu-kvm"]="QEMU execution layer daemon"
        ["smbd"]="Samba network file share engine"
        ["nmbd"]="Samba NetBIOS routing daemon"
        ["atd"]="At job scheduler service"
        ["rsyslog"]="rsyslog system log capture daemon"
        ["systemd-journal-remote"]="systemd log remote ingestion daemon"
        ["systemd-journal-upload"]="systemd log remote uploading daemon"
    )
    
    local sorted_list
    sorted_list=($(echo "${!system_daemons[@]}" | tr ' ' '\n' | sort))
    
    print_subsection "Daemon Services Verification"
    print_warning "Only turn off services you are positive are redundant."
    print_critical "Disabling core elements (such as docker or database backends) will halt applications!"
    echo ""
    
    local deactivated_ctr=0
    local d_unit
    for d_unit in "${sorted_list[@]}"; do
        local desc="${system_daemons[$d_unit]}"
        
        if systemctl list-unit-files "${d_unit}.service" &>/dev/null 2>&1; then
            local state
            state=$(systemctl is-enabled "$d_unit" 2>/dev/null || echo "not-found")
            local active
            active=$(systemctl is-active "$d_unit" 2>/dev/null || echo "inactive")
            
            if [ "$state" != "not-found" ] && [ "$state" != "masked" ]; then
                local st_col="${GREEN}"
                [ "$active" = "active" ] && st_col="${RED}"
                
                echo -e "  ${st_col}[${active}]${NC} ${BOLD}${d_unit}${NC} - ${desc}"
                
                if confirm "Disable and mask ${d_unit}?" "n"; then
                    systemctl stop "$d_unit" 2>>"$LOG_FILE" || true
                    systemctl disable "$d_unit" 2>>"$LOG_FILE" || true
                    systemctl mask "$d_unit" 2>>"$LOG_FILE" || true
                    print_status "Deactivated and masked service: ${d_unit}"
                    ((deactivated_ctr++))
                fi
            fi
        fi
    done
    
    # Secure journald listening sockets
    print_subsection "Deactivating Vulnerable Systemd sockets"
    local sockets_to_mask=(
        "systemd-journal-remote.socket"
        "systemd-journal-upload.socket"
        "systemd-journal-gatewayd.socket"
    )
    
    local d_sock
    for d_sock in "${sockets_to_mask[@]}"; do
        if systemctl list-unit-files "$d_sock" &>/dev/null 2>&1; then
            local sock_state
            sock_state=$(systemctl is-enabled "$d_sock" 2>/dev/null || echo "not-found")
            if [ "$sock_state" != "not-found" ] && [ "$sock_state" != "masked" ]; then
                if confirm "Disable and mask ${d_sock}?" "n"; then
                    systemctl stop "$d_sock" 2>/dev/null || true
                    systemctl mask "$d_sock" 2>/dev/null || true
                    print_status "Deactivated socket interface: ${d_sock}"
                    ((deactivated_ctr++))
                fi
            fi
        fi
    done
    
    print_status "System daemon processing completed. ${deactivated_ctr} elements disabled."
    mark_completed "disable_unnecessary_services"
}

# ----------------------------------------------------------------------------
# Function: restrict_cron_at
# Purpose: Lock scheduled execution engines to restricted users only
# ----------------------------------------------------------------------------
restrict_cron_at() {
    start_task_timer
    print_section "RESTRICT CRON & AT ACCESS"
    
    print_info "Scheduled scripts are common persistence locations for intruders."
    print_info "Isolating access to administrators protects system scheduling."
    echo ""
    
    print_subsection "Cron access validation configuration"
    local cron_users_input=""
    prompt_input "Identify users allowed to execute cron jobs (comma-separated list)" "root" cron_users_input
    
    rm -f /etc/cron.deny
    : > /etc/cron.allow
    
    IFS=',' read -ra PROCESSED_USERS <<< "$cron_users_input"
    local usr
    for usr in "${PROCESSED_USERS[@]}"; do
        usr=$(echo "$usr" | xargs)
        if [ -n "$usr" ]; then
            if id "$usr" &>/dev/null; then
                echo "$usr" >> /etc/cron.allow
                print_status "Schedule authorization registered: ${usr}"
            else
                print_warning "Identified target user [${usr}] does not exist on this OS host"
            fi
        fi
    done
    chmod 640 /etc/cron.allow
    chown root:root /etc/cron.allow
    print_status "Cron scheduling restricted: /etc/cron.allow configured"
    
    # Directory lockdown
    print_subsection "Scheduled Paths Hardening"
    local system_cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
    local sc_dir
    for sc_dir in "${system_cron_dirs[@]}"; do
        if [ -d "$sc_dir" ]; then
            chmod 700 "$sc_dir" 2>/dev/null || true
            chown root:root "$sc_dir" 2>/dev/null || true
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
    print_status "Cron system file permissions locked down (700/600)"
    
    # Lock AT scheduler
    print_subsection "At Scheduler Lockdown"
    if command_exists at; then
        if confirm "Purge at daemon scheduler entirely from system?" "y"; then
            apt-get purge -y at >> "$LOG_FILE" 2>&1
            print_status "at system scheduler completely purged"
        else
            rm -f /etc/at.deny
            : > /etc/at.allow
            echo "root" >> /etc/at.allow
            chmod 640 /etc/at.allow
            chown root:root /etc/at.allow
            print_status "at scheduler isolated exclusively to root user"
        fi
    fi
    
    mark_completed "restrict_cron_at"
}

# End of Section 5
# ============================================================================
# TIER 2 CONTINUED: ENCRYPTED DNS, PAM LOGIN QUALITY & ACCOUNT ISOLATION
# ============================================================================

# ----------------------------------------------------------------------------
# Function: setup_dns_over_tls
# Purpose: Configure DNS over TLS (DoT) to prevent DNS spoofing and snooping
# ----------------------------------------------------------------------------
setup_dns_over_tls() {
    start_task_timer
    print_section "DNS OVER TLS (ENCRYPTED DNS)"
    
    print_info "Standard DNS queries are sent in plaintext, allowing ISPs,"
    print_info "network eavesdroppers, and attackers to monitor or spoof nameserver lookups."
    print_info "DNS over TLS (DoT) encrypts all requests using TLS on port 853."
    echo ""
    
    print_subsection "Analyze Current DNS Resolvers"
    if [ -f /etc/resolv.conf ]; then
        print_info "Active nameservers in /etc/resolv.conf:"
        grep "^nameserver" /etc/resolv.conf | while IFS= read -r line; do
            echo -e "    ${GRAY}• ${line}${NC}"
        done
    else
        print_warning "/etc/resolv.conf was not found"
    fi
    echo ""
    
    # Ensure systemd-resolved is installed
    if ! service_exists "systemd-resolved"; then
        print_step "Installing systemd-resolved package..."
        if apt-get install -y systemd-resolved >> "$LOG_FILE" 2>&1; then
            print_status "systemd-resolved installed successfully"
        else
            print_error "Failed to install systemd-resolved"
            mark_failed "setup_dns_over_tls" "Apt installation failed"
            return 1
        fi
    else
        print_info "systemd-resolved is already available"
    fi
    
    backup_file /etc/systemd/resolved.conf "pre-DoT-hardening"
    
    print_subsection "Encrypted Nameserver Provider Selection"
    local dns_choice=""
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Select DNS over TLS provider:"
    echo -e "      ${CYAN}1)${NC} Cloudflare (1.1.1.1 / 1.0.0.1) - Fast, privacy-focused"
    echo -e "      ${CYAN}2)${NC} Quad9 (9.9.9.9 / 149.112.112.112) - Security-focused (malware blocking)"
    echo -e "      ${CYAN}3)${NC} Google (8.8.8.8 / 8.8.4.4) - Fast and reliable"
    echo -e "      ${CYAN}4)${NC} Cloudflare + Quad9 (Recommended - provides speed & security redundancy)"
    echo -e "      ${CYAN}5)${NC} Custom DoT Providers"
    echo ""
    prompt_input "Choose resolver profile" "4" dns_choice
    
    local dns_servers="" fallback_dns=""
    
    case "$dns_choice" in
        1)
            dns_servers="1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 2606:4700:4700::1111#cloudflare-dns.com 2606:4700:4700::1001#cloudflare-dns.com"
            fallback_dns="9.9.9.9#dns.quad9.net"
            ;;
        2)
            dns_servers="9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net 2620:fe::fe#dns.quad9.net 2620:fe::9#dns.quad9.net"
            fallback_dns="1.1.1.1#cloudflare-dns.com"
            ;;
        3)
            dns_servers="8.8.8.8#dns.google 8.8.4.4#dns.google 2001:4860:4860::8888#dns.google 2001:4860:4860::8844#dns.google"
            fallback_dns="1.1.1.1#cloudflare-dns.com"
            ;;
        4)
            dns_servers="1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net 2606:4700:4700::1111#cloudflare-dns.com 2620:fe::fe#dns.quad9.net"
            fallback_dns="1.0.0.1#cloudflare-dns.com 149.112.112.112#dns.quad9.net"
            ;;
        5)
            print_info "Format: IP#hostname (e.g. 1.1.1.1#cloudflare-dns.com)"
            prompt_input "Enter custom primary DNS server(s)" "" dns_servers
            prompt_input "Enter custom fallback DNS server(s)" "" fallback_dns
            ;;
        *)
            dns_servers="1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net 2606:4700:4700::1111#cloudflare-dns.com 2620:fe::fe#dns.quad9.net"
            fallback_dns="1.0.0.1#cloudflare-dns.com 149.112.112.112#dns.quad9.net"
            ;;
    esac
    
    print_subsection "Deploying Resolver Configuration"
    print_step "Writing network profile parameters..."
    
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
    chown root:root /etc/systemd/resolved.conf
    print_status "Configuration saved: /etc/systemd/resolved.conf"
    
    # Reload and activate resolver
    print_step "Restarting systemd-resolved..."
    systemctl daemon-reload
    systemctl enable systemd-resolved >> "$LOG_FILE" 2>&1
    
    if systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1; then
        print_status "systemd-resolved resolver is active and listening"
    else
        print_error "Failed to activate systemd-resolved"
        mark_failed "setup_dns_over_tls" "Service failed to start"
        return 1
    fi
    
    # Link resolv.conf to systemd stub listener
    print_subsection "Resolv.conf System Integration"
    local current_symlink=""
    if [ -L /etc/resolv.conf ]; then
        current_symlink=$(readlink /etc/resolv.conf)
    fi
    
    if [ "$current_symlink" != "/run/systemd/resolve/stub-resolv.conf" ]; then
        print_warning "Your /etc/resolv.conf is not managed by systemd-resolved"
        if confirm "Link /etc/resolv.conf to the local systemd-resolved stub? (Highly Recommended)" "y"; then
            backup_file /etc/resolv.conf "pre-resolved-symlink"
            rm -f /etc/resolv.conf
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            print_status "/etc/resolv.conf successfully linked to systemd-resolved stub resolver"
        else
            print_warning "Resolv.conf was not linked. DNS over TLS may not work for all system libraries."
        fi
    else
        print_status "/etc/resolv.conf is correctly linked to the local stub resolver"
    fi
    
    # Verify resolution is working
    print_subsection "DNS over TLS Resolution Verification"
    sleep 2
    
    if resolvectl query google.com >> "$LOG_FILE" 2>&1; then
        print_status "DNS queries are resolving successfully ✔"
        
        # Display DoT parameter status
        local dot_state
        dot_state=$(resolvectl status 2>/dev/null | grep -i "DNS over TLS" | awk '{print $NF}' | head -1 || echo "unknown")
        print_info "DoT Runtime Engine status: ${dot_state}"
    else
        print_error "DNS query resolution test failed. Checking fallback methods..."
        # Restore backup if resolution broke and user confirmed linking
        if [ "$current_symlink" != "/run/systemd/resolve/stub-resolv.conf" ] && [ -f "${BACKUP_DIR}/etc/resolv.conf" ]; then
            print_step "Reverting resolv.conf to original configuration..."
            rm -f /etc/resolv.conf
            cp -p "${BACKUP_DIR}/etc/resolv.conf" /etc/resolv.conf
            print_status "resolv.conf configuration reverted"
        fi
        mark_failed "setup_dns_over_tls" "Resolution test failed"
        return 1
    fi
    
    mark_completed "setup_dns_over_tls"
}

# ----------------------------------------------------------------------------
# Function: setup_login_security
# Purpose: Configure password strength requirements, PAM limits, and timeouts
# ----------------------------------------------------------------------------
setup_login_security() {
    start_task_timer
    print_section "LOGIN & PASSWORD SECURITY"
    
    # ---- Password Strength (pam_pwquality) ----
    print_subsection "Password Quality Requirements"
    if confirm "Install and configure advanced password complexity enforcement?" "y"; then
        if ! package_installed "libpam-pwquality"; then
            print_step "Installing libpam-pwquality library..."
            if apt-get install -y libpam-pwquality >> "$LOG_FILE" 2>&1; then
                print_status "libpam-pwquality successfully installed"
            else
                print_error "Failed to install libpam-pwquality"
            fi
        else
            print_info "libpam-pwquality library is already present"
        fi
        
        if package_installed "libpam-pwquality"; then
            backup_file /etc/security/pwquality.conf "pre-pwquality-hardening"
            
            local min_len="" min_class=""
            prompt_input "Set minimum password length (characters)" "14" min_len
            prompt_input "Set minimum character classes required (1-4)" "3" min_class
            
            cat > /etc/security/pwquality.conf << EOF
# ============================================================
# VPS Hardening - Password Quality Rules
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# Enforce minimum characters length
minlen = ${min_len}

# Enforce character classes (upper, lower, digit, special)
minclass = ${min_class}

# Maximum consecutive identical characters
maxrepeat = 3

# Maximum consecutive characters of the same class
maxclassrepeat = 4

# Reject passwords containing the username
reject_username

# Enforce strength requirements for root as well
enforce_for_root

# Characters that must differ from old password
difok = 4

# Reject passwords that are plain palindromes
palindrome

# Enable dictionary checks
dictcheck = 1
EOF
            chmod 644 /etc/security/pwquality.conf
            chown root:root /etc/security/pwquality.conf
            print_status "Password quality parameters applied: /etc/security/pwquality.conf"
        fi
    fi
    
    # ---- PAM Login Delay ----
    print_subsection "Authentication Delay (Anti-Brute-Force)"
    if confirm "Enforce systematic authentication delay after login failures?" "y"; then
        local delay_sec=""
        prompt_input "Set authentication delay (seconds)" "4" delay_sec
        local delay_micro=$(( delay_sec * 1000000 ))
        
        backup_file /etc/pam.d/common-auth "pre-pam-delay"
        
        if ! grep -q "pam_faildelay.so" /etc/pam.d/common-auth 2>/dev/null; then
            print_step "Injecting pam_faildelay.so rule into /etc/pam.d/common-auth..."
            sed -i "1i auth optional pam_faildelay.so delay=${delay_micro}" /etc/pam.d/common-auth
            print_status "систем delay of ${delay_sec}s applied to PAM authentication loops"
        else
            print_step "Updating existing pam_faildelay.so configuration..."
            sed -i "s/pam_faildelay.so delay=[0-9]*/pam_faildelay.so delay=${delay_micro}/" /etc/pam.d/common-auth
            print_status "PAM auth delay updated to ${delay_sec}s"
        fi
    fi
    
    # ---- Idle Shell Timeout ----
    print_subsection "Interactive Shell Inactivity Timeout"
    local timeout_val=""
    prompt_input "Set inactive session auto-logout (seconds, 0 to skip)" "900" timeout_val
    
    if [ -n "$timeout_val" ] && [ "$timeout_val" -ne 0 ]; then
        print_step "Deploying profile timeout rules..."
        cat > /etc/profile.d/99-vps-timeout.sh << EOF
# ============================================================
# VPS Hardening - Shell Session Timeout Profile
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

# Auto-logout shell sessions after ${timeout_val} seconds of inactivity
TMOUT=${timeout_val}
readonly TMOUT
export TMOUT
EOF
        chmod 644 /etc/profile.d/99-vps-timeout.sh
        chown root:root /etc/profile.d/99-vps-timeout.sh
        print_status "Shell auto-logout set to ${timeout_val}s ($(( timeout_val / 60 )) minutes)"
    fi
    
    # ---- Password Expiry Policies (login.defs) ----
    print_subsection "Account Expiry & Aging Policies"
    backup_file /etc/login.defs "pre-login-defs-hardening"
    
    if confirm "Apply restrictive password aging parameters?" "y"; then
        local max_days="" min_days="" warn_days=""
        prompt_input "Maximum password validity (days)" "90" max_days
        prompt_input "Minimum days between password changes" "1" min_days
        prompt_input "Password expiration warning window (days)" "14" warn_days
        
        sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   ${max_days}/" /etc/login.defs
        sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   ${min_days}/" /etc/login.defs
        sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE   ${warn_days}/" /etc/login.defs
        
        print_status "Password age constraints written to /etc/login.defs"
        print_info "Note: Aging policies will apply only to newly created accounts."
        print_info "To apply to existing users, use: chage -M ${max_days} -m ${min_days} -W ${warn_days} <user>"
    fi
    
    # ---- Bash History Hardening ----
    print_subsection "Secure Shell History Configuration"
    if confirm "Harden Bash command history logging?" "y"; then
        cat > /etc/profile.d/99-vps-history.sh << 'EOF'
# ============================================================
# VPS Hardening - Hardened History Tracing Profile
# ============================================================

# Set expanded log boundary sizes
HISTSIZE=10000
HISTFILESIZE=20000

# Prevent duplicate lines and simple white-space command bypasses
HISTCONTROL=ignoredups:erasedups:ignorespace

# Record chronological timestamps
HISTTIMEFORMAT="%F %T "

# Force real-time appending instead of buffer overwriting on logout
shopt -s histappend
PROMPT_COMMAND="history -a; history -c; history -r; $PROMPT_COMMAND"

# Block manual execution log tampering
readonly HISTFILE
EOF
        chmod 644 /etc/profile.d/99-vps-history.sh
        chown root:root /etc/profile.d/99-vps-history.sh
        print_status "Secure Shell history profile deployed"
    fi
    
    mark_completed "setup_login_security"
}

# ----------------------------------------------------------------------------
# Function: setup_user_hardening
# Purpose: Lock unused default accounts, harden default system umask, secure homes
# ----------------------------------------------------------------------------
setup_user_hardening() {
    start_task_timer
    print_section "USER ACCOUNT HARDENING"
    
    # ---- Lock Unused System Accounts ----
    print_subsection "Lock Unused Default Accounts"
    if confirm "Lock default system shell accounts that do not run services?" "y"; then
        local accounts_to_lock=(
            "daemon" "bin" "sys" "games" "man" "lp"
            "mail" "news" "uucp" "proxy" "www-data"
            "backup" "list" "irc" "gnats" "nobody"
            "systemd-network" "systemd-resolve" "messagebus"
            "syslog" "uuidd" "tcpdump" "pollinate"
        )
        
        local locked_count=0
        local acct
        for acct in "${accounts_to_lock[@]}"; do
            if id "$acct" &>/dev/null; then
                # Prevent locking critical management targets
                if [ "$acct" != "$TARGET_USER" ] && [ "$acct" != "root" ]; then
                    usermod -L "$acct" 2>>"$LOG_FILE" || true
                    usermod -s /usr/sbin/nologin "$acct" 2>>"$LOG_FILE" || true
                    ((locked_count++))
                    print_debug "Locked account: ${acct}"
                fi
            fi
        done
        print_status "Locked ${locked_count} unused system shell accounts"
    fi
    
    # ---- Default System Umask ----
    print_subsection "Enforce Restrictive System-Wide Umask"
    local umask_choice=""
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Select default system umask:"
    echo -e "      ${CYAN}1)${NC} 022 - Default (Owner: RWX, Group: R, Others: R)"
    echo -e "      ${CYAN}2)${NC} 027 - Restrictive (Owner: RWX, Group: R, Others: None) [Recommended]"
    echo -e "      ${CYAN}3)${NC} 077 - Strict (Owner: RWX, Group: None, Others: None)"
    echo ""
    prompt_input "Select umask option" "2" umask_choice
    
    local umask_val=""
    case "$umask_choice" in
        1) umask_val="022" ;;
        2) umask_val="027" ;;
        3) umask_val="077" ;;
        *) umask_val="027" ;;
    esac
    
    backup_file /etc/login.defs "pre-umask-hardening"
    sed -i "s/^UMASK.*/UMASK           ${umask_val}/" /etc/login.defs
    
    # Deploy profile drop-in to override shell environments
    cat > /etc/profile.d/99-vps-umask.sh << EOF
# VPS Hardening - Default system umask override
umask ${umask_val}
EOF
    chmod 644 /etc/profile.d/99-vps-umask.sh
    chown root:root /etc/profile.d/99-vps-umask.sh
    print_status "Default system umask set to ${umask_val} system-wide"
    
    # ---- Secure Home Directories ----
    print_subsection "Hardening Home Directories Permissions"
    if confirm "Enforce restrictive permissions (750) on user home directories?" "y"; then
        local user_name user_uid user_home user_shell
        while IFS=: read -r user_name _ user_uid _ _ user_home user_shell; do
            if [ "$user_uid" -ge 1000 ] && [ "$user_uid" -lt 65534 ] && [ -d "$user_home" ]; then
                # Only touch human/interactive users
                if [ "$user_shell" != "/usr/sbin/nologin" ] && [ "$user_shell" != "/bin/false" ]; then
                    chmod 750 "$user_home" 2>/dev/null || true
                    print_status "Permissions locked: ${user_home} (Mode: 750)"
                fi
            fi
        done < /etc/passwd
        
        # Update useradd skeleton behavior
        backup_file /etc/adduser.conf "pre-adduser-home-hardening"
        if [ -f /etc/adduser.conf ]; then
            sed -i 's/^DIR_MODE=.*/DIR_MODE=0750/' /etc/adduser.conf
            print_status "Default directory mode for future new home creations set to 0750"
        fi
    fi
    
    # ---- Inactive Lock Limits ----
    print_subsection "Configure Default Inactive Account Lock policies"
    if confirm "Configure automatic account locking for inactive users?" "y"; then
        backup_file /etc/default/useradd "pre-inactivity-hardening"
        if [ -f /etc/default/useradd ]; then
            if grep -q "^INACTIVE=" /etc/default/useradd; then
                sed -i 's/^INACTIVE=.*/INACTIVE=30/' /etc/default/useradd
            else
                echo "INACTIVE=30" >> /etc/default/useradd
            fi
            print_status "System accounts configured to lock after 30 days of persistent inactivity"
        fi
    fi
    
    # ---- Secure TTY access ----
    print_subsection "Restrict Root logins via secure TTY definition maps"
    if confirm "Restrict root shell logins strictly to physical system consoles?" "y"; then
        backup_file /etc/securetty "pre-securetty-lockdown"
        cat > /etc/securetty << 'EOF'
# ============================================================
# VPS Hardening - Secure TTY console map
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================
console
tty1
tty2
EOF
        chmod 600 /etc/securetty
        chown root:root /etc/securetty
        print_status "Console securetty mapping isolated"
    fi
    
    mark_completed "setup_user_hardening"
}

# End of Section 6
# ============================================================================
# TIER 2 CONTINUED: SECURITY AUDITING, LOG FORWARDING, KERNEL LOCKDOWN
# ============================================================================

# ----------------------------------------------------------------------------
# Function: install_lynis
# Purpose: Install Lynis CIS benchmark auditing tool with automated scheduling
# ----------------------------------------------------------------------------
install_lynis() {
    start_task_timer
    print_section "SECURITY AUDITING (LYNIS)"
    
    print_info "Lynis is an open-source security auditing tool that performs"
    print_info "comprehensive CIS-benchmark-based scans across hundreds of controls."
    print_info "It evaluates SSH, firewall, kernel, file permissions, malware, and more."
    echo ""
    
    # Install Lynis
    if ! command_exists lynis; then
        print_step "Installing Lynis auditing framework..."
        if apt-get install -y lynis >> "$LOG_FILE" 2>&1; then
            print_status "Lynis framework deployed successfully"
        else
            print_error "Failed to install Lynis"
            mark_failed "install_lynis" "Apt installation failed"
            return 1
        fi
    else
        print_info "Lynis is already installed"
        local lynis_version
        lynis_version=$(lynis --version 2>/dev/null | head -1 || echo "unknown")
        print_info "Current version: ${lynis_version}"
    fi
    
    # Run initial audit
    print_subsection "Initial CIS Benchmark Audit"
    if confirm "Run a quick Lynis security audit now? (takes 2-5 minutes)"; then
        print_step "Executing Lynis quick audit scan..."
        print_info "This scans SSH, kernel, firewall, users, file permissions, and more."
        echo ""
        
        local audit_output
        audit_output=$(lynis audit system --quick --no-colors 2>&1) || true
        
        # Extract key metrics from output
        local hardening_index
        hardening_index=$(echo "$audit_output" | grep -i "Hardening index" | grep -oP '\d+' | head -1 || echo "N/A")
        
        local warnings_count
        warnings_count=$(echo "$audit_output" | grep -i "Warnings" | grep -oP '\d+' | head -1 || echo "N/A")
        
        local suggestions_count
        suggestions_count=$(echo "$audit_output" | grep -i "Suggestions" | grep -oP '\d+' | head -1 || echo "N/A")
        
        local tests_executed
        tests_executed=$(echo "$audit_output" | grep -i "Tests executed" | grep -oP '\d+' | head -1 || echo "N/A")
        
        echo ""
        print_double_separator
        echo -e "  ${BOLD}Lynis Audit Summary:${NC}"
        echo -e "    Hardening Index:  ${CYAN}${hardening_index}/100${NC}"
        echo -e "    Tests Executed:   ${WHITE}${tests_executed}${NC}"
        echo -e "    Warnings:         ${YELLOW}${warnings_count}${NC}"
        echo -e "    Suggestions:      ${MAGENTA}${suggestions_count}${NC}"
        print_double_separator
        
        # Save full report
        local report_path="/root/lynis-initial-audit-${TIMESTAMP}.txt"
        echo "$audit_output" > "$report_path"
        chmod 600 "$report_path"
        print_status "Full audit report saved: ${report_path}"
        
        # Send Telegram notification if configured
        if [ -f /etc/vps-hardening/telegram.conf ]; then
            source /etc/vps-hardening/telegram.conf
            local tg_msg="📊 <b>Lynis Audit Complete</b>%0A%0A"
            tg_msg+="🖥 Host: <code>${TELEGRAM_HOSTNAME}</code>%0A"
            tg_msg+="📈 Hardening: <code>${hardening_index}/100</code>%0A"
            tg_msg+="⚠️ Warnings: <code>${warnings_count}</code>%0A"
            tg_msg+="💡 Suggestions: <code>${suggestions_count}</code>"
            curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
                -d "chat_id=${TELEGRAM_CHAT_ID}" -d "text=${tg_msg}" \
                -d "parse_mode=HTML" > /dev/null 2>&1
            print_info "Audit results sent to Telegram"
        fi
    fi
    
    # Schedule automated weekly audits
    print_subsection "Automated Weekly Audit Scheduling"
    if confirm "Schedule weekly automated Lynis security audits?"; then
        cat > /etc/cron.weekly/lynis-security-audit << 'CRONEOF'
#!/bin/bash
# ============================================================
# VPS Hardening - Weekly Lynis Security Audit
# ============================================================

REPORT_DIR="/var/log/lynis"
mkdir -p "$REPORT_DIR"
chmod 700 "$REPORT_DIR"

DATE=$(date +%Y%m%d)
REPORT_FILE="${REPORT_DIR}/lynis-report-${DATE}.txt"
LOG_OUTPUT="${REPORT_DIR}/lynis-log-${DATE}.log"

# Execute full system audit
/usr/bin/lynis audit system --cronjob --report-file "$REPORT_FILE" > "$LOG_OUTPUT" 2>&1

# Extract hardening index
HARDENING=$(grep -i "Hardening index" "$REPORT_FILE" 2>/dev/null | grep -oP '\d+' | head -1)
WARNINGS=$(grep -i "Warnings" "$REPORT_FILE" 2>/dev/null | grep -oP '\d+' | head -1)

# Log to syslog
logger -t lynis-audit -p auth.info "Weekly audit complete. Index: ${HARDENING:-unknown}/100, Warnings: ${WARNINGS:-0}"

# Alert if hardening index drops below threshold
THRESHOLD=65
if [ -n "$HARDENING" ] && [ "$HARDENING" -lt "$THRESHOLD" ]; then
    logger -t lynis-audit -p auth.warning "ALERT: Hardening index ${HARDENING} dropped below threshold ${THRESHOLD}!"
    
    # Send Telegram alert if configured
    if [ -f /etc/vps-hardening/telegram.conf ]; then
        source /etc/vps-hardening/telegram.conf
        MSG="⚠️ <b>Lynis Security Alert</b>%0A%0AHardening index dropped to <code>${HARDENING}/100</code> on <code>${TELEGRAM_HOSTNAME}</code>%0A%0AReview: <code>cat ${REPORT_FILE}</code>"
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_CHAT_ID}" -d "text=${MSG}" \
            -d "parse_mode=HTML" > /dev/null 2>&1
    fi
fi

# Clean old reports (keep 12 weeks)
find "$REPORT_DIR" -name "lynis-*" -mtime +84 -delete 2>/dev/null

exit 0
CRONEOF
        
        chmod 755 /etc/cron.weekly/lynis-security-audit
        chown root:root /etc/cron.weekly/lynis-security-audit
        mkdir -p /var/log/lynis
        chmod 700 /var/log/lynis
        print_status "Weekly Lynis audit scheduled with Telegram alert integration"
    fi
    
    echo ""
    print_info "Useful Lynis commands:"
    echo -e "    ${CYAN}lynis audit system${NC}             # Full interactive audit"
    echo -e "    ${CYAN}lynis audit system --quick${NC}     # Quick audit scan"
    echo -e "    ${CYAN}lynis show details${NC}             # Show detailed test results"
    echo -e "    ${CYAN}lynis show groups${NC}              # List all test groups"
    echo -e "    ${CYAN}cat /var/log/lynis/*.txt${NC}       # View saved reports"
    
    mark_completed "install_lynis"
}

# ----------------------------------------------------------------------------
# Function: setup_log_forwarding
# Purpose: Configure remote log forwarding for anti-tampering protection
# ----------------------------------------------------------------------------
setup_log_forwarding() {
    start_task_timer
    print_section "LOG FORWARDING (ANTI-TAMPERING)"
    
    print_info "If an attacker gains root access, their first action is typically"
    print_info "deleting /var/log to erase forensic evidence of the intrusion."
    print_info "Remote log forwarding sends real-time copies to an external server"
    print_info "so evidence survives even if the VPS is fully compromised."
    echo ""
    
    print_subsection "Remote Syslog Server Configuration"
    local remote_server=""
    prompt_input "Enter remote syslog server address (e.g., logs.example.com or 10.0.0.5)" "" remote_server
    
    if [ -z "$remote_server" ]; then
        print_warning "No remote server specified. Skipping log forwarding setup."
        print_info "You can configure this later by re-running this menu option."
        mark_skipped "setup_log_forwarding" "No server specified"
        return 0
    fi
    
    local remote_port=""
    prompt_input "Enter remote syslog port" "514" remote_port
    
    local remote_proto=""
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Select transport protocol:"
    echo -e "      ${CYAN}1)${NC} TCP (reliable delivery, recommended)"
    echo -e "      ${CYAN}2)${NC} UDP (faster, may lose packets under load)"
    echo -e "      ${CYAN}3)${NC} TLS (encrypted transport, requires certificates)"
    echo ""
    prompt_input "Choose protocol" "1" remote_proto
    
    # Install rsyslog if needed
    if ! command_exists rsyslogd; then
        print_step "Installing rsyslog..."
        apt-get install -y rsyslog >> "$LOG_FILE" 2>&1
    fi
    
    backup_directory /etc/rsyslog.d "pre-log-forwarding"
    
    print_subsection "Deploying Forwarding Configuration"
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
            print_step "Installing TLS support for rsyslog..."
            apt-get install -y rsyslog-gnutls >> "$LOG_FILE" 2>&1
            
            cat > /etc/rsyslog.d/10-tls.conf << 'EOF'
# VPS Hardening - TLS Configuration for Remote Logging
global(
    DefaultNetstreamDriver="gtls"
    DefaultNetstreamDriverCAFile="/etc/ssl/certs/ca-certificates.crt"
)
EOF
            chmod 640 /etc/rsyslog.d/10-tls.conf
            print_status "TLS transport support configured"
            ;;
    esac
    
    cat > /etc/rsyslog.d/50-remote-forwarding.conf << EOF
# ============================================================
# VPS Hardening - Remote Log Forwarding Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Target: ${remote_server}:${remote_port} (${proto_label})
# ============================================================

# Forward all log messages to remote server
*.* ${proto_prefix}${remote_server}:${remote_port}

# Optional: Forward only specific high-priority facilities
# auth,authpriv.*    ${proto_prefix}${remote_server}:${remote_port}
# kern.*             ${proto_prefix}${remote_server}:${remote_port}
# *.emerg            ${proto_prefix}${remote_server}:${remote_port}
EOF
    
    chmod 640 /etc/rsyslog.d/50-remote-forwarding.conf
    chown root:adm /etc/rsyslog.d/50-remote-forwarding.conf 2>/dev/null || true
    
    # Validate and restart rsyslog
    print_step "Validating rsyslog configuration..."
    if rsyslogd -N1 >> "$LOG_FILE" 2>&1; then
        print_status "Configuration syntax is valid"
        systemctl restart rsyslog >> "$LOG_FILE" 2>&1
        print_status "Log forwarding active: ${remote_server}:${remote_port} (${proto_label})"
    else
        print_error "Rsyslog configuration validation failed"
        print_info "Check syntax with: rsyslogd -N1"
        mark_failed "setup_log_forwarding" "Config validation failed"
        return 1
    fi
    
    # Local log protection
    print_subsection "Local Log File Protection"
    if confirm "Make critical log files append-only with chattr? (prevents deletion even by root)"; then
        local protected_logs=(
            "/var/log/auth.log"
            "/var/log/syslog"
            "/var/log/kern.log"
            "/var/log/fail2ban.log"
            "/var/log/audit/audit.log"
        )
        
        local log_file
        for log_file in "${protected_logs[@]}"; do
            if [ -f "$log_file" ]; then
                if chattr +a "$log_file" 2>>"$LOG_FILE"; then
                    print_status "Append-only protection: ${log_file}"
                else
                    print_warning "Failed to set append-only on ${log_file}"
                fi
            fi
        done
        
        echo ""
        print_warning "Append-only logs may interfere with logrotate."
        print_info "To temporarily remove: chattr -a /var/log/auth.log"
        print_info "To re-apply: chattr +a /var/log/auth.log"
    fi
    
    echo ""
    print_info "Verify forwarding: logger 'test message from VPS hardening' && check remote server"
    print_info "Config file: /etc/rsyslog.d/50-remote-forwarding.conf"
    
    mark_completed "setup_log_forwarding"
}

# ----------------------------------------------------------------------------
# Function: setup_kernel_lockdown
# Purpose: Enable kernel lockdown mode and module signing enforcement
# ----------------------------------------------------------------------------
setup_kernel_lockdown() {
    start_task_timer
    print_section "KERNEL LOCKDOWN & MODULE RESTRICTIONS"
    
    print_warning_box "Kernel lockdown restricts even root from accessing raw memory, loading unsigned modules, and modifying kernel code. This may break monitoring tools, custom kernel modules, or hibernation."
    echo ""
    
    # Check current lockdown status
    print_subsection "Current Kernel Security Status"
    if [ -f /sys/kernel/security/lockdown ]; then
        local current_lockdown
        current_lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "unknown")
        print_info "Current lockdown mode: ${current_lockdown}"
    else
        print_info "Kernel lockdown interface not available (may require newer kernel or Secure Boot)"
    fi
    
    print_info "Kernel version: ${KERNEL_VERSION}"
    print_info "Secure Boot: $(mokutil --sb-state 2>/dev/null || echo 'unknown/not available')"
    echo ""
    
    # Lockdown mode selection
    print_subsection "Kernel Lockdown Mode Selection"
    echo -e "  ${MAGENTA}${BOLD}[?]${NC} Select lockdown enforcement mode:"
    echo -e "      ${CYAN}1)${NC} None - No lockdown (current default)"
    echo -e "      ${CYAN}2)${NC} Integrity - Prevent kernel code modification (recommended)"
    echo -e "      ${CYAN}3)${NC} Confidentiality - Prevent kernel data extraction (strictest)"
    echo ""
    
    local lockdown_choice=""
    prompt_input "Choose lockdown mode" "2" lockdown_choice
    
    local lockdown_mode=""
    case "$lockdown_choice" in
        1) lockdown_mode="" ;;
        2) lockdown_mode="integrity" ;;
        3) lockdown_mode="confidentiality" ;;
        *) lockdown_mode="integrity" ;;
    esac
    
    if [ -n "$lockdown_mode" ]; then
        backup_file /etc/default/grub "pre-lockdown-grub"
        
        if grep -q "lockdown=" /etc/default/grub; then
            sed -i "s/lockdown=[a-z]*/lockdown=${lockdown_mode}/" /etc/default/grub
        else
            sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"\(.*\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 lockdown=${lockdown_mode}\"/" /etc/default/grub
        fi
        
        print_step "Regenerating GRUB boot configuration..."
        if command_exists update-grub; then
            update-grub >> "$LOG_FILE" 2>&1
            print_status "Kernel lockdown '${lockdown_mode}' configured (active after reboot)"
        elif command_exists grub2-mkconfig; then
            grub2-mkconfig -o /boot/grub2/grub.cfg >> "$LOG_FILE" 2>&1
            print_status "Kernel lockdown '${lockdown_mode}' configured (active after reboot)"
        else
            print_warning "No GRUB update command found. Add 'lockdown=${lockdown_mode}' to GRUB_CMDLINE_LINUX_DEFAULT manually."
        fi
    else
        print_info "No lockdown mode selected"
    fi
    
    # Module restrictions
    print_subsection "Kernel Module Loading Restrictions"
    
    if confirm "Prevent loading new kernel modules after boot? (irreversible until reboot)"; then
        print_warning "After reboot, NO new kernel modules can be loaded."
        print_warning "Ensure all required modules (network, disk, filesystem) are built-in or pre-loaded."
        
        if confirm "Are you absolutely sure? This requires console access to reverse."; then
            cat > /etc/sysctl.d/97-module-lock.conf << 'EOF'
# VPS Hardening - Prevent module loading after boot
# WARNING: This is irreversible until reboot
kernel.modules_disabled = 1
EOF
            chmod 644 /etc/sysctl.d/97-module-lock.conf
            print_status "Module loading will be permanently disabled on next boot"
        fi
    fi
    
    if confirm "Enforce kernel module signature verification?"; then
        cat > /etc/modprobe.d/99-module-signing.conf << 'EOF'
# VPS Hardening - Enforce module signature verification
options module.sig_enforce=1
EOF
        chmod 644 /etc/modprobe.d/99-module-signing.conf
        print_status "Module signature enforcement configured"
    fi
    
    # Additional kernel protections
    print_subsection "Additional Kernel Protections"
    
    if confirm "Restrict kernel performance profiling to root only?"; then
        if ! grep -q "perf_event_paranoid" /etc/sysctl.d/99-vps-hardening.conf 2>/dev/null; then
            echo -e "\n# Restrict perf events to root\nkernel.perf_event_paranoid = 3" >> /etc/sysctl.d/99-vps-hardening.conf
            sysctl --system >> "$LOG_FILE" 2>&1 || true
            print_status "Kernel perf profiling restricted to root"
        else
            print_info "Perf event restriction already configured"
        fi
    fi
    
    echo ""
    print_info "Most kernel lockdown features require a reboot to activate"
    print_info "Verify after reboot: cat /sys/kernel/security/lockdown"
    
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
    start_task_timer
    print_section "TAILSCALE VPN (ZERO TRUST NETWORK)"
    
    print_info "Tailscale creates an encrypted WireGuard mesh network between your devices."
    print_info "Once connected, you can remove SSH from the public internet entirely,"
    print_info "making your VPS completely invisible to port scanners and botnets."
    echo ""
    
    # Check if already installed
    if command_exists tailscale; then
        print_info "Tailscale is already installed on this system"
        local ts_status
        ts_status=$(tailscale status 2>/dev/null | head -5 || echo "not connected")
        echo -e "    ${GRAY}${ts_status}${NC}"
        echo ""
    else
        if ! confirm "Install Tailscale VPN?"; then
            mark_skipped "setup_tailscale" "User declined installation"
            return 0
        fi
        
        print_step "Downloading and installing Tailscale..."
        if curl -fsSL https://tailscale.com/install.sh | sh >> "$LOG_FILE" 2>&1; then
            print_status "Tailscale installed successfully"
        else
            print_error "Tailscale installation failed"
            mark_failed "setup_tailscale" "Installation script failed"
            return 1
        fi
    fi
    
    # Authentication
    print_subsection "Tailscale Network Authentication"
    if ! tailscale status &>/dev/null 2>&1; then
        print_step "Starting Tailscale authentication flow..."
        print_info "A URL will appear below. Open it in your browser to authenticate."
        echo ""
        tailscale up 2>&1 || true
        echo ""
    else
        print_info "Tailscale is already authenticated and connected"
    fi
    
    # Network information
    print_subsection "Tailscale Network Information"
    local ts_ip
    ts_ip=$(tailscale ip -4 2>/dev/null || echo "pending...")
    print_info "Tailscale IPv4: ${ts_ip}"
    
    local ts_ip6
    ts_ip6=$(tailscale ip -6 2>/dev/null || echo "N/A")
    print_info "Tailscale IPv6: ${ts_ip6}"
    
    local ts_hostname
    ts_hostname=$(tailscale status 2>/dev/null | head -1 | awk '{print $1}' || echo "unknown")
    print_info "Tailscale hostname: ${ts_hostname}"
    
    # Restrict SSH to Tailscale interface
    print_subsection "SSH Access Restriction"
    if command_exists ufw; then
        if [ -z "$SSH_PORT" ]; then
            SSH_PORT=$(load_state "SSH_PORT")
            SSH_PORT="${SSH_PORT:-2222}"
        fi
        
        print_warning "This will remove public SSH access from the internet."
        print_warning "SSH will ONLY be accessible through the Tailscale network."
        echo ""
        
        if confirm "Restrict SSH to Tailscale interface ONLY?"; then
            # Remove all public SSH rules
            ufw delete allow "${SSH_PORT}/tcp" 2>/dev/null || true
            ufw delete limit "${SSH_PORT}/tcp" 2>/dev/null || true
            
            # Add Tailscale-only rule
            ufw allow in on tailscale0 to any port "${SSH_PORT}" proto tcp \
                comment "SSH via Tailscale only" >> "$LOG_FILE" 2>&1
            
            ufw reload >> "$LOG_FILE" 2>&1
            print_status "SSH restricted to Tailscale interface (tailscale0)"
            
            echo ""
            print_warning_box "SSH is now ONLY accessible via Tailscale!"
            echo -e "  ${BOLD}Connect with:${NC}"
            echo -e "    ${CYAN}ssh -p ${SSH_PORT} ${ts_ip}${NC}"
            echo -e "    ${CYAN}ssh -p ${SSH_PORT} ${ts_hostname}${NC}"
            echo ""
            print_warning "Make sure Tailscale is running on your local machine before disconnecting!"
        fi
    else
        print_warning "UFW not found. Configure iptables manually for Tailscale-only SSH."
    fi
    
    # Optional Tailscale SSH
    print_subsection "Tailscale SSH (Keyless Access)"
    if confirm "Enable Tailscale SSH? (SSH through Tailscale without managing SSH keys)"; then
        tailscale up --ssh >> "$LOG_FILE" 2>&1
        print_status "Tailscale SSH enabled - access via: ssh user@${ts_hostname}"
    fi
    
    # Auto-updates
    if confirm "Enable Tailscale automatic updates?"; then
        tailscale set --auto-update >> "$LOG_FILE" 2>&1 || true
        print_status "Tailscale auto-updates enabled"
    fi
    
    echo ""
    print_info "Useful Tailscale commands:"
    echo -e "    ${CYAN}tailscale status${NC}          # Show network status and peers"
    echo -e "    ${CYAN}tailscale ip${NC}              # Show Tailscale IP addresses"
    echo -e "    ${CYAN}tailscale ping <host>${NC}     # Test connectivity to peer"
    echo -e "    ${CYAN}tailscale down${NC}            # Disconnect from network"
    echo -e "    ${CYAN}tailscale up${NC}              # Reconnect to network"
    
    mark_completed "setup_tailscale"
}

# ----------------------------------------------------------------------------
# Function: setup_fwknop
# Purpose: Configure Single Packet Authorization for invisible SSH
# ----------------------------------------------------------------------------
setup_fwknop() {
    start_task_timer
    print_section "SINGLE PACKET AUTHORIZATION (fwknop)"
    
    print_info "fwknop (FireWall KNock OPerator) implements Single Packet Authorization."
    print_info "Your SSH port stays completely CLOSED and invisible to all scanners."
    print_info "You send one encrypted UDP 'knock' packet to temporarily open the port."
    echo ""
    print_info "Connection workflow:"
    echo -e "    ${GRAY}1. SSH port is BLOCKED in firewall (invisible to nmap)${NC}"
    echo -e "    ${GRAY}2. You send one encrypted knock packet from your device${NC}"
    echo -e "    ${GRAY}3. fwknop opens the port for YOUR IP only (30 seconds)${NC}"
    echo -e "    ${GRAY}4. You SSH in during the 30-second window${NC}"
    echo -e "    ${GRAY}5. Port closes automatically after timeout${NC}"
    echo ""
    
    if ! confirm "Install and configure fwknop SPA?"; then
        mark_skipped "setup_fwknop" "User declined installation"
        return 0
    fi
    
    # Install fwknop
    if ! command_exists fwknopd; then
        print_step "Installing fwknop server..."
        if apt-get install -y fwknop-server >> "$LOG_FILE" 2>&1; then
            print_status "fwknop server installed"
        else
            print_error "fwknop installation failed"
            mark_failed "setup_fwknop" "Apt installation failed"
            return 1
        fi
    else
        print_info "fwknop is already installed"
    fi
    
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        SSH_PORT="${SSH_PORT:-2222}"
    fi
    
    backup_file /etc/fwknop/fwknopd.conf "pre-fwknop-hardening"
    backup_file /etc/fwknop/access.conf "pre-fwknop-hardening"
    
    # Generate cryptographic keys
    print_subsection "Cryptographic Key Generation"
    print_step "Generating 256-bit encryption keys..."
    
    local spa_key
    spa_key=$(openssl rand -base64 32)
    local hmac_key
    hmac_key=$(openssl rand -base64 32)
    
    print_status "AES-256 encryption key generated"
    print_status "HMAC-SHA256 authentication key generated"
    
    # Server configuration
    print_subsection "Server Configuration"
    local primary_iface
    primary_iface=$(ip route | grep default | awk '{print $5}' | head -1)
    primary_iface="${primary_iface:-eth0}"
    print_info "Primary network interface: ${primary_iface}"
    
    cat > /etc/fwknop/access.conf << EOF
# ============================================================
# VPS Hardening - fwknop SPA Access Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================

SOURCE                  ANY
OPEN_PORTS              tcp/${SSH_PORT}
FW_ACCESS_TIMEOUT       30
REQUIRE_SOURCE_ADDRESS  Y
KEY_BASE64              ${spa_key}
HMAC_KEY_BASE64         ${hmac_key}
EOF
    
    chmod 600 /etc/fwknop/access.conf
    chown root:root /etc/fwknop/access.conf
    
    if [ -f /etc/fwknop/fwknopd.conf ]; then
        sed -i "s/^#\?PCAP_INTF .*/PCAP_INTF             ${primary_iface};/" /etc/fwknop/fwknopd.conf 2>/dev/null || true
    fi
    
    systemctl enable fwknop-server >> "$LOG_FILE" 2>&1
    if systemctl restart fwknop-server >> "$LOG_FILE" 2>&1; then
        print_status "fwknop server started and monitoring"
    else
        print_warning "fwknop failed to start. Check: journalctl -u fwknop-server"
    fi
    
    # Block SSH in UFW
    if command_exists ufw; then
        if confirm "Block SSH port in UFW? (fwknop will open it on demand)"; then
            ufw delete allow "${SSH_PORT}/tcp" 2>/dev/null || true
            ufw delete limit "${SSH_PORT}/tcp" 2>/dev/null || true
            print_status "SSH port blocked in UFW (fwknop manages access)"
        fi
    fi
    
    # Display client credentials
    print_subsection "Client Credentials (SAVE SECURELY!)"
    echo ""
    print_warning_box "SAVE THESE CREDENTIALS IN A PASSWORD MANAGER! You need them on every client device."
    echo ""
    echo -e "  ${BOLD}SPA Key:${NC}     ${YELLOW}${spa_key}${NC}"
    echo -e "  ${BOLD}HMAC Key:${NC}    ${YELLOW}${hmac_key}${NC}"
    echo -e "  ${BOLD}SSH Port:${NC}    ${YELLOW}${SSH_PORT}${NC}"
    echo -e "  ${BOLD}Server IP:${NC}   ${YELLOW}${PRIMARY_IP}${NC}"
    echo ""
    echo -e "  ${BOLD}Linux/macOS Client Command:${NC}"
    echo -e "    ${CYAN}fwknop -A tcp/${SSH_PORT} -D ${PRIMARY_IP} \\${NC}"
    echo -e "    ${CYAN}  --key-base64 ${spa_key} \\${NC}"
    echo -e "    ${CYAN}  --hmac-base64 ${hmac_key}${NC}"
    echo -e "    ${CYAN}ssh -p ${SSH_PORT} user@${PRIMARY_IP}${NC}"
    echo ""
    echo -e "  ${BOLD}Mobile Apps:${NC}"
    echo -e "    ${GRAY}• Android: FWKnop2 (Google Play Store)${NC}"
    echo -e "    ${GRAY}• iOS: FWKnop (Apple App Store)${NC}"
    echo ""
    
    # Save credentials to file
    local creds_file="/root/.fwknop-credentials-${TIMESTAMP}.txt"
    cat > "$creds_file" << EOF
fwknop SPA Credentials - Generated $(date '+%Y-%m-%d %H:%M:%S')
================================================================
Server IP:  ${PRIMARY_IP}
SSH Port:   ${SSH_PORT}
SPA Key:    ${spa_key}
HMAC Key:   ${hmac_key}

Client Command:
fwknop -A tcp/${SSH_PORT} -D ${PRIMARY_IP} \
  --key-base64 ${spa_key} \
  --hmac-base64 ${hmac_key}

Then immediately:
ssh -p ${SSH_PORT} user@${PRIMARY_IP}
EOF
    chmod 600 "$creds_file"
    chown root:root "$creds_file"
    print_info "Credentials saved to: ${creds_file}"
    
    mark_completed "setup_fwknop"
}

# End of Section 7
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
# Purpose: Deploy the full interactive Telegram bot system
# ----------------------------------------------------------------------------
setup_telegram_interactive() {
    start_task_timer
    print_section "INTERACTIVE TELEGRAM BOT"

    print_info "This deploys a two-way Telegram bot that lets you:"
    echo -e "    ${GRAY}• Run commands from Telegram (/status, /health, /security)${NC}"
    echo -e "    ${GRAY}• Navigate with clickable inline button menus${NC}"
    echo -e "    ${GRAY}• Manage services, firewall, and users remotely${NC}"
    echo -e "    ${GRAY}• Receive real-time SSH login alerts with geolocation${NC}"
    echo -e "    ${GRAY}• Get push alerts for disk, memory, brute force attacks${NC}"
    echo -e "    ${GRAY}• Download log files and reports directly to your phone${NC}"
    echo -e "    ${GRAY}• Ban/unban IPs and reboot server from Telegram${NC}"
    echo ""

    print_subsection "Prerequisites"
    echo -e "  ${CYAN}1.${NC} Create a bot via ${BOLD}@BotFather${NC} on Telegram:"
    echo -e "     ${GRAY}Open Telegram → Search '@BotFather' → /newbot → Follow prompts${NC}"
    echo -e "     ${GRAY}Copy the API token (format: 123456789:ABCdefGHIjklMNOpqrs)${NC}"
    echo ""
    echo -e "  ${CYAN}2.${NC} Get your Chat ID via ${BOLD}@userinfobot${NC}:"
    echo -e "     ${GRAY}Open Telegram → Search '@userinfobot' → /start → Copy numeric ID${NC}"
    echo ""
    echo -e "  ${CYAN}3.${NC} Start a chat with your new bot:"
    echo -e "     ${GRAY}Search for your bot name → Send /start to activate${NC}"
    echo ""

    if ! confirm "Do you have your Bot Token and Chat ID ready?"; then
        print_info "Complete the prerequisites first, then re-run this option."
        mark_skipped "setup_telegram_interactive" "Prerequisites not ready"
        return 0
    fi

    # Collect credentials
    print_subsection "Bot Credentials"

    local bot_token="" chat_id=""

    while true; do
        prompt_input "Enter your Telegram Bot Token (from @BotFather)" "" bot_token
        if [[ "$bot_token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]; then
            break
        else
            print_error "Invalid token format. Example: 123456789:ABCdefGHIjklMNOpqrs"
        fi
    done

    while true; do
        prompt_input "Enter your Telegram Chat ID (numeric)" "" chat_id
        if [[ "$chat_id" =~ ^-?[0-9]+$ ]]; then
            break
        else
            print_error "Chat ID must be a numeric value (may be negative for groups)"
        fi
    done

    # Test connection
    print_step "Testing bot connection..."
    local test_resp
    test_resp=$(curl -s "https://api.telegram.org/bot${bot_token}/getMe" 2>&1)

    if echo "$test_resp" | grep -q '"ok":true'; then
        local bot_name
        bot_name=$(echo "$test_resp" | grep -oP '"username":"[^"]*"' | cut -d'"' -f4)
        local bot_first
        bot_first=$(echo "$test_resp" | grep -oP '"first_name":"[^"]*"' | cut -d'"' -f4)
        print_status "Connected to @${bot_name} (${bot_first})"
    else
        print_error "Invalid token or network error"
        print_info "Response: ${test_resp}"
        if ! confirm "Save configuration anyway?"; then
            mark_failed "setup_telegram_interactive" "Token validation failed"
            return 1
        fi
    fi

    # Save configuration
    print_subsection "Saving Configuration"
    mkdir -p /etc/vps-hardening
    chmod 700 /etc/vps-hardening

    cat > "$TG_CONFIG" << EOF
# ============================================================
# VPS Hardening - Interactive Telegram Bot Configuration
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================
# SECURITY: This file contains sensitive credentials.
# Never share, commit, or expose this file.

TELEGRAM_BOT_TOKEN="${bot_token}"
TELEGRAM_CHAT_ID="${chat_id}"
TELEGRAM_HOSTNAME="$(hostname)"
TELEGRAM_SERVER_IP="${PRIMARY_IP}"

# Notification toggles (true/false)
NOTIFY_SSH_LOGIN=true
NOTIFY_FAIL2BAN=true
NOTIFY_HIGH_LOAD=true
NOTIFY_DISK_FULL=true
NOTIFY_SECURITY_UPDATES=true
NOTIFY_ROOT_LOGIN=true
NOTIFY_SUDO_USAGE=false

# Alert thresholds
DISK_WARN_THRESHOLD=80
DISK_CRITICAL_THRESHOLD=90
MEMORY_WARN_THRESHOLD=85
LOAD_WARN_THRESHOLD=5.0
FAILED_LOGIN_THRESHOLD=10

# Bot settings
BOT_POLL_INTERVAL=2
BOT_MAX_MESSAGE_LENGTH=4000
EOF

    chmod 600 "$TG_CONFIG"
    chown root:root "$TG_CONFIG"
    print_status "Configuration saved to ${TG_CONFIG}"

    # Register bot commands with Telegram API
    print_step "Registering slash commands with Telegram..."
    curl -s -X POST "https://api.telegram.org/bot${bot_token}/setMyCommands" \
        -H "Content-Type: application/json" \
        -d '{"commands":[
            {"command":"start","description":"Welcome message and main menu"},
            {"command":"menu","description":"Interactive button control panel"},
            {"command":"status","description":"Quick system status overview"},
            {"command":"health","description":"Full health report with details"},
            {"command":"security","description":"Security status and SSH stats"},
            {"command":"firewall","description":"UFW firewall rules and status"},
            {"command":"services","description":"Service management panel"},
            {"command":"logs","description":"View and download system logs"},
            {"command":"users","description":"Active users and login history"},
            {"command":"updates","description":"Check and apply package updates"},
            {"command":"ban","description":"Ban an IP address via Fail2ban"},
            {"command":"unban","description":"Unban an IP address"},
            {"command":"reboot","description":"Reboot the server (with confirm)"},
            {"command":"help","description":"Show all available commands"}
        ]}' > /dev/null 2>&1
    print_status "14 bot commands registered with Telegram"

    # Deploy bot daemon and notifications
    deploy_interactive_bot
    setup_interactive_notifications

    # Start the bot service
    print_subsection "Starting Bot Service"
    systemctl daemon-reload
    systemctl enable "$TG_BOT_SERVICE" >> "$LOG_FILE" 2>&1
    systemctl restart "$TG_BOT_SERVICE" >> "$LOG_FILE" 2>&1

    sleep 3
    if systemctl is-active --quiet "$TG_BOT_SERVICE"; then
        print_success_box "Interactive Telegram bot is running!"
    else
        print_error "Bot failed to start. Check: journalctl -u ${TG_BOT_SERVICE} -f"
        mark_failed "setup_telegram_interactive" "Service failed to start"
    fi

    # Send welcome message
    print_step "Sending welcome message to Telegram..."
    local welcome_msg="🎉 <b>VPS Bot Activated!</b>%0A%0A"
    welcome_msg+="Your interactive bot is now online.%0A%0A"
    welcome_msg+="🖥 Host: <code>$(hostname)</code>%0A"
    welcome_msg+="🌐 IP: <code>${PRIMARY_IP}</code>%0A"
    welcome_msg+="⏰ Time: <code>$(date '+%Y-%m-%d %H:%M:%S')</code>%0A%0A"
    welcome_msg+="Try these commands:%0A"
    welcome_msg+="/menu - Button control panel%0A"
    welcome_msg+="/status - Quick system status%0A"
    welcome_msg+="/help - All available commands"

    curl -s -X POST "https://api.telegram.org/bot${bot_token}/sendMessage" \
        -d "chat_id=${chat_id}" \
        -d "text=${welcome_msg}" \
        -d "parse_mode=HTML" > /dev/null 2>&1
    print_status "Welcome message sent"

    echo ""
    print_info "Open Telegram and try /menu on your bot!"
    print_info "Service management: systemctl status ${TG_BOT_SERVICE}"
    print_info "Live bot logs: journalctl -u ${TG_BOT_SERVICE} -f"
    print_info "Bot script: ${TG_BOT_SCRIPT}"

    mark_completed "setup_telegram_interactive"
}

# ----------------------------------------------------------------------------
# Function: deploy_interactive_bot
# Purpose: Deploy the Python bot daemon with full command set
# ----------------------------------------------------------------------------
deploy_interactive_bot() {
    print_step "Deploying interactive bot daemon..."

    mkdir -p "$TG_BOT_DIR"
    chmod 700 "$TG_BOT_DIR"

    # Write the complete Python bot daemon
    cat > "$TG_BOT_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""
VPS Hardening Interactive Telegram Bot v3.1
Two-way communication with inline menus and remote management.
Uses only Python 3 standard library (no pip dependencies).
"""
import json, os, subprocess, time, urllib.request, urllib.error
import sys, logging, mimetypes
from datetime import datetime

CONFIG_FILE = "/etc/vps-hardening/telegram.conf"
LOG_PATH = "/var/log/vps-telegram-bot.log"

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()])
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

# ---- Telegram API Helpers ----
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
    if kb:
        d["reply_markup"] = kb
    return tg("sendMessage", d)

def edit(mid, text, cid=None, kb=None):
    d = {"chat_id": cid or CHAT_ID, "message_id": mid,
         "text": text[:4096], "parse_mode": "HTML"}
    if kb:
        d["reply_markup"] = kb
    return tg("editMessageText", d)

def answer_cb(qid, text=""):
    tg("answerCallbackQuery", {"callback_query_id": qid, "text": text})

def kb(rows):
    """Build inline keyboard from list of [(text, callback_data), ...] rows."""
    return {"inline_keyboard": [
        [{"text": t, "callback_data": d} for t, d in row] for row in rows
    ]}

def send_file(path, cid=None, caption=None):
    """Send a file as document using multipart form upload."""
    cid = cid or CHAT_ID
    boundary = "----VPSBotBoundary7d3b4a"
    try:
        with open(path, "rb") as f:
            fdata = f.read()
    except Exception as e:
        send(f"❌ Cannot read file: {e}", cid)
        return
    body = f"--{boundary}\r\n"
    body += f'Content-Disposition: form-data; name="chat_id"\r\n\r\n{cid}\r\n'
    if caption:
        body += f"--{boundary}\r\n"
        body += f'Content-Disposition: form-data; name="caption"\r\n\r\n{caption}\r\n'
    fname = os.path.basename(path)
    body += f"--{boundary}\r\n"
    body += f'Content-Disposition: form-data; name="document"; filename="{fname}"\r\n'
    body += f"Content-Type: application/octet-stream\r\n\r\n"
    raw = body.encode() + fdata + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{API}/sendDocument", raw,
        {"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        urllib.request.urlopen(req, timeout=60)
    except Exception as e:
        logger.error(f"sendFile error: {e}")

# ---- System Command Helper ----
def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip() or r.stderr.strip() or "No output"
    except subprocess.TimeoutExpired:
        return "⏱ Command timed out"
    except Exception as e:
        return f"❌ Error: {e}"

# ---- Command Handlers ----
def cmd_start(c):
    send(
        f"👋 <b>Welcome to {HOST} VPS Bot!</b>\n\n"
        f"🖥 Server: <code>{HOST}</code>\n"
        f"🌐 IP: <code>{IP}</code>\n"
        f"🐧 Kernel: <code>{run('uname -r')}</code>\n\n"
        f"Use /menu for the interactive button panel\n"
        f"or /help to see all available commands.", c)

def cmd_help(c):
    send(
        "❓ <b>Available Commands</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "📊 <b>Monitoring</b>\n"
        "  /status — Quick system overview\n"
        "  /health — Full health report\n"
        "  /security — Security status\n\n"
        "🔧 <b>Management</b>\n"
        "  /firewall — Firewall status & rules\n"
        "  /services — Service management\n"
        "  /updates — Check package updates\n"
        "  /users — Active users & sessions\n"
        "  /logs — Recent system logs\n\n"
        "🛡 <b>Security Actions</b>\n"
        "  /ban &lt;ip&gt; — Ban an IP address\n"
        "  /unban &lt;ip&gt; — Unban an IP address\n\n"
        "⚠️ <b>Danger Zone</b>\n"
        "  /reboot — Reboot server (with confirm)\n\n"
        "📱 <b>Navigation</b>\n"
        "  /menu — Interactive button menu", c)

def cmd_status(c):
    uptime = run("uptime -p | sed 's/up //'")
    cpu = run("top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}'")
    cores = run("nproc")
    load = run("uptime | awk -F'load average:' '{print $2}' | xargs")
    ram = run("free -m | awk 'NR==2{printf \"%dMB / %dMB (%.1f%%)\", $3, $2, $3/$2*100}'")
    disk = run("df -h / | awk 'NR==2{printf \"%s / %s (%s)\", $3, $2, $5}'")
    ports = run("ss -tlnp 2>/dev/null | grep -c LISTEN")
    t = (
        f"📊 <b>System Status</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🖥 Host: <code>{HOST}</code>\n"
        f"⏱ Uptime: <code>{uptime}</code>\n"
        f"⚡ CPU: <code>{cpu}% ({cores} cores)</code>\n"
        f"📈 Load: <code>{load}</code>\n"
        f"🧠 RAM: <code>{ram}</code>\n"
        f"💾 Disk: <code>{disk}</code>\n"
        f"🌐 Ports: <code>{ports} listening</code>\n\n"
        f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>")
    send(t, c, kb([
        [("🔄 Refresh", "cmd_status"), ("🏥 Full Health", "cmd_health")],
        [("🔙 Menu", "cmd_menu")]]))

def cmd_health(c):
    uptime = run("uptime -p | sed 's/up //'")
    cpu = run("top -bn1 | grep 'Cpu(s)' | awk '{print $2+$4}'")
    load = run("uptime | awk -F'load average:' '{print $2}' | xargs")
    ram = run("free -m | awk 'NR==2{printf \"%dMB / %dMB (%.1f%%)\", $3, $2, $3/$2*100}'")
    swap = run("free -m | awk 'NR==3{printf \"%dMB / %dMB\", $3, $2}'")
    disk = run("df -h / | awk 'NR==2{printf \"%s / %s (%s)\", $3, $2, $5}'")
    top_cpu = run("ps aux --sort=-%cpu | awk 'NR==2{print $11, $3\"%\"}'")
    top_ram = run("ps aux --sort=-%mem | awk 'NR==2{print $11, $4\"%\"}'")
    procs = run("ps aux | wc -l")
    t = (
        f"🏥 <b>Full Health Report</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🖥 <b>System</b>\n"
        f"• Host: <code>{HOST}</code>\n"
        f"• IP: <code>{IP}</code>\n"
        f"• Kernel: <code>{run('uname -r')}</code>\n"
        f"• Uptime: <code>{uptime}</code>\n\n"
        f"⚡ <b>Performance</b>\n"
        f"• CPU: <code>{cpu}%</code>\n"
        f"• Load: <code>{load}</code>\n"
        f"• Memory: <code>{ram}</code>\n"
        f"• Swap: <code>{swap}</code>\n\n"
        f"💾 <b>Storage</b>\n"
        f"• Root: <code>{disk}</code>\n\n"
        f"🔧 <b>Processes ({procs})</b>\n"
        f"• Top CPU: <code>{top_cpu}</code>\n"
        f"• Top RAM: <code>{top_ram}</code>\n\n"
        f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>")
    send(t, c, kb([
        [("🔄 Refresh", "cmd_health"), ("📊 Quick", "cmd_status")],
        [("🔒 Security", "cmd_security"), ("🔙 Menu", "cmd_menu")]]))

def cmd_security(c):
    fl = run("grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -200 | wc -l")
    sl = run("grep -c 'Accepted' /var/log/auth.log 2>/dev/null | tail -1")
    bn = run("fail2ban-client status 2>/dev/null | grep -oP '\\d+(?= currently banned)' | head -1") or "0"
    uf = run("ufw status 2>/dev/null | head -1 | awk '{print $2}'")
    up = run("apt list --upgradable 2>/dev/null | grep -v Listing | wc -l")
    su = run("apt list --upgradable 2>/dev/null | grep -ic security") or "0"
    rb = "🔴 Required" if os.path.exists("/var/run/reboot-required") else "✅ Not needed"
    aa = run("aa-status 2>/dev/null | grep -oP '\\d+(?= profiles are in enforce mode)' | head -1") or "N/A"
    au = run("systemctl is-active auditd 2>/dev/null") or "N/A"
    em = "🔒" if uf == "active" and int(fl or 0) < 50 else "⚠️"
    t = (
        f"{em} <b>Security Report</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔐 <b>SSH Activity (24h)</b>\n"
        f"• Failed logins: <code>{fl}</code>\n"
        f"• Successful: <code>{sl}</code>\n"
        f"• Banned IPs: <code>{bn}</code>\n\n"
        f"🔥 <b>Firewall</b>\n"
        f"• UFW: <code>{uf}</code>\n"
        f"• Listening: <code>{run('ss -tlnp 2>/dev/null | grep -c LISTEN')} ports</code>\n\n"
        f"📦 <b>Updates</b>\n"
        f"• Pending: <code>{up}</code>\n"
        f"• Security: <code>{su}</code>\n"
        f"• Reboot: {rb}\n\n"
        f"🛡 <b>Security Modules</b>\n"
        f"• AppArmor: <code>{aa} enforced</code>\n"
        f"• Auditd: <code>{au}</code>\n\n"
        f"<i>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>")
    send(t, c, kb([
        [("🔄 Refresh", "cmd_security"), ("🔥 Firewall", "cmd_firewall")],
        [("📦 Updates", "cmd_updates"), ("🔙 Menu", "cmd_menu")]]))

def cmd_firewall(c):
    ufw_out = run("ufw status verbose 2>/dev/null")
    send(f"🔥 <b>Firewall Status</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n<code>{ufw_out[:3500]}</code>",
         c, kb([[("🔄 Refresh", "cmd_firewall")],
                [("🔒 Security", "cmd_security"), ("🔙 Menu", "cmd_menu")]]))

def cmd_services(c):
    send("⚙️ <b>Service Management</b>\n━━━━━━━━━━━━━━━━━━━━━\n\nSelect a service:",
         c, kb([
             [("SSH", "svc_ssh"), ("UFW", "svc_ufw"), ("Fail2ban", "svc_f2b")],
             [("Nginx", "svc_nginx"), ("Apache", "svc_apache"), ("Docker", "svc_docker")],
             [("Cron", "svc_cron"), ("Auditd", "svc_auditd"), ("AppArmor", "svc_apparmor")],
             [("🔙 Back to Menu", "cmd_menu")]]))

def handle_svc(c, name, action="status"):
    svc_map = {"ssh": "ssh", "ufw": "ufw", "f2b": "fail2ban",
               "nginx": "nginx", "apache": "apache2", "docker": "docker",
               "cron": "cron", "auditd": "auditd", "apparmor": "apparmor"}
    svc = svc_map.get(name, name)
    label = svc.upper()
    if action == "status":
        st = run(f"systemctl is-active {svc} 2>/dev/null")
        en = run(f"systemctl is-enabled {svc} 2>/dev/null")
        em = "🟢" if st == "active" else "🔴"
        send(f"⚙️ <b>{label}</b>\n\n• Status: {em} <code>{st}</code>\n• Enabled: <code>{en}</code>",
             c, kb([
                 [("▶️ Start", f"svc_{name}_start"), ("⏹ Stop", f"svc_{name}_stop")],
                 [("🔄 Restart", f"svc_{name}_restart")],
                 [("⚙️ Services", "cmd_services"), ("🔙 Menu", "cmd_menu")]]))
    elif action in ("start", "stop", "restart"):
        r = run(f"systemctl {action} {svc} 2>&1")
        st = run(f"systemctl is-active {svc} 2>/dev/null")
        em = "🟢" if st == "active" else "🔴"
        send(f"⚙️ <b>{label}</b> → {action}\n\n{em} <code>{st}</code>\n<code>{r[:500]}</code>",
             c, kb([[("🔄 Refresh", f"svc_{name}")],
                    [("⚙️ Services", "cmd_services"), ("🔙 Menu", "cmd_menu")]]))

def cmd_logs(c):
    logs = run("tail -30 /var/log/syslog 2>/dev/null || journalctl -n 30 --no-pager 2>/dev/null")
    send(f"📋 <b>Recent System Logs</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n<code>{logs[:3500]}</code>",
         c, kb([
             [("📋 Auth Log", "logs_auth"), ("📋 Syslog", "logs_sys")],
             [("📄 Download Full Log", "logs_dl")],
             [("🔄 Refresh", "cmd_logs"), ("🔙 Menu", "cmd_menu")]]))

def cmd_users(c):
    who = run("who 2>/dev/null || echo 'No users logged in'")
    last = run("last -n 5 -F 2>/dev/null | head -6")
    send(f"👤 <b>Active Users</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
         f"<b>Currently online:</b>\n<code>{who}</code>\n\n"
         f"<b>Recent logins:</b>\n<code>{last[:1500]}</code>",
         c, kb([[("🔄 Refresh", "cmd_users"), ("🔙 Menu", "cmd_menu")]]))

def cmd_updates(c):
    run("apt-get update -qq 2>/dev/null", 30)
    u = run("apt list --upgradable 2>/dev/null | grep -v Listing | head -20")
    n = run("apt list --upgradable 2>/dev/null | grep -v Listing | wc -l")
    send(f"📦 <b>Package Updates</b>\n━━━━━━━━━━━━━━━━━━━━━\n\n"
         f"Available: <code>{n}</code> packages\n\n<code>{u[:3000]}</code>",
         c, kb([
             [("📦 Upgrade Now", "confirm_upgrade"), ("🔄 Refresh", "cmd_updates")],
             [("🔙 Menu", "cmd_menu")]]))

def cmd_ban(c, ip):
    if not ip:
        send("❌ Usage: /ban <ip_address>\nExample: /ban 192.168.1.100", c)
        return
    r = run(f"fail2ban-client set sshd banip {ip} 2>&1")
    send(f"🚫 <b>IP Banned</b>\n\n• IP: <code>{ip}</code>\n• Result: <code>{r}</code>", c)

def cmd_unban(c, ip):
    if not ip:
        send("❌ Usage: /unban <ip_address>", c)
        return
    r = run(f"fail2ban-client set sshd unbanip {ip} 2>&1")
    send(f"✅ <b>IP Unbanned</b>\n\n• IP: <code>{ip}</code>\n• Result: <code>{r}</code>", c)

def cmd_reboot(c):
    send("⚠️ <b>REBOOT SERVER?</b>\n\n"
         "This will disconnect ALL users and restart the server.\n"
         "The bot will be offline for 1-2 minutes.\n\n"
         "Are you absolutely sure?", c,
         kb([[("✅ Yes, Reboot Now", "confirm_reboot"), ("❌ Cancel", "cmd_menu")]]))

def cmd_menu(c):
    send(f"📱 <b>{HOST} Control Panel</b>\n"
         f"━━━━━━━━━━━━━━━━━━━━━\n"
         f"<i>Select an option below:</i>", c,
         kb([
             [("📊 Status", "cmd_status"), ("🏥 Health", "cmd_health")],
             [("🔒 Security", "cmd_security"), ("🔥 Firewall", "cmd_firewall")],
             [("⚙️ Services", "cmd_services"), ("📦 Updates", "cmd_updates")],
             [("📋 Logs", "cmd_logs"), ("👤 Users", "cmd_users")],
             [("🔄 Reboot", "cmd_reboot"), ("❓ Help", "cmd_help")]]))

# ---- Callback Router ----
def handle_cb(q):
    d = q.get("data", "")
    c = q["message"]["chat"]["id"]
    answer_cb(q["id"])
    cmds = {
        "cmd_menu": cmd_menu, "cmd_status": cmd_status,
        "cmd_health": cmd_health, "cmd_security": cmd_security,
        "cmd_firewall": cmd_firewall, "cmd_services": cmd_services,
        "cmd_logs": cmd_logs, "cmd_users": cmd_users,
        "cmd_updates": cmd_updates, "cmd_help": cmd_help,
        "cmd_reboot": cmd_reboot
    }
    if d in cmds:
        cmds[d](c)
    elif d.startswith("svc_"):
        parts = d.split("_")
        handle_svc(c, parts[1], parts[2] if len(parts) > 2 else "status")
    elif d == "logs_auth":
        logs = run("tail -40 /var/log/auth.log 2>/dev/null")
        send(f"📋 <b>Auth Log (last 40 lines)</b>\n\n<code>{logs[:3500]}</code>", c)
    elif d == "logs_sys":
        cmd_logs(c)
    elif d == "logs_dl":
        send_file("/var/log/syslog", c, "📄 Full system log")
    elif d == "confirm_reboot":
        send("🔄 <b>Rebooting server now...</b>\n\nSee you in a minute!", c)
        time.sleep(2)
        run("reboot")
    elif d == "confirm_upgrade":
        send("📦 <b>Upgrading packages...</b>\nThis may take several minutes.", c)
        r = run("DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1 | tail -25", 300)
        send(f"📦 <b>Upgrade Complete</b>\n\n<code>{r[:3500]}</code>", c)

# ---- Main Polling Loop ----
def main():
    if not TOKEN:
        logger.error("No bot token configured!")
        sys.exit(1)
    logger.info(f"Bot started for {HOST} ({IP})")
    send(f"🟢 <b>Bot Online</b>\n\n{HOST} monitoring is now active.\n"
         f"Kernel: <code>{run('uname -r')}</code>\n"
         f"Uptime: <code>{run('uptime -p | sed \"s/up //\"')}</code>", CHAT_ID)
    offset = 0
    while True:
        try:
            resp = tg("getUpdates", {"offset": offset, "timeout": 30})
            if not resp or not resp.get("ok"):
                time.sleep(5)
                continue
            for u in resp.get("result", []):
                offset = u["update_id"] + 1
                if "message" in u:
                    m = u["message"]
                    c = m["chat"]["id"]
                    # Security: only respond to authorized chat
                    if str(c) != str(CHAT_ID):
                        send("🚫 Unauthorized access attempt logged.", c)
                        logger.warning(f"Unauthorized access from chat {c}")
                        continue
                    t = m.get("text", "").strip()
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
                    elif t.startswith("/ban"):
                        cmd_ban(c, t.split(" ", 1)[1] if " " in t else "")
                    elif t.startswith("/unban"):
                        cmd_unban(c, t.split(" ", 1)[1] if " " in t else "")
                    elif t == "/reboot": cmd_reboot(c)
                    elif t == "/help": cmd_help(c)
                elif "callback_query" in u:
                    q = u["callback_query"]
                    if str(q["message"]["chat"]["id"]) == str(CHAT_ID):
                        handle_cb(q)
        except KeyboardInterrupt:
            logger.info("Bot stopped by user")
            break
        except Exception as e:
            logger.error(f"Polling error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
PYEOF

    chmod 700 "$TG_BOT_SCRIPT"
    chown -R root:root "$TG_BOT_DIR"
    print_status "Bot daemon deployed to ${TG_BOT_SCRIPT}"

    # Create systemd service unit
    cat > "/etc/systemd/system/${TG_BOT_SERVICE}" << EOF
[Unit]
Description=VPS Hardening Interactive Telegram Bot
Documentation=https://github.com/nrikmoh/vps-hardening
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

# Security sandboxing for the bot process
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log /tmp /var/lib/vps-hardening
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "/etc/systemd/system/${TG_BOT_SERVICE}"
    print_status "Systemd service unit created with security sandboxing"
}

# ----------------------------------------------------------------------------
# Function: setup_interactive_notifications
# Purpose: Deploy push notification hooks (SSH, resources, daily reports)
# ----------------------------------------------------------------------------
setup_interactive_notifications() {
    print_step "Deploying push notification hooks..."

    # ---- SSH Login PAM Hook ----
    print_subsection "SSH Login Real-Time Alerts"
    cat > /usr/local/bin/vps-tg-ssh-notify.sh << 'EOF'
#!/bin/bash
# VPS Hardening - SSH Login Telegram Notification
[ "$PAM_TYPE" != "open_session" ] && exit 0
source /etc/vps-hardening/telegram.conf 2>/dev/null || exit 0
[ "${NOTIFY_SSH_LOGIN:-true}" != "true" ] && exit 0

USER="${PAM_USER:-unknown}"
IP="${PAM_RHOST:-local}"
TIME=$(date '+%Y-%m-%d %H:%M:%S %Z')
TTY="${PAM_TTY:-unknown}"

# Determine severity
[ "$USER" = "root" ] && EMOJI="🚨" && SEVERITY="CRITICAL" || EMOJI="🔐" && SEVERITY="Info"

# Geolocation lookup
GEO=""
if [ "$IP" != "local" ] && [ "$IP" != "::1" ] && [ "$IP" != "127.0.0.1" ]; then
    GEO_DATA=$(curl -s --max-time 3 "https://ipapi.co/${IP}/json/" 2>/dev/null)
    if [ -n "$GEO_DATA" ]; then
        COUNTRY=$(echo "$GEO_DATA" | grep -oP '"country_name":"[^"]*"' | cut -d'"' -f4)
        CITY=$(echo "$GEO_DATA" | grep -oP '"city":"[^"]*"' | cut -d'"' -f4)
        ORG=$(echo "$GEO_DATA" | grep -oP '"org":"[^"]*"' | cut -d'"' -f4)
        [ -n "$COUNTRY" ] && GEO="%0A• 🌍 Location: <code>${CITY:-Unknown}, ${COUNTRY}</code>"
        [ -n "$ORG" ] && GEO="${GEO}%0A• 🏢 ISP: <code>${ORG}</code>"
    fi
fi

MSG="${EMOJI} <b>SSH Login - ${SEVERITY}</b>%0A"
MSG+="━━━━━━━━━━━━━━━━━━━%0A%0A"
MSG+="🖥 Server: <code>${TELEGRAM_HOSTNAME}</code>%0A%0A"
MSG+="👤 User: <code>${USER}</code>%0A"
MSG+="🌐 From: <code>${IP}</code>${GEO}%0A"
MSG+="📺 TTY: <code>${TTY}</code>%0A"
MSG+="⏰ Time: <code>${TIME}</code>"

curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT_ID}" -d "text=${MSG}" \
    -d "parse_mode=HTML" > /dev/null 2>&1 &
exit 0
EOF

    chmod 750 /usr/local/bin/vps-tg-ssh-notify.sh
    chown root:root /usr/local/bin/vps-tg-ssh-notify.sh

    if ! grep -q "vps-tg-ssh-notify" /etc/pam.d/sshd 2>/dev/null; then
        echo "" >> /etc/pam.d/sshd
        echo "# VPS Hardening - Telegram SSH login notification" >> /etc/pam.d/sshd
        echo "session optional pam_exec.so /usr/local/bin/vps-tg-ssh-notify.sh" >> /etc/pam.d/sshd
        print_status "SSH login alerts configured via PAM"
    else
        print_info "SSH login alerts already configured"
    fi

    # ---- Resource Monitoring Script ----
    print_subsection "Resource Monitoring Alerts"
    cat > /usr/local/bin/vps-tg-monitor.sh << 'MEOF'
#!/bin/bash
# VPS Hardening - Resource Monitoring & Alerting
source /etc/vps-hardening/telegram.conf 2>/dev/null || exit 0
SD="/var/lib/vps-hardening"
mkdir -p "$SD"

# Anti-spam cooldown function
cd_check() {
    local key="$1" mins="${2:-60}"
    local f="$SD/tg-${key}.ts"
    [ -f "$f" ] && [ $(( $(date +%s) - $(cat "$f") )) -lt $((mins*60)) ] && return 0
    date +%s > "$f"
    return 1
}

# Send alert helper
sa() {
    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}" -d "text=$1" \
        -d "parse_mode=HTML" > /dev/null 2>&1
}

# ---- Disk Usage ----
if [ "${NOTIFY_DISK_FULL:-true}" = "true" ]; then
    D=$(df / | awk 'NR==2{print $5}' | tr -d '%')
    if [ "$D" -ge "${DISK_CRITICAL_THRESHOLD:-90}" ]; then
        cd_check "disk-crit" 30 && : || \
            sa "🚨 <b>CRITICAL: Disk ${D}% Full</b>%0A%0ATake immediate action!%0AUse /updates to check for cleanup."
    elif [ "$D" -ge "${DISK_WARN_THRESHOLD:-80}" ]; then
        cd_check "disk-warn" 240 && : || \
            sa "⚠️ <b>Disk Warning: ${D}% Full</b>%0A%0AConsider cleaning up soon."
    fi
fi

# ---- Memory Usage ----
if [ "${NOTIFY_HIGH_LOAD:-true}" = "true" ]; then
    M=$(free | awk 'NR==2{printf "%.0f",$3/$2*100}')
    if [ "$M" -ge "${MEMORY_WARN_THRESHOLD:-85}" ]; then
        cd_check "mem" 120 && : || {
            TOP=$(ps aux --sort=-%mem | awk 'NR<=4{printf "• %s: %s%%\n",$11,$4}')
            sa "⚠️ <b>High Memory: ${M}%</b>%0A%0A<b>Top processes:</b>%0A${TOP}"
        }
    fi
fi

# ---- Load Average ----
if [ "${NOTIFY_HIGH_LOAD:-true}" = "true" ]; then
    L=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | xargs)
    THRESH="${LOAD_WARN_THRESHOLD:-5.0}"
    if [ "$(echo "$L > $THRESH" | bc -l 2>/dev/null || echo 0)" = "1" ]; then
        cd_check "load" 60 && : || {
            TOP=$(ps aux --sort=-%cpu | awk 'NR<=4{printf "• %s: %s%%\n",$11,$3}')
            sa "⚠️ <b>High Load: ${L}</b>%0A%0AThreshold: <code>${THRESH}</code>%0A%0A<b>Top CPU:</b>%0A${TOP}"
        }
    fi
fi

# ---- Brute Force Detection ----
F=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -100 | wc -l)
if [ "$F" -ge "${FAILED_LOGIN_THRESHOLD:-10}" ]; then
    cd_check "brute" 60 && : || {
        IPS=$(grep "Failed password" /var/log/auth.log | grep -oP 'from \K[0-9.]+' | \
              sort | uniq -c | sort -rn | head -5 | awk '{printf "• %s (%s attempts)\n",$2,$1}')
        sa "🚨 <b>Brute Force Attack</b>%0A%0AFailed logins: <code>${F}</code>%0A%0A<b>Top attackers:</b>%0A${IPS}%0AUse /ban &lt;ip&gt; to block"
    }
fi

# ---- Security Updates ----
if [ "${NOTIFY_SECURITY_UPDATES:-true}" = "true" ]; then
    S=$(apt list --upgradable 2>/dev/null | grep -ic security)
    [ "$S" -gt 0 ] && { cd_check "secupd" 1440 && : || sa "📦 <b>${S} Security Updates Available</b>%0A%0AUse /updates to review and apply"; }
fi

# ---- Reboot Required ----
if [ -f /var/run/reboot-required ]; then
    cd_check "reboot" 1440 && : || {
        PKGS=$(cat /var/run/reboot-required.pkgs 2>/dev/null | head -5 | awk '{printf "• %s\n",$1}')
        sa "🔄 <b>Reboot Required</b>%0A%0A<b>Affected:</b>%0A${PKGS:-Multiple packages}%0A%0AUse /reboot when ready"
    }
fi
MEOF

    chmod 750 /usr/local/bin/vps-tg-monitor.sh
    chown root:root /usr/local/bin/vps-tg-monitor.sh

    cat > /etc/cron.d/vps-telegram-monitor << 'EOF'
# VPS Hardening - Resource Monitoring (every 15 minutes)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/15 * * * * root /usr/local/bin/vps-tg-monitor.sh
EOF
    chmod 644 /etc/cron.d/vps-telegram-monitor
    print_status "Resource monitoring active (runs every 15 minutes)"

    # ---- Daily Report Cron ----
    print_subsection "Daily Health & Security Reports"
    cat > /etc/cron.d/vps-telegram-daily << 'EOF'
# VPS Hardening - Daily Telegram Reports
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Health report at 08:00
0 8 * * * root /usr/bin/python3 -c "
import sys; sys.path.insert(0, '/opt/vps-telegram-bot')
from bot import cmd_health, cmd_security, CHAT_ID
cmd_health(CHAT_ID)
import time; time.sleep(5)
cmd_security(CHAT_ID)
"
EOF
    chmod 644 /etc/cron.d/vps-telegram-daily
    print_status "Daily health + security reports scheduled at 08:00"
}

# ----------------------------------------------------------------------------
# Function: telegram_bot_manage
# Purpose: Manage the interactive bot service
# ----------------------------------------------------------------------------
telegram_bot_manage() {
    print_section "TELEGRAM BOT MANAGEMENT"

    if [ ! -f "$TG_CONFIG" ]; then
        print_error "Bot not configured yet. Run 'Setup Interactive Telegram Bot' first (option 40)."
        return 1
    fi

    local bot_status
    bot_status=$(systemctl is-active "$TG_BOT_SERVICE" 2>/dev/null || echo "inactive")
    local bot_emoji="🔴"
    [ "$bot_status" = "active" ] && bot_emoji="🟢"

    echo -e "  ${BOLD}Bot Status:${NC}    ${bot_emoji} ${bot_status}"
    echo -e "  ${BOLD}Service:${NC}       ${TG_BOT_SERVICE}"
    echo -e "  ${BOLD}Script:${NC}        ${TG_BOT_SCRIPT}"
    echo -e "  ${BOLD}Config:${NC}        ${TG_CONFIG}"
    echo -e "  ${BOLD}Bot Logs:${NC}      journalctl -u ${TG_BOT_SERVICE}"
    echo -e "  ${BOLD}Bot Log File:${NC}  /var/log/vps-telegram-bot.log"
    echo ""
    echo -e "  ${CYAN}1)${NC} Start bot"
    echo -e "  ${CYAN}2)${NC} Stop bot"
    echo -e "  ${CYAN}3)${NC} Restart bot"
    echo -e "  ${CYAN}4)${NC} View live bot logs"
    echo -e "  ${CYAN}5)${NC} Edit configuration"
    echo -e "  ${CYAN}6)${NC} Send test notification"
    echo -e "  ${CYAN}7)${NC} Remove bot completely"
    echo -e "  ${CYAN}8)${NC} Return to menu"
    echo ""

    local choice=""
    prompt_input "Select option" "8" choice

    case "$choice" in
        1)
            systemctl start "$TG_BOT_SERVICE"
            print_status "Bot started"
            ;;
        2)
            systemctl stop "$TG_BOT_SERVICE"
            print_status "Bot stopped"
            ;;
        3)
            systemctl restart "$TG_BOT_SERVICE"
            print_status "Bot restarted"
            ;;
        4)
            journalctl -u "$TG_BOT_SERVICE" -f
            ;;
        5)
            ${EDITOR:-nano} "$TG_CONFIG"
            systemctl restart "$TG_BOT_SERVICE"
            print_status "Configuration updated and bot restarted"
            ;;
        6)
            source "$TG_CONFIG"
            local test_msg="🧪 <b>Test Notification</b>%0A%0AIf you see this, your bot is working correctly!%0A%0A🖥 <code>${TELEGRAM_HOSTNAME}</code>%0A⏰ <code>$(date '+%Y-%m-%d %H:%M:%S')</code>"
            curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
                -d "chat_id=${TELEGRAM_CHAT_ID}" -d "text=${test_msg}" \
                -d "parse_mode=HTML" > /dev/null 2>&1
            print_status "Test notification sent. Check your Telegram!"
            ;;
        7)
            if confirm "Remove ALL Telegram bot components? This cannot be undone." "n"; then
                print_step "Stopping and disabling service..."
                systemctl stop "$TG_BOT_SERVICE" 2>/dev/null || true
                systemctl disable "$TG_BOT_SERVICE" 2>/dev/null || true
                rm -f "/etc/systemd/system/${TG_BOT_SERVICE}"

                print_step "Removing bot files..."
                rm -rf "$TG_BOT_DIR"
                rm -f "$TG_CONFIG"
                rmdir /etc/vps-hardening 2>/dev/null || true

                print_step "Removing notification hooks..."
                rm -f /usr/local/bin/vps-tg-ssh-notify.sh
                rm -f /usr/local/bin/vps-tg-monitor.sh
                rm -f /etc/cron.d/vps-telegram-monitor
                rm -f /etc/cron.d/vps-telegram-daily

                print_step "Cleaning PAM configuration..."
                sed -i '/vps-tg-ssh-notify/d' /etc/pam.d/sshd 2>/dev/null || true
                sed -i '/VPS Hardening - Telegram SSH/d' /etc/pam.d/sshd 2>/dev/null || true

                systemctl daemon-reload
                print_status "Telegram bot completely removed from system"
            fi
            ;;
        8)
            return 0
            ;;
        *)
            print_error "Invalid option"
            ;;
    esac
}

# End of Section 8
# ============================================================================
# SECURITY STATUS DASHBOARD
# ============================================================================

# ----------------------------------------------------------------------------
# Function: show_security_status
# Purpose: Display a comprehensive real-time security status overview
# ----------------------------------------------------------------------------
show_security_status() {
    set +u  # Prevent unbound variable errors on empty arrays
    print_section "CURRENT SECURITY STATUS DASHBOARD"

    # ---- System Information ----
    print_subsection "System Information"
    print_key_value "Hostname" "$(hostname)"
    print_key_value "FQDN" "$HOSTNAME_FQDN"
    print_key_value "Operating System" "$OS_NAME"
    print_key_value "Kernel" "$KERNEL_VERSION"
    print_key_value "Architecture" "$ARCH"
    print_key_value "Uptime" "$(uptime -p 2>/dev/null || uptime)"
    print_key_value "Current User" "$TARGET_USER"
    print_key_value "Primary IP" "$PRIMARY_IP"

    local virt_type="unknown"
    if command_exists systemd-detect-virt; then
        virt_type=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    fi
    print_key_value "Virtualization" "$virt_type"
    echo ""

    # ---- SSH Configuration ----
    print_subsection "SSH Configuration"
    local ssh_port_current
    ssh_port_current=$(grep -rh "^Port " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}' || echo "22")
    print_key_value "Port" "$ssh_port_current" "$CYAN"

    local pass_auth
    pass_auth=$(grep -rh "^PasswordAuthentication " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    if [ "$pass_auth" = "no" ]; then
        print_check "Password Authentication" "ok" "disabled"
    else
        print_check "Password Authentication" "fail" "enabled"
    fi

    local root_login
    root_login=$(grep -rh "^PermitRootLogin " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    if [ "$root_login" = "no" ]; then
        print_check "Root Login" "ok" "disabled"
    else
        print_check "Root Login" "fail" "$root_login"
    fi

    local pubkey_auth
    pubkey_auth=$(grep -rh "^PubkeyAuthentication " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    print_check "Pubkey Authentication" "info" "$pubkey_auth"

    local max_auth
    max_auth=$(grep -rh "^MaxAuthTries " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}' || echo "6")
    print_check "Max Auth Tries" "info" "$max_auth"

    local x11_fwd
    x11_fwd=$(grep -rh "^X11Forwarding " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}' || echo "unknown")
    if [ "$x11_fwd" = "no" ]; then
        print_check "X11 Forwarding" "ok" "disabled"
    else
        print_check "X11 Forwarding" "warn" "enabled"
    fi
    echo ""

    # ---- Firewall ----
    print_subsection "Firewall (UFW)"
    if command_exists ufw; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1 | awk '{print $2}')
        if [ "$ufw_status" = "active" ]; then
            print_check "UFW Status" "ok" "active"
            local rule_count
            rule_count=$(ufw status numbered 2>/dev/null | grep -c '^\[' || echo "0")
            print_key_value "Active Rules" "$rule_count"
            local ipv6_status
            ipv6_status=$(grep "^IPV6=" /etc/default/ufw 2>/dev/null | cut -d'=' -f2 || echo "unknown")
            print_check "IPv6 Support" "info" "$ipv6_status"
        else
            print_check "UFW Status" "fail" "inactive"
        fi
    else
        print_check "UFW" "fail" "not installed"
    fi
    echo ""

    # ---- Fail2ban ----
    print_subsection "Intrusion Prevention (Fail2ban)"
    if command_exists fail2ban-client; then
        local f2b_status
        f2b_status=$(systemctl is-active fail2ban 2>/dev/null || echo "inactive")
        if [ "$f2b_status" = "active" ]; then
            print_check "Fail2ban Status" "ok" "active"
            local jails
            jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/^\s*//' || echo "none")
            print_key_value "Active Jails" "$jails"

            local total_banned=0
            local jail
            for jail in $(echo "$jails" | tr ',' ' '); do
                jail=$(echo "$jail" | xargs)
                if [ -n "$jail" ]; then
                    local banned
                    banned=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | grep -oP '\d+' || echo "0")
                    total_banned=$(( total_banned + banned ))
                    local jail_total
                    jail_total=$(fail2ban-client status "$jail" 2>/dev/null | grep "Total banned" | grep -oP '\d+' || echo "0")
                    print_key_value "  ${jail}" "${banned} currently / ${jail_total} total banned"
                fi
            done
            print_key_value "Total Banned IPs" "$total_banned" "$RED"
        else
            print_check "Fail2ban Status" "fail" "inactive"
        fi
    else
        print_check "Fail2ban" "fail" "not installed"
    fi
    echo ""

    # ---- AppArmor ----
    print_subsection "Mandatory Access Control (AppArmor)"
    if command_exists aa-status; then
        local aa_status
        aa_status=$(systemctl is-active apparmor 2>/dev/null || echo "inactive")
        if [ "$aa_status" = "active" ]; then
            print_check "AppArmor Status" "ok" "active"
            local aa_enforced
            aa_enforced=$(aa-status 2>/dev/null | grep -oP '\d+(?= profiles are in enforce mode)' | head -1 || echo "0")
            local aa_complain
            aa_complain=$(aa-status 2>/dev/null | grep -oP '\d+(?= profiles are in complain mode)' | head -1 || echo "0")
            local aa_unconfined
            aa_unconfined=$(aa-status 2>/dev/null | grep -oP '\d+(?= processes are unconfined)' | head -1 || echo "0")
            print_key_value "Enforced Profiles" "$aa_enforced" "$GREEN"
            print_key_value "Complain Profiles" "$aa_complain" "$YELLOW"
            print_key_value "Unconfined Processes" "$aa_unconfined"
        else
            print_check "AppArmor Status" "warn" "inactive"
        fi
    else
        print_check "AppArmor" "fail" "not installed"
    fi
    echo ""

    # ---- Audit Daemon ----
    print_subsection "Kernel Auditing (auditd)"
    if command_exists auditctl; then
        local audit_status
        audit_status=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
        if [ "$audit_status" = "active" ]; then
            print_check "Auditd Status" "ok" "active"
            local audit_rules
            audit_rules=$(auditctl -l 2>/dev/null | wc -l || echo "0")
            print_key_value "Loaded Rules" "$audit_rules"
            local audit_enabled
            audit_enabled=$(auditctl -s 2>/dev/null | grep "enabled" | awk '{print $2}' || echo "unknown")
            print_key_value "Audit Enabled" "$audit_enabled"
        else
            print_check "Auditd Status" "warn" "inactive"
        fi
    else
        print_check "Auditd" "fail" "not installed"
    fi
    echo ""

    # ---- File Integrity (AIDE) ----
    print_subsection "File Integrity Monitoring (AIDE)"
    if command_exists aide; then
        print_check "AIDE" "ok" "installed"
        if [ -f /var/lib/aide/aide.db ] || [ -f /var/lib/aide/aide.db.gz ]; then
            local db_date
            db_date=$(stat -c '%y' /var/lib/aide/aide.db 2>/dev/null | cut -d'.' -f1 || echo "unknown")
            print_check "Database" "ok" "initialized (${db_date})"
        else
            print_check "Database" "warn" "not initialized"
        fi
        if [ -f /etc/cron.daily/aide-integrity-check ]; then
            print_check "Daily Check" "ok" "scheduled"
        else
            print_check "Daily Check" "warn" "not scheduled"
        fi
    else
        print_check "AIDE" "fail" "not installed"
    fi
    echo ""

    # ---- Automatic Updates ----
    print_subsection "Automatic Updates"
    if package_installed "unattended-upgrades"; then
        local unattended_status
        unattended_status=$(systemctl is-active unattended-upgrades 2>/dev/null || echo "inactive")
        if [ "$unattended_status" = "active" ]; then
            print_check "Unattended-Upgrades" "ok" "active"
            if [ -f /etc/apt/apt.conf.d/51unattended-upgrades-custom ]; then
                local auto_reboot
                auto_reboot=$(grep "Automatic-Reboot " /etc/apt/apt.conf.d/51unattended-upgrades-custom 2>/dev/null | grep -oP '"[^"]+"' | tr -d '"' | head -1)
                print_key_value "Auto-Reboot" "${auto_reboot:-false}"
            fi
        else
            print_check "Unattended-Upgrades" "warn" "inactive"
        fi
    else
        print_check "Unattended-Upgrades" "fail" "not installed"
    fi
    echo ""

    # ---- Kernel Hardening ----
    print_subsection "Kernel Security Parameters"
    local aslr_val
    aslr_val=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "N/A")
    [ "$aslr_val" = "2" ] && print_check "ASLR" "ok" "full (${aslr_val}/2)" || print_check "ASLR" "warn" "partial (${aslr_val}/2)"

    local dmesg_val
    dmesg_val=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "N/A")
    [ "$dmesg_val" = "1" ] && print_check "dmesg_restrict" "ok" "enabled" || print_check "dmesg_restrict" "fail" "disabled"

    local kptr_val
    kptr_val=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "N/A")
    [ "$kptr_val" = "2" ] && print_check "kptr_restrict" "ok" "strict (${kptr_val})" || print_check "kptr_restrict" "warn" "level ${kptr_val}"

    local syn_val
    syn_val=$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo "N/A")
    [ "$syn_val" = "1" ] && print_check "SYN Cookies" "ok" "enabled" || print_check "SYN Cookies" "fail" "disabled"

    local rp_val
    rp_val=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo "N/A")
    [ "$rp_val" = "1" ] && print_check "Reverse Path Filter" "ok" "enabled" || print_check "Reverse Path Filter" "fail" "disabled"

    local ptrace_val
    ptrace_val=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "N/A")
    [ "$ptrace_val" -ge 2 ] 2>/dev/null && print_check "ptrace_scope" "ok" "restricted (${ptrace_val})" || print_check "ptrace_scope" "warn" "level ${ptrace_val}"

    local bpf_val
    bpf_val=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "N/A")
    [ "$bpf_val" = "1" ] && print_check "Unprivileged BPF" "ok" "disabled" || print_check "Unprivileged BPF" "warn" "enabled"

    local suid_val
    suid_val=$(cat /proc/sys/fs/suid_dumpable 2>/dev/null || echo "N/A")
    [ "$suid_val" = "0" ] && print_check "SUID Core Dumps" "ok" "disabled" || print_check "SUID Core Dumps" "fail" "enabled"
    echo ""

    # ---- Telegram Bot ----
    print_subsection "Telegram Bot"
    if [ -f "$TG_CONFIG" ]; then
        local tg_status
        tg_status=$(systemctl is-active "$TG_BOT_SERVICE" 2>/dev/null || echo "inactive")
        if [ "$tg_status" = "active" ]; then
            print_check "Bot Status" "ok" "active and running"
        else
            print_check "Bot Status" "warn" "configured but inactive"
        fi
        if [ -f /usr/local/bin/vps-tg-ssh-notify.sh ]; then
            print_check "SSH Alerts" "ok" "PAM hook installed"
        fi
        if [ -f /usr/local/bin/vps-tg-monitor.sh ]; then
            print_check "Resource Monitor" "ok" "cron active (15min)"
        fi
        if [ -f /etc/cron.d/vps-telegram-daily ]; then
            print_check "Daily Reports" "ok" "scheduled at 08:00"
        fi
    else
        print_check "Telegram Bot" "info" "not configured"
    fi
    echo ""

    # ---- Listening Ports ----
    print_subsection "Listening Network Ports"
    ss -tlnp 2>/dev/null | grep LISTEN | awk '{printf "    %-30s %s\n", $4, $6}' | head -20
    local total_ports
    total_ports=$(ss -tlnp 2>/dev/null | grep -c LISTEN || echo "0")
    echo ""
    print_key_value "Total Listening Ports" "$total_ports"
    echo ""

       # ---- Authentication Activity ----
    print_subsection "Recent Authentication Activity"
    
    local today_date
    today_date="$(date '+%b %e')"
    local today_iso
    today_iso="$(date '+%Y-%m-%d')"

    if [ -f /var/log/auth.log ]; then
        local failed_today
        local success_today
        local root_attempts
        local invalid_users

        # Use awk to guarantee a clean single integer output even under set -o pipefail
        failed_today=$(grep "Failed password" /var/log/auth.log 2>/dev/null | grep -E "$today_date|$today_iso" | awk 'END {print NR}')
        success_today=$(grep -E "Accepted (publickey|password)" /var/log/auth.log 2>/dev/null | grep -E "$today_date|$today_iso" | awk 'END {print NR}')
        root_attempts=$(grep "Failed password.*root" /var/log/auth.log 2>/dev/null | grep -E "$today_date|$today_iso" | awk 'END {print NR}')
        invalid_users=$(grep "Invalid user" /var/log/auth.log 2>/dev/null | grep -E "$today_date|$today_iso" | awk 'END {print NR}')

        # Sanitize variables (ensure they are always numbers, default to 0)
        failed_today=${failed_today:-0}
        success_today=${success_today:-0}
        root_attempts=${root_attempts:-0}
        invalid_users=${invalid_users:-0}

        local failed_color="$GREEN"
        [ "$failed_today" -gt 10 ] && failed_color="$RED"

        local root_color="$GREEN"
        [ "$root_attempts" -gt 0 ] && root_color="$RED"

        local invalid_color="$GREEN"
        [ "$invalid_users" -gt 5 ] && invalid_color="$YELLOW"

        print_key_value "Failed Logins (today)" "$failed_today" "$failed_color"
        print_key_value "Successful Logins (today)" "$success_today" "$GREEN"
        print_key_value "Root Login Attempts" "$root_attempts" "$root_color"
        print_key_value "Invalid User Attempts" "$invalid_users" "$invalid_color"

        if [ "$failed_today" -gt 0 ]; then
            echo ""
            echo -e "    ${BOLD}Top Attacking IPs (today):${NC}"
            grep "Failed password" /var/log/auth.log 2>/dev/null | grep -E "$today_date|$today_iso" | \
                grep -oP 'from \K[0-9.]+' | sort | uniq -c | sort -rn | head -5 | \
                while read -r count ip; do
                    [ -n "$ip" ] && echo -e "      ${RED}• ${ip}${NC} (${count} attempts)"
                done
        fi
    else
        print_info "Auth log not available (systemd journal in use)"
        local journal_failed
        journal_failed=$(journalctl -u ssh -u sshd --since today 2>/dev/null | grep "Failed password" | awk 'END {print NR}')
        journal_failed=${journal_failed:-0}
        print_key_value "Failed SSH Logins (today)" "$journal_failed"
    fi
    echo ""
    
    # ---- System Resources ----
    print_subsection "System Resources"
    local disk_usage
    disk_usage=$(df -h / 2>/dev/null | awk 'NR==2 {print $5}')
    local disk_num
    disk_num=$(echo "$disk_usage" | tr -d '%')
    local disk_color="$GREEN"
    [ "$disk_num" -ge 80 ] 2>/dev/null && disk_color="$YELLOW"
    [ "$disk_num" -ge 90 ] 2>/dev/null && disk_color="$RED"
    print_key_value "Disk Usage (/)" "$disk_usage" "$disk_color"

    local mem_info
    mem_info=$(free -h 2>/dev/null | awk 'NR==2 {printf "%s / %s (%.0f%%)", $3, $2, $3/$2*100}')
    print_key_value "Memory Usage" "$mem_info"

    local swap_info
    swap_info=$(free -h 2>/dev/null | awk 'NR==3 {printf "%s / %s", $3, $2}')
    print_key_value "Swap Usage" "$swap_info"

    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    print_key_value "Load Average" "$load_avg"

    local cpu_cores
    cpu_cores=$(nproc 2>/dev/null || echo "?")
    print_key_value "CPU Cores" "$cpu_cores"

    local proc_count
    proc_count=$(ps aux 2>/dev/null | wc -l || echo "?")
    print_key_value "Running Processes" "$proc_count"
    echo ""

    # ---- Reboot Status ----
    print_subsection "System Status"
    if [ -f /var/run/reboot-required ]; then
        print_check "Reboot Required" "warn" "yes"
        if [ -f /var/run/reboot-required.pkgs ]; then
            echo -e "    ${DIM}Packages: $(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ', ' | sed 's/,$//')${NC}"
        fi
    else
        print_check "Reboot Required" "ok" "no"
    fi

    local last_reboot
    last_reboot=$(who -b 2>/dev/null | awk '{print $3, $4}' || echo "unknown")
    print_key_value "Last Reboot" "$last_reboot"
    echo ""

    print_separator
    echo -e "  ${DIM}Dashboard generated: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "  ${DIM}Log file: ${LOG_FILE}${NC}"
    echo -e "  ${DIM}Backups:  ${BACKUP_DIR}${NC}"
    echo ""
    set -u  # Restore nounset
}

# ============================================================================
# REPORT GENERATION
# ============================================================================

# ----------------------------------------------------------------------------
# Function: generate_report
# Purpose: Generate a comprehensive hardening session report
# ----------------------------------------------------------------------------
generate_report() {
    print_step "Generating comprehensive hardening report..."

    local end_time
    end_time=$(date +%s)
    local total_duration=$(( end_time - SCRIPT_START_TIME ))
    local minutes=$(( total_duration / 60 ))
    local seconds=$(( total_duration % 60 ))

    set +u  # Prevent unbound array checks under empty parameters
    {
        echo "================================================================"
        echo "  VPS HARDENING SESSION REPORT"
        echo "  Script Version: ${SCRIPT_VERSION}"
        echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "================================================================"
        echo ""
        echo "SYSTEM INFORMATION"
        echo "  Hostname:     $(hostname)"
        echo "  FQDN:         ${HOSTNAME_FQDN}"
        echo "  OS:           ${OS_NAME}"
        echo "  Kernel:       ${KERNEL_VERSION}"
        echo "  Architecture: ${ARCH}"
        echo "  IP Address:   ${PRIMARY_IP}"
        echo ""
        echo "SESSION STATISTICS"
        echo "  Duration:     ${minutes}m ${seconds}s"
        echo "  Completed:    ${#COMPLETED_TASKS[@]} tasks"
        echo "  Failed:       ${#FAILED_TASKS[@]} tasks"
        echo "  Skipped:      ${#SKIPPED_TASKS[@]} tasks"
        echo "  Warnings:     ${TOTAL_WARNINGS}"
        echo "  Errors:       ${TOTAL_ERRORS}"
        echo "  Actions:      ${TOTAL_ACTIONS}"
        echo ""

        if [ ${#COMPLETED_TASKS[@]} -gt 0 ]; then
            echo "COMPLETED TASKS"
            local task
            for task in "${!COMPLETED_TASKS[@]}"; do
                local duration="${TASK_DURATIONS[$task]:-N/A}"
                echo "  ✔ ${task} (${COMPLETED_TASKS[$task]}) [${duration}]"
            done
            echo ""
        fi

        if [ ${#FAILED_TASKS[@]} -gt 0 ]; then
            echo "FAILED TASKS"
            for task in "${!FAILED_TASKS[@]}"; do
                echo "  ✘ ${task}: ${FAILED_TASKS[$task]}"
            done
            echo ""
        fi

        if [ ${#SKIPPED_TASKS[@]} -gt 0 ]; then
            echo "SKIPPED TASKS"
            for task in "${!SKIPPED_TASKS[@]}"; do
                echo "  - ${task}: ${SKIPPED_TASKS[$task]}"
            done
            echo ""
        fi

        echo "SSH ACCESS"
        [ -n "$SSH_PORT" ] && echo "  Port: ${SSH_PORT}" || echo "  Port: unchanged"
        echo "  User: ${TARGET_USER}"
        echo "  Command: ssh -p ${SSH_PORT:-22} ${TARGET_USER}@${PRIMARY_IP}"
        echo ""

        echo "CONFIGURATION BACKUPS"
        echo "  Location: ${BACKUP_DIR}"
        if [ -d "$BACKUP_DIR" ]; then
            local backup_count
            backup_count=$(find "$BACKUP_DIR" -type f 2>/dev/null | wc -l)
            echo "  Files backed up: ${backup_count}"
        fi
        echo ""

        echo "LOG FILES"
        echo "  Script log:    ${LOG_FILE}"
        echo "  System log:    /var/log/syslog"
        echo "  Auth log:      /var/log/auth.log"
        echo "  Audit log:     /var/log/audit/audit.log"
        echo "  Fail2ban log:  /var/log/fail2ban.log"
        echo ""

        if [ -f "$TG_CONFIG" ]; then
            echo "TELEGRAM BOT"
            echo "  Status: $(systemctl is-active "$TG_BOT_SERVICE" 2>/dev/null || echo 'inactive')"
            echo "  Config: ${TG_CONFIG}"
            echo ""
        fi

        echo "RECOMMENDED NEXT STEPS"
        echo "  1. Test SSH login in a NEW terminal before closing this session"
        echo "  2. Run 'lynis audit system' for a full CIS benchmark audit"
        echo "  3. Set up Telegram bot notifications (menu option 40)"
        echo "  4. Take a VPS snapshot via your hosting provider's dashboard"
        echo "  5. Schedule a reboot to apply all kernel changes"
        echo "  6. Review this report and the log file for any issues"
        echo ""
        echo "================================================================"
        echo "  End of Report"
        echo "================================================================"
    } > "$REPORT_FILE"
    set -u

    chmod 600 "$REPORT_FILE"
    chown root:root "$REPORT_FILE"
    print_status "Report saved to: ${REPORT_FILE}"
}

# ============================================================================
# BATCH OPERATIONS
# ============================================================================

# ----------------------------------------------------------------------------
# Function: run_tier0_essential
# Purpose: Execute all Tier 0 essential hardening tasks in sequence
# ----------------------------------------------------------------------------
run_tier0_essential() {
    print_section "BATCH: TIER 0 ESSENTIAL HARDENING"
    print_info "This will execute 7 tasks in sequence."
    echo ""
    
    if ! confirm "Proceed with Tier 0 batch execution?"; then
        print_info "Batch operation cancelled"
        return 0
    fi

    local task_num=0
    local total_tasks=7

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "System Update"
    system_update

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "SSH Hardening"
    harden_ssh

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Firewall"
    configure_firewall

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Fail2ban"
    setup_fail2ban

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Kernel"
    kernel_hardening

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Auto-Updates"
    setup_auto_updates

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "User Setup"
    setup_user_account

    echo ""
    print_success_box "TIER 0 ESSENTIAL HARDENING COMPLETE"
}

run_tier0_plus_tier1() {
    print_section "BATCH: TIER 0 + TIER 1 HARDENING"
    print_info "This will execute 13 hardening tasks across Tier 0 and Tier 1."
    echo ""

    if ! confirm "Proceed with Tier 0+1 batch execution?"; then
        print_info "Batch operation cancelled"
        return 0
    fi

    local task_num=0
    local total_tasks=13

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "System Update"
    system_update

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "SSH"
    harden_ssh

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Firewall"
    configure_firewall

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Fail2ban"
    setup_fail2ban

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Kernel"
    kernel_hardening

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Auto-Updates"
    setup_auto_updates

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "User Setup"
    setup_user_account

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "/dev/shm"
    secure_shared_memory

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Protocols"
    disable_unused_protocols

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "AppArmor"
    setup_apparmor

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "AIDE"
    setup_aide

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Auditd"
    setup_auditd

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "/tmp"
    secure_tmp_directories

    echo ""
    print_success_box "TIER 0 + TIER 1 HARDENING COMPLETE"
}

run_full_hardening() {
    print_section "BATCH: FULL HARDENING (TIER 0 + 1 + 2)"
    print_info "This will execute 22 hardening tasks across all three tiers."
    echo ""

    if ! confirm "Proceed with FULL batch execution?"; then
        print_info "Batch operation cancelled"
        return 0
    fi

    local task_num=0
    local total_tasks=22

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "System Update"
    system_update

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "SSH"
    harden_ssh

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Firewall"
    configure_firewall

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Fail2ban"
    setup_fail2ban

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Kernel"
    kernel_hardening

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Auto-Updates"
    setup_auto_updates

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "User Setup"
    setup_user_account

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "/dev/shm"
    secure_shared_memory

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Protocols"
    disable_unused_protocols

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "AppArmor"
    setup_apparmor

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "AIDE"
    setup_aide

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Auditd"
    setup_auditd

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "/tmp"
    secure_tmp_directories

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Resource Limits"
    setup_resource_limits

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Services"
    disable_unnecessary_services

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Cron/At"
    restrict_cron_at

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "DNS over TLS"
    setup_dns_over_tls

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Login Security"
    setup_login_security

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "User Hardening"
    setup_user_hardening

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Lynis"
    install_lynis

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Log Forwarding"
    setup_log_forwarding

    task_num=$((task_num + 1)); print_progress $task_num $total_tasks "Kernel Lockdown"
    setup_kernel_lockdown

    echo ""
    print_success_box "FULL HARDENING (TIER 0+1+2) COMPLETE"
}
# End of Section 9
# ============================================================================
# INTERACTIVE MENU SYSTEM
# ============================================================================

# ============================================================================
# INTERACTIVE MENU SYSTEM
# ============================================================================

# ----------------------------------------------------------------------------
# Function: show_menu
# Purpose: Display the main interactive menu with all hardening options
# ----------------------------------------------------------------------------
show_menu() {
    clear
    echo ""
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════════════╗
    ║                                                                      ║
    ║          VPS HARDENING SCRIPT - INTERACTIVE MENU v3.1.0              ║
    ║                                                                      ║
    ║              Fully Enhanced Edition + Telegram Bot                   ║
    ║                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo ""

    # Tier 0
    echo -e "  ${GREEN}${BOLD}━━━ TIER 0: ESSENTIAL HARDENING ━━━${NC}"
    echo -e "   ${WHITE} 1)${NC} System Update & Cleanup"
    echo -e "   ${WHITE} 2)${NC} SSH Hardening (with lockout prevention)"
    echo -e "   ${WHITE} 3)${NC} Firewall Configuration (UFW)"
    echo -e "   ${WHITE} 4)${NC} Fail2ban Setup"
    echo -e "   ${WHITE} 5)${NC} Kernel Hardening (sysctl)"
    echo -e "   ${WHITE} 6)${NC} Automatic Security Updates"
    echo -e "   ${WHITE} 7)${NC} User Account & Sudo Setup"
    echo ""

    # Tier 1
    echo -e "  ${YELLOW}${BOLD}━━━ TIER 1: HIGH IMPACT DEFENSES ━━━${NC}"
    echo -e "   ${WHITE} 8)${NC} Secure Shared Memory (/dev/shm)"
    echo -e "   ${WHITE} 9)${NC} Disable Unused Network Protocols"
    echo -e "   ${WHITE}10)${NC} AppArmor (Mandatory Access Control)"
    echo -e "   ${WHITE}11)${NC} File Integrity Monitoring (AIDE)"
    echo -e "   ${WHITE}12)${NC} Kernel Audit Daemon (auditd)"
    echo -e "   ${WHITE}13)${NC} Secure Temporary Directories"
    echo ""

    # Tier 2
    echo -e "  ${MAGENTA}${BOLD}━━━ TIER 2: ADVANCED SECURITY CONTROLS ━━━${NC}"
    echo -e "   ${WHITE}14)${NC} Resource Limits & Fork Bomb Protection"
    echo -e "   ${WHITE}15)${NC} Disable Unnecessary Services"
    echo -e "   ${WHITE}16)${NC} Restrict Cron & At Access"
    echo -e "   ${WHITE}17)${NC} DNS over TLS (Encrypted DNS)"
    echo -e "   ${WHITE}18)${NC} Login & Password Security"
    echo -e "   ${WHITE}19)${NC} User Account Hardening"
    echo -e "   ${WHITE}20)${NC} Security Auditing (Lynis)"
    echo -e "   ${WHITE}21)${NC} Log Forwarding (Anti-Tampering)"
    echo -e "   ${WHITE}22)${NC} Kernel Lockdown & Module Restrictions"
    echo ""

    # Tier 3
    echo -e "  ${RED}${BOLD}━━━ TIER 3: ZERO TRUST NETWORKING ━━━${NC}"
    echo -e "   ${WHITE}23)${NC} Tailscale VPN (recommended)"
    echo -e "   ${WHITE}24)${NC} Single Packet Authorization (fwknop)"
    echo ""

    # Telegram
    echo -e "  ${TEAL}${BOLD}━━━ TELEGRAM BOT ━━━${NC}"
    echo -e "   ${WHITE}40)${NC} Setup Interactive Telegram Bot"
    echo -e "   ${WHITE}41)${NC} Manage Telegram Bot"
    echo ""

    # Batch
    echo -e "  ${ORANGE}${BOLD}━━━ BATCH OPERATIONS ━━━${NC}"
    echo -e "   ${WHITE}30)${NC} Run ALL Tier 0 (Essential - 7 tasks)"
    echo -e "   ${WHITE}31)${NC} Run Tier 0 + Tier 1 (13 tasks)"
    echo -e "   ${WHITE}32)${NC} Run Full Hardening Tier 0+1+2 (22 tasks)"
    echo ""

    # Utilities
    echo -e "  ${BLUE}${BOLD}━━━ INFORMATION & UTILITIES ━━━${NC}"
    echo -e "   ${WHITE} s)${NC} Show Security Status Dashboard"
    echo -e "   ${WHITE} r)${NC} Generate Hardening Report"
    echo -e "   ${WHITE} l)${NC} View Log File"
    echo -e "   ${WHITE} b)${NC} List Configuration Backups"
    echo -e "   ${WHITE} q)${NC} Quit"
    echo ""
    print_separator
    echo ""
}

# ============================================================================
# MAIN EXECUTION LOOP
# ============================================================================

# ----------------------------------------------------------------------------
# Function: main
# Purpose: Main execution flow - initialization, menu loop, exit handling
# ----------------------------------------------------------------------------
main() {
    # ---- Pre-Flight Checks ----
    check_root
    acquire_lock
    init_logging
    print_banner

    # ---- System Detection ----
    detect_os
    check_internet
    create_backup_dir

    # ---- Load Previous State ----
    if [ -f "$STATE_FILE" ]; then
        SSH_PORT=$(load_state "SSH_PORT")
        local saved_user
        saved_user=$(load_state "ADMIN_USER")
        if [ -n "$saved_user" ]; then
            TARGET_USER="$saved_user"
            USER_HOME="$(eval echo "~${TARGET_USER}")"
        fi
        print_info "Previous session state loaded"
    fi

    # ---- Initial Backup ----
    if confirm "Create a comprehensive backup of all critical configurations before starting?" "y"; then
        backup_critical_configs
    fi

    echo ""
    print_info "Press Enter to open the main menu..."
    read -r

    # ---- Main Menu Loop ----
    while true; do
        show_menu
        echo -ne "  ${BOLD}${MAGENTA}Select option: ${NC}"
        read -r choice
        echo ""

        case "$choice" in
            # ---- Tier 0: Essential ----
            1)
                system_update
                ;;
            2)
                harden_ssh
                ;;
            3)
                configure_firewall
                ;;
            4)
                setup_fail2ban
                ;;
            5)
                kernel_hardening
                ;;
            6)
                setup_auto_updates
                ;;
            7)
                setup_user_account
                ;;

            # ---- Tier 1: High Impact ----
            8)
                secure_shared_memory
                ;;
            9)
                disable_unused_protocols
                ;;
            10)
                setup_apparmor
                ;;
            11)
                setup_aide
                ;;
            12)
                setup_auditd
                ;;
            13)
                secure_tmp_directories
                ;;

            # ---- Tier 2: Advanced ----
            14)
                setup_resource_limits
                ;;
            15)
                disable_unnecessary_services
                ;;
            16)
                restrict_cron_at
                ;;
            17)
                setup_dns_over_tls
                ;;
            18)
                setup_login_security
                ;;
            19)
                setup_user_hardening
                ;;
            20)
                install_lynis
                ;;
            21)
                setup_log_forwarding
                ;;
            22)
                setup_kernel_lockdown
                ;;

            # ---- Tier 3: Zero Trust ----
            23)
                setup_tailscale
                ;;
            24)
                setup_fwknop
                ;;

            # ---- Batch Operations ----
            30)
                run_tier0_essential
                ;;
            31)
                run_tier0_plus_tier1
                ;;
            32)
                run_full_hardening
                ;;

            # ---- Telegram Bot ----
            40)
                setup_telegram_interactive
                ;;
            41)
                telegram_bot_manage
                ;;

            # ---- Information & Utilities ----
            s|S)
                show_security_status
                ;;
            r|R)
                generate_report
                echo ""
                if confirm "View the report now?"; then
                    less "$REPORT_FILE"
                fi
                ;;
            l|L)
                if [ -f "$LOG_FILE" ]; then
                    print_info "Opening log file: ${LOG_FILE}"
                    less "$LOG_FILE"
                else
                    print_error "Log file not found: ${LOG_FILE}"
                fi
                ;;
            b|B)
                print_section "CONFIGURATION BACKUPS"
                if [ -d "$BACKUP_ROOT" ]; then
                    print_info "Backup root directory: ${BACKUP_ROOT}"
                    echo ""
                    echo -e "  ${BOLD}Available backup sessions:${NC}"
                    ls -lah "$BACKUP_ROOT/" 2>/dev/null | tail -20
                    echo ""
                    print_info "Current session backups: ${BACKUP_DIR}"
                    if [ -d "$BACKUP_DIR" ]; then
                        local file_count
                        file_count=$(find "$BACKUP_DIR" -type f 2>/dev/null | wc -l)
                        local dir_size
                        dir_size=$(du -sh "$BACKUP_DIR" 2>/dev/null | awk '{print $1}')
                        print_info "Files: ${file_count} | Size: ${dir_size}"
                    fi
                else
                    print_warning "No backups found"
                fi
                ;;

            # ---- Quit ----
            q|Q|quit|exit)
                # Generate final report
                print_section "HARDENING SESSION COMPLETE"
                generate_report

                # Session summary
                local end_time
                end_time=$(date +%s)
                local total_duration=$(( end_time - SCRIPT_START_TIME ))
                local minutes=$(( total_duration / 60 ))
                local seconds=$(( total_duration % 60 ))

                echo ""
                print_thick_separator
                echo -e "  ${BOLD}Session Summary:${NC}"
                echo -e "    ${BOLD}Duration:${NC}       ${minutes}m ${seconds}s"
                
                # Wrap arrays in set +u to prevent crash on exit
                set +u
                echo -e "    ${BOLD}Completed:${NC}      ${GREEN}${#COMPLETED_TASKS[@]} tasks${NC}"
                echo -e "    ${BOLD}Failed:${NC}         ${RED}${#FAILED_TASKS[@]} tasks${NC}"
                echo -e "    ${BOLD}Skipped:${NC}        ${YELLOW}${#SKIPPED_TASKS[@]} tasks${NC}"
                echo -e "    ${BOLD}Warnings:${NC}       ${TOTAL_WARNINGS}"
                echo -e "    ${BOLD}Errors:${NC}         ${TOTAL_ERRORS}"
                echo -e "    ${BOLD}Total Actions:${NC}  ${TOTAL_ACTIONS}"
                print_thick_separator
                echo ""

                # Completed tasks list
                if [ ${#COMPLETED_TASKS[@]} -gt 0 ]; then
                    print_info "Completed tasks:"
                    local task
                    for task in "${!COMPLETED_TASKS[@]}"; do
                        local dur="${TASK_DURATIONS[$task]:-N/A}"
                        echo -e "    ${GREEN}✔${NC} ${task} ${DIM}(${dur})${NC}"
                    done
                    echo ""
                fi

                # Failed tasks list
                if [ ${#FAILED_TASKS[@]} -gt 0 ]; then
                    print_warning "Failed tasks:"
                    for task in "${!FAILED_TASKS[@]}"; do
                        echo -e "    ${RED}✘${NC} ${task}: ${FAILED_TASKS[$task]}"
                    done
                    echo ""
                fi
                set -u

                # File locations
                print_info "Session files:"
                echo -e "    ${CYAN}Log:${NC}       ${LOG_FILE}"
                echo -e "    ${CYAN}Report:${NC}    ${REPORT_FILE}"
                echo -e "    ${CYAN}Backups:${NC}   ${BACKUP_DIR}"
                echo -e "    ${CYAN}State:${NC}     ${STATE_FILE}"
                echo ""

                # SSH warning
                if [ -n "$SSH_PORT" ]; then
                    print_warning_box "IMPORTANT: SSH port has been changed to ${SSH_PORT}"
                    echo -e "  ${BOLD}Test your connection in a NEW terminal before closing:${NC}"
                    echo -e "    ${CYAN}ssh -p ${SSH_PORT} ${TARGET_USER}@${PRIMARY_IP}${NC}"
                    echo ""
                fi

                # Recommended next steps
                print_info "Recommended Next Steps:"
                echo -e "    ${CYAN}1.${NC} Test SSH login in a ${RED}NEW terminal${NC} before closing this session"
                echo -e "    ${CYAN}2.${NC} Run: ${BOLD}lynis audit system${NC} for a full CIS benchmark audit"
                echo -e "    ${CYAN}3.${NC} Set up Telegram bot notifications (menu option 40)"
                echo -e "    ${CYAN}4.${NC} Take a VPS snapshot via your hosting provider's dashboard"
                echo -e "    ${CYAN}5.${NC} Schedule a reboot to apply all kernel and module changes"
                echo -e "    ${CYAN}6.${NC} Review the full report: ${BOLD}cat ${REPORT_FILE}${NC}"
                echo ""

                # Reboot check
                if [ -f /var/run/reboot-required ]; then
                    print_warning_box "A SYSTEM REBOOT IS REQUIRED to apply all changes"
                    echo -e "  ${BOLD}Reboot command:${NC} ${CYAN}sudo reboot${NC}"
                    echo ""
                    if [ -f /var/run/reboot-required.pkgs ]; then
                        print_info "Packages requiring reboot:"
                        cat /var/run/reboot-required.pkgs 2>/dev/null | while IFS= read -r pkg_line; do
                            echo -e "    ${GRAY}• ${pkg_line}${NC}"
                        done
                        echo ""
                    fi
                fi

                # Final message
                echo ""
                echo -e "  ${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
                echo -e "  ${GREEN}${BOLD}║                                                          ║${NC}"
                echo -e "  ${GREEN}${BOLD}║   Thank you for using VPS Hardening Script v${SCRIPT_VERSION}!   ║${NC}"
                echo -e "  ${GREEN}${BOLD}║                                                          ║${NC}"
                echo -e "  ${GREEN}${BOLD}║   Stay secure. Stay vigilant. 🔒🛡️                        ║${NC}"
                echo -e "  ${GREEN}${BOLD}║                                                          ║${NC}"
                echo -e "  ${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
                echo ""

                release_lock
                exit 0
                ;;

            # ---- Invalid Input ----
            *)
                print_error "Invalid option: '${choice}'"
                print_info "Please select a valid option from the menu (1-24, 30-32, 40-41, s/r/l/b/q)"
                ;;
        esac

        # Pause before returning to menu (except for quit)
        if [[ "$choice" != "q" && "$choice" != "Q" && "$choice" != "quit" && "$choice" != "exit" ]]; then
            pause
        fi
    done
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

# Run main function with all command-line arguments
main "$@"

# ============================================================================
# END OF VPS HARDENING SCRIPT v3.1.0 - FULLY ENHANCED EDITION
# ============================================================================
