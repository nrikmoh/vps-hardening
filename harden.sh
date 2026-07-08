#!/bin/bash
# =============================================================================
# VPS Hardening Script v5.1
# Supports: Ubuntu 20.04, 22.04, 24.04
# Providers: Oracle, AWS, DigitalOcean, Hetzner, Linode, Vultr, GCP, Azure
# Usage: sudo ./harden.sh [--resume] [--skip PHASE] [--only PHASE] [--no-color]
# =============================================================================

set -euo pipefail

# =============================================================================
# VERSION & PATHS
# =============================================================================

VPS_VERSION="5.0.0"
VPS_STATE_DIR="/var/lib/vps-hardening"
VPS_LOG_DIR="/var/log/vps-hardening"
VPS_STATE_FILE="${VPS_STATE_DIR}/state"
VPS_INSTALL_LOG="${VPS_LOG_DIR}/install.log"

# =============================================================================
# CLI FLAGS
# =============================================================================

RESUME_MODE=false
SKIP_PHASES=()
ONLY_PHASE=""
NO_COLOR=${NO_COLOR:-0}
DRY_RUN=false
VERBOSE=false

usage() {
    cat << EOF
Usage: sudo ./harden.sh [OPTIONS]

Options:
  --resume          Resume from last completed phase
  --skip PHASE_ID   Skip a phase (e.g. --skip 07)
  --only PHASE_ID   Run only one phase
  --no-color        Disable colors
  --dry-run         Show what would be done without making changes
  --verbose         Extra output
  --version         Print version
  --help            This help text

Phase IDs: 01 02 03 04 05 06 07 08 09 10 11 12 13 14
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --resume)    RESUME_MODE=true ;;
        --skip)      SKIP_PHASES+=("$2"); shift ;;
        --only)      ONLY_PHASE="$2"; shift ;;
        --no-color)  NO_COLOR=1 ;;
        --dry-run)   DRY_RUN=true ;;
        --verbose)   VERBOSE=true ;;
        --version)   echo "vps-hardening ${VPS_VERSION}"; exit 0 ;;
        --help|-h)   usage; exit 0 ;;
        *)           echo "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

# =============================================================================
# COLORS
# =============================================================================

if [[ -t 1 ]] && [[ "${NO_COLOR}" != "1" ]] && [[ "${TERM:-}" != "dumb" ]]; then
    _COLOR=1
else
    _COLOR=0
fi

_c() { [[ "$_COLOR" -eq 1 ]] && echo -ne "\033[${1}m" || true; }

RED="$(_c '0;31')"
YELLOW="$(_c '1;33')"
GREEN="$(_c '0;32')"
BLUE="$(_c '0;34')"
CYAN="$(_c '0;36')"
MAGENTA="$(_c '0;35')"
WHITE="$(_c '1;37')"
BOLD="$(_c '1')"
DIM="$(_c '2')"
ITALIC="$(_c '3')"
NC="$(_c '0')"

SPINNER_CHARS='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

# =============================================================================
# LOGGING
# =============================================================================

_log_raw() {
    local LEVEL="$1" MSG="$2"
    local TS
    TS=$(date '+%Y-%m-%dT%H:%M:%S')
    echo "${TS} [${LEVEL}] ${MSG}" >> "${VPS_INSTALL_LOG}" 2>/dev/null || true
}

log_ok()    { echo -e "  ${GREEN}✓${NC}  $1"; _log_raw "OK"    "$1"; }
log_warn()  { echo -e "  ${YELLOW}⚠${NC}  $1"; _log_raw "WARN"  "$1"; }
log_error() { echo -e "  ${RED}✗${NC}  $1" >&2; _log_raw "ERROR" "$1"; }
log_info()  { echo -e "  ${BLUE}ℹ${NC}  $1"; _log_raw "INFO"  "$1"; }
log_step()  { echo -e "  ${CYAN}→${NC}  $1"; _log_raw "STEP"  "$1"; }
log_tip()   { echo -e "  ${MAGENTA}💡${NC} $1"; _log_raw "TIP"   "$1"; }
log_verbose() { [[ "$VERBOSE" == "true" ]] && echo -e "  ${DIM}   $1${NC}" || true; }

die() {
    local MSG="${1:-Fatal error}" CODE="${2:-1}"
    log_error "$MSG"
    _log_raw "FATAL" "$MSG (exit $CODE)"
    cleanup_on_exit
    exit "$CODE"
}

# =============================================================================
# DRY RUN WRAPPER
# =============================================================================

dry_run_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${DIM}[DRY-RUN]${NC} $*"
        return 0
    fi
    "$@"
}

# =============================================================================
# PROGRESS BAR
# =============================================================================

TOTAL_PHASES=14
CURRENT_PHASE_NUM=0

draw_progress() {
    local CURRENT="$1" TOTAL="$2" LABEL="${3:-}"
    local PCT=$(( CURRENT * 100 / TOTAL ))
    local FILLED=$(( CURRENT * 40 / TOTAL ))
    local EMPTY=$(( 40 - FILLED ))
    local BAR=""

    for (( i=0; i<FILLED; i++ )); do BAR+="█"; done
    for (( i=0; i<EMPTY;  i++ )); do BAR+="░"; done

    # Precise mapping of 13 specifiers to 13 variables
    printf "\n  %sProgress%s  [%s%s%s] %s%d%%%s  %sPhase %d/%d%s  %s\n\n" \
        "${CYAN}" "${NC}" \
        "${GREEN}" "$BAR" "${NC}" \
        "${BOLD}" "$PCT" "${NC}" \
        "${DIM}" "$CURRENT" "$TOTAL" "${NC}" \
        "$LABEL"
}

# =============================================================================
# SPINNER / RUN_SILENT
# =============================================================================

spin() {
    local MSG="$1" PID="$2" EXIT_FILE="$3"
    local i=0 LEN=${#SPINNER_CHARS}

    if [[ "$_COLOR" -eq 1 ]]; then
        echo -ne "  ${CYAN}${SPINNER_CHARS:0:1}${NC}  $MSG"
        while kill -0 "$PID" 2>/dev/null; do
            i=$(( (i+1) % LEN ))
            echo -ne "\r  ${CYAN}${SPINNER_CHARS:$i:1}${NC}  $MSG"
            sleep 0.1
        done
        echo -ne "\r"
    else
        echo -n "  …  $MSG"
    fi

    wait "$PID" 2>/dev/null || true
    local CODE
    CODE=$(cat "$EXIT_FILE" 2>/dev/null || echo 1)

    if [[ "$CODE" -eq 0 ]]; then
        echo -e "  ${GREEN}✓${NC}  $MSG"
        _log_raw "OK" "$MSG"
    else
        echo -e "  ${RED}✗${NC}  $MSG ${RED}(failed — see ${VPS_INSTALL_LOG})${NC}"
        _log_raw "FAIL" "$MSG"
    fi
    return "$CODE"
}

run_silent() {
    local MSG="$1"; shift

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${DIM}[DRY-RUN]${NC}  $MSG"
        return 0
    fi

    local EXIT_FILE STDERR_FILE
    EXIT_FILE=$(mktemp)
    STDERR_FILE=$(mktemp)

    # Use an internal trap inside the subshell to intercept unexpected deaths
    ( 
      trap 'echo $? > "$EXIT_FILE"' EXIT
      DEBIAN_FRONTEND=noninteractive "$@" > /dev/null 2>"$STDERR_FILE"
    ) &
    local PID=$!

    spin "$MSG" "$PID" "$EXIT_FILE"
    local CODE=$?

    if [[ "$CODE" -ne 0 ]]; then
        echo "--- stderr for: $* ---" >> "${VPS_INSTALL_LOG}"
        cat "$STDERR_FILE"            >> "${VPS_INSTALL_LOG}"
        echo "--- end stderr ---"     >> "${VPS_INSTALL_LOG}"
    fi

    rm -f "$EXIT_FILE" "$STDERR_FILE"
    return "$CODE"
}
# =============================================================================
# TIMING TRACKER
# =============================================================================

declare -A PHASE_TIMES

phase_timer_start() {
    PHASE_TIMES["${1}_start"]=$(date +%s%N)
}

phase_timer_end() {
    local ID="$1"
    local END NOW START
    END=$(date +%s%N)
    START="${PHASE_TIMES["${ID}_start"]:-$END}"
    local MS=$(( (END - START) / 1000000 ))
    if [[ $MS -lt 1000 ]]; then
        PHASE_TIMES["${ID}_duration"]="${MS}ms"
    else
        PHASE_TIMES["${ID}_duration"]="$(( MS / 1000 ))s"
    fi
}

# =============================================================================
# APT WRAPPER
# =============================================================================

apt_get() {
    DEBIAN_FRONTEND=noninteractive \
    apt-get "$@" \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        -o APT::Get::Assume-Yes=true \
        -qq \
        > /dev/null 2>&1
}

apt_install() { apt_get install "$@"; }

# =============================================================================
# SERVICE HELPERS
# =============================================================================

service_exists() {
    systemctl list-unit-files "$1" 2>/dev/null | grep -q "$1" || \
    systemctl list-units --all "$1" 2>/dev/null | grep -q "$1"
}

service_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

wait_for_service() {
    local SVC="$1" MAX="${2:-20}" ELAPSED=0
    while ! service_active "$SVC"; do
        sleep 1; ELAPSED=$((ELAPSED+1))
        [[ "$ELAPSED" -ge "$MAX" ]] && return 1
    done
    return 0
}

mask_service() {
    systemctl stop    "$1" 2>/dev/null || true
    systemctl disable "$1" 2>/dev/null || true
    systemctl mask    "$1" 2>/dev/null || true
}

policy_block_start() {
    echo "exit 101" > /usr/sbin/policy-rc.d
    chmod +x /usr/sbin/policy-rc.d
}

policy_allow_start() { rm -f /usr/sbin/policy-rc.d; }

# =============================================================================
# STATE MANAGEMENT
# =============================================================================

state_set() {
    local KEY="$1" VALUE="$2"
    mkdir -p "$VPS_STATE_DIR"
    local TMP; TMP=$(mktemp)
    grep -v "^${KEY}=" "$VPS_STATE_FILE" 2>/dev/null > "$TMP" || true
    echo "${KEY}=${VALUE}" >> "$TMP"
    mv "$TMP" "$VPS_STATE_FILE"
    chmod 600 "$VPS_STATE_FILE"
}

state_get() {
    grep "^${1}=" "$VPS_STATE_FILE" 2>/dev/null \
        | tail -1 | cut -d= -f2-
}

state_has() { local V; V=$(state_get "$1"); [[ -n "$V" ]]; }

phase_done()     { state_set "phase_${1}" "done"; }
phase_complete() { [[ "$(state_get "phase_${1}")" == "done" ]]; }

# =============================================================================
# NETWORK HELPERS
# =============================================================================

get_public_ip() {
    local IP ENDPOINTS
    ENDPOINTS=(
        "https://ifconfig.me"
        "https://icanhazip.com"
        "https://api.ipify.org"
        "https://ipecho.net/plain"
    )
    for EP in "${ENDPOINTS[@]}"; do
        if IP=$(curl -s --max-time 5 --retry 2 "$EP" 2>/dev/null) \
           && [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$IP"; return 0
        fi
    done
    log_warn "Could not detect public IP." >&2
    echo "YOUR_SERVER_IP"
}

get_geo_info() {
    local IP="${1:-}"
    local GEO
    GEO=$(curl -s --max-time 5 "https://ipapi.co/${IP}/json/" 2>/dev/null || echo "{}")
    
    # Safely extract values using sed instead of grep -oP to ensure cross-compatibility
    local COUNTRY; COUNTRY=$(echo "$GEO" | sed -n 's/.*"country_name": *"\([^"]*\)".*/\1/p')
    local CITY;    CITY=$(echo "$GEO" | sed -n 's/.*"city": *"\([^"]*\)".*/\1/p')
    local ORG;     ORG=$(echo "$GEO" | sed -n 's/.*"org": *"\([^"]*\)".*/\1/p')

    # Fallback default assignments if strings evaluate empty
    echo "${CITY:-Unknown}, ${COUNTRY:-Unknown} (${ORG:-Unknown})"
}

# =============================================================================
# REBOOT DETECTION
# =============================================================================

REBOOT_REQUIRED=false

check_reboot_required() {
    local KERNEL_BEFORE="${1:-$(uname -r)}"

    if [[ -f /var/run/reboot-required ]]; then
        REBOOT_REQUIRED=true
        local PKGS=""
        [[ -f /var/run/reboot-required.pkgs ]] \
            && PKGS=$(cat /var/run/reboot-required.pkgs | tr '\n' ' ')
        log_warn "Reboot required${PKGS:+ for: $PKGS}"
        state_set "reboot_required" "true"
        state_set "reboot_reason" "${PKGS:-reboot-required flag}"
        return
    fi

    local NEWEST
    NEWEST=$(dpkg -l 'linux-image-*' 2>/dev/null \
        | grep "^ii" \
        | awk '{print $2}' \
        | grep -v "linux-image-generic" \
        | sort -V | tail -1 \
        | sed 's/linux-image-//' || echo "")

    if [[ -n "$NEWEST" ]] && [[ "$KERNEL_BEFORE" != *"$NEWEST"* ]]; then
        REBOOT_REQUIRED=true
        log_warn "New kernel: $NEWEST (running: $KERNEL_BEFORE) — reboot needed"
        state_set "reboot_required" "true"
        state_set "reboot_reason"   "kernel: $NEWEST"
        return
    fi

    if [[ -f /var/run/reboot-required.pkgs ]] \
       && [[ -s /var/run/reboot-required.pkgs ]]; then
        REBOOT_REQUIRED=true
        local PKGS
        PKGS=$(cat /var/run/reboot-required.pkgs | tr '\n' ' ')
        log_warn "Reboot required for: $PKGS"
        state_set "reboot_required" "true"
        state_set "reboot_reason"   "packages: $PKGS"
        return
    fi

    log_ok "No reboot required — kernel is current"
}

# =============================================================================
# SUID / SSH SOCKET HELPERS
# =============================================================================

safe_find_suid() {
    local RESULT
    RESULT=$(find / -perm -4000 -type f 2>/dev/null \
        | grep -v -E '/(snap|proc|sys)/' | sort || true)
    [[ -z "$RESULT" ]] \
        && log_warn "SUID scan returned no results." >&2
    echo "$RESULT"
}

apply_ssh_socket_fix() {
    local SOCKET_EXISTS=false
    systemctl list-units --all 2>/dev/null | grep -q "ssh.socket" \
        && SOCKET_EXISTS=true || true
    [[ -f /lib/systemd/system/ssh.socket ]]     && SOCKET_EXISTS=true || true
    [[ -f /usr/lib/systemd/system/ssh.socket ]] && SOCKET_EXISTS=true || true

    if [[ "$SOCKET_EXISTS" == "true" ]]; then
        log_step "Disabling SSH socket activation (Ubuntu 24.04)"
        mask_service ssh.socket
        systemctl enable ssh.service 2>/dev/null || true
        log_ok "SSH socket activation disabled"
    fi
    [[ ! -d /run/sshd ]] && { mkdir -p /run/sshd; chmod 755 /run/sshd; }
}

# =============================================================================
# CLEANUP / TRAP
# =============================================================================

_TEMP_FILES=()
register_temp() { _TEMP_FILES+=("$1"); }

cleanup_on_exit() {
    for F in "${_TEMP_FILES[@]:-}"; do rm -f "$F" 2>/dev/null || true; done
    rm -f /usr/sbin/policy-rc.d 2>/dev/null || true
    exec >&- 2>&-
    wait 2>/dev/null || true
}

trap 'cleanup_on_exit' EXIT

# =============================================================================
# PRECONDITION CHECKS
# =============================================================================

if [[ $EUID -ne 0 ]]; then
    echo -e "  ${RED}✗${NC}  Root required. Run: ${CYAN}sudo ./harden.sh${NC}"
    exit 1
fi

# =============================================================================
# UI HELPERS
# =============================================================================

print_banner() {
    clear
    echo ""
    if [[ "$_COLOR" -eq 1 ]]; then
        echo $'\033[1;37m╔══════════════════════════════════════════════════════════╗\033[0m'
        echo $'\033[1;37m║                                                          ║\033[0m'
        echo $'\033[1;37m║   🛡️   VPS HARDENING SCRIPT  v5.1.0                     ║\033[0m'
        echo $'\033[2m║    Production-grade server security in one script       ║\033[0m'
        echo $'\033[1;37m║                                                          ║\033[0m'
        echo $'\033[1;37m╚══════════════════════════════════════════════════════════╝\033[0m'
    else
        echo "  ╔══════════════════════════════════════════════════════════╗"
        echo "  ║   VPS HARDENING SCRIPT  v${VPS_VERSION}                      ║"
        echo "  ╚══════════════════════════════════════════════════════════╝"
    fi
    echo -e "  ${DIM}Ubuntu 20.04 / 22.04 / 24.04${NC}"
    echo -e "  ${DIM}Oracle · AWS · DigitalOcean · Hetzner · Linode · Vultr · GCP · Azure${NC}"
    [[ "$DRY_RUN"  == "true" ]] && echo -e "  ${YELLOW}⚠  DRY-RUN MODE — no changes will be made${NC}"
    [[ "$VERBOSE"  == "true" ]] && echo -e "  ${BLUE}ℹ  VERBOSE MODE active${NC}"
    echo ""
}

print_phase() {
    local NUM="$1" TITLE="$2" DESC="${3:-}"
    CURRENT_PHASE_NUM=$((CURRENT_PHASE_NUM + 1))
    draw_progress "$CURRENT_PHASE_NUM" "$TOTAL_PHASES" "$TITLE"
    echo -e "  ${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}${WHITE}  Phase $NUM${NC}  ${BOLD}$TITLE${NC}"
    [[ -n "$DESC" ]] && echo -e "  ${DIM}  $DESC${NC}"
    echo -e "  ${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    _log_raw "PHASE" "=== Phase $NUM: $TITLE ==="
    phase_timer_start "$NUM"
}

print_phase_done() {
    local NUM="$1"
    phase_timer_end "$NUM"
    local DUR="${PHASE_TIMES["${NUM}_duration"]:-?}"
    echo -e "  ${DIM}  Phase $NUM complete — ${DUR}${NC}"
    echo ""
}

print_divider() {
    echo ""
    echo -e "  ${DIM}┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈┈${NC}"
    echo ""
}

print_box() {
    local TITLE="$1" COLOR="${2:-$YELLOW}"
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

# Typewriter effect for important messages
typewrite() {
    local MSG="$1" DELAY="${2:-0.02}"
    if [[ "$_COLOR" -eq 1 ]]; then
        echo -n "  "
        while IFS= read -r -n1 char; do
            echo -n "$char"
            sleep "$DELAY"
        done <<< "$MSG"
        echo ""
    else
        echo "  $MSG"
    fi
}

# =============================================================================
# PHASE RUNNER
# =============================================================================

run_phase() {
    local PHASE_ID="$1" PHASE_FN="$2"

    for SKIP in "${SKIP_PHASES[@]:-}"; do
        [[ "$SKIP" == "$PHASE_ID" ]] && {
            log_info "Phase $PHASE_ID skipped (--skip)"
            return 0
        }
    done

    if [[ -n "$ONLY_PHASE" && "$ONLY_PHASE" != "$PHASE_ID" ]]; then
        return 0
    fi

    if [[ "$RESUME_MODE" == "true" ]] && phase_complete "$PHASE_ID"; then
        log_info "Phase $PHASE_ID already done — skipping (--resume)"
        CURRENT_PHASE_NUM=$((CURRENT_PHASE_NUM + 1))
        return 0
    fi

    "$PHASE_FN"
}

# =============================================================================
# INIT LOGGING & STATE
# =============================================================================

mkdir -p "${VPS_LOG_DIR}" "${VPS_STATE_DIR}"
chmod 700 "${VPS_STATE_DIR}"

[[ -f "${VPS_INSTALL_LOG}" ]] && \
    mv "${VPS_INSTALL_LOG}" \
       "${VPS_INSTALL_LOG}.$(date +%Y%m%d-%H%M%S)"

exec > >(tee -a "${VPS_INSTALL_LOG}") 2>&1
_log_raw "START" "vps-hardening ${VPS_VERSION}"

SCRIPT_START=$(date +%s)

# =============================================================================
# WELCOME
# =============================================================================

print_banner

echo -e "  ${BOLD}Welcome!${NC} This script will:"
echo ""
echo -e "  ${CYAN}  1.${NC}  Update system + detect kernel reboot requirement"
echo -e "  ${CYAN}  2.${NC}  Disable unnecessary services"
echo -e "  ${CYAN}  3.${NC}  Configure UFW firewall"
echo -e "  ${CYAN}  4.${NC}  Harden SSH (port, crypto, settings)"
echo -e "  ${CYAN}  5.${NC}  Install fail2ban (brute-force protection)"
echo -e "  ${CYAN}  6.${NC}  Enable AppArmor mandatory access control"
echo -e "  ${CYAN}  7.${NC}  Persistent logging + logrotate + integrity checks"
echo -e "  ${CYAN}  8.${NC}  Package cleanup"
echo -e "  ${CYAN}  9.${NC}  Automatic security updates (unattended-upgrades)"
echo -e "  ${CYAN} 10.${NC}  Kernel hardening (sysctl)"
echo -e "  ${CYAN} 11.${NC}  auditd — kernel-level activity logging"
echo -e "  ${CYAN} 12.${NC}  Create admin account + final SSH lockdown"
echo -e "  ${CYAN} 13.${NC}  Security monitoring (daily audit + check-alerts)"
echo -e "  ${CYAN} 14.${NC}  ${BOLD}${GREEN}NEW${NC} — Login banner + MOTD + SSH fingerprint"
echo ""
echo -e "  ${DIM}Estimated time: 10–15 minutes${NC}"
[[ "$RESUME_MODE" == "true" ]] && log_info "Resume mode active"
[[ "$DRY_RUN"    == "true" ]] && log_info "Dry-run mode — no changes"
echo ""

pause

# =============================================================================
# PHASE 0a — ENVIRONMENT DETECTION
# =============================================================================

echo ""
echo -e "  ${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}${WHITE}  Phase 0a${NC}  ${BOLD}Environment Detection${NC}"
echo -e "  ${DIM}  Analyzing your server${NC}"
echo -e "  ${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -ne "  ${CYAN}⠋${NC}  Reading OS information"
OS_ID=$(grep      "^ID="               /etc/os-release | cut -d= -f2 | tr -d '"')
OS_VERSION=$(grep "^VERSION_ID="       /etc/os-release | cut -d= -f2 | tr -d '"')
OS_CODENAME=$(grep "^VERSION_CODENAME=" /etc/os-release \
    | cut -d= -f2 | tr -d '"' 2>/dev/null || echo "unknown")
OS_MAJOR=$(echo "$OS_VERSION" | cut -d. -f1)
sleep 0.2
echo -e "\r  ${GREEN}✓${NC}  OS: ${BOLD}$OS_ID $OS_VERSION${NC} ($OS_CODENAME)"

if [[ "$OS_ID" != "ubuntu" ]]; then
    log_warn "Designed for Ubuntu. Detected: $OS_ID"
    read -rp "  Continue anyway? (yes/no): " _ANS
    [[ "$_ANS" != "yes" ]] && exit 1
fi

CURRENT_USER="${SUDO_USER:-}"
CURRENT_USER="${CURRENT_USER:-root}"
[[ -z "$CURRENT_USER" ]] && CURRENT_USER="root"
[[ "$CURRENT_USER" == "root" ]] \
    && CURRENT_USER_HOME="/root" \
    || CURRENT_USER_HOME="/home/$CURRENT_USER"

echo -ne "  ${CYAN}⠋${NC}  Detecting cloud provider"
CLOUD_PROVIDER="generic"
DEFAULT_CLOUD_USER="$CURRENT_USER"

if systemctl list-units --all 2>/dev/null | grep -q "oracle" \
   || [[ -f /etc/oracle-cloud-agent/agent.yml ]] \
   || curl -sf --max-time 2 -H "Authorization: Bearer Oracle" \
        http://169.254.169.254/opc/v2/instance/ > /dev/null 2>&1; then
    CLOUD_PROVIDER="oracle";       DEFAULT_CLOUD_USER="ubuntu"
elif curl -sf --max-time 2 \
        http://169.254.169.254/latest/meta-data/ami-id > /dev/null 2>&1; then
    CLOUD_PROVIDER="aws";          DEFAULT_CLOUD_USER="ubuntu"
elif [[ -f /etc/digitalocean ]] \
     || curl -sf --max-time 2 \
        http://169.254.169.254/metadata/v1/id > /dev/null 2>&1; then
    CLOUD_PROVIDER="digitalocean"; DEFAULT_CLOUD_USER="root"
elif [[ -f /etc/hetzner-build ]] \
     || curl -sf --max-time 2 \
        http://169.254.169.254/hetzner/v1/metadata > /dev/null 2>&1; then
    CLOUD_PROVIDER="hetzner";      DEFAULT_CLOUD_USER="root"
elif curl -sf --max-time 2 \
        http://169.254.169.254/linode/v1/ > /dev/null 2>&1; then
    CLOUD_PROVIDER="linode";       DEFAULT_CLOUD_USER="root"
elif curl -sf --max-time 2 \
        http://169.254.169.254/v1.json > /dev/null 2>&1; then
    CLOUD_PROVIDER="vultr";        DEFAULT_CLOUD_USER="root"
elif curl -sf --max-time 2 -H "Metadata-Flavor: Google" \
        http://169.254.169.254/computeMetadata/v1/ > /dev/null 2>&1; then
    CLOUD_PROVIDER="gcp";          DEFAULT_CLOUD_USER="ubuntu"
elif curl -sf --max-time 2 -H "Metadata: true" \
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
        > /dev/null 2>&1; then
    CLOUD_PROVIDER="azure";        DEFAULT_CLOUD_USER="azureuser"
fi

id "$DEFAULT_CLOUD_USER" > /dev/null 2>&1 \
    || DEFAULT_CLOUD_USER="$CURRENT_USER"
echo -e "\r  ${GREEN}✓${NC}  Cloud: ${BOLD}$CLOUD_PROVIDER${NC}"

echo -ne "  ${CYAN}⠋${NC}  Checking iptables"
CONFLICTING_IPTABLES=false
CONFLICTING_SPECS=()
if command -v iptables > /dev/null 2>&1; then
    while IFS= read -r line; do
        if echo "$line" | grep -qE "REJECT|DROP"; then
            RULE_SPEC=$(echo "$line" | awk '{$1=""; print $0}' | xargs)
            CONFLICTING_SPECS+=("$RULE_SPEC")
            CONFLICTING_IPTABLES=true
        fi
    done < <(iptables -L INPUT -n --line-numbers 2>/dev/null | tail -n +3)
fi
echo -e "\r  ${GREEN}✓${NC}  iptables: $( \
    [[ "$CONFLICTING_IPTABLES" == "true" ]] \
    && echo "${YELLOW}conflicts found${NC}" || echo "clean")"

echo -ne "  ${CYAN}⠋${NC}  Checking services"
HAS_CLOUD_INIT=false
HAS_RPCBIND=false; HAS_MODEMMANAGER=false; HAS_ISCSID=false
command -v cloud-init > /dev/null 2>&1 && HAS_CLOUD_INIT=true
UNITS=$(systemctl list-units --all 2>/dev/null)
echo "$UNITS" | grep -q "rpcbind"      && HAS_RPCBIND=true      || true
echo "$UNITS" | grep -q "ModemManager" && HAS_MODEMMANAGER=true  || true
echo "$UNITS" | grep -q "iscsid"       && HAS_ISCSID=true        || true

CPU_CORES=$(nproc 2>/dev/null || echo 1)
RAM_MB=$(free -m | grep Mem | awk '{print $2}')
echo -e "\r  ${GREEN}✓${NC}  Services scanned | Hardware: ${CPU_CORES} CPU / ${RAM_MB}MB RAM"

# Check for existing security tools
echo -ne "  ${CYAN}⠋${NC}  Scanning existing security tools"
HAS_UFW=false; HAS_FAIL2BAN=false; HAS_APPARMOR=false
HAS_AUDITD=false; HAS_AIDE=false; HAS_RKHUNTER=false
command -v ufw         > /dev/null 2>&1 && HAS_UFW=true
command -v fail2ban-client > /dev/null 2>&1 && HAS_FAIL2BAN=true
command -v aa-status   > /dev/null 2>&1 && HAS_APPARMOR=true
command -v auditctl    > /dev/null 2>&1 && HAS_AUDITD=true
command -v aide        > /dev/null 2>&1 && HAS_AIDE=true
command -v rkhunter    > /dev/null 2>&1 && HAS_RKHUNTER=true
echo -e "\r  ${GREEN}✓${NC}  Security tool inventory complete"

print_divider
echo -e "  ${BOLD}Detection Summary:${NC}"
echo ""
echo -e "    ${DIM}OS${NC}          $OS_ID $OS_VERSION ($OS_CODENAME)"
echo -e "    ${DIM}Cloud${NC}       $CLOUD_PROVIDER"
echo -e "    ${DIM}User${NC}        $CURRENT_USER"
echo -e "    ${DIM}CPU/RAM${NC}     ${CPU_CORES} cores / ${RAM_MB}MB"
echo -e "    ${DIM}cloud-init${NC}  $( [[ "$HAS_CLOUD_INIT" == "true" ]] \
    && echo "${GREEN}present${NC}" || echo "absent")"
echo -e "    ${DIM}iptables${NC}    $( [[ "$CONFLICTING_IPTABLES" == "true" ]] \
    && echo "${YELLOW}conflicts${NC}" || echo "${GREEN}clean${NC}")"
echo -e "    ${DIM}Preinstalled${NC} $( \
    [[ "$HAS_UFW" == "true" ]]      && echo -n "ufw " ; \
    [[ "$HAS_FAIL2BAN" == "true" ]] && echo -n "fail2ban " ; \
    [[ "$HAS_APPARMOR" == "true" ]] && echo -n "apparmor " ; \
    [[ "$HAS_AUDITD" == "true" ]]   && echo -n "auditd " ; \
    echo "")"
echo ""
log_ok "Detection complete"

# =============================================================================
# PHASE 0b — CONFIGURATION
# =============================================================================

echo ""
echo -e "  ${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}${WHITE}  Phase 0b${NC}  ${BOLD}Configuration${NC}"
echo -e "  ${DIM}  Your choices — no changes made yet${NC}"
echo -e "  ${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ---------------------------------------------------------------------------
# Auth method
# ---------------------------------------------------------------------------
print_divider
echo -e "  ${BOLD}🔐 Authentication Method${NC}"
echo ""
echo -e "    ${CYAN}1)${NC}  SSH key  ${DIM}(recommended)${NC}"
echo -e "    ${CYAN}2)${NC}  Password"
echo ""
read -rp "  How are you logged in? (1/2): " AUTH_METHOD
while [[ "$AUTH_METHOD" != "1" && "$AUTH_METHOD" != "2" ]]; do
    log_warn "Enter 1 or 2."
    read -rp "  (1/2): " AUTH_METHOD
done

AUTH_TYPE=""
INPUT_PUBLIC_KEY=""

if [[ "$AUTH_METHOD" == "1" ]]; then
    AUTH_TYPE="key"
    log_ok "SSH key authentication selected"
    KEY_FOUND=false
    if [[ -f "$CURRENT_USER_HOME/.ssh/authorized_keys" ]] \
       && [[ -s "$CURRENT_USER_HOME/.ssh/authorized_keys" ]]; then
        log_ok "Found authorized_keys in $CURRENT_USER_HOME/.ssh/"
        KEY_FOUND=true
    elif [[ -f "/root/.ssh/authorized_keys" ]] \
         && [[ -s "/root/.ssh/authorized_keys" ]]; then
        log_ok "Found authorized_keys in /root/.ssh/"
        KEY_FOUND=true
    fi
    if [[ "$KEY_FOUND" == "false" ]]; then
        log_warn "No authorized_keys found."
        read -rp "  Continue anyway? (yes/no): " _KC
        [[ "$_KC" != "yes" ]] && exit 1
    fi
else
    print_box "SSH KEY RECOMMENDATION" "$YELLOW"
    echo -e "  SSH keys are ${BOLD}far more secure${NC} than passwords."
    echo -e "  Bots are attacking port 22 ${ITALIC}right now${NC}."
    echo ""
    echo -e "    ${CYAN}a)${NC}  ${GREEN}Yes${NC} — set up SSH key now ${DIM}(recommended)${NC}"
    echo -e "    ${CYAN}b)${NC}  No  — keep password"
    echo ""
    read -rp "  Enter a or b: " KEY_CHOICE
    while [[ "$KEY_CHOICE" != "a" && "$KEY_CHOICE" != "b" ]]; do
        log_warn "Enter a or b."
        read -rp "  a or b: " KEY_CHOICE
    done

    if [[ "$KEY_CHOICE" == "a" ]]; then
        AUTH_TYPE="key"
        echo ""
        echo -e "  ${BOLD}Generate key on your LOCAL machine:${NC}"
        echo -e "    ${CYAN}ssh-keygen -t ed25519 -C \"my-vps-key\"${NC}"
        echo -e "    ${CYAN}cat ~/.ssh/id_ed25519.pub${NC}"
        echo ""
        read -rp "  Generated? (yes/no): " KEY_GEN
        [[ "$KEY_GEN" != "yes" ]] && { log_warn "Generate a key first then re-run."; exit 1; }
        echo ""
        echo -e "  Paste your ${BOLD}public key${NC} (.pub):"
        read -rp "  > " INPUT_PUBLIC_KEY
        while [[ ! "$INPUT_PUBLIC_KEY" =~ ^ssh-(ed25519|rsa|ecdsa) ]]; do
            log_warn "Must start with ssh-ed25519, ssh-rsa, or ssh-ecdsa."
            read -rp "  Public key: " INPUT_PUBLIC_KEY
        done
        KEY_DIR="$( [[ "$CURRENT_USER" == "root" ]] && echo "/root/.ssh" \
            || echo "/home/$CURRENT_USER/.ssh" )"
        mkdir -p "$KEY_DIR"; chmod 700 "$KEY_DIR"
        echo "$INPUT_PUBLIC_KEY" >> "$KEY_DIR/authorized_keys"
        chmod 600 "$KEY_DIR/authorized_keys"
        [[ "$CURRENT_USER" != "root" ]] \
            && chown -R "$CURRENT_USER:$CURRENT_USER" "$KEY_DIR"
        log_ok "Public key installed"
        PUBLIC_IP_EARLY=$(get_public_ip)
        print_box "TEST KEY LOGIN NOW" "$YELLOW"
        echo -e "  ${CYAN}ssh -i ~/.ssh/id_ed25519 $CURRENT_USER@$PUBLIC_IP_EARLY${NC}"
        echo ""
        read -rp "  Key login succeeded? (yes/no): " KEY_TEST
        if [[ "$KEY_TEST" != "yes" ]]; then
            read -rp "  Fall back to password? (yes/no): " FALLBACK
            [[ "$FALLBACK" == "yes" ]] && AUTH_TYPE="password" \
                || die "Fix the key and re-run."
        else
            log_ok "Key login confirmed"
        fi
    else
        AUTH_TYPE="password"
        log_info "Continuing with password authentication."
    fi
fi

# ---------------------------------------------------------------------------
# Hostname
# ---------------------------------------------------------------------------
print_divider
echo -e "  ${BOLD}🏷️  Hostname${NC}"
echo -e "  ${DIM}Letters, numbers, hyphens. Max 63 chars.${NC}"
echo ""
read -rp "  Hostname: " INPUT_HOSTNAME
while [[ -z "$INPUT_HOSTNAME" \
       || ! "$INPUT_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; do
    log_warn "Invalid. Use letters, numbers, hyphens. Cannot start/end with hyphen."
    read -rp "  Hostname: " INPUT_HOSTNAME
done

# ---------------------------------------------------------------------------
# Timezone
# ---------------------------------------------------------------------------

is_valid_timezone() {
    [[ -e "/usr/share/zoneinfo/$1" ]]
}

print_divider
echo -e "  ${BOLD}🕐 Timezone${NC}"

# Detect current timezone
CURRENT_TZ=""

if command -v timedatectl >/dev/null 2>&1; then
    CURRENT_TZ="$(timedatectl show --property=Timezone --value 2>/dev/null)"
fi

if [[ -z "$CURRENT_TZ" && -f /etc/timezone ]]; then
    CURRENT_TZ="$(< /etc/timezone)"
fi

CURRENT_TZ="${CURRENT_TZ:-UTC}"

echo -e "  ${DIM}Current: ${CURRENT_TZ}${NC}"
echo -e "  ${DIM}Examples: UTC  Europe/Berlin  Europe/London  America/New_York  Asia/Tokyo${NC}"
echo ""

while true; do
    read -rp "  Timezone [${CURRENT_TZ}]: " INPUT_TZ

    # Keep current timezone if user presses Enter
    INPUT_TZ="${INPUT_TZ:-$CURRENT_TZ}"

    # Trim leading/trailing whitespace
    INPUT_TZ="$(echo "$INPUT_TZ" | xargs)"

    if is_valid_timezone "$INPUT_TZ"; then
        break
    fi

    log_warn "'$INPUT_TZ' is not a valid timezone."

    echo "👉 Please enter a valid IANA timezone."
    echo "👉 Examples:"
    echo "     UTC"
    echo "     Europe/Berlin"
    echo "     Europe/London"
    echo "     America/New_York"
    echo "     Asia/Tokyo"
    echo ""
done

log_ok "Timezone: $INPUT_TZ"

# ---------------------------------------------------------------------------
# SSH Port
# ---------------------------------------------------------------------------
print_divider
echo -e "  ${BOLD}🔌 SSH Port${NC}"
echo -e "  ${DIM}Range 1024–65535. Avoid 2222.${NC}"
echo ""
read -rp "  SSH port: " INPUT_SSH_PORT
while true; do
    if ! [[ "$INPUT_SSH_PORT" =~ ^[0-9]+$ ]]; then
        log_warn "Must be a number."
    elif [[ "$INPUT_SSH_PORT" -lt 1024 || "$INPUT_SSH_PORT" -gt 65535 ]]; then
        log_warn "Must be 1024–65535."
    elif [[ "$INPUT_SSH_PORT" -eq 2222 ]]; then
        log_warn "2222 is heavily scanned. Pick another."
    else
        break
    fi
    read -rp "  SSH port: " INPUT_SSH_PORT
done

# ---------------------------------------------------------------------------
# Admin username
# ---------------------------------------------------------------------------
print_divider
echo -e "  ${BOLD}👤 Admin Username${NC}"
echo -e "  ${DIM}Lowercase, starts with letter/underscore, max 32 chars.${NC}"
echo -e "  ${DIM}Avoid: ubuntu admin root test user deploy git pi postgres${NC}"
echo ""

BLOCKED_NAMES="ubuntu admin root test user deploy git ansible pi postgres \
    ec2-user centos fedora vagrant daemon www-data nobody"

read -rp "  Username: " INPUT_USERNAME
while true; do
    if [[ -z "$INPUT_USERNAME" ]]; then
        log_warn "Cannot be empty."
    elif [[ ! "$INPUT_USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        log_warn "Invalid format."
    elif echo "$BLOCKED_NAMES" | grep -qw "$INPUT_USERNAME"; then
        log_warn "Too predictable. Choose something unique."
    else
        break
    fi
    read -rp "  Username: " INPUT_USERNAME
done

# ---------------------------------------------------------------------------
# Cloud user
# ---------------------------------------------------------------------------
INPUT_CLOUD_USER="$CURRENT_USER"
if [[ "$CURRENT_USER" != "root" ]]; then
    print_divider
    echo -e "  ${BOLD}Cloud Default User to Demote${NC}"
    echo ""
    read -rp "  Cloud user [$CURRENT_USER]: " INPUT_CLOUD_USER
    INPUT_CLOUD_USER="${INPUT_CLOUD_USER:-$CURRENT_USER}"
    id "$INPUT_CLOUD_USER" > /dev/null 2>&1 \
        || { log_warn "User not found — using $CURRENT_USER"; INPUT_CLOUD_USER="$CURRENT_USER"; }
fi

# ---------------------------------------------------------------------------
# Login banner text
# ---------------------------------------------------------------------------
print_divider
echo -e "  ${BOLD}🚨 Legal Warning Banner${NC}"
echo -e "  ${DIM}Shown before login — deters attackers, required for legal protection.${NC}"
echo ""
echo -e "    ${CYAN}1)${NC}  Default (recommended)"
echo -e "    ${CYAN}2)${NC}  Custom"
echo ""
read -rp "  Banner (1/2): " BANNER_CHOICE
BANNER_TEXT=""
if [[ "$BANNER_CHOICE" == "2" ]]; then
    echo -e "  Enter your banner text (one line):"
    read -rp "  > " BANNER_TEXT
fi
if [[ -z "$BANNER_TEXT" ]]; then
    BANNER_TEXT="UNAUTHORIZED ACCESS PROHIBITED. All connections are monitored and logged. Disconnect immediately if you are not an authorized user."
fi

# ---------------------------------------------------------------------------
# Optional features
# ---------------------------------------------------------------------------
print_divider
echo -e "  ${BOLD}⚙️  Optional Security Features${NC}"
echo ""
echo -e "  ${DIM}Select additional hardening (all recommended):${NC}"
echo ""
echo -e "    ${CYAN}a)${NC}  Kernel hardening (sysctl)            ${DIM}highly recommended${NC}"
echo -e "    ${CYAN}b)${NC}  auditd kernel-level logging          ${DIM}highly recommended${NC}"
echo -e "    ${CYAN}c)${NC}  rkhunter + chkrootkit                ${DIM}recommended${NC}"
echo -e "    ${CYAN}d)${NC}  ClamAV malware scanner               ${DIM}optional${NC}"
echo -e "    ${CYAN}e)${NC}  AIDE file integrity (full system)    ${DIM}optional, takes 10min${NC}"
echo ""
echo -e "  ${DIM}Enter letters to enable (e.g. ab or abcd or all):${NC}"
read -rp "  Features: " FEATURE_INPUT
FEATURE_INPUT="${FEATURE_INPUT,,}"

ENABLE_SYSCTL=false
ENABLE_AUDITD=false
ENABLE_RKHUNTER=false
ENABLE_CLAMAV=false
ENABLE_AIDE=false

if [[ "$FEATURE_INPUT" == "all" || "$FEATURE_INPUT" == *"a"* ]]; then ENABLE_SYSCTL=true;   fi
if [[ "$FEATURE_INPUT" == "all" || "$FEATURE_INPUT" == *"b"* ]]; then ENABLE_AUDITD=true;   fi
if [[ "$FEATURE_INPUT" == "all" || "$FEATURE_INPUT" == *"c"* ]]; then ENABLE_RKHUNTER=true; fi
if [[ "$FEATURE_INPUT" == "all" || "$FEATURE_INPUT" == *"d"* ]]; then ENABLE_CLAMAV=true;   fi
if [[ "$FEATURE_INPUT" == "all" || "$FEATURE_INPUT" == *"e"* ]]; then ENABLE_AIDE=true;     fi

# ---------------------------------------------------------------------------
# Summary + confirm
# ---------------------------------------------------------------------------
echo ""
echo -e "  ${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "  ${BOLD}${CYAN}║${NC}  ${BOLD}${WHITE}CONFIGURATION SUMMARY${NC}"
echo -e "  ${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "    ${DIM}Hostname${NC}         ${BOLD}${GREEN}$INPUT_HOSTNAME${NC}"
echo -e "    ${DIM}Timezone${NC}         ${BOLD}${GREEN}$INPUT_TZ${NC}"
echo -e "    ${DIM}SSH Port${NC}         ${BOLD}${GREEN}$INPUT_SSH_PORT${NC}"
echo -e "    ${DIM}Admin User${NC}       ${BOLD}${GREEN}$INPUT_USERNAME${NC}"
echo -e "    ${DIM}Auth Method${NC}      ${BOLD}${GREEN}$AUTH_TYPE${NC}"
echo -e "    ${DIM}Provider${NC}         $CLOUD_PROVIDER"
echo -e "    ${DIM}OS${NC}               $OS_ID $OS_VERSION"
echo ""
echo -e "    ${DIM}Kernel sysctl${NC}    $( [[ "$ENABLE_SYSCTL"   == true ]] && echo "${GREEN}yes${NC}" || echo "no" )"
echo -e "    ${DIM}auditd${NC}           $( [[ "$ENABLE_AUDITD"   == true ]] && echo "${GREEN}yes${NC}" || echo "no" )"
echo -e "    ${DIM}rkhunter${NC}         $( [[ "$ENABLE_RKHUNTER" == true ]] && echo "${GREEN}yes${NC}" || echo "no" )"
echo -e "    ${DIM}ClamAV${NC}           $( [[ "$ENABLE_CLAMAV"   == true ]] && echo "${GREEN}yes${NC}" || echo "no" )"
echo -e "    ${DIM}AIDE${NC}             $( [[ "$ENABLE_AIDE"     == true ]] && echo "${GREEN}yes${NC}" || echo "no" )"
echo ""
read -rp "  Proceed? (yes/no): " CONFIRM
[[ "$CONFIRM" != "yes" ]] && { log_warn "Aborted."; exit 1; }

# =============================================================================
# LOGGING HEADER
# =============================================================================

{
    echo "════════════════════════════════════════"
    echo "Started : $(date)"
    echo "Config  : Host=$INPUT_HOSTNAME TZ=$INPUT_TZ Port=$INPUT_SSH_PORT User=$INPUT_USERNAME"
    echo "Auth    : $AUTH_TYPE | Provider: $CLOUD_PROVIDER | OS: $OS_ID $OS_VERSION"
    echo "Options : sysctl=$ENABLE_SYSCTL auditd=$ENABLE_AUDITD rkhunter=$ENABLE_RKHUNTER clamav=$ENABLE_CLAMAV aide=$ENABLE_AIDE"
    echo "════════════════════════════════════════"
} >> "${VPS_INSTALL_LOG}"

# =============================================================================
# ASSESSMENT
# =============================================================================

echo ""
echo -e "  ${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}${WHITE}  Assessment${NC}  ${BOLD}Initial State${NC}"
echo -e "  ${DIM}  Snapshot before changes${NC}"
echo -e "  ${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

PUBLIC_IP=$(get_public_ip)
GEO_INFO=$(get_geo_info "$PUBLIC_IP")

echo -e "  ${BOLD}System Overview:${NC}"
echo ""
echo -e "    ${DIM}Hostname${NC}     $(hostname)"
echo -e "    ${DIM}Public IP${NC}    ${BOLD}$PUBLIC_IP${NC}  ${DIM}($GEO_INFO)${NC}"
echo -e "    ${DIM}Kernel${NC}       $(uname -r)"
echo -e "    ${DIM}OS${NC}           $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
echo -e "    ${DIM}Uptime${NC}       $(uptime -p 2>/dev/null || echo 'unknown')"
echo -e "    ${DIM}Disk${NC}         $(df -h / | tail -1 | awk '{print $5 " of " $2}')"
echo -e "    ${DIM}Memory${NC}       $(free -h | grep Mem | awk '{print $3 " / " $2}')"

echo ""
echo -e "  ${BOLD}Open Ports:${NC}"
ss -tlnp | grep LISTEN | while IFS= read -r line; do
    PORT=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
    PROC=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")
    echo -e "    ${DIM}:${PORT}${NC} — $PROC"
done

echo ""
log_ok "Assessment complete"
pause

# =============================================================================
# PHASE 01 — SYSTEM UPDATE
# =============================================================================

phase_01() {
    print_phase "01" "System Update" \
        "Full update + kernel reboot detection + timezone"

    phase_complete "01" && { log_ok "Phase 01 done — skipping"; print_phase_done "01"; return 0; }

    local KERNEL_BEFORE
    KERNEL_BEFORE=$(uname -r)

    run_silent "Updating package lists" \
        bash -c 'apt-get update -qq'

    run_silent "Applying upgrades" \
        bash -c 'DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold"'

    check_reboot_required "$KERNEL_BEFORE"

    run_silent "Setting hostname to $INPUT_HOSTNAME" \
        hostnamectl set-hostname "$INPUT_HOSTNAME"

    run_silent "Setting timezone to $INPUT_TZ" \
        timedatectl set-timezone "$INPUT_TZ"

    # Enable NTP time sync
    if command -v timedatectl > /dev/null 2>&1; then
        timedatectl set-ntp true > /dev/null 2>&1 || true
        log_ok "NTP time synchronisation enabled"
    fi

    if [[ "$HAS_CLOUD_INIT" == "true" ]]; then
        echo "preserve_hostname: true" \
            > /etc/cloud/cloud.cfg.d/99-preserve-hostname.cfg 2>/dev/null || true
        log_ok "cloud-init hostname lock applied"
    fi

    if grep -q "127.0.1.1" /etc/hosts; then
        sed -i "s/^127\.0\.1\.1.*/127.0.1.1 $INPUT_HOSTNAME/" /etc/hosts
    else
        echo "127.0.1.1 $INPUT_HOSTNAME" >> /etc/hosts
    fi

    log_ok "Hostname: ${BOLD}$INPUT_HOSTNAME${NC}"
    log_ok "Timezone: ${BOLD}$INPUT_TZ${NC}"

    phase_done "01"
    print_phase_done "01"
}

# =============================================================================
# PHASE 02 — SERVICES
# =============================================================================

phase_02() {
    print_phase "02" "Remove Unnecessary Services" \
        "Less attack surface"

    phase_complete "02" && { log_ok "Phase 02 done — skipping"; print_phase_done "02"; return 0; }

    local REMOVED=0

    if [[ "$HAS_RPCBIND" == "true" ]]; then
        run_silent "Removing rpcbind" bash -c '
            systemctl stop    rpcbind.socket rpcbind.service 2>/dev/null || true
            systemctl disable rpcbind.socket rpcbind.service 2>/dev/null || true
            systemctl mask    rpcbind.socket rpcbind.service 2>/dev/null || true'
        REMOVED=$((REMOVED+1))
    fi

    if [[ "$HAS_MODEMMANAGER" == "true" ]]; then
        run_silent "Removing ModemManager" bash -c '
            systemctl stop    ModemManager 2>/dev/null || true
            systemctl disable ModemManager 2>/dev/null || true
            systemctl mask    ModemManager 2>/dev/null || true'
        REMOVED=$((REMOVED+1))
    fi

    if [[ "$HAS_ISCSID" == "true" ]]; then
        run_silent "Removing iscsid" bash -c '
            systemctl stop    iscsid.socket iscsid.service 2>/dev/null || true
            systemctl disable iscsid.socket iscsid.service 2>/dev/null || true
            systemctl mask    iscsid.socket iscsid.service 2>/dev/null || true'
        REMOVED=$((REMOVED+1))
    fi

    # Disable Avahi/mDNS (not needed on server)
    if systemctl list-unit-files avahi-daemon.service &>/dev/null \
       | grep -q "avahi-daemon"; then
        run_silent "Masking avahi-daemon (mDNS not needed on server)" bash -c '
            systemctl stop    avahi-daemon 2>/dev/null || true
            systemctl disable avahi-daemon 2>/dev/null || true
            systemctl mask    avahi-daemon 2>/dev/null || true'
        REMOVED=$((REMOVED+1))
    fi

    systemctl daemon-reload 2>/dev/null || true
    echo ""
    [[ "$REMOVED" -eq 0 ]] \
        && log_ok "No unnecessary services found" \
        || log_ok "$REMOVED service(s) disabled and masked"

    phase_done "02"
    print_phase_done "02"
}

# =============================================================================
# PHASE 03 — FIREWALL
# =============================================================================

phase_03() {
    print_phase "03" "Firewall" "UFW + iptables cleanup + rate limiting"

    phase_complete "03" && { log_ok "Phase 03 done — skipping"; print_phase_done "03"; return 0; }

    run_silent "Installing UFW" \
        bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw'

    ufw default deny incoming  > /dev/null 2>&1
    ufw default deny forward   > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    log_ok "Default: deny incoming+forward / allow outgoing"

    # Rate-limit SSH to stop floods even before fail2ban kicks in
    ufw limit 22/tcp               comment "SSH safety net (rate-limited)" > /dev/null 2>&1
    ufw limit "$INPUT_SSH_PORT"/tcp comment "SSH hardened (rate-limited)"   > /dev/null 2>&1
    log_ok "Ports open: 22 safety net + ${BOLD}$INPUT_SSH_PORT${NC} (both rate-limited)"

    # Logging
    ufw logging on > /dev/null 2>&1 || true
    log_ok "UFW logging enabled"

    echo "y" | ufw enable > /dev/null 2>&1
    log_ok "UFW ${BOLD}${GREEN}active${NC}"

    if [[ "$CONFLICTING_IPTABLES" == "true" ]]; then
        for SPEC in "${CONFLICTING_SPECS[@]}"; do
            iptables -D INPUT $SPEC 2>/dev/null || true
        done
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        log_ok "iptables conflicts cleaned"
    fi

    case "$CLOUD_PROVIDER" in
        oracle)
            echo ""
            log_warn "${BOLD}Oracle:${NC} Open port $INPUT_SSH_PORT in your Security List"
            log_info "VCN → Subnet → Security List → Add Ingress Rule"
            pause ;;
        aws)
            echo ""
            log_warn "${BOLD}AWS:${NC} Open port $INPUT_SSH_PORT in your Security Group"
            pause ;;
        azure)
            echo ""
            log_warn "${BOLD}Azure:${NC} Open port $INPUT_SSH_PORT in your NSG"
            pause ;;
        gcp)
            echo ""
            log_warn "${BOLD}GCP:${NC} Open port $INPUT_SSH_PORT in VPC Firewall Rules"
            pause ;;
    esac

    phase_done "03"
    print_phase_done "03"
}

# =============================================================================
# PHASE 04 — SSH HARDENING
# =============================================================================

phase_04() {
    print_phase "04" "SSH Hardening" \
        "Port + crypto + settings (AllowUsers added after account confirmed)"

    phase_complete "04" && { log_ok "Phase 04 done — skipping"; print_phase_done "04"; return 0; }

    echo -e "  ${DIM}Port 22 stays open until Phase 12 confirms your new account.${NC}"
    echo ""
    log_warn "Keep your current session open throughout."
    pause

    run_silent "Backing up SSH config" bash -c "
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
        mkdir -p /etc/ssh/sshd_config.d"

    # Regenerate weak moduli
    run_silent "Hardening SSH moduli (removing weak DH params)" bash -c '
        if [[ -f /etc/ssh/moduli ]]; then
            awk "\$5 >= 3071" /etc/ssh/moduli > /tmp/moduli.safe
            [[ -s /tmp/moduli.safe ]] && mv /tmp/moduli.safe /etc/ssh/moduli
        fi' || true

    local CRYPTO_BLOCK
    CRYPTO_BLOCK="KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"

    if [[ "$AUTH_TYPE" == "key" ]]; then
        cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# Hardened SSH — Phase 04 (no AllowUsers yet — added in Phase 12)
# Generated: $(date) by vps-hardening ${VPS_VERSION}
Port $INPUT_SSH_PORT
PermitRootLogin yes
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
MaxAuthTries 3
MaxStartups 10:30:60
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 3
TCPKeepAlive no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
PermitUserRC no
DisableForwarding yes
PrintMotd no
PrintLastLog yes
Banner /etc/issue.net
LogLevel VERBOSE
${CRYPTO_BLOCK}
EOF
    else
        cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# Hardened SSH — Phase 04 (no AllowUsers yet — added in Phase 12)
# Generated: $(date) by vps-hardening ${VPS_VERSION}
Port $INPUT_SSH_PORT
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
MaxStartups 10:30:60
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 3
TCPKeepAlive no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
PermitUserRC no
DisableForwarding yes
PrintMotd no
PrintLastLog yes
Banner /etc/issue.net
LogLevel VERBOSE
${CRYPTO_BLOCK}
EOF
    fi

   log_ok "SSH config written (modern crypto + hardened settings)"

[[ "$OS_VERSION" == "24.04" ]] && apply_ssh_socket_fix

# ================================
# STEP 1: STATIC CONFIG VALIDATION
# ================================
if ! sshd -t 2>/dev/null; then
    log_error "SSH config syntax error — restoring backup"
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/99-hardened.conf
    exit 1
fi

# ================================
# STEP 2: SAFE RESTART (NEW FIX)
# ================================
log_step "Testing SSH restart safety"

run_silent "Restarting SSH safely" bash -c '
    systemctl restart ssh
    sleep 2
'

# ================================
# STEP 3: VERIFY SSH IS BACK
# ================================
if ! ss -tulpn | grep -q sshd; then
    log_error "SSH did not come back — rolling back"

    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/99-hardened.conf

    systemctl restart ssh

    die "SSH rollback executed — server protected"
fi

log_ok "SSH restarted successfully and is listening"

    local SSH_UP=false
    for _i in {1..20}; do
        ss -tlnp | grep -q ":$INPUT_SSH_PORT" && { SSH_UP=true; break; }
        sleep 0.5
    done

    [[ "$SSH_UP" == "false" ]] && \
        die "SSH not listening on $INPUT_SSH_PORT — check: journalctl -u ssh -n 30"

    log_ok "SSH listening on port ${BOLD}$INPUT_SSH_PORT${NC}"

    # Display SSH host key fingerprints for verification
    echo ""
    echo -e "  ${BOLD}SSH Host Fingerprints${NC} ${DIM}(save these for verification)${NC}"
    ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null \
        && true || true
    ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null \
        && true || true

    print_box "TEST YOUR CONNECTION NOW" "$YELLOW"
    echo -e "  Open a NEW terminal:"
    if [[ "$AUTH_TYPE" == "key" ]]; then
        echo -e "    ${CYAN}ssh -i /path/to/key -p $INPUT_SSH_PORT $CURRENT_USER@$PUBLIC_IP${NC}"
    else
        echo -e "    ${CYAN}ssh -p $INPUT_SSH_PORT $CURRENT_USER@$PUBLIC_IP${NC}"
    fi
    echo ""
    echo -e "  ${RED}Keep THIS session open!${NC}"
    echo ""
    read -rp "  Connection succeeded? (yes/no): " SSH_TEST
    [[ "$SSH_TEST" != "yes" ]] && die "SSH test failed. Diagnose from this session."

    log_ok "Port $INPUT_SSH_PORT confirmed"
    phase_done "04"
    print_phase_done "04"
}

# =============================================================================
# PHASE 05 — FAIL2BAN
# =============================================================================

phase_05() {
    print_phase "05" "Brute Force Protection" \
        "fail2ban — 3 failures = 24h ban + recidive jail"

    phase_complete "05" && { log_ok "Phase 05 done — skipping"; print_phase_done "05"; return 0; }

    log_step "Writing jail configuration"
    mkdir -p /etc/fail2ban
    cat > /etc/fail2ban/jail.local << EOF
# jail.local — vps-hardening ${VPS_VERSION} — $(date)
[DEFAULT]
bantime   = 86400
findtime  = 1200
maxretry  = 3
backend   = systemd
ignoreip  = 127.0.0.1/8 ::1
banaction = ufw

[sshd]
enabled  = true
port     = ${INPUT_SSH_PORT}
logpath  = %(sshd_log)s
backend  = systemd
maxretry = 3

# Recidive: persistent offenders get 7-day ban
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = ufw
bantime  = 604800
findtime = 86400
maxretry = 3
EOF
    chmod 640 /etc/fail2ban/jail.local
    log_ok "jail.local written (SSH + recidive jail)"

    policy_block_start
    run_silent "Installing fail2ban" \
        bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban'
    policy_allow_start

    run_silent "Enabling fail2ban" systemctl enable fail2ban
    run_silent "Starting fail2ban"  systemctl start fail2ban

    if ! wait_for_service fail2ban 20; then
        log_warn "fail2ban slow to start — check: journalctl -u fail2ban -n 30"
        log_warn "Continuing — investigate after script completes."
    else
        local BANNED=0
        fail2ban-client ping > /dev/null 2>&1 && \
            BANNED=$(fail2ban-client status sshd 2>/dev/null \
                | grep "Currently banned" | awk '{print $NF}' || echo 0)
        log_ok "fail2ban active — 3 strikes = 24h ban | repeat offenders = 7-day ban"
        [[ "${BANNED:-0}" -gt 0 ]] && \
            log_info "Already banned: ${BOLD}$BANNED${NC} IP(s)"
    fi

    phase_done "05"
    print_phase_done "05"
}

# =============================================================================
# PHASE 06 — APPARMOR
# =============================================================================

phase_06() {
    print_phase "06" "AppArmor" "Mandatory access control"

    phase_complete "06" && { log_ok "Phase 06 done — skipping"; print_phase_done "06"; return 0; }

    if command -v aa-status > /dev/null 2>&1; then
        local BEFORE AFTER ENFORCED
        BEFORE=$(aa-status 2>/dev/null \
            | grep "profiles are loaded" | awk '{print $1}' || echo 0)
        run_silent "Installing AppArmor profiles" \
            bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
                apparmor-profiles apparmor-profiles-extra'
        AFTER=$(aa-status 2>/dev/null \
            | grep "profiles are loaded" | awk '{print $1}' || echo 0)
        ENFORCED=$(aa-status 2>/dev/null \
            | grep "in enforce mode" | head -1 | awk '{print $1}' || echo 0)
        echo ""
        log_ok "AppArmor: ${BOLD}$AFTER${NC} profiles loaded, ${BOLD}$ENFORCED${NC} enforcing"
        [[ "$AFTER" -gt "$BEFORE" ]] && \
            log_info "Added $((AFTER - BEFORE)) new profiles"
    else
        log_warn "AppArmor not available — skipping"
    fi

    phase_done "06"
    print_phase_done "06"
}

# =============================================================================
# PHASE 07 — LOGGING + LOGROTATE + INTEGRITY
# =============================================================================

phase_07() {
    print_phase "07" "Persistent Logging" \
        "journald + logrotate hardening + integrity checksums"

    phase_complete "07" && { log_ok "Phase 07 done — skipping"; print_phase_done "07"; return 0; }

    # -- journald --
    run_silent "Configuring persistent journal" bash -c '
        mkdir -p /var/log/journal
        systemd-tmpfiles --create --prefix /var/log/journal > /dev/null 2>&1 || true
        mkdir -p /etc/systemd/journald.conf.d
        cat > /etc/systemd/journald.conf.d/99-hardening.conf << JEOF
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
SystemMaxFileSize=50M
SystemKeepFree=100M
RuntimeMaxUse=50M
MaxRetentionSec=6month
MaxFileSec=1week
Audit=yes
JEOF
        systemctl restart systemd-journald'

    local JSIZE JBOOTS
    JSIZE=$(journalctl --disk-usage 2>/dev/null \
        | grep -oP '[\d.]+\s*[A-Za-z]+' | head -1 || echo "unknown")
    JBOOTS=$(journalctl --list-boots --no-pager 2>/dev/null | wc -l || echo "1")
    log_ok "Journal: persistent, 500MB cap, 6mo retention, $JBOOTS boot(s)"

    # -- logrotate --
    run_silent "Installing logrotate" \
        bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq logrotate'

    cat > /etc/logrotate.d/vps-hardening << EOF
${VPS_LOG_DIR}/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    dateext
    dateformat -%Y%m%d
    sharedscripts
    postrotate
        systemctl kill -s HUP rsyslog.service > /dev/null 2>&1 || true
    endscript
}
EOF
    log_ok "logrotate: 90-day retention, compressed, dated"

    # -- Log directory protection --
    for DIR in /var/log "${VPS_LOG_DIR}"; do
        mkdir -p "$DIR"
        chmod 1775 "$DIR"
        chown root:adm "$DIR" 2>/dev/null || true
    done
    if [[ -d /var/log/journal ]]; then
        chmod 2755 /var/log/journal
        chown root:systemd-journal /var/log/journal 2>/dev/null || true
    fi
    log_ok "Log directories: sticky bit + restricted permissions"

    # -- Log integrity checksums --
    # Define watched files in outer scope for count
    local WATCHED_FILES=(
        /etc/ssh/sshd_config
        /etc/ssh/sshd_config.d/99-hardened.conf
        /etc/fail2ban/jail.local
        /etc/sudoers
        /etc/passwd
        /etc/shadow
        /etc/group
        /etc/hosts
        /etc/crontab
    )
    local WATCHED_COUNT="${#WATCHED_FILES[@]}"

    cat > /usr/local/sbin/vps-log-integrity << 'INTEGRITY_EOF'
#!/bin/bash
STATE_DIR="/var/lib/vps-hardening"
BASELINE="${STATE_DIR}/log-checksums.sha256"
LOGFILE="/var/log/vps-hardening/integrity.log"
TS=$(date '+%Y-%m-%dT%H:%M:%S')

WATCHED=(
    /etc/ssh/sshd_config
    /etc/ssh/sshd_config.d/99-hardened.conf
    /etc/fail2ban/jail.local
    /etc/sudoers
    /etc/passwd
    /etc/shadow
    /etc/group
    /etc/hosts
    /etc/crontab
)

mkdir -p "$STATE_DIR"
mkdir -p "$(dirname "$LOGFILE")"

if [[ ! -f "$BASELINE" ]]; then
    sha256sum "${WATCHED[@]}" 2>/dev/null > "$BASELINE"
    chmod 600 "$BASELINE"
    echo "${TS} Baseline created: ${#WATCHED[@]} files" >> "$LOGFILE"
    exit 0
fi

CURRENT=$(sha256sum "${WATCHED[@]}" 2>/dev/null)
DIFF=$(diff <(sort "$BASELINE") <(echo "$CURRENT" | sort) 2>/dev/null || true)

if [[ -n "$DIFF" ]]; then
    echo "${TS} ALERT: Integrity change detected!" >> "$LOGFILE"
    echo "$DIFF" >> "$LOGFILE"
    logger -t vps-integrity -p auth.alert \
        "INTEGRITY ALERT: Critical file changed — check ${LOGFILE}"
    # Update baseline to avoid alert spam — admin is expected to review log
    sha256sum "${WATCHED[@]}" 2>/dev/null > "${BASELINE}.new"
    mv "${BASELINE}.new" "$BASELINE"
else
    echo "${TS} OK: All ${#WATCHED[@]} files match baseline" >> "$LOGFILE"
fi
INTEGRITY_EOF
    chmod 750 /usr/local/sbin/vps-log-integrity

    /usr/local/sbin/vps-log-integrity
    log_ok "Integrity baseline created (${WATCHED_COUNT} files watched)"

    local CRON_INTEG="0 5 * * * /usr/local/sbin/vps-log-integrity"
    ( crontab -l 2>/dev/null || true ) \
        | grep -qF "vps-log-integrity" \
        || { ( crontab -l 2>/dev/null || true; echo "$CRON_INTEG" ) | crontab -; }
    log_ok "Integrity check: daily 05:00"

    phase_done "07"
    print_phase_done "07"
}

# =============================================================================
# PHASE 08 — PACKAGE CLEANUP
# =============================================================================

phase_08() {
    print_phase "08" "Package Cleanup" "Less software = fewer vulnerabilities"

    phase_complete "08" && { log_ok "Phase 08 done — skipping"; print_phase_done "08"; return 0; }

    local REMOVE=()
    for PKG in nfs-common open-iscsi ssh-import-id telnet netcat-traditional ftp; do
        dpkg -l "$PKG" 2>/dev/null | grep -q "^ii" && REMOVE+=("$PKG")
    done

    if [[ ${#REMOVE[@]} -gt 0 ]]; then
        run_silent "Removing: ${REMOVE[*]}" \
            bash -c "DEBIAN_FRONTEND=noninteractive \
                apt-get remove -y -qq ${REMOVE[*]}"
    fi

    run_silent "Running autoremove" \
        bash -c 'DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq'

    run_silent "Cleaning apt cache" \
        bash -c 'apt-get clean -qq'

    echo ""
    log_ok "Cleanup: ${#REMOVE[@]} package(s) removed"
    phase_done "08"
    print_phase_done "08"
}

# =============================================================================
# PHASE 09 — UNATTENDED UPGRADES
# =============================================================================

phase_09() {
    print_phase "09" "Automatic Security Updates" \
        "Security patches daily — safe auto-reboot at 03:00"

    phase_complete "09" && { log_ok "Phase 09 done — skipping"; print_phase_done "09"; return 0; }

    policy_block_start
    run_silent "Installing unattended-upgrades" \
        bash -c 'DEBIAN_FRONTEND=noninteractive \
            apt-get install -y -qq unattended-upgrades apt-listchanges'
    policy_allow_start

    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::Verbose "false";
Unattended-Upgrade::Mail "root";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    systemctl enable apt-daily.timer apt-daily-upgrade.timer \
        > /dev/null 2>&1 || true
    systemctl start  apt-daily.timer apt-daily-upgrade.timer \
        > /dev/null 2>&1 || true
    log_ok "APT daily timers enabled"

    cat > /usr/local/sbin/vps-safe-reboot << 'REBOOT_EOF'
#!/bin/bash
LOGFILE="/var/log/vps-hardening/reboot.log"
TS=$(date '+%Y-%m-%dT%H:%M:%S')
log() { echo "${TS} $*" | tee -a "$LOGFILE"; }

[[ ! -f /var/run/reboot-required ]] && { log "No reboot needed."; exit 0; }

SESSIONS=$(who | grep -c "pts\|tty" || echo 0)
[[ "$SESSIONS" -gt 0 ]] && { log "Deferred — $SESSIONS session(s) active."; exit 0; }

LOAD=$(awk '{print $1}' /proc/loadavg)
CORES=$(nproc)
if awk "BEGIN {exit !($LOAD > $CORES)}"; then
    log "Deferred — load $LOAD > $CORES."
    exit 0
fi

log "Rebooting: $(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')"
systemctl reboot
REBOOT_EOF
    chmod 750 /usr/local/sbin/vps-safe-reboot

    cat > /etc/systemd/system/vps-safe-reboot.service << 'EOF'
[Unit]
Description=VPS safe reboot after unattended-upgrades
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vps-safe-reboot
EOF

    cat > /etc/systemd/system/vps-safe-reboot.timer << 'EOF'
[Unit]
Description=VPS safe reboot check — daily 03:00
Requires=vps-safe-reboot.service
[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=600
Persistent=true
[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable vps-safe-reboot.timer > /dev/null 2>&1 || true
    systemctl start  vps-safe-reboot.timer > /dev/null 2>&1 || true
    log_ok "Safe auto-reboot: daily 03:00 (only if needed + no sessions + low load)"

    if ! unattended-upgrades --dry-run --debug > /tmp/uu-test.log 2>&1; then
        log_warn "unattended-upgrades dry-run had warnings — see /tmp/uu-test.log"
    else
        log_ok "unattended-upgrades configuration validated"
        rm -f /tmp/uu-test.log
    fi

    phase_done "09"
    print_phase_done "09"
}

# =============================================================================
# PHASE 10 — KERNEL HARDENING (sysctl)
# =============================================================================

phase_10() {
    print_phase "10" "Kernel Hardening" "sysctl — stops network attacks + hardens memory"

    phase_complete "10" && { log_ok "Phase 10 done — skipping"; print_phase_done "10"; return 0; }

    if [[ "$ENABLE_SYSCTL" != "true" ]]; then
        log_info "Kernel sysctl hardening skipped (not selected)"
        phase_done "10"
        print_phase_done "10"
        return 0
    fi

    cat > /etc/sysctl.d/99-vps-hardening.conf << 'EOF'
# vps-hardening sysctl — network + memory hardening

# ── Network: Stop common attack vectors ──────────────────────────────────────
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── Memory: Stop exploitation techniques ─────────────────────────────────────
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.sysrq = 0
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 1

# ── Filesystem ────────────────────────────────────────────────────────────────
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 1
fs.protected_regular = 2

# ── Network performance + security ───────────────────────────────────────────
net.core.somaxconn = 1024
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
EOF

    run_silent "Applying sysctl settings" \
        bash -c 'sysctl --system > /dev/null 2>&1'

    log_ok "Kernel hardening applied — settings persist across reboots"

    phase_done "10"
    print_phase_done "10"
}

# =============================================================================
# PHASE 11 — AUDITD
# =============================================================================

phase_11() {
    print_phase "11" "Kernel Audit Logging" \
        "auditd — kernel-level activity that rootkits cannot hide from"

    phase_complete "11" && { log_ok "Phase 11 done — skipping"; print_phase_done "11"; return 0; }

    if [[ "$ENABLE_AUDITD" != "true" ]]; then
        log_info "auditd skipped (not selected)"
        _install_optional_tools
        phase_done "11"
        print_phase_done "11"
        return 0
    fi

    policy_block_start
    run_silent "Installing auditd" \
        bash -c 'DEBIAN_FRONTEND=noninteractive \
            apt-get install -y -qq auditd audispd-plugins'
    policy_allow_start

    cat > /etc/audit/rules.d/99-hardening.rules << 'EOF'
# vps-hardening audit rules
-D
-b 8192
-f 1

# ── Identity files ────────────────────────────────────────────────────────────
-w /etc/passwd   -p wa -k identity
-w /etc/shadow   -p wa -k identity
-w /etc/group    -p wa -k identity
-w /etc/gshadow  -p wa -k identity

# ── Sudoers ───────────────────────────────────────────────────────────────────
-w /etc/sudoers    -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# ── SSH config ────────────────────────────────────────────────────────────────
-w /etc/ssh/sshd_config     -p wa -k sshd
-w /etc/ssh/sshd_config.d/  -p wa -k sshd

# ── Privilege escalation ──────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S setuid    -F a0=0 -F exe=/usr/bin/su -k su-root
-a always,exit -F arch=b64 -S setresuid -k privilege-escalation
-a always,exit -F arch=b32 -S setresuid -k privilege-escalation

# ── Cron (persistence mechanism) ─────────────────────────────────────────────
-w /etc/cron.d/        -p wa -k cron
-w /etc/cron.daily/    -p wa -k cron
-w /etc/cron.hourly/   -p wa -k cron
-w /var/spool/cron/    -p wa -k cron

# ── Kernel modules (rootkit technique) ───────────────────────────────────────
-w /sbin/insmod   -p x -k module-load
-w /sbin/rmmod    -p x -k module-load
-w /sbin/modprobe -p x -k module-load
-a always,exit -F arch=b64 -S init_module -S delete_module -k module-load

# ── Network connections ───────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S connect -k network-connect
-a always,exit -F arch=b32 -S connect -k network-connect

# ── File deletions ────────────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete

# ── Immutable ─────────────────────────────────────────────────────────────────
-e 2
EOF

    run_silent "Loading audit rules" \
        bash -c 'augenrules --load > /dev/null 2>&1 || true'

    systemctl enable auditd > /dev/null 2>&1 || true
    run_silent "Starting auditd" systemctl start auditd

    if wait_for_service auditd 15; then
        log_ok "auditd active — kernel-level logging enabled"
        log_info "Query: ausearch -k identity | ausearch -k sudoers"
    else
        log_warn "auditd slow to start — check: journalctl -u auditd -n 20"
    fi

    _install_optional_tools
    phase_done "11"
    print_phase_done "11"
}

# Optional tools: rkhunter, chkrootkit, clamav, aide
_install_optional_tools() {

    # -----------------------------------------------------------------------
    # rkhunter + chkrootkit
    # -----------------------------------------------------------------------
    if [[ "$ENABLE_RKHUNTER" == "true" ]]; then
        log_step "Installing rkhunter + chkrootkit"

        policy_block_start

        run_silent "Installing rkhunter + chkrootkit" \
            bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rkhunter chkrootkit'

        policy_allow_start

        run_silent "Updating rkhunter database" \
            bash -c 'rkhunter --update >/dev/null 2>&1 || logger -t rkhunter "Unable to update database"'

        run_silent "Creating rkhunter baseline" \
            bash -c 'rkhunter --propupd >/dev/null 2>&1 || true'

        cat > /etc/cron.daily/vps-rkhunter <<'EOF'
#!/bin/bash
rkhunter --check --skip-keypress --report-warnings-only \
    --logfile /var/log/vps-hardening/rkhunter.log >/dev/null 2>&1 || true
EOF

        cat > /etc/cron.daily/vps-chkrootkit <<'EOF'
#!/bin/bash
chkrootkit 2>/dev/null \
    | grep -v "not infected" \
    | grep -v "nothing found" \
    | grep -v "^$" \
    >> /var/log/vps-hardening/chkrootkit.log || true
EOF

        chmod +x /etc/cron.daily/vps-rkhunter
        chmod +x /etc/cron.daily/vps-chkrootkit

        log_ok "rkhunter + chkrootkit installed (daily scans)"
    fi

    # -----------------------------------------------------------------------
    # ClamAV
    # -----------------------------------------------------------------------
    if [[ "$ENABLE_CLAMAV" == "true" ]]; then

        log_step "Installing ClamAV"

        policy_block_start

        run_silent "Installing ClamAV" \
            bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clamav clamav-daemon'

        policy_allow_start

        run_silent "Updating ClamAV signatures" \
            bash -c '
                if systemctl list-unit-files | grep -q "^clamav-freshclam"; then
                    systemctl stop clamav-freshclam 2>/dev/null || true
                elif systemctl list-unit-files | grep -q "^freshclam"; then
                    systemctl stop freshclam 2>/dev/null || true
                fi

                freshclam >/dev/null 2>&1 || true

                if systemctl list-unit-files | grep -q "^clamav-freshclam"; then
                    systemctl start clamav-freshclam 2>/dev/null || true
                elif systemctl list-unit-files | grep -q "^freshclam"; then
                    systemctl start freshclam 2>/dev/null || true
                fi
            '

        cat >/etc/cron.daily/vps-clamav <<'EOF'
#!/bin/bash

LOGFILE="/var/log/vps-hardening/clamav.log"

echo "=== Scan $(date '+%Y-%m-%d %H:%M') ===" >> "$LOGFILE"

clamscan -r \
    --exclude-dir=/proc \
    --exclude-dir=/sys \
    --exclude-dir=/dev \
    --exclude-dir=/run \
    --infected \
    --quiet \
    / >> "$LOGFILE" 2>&1

if grep -q "FOUND" "$LOGFILE"; then
    logger -t clamav -p auth.alert \
        "MALWARE DETECTED - check $LOGFILE"
fi
EOF

        chmod +x /etc/cron.daily/vps-clamav

        log_ok "ClamAV installed (daily scan)"
    fi

    # -----------------------------------------------------------------------
    # AIDE
    # -----------------------------------------------------------------------
    if [[ "$ENABLE_AIDE" == "true" ]]; then

        log_step "Installing AIDE (full filesystem integrity)"
        log_info "This takes 5–10 minutes for the initial baseline..."

        policy_block_start

        run_silent "Installing AIDE" \
            bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq aide'

        policy_allow_start

        # Locate configuration
        AIDE_CONF=""

        for conf in \
            /etc/aide/aide.conf \
            /etc/aide.conf
        do
            if [[ -f "$conf" ]]; then
                AIDE_CONF="$conf"
                break
            fi
        done

        if [[ -z "$AIDE_CONF" ]]; then

            log_warn "AIDE configuration not found. Skipping setup."

        else

            run_silent "Building AIDE baseline (be patient)" \
                bash -c "
                    if command -v aideinit >/dev/null 2>&1; then
                        aideinit >/dev/null 2>&1 || exit 1
                    else
                        aide --config=\"$AIDE_CONF\" --init >/dev/null 2>&1 || exit 1
                    fi
                "

            run_silent "Installing AIDE database" \
                bash -c '
                    NEW_DB=$(find /var/lib/aide \
                        -maxdepth 1 \
                        -type f \
                        -name "aide.db.new*" \
                        | sort \
                        | head -n1)

                    if [[ -n "$NEW_DB" ]]; then
                        mv "$NEW_DB" "${NEW_DB/.new/}"
                    else
                        exit 1
                    fi
                '

            if compgen -G "/var/lib/aide/aide.db*" >/dev/null; then

                log_ok "AIDE baseline created"

                cat >/etc/cron.daily/vps-aide <<'EOF'
#!/bin/bash

CONF=""

for f in \
    /etc/aide/aide.conf \
    /etc/aide.conf
do
    [[ -f "$f" ]] && {
        CONF="$f"
        break
    }
done

[[ -z "$CONF" ]] && exit 0

aide --config="$CONF" --check \
    >> /var/log/vps-hardening/aide.log 2>&1

if [[ $? -ne 0 ]]; then
    logger -t aide -p auth.alert \
        "AIDE: filesystem changes detected - check aide.log"
fi
EOF

                chmod +x /etc/cron.daily/vps-aide

                log_ok "AIDE installed (daily integrity monitoring)"

            else

                log_warn "AIDE baseline was not created. Daily checks disabled."

            fi

        fi
    fi
}

set_user_password() {
    local user="$1"

    while true; do
        echo ""
        passwd "$user"

        if id "$user" >/dev/null 2>&1; then
            echo "✅ User exists and password likely set"
            break
        fi

        echo "❌ Password not confirmed. Retrying..."
    done
}
# =============================================================================
# PHASE 12 — ADMIN ACCOUNT + FINAL SSH LOCKDOWN
# =============================================================================

phase_12() {
    print_phase "12" "Admin Account + Final Lockdown" \
        "Create account → test → lock root → close port 22"

    phase_complete "12" && { log_ok "Phase 12 done — skipping"; print_phase_done "12"; return 0; }

    if id "$INPUT_USERNAME" > /dev/null 2>&1; then
        log_warn "User $INPUT_USERNAME already exists — skipping creation"
    else
        echo -e "  ${BOLD}Create password for ${GREEN}$INPUT_USERNAME${NC}${BOLD}:${NC}"
        echo ""
        adduser --gecos "" "$INPUT_USERNAME"

        echo ""
        echo "🔐 Setting password for $INPUT_USERNAME"

        set_user_password "$INPUT_USERNAME"
    fi

    if ! passwd -S "$INPUT_USERNAME" >/dev/null 2>&1; then
    log_error "Password not set or user invalid — aborting Phase 12"
    exit 1
    fi
    
    echo ""
    run_silent "Adding $INPUT_USERNAME to sudo + adm" bash -c "
        usermod -aG sudo $INPUT_USERNAME
        usermod -aG adm  $INPUT_USERNAME"

    # Set up sudo with password (no NOPASSWD for new admin)
    cat > "/etc/sudoers.d/99-${INPUT_USERNAME}" << EOF
# vps-hardening: $INPUT_USERNAME sudo config
$INPUT_USERNAME ALL=(ALL:ALL) ALL
Defaults:$INPUT_USERNAME timestamp_timeout=5
EOF
    chmod 440 "/etc/sudoers.d/99-${INPUT_USERNAME}"
    log_ok "sudo configured for $INPUT_USERNAME (5-min timeout)"

    # SSH key for new account
    mkdir -p "/home/$INPUT_USERNAME/.ssh"
    chmod 700 "/home/$INPUT_USERNAME/.ssh"

    if [[ "$AUTH_TYPE" == "key" ]]; then
        local KEY_CONTENT=""
        if [[ -n "${INPUT_PUBLIC_KEY:-}" ]]; then
            KEY_CONTENT="$INPUT_PUBLIC_KEY"
            log_info "Using the key you pasted"
        elif [[ "$INPUT_CLOUD_USER" != "root" ]] \
             && [[ -f "/home/$INPUT_CLOUD_USER/.ssh/authorized_keys" ]] \
             && [[ -s "/home/$INPUT_CLOUD_USER/.ssh/authorized_keys" ]]; then
            KEY_CONTENT=$(cat "/home/$INPUT_CLOUD_USER/.ssh/authorized_keys")
            log_info "Copying key from $INPUT_CLOUD_USER"
        elif [[ -f "/root/.ssh/authorized_keys" ]] \
             && [[ -s "/root/.ssh/authorized_keys" ]]; then
            KEY_CONTENT=$(cat "/root/.ssh/authorized_keys")
            log_warn "Falling back to root's authorized_keys — verify these are yours"
        fi

        if [[ -n "$KEY_CONTENT" ]]; then
            echo "$KEY_CONTENT" > "/home/$INPUT_USERNAME/.ssh/authorized_keys"
            chmod 600 "/home/$INPUT_USERNAME/.ssh/authorized_keys"
            log_ok "SSH key installed for $INPUT_USERNAME"
        else
            log_warn "No key found — $INPUT_USERNAME will use password"
        fi
    fi

    chown -R "$INPUT_USERNAME:$INPUT_USERNAME" "/home/$INPUT_USERNAME/.ssh"

    # Harden home directory permissions
    chmod 750 "/home/$INPUT_USERNAME"
    log_ok "Home directory permissions: 750"

    print_box "TEST YOUR NEW ACCOUNT" "$YELLOW"
    echo -e "  Open a NEW terminal:"
    if [[ "$AUTH_TYPE" == "key" ]]; then
        echo -e "    ${CYAN}ssh -i /path/to/key -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    else
        echo -e "    ${CYAN}ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    fi
    echo -e "  Then verify sudo:"
    echo -e "    ${CYAN}sudo id${NC}  ${DIM}(should show uid=0)${NC}"
    echo ""
    echo -e "  ${RED}Keep THIS session open!${NC}"
    echo ""
    read -rp "  Login + sudo both succeeded? (yes/no): " ACCT_TEST

    if [[ "$ACCT_TEST" != "yes" ]]; then
        log_error "Test failed — lockdown NOT applied. Root preserved."
        log_info "Diagnose: id $INPUT_USERNAME | passwd $INPUT_USERNAME"
        {
            echo "sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' \\"
            echo "    /etc/ssh/sshd_config.d/99-hardened.conf"
            echo "echo 'AllowUsers $INPUT_USERNAME' | sudo tee -a \\"
            echo "    /etc/ssh/sshd_config.d/99-hardened.conf"
            echo "sudo ufw delete allow 22/tcp"
            echo "sudo sshd -t && sudo systemctl restart ssh"
        } >> "${VPS_INSTALL_LOG}"
        log_warn "Continuing to Phase 13 without lockdown..."
        return 0
    fi

    # Write final SSH config
    local CRYPTO_BLOCK="KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"

    if [[ "$AUTH_TYPE" == "key" ]]; then
        cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# FINAL hardened SSH — vps-hardening ${VPS_VERSION} — $(date)
Port $INPUT_SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
MaxAuthTries 3
MaxStartups 10:30:60
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 3
TCPKeepAlive no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
PermitUserRC no
DisableForwarding yes
PrintMotd no
PrintLastLog yes
Banner /etc/issue.net
LogLevel VERBOSE
AllowUsers $INPUT_USERNAME
${CRYPTO_BLOCK}
EOF
    else
        cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# FINAL hardened SSH — vps-hardening ${VPS_VERSION} — $(date)
Port $INPUT_SSH_PORT
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
MaxStartups 10:30:60
MaxSessions 2
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 3
TCPKeepAlive no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
PermitUserRC no
DisableForwarding yes
PrintMotd no
PrintLastLog yes
Banner /etc/issue.net
LogLevel VERBOSE
AllowUsers $INPUT_USERNAME
${CRYPTO_BLOCK}
EOF
    fi

    if sshd -t 2>/dev/null; then
        run_silent "Applying final SSH lockdown" systemctl restart ssh
        log_ok "Root login disabled — only ${BOLD}$INPUT_USERNAME${NC} can log in"
        ufw delete allow 22/tcp   > /dev/null 2>&1 || true
        ufw delete limit 22/tcp   > /dev/null 2>&1 || true
        log_ok "Port 22 closed — only ${BOLD}$INPUT_SSH_PORT${NC} accessible"
    else
        log_error "SSH config error — keeping safe config, NOT restarting"
    fi

    # Demote cloud user
    if [[ "$INPUT_CLOUD_USER" != "root" && "$INPUT_CLOUD_USER" != "$INPUT_USERNAME" ]]; then
        for GRP in sudo lxd cdrom dip; do
            deluser "$INPUT_CLOUD_USER" "$GRP" 2>/dev/null || true
        done
        passwd -l "$INPUT_CLOUD_USER" > /dev/null 2>&1 || true
        log_ok "$INPUT_CLOUD_USER demoted and locked"
    fi

    # Remove NOPASSWD from cloud sudoers
    local SUDOERS_FILE=""
    for F in /etc/sudoers.d/*; do
        grep -q "${INPUT_CLOUD_USER}" "$F" 2>/dev/null \
            && { SUDOERS_FILE="$F"; break; }
    done

    if [[ -n "$SUDOERS_FILE" ]]; then
        local TMP_SUDOERS
        TMP_SUDOERS=$(mktemp)
        sed "s|${INPUT_CLOUD_USER} ALL=(ALL) NOPASSWD:ALL|${INPUT_CLOUD_USER} ALL=(ALL) ALL|g;
             s|${INPUT_CLOUD_USER} ALL=(ALL:ALL) NOPASSWD:ALL|${INPUT_CLOUD_USER} ALL=(ALL:ALL) ALL|g" \
            "$SUDOERS_FILE" > "$TMP_SUDOERS"

        if visudo -c -f "$TMP_SUDOERS" > /dev/null 2>&1; then
            cp "$SUDOERS_FILE" "${SUDOERS_FILE}.backup"
            mv "$TMP_SUDOERS" "$SUDOERS_FILE"
            log_ok "NOPASSWD removed from $INPUT_CLOUD_USER"
        else
            rm -f "$TMP_SUDOERS"
            log_warn "sudoers unchanged — visudo validation failed (safe)"
        fi
    fi

    phase_done "12"
    print_phase_done "12"
}

# =============================================================================
# PHASE 13 — MONITORING
# =============================================================================

phase_13() {
    print_phase "13" "Security Monitoring" \
        "Daily audit + check-alerts dashboard"

    phase_complete "13" && { log_ok "Phase 13 done — skipping"; print_phase_done "13"; return 0; }

    local SCRIPTS_DIR="/opt/${INPUT_HOSTNAME}/scripts"
    local BASELINE_DIR="/opt/${INPUT_HOSTNAME}/baseline"
    local AUDIT_LOG="${VPS_LOG_DIR}/${INPUT_HOSTNAME}-audit.log"

    state_set "SCRIPTS_DIR"  "$SCRIPTS_DIR"
    state_set "BASELINE_DIR" "$BASELINE_DIR"
    state_set "AUDIT_LOG"    "$AUDIT_LOG"

    run_silent "Creating directories" \
        mkdir -p "$SCRIPTS_DIR" "$BASELINE_DIR" "${VPS_LOG_DIR}"

    # SUID baseline
    safe_find_suid > "${BASELINE_DIR}/suid-baseline.txt"
    chmod 600 "${BASELINE_DIR}/suid-baseline.txt"
    local SUID_COUNT
    SUID_COUNT=$(wc -l < "${BASELINE_DIR}/suid-baseline.txt")
    log_ok "SUID baseline: ${BOLD}$SUID_COUNT${NC} binaries tracked"

    # --- daily-audit.sh ---
    cat > "${SCRIPTS_DIR}/daily-audit.sh" << AUDIT_EOF
#!/bin/bash
# daily-audit.sh — vps-hardening ${VPS_VERSION}
LOGFILE="${AUDIT_LOG}"
DATE=\$(date '+%Y-%m-%d %H:%M:%S')

{
echo "========================================"
echo "Audit: \${DATE} | Host: \$(hostname -s)"
echo "========================================"

echo "--- Reboot Status ---"
if [[ -f /var/run/reboot-required ]]; then
    echo "REBOOT REQUIRED: \$(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')"
else
    echo "No reboot required"
fi

echo "--- Kernel ---"
echo "Running  : \$(uname -r)"
echo "Installed: \$(dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' \
    | awk '{print \$2}' | grep -v generic | sort -V | tail -1)"

echo "--- System Health ---"
echo "Uptime: \$(uptime)"
df -h /
free -h
echo "Load: \$(cat /proc/loadavg)"

echo "--- Failed SSH (24h) ---"
FAILED=\$(journalctl -u ssh --since '24 hours ago' 2>/dev/null \
    | grep -c 'Invalid user\|Failed password' || echo 0)
echo "Failed: \$FAILED"
journalctl -u ssh --since '24 hours ago' 2>/dev/null \
    | grep -i 'failed\|invalid' | tail -10

echo "--- fail2ban (24h) ---"
journalctl -u fail2ban --since '24 hours ago' 2>/dev/null \
    | grep 'Ban' || echo 'No bans.'

echo "--- Unattended-Upgrades ---"
grep -i 'upgraded\|error\|warning' \
    /var/log/unattended-upgrades/*.log 2>/dev/null | tail -10 \
    || echo 'No recent upgrade entries.'

echo "--- SUID Changes ---"
find / -perm -4000 -type f 2>/dev/null \
    | grep -v -E '/(snap|proc|sys)/' | sort > /tmp/suid-now.txt || true
SDIFF=\$(diff ${BASELINE_DIR}/suid-baseline.txt /tmp/suid-now.txt 2>/dev/null || true)
[[ -z "\$SDIFF" ]] && echo 'No SUID changes.' \
    || { echo 'WARNING: SUID changed!'; echo "\$SDIFF"; }
rm -f /tmp/suid-now.txt

echo "--- Integrity ---"
[[ -x /usr/local/sbin/vps-log-integrity ]] \
    && /usr/local/sbin/vps-log-integrity

echo "--- Open Ports ---"
ss -tlnp

echo "--- Users ---"
who
last | head -5

echo "--- Sudo (24h) ---"
journalctl --since '24 hours ago' 2>/dev/null \
    | grep 'sudo' | grep -v 'pam_unix' || true

echo "--- New/Modified files in /etc (24h) ---"
find /etc -newer /etc/passwd -type f 2>/dev/null | head -20 || true

echo ""
} >> "\$LOGFILE"
AUDIT_EOF

    # --- .check-alerts-env ---
    cat > "${SCRIPTS_DIR}/.check-alerts-env" << ENV_EOF
# vps-hardening ${VPS_VERSION} — auto-generated
BASELINE_DIR="${BASELINE_DIR}"
AUDIT_LOG="${AUDIT_LOG}"
VPS_VERSION="${VPS_VERSION}"
ENABLE_SYSCTL="${ENABLE_SYSCTL}"
ENABLE_AUDITD="${ENABLE_AUDITD}"
ENABLE_RKHUNTER="${ENABLE_RKHUNTER}"
ENABLE_CLAMAV="${ENABLE_CLAMAV}"
ENABLE_AIDE="${ENABLE_AIDE}"
SSH_PORT="${INPUT_SSH_PORT}"
ADMIN_USER="${INPUT_USERNAME}"
ENV_EOF
    chmod 640 "${SCRIPTS_DIR}/.check-alerts-env"

    # --- check-alerts.sh ---
    cat > "${SCRIPTS_DIR}/check-alerts.sh" << 'ALERTS_EOF'
#!/bin/bash
# check-alerts.sh — vps-hardening interactive dashboard

# 1. Safely resolve the real physical script directory, even if executed via a Symlink
REAL_SOURCE="${BASH_SOURCE[0]}"
while [ -h "$REAL_SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$REAL_SOURCE")" && pwd)"
    REAL_SOURCE="$(readlink "$REAL_SOURCE")"
    [[ $REAL_SOURCE != /* ]] && REAL_SOURCE="$DIR/$REAL_SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$REAL_SOURCE")" && pwd)"

# 2. Source the environment file using its true absolute path location
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/.check-alerts-env" 2>/dev/null || {
    echo "Error: .check-alerts-env missing from ${SCRIPT_DIR}" >&2; exit 1
}

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; WHITE='\033[1;37m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

ALERTS=0; WARNINGS=0
ALERT_LIST=()
WARN_LIST=()

check() {
    case "$1" in
        ok)   echo -e "  ${GREEN}✓${NC}  $2" ;;
        warn) echo -e "  ${YELLOW}⚠${NC}  $2"; WARNINGS=$((WARNINGS+1)); WARN_LIST+=("$2") ;;
        crit) echo -e "  ${RED}✗${NC}  $2";    ALERTS=$((ALERTS+1)); ALERT_LIST+=("$2") ;;
        info) echo -e "  ${CYAN}ℹ${NC}  $2" ;;
    esac
}

section() {
    echo ""
    echo -e "  ${BOLD}${WHITE}$1${NC}"
    echo -e "  ${DIM}$(printf '%.0s─' {1..54})${NC}"
    echo ""
}

clear
echo ""
echo -e "${BOLD}${CYAN}  ╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}  ║${NC}  ${BOLD}${WHITE}🛡️  Security Status — $(hostname)${NC}"
echo -e "${BOLD}${CYAN}  ║${NC}  ${DIM}$(date '+%Y-%m-%d %H:%M:%S') • $(uptime -p 2>/dev/null) • vps-hardening ${VPS_VERSION}${NC}"
echo -e "${BOLD}${CYAN}  ╚══════════════════════════════════════════════════════════╝${NC}"

# ── System ────────────────────────────────────────────────────────────────────
section "System Status"
if [[ -f /var/run/reboot-required ]]; then
    REASON=$(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')
    check "warn" "Reboot required: ${REASON:-kernel update}"
else
    check "ok" "No reboot required"
fi

RUNNING=$(uname -r)
INSTALLED=$(dpkg -l 'linux-image-*' 2>/dev/null \
    | grep "^ii" | awk '{print $2}' \
    | grep -v generic | sort -V | tail -1 \
    | sed 's/linux-image-//' || echo "")
if [[ -n "$INSTALLED" && "$RUNNING" != *"$INSTALLED"* ]]; then
    check "warn" "Kernel mismatch — running: $RUNNING | installed: $INSTALLED"
else
    check "ok" "Kernel: $RUNNING"
fi

if systemctl is-enabled --quiet apt-daily-upgrade.timer 2>/dev/null; then
    LAST_RUN=$(stat -c %y /var/log/unattended-upgrades/ 2>/dev/null | cut -d' ' -f1 || echo "unknown")
    check "ok" "Auto security updates: active (last: $LAST_RUN)"
else
    check "warn" "Auto security updates: not active"
fi

TZ_NOW=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "unknown")
NTP=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null || echo "no")
[[ "$NTP" == "yes" ]] \
    && check "ok" "Time: ${TZ_NOW} — NTP synced" \
    || check "warn" "Time: ${TZ_NOW} — NTP NOT synced"

# ── Resources ─────────────────────────────────────────────────────────────────
section "Resources"
DISK=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
DISK_FREE=$(df -h / | tail -1 | awk '{print $4}')
if   [ "$DISK" -gt 80 ]; then check "crit" "Disk: ${DISK}% used — ${DISK_FREE} free (critical)"
elif [ "$DISK" -gt 60 ]; then check "warn" "Disk: ${DISK}% used — ${DISK_FREE} free"
else                           check "ok"   "Disk: ${DISK}% used — ${DISK_FREE} free"
fi

MEM=$(free | grep Mem | awk '{printf "%.0f", $3/$2*100}')
MEM_FREE=$(free -h | grep Mem | awk '{print $7}')
if   [ "$MEM" -gt 90 ]; then check "crit" "Memory: ${MEM}% — ${MEM_FREE} available"
elif [ "$MEM" -gt 75 ]; then check "warn" "Memory: ${MEM}% — ${MEM_FREE} available"
else                          check "ok"   "Memory: ${MEM}% — ${MEM_FREE} available"
fi

LOAD=$(awk '{print $1}' /proc/loadavg)
LOAD5=$(awk '{print $2}' /proc/loadavg)
LOAD15=$(awk '{print $3}' /proc/loadavg)
CORES=$(nproc)
check "info" "Load avg: ${LOAD} ${LOAD5} ${LOAD15} (${CORES} cores)"

# ── Intrusion protection ──────────────────────────────────────────────────────
section "Intrusion Protection"
FAILED=$(journalctl -u ssh --since "24 hours ago" 2>/dev/null \
    | grep -c "Invalid user\|Failed password" || echo 0)
if   [ "$FAILED" -gt 200 ]; then check "crit" "Failed SSH (24h): $FAILED — investigate immediately"
elif [ "$FAILED" -gt 50  ]; then check "warn" "Failed SSH (24h): $FAILED"
else                              check "ok"   "Failed SSH (24h): $FAILED"
fi

# Top attacking IPs
if [ "$FAILED" -gt 10 ]; then
    echo ""
    echo -e "  ${DIM}  Top attacking IPs (24h):${NC}"
    journalctl -u ssh --since "24 hours ago" 2>/dev/null \
        | grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" \
        | awk '{print $2}' | sort | uniq -c | sort -rn | head -5 \
        | while read -r COUNT IP; do
            echo -e "    ${RED}$IP${NC} ${DIM}— $COUNT attempts${NC}"
        done
    echo ""
fi

if fail2ban-client ping > /dev/null 2>&1; then
    BANS=$(fail2ban-client status sshd 2>/dev/null \
        | grep "Currently banned" | awk '{print $NF}')
    TOTAL=$(fail2ban-client status sshd 2>/dev/null \
        | grep "Total banned" | awk '{print $NF}')
    BANS="${BANS:-0}"; TOTAL="${TOTAL:-0}"
    if [ "$BANS" -gt 0 ]; then
        check "info" "fail2ban: ${BOLD}$BANS${NC} banned now ($TOTAL total all-time)"
        fail2ban-client status sshd 2>/dev/null \
            | grep "Banned IP" | cut -d: -f2 \
            | tr ' ' '\n' | grep -v "^$" | head -5 \
            | while read -r IP; do echo -e "    ${DIM}  $IP${NC}"; done
    else
        check "ok" "fail2ban: None banned now ($TOTAL total all-time)"
    fi
else
    check "crit" "fail2ban not responding"
fi

# Recidive jail status
if fail2ban-client status recidive > /dev/null 2>&1; then
    REC_BANS=$(fail2ban-client status recidive 2>/dev/null \
        | grep "Currently banned" | awk '{print $NF}')
    REC_BANS="${REC_BANS:-0}"
    [ "$REC_BANS" -gt 0 ] \
        && check "info" "Recidive (7-day) jail: $REC_BANS repeat offender(s)" \
        || check "ok"   "Recidive jail: no repeat offenders"
fi

# ── File integrity ────────────────────────────────────────────────────────────
section "File Integrity"
if [ -f "${BASELINE_DIR}/suid-baseline.txt" ]; then
    find / -perm -4000 -type f 2>/dev/null \
        | grep -v -E '/(snap|proc|sys)/' | sort \
        > /tmp/suid-chk.txt || true
    SDIFF=$(diff "${BASELINE_DIR}/suid-baseline.txt" \
        /tmp/suid-chk.txt 2>/dev/null || true)
    rm -f /tmp/suid-chk.txt
    if [ -n "$SDIFF" ]; then
        check "crit" "SUID files changed!"
        echo -e "${RED}$SDIFF${NC}"
    else
        COUNT=$(wc -l < "${BASELINE_DIR}/suid-baseline.txt")
        check "ok" "SUID unchanged ($COUNT tracked)"
    fi
else
    check "warn" "SUID baseline not found"
fi

INTEG_LOG="/var/log/vps-hardening/integrity.log"
if [[ -f "$INTEG_LOG" ]]; then
    LAST=$(tail -1 "$INTEG_LOG")
    if echo "$LAST" | grep -qi "alert"; then
        check "crit" "Integrity: ALERT — critical file changed"
        echo -e "  ${DIM}  $LAST${NC}"
    else
        check "ok" "Integrity: $(echo "$LAST" | cut -c1-60)"
    fi
else
    check "warn" "Integrity log not found — run vps-log-integrity"
fi

if [[ "${ENABLE_AIDE:-false}" == "true" ]] \
   && [[ -f /var/log/vps-hardening/aide.log ]]; then
    AIDE_LAST=$(tail -1 /var/log/vps-hardening/aide.log)
    if echo "$AIDE_LAST" | grep -qi "changed\|error"; then
        check "crit" "AIDE: $AIDE_LAST"
    else
        check "ok" "AIDE: clean"
    fi
fi

if [[ "${ENABLE_RKHUNTER:-false}" == "true" ]] \
   && [[ -f /var/log/vps-hardening/rkhunter.log ]]; then
    RKWARN=$(grep -c "Warning" /var/log/vps-hardening/rkhunter.log 2>/dev/null || echo 0)
    [ "$RKWARN" -gt 0 ] \
        && check "warn" "rkhunter: $RKWARN warning(s)" \
        || check "ok"   "rkhunter: clean"
fi

if [[ "${ENABLE_CLAMAV:-false}" == "true" ]] \
   && [[ -f /var/log/vps-hardening/clamav.log ]]; then
    FOUND=$(grep -c "FOUND" /var/log/vps-hardening/clamav.log 2>/dev/null || echo 0)
    [ "$FOUND" -gt 0 ] \
        && check "crit" "ClamAV: $FOUND infection(s) found!" \
        || check "ok"   "ClamAV: clean"
fi

# ── Services ──────────────────────────────────────────────────────────────────
section "Critical Services"
for SVC in ssh fail2ban; do
    systemctl is-active --quiet "$SVC" 2>/dev/null \
        && check "ok" "$SVC running" \
        || check "crit" "$SVC NOT running — systemctl start $SVC"
done

ufw status 2>/dev/null | grep -q "Status: active" \
    && check "ok" "UFW active" \
    || check "crit" "UFW NOT active — ufw enable"

command -v aa-status > /dev/null 2>&1 && {
    ENF=$(aa-status 2>/dev/null \
        | grep "in enforce mode" | head -1 | awk '{print $1}' || echo 0)
    check "ok" "AppArmor: $ENF profiles enforcing"
}

[[ "${ENABLE_AUDITD:-false}" == "true" ]] && {
    systemctl is-active --quiet auditd 2>/dev/null \
        && check "ok" "auditd running" \
        || check "warn" "auditd not running"
}

# Check SSH is only on hardened port
SSH_PORTS=$(ss -tlnp | grep sshd | awk '{print $4}' | rev | cut -d: -f1 | rev | tr '\n' ' ')
check "info" "SSH listening on: ${SSH_PORTS:-unknown}"
if echo "$SSH_PORTS" | grep -qw "22"; then
    check "warn" "Port 22 still open — expected only ${SSH_PORT:-custom}"
fi

# ── Recent logins ─────────────────────────────────────────────────────────────
section "Recent Logins"
last -n 8 --time-format iso 2>/dev/null \
    | grep -v "^$\|^wtmp" \
    | while IFS= read -r line; do
        if echo "$line" | grep -qE "pts|tty"; then
            echo -e "  ${DIM}$line${NC}"
        fi
    done || echo -e "  ${DIM}No recent logins${NC}"

# ── Audit log tail ────────────────────────────────────────────────────────────
section "Recent Audit (last 5 lines)"
[[ -f "${AUDIT_LOG}" ]] \
    && tail -5 "${AUDIT_LOG}" | while IFS= read -r L; do
        echo -e "  ${DIM}$L${NC}"
    done \
    || echo -e "  ${DIM}No audit log yet — run: sudo vps-audit${NC}"

# ── Ports ─────────────────────────────────────────────────────────────────────
section "Listening Ports"
ss -tlnp | grep LISTEN | while IFS= read -r line; do
    PORT=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
    PROC=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "?")
    echo -e "    ${DIM}:${PORT}${NC} — $PROC"
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
if [ "$ALERTS" -gt 0 ]; then
    echo -e "  ${RED}${BOLD}✗  $ALERTS critical alert(s) require immediate action:${NC}"
    for A in "${ALERT_LIST[@]}"; do echo -e "     ${RED}• $A${NC}"; done
elif [ "$WARNINGS" -gt 0 ]; then
    echo -e "  ${YELLOW}${BOLD}⚠  $WARNINGS warning(s) — review when possible:${NC}"
    for W in "${WARN_LIST[@]}"; do echo -e "     ${YELLOW}• $W${NC}"; done
else
    echo -e "  ${GREEN}${BOLD}✓  All systems healthy — no alerts${NC}"
fi
echo ""
echo -e "  ${DIM}Commands: sudo vps-audit | sudo fail2ban-client status sshd | sudo ufw status${NC}"
echo -e "  ${DIM}Log: ${AUDIT_LOG}${NC}"
echo ""
ALERTS_EOF

    chmod 750 "${SCRIPTS_DIR}/daily-audit.sh" "${SCRIPTS_DIR}/check-alerts.sh"

    if id "$INPUT_USERNAME" > /dev/null 2>&1; then
        chown root:"$INPUT_USERNAME" \
            "${SCRIPTS_DIR}/daily-audit.sh" \
            "${SCRIPTS_DIR}/check-alerts.sh" \
            "${SCRIPTS_DIR}/.check-alerts-env"
    fi

    # Symlinks
    ln -sf "${SCRIPTS_DIR}/check-alerts.sh" /usr/local/bin/check-alerts
    ln -sf "${SCRIPTS_DIR}/daily-audit.sh"  /usr/local/bin/vps-audit

    # Cron
    local CRON_AUDIT="0 4 * * * ${SCRIPTS_DIR}/daily-audit.sh"
    ( crontab -l 2>/dev/null || true ) \
        | grep -qF "${SCRIPTS_DIR}/daily-audit.sh" \
        || { ( crontab -l 2>/dev/null || true; echo "$CRON_AUDIT" ) | crontab -; }
    log_ok "Daily audit: 04:00"

    run_silent "Running initial audit" \
        bash "${SCRIPTS_DIR}/daily-audit.sh"

    log_ok "Monitoring ready — run ${BOLD}${CYAN}sudo check-alerts${NC}"
    phase_done "13"
    print_phase_done "13"
}

# =============================================================================
# PHASE 14 — LOGIN BANNER + MOTD + SSH FINGERPRINT RECORD
# =============================================================================

phase_14() {
    print_phase "14" "Login Banner + MOTD + Hardening Record" \
        "Legal warning banner + dynamic MOTD + SSH fingerprint file"

    phase_complete "14" && { log_ok "Phase 14 done — skipping"; print_phase_done "14"; return 0; }

    # /etc/issue.net — shown by SSH before login (referenced in sshd_config Banner)
    cat > /etc/issue.net << EOF
╔══════════════════════════════════════════════════════════╗
║  WARNING: UNAUTHORIZED ACCESS PROHIBITED                 ║
╠══════════════════════════════════════════════════════════╣
║  ${BANNER_TEXT:0:54}
║                                                          ║
║  All activity is monitored and logged.                   ║
║  Violators will be prosecuted to the full extent of law. ║
╚══════════════════════════════════════════════════════════╝
EOF
    chmod 644 /etc/issue.net
    log_ok "SSH pre-login banner written to /etc/issue.net"

    # /etc/issue — shown on local console
    cp /etc/issue.net /etc/issue
    log_ok "Console banner written to /etc/issue"

    # Dynamic MOTD — shown after login
    # Disable default Ubuntu MOTD components that are noisy
    if [[ -d /etc/update-motd.d ]]; then
        for F in /etc/update-motd.d/*; do
            chmod -x "$F" 2>/dev/null || true
        done
        log_ok "Default Ubuntu MOTD components disabled"
    fi

    cat > /etc/update-motd.d/01-vps-hardening << 'MOTD_EOF'
#!/bin/bash
# Dynamic MOTD — vps-hardening

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; WHITE='\033[1;37m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

HOST=$(hostname -s)
KERNEL=$(uname -r)
UPTIME=$(uptime -p 2>/dev/null || uptime)
DISK=$(df -h / | tail -1 | awk '{print $5 " used (" $4 " free)"}')
MEM=$(free -h | grep Mem | awk '{print $3 " / " $2}')
LOAD=$(awk '{print $1, $2, $3}' /proc/loadavg)
LAST_LOGIN=$(last -n 2 --time-format iso "$USER" 2>/dev/null | grep -v "^$\|still" | tail -1)
TZ=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")

# Quick security pulse
FAILED_SSH=$(journalctl -u ssh --since "24 hours ago" 2>/dev/null \
    | grep -c 'Invalid user\|Failed password' 2>/dev/null || echo "?")
BANNED=$(fail2ban-client status sshd 2>/dev/null \
    | grep "Currently banned" | awk '{print $NF}' 2>/dev/null || echo "?")
REBOOT_NEEDED=""
[[ -f /var/run/reboot-required ]] && REBOOT_NEEDED="${YELLOW}⚠ Reboot required${NC}"

echo ""
echo -e "${BOLD}${CYAN}  ┌─────────────────────────────────────────────────────────┐${NC}"
echo -e "${BOLD}${CYAN}  │${NC}  ${BOLD}${WHITE}${HOST}${NC}  ${DIM}— Secured by vps-hardening${NC}"
echo -e "${BOLD}${CYAN}  └─────────────────────────────────────────────────────────┘${NC}"
echo ""
printf "  ${DIM}%-12s${NC} %s\n" "Kernel"  "$KERNEL"
printf "  ${DIM}%-12s${NC} %s\n" "Uptime"  "$UPTIME"
printf "  ${DIM}%-12s${NC} %s\n" "Load"    "$LOAD"
printf "  ${DIM}%-12s${NC} %s\n" "Disk"    "$DISK"
printf "  ${DIM}%-12s${NC} %s\n" "Memory"  "$MEM"
printf "  ${DIM}%-12s${NC} %s\n" "Timezone" "$TZ"
echo ""
echo -e "  ${BOLD}${WHITE}Security Pulse (24h):${NC}"
[[ "$FAILED_SSH" -gt 50 ]] 2>/dev/null \
    && printf "  ${RED}%-12s${NC} %s\n" "SSH fails"  "$FAILED_SSH ⚠" \
    || printf "  ${DIM}%-12s${NC} %s\n" "SSH fails"  "$FAILED_SSH"
printf "  ${DIM}%-12s${NC} %s\n" "Banned IPs" "${BANNED:-0}"
[[ -n "$REBOOT_NEEDED" ]] && echo -e "  $REBOOT_NEEDED"
echo ""
[[ -n "$LAST_LOGIN" ]] \
    && echo -e "  ${DIM}Last login: $LAST_LOGIN${NC}" \
    || true
echo -e "  ${DIM}Run ${NC}${CYAN}sudo check-alerts${NC}${DIM} for full security status${NC}"
echo ""
MOTD_EOF
    chmod +x /etc/update-motd.d/01-vps-hardening
    log_ok "Dynamic MOTD installed"

    # SSH fingerprint record
    local FINGERPRINT_FILE="${VPS_STATE_DIR}/ssh-fingerprints.txt"
    {
        echo "# SSH Host Key Fingerprints — $(hostname) — $(date)"
        echo "# Verify these when connecting to confirm you are on the right server"
        echo ""
        for KEY in /etc/ssh/ssh_host_*.pub; do
            [[ -f "$KEY" ]] || continue
            ALGO=$(echo "$KEY" | grep -oP 'ssh_host_\K[^.]+')
            FP=$(ssh-keygen -l -f "$KEY" 2>/dev/null || echo "unreadable")
            echo "  $ALGO: $FP"
        done
    } > "$FINGERPRINT_FILE"
    chmod 644 "$FINGERPRINT_FILE"
    log_ok "SSH fingerprints saved: $FINGERPRINT_FILE"

    echo ""
    echo -e "  ${BOLD}SSH Host Fingerprints${NC} ${DIM}(share with users for verification)${NC}"
    cat "$FINGERPRINT_FILE"

    # Harden /etc/securetty — restrict root console logins
    if [[ -f /etc/securetty ]]; then
        cp /etc/securetty /etc/securetty.backup
        # Keep only tty1 for emergency console access
        echo "tty1" > /etc/securetty
        log_ok "/etc/securetty restricted (console root login: tty1 only)"
    fi

    # Set idle session timeout via profile
    cat > /etc/profile.d/99-vps-timeout.sh << 'TIMEOUT_EOF'
# Auto-logout idle sessions after 30 minutes
TMOUT=1800
readonly TMOUT
export TMOUT
TIMEOUT_EOF
    chmod 644 /etc/profile.d/99-vps-timeout.sh
    log_ok "Idle session timeout: 30 minutes"

    phase_done "14"
    print_phase_done "14"
}

# =============================================================================
# EXECUTE ALL PHASES
# =============================================================================

TOTAL_PHASES=14

run_phase "01" phase_01
run_phase "02" phase_02
run_phase "03" phase_03
run_phase "04" phase_04
run_phase "05" phase_05
run_phase "06" phase_06
run_phase "07" phase_07
run_phase "08" phase_08
run_phase "09" phase_09
run_phase "10" phase_10
run_phase "11" phase_11
run_phase "12" phase_12
run_phase "13" phase_13
run_phase "14" phase_14

# =============================================================================
# FINAL SUMMARY
# =============================================================================

SCRIPT_END=$(date +%s)
ELAPSED=$(( SCRIPT_END - SCRIPT_START ))
MINUTES=$(( ELAPSED / 60 ))
SECS=$(( ELAPSED % 60 ))

echo ""
echo ""
echo -e "${BOLD}${GREEN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║                                                          ║"
echo "  ║    🛡️   VPS HARDENING COMPLETE  v${VPS_VERSION}             ║"
echo "  ║    Your server is secured and self-maintaining.          ║"
echo "  ║                                                          ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${DIM}Completed in ${MINUTES}m ${SECS}s${NC}"
echo ""

# Phase timing summary
echo -e "  ${BOLD}${WHITE}Phase Timings:${NC}"
echo ""
for ID in 01 02 03 04 05 06 07 08 09 10 11 12 13 14; do
    DUR="${PHASE_TIMES["${ID}_duration"]:-skipped}"
    printf "    ${DIM}Phase %s${NC}  %s\n" "$ID" "$DUR"
done
echo ""

echo -e "  ${BOLD}${WHITE}What was applied:${NC}"
echo ""
echo -e "  ${GREEN}✓${NC}  ${BOLD}Firewall${NC}           Port $INPUT_SSH_PORT only (rate-limited)"
echo -e "  ${GREEN}✓${NC}  ${BOLD}SSH${NC}                Port + modern crypto + moduli + AllowUsers"
echo -e "  ${GREEN}✓${NC}  ${BOLD}fail2ban${NC}           3 attempts = 24h ban + recidive 7-day jail"
echo -e "  ${GREEN}✓${NC}  ${BOLD}AppArmor${NC}           Mandatory access control"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Logging${NC}            Persistent, 90-day rotation, integrity (9 files)"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Auto updates${NC}       Security patches daily"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Safe reboot${NC}        03:00 — only when safe"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Admin account${NC}      $INPUT_USERNAME (sudo with 5-min timeout)"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Timezone${NC}           $INPUT_TZ + NTP sync"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Login banner${NC}       Legal warning + dynamic MOTD + idle timeout"
echo -e "  ${GREEN}✓${NC}  ${BOLD}SSH fingerprints${NC}   Saved to ${VPS_STATE_DIR}/ssh-fingerprints.txt"

[[ "$AUTH_TYPE" == "key" ]] \
    && echo -e "  ${GREEN}✓${NC}  ${BOLD}Auth${NC}               SSH key only" \
    || echo -e "  ${YELLOW}⚠${NC}  ${BOLD}Auth${NC}               Password (add keys when possible)"

[[ "$ENABLE_SYSCTL"   == "true" ]] && echo -e "  ${GREEN}✓${NC}  ${BOLD}Kernel sysctl${NC}      Network + memory hardening (expanded)"
[[ "$ENABLE_AUDITD"   == "true" ]] && echo -e "  ${GREEN}✓${NC}  ${BOLD}auditd${NC}             Kernel-level audit logging + file deletions"
[[ "$ENABLE_RKHUNTER" == "true" ]] && echo -e "  ${GREEN}✓${NC}  ${BOLD}rkhunter${NC}           Daily rootkit scan"
[[ "$ENABLE_CLAMAV"   == "true" ]] && echo -e "  ${GREEN}✓${NC}  ${BOLD}ClamAV${NC}             Daily malware scan"
[[ "$ENABLE_AIDE"     == "true" ]] && echo -e "  ${GREEN}✓${NC}  ${BOLD}AIDE${NC}               Full filesystem integrity"

echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${WHITE}Your server:${NC}"
echo ""
echo -e "    ${DIM}Hostname${NC}   ${BOLD}$INPUT_HOSTNAME${NC}"
echo -e "    ${DIM}IP${NC}         ${BOLD}$PUBLIC_IP${NC}"
echo -e "    ${DIM}Location${NC}   $(get_geo_info "$PUBLIC_IP")"
echo -e "    ${DIM}SSH Port${NC}   ${BOLD}$INPUT_SSH_PORT${NC}"
echo -e "    ${DIM}Admin${NC}      ${BOLD}$INPUT_USERNAME${NC}"
echo -e "    ${DIM}Auth${NC}       $AUTH_TYPE"
echo -e "    ${DIM}Timezone${NC}   $INPUT_TZ"
echo -e "    ${DIM}Provider${NC}   $CLOUD_PROVIDER"
echo ""
echo -e "  ${BOLD}${WHITE}Connect:${NC}"
if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "    ${DIM}Mac/Linux${NC}"
    echo -e "    ${CYAN}ssh -i ~/.ssh/id_ed25519 -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    echo ""
    echo -e "    ${DIM}Windows${NC}"
    echo -e "    ${CYAN}ssh -i \$env:USERPROFILE\\.ssh\\id_ed25519 -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
else
    echo -e "    ${CYAN}ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
fi

echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${WHITE}Commands:${NC}"
echo ""
echo -e "    ${CYAN}sudo check-alerts${NC}                  ${DIM}Full security dashboard${NC}"
echo -e "    ${CYAN}sudo vps-audit${NC}                     ${DIM}Run full audit now${NC}"
echo -e "    ${CYAN}sudo fail2ban-client status sshd${NC}   ${DIM}Banned IPs${NC}"
echo -e "    ${CYAN}sudo fail2ban-client status recidive${NC} ${DIM}Repeat offenders${NC}"
echo -e "    ${CYAN}sudo ufw status verbose${NC}            ${DIM}Firewall rules${NC}"
echo -e "    ${CYAN}sudo journalctl -u ssh -n 50${NC}       ${DIM}SSH log${NC}"
echo -e "    ${CYAN}sudo vps-log-integrity${NC}             ${DIM}Run integrity check now${NC}"
[[ "$ENABLE_AUDITD" == "true" ]] && \
    echo -e "    ${CYAN}sudo ausearch -k identity${NC}          ${DIM}Who touched /etc/passwd${NC}"
[[ "$ENABLE_AUDITD" == "true" ]] && \
    echo -e "    ${CYAN}sudo ausearch -k delete${NC}            ${DIM}File deletions${NC}"
echo -e "    ${CYAN}sudo tail -f ${VPS_INSTALL_LOG}${NC}"

echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${WHITE}Next steps:${NC}"
echo ""

STEP=1

if [[ "${REBOOT_REQUIRED:-false}" == "true" ]]; then
    REASON=$(state_get "reboot_reason" || echo "system update")
    echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Reboot required${NC} — $REASON"
    echo -e "       ${CYAN}sudo reboot${NC}"
    echo -e "       ${DIM}Reconnect: ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    STEP=$((STEP+1)); echo ""
fi

if [[ "$AUTH_TYPE" == "password" ]]; then
    echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Add SSH key${NC} — eliminates password attacks"
    echo -e "       ${CYAN}ssh-keygen -t ed25519${NC}"
    echo -e "       ${CYAN}ssh-copy-id -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    STEP=$((STEP+1)); echo ""
fi

if [[ "$CLOUD_PROVIDER" =~ ^(oracle|aws|azure|gcp)$ ]]; then
    echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Cloud firewall${NC} — confirm port $INPUT_SSH_PORT open in $CLOUD_PROVIDER console"
    STEP=$((STEP+1)); echo ""
fi

if [[ "$ENABLE_SYSCTL" != "true" || "$ENABLE_AUDITD" != "true" ]]; then
    echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Re-run with more features${NC}"
    echo -e "       ${CYAN}sudo ./harden.sh --resume${NC}  ${DIM}(picks up where you left off)${NC}"
    STEP=$((STEP+1)); echo ""
fi

echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Verify SSH fingerprints${NC}"
echo -e "       ${DIM}${VPS_STATE_DIR}/ssh-fingerprints.txt${NC}"
STEP=$((STEP+1)); echo ""

echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Consider WireGuard VPN${NC} — hides SSH from internet entirely"
echo -e "       ${DIM}Makes port-scanning and brute force impossible${NC}"
echo ""

echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${WHITE}Key files:${NC}"
echo ""
echo -e "    ${DIM}SSH config${NC}      /etc/ssh/sshd_config.d/99-hardened.conf"
echo -e "    ${DIM}fail2ban${NC}        /etc/fail2ban/jail.local"
echo -e "    ${DIM}Banner${NC}          /etc/issue.net"
echo -e "    ${DIM}MOTD${NC}            /etc/update-motd.d/01-vps-hardening"
echo -e "    ${DIM}Fingerprints${NC}    ${VPS_STATE_DIR}/ssh-fingerprints.txt"
echo -e "    ${DIM}Install log${NC}     ${VPS_INSTALL_LOG}"
echo -e "    ${DIM}Audit log${NC}       $(state_get "AUDIT_LOG" 2>/dev/null || echo "${VPS_LOG_DIR}/")"
echo -e "    ${DIM}State${NC}           ${VPS_STATE_FILE}"
echo -e "    ${DIM}Integrity${NC}       ${VPS_STATE_DIR}/log-checksums.sha256"
[[ "$ENABLE_SYSCTL"  == "true" ]] && \
    echo -e "    ${DIM}sysctl${NC}          /etc/sysctl.d/99-vps-hardening.conf"
[[ "$ENABLE_AUDITD"  == "true" ]] && \
    echo -e "    ${DIM}auditd${NC}          /etc/audit/rules.d/99-hardening.rules"
echo ""
echo -e "  ${BOLD}${CYAN}  Stay safe out there. 🚀${NC}"
echo ""
echo -e "  ${DIM}Full log: ${VPS_INSTALL_LOG}${NC}"
echo ""

_log_raw "COMPLETE" "vps-hardening ${VPS_VERSION} finished in ${MINUTES}m ${SECS}s"
