#!/bin/bash
# =============================================================================
# VPS Hardening Script v3.2
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

SPINNER='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

log_ok()    { echo -e "  ${GREEN}✓${NC}  $1"; }
log_warn()  { echo -e "  ${YELLOW}⚠${NC}  $1"; }
log_error() { echo -e "  ${RED}✗${NC}  $1"; }
log_info()  { echo -e "  ${BLUE}ℹ${NC}  $1"; }
log_step()  { echo -e "  ${CYAN}→${NC}  $1"; }
log_tip()   { echo -e "  ${MAGENTA}💡${NC} $1"; }

# -----------------------------------------------------------------------------
# spin() — animated spinner tied to a background PID.
# Uses an exit-code temp file to avoid race conditions with wait.
# -----------------------------------------------------------------------------
spin() {
    local MSG="$1"
    local PID="$2"
    local EXIT_FILE="$3"
    local i=0
    local LEN=${#SPINNER}

    echo -ne "  ${CYAN}${SPINNER:0:1}${NC}  $MSG"

    while kill -0 "$PID" 2>/dev/null; do
        i=$(( (i + 1) % LEN ))
        echo -ne "\r  ${CYAN}${SPINNER:$i:1}${NC}  $MSG"
        sleep 0.1
    done

    wait "$PID" 2>/dev/null || true
    local CODE
    CODE=$(cat "$EXIT_FILE" 2>/dev/null || echo 1)
    echo -ne "\r"

    if [[ "$CODE" -eq 0 ]]; then
        echo -e "  ${GREEN}✓${NC}  $MSG"
    else
        echo -e "  ${RED}✗${NC}  $MSG ${RED}(failed)${NC}"
    fi

    return "$CODE"
}

# -----------------------------------------------------------------------------
# run_silent() — runs a command in the background with an animated spinner.
# Sets DEBIAN_FRONTEND=noninteractive to prevent apt prompts from hanging.
# -----------------------------------------------------------------------------
run_silent() {
    local MSG="$1"
    shift
    local EXIT_FILE
    EXIT_FILE=$(mktemp)

    # DEBIAN_FRONTEND prevents debconf/apt interactive prompts from blocking
    ( DEBIAN_FRONTEND=noninteractive "$@" > /dev/null 2>&1; echo $? > "$EXIT_FILE" ) &
    local PID=$!

    spin "$MSG" "$PID" "$EXIT_FILE"
    local CODE=$?
    rm -f "$EXIT_FILE"
    return "$CODE"
}

# -----------------------------------------------------------------------------
# apt_install() — wrapper around apt install that always sets noninteractive
# and passes the correct flags. Prevents postinstall hook hangs.
# -----------------------------------------------------------------------------
apt_install() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "$@" > /dev/null 2>&1
}

print_banner() {
    clear
    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║                                                          ║"
    echo "  ║     🛡️   VPS HARDENING SCRIPT  v3.2                     ║"
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
    [[ -n "$DESC" ]] && echo -e "  ${DIM}  $DESC${NC}"
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

# =============================================================================
# ROOT CHECK
# =============================================================================

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
        log_warn "Could not detect public IP — replace YOUR_SERVER_IP in the commands below." >&2
        echo "YOUR_SERVER_IP"
    fi
}

safe_find_suid() {
    local RESULT
    RESULT=$(find / -perm -4000 -type f 2>/dev/null | grep -v snap | sort || true)
    if [[ -z "$RESULT" ]]; then
        log_warn "SUID scan returned no results — baseline may be unreliable in this environment." >&2
    fi
    echo "$RESULT"
}

apply_ssh_socket_fix() {
    local SOCKET_EXISTS=false
    systemctl list-units   --all 2>/dev/null | grep -q "ssh.socket" && SOCKET_EXISTS=true || true
    systemctl list-unit-files     2>/dev/null | grep -q "ssh.socket" && SOCKET_EXISTS=true || true
    [[ -f /lib/systemd/system/ssh.socket ]]                          && SOCKET_EXISTS=true || true
    [[ -f /usr/lib/systemd/system/ssh.socket ]]                      && SOCKET_EXISTS=true || true

    if [[ "$SOCKET_EXISTS" == "true" ]]; then
        log_step "Disabling SSH socket activation ${DIM}(Ubuntu 24.04 specific)${NC}"
        systemctl stop    ssh.socket  2>/dev/null || true
        systemctl disable ssh.socket  2>/dev/null || true
        systemctl mask    ssh.socket  2>/dev/null || true
        systemctl enable  ssh.service 2>/dev/null || true
        log_ok "Socket activation disabled — sshd controls its own port now"
    fi

    if [[ ! -d /run/sshd ]]; then
        mkdir -p /run/sshd
        chmod 755 /run/sshd
    fi
}

# -----------------------------------------------------------------------------
# wait_for_service() — polls until a systemd service is active or times out.
# Usage: wait_for_service <service_name> [max_seconds]
# -----------------------------------------------------------------------------
wait_for_service() {
    local SVC="$1"
    local MAX="${2:-15}"
    local ELAPSED=0
    while ! systemctl is-active --quiet "$SVC" 2>/dev/null; do
        sleep 1
        ELAPSED=$((ELAPSED + 1))
        if [[ "$ELAPSED" -ge "$MAX" ]]; then
            return 1
        fi
    done
    return 0
}

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
# PHASE 0a — ENVIRONMENT DETECTION
# =============================================================================

print_phase "0" "Environment Detection" "Analyzing your server before making changes"

# --- OS ---
echo -ne "  ${CYAN}⠋${NC}  Reading OS information"
OS_ID=$(grep      "^ID="               /etc/os-release | cut -d= -f2 | tr -d '"')
OS_VERSION=$(grep "^VERSION_ID="       /etc/os-release | cut -d= -f2 | tr -d '"')
OS_CODENAME=$(grep "^VERSION_CODENAME=" /etc/os-release | cut -d= -f2 | tr -d '"' 2>/dev/null || echo "unknown")
sleep 0.3
echo -e "\r  ${GREEN}✓${NC}  Reading OS information"

if [[ "$OS_ID" != "ubuntu" ]]; then
    log_warn "This script is designed for Ubuntu. Detected: $OS_ID"
    read -rp "  Continue anyway? (yes/no): " CONTINUE_ANYWAY
    [[ "$CONTINUE_ANYWAY" != "yes" ]] && exit 1
fi

CURRENT_USER="${SUDO_USER:-}"
CURRENT_USER="${CURRENT_USER:-root}"
[[ -z "$CURRENT_USER" ]] && CURRENT_USER="root"

# --- Cloud Provider ---
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

id "$DEFAULT_CLOUD_USER" > /dev/null 2>&1 || DEFAULT_CLOUD_USER="$CURRENT_USER"
echo -e "\r  ${GREEN}✓${NC}  Detecting cloud provider"

# --- iptables ---
echo -ne "  ${CYAN}⠋${NC}  Checking firewall rules"
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
echo -e "\r  ${GREEN}✓${NC}  Checking firewall rules"

# --- cloud-init ---
echo -ne "  ${CYAN}⠋${NC}  Checking cloud-init"
HAS_CLOUD_INIT=false
command -v cloud-init > /dev/null 2>&1 && HAS_CLOUD_INIT=true
echo -e "\r  ${GREEN}✓${NC}  Checking cloud-init"

# --- Services ---
echo -ne "  ${CYAN}⠋${NC}  Scanning installed services"
HAS_RPCBIND=false; HAS_MODEMMANAGER=false; HAS_ISCSID=false
systemctl list-units --all 2>/dev/null | grep -q "rpcbind"      && HAS_RPCBIND=true      || true
systemctl list-units --all 2>/dev/null | grep -q "ModemManager" && HAS_MODEMMANAGER=true  || true
systemctl list-units --all 2>/dev/null | grep -q "iscsid"       && HAS_ISCSID=true        || true
echo -e "\r  ${GREEN}✓${NC}  Scanning installed services"

# --- Results ---
print_divider
echo -e "  ${BOLD}Your Server:${NC}"
echo ""
echo -e "    ${DIM}Operating System${NC}    $OS_ID $OS_VERSION ($OS_CODENAME)"
echo -e "    ${DIM}Cloud Provider${NC}      $CLOUD_PROVIDER"
echo -e "    ${DIM}Logged in as${NC}        $CURRENT_USER"
echo -e "    ${DIM}Cloud default user${NC}  $DEFAULT_CLOUD_USER"
echo -e "    ${DIM}cloud-init${NC}          $( [[ "$HAS_CLOUD_INIT" == "true" ]] \
    && echo "${GREEN}present${NC}" || echo "${DIM}not found${NC}" )"
echo -e "    ${DIM}iptables${NC}            $( [[ "$CONFLICTING_IPTABLES" == "true" ]] \
    && echo "${YELLOW}conflicts found (will fix)${NC}" || echo "${GREEN}clean${NC}" )"

SVC_COUNT=0
[[ "$HAS_RPCBIND"      == "true" ]] && SVC_COUNT=$((SVC_COUNT+1))
[[ "$HAS_MODEMMANAGER" == "true" ]] && SVC_COUNT=$((SVC_COUNT+1))
[[ "$HAS_ISCSID"       == "true" ]] && SVC_COUNT=$((SVC_COUNT+1))
echo -e "    ${DIM}Services to remove${NC}  ${SVC_COUNT} found"
echo ""
log_ok "Environment scan complete"

# =============================================================================
# PHASE 0b — CONFIGURATION
# =============================================================================

print_phase "0" "Configuration" "Tell me how you want your server set up"

# ---------------------------------------------------------------------------
# Authentication method
# ---------------------------------------------------------------------------
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
    log_ok "SSH key authentication selected"

    CURRENT_USER_HOME=$(eval echo "~${CURRENT_USER}")
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
        log_warn "No authorized_keys file found."
        read -rp "  Continue anyway? (yes/no): " KEY_CONFIRM
        [[ "$KEY_CONFIRM" != "yes" ]] && exit 1
    fi

else
    print_box "SSH KEY RECOMMENDATION" "$YELLOW"
    echo -e "  SSH keys are ${BOLD}far more secure${NC} than passwords:"
    echo ""
    echo -e "    ${YELLOW}•${NC}  Passwords can be brute-forced — keys ${BOLD}cannot${NC}"
    echo -e "    ${YELLOW}•${NC}  Keys use 256+ bits of cryptographic randomness"
    echo -e "    ${YELLOW}•${NC}  Automated bots are trying passwords on your server ${ITALIC}right now${NC}"
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
            log_warn "Invalid format. Must start with ssh-ed25519, ssh-rsa, or ssh-ecdsa."
            log_warn "Make sure you copied the .pub file, not the private key."
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
        log_ok "Public key installed for $CURRENT_USER"

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
            log_warn "Key login failed. Tips:"
            echo -e "    ${CYAN}1)${NC} Confirm you copied the .pub file (public key)"
            echo -e "    ${CYAN}2)${NC} Check: ${CYAN}cat $KEY_DIR/authorized_keys${NC}"
            echo -e "    ${CYAN}3)${NC} Debug: ${CYAN}ssh -vvv -i ~/.ssh/id_ed25519 $CURRENT_USER@$PUBLIC_IP_EARLY${NC}"
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
            log_ok "Key login confirmed"
        fi
    else
        AUTH_TYPE="password"
        log_info "Continuing with password authentication."
        log_tip  "You can add SSH keys later for stronger security."
    fi
fi

# ---------------------------------------------------------------------------
# Hostname
# ---------------------------------------------------------------------------
print_divider
echo -e "  ${BOLD}🏷️  Server Hostname${NC}"
echo -e "  ${DIM}A meaningful name for this server (letters, numbers, hyphens)${NC}"
echo ""
read -rp "  Hostname (e.g., web-01, vpn, myserver): " INPUT_HOSTNAME
while [[ -z "$INPUT_HOSTNAME" || ! "$INPUT_HOSTNAME" =~ ^[a-zA-Z0-9-]+$ ]]; do
    log_warn "Invalid. Use letters, numbers, and hyphens only."
    read -rp "  Hostname: " INPUT_HOSTNAME
done

# ---------------------------------------------------------------------------
# SSH Port
# ---------------------------------------------------------------------------
print_divider
echo -e "  ${BOLD}🔌 New SSH Port${NC}"
echo -e "  ${DIM}Moving SSH off port 22 blocks most automated scanners.${NC}"
echo -e "  ${DIM}Pick any number 1024–65535. Avoid 2222 (bots scan that too).${NC}"
echo ""
read -rp "  SSH port (e.g., 7022, 30044, 45678): " INPUT_SSH_PORT
while ! [[ "$INPUT_SSH_PORT" =~ ^[0-9]+$ ]] \
      || [[ "$INPUT_SSH_PORT" -lt 1024 ]] \
      || [[ "$INPUT_SSH_PORT" -gt 65535 ]]; do
    log_warn "Invalid. Must be 1024–65535."
    read -rp "  SSH port: " INPUT_SSH_PORT
done

# ---------------------------------------------------------------------------
# Admin username
# ---------------------------------------------------------------------------
print_divider
echo -e "  ${BOLD}👤 Admin Username${NC}"
echo -e "  ${DIM}Your personal admin account.${NC}"
echo -e "  ${DIM}Avoid common names: ubuntu, admin, root, test, user, deploy, git, pi${NC}"
echo ""

BLOCKED_NAMES="ubuntu admin root test user deploy git ansible pi postgres ec2-user centos fedora"

read -rp "  Username: " INPUT_USERNAME
while true; do
    if [[ -z "$INPUT_USERNAME" ]]; then
        log_warn "Username cannot be empty."
    elif [[ ! "$INPUT_USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
        log_warn "Must start with a lowercase letter or underscore, max 32 chars, lowercase only."
    elif echo "$BLOCKED_NAMES" | grep -qw "$INPUT_USERNAME"; then
        log_warn "Too predictable. Choose something unique."
    else
        break
    fi
    read -rp "  Username: " INPUT_USERNAME
done

# ---------------------------------------------------------------------------
# Cloud user to demote
# ---------------------------------------------------------------------------
INPUT_CLOUD_USER="$CURRENT_USER"
if [[ "$CURRENT_USER" != "root" ]]; then
    print_divider
    echo -e "  ${BOLD}Cloud Default User to Demote${NC}"
    echo ""
    read -rp "  Cloud username to demote [$CURRENT_USER]: " INPUT_CLOUD_USER
    INPUT_CLOUD_USER="${INPUT_CLOUD_USER:-$CURRENT_USER}"
fi

# ---------------------------------------------------------------------------
# Confirmation summary
# ---------------------------------------------------------------------------
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
    log_warn "Aborted. No changes were made."
    exit 1
fi

# =============================================================================
# LOGGING — tee everything to file from here onward
# =============================================================================

LOGFILE="/var/log/harden-script.log"
exec > >(tee -a "$LOGFILE") 2>&1
{
    echo "════════════════════════════════════════"
    echo "Started : $(date)"
    echo "Provider: $CLOUD_PROVIDER | OS: $OS_ID $OS_VERSION | Auth: $AUTH_TYPE"
    echo "Host    : $INPUT_HOSTNAME | Port: $INPUT_SSH_PORT | User: $INPUT_USERNAME"
    echo "════════════════════════════════════════"
} >> "$LOGFILE"

# =============================================================================
# PHASE 1 — ASSESSMENT
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
echo -e "  ${BOLD}Running Services:${NC} $(systemctl list-units --type=service --state=running \
    --no-pager 2>/dev/null | grep -c "\.service" || echo "unknown")"

[[ -f /var/run/reboot-required ]] \
    && log_warn "A system reboot is pending — will remind you at the end."

echo ""
log_ok "Assessment complete"
pause

# =============================================================================
# PHASE 2 — SYSTEM PREPARATION
# =============================================================================

print_phase "2" "System Preparation" "Updating packages and setting hostname"

run_silent "Updating package lists" \
    bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq'

run_silent "Installing available upgrades" \
    bash -c 'DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold"'

run_silent "Setting hostname to $INPUT_HOSTNAME" \
    hostnamectl set-hostname "$INPUT_HOSTNAME"

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

log_ok "System updated, hostname set to ${BOLD}$INPUT_HOSTNAME${NC}"

# =============================================================================
# PHASE 3 — SERVICES
# =============================================================================

print_phase "3" "Remove Unnecessary Services" "Each service is a potential attack target"

REMOVED=0

if [[ "$HAS_RPCBIND" == "true" ]]; then
    run_silent "Removing rpcbind (NFS — not needed on a VPS)" bash -c '
        systemctl stop    rpcbind.socket rpcbind.service 2>/dev/null || true
        systemctl disable rpcbind.socket rpcbind.service 2>/dev/null || true
        systemctl mask    rpcbind.socket rpcbind.service 2>/dev/null || true
    '
    REMOVED=$((REMOVED+1))
fi

if [[ "$HAS_MODEMMANAGER" == "true" ]]; then
    run_silent "Removing ModemManager (cellular — useless on VPS)" bash -c '
        systemctl stop    ModemManager 2>/dev/null || true
        systemctl disable ModemManager 2>/dev/null || true
        systemctl mask    ModemManager 2>/dev/null || true
    '
    REMOVED=$((REMOVED+1))
fi

if [[ "$HAS_ISCSID" == "true" ]]; then
    run_silent "Removing iSCSI (enterprise storage — not needed)" bash -c '
        systemctl stop    iscsid.socket iscsid.service 2>/dev/null || true
        systemctl disable iscsid.socket iscsid.service 2>/dev/null || true
        systemctl mask    iscsid.socket iscsid.service 2>/dev/null || true
    '
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
# PHASE 4 — FIREWALL
# =============================================================================

print_phase "4" "Firewall Configuration" "Only allow what you explicitly permit"

run_silent "Installing UFW firewall" \
    bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw'

ufw default deny incoming  > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
log_ok "Default policy: ${BOLD}deny incoming${NC}, allow outgoing"

ufw allow 22/tcp                comment "SSH default - safety net" > /dev/null 2>&1
ufw allow "$INPUT_SSH_PORT"/tcp comment "SSH hardened"              > /dev/null 2>&1
log_ok "Opened: 22 ${DIM}(safety net — closed after account confirmed in Phase 10)${NC} and ${BOLD}$INPUT_SSH_PORT${NC}"

echo "y" | ufw enable > /dev/null 2>&1
log_ok "UFW firewall ${BOLD}${GREEN}active${NC}"

if [[ "$CONFLICTING_IPTABLES" == "true" ]]; then
    for SPEC in "${CONFLICTING_SPECS[@]}"; do
        # shellcheck disable=SC2086
        iptables -D INPUT $SPEC 2>/dev/null || true
    done
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
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
# PHASE 5 — SSH HARDENING
# =============================================================================

print_phase "5" "SSH Hardening" "Port change + security settings (no lockout risk)"

echo -e "  ${DIM}This phase changes the port and applies hardening settings.${NC}"
echo -e "  ${DIM}AllowUsers and 'PermitRootLogin no' are applied in Phase 10,${NC}"
echo -e "  ${DIM}only after your new account is confirmed working.${NC}"
echo -e "  ${DIM}Port 22 stays open as a safety net until then.${NC}"
echo ""
log_warn "Keep your current SSH session open throughout."
pause

run_silent "Backing up SSH configuration" bash -c "
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    mkdir -p /etc/ssh/sshd_config.d
"

if [[ "$AUTH_TYPE" == "key" ]]; then
    cat > /etc/ssh/sshd_config.d/99-hardened.conf << EOF
# Hardened SSH — Phase 5 (safe, no user restrictions yet)
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
# Hardened SSH — Phase 5 (safe, no user restrictions yet)
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
    log_error "SSH config syntax error — restoring backup"
    cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.d/99-hardened.conf
    exit 1
fi

run_silent "Restarting SSH on port $INPUT_SSH_PORT" systemctl restart ssh

SSH_UP=false
for _i in {1..20}; do
    if ss -tlnp | grep -q ":$INPUT_SSH_PORT"; then
        SSH_UP=true
        break
    fi
    sleep 0.5
done

if [[ "$SSH_UP" == "false" ]]; then
    log_error "SSH is NOT listening on port $INPUT_SSH_PORT after 10 seconds."
    log_info  "Check: journalctl -u ssh -n 30"
    exit 1
fi
log_ok "SSH listening on port ${BOLD}$INPUT_SSH_PORT${NC}"

print_box "TEST YOUR CONNECTION" "$YELLOW"
echo -e "  Open a ${BOLD}NEW terminal${NC} and connect on the new port:"
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
    log_error "SSH test failed. Diagnose from this session:"
    log_info  "  systemctl status ssh"
    log_info  "  journalctl -u ssh -n 30"
    exit 1
fi

log_ok "Port $INPUT_SSH_PORT confirmed — port 22 stays open until Phase 10"

# =============================================================================
# PHASE 6 — FAIL2BAN
# =============================================================================
#
# FIX: The original script hung here because:
#   1. DEBIAN_FRONTEND was unset — debconf could prompt and block apt
#   2. apt's postinstall hook starts fail2ban immediately during install,
#      but our jail.local doesn't exist yet — the service start races
#      with the package install inside the background subshell, causing
#      dpkg to hang waiting for the service to settle
#   3. run_silent captured all output to /dev/null so the hang was silent
#
# Solution:
#   1. Write jail.local BEFORE installing the package so fail2ban's
#      postinstall start uses the correct config immediately
#   2. Set DEBIAN_FRONTEND=noninteractive via apt_install() wrapper
#   3. Use --no-start flag (via policy-rc.d) to prevent postinstall from
#      starting the service, then start it ourselves after verifying config
#   4. Add wait_for_service() to confirm the service is actually running
# =============================================================================

print_phase "6" "Brute Force Protection" "fail2ban blocks attackers after 3 failures"

# Step 1: Write the jail config BEFORE installing the package.
# This ensures fail2ban's postinstall start uses the correct settings.
log_step "Writing fail2ban jail configuration"
mkdir -p /etc/fail2ban
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
log_ok "jail.local written"

# Step 2: Prevent the postinstall script from auto-starting fail2ban.
# We do this by temporarily installing a policy-rc.d that returns 101
# (action not allowed), then remove it after the package installs.
echo "exit 101" > /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d

run_silent "Installing fail2ban" \
    bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban'

# Step 3: Remove the policy block, then enable and start the service ourselves.
rm -f /usr/sbin/policy-rc.d

run_silent "Enabling fail2ban service" \
    systemctl enable fail2ban

run_silent "Starting fail2ban" \
    systemctl start fail2ban

# Step 4: Confirm the service actually came up before proceeding.
if ! wait_for_service fail2ban 15; then
    log_error "fail2ban failed to start within 15 seconds."
    log_info  "Check: journalctl -u fail2ban -n 30"
    log_info  "Check: fail2ban-client ping"
    # Not fatal — hardening continues, but warn loudly.
    log_warn  "Continuing without confirmed fail2ban — investigate after script completes."
else
    BANNED=$(fail2ban-client status sshd 2>/dev/null \
        | grep "Currently banned" | awk '{print $NF}' || echo "0")
    BANNED="${BANNED:-0}"
    echo ""
    log_ok "fail2ban active — 3 strikes = 24 h ban"
    [[ "$BANNED" -gt 0 ]] \
        && log_info "Already banned: ${BOLD}$BANNED IP(s)${NC} from previous attacks"
fi

# =============================================================================
# PHASE 7 — APPARMOR
# =============================================================================

print_phase "7" "Mandatory Access Control" "AppArmor limits what programs can do, even as root"

if command -v aa-status > /dev/null 2>&1; then
    PROFILES_BEFORE=$(aa-status 2>/dev/null \
        | grep "profiles are loaded" | awk '{print $1}' || echo "0")
    run_silent "Installing additional AppArmor profiles" \
        bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            apparmor-profiles apparmor-profiles-extra'
    PROFILES_AFTER=$(aa-status 2>/dev/null \
        | grep "profiles are loaded" | awk '{print $1}' || echo "0")
    ENFORCED=$(aa-status 2>/dev/null \
        | grep "in enforce mode" | head -1 | awk '{print $1}' || echo "0")
    echo ""
    log_ok "AppArmor: ${BOLD}$PROFILES_AFTER${NC} profiles loaded, ${BOLD}$ENFORCED${NC} enforcing"
    [[ "$PROFILES_AFTER" -gt "$PROFILES_BEFORE" ]] \
        && log_info "Added $((PROFILES_AFTER - PROFILES_BEFORE)) new security profiles"
else
    log_warn "AppArmor not available — skipping"
fi

# =============================================================================
# PHASE 8 — PERSISTENT LOGGING
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

JOURNAL_SIZE=$(journalctl --disk-usage 2>/dev/null \
    | grep -oP '[\d.]+\w+' | head -1 || echo "unknown")
BOOT_COUNT=$(journalctl --list-boots --no-pager 2>/dev/null | wc -l || echo "1")
echo ""
log_ok "Persistent logging enabled — ${BOLD}${JOURNAL_SIZE}${NC} stored, $BOOT_COUNT boot(s) recorded"

# =============================================================================
# PHASE 9 — PACKAGE CLEANUP
# =============================================================================

print_phase "9" "Package Cleanup" "Less software = fewer vulnerabilities"

PACKAGES_TO_REMOVE=()
for PKG in nfs-common open-iscsi ssh-import-id; do
    dpkg -l "$PKG" 2>/dev/null | grep -q "^ii" && PACKAGES_TO_REMOVE+=("$PKG")
done

if [[ ${#PACKAGES_TO_REMOVE[@]} -gt 0 ]]; then
    run_silent "Removing: ${PACKAGES_TO_REMOVE[*]}" \
        bash -c "DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq ${PACKAGES_TO_REMOVE[*]}"
fi

run_silent "Cleaning up unused dependencies" \
    bash -c 'DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq'

echo ""
log_ok "Package cleanup complete — ${#PACKAGES_TO_REMOVE[@]} package(s) removed"

# =============================================================================
# PHASE 10 — ADMIN ACCOUNT + FINAL LOCKDOWN
# =============================================================================

print_phase "10" "Admin Account + Final Lockdown" "Create your account, then lock everything down"

echo -e "  ${DIM}Your personal admin account is created first.${NC}"
echo -e "  ${DIM}SSH restrictions are applied ONLY after you confirm it works.${NC}"
echo -e "  ${DIM}Port 22 is closed and root login disabled after confirmation.${NC}"
echo ""

# --- Create account ---
if id "$INPUT_USERNAME" > /dev/null 2>&1; then
    log_warn "User $INPUT_USERNAME already exists — skipping creation"
else
    echo -e "  ${BOLD}Create password for ${GREEN}$INPUT_USERNAME${NC}${BOLD}:${NC}"
    echo ""
    adduser --gecos "" "$INPUT_USERNAME"
fi

echo ""
run_silent "Adding $INPUT_USERNAME to sudo and adm groups" bash -c "
    usermod -aG sudo $INPUT_USERNAME
    usermod -aG adm  $INPUT_USERNAME
"

# --- SSH key for new account ---
mkdir -p "/home/$INPUT_USERNAME/.ssh"
chmod 700 "/home/$INPUT_USERNAME/.ssh"

if [[ "$AUTH_TYPE" == "key" ]]; then
    KEY_CONTENT=""

    if [[ -n "${INPUT_PUBLIC_KEY:-}" ]]; then
        KEY_CONTENT="$INPUT_PUBLIC_KEY"
        log_info "Using the public key you pasted."
    elif [[ "$INPUT_CLOUD_USER" != "root" ]] \
         && [[ -f "/home/$INPUT_CLOUD_USER/.ssh/authorized_keys" ]] \
         && [[ -s "/home/$INPUT_CLOUD_USER/.ssh/authorized_keys" ]]; then
        KEY_CONTENT=$(cat "/home/$INPUT_CLOUD_USER/.ssh/authorized_keys")
        log_info "Copying key from $INPUT_CLOUD_USER's authorized_keys."
    elif [[ -f "/root/.ssh/authorized_keys" ]] \
         && [[ -s "/root/.ssh/authorized_keys" ]]; then
        KEY_CONTENT=$(cat "/root/.ssh/authorized_keys")
        log_warn "Falling back to root's authorized_keys — verify these keys are yours."
    fi

    if [[ -n "$KEY_CONTENT" ]]; then
        echo "$KEY_CONTENT" > "/home/$INPUT_USERNAME/.ssh/authorized_keys"
        chmod 600 "/home/$INPUT_USERNAME/.ssh/authorized_keys"
        log_ok "SSH key installed for $INPUT_USERNAME"
    else
        log_warn "No SSH key found — $INPUT_USERNAME will need a password to log in."
    fi
else
    log_info "Password mode — $INPUT_USERNAME will use password to log in."
fi

chown -R "$INPUT_USERNAME:$INPUT_USERNAME" "/home/$INPUT_USERNAME/.ssh"

# --- Test new account ---
print_box "TEST YOUR NEW ADMIN ACCOUNT" "$YELLOW"
echo -e "  Open a ${BOLD}NEW terminal${NC} and connect as your new user:"
echo ""
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
    log_error "Test failed — lockdown and port 22 closure NOT applied."
    log_error "Root access preserved. You are still connected."
    echo ""
    log_info "Diagnose:"
    echo -e "    ${CYAN}id $INPUT_USERNAME${NC}"
    echo -e "    ${CYAN}passwd $INPUT_USERNAME${NC}"
    echo -e "    ${CYAN}journalctl -u ssh -n 20${NC}"
    echo ""
    log_info "Once fixed, apply lockdown manually:"
    echo -e "    ${CYAN}sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' \\${NC}"
    echo -e "    ${CYAN}    /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "    ${CYAN}echo 'AllowUsers $INPUT_USERNAME' | sudo tee -a \\${NC}"
    echo -e "    ${CYAN}    /etc/ssh/sshd_config.d/99-hardened.conf${NC}"
    echo -e "    ${CYAN}sudo ufw delete allow 22/tcp${NC}"
    echo -e "    ${CYAN}sudo sshd -t && sudo systemctl restart ssh${NC}"
    echo ""
    log_warn "Continuing to Phase 11 without lockdown..."

else
    # --- Write final hardened SSH config ---
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
# To upgrade to key-only auth later:
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
        log_ok "Root login ${BOLD}disabled${NC} — only ${BOLD}$INPUT_USERNAME${NC} can log in"

        ufw delete allow 22/tcp > /dev/null 2>&1 || true
        log_ok "Port 22 closed — only ${BOLD}$INPUT_SSH_PORT${NC} is accessible"
    else
        log_error "SSH config syntax error — keeping safe config, NOT restarting"
    fi

    # --- Demote cloud user ---
    if [[ "$INPUT_CLOUD_USER" != "root" ]]; then
        for GRP in sudo lxd cdrom dip; do
            deluser "$INPUT_CLOUD_USER" "$GRP" 2>/dev/null || true
        done
        passwd -l "$INPUT_CLOUD_USER" > /dev/null 2>&1 || true
        log_ok "$INPUT_CLOUD_USER demoted and account locked"
    fi

    # --- Remove NOPASSWD from cloud user's sudoers ---
    SUDOERS_FILE=""
    for F in /etc/sudoers.d/*; do
        grep -q "$INPUT_CLOUD_USER" "$F" 2>/dev/null && { SUDOERS_FILE="$F"; break; }
    done

    if [[ -n "$SUDOERS_FILE" ]]; then
        cp "$SUDOERS_FILE" "${SUDOERS_FILE}.tmp"
        sed -i \
            "s|$INPUT_CLOUD_USER ALL=(ALL) NOPASSWD:ALL|$INPUT_CLOUD_USER ALL=(ALL) ALL|g" \
            "${SUDOERS_FILE}.tmp"
        sed -i \
            "s|$INPUT_CLOUD_USER ALL=(ALL:ALL) NOPASSWD:ALL|$INPUT_CLOUD_USER ALL=(ALL:ALL) ALL|g" \
            "${SUDOERS_FILE}.tmp"

        if visudo -c -f "${SUDOERS_FILE}.tmp" > /dev/null 2>&1; then
            cp "$SUDOERS_FILE" "${SUDOERS_FILE}.backup"
            mv "${SUDOERS_FILE}.tmp" "$SUDOERS_FILE"
            log_ok "NOPASSWD removed from $INPUT_CLOUD_USER sudoers entry"
        else
            rm -f "${SUDOERS_FILE}.tmp"
            log_warn "sudoers modification skipped — visudo validation failed (safe, no change made)"
        fi
    fi
fi

# =============================================================================
# PHASE 11 — SECURITY MONITORING
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

# ---------------------------------------------------------------------------
# daily-audit.sh
# ---------------------------------------------------------------------------
cat > "$SCRIPTS_DIR/daily-audit.sh" << AUDIT_EOF
#!/bin/bash
# daily-audit.sh — plain-text log, runs from cron at 4 AM.
LOGFILE="$AUDIT_LOG"
DATE=\$(date '+%Y-%m-%d %H:%M:%S')

echo "========================================" >> "\$LOGFILE"
echo "Audit: \$DATE"                            >> "\$LOGFILE"
echo "========================================" >> "\$LOGFILE"

echo "--- System Health ---"          >> "\$LOGFILE"
echo "Uptime: \$(uptime)"             >> "\$LOGFILE"
df -h /                                >> "\$LOGFILE"
free -h                                >> "\$LOGFILE"
echo "CPU Load: \$(cat /proc/loadavg)" >> "\$LOGFILE"

echo "--- Failed SSH (24h) ---" >> "\$LOGFILE"
FAILED=\$(journalctl -u ssh --since "24 hours ago" 2>/dev/null \
    | grep -c "Invalid user\|Failed password" || echo 0)
echo "Failed logins: \$FAILED" >> "\$LOGFILE"
journalctl -u ssh --since "24 hours ago" 2>/dev/null \
    | grep -i "failed\|invalid" | tail -10 >> "\$LOGFILE"

echo "--- fail2ban (24h) ---" >> "\$LOGFILE"
journalctl -u fail2ban --since "24 hours ago" 2>/dev/null \
    | grep "Ban" >> "\$LOGFILE" || echo "No bans." >> "\$LOGFILE"

echo "--- SUID Changes ---" >> "\$LOGFILE"
find / -perm -4000 -type f 2>/dev/null | grep -v snap | sort \
    > /tmp/current-suid.txt || true
SDIFF=\$(diff $BASELINE_DIR/suid-baseline.txt /tmp/current-suid.txt \
    2>/dev/null || true)
if [ -z "\$SDIFF" ]; then
    echo "No SUID changes." >> "\$LOGFILE"
else
    echo "WARNING: SUID files changed!" >> "\$LOGFILE"
    echo "\$SDIFF" >> "\$LOGFILE"
fi
rm -f /tmp/current-suid.txt

echo "--- Open Ports ---" >> "\$LOGFILE"
ss -tlnp >> "\$LOGFILE"

echo "--- Logged-in Users ---" >> "\$LOGFILE"
who           >> "\$LOGFILE"
last | head -5 >> "\$LOGFILE"

echo "--- Sudo Activity (24h) ---" >> "\$LOGFILE"
journalctl --since "24 hours ago" 2>/dev/null \
    | grep "sudo" | grep -v "pam_unix" >> "\$LOGFILE" || true

echo "" >> "\$LOGFILE"
AUDIT_EOF

# ---------------------------------------------------------------------------
# check-alerts.sh
# ---------------------------------------------------------------------------
cat > "$SCRIPTS_DIR/check-alerts.sh" << 'ALERTS_SCRIPT'
#!/bin/bash
# check-alerts.sh — interactive security health dashboard.
# Run with: sudo check-alerts

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# shellcheck source=/dev/null
source "$(dirname "$0")/.check-alerts-env" 2>/dev/null || true

HOST=$(hostname)
DATE=$(date '+%Y-%m-%d %H:%M:%S')
UPTIME_STR=$(uptime -p 2>/dev/null || echo "unknown")

echo ""
echo -e "${BOLD}${CYAN}  ╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}  ║${NC}  ${BOLD}${WHITE}🛡️  Security Status — ${HOST}${NC}"
echo -e "${BOLD}${CYAN}  ║${NC}  ${DIM}${DATE} • ${UPTIME_STR}${NC}"
echo -e "${BOLD}${CYAN}  ╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

ALERTS=0
WARNINGS=0

check() {
    local STATUS="$1"
    local MSG="$2"
    case "$STATUS" in
        ok)   echo -e "  ${GREEN}✓${NC}  $MSG" ;;
        warn) echo -e "  ${YELLOW}⚠${NC}  $MSG"; WARNINGS=$((WARNINGS+1)) ;;
        crit) echo -e "  ${RED}✗${NC}  $MSG";    ALERTS=$((ALERTS+1)) ;;
        info) echo -e "  ${CYAN}ℹ${NC}  $MSG" ;;
    esac
}

# Disk
DISK=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if   [ "$DISK" -gt 80 ]; then check "crit" "Disk: ${DISK}% — critically full"
elif [ "$DISK" -gt 60 ]; then check "warn" "Disk: ${DISK}% — getting full"
else                           check "ok"   "Disk: ${DISK}%"
fi

# Memory
MEM=$(free | grep Mem | awk '{printf "%.0f", $3/$2*100}')
if   [ "$MEM" -gt 90 ]; then check "crit" "Memory: ${MEM}%"
elif [ "$MEM" -gt 75 ]; then check "warn" "Memory: ${MEM}%"
else                          check "ok"   "Memory: ${MEM}%"
fi

# SSH failures
FAILED=$(journalctl -u ssh --since "24 hours ago" 2>/dev/null \
    | grep -c "Invalid user\|Failed password" || echo 0)
if   [ "$FAILED" -gt 200 ]; then check "crit" "Failed SSH (24h): ${FAILED} — unusual volume"
elif [ "$FAILED" -gt 50  ]; then check "warn" "Failed SSH (24h): ${FAILED}"
else                              check "ok"   "Failed SSH (24h): ${FAILED}"
fi

# fail2ban
BANS=$(fail2ban-client status sshd 2>/dev/null \
    | grep "Currently banned" | awk '{print $NF}')
BANS=${BANS:-0}
TOTAL=$(fail2ban-client status sshd 2>/dev/null \
    | grep "Total banned" | awk '{print $NF}')
TOTAL=${TOTAL:-0}
if [ "$BANS" -gt 0 ]; then
    check "info" "fail2ban: ${BANS} currently banned (${TOTAL} total)"
    BANNED_IPS=$(fail2ban-client status sshd 2>/dev/null \
        | grep "Banned IP" | cut -d: -f2)
    echo -e "  ${DIM}  ${BANNED_IPS}${NC}"
else
    check "ok" "fail2ban: No IPs currently banned (${TOTAL} total)"
fi

# SUID drift
if [ -f "${BASELINE_DIR}/suid-baseline.txt" ]; then
    find / -perm -4000 -type f 2>/dev/null | grep -v snap | sort \
        > /tmp/suid-chk.txt || true
    SDIFF=$(diff "${BASELINE_DIR}/suid-baseline.txt" /tmp/suid-chk.txt \
        2>/dev/null || true)
    rm -f /tmp/suid-chk.txt
    if [ -n "$SDIFF" ]; then
        check "crit" "SUID files changed — investigate!"
        echo "$SDIFF"
    else
        SUID_COUNT=$(wc -l < "${BASELINE_DIR}/suid-baseline.txt")
        check "ok" "SUID files unchanged (${SUID_COUNT} tracked)"
    fi
else
    check "warn" "SUID baseline not found — run harden.sh to generate it"
fi

# Critical services
for SVC in ssh fail2ban; do
    if systemctl is-active --quiet "$SVC"; then
        check "ok" "$SVC running"
    else
        check "crit" "$SVC NOT running — investigate immediately"
    fi
done

# UFW
if ufw status 2>/dev/null | grep -q "Status: active"; then
    check "ok" "UFW firewall active"
else
    check "crit" "UFW firewall NOT active"
fi

# AppArmor
if command -v aa-status > /dev/null 2>&1; then
    ENF=$(aa-status 2>/dev/null \
        | grep "in enforce mode" | head -1 | awk '{print $1}' || echo "0")
    check "ok" "AppArmor: ${ENF} profiles enforcing"
fi

# Open ports
echo ""
echo -e "  ${BOLD}Listening Ports:${NC}"
ss -tlnp | grep LISTEN | while read -r line; do
    PORT=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
    PROC=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "?")
    echo -e "    ${DIM}:${PORT}${NC} — ${PROC}"
done

# Summary
echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
if   [ "$ALERTS"   -gt 0 ]; then
    echo -e "  ${RED}✗  ${ALERTS} critical alert(s) — action required${NC}"
elif [ "$WARNINGS" -gt 0 ]; then
    echo -e "  ${YELLOW}⚠  ${WARNINGS} warning(s) — review when possible${NC}"
else
    echo -e "  ${GREEN}✓  All systems healthy — no issues found${NC}"
fi
echo ""
ALERTS_SCRIPT

# Write env file sourced by check-alerts.sh
cat > "$SCRIPTS_DIR/.check-alerts-env" << ENV_EOF
# Auto-generated by harden.sh — do not edit manually.
BASELINE_DIR="$BASELINE_DIR"
AUDIT_LOG="$AUDIT_LOG"
ENV_EOF
chmod 640 "$SCRIPTS_DIR/.check-alerts-env"

# Permissions
chmod 750 "$SCRIPTS_DIR/daily-audit.sh" "$SCRIPTS_DIR/check-alerts.sh"
if id "$INPUT_USERNAME" > /dev/null 2>&1; then
    chown root:"$INPUT_USERNAME" \
        "$SCRIPTS_DIR/daily-audit.sh" \
        "$SCRIPTS_DIR/check-alerts.sh" \
        "$SCRIPTS_DIR/.check-alerts-env"
fi

ln -sf "$SCRIPTS_DIR/check-alerts.sh" /usr/local/bin/check-alerts

# Idempotent cron entry
CRON_CMD="0 4 * * * $SCRIPTS_DIR/daily-audit.sh"
( crontab -l 2>/dev/null || true ) \
    | grep -qF "$SCRIPTS_DIR/daily-audit.sh" \
    || { ( crontab -l 2>/dev/null || true; echo "$CRON_CMD" ) | crontab -; }
log_ok "Daily audit scheduled at ${BOLD}4:00 AM${NC}"

run_silent "Running initial audit" bash "$SCRIPTS_DIR/daily-audit.sh"
log_ok "Monitoring installed — run ${BOLD}${CYAN}sudo check-alerts${NC} anytime"

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
echo "  ║    🛡️   VPS HARDENING COMPLETE                          ║"
echo "  ║    Your server is now secured and monitored.             ║"
echo "  ║                                                          ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${DIM}Completed in ${MINUTES}m ${SECS}s${NC}"
echo ""

echo -e "  ${BOLD}${WHITE}What was secured:${NC}"
echo ""
echo -e "  ${GREEN}✓${NC}  ${BOLD}Firewall${NC}         Only port $INPUT_SSH_PORT is open"
echo -e "  ${GREEN}✓${NC}  ${BOLD}SSH${NC}              Moved 22 → $INPUT_SSH_PORT, root login disabled"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Admin Account${NC}    ${BOLD}$INPUT_USERNAME${NC} created with sudo access"

if [[ "$AUTH_TYPE" == "key" ]]; then
    echo -e "  ${GREEN}✓${NC}  ${BOLD}Auth Method${NC}      SSH key only — passwords rejected"
else
    echo -e "  ${YELLOW}⚠${NC}  ${BOLD}Auth Method${NC}      Password ${DIM}(upgrade to SSH keys recommended)${NC}"
fi

echo -e "  ${GREEN}✓${NC}  ${BOLD}fail2ban${NC}         3 failed logins = 24 h IP ban"
echo -e "  ${GREEN}✓${NC}  ${BOLD}AppArmor${NC}         Mandatory access control enforcing"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Logging${NC}          Persistent, reboot-safe, 500 MB cap"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Monitoring${NC}       Daily audit 4 AM + on-demand health check"
echo -e "  ${GREEN}✓${NC}  ${BOLD}Cleanup${NC}          Unnecessary services and packages removed"

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

echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${WHITE}📋 Useful Commands:${NC}"
echo ""
echo -e "    ${CYAN}sudo check-alerts${NC}                  ${DIM}Full security health check${NC}"
echo -e "    ${CYAN}sudo fail2ban-client status sshd${NC}   ${DIM}View banned attackers${NC}"
echo -e "    ${CYAN}sudo ufw status verbose${NC}            ${DIM}View firewall rules${NC}"
echo -e "    ${CYAN}sudo journalctl -u ssh -n 50${NC}       ${DIM}Recent SSH activity${NC}"
echo -e "    ${CYAN}sudo tail -f $AUDIT_LOG${NC}"
echo -e "                                          ${DIM}Live audit log${NC}"

echo ""
echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}${WHITE}📝 Recommended Next Steps:${NC}"
echo ""

STEP=1

if [[ -f /var/run/reboot-required ]]; then
    echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Reboot your server${NC} to load the new kernel"
    echo -e "       ${CYAN}sudo reboot${NC}"
    echo -e "       ${DIM}Then reconnect: ssh -p $INPUT_SSH_PORT $INPUT_USERNAME@$PUBLIC_IP${NC}"
    STEP=$((STEP+1))
    echo ""
fi

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

if [[ "$CLOUD_PROVIDER" =~ ^(oracle|aws|azure|gcp)$ ]]; then
    echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Cloud firewall${NC} — verify port $INPUT_SSH_PORT is open"
    echo -e "       ${DIM}in your ${CLOUD_PROVIDER} network security console${NC}"
    STEP=$((STEP+1))
    echo ""
fi

echo -e "  ${YELLOW}  $STEP.${NC}  ${BOLD}Run a health check${NC} after reconnecting"
echo -e "       ${CYAN}sudo check-alerts${NC}"
echo ""

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
