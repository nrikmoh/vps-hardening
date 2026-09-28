#!/usr/bin/env bash
#
# VPS Hardening Script - Enhanced Edition
# Comprehensive server security hardening with interactive menu
#

# Strict error handling
set -euo pipefail
IFS=$'\n\t'

# ============================================================
# COLOR DEFINITIONS
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ============================================================
# GLOBAL VARIABLES
# ============================================================
LOG_FILE="/var/log/vps-hardening.log"
BACKUP_DIR="/root/.vps-hardening-backups/$(date +%Y%m%d_%H%M%S)"
SSH_PORT=""
TARGET_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo "~$TARGET_USER")
export DEBIAN_FRONTEND=noninteractive

# ============================================================
# UTILITY FUNCTIONS
# ============================================================

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg" >> "$LOG_FILE"
}

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              VPS HARDENING SCRIPT - ENHANCED                ║"
    echo "║              Comprehensive Server Security                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}  [!] Run this script as root or with sudo${NC}"
    echo -e "${YELLOW}  [!] A backup is created before each change${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}${BOLD}  $1${NC}"
    echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_status() {
    echo -e "  ${GREEN}[✔]${NC} $1"
    log "[SUCCESS] $1"
}

print_warning() {
    echo -e "  ${YELLOW}[!]${NC} $1"
    log "[WARNING] $1"
}

print_error() {
    echo -e "  ${RED}[✘]${NC} $1"
    log "[ERROR] $1"
}

print_info() {
    echo -e "  ${CYAN}[i]${NC} $1"
    log "[INFO] $1"
}

confirm() {
    local prompt="$1"
    local response
    echo -ne "  ${MAGENTA}[?]${NC} ${prompt} (y/n): "
    read -r response
    [[ "$response" =~ ^[Yy]$ ]]
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        local backup_path="${BACKUP_DIR}$(dirname "$file")"
        mkdir -p "$backup_path"
        cp -p "$file" "$backup_path/"
        log "[BACKUP] $file -> $backup_path/"
    fi
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        print_error "This script must be run as root."
        echo -e "  ${YELLOW}Run with: sudo bash $0${NC}"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_VERSION="${VERSION_ID:-unknown}"
        OS_NAME="${PRETTY_NAME}"
        print_info "Detected OS: ${OS_NAME}"
    else
        print_error "Unsupported Linux distribution. /etc/os-release not found."
        exit 1
    fi
}

create_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    print_info "Backup directory: ${BACKUP_DIR}"
}

# ============================================================
# TIER 0: ORIGINAL HARDENING FUNCTIONS (ENHANCED)
# ============================================================

harden_ssh() {
    print_section "SSH HARDENING"

    # Determine SSH port
    echo -ne "  ${MAGENTA}[?]${NC} Enter desired SSH port [default: 2222]: "
    read -r port_input
    SSH_PORT="${port_input:-2222}"

    # Validate port number
    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        print_error "Invalid port number. Using default 2222."
        SSH_PORT=2222
    fi

    # Check for existing SSH keys BEFORE disabling password auth
    local AUTH_KEYS="${USER_HOME}/.ssh/authorized_keys"
    local disable_password="yes"

    if [ ! -s "$AUTH_KEYS" ]; then
        print_warning "No SSH keys found in ${AUTH_KEYS}"
        print_warning "PasswordAuthentication will NOT be disabled to prevent lockout."
        print_warning "Add your public key first, then re-run this section."
        disable_password="no"
    else
        local key_count
        key_count=$(grep -cve '^\s*$' "$AUTH_KEYS" 2>/dev/null || echo "0")
        print_info "Found ${key_count} SSH key(s) in ${AUTH_KEYS}"
    fi

    # Backup original config
    backup_file /etc/ssh/sshd_config

    # Use drop-in configuration file (idempotent)
    mkdir -p /etc/ssh/sshd_config.d

    cat <<EOF > /etc/ssh/sshd_config.d/99-hardening.conf
# VPS Hardening - SSH Configuration
# Generated on $(date)

Port ${SSH_PORT}
PermitRootLogin no
MaxAuthTries 3
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication ${disable_password == "yes" && echo "no" || echo "yes"}
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
Banner /etc/issue.net
Protocol 2
EOF

    # Fix the PasswordAuthentication line properly
    if [ "$disable_password" = "yes" ]; then
        sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config.d/99-hardening.conf
    else
        sed -i 's/^PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config.d/99-hardening.conf
    fi

    chmod 600 /etc/ssh/sshd_config.d/99-hardening.conf

    # Handle Ubuntu 24.04+ systemd socket activation
    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
        print_info "Detected systemd SSH socket activation (Ubuntu 24.04+)"
        mkdir -p /etc/systemd/system/ssh.socket.d
        cat <<EOF > /etc/systemd/system/ssh.socket.d/listen.conf
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF
        systemctl daemon-reload
        print_status "SSH socket override created for port ${SSH_PORT}"
    fi

    # Set login banner
    echo "Authorized access only. All activity is monitored and logged." > /etc/issue.net

    # Validate SSH configuration before restarting
    if sshd -t 2>/dev/null; then
        print_status "SSH configuration syntax is valid"

        if systemctl is-active --quiet ssh.socket 2>/dev/null; then
            systemctl restart ssh.socket
        elif systemctl is-active --quiet ssh 2>/dev/null; then
            systemctl restart ssh
        elif systemctl is-active --quiet sshd 2>/dev/null; then
            systemctl restart sshd
        fi

        print_status "SSH hardened on port ${SSH_PORT}"
    else
        print_error "SSH configuration test FAILED! Reverting changes..."
        rm -f /etc/ssh/sshd_config.d/99-hardening.conf
        rm -rf /etc/systemd/system/ssh.socket.d/listen.conf
        systemctl daemon-reload 2>/dev/null
        print_error "Changes reverted. Please check your SSH configuration manually."
        return 1
    fi

    if [ "$disable_password" = "no" ]; then
        print_warning "Password authentication is still ENABLED."
        print_warning "To disable it: add your SSH key, then re-run SSH hardening."
    fi
}

configure_firewall() {
    print_section "FIREWALL CONFIGURATION (UFW)"

    if ! command -v ufw &>/dev/null; then
        print_info "Installing UFW..."
        apt-get install -y ufw >> "$LOG_FILE" 2>&1
    fi

    # Determine SSH port to allow
    if [ -z "$SSH_PORT" ]; then
        echo -ne "  ${MAGENTA}[?]${NC} Enter your SSH port [default: 2222]: "
        read -r port_input
        SSH_PORT="${port_input:-2222}"
    fi

    backup_file /etc/ufw/ufw.conf

    # Reset UFW to clean state
    ufw --force reset >> "$LOG_FILE" 2>&1

    # Default policies
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1

    # Allow SSH on custom port
    ufw allow "${SSH_PORT}/tcp" comment "SSH" >> "$LOG_FILE" 2>&1
    print_status "Allowed SSH on port ${SSH_PORT}"

    # Optional services
    if confirm "Allow HTTP (port 80)?"; then
        ufw allow 80/tcp comment "HTTP" >> "$LOG_FILE" 2>&1
        print_status "Allowed HTTP"
    fi

    if confirm "Allow HTTPS (port 443)?"; then
        ufw allow 443/tcp comment "HTTPS" >> "$LOG_FILE" 2>&1
        print_status "Allowed HTTPS"
    fi

    if confirm "Add any additional custom ports?"; then
        while true; do
            echo -ne "  ${MAGENTA}[?]${NC} Enter port (or 'done' to finish): "
            read -r custom_port
            [ "$custom_port" = "done" ] && break
            if [[ "$custom_port" =~ ^[0-9]+$ ]] && [ "$custom_port" -ge 1 ] && [ "$custom_port" -le 65535 ]; then
                echo -ne "  ${MAGENTA}[?]${NC} Protocol (tcp/udp/both) [default: tcp]: "
                read -r proto
                proto="${proto:-tcp}"
                if [ "$proto" = "both" ]; then
                    ufw allow "$custom_port" comment "Custom" >> "$LOG_FILE" 2>&1
                else
                    ufw allow "${custom_port}/${proto}" comment "Custom" >> "$LOG_FILE" 2>&1
                fi
                print_status "Allowed port ${custom_port}/${proto}"
            else
                print_warning "Invalid port: ${custom_port}"
            fi
        done
    fi

    # Enable UFW
    ufw --force enable >> "$LOG_FILE" 2>&1
    print_status "UFW firewall enabled"

    echo ""
    print_info "Current firewall rules:"
    ufw status verbose
}

setup_fail2ban() {
    print_section "FAIL2BAN CONFIGURATION"

    if ! command -v fail2ban-client &>/dev/null; then
        print_info "Installing Fail2ban..."
        apt-get install -y fail2ban >> "$LOG_FILE" 2>&1
    fi

    # Determine SSH port
    if [ -z "$SSH_PORT" ]; then
        echo -ne "  ${MAGENTA}[?]${NC} Enter your SSH port [default: 2222]: "
        read -r port_input
        SSH_PORT="${port_input:-2222}"
    fi

    echo -ne "  ${MAGENTA}[?]${NC} Ban time in minutes [default: 60]: "
    read -r bantime_input
    local bantime="${bantime_input:-60}"

    echo -ne "  ${MAGENTA}[?]${NC} Max retry attempts [default: 4]: "
    read -r maxretry_input
    local maxretry="${maxretry_input:-4}"

    echo -ne "  ${MAGENTA}[?]${NC} Find time window in minutes [default: 10]: "
    read -r findtime_input
    local findtime="${findtime_input:-10}"

    # Determine backend
    local backend="auto"
    if systemctl is-active --quiet systemd-journald 2>/dev/null; then
        backend="systemd"
    fi

    # Use jail.d drop-in (never modify jail.conf directly)
    mkdir -p /etc/fail2ban/jail.d

    cat <<EOF > /etc/fail2ban/jail.d/custom-ssh.local
# VPS Hardening - Fail2ban Configuration
# Generated on $(date)

[DEFAULT]
bantime  = ${bantime}m
findtime = ${findtime}m
maxretry = ${maxretry}
banaction = ufw
backend = ${backend}
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port    = ${SSH_PORT}
EOF

    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl restart fail2ban >> "$LOG_FILE" 2>&1
    print_status "Fail2ban configured (ban: ${bantime}m, retries: ${maxretry}, window: ${findtime}m)"
}

kernel_hardening() {
    print_section "KERNEL HARDENING (SYSCTL)"

    # Use drop-in file (idempotent)
    backup_file /etc/sysctl.d/99-security.conf

    cat <<'EOF' > /etc/sysctl.d/99-security.conf
# VPS Hardening - Kernel Security Parameters

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

# ---- Disable ICMP Redirects (Prevent MITM) ----
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# ---- SYN Flood Protection ----
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_rfc1337 = 1

# ---- Disable IPv4 Forwarding (unless router) ----
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# ---- Memory Protection (ASLR) ----
kernel.randomize_va_space = 2

# ---- Restrict Kernel Information Leaks ----
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2

# ---- Restrict Unprivileged BPF ----
kernel.unprivileged_bpf_disabled = 1

# ---- Restrict Ptrace (process tracing) ----
kernel.yama.ptrace_scope = 2

# ---- File Protection ----
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# ---- Restrict Core Dumps ----
fs.suid_dumpable = 0
EOF

    sysctl --system >> "$LOG_FILE" 2>&1
    print_status "Kernel parameters hardened via /etc/sysctl.d/99-security.conf"
}

setup_auto_updates() {
    print_section "AUTOMATIC SECURITY UPDATES"

    apt-get install -y unattended-upgrades apt-listchanges >> "$LOG_FILE" 2>&1

    # Enable unattended upgrades
    cat <<'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

    if confirm "Enable automatic reboot after kernel updates (at 03:30)?"; then
        cat <<'EOF' > /etc/apt/apt.conf.d/51unattended-upgrades-custom
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
        print_status "Automatic reboot enabled at 03:30"
    fi

    systemctl enable unattended-upgrades >> "$LOG_FILE" 2>&1
    systemctl restart unattended-upgrades >> "$LOG_FILE" 2>&1
    print_status "Automatic security updates configured"
}

system_update() {
    print_section "SYSTEM UPDATE"

    print_info "Updating package lists..."
    apt-get update -y >> "$LOG_FILE" 2>&1
    print_status "Package lists updated"

    print_info "Upgrading installed packages..."
    apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade -y >> "$LOG_FILE" 2>&1
    print_status "System packages upgraded"

    print_info "Removing unnecessary packages..."
    apt-get autoremove -y >> "$LOG_FILE" 2>&1
    apt-get autoclean -y >> "$LOG_FILE" 2>&1
    print_status "System cleaned"
}

# ============================================================
# TIER 1: HIGH IMPACT ADDITIONS
# ============================================================

secure_shared_memory() {
    print_section "SECURE SHARED MEMORY (/dev/shm)"

    if grep -q " /dev/shm " /etc/fstab; then
        print_warning "/dev/shm already has an entry in /etc/fstab. Skipping."
    else
        backup_file /etc/fstab
        echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
        mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null || true
        print_status "/dev/shm secured with noexec,nosuid,nodev"
    fi
}

disable_unused_protocols() {
    print_section "DISABLE UNUSED NETWORK PROTOCOLS"

    cat <<'EOF' > /etc/modprobe.d/disable-protocols.conf
# VPS Hardening - Disable unused network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
    print_status "Disabled DCCP, SCTP, RDS, TIPC kernel modules"

    if confirm "Also disable USB storage module? (recommended for remote VPS)"; then
        echo "install usb-storage /bin/true" >> /etc/modprobe.d/disable-protocols.conf
        print_status "USB storage module disabled"
    fi
}

setup_apparmor() {
    print_section "APPARMOR - MANDATORY ACCESS CONTROL"

    if ! command -v apparmor_status &>/dev/null && ! command -v aa-status &>/dev/null; then
        print_info "Installing AppArmor..."
        apt-get install -y apparmor apparmor-utils >> "$LOG_FILE" 2>&1
    fi

    apt-get install -y apparmor-profiles apparmor-profiles-extra >> "$LOG_FILE" 2>&1

    # Enforce all loaded profiles
    local profiles_enforced=0
    if command -v aa-enforce &>/dev/null; then
        for profile in /etc/apparmor.d/*; do
            if [ -f "$profile" ] && [[ ! "$(basename "$profile")" =~ ^(local|abstractions|tunables|disable|force-complain|lxc)$ ]]; then
                aa-enforce "$profile" >> "$LOG_FILE" 2>&1 && ((profiles_enforced++)) || true
            fi
        done
    fi

    systemctl enable apparmor >> "$LOG_FILE" 2>&1
    systemctl restart apparmor >> "$LOG_FILE" 2>&1

    print_status "AppArmor enabled with ${profiles_enforced} profiles enforced"
    print_info "Check status with: aa-status"
}

setup_aide() {
    print_section "FILE INTEGRITY MONITORING (AIDE)"

    if ! command -v aide &>/dev/null; then
        print_info "Installing AIDE (this may take a moment)..."
        apt-get install -y aide aide-common >> "$LOG_FILE" 2>&1
    fi

    print_info "Initializing AIDE database (this takes several minutes)..."
    aideinit >> "$LOG_FILE" 2>&1 || true

    if [ -f /var/lib/aide/aide.db.new ]; then
        cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        print_status "AIDE database initialized"
    elif [ -f /var/lib/aide/aide.db.new.gz ]; then
        cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
        print_status "AIDE database initialized (compressed)"
    fi

    # Create daily check cron
    cat <<'CRONEOF' > /etc/cron.daily/aide-check
#!/bin/bash
REPORT=$(/usr/bin/aide --check 2>&1)
if [ $? -ne 0 ]; then
    echo "$REPORT" | logger -t aide-check -p auth.warning
fi
CRONEOF
    chmod +x /etc/cron.daily/aide-check
    print_status "Daily AIDE integrity check scheduled"
    print_info "Run manual check with: aide --check"
}

setup_auditd() {
    print_section "KERNEL AUDIT DAEMON (auditd)"

    if ! command -v auditctl &>/dev/null; then
        print_info "Installing auditd..."
        apt-get install -y auditd audispd-plugins >> "$LOG_FILE" 2>&1
    fi

    mkdir -p /etc/audit/rules.d
    backup_file /etc/audit/rules.d/hardening.rules

    cat <<'EOF' > /etc/audit/rules.d/hardening.rules
# VPS Hardening - Audit Rules

# Delete existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (1 = printk, 2 = panic)
-f 1

# Monitor privilege escalation
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor user/group changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Monitor SSH configuration
-w /etc/ssh/ -p wa -k sshd_config
-w /root/.ssh/ -p wa -k ssh_keys

# Monitor cron jobs
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Monitor kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules

# Monitor network configuration
-w /etc/hosts -p wa -k hosts
-w /etc/resolv.conf -p wa -k dns
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl

# Monitor AppArmor policy changes
-w /etc/apparmor/ -p wa -k apparmor
-w /etc/apparmor.d/ -p wa -k apparmor

# Log all failed access attempts
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EPERM -k access_denied
-a always,exit -F arch=b32 -S open,openat,creat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b32 -S open,openat,creat -F exit=-EPERM -k access_denied

# Log su and sudo usage
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/su -k privilege_escalation
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/sudo -k privilege_escalation

# Make rules immutable (requires reboot to change)
-e 2
EOF

    systemctl enable auditd >> "$LOG_FILE" 2>&1
    systemctl restart auditd >> "$LOG_FILE" 2>&1
    print_status "Audit daemon configured with comprehensive rules"
    print_info "Query logs with: ausearch -k sudoers | aureport --auth"
}

# ============================================================
# TIER 2: ADVANCED HARDENING
# ============================================================

setup_resource_limits() {
    print_section "RESOURCE LIMITS & FORK BOMB PROTECTION"

    backup_file /etc/security/limits.d/99-hardening.conf

    cat <<'EOF' > /etc/security/limits.d/99-hardening.conf
# VPS Hardening - Resource Limits

# Max processes per user (fork bomb protection)
*    hard    nproc     512
*    soft    nproc     256
root hard    nproc     unlimited

# Max open files
*    hard    nofile    65536
*    soft    nofile    8192

# Max memory lock
*    hard    memlock   65536

# Disable core dumps (prevent memory scraping)
*    hard    core      0
*    soft    core      0
EOF

    # Ensure pam_limits is loaded
    if ! grep -q "pam_limits.so" /etc/pam.d/common-session 2>/dev/null; then
        echo "session required pam_limits.so" >> /etc/pam.d/common-session
    fi

    # Also disable core dumps via sysctl (belt and suspenders)
    echo "* hard core 0" > /etc/security/limits.d/disable-coredumps.conf
    mkdir -p /etc/systemd/coredump.conf.d
    cat <<'EOF' > /etc/systemd/coredump.conf.d/disable.conf
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

    print_status "Resource limits and fork bomb protection configured"
}

disable_unnecessary_services() {
    print_section "DISABLE UNNECESSARY SERVICES"

    local services_to_check=(
        "rpcbind:RPC Bind (NFS)"
        "nfs-server:NFS Server"
        "cups:CUPS Print Server"
        "avahi-daemon:Avahi mDNS"
        "bluetooth:Bluetooth"
        "apache2:Apache Web Server"
        "postfix:Postfix Mail Server"
        "exim4:Exim Mail Server"
        "snapd:Snap Package Manager"
    )

    for entry in "${services_to_check[@]}"; do
        local svc="${entry%%:*}"
        local desc="${entry##*:}"

        if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1 && \
           systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -q "$svc"; then
            local state
            state=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not found")
            if [ "$state" != "not found" ] && [ "$state" != "masked" ]; then
                if confirm "Disable ${desc} (${svc})? [current: ${state}]"; then
                    systemctl stop "$svc" 2>/dev/null || true
                    systemctl disable "$svc" 2>/dev/null || true
                    systemctl mask "$svc" 2>/dev/null || true
                    print_status "Disabled and masked: ${svc}"
                fi
            fi
        fi
    done

    print_status "Unnecessary services review complete"
}

restrict_cron_at() {
    print_section "RESTRICT CRON & AT ACCESS"

    # Restrict cron
    echo -ne "  ${MAGENTA}[?]${NC} Users allowed to use cron (comma-separated) [default: root]: "
    read -r cron_users_input
    local cron_users="${cron_users_input:-root}"

    rm -f /etc/cron.deny
    : > /etc/cron.allow
    IFS=',' read -ra CRON_ARRAY <<< "$cron_users"
    for user in "${CRON_ARRAY[@]}"; do
        user=$(echo "$user" | xargs)  # trim whitespace
        echo "$user" >> /etc/cron.allow
        print_status "Cron access granted to: ${user}"
    done
    chmod 640 /etc/cron.allow
    chown root:root /etc/cron.allow

    # Restrict at
    if command -v at &>/dev/null; then
        if confirm "Disable 'at' scheduler entirely?"; then
            apt-get purge -y at >> "$LOG_FILE" 2>&1
            print_status "'at' scheduler removed"
        else
            rm -f /etc/at.deny
            : > /etc/at.allow
            echo "root" >> /etc/at.allow
            chmod 640 /etc/at.allow
            print_status "'at' restricted to root only"
        fi
    fi

    # Secure cron directories
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
    chmod 600 /etc/crontab 2>/dev/null || true
    print_status "Cron directories secured"
}

setup_dns_over_tls() {
    print_section "DNS OVER TLS (ENCRYPTED DNS)"

    if ! systemctl list-unit-files systemd-resolved.service &>/dev/null 2>&1; then
        apt-get install -y systemd-resolved >> "$LOG_FILE" 2>&1
    fi

    backup_file /etc/systemd/resolved.conf

    echo -ne "  ${MAGENTA}[?]${NC} DNS provider:
    1) Cloudflare (1.1.1.1)
    2) Quad9 (9.9.9.9)
    3) Google (8.8.8.8)
    4) Cloudflare + Quad9 (default)
  Choice [4]: "
    read -r dns_choice
    dns_choice="${dns_choice:-4}"

    local dns_servers
    case "$dns_choice" in
        1) dns_servers="1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com" ;;
        2) dns_servers="9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net" ;;
        3) dns_servers="8.8.8.8#dns.google 8.8.4.4#dns.google" ;;
        *) dns_servers="1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net" ;;
    esac

    cat <<EOF > /etc/systemd/resolved.conf
[Resolve]
DNS=${dns_servers}
DNSOverTLS=yes
DNSSEC=allow-downgrade
FallbackDNS=1.0.0.1#cloudflare-dns.com 149.112.112.112#dns.quad9.net
Cache=yes
CacheFromLocalhost=no
EOF

    systemctl enable systemd-resolved >> "$LOG_FILE" 2>&1
    systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1

    # Symlink resolv.conf if not already managed
    if [ ! -L /etc/resolv.conf ] || [ "$(readlink /etc/resolv.conf)" != "/run/systemd/resolve/stub-resolv.conf" ]; then
        if confirm "Replace /etc/resolv.conf with systemd-resolved stub? (recommended)"; then
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            print_status "/etc/resolv.conf linked to systemd-resolved"
        fi
    fi

    print_status "DNS over TLS configured"
    print_info "Verify with: resolvectl status"
}

install_lynis() {
    print_section "SECURITY AUDITING (LYNIS)"

    if ! command -v lynis &>/dev/null; then
        print_info "Installing Lynis..."
        apt-get install -y lynis >> "$LOG_FILE" 2>&1
    fi

    # Schedule weekly audit
    cat <<'CRONEOF' > /etc/cron.weekly/lynis-audit
#!/bin/bash
/usr/bin/lynis audit system --cronjob --report-file /var/log/lynis-report.txt 2>&1 | logger -t lynis-audit
CRONEOF
    chmod +x /etc/cron.weekly/lynis-audit

    print_status "Lynis installed with weekly automated audit"

    if confirm "Run a quick Lynis audit now?"; then
        echo ""
        lynis audit system --quick 2>&1 | tail -30
        echo ""
        print_info "Full report at: /var/log/lynis-report.dat"
    fi
}

setup_log_forwarding() {
    print_section "LOG FORWARDING (ANTI-TAMPERING)"

    print_info "Log forwarding sends copies of your logs to an external server"
    print_info "so attackers cannot erase evidence after compromise."
    echo ""

    echo -ne "  ${MAGENTA}[?]${NC} Remote syslog server address (e.g., logs.example.com): "
    read -r remote_server

    if [ -z "$remote_server" ]; then
        print_warning "No server specified. Skipping log forwarding."
        return
    fi

    echo -ne "  ${MAGENTA}[?]${NC} Remote port [default: 514]: "
    read -r remote_port
    remote_port="${remote_port:-514}"

    echo -ne "  ${MAGENTA}[?]${NC} Protocol (tcp/udp) [default: tcp]: "
    read -r remote_proto
    remote_proto="${remote_proto:-tcp}"

    if ! command -v rsyslogd &>/dev/null; then
        apt-get install -y rsyslog >> "$LOG_FILE" 2>&1
    fi

    backup_file /etc/rsyslog.d/50-remote.conf

    if [ "$remote_proto" = "tcp" ]; then
        cat <<EOF > /etc/rsyslog.d/50-remote.conf
# VPS Hardening - Remote Log Forwarding
*.* @@${remote_server}:${remote_port}
EOF
    else
        cat <<EOF > /etc/rsyslog.d/50-remote.conf
# VPS Hardening - Remote Log Forwarding
*.* @${remote_server}:${remote_port}
EOF
    fi

    systemctl restart rsyslog >> "$LOG_FILE" 2>&1
    print_status "Log forwarding configured to ${remote_server}:${remote_port} (${remote_proto})"
}

setup_kernel_lockdown() {
    print_section "KERNEL LOCKDOWN & MODULE RESTRICTIONS"

    print_warning "Kernel lockdown restricts even root from accessing raw memory."
    print_warning "This may break some monitoring tools or custom kernel modules."

    if confirm "Enable kernel lockdown (integrity mode)?"; then
        backup_file /etc/default/grub

        if grep -q "lockdown=" /etc/default/grub; then
            sed -i 's/lockdown=[a-z]*/lockdown=integrity/' /etc/default/grub
        else
            sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 lockdown=integrity"/' /etc/default/grub
        fi

        if command -v update-grub &>/dev/null; then
            update-grub >> "$LOG_FILE" 2>&1
        elif command -v grub2-mkconfig &>/dev/null; then
            grub2-mkconfig -o /boot/grub2/grub.cfg >> "$LOG_FILE" 2>&1
        fi

        print_status "Kernel lockdown (integrity mode) will be active after reboot"
    fi

    if confirm "Restrict kernel module loading after boot?"; then
        # This prevents loading NEW modules after boot
        cat <<'EOF' > /etc/sysctl.d/99-module-restrict.conf
# Restrict module loading
kernel.modules_disabled = 1
EOF
        print_warning "kernel.modules_disabled=1 will be applied on next reboot."
        print_warning "After boot, no new kernel modules can be loaded until reboot."
        print_status "Kernel module restriction configured"
    fi
}

# ============================================================
# TIER 3: NETWORK ZERO TRUST
# ============================================================

setup_tailscale() {
    print_section "TAILSCALE VPN (ZERO TRUST NETWORK)"

    print_info "Tailscale creates an encrypted WireGuard mesh network."
    print_info "Once connected, you can remove SSH from the public internet entirely."
    echo ""

    if ! command -v tailscale &>/dev/null; then
        if confirm "Install Tailscale?"; then
            curl -fsSL https://tailscale.com/install.sh | sh
            print_status "Tailscale installed"
        else
            return
        fi
    fi

    if confirm "Start Tailscale and authenticate?"; then
        tailscale up
        echo ""
        print_info "Tailscale IP: $(tailscale ip -4 2>/dev/null || echo 'pending...')"
    fi

    if confirm "Restrict SSH to Tailscale interface ONLY? (blocks public SSH)"; then
        if [ -z "$SSH_PORT" ]; then
            echo -ne "  ${MAGENTA}[?]${NC} Your SSH port: "
            read -r SSH_PORT
        fi
        ufw delete allow "${SSH_PORT}/tcp" 2>/dev/null || true
        ufw allow in on tailscale0 to any port "${SSH_PORT}" proto tcp comment "SSH via Tailscale only" >> "$LOG_FILE" 2>&1
        print_status "SSH now only accessible via Tailscale"
        print_warning "Make sure your Tailscale connection is working before disconnecting!"
    fi
}

setup_fwknop() {
    print_section "SINGLE PACKET AUTHORIZATION (fwknop)"

    print_info "fwknop keeps your SSH port completely invisible."
    print_info "You send one encrypted UDP packet to 'knock' the port open for your IP."
    echo ""

    if ! command -v fwknopd &>/dev/null; then
        if confirm "Install fwknop?"; then
            apt-get install -y fwknop-server >> "$LOG_FILE" 2>&1
            print_status "fwknop installed"
        else
            return
        fi
    fi

    if [ -z "$SSH_PORT" ]; then
        echo -ne "  ${MAGENTA}[?]${NC} Your SSH port: "
        read -r SSH_PORT
    fi

    backup_file /etc/fwknop/fwknopd.conf
    backup_file /etc/fwknop/access.conf

    # Generate access key
    local spa_key
    spa_key=$(fwknop --key-gen 2>/dev/null | grep "KEY_BASE64" | head -1 | awk '{print $2}')
    local hmac_key
    hmac_key=$(fwknop --key-gen 2>/dev/null | grep "HMAC_KEY_BASE64" | head -1 | awk '{print $2}')

    if [ -z "$spa_key" ] || [ -z "$hmac_key" ]; then
        # Fallback key generation
        spa_key=$(openssl rand -base64 32)
        hmac_key=$(openssl rand -base64 32)
    fi

    cat <<EOF > /etc/fwknop/access.conf
SOURCE                  ANY
OPEN_PORTS              tcp/${SSH_PORT}
FW_ACCESS_TIMEOUT       30
REQUIRE_SOURCE_ADDRESS  Y
KEY_BASE64              ${spa_key}
HMAC_KEY_BASE64         ${hmac_key}
EOF

    sed -i "s/^#\?PCAP_INTF .*/PCAP_INTF eth0;/" /etc/fwknop/fwknopd.conf 2>/dev/null || true

    chmod 600 /etc/fwknop/access.conf
    systemctl enable fwknop-server >> "$LOG_FILE" 2>&1
    systemctl restart fwknop-server >> "$LOG_FILE" 2>&1

    print_status "fwknop configured for port ${SSH_PORT}"
    echo ""
    print_warning "SAVE THESE KEYS SECURELY - you need them on your client:"
    echo -e "    ${YELLOW}SPA Key:  ${spa_key}${NC}"
    echo -e "    ${YELLOW}HMAC Key: ${hmac_key}${NC}"
    echo ""
    print_info "Client usage: fwknop -A tcp/${SSH_PORT} -D your-vps-ip --key-base64 <SPA_KEY> --hmac-base64 <HMAC_KEY>"
}

# ============================================================
# ADDITIONAL SECURITY FUNCTIONS
# ============================================================

secure_tmp_directories() {
    print_section "SECURE TEMPORARY DIRECTORIES"

    # Secure /tmp if it's not already a separate mount
    if ! mount | grep -q " /tmp "; then
        if confirm "Mount /tmp with noexec,nosuid,nodev?"; then
            if ! grep -q " /tmp " /etc/fstab; then
                backup_file /etc/fstab
                echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=2G 0 0" >> /etc/fstab
                mount -o remount /tmp 2>/dev/null || true
                print_status "/tmp secured"
            fi
        fi
    else
        print_info "/tmp is already a separate mount"
    fi

    # Secure /var/tmp
    if confirm "Restrict /var/tmp?"; then
        if ! grep -q " /var/tmp " /etc/fstab; then
            backup_file /etc/fstab
            echo "tmpfs /var/tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=1G 0 0" >> /etc/fstab
            mount -o remount /var/tmp 2>/dev/null || true
            print_status "/var/tmp secured"
        fi
    fi
}

setup_login_security() {
    print_section "LOGIN & PASSWORD SECURITY"

    # Password quality
    if confirm "Install and configure password quality requirements?"; then
        apt-get install -y libpam-pwquality >> "$LOG_FILE" 2>&1
        backup_file /etc/security/pwquality.conf

        cat <<'EOF' > /etc/security/pwquality.conf
# VPS Hardening - Password Quality
minlen = 12
minclass = 3
maxrepeat = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
reject_username
enforce_for_root
EOF
        print_status "Password quality requirements configured"
    fi

    # Login delay on failure
    if confirm "Add delay after failed login attempts?"; then
        if ! grep -q "pam_faildelay.so" /etc/pam.d/common-auth 2>/dev/null; then
            echo "auth optional pam_faildelay.so delay=4000000" >> /etc/pam.d/common-auth
            print_status "4-second delay added after failed logins"
        fi
    fi

    # Login timeout
    if ! grep -q "^TMOUT=" /etc/profile.d/timeout.sh 2>/dev/null; then
        echo -ne "  ${MAGENTA}[?]${NC} Shell timeout in seconds (0 to skip) [default: 900]: "
        read -r timeout_input
        local timeout_val="${timeout_input:-900}"
        if [ "$timeout_val" != "0" ]; then
            cat <<EOF > /etc/profile.d/timeout.sh
# Auto-logout inactive sessions
TMOUT=${timeout_val}
readonly TMOUT
export TMOUT
EOF
            print_status "Shell auto-logout after ${timeout_val}s of inactivity"
        fi
    fi
}

setup_user_hardening() {
    print_section "USER ACCOUNT HARDENING"

    # Restrict su to wheel/sudo group
    if confirm "Restrict 'su' command to sudo group only?"; then
        backup_file /etc/pam.d/su
        if ! grep -q "pam_wheel.so" /etc/pam.d/su 2>/dev/null || grep -q "^#.*pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
            sed -i 's/^#\s*auth\s*required\s*pam_wheel.so/auth required pam_wheel.so/' /etc/pam.d/su
            print_status "'su' restricted to sudo group members"
        fi
    fi

    # Lock unused system accounts
    if confirm "Lock unused default system accounts?"; then
        local accounts_to_lock=("games" "lp" "mail" "news" "uucp" "proxy" "www-data" "list" "irc" "gnats" "nobody")
        for acct in "${accounts_to_lock[@]}"; do
            if id "$acct" &>/dev/null; then
                usermod -L "$acct" 2>/dev/null || true
                usermod -s /usr/sbin/nologin "$acct" 2>/dev/null || true
            fi
        done
        print_status "Unused system accounts locked"
    fi

    # Umask hardening
    if confirm "Set restrictive default umask (027)?"; then
        backup_file /etc/login.defs
        sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
        echo "umask 027" > /etc/profile.d/umask.sh
        print_status "Default umask set to 027"
    fi
}

# ============================================================
# INTERACTIVE MENU
# ============================================================

show_menu() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    HARDENING MENU                          ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║                                                            ║"
    echo "║  ${GREEN}── ESSENTIAL (Tier 0) ──────────────────────────────${CYAN}       ║"
    echo "║   ${WHITE} 1)  System Update & Cleanup${CYAN}                            ║"
    echo "║   ${WHITE} 2)  SSH Hardening${CYAN}                                      ║"
    echo "║   ${WHITE} 3)  Firewall (UFW)${CYAN}                                     ║"
    echo "║   ${WHITE} 4)  Fail2ban${CYAN}                                           ║"
    echo "║   ${WHITE} 5)  Kernel Hardening (sysctl)${CYAN}                           ║"
    echo "║   ${WHITE} 6)  Automatic Security Updates${CYAN}                          ║"
    echo "║                                                            ║"
    echo "║  ${YELLOW}── HIGH IMPACT (Tier 1) ────────────────────────────${CYAN}     ║"
    echo "║   ${WHITE} 7)  Secure Shared Memory (/dev/shm)${CYAN}                    ║"
    echo "║   ${WHITE} 8)  Disable Unused Network Protocols${CYAN}                    ║"
    echo "║   ${WHITE} 9)  AppArmor (Mandatory Access Control)${CYAN}                 ║"
    echo "║   ${WHITE}10)  File Integrity Monitoring (AIDE)${CYAN}                    ║"
    echo "║   ${WHITE}11)  Kernel Audit Daemon (auditd)${CYAN}                        ║"
    echo "║   ${WHITE}12)  Secure Temporary Directories${CYAN}                        ║"
    echo "║                                                            ║"
    echo "║  ${MAGENTA}── ADVANCED (Tier 2) ───────────────────────────────${CYAN}    ║"
    echo "║   ${WHITE}13)  Resource Limits & Fork Bomb Protection${CYAN}              ║"
    echo "║   ${WHITE}14)  Disable Unnecessary Services${CYAN}                        ║"
    echo "║   ${WHITE}15)  Restrict Cron & At Access${CYAN}                           ║"
    echo "║   ${WHITE}16)  DNS over TLS${CYAN}                                        ║"
    echo "║   ${WHITE}17)  Login & Password Security${CYAN}                           ║"
    echo "║   ${WHITE}18)  User Account Hardening${CYAN}                              ║"
    echo "║   ${WHITE}19)  Security Auditing (Lynis)${CYAN}                           ║"
    echo "║   ${WHITE}20)  Log Forwarding (Anti-Tampering)${CYAN}                     ║"
    echo "║   ${WHITE}21)  Kernel Lockdown & Module Restrictions${CYAN}               ║"
    echo "║                                                            ║"
    echo "║  ${RED}── ZERO TRUST NETWORK (Tier 3) ────────────────────${CYAN}      ║"
    echo "║   ${WHITE}22)  Tailscale VPN${CYAN}                                       ║"
    echo "║   ${WHITE}23)  Single Packet Authorization (fwknop)${CYAN}                ║"
    echo "║                                                            ║"
    echo "║  ${GREEN}── BATCH OPERATIONS ───────────────────────────────${CYAN}      ║"
    echo "║   ${WHITE}30)  Run ALL Essential (Tier 0: options 1-6)${CYAN}             ║"
    echo "║   ${WHITE}31)  Run ALL Essential + High Impact (Tier 0+1)${CYAN}          ║"
    echo "║   ${WHITE}32)  Run EVERYTHING (Tier 0+1+2)${CYAN}                         ║"
    echo "║                                                            ║"
    echo "║   ${WHITE} s)  Show Current Security Status${CYAN}                        ║"
    echo "║   ${WHITE} q)  Quit${CYAN}                                                ║"
    echo "║                                                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_security_status() {
    print_section "CURRENT SECURITY STATUS"

    # SSH
    echo -e "  ${BOLD}SSH:${NC}"
    local ssh_port_current
    ssh_port_current=$(grep -h "^Port " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
    echo -e "    Port: ${CYAN}${ssh_port_current:-22}${NC}"
    local pass_auth
    pass_auth=$(grep -h "^PasswordAuthentication " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
    echo -e "    PasswordAuth: ${pass_auth:-unknown}"
    local root_login
    root_login=$(grep -h "^PermitRootLogin " /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
    echo -e "    RootLogin: ${root_login:-unknown}"
    echo ""

    # Firewall
    echo -e "  ${BOLD}Firewall (UFW):${NC}"
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status | head -1)
        echo -e "    Status: ${CYAN}${ufw_status}${NC}"
    else
        echo -e "    ${RED}Not installed${NC}"
    fi
    echo ""

    # Fail2ban
    echo -e "  ${BOLD}Fail2ban:${NC}"
    if command -v fail2ban-client &>/dev/null; then
        local f2b_status
        f2b_status=$(systemctl is-active fail2ban 2>/dev/null || echo "inactive")
        echo -e "    Status: ${CYAN}${f2b_status}${NC}"
        if [ "$f2b_status" = "active" ]; then
            local jails
            jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g' || echo "none")
            echo -e "    Jails: ${jails}"
        fi
    else
        echo -e "    ${RED}Not installed${NC}"
    fi
    echo ""

    # AppArmor
    echo -e "  ${BOLD}AppArmor:${NC}"
    if command -v aa-status &>/dev/null; then
        local aa_enforced
        aa_enforced=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" || echo "unknown")
        echo -e "    ${CYAN}${aa_enforced}${NC}"
    else
        echo -e "    ${RED}Not installed${NC}"
    fi
    echo ""

    # auditd
    echo -e "  ${BOLD}Audit Daemon:${NC}"
    if command -v auditctl &>/dev/null; then
        local audit_status
        audit_status=$(systemctl is-active auditd 2>/dev/null || echo "inactive")
        local audit_rules
        audit_rules=$(auditctl -l 2>/dev/null | wc -l || echo "0")
        echo -e "    Status: ${CYAN}${audit_status}${NC} (${audit_rules} rules)"
    else
        echo -e "    ${RED}Not installed${NC}"
    fi
    echo ""

    # AIDE
    echo -e "  ${BOLD}File Integrity (AIDE):${NC}"
    if command -v aide &>/dev/null; then
        echo -e "    ${GREEN}Installed${NC}"
        [ -f /var/lib/aide/aide.db ] && echo -e "    Database: ${GREEN}initialized${NC}" || echo -e "    Database: ${RED}not initialized${NC}"
    else
        echo -e "    ${RED}Not installed${NC}"
    fi
    echo ""

    # Tailscale
    echo -e "  ${BOLD}Tailscale:${NC}"
    if command -v tailscale &>/dev/null; then
        local ts_status
        ts_status=$(tailscale status --json 2>/dev/null | grep -o '"BackendState":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
        local ts_ip
        ts_ip=$(tailscale ip -4 2>/dev/null || echo "N/A")
        echo -e "    Status: ${CYAN}${ts_status}${NC} | IP: ${ts_ip}"
    else
        echo -e "    ${RED}Not installed${NC}"
    fi
    echo ""

    # Listening ports
    echo -e "  ${BOLD}Listening Ports:${NC}"
    ss -tlnp 2>/dev/null | grep LISTEN | awk '{printf "    %-40s %s\n", $4, $6}'
    echo ""

    # Kernel hardening
    echo -e "  ${BOLD}Kernel:${NC}"
    echo -e "    ASLR: $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)"
    echo -e "    dmesg_restrict: $(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)"
    echo -e "    SYN cookies: $(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null)"
    echo ""
}

# ============================================================
# MAIN EXECUTION
# ============================================================

main() {
    check_root
    print_banner
    detect_os
    create_backup_dir
    echo ""

    while true; do
        show_menu
        echo -ne "  ${BOLD}Select option: ${NC}"
        read -r choice

        case "$choice" in
            1)  system_update ;;
            2)  harden_ssh ;;
            3)  configure_firewall ;;
            4)  setup_fail2ban ;;
            5)  kernel_hardening ;;
            6)  setup_auto_updates ;;
            7)  secure_shared_memory ;;
            8)  disable_unused_protocols ;;
            9)  setup_apparmor ;;
            10) setup_aide ;;
            11) setup_auditd ;;
            12) secure_tmp_directories ;;
            13) setup_resource_limits ;;
            14) disable_unnecessary_services ;;
            15) restrict_cron_at ;;
            16) setup_dns_over_tls ;;
            17) setup_login_security ;;
            18) setup_user_hardening ;;
            19) install_lynis ;;
            20) setup_log_forwarding ;;
            21) setup_kernel_lockdown ;;
            22) setup_tailscale ;;
            23) setup_fwknop ;;
            30)
                print_section "RUNNING ALL ESSENTIAL (TIER 0)"
                if confirm "This will run options 1-6. Continue?"; then
                    system_update
                    harden_ssh
                    configure_firewall
                    setup_fail2ban
                    kernel_hardening
                    setup_auto_updates
                fi
                ;;
            31)
                print_section "RUNNING TIER 0 + TIER 1"
                if confirm "This will run options 1-12. Continue?"; then
                    system_update
                    harden_ssh
                    configure_firewall
                    setup_fail2ban
                    kernel_hardening
                    setup_auto_updates
                    secure_shared_memory
                    disable_unused_protocols
                    setup_apparmor
                    setup_aide
                    setup_auditd
                    secure_tmp_directories
                fi
                ;;
            32)
                print_section "RUNNING TIER 0 + TIER 1 + TIER 2"
                if confirm "This will run options 1-21. Continue?"; then
                    system_update
                    harden_ssh
                    configure_firewall
                    setup_fail2ban
                    kernel_hardening
                    setup_auto_updates
                    secure_shared_memory
                    disable_unused_protocols
                    setup_apparmor
                    setup_aide
                    setup_auditd
                    secure_tmp_directories
                    setup_resource_limits
                    disable_unnecessary_services
                    restrict_cron_at
                    setup_dns_over_tls
                    setup_login_security
                    setup_user_hardening
                    install_lynis
                    setup_log_forwarding
                    setup_kernel_lockdown
                fi
                ;;
            s|S)
                show_security_status
                ;;
            q|Q)
                echo ""
                print_section "HARDENING COMPLETE"
                print_info "Log file: ${LOG_FILE}"
                print_info "Backups: ${BACKUP_DIR}"
                echo ""
                if [ -n "$SSH_PORT" ]; then
                    print_warning "SSH is now on port ${SSH_PORT}"
                    print_warning "Connect with: ssh -p ${SSH_PORT} user@your-server"
                fi
                echo ""
                print_info "Recommended next steps:"
                echo -e "    1. Test SSH login in a ${RED}NEW terminal${NC} before closing this session"
                echo -e "    2. Run: ${CYAN}lynis audit system${NC} for a full security audit"
                echo -e "    3. Review: ${CYAN}cat ${LOG_FILE}${NC}"
                echo -e "    4. Consider setting up Tailscale (option 22) for zero-trust SSH"
                echo ""
                exit 0
                ;;
            *)
                print_error "Invalid option: ${choice}"
                ;;
        esac

        echo ""
        echo -ne "  Press ${BOLD}Enter${NC} to return to menu..."
        read -r
    done
}

# Run main function
main "$@"
