#!/bin/bash

# ==============================================================================
# Comprehensive System Security & Optimization Audit Script
# ==============================================================================

# --- Configuration ---
SENSITIVE_PATTERNS=(
    "password" "secret" "token" "passwd" "auth.db" "rbcpass"
    "SA\$YXy" "info.txt" "account-info" "pass_keys" "access-keys"
    "credentials" "api_key" "PB24" "githubinfo" "udemycom-info"
    "reddit-info" "soundcloudinfo" "cyberghostvpn-info"
    "digitalocean-info" "chatgpt-info" "bluesky-info" "hetzner.com"
    "proton-info" "edenred-info" "postat-info" "booking-info"
    "access-keys.txt" "argocd-initial-admin-secret"
)

# Output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Command Line Options
AUTO_FIX=false
GENERATE_REPORT=false
REPORT_DIR="$HOME/Labolatory/bash/reports"

# Executive Scorecard Counters
PASSED_COUNT=0
WARNING_COUNT=0
CRITICAL_COUNT=0
TOTAL_CHECKS=0

for arg in "$@"; do
    case "$arg" in
        --fix|-f)
            AUTO_FIX=true
            ;;
        --report|-r)
            GENERATE_REPORT=true
            ;;
        --help|-h)
            printf "Usage: %s [OPTIONS]\n" "$0"
            printf "Options:\n"
            printf "  -f, --fix     Automatically fix permissions & add safety aliases\n"
            printf "  -r, --report  Generate Markdown report log in %s\n" "$REPORT_DIR"
            printf "  -h, --help    Show this help message\n"
            exit 0
            ;;
    esac
done

if [[ "$GENERATE_REPORT" == true ]]; then
    mkdir -p "$REPORT_DIR"
    REPORT_FILE="$REPORT_DIR/audit-report-$(date +%Y-%m-%d_%H-%M-%S).md"
    exec > >(tee >(sed -r 's/\x1B\[[0-9;]*[mK]//g' > "$REPORT_FILE")) 2>&1
fi

echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}=== Starting System Security & Optimization Audit ===${NC}"
echo -e "${CYAN}=====================================================${NC}"

if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}Note: Running as non-root user. Deep system inspections (system logs, rootkit scans, password hashes) may be limited.${NC}"
    echo -e "${YELLOW}Tip: For complete audit coverage, run with 'sudo $0'\n${NC}"
fi

# --- Helper Functions & Tool Resolution ---

section() {
    echo -e "\n${BLUE}[$1] $2${NC}"
}

log_pass() {
    ((PASSED_COUNT++))
    ((TOTAL_CHECKS++))
    echo -e "${GREEN}✓ $1${NC}"
}

log_warn() {
    ((WARNING_COUNT++))
    ((TOTAL_CHECKS++))
    echo -e "${YELLOW}⚠️ $1${NC}"
}

log_crit() {
    ((CRITICAL_COUNT++))
    ((TOTAL_CHECKS++))
    echo -e "${RED}⚠️ CRITICAL: $1${NC}"
}

# Safe sudo execution wrapper (avoids hanging in non-interactive scripts)
run_sudo() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    elif sudo -n true 2>/dev/null; then
        sudo "$@"
    elif [[ -t 0 ]]; then
        sudo "$@"
    else
        return 1
    fi
}

# Helper to find tool paths in standard and system binary paths
find_tool() {
    local tool="$1"
    local path
    path=$(command -v "$tool" 2>/dev/null)
    if [[ -z "$path" ]]; then
        for extra_path in "/sbin/$tool" "/usr/sbin/$tool" "/usr/local/bin/$tool"; do
            if [[ -x "$extra_path" ]]; then
                path="$extra_path"
                break
            fi
        done
    fi
    echo "$path"
}

# --- Tool Cache & Pre-Flight Dependency Inspection ---
declare -A TOOL_BIN
declare -A TOOL_FOUND

TOOLS_TO_CHECK=(
    "sudo" "systemctl" "journalctl" "ss" "sysctl" "ssh-keygen" 
    "crontab" "ip" "df" "awk" "grep" "sed" "find" "clamscan" 
    "freshclam" "rkhunter" "trivy" "nmcli" "nmap" "docker" "podman"
    "apt-get" "dnf" "rpm" "dpkg-query" "lynis" "needrestart" "debsums"
)

check_all_dependencies() {
    echo -e "${YELLOW}=== Pre-Flight Security Tools & Dependency Check ===${NC}"
    local missing_tools=()

    for tool in "${TOOLS_TO_CHECK[@]}"; do
        local path
        path=$(find_tool "$tool")
        if [[ -n "$path" ]]; then
            TOOL_BIN["$tool"]="$path"
            TOOL_FOUND["$tool"]=1
            printf "  [${GREEN}✓${NC}] %-15s : Installed (%s)\n" "$tool" "$path"
        else
            TOOL_FOUND["$tool"]=0
            printf "  [${YELLOW}!${NC}] %-15s : ${YELLOW}NOT installed${NC}\n" "$tool"
            case "$tool" in
                clamscan|freshclam|rkhunter|trivy|nmap|lynis|needrestart|debsums)
                    missing_tools+=("$tool")
                    ;;
            esac
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "\n${YELLOW}Recommended Security Tools Installation Tip:${NC}"
        if [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
            echo -e "  Debian/Ubuntu: ${CYAN}sudo apt install ${missing_tools[*]}${NC}"
        elif [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
            echo -e "  Fedora/RHEL:   ${CYAN}sudo dnf install ${missing_tools[*]}${NC}"
        fi
    fi
    echo ""
}

check_all_dependencies

if [[ "$AUTO_FIX" == true ]]; then
    echo -e "${YELLOW}=== Running in Auto-Fix Mode (--fix enabled) ===${NC}"
    chmod 700 "$HOME/.ssh" 2>/dev/null
    chmod 600 "$HOME/.ssh"/* 2>/dev/null
    if [[ -d "$HOME/.minikube" ]]; then
        find "$HOME/.minikube" -name "*.pem" -exec chmod 600 {} + 2>/dev/null
    fi
    for rc_file in "$HOME/.zshrc" "$HOME/.bashrc"; do
        if [[ -f "$rc_file" ]]; then
            grep -q "alias rm=" "$rc_file" 2>/dev/null || echo "alias rm='rm -i'" >> "$rc_file"
            grep -q "alias cp=" "$rc_file" 2>/dev/null || echo "alias cp='cp -i'" >> "$rc_file"
            grep -q "alias mv=" "$rc_file" 2>/dev/null || echo "alias mv='mv -i'" >> "$rc_file"
        fi
    done
    echo -e "${GREEN}✓ Auto-fix completed: Permissions & safety aliases applied.${NC}\n"
fi

# Helper function to update security databases before audit
update_security_databases() {
    echo -e "${YELLOW}--- Updating Security & Audit Tool Databases ---${NC}"

    if [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
        echo -n "Updating APT package index... "
        run_sudo "${TOOL_BIN['apt-get']}" update -qq 2>/dev/null && echo -e "${GREEN}✓ Done${NC}" || echo -e "${YELLOW}Skipped/Cached${NC}"
    elif [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
        echo -n "Refreshing DNF repository metadata... "
        run_sudo "${TOOL_BIN['dnf']}" makecache --refresh &>/dev/null && echo -e "${GREEN}✓ Done${NC}" || echo -e "${YELLOW}Skipped/Cached${NC}"
    fi

    if [[ "${TOOL_FOUND['freshclam']}" -eq 1 ]]; then
        echo -n "Updating ClamAV virus signatures... "
        run_sudo "${TOOL_BIN['freshclam']}" 2>/dev/null && echo -e "${GREEN}✓ Done${NC}" || echo -e "${YELLOW}Updated or locked by daemon${NC}"
    fi

    if [[ "${TOOL_FOUND['rkhunter']}" -eq 1 ]]; then
        echo -n "Updating rkhunter rootkit definitions... "
        run_sudo "${TOOL_BIN['rkhunter']}" --update 2>/dev/null && echo -e "${GREEN}✓ Done${NC}" || echo -e "${YELLOW}Completed/Skipped${NC}"
    fi

    if [[ "${TOOL_FOUND['trivy']}" -eq 1 ]]; then
        echo -n "Updating Trivy vulnerability database... "
        "${TOOL_BIN['trivy']}" image --download-db-only 2>/dev/null && echo -e "${GREEN}✓ Done${NC}" || echo -e "${YELLOW}Skipped/Up to date${NC}"
    fi
    echo ""
}

update_security_databases

# 1. Shell History Scanning & Cleaning
section "1/20" "Cleaning Shell History for Sensitive Data..."
clean_history() {
    local file="$1"
    if [[ -f "$file" ]]; then
        echo "Processing $file..."
        local temp_file
        temp_file=$(mktemp)
        local pattern_regex
        pattern_regex=$(IFS="|"; echo "${SENSITIVE_PATTERNS[*]}")
        grep -vEia "$pattern_regex" "$file" > "$temp_file" 2>/dev/null
        mv "$temp_file" "$file"
        chmod 600 "$file"
    fi
}

find "$HOME" -maxdepth 1 \( -name ".zsh_history" -o -name ".bash_history*" \) 2>/dev/null | while read -r h_file; do
    clean_history "$h_file"
done
log_pass "Shell history cleaned and permissions set to 600."

# 2. Certificate & File Permission Checks
section "2/20" "Checking Minikube & SSH Certificate Permissions..."
MINIKUBE_DIR="$HOME/.minikube"
if [[ -d "$MINIKUBE_DIR" ]]; then
    CERT_FILES=$(find "$MINIKUBE_DIR" -name "*.pem" -perm /o+rwx,g+rwx 2>/dev/null)
    if [[ -n "$CERT_FILES" ]]; then
        log_warn "Found minikube files with insecure permissions:\n$CERT_FILES"
        echo "Fixing permissions to 600..."
        find "$MINIKUBE_DIR" -name "*.pem" -exec chmod 600 {} + 2>/dev/null
        log_pass "Minikube permissions fixed."
    else
        log_pass "Minikube certificate permissions are secure."
    fi
else
    echo "Minikube directory not found."
fi

echo -e "\n${YELLOW}--- Auditing SSH Private Keys & Passphrase Protection (All Users) ---${NC}"
check_ssh_keys_passphrase() {
    local unencrypted_keys_found=0
    local total_keys_found=0

    while IFS=: read -r username password uid gid gecos home shell; do
        local ssh_dir="$home/.ssh"
        if [[ -d "$ssh_dir" ]]; then
            chmod 700 "$ssh_dir" 2>/dev/null
            
            while read -r key_file; do
                [[ -f "$key_file" ]] || continue
                
                if grep -q "PRIVATE KEY" "$key_file" 2>/dev/null; then
                    chmod 600 "$key_file" 2>/dev/null
                    ((total_keys_found++))
                    
                    if [[ "${TOOL_FOUND['ssh-keygen']}" -eq 1 ]] && "${TOOL_BIN['ssh-keygen']}" -y -P "" -f "$key_file" &>/dev/null; then
                        ((unencrypted_keys_found++))
                        log_crit "UNPROTECTED SSH KEY: User ${username} -> ${key_file} (No passphrase set!)"
                    else
                        echo -e "  - ${GREEN}✓ Protected SSH Key:${NC} User ${CYAN}${username}${NC} -> $(basename "$key_file")"
                    fi
                fi
            done < <(find "$ssh_dir" -maxdepth 2 -type f ! -name "*.pub" ! -name "known_hosts*" ! -name "authorized_keys*" ! -name "config" 2>/dev/null)
        fi
    done < /etc/passwd

    if [[ "$total_keys_found" -eq 0 ]]; then
        log_pass "No SSH private keys found on the system."
    elif [[ "$unencrypted_keys_found" -eq 0 ]]; then
        log_pass "All discovered SSH private keys (${total_keys_found}) are protected with passphrases."
    fi
}
check_ssh_keys_passphrase

# 3. Application CVE Checks
section "3/20" "Checking Installed Applications for Security Vulnerabilities (CVEs)..."
APPS_TO_CHECK=("code" "google-chrome-stable" "firefox" "docker-cli" "kubernetes1.34-client" "clamav")
if [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
    for app in "${APPS_TO_CHECK[@]}"; do
        if rpm -q "$app" &> /dev/null; then
            echo -n "Checking $app... "
            SECURITY_INFO=$(dnf updateinfo list security --installed "$app" 2>/dev/null | grep "$app")
            if [[ -n "$SECURITY_INFO" ]]; then
                log_crit "VULNERABILITY FOUND IN $app:\n$SECURITY_INFO"
            else
                log_pass "Application $app has no known unpatched security alerts in repo."
            fi
        fi
    done
elif [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
    for app in "${APPS_TO_CHECK[@]}"; do
        if dpkg-query -W -f='${Status}' "$app" 2>/dev/null | grep -q "ok installed"; then
            echo -n "Checking $app... "
            SECURITY_INFO=$(apt list --upgradable 2>/dev/null | grep -i "$app")
            if [[ -n "$SECURITY_INFO" ]]; then
                log_warn "Update / security patch available for $app:\n$SECURITY_INFO"
            else
                log_pass "Application $app is up to date."
            fi
        fi
    done
else
    echo "No DNF or APT package manager available for CVE checks."
fi

# 4. SSH Configuration Audit
section "4/20" "Auditing SSH Daemon Configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONFIG" ]] || [[ -d "/etc/ssh/sshd_config.d" ]]; then
    ROOT_LOGIN=$(run_sudo sshd -T 2>/dev/null | grep -i "^permitrootlogin" || echo "permitrootlogin unknown")
    PASS_AUTH=$(run_sudo sshd -T 2>/dev/null | grep -i "^passwordauthentication" || echo "passwordauthentication unknown")
    EMPTY_PASS=$(run_sudo sshd -T 2>/dev/null | grep -i "^permitemptypasswords" || echo "permitemptypasswords unknown")

    echo "Current SSH Settings:"
    echo "  - $ROOT_LOGIN"
    echo "  - $PASS_AUTH"
    echo "  - $EMPTY_PASS"

    if [[ "$ROOT_LOGIN" =~ "yes" ]]; then
        log_warn "Recommendation: Set 'PermitRootLogin no' or 'prohibit-password' in /etc/ssh/sshd_config"
    else
        log_pass "Root SSH login is restricted."
    fi
    if [[ "$PASS_AUTH" =~ "yes" ]]; then
        log_warn "Recommendation: Consider disabling PasswordAuthentication in favor of SSH Keys"
    else
        log_pass "SSH password authentication is disabled."
    fi
else
    echo "SSHD config not found or sshd not installed."
fi

# 5. Network & Open Ports Audit
section "5/20" "Checking Active Listening Ports & Firewall Status..."
if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]]; then
    if systemctl is-active --quiet firewalld; then
        log_pass "firewalld is active."
    elif systemctl is-active --quiet ufw; then
        log_pass "ufw is active."
    else
        log_warn "Firewall service (firewalld/ufw) is inactive!"
    fi
fi

if [[ "${TOOL_FOUND['ss']}" -eq 1 ]]; then
    echo -e "${YELLOW}--- Listening Public TCP/UDP Ports ---${NC}"
    LISTEN_PORTS=$(ss -tulpn 2>/dev/null | grep -E '0\.0\.0\.0|::|\*')
    if [[ -n "$LISTEN_PORTS" ]]; then
        echo "$LISTEN_PORTS"
    else
        log_pass "No open public listening ports found."
    fi

    MDNS_LLMNR=$(ss -tuln 2>/dev/null | grep -E '5353|5355')
    if [[ -n "$MDNS_LLMNR" ]]; then
        log_warn "Active mDNS/LLMNR services found (5353/5355). Disable systemd-resolved LLMNR/MulticastDNS if not needed."
    fi
fi

# 6. Antivirus & Rootkit Audit (ClamAV / rkhunter)
section "6/20" "Antivirus & Rootkit Audit (ClamAV / rkhunter)..."
if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]] && systemctl is-active --quiet clamav-freshclam; then
    log_pass "clamav-freshclam service is active."
fi

if [[ "${TOOL_FOUND['clamscan']}" -eq 1 ]]; then
    echo "Scanning active system binary paths for malware..."
    CLAM_OUT=$(run_sudo "${TOOL_BIN['clamscan']}" -r --exclude-dir="^/sys" --exclude-dir="^/dev" --exclude-dir="^/proc" /bin /sbin /usr/bin /usr/sbin 2>/dev/null | grep -E "Infected|Summary|FOUND")
    if [[ "$CLAM_OUT" =~ "FOUND" || "$CLAM_OUT" =~ "Infected files: "[1-9] ]]; then
        log_crit "ClamAV malware threats found!\n$CLAM_OUT"
    else
        log_pass "ClamAV scan completed: No threats found."
    fi
else
    echo -e "${YELLOW}ClamAV (clamscan) not installed.${NC}"
fi

if [[ "${TOOL_FOUND['rkhunter']}" -eq 1 ]]; then
    echo "Running Rootkit Detection (rkhunter)..."
    run_sudo "${TOOL_BIN['rkhunter']}" --check --sk --quiet 2>/dev/null
    log_pass "rkhunter check completed."
else
    echo -e "${YELLOW}rkhunter not installed.${NC}"
fi

# 7. Filesystem, Container & Lynis Security Scanning
section "7/20" "Filesystem, Container & Lynis Security Audit..."
if [[ "${TOOL_FOUND['trivy']}" -eq 1 ]]; then
    "${TOOL_BIN['trivy']}" fs --severity HIGH,CRITICAL --format table "$HOME/Labolatory" 2>/dev/null
else
    echo -e "${YELLOW}Trivy not installed. (Install trivy for vulnerability scanning of code/containers).${NC}"
fi

if [[ "${TOOL_FOUND['lynis']}" -eq 1 ]]; then
    echo -e "\n${CYAN}Running Lynis System Audit Summary...${NC}"
    run_sudo "${TOOL_BIN['lynis']}" audit system --quick --no-colors 2>/dev/null | grep -E "Hardening index|Warnings|Suggestions"
else
    echo -e "${YELLOW}Lynis security auditor not installed. (Install lynis for deep security scoring).${NC}"
fi

# 8. System Log & Auth Audit
section "8/20" "Analyzing System Logs & Parsing Suspicious Security Entries..."

parse_security_logs() {
    local pattern_regex="Failed password|Invalid user|authentication failure|NOT in sudoers|maximum authentication attempts|segfault|Out of memory: Kill process|denied"

    echo -e "${YELLOW}--- Scanning System Logs for Security Anomaly Indicators ---${NC}"

    if [[ "${TOOL_FOUND['journalctl']}" -eq 1 ]]; then
        echo -e "${CYAN}Scanning systemd journal (last 24h)...${NC}"
        local journal_matches
        journal_matches=$("${TOOL_BIN['journalctl']}" --since "24 hours ago" -p warning..emerg --grep="$pattern_regex" --no-pager -n 15 2>/dev/null)
        
        if [[ -n "$journal_matches" ]]; then
            log_warn "Suspicious entries found in systemd journal:\n$journal_matches"
        else
            log_pass "No high-severity security anomalies found in systemd journal (last 24h)."
        fi

        local failed_count
        failed_count=$("${TOOL_BIN['journalctl']}" --since "24 hours ago" --grep="failed|invalid" --no-pager 2>/dev/null | wc -l)
        echo -e "Failed authentication events (24h): ${CYAN}${failed_count}${NC}"
        if [[ "$failed_count" -gt 20 ]]; then
            log_warn "High number of failed auth attempts detected (${failed_count})! Possible brute-force attack."
        fi
    fi

    local target_logs=()
    [[ -f "/var/log/auth.log" ]] && target_logs+=("/var/log/auth.log")
    [[ -f "/var/log/secure" ]] && target_logs+=("/var/log/secure")
    [[ -f "/var/log/syslog" ]] && target_logs+=("/var/log/syslog")
    [[ -f "/var/log/messages" ]] && target_logs+=("/var/log/messages")

    if [[ ${#target_logs[@]} -gt 0 ]]; then
        echo -e "\n${CYAN}Scanning security log files (${target_logs[*]})...${NC}"
        for logfile in "${target_logs[@]}"; do
            local file_matches
            file_matches=$(run_sudo grep -Ei "$pattern_regex" "$logfile" 2>/dev/null | tail -n 10)
            if [[ -n "$file_matches" ]]; then
                log_warn "Recent suspicious entries in ${logfile}:\n$file_matches"
            else
                log_pass "No critical security entries found in ${logfile}."
            fi
        done
    fi

    echo -e "\n${YELLOW}--- Recent Sudo Usage & Privilege Escalation ---${NC}"
    if [[ -f "/var/log/secure" ]]; then
        run_sudo grep "sudo" /var/log/secure 2>/dev/null | tail -n 10 || echo "No sudo records found in /var/log/secure."
    elif [[ -f "/var/log/auth.log" ]]; then
        run_sudo grep "sudo" /var/log/auth.log 2>/dev/null | tail -n 10 || echo "No sudo records found in /var/log/auth.log."
    elif [[ "${TOOL_FOUND['journalctl']}" -eq 1 ]]; then
        run_sudo "${TOOL_BIN['journalctl']}" _COMM=sudo -n 10 --no-pager 2>/dev/null || echo "No sudo records found in journal."
    fi
}

parse_security_logs

# 9. System Optimization & Resource Audit
section "9/20" "Checking System Resources & Optimization Opportunities..."
echo -e "${YELLOW}--- Disk Space Usage & Free Space Check ---${NC}"
df -h -x tmpfs -x devtmpfs -x squashfs

HIGH_DISK_ALERT=""
while read -r line; do
    fs=$(echo "$line" | awk '{print $1}')
    size=$(echo "$line" | awk '{print $2}')
    used=$(echo "$line" | awk '{print $3}')
    avail=$(echo "$line" | awk '{print $4}')
    use_pct_str=$(echo "$line" | awk '{print $5}')
    mount=$(echo "$line" | awk '{print $6}')

    use_pct=${use_pct_str%\%}

    if [[ "$use_pct" =~ ^[0-9]+$ ]] && [[ "$use_pct" -ge 80 ]]; then
        HIGH_DISK_ALERT+="Partition ${mount} (${fs}) is ${use_pct}% full! (Free: ${avail} / ${size}, Used: ${used})\n"
    fi
done < <(df -h -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk 'NR>1')

if [[ -n "$HIGH_DISK_ALERT" ]]; then
    log_warn "High disk usage detected (>= 80% occupied):\n$HIGH_DISK_ALERT"
else
    log_pass "All disk partitions have sufficient free space (< 80% used)."
fi

echo -e "\n${YELLOW}--- Systemd Failed Services ---${NC}"
if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]]; then
    FAILED_SERVICES=$(systemctl --failed --no-legend 2>/dev/null)
    if [[ -n "$FAILED_SERVICES" ]]; then
        log_warn "Found failed systemd services:\n$FAILED_SERVICES"
    else
        log_pass "No failed systemd services."
    fi
fi

echo -e "\n${YELLOW}--- Systemd Journal Disk Usage ---${NC}"
if [[ "${TOOL_FOUND['journalctl']}" -eq 1 ]]; then
    "${TOOL_BIN['journalctl']}" --disk-usage
    echo "Tip: Run 'sudo journalctl --vacuum-time=2weeks' or '--vacuum-size=500M' if journal size is too large."
fi

echo -e "\n${YELLOW}--- Package Cache & Unused Packages ---${NC}"
if [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
    UNNEEDED=$(dnf autoremove --dry-run 2>/dev/null | grep -E "Removing:" | head -n 5)
    if [[ -n "$UNNEEDED" ]]; then
        log_warn "Orphaned/unused packages detected. Consider running 'sudo dnf autoremove'."
    else
        log_pass "Package database clean."
    fi
elif [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
    UNNEEDED=$(apt-get autoremove --dry-run 2>/dev/null | grep -E "^Remv " | head -n 5)
    if [[ -n "$UNNEEDED" ]]; then
        log_warn "Orphaned/unused packages detected. Consider running 'sudo apt autoremove'."
    else
        log_pass "Package database clean."
    fi
fi

# 10. Privilege & Account Audit
section "10/20" "Privilege & Security Misconfiguration Audit..."
echo -e "${YELLOW}--- Checking for Non-Root Accounts with UID 0 ---${NC}"
UID_ZERO=$(awk -F: '($3 == "0" && $1 != "root") { print $1 }' /etc/passwd)
if [[ -n "$UID_ZERO" ]]; then
    log_crit "Non-root users with UID 0 found: $UID_ZERO"
else
    log_pass "Only root user has UID 0."
fi

echo -e "\n${YELLOW}--- Accounts with Console / Interactive Shell Access ---${NC}"
check_console_users() {
    while IFS=: read -r username password uid gid gecos home shell; do
        if [[ "$shell" =~ (nologin|false|sync|halt|shutdown|null)$ ]]; then
            continue
        fi

        local is_sudo="No"
        if [[ "$uid" -eq 0 ]]; then
            is_sudo="${RED}YES (ROOT)${NC}"
        elif id -nG "$username" 2>/dev/null | grep -E -q '\b(sudo|wheel|admin)\b'; then
            is_sudo="${YELLOW}YES (Sudo Group)${NC}"
        fi

        local pass_status="Unknown"
        if command -v passwd &>/dev/null; then
            local p_info
            p_info=$(run_sudo passwd -S "$username" 2>/dev/null | awk '{print $2}')
            case "$p_info" in
                L|LK) pass_status="${YELLOW}Locked${NC}" ;;
                P|PS) pass_status="${GREEN}Password Set${NC}" ;;
                NP)   pass_status="${RED}NO PASSWORD!${NC}" ;;
                *)    pass_status="Active" ;;
            esac
        fi

        echo -e "  - ${CYAN}${username}${NC} (UID: ${uid}, Shell: ${shell})"
        echo -e "    Home: ${home} | Sudo Privileges: ${is_sudo} | Password Status: ${pass_status}"

        if [[ "$p_info" == "NP" ]]; then
            log_crit "User '${username}' has NO password set!"
        fi

    done < /etc/passwd
}
check_console_users

# 11. Repository Kernel & Security Package Updates Audit
section "11/20" "Auditing Repository Kernel Updates & Recommended Security Packages..."
RUNNING_KERNEL=$(uname -r)
echo -e "Current running kernel: ${CYAN}${RUNNING_KERNEL}${NC}"

if [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
    echo -e "Detected package manager: ${BLUE}dnf${NC} (RedHat/Fedora family)"

    echo -e "\n${YELLOW}--- Checking Kernel Updates in Repository ---${NC}"
    KERNEL_UPDATES=$(dnf check-update kernel kernel-core kernel-modules 2>/dev/null | grep -E '^kernel(-core|-modules)?\.')
    if [[ -n "$KERNEL_UPDATES" ]]; then
        log_warn "New kernel update available in repository:\n$KERNEL_UPDATES"
    else
        log_pass "Kernel is up to date in repository."
    fi

    LATEST_INSTALLED_KERNEL=$(rpm -q kernel --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | tail -n 1)
    if [[ -z "$LATEST_INSTALLED_KERNEL" ]]; then
        LATEST_INSTALLED_KERNEL=$(rpm -q kernel-core --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | tail -n 1)
    fi
    if [[ -n "$LATEST_INSTALLED_KERNEL" && "$RUNNING_KERNEL" != "$LATEST_INSTALLED_KERNEL"* ]]; then
        log_warn "System reboot required! Running kernel ($RUNNING_KERNEL) differs from installed ($LATEST_INSTALLED_KERNEL)."
    fi

    echo -e "\n${YELLOW}--- Checking Recommended Security Packages ---${NC}"
    RECOMMENDED_PKGS=("fail2ban" "firewalld" "audit" "clamav" "rkhunter" "trivy" "policycoreutils" "crypto-policies")
    for pkg in "${RECOMMENDED_PKGS[@]}"; do
        if rpm -q "$pkg" &> /dev/null; then
            PKG_UPDATE=$(dnf check-update "$pkg" 2>/dev/null | grep -E "^${pkg}\.")
            if [[ -n "$PKG_UPDATE" ]]; then
                echo -e "  - $pkg: ${GREEN}Installed${NC} | ${RED}Update Available in Repo${NC}"
            else
                echo -e "  - $pkg: ${GREEN}Installed (Up to date)${NC}"
            fi
        else
            echo -e "  - $pkg: ${YELLOW}Not installed${NC} (Recommended for security)"
        fi
    done

elif [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
    echo -e "Detected package manager: ${BLUE}apt${NC} (Debian family)"

    echo -e "\n${YELLOW}--- Checking Kernel Updates in Repository ---${NC}"
    KERNEL_UPDATES=$(apt list --upgradable 2>/dev/null | grep -E '^linux-(image|headers|generic|amd64|arm64)')
    if [[ -n "$KERNEL_UPDATES" ]]; then
        log_warn "New kernel update available in repository:\n$KERNEL_UPDATES"
    else
        log_pass "Kernel is up to date in repository."
    fi

    if [[ -f "/var/run/reboot-required" ]]; then
        log_warn "System reboot required! (/var/run/reboot-required exists)"
        if [[ -f "/var/run/reboot-required.pkgs" ]]; then
            echo "Packages requiring reboot:"
            cat /var/run/reboot-required.pkgs | sed 's/^/  - /'
        fi
    fi

    echo -e "\n${YELLOW}--- Checking Recommended Security Packages ---${NC}"
    RECOMMENDED_PKGS=("fail2ban" "ufw" "auditd" "apparmor" "unattended-upgrades" "clamav" "rkhunter" "trivy" "needrestart" "debsums" "lynis")
    for pkg in "${RECOMMENDED_PKGS[@]}"; do
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed"; then
            PKG_UPDATE=$(apt list --upgradable 2>/dev/null | grep -E "^${pkg}/")
            if [[ -n "$PKG_UPDATE" ]]; then
                echo -e "  - $pkg: ${GREEN}Installed${NC} | ${RED}Update Available in Repo${NC}"
            else
                echo -e "  - $pkg: ${GREEN}Installed (Up to date)${NC}"
            fi
        else
            echo -e "  - $pkg: ${YELLOW}Not installed${NC} (Recommended for security)"
        fi
    done

    if [[ "${TOOL_FOUND['needrestart']}" -eq 1 ]]; then
        echo -e "\n${CYAN}Needrestart Check (Services needing restart):${NC}"
        run_sudo "${TOOL_BIN['needrestart']}" -b 2>/dev/null | grep 'NEEDRESTART-SVC' || echo -e "${GREEN}✓ No background services require restart.${NC}"
    fi
else
    echo -e "${YELLOW}Unsupported package manager. Skipping repository kernel & package audit.${NC}"
fi

# 12. Suspicious Process & Threat Detection Audit
section "12/20" "Auditing Running Processes for Suspicious Activity & Malware Indicators..."

audit_suspicious_processes() {
    local threats_found=0

    echo -e "${YELLOW}--- 1. Checking for Processes Running Deleted Executables (Process Hiding) ---${NC}"
    local deleted_procs=""
    for exe in /proc/[0-9]*/exe; do
        local target
        target=$(readlink "$exe" 2>/dev/null)
        if [[ "$target" =~ \(deleted\)$ ]]; then
            local pid
            pid=$(echo "$exe" | cut -d/ -f3)
            local user
            user=$(ps -p "$pid" -o user= 2>/dev/null)
            local cmd
            cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
            deleted_procs+="PID ${pid} (User: ${user}) -> ${target} [Cmd: ${cmd}]\n"
            ((threats_found++))
        fi
    done
    if [[ -n "$deleted_procs" ]]; then
        log_crit "Processes executing deleted binary files detected!\n$deleted_procs"
    else
        log_pass "No processes running deleted binaries found."
    fi

    echo -e "\n${YELLOW}--- 2. Checking for Processes Executing from Temporary Directories (/tmp, /dev/shm) ---${NC}"
    local temp_procs=""
    for exe in /proc/[0-9]*/exe; do
        local target
        target=$(readlink "$exe" 2>/dev/null)
        if [[ "$target" =~ ^/tmp/|^/var/tmp/|^/dev/shm/ ]]; then
            local pid
            pid=$(echo "$exe" | cut -d/ -f3)
            local user
            user=$(ps -p "$pid" -o user= 2>/dev/null)
            local cmd
            cmd=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
            temp_procs+="PID ${pid} (User: ${user}) -> ${target} [Cmd: ${cmd}]\n"
            ((threats_found++))
        fi
    done
    if [[ -n "$temp_procs" ]]; then
        log_warn "Processes running from temporary/volatile directories found:\n$temp_procs"
    else
        log_pass "No processes executing from /tmp, /var/tmp, or /dev/shm."
    fi

    echo -e "\n${YELLOW}--- 3. Checking for Known Miner & Suspicious Tool Signatures ---${NC}"
    local miner_pattern="xmrig|minerd|cgminer|cpuminer|kworkerds|stratum|masscan|zmap|kinsing|sysupdate"
    local suspicious_procs
    suspicious_procs=$(ps aux 2>/dev/null | grep -Ei "$miner_pattern" | grep -vE "grep|system-audit.sh")
    if [[ -n "$suspicious_procs" ]]; then
        log_crit "Known suspicious miner or scanning tools detected:\n$suspicious_procs"
        ((threats_found++))
    else
        log_pass "No known miner or scanning tool signatures detected."
    fi

    echo -e "\n${YELLOW}--- 4. Checking for Potential Reverse Shell Patterns ---${NC}"
    local revshell_pattern="nc -e|nc\.openbsd -e|bash -i|sh -i|python.*socket|perl.*socket|php -r.*socket"
    local revshell_procs
    revshell_procs=$(ps aux 2>/dev/null | grep -Ei "$revshell_pattern" | grep -vE "grep|system-audit.sh")
    if [[ -n "$revshell_procs" ]]; then
        log_crit "Potential reverse shell processes detected:\n$revshell_procs"
        ((threats_found++))
    else
        log_pass "No reverse shell command patterns detected."
    fi

    echo -e "\n${YELLOW}--- 5. Top CPU & RAM Consuming Processes ---${NC}"
    echo -e "${CYAN}Highest CPU Processes (>70% CPU):${NC}"
    local high_cpu
    high_cpu=$(ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | awk 'NR>1 && $3 > 70.0 {print $0}')
    if [[ -n "$high_cpu" ]]; then
        log_warn "Processes consuming high CPU (>70%):\n$high_cpu"
    else
        log_pass "No processes consuming excessive CPU (>70%)."
    fi

    echo -e "${CYAN}Highest RAM Consuming Processes (Top 5):${NC}"
    ps -eo pid,user,%cpu,%mem,comm --sort=-%mem | head -n 6
}

audit_suspicious_processes

# 13. Shell Configuration & Security Alias Audit
section "13/20" "Auditing Shell Config Files (.bashrc, .zshrc) & Security Aliases (All Users)..."

audit_shell_configs_and_aliases() {
    local target_rc_files=(".bashrc" ".zshrc" ".profile" ".bash_profile" ".zprofile" ".bash_aliases" ".zsh_aliases")

    while IFS=: read -r username password uid gid gecos home shell; do
        [[ -d "$home" ]] || continue

        local user_rc_found=()
        for rc in "${target_rc_files[@]}"; do
            local rc_path="$home/$rc"
            [[ -f "$rc_path" ]] && user_rc_found+=("$rc_path")
        done

        [[ ${#user_rc_found[@]} -gt 0 ]] || continue

        echo -e "\n${CYAN}--- User '${username}' Shell Configuration Audit (${user_rc_found[*]}) ---${NC}"

        local suspicious_findings=""
        local hijacking_patterns="alias (sudo|su|ssh|cd|ls|cat|curl|wget)="
        local dangerous_exec_patterns="curl.*\|.*(bash|sh)|wget.*\|.*(bash|sh)|eval \$\(|base64 -d"

        for rc_path in "${user_rc_found[@]}"; do
            local found_suspicious
            found_suspicious=$(grep -Ei "$hijacking_patterns" "$rc_path" 2>/dev/null | grep -vE "alias ls='ls --color|alias ll=|alias la=")
            if [[ -n "$found_suspicious" ]]; then
                suspicious_findings+="Suspicious alias in ${rc_path}:\n$found_suspicious\n"
            fi

            local found_exec
            found_exec=$(grep -Ei "$dangerous_exec_patterns" "$rc_path" 2>/dev/null)
            if [[ -n "$found_exec" ]]; then
                suspicious_findings+="Dangerous execution pattern in ${rc_path}:\n$found_exec\n"
            fi
        done

        if [[ -n "$suspicious_findings" ]]; then
            log_warn "Suspicious aliases or remote execution patterns detected for ${username}:\n$suspicious_findings"
        else
            log_pass "No suspicious alias hijacking or remote code execution patterns found for ${username}."
        fi

        local has_rm_safe=0
        local has_cp_safe=0
        local has_mv_safe=0
        local has_preserve_root=0

        for rc_path in "${user_rc_found[@]}"; do
            grep -Eq "alias rm=['\"].*rm.*-i" "$rc_path" 2>/dev/null && has_rm_safe=1
            grep -Eq "alias cp=['\"].*cp.*-i" "$rc_path" 2>/dev/null && has_cp_safe=1
            grep -Eq "alias mv=['\"].*mv.*-i" "$rc_path" 2>/dev/null && has_mv_safe=1
            grep -Eq "preserve-root" "$rc_path" 2>/dev/null && has_preserve_root=1
        done

        echo -e "${YELLOW}Safety Aliases & Protection Recommendations for ${username}:${NC}"
        if [[ "$has_rm_safe" -eq 1 ]]; then
            echo -e "  - 'rm' safety alias: ${GREEN}Enabled${NC}"
        else
            log_warn "Missing 'rm' safety alias for ${username} -> Add alias rm='rm -i' to ${user_rc_found[0]}"
        fi

        if [[ "$has_cp_safe" -eq 1 ]]; then
            echo -e "  - 'cp' safety alias: ${GREEN}Enabled${NC}"
        else
            log_warn "Missing 'cp' safety alias for ${username} -> Add alias cp='cp -i' to ${user_rc_found[0]}"
        fi

        if [[ "$has_mv_safe" -eq 1 ]]; then
            echo -e "  - 'mv' safety alias: ${GREEN}Enabled${NC}"
        else
            log_warn "Missing 'mv' safety alias for ${username} -> Add alias mv='mv -i' to ${user_rc_found[0]}"
        fi

    done < /etc/passwd
}

audit_shell_configs_and_aliases

# 14. SUID / SGID Executable File Audit
section "14/20" "Auditing SUID / SGID Files for Privilege Escalation Risk..."
audit_suid_files() {
    echo -e "${YELLOW}--- Scanning for SUID/SGID Binaries in Volatile / Non-Standard Paths ---${NC}"
    local suspicious_suid
    suspicious_suid=$(find /tmp /var/tmp /dev/shm /home -perm -4000 -o -perm -2000 2>/dev/null)
    if [[ -n "$suspicious_suid" ]]; then
        log_crit "SUID/SGID files found in non-standard/writable paths:\n$suspicious_suid"
    else
        log_pass "No SUID/SGID files found in volatile/user paths (/tmp, /dev/shm, /home)."
    fi

    echo -e "\n${YELLOW}--- System SUID Executables Count ---${NC}"
    local suid_count
    suid_count=$(find /usr/bin /usr/sbin /bin /sbin -perm -4000 2>/dev/null | wc -l)
    echo -e "Total SUID binaries in system paths: ${CYAN}${suid_count}${NC}"
}
audit_suid_files

# 15. Persistence Audit (Cron Jobs & Systemd Timers)
section "15/20" "Auditing System Persistence (Cron Jobs & Systemd Timers)..."
audit_persistence() {
    echo -e "${YELLOW}--- User Cron Jobs Audit ---${NC}"
    while IFS=: read -r username password uid gid gecos home shell; do
        local crontab_out
        crontab_out=$(crontab -u "$username" -l 2>/dev/null | grep -v '^#')
        if [[ -n "$crontab_out" ]]; then
            echo -e "${CYAN}Crontab for user '${username}':${NC}"
            echo "$crontab_out"
        fi
    done < /etc/passwd

    echo -e "\n${YELLOW}--- System Cron Files (/etc/crontab, /etc/cron.*) ---${NC}"
    if [[ -f "/etc/crontab" ]]; then
        grep -v '^#' /etc/crontab | grep -v '^\s*$' || echo "No custom jobs in /etc/crontab."
    fi

    echo -e "\n${YELLOW}--- Active Systemd Timers ---${NC}"
    if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]]; then
        systemctl list-timers --no-pager --no-legend 2>/dev/null | head -n 10
    fi
    log_pass "Persistence mechanisms audited."
}
audit_persistence

# 16. SSH authorized_keys Audit (All Users)
section "16/20" "Auditing SSH Authorized Keys Across All Users..."
audit_authorized_keys() {
    local keys_count=0
    while IFS=: read -r username password uid gid gecos home shell; do
        local auth_keys="$home/.ssh/authorized_keys"
        if [[ -f "$auth_keys" ]]; then
            local key_num
            key_num=$(grep -v '^#' "$auth_keys" | grep -v '^\s*$' | wc -l)
            if [[ "$key_num" -gt 0 ]]; then
                ((keys_count += key_num))
                echo -e "  - User ${CYAN}${username}${NC}: ${key_num} authorized key(s) in ${auth_keys}"
                if [[ "$username" == "root" ]]; then
                    log_warn "Root account has SSH authorized keys configured!"
                fi
            fi
        fi
    done < /etc/passwd

    if [[ "$keys_count" -eq 0 ]]; then
        log_pass "No authorized_keys files found."
    else
        log_pass "Discovered ${keys_count} SSH authorized key(s) across user accounts."
    fi
}
audit_authorized_keys

# 17. Docker & Kubernetes Container Security Audit
section "17/20" "Auditing Docker & Container Security Settings..."
audit_container_security() {
    if [[ -S "/var/run/docker.sock" ]]; then
        local sock_perm
        sock_perm=$(ls -l /var/run/docker.sock 2>/dev/null)
        echo -e "Docker socket status: ${CYAN}${sock_perm}${NC}"
    else
        echo "Docker socket (/var/run/docker.sock) not active."
    fi

    if [[ "${TOOL_FOUND['docker']}" -eq 1 ]] && docker ps &>/dev/null; then
        echo -e "\n${YELLOW}--- Running Docker Containers ---${NC}"
        local priv_containers
        priv_containers=$(docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}' 2>/dev/null | grep 'Privileged=true')
        if [[ -n "$priv_containers" ]]; then
            log_warn "Privileged containers detected:\n$priv_containers"
        else
            log_pass "No privileged Docker containers running."
        fi
    elif [[ "${TOOL_FOUND['podman']}" -eq 1 ]] && podman ps &>/dev/null; then
        echo -e "\n${YELLOW}--- Running Podman Containers ---${NC}"
        log_pass "Podman container daemon verified."
    fi
}
audit_container_security

# 18. Kernel Security Hardening (Sysctl Parameters Audit)
section "18/20" "Auditing Kernel Security Hardening (sysctl Parameters)..."
audit_kernel_hardening() {
    local sysctl_cmd="${TOOL_BIN['sysctl']}"
    if [[ -z "$sysctl_cmd" ]]; then
        sysctl_cmd="/sbin/sysctl"
    fi

    check_sysctl() {
        local param="$1"
        local expected="$2"
        local val
        val=$("$sysctl_cmd" -n "$param" 2>/dev/null)
        if [[ "$val" == "$expected" ]]; then
            log_pass "${param}: ${val} (Secure)"
        else
            log_warn "${param}: ${val} (Recommended: ${expected})"
        fi
    }

    check_sysctl "net.ipv4.ip_forward" "0"
    check_sysctl "kernel.kptr_restrict" "1"
    check_sysctl "kernel.dmesg_restrict" "1"
    check_sysctl "fs.protected_symlinks" "1"
    check_sysctl "fs.protected_hardlinks" "1"
}
audit_kernel_hardening

# 19. Network DNS & /etc/hosts Integrity Audit
section "19/20" "Auditing DNS Settings & /etc/hosts Integrity..."
audit_dns_hosts() {
    echo -e "${YELLOW}--- DNS Resolvers (/etc/resolv.conf) ---${NC}"
    if [[ -f "/etc/resolv.conf" ]]; then
        grep '^nameserver' /etc/resolv.conf | sed 's/^/  - /'
    fi

    echo -e "\n${YELLOW}--- /etc/hosts Non-Standard Entries Check ---${NC}"
    if [[ -f "/etc/hosts" ]]; then
        local custom_hosts
        custom_hosts=$(grep -vE '^\s*#|localhost|127\.0\.0\.1|::1|fe00::0|ff02::' /etc/hosts | grep -v '^\s*$')
        if [[ -n "$custom_hosts" ]]; then
            echo -e "${CYAN}Custom /etc/hosts entries:${NC}"
            echo "$custom_hosts"
        else
            log_pass "No unusual custom entries in /etc/hosts."
        fi
    fi
}
audit_dns_hosts

# 20. Wi-Fi Access Points, Security & Local Network Hosts Audit
section "20/20" "Auditing Wi-Fi Networks, Connected AP Security & Local Network Hosts..."

audit_wifi_and_network_hosts() {
    echo -e "${YELLOW}--- 1. Primary Network Interface & Subnet Info ---${NC}"
    local default_route
    default_route=$(ip route show default 2>/dev/null | head -n 1)
    local gw_ip=""
    if [[ -n "$default_route" ]]; then
        gw_ip=$(echo "$default_route" | awk '{print $3}')
        local iface
        iface=$(echo "$default_route" | awk '{print $5}')
        local local_ip
        local_ip=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet / {print $2}')
        echo -e "Primary Interface: ${CYAN}${iface}${NC} | Local IP: ${CYAN}${local_ip}${NC} | Gateway: ${CYAN}${gw_ip}${NC}"
    else
        echo "No active default network gateway found."
    fi

    echo -e "\n${YELLOW}--- 2. Wi-Fi Networks & Connected Access Point Security ---${NC}"
    if [[ "${TOOL_FOUND['nmcli']}" -eq 1 ]]; then
        local connected_wifi
        connected_wifi=$("${TOOL_BIN['nmcli']}" -f IN-USE,SSID,BSSID,RATE,SIGNAL,SECURITY dev wifi 2>/dev/null | grep '^\*')
        if [[ -n "$connected_wifi" ]]; then
            echo -e "${CYAN}Currently Connected Wi-Fi Network:${NC}"
            echo "$connected_wifi"

            local wifi_sec
            wifi_sec=$(echo "$connected_wifi" | awk '{print $NF}')
            echo -n "Connected Security Protocol Assessment: "
            if [[ "$wifi_sec" =~ OPEN|NONE ]]; then
                log_crit "Connected to an UNENCRYPTED (OPEN) Wi-Fi network! Traffic can be intercepted."
            elif [[ "$wifi_sec" =~ WEP|WPA1 ]]; then
                log_warn "Connected to obsolete/vulnerable ${wifi_sec} network."
            elif [[ "$wifi_sec" =~ WPA3 ]]; then
                log_pass "WPA3 Security (Strongest modern encryption standard)."
            elif [[ "$wifi_sec" =~ WPA2 ]]; then
                log_pass "WPA2 Security (Secure standard)."
            else
                echo -e "${CYAN}${wifi_sec}${NC}"
            fi
        else
            echo "Not connected to any Wi-Fi access point."
        fi

        echo -e "\n${CYAN}Nearby Wi-Fi Access Points in Range:${NC}"
        local wifi_list
        wifi_list=$("${TOOL_BIN['nmcli']}" -f SSID,BSSID,SIGNAL,SECURITY dev wifi 2>/dev/null | head -n 12)
        if [[ -n "$wifi_list" ]]; then
            echo "$wifi_list"
            local open_nearby
            open_nearby=$(echo "$wifi_list" | grep -Ei 'OPEN|NONE')
            if [[ -n "$open_nearby" ]]; then
                log_warn "Open/unencrypted Wi-Fi networks detected nearby!"
            fi
        else
            echo "No nearby Wi-Fi networks found or Wi-Fi adapter disabled."
        fi
    else
        echo -e "${YELLOW}nmcli not available for Wi-Fi scanning.${NC}"
    fi

    echo -e "\n${YELLOW}--- 3. Local Subnet Active Hosts Discovery ---${NC}"
    if [[ -n "$gw_ip" ]]; then
        local subnet_prefix
        subnet_prefix=$(echo "$gw_ip" | awk -F. '{print $1"."$2"."$3}')
        local subnet_cidr="${subnet_prefix}.0/24"
        
        echo -e "Scanning local subnet (${CYAN}${subnet_cidr}${NC})..."
        if [[ "${TOOL_FOUND['nmap']}" -eq 1 ]]; then
            local nmap_hosts
            nmap_hosts=$("${TOOL_BIN['nmap']}" -sn --host-timeout 3s "$subnet_cidr" 2>/dev/null | grep -E "Nmap scan report|Host is up")
            if [[ -n "$nmap_hosts" ]]; then
                echo "$nmap_hosts"
                local host_count
                host_count=$(echo "$nmap_hosts" | grep -c "Nmap scan report")
                log_pass "Total active hosts discovered on local subnet: ${host_count}"
            fi
        else
            echo -e "${CYAN}Active neighbors (ARP / IP Cache):${NC}"
            ip neighbor show 2>/dev/null | grep -v 'FAILED' | sed 's/^/  - /'
        fi
    fi
}
audit_wifi_and_network_hosts

# --- Executive Audit Summary Scorecard ---
print_scorecard() {
    echo -e "\n${CYAN}=====================================================${NC}"
    echo -e "${CYAN}===           AUDIT EXECUTIVE SCORECARD           ===${NC}"
    echo -e "${CYAN}=====================================================${NC}"

    local score=100
    if [[ $TOTAL_CHECKS -gt 0 ]]; then
        score=$(( (PASSED_COUNT * 100) / TOTAL_CHECKS ))
    fi

    printf "  %-30s : %d\n" "Total Security Checks" "$TOTAL_CHECKS"
    printf "  %-30s : ${GREEN}%d${NC}\n" "Checks Passed" "$PASSED_COUNT"
    printf "  %-30s : ${YELLOW}%d${NC}\n" "Warnings / Suggestions" "$WARNING_COUNT"
    printf "  %-30s : ${RED}%d${NC}\n" "Critical Vulnerabilities" "$CRITICAL_COUNT"
    echo -e "-----------------------------------------------------"

    # Build visual progress bar
    local bar_width=20
    local filled=$(( (score * bar_width) / 100 ))
    local empty=$(( bar_width - filled ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="#"; done
    for ((i=0; i<empty; i++)); do bar+="-"; done

    if [[ $score -ge 80 ]]; then
        echo -e "  Overall Security Score        : ${GREEN}${score}% [${bar}]${NC}"
    elif [[ $score -ge 50 ]]; then
        echo -e "  Overall Security Score        : ${YELLOW}${score}% [${bar}]${NC}"
    else
        echo -e "  Overall Security Score        : ${RED}${score}% [${bar}]${NC}"
    fi

    echo -e "${CYAN}=====================================================${NC}"
    if [[ "$GENERATE_REPORT" == true ]]; then
        echo -e "${GREEN}✓ Audit Completed! Detailed report saved to:${NC}"
        echo -e "  ${CYAN}${REPORT_FILE}${NC}"
    else
        echo -e "${GREEN}✓ Audit Completed Successfully!${NC}"
        echo -e "  Tip: Use ${CYAN}--report${NC} to export a clean Markdown report."
    fi
    echo -e "${CYAN}=====================================================${NC}"
}

print_scorecard
