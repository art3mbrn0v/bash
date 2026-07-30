#!/bin/bash

# ==============================================================================
# System Security & Optimization Audit Script
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
    exec > >(tee -a "$REPORT_FILE") 2>&1
fi

echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}=== Starting System Security & Optimization Audit ===${NC}"
echo -e "${CYAN}=====================================================${NC}"

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

# Helper function to print section headers
section() {
    echo -e "\n${BLUE}[$1] $2${NC}"
}

# Helper function to update security databases before audit
update_security_databases() {
    echo -e "${YELLOW}--- Updating Security & Audit Tool Databases ---${NC}"

    if command -v apt-get &> /dev/null || command -v apt &> /dev/null; then
        echo -n "Updating APT package index... "
        sudo apt-get update -qq 2>/dev/null && echo -e "${GREEN}✓ Done${NC}" || echo -e "${YELLOW}Skipped/Cached${NC}"
    elif command -v dnf &> /dev/null; then
        echo -n "Refreshing DNF repository metadata... "
        sudo dnf makecache --refresh &>/dev/null && echo -e "${GREEN}✓ Done${NC}" || echo -e "${YELLOW}Skipped/Cached${NC}"
    fi

    if command -v freshclam &> /dev/null; then
        echo -n "Updating ClamAV virus signatures... "
        sudo freshclam 2>/dev/null && echo -e "${GREEN}✓ Done${NC}" || echo -e "${YELLOW}Updated or locked by daemon${NC}"
    fi

    if command -v rkhunter &> /dev/null; then
        echo -n "Updating rkhunter rootkit definitions... "
        sudo rkhunter --update 2>/dev/null && echo -e "${GREEN}✓ Done${NC}" || echo -e "${YELLOW}Completed/Skipped${NC}"
    fi

    if command -v trivy &> /dev/null; then
        echo -n "Updating Trivy vulnerability database... "
        trivy image --download-db-only 2>/dev/null && echo -e "${GREEN}✓ Done${NC}" || echo -e "${YELLOW}Skipped/Up to date${NC}"
    fi
    echo ""
}

update_security_databases

# 1. Shell History Scanning & Cleaning
section "1/19" "Cleaning Shell History for Sensitive Data..."
clean_history() {
    local file="$1"
    if [[ -f "$file" ]]; then
        echo "Processing $file..."
        local temp_file
        temp_file=$(mktemp)
        local pattern_regex
        pattern_regex=$(IFS="|"; echo "${SENSITIVE_PATTERNS[*]}")
        grep -vEia "$pattern_regex" "$file" > "$temp_file"
        mv "$temp_file" "$file"
        chmod 600 "$file"
    fi
}

find "$HOME" -maxdepth 1 \( -name ".zsh_history" -o -name ".bash_history*" \) | while read -r h_file; do
    clean_history "$h_file"
done
echo -e "${GREEN}✓ History cleaned and permissions set to 600.${NC}"

# 2. Certificate & File Permission Checks
section "2/19" "Checking Minikube & SSH Certificate Permissions..."
MINIKUBE_DIR="$HOME/.minikube"
if [[ -d "$MINIKUBE_DIR" ]]; then
    CERT_FILES=$(find "$MINIKUBE_DIR" -name "*.pem" -perm /o+rwx,g+rwx 2>/dev/null)
    if [[ -n "$CERT_FILES" ]]; then
        echo -e "${RED}Found minikube files with insecure permissions:${NC}"
        echo "$CERT_FILES"
        echo "Fixing permissions to 600..."
        find "$MINIKUBE_DIR" -name "*.pem" -exec chmod 600 {} +
        echo -e "${GREEN}✓ Minikube permissions fixed.${NC}"
    else
        echo -e "${GREEN}✓ Minikube certificate permissions are secure.${NC}"
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
                    
                    if ssh-keygen -y -P "" -f "$key_file" &>/dev/null; then
                        ((unencrypted_keys_found++))
                        echo -e "  - ${RED}⚠️ UNPROTECTED SSH KEY:${NC} User ${CYAN}${username}${NC} -> ${key_file} (${RED}No passphrase set!${NC})"
                    else
                        echo -e "  - ${GREEN}✓ Protected SSH Key:${NC} User ${CYAN}${username}${NC} -> $(basename "$key_file")"
                    fi
                fi
            done < <(find "$ssh_dir" -maxdepth 2 -type f ! -name "*.pub" ! -name "known_hosts*" ! -name "authorized_keys*" ! -name "config" 2>/dev/null)
        fi
    done < /etc/passwd

    if [[ "$total_keys_found" -eq 0 ]]; then
        echo -e "${GREEN}✓ No SSH private keys found on the system.${NC}"
    elif [[ "$unencrypted_keys_found" -eq 0 ]]; then
        echo -e "${GREEN}✓ All discovered SSH private keys (${total_keys_found}) are protected with passphrases.${NC}"
    else
        echo -e "${RED}⚠️ Found ${unencrypted_keys_found} SSH private key(s) without a passphrase! Setting a passphrase is recommended for security.${NC}"
    fi
}
check_ssh_keys_passphrase

# 3. Application CVE Checks
section "3/19" "Checking Installed Applications for Security Vulnerabilities (CVEs)..."
APPS_TO_CHECK=("code" "google-chrome-stable" "firefox" "docker-cli" "kubernetes1.34-client" "clamav")
if command -v dnf &> /dev/null; then
    for app in "${APPS_TO_CHECK[@]}"; do
        if rpm -q "$app" &> /dev/null; then
            echo -n "Checking $app... "
            SECURITY_INFO=$(dnf updateinfo list security --installed "$app" 2>/dev/null | grep "$app")
            if [[ -n "$SECURITY_INFO" ]]; then
                echo -e "${RED}VULNERABILITY FOUND!${NC}"
                echo "$SECURITY_INFO"
            else
                echo -e "${GREEN}OK${NC}"
            fi
        fi
    done
else
    echo "DNF package manager not available."
fi

# 4. SSH Configuration Audit
section "4/19" "Auditing SSH Daemon Configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"
if [[ -f "$SSHD_CONFIG" ]] || [[ -d "/etc/ssh/sshd_config.d" ]]; then
    ROOT_LOGIN=$(sudo sshd -T 2>/dev/null | grep -i "^permitrootlogin" || echo "permitrootlogin unknown")
    PASS_AUTH=$(sudo sshd -T 2>/dev/null | grep -i "^passwordauthentication" || echo "passwordauthentication unknown")
    EMPTY_PASS=$(sudo sshd -T 2>/dev/null | grep -i "^permitemptypasswords" || echo "permitemptypasswords unknown")

    echo "Current SSH Settings:"
    echo "  - $ROOT_LOGIN"
    echo "  - $PASS_AUTH"
    echo "  - $EMPTY_PASS"

    if [[ "$ROOT_LOGIN" =~ "yes" ]]; then
        echo -e "${YELLOW}⚠️  Recommendation: Set 'PermitRootLogin no' or 'prohibit-password' in /etc/ssh/sshd_config${NC}"
    fi
    if [[ "$PASS_AUTH" =~ "yes" ]]; then
        echo -e "${YELLOW}⚠️  Recommendation: Consider disabling PasswordAuthentication in favor of SSH Keys${NC}"
    fi
else
    echo "SSHD config not found or sshd not installed."
fi

# 5. Network & Open Ports Audit
section "5/19" "Checking Active Listening Ports & Firewall Status..."
if command -v systemctl &> /dev/null; then
    if systemctl is-active --quiet firewalld; then
        echo -e "${GREEN}✓ firewalld is active.${NC}"
    elif systemctl is-active --quiet ufw; then
        echo -e "${GREEN}✓ ufw is active.${NC}"
    else
        echo -e "${YELLOW}⚠️  Warning: Firewall service (firewalld/ufw) is inactive!${NC}"
    fi
fi

if command -v ss &> /dev/null; then
    echo -e "${YELLOW}--- Listening Public TCP/UDP Ports ---${NC}"
    LISTEN_PORTS=$(ss -tulpn 2>/dev/null | grep -E '0\.0\.0\.0|::|\*')
    if [[ -n "$LISTEN_PORTS" ]]; then
        echo "$LISTEN_PORTS"
    else
        echo "No open public listening ports found."
    fi

    # Check dangerous/unnecessary protocols
    MDNS_LLMNR=$(ss -tuln 2>/dev/null | grep -E '5353|5355')
    if [[ -n "$MDNS_LLMNR" ]]; then
        echo -e "${RED}Warning! Active mDNS/LLMNR services found (5353/5355). Disable systemd-resolved LLMNR/MulticastDNS if not needed.${NC}"
    fi
fi

# 6. Antivirus & Security Daemon Checks (ClamAV & rkhunter)
section "6/19" "Antivirus & Rootkit Audit (ClamAV / rkhunter)..."
if command -v systemctl &> /dev/null && systemctl is-active --quiet clamav-freshclam; then
    echo -e "${GREEN}✓ clamav-freshclam service is active and managing database updates automatically.${NC}"
elif command -v freshclam &> /dev/null; then
    echo "Updating ClamAV database..."
    sudo freshclam 2>/dev/null || echo "Existing DB will be used or lock acquired by background service."
fi

if command -v clamscan &> /dev/null; then
    echo "Scanning active system binary paths for malware..."
    sudo clamscan -r --exclude-dir="^/sys" --exclude-dir="^/dev" --exclude-dir="^/proc" /bin /sbin /usr/bin /usr/sbin 2>/dev/null | grep -E "Infected|Summary|FOUND" || echo -e "${GREEN}✓ ClamAV scan completed: No threats found.${NC}"
else
    echo -e "${YELLOW}ClamAV not installed.${NC}"
fi

if command -v rkhunter &> /dev/null; then
    echo "Running Rootkit Detection (rkhunter)..."
    sudo rkhunter --check --sk --quiet 2>/dev/null
    echo -e "${GREEN}✓ rkhunter check completed.${NC}"
else
    echo -e "${YELLOW}rkhunter not installed.${NC}"
fi

# 7. Filesystem & Container Security Scanning (Trivy)
section "7/19" "Trivy Code & Filesystem Security Scan..."
if command -v trivy &> /dev/null; then
    trivy fs --severity HIGH,CRITICAL --format table "$HOME/Labolatory"
else
    echo -e "${YELLOW}Trivy not installed. (Install trivy for automated vulnerability scanning of code/containers).${NC}"
fi

# 8. System Log & Auth Audit
section "8/19" "Analyzing System Logs & Parsing Suspicious Security Entries..."

parse_security_logs() {
    local pattern_regex="Failed password|Invalid user|authentication failure|NOT in sudoers|maximum authentication attempts|segfault|Out of memory: Kill process|denied"

    echo -e "${YELLOW}--- Scanning System Logs for Security Anomaly Indicators ---${NC}"

    # 1. Systemd Journal Analysis
    if command -v journalctl &> /dev/null; then
        echo -e "${CYAN}Scanning systemd journal (last 24h)...${NC}"
        local journal_matches
        journal_matches=$(journalctl --since "24 hours ago" -p warning..emerg --grep="$pattern_regex" --no-pager -n 15 2>/dev/null)
        
        if [[ -n "$journal_matches" ]]; then
            echo -e "${RED}⚠️ Found suspicious entries in systemd journal:${NC}"
            echo "$journal_matches"
        else
            echo -e "${GREEN}✓ No high-severity security anomalies found in systemd journal (last 24h).${NC}"
        fi

        local failed_count
        failed_count=$(journalctl --since "24 hours ago" --grep="failed|invalid" --no-pager 2>/dev/null | wc -l)
        echo -e "Failed authentication events (24h): ${CYAN}${failed_count}${NC}"
        if [[ "$failed_count" -gt 20 ]]; then
            echo -e "${RED}⚠️ High number of failed auth attempts detected (${failed_count})! Possible brute-force attack.${NC}"
        fi
    fi

    # 2. Traditional Log Files Scan (/var/log/auth.log, /var/log/secure, /var/log/syslog)
    local target_logs=()
    [[ -f "/var/log/auth.log" ]] && target_logs+=("/var/log/auth.log")
    [[ -f "/var/log/secure" ]] && target_logs+=("/var/log/secure")
    [[ -f "/var/log/syslog" ]] && target_logs+=("/var/log/syslog")
    [[ -f "/var/log/messages" ]] && target_logs+=("/var/log/messages")

    if [[ ${#target_logs[@]} -gt 0 ]]; then
        echo -e "\n${CYAN}Scanning security log files (${target_logs[*]})...${NC}"
        for logfile in "${target_logs[@]}"; do
            local file_matches
            file_matches=$(sudo grep -Ei "$pattern_regex" "$logfile" 2>/dev/null | tail -n 10)
            if [[ -n "$file_matches" ]]; then
                echo -e "${YELLOW}Recent suspicious entries in ${logfile}:${NC}"
                echo "$file_matches"
            else
                echo -e "${GREEN}✓ No critical security entries found in ${logfile}.${NC}"
            fi
        done
    fi

    echo -e "\n${YELLOW}--- Recent Sudo Usage & Privilege Escalation ---${NC}"
    if [[ -f "/var/log/secure" ]]; then
        sudo grep "sudo" /var/log/secure 2>/dev/null | tail -n 10 || echo "No sudo records found in /var/log/secure."
    elif [[ -f "/var/log/auth.log" ]]; then
        sudo grep "sudo" /var/log/auth.log 2>/dev/null | tail -n 10 || echo "No sudo records found in /var/log/auth.log."
    else
        sudo journalctl _COMM=sudo -n 10 --no-pager 2>/dev/null || echo "No sudo records found in journal."
    fi
}

parse_security_logs

# 9. System Optimization & Resource Audit
section "9/19" "Checking System Resources & Optimization Opportunities..."
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
        HIGH_DISK_ALERT+="$(echo -e "  - ${RED}WARNING! Partition ${mount} (${fs}) is ${use_pct}% full!${NC} (Free space: ${GREEN}${avail}${NC} available out of ${size}, Used: ${used})")\n"
    fi
done < <(df -h -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk 'NR>1')

if [[ -n "$HIGH_DISK_ALERT" ]]; then
    echo -e "\n${RED}⚠️ High disk usage detected (>= 80% occupied):${NC}"
    echo -e "$HIGH_DISK_ALERT"
else
    echo -e "\n${GREEN}✓ All disk partitions have sufficient free space (< 80% used).${NC}"
fi

echo -e "\n${YELLOW}--- Systemd Failed Services ---${NC}"
FAILED_SERVICES=$(systemctl --failed --no-legend 2>/dev/null)
if [[ -n "$FAILED_SERVICES" ]]; then
    echo -e "${RED}Found failed systemd services:${NC}"
    echo "$FAILED_SERVICES"
else
    echo -e "${GREEN}✓ No failed systemd services.${NC}"
fi

echo -e "\n${YELLOW}--- Systemd Journal Disk Usage ---${NC}"
if command -v journalctl &> /dev/null; then
    journalctl --disk-usage
    echo "Tip: Run 'sudo journalctl --vacuum-time=2weeks' or '--vacuum-size=500M' if journal size is too large."
fi

echo -e "\n${YELLOW}--- DNF Package Cache & Unused Packages ---${NC}"
if command -v dnf &> /dev/null; then
    UNNEEDED=$(dnf autoremove --dry-run 2>/dev/null | grep -E "Removing:" | head -n 5)
    if [[ -n "$UNNEEDED" ]]; then
        echo -e "${YELLOW}Orphaned/unused packages detected. Consider running 'sudo dnf autoremove'.${NC}"
    else
        echo -e "${GREEN}✓ Package database clean.${NC}"
    fi
fi

# 10. Privilege & Account Audit
section "10/19" "Privilege & Security Misconfiguration Audit..."
echo -e "${YELLOW}--- Checking for Non-Root Accounts with UID 0 ---${NC}"
UID_ZERO=$(awk -F: '($3 == "0" && $1 != "root") { print $1 }' /etc/passwd)
if [[ -n "$UID_ZERO" ]]; then
    echo -e "${RED}CRITICAL! Non-root users with UID 0 found:${NC} $UID_ZERO"
else
    echo -e "${GREEN}✓ Only root user has UID 0.${NC}"
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
            p_info=$(sudo passwd -S "$username" 2>/dev/null | awk '{print $2}')
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
            echo -e "    ${RED}⚠️ SECURITY ALERT: User '${username}' has NO password set!${NC}"
        fi

    done < /etc/passwd
}
check_console_users

# 11. Repository Kernel & Security Package Updates Audit
section "11/19" "Auditing Repository Kernel Updates & Recommended Security Packages..."
RUNNING_KERNEL=$(uname -r)
echo -e "Current running kernel: ${CYAN}${RUNNING_KERNEL}${NC}"

if command -v dnf &> /dev/null || command -v yum &> /dev/null; then
    PKG_MGR="dnf"
    command -v dnf &> /dev/null || PKG_MGR="yum"
    echo -e "Detected package manager: ${BLUE}${PKG_MGR}${NC} (RedHat/Fedora family)"

    echo -e "\n${YELLOW}--- Checking Kernel Updates in Repository ---${NC}"
    KERNEL_UPDATES=$($PKG_MGR check-update kernel kernel-core kernel-modules 2>/dev/null | grep -E '^kernel(-core|-modules)?\.')
    if [[ -n "$KERNEL_UPDATES" ]]; then
        echo -e "${RED}⚠️ New kernel update available in repository:${NC}"
        echo "$KERNEL_UPDATES"
    else
        echo -e "${GREEN}✓ Kernel is up to date in repository.${NC}"
    fi

    LATEST_INSTALLED_KERNEL=$(rpm -q kernel --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | tail -n 1)
    if [[ -z "$LATEST_INSTALLED_KERNEL" ]]; then
        LATEST_INSTALLED_KERNEL=$(rpm -q kernel-core --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | tail -n 1)
    fi
    if [[ -n "$LATEST_INSTALLED_KERNEL" && "$RUNNING_KERNEL" != "$LATEST_INSTALLED_KERNEL"* ]]; then
        echo -e "${YELLOW}⚠️ System reboot required! Running kernel ($RUNNING_KERNEL) differs from installed ($LATEST_INSTALLED_KERNEL).${NC}"
    fi

    echo -e "\n${YELLOW}--- Checking Recommended Security Packages ---${NC}"
    RECOMMENDED_PKGS=("fail2ban" "firewalld" "audit" "clamav" "rkhunter" "trivy" "policycoreutils" "crypto-policies")
    for pkg in "${RECOMMENDED_PKGS[@]}"; do
        if rpm -q "$pkg" &> /dev/null; then
            PKG_UPDATE=$($PKG_MGR check-update "$pkg" 2>/dev/null | grep -E "^${pkg}\.")
            if [[ -n "$PKG_UPDATE" ]]; then
                echo -e "  - $pkg: ${GREEN}Installed${NC} | ${RED}Update Available in Repo${NC}"
            else
                echo -e "  - $pkg: ${GREEN}Installed (Up to date)${NC}"
            fi
        else
            echo -e "  - $pkg: ${YELLOW}Not installed${NC} (Recommended for security)"
        fi
    done

elif command -v apt-get &> /dev/null || command -v apt &> /dev/null; then
    echo -e "Detected package manager: ${BLUE}apt${NC} (Debian family)"

    echo -e "\n${YELLOW}--- Checking Kernel Updates in Repository ---${NC}"
    KERNEL_UPDATES=$(apt list --upgradable 2>/dev/null | grep -E '^linux-(image|headers|generic|amd64|arm64)')
    if [[ -n "$KERNEL_UPDATES" ]]; then
        echo -e "${RED}⚠️ New kernel update available in repository:${NC}"
        echo "$KERNEL_UPDATES"
    else
        echo -e "${GREEN}✓ Kernel is up to date in repository.${NC}"
    fi

    if [[ -f "/var/run/reboot-required" ]]; then
        echo -e "${YELLOW}⚠️ System reboot required! (/var/run/reboot-required exists)${NC}"
        if [[ -f "/var/run/reboot-required.pkgs" ]]; then
            echo "Packages requiring reboot:"
            cat /var/run/reboot-required.pkgs | sed 's/^/  - /'
        fi
    fi

    echo -e "\n${YELLOW}--- Checking Recommended Security Packages ---${NC}"
    RECOMMENDED_PKGS=("fail2ban" "ufw" "auditd" "apparmor" "unattended-upgrades" "clamav" "rkhunter" "trivy" "needrestart")
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

else
    echo -e "${YELLOW}Unsupported package manager. Skipping repository kernel & package audit.${NC}"
fi

# 12. Suspicious Process & Threat Detection Audit
section "12/19" "Auditing Running Processes for Suspicious Activity & Malware Indicators..."

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
            deleted_procs+="  - ${RED}PID ${pid}${NC} (User: ${user}) -> ${target}\n    Command: ${cmd}\n"
            ((threats_found++))
        fi
    done
    if [[ -n "$deleted_procs" ]]; then
        echo -e "${RED}⚠️ CRITICAL: Processes executing deleted binary files detected!${NC}"
        echo -e "$deleted_procs"
    else
        echo -e "${GREEN}✓ No processes running deleted binaries found.${NC}"
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
            temp_procs+="  - ${RED}PID ${pid}${NC} (User: ${user}) -> ${target}\n    Command: ${cmd}\n"
            ((threats_found++))
        fi
    done
    if [[ -n "$temp_procs" ]]; then
        echo -e "${RED}⚠️ WARNING: Processes running from temporary/volatile directories found:${NC}"
        echo -e "$temp_procs"
    else
        echo -e "${GREEN}✓ No processes executing from /tmp, /var/tmp, or /dev/shm.${NC}"
    fi

    echo -e "\n${YELLOW}--- 3. Checking for Known Miner & Suspicious Tool Signatures ---${NC}"
    local miner_pattern="xmrig|minerd|cgminer|cpuminer|kworkerds|stratum|masscan|zmap|kinsing|sysupdate"
    local suspicious_procs
    suspicious_procs=$(ps aux 2>/dev/null | grep -Ei "$miner_pattern" | grep -vE "grep|system-audit.sh")
    if [[ -n "$suspicious_procs" ]]; then
        echo -e "${RED}⚠️ ALERT: Known suspicious miner or scanning tools detected:${NC}"
        echo "$suspicious_procs"
        ((threats_found++))
    else
        echo -e "${GREEN}✓ No known miner or scanning tool signatures detected.${NC}"
    fi

    echo -e "\n${YELLOW}--- 4. Checking for Potential Reverse Shell Patterns ---${NC}"
    local revshell_pattern="nc -e|nc\.openbsd -e|bash -i|sh -i|python.*socket|perl.*socket|php -r.*socket"
    local revshell_procs
    revshell_procs=$(ps aux 2>/dev/null | grep -Ei "$revshell_pattern" | grep -vE "grep|system-audit.sh")
    if [[ -n "$revshell_procs" ]]; then
        echo -e "${RED}⚠️ ALERT: Potential reverse shell processes detected:${NC}"
        echo "$revshell_procs"
        ((threats_found++))
    else
        echo -e "${GREEN}✓ No reverse shell command patterns detected.${NC}"
    fi

    echo -e "\n${YELLOW}--- 5. Top CPU & RAM Consuming Processes ---${NC}"
    echo -e "${CYAN}Highest CPU Processes (>70% CPU):${NC}"
    local high_cpu
    high_cpu=$(ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | awk 'NR>1 && $3 > 70.0 {print $0}')
    if [[ -n "$high_cpu" ]]; then
        echo -e "${YELLOW}$high_cpu${NC}"
    else
        echo -e "${GREEN}✓ No processes consuming excessive CPU (>70%).${NC}"
    fi

    echo -e "${CYAN}Highest RAM Consuming Processes (Top 5):${NC}"
    ps -eo pid,user,%cpu,%mem,comm --sort=-%mem | head -n 6
}

audit_suspicious_processes

# 13. Shell Configuration & Security Alias Audit
section "13/19" "Auditing Shell Config Files (.bashrc, .zshrc) & Security Aliases (All Users)..."

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
                suspicious_findings+="  - ${RED}Suspicious alias in ${rc_path}:${NC}\n$found_suspicious\n"
            fi

            local found_exec
            found_exec=$(grep -Ei "$dangerous_exec_patterns" "$rc_path" 2>/dev/null)
            if [[ -n "$found_exec" ]]; then
                suspicious_findings+="  - ${RED}Dangerous execution pattern in ${rc_path}:${NC}\n$found_exec\n"
            fi
        done

        if [[ -n "$suspicious_findings" ]]; then
            echo -e "${RED}⚠️ Suspicious aliases or remote execution patterns detected:${NC}"
            echo -e "$suspicious_findings"
        else
            echo -e "${GREEN}✓ No suspicious alias hijacking or remote code execution patterns found.${NC}"
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

        echo -e "${YELLOW}Safety Aliases & Protection Recommendations:${NC}"
        if [[ "$has_rm_safe" -eq 1 ]]; then
            echo -e "  - 'rm' safety alias: ${GREEN}Enabled${NC}"
        else
            echo -e "  - 'rm' safety alias: ${YELLOW}Missing${NC} -> Recommendation: Add ${CYAN}alias rm='rm -i'${NC} to ${user_rc_found[0]} to prevent accidental 'rm -rf' data loss."
        fi

        if [[ "$has_cp_safe" -eq 1 ]]; then
            echo -e "  - 'cp' safety alias: ${GREEN}Enabled${NC}"
        else
            echo -e "  - 'cp' safety alias: ${YELLOW}Missing${NC} -> Recommendation: Add ${CYAN}alias cp='cp -i'${NC} to ${user_rc_found[0]} to prevent overwriting files."
        fi

        if [[ "$has_mv_safe" -eq 1 ]]; then
            echo -e "  - 'mv' safety alias: ${GREEN}Enabled${NC}"
        else
            echo -e "  - 'mv' safety alias: ${YELLOW}Missing${NC} -> Recommendation: Add ${CYAN}alias mv='mv -i'${NC} to ${user_rc_found[0]} to prevent overwriting files."
        fi

        if [[ "$has_preserve_root" -eq 0 ]]; then
            echo -e "  - Extra safety recommendation: Add ${CYAN}alias chown='chown --preserve-root'${NC} and ${CYAN}alias chmod='chmod --preserve-root'${NC} to ${user_rc_found[0]}"
        fi

    done < /etc/passwd
}

audit_shell_configs_and_aliases

# 14. SUID / SGID Executable File Audit
section "14/19" "Auditing SUID / SGID Files for Privilege Escalation Risk..."
audit_suid_files() {
    echo -e "${YELLOW}--- Scanning for SUID/SGID Binaries in Volatile / Non-Standard Paths ---${NC}"
    local suspicious_suid
    suspicious_suid=$(find /tmp /var/tmp /dev/shm /home -perm -4000 -o -perm -2000 2>/dev/null)
    if [[ -n "$suspicious_suid" ]]; then
        echo -e "${RED}⚠️ CRITICAL! SUID/SGID files found in non-standard/writable paths:${NC}"
        echo "$suspicious_suid"
    else
        echo -e "${GREEN}✓ No SUID/SGID files found in volatile/user paths (/tmp, /dev/shm, /home).${NC}"
    fi

    echo -e "\n${YELLOW}--- System SUID Executables Count ---${NC}"
    local suid_count
    suid_count=$(find /usr/bin /usr/sbin /bin /sbin -perm -4000 2>/dev/null | wc -l)
    echo -e "Total SUID binaries in system paths: ${CYAN}${suid_count}${NC}"
}
audit_suid_files

# 15. Persistence Audit (Cron Jobs & Systemd Timers)
section "15/19" "Auditing System Persistence (Cron Jobs & Systemd Timers)..."
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
    if command -v systemctl &>/dev/null; then
        systemctl list-timers --no-pager --no-legend 2>/dev/null | head -n 10
    fi
}
audit_persistence

# 16. SSH authorized_keys Audit (All Users)
section "16/19" "Auditing SSH Authorized Keys Across All Users..."
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
                    echo -e "    ${RED}⚠️ Warning: Root account has SSH authorized keys configured!${NC}"
                fi
            fi
        fi
    done < /etc/passwd

    if [[ "$keys_count" -eq 0 ]]; then
        echo -e "${GREEN}✓ No authorized_keys files found.${NC}"
    fi
}
audit_authorized_keys

# 17. Docker & Kubernetes Container Security Audit
section "17/19" "Auditing Docker & Container Security Settings..."
audit_container_security() {
    if [[ -S "/var/run/docker.sock" ]]; then
        local sock_perm
        sock_perm=$(ls -l /var/run/docker.sock 2>/dev/null)
        echo -e "Docker socket status: ${CYAN}${sock_perm}${NC}"
    else
        echo "Docker socket (/var/run/docker.sock) not active."
    fi

    if command -v docker &>/dev/null && docker ps &>/dev/null; then
        echo -e "\n${YELLOW}--- Running Docker Containers ---${NC}"
        local priv_containers
        priv_containers=$(docker ps --quiet | xargs docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}' 2>/dev/null | grep 'Privileged=true')
        if [[ -n "$priv_containers" ]]; then
            echo -e "${RED}⚠️ Privileged containers detected:${NC}\n$priv_containers"
        else
            echo -e "${GREEN}✓ No privileged Docker containers running.${NC}"
        fi
    fi
}
audit_container_security

# 18. Kernel Security Hardening (Sysctl Parameters Audit)
section "18/19" "Auditing Kernel Security Hardening (sysctl Parameters)..."
audit_kernel_hardening() {
    local SYSCTL_BIN="sysctl"
    command -v sysctl &>/dev/null || SYSCTL_BIN="/usr/sbin/sysctl"

    check_sysctl() {
        local param="$1"
        local expected="$2"
        local val
        val=$($SYSCTL_BIN -n "$param" 2>/dev/null)
        if [[ "$val" == "$expected" ]]; then
            echo -e "  - ${param}: ${GREEN}${val}${NC} (Secure)"
        else
            echo -e "  - ${param}: ${YELLOW}${val}${NC} (Recommended: ${expected})"
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
section "19/19" "Auditing DNS Settings & /etc/hosts Integrity..."
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
            echo -e "${GREEN}✓ No unusual custom entries in /etc/hosts.${NC}"
        fi
    fi
}
audit_dns_hosts

echo -e "\n${CYAN}=====================================================${NC}"
echo -e "${GREEN}=== Audit Completed Successfully! ===${NC}"
if [[ "$GENERATE_REPORT" == true ]]; then
    echo -e "${GREEN}Report saved to: ${REPORT_FILE}${NC}"
fi
echo -e "${CYAN}=====================================================${NC}"
