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

echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}=== Starting System Security & Optimization Audit ===${NC}"
echo -e "${CYAN}=====================================================${NC}"

# Helper function to print section headers
section() {
    echo -e "\n${BLUE}[$1] $2${NC}"
}

# 1. Shell History Scanning & Cleaning
section "1/10" "Cleaning Shell History for Sensitive Data..."
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
section "2/10" "Checking Minikube & SSH Certificate Permissions..."
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

if [[ -d "$HOME/.ssh" ]]; then
    chmod 700 "$HOME/.ssh" 2>/dev/null
    find "$HOME/.ssh" -type f -exec chmod 600 {} + 2>/dev/null
    echo -e "${GREEN}✓ SSH directory permissions secured (700 for .ssh, 600 for keys).${NC}"
fi

# 3. Application CVE Checks
section "3/10" "Checking Installed Applications for Security Vulnerabilities (CVEs)..."
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
section "4/10" "Auditing SSH Daemon Configuration..."
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
section "5/10" "Checking Active Listening Ports & Firewall Status..."
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
section "6/10" "Antivirus & Rootkit Audit (ClamAV / rkhunter)..."
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
section "7/10" "Trivy Code & Filesystem Security Scan..."
if command -v trivy &> /dev/null; then
    trivy fs --severity HIGH,CRITICAL --format table "$HOME/Labolatory"
else
    echo -e "${YELLOW}Trivy not installed. (Install trivy for automated vulnerability scanning of code/containers).${NC}"
fi

# 8. System Log & Auth Audit
section "8/10" "Analyzing System Logs for Suspicious Activity..."
echo -e "${YELLOW}--- Failed Auth Attempts (Last 10) ---${NC}"
if [[ -f "/var/log/secure" ]]; then
    sudo grep -i "failed" /var/log/secure 2>/dev/null | tail -n 10 || echo "No failed attempts in /var/log/secure."
else
    sudo journalctl -u sshd -u gdm --grep="failed|invalid" -n 10 --no-pager 2>/dev/null || echo "No failed authentication entries in journal."
fi

echo -e "${YELLOW}--- Recent Sudo Usage (Last 10) ---${NC}"
if [[ -f "/var/log/secure" ]]; then
    sudo grep "sudo" /var/log/secure 2>/dev/null | tail -n 10 || echo "No sudo records found in /var/log/secure."
else
    sudo journalctl _COMM=sudo -n 10 --no-pager 2>/dev/null || echo "No sudo records found in journal."
fi

# 9. System Optimization & Resource Audit
section "9/10" "Checking System Resources & Optimization Opportunities..."
echo -e "${YELLOW}--- Disk Space Usage ---${NC}"
df -h --total -x tmpfs -x devtmpfs | grep -E 'Filesystem|total|/[a-z]*$'

# Warn on high disk usage (>85%)
HIGH_DISK=$(df -h | awk '0+$5 > 85 {print $5 " occupied on " $6}')
if [[ -n "$HIGH_DISK" ]]; then
    echo -e "${RED}⚠️ High disk usage detected:${NC}\n$HIGH_DISK"
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
section "10/10" "Privilege & Security Misconfiguration Audit..."
echo -e "${YELLOW}--- Checking for Non-Root Accounts with UID 0 ---${NC}"
UID_ZERO=$(awk -F: '($3 == "0" && $1 != "root") { print $1 }' /etc/passwd)
if [[ -n "$UID_ZERO" ]]; then
    echo -e "${RED}CRITICAL! Non-root users with UID 0 found:${NC} $UID_ZERO"
else
    echo -e "${GREEN}✓ Only root user has UID 0.${NC}"
fi

echo -e "\n${CYAN}=====================================================${NC}"
echo -e "${GREEN}=== Audit Completed Successfully! ===${NC}"
echo -e "${CYAN}=====================================================${NC}"
