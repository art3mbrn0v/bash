#!/bin/bash

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
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Starting System Security Audit ===${NC}"

# 1. Shell History Scanning
echo -e "\n${GREEN}[1/8] Cleaning Shell History...${NC}"
clean_history() {
    local file="$1"
    if [[ -f "$file" ]]; then
        echo "Processing $file..."
        local temp_file
        temp_file=$(mktemp)
        local pattern_regex
        pattern_regex=$(IFS="|"; echo "${SENSITIVE_PATTERNS[*]}")
        # Use -a to handle binary zsh history files
        grep -vEia "$pattern_regex" "$file" > "$temp_file"
        mv "$temp_file" "$file"
        chmod 600 "$file"
    fi
}

find "$HOME" -maxdepth 1 -name ".zsh_history" -o -name ".bash_history*" | while read -r h_file; do
    clean_history "$h_file"
done
echo "History cleaned."

# 2. Minikube Certificate Permission Check
echo -e "\n${GREEN}[2/8] Checking Minikube Certificates...${NC}"
MINIKUBE_DIR="$HOME/.minikube"
if [[ -d "$MINIKUBE_DIR" ]]; then
    CERT_FILES=$(find "$MINIKUBE_DIR" -name "*.pem" -perm /o+rwx,g+rwx)
    if [[ -n "$CERT_FILES" ]]; then
        echo -e "${RED}Found files with insecure permissions:${NC}"
        echo "$CERT_FILES"
        echo "Fixing permissions to 600..."
        find "$MINIKUBE_DIR" -name "*.pem" -exec chmod 600 {} +
        echo "Permissions fixed."
    else
        echo "Certificate permissions are OK."
    fi
else
    echo "Minikube not found."
fi

# 3. Application CVE Checks
echo -e "\n${GREEN}[3/8] Checking Applications for CVEs...${NC}"
APPS_TO_CHECK=("code" "google-chrome-stable" "firefox" "docker-cli" "kubernetes1.34-client")
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

# 4. Filesystem Scanning (Trivy)
echo -e "\n${GREEN}[4/8] Trivy Filesystem Scanning...${NC}"
if command -v trivy &> /dev/null; then
    trivy fs --severity HIGH,CRITICAL --format table "$HOME/Labolatory"
else
    echo -e "${YELLOW}Trivy not installed.${NC}"
fi

# 5. Antivirus Update & Scan (ClamAV)
echo -e "\n${GREEN}[5/8] ClamAV Update & Process Scan...${NC}"
if command -v freshclam &> /dev/null; then
    echo "Updating ClamAV database..."
    sudo freshclam 2>/dev/null || echo "Existing DB will be used."
fi
if command -v clamscan &> /dev/null; then
    echo "Scanning processes and binaries..."
    sudo clamscan -r --memory --exclude-dir="^/sys" --exclude-dir="^/dev" --exclude-dir="^/proc" /bin /sbin /usr/bin /usr/sbin 2>/dev/null | grep -E "Infected|Summary|FOUND" || echo "No threats found."
else
    echo -e "${YELLOW}ClamAV not installed.${NC}"
fi

# 6. Rootkit Detection (rkhunter)
echo -e "\n${GREEN}[6/8] Rootkit Detection (rkhunter)...${NC}"
if command -v rkhunter &> /dev/null; then
    sudo rkhunter --check --sk --quiet 2>/dev/null
    echo "rkhunter check completed."
else
    echo -e "${YELLOW}rkhunter not installed.${NC}"
fi

# 7. Log Analysis (Secure, Messages, Packages)
echo -e "\n${GREEN}[7/8] Analyzing System Logs for suspicious activity...${NC}"

# Check for failed login attempts
echo -e "${YELLOW}--- Failed Auth (Last 20) ---${NC}"
sudo grep -i "failed" /var/log/secure 2>/dev/null | tail -n 20 || echo "No failed attempts in secure log."

# Check for sudo usage
echo -e "${YELLOW}--- Sudo Usage (Last 10) ---${NC}"
sudo grep "sudo" /var/log/secure 2>/dev/null | tail -n 10 || echo "No sudo records found."

# Check for suspicious system messages
echo -e "${YELLOW}--- Suspicious Messages (Last 20) ---${NC}"
sudo grep -iE "error|critical|warning|segfault|denied" /var/log/messages 2>/dev/null | tail -n 20 || echo "No critical messages."

# Check recently installed packages
echo -e "${YELLOW}--- Recently Installed Packages ---${NC}"
if [[ -f "/var/log/dnf.log" ]]; then
    sudo grep "Installed:" /var/log/dnf.log 2>/dev/null | tail -n 10
elif [[ -f "/var/log/dnf.rpm.log" ]]; then
    sudo grep "Installed:" /var/log/dnf.rpm.log 2>/dev/null | tail -n 10
else
    rpm -qa --last | head -n 10
fi

# 8. Network Audit
echo -e "\n${GREEN}[8/8] Checking Network Ports...${NC}"
if command -v ss &> /dev/null; then
    OPEN_PORTS=$(ss -tuln | grep -E '5353|5355')
    if [[ -n "$OPEN_PORTS" ]]; then
        echo -e "${RED}Warning! Active mDNS/LLMNR services found (5353/5355):${NC}"
        echo "$OPEN_PORTS"
    else
        echo "No suspicious ports detected."
    fi
fi

echo -e "\n${GREEN}=== Audit Completed ===${NC}"
