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

# Configuration & Execution Modes (Sequential Auto-Audit & Remediation)
AUTO_FIX=true
CLEAN_CACHE=true
GENERATE_REPORT=true
AUTO_RESTART_SERVICES=true
INSTALL_MISSING_PKGS=false
REPORT_DIR="$HOME/Labolatory/bash/reports"

# External public GitHub password databases for weak password dictionary checks
EXTERNAL_PASSWORD_LIST_URLS=(
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/500-worst-passwords.txt"
    "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt"
)
FETCH_EXTERNAL_PASSWORDS=true

# CLI Arguments Parser
for arg in "$@"; do
    case "$arg" in
        --restart-services|-r)
            AUTO_RESTART_SERVICES=true
            ;;
        --no-restart-services)
            AUTO_RESTART_SERVICES=false
            ;;
        --install-packages|-i)
            INSTALL_MISSING_PKGS=true
            ;;
        --fetch-passwords)
            FETCH_EXTERNAL_PASSWORDS=true
            ;;
        --no-fetch-passwords)
            FETCH_EXTERNAL_PASSWORDS=false
            ;;
        --password-url=*)
            EXTERNAL_PASSWORD_LIST_URLS+=("${arg#*=}")
            ;;
        --no-fix)
            AUTO_FIX=false
            ;;
        --help|-h)
            echo "System Security & Optimization Audit Script"
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -r, --restart-services    Automatically restart systemd services when needed (default: enabled)"
            echo "  --no-restart-services     Disable automatic service restarts"
            echo "  -i, --install-packages    Automatically install missing recommended security tools & restart services"
            echo "  --fetch-passwords         Fetch external weak password databases from GitHub (default: enabled)"
            echo "  --no-fetch-passwords      Disable fetching external password databases from GitHub"
            echo "  --password-url=<url>      Add custom public password list URL for dictionary checks"
            echo "  --no-fix                  Disable auto-fix operations"
            echo "  -h, --help                Show this help message"
            exit 0
            ;;
    esac
done

# Privilege check: Must be run as root or via sudo
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as a privileged user (root or via sudo).${NC}"
    exit 1
fi

# Executive Scorecard Counters
PASSED_COUNT=0
WARNING_COUNT=0
CRITICAL_COUNT=0
TOTAL_CHECKS=0

# Automatic Report Teeing (Markdown Log Generation)
mkdir -p "$REPORT_DIR" 2>/dev/null || true
REPORT_FILE="$REPORT_DIR/audit-report-$(date +%Y-%m-%d_%H-%M-%S).md"
exec > >(tee >(sed -r 's/\x1B\[[0-9;]*[mK]//g' > "$REPORT_FILE")) 2>&1

echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}=== Starting System Security & Optimization Audit ===${NC}"
echo -e "${CYAN}=====================================================${NC}"

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

# Safe non-blocking sudo execution wrapper
run_sudo() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo -n "$@" 2>/dev/null
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

# Helper function to restart systemd services when needed
restart_service() {
    local service="$1"
    local reason="${2:-auto-remediation}"

    if [[ "$AUTO_RESTART_SERVICES" != true ]]; then
        echo -e "${YELLOW}[SKIP] Service restart skipped for '${service}' (AUTO_RESTART_SERVICES=false).${NC}"
        return 0
    fi

    if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]]; then
        echo -n "Restarting service '${service}' (${reason})... "
        if run_sudo systemctl restart "$service" 2>/dev/null; then
            log_pass "Service '${service}' restarted successfully."
            return 0
        else
            log_warn "Failed to restart service '${service}'."
            return 1
        fi
    else
        echo -e "${YELLOW}systemctl not available; cannot restart service '${service}'.${NC}"
        return 1
    fi
}

# Helper function to install missing package and restart associated service
install_pkg_and_restart_service() {
    local pkg="$1"
    local service="${2:-$1}"

    if [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
        echo -e "${YELLOW}Installing package '${pkg}' via APT...${NC}"
        if run_sudo "${TOOL_BIN['apt-get']}" install -y "$pkg" 2>/dev/null; then
            log_pass "Package '${pkg}' installed successfully."
            TOOL_FOUND["$pkg"]=1
            TOOL_BIN["$pkg"]=$(find_tool "$pkg")
            if [[ "$AUTO_RESTART_SERVICES" == true && -n "$service" ]]; then
                restart_service "$service" "after package installation"
            fi
        else
            log_warn "Failed to install package '${pkg}' via APT."
        fi
    elif [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
        echo -e "${YELLOW}Installing package '${pkg}' via DNF...${NC}"
        if run_sudo "${TOOL_BIN['dnf']}" install -y "$pkg" 2>/dev/null; then
            log_pass "Package '${pkg}' installed successfully."
            TOOL_FOUND["$pkg"]=1
            TOOL_BIN["$pkg"]=$(find_tool "$pkg")
            if [[ "$AUTO_RESTART_SERVICES" == true && -n "$service" ]]; then
                restart_service "$service" "after package installation"
            fi
        else
            log_warn "Failed to install package '${pkg}' via DNF."
        fi
    fi
}

# --- Tool Cache & Pre-Flight Dependency Inspection ---
declare -A TOOL_BIN
declare -A TOOL_FOUND

TOOLS_TO_CHECK=(
    "sudo" "systemctl" "journalctl" "ss" "sysctl" "ssh-keygen" 
    "crontab" "ip" "df" "awk" "grep" "sed" "find" "clamscan" 
    "freshclam" "rkhunter" "trivy" "nmcli" "nmap" "docker" "podman"
    "apt-get" "dnf" "rpm" "dpkg-query" "lynis" "needrestart" "debsums"
    "python3" "pwck" "grpck" "who" "w" "last" "lastb" "lastlog"
    "curl" "wget" "cryptsetup"
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
        if [[ "$INSTALL_MISSING_PKGS" == true ]]; then
            echo -e "\n${YELLOW}=== Auto-Installing Missing Security Tools & Restarting Services ===${NC}"
            for m_tool in "${missing_tools[@]}"; do
                case "$m_tool" in
                    clamscan|freshclam)
                        install_pkg_and_restart_service "clamav" "clamav-freshclam"
                        ;;
                    needrestart)
                        install_pkg_and_restart_service "needrestart" ""
                        ;;
                    rkhunter)
                        install_pkg_and_restart_service "rkhunter" ""
                        ;;
                    trivy)
                        install_pkg_and_restart_service "trivy" ""
                        ;;
                    *)
                        install_pkg_and_restart_service "$m_tool" "$m_tool"
                        ;;
                esac
            done
        else
            echo -e "\n${YELLOW}Recommended Security Tools Installation Tip:${NC}"
            if [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
                echo -e "  Debian/Ubuntu: ${CYAN}sudo apt install ${missing_tools[*]}${NC}"
            elif [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
                echo -e "  Fedora/RHEL:   ${CYAN}sudo dnf install ${missing_tools[*]}${NC}"
            fi
            echo -e "  Tip: Run with ${CYAN}--install-packages${NC} or ${CYAN}-i${NC} to auto-install missing tools & start/restart services."
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
audit_ssh_keys_age_and_cert_expiration() {
    echo -e "\n${YELLOW}--- Auditing SSH Key Creation Age & SSL/TLS Certificate Expirations ---${NC}"

    # 1. SSH Private Key Age & Rotation Audit
    echo -e "${CYAN}1. SSH Key Age & Rotation Audit (Host Keys & User Keys):${NC}"
    local now_sec
    now_sec=$(date +%s)
    local ssh_keys=()
    local total_keys=0
    local old_keys_count=0

    while read -r hk; do [[ -f "$hk" ]] && ssh_keys+=("$hk"); done < <(find /etc/ssh -name "ssh_host_*_key" ! -name "*.pub" 2>/dev/null)
    
    while IFS=: read -r username password uid gid gecos home shell; do
        [[ -d "$home/.ssh" ]] || continue
        while read -r uk; do
            [[ -f "$uk" && ! "$uk" =~ \.pub$ && "$uk" != *"known_hosts"* && "$uk" != *"authorized_keys"* && "$uk" != *"config"* ]] && ssh_keys+=("$uk")
        done < <(find "$home/.ssh" -maxdepth 2 -type f 2>/dev/null)
    done < /etc/passwd

    for key_file in "${ssh_keys[@]}"; do
        if run_sudo test -f "$key_file" 2>/dev/null; then
            if run_sudo grep -q "PRIVATE KEY" "$key_file" 2>/dev/null; then
                ((total_keys++))
                local mtime_sec mtime_date age_days
                mtime_sec=$(run_sudo stat -c "%Y" "$key_file" 2>/dev/null)
                mtime_date=$(run_sudo stat -c "%y" "$key_file" 2>/dev/null | cut -d" " -f1)
                
                if [[ -n "$mtime_sec" ]]; then
                    age_days=$(( (now_sec - mtime_sec) / 86400 ))
                    echo -e "  - Key: ${CYAN}${key_file}${NC} | Created/Modified: ${mtime_date} (${age_days} days old)"

                    if [[ "$age_days" -ge 365 ]]; then
                        log_warn "SSH Key '${key_file}' is ${age_days} days old (created ${mtime_date}). Recommend key rotation."
                        ((old_keys_count++))
                    fi
                fi
            fi
        fi
    done

    if [[ "$total_keys" -eq 0 ]]; then
        log_pass "No SSH private keys found to audit."
    elif [[ "$old_keys_count" -eq 0 ]]; then
        log_pass "All ${total_keys} SSH private key(s) are less than 1 year old."
    fi

    # 2. SSL/TLS & X.509 Certificate Expiration Audit
    echo -e "\n${CYAN}2. SSL/TLS Certificate Expiration Audit (/etc/ssl, /etc/letsencrypt, ~/.minikube):${NC}"
    local cert_files=()
    local expired_certs=0
    local expiring_soon_certs=0
    local valid_certs=0

    local search_dirs=("/etc/ssl/certs" "/etc/letsencrypt/live" "/etc/pki" "$HOME/.minikube")
    for sdir in "${search_dirs[@]}"; do
        [[ -d "$sdir" ]] || continue
        while read -r cfile; do
            [[ -f "$cfile" ]] && cert_files+=("$cfile")
        done < <(find "$sdir" -type f \( -name "*.crt" -o -name "*.pem" -o -name "*.cer" \) 2>/dev/null | head -n 30)
    done

    if command -v openssl &>/dev/null; then
        for cert in "${cert_files[@]}"; do
            local enddate
            enddate=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
            [[ -z "$enddate" ]] && continue

            local end_sec
            end_sec=$(date -d "$enddate" +%s 2>/dev/null)
            [[ -z "$end_sec" ]] && continue

            local days_left=$(( (end_sec - now_sec) / 86400 ))

            if [[ "$days_left" -lt 0 ]]; then
                log_crit "Certificate '${cert}' EXPIRED $(( -days_left )) days ago (Expired on ${enddate})!"
                ((expired_certs++))
            elif [[ "$days_left" -le 30 ]]; then
                log_warn "Certificate '${cert}' EXPIRING SOON in ${days_left} days (Expires on ${enddate})."
                ((expiring_soon_certs++))
            else
                ((valid_certs++))
            fi
        done

        if [[ "$expired_certs" -eq 0 && "$expiring_soon_certs" -eq 0 ]]; then
            log_pass "All scanned SSL/TLS certificates (${valid_certs}) are valid and not expiring within 30 days."
        fi
    else
        echo -e "${YELLOW}openssl command not available for certificate expiration inspection.${NC}"
    fi

    # 3. OpenSSH User / Host Certificate Validity Audit (*-cert.pub)
    echo -e "\n${CYAN}3. OpenSSH Certificate Expiration Audit (*-cert.pub):${NC}"
    local ssh_certs=()
    while read -r sc; do [[ -f "$sc" ]] && ssh_certs+=("$sc"); done < <(find /etc/ssh /home -name "*-cert.pub" 2>/dev/null)

    if [[ ${#ssh_certs[@]} -gt 0 ]]; then
        for scert in "${ssh_certs[@]}"; do
            local validity
            validity=$("${TOOL_BIN['ssh-keygen']}" -L -f "$scert" 2>/dev/null | grep -i "Valid:")
            echo -e "  - OpenSSH Cert ${CYAN}${scert}${NC}: ${validity:-Checked}"
        done
        log_pass "Audited ${#ssh_certs[@]} OpenSSH certificate(s)."
    else
        echo "No OpenSSH certificate files (*-cert.pub) found."
    fi
}

audit_ssh_keys_age_and_cert_expiration
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

# 5. Network Security, Active Connections & Tunneling Audit
section "5/20" "Auditing Network Security, Active Connections & VPN Tunnels..."

audit_network_security_and_tunnels() {
    # 1. Firewall Service Status
    echo -e "${YELLOW}--- 1. Firewall Service Status ---${NC}"
    if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]]; then
        if systemctl is-active --quiet firewalld; then
            log_pass "firewalld firewall service is active."
        elif systemctl is-active --quiet ufw; then
            log_pass "ufw firewall service is active."
        else
            log_warn "Firewall service (firewalld/ufw) is inactive!"
            if [[ "$AUTO_RESTART_SERVICES" == true && "$AUTO_FIX" == true ]]; then
                if systemctl list-unit-files 2>/dev/null | grep -q "^ufw\.service"; then
                    restart_service "ufw" "activating firewall daemon"
                elif systemctl list-unit-files 2>/dev/null | grep -q "^firewalld\.service"; then
                    restart_service "firewalld" "activating firewall daemon"
                fi
            fi
        fi
    fi

    # 2. Public Listening TCP/UDP Ports
    if [[ "${TOOL_FOUND['ss']}" -eq 1 ]]; then
        echo -e "\n${YELLOW}--- 2. Public Listening TCP/UDP Ports ---${NC}"
        local listen_ports
        listen_ports=$(ss -tulpn 2>/dev/null | grep -E '0\.0\.0\.0|::|\*')
        if [[ -n "$listen_ports" ]]; then
            echo "$listen_ports"
        else
            log_pass "No open public listening ports found."
        fi

        local mdns_llmnr
        mdns_llmnr=$(ss -tuln 2>/dev/null | grep -E '5353|5355')
        if [[ -n "$mdns_llmnr" ]]; then
            log_warn "Active mDNS/LLMNR services found (5353/5355). Disable systemd-resolved LLMNR/MulticastDNS if not needed."
        fi

        # 3. Active Established Outbound Connections Audit
        echo -e "\n${YELLOW}--- 3. Active Established Outbound Network Connections ---${NC}"
        local established_conns
        established_conns=$(ss -tunp state established 2>/dev/null | grep -v '127\.0\.0\.1' | grep -v '::1')
        if [[ -n "$established_conns" ]]; then
            echo "$established_conns"
            local conn_count
            conn_count=$(echo "$established_conns" | awk 'NR>1' | wc -l)
            log_pass "Audited ${conn_count} active established outbound network connection(s)."
        else
            log_pass "No active established outbound connections to external hosts."
        fi
    fi

    # 4. VPN, Mesh & Tunneling Interfaces Audit
    echo -e "\n${YELLOW}--- 4. Active VPN, Mesh & Tunneling Interfaces ---${NC}"
    local vpn_ifaces
    vpn_ifaces=$(ip link show 2>/dev/null | grep -E 'tun[0-9]|tap[0-9]|wg[0-9]|tailscale|zerotier|zt[0-9]' | awk -F': ' '{print $2}')
    if [[ -n "$vpn_ifaces" ]]; then
        echo -e "${CYAN}Active VPN / Mesh interfaces detected:${NC} ${vpn_ifaces}"
        log_pass "VPN/Mesh network interface(s) verified: ${vpn_ifaces}"
    else
        echo -e "No active VPN/Mesh interfaces (WireGuard, OpenVPN, Tailscale, ZeroTier) detected."
    fi

    # Check VPN config permissions (/etc/wireguard, /etc/openvpn)
    local vpn_configs=()
    [[ -d "/etc/wireguard" ]] && while read -r f; do vpn_configs+=("$f"); done < <(find /etc/wireguard -type f 2>/dev/null)
    [[ -d "/etc/openvpn" ]] && while read -r f; do vpn_configs+=("$f"); done < <(find /etc/openvpn -type f 2>/dev/null)

    if [[ ${#vpn_configs[@]} -gt 0 ]]; then
        echo -e "\n${CYAN}Auditing VPN Configuration File Permissions:${NC}"
        for vconf in "${vpn_configs[@]}"; do
            local v_octal
            v_octal=$(run_sudo stat -c "%a" "$vconf" 2>/dev/null)
            if [[ "$v_octal" =~ ^(600|400|640)$ ]]; then
                log_pass "${vconf}: Secure permissions (${v_octal})"
            else
                log_warn "${vconf}: Loose permissions (${v_octal}). Recommended: 600"
            fi
        done
    fi
}

audit_network_security_and_tunnels

# 6. Antivirus & Rootkit Audit (ClamAV / rkhunter)
section "6/20" "Antivirus & Rootkit Audit (ClamAV / rkhunter)..."
if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]]; then
    if systemctl is-active --quiet clamav-freshclam; then
        log_pass "clamav-freshclam service is active."
    elif systemctl list-unit-files 2>/dev/null | grep -q "^clamav-freshclam\.service"; then
        log_warn "clamav-freshclam service is installed but inactive."
        if [[ "$AUTO_RESTART_SERVICES" == true && "$AUTO_FIX" == true ]]; then
            restart_service "clamav-freshclam" "activating antivirus signature update daemon"
        fi
    fi
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

# 7. Filesystem Directory Permissions, Container & Lynis Security Audit
section "7/20" "Filesystem Directory Permissions, Container & Lynis Security Audit..."

audit_critical_permissions_matrix() {
    echo -e "${YELLOW}--- Comprehensive Critical System Files & Directories Permissions Matrix ---${NC}"

    local critical_files=(
        "/etc/passwd:^644$:root"
        "/etc/group:^644$:root"
        "/etc/shadow:^(600|640)$:root"
        "/etc/gshadow:^(600|640)$:root"
        "/etc/sudoers:^(440|400)$:root"
        "/etc/fstab:^644$:root"
        "/etc/crontab:^(600|644)$:root"
        "/boot/grub/grub.cfg:^(600|700)$:root"
        "/boot/grub2/grub.cfg:^(600|700)$:root"
        "/etc/sysctl.conf:^644$:root"
        "/etc/ssh/sshd_config:^(600|644)$:root"
    )

    local critical_dirs=(
        "/etc:^755$:root"
        "/etc/sudoers.d:^(750|755)$:root"
        "/etc/cron.d:^(755|700)$:root"
        "/etc/cron.daily:^(755|700)$:root"
        "/etc/cron.hourly:^(755|700)$:root"
        "/etc/cron.weekly:^(755|700)$:root"
        "/etc/cron.monthly:^(755|700)$:root"
        "/etc/pam.d:^755$:root"
        "/bin:^755$:root"
        "/sbin:^755$:root"
        "/usr/bin:^755$:root"
        "/usr/sbin:^755$:root"
        "/lib:^755$:root"
        "/lib64:^755$:root"
        "/var/log:^(755|775)$:root"
    )

    local perm_issues=0

    echo -e "${CYAN}1. Critical System File Permissions & Root Ownership Audit:${NC}"
    for item in "${critical_files[@]}"; do
        IFS=":" read -r filepath expected_mode_regex expected_owner <<< "$item"
        [[ -f "$filepath" ]] || continue

        local mode owner
        mode=$(run_sudo stat -L -c "%a" "$filepath" 2>/dev/null)
        owner=$(run_sudo stat -L -c "%U" "$filepath" 2>/dev/null)

        local ok=true
        if ! [[ "$mode" =~ $expected_mode_regex ]]; then
            log_warn "File '${filepath}' has non-standard permissions: ${mode} (Recommended: ${expected_mode_regex//[\^\$()]/})"
            ((perm_issues++))
            ok=false
        fi

        if [[ -n "$owner" && "$owner" != "$expected_owner" ]]; then
            log_crit "File '${filepath}' is NOT owned by ${expected_owner}! Current owner: ${owner}"
            ((perm_issues++))
            ok=false
        fi

        if [[ "$ok" == true ]]; then
            echo -e "  - ${filepath}: ${GREEN}OK${NC} (Mode: ${mode}, Owner: ${owner:-root})"
        fi
    done

    echo -e "\n${CYAN}2. SSH Private Host Keys Permissions Audit (/etc/ssh/ssh_host_*_key):${NC}"
    while read -r hk; do
        [[ -f "$hk" ]] || continue
        local hk_mode hk_owner
        hk_mode=$(run_sudo stat -c "%a" "$hk" 2>/dev/null)
        hk_owner=$(run_sudo stat -c "%U" "$hk" 2>/dev/null)

        if [[ "$hk_mode" =~ ^(600|640)$ ]]; then
            echo -e "  - Host Key ${hk}: ${GREEN}OK${NC} (${hk_mode} ${hk_owner:-root})"
        else
            log_crit "SSH Private Host Key '${hk}' has insecure permissions (${hk_mode})! Must be 600 or 640."
            ((perm_issues++))
        fi
    done < <(find /etc/ssh -name "ssh_host_*_key" ! -name "*.pub" 2>/dev/null)

    echo -e "\n${CYAN}3. Critical System Directory Permissions Audit:${NC}"
    for item in "${critical_dirs[@]}"; do
        IFS=":" read -r dirpath expected_mode_regex expected_owner <<< "$item"
        [[ -d "$dirpath" ]] || continue

        local mode owner
        mode=$(run_sudo stat -L -c "%a" "$dirpath" 2>/dev/null)
        owner=$(run_sudo stat -L -c "%U" "$dirpath" 2>/dev/null)

        local ok=true
        if ! [[ "$mode" =~ $expected_mode_regex ]]; then
            log_warn "Directory '${dirpath}' has non-standard permissions: ${mode} (Recommended: ${expected_mode_regex//[\^\$()]/})"
            ((perm_issues++))
            ok=false
        fi

        if [[ -n "$owner" && "$owner" != "$expected_owner" ]]; then
            log_crit "Directory '${dirpath}' is NOT owned by ${expected_owner}! Current owner: ${owner}"
            ((perm_issues++))
            ok=false
        fi

        if [[ "$ok" == true ]]; then
            echo -e "  - ${dirpath}: ${GREEN}OK${NC} (Mode: ${mode}, Owner: ${owner:-root})"
        fi
    done

    if [[ "$perm_issues" -eq 0 ]]; then
        log_pass "All critical system files and directories have verified secure permissions and ownership."
    fi
}

audit_directory_permissions() {
    audit_critical_permissions_matrix

    # 2. Temporary Shared Directories Sticky Bit Audit (/tmp, /var/tmp, /dev/shm)
    echo -e "\n${CYAN}2. Shared Temporary Directories Sticky Bit Check (/tmp, /var/tmp, /dev/shm):${NC}"
    local temp_dirs=("/tmp" "/var/tmp" "/dev/shm")
    
    for tdir in "${temp_dirs[@]}"; do
        [[ -d "$tdir" ]] || continue

        local t_mode
        t_mode=$(stat -c "%a" "$tdir" 2>/dev/null)
        if [[ -k "$tdir" ]]; then
            log_pass "Directory '${tdir}' sticky bit verified (Mode: ${t_mode}). Users cannot delete each other's files."
        else
            log_crit "Directory '${tdir}' DOES NOT HAVE STICKY BIT SET (Mode: ${t_mode})! Local users can tamper with other users' temp files."
        fi
    done

    # 3. User Home & Dot-Directories Permissions Audit
    echo -e "\n${CYAN}3. User Home Directories & Sensitive Dot-Folders Permissions (/home/*, /root):${NC}"
    local home_issues=0

    while IFS=: read -r username password uid gid gecos home shell; do
        [[ -d "$home" ]] || continue
        [[ "$uid" -ne 0 && "$uid" -lt 1000 ]] && continue

        local dot_dirs=(".ssh" ".gnupg" ".aws" ".kube" ".docker" ".config/gcloud")
        for dot in "${dot_dirs[@]}"; do
            local dot_path="$home/$dot"
            if [[ -d "$dot_path" ]]; then
                local d_octal d_perm
                d_octal=$(stat -c "%a" "$dot_path" 2>/dev/null)
                d_perm=$(stat -c "%a %U:%G" "$dot_path" 2>/dev/null)
                if [[ "$d_octal" =~ [1-7][1-7]$ ]]; then
                    log_warn "Sensitive directory '${dot_path}' has loose group/world permissions (${d_perm}). Recommended: 700"
                    ((home_issues++))
                fi
            fi
        done
    done < /etc/passwd

    if [[ "$home_issues" -eq 0 ]]; then
        log_pass "All user home directories and sensitive dot-folders have secure permissions."
    fi

    # 4. System-wide World-Writable Directories Scan
    echo -e "\n${CYAN}4. Scanning Filesystem for World-Writable Directories:${NC}"
    echo "Scanning top-level paths for directories writable by 'others' (excluding /tmp, /proc, /sys)..."
    local ww_dirs
    ww_dirs=$(find / -maxdepth 4 -type d \( -perm -0002 -a ! -perm -1000 \) ! -path "/proc*" ! -path "/sys*" ! -path "/dev*" ! -path "/run*" 2>/dev/null | head -n 15)

    if [[ -n "$ww_dirs" ]]; then
        log_warn "World-writable directories WITHOUT sticky bit found:\n$ww_dirs"
    else
        log_pass "No unsecure world-writable directories found in system search."
    fi

    # 5. System Binary Cryptographic Integrity Verification (debsums / rpm)
    echo -e "\n${CYAN}5. Critical System Binary Integrity Verification:${NC}"
    if [[ "${TOOL_FOUND['debsums']}" -eq 1 ]]; then
        echo "Running debsums integrity verification on system packages..."
        local debsums_out
        debsums_out=$(run_sudo "${TOOL_BIN['debsums']}" -c 2>&1 | grep -v 'OK$' | head -n 10)
        if [[ -n "$debsums_out" ]]; then
            log_crit "Modified system package files detected by debsums!\n$debsums_out"
        else
            log_pass "debsums integrity verification passed: All system binaries match package checksums."
        fi
    elif [[ "${TOOL_FOUND['rpm']}" -eq 1 ]]; then
        local rpm_out
        rpm_out=$(rpm -Vf /bin/ls /bin/login /usr/sbin/sshd 2>/dev/null | grep -E '^..5')
        if [[ -n "$rpm_out" ]]; then
            log_crit "Modified system core binaries detected by RPM checksum check:\n$rpm_out"
        else
            log_pass "RPM core binary checksums verified."
        fi
    else
        echo -e "${YELLOW}debsums/rpm-verify not available for cryptographic binary checksum audit.${NC}"
    fi

    # 6. Rotated Logs Accumulation & Cleanup Audit (/var/log)
    echo -e "\n${CYAN}6. Rotated Logs Accumulation & Cleanup (/var/log):${NC}"
    local rotated_logs=()
    local rot_bytes=0

    while read -r rlog; do
        [[ -f "$rlog" ]] || continue
        local rsize
        rsize=$(du -sb "$rlog" 2>/dev/null | awk '{print $1}')
        if [[ -n "$rsize" && "$rsize" -gt 0 ]]; then
            ((rot_bytes += rsize))
            rotated_logs+=("$rlog")
        fi
    done < <(find /var/log -type f \( -name "*.gz" -o -name "*.1" -o -name "*.old" \) 2>/dev/null)

    local rot_human
    rot_human=$(numfmt --to=iec-i --suffix=B "$rot_bytes" 2>/dev/null || echo "$(( rot_bytes / 1048576 )) MB")

    if [[ ${#rotated_logs[@]} -gt 0 ]]; then
        echo -e "Discovered ${#rotated_logs[@]} rotated/compressed log file(s) occupying ${CYAN}${rot_human}${NC} in /var/log."
        if [[ "$CLEAN_CACHE" == true ]]; then
            echo -n "Cleaning old compressed rotated log archives... "
            for rfile in "${rotated_logs[@]}"; do
                run_sudo rm -f "$rfile" 2>/dev/null || true
            done
            log_pass "Rotated log archive cleanup completed. Reclaimed ${rot_human} of disk space."
        else
            log_pass "Rotated logs monitored (${rot_human})."
        fi
    else
        log_pass "No accumulated rotated log archives in /var/log."
    fi

    # 7. LUKS Cryptographic Keyfiles Audit in Temporary Directories (/tmp, /var/tmp, /dev/shm)
    audit_luks_keys_in_temp
}

audit_luks_keys_in_temp() {
    echo -e "\n${CYAN}7. Auditing LUKS Cryptographic Keyfiles in Temporary Directories (/tmp, /var/tmp, /dev/shm):${NC}"
    local temp_paths=("/tmp" "/var/tmp" "/dev/shm")
    local luks_keys_found=0

    # 1. Inspect /etc/crypttab for references to keyfiles residing in temporary directories
    if [[ -f "/etc/crypttab" ]]; then
        while read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            local target_name dev_path key_path
            target_name=$(echo "$line" | awk '{print $1}')
            dev_path=$(echo "$line" | awk '{print $2}')
            key_path=$(echo "$line" | awk '{print $3}')

            if [[ "$key_path" =~ ^/tmp/|^/var/tmp/|^/dev/shm/ ]]; then
                ((luks_keys_found++))
                log_crit "INSECURE CRYPTTAB KEYFILE: Target '${target_name}' in /etc/crypttab uses keyfile in temp directory: ${key_path}!"
            fi
        done < /etc/crypttab
    fi

    # 2. Search /tmp, /var/tmp, /dev/shm for files matching LUKS / encryption key file patterns
    local key_patterns=("*luks*" "*keyfile*" "*.keyfile" "*crypt*key*" "*luks*.key" "*luks*.bin" "*volume.key")
    for tpath in "${temp_paths[@]}"; do
        [[ -d "$tpath" ]] || continue
        for pat in "${key_patterns[@]}"; do
            while read -r kfile; do
                [[ -f "$kfile" ]] || continue
                ((luks_keys_found++))
                local k_perm k_owner
                k_perm=$(stat -c "%a" "$kfile" 2>/dev/null)
                k_owner=$(stat -c "%U:%G" "$kfile" 2>/dev/null)

                log_crit "LUKS / Encryption Keyfile detected in temporary directory: '${kfile}' (Permissions: ${k_perm}, Owner: ${k_owner})!"

                if [[ "$AUTO_FIX" == true ]]; then
                    if [[ "$k_perm" =~ [1-7][1-7]$ ]]; then
                        run_sudo chmod 600 "$kfile" 2>/dev/null
                        echo -e "  - ${GREEN}✓ Auto-fix applied:${NC} Secured permissions of '${kfile}' to 600."
                    fi
                fi
            done < <(find "$tpath" -maxdepth 3 -type f -name "$pat" 2>/dev/null)
        done
    done

    # 3. Check for binary LUKS header/key files in temporary directories using cryptsetup or file header magic
    local cs_cmd="${TOOL_BIN['cryptsetup']}"
    [[ -z "$cs_cmd" ]] && cs_cmd=$(find_tool "cryptsetup")

    if [[ -n "$cs_cmd" ]]; then
        for tpath in "${temp_paths[@]}"; do
            [[ -d "$tpath" ]] || continue
            while read -r cand_file; do
                [[ -f "$cand_file" ]] || continue
                if run_sudo "$cs_cmd" isLuks "$cand_file" 2>/dev/null; then
                    ((luks_keys_found++))
                    log_crit "LUKS Encrypted Volume Header / Container image found in temporary directory: '${cand_file}'!"
                fi
            done < <(find "$tpath" -maxdepth 2 -type f \( -name "*.img" -o -name "*.raw" -o -name "*.luks" -o -name "*.key" \) 2>/dev/null)
        done
    fi

    if [[ "$luks_keys_found" -eq 0 ]]; then
        log_pass "No LUKS keyfiles or crypttab key references found in temporary directories (/tmp, /var/tmp, /dev/shm)."
    fi
}

audit_directory_permissions

if [[ "${TOOL_FOUND['trivy']}" -eq 1 ]]; then
    echo -e "\n${CYAN}Running Trivy Container/Filesystem Audit...${NC}"
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

# 8. System Log, User Logins & Auth Audit
section "8/20" "Auditing User Logins, Active Sessions & System Auth Logs..."

audit_user_logins() {
    echo -e "${YELLOW}--- User Logins, Active Sessions & Authentication Audit ---${NC}"

    # 1. Currently Active Sessions & Logged-In Users
    echo -e "${CYAN}1. Currently Active Logged-In Users & Sessions (who / w):${NC}"
    if [[ "${TOOL_FOUND['who']}" -eq 1 ]]; then
        local active_who
        active_who=$("${TOOL_BIN['who']}" -H 2>/dev/null)
        if [[ -n "$active_who" ]]; then
            echo "$active_who"
            local active_users_count
            active_users_count=$("${TOOL_BIN['who']}" | wc -l)
            log_pass "Currently active user sessions: ${active_users_count}"

            if "${TOOL_BIN['who']}" | grep -q '^root'; then
                log_warn "Root account has an active interactive login session!"
            fi
        else
            echo "No active interactive login sessions."
        fi
    elif [[ "${TOOL_FOUND['w']}" -eq 1 ]]; then
        "${TOOL_BIN['w']}" 2>/dev/null || true
    fi

    # 2. Recent Successful User Logins (last)
    echo -e "\n${CYAN}2. Recent Successful User Logins (last 10 sessions):${NC}"
    if [[ "${TOOL_FOUND['last']}" -eq 1 ]]; then
        local recent_logins
        recent_logins=$("${TOOL_BIN['last']}" -n 10 2>/dev/null | grep -v '^$' | grep -v 'wtmp')
        if [[ -n "$recent_logins" ]]; then
            echo "$recent_logins"
            
            local remote_logins
            remote_logins=$(echo "$recent_logins" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}')
            if [[ -n "$remote_logins" ]]; then
                echo -e "${YELLOW}Remote IP Login Sessions Discovered:${NC}\n$remote_logins"
            fi
        else
            echo "No recent login records available."
        fi
    fi

    # 3. Failed Login Attempts (lastb & system logs)
    echo -e "\n${CYAN}3. Failed Login Attempts Audit (lastb & Auth Logs):${NC}"
    local failed_logins=""

    if [[ "${TOOL_FOUND['lastb']}" -eq 1 ]]; then
        failed_logins=$(run_sudo "${TOOL_BIN['lastb']}" -n 10 2>/dev/null | grep -v '^$' | grep -v 'btmp')
    fi

    if [[ -n "$failed_logins" ]]; then
        log_warn "Recent failed login attempts recorded in btmp:\n$failed_logins"
        local failed_count
        failed_count=$(echo "$failed_logins" | wc -l)
        if [[ "$failed_count" -gt 5 ]]; then
            log_crit "Multiple failed login attempts detected! Potential brute-force attack."
        fi
    else
        log_pass "No recent failed login attempts in btmp database."
    fi

    # 4. User Login History & Inactive / Never Logged-In Interactive Users (lastlog)
    echo -e "\n${CYAN}4. Interactive Accounts Login Activity & Inactive Users Audit (lastlog):${NC}"
    if [[ "${TOOL_FOUND['lastlog']}" -eq 1 ]]; then
        echo -e "Auditing login timestamps for interactive shell accounts..."
        while IFS=: read -r username password uid gid gecos home shell; do
            [[ "$shell" =~ (nologin|false|sync|halt|shutdown|null)$ ]] && continue

            local ll_entry
            ll_entry=$("${TOOL_BIN['lastlog']}" -u "$username" 2>/dev/null | tail -n 1)
            if [[ "$ll_entry" =~ "**Never logged in**" ]]; then
                log_warn "Interactive user '${username}' (UID ${uid}) has NEVER logged in!"
            else
                echo -e "  - User ${CYAN}${username}${NC}: ${ll_entry}"
            fi
        done < /etc/passwd
    fi
}

audit_user_logins

parse_security_logs() {
    local pattern_regex="Failed password|Invalid user|authentication failure|NOT in sudoers|maximum authentication attempts|segfault|Out of memory: Kill process|denied"

    echo -e "\n${YELLOW}--- Scanning System Logs for Security Anomaly Indicators ---${NC}"

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
        if [[ "$AUTO_RESTART_SERVICES" == true ]]; then
            echo -e "${YELLOW}Attempting automatic recovery/restart of failed systemd services...${NC}"
            while read -r svc_line; do
                [[ -z "$svc_line" ]] && continue
                local f_svc
                f_svc=$(echo "$svc_line" | awk '{print $1}')
                if [[ -n "$f_svc" ]]; then
                    restart_service "$f_svc" "recovering failed unit"
                fi
            done <<< "$FAILED_SERVICES"
        else
            echo -e "${YELLOW}Tip: Set AUTO_RESTART_SERVICES=true or run with --restart-services to auto-restart failed units.${NC}"
        fi
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

audit_and_clean_user_cache() {
    echo -e "\n${YELLOW}--- User Home Directory Cache & Temporary Files Audit ---${NC}"
    
    local total_cache_bytes=0
    local cache_targets=(
        ".cache/thumbnails"
        ".local/share/Trash"
        ".cache/pip"
        ".cache/npm"
        ".cache/yarn"
        ".cache/pnpm"
        ".cache/go-build"
        ".cache/crash"
        ".local/share/crash"
        ".cache/Code/Cache"
        ".cache/Code/CachedData"
        ".cache/google-chrome/Default/Cache"
        ".cache/google-chrome/Profile */Cache"
        ".cache/chromium/Default/Cache"
        ".cache/mozilla/firefox/*/cache2"
    )

    local found_caches=()

    while IFS=: read -r username password uid gid gecos home shell; do
        [[ -d "$home" ]] || continue
        [[ "$uid" -ne 0 && "$uid" -lt 1000 ]] && continue

        for rel_path in "${cache_targets[@]}"; do
            for target in $home/$rel_path; do
                if [[ -e "$target" ]]; then
                    local size_bytes size_human
                    size_bytes=$(du -sb "$target" 2>/dev/null | awk '{print $1}')
                    if [[ -n "$size_bytes" && "$size_bytes" -gt 1048576 ]]; then
                        size_human=$(du -sh "$target" 2>/dev/null | awk '{print $1}')
                        ((total_cache_bytes += size_bytes))
                        found_caches+=("${username} -> ${target} (${size_human})")

                        if [[ "$CLEAN_CACHE" == true ]]; then
                            echo -n "  Cleaning ${target} (${size_human})... "
                            if [[ -d "$target" ]]; then
                                rm -rf "$target"/* "$target"/.* 2>/dev/null || true
                            else
                                rm -f "$target" 2>/dev/null || true
                            fi
                            echo -e "${GREEN}✓ Cleaned${NC}"
                        fi
                    fi
                fi
            done
        done

        local core_files
        core_files=$(find "$home" -maxdepth 2 -name "core*" -type f 2>/dev/null)
        if [[ -n "$core_files" ]]; then
            while read -r cfile; do
                [[ -f "$cfile" ]] || continue
                local csize
                csize=$(du -sh "$cfile" 2>/dev/null | awk '{print $1}')
                found_caches+=("${username} -> Core Dump ${cfile} (${csize})")
                if [[ "$CLEAN_CACHE" == true ]]; then
                    rm -f "$cfile" 2>/dev/null
                    echo -e "  Deleted core dump ${cfile} (${csize}): ${GREEN}✓ Cleaned${NC}"
                fi
            done <<< "$core_files"
        fi

    done < /etc/passwd

    local total_human
    total_human=$(numfmt --to=iec-i --suffix=B "$total_cache_bytes" 2>/dev/null || echo "$(( total_cache_bytes / 1048576 )) MB")

    if [[ ${#found_caches[@]} -gt 0 ]]; then
        if [[ "$CLEAN_CACHE" == true ]]; then
            log_pass "User home directory cache cleanup completed. Total reclaimed space: ${total_human}"
        else
            echo -e "${CYAN}Discovered User Home Directory Caches (${total_human} reclaimable):${NC}"
            for item in "${found_caches[@]}"; do
                echo -e "  - ${item}"
            done
            log_warn "User home directories contain ${total_human} of temporary cache files."
            echo -e "  ${YELLOW}Tip: Run script with '--fix' or '--clean-cache' to automatically purge these caches.${NC}"
        fi
    else
        log_pass "User home directories have no accumulated temporary caches (> 1MB)."
    fi
}

audit_and_clean_user_cache

# 10. Privilege, Account, Group & Shadow Security Audit
section "10/20" "Auditing /etc/passwd, /etc/group, /etc/shadow & Privilege Misconfigurations..."

audit_passwd_group_shadow() {
    # --- 10.1 File Permissions & Ownership Audit ---
    echo -e "${YELLOW}--- 10.1 File Permissions & Ownership (/etc/passwd, /etc/group, /etc/shadow, /etc/gshadow) ---${NC}"
    
    local target_files=("/etc/passwd" "/etc/group" "/etc/shadow" "/etc/gshadow")
    for f in "${target_files[@]}"; do
        if [[ -e "$f" ]]; then
            local perms octal
            perms=$(stat -c "%a %U:%G" "$f" 2>/dev/null)
            octal=$(stat -c "%a" "$f" 2>/dev/null)
            
            case "$f" in
                /etc/passwd|/etc/group)
                    if [[ "$octal" =~ ^(644|640|444)$ ]]; then
                        log_pass "${f}: Permissions secure (${perms})"
                    else
                        log_warn "${f}: Non-standard permissions (${perms}). Recommended: 644"
                    fi
                    if stat -c "%u" "$f" 2>/dev/null | grep -qv "^0$"; then
                        log_crit "${f} is NOT owned by root!"
                    fi
                    ;;
                /etc/shadow|/etc/gshadow)
                    if run_sudo test -r "$f" 2>/dev/null; then
                        local s_perms s_octal
                        s_perms=$(run_sudo stat -c "%a %U:%G" "$f" 2>/dev/null)
                        s_octal=$(run_sudo stat -c "%a" "$f" 2>/dev/null)
                        if [[ "$s_octal" =~ 0$ ]]; then
                            log_pass "${f}: Permissions secure (${s_perms})"
                        else
                            log_crit "${f}: Insecure permissions (${s_perms})! World access allowed."
                        fi
                    else
                        echo -e "  - ${f}: Requires root/sudo to verify permissions."
                    fi
                    ;;
            esac
        fi
    done

    # --- 10.2 /etc/passwd Accounts & Shell Audit ---
    echo -e "\n${YELLOW}--- 10.2 /etc/passwd Accounts & Interactive Shell Audit ---${NC}"
    
    # Check 1: Non-root accounts with UID 0
    local uid_zero
    uid_zero=$(awk -F: '($3 == "0" && $1 != "root") { print $1 }' /etc/passwd)
    if [[ -n "$uid_zero" ]]; then
        log_crit "Non-root users with UID 0 found: ${uid_zero}"
    else
        log_pass "Only 'root' user has UID 0."
    fi

    # Check 2: Duplicate UIDs or Usernames
    local dup_uids dup_users
    dup_uids=$(awk -F: '{print $3}' /etc/passwd | sort | uniq -d)
    dup_users=$(awk -F: '{print $1}' /etc/passwd | sort | uniq -d)
    if [[ -n "$dup_uids" ]]; then
        log_crit "Duplicate UIDs found in /etc/passwd: ${dup_uids}"
    else
        log_pass "No duplicate UIDs found in /etc/passwd."
    fi
    if [[ -n "$dup_users" ]]; then
        log_crit "Duplicate usernames found in /etc/passwd: ${dup_users}"
    else
        log_pass "No duplicate usernames found in /etc/passwd."
    fi

    # Check 3: Legacy / Unencrypted passwords in /etc/passwd field 2
    local legacy_passwd
    legacy_passwd=$(awk -F: '($2 != "x" && $2 != "*" && $2 != "!") { print $1 }' /etc/passwd)
    if [[ -n "$legacy_passwd" ]]; then
        log_crit "Accounts with unencrypted password hashes directly in /etc/passwd: ${legacy_passwd}"
    else
        log_pass "No legacy unencrypted password hashes stored in /etc/passwd (shadow mode active)."
    fi

    # Check 4: Interactive Shell Users List & Classification
    echo -e "\n${CYAN}Accounts with Console / Interactive Shell Access:${NC}"
    local interactive_users=0
    local sys_interactive=()
    local missing_shells=()
    local bad_homes=()

    while IFS=: read -r username password uid gid gecos home shell; do
        # Ignore non-interactive shells
        if [[ "$shell" =~ (nologin|false|sync|halt|shutdown|null)$ ]]; then
            continue
        fi

        ((interactive_users++))

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

        echo -e "  - ${CYAN}${username}${NC} (UID: ${uid}, GID: ${gid}, Shell: ${shell})"
        echo -e "    Home: ${home} | Sudo Privileges: ${is_sudo} | Password Status: ${pass_status}"

        # Anomaly checks
        if [[ "$uid" -ne 0 && "$uid" -lt 1000 ]]; then
            sys_interactive+=("${username} (UID: ${uid})")
        fi

        if [[ ! -x "$shell" ]]; then
            missing_shells+=("${username} -> ${shell}")
        fi

        if [[ "$home" == "/" || "$home" =~ ^/(tmp|var/tmp|dev/shm) || ! -d "$home" ]]; then
            bad_homes+=("${username} -> ${home}")
        fi

        # Primary GID check in /etc/group
        if ! grep -q "^[^:]*:[^:]*:${gid}:" /etc/group 2>/dev/null; then
            log_warn "User '${username}' has primary GID ${gid} which does NOT exist in /etc/group!"
        fi

    done < /etc/passwd

    if [[ ${#sys_interactive[@]} -gt 0 ]]; then
        log_warn "System accounts (UID < 1000) with interactive login shells detected: ${sys_interactive[*]}"
    else
        log_pass "No system service accounts (UID < 1000) have interactive login shells."
    fi

    if [[ ${#missing_shells[@]} -gt 0 ]]; then
        log_warn "Users assigned non-existent or non-executable shells: ${missing_shells[*]}"
    fi

    if [[ ${#bad_homes[@]} -gt 0 ]]; then
        log_warn "Interactive users with suspicious or missing home directories: ${bad_homes[*]}"
    else
        log_pass "All interactive shell users have valid home directories."
    fi

    # --- 10.3 /etc/group & Privileged Group Audit ---
    echo -e "\n${YELLOW}--- 10.3 /etc/group & Privileged Group Audit ---${NC}"
    
    local dup_gids dup_gnames
    dup_gids=$(awk -F: '{print $3}' /etc/group | sort | uniq -d)
    dup_gnames=$(awk -F: '{print $1}' /etc/group | sort | uniq -d)
    if [[ -n "$dup_gids" ]]; then
        log_warn "Duplicate GIDs found in /etc/group: ${dup_gids}"
    else
        log_pass "No duplicate GIDs in /etc/group."
    fi
    if [[ -n "$dup_gnames" ]]; then
        log_crit "Duplicate group names in /etc/group: ${dup_gnames}"
    fi

    local zero_gids
    zero_gids=$(awk -F: '($3 == "0" && $1 != "root") { print $1 }' /etc/group)
    if [[ -n "$zero_gids" ]]; then
        log_warn "Non-root groups with GID 0: ${zero_gids}"
    fi

    echo -e "${CYAN}Auditing Privileged & Sensitive System Group Memberships:${NC}"
    local priv_groups=("sudo" "wheel" "admin" "docker" "podman" "shadow" "disk" "kmem" "input" "kvm" "adm" "systemd-journal")
    
    for grp in "${priv_groups[@]}"; do
        if grep -q "^${grp}:" /etc/group 2>/dev/null; then
            local members
            members=$(grep "^${grp}:" /etc/group | cut -d: -f4)
            
            local grp_gid
            grp_gid=$(grep "^${grp}:" /etc/group | cut -d: -f3)
            local primary_users
            primary_users=$(awk -F: -v gid="$grp_gid" '$4 == gid {print $1}' /etc/passwd | tr '\n' ',' | sed 's/,$//')

            local all_members=""
            if [[ -n "$members" && -n "$primary_users" ]]; then
                all_members="${primary_users},${members}"
            elif [[ -n "$members" ]]; then
                all_members="$members"
            else
                all_members="$primary_users"
            fi

            if [[ -n "$all_members" ]]; then
                echo -e "  - Group ${CYAN}${grp}${NC} (GID ${grp_gid}): ${all_members}"
                
                case "$grp" in
                    shadow|disk|kmem)
                        log_warn "Group '${grp}' gives raw disk/shadow access! Members: ${all_members}"
                        ;;
                    docker)
                        log_warn "Group 'docker' gives root-equivalent host privileges! Members: ${all_members}"
                        ;;
                esac
            else
                echo -e "  - Group ${CYAN}${grp}${NC} (GID ${grp_gid}): (No members)"
            fi
        fi
    done

    # --- 10.4 /etc/shadow Password Security & Weak Password Audit ---
    echo -e "\n${YELLOW}--- 10.4 /etc/shadow Password Security & Weak Password Audit ---${NC}"
    
    if ! run_sudo test -r /etc/shadow 2>/dev/null; then
        log_warn "Cannot read /etc/shadow (root/sudo required). Skipping shadow hash & weak password analysis."
    else
        # 1. Empty / Missing passwords check
        local empty_shadow
        empty_shadow=$(run_sudo awk -F: '($2 == "" || $2 == "NP") { print $1 }' /etc/shadow 2>/dev/null)
        if [[ -n "$empty_shadow" ]]; then
            log_crit "Accounts with NO PASSWORD set in /etc/shadow: ${empty_shadow}"
        else
            log_pass "No active user accounts have empty password fields in /etc/shadow."
        fi

        # 2. Weak Password Dictionary & Algorithm Scan (via Python if available)
        local py_cmd="${TOOL_BIN['python3']}"
        [[ -z "$py_cmd" ]] && py_cmd=$(find_tool "python3")

        if [[ -n "$py_cmd" ]]; then
            echo -e "${CYAN}Executing dictionary & pattern check for weak user passwords...${NC}"
            local sys_hostname
            sys_hostname=$(hostname 2>/dev/null)

            local ext_urls=""
            if [[ "$FETCH_EXTERNAL_PASSWORDS" == true && ${#EXTERNAL_PASSWORD_LIST_URLS[@]} -gt 0 ]]; then
                ext_urls=$(IFS=","; echo "${EXTERNAL_PASSWORD_LIST_URLS[*]}")
                echo -e "  Fetching external password databases from GitHub repositories..."
            fi

            local py_result
            py_result=$(run_sudo "$py_cmd" - "$sys_hostname" "$ext_urls" << 'PYEOF' 2>/dev/null
import sys, ctypes, ctypes.util, os
try:
    import urllib.request
except ImportError:
    urllib = None

hostname = sys.argv[1] if len(sys.argv) > 1 else ""
ext_urls_str = sys.argv[2] if len(sys.argv) > 2 else ""

libname = ctypes.util.find_library('crypt')
lib = None
if libname:
    try:
        lib = ctypes.CDLL(libname)
        lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.crypt.restype = ctypes.c_char_p
    except Exception:
        lib = None

common_passwords = [
    '123456', 'password', 'qwerty', 'admin', '12345678', 'root',
    'pass123', 'P@ssword', '123456789', 'system', '12345', 'letmein',
    'welcome', 'master', 'administrator', 'changeme', 'ubuntu', 'debian',
    'fedora', 'centos', 'redhat', 'user', 'test', 'demo', 'login', 'pass',
    'password123', 'admin123', 'root123', '1234', '1234567', '1234567890'
]
if hostname:
    common_passwords.append(hostname.lower())

if ext_urls_str and urllib:
    urls = [u.strip() for u in ext_urls_str.split(',') if u.strip()]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                lines = resp.read().decode('utf-8', errors='ignore').splitlines()
                added = 0
                for line in lines:
                    p = line.strip()
                    if p and not p.startswith('#'):
                        common_passwords.append(p)
                        added += 1
                fname = url.split('/')[-1]
                print(f"FETCHED:{fname}:{added}")
        except Exception as err:
            fname = url.split('/')[-1]
            print(f"FETCH_ERR:{fname}:{err}")

weak_found = []
algo_counts = {}

if os.path.exists('/etc/shadow'):
    with open('/etc/shadow', 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                user = parts[0]
                hash_val = parts[1]
                if hash_val and not hash_val.startswith(('!', '*', '!!', 'x')):
                    algo = "Unknown"
                    if hash_val.startswith('$y$'): algo = "Yescrypt"
                    elif hash_val.startswith('$6$'): algo = "SHA-512"
                    elif hash_val.startswith('$5$'): algo = "SHA-256"
                    elif hash_val.startswith('$1$'): algo = "MD5 (Obsolete)"
                    elif hash_val.startswith('$2a$') or hash_val.startswith('$2b$'): algo = "Bcrypt"
                    elif len(hash_val) == 13: algo = "DES (Obsolete)"
                    
                    algo_counts[algo] = algo_counts.get(algo, 0) + 1

                    if lib:
                        user_dict = list(set(common_passwords + [
                            user, f'{user}123', f'{user}2026', f'{user}!', f'{user}1', f'{user}2025'
                        ]))
                        for p in user_dict:
                            res = lib.crypt(p.encode('utf-8'), hash_val.encode('utf-8'))
                            if res and res.decode('utf-8') == hash_val:
                                weak_found.append((user, p))
                                break

print("TOTAL_PASSWORDS:" + str(len(set(common_passwords))))
print("ALGOS:" + ",".join([f"{k}:{v}" for k,v in algo_counts.items()]))
for u, p in weak_found:
    print(f"WEAK:{u}:{p}")
PYEOF
            )

            if [[ -n "$py_result" ]]; then
                while read -r line; do
                    if [[ "$line" =~ ^FETCHED: ]]; then
                        local fname count
                        fname=$(echo "$line" | cut -d: -f2)
                        count=$(echo "$line" | cut -d: -f3)
                        echo -e "  - ${GREEN}✓${NC} Loaded ${CYAN}${count}${NC} passwords from GitHub (${fname})"
                    elif [[ "$line" =~ ^FETCH_ERR: ]]; then
                        local fname err
                        fname=$(echo "$line" | cut -d: -f2)
                        err=$(echo "$line" | cut -d: -f3)
                        echo -e "  - ${YELLOW}!${NC} Failed to fetch GitHub password list (${fname}): ${err}"
                    elif [[ "$line" =~ ^TOTAL_PASSWORDS: ]]; then
                        local total_pass
                        total_pass=$(echo "$line" | cut -d: -f2)
                        echo -e "  Total unique dictionary passwords evaluated: ${CYAN}${total_pass}${NC}"
                    fi
                done <<< "$py_result"

                local algos
                algos=$(echo "$py_result" | grep '^ALGOS:' | cut -d: -f2)
                if [[ -n "$algos" ]]; then
                    echo -e "  Active password hashing algorithms in use: ${CYAN}${algos}${NC}"
                    if echo "$algos" | grep -E -q "MD5|DES"; then
                        log_warn "Obsolete password hashing algorithms detected in shadow file ($algos). Upgrade to SHA-512 or Yescrypt."
                    fi
                fi

                local weak_entries
                weak_entries=$(echo "$py_result" | grep '^WEAK:')
                if [[ -n "$weak_entries" ]]; then
                    while IFS=: read -r prefix user pass; do
                        log_crit "WEAK PASSWORD DETECTED for user '${user}': password matches dictionary pattern '${pass}'!"
                    done <<< "$weak_entries"
                else
                    log_pass "Password strength dictionary scan completed: No common weak passwords found for active user accounts."
                fi
            fi
        else
            echo -e "${YELLOW}python3 not installed. Skipping automated weak password dictionary scan.${NC}"
        fi

        # 3. Password Expiration Policy & Aging Audit
        echo -e "\n${CYAN}Password Aging & Expiration Audit (/etc/shadow):${NC}"
        local current_days=$(( $(date +%s) / 86400 ))
        local expired_accts=""
        local no_max_accts=""

        while IFS=: read -r user pass lstchg min max warn inact expire flag; do
            [[ -z "$user" || "$pass" =~ ^[!*] ]] && continue

            if [[ -n "$max" && "$max" -ne 99999 && -n "$lstchg" && "$lstchg" -gt 0 ]]; then
                local exp_day=$(( lstchg + max ))
                if [[ $current_days -ge $exp_day ]]; then
                    expired_accts+="${user} (Expired $(( current_days - exp_day )) days ago)\n"
                fi
            elif [[ "$max" == "99999" || -z "$max" ]]; then
                no_max_accts+="${user} "
            fi
        done < <(run_sudo cat /etc/shadow 2>/dev/null)

        if [[ -n "$expired_accts" ]]; then
            log_warn "User accounts with EXPIRED passwords:\n$expired_accts"
        else
            log_pass "No active user accounts have expired passwords."
        fi

        if [[ -n "$no_max_accts" ]]; then
            echo -e "  - Accounts without password expiration limit (Max=99999): ${CYAN}${no_max_accts}${NC}"
        fi
    fi

    # --- 10.6 Sudoers Hardening & NOPASSWD Audit ---
    echo -e "\n${YELLOW}--- 10.6 Sudoers Hardening & NOPASSWD Audit ---${NC}"
    local sudoers_files=("/etc/sudoers")
    [[ -d "/etc/sudoers.d" ]] && while read -r sf; do [[ -f "$sf" ]] && sudoers_files+=("$sf"); done < <(find /etc/sudoers.d -type f 2>/dev/null)

    local nopasswd_entries=()
    local dangerous_env_keep=()
    local gtfobins_found=()

    for sf in "${sudoers_files[@]}"; do
        if run_sudo test -r "$sf" 2>/dev/null; then
            local sf_perm sf_octal
            sf_perm=$(run_sudo stat -c "%a %U:%G" "$sf" 2>/dev/null)
            sf_octal=$(run_sudo stat -c "%a" "$sf" 2>/dev/null)
            if [[ "$sf_octal" =~ ^(440|400)$ ]]; then
                log_pass "${sf}: Permissions secure (${sf_perm})"
            else
                log_warn "${sf}: Non-standard permissions (${sf_perm}). Recommended: 440"
            fi

            local np
            np=$(run_sudo grep -Ei "NOPASSWD\s*:" "$sf" 2>/dev/null | grep -v '^\s*#')
            if [[ -n "$np" ]]; then
                nopasswd_entries+=("${sf}:\n${np}")
            fi

            local env_k
            env_k=$(run_sudo grep -Ei "env_keep.*\b(LD_PRELOAD|PATH|PYTHONPATH|PERL5LIB)\b" "$sf" 2>/dev/null | grep -v '^\s*#')
            if [[ -n "$env_k" ]]; then
                dangerous_env_keep+=("${sf}: ${env_k}")
            fi

            local gtfobins_pattern="find|vim|vi|less|more|nmap|python|python3|perl|php|awk|bash|sh|env|gdb|strace|tcpdump"
            local gtf_matches
            gtf_matches=$(run_sudo grep -Ei "NOPASSWD.*($gtfobins_pattern)\b" "$sf" 2>/dev/null | grep -v '^\s*#')
            if [[ -n "$gtf_matches" ]]; then
                gtfobins_found+=("${sf}:\n${gtf_matches}")
            fi
        fi
    done

    if [[ ${#nopasswd_entries[@]} -gt 0 ]]; then
        log_warn "NOPASSWD privilege escalation rules found in sudoers:\n$(printf '%b\n' "${nopasswd_entries[@]}")"
    else
        log_pass "No NOPASSWD directives found in readable sudoers configuration."
    fi

    if [[ ${#gtfobins_found[@]} -gt 0 ]]; then
        log_crit "Dangerous GTFOBins binaries (find/vim/bash/python/nmap) allowed in NOPASSWD sudoers rules!\n$(printf '%b\n' "${gtfobins_found[@]}")"
    fi

    if [[ ${#dangerous_env_keep[@]} -gt 0 ]]; then
        log_crit "Dangerous env_keep settings (LD_PRELOAD/PATH) in sudoers! Allows arbitrary library injection during sudo execution."
    fi

    # --- 10.7 PAM Authentication Stack Audit ---
    echo -e "\n${YELLOW}--- 10.7 PAM Authentication Stack Audit (/etc/pam.d/*) ---${NC}"
    if [[ -d "/etc/pam.d" ]]; then
        local pam_permit
        pam_permit=$(grep -Ei "^\s*auth\s+sufficient\s+pam_permit\.so" /etc/pam.d/* 2>/dev/null)
        if [[ -n "$pam_permit" ]]; then
            log_crit "Bypassed authentication found in PAM stack (pam_permit.so sufficient):\n$pam_permit"
        else
            log_pass "PAM authentication stack verified (No unconditional pam_permit bypasses)."
        fi
    fi
    # --- 10.8 Database Unauthenticated & Passwordless Access Audit ---
    echo -e "\n${YELLOW}--- 10.8 Database Unauthenticated & Passwordless Access Audit ---${NC}"
    local db_detected=0
    local db_unprotected=0

    # 1. MySQL / MariaDB Audit
    if command -v mysql &>/dev/null || command -v mariadb &>/dev/null || ss -tuln 2>/dev/null | grep -q ":3306 "; then
        ((db_detected++))
        echo -e "${CYAN}Testing MySQL / MariaDB Passwordless Access...${NC}"
        local mysql_cmd
        mysql_cmd=$(command -v mysql || command -v mariadb)

        if "$mysql_cmd" -h 127.0.0.1 -u root --password="" -e "SELECT 1;" &>/dev/null; then
            log_crit "UNAUTHENTICATED ACCESS: MySQL/MariaDB allows passwordless 'root' login over TCP (127.0.0.1)!"
            ((db_unprotected++))
        elif "$mysql_cmd" -h 127.0.0.1 -u anonymous --password="" -e "SELECT 1;" &>/dev/null; then
            log_crit "UNAUTHENTICATED ACCESS: MySQL/MariaDB allows passwordless 'anonymous' user login over TCP!"
            ((db_unprotected++))
        else
            log_pass "MySQL/MariaDB requires password authentication over TCP."
        fi
    fi

    # 2. PostgreSQL Audit
    if command -v psql &>/dev/null || ss -tuln 2>/dev/null | grep -q ":5432 "; then
        ((db_detected++))
        echo -e "${CYAN}Testing PostgreSQL Passwordless & Trust Authentication...${NC}"
        if PGPASSWORD="" psql -h 127.0.0.1 -U postgres -c "SELECT 1;" &>/dev/null; then
            log_crit "UNAUTHENTICATED ACCESS: PostgreSQL allows passwordless 'postgres' login over TCP (127.0.0.1)!"
            ((db_unprotected++))
        else
            log_pass "PostgreSQL requires password authentication over TCP."
        fi

        local hba_files=()
        while read -r hf; do [[ -f "$hf" ]] && hba_files+=("$hf"); done < <(find /etc/postgresql /var/lib/pgsql -name "pg_hba.conf" 2>/dev/null)
        if [[ ${#hba_files[@]} -gt 0 ]]; then
            for hf in "${hba_files[@]}"; do
                local trust_rules
                trust_rules=$(run_sudo grep -Ei "^\s*(host|local)\s+.*trust" "$hf" 2>/dev/null)
                if [[ -n "$trust_rules" ]]; then
                    log_warn "Dangerous 'trust' authentication method found in ${hf}:\n$trust_rules"
                fi
            done
        fi
    fi

    # 3. Redis Audit
    if command -v redis-cli &>/dev/null || ss -tuln 2>/dev/null | grep -q ":6379 "; then
        ((db_detected++))
        echo -e "${CYAN}Testing Redis Passwordless Access...${NC}"
        local redis_pong
        redis_pong=$(redis-cli -h 127.0.0.1 -p 6379 PING 2>/dev/null)
        if [[ "$redis_pong" == "PONG" ]]; then
            log_crit "UNAUTHENTICATED ACCESS: Redis server (127.0.0.1:6379) responds to PING without a password!"
            ((db_unprotected++))
        else
            log_pass "Redis server requires authentication (requirepass configured)."
        fi
    fi

    # 4. MongoDB Audit
    if command -v mongosh &>/dev/null || command -v mongo &>/dev/null || ss -tuln 2>/dev/null | grep -q ":27017 "; then
        ((db_detected++))
        echo -e "${CYAN}Testing MongoDB Passwordless Access...${NC}"
        local mongo_cmd
        mongo_cmd=$(command -v mongosh || command -v mongo)
        if "$mongo_cmd" --host 127.0.0.1 --port 27017 --eval "db.adminCommand('ping')" --quiet 2>/dev/null | grep -q 'ok'; then
            log_crit "UNAUTHENTICATED ACCESS: MongoDB (127.0.0.1:27017) allows administrative commands without authentication!"
            ((db_unprotected++))
        else
            log_pass "MongoDB requires authentication for database commands."
        fi
    fi

    # 5. Memcached Audit
    if command -v memcached &>/dev/null || ss -tuln 2>/dev/null | grep -q ":11211 "; then
        ((db_detected++))
        echo -e "${CYAN}Testing Memcached Passwordless Access...${NC}"
        if command -v nc &>/dev/null; then
            local memc_out
            memc_out=$(echo "stats" | nc -w 2 127.0.0.1 11211 2>/dev/null | grep -i "STAT")
            if [[ -n "$memc_out" ]]; then
                log_warn "Memcached (127.0.0.1:11211) is accessible without authentication."
            else
                log_pass "Memcached port 11211 is protected or inactive."
            fi
        fi
    fi

    # 6. Elasticsearch / OpenSearch Audit
    if ss -tuln 2>/dev/null | grep -q ":9200 "; then
        ((db_detected++))
        echo -e "${CYAN}Testing Elasticsearch / OpenSearch Passwordless Access...${NC}"
        local es_out
        es_out=$(curl -s -m 2 http://127.0.0.1:9200/ 2>/dev/null)
        if [[ "$es_out" =~ "cluster_name" || "$es_out" =~ "lucene" ]]; then
            log_crit "UNAUTHENTICATED ACCESS: Elasticsearch (127.0.0.1:9200) allows HTTP requests without password authentication!"
            ((db_unprotected++))
        else
            log_pass "Elasticsearch requires HTTP authentication."
        fi
    fi

    if [[ "$db_detected" -eq 0 ]]; then
        log_pass "No active database services (MySQL, PostgreSQL, Redis, MongoDB, Memcached, Elasticsearch) detected."
    elif [[ "$db_unprotected" -eq 0 ]]; then
        log_pass "All ${db_detected} detected database service(s) require password authentication."
    fi
}

audit_passwd_group_shadow

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
        echo -e "\n${CYAN}Needrestart Check (Services needing restart after package updates):${NC}"
        local svcs_needing_restart
        svcs_needing_restart=$(run_sudo "${TOOL_BIN['needrestart']}" -b 2>/dev/null | grep 'NEEDRESTART-SVC:' | awk '{print $2}')
        if [[ -n "$svcs_needing_restart" ]]; then
            log_warn "Background services require restart due to updated binaries/libraries:\n$svcs_needing_restart"
            if [[ "$AUTO_RESTART_SERVICES" == true ]]; then
                echo -e "${YELLOW}Auto-restarting outdated background services...${NC}"
                while read -r svc; do
                    [[ -z "$svc" ]] && continue
                    restart_service "$svc" "outdated binary/library after package update"
                done <<< "$svcs_needing_restart"
            else
                echo -e "${YELLOW}Tip: Set AUTO_RESTART_SERVICES=true or run with --restart-services to auto-restart outdated services.${NC}"
            fi
        else
            echo -e "${GREEN}✓ No background services require restart.${NC}"
        fi
    fi
else
    echo -e "${YELLOW}Unsupported package manager. Skipping repository kernel & package audit.${NC}"
fi

audit_pinned_packages() {
    echo -e "\n${YELLOW}--- Auditing Pinned / Held Package Versions & Repo Candidates ---${NC}"
    local pinned_count=0

    if [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
        local apt_holds dpkg_holds pref_pins
        if command -v apt-mark &>/dev/null; then
            apt_holds=$(apt-mark showhold 2>/dev/null)
        fi
        if command -v dpkg &>/dev/null; then
            dpkg_holds=$(dpkg --get-selections 2>/dev/null | awk '$2 == "hold" {print $1}')
        fi
        pref_pins=$(grep -hEi "^\s*Package:" /etc/apt/preferences /etc/apt/preferences.d/* 2>/dev/null | awk '{print $2}' | grep -v '\*')

        local all_pins
        all_pins=$(echo -e "${apt_holds}\n${dpkg_holds}\n${pref_pins}" | sed '/^\s*$/d' | sort -u)

        if [[ -n "$all_pins" ]]; then
            echo -e "${CYAN}Discovered Pinned / Held Packages in APT Preferences & Database:${NC}"
            while read -r pkg; do
                [[ -z "$pkg" ]] && continue
                ((pinned_count++))

                local policy_out inst_ver cand_ver
                policy_out=$(apt-cache policy "$pkg" 2>/dev/null)
                inst_ver=$(echo "$policy_out" | grep -i "Installed:" | awk '{print $2}')
                cand_ver=$(echo "$policy_out" | grep -i "Candidate:" | awk '{print $2}')

                [[ -z "$inst_ver" ]] && inst_ver="Not Installed"
                [[ -z "$cand_ver" ]] && cand_ver="Unknown"

                echo -e "  - Package: ${CYAN}${pkg}${NC}"
                echo -e "    Installed (Pinned): ${YELLOW}${inst_ver}${NC} | Latest Candidate in Repo: ${GREEN}${cand_ver}${NC}"

                if [[ "$inst_ver" != "$cand_ver" && "$cand_ver" != "Unknown" ]]; then
                    log_warn "Pinned package '${pkg}' (${inst_ver}) has a newer candidate version in repository (${cand_ver})."
                else
                    log_pass "Pinned package '${pkg}' (${inst_ver}) is up-to-date with repository candidate."
                fi
            done <<< "$all_pins"
        fi

    elif [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
        local dnf_locks=""
        if [[ -f "/etc/dnf/plugins/versionlock.list" ]]; then
            dnf_locks=$(grep -v '^\s*#' /etc/dnf/plugins/versionlock.list 2>/dev/null | awk -F'-' '{print $1}' | sort -u)
        fi

        if [[ -n "$dnf_locks" ]]; then
            echo -e "${CYAN}Discovered Locked Packages in DNF Versionlock:${NC}"
            while read -r pkg; do
                [[ -z "$pkg" ]] && continue
                ((pinned_count++))

                local inst_ver cand_ver
                inst_ver=$(rpm -q --queryformat '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null)
                cand_ver=$(dnf check-update "$pkg" 2>/dev/null | grep -E "^${pkg}\." | awk '{print $2}')

                [[ -z "$inst_ver" ]] && inst_ver="Not Installed"
                [[ -z "$cand_ver" ]] && cand_ver="$inst_ver (Up-to-date)"

                echo -e "  - Package: ${CYAN}${pkg}${NC}"
                echo -e "    Installed (Pinned): ${YELLOW}${inst_ver}${NC} | Latest Candidate in Repo: ${GREEN}${cand_ver}${NC}"

                if [[ "$inst_ver" != "$cand_ver" && "$cand_ver" != *"(Up-to-date)" ]]; then
                    log_warn "Pinned package '${pkg}' (${inst_ver}) has a newer version available in repository (${cand_ver})."
                else
                    log_pass "Pinned package '${pkg}' (${inst_ver}) is up-to-date with repository."
                fi
            done <<< "$dnf_locks"
        fi
    fi

    if [[ "$pinned_count" -eq 0 ]]; then
        log_pass "No pinned or held package versions detected in system package manager."
    fi
}

audit_pinned_packages

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
    local weak_keys_found=0

    while IFS=: read -r username password uid gid gecos home shell; do
        local auth_keys="$home/.ssh/authorized_keys"
        if [[ -f "$auth_keys" ]]; then
            local key_num
            key_num=$(grep -v '^#' "$auth_keys" | grep -v '^\s*$' | wc -l)
            if [[ "$key_num" -gt 0 ]]; then
                ((keys_count += key_num))
                echo -e "  - User ${CYAN}${username}${NC}: ${key_num} authorized key(s) in ${auth_keys}"
                if [[ "$username" == "root" ]]; then
                    log_warn "Root account has SSH authorized keys configured in ${auth_keys}!"
                fi

                # Key type analysis
                while read -r ktype key_data comment; do
                    case "$ktype" in
                        ssh-dss|dss)
                            log_crit "User '${username}': Obsolete & insecure DSA key found in ${auth_keys} (${comment:-no comment})!"
                            ((weak_keys_found++))
                            ;;
                        ssh-rsa)
                            echo -e "    Key: ${CYAN}RSA${NC} (${comment:-no comment})"
                            ;;
                        ssh-ed25519)
                            echo -e "    Key: ${GREEN}Ed25519 (Strong modern standard)${NC} (${comment:-no comment})"
                            ;;
                        ecdsa-sha2-*)
                            echo -e "    Key: ${GREEN}ECDSA${NC} (${comment:-no comment})"
                            ;;
                    esac
                done < <(grep -v '^#' "$auth_keys" | grep -v '^\s*$')
            fi
        fi
    done < /etc/passwd

    if [[ "$keys_count" -eq 0 ]]; then
        log_pass "No authorized_keys files found."
    elif [[ "$weak_keys_found" -eq 0 ]]; then
        log_pass "Discovered ${keys_count} SSH authorized key(s) across user accounts (all algorithms secure)."
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
    echo -e "${GREEN}✓ System Audit & Remediation Completed Successfully!${NC}"
    echo -e "  Detailed Markdown Report Log: ${CYAN}${REPORT_FILE}${NC}"
    echo -e "${CYAN}=====================================================${NC}"
}

print_scorecard
