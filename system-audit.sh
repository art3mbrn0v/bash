# ==============================================================================

# Script directory resolution
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Output colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration & Execution Modes (Fully Automated Execution by Default)
AUTO_FIX=true
CLEAN_CACHE=true
GENERATE_REPORT=true
AUTO_RESTART_SERVICES=true
INSTALL_MISSING_PKGS=true
FETCH_EXTERNAL_PASSWORDS=true
REPORT_DIR="${SCRIPT_DIR}/reports"

# Sensitive file and credential pattern definitions for security auditing
SENSITIVE_PATTERNS=(
    "password" "secret" "token" "passwd" "auth.db"
    "credentials" "api_key" "access_key" "private_key" "id_rsa"
    "account_info" "pass_keys" "access_keys"
)

# External public password databases for weak password dictionary checks
EXTERNAL_PASSWORD_LIST_URLS=(
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/500-worst-passwords.txt"
    "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt"
)

# Persistent cache for the weak-password dictionary:
# raw source files + one combined deduplicated dictionary. Kept between runs;
# a source is re-downloaded only if its remote size differs from the cached copy.
DICT_CACHE_DIR="${REPORT_DIR}/password-dict-cache"
DICT_FILE="${DICT_CACHE_DIR}/combined-dict.txt"
DICT_DOWNLOAD_TIMEOUT_SEC=300   # overall download budget: 5 minutes

fetch_external_password_lists() {
    echo -e "${YELLOW}--- Weak Password Dictionary Cache (GitHub sources) ---${NC}"
    mkdir -p "$DICT_CACHE_DIR" 2>/dev/null
    chmod 700 "$DICT_CACHE_DIR" 2>/dev/null

    # Choose an available download tool
    local fetch_cmd=""
    if [[ "${TOOL_FOUND['curl']}" -eq 1 ]]; then
        fetch_cmd="curl"
    elif [[ "${TOOL_FOUND['wget']}" -eq 1 ]]; then
        fetch_cmd="wget"
    else
        echo -e "  ${YELLOW}Neither curl nor wget available: cannot refresh dictionary cache.${NC}"
        [[ -s "$DICT_FILE" ]] && echo -e "  ${CYAN}Using existing cached dictionary: ${DICT_FILE}${NC}"
        return 0
    fi

    local dl_start now elapsed rem
    dl_start=$(date +%s)
    local downloaded=0 skipped=0 failed=0
    local raw_files=()

    for url in "${EXTERNAL_PASSWORD_LIST_URLS[@]}"; do
        now=$(date +%s); elapsed=$(( now - dl_start ))
        if [[ "$elapsed" -ge "$DICT_DOWNLOAD_TIMEOUT_SEC" ]]; then
            echo -e "  ${YELLOW}! Download budget (${DICT_DOWNLOAD_TIMEOUT_SEC}s) reached; continuing with sources fetched so far.${NC}"
            break
        fi
        rem=$(( DICT_DOWNLOAD_TIMEOUT_SEC - elapsed ))

        local fname="${url##*/}"
        local dest="$DICT_CACHE_DIR/$fname"

        # Cache hit check: skip download if the cached file size matches the remote size
        if [[ -s "$dest" ]]; then
            local remote_size="" local_size
            if [[ "$fetch_cmd" == "curl" ]]; then
                remote_size=$(curl -sIL --max-time 20 "$url" 2>/dev/null | grep -i '^Content-Length:' | tail -n 1 | tr -dc '0-9')
            else
                remote_size=$(wget --spider -S --timeout=20 "$url" 2>&1 | grep -i 'Content-Length' | tail -n 1 | tr -dc '0-9')
            fi
            local_size=$(stat -c %s "$dest" 2>/dev/null || echo 0)
            if [[ -n "$remote_size" && "$remote_size" == "$local_size" ]]; then
                echo -e "  - ${CYAN}${fname}${NC}: cache up to date (${local_size} bytes) - download skipped."
                skipped=$((skipped + 1))
                raw_files+=("$dest")
                continue
            fi
        fi

        echo -n "  Downloading ${fname}... "
        if [[ "$fetch_cmd" == "curl" ]]; then
            if curl -sL --max-time "$rem" -o "${dest}.tmp" "$url" 2>/dev/null && [[ -s "${dest}.tmp" ]]; then
                mv -f "${dest}.tmp" "$dest"
                echo -e "${GREEN}OK${NC} ($(stat -c %s "$dest") bytes)"
                downloaded=$((downloaded + 1))
                raw_files+=("$dest")
            else
                rm -f "${dest}.tmp"
                echo -e "${YELLOW}FAILED${NC}"
                failed=$((failed + 1))
                [[ -s "$dest" ]] && raw_files+=("$dest")
            fi
        else
            if wget -q --timeout="$rem" -O "${dest}.tmp" "$url" 2>/dev/null && [[ -s "${dest}.tmp" ]]; then
                mv -f "${dest}.tmp" "$dest"
                echo -e "${GREEN}OK${NC} ($(stat -c %s "$dest") bytes)"
                downloaded=$((downloaded + 1))
                raw_files+=("$dest")
            else
                rm -f "${dest}.tmp"
                echo -e "${YELLOW}FAILED${NC}"
                failed=$((failed + 1))
                [[ -s "$dest" ]] && raw_files+=("$dest")
            fi
        fi
    done

    # Build / refresh the single combined deduplicated dictionary
    if [[ ${#raw_files[@]} -gt 0 ]]; then
        echo -n "  Building combined dictionary (deduplicated, sorted)... "
        cat "${raw_files[@]}" 2>/dev/null | tr -d '\r' | grep -vE '^\s*(#|$)' | sort -u > "${DICT_FILE}.tmp"
        if [[ -s "${DICT_FILE}.tmp" ]]; then
            mv -f "${DICT_FILE}.tmp" "$DICT_FILE"
            chmod 600 "$DICT_FILE" 2>/dev/null
            local dict_count
            dict_count=$(wc -l < "$DICT_FILE")
            echo -e "${GREEN}OK${NC} ($(stat -c %s "$DICT_FILE") bytes, ${dict_count} unique passwords)"
        else
            rm -f "${DICT_FILE}.tmp"
            echo -e "${YELLOW}FAILED (kept previous dictionary if any)${NC}"
        fi
    fi

    echo -e "  Dictionary cache summary: ${CYAN}${downloaded} downloaded, ${skipped} reused from cache, ${failed} failed${NC}"
    echo -e "  Cached dictionary file: ${CYAN}${DICT_FILE}${NC} (kept for future runs)"
}

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

# Audit Timestamp & Execution Time Tracking
AUDIT_START_TIME_SEC=$(date +%s)
AUDIT_START_TIME_STR=$(date "+%Y-%m-%d %H:%M:%S %Z")

# Automatic Report Teeing (Markdown Log Generation)
mkdir -p "$REPORT_DIR" 2>/dev/null || true
REPORT_FILE="$REPORT_DIR/audit-report-$(date +%Y-%m-%d_%H-%M-%S).md"
touch "$REPORT_FILE" && chmod 600 "$REPORT_FILE" 2>/dev/null || true
exec > >(tee >(sed -r 's/\x1B\[[0-9;]*[mK]//g' > "$REPORT_FILE")) 2>&1

echo -e "${CYAN}=====================================================${NC}"
echo -e "${CYAN}=== Starting System Security & Optimization Audit ===${NC}"
echo -e "${CYAN}=====================================================${NC}"
echo -e "Audit Started At : ${CYAN}${AUDIT_START_TIME_STR}${NC}"

# --- Helper Functions & Tool Resolution ---

section() {
    echo -e "\n${BLUE}[$1] $2${NC}"
}

log_pass() {
    PASSED_COUNT=$((PASSED_COUNT + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo -e "${GREEN}[OK] $1${NC}"
}

log_warn() {
    WARNING_COUNT=$((WARNING_COUNT + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo -e "${YELLOW}[WARN] $1${NC}"
}

log_crit() {
    CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    echo -e "${RED}CRITICAL: $1${NC}"
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
            AUDIT_INSTALLED_PKGS["$pkg"]=1
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
            AUDIT_INSTALLED_PKGS["$pkg"]=1
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

# Helper function to apply runbook-based automatic permission & system remediations
apply_runbook_permission_remediations() {
    echo -e "${YELLOW}--- Applying System Runbook Automatic Permission & System Fixes ---${NC}"
    local runbook_count=0

    # 1. Fix PAM wtmpdb SQLite Database Permissions (/var/log/wtmp.db -> root:utmp 664)
    if [[ -f "/var/log/wtmp.db" ]]; then
        local w_perm w_owner
        w_perm=$(stat -c "%a" /var/log/wtmp.db 2>/dev/null)
        w_owner=$(stat -c "%U:%G" /var/log/wtmp.db 2>/dev/null)

        if [[ "$w_owner" != "root:utmp" || "$w_perm" != "664" ]]; then
            echo -e "  - ${YELLOW}System Runbook Sec 2.3:${NC} Fixing /var/log/wtmp.db permissions (${w_owner} ${w_perm} -> root:utmp 664)..."
            if run_sudo chown root:utmp /var/log/wtmp.db 2>/dev/null && run_sudo chmod 664 /var/log/wtmp.db 2>/dev/null; then
                log_pass "Fixed /var/log/wtmp.db permissions to root:utmp 664 (Resolved PAM wtmpdb SQLITE_READONLY error 8)."
                ((runbook_count++))
            else
                log_warn "Failed to set /var/log/wtmp.db permissions to root:utmp 664."
            fi
        else
            log_pass "/var/log/wtmp.db permissions verified (root:utmp 664)."
        fi
    fi

    # 2. Fix GTK 3 Theme Parsing Syntax Error (!important in ~/.config/gtk-3.0/gtk.css)
    while IFS=: read -r username password uid gid gecos home shell; do
        [[ -d "$home" ]] || continue
        local gtk_css="$home/.config/gtk-3.0/gtk.css"
        if [[ -f "$gtk_css" ]] && grep -q "!important" "$gtk_css" 2>/dev/null; then
            echo -e "  - ${YELLOW}System Runbook Sec 2.1:${NC} Removing '!important' from ${gtk_css} for user ${username}..."
            sed -i 's/\s*!important//g' "$gtk_css" 2>/dev/null
            log_pass "Removed '!important' from ${gtk_css} (Resolved GTK 3 CSS theme parsing errors)."
            ((runbook_count++))
        fi
    done < /etc/passwd

    # 3. Fix ALSA Restore Udev Rule GOTO Label Mismatch
    if [[ -f "/usr/lib/udev/rules.d/90-alsa-restore.rules" ]] && grep -q 'LABEL="alsa_restore_go"' /usr/lib/udev/rules.d/90-alsa-restore.rules 2>/dev/null; then
        if [[ ! -f "/etc/udev/rules.d/90-alsa-restore.rules" ]] || grep -q 'LABEL="alsa_restore_go"' /etc/udev/rules.d/90-alsa-restore.rules 2>/dev/null; then
            echo -e "  - ${YELLOW}System Runbook Sec 2.2:${NC} Creating override /etc/udev/rules.d/90-alsa-restore.rules to fix GOTO label mismatch..."
            run_sudo mkdir -p /etc/udev/rules.d 2>/dev/null
            run_sudo cp /usr/lib/udev/rules.d/90-alsa-restore.rules /etc/udev/rules.d/ 2>/dev/null
            run_sudo sed -i 's/LABEL="alsa_restore_go"/LABEL="alsa_restore_std"/2' /etc/udev/rules.d/90-alsa-restore.rules 2>/dev/null
            if command -v udevadm &>/dev/null; then
                run_sudo udevadm control --reload-rules 2>/dev/null || true
            fi
            log_pass "Created fixed udev rule /etc/udev/rules.d/90-alsa-restore.rules (LABEL=alsa_restore_std)."
            ((runbook_count++))
        fi
    fi

    if [[ "$runbook_count" -gt 0 ]]; then
        echo -e "  ${GREEN}[OK] Applied ${runbook_count} runbook-based automatic permission/system fix(es).${NC}\n"
    fi
}

# --- Tool Cache & Pre-Flight Dependency Inspection ---
# Tool cache arrays for tracking availability and binary paths
declare -A TOOL_BIN
declare -A TOOL_FOUND

# Packages installed BY THIS SCRIPT during the current run.
# Used by the post-audit cleanup to remove only our own footprint,
# never touching packages that existed on the system before the audit.
declare -A AUDIT_INSTALLED_PKGS

# List of critical system and security tools checked during pre-flight
TOOLS_TO_CHECK=(
    "sudo" "systemctl" "journalctl" "ss" "sysctl" "ssh-keygen" 
    "crontab" "ip" "df" "awk" "grep" "sed" "find" "clamscan" 
    "freshclam" "chkrootkit" "trivy" "nmcli" "nmap" "docker" "podman"
    "apt-get" "dnf" "rpm" "dpkg-query" "lynis" "needrestart" "debsums"
    "python3" "pwck" "grpck" "who" "w" "last" "lastb" "lastlog"
    "curl" "wget" "cryptsetup" "unhide" "lsusb" "lsblk" "lspci" "bluetoothctl" "mokutil"
)

# Inspect system for required tools and auto-install missing security packages
check_all_dependencies() {
    echo -e "${YELLOW}=== Pre-Flight Security Tools & Dependency Check ===${NC}"
    local missing_tools=()

    for tool in "${TOOLS_TO_CHECK[@]}"; do
        local path
        path=$(find_tool "$tool")
        if [[ -n "$path" ]]; then
            TOOL_BIN["$tool"]="$path"
            TOOL_FOUND["$tool"]=1
            printf "  [${GREEN}OK${NC}] %-15s : Installed (%s)\n" "$tool" "$path"
        else
            TOOL_FOUND["$tool"]=0
            printf "  [${YELLOW}!${NC}] %-15s : ${YELLOW}NOT installed${NC}\n" "$tool"
            case "$tool" in
                clamscan|freshclam|chkrootkit|trivy|nmap|lynis|needrestart|debsums)
                    missing_tools+=("$tool")
                    ;;
            esac
        fi
    done

    # Automatically install missing recommended security tools if enabled
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
                    chkrootkit)
                        install_pkg_and_restart_service "chkrootkit" ""
                        ;;
                    trivy)
                        install_pkg_and_restart_service "trivy" ""
                        ;;
                    *)
                        install_pkg_and_restart_service "$m_tool" "$m_tool"
                        ;;
                esac
            done

            # Re-resolve tool paths after installation:
            # e.g. installing the 'clamav' package provides clamscan/freshclam binaries.
            for tool in "${TOOLS_TO_CHECK[@]}"; do
                if [[ "${TOOL_FOUND[$tool]}" -eq 0 ]]; then
                    local newpath
                    newpath=$(find_tool "$tool")
                    if [[ -n "$newpath" ]]; then
                        TOOL_BIN["$tool"]="$newpath"
                        TOOL_FOUND["$tool"]=1
                        printf "  [${GREEN}OK${NC}] %-15s : Now available (%s)\n" "$tool" "$newpath"
                    fi
                fi
            done
        else
            echo -e "\n${YELLOW}Recommended Security Tools Installation Tip:${NC}"
            if [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
                echo -e "  Debian/Ubuntu: ${CYAN}sudo apt install ${missing_tools[*]}${NC}"
            elif [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
                echo -e "  Fedora/RHEL:   ${CYAN}sudo dnf install ${missing_tools[*]}${NC}"
            fi
            echo -e "  Tip: Set INSTALL_MISSING_PKGS=true to auto-install missing tools & start services."
        fi
    fi
    echo ""
}

check_all_dependencies

# Apply automatic security fixes and permission hardening
if [[ "$AUTO_FIX" == true ]]; then
    echo -e "${YELLOW}=== Running in Auto-Fix Mode (--fix enabled) ===${NC}"
    # Harden ~/.ssh for root and for every real user home (not just $HOME of the invoking user)
    while IFS=: read -r u_name u_pass u_uid u_gid u_gecos u_home u_shell; do
        [[ -d "$u_home/.ssh" ]] || continue
        if [[ "$u_uid" -eq 0 || "$u_uid" -ge 1000 ]]; then
            chmod 700 "$u_home/.ssh" 2>/dev/null
            find "$u_home/.ssh" -maxdepth 1 -type f -exec chmod 600 {} + 2>/dev/null
        fi
    done < /etc/passwd
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

    # Runbook-Based Automatic Permission & System Remediations
    apply_runbook_permission_remediations

    echo -e "${GREEN}[OK] Auto-fix completed: Permissions, safety aliases & runbook fixes applied.${NC}\n"
fi

# Update security tool databases and vulnerability definitions before audit
update_security_databases() {
    echo -e "${YELLOW}--- Updating Security & Audit Tool Databases ---${NC}"

    if [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
        echo -n "Updating APT package index... "
        run_sudo "${TOOL_BIN['apt-get']}" update -qq 2>/dev/null && echo -e "${GREEN}Done${NC}" || echo -e "${YELLOW}Skipped/Cached${NC}"
    elif [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
        echo -n "Refreshing DNF repository metadata... "
        run_sudo "${TOOL_BIN['dnf']}" makecache --refresh &>/dev/null && echo -e "${GREEN}Done${NC}" || echo -e "${YELLOW}Skipped/Cached${NC}"
    fi

    if [[ "${TOOL_FOUND['freshclam']}" -eq 1 ]]; then
        echo -n "Updating ClamAV virus signatures... "
        run_sudo "${TOOL_BIN['freshclam']}" 2>/dev/null && echo -e "${GREEN}Done${NC}" || echo -e "${YELLOW}Updated or locked by daemon${NC}"
    fi

    if [[ "${TOOL_FOUND['trivy']}" -eq 1 ]]; then
        echo -n "Updating Trivy vulnerability database... "
        "${TOOL_BIN['trivy']}" image --download-db-only 2>/dev/null && echo -e "${GREEN}Done${NC}" || echo -e "${YELLOW}Skipped/Up to date${NC}"
    fi
    echo ""
}

update_security_databases

# 1. Shell History Scanning & Cleaning
section "1/24" "Cleaning Shell History for Sensitive Data..."
clean_history() {
    local file="$1"
    if [[ -f "$file" ]]; then
        echo "Processing $file..."
        local temp_file
        temp_file=$(mktemp)
        local pattern_regex
        pattern_regex=$(IFS="|"; echo "${SENSITIVE_PATTERNS[*]}")
        if grep -vEia "$pattern_regex" "$file" > "$temp_file" 2>/dev/null; then
            # Only rewrite the history file if something was actually removed,
            # and keep a backup so the cleanup is reversible.
            if ! cmp -s "$temp_file" "$file"; then
                cp -p "$file" "${file}.audit-backup" 2>/dev/null || true
                chmod 600 "${file}.audit-backup" 2>/dev/null || true
                cat "$temp_file" > "$file"
            fi
            rm -f "$temp_file"
        else
            rm -f "$temp_file"
        fi
        chmod 600 "$file"
    fi
}

find "$HOME" -maxdepth 1 \( -name ".zsh_history" -o -name ".bash_history*" \) 2>/dev/null | while read -r h_file; do
    clean_history "$h_file"
done
log_pass "Shell history cleaned and permissions set to 600."

# 2. Certificate & File Permission Checks
section "2/24" "Checking Minikube & SSH Certificate Permissions..."
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
                        echo -e "  - ${GREEN}[OK] Protected SSH Key:${NC} User ${CYAN}${username}${NC} -> $(basename "$key_file")"
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
section "3/24" "Checking Installed Applications for Security Vulnerabilities (CVEs)..."
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

# 4. SSH Daemon & Remote Access Security Audit
section "4/24" "Auditing SSH Daemon Configuration, Ciphers & Security Directives..."

audit_ssh_daemon_config() {
    local sshd_config="/etc/ssh/sshd_config"
    local sshd_dir="/etc/ssh/sshd_config.d"
    
    if [[ ! -f "$sshd_config" && ! -d "$sshd_dir" ]]; then
        echo -e "  ${YELLOW}OpenSSH Daemon config not found (/etc/ssh/sshd_config missing). SSH daemon may not be installed.${NC}"
        return 0
    fi

    echo -e "${YELLOW}--- 4.1 SSH Daemon Effective Configuration & Authentication Directives ---${NC}"

    local sshd_eval=""
    if command -v sshd &>/dev/null; then
        sshd_eval=$(run_sudo sshd -T 2>/dev/null || sshd -T 2>/dev/null)
    fi

    get_ssh_param() {
        local param="$1"
        local default_val="$2"
        local val=""

        if [[ -n "$sshd_eval" ]]; then
            val=$(echo "$sshd_eval" | grep -i "^${param} " | head -n 1 | awk '{print $2}')
        fi

        if [[ -z "$val" && -f "$sshd_config" ]]; then
            val=$(grep -v '^\s*#' "$sshd_config" 2>/dev/null | grep -i "^${param}" | head -n 1 | awk '{print $2}')
        fi

        if [[ -z "$val" && -d "$sshd_dir" ]]; then
            val=$(grep -v '^\s*#' "$sshd_dir"/*.conf 2>/dev/null | grep -i "^${param}" | head -n 1 | awk '{print $2}')
        fi

        echo "${val:-$default_val}"
    }

    # 1. SSH Listening Port
    local ssh_port
    ssh_port=$(get_ssh_param "port" "22")
    echo -e "  SSH Listening Port          : ${CYAN}${ssh_port}${NC}"
    if [[ "$ssh_port" == "22" ]]; then
        echo -e "  ${YELLOW}Tip: SSH daemon is running on standard port 22. Changing to a non-standard port reduces automated bot brute-force noise.${NC}"
    else
        log_pass "SSH daemon running on custom non-standard port (${ssh_port})."
    fi

    # 2. PermitRootLogin
    local root_login
    root_login=$(get_ssh_param "permitrootlogin" "prohibit-password")
    echo -e "  PermitRootLogin             : ${CYAN}${root_login}${NC}"
    if [[ "$root_login" == "yes" ]]; then
        log_crit "PermitRootLogin is enabled ('yes')! Direct root SSH login allows brute-force attacks against the root account! Recommended: 'no' or 'prohibit-password'."
    elif [[ "$root_login" == "prohibit-password" || "$root_login" == "without-password" ]]; then
        log_pass "PermitRootLogin set to '${root_login}' (Root SSH login allowed via SSH key only)."
    else
        log_pass "PermitRootLogin set to 'no' (Direct root SSH login disabled)."
    fi

    # 3. PasswordAuthentication
    local pass_auth
    pass_auth=$(get_ssh_param "passwordauthentication" "yes")
    echo -e "  PasswordAuthentication      : ${CYAN}${pass_auth}${NC}"
    if [[ "$pass_auth" == "yes" ]]; then
        log_warn "PasswordAuthentication is enabled ('yes'). Password brute-force attacks are possible. Recommended: Disable password authentication in favor of SSH Keys ('PasswordAuthentication no')."
    else
        log_pass "PasswordAuthentication is disabled (Enforced SSH key authentication)."
    fi

    # 4. PermitEmptyPasswords
    local empty_pass
    empty_pass=$(get_ssh_param "permitemptypasswords" "no")
    echo -e "  PermitEmptyPasswords        : ${CYAN}${empty_pass}${NC}"
    if [[ "$empty_pass" == "yes" ]]; then
        log_crit "PermitEmptyPasswords is enabled ('yes')! Accounts with blank passwords can log in via SSH!"
    else
        log_pass "PermitEmptyPasswords is set to 'no'."
    fi

    # 5. PubkeyAuthentication
    local pubkey_auth
    pubkey_auth=$(get_ssh_param "pubkeyauthentication" "yes")
    echo -e "  PubkeyAuthentication        : ${CYAN}${pubkey_auth}${NC}"
    if [[ "$pubkey_auth" == "no" ]]; then
        log_warn "PubkeyAuthentication is disabled! SSH key authentication is turned off."
    else
        log_pass "PubkeyAuthentication is enabled."
    fi

    # 6. X11Forwarding
    local x11_fwd
    x11_fwd=$(get_ssh_param "x11forwarding" "no")
    echo -e "  X11Forwarding               : ${CYAN}${x11_fwd}${NC}"
    if [[ "$x11_fwd" == "yes" ]]; then
        log_warn "X11Forwarding is enabled ('yes'). X11 display redirection increases attack surface unless required."
    else
        log_pass "X11Forwarding is disabled."
    fi

    # 7. MaxAuthTries
    local max_tries
    max_tries=$(get_ssh_param "maxauthtries" "6")
    echo -e "  MaxAuthTries                : ${CYAN}${max_tries}${NC}"
    if [[ "$max_tries" =~ ^[0-9]+$ && "$max_tries" -gt 4 ]]; then
        log_warn "MaxAuthTries is set to ${max_tries} (Recommended: <= 4 to mitigate brute-force attempts)."
    else
        log_pass "MaxAuthTries configuration verified (${max_tries})."
    fi

    # 4.2 Ciphers, MACs & Key Exchange (KEX) Cryptographic Algorithms Audit
    echo -e "\n${YELLOW}--- 4.2 SSH Cryptographic Algorithms Audit (Ciphers, MACs, KEX) ---${NC}"

    local ciphers_val macs_val kex_val
    ciphers_val=$(get_ssh_param "ciphers" "")
    macs_val=$(get_ssh_param "macs" "")
    kex_val=$(get_ssh_param "kexalgorithms" "")

    local weak_ciphers_pattern="3des-cbc|blowfish-cbc|cast128-cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|none"
    if [[ -n "$ciphers_val" ]]; then
        echo -e "  Configured Ciphers          : ${CYAN}${ciphers_val}${NC}"
        local found_weak_ciphers
        found_weak_ciphers=$(echo "$ciphers_val" | grep -Ei "$weak_ciphers_pattern")
        if [[ -n "$found_weak_ciphers" ]]; then
            log_crit "Weak / Obsolete SSH Ciphers enabled: ${found_weak_ciphers}! Recommended: chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com."
        else
            log_pass "SSH Cipher suite configuration verified (only strong AEAD/GCM ciphers configured)."
        fi
    fi

    local weak_macs_pattern="hmac-md5|hmac-md5-96|hmac-sha1|hmac-sha1-96|umac-64@openssh.com"
    if [[ -n "$macs_val" ]]; then
        echo -e "  Configured MACs             : ${CYAN}${macs_val}${NC}"
        local found_weak_macs
        found_weak_macs=$(echo "$macs_val" | grep -Ei "$weak_macs_pattern")
        if [[ -n "$found_weak_macs" ]]; then
            log_warn "Weak / Obsolete SSH MAC Algorithms enabled: ${found_weak_macs}! Recommended: hmac-sha2-512-etm@openssh.com, hmac-sha2-256-etm@openssh.com."
        else
            log_pass "SSH MAC Algorithms verified."
        fi
    fi

    local weak_kex_pattern="diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1"
    if [[ -n "$kex_val" ]]; then
        echo -e "  Configured KEX Algorithms   : ${CYAN}${kex_val}${NC}"
        local found_weak_kex
        found_weak_kex=$(echo "$kex_val" | grep -Ei "$weak_kex_pattern")
        if [[ -n "$found_weak_kex" ]]; then
            log_warn "Weak / Obsolete SSH Key Exchange (KEX) algorithms enabled: ${found_weak_kex}! Recommended: curve25519-dalek@coderberg.org, curve25519-sha256, diffie-hellman-group16-sha512."
        else
            log_pass "SSH Key Exchange (KEX) algorithms verified."
        fi
    fi
}

audit_ssh_daemon_config

# 5. Network Security, Active Connections & Tunneling Audit
section "5/24" "Auditing Network Security, Firewall Rules, Listening Ports & VPN Tunnels..."

audit_network_security_and_tunnels() {
    # 5.1 Firewall Configuration & Active Rule Audit (UFW / firewalld / nftables / iptables)
    echo -e "${YELLOW}--- 5.1 Firewall Configuration & Active Rule Audit (UFW / firewalld / nftables / iptables) ---${NC}"
    local firewall_active=false

    # 1. UFW Audit
    if command -v ufw &>/dev/null; then
        local ufw_out
        ufw_out=$(run_sudo ufw status verbose 2>/dev/null || ufw status verbose 2>/dev/null)
        if [[ -n "$ufw_out" ]]; then
            if [[ "$ufw_out" =~ "Status: active" ]]; then
                firewall_active=true
                local ufw_default
                ufw_default=$(echo "$ufw_out" | grep -i "Default:" | head -n 1)
                echo -e "  UFW Firewall Status: ${GREEN}ACTIVE${NC} (${ufw_default:-Default rules configured})"
                log_pass "UFW packet filtering firewall is ACTIVE."
            else
                echo -e "  UFW Firewall Status: ${YELLOW}INACTIVE${NC}"
            fi
        fi
    fi

    # 2. firewalld Audit
    if command -v firewall-cmd &>/dev/null; then
        local fw_state
        fw_state=$(firewall-cmd --state 2>/dev/null)
        if [[ "$fw_state" == "running" ]]; then
            firewall_active=true
            local active_zone
            active_zone=$(firewall-cmd --get-active-zones 2>/dev/null | head -n 1)
            echo -e "  firewalld Status: ${GREEN}RUNNING${NC} (Active Zone: ${active_zone:-default})"
            log_pass "firewalld packet filtering firewall is RUNNING."
        fi
    fi

    # 3. nftables Audit
    if command -v nft &>/dev/null; then
        local nft_rules
        nft_rules=$(run_sudo nft list ruleset 2>/dev/null)
        if [[ -n "$nft_rules" && "$nft_rules" =~ "table " ]]; then
            firewall_active=true
            local chain_cnt
            chain_cnt=$(echo "$nft_rules" | grep -c "chain ")
            echo -e "  nftables Status: ${GREEN}ACTIVE${NC} (${chain_cnt} active filtering chain(s))"
            log_pass "nftables packet filtering ruleset verified."
        fi
    fi

    # 4. iptables Audit
    if command -v iptables &>/dev/null; then
        local ipt_rules
        ipt_rules=$(run_sudo iptables -L -n -v 2>/dev/null)
        if [[ -n "$ipt_rules" ]]; then
            local input_pol rule_count
            input_pol=$(echo "$ipt_rules" | grep -E "^Chain INPUT" | awk '{print $4}')
            rule_count=$(echo "$ipt_rules" | grep -c -E '^[[:space:]]*[0-9]+')
            echo -e "  iptables IPv4 INPUT Policy : ${CYAN}${input_pol:-UNKNOWN}${NC} (${rule_count} active filtering rules)"

            if [[ "$rule_count" -gt 0 || "$input_pol" == "(policy DROP)" || "$input_pol" == "(policy REJECT)" ]]; then
                firewall_active=true
            fi
        fi
    fi

    if [[ "$firewall_active" == true ]]; then
        log_pass "Active network packet filtering firewall verified."
    else
        log_crit "NO ACTIVE FIREWALL FILTERING: System has no active iptables/nftables/ufw filtering rules! All incoming network connections are unfiltered!"
    fi

    # 5.2 Open Listening TCP/UDP Ports & Associated Processes Audit (ss -tulpn)
    echo -e "\n${YELLOW}--- 5.2 Open Listening TCP/UDP Ports & Associated Processes (ss -tulpn) ---${NC}"
    if [[ "${TOOL_FOUND['ss']}" -eq 1 ]]; then
        local ss_output
        ss_output=$(run_sudo ss -tulpn 2>/dev/null || ss -tulpn 2>/dev/null)
        if [[ -n "$ss_output" ]]; then
            local public_count=0
            local local_count=0
            local suspicious_services=()

            echo -e "  ${CYAN}Active Listening Network Sockets:${NC}"
            
            while read -r netid state recvq sendq local_addr peer_addr proc; do
                [[ -z "$local_addr" || "$netid" == "Netid" ]] && continue
                
                local port="${local_addr##*:}"
                local addr_part="${local_addr%:*}"
                
                local proc_name="[Unknown/Root]"
                if [[ "$proc" =~ users:\(\(\"([^\"]+)\" ]]; then
                    proc_name="${BASH_REMATCH[1]}"
                fi
                if [[ "$proc" =~ pid=([0-9]+) ]]; then
                    local proc_pid="${BASH_REMATCH[1]}"
                    proc_name="${proc_name} (PID: ${proc_pid})"
                fi

                local scope="Public"
                if [[ "$addr_part" =~ ^127\. || "$addr_part" == "[::1]" ]]; then
                    scope="Localhost"
                    ((local_count++))
                else
                    ((public_count++))
                    case "$port" in
                        21) suspicious_services+=("FTP (Port 21, Unencrypted cleartext credentials)") ;;
                        23) suspicious_services+=("Telnet (Port 23, Unencrypted cleartext shell access)") ;;
                        25) suspicious_services+=("SMTP (Port 25, Plaintext mail relay)") ;;
                        69) suspicious_services+=("TFTP (Port 69, Unauthenticated file transfer)") ;;
                        80) echo -e "    - HTTP (Port 80): Plaintext web service active" ;;
                        161|162) suspicious_services+=("SNMP (Port ${port}, Unencrypted network management)") ;;
                        512|513|514) suspicious_services+=("Legacy Remote Shell R-Services (Port ${port})") ;;
                        3306) suspicious_services+=("MySQL Database (Port 3306 exposed on public interface!)") ;;
                        5432) suspicious_services+=("PostgreSQL Database (Port 5432 exposed on public interface!)") ;;
                        6379) suspicious_services+=("Redis Cache (Port 6379 exposed on public interface!)") ;;
                        27017) suspicious_services+=("MongoDB (Port 27017 exposed on public interface!)") ;;
                        11211) suspicious_services+=("Memcached (Port 11211 exposed on public interface!)") ;;
                        9200) suspicious_services+=("Elasticsearch (Port 9200 exposed on public interface!)") ;;
                    esac
                fi

                printf "    - %-5s | %-20s | Port %-5s | Scope: %-9s | Process: %s\n" "$netid" "$addr_part" "$port" "$scope" "$proc_name"
            done < <(echo "$ss_output" | awk 'NR>1')

            log_pass "Listening Sockets Audit Summary: ${public_count} public socket(s), ${local_count} localhost-only socket(s)."

            if [[ ${#suspicious_services[@]} -gt 0 ]]; then
                local susp_msg
                susp_msg=$(IFS=$'\n'; echo "${suspicious_services[*]}")
                log_crit "RISKY / UNENCRYPTED PUBLIC LISTENING SERVICES DETECTED:\n${susp_msg}"
            fi

            local mdns_llmnr
            mdns_llmnr=$(echo "$ss_output" | grep -E ':5353|:5355')
            if [[ -n "$mdns_llmnr" ]]; then
                log_warn "Active mDNS/LLMNR services found (5353/5355). Disable systemd-resolved LLMNR/MulticastDNS if not needed."
            fi
        else
            log_pass "No active listening TCP/UDP sockets found."
        fi
    fi

    # 5.3 Active Established Outbound Connections Audit
    echo -e "\n${YELLOW}--- 5.3 Active Established Outbound Network Connections ---${NC}"
    if [[ "${TOOL_FOUND['ss']}" -eq 1 ]]; then
        local established_conns
        established_conns=$(run_sudo ss -tunp state established 2>/dev/null | grep -v '127\.0\.0\.1' | grep -v '::1')
        if [[ -n "$established_conns" ]]; then
            echo "$established_conns" | sed 's/^/  /'
            local conn_count
            conn_count=$(echo "$established_conns" | awk 'NR>1' | wc -l)
            log_pass "Audited ${conn_count} active established outbound network connection(s)."
        else
            log_pass "No active established outbound connections to external hosts."
        fi
    fi

    # 5.4 Active VPN, Mesh & Tunneling Interfaces Audit
    echo -e "\n${YELLOW}--- 5.4 Active VPN, Mesh & Tunneling Interfaces ---${NC}"
    local vpn_ifaces
    vpn_ifaces=$(ip link show 2>/dev/null | grep -E 'tun[0-9]|tap[0-9]|wg[0-9]|tailscale|zerotier|zt[0-9]' | awk -F': ' '{print $2}')
    if [[ -n "$vpn_ifaces" ]]; then
        echo -e "  Active VPN / Mesh interfaces detected: ${CYAN}${vpn_ifaces}${NC}"
        log_pass "VPN/Mesh network interface(s) verified: ${vpn_ifaces}"
    else
        echo -e "  No active VPN/Mesh interfaces (WireGuard, OpenVPN, Tailscale, ZeroTier) detected."
    fi

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

# 6. Antivirus & Rootkit Audit (ClamAV / chkrootkit)
section "6/24" "Antivirus & Rootkit Audit (ClamAV / chkrootkit)..."

audit_antivirus_and_rootkits() {
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
        local clam_out
        clam_out=$(run_sudo "${TOOL_BIN['clamscan']}" -r --exclude-dir="^/sys" --exclude-dir="^/dev" --exclude-dir="^/proc" /bin /sbin /usr/bin /usr/sbin 2>/dev/null | grep -E "Infected|Summary|FOUND")
        if [[ "$clam_out" =~ "FOUND" || "$clam_out" =~ "Infected files: "[1-9] ]]; then
            log_crit "ClamAV malware threats found!\n$clam_out"
        else
            log_pass "ClamAV scan completed: No threats found."
        fi
    else
        echo -e "${YELLOW}ClamAV (clamscan) not installed.${NC}"
    fi

    if [[ "${TOOL_FOUND['chkrootkit']}" -eq 1 ]]; then
        echo -e "${CYAN}Running Rootkit Detection (chkrootkit)...${NC}"
        local chk_raw chk_infected
        chk_raw=$(run_sudo "${TOOL_BIN['chkrootkit']}" -q 2>/dev/null)
        # Filter for actual INFECTED or VULNERABLE findings, excluding generic empty warning headers
        chk_infected=$(echo "$chk_raw" | grep -Ei "INFECTED|VULNERABLE" | grep -v "not infected")

        if [[ -n "$chk_infected" ]]; then
            log_crit "chkrootkit detected potential rootkit signatures:\n$chk_infected"
        else
            log_pass "chkrootkit scan completed: No rootkit signatures detected."
        fi
    elif [[ "${TOOL_FOUND['rkhunter']}" -eq 1 ]]; then
        echo -e "${CYAN}Running Rootkit Detection (rkhunter)...${NC}"
        run_sudo "${TOOL_BIN['rkhunter']}" --check --sk --quiet 2>/dev/null || true
        log_pass "rkhunter check completed."
    else
        echo -e "${YELLOW}Neither chkrootkit nor rkhunter installed.${NC}"
    fi
}

audit_antivirus_and_rootkits

# 7. Filesystem Directory Permissions, Container & Lynis Security Audit
section "7/24" "Filesystem Directory Permissions, Container & Lynis Security Audit..."

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
                # Only remove rotated archives older than 14 days (keeps recent
                # logs available for security incident investigation).
                if [[ -z $(find "$rfile" -mtime -14 2>/dev/null) ]]; then
                    run_sudo rm -f "$rfile" 2>/dev/null || true
                fi
            done
            log_pass "Rotated log archive cleanup completed. Reclaimed ${rot_human} of disk space."
        else
            log_pass "Rotated logs monitored (${rot_human})."
        fi
    else
        log_pass "No accumulated rotated log archives in /var/log."
    fi

    # 7. LUKS Cryptographic Keyfiles Audit in Temporary Directories (/tmp, /var/tmp, /dev/shm)
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
                        echo -e "  - ${GREEN}[OK] Auto-fix applied:${NC} Secured permissions of '${kfile}' to 600."
                    fi
                fi
            done < <(find "$tpath" -maxdepth 3 -type f -name "$pat" 2>/dev/null)
        done
    done

    # 3. Check for binary LUKS header/key files in temporary directories using cryptsetup
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

    # 8. Orphaned Files & Directories Without Owner or Group (-nouser / -nogroup)
    echo -e "\n${CYAN}8. Orphaned Files & Directories Without Owner or Group Audit (-nouser / -nogroup):${NC}"
    local nouser_list
    nouser_list=$(run_sudo find /etc /var /opt /home /tmp /usr /srv /boot -maxdepth 4 \( -nouser -o -nogroup \) ! -path "/proc*" ! -path "/sys*" ! -path "/dev*" ! -path "/run*" 2>/dev/null | head -n 20)
    if [[ -n "$nouser_list" ]]; then
        local nouser_cnt
        nouser_cnt=$(echo "$nouser_list" | wc -l)
        log_warn "Orphaned files/directories without valid owner or group found (${nouser_cnt} items):\n$(echo "$nouser_list" | sed 's/^/  - /')"
    else
        log_pass "No orphaned files without owner or group (-nouser / -nogroup) found on the system."
    fi

    # 9. World-Writable Directories & Sticky Bit (+t) Integrity Audit
    echo -e "\n${CYAN}9. World-Writable Directories & Sticky Bit (+t) Integrity Audit:${NC}"
    local ww_dirs
    ww_dirs=$(run_sudo find /tmp /var/tmp /dev/shm /var /etc /opt /home /usr -type d -perm -0002 ! -path "/proc*" ! -path "/sys*" ! -path "/dev*" ! -path "/run*" 2>/dev/null)
    if [[ -n "$ww_dirs" ]]; then
        local missing_sticky=0
        while read -r wdir; do
            [[ -z "$wdir" ]] && continue
            local wperm
            wperm=$(run_sudo stat -c "%a" "$wdir" 2>/dev/null)
            if [[ "$wperm" =~ ^[1357] ]]; then
                echo -e "  - World-Writable Dir: ${CYAN}${wdir}${NC} (Mode: ${wperm}) [${GREEN}Sticky bit +t set${NC}]"
            else
                log_crit "INSECURE WORLD-WRITABLE DIRECTORY: '${wdir}' (Mode: ${wperm}) is world-writable WITHOUT sticky bit (+t)! Any local user can delete or tamper with other users' files!"
                ((missing_sticky++))
            fi
        done <<< "$ww_dirs"

        if [[ "$missing_sticky" -eq 0 ]]; then
            log_pass "All discovered world-writable directories have sticky bit (+t) enabled."
        fi
    else
        log_pass "No world-writable directories detected."
    fi
}

audit_directory_permissions

if [[ "${TOOL_FOUND['trivy']}" -eq 1 ]]; then
    echo -e "\n${CYAN}Running Trivy Container/Filesystem Audit...${NC}"
    "${TOOL_BIN['trivy']}" fs --severity HIGH,CRITICAL --format table "${SCRIPT_DIR}" 2>/dev/null
else
    echo -e "${YELLOW}Trivy not installed - install trivy for vulnerability scanning of code/containers.${NC}"
fi

if [[ "${TOOL_FOUND['lynis']}" -eq 1 ]]; then
    echo -e "\n${CYAN}Running Lynis System Audit Summary...${NC}"
    run_sudo "${TOOL_BIN['lynis']}" audit system --quick --no-colors 2>/dev/null | grep -E "Hardening index|Warnings|Suggestions"
else
    echo -e "${YELLOW}Lynis security auditor not installed - install lynis for deep security scoring.${NC}"
fi

# 8. System Log, User Logins & Auth Audit
section "8/24" "Auditing User Logins, Active Sessions & System Auth Logs..."

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

audit_timezone_and_time_sync() {
    echo -e "${YELLOW}--- System Timezone & Time Synchronization Audit ---${NC}"
    local tz_abbr tz_offset tz_target ntp_sync ntp_service

    tz_abbr=$(date "+%Z")
    tz_offset=$(date "+%z")

    if [[ -L "/etc/localtime" ]]; then
        tz_target=$(readlink -f /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||')
    elif [[ -f "/etc/timezone" ]]; then
        tz_target=$(cat /etc/timezone 2>/dev/null)
    else
        tz_target="$tz_abbr"
    fi

    echo -e "  Configured Timezone        : ${CYAN}${tz_target:-$tz_abbr}${NC} (${tz_abbr}, UTC${tz_offset})"

    local is_synced=false
    if command -v timedatectl &>/dev/null; then
        ntp_sync=$(timedatectl status 2>/dev/null | grep -i "System clock synchronized:" | awk '{print $4}')
        ntp_service=$(timedatectl status 2>/dev/null | grep -i "NTP service:" | awk '{print $3}')

        [[ "$ntp_sync" == "yes" ]] && is_synced=true
        echo -e "  NTP Time Sync Service      : ${CYAN}${ntp_service:-unknown}${NC}"
        echo -e "  System Clock Synchronized  : ${CYAN}${ntp_sync:-unknown}${NC}"
    else
        if systemctl is-active --quiet systemd-timesyncd || systemctl is-active --quiet chronyd || systemctl is-active --quiet ntp; then
            is_synced=true
        fi
    fi

    if [[ "$is_synced" == true ]]; then
        log_pass "Timezone configuration ('${tz_target:-$tz_abbr}') verified & system clock is synchronized via NTP."
    else
        log_warn "Timezone is configured ('${tz_target:-$tz_abbr}'), but system clock is NOT synchronized with NTP servers!"
    fi
    echo ""
}

# 9. System Optimization & Resource Audit
section "9/24" "Checking System Resources & Optimization Opportunities..."
audit_timezone_and_time_sync

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
                                # Safe recursive delete (does not follow "." / ".." entries)
                                find "$target" -mindepth 1 -delete 2>/dev/null || true
                            else
                                rm -f "$target" 2>/dev/null || true
                            fi
                            echo -e "${GREEN}Cleaned${NC}"
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
                    echo -e "  Deleted core dump ${cfile} (${csize}): ${GREEN}Cleaned${NC}"
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

audit_user_privileges_groups_and_login_counts() {
    echo -e "\n${YELLOW}--- User Accounts, Privileges, Group Memberships & Login Frequency Audit ---${NC}"

    local interactive_users=0
    local privileged_users_count=0

    # Track per-user login counts from wtmp / last logs
    declare -A USER_LOGIN_COUNTS
    declare -A USER_LAST_LOGIN

    if [[ "${TOOL_FOUND['last']}" -eq 1 ]]; then
        while read -r line; do
            [[ -z "$line" || "$line" =~ ^wtmp|^$ ]] && continue
            local uname
            uname=$(echo "$line" | awk '{print $1}')
            
            if [[ -n "$uname" ]]; then
                ((USER_LOGIN_COUNTS["$uname"]++))
                if [[ -z "${USER_LAST_LOGIN["$uname"]}" ]]; then
                    USER_LAST_LOGIN["$uname"]=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i; print ""}')
                fi
            fi
        done < <("${TOOL_BIN['last']}" -a 2>/dev/null | grep -v 'system boot' | grep -v 'wtmp begins')
    fi

    echo -e "${CYAN}Per-User Account Details (UID, Primary/Secondary Groups, Privileges, Login Count):${NC}"

    while IFS=: read -r username password uid gid gecos home shell; do
        # Filter for interactive users (UID >= 1000 or UID 0 / root or accounts with login shells)
        if [[ "$uid" -ge 1000 || "$uid" -eq 0 || "$shell" =~ (bash|zsh|sh|csh|tcsh|ksh)$ ]]; then
            ((interactive_users++))
            
            # Retrieve all groups user belongs to
            local user_groups=""
            if command -v id &>/dev/null; then
                user_groups=$(id -Gn "$username" 2>/dev/null | tr ' ' ',')
            fi
            [[ -z "$user_groups" ]] && user_groups="GID:${gid}"

            # Retrieve login count from last logs
            local login_cnt="${USER_LOGIN_COUNTS["$username"]:-0}"
            local last_log_info="${USER_LAST_LOGIN["$username"]:-No recent logins recorded}"

            # Privilege assessment
            local is_privileged=false
            local priv_details=""
            if [[ "$uid" -eq 0 ]]; then
                is_privileged=true
                priv_details="[UID 0 ROOT]"
            fi
            if [[ "$user_groups" =~ \b(sudo|wheel|admin)\b ]]; then
                is_privileged=true
                priv_details+=" [SUDOERS ACCESS]"
            fi
            if [[ "$user_groups" =~ \b(docker|containerd|podman)\b ]]; then
                is_privileged=true
                priv_details+=" [DOCKER/CONTAINER HOST ACCESS]"
            fi
            if [[ "$user_groups" =~ \b(shadow|disk|kmem)\b ]]; then
                is_privileged=true
                priv_details+=" [RAW DISK/SHADOW ACCESS]"
            fi

            if [[ "$is_privileged" == true ]]; then
                ((privileged_users_count++))
                echo -e "  - User: ${CYAN}${username}${NC} (UID: ${uid}, Shell: ${shell})"
                echo -e "    Groups       : ${YELLOW}${user_groups}${NC}"
                echo -e "    Privileges   : ${RED}${priv_details}${NC}"
                echo -e "    Total Logins : ${CYAN}${login_cnt} session(s)${NC} (Last: ${last_log_info})"
            else
                echo -e "  - User: ${CYAN}${username}${NC} (UID: ${uid}, Shell: ${shell})"
                echo -e "    Groups       : ${GREEN}${user_groups}${NC}"
                echo -e "    Privileges   : Standard User"
                echo -e "    Total Logins : ${CYAN}${login_cnt} session(s)${NC} (Last: ${last_log_info})"
            fi
        fi
    done < /etc/passwd

    if [[ "$privileged_users_count" -gt 0 ]]; then
        log_warn "Discovered ${privileged_users_count} privileged/administrative account(s) out of ${interactive_users} total user account(s)."
    else
        log_pass "User privileges audit completed: ${interactive_users} interactive user account(s) evaluated."
    fi
}

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

    # --- 10.4 User Accounts, Privileges, Group Memberships & Login Frequency Audit ---
    audit_user_privileges_groups_and_login_counts

    # --- 10.5 /etc/shadow Password Security & Weak Password Audit ---
    echo -e "\n${YELLOW}--- 10.5 /etc/shadow Password Security & Weak Password Audit ---${NC}"
    
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

            local dict_arg=""
            if [[ "$FETCH_EXTERNAL_PASSWORDS" == true && ${#EXTERNAL_PASSWORD_LIST_URLS[@]} -gt 0 ]]; then
                fetch_external_password_lists
                dict_arg="$DICT_FILE"
            fi

            local py_result
            py_result=$(run_sudo timeout 600s "$py_cmd" - "$sys_hostname" "$dict_arg" << 'PYEOF' 2>/dev/null
import sys, ctypes, ctypes.util, os, time
try:
    import urllib.request
except ImportError:
    urllib = None

hostname = sys.argv[1] if len(sys.argv) > 1 else ""
dict_file = sys.argv[2] if len(sys.argv) > 2 else ""

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

if dict_file and os.path.exists(dict_file):
    try:
        added = 0
        with open(dict_file, 'r', errors='ignore') as df:
            for line in df:
                p = line.strip()
                if p:
                    common_passwords.append(p)
                    added += 1
        print(f"DICT_LOADED:{added}")
    except Exception as err:
        print(f"FETCH_ERR:combined-dict.txt:{err}:0s")

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
                    if [[ "$line" =~ ^DICT_LOADED: ]]; then
                        local dict_cnt
                        dict_cnt=$(echo "$line" | cut -d: -f2)
                        echo -e "  - ${GREEN}[OK] [DICTIONARY]${NC} Loaded ${CYAN}${dict_cnt}${NC} unique passwords from cached combined dictionary."
                    elif [[ "$line" =~ ^FETCHED: ]]; then
                        local fname count t_sec
                        fname=$(echo "$line" | cut -d: -f2)
                        count=$(echo "$line" | cut -d: -f3)
                        t_sec=$(echo "$line" | cut -d: -f4)
                        echo -e "  - ${GREEN}[OK] [DOWNLOADED]${NC} Downloaded ${CYAN}${fname}${NC} (${count} passwords, ${t_sec}) from GitHub"
                    elif [[ "$line" =~ ^FETCH_ERR: ]]; then
                        local fname err
                        fname=$(echo "$line" | cut -d: -f2)
                        err=$(echo "$line" | cut -d: -f3)
                        echo -e "  - ${YELLOW}! [DOWNLOAD ERROR]${NC} Failed to fetch ${fname} from GitHub: ${err}"
                    elif [[ "$line" =~ ^FETCH_TIMEOUT: ]]; then
                        local timeout_msg
                        timeout_msg=$(echo "$line" | cut -d: -f2)
                        log_warn "GitHub download section timed out: ${timeout_msg}"
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
                        # Do NOT log the matched password itself into the report file
                        log_crit "WEAK PASSWORD DETECTED for user '${user}': password matches a common dictionary pattern. Change it immediately."
                    done <<< "$weak_entries"
                else
                    log_pass "Password strength dictionary scan completed: No common weak passwords found for active user accounts."
                fi
            fi
        else
            echo -e "${YELLOW}python3 not installed. Skipping automated weak password dictionary scan.${NC}"
        fi

        # 10.6 System Password Expiration & Aging Policies (/etc/login.defs & chage)
        echo -e "\n${YELLOW}--- 10.6 System Password Expiration & Aging Policies (/etc/login.defs & chage) ---${NC}"
        
        if [[ -f "/etc/login.defs" ]]; then
            local def_max def_min def_warn def_umask def_enc
            def_max=$(grep -E "^\s*PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
            def_min=$(grep -E "^\s*PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
            def_warn=$(grep -E "^\s*PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}')
            def_umask=$(grep -E "^\s*UMASK" /etc/login.defs 2>/dev/null | awk '{print $2}')
            def_enc=$(grep -E "^\s*ENCRYPT_METHOD" /etc/login.defs 2>/dev/null | awk '{print $2}')

            echo -e "  /etc/login.defs Default Policies:"
            echo -e "    - PASS_MAX_DAYS : ${CYAN}${def_max:-99999}${NC}"
            echo -e "    - PASS_MIN_DAYS : ${CYAN}${def_min:-0}${NC}"
            echo -e "    - PASS_WARN_AGE : ${CYAN}${def_warn:-7}${NC}"
            echo -e "    - UMASK         : ${CYAN}${def_umask:-022}${NC}"
            echo -e "    - ENCRYPT_METHOD: ${CYAN}${def_enc:-YESCRYPT}${NC}"

            if [[ -n "$def_max" && "$def_max" -ge 99999 ]]; then
                log_warn "PASS_MAX_DAYS in /etc/login.defs is set to 99999 (Default password expiration is disabled). Recommended: <= 90 or <= 180 days."
            else
                log_pass "System PASS_MAX_DAYS policy verified (${def_max} days)."
            fi

            if [[ -n "$def_min" && "$def_min" -eq 0 ]]; then
                log_warn "PASS_MIN_DAYS in /etc/login.defs is 0 (Users can change password multiple times in the same day). Recommended: >= 1 day."
            fi

            if [[ "$def_umask" =~ ^(022|002)$ ]]; then
                log_warn "Default system UMASK in /etc/login.defs is ${def_umask} (Group/world readable default files). Recommended: 027 or 077."
            else
                log_pass "Default system UMASK policy verified (${def_umask:-027})."
            fi

            if [[ "$def_enc" =~ DES|MD5 ]]; then
                log_crit "Obsolete & insecure password encryption method '${def_enc}' in /etc/login.defs! Upgrade to SHA512 or YESCRYPT."
            fi
        fi

        # Password Aging & Expiration Audit (/etc/shadow)
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

    # --- 10.7 Sudoers Hardening & NOPASSWD Audit ---
    echo -e "\n${YELLOW}--- 10.7 Sudoers Hardening & NOPASSWD Audit ---${NC}"
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
        local pam_permit pam_exec pam_nonstandard
        pam_permit=$(grep -Ei "^\s*auth\s+sufficient\s+pam_permit\.so" /etc/pam.d/* 2>/dev/null)
        if [[ -n "$pam_permit" ]]; then
            log_crit "Bypassed authentication found in PAM stack (pam_permit.so sufficient):\n$pam_permit"
        else
            log_pass "PAM authentication stack verified (No unconditional pam_permit bypasses)."
        fi

        pam_exec=$(grep -Ei "pam_exec\.so" /etc/pam.d/* 2>/dev/null | grep -v '^\s*#')
        if [[ -n "$pam_exec" ]]; then
            log_warn "PAM exec module (pam_exec.so) detected in auth stack (Potential keylogging/hook):\n$pam_exec"
        else
            log_pass "No pam_exec.so hooks detected in PAM configuration."
        fi

        pam_nonstandard=$(grep -Ei "\.so" /etc/pam.d/* 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/|/home/")
        if [[ -n "$pam_nonstandard" ]]; then
            log_crit "UNAUTHORIZED PAM MODULE: PAM configuration loads module from temporary/user directory:\n$pam_nonstandard"
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

# 10. User Accounts, Privileges, Passwords & System Auth Files Audit
section "10/24" "Auditing User Accounts, Privileges, Passwords & System Auth Files..."
audit_passwd_group_shadow

# 11. Package Manager & Repository Audit
section "11/24" "Auditing Package Repositories, Kernel Updates & Recommended Packages..."

audit_package_repositories() {
    echo -e "${YELLOW}--- Auditing Configured Package Repositories (Official vs Unofficial/Third-Party) ---${NC}"

    local total_repos=0
    local unofficial_repos=0
    local repo_findings=""

    if [[ "${TOOL_FOUND['apt-get']}" -eq 1 || -d "/etc/apt" ]]; then
        local apt_sources_files=()
        [[ -f "/etc/apt/sources.list" ]] && apt_sources_files+=("/etc/apt/sources.list")
        if [[ -d "/etc/apt/sources.list.d" ]]; then
            while read -r sfile; do
                [[ -f "$sfile" ]] && apt_sources_files+=("$sfile")
            done < <(find /etc/apt/sources.list.d -type f \( -name "*.list" -o -name "*.sources" \) 2>/dev/null)
        fi

        echo -e "${CYAN}Discovered APT Repositories (${#apt_sources_files[@]} config file(s)):${NC}"
        local official_pattern="debian\.org|ubuntu\.com|kali\.org|raspbian\.org|mint\.com"

        for sf in "${apt_sources_files[@]}"; do
            while read -r rline; do
                [[ -z "$rline" || "$rline" =~ ^\s*# ]] && continue
                if [[ "$rline" =~ ^\s*(deb|deb-src)\s+|^\s*URIs:\s* ]]; then
                    ((total_repos++))
                    local repo_url
                    repo_url=$(echo "$rline" | grep -oE '(https?|ftp)://[^ "]+' | head -n 1)
                    [[ -z "$repo_url" ]] && repo_url="$rline"

                    local domain
                    domain=$(echo "$repo_url" | awk -F/ '{print $3}')
                    [[ -z "$domain" ]] && domain="$repo_url"

                    if [[ "$domain" =~ $official_pattern ]]; then
                        echo -e "  [${GREEN}OFFICIAL${NC}] ${CYAN}${domain}${NC} -> ${repo_url}"
                    else
                        ((unofficial_repos++))
                        echo -e "  [${RED}UNOFFICIAL / THIRD-PARTY${NC}] ${YELLOW}${domain}${NC} -> ${repo_url}"
                        repo_findings+="  - Unofficial Repo (${domain}): ${repo_url}\n"
                    fi
                fi
            done < "$sf"
        done

    elif [[ "${TOOL_FOUND['dnf']}" -eq 1 || -d "/etc/yum.repos.d" ]]; then
        echo -e "${CYAN}Discovered DNF/YUM Repositories (/etc/yum.repos.d/*.repo):${NC}"
        local official_dnf_pattern="fedoraproject\.org|redhat\.com|centos\.org|almalinux\.org|rockylinux\.org"

        for rfile in /etc/yum.repos.d/*.repo; do
            [[ -f "$rfile" ]] || continue
            local repo_id base_url enabled
            repo_id=$(basename "$rfile" .repo)
            base_url=$(grep -Ei '^\s*(baseurl|metalink|mirrorlist)\s*=' "$rfile" 2>/dev/null | head -n 1 | cut -d= -f2 | tr -d ' ')
            enabled=$(grep -Ei '^\s*enabled\s*=' "$rfile" 2>/dev/null | tail -n 1 | cut -d= -f2 | tr -d ' ')

            [[ "$enabled" == "0" ]] && continue
            ((total_repos++))

            local domain
            domain=$(echo "$base_url" | awk -F/ '{print $3}')
            [[ -z "$domain" ]] && domain="$repo_id"

            if [[ "$domain" =~ $official_dnf_pattern ]]; then
                echo -e "  [${GREEN}OFFICIAL${NC}] ${CYAN}${repo_id}${NC} -> ${base_url:-$rfile}"
            else
                ((unofficial_repos++))
                echo -e "  [${RED}UNOFFICIAL / THIRD-PARTY${NC}] ${YELLOW}${repo_id}${NC} -> ${base_url:-$rfile}"
                repo_findings+="  - Unofficial DNF Repo (${repo_id}): ${base_url:-$rfile}\n"
            fi
        done
    fi

    if [[ "$unofficial_repos" -gt 0 ]]; then
        log_warn "Discovered ${unofficial_repos} unofficial/third-party package repositories:\n$repo_findings"
    else
        log_pass "Repository audit completed: All ${total_repos} configured package repositories belong to official distribution sources."
    fi
    echo ""
}

audit_package_repositories

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
    RECOMMENDED_PKGS=("fail2ban" "firewalld" "audit" "clamav" "chkrootkit" "trivy" "policycoreutils" "crypto-policies")
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
    RECOMMENDED_PKGS=("fail2ban" "ufw" "auditd" "apparmor" "unattended-upgrades" "clamav" "chkrootkit" "trivy" "needrestart" "debsums" "lynis")
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
            echo -e "${GREEN}[OK] No background services require restart.${NC}"
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
section "12/24" "Auditing Running Processes for Suspicious Activity & Malware Indicators..."

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

    echo -e "\n${YELLOW}--- 5. Checking for Hidden Processes & Rootkit Stealth Techniques ---${NC}"
    local hidden_found=0
    local hidden_procs_list=""

    # 1. LD_PRELOAD Userland Rootkit Inspection (/etc/ld.so.preload)
    if [[ -f "/etc/ld.so.preload" ]]; then
        local preload_content
        preload_content=$(run_sudo cat /etc/ld.so.preload 2>/dev/null | grep -v '^\s*#')
        if [[ -n "$preload_content" ]]; then
            log_crit "POTENTIAL USERLAND ROOTKIT: /etc/ld.so.preload exists and contains preloaded libraries:\n$preload_content"
            ((hidden_found++))
            ((threats_found++))
        fi
    fi

    # 2. /proc PID directory vs 'ps' process table comparison
    local proc_pids ps_pids
    proc_pids=$(find /proc -maxdepth 1 -type d -name "[0-9]*" 2>/dev/null | awk -F/ '{print $2}' | sort -n)
    ps_pids=$(ps -eo pid= 2>/dev/null | tr -d ' ' | sort -n)

    if [[ -n "$proc_pids" && -n "$ps_pids" ]]; then
        local hidden_pids
        hidden_pids=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))

        if [[ -n "$hidden_pids" ]]; then
            while read -r hpid; do
                [[ -z "$hpid" ]] && continue
                # Verify PID is still active in /proc to filter transient processes
                if [[ -d "/proc/$hpid" ]]; then
                    local hname huser hcmd
                    hname=$(run_sudo cat "/proc/$hpid/comm" 2>/dev/null || echo "Unknown")
                    hcmd=$(run_sudo cat "/proc/$hpid/cmdline" 2>/dev/null | tr '\0' ' ' || echo "N/A")
                    huser=$(run_sudo stat -c "%U" "/proc/$hpid" 2>/dev/null || echo "Unknown")
                    hidden_procs_list+="PID ${hpid} (User: ${huser}, Name: ${hname}) [Cmd: ${hcmd}]\n"
                    ((hidden_found++))
                    ((threats_found++))
                fi
            done <<< "$hidden_pids"
        fi
    fi

    if [[ -n "$hidden_procs_list" ]]; then
        log_crit "HIDDEN PROCESSES DETECTED (Present in /proc but hidden from 'ps'):\n$hidden_procs_list"
    fi

    # 3. Deep Hidden Process Scan using 'unhide' tool if installed
    local unhide_cmd="${TOOL_BIN['unhide']}"
    [[ -z "$unhide_cmd" ]] && unhide_cmd=$(find_tool "unhide")

    if [[ -n "$unhide_cmd" ]]; then
        echo -e "${CYAN}Running deep hidden process detection using 'unhide'...${NC}"
        local unhide_out
        unhide_out=$(run_sudo "$unhide_cmd" -m proc sys 2>/dev/null | grep -i "Found HIDDEN")
        if [[ -n "$unhide_out" ]]; then
            log_crit "Unhide tool detected hidden processes:\n$unhide_out"
            ((hidden_found++))
            ((threats_found++))
        fi
    fi

    if [[ "$hidden_found" -eq 0 ]]; then
        log_pass "Hidden process audit completed: No hidden processes or /etc/ld.so.preload rootkit indicators found."
    fi

    echo -e "\n${YELLOW}--- 6. Auditing Zombie & Orphan Processes ---${NC}"
    local zombie_count=0
    local orphan_count=0

    # 1. Zombie Processes Check & Remediation
    local zombie_procs
    zombie_procs=$(ps -eo pid,ppid,user,stat,comm 2>/dev/null | awk '$4 ~ /^Z/ {print $1":"$2":"$3":"$5}')

    if [[ -n "$zombie_procs" ]]; then
        echo -e "${CYAN}Discovered Zombie (Defunct) Processes:${NC}"
        while IFS=: read -r zpid zppid zuser zcomm; do
            [[ -z "$zpid" ]] && continue
            ((zombie_count++))
            ((threats_found++))
            local pcomm
            pcomm=$(ps -p "$zppid" -o comm= 2>/dev/null || echo "Unknown")
            log_warn "ZOMBIE PROCESS: PID ${zpid} (Name: '${zcomm}', User: ${zuser}) | Parent PPID ${zppid} (Name: '${pcomm}')"

            if [[ "$AUTO_FIX" == true ]]; then
                echo -n "  Attempting cleanup of Zombie PID ${zpid} (Notifying Parent PPID ${zppid})... "
                # Step A: Send SIGCHLD to parent process to harvest zombie
                run_sudo kill -SIGCHLD "$zppid" 2>/dev/null
                sleep 0.2
                if ! ps -p "$zpid" &>/dev/null; then
                    log_pass "Zombie PID ${zpid} successfully harvested by parent process."
                else
                    # Step B: If parent is not init/systemd, terminate parent process so PID 1 inherits and reaps the zombie
                    if [[ "$zppid" -gt 1 && "$pcomm" != "systemd" && "$pcomm" != "init" ]]; then
                        echo -n "  Parent did not harvest. Terminating parent process PPID ${zppid} (${pcomm})... "
                        run_sudo kill -15 "$zppid" 2>/dev/null || run_sudo kill -9 "$zppid" 2>/dev/null
                        sleep 0.2
                        if ! ps -p "$zpid" &>/dev/null; then
                            log_pass "Zombie PID ${zpid} reaped after parent process termination."
                        else
                            log_warn "Could not clean Zombie PID ${zpid} (Parent PPID ${zppid} active)."
                        fi
                    else
                        log_warn "Cannot kill Parent PPID ${zppid} (System daemon/Init)."
                    fi
                fi
            fi
        done <<< "$zombie_procs"
    else
        log_pass "No Zombie (defunct) processes detected."
    fi

    # 2. Orphan Processes Check
    echo -e "\n${CYAN}Auditing Active Orphan Processes (Re-parented to PID 1):${NC}"
    local orphan_procs=""
    while read -r opid ouser ostat oargs; do
        [[ -z "$opid" ]] && continue
        if [[ "$oargs" != *systemd* && "$oargs" != *dbus* && "$oargs" != *sshd* && "$oargs" != *NetworkManager* && "$oargs" != *journald* ]]; then
            orphan_procs+="PID ${opid} (User: ${ouser}, Stat: ${ostat}) [Cmd: ${oargs}]\n"
            ((orphan_count++))
        fi
    done < <(ps -eo pid,user,stat,args 2>/dev/null | awk '$1 != 1 && $2 != "root" && $3 !~ /^Z/ {print $1, $2, $3, $4}')

    if [[ -n "$orphan_procs" ]]; then
        log_warn "Discovered non-system Orphan processes (PPID=1):\n$orphan_procs"
    else
        log_pass "No non-system orphan processes detected."
    fi

    echo -e "\n${YELLOW}--- 7. Top CPU & RAM Consuming Processes ---${NC}"
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
section "13/24" "Auditing Shell Config Files (.bashrc, .zshrc) & Security Aliases (All Users)..."

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

    echo -e "\n${YELLOW}--- Auditing System \$PATH Environment Directories for Binary Hijacking Risk ---${NC}"
    local path_dirs=()
    IFS=':' read -ra path_dirs <<< "$PATH"

    local path_issues=0
    for pdir in "${path_dirs[@]}"; do
        if [[ -z "$pdir" || "$pdir" == "." ]]; then
            log_crit "DANGEROUS \$PATH ENTRY: Current directory '.' or empty entry found in \$PATH! Vulnerable to local binary hijacking."
            ((path_issues++))
            continue
        fi

        if [[ ! -d "$pdir" ]]; then
            log_warn "\$PATH directory '${pdir}' does not exist."
            continue
        fi

        # Dereference symlinks using stat -L to get target directory permissions and ownership
        local p_perm p_owner real_target
        p_perm=$(stat -L -c "%a" "$pdir" 2>/dev/null)
        p_owner=$(stat -L -c "%U" "$pdir" 2>/dev/null)
        real_target=$(readlink -f "$pdir" 2>/dev/null)

        # World-writable check: 3rd octal digit is 2, 3, 6, or 7 (other write bit set)
        if [[ "$p_perm" =~ [2367]$ ]]; then
            log_crit "WORLD-WRITABLE \$PATH DIRECTORY: '${pdir}' (Target: '${real_target}', Mode: ${p_perm}, Owner: ${p_owner})! Unprivileged users can drop malicious binaries to hijack root/user commands."
            ((path_issues++))
        elif [[ "$p_owner" != "root" ]]; then
            log_warn "\$PATH directory '${pdir}' is owned by non-root user '${p_owner}' (Mode: ${p_perm})."
        else
            echo -e "  - \$PATH Directory ${CYAN}${pdir}${NC}: ${GREEN}Secure permissions (${p_perm}, Owner: ${p_owner})${NC}"
        fi
    done

    if [[ "$path_issues" -eq 0 ]]; then
        log_pass "All directories in system \$PATH are secure, non-world-writable, and owned by root."
    fi
}

audit_shell_configs_and_aliases

# 14. SUID / SGID Executable File Audit & GTFOBins Privilege Escalation Risk
section "14/24" "Auditing SUID / SGID Executables & Privilege Escalation Risks..."

audit_suid_files() {
    echo -e "${YELLOW}--- 14.1 SUID/SGID Binaries in Volatile & Non-Standard Paths ---${NC}"
    local suspicious_suid
    suspicious_suid=$(run_sudo find /tmp /var/tmp /dev/shm /home /opt /var/www /srv -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
    if [[ -n "$suspicious_suid" ]]; then
        log_crit "SUID/SGID executable files found in volatile / user / web paths:\n$(echo "$suspicious_suid" | sed 's/^/  - /')"
    else
        log_pass "No SUID/SGID files found in volatile or user paths (/tmp, /dev/shm, /home, /opt, /var/www)."
    fi

    echo -e "\n${YELLOW}--- 14.2 System-Wide SUID Binaries & GTFOBins Privilege Escalation Risk ---${NC}"
    local suid_files=()
    while read -r sfile; do
        [[ -f "$sfile" ]] && suid_files+=("$sfile")
    done < <(run_sudo find /usr/bin /usr/sbin /bin /sbin /usr/lib /usr/libexec -type f -perm -4000 2>/dev/null)

    echo -e "  Total SUID binaries in system paths: ${CYAN}${#suid_files[@]}${NC}"

    local gtfobins_pattern="find|vim|vi|bash|sh|python|python3|perl|php|awk|less|more|nmap|env|gdb|strace|tcpdump|tar|cp|mv|base64|cpulimit|docker|date|dd|flock|ionice|nice|taskset|time|timeout|watch|xargs|zip|zsh"
    local gtfobins_suid=()

    for sfile in "${suid_files[@]}"; do
        local fname
        fname=$(basename "$sfile")
        if [[ "$fname" =~ ^($gtfobins_pattern)$ ]]; then
            gtfobins_suid+=("$sfile")
        fi
    done

    if [[ ${#gtfobins_suid[@]} -gt 0 ]]; then
        log_crit "DANGEROUS SUID GTFOBINS BINARIES DETECTED:\n$(printf '  - %s\n' "${gtfobins_suid[@]}")\nThese SUID binaries allow immediate local privilege escalation to root shell!"
    else
        log_pass "No GTFOBins privilege escalation binaries have SUID flags enabled."
    fi

    echo -e "\n${YELLOW}--- 14.3 World-Writable System Files Audit ---${NC}"
    local ww_files
    ww_files=$(run_sudo find /etc /var /opt /usr /boot -type f -perm -0002 ! -path "/proc*" ! -path "/sys*" ! -path "/dev*" ! -path "/run*" 2>/dev/null | head -n 20)
    if [[ -n "$ww_files" ]]; then
        log_crit "WORLD-WRITABLE FILES DETECTED in system paths:\n$(echo "$ww_files" | sed 's/^/  - /')\nAny unprivileged user can modify or replace these files!"
    else
        log_pass "No world-writable files found in system directories (/etc, /var, /usr, /opt)."
    fi
}
audit_suid_files

# 15. Persistence Audit (Cron Jobs & Systemd Timers)
section "15/24" "Auditing System Persistence (Cron Jobs & Systemd Timers)..."
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

# 16. SSH authorized_keys & Remote Access Security Audit (All Users)
section "16/24" "Auditing SSH Authorized Keys & Remote Access Permissions (All Users)..."

audit_authorized_keys() {
    local keys_count=0
    local weak_keys_found=0
    local insecure_perms_found=0
    local unrestricted_admin_keys=0

    echo -e "${YELLOW}--- Auditing SSH Authorized Keys Across All System Accounts ---${NC}"

    while IFS=: read -r username password uid gid gecos home shell; do
        [[ -d "$home" ]] || continue

        local ssh_dir="$home/.ssh"
        if [[ -d "$ssh_dir" ]]; then
            local dir_perm dir_owner
            dir_perm=$(stat -c "%a" "$ssh_dir" 2>/dev/null)
            dir_owner=$(stat -c "%U:%G" "$ssh_dir" 2>/dev/null)
            if [[ "$dir_perm" =~ ^(755|775|777)$ ]]; then
                log_crit "User '${username}': Loose permissions on ${ssh_dir} (${dir_perm})! Directory should be 700 to prevent key tampering."
                ((insecure_perms_found++))
            fi
        fi

        local auth_files=(
            "$home/.ssh/authorized_keys"
            "$home/.ssh/authorized_keys2"
        )

        for auth_keys in "${auth_files[@]}"; do
            if [[ -f "$auth_keys" ]]; then
                local file_perm file_owner
                file_perm=$(stat -c "%a" "$auth_keys" 2>/dev/null)
                file_owner=$(stat -c "%U:%G" "$auth_keys" 2>/dev/null)

                if [[ "$file_perm" =~ ^(644|664|666|777)$ ]]; then
                    log_crit "User '${username}': Loose permissions on ${auth_keys} (${file_perm})! File is readable/writable by group or others. Recommended: 600."
                    ((insecure_perms_found++))
                fi

                while read -r raw_line; do
                    [[ -z "$raw_line" || "$raw_line" =~ ^\s*# ]] && continue
                    ((keys_count++))

                    local key_options=""
                    local ktype=""
                    local comment=""

                    if [[ "$raw_line" =~ ^(command|from|environment|no-|principals|restrict|cert-authority|tunnel) ]]; then
                        key_options=$(echo "$raw_line" | awk '{print $1}')
                        ktype=$(echo "$raw_line" | awk '{print $2}')
                        comment=$(echo "$raw_line" | awk '{print $NF}')
                    else
                        ktype=$(echo "$raw_line" | awk '{print $1}')
                        comment=$(echo "$raw_line" | awk '{print $NF}')
                    fi

                    local is_admin=false
                    if [[ "$uid" -eq 0 || "$username" == "root" ]]; then
                        is_admin=true
                    elif groups "$username" 2>/dev/null | grep -qE '\b(sudo|wheel|admin)\b'; then
                        is_admin=true
                    fi

                    if [[ "$is_admin" == true ]]; then
                        if [[ "$raw_line" != *"from="* ]]; then
                            log_warn "User '${username}' (Administrative Account): Authorized key '${comment}' has NO 'from=\"IP\"' restriction! Key can connect from any remote host."
                            ((unrestricted_admin_keys++))
                        else
                            local from_val
                            from_val=$(echo "$raw_line" | grep -o 'from="[^"]*"' || echo "from=restricted")
                            log_pass "User '${username}': Authorized key '${comment}' is IP-restricted (${from_val})."
                        fi
                    fi

                    case "$ktype" in
                        ssh-dss|dss)
                            log_crit "User '${username}': Obsolete & insecure DSA key in ${auth_keys} ('${comment}')! DSA 1024-bit keys are cryptographically broken."
                            ((weak_keys_found++))
                            ;;
                        ssh-rsa)
                            echo -e "    - User ${CYAN}${username}${NC}: RSA Key ('${comment:-no comment}')"
                            ;;
                        ssh-ed25519)
                            echo -e "    - User ${CYAN}${username}${NC}: ${GREEN}Ed25519 Key${NC} ('${comment:-no comment}')"
                            ;;
                        ecdsa-sha2-*)
                            echo -e "    - User ${CYAN}${username}${NC}: ${GREEN}ECDSA Key${NC} ('${comment:-no comment}')"
                            ;;
                    esac

                done < "$auth_keys"
            fi
        done
    done < /etc/passwd

    if [[ -f "/etc/ssh/authorized_keys" ]]; then
        local global_key_cnt
        global_key_cnt=$(grep -v '^#' /etc/ssh/authorized_keys 2>/dev/null | grep -v '^\s*$' | wc -l)
        if [[ "$global_key_cnt" -gt 0 ]]; then
            log_warn "Global SSH authorized_keys file detected (/etc/ssh/authorized_keys) containing ${global_key_cnt} key(s)."
        fi
    fi

    if [[ "$keys_count" -eq 0 ]]; then
        log_pass "No SSH authorized_keys files found across system user accounts."
    else
        log_pass "Audited ${keys_count} SSH authorized key(s) across all system users."
    fi
}
audit_authorized_keys

# 17. Docker & Kubernetes Container Security Audit
section "17/24" "Auditing Docker & Container Security Settings..."
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

# 18. Kernel Security Hardening & GRUB Bootloader Audit
section "18/24" "Auditing Kernel Hardening (sysctl) & GRUB Bootloader Configuration..."

audit_grub_bootloader() {
    echo -e "${YELLOW}--- Bootloader & GRUB Security Configuration Audit ---${NC}"

    local grub_cfg_files=(
        "/boot/grub/grub.cfg"
        "/boot/grub2/grub.cfg"
        "/boot/efi/EFI/debian/grub.cfg"
        "/boot/efi/EFI/ubuntu/grub.cfg"
        "/boot/efi/EFI/redhat/grub.cfg"
        "/boot/efi/EFI/centos/grub.cfg"
        "/boot/efi/EFI/fedora/grub.cfg"
    )
    local default_grub="/etc/default/grub"
    local found_grub_cfg=""

    # 18.1 GRUB Config File Discovery & Permissions Audit
    for cfg in "${grub_cfg_files[@]}"; do
        if [[ -f "$cfg" ]]; then
            found_grub_cfg="$cfg"
            local owner_group perm
            owner_group=$(stat -c "%U:%G" "$cfg" 2>/dev/null)
            perm=$(stat -c "%a" "$cfg" 2>/dev/null)

            echo -e "  Found GRUB config file      : ${CYAN}${cfg}${NC} (Perms: ${perm}, Owner: ${owner_group})"

            if [[ "$owner_group" != "root:root" && "$owner_group" != "root:wheel" ]]; then
                log_warn "Insecure ownership on ${cfg}: owned by '${owner_group}' (Expected: root:root)."
            fi

            if [[ "$perm" =~ ^(600|700|400|440)$ ]]; then
                log_pass "GRUB config permissions verified (${cfg}: ${perm})."
            else
                log_warn "Insecure permissions on ${cfg} (${perm})! GRUB config is readable by non-root users. Recommended permissions: 600 or 700."
            fi
            break
        fi
    done

    if [[ -z "$found_grub_cfg" ]]; then
        if [[ -d "/sys/firmware/efi" ]]; then
            echo -e "  ${YELLOW}No standard GRUB configuration file found at /boot/grub/grub.cfg. System may use systemd-boot or EFI stub.${NC}"
        else
            echo -e "  ${YELLOW}No GRUB configuration file found in standard /boot locations.${NC}"
        fi
    fi

    if [[ -f "$default_grub" ]]; then
        local def_perm def_owner
        def_perm=$(stat -c "%a" "$default_grub" 2>/dev/null)
        def_owner=$(stat -c "%U:%G" "$default_grub" 2>/dev/null)
        echo -e "  GRUB environment config     : ${CYAN}${default_grub}${NC} (Perms: ${def_perm}, Owner: ${def_owner})"
        if [[ "$def_perm" =~ ^(644|600|400)$ ]]; then
            log_pass "/etc/default/grub permissions verified (${def_perm})."
        else
            log_warn "Insecure permissions on ${default_grub} (${def_perm}). Recommended: 644 or 600."
        fi
    fi

    # 18.2 GRUB Password Protection Audit
    echo -e "\n${YELLOW}--- GRUB Password Protection & Bootloader Authentication Audit ---${NC}"
    local password_protected=false
    if [[ -n "$found_grub_cfg" && -r "$found_grub_cfg" ]]; then
        if grep -qE "password_pbkdf2|password " "$found_grub_cfg" 2>/dev/null; then
            password_protected=true
        fi
    fi

    if [[ "$password_protected" == false && -d "/etc/grub.d" ]]; then
        if grep -rqE "password_pbkdf2|password " /etc/grub.d/ 2>/dev/null; then
            password_protected=true
        fi
    fi

    if [[ "$password_protected" == true ]]; then
        log_pass "GRUB password protection is configured (PBKDF2/password protection active)."
    else
        log_warn "GRUB bootloader is NOT password protected! Users with physical or console access can modify boot options or gain root shell."
    fi

    # 18.3 Recovery Mode & Timeout Audit
    echo -e "\n${YELLOW}--- GRUB Recovery Mode & Unauthenticated Boot Settings ---${NC}"
    if [[ -f "$default_grub" ]]; then
        local disable_rec
        disable_rec=$(grep -v '^\s*#' "$default_grub" 2>/dev/null | grep -i 'GRUB_DISABLE_RECOVERY' | cut -d'=' -f2 | tr -d '"' | tr -d "'")
        if [[ "$disable_rec" == "true" || "$disable_rec" == "1" ]]; then
            log_pass "Unauthenticated GRUB recovery mode menu entries are disabled."
        else
            log_warn "GRUB recovery mode entries are enabled (GRUB_DISABLE_RECOVERY is not 'true'). Booting into recovery mode allows unauthenticated root access."
        fi

        local timeout_val
        timeout_val=$(grep -v '^\s*#' "$default_grub" 2>/dev/null | grep -i 'GRUB_TIMEOUT=' | head -n 1 | cut -d'=' -f2 | tr -d '"' | tr -d "'")
        if [[ -n "$timeout_val" ]]; then
            echo -e "  GRUB Menu Timeout           : ${CYAN}${timeout_val} second(s)${NC}"
            if [[ "$timeout_val" -eq -1 || "$timeout_val" -gt 10 ]]; then
                log_warn "GRUB_TIMEOUT is set to ${timeout_val}s (extended delay increases boot menu tampering window). Recommended: <= 5 seconds."
            else
                log_pass "GRUB boot menu timeout configuration verified (${timeout_val}s)."
            fi
        fi
    fi

    # 18.4 Kernel Boot Parameters Audit (/proc/cmdline)
    echo -e "\n${YELLOW}--- Active Kernel Boot Parameters Audit (/proc/cmdline) ---${NC}"
    if [[ -f "/proc/cmdline" ]]; then
        local cmdline
        cmdline=$(cat /proc/cmdline 2>/dev/null)
        echo -e "  Active Kernel Cmdline: ${CYAN}${cmdline}${NC}"

        local dangerous_params=("init=/bin/bash" "init=/bin/sh" "rd.break" "emerg" "emergency")
        for dp in "${dangerous_params[@]}"; do
            if [[ "$cmdline" =~ $dp ]]; then
                log_crit "DANGEROUS BOOT PARAMETER ACTIVE: Kernel parameter '${dp}' is active in /proc/cmdline! Direct root shell execution on boot!"
            fi
        done

        if [[ "$cmdline" =~ [[:space:]](single|1|s|S)[[:space:]]? ]]; then
            log_warn "Kernel is booting in single-user maintenance mode!"
        fi

        if [[ "$cmdline" =~ selinux=0|enforcing=0|apparmor=0 ]]; then
            log_warn "Mandatory Access Control framework disabled in kernel boot parameters!"
        fi

        if [[ "$cmdline" =~ mitigations=off|noibrs|noibpb|nopti|nospectre_v1|nospectre_v2|nospec_store_bypass_disable ]]; then
            log_warn "CPU vulnerability mitigations disabled in kernel boot parameters!"
        else
            log_pass "CPU vulnerability mitigations are active in kernel parameters."
        fi

        if [[ "$cmdline" =~ audit=1 ]]; then
            log_pass "Kernel auditing parameter 'audit=1' is enabled."
        else
            echo -e "  ${YELLOW}Tip: Consider adding 'audit=1' to GRUB_CMDLINE_LINUX to enable early boot kernel auditing.${NC}"
        fi
    fi

    # 18.5 UEFI Secure Boot Audit
    echo -e "\n${YELLOW}--- UEFI Secure Boot Status Audit ---${NC}"
    if [[ "${TOOL_FOUND['mokutil']}" -eq 1 ]]; then
        local sb_out
        sb_out=$(mokutil --sb-state 2>/dev/null)
        if [[ "$sb_out" =~ "SecureBoot enabled" ]]; then
            log_pass "UEFI Secure Boot is ENABLED."
        else
            log_warn "UEFI Secure Boot is DISABLED: ${sb_out}"
        fi
    elif [[ -d "/sys/firmware/efi" ]]; then
        local sb_var
        sb_var=$(find /sys/firmware/efi/efivars/ -name "SecureBoot-*" 2>/dev/null | head -n 1)
        if [[ -n "$sb_var" ]]; then
            local sb_val
            sb_val=$(od -An -t u1 "$sb_var" 2>/dev/null | awk '{print $NF}')
            if [[ "$sb_val" == "1" ]]; then
                log_pass "UEFI Secure Boot is ENABLED (via efivars)."
            else
                log_warn "UEFI Secure Boot is DISABLED (via efivars)."
            fi
        else
            echo -e "  UEFI firmware detected, but SecureBoot efivar status could not be read."
        fi
    else
        echo -e "  Legacy BIOS system detected (UEFI Secure Boot not applicable)."
    fi
}

audit_grub_bootloader

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
    check_sysctl "fs.suid_dumpable" "0"

    # --- ASLR (Address Space Layout Randomization) ---
    local aslr_val
    aslr_val=$("$sysctl_cmd" -n kernel.randomize_va_space 2>/dev/null)
    echo -e "\n  ${CYAN}ASLR (kernel.randomize_va_space)  : ${aslr_val}${NC} (2=full randomization, 1=conservative, 0=DISABLED)"
    if [[ "$aslr_val" == "2" ]]; then
        log_pass "kernel.randomize_va_space=2: Full ASLR enabled (mmap, heap, stack, VDSO randomized)."
    elif [[ "$aslr_val" == "1" ]]; then
        log_warn "kernel.randomize_va_space=1: Conservative ASLR only (stack/mmap randomized, heap not). Recommended: 2."
    else
        log_crit "kernel.randomize_va_space=${aslr_val}: ASLR is DISABLED! Exploit mitigations (ROP/heap spraying) are ineffective."
    fi

    # --- ptrace_scope ---
    local ptrace_val
    ptrace_val=$("$sysctl_cmd" -n kernel.yama.ptrace_scope 2>/dev/null)
    if [[ -n "$ptrace_val" ]]; then
        echo -e "  ${CYAN}ptrace_scope (kernel.yama)        : ${ptrace_val}${NC} (0=any process can ptrace, 1=restricted, 2=admin-only, 3=no attach)"
        if [[ "$ptrace_val" -ge 1 ]]; then
            log_pass "kernel.yama.ptrace_scope=${ptrace_val}: ptrace attach is restricted (Yama LSM active)."
        else
            log_warn "kernel.yama.ptrace_scope=0: any process with matching UID can ptrace others (credential/secret extraction via memory inspection). Recommended: >= 1."
        fi
    else
        echo -e "  ${YELLOW}kernel.yama.ptrace_scope not available (Yama LSM not built into this kernel).${NC}"
    fi

    # --- SYN cookies (SYN flood mitigation) ---
    local syncookies_val
    syncookies_val=$("$sysctl_cmd" -n net.ipv4.tcp_syncookies 2>/dev/null)
    echo -e "  ${CYAN}TCP SYN cookies                  : ${syncookies_val}${NC}"
    if [[ "$syncookies_val" == "1" ]]; then
        log_pass "net.ipv4.tcp_syncookies=1: SYN flood/DoS mitigation enabled."
    else
        log_warn "net.ipv4.tcp_syncookies=${syncookies_val}: SYN cookie protection is disabled. Recommended: 1."
    fi

    # --- IPv6 forwarding (if IPv6 is enabled) ---
    local ipv6_fwd
    ipv6_fwd=$("$sysctl_cmd" -n net.ipv6.conf.all.forwarding 2>/dev/null)
    if [[ -n "$ipv6_fwd" && "$ipv6_fwd" != "0" ]]; then
        log_warn "net.ipv6.conf.all.forwarding=${ipv6_fwd}: IPv6 forwarding is enabled on a non-router system."
    fi

    # --- Kernel version & unpatched CVE exposure check ---
    echo -e "\n${YELLOW}--- Kernel Version & Unpatched CVE Exposure Check ---${NC}"
    local kernel_ver kernel_build_date
    kernel_ver=$(uname -r)
    kernel_build_date=$(uname -v)
    echo -e "  Running Kernel Version       : ${CYAN}${kernel_ver}${NC} (${kernel_build_date})"

    # A pending kernel security update strongly implies unpatched known CVEs in the running kernel.
    local kernel_update_pending=""
    if [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
        kernel_update_pending=$(apt list --upgradable 2>/dev/null | grep -E '^linux-(image|kernel|firmware)' | head -n 5)
    elif [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
        kernel_update_pending=$(dnf -q updateinfo list security --installed 2>/dev/null | grep -iE 'kernel' | head -n 5)
    fi
    if [[ -n "$kernel_update_pending" ]]; then
        log_crit "PENDING KERNEL SECURITY UPDATE: the running kernel (${kernel_ver}) has known unpatched CVEs. Update and reboot immediately:\n$kernel_update_pending"
    else
        log_pass "No pending kernel security updates detected for running kernel (${kernel_ver})."
    fi

    # Warn if the system has not rebooted into a freshly installed kernel (old running kernel after patch).
    if [[ -f "/boot/vmlinuz-${kernel_ver}" || -d "/boot" ]]; then
        local newest_kernel
        if [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
            newest_kernel=$(rpm -q --qf '%{BUILDTIME}\n' kernel-core 2>/dev/null | sort -n | tail -n 1)
        fi
        local uptime_days
        uptime_days=$(awk '{printf "%d", $1/86400}' /proc/uptime 2>/dev/null)
        if [[ -n "$uptime_days" && "$uptime_days" -gt 90 ]]; then
            log_warn "System uptime is ${uptime_days} days: if kernel patches were installed without reboot, the running kernel may still expose patched CVEs (reboot required)."
        fi
    fi

    echo -e "\n${YELLOW}--- Core Dumps & Memory Leakage Hardening ---${NC}"
    local core_pattern
    core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
    echo -e "  System Core Pattern        : ${CYAN}${core_pattern:-default}${NC}"
    if [[ "$core_pattern" =~ ^/tmp/|^/var/tmp/|^/dev/shm/ ]]; then
        log_crit "INSECURE CORE PATTERN: Core dumps write process memory to world-writable directory: ${core_pattern}!"
    else
        log_pass "Core dump pattern configuration verified."
    fi
}
audit_kernel_hardening

# 19. Network DNS, Encrypted DNS (DoH/DoT) & /etc/hosts Integrity Audit
section "19/24" "Auditing DNS Settings, Encrypted DNS (DoH/DoT) & /etc/hosts Integrity..."

audit_dns_hosts() {
    # 19.1 DNS Resolvers & /etc/resolv.conf Integrity Audit
    echo -e "${YELLOW}--- 19.1 DNS Resolvers & /etc/resolv.conf Integrity Audit ---${NC}"
    local resolv_file="/etc/resolv.conf"
    
    if [[ -L "$resolv_file" ]]; then
        local link_target
        link_target=$(readlink -f "$resolv_file" 2>/dev/null)
        echo -e "  /etc/resolv.conf mode      : ${CYAN}Symlink -> ${link_target}${NC}"
        log_pass "/etc/resolv.conf is managed dynamically via symlink (${link_target})."
    elif [[ -f "$resolv_file" ]]; then
        local r_perm r_owner
        r_perm=$(stat -c "%a" "$resolv_file" 2>/dev/null)
        r_owner=$(stat -c "%U:%G" "$resolv_file" 2>/dev/null)
        echo -e "  /etc/resolv.conf mode      : ${CYAN}Static File (Perms: ${r_perm}, Owner: ${r_owner})${NC}"
        if [[ "$r_perm" =~ ^(644|600|400)$ ]]; then
            log_pass "/etc/resolv.conf file permissions verified (${r_perm})."
        else
            log_warn "Loose permissions on /etc/resolv.conf (${r_perm})! Non-root processes might modify DNS servers."
        fi
    else
        log_warn "/etc/resolv.conf file is missing!"
    fi

    # Check immutable attribute (+i)
    if command -v lsattr &>/dev/null && [[ -f "$resolv_file" ]]; then
        local attr
        attr=$(lsattr "$resolv_file" 2>/dev/null | awk '{print $1}')
        if [[ "$attr" =~ i ]]; then
            log_pass "/etc/resolv.conf has immutable attribute (+i) set against unauthorized tampering."
        fi
    fi

    # Extract nameservers
    if [[ -f "$resolv_file" ]]; then
        echo -e "\n  ${CYAN}Configured Nameservers in /etc/resolv.conf:${NC}"
        local nameservers=()
        while read -r line; do
            [[ -z "$line" ]] && continue
            local ns_ip
            ns_ip=$(echo "$line" | awk '{print $2}')
            [[ -z "$ns_ip" ]] && continue
            nameservers+=("$ns_ip")
            
            local ns_type="Public / Upstream DNS"
            if [[ "$ns_ip" =~ ^127\. || "$ns_ip" == "::1" ]]; then
                ns_type="Local Stub Resolver (systemd-resolved / dnsmasq)"
            elif [[ "$ns_ip" =~ ^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; then
                ns_type="Local Gateway / LAN Router DNS"
            elif [[ "$ns_ip" == "1.1.1.1" || "$ns_ip" == "1.0.0.1" ]]; then
                ns_type="Cloudflare Public DNS (Secured)"
            elif [[ "$ns_ip" == "8.8.8.8" || "$ns_ip" == "8.8.4.4" ]]; then
                ns_type="Google Public DNS"
            elif [[ "$ns_ip" == "9.9.9.9" || "$ns_ip" == "149.112.112.112" ]]; then
                ns_type="Quad9 Threat-Blocking DNS"
            elif [[ "$ns_ip" == "94.140.14.14" || "$ns_ip" == "94.140.15.15" ]]; then
                ns_type="AdGuard Public DNS"
            fi

            echo -e "    - ${CYAN}${ns_ip}${NC} (${ns_type})"
        done < <(grep '^nameserver' "$resolv_file" 2>/dev/null)

        if [[ ${#nameservers[@]} -eq 0 ]]; then
            log_crit "No active nameservers defined in /etc/resolv.conf! DNS resolution will fail!"
        else
            log_pass "Extracted ${#nameservers[@]} active DNS nameserver(s)."
        fi
    fi

    # 19.2 Encrypted DNS (DoH / DoT), DNSSEC & Resolver Security Audit
    echo -e "\n${YELLOW}--- 19.2 Encrypted DNS (DoH / DoT), DNSSEC & Resolver Security Audit ---${NC}"
    if command -v resolvectl &>/dev/null; then
        local rctl_status
        rctl_status=$(resolvectl status 2>/dev/null)
        if [[ -n "$rctl_status" ]]; then
            local doh_line dnssec_line
            doh_line=$(echo "$rctl_status" | grep -i "DNSOverTLS" | head -n 1)
            dnssec_line=$(echo "$rctl_status" | grep -i "DNSSEC" | head -n 1)

            echo -e "  systemd-resolved DoT Status : ${CYAN}${doh_line:-Not reported}${NC}"
            echo -e "  systemd-resolved DNSSEC     : ${CYAN}${dnssec_line:-Not reported}${NC}"

            if [[ "$doh_line" =~ yes|opportunistic ]]; then
                log_pass "DNS-over-TLS (DoT) is active in systemd-resolved."
            else
                log_warn "DNS-over-TLS (DoT) is NOT enabled in systemd-resolved (DNS queries are transmitted in plain text)."
            fi

            if [[ "$dnssec_line" =~ yes|allow-downgrade ]]; then
                log_pass "DNSSEC validation is active in systemd-resolved."
            else
                echo -e "  ${YELLOW}Tip: Consider enabling DNSSEC in /etc/systemd/resolved.conf (DNSSEC=allow-downgrade).${NC}"
            fi
        fi
    fi

    local doh_proxies=("cloudflared" "dnscrypt-proxy" "stubby" "adguardhome" "dnsmasq" "unbound")
    local found_doh_daemon=""
    for proxy in "${doh_proxies[@]}"; do
        if pgrep -x "$proxy" &>/dev/null; then
            found_doh_daemon+="${proxy} "
        fi
    done

    if [[ -n "$found_doh_daemon" ]]; then
        log_pass "Active Encrypted DNS / DoH Proxy Daemon(s) detected: ${found_doh_daemon}"
    fi

    # 19.3 DNS Resolution Hijacking & /etc/hosts Integrity Audit
    echo -e "\n${YELLOW}--- 19.3 DNS Resolution Hijacking & /etc/hosts Integrity Audit ---${NC}"
    if [[ -f "/etc/hosts" ]]; then
        local custom_hosts
        custom_hosts=$(grep -vE '^\s*#|localhost|127\.0\.0\.1|127\.0\.1\.1|::1|fe00::0|ff02::' /etc/hosts 2>/dev/null | grep -v '^\s*$')
        if [[ -n "$custom_hosts" ]]; then
            echo -e "${CYAN}Custom /etc/hosts entries:${NC}"
            echo "$custom_hosts" | sed 's/^/  - /'
            log_warn "Custom static /etc/hosts overrides detected. Verify that no security or update domains are hijacked."
        else
            log_pass "No unusual custom entries in /etc/hosts."
        fi
    fi

    echo -e "  Testing functional DNS resolution (google.com)..."
    local test_ip
    test_ip=$(getent ahosts google.com 2>/dev/null | head -n 1 | awk '{print $1}')
    if [[ -n "$test_ip" ]]; then
        log_pass "System DNS resolution functional (google.com -> ${test_ip})."
    else
        log_warn "System DNS resolution test failed or timed out for google.com!"
    fi
}
audit_dns_hosts

# 20. Connected Hardware Devices, Wi-Fi Networks & Local Network Hosts Audit
section "20/24" "Auditing Connected Hardware Devices, Wi-Fi Security & Local Network Hosts..."

audit_connected_devices() {
    echo -e "${YELLOW}--- Connected Hardware Devices & Removable Storage Media Audit ---${NC}"

    # 1. USB Connected Devices Audit (lsusb / sysfs)
    echo -e "${CYAN}1. Connected USB Devices (lsusb):${NC}"
    if command -v lsusb &>/dev/null; then
        local usb_devices
        usb_devices=$(lsusb 2>/dev/null)
        if [[ -n "$usb_devices" ]]; then
            echo "$usb_devices" | sed 's/^/  - /'
            local usb_count
            usb_count=$(echo "$usb_devices" | wc -l)
            log_pass "Discovered ${usb_count} connected USB device(s)."

            # Detect potential suspicious USB HID attack tools & sniffing hardware
            local suspicious_usb
            suspicious_usb=$(echo "$usb_devices" | grep -Ei "rubber|ducky|badusb|keysmith|keystroke|wireless[ _]?sniffer|packet[ _]?sniffer|wifi[ _]?pineapple|lan[ _]?turtle|bash[ _]?bunny|pwnagotchi")
            if [[ -n "$suspicious_usb" ]]; then
                log_crit "POTENTIAL SUSPICIOUS USB DEVICE DETECTED:\n$suspicious_usb"
            fi
        else
            echo "No USB devices detected."
        fi
    elif [[ -d "/sys/bus/usb/devices" ]]; then
        local sys_usb_count
        sys_usb_count=$(find /sys/bus/usb/devices -maxdepth 1 -type l 2>/dev/null | wc -l)
        echo -e "  Discovered ${CYAN}${sys_usb_count}${NC} USB device nodes in /sys/bus/usb/devices."
    fi

    # 2. Block Storage & Removable Drives Audit (lsblk)
    echo -e "\n${CYAN}2. Block Storage Devices & Removable Media (lsblk):${NC}"
    if command -v lsblk &>/dev/null; then
        local block_devs
        block_devs=$(lsblk -o NAME,SIZE,TYPE,TRAN,RM,MOUNTPOINT,RO 2>/dev/null)
        if [[ -n "$block_devs" ]]; then
            echo "$block_devs" | sed 's/^/  /'

            local removable_mounts
            removable_mounts=$(lsblk -rn -o NAME,TRAN,RM,MOUNTPOINT 2>/dev/null | awk '$3 == "1" || $2 == "usb" {if ($4 != "") print $1, $4}')
            if [[ -n "$removable_mounts" ]]; then
                log_warn "Mounted removable storage media detected:\n$removable_mounts"
                
                # Check mount security options (noexec, nosuid, nodev)
                while read -r dev mpoint; do
                    [[ -z "$mpoint" ]] && continue
                    local mopts
                    mopts=$(findmnt -n -o OPTIONS "$mpoint" 2>/dev/null)
                    if [[ "$mopts" != *noexec* || "$mopts" != *nosuid* ]]; then
                        log_warn "Removable media mounted at '${mpoint}' lacks 'noexec' or 'nosuid' mount flags! (Current options: ${mopts:-default})"
                    else
                        log_pass "Removable media mounted at '${mpoint}' has secure mount options (${mopts})."
                    fi
                done <<< "$removable_mounts"
            else
                log_pass "No mounted removable storage drives (USB/SD cards) detected."
            fi
        fi
    fi

    # 3. PCI Hardware Controllers Audit (lspci)
    echo -e "\n${CYAN}3. PCI Hardware Controllers (lspci):${NC}"
    if command -v lspci &>/dev/null; then
        local pci_summary
        pci_summary=$(lspci 2>/dev/null | grep -Ei "VGA|Network|Ethernet|Wireless|Thunderbolt|RAID|SATA|NVMe" | head -n 10)
        if [[ -n "$pci_summary" ]]; then
            echo "$pci_summary" | sed 's/^/  - /'
        fi
    fi

    # 4. Bluetooth Controller & Discoverability Audit
    echo -e "\n${CYAN}4. Bluetooth Adapter & Pairing Status:${NC}"
    if command -v bluetoothctl &>/dev/null; then
        local bt_status
        bt_status=$(bluetoothctl show 2>/dev/null)
        if [[ -n "$bt_status" ]]; then
            local bt_power bt_disc
            bt_power=$(echo "$bt_status" | grep -i "Powered:" | awk '{print $2}')
            bt_disc=$(echo "$bt_status" | grep -i "Discoverable:" | awk '{print $2}')
            echo -e "  Bluetooth Powered     : ${CYAN}${bt_power:-unknown}${NC}"
            echo -e "  Bluetooth Discoverable: ${CYAN}${bt_disc:-unknown}${NC}"

            if [[ "$bt_disc" == "yes" ]]; then
                log_warn "Bluetooth adapter is DISCOVERABLE to nearby un-paired devices!"
            else
                log_pass "Bluetooth adapter is non-discoverable."

            fi
        else
            echo "Bluetooth controller inactive or not present."
        fi
    elif command -v hciconfig &>/dev/null; then
        local hci_info
        hci_info=$(hciconfig 2>/dev/null | grep -E "hci[0-9]|UP|RUNNING|ISCAN|PSCAN")
        if [[ -n "$hci_info" ]]; then
            echo "$hci_info" | sed 's/^/  - /'
        fi
    else
        echo "Bluetooth stack/tools not present."
    fi
    echo ""
}

audit_connected_devices

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

# ==============================================================================
# 21. Pending Updates & Automatic Security Updates Audit
# ==============================================================================
section "21/24" "Auditing Pending Package Updates & Automatic Security Updates..."

audit_pending_updates() {
    echo -e "${YELLOW}--- Pending Package Updates Count (Security & Total) ---${NC}"

    local total_updates=0 security_updates=0

    if [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
        total_updates=$(apt list --upgradable 2>/dev/null | grep -c '^' 2>/dev/null)
        # subtract the "Listing..." header line
        [[ "$total_updates" -gt 0 ]] && total_updates=$((total_updates - 1))
        [[ "$total_updates" -lt 0 ]] && total_updates=0
        security_updates=$(apt-get -s dist-upgrade 2>/dev/null | grep -cE '^Inst [^ ]+ \([^ ]* .*(security|-security|updates)' || true)
        echo -e "  Total packages awaiting update : ${CYAN}${total_updates}${NC}"
        echo -e "  Security updates pending        : ${CYAN}${security_updates}${NC}"
    elif [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
        total_updates=$(dnf -q check-update 2>/dev/null | grep -cE '^[a-zA-Z0-9]' || true)
        security_updates=$(dnf -q updateinfo list security --installed 2>/dev/null | grep -cE '^[a-zA-Z0-9]' || true)
        echo -e "  Total packages awaiting update : ${CYAN}${total_updates}${NC}"
        echo -e "  Security updates pending        : ${CYAN}${security_updates}${NC}"
    else
        echo -e "  ${YELLOW}No supported package manager found for update counting.${NC}"
    fi

    if [[ "$security_updates" -gt 0 ]]; then
        log_crit "${security_updates} SECURITY update(s) are pending installation! Known CVEs are exploitable until patched. Run the package manager update immediately."
    elif [[ "$total_updates" -gt 0 ]]; then
        log_warn "${total_updates} package update(s) available (no explicit security flags detected). Regular patching is recommended."
    else
        log_pass "All installed packages are up to date."
    fi

    # --- Automatic security updates ---
    echo -e "\n${YELLOW}--- Automatic Security Updates Status ---${NC}"
    local auto_sec=false

    # Debian/Ubuntu: unattended-upgrades
    if [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
        if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]] && systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
            auto_sec=true
            log_pass "unattended-upgrades service is active: automatic security updates enabled."
        elif [[ -f "/etc/apt/apt.conf.d/20auto-upgrades" ]] && \
             grep -qE 'APT::Periodic::Unattended-Upgrade\s+"1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then
            auto_sec=true
            log_pass "unattended-upgrades is configured (APT::Periodic::Unattended-Upgrade=1)."
        elif [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]] && systemctl list-unit-files 2>/dev/null | grep -q "apt-daily-upgrade"; then
            log_warn "apt-daily-upgrade timer exists but unattended-upgrades package/config is not enabled. Automatic SECURITY updates are likely NOT active."
        else
            log_warn "Automatic security updates are NOT configured. Install & enable 'unattended-upgrades' for timely CVE patching."
        fi
    fi

    # RHEL/Fedora: dnf-automatic
    if [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
        if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]] && (systemctl is-active --quiet dnf-automatic 2>/dev/null || systemctl is-active --quiet dnf-automatic-install 2>/dev/null); then
            auto_sec=true
            log_pass "dnf-automatic service is active: automatic updates enabled."
        elif [[ -f "/etc/dnf/automatic.conf" ]] && grep -qE '^apply_updates\s*=\s*yes' /etc/dnf/automatic.conf 2>/dev/null; then
            auto_sec=true
            log_pass "dnf-automatic is configured with apply_updates=yes."
        else
            log_warn "Automatic updates (dnf-automatic) are NOT configured. Security patches will only apply on manual 'dnf update'."
        fi
    fi
}

audit_pending_updates

# ==============================================================================
# 22. Logging & Monitoring (auditd / rsyslog / journald) + Scheduled Task Anomalies
# ==============================================================================
section "22/24" "Auditing Logging Services (auditd/rsyslog) & Scheduled Task Anomalies..."

audit_logging_services() {
    echo -e "${YELLOW}--- System Logging Infrastructure (rsyslog / journald) ---${NC}"
    local logs_working=false

    if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]]; then
        if systemctl is-active --quiet rsyslog 2>/dev/null; then
            logs_working=true
            log_pass "rsyslog service is active (system logging daemon running)."
        elif systemctl list-unit-files 2>/dev/null | grep -q '^rsyslog'; then
            log_warn "rsyslog is installed but NOT running. System events may not be persistently logged."
        fi

        if systemctl is-active --quiet systemd-journald 2>/dev/null; then
            logs_working=true
            log_pass "systemd-journald is active."
        elif [[ -d "/run/systemd/journal" ]]; then
            log_warn "systemd-journald does not report as active."
        fi
    fi

    # Sanity check: are logs actually being written to?
    local auth_target=""
    [[ -f "/var/log/auth.log" ]] && auth_target="/var/log/auth.log"
    [[ -f "/var/log/secure" ]] && auth_target="/var/log/secure"
    if [[ -n "$auth_target" ]]; then
        local log_mtime_age
        log_mtime_age=$(( ($(date +%s) - $(stat -c %Y "$auth_target" 2>/dev/null || echo 0)) / 3600 ))
        if [[ "$log_mtime_age" -le 24 ]]; then
            logs_working=true
            log_pass "Auth log '${auth_target}' was updated within the last ${log_mtime_age}h (logging is functioning)."
        else
            log_warn "Auth log '${auth_target}' has not been written for ${log_mtime_age}h! Logging may be broken."
        fi
    else
        if [[ "${TOOL_FOUND['journalctl']}" -eq 1 ]]; then
            local recent_journal
            recent_journal=$("${TOOL_BIN['journalctl']}" --since "24 hours ago" -n 1 --no-pager 2>/dev/null)
            if [[ -n "$recent_journal" ]]; then
                logs_working=true
                log_pass "journald contains recent entries (last 24h) - event logging is functioning."
            else
                log_warn "journald has NO entries for the last 24 hours! System activity is not being recorded."
            fi
        fi
    fi

    if [[ "$logs_working" == false ]]; then
        log_crit "NO ACTIVE LOGGING: neither rsyslog nor a functioning journald/auth log was verified. Security events are NOT being recorded!"
    fi

    # --- auditd ---
    echo -e "\n${YELLOW}--- Kernel Audit Framework (auditd) ---${NC}"
    if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]]; then
        if systemctl is-active --quiet auditd 2>/dev/null; then
            log_pass "auditd service is active (kernel syscall & access auditing enabled)."
            local audit_recent
            audit_recent=$(grep -c . /var/log/audit/audit.log 2>/dev/null || echo 0)
            echo -e "  audit.log entries present      : ${CYAN}${audit_recent}${NC}"
        elif systemctl list-unit-files 2>/dev/null | grep -q '^auditd'; then
            log_warn "auditd is installed but NOT running. Security-relevant events (file access, syscall anomalies) are not audited."
            if [[ "$AUTO_RESTART_SERVICES" == true ]]; then
                restart_service "auditd" "enabling kernel security auditing"
            fi
        else
            log_warn "auditd is NOT installed. Recommended: 'apt install auditd' / 'dnf install audit' for system activity auditing."
        fi
    fi

    # --- Suspicious scheduled tasks (cron / systemd timers / at) ---
    echo -e "\n${YELLOW}--- Suspicious Scheduled Task Detection (cron / systemd / at) ---${NC}"
    local suspicious_tasks=0

    local cron_blacklist="/dev/shm|/tmp/|/var/tmp/|curl.*\||wget.*\||python.*-c|base64.*-d|nohup|/dev/tcp|chmod 777|eval"
    while read -r cfile; do
        [[ -f "$cfile" ]] || continue
        local hits
        hits=$(grep -E "$cron_blacklist" "$cfile" 2>/dev/null | grep -v '^\s*#' | head -n 5)
        if [[ -n "$hits" ]]; then
            log_crit "SUSPICIOUS CRON TASK in ${cfile} (download/decode/obfuscation patterns):\n$hits"
            suspicious_tasks=$((suspicious_tasks + 1))
        fi
    done < <(find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -type f 2>/dev/null; [[ -f /etc/crontab ]] && echo /etc/crontab)

    while IFS=: read -r username password uid gid gecos home shell; do
        local ucron
        ucron=$(crontab -u "$username" -l 2>/dev/null | grep -v '^\s*#' | grep -E "$cron_blacklist" | head -n 5)
        if [[ -n "$ucron" ]]; then
            log_crit "SUSPICIOUS CRON TASK for user '${username}':\n$ucron"
            suspicious_tasks=$((suspicious_tasks + 1))
        fi
    done < /etc/passwd

    # systemd timers executing from temporary/world-writable paths
    if [[ "${TOOL_FOUND['systemctl']}" -eq 1 ]]; then
        local timer_units
        timer_units=$(systemctl list-timers --no-pager --no-legend 2>/dev/null | awk '{print $1}' | grep -v '^$')
        for tu in $timer_units; do
            local exec_path
            exec_path=$(systemctl cat "$tu" 2>/dev/null | grep -E 'ExecStart=' | head -n 1 | sed 's/.*ExecStart=//;s/^-//;s/ .*//')
            if [[ -n "$exec_path" ]]; then
                if [[ "$exec_path" =~ ^/tmp|^/dev/shm|^/var/tmp ]]; then
                    log_crit "systemd timer '${tu}' executes from a temporary directory: ${exec_path}"
                    suspicious_tasks=$((suspicious_tasks + 1))
                elif [[ -f "$exec_path" ]] && [[ -w "$exec_path" ]]; then
                    local ep_octal
                    ep_octal=$(stat -c "%a" "$exec_path" 2>/dev/null)
                    if ! [[ "$ep_octal" =~ ^[0-7]0[0-7]$ ]]; then
                        log_warn "systemd timer '${tu}' executes a group/world-writable binary: ${exec_path} (${ep_octal})"
                    fi
                fi
            fi
        done
    fi

    if command -v atq &>/dev/null; then
        local at_jobs
        at_jobs=$(atq 2>/dev/null | head -n 5)
        [[ -n "$at_jobs" ]] && echo -e "  Pending 'at' jobs:\n$at_jobs"
    fi

    if [[ "$suspicious_tasks" -eq 0 ]]; then
        log_pass "No suspicious scheduled tasks (cron/systemd-timers) detected."
    fi
}

audit_logging_services

# ==============================================================================
# 23. Disk Encryption (LUKS) & Mandatory Access Control (SELinux/AppArmor)
# ==============================================================================
section "23/24" "Auditing Disk Encryption (LUKS) & MAC Framework (SELinux/AppArmor)..."

audit_disk_encryption_and_mac() {
    echo -e "${YELLOW}--- Full Disk Encryption (LUKS) Status ---${NC}"
    local luks_devices=0
    local root_encrypted=false

    if [[ "${TOOL_FOUND['lsblk']}" -eq 1 ]]; then
        echo "Block device encryption map:"
        "${TOOL_BIN['lsblk']}" -o NAME,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null | sed 's/^/  /'

        local root_src
        root_src=$(findmnt -n -o SOURCE / 2>/dev/null)
        if [[ -n "$root_src" && ( "$root_src" =~ /dev/mapper/ || "$root_src" =~ crypt ) ]]; then
            root_encrypted=true
        fi
    fi

    local cs_cmd="${TOOL_BIN['cryptsetup']}"
    [[ -z "$cs_cmd" ]] && cs_cmd=$(find_tool "cryptsetup")
    if [[ -n "$cs_cmd" ]]; then
        while read -r blkdev; do
            [[ -b "$blkdev" ]] || continue
            if run_sudo "$cs_cmd" isLuks "$blkdev" 2>/dev/null; then
                luks_devices=$((luks_devices + 1))
            fi
        done < <(lsblk -rn -o PATH,TYPE 2>/dev/null | awk '$2=="part"||$2=="disk"{print $1}' | head -n 20)
    fi

    echo -e "  LUKS-encrypted block devices found : ${CYAN}${luks_devices}${NC}"

    if [[ "$root_encrypted" == true ]]; then
        log_pass "Root filesystem resides on a mapped (LUKS-encrypted) device."
    fi

    if [[ -f "/etc/crypttab" ]] && grep -qE '^[^#]' /etc/crypttab 2>/dev/null; then
        log_pass "crypttab contains active encrypted volume mappings:"
        grep -vE '^\s*#|^\s*$' /etc/crypttab 2>/dev/null | sed 's/^/    /'
        if grep -vE '^\s*#' /etc/crypttab 2>/dev/null | awk '{print $3}' | grep -qE '^/'; then
            log_warn "crypttab uses key files on disk for at least one volume (not passphrase-prompted)."
        fi
    fi

    if [[ "$root_encrypted" == false && "$luks_devices" -eq 0 ]]; then
        log_crit "Root filesystem is on an UNENCRYPTED partition and no LUKS volumes exist! Physical access / disk theft exposes all stored data. Recommended: LUKS full disk encryption."
    elif [[ "$luks_devices" -gt 0 ]]; then
        log_pass "Disk encryption (LUKS) is in use on this system (${luks_devices} encrypted device(s))."
    else
        log_warn "No LUKS-encrypted devices detected (system may be virtual, or disks are unencrypted)."
    fi

    # --- Mandatory Access Control ---
    echo -e "\n${YELLOW}--- Mandatory Access Control (SELinux / AppArmor) ---${NC}"
    local mac_active=false

    if command -v getenforce &>/dev/null; then
        local se_mode
        se_mode=$(getenforce 2>/dev/null)
        echo -e "  SELinux status                  : ${CYAN}${se_mode}${NC}"
        case "$se_mode" in
            Enforcing) log_pass "SELinux is ENFORCING (mandatory access control active)."; mac_active=true ;;
            Permissive) log_warn "SELinux is PERMISSIVE: policy violations are logged but NOT blocked." ;;
            Disabled)   log_warn "SELinux is DISABLED." ;;
        esac
    fi

    if command -v aa-enabled &>/dev/null; then
        if aa-enabled &>/dev/null; then
            local loaded_profiles
            loaded_profiles=$(cat /sys/kernel/security/apparmor/profiles 2>/dev/null | wc -l)
            log_pass "AppArmor is enabled with ${loaded_profiles} loaded profile(s)."
            mac_active=true
        else
            local aa_rc=$?
            if [[ "$aa_rc" -eq 2 ]]; then
                log_warn "AppArmor is enabled but no profiles are loaded."
            else
                log_warn "AppArmor is installed but DISABLED."
            fi
        fi
    elif [[ -d /sys/kernel/security/apparmor ]]; then
        mac_active=true
        local loaded_profiles
        loaded_profiles=$(cat /sys/kernel/security/apparmor/profiles 2>/dev/null | wc -l)
        log_pass "AppArmor kernel module active with ${loaded_profiles} loaded profile(s)."
    fi

    if [[ "$mac_active" == false ]]; then
        log_crit "NO MANDATORY ACCESS CONTROL ACTIVE: neither SELinux (enforcing) nor AppArmor is protecting this system! Service compromise leads directly to full filesystem access."
    fi
}

audit_disk_encryption_and_mac

# ==============================================================================
# 24. Behavioral Rootkit Detection (process/filesystem anomalies, no signature DB)
# ==============================================================================
section "24/24" "Behavioral Rootkit Detection (hidden processes, preload hooks, deleted binaries)..."

audit_behavioral_rootkit_indicators() {
    echo -e "${YELLOW}--- Behavioral Rootkit Indicators ---${NC}"
    local indicators=0

    # 1. Hidden processes: a userland rootkit hides entries from ps but not from /proc.
    echo -e "\n${CYAN}1. Hidden Process Detection (/proc enumeration vs ps):${NC}"
    local ps_pids proc_pids hidden_pids=""
    ps_pids=$(ps -e -o pid= 2>/dev/null | awk '{print $1}' | sort -n | tr '\n' ' ')
    proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | awk -F/ '{print $3}' | sort -n)
    for pid in $proc_pids; do
        if [[ " $ps_pids " != *" $pid "* ]]; then
            hidden_pids+="$pid "
        fi
    done
    if [[ -n "$hidden_pids" ]]; then
        log_crit "HIDDEN PROCESSES DETECTED: PIDs visible in /proc but hidden from 'ps': ${hidden_pids}(possible userland rootkit / LD_PRELOAD hook)."
        indicators=$((indicators + 1))
    else
        log_pass "No hidden processes: all /proc PIDs are visible to ps."
    fi

    # 2. Shared library preload hooks (classic userland rootkit mechanism)
    echo -e "\n${CYAN}2. Shared Library Preload Hooks (/etc/ld.so.preload):${NC}"
    if [[ -f "/etc/ld.so.preload" ]] && grep -qE '^\s*[^#]' /etc/ld.so.preload 2>/dev/null; then
        local preload_libs
        preload_libs=$(grep -vE '^\s*#|^\s*$' /etc/ld.so.preload)
        log_crit "LIBRARY PRELOAD HOOK ACTIVE in /etc/ld.so.preload (common userland rootkit technique):\n$preload_libs"
        indicators=$((indicators + 1))
    else
        log_pass "No system-wide library preload hooks (/etc/ld.so.preload empty or absent)."
    fi

    # 3. Running binaries deleted from disk (packed/hidden malware pattern)
    echo -e "\n${CYAN}3. Running-But-Deleted Binaries (/proc/*/exe with '(deleted)'):${NC}"
    local deleted_bins
    deleted_bins=$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep '(deleted)' | awk '{print $(NF-2), $NF}' | head -n 10)
    if [[ -n "$deleted_bins" ]]; then
        log_warn "Processes executing binaries that have been DELETED from disk (packer/malware or in-progress update):\n$deleted_bins"
        indicators=$((indicators + 1))
    else
        log_pass "No processes running from deleted binaries."
    fi

    # 4. Network interface promiscuous mode (packet sniffing / MITM rootkits)
    echo -e "\n${CYAN}4. Promiscuous Mode Network Interfaces (packet sniffing):${NC}"
    local promisc_ifaces
    promisc_ifaces=$(ip -o link show 2>/dev/null | grep -i 'promisc' | awk -F': ' '{print $2}')
    if [[ -n "$promisc_ifaces" ]]; then
        log_warn "Network interface(s) in PROMISCUOUS MODE (traffic capture active): ${promisc_ifaces}"
        indicators=$((indicators + 1))
    else
        log_pass "No network interfaces in promiscuous mode."
    fi

    # 5. Core binary tampering (world-writable system tools)
    echo -e "\n${CYAN}5. Core Binary Path Hijack Check (world-writable system tools):${NC}"
    local hijack_hits
    hijack_hits=$(find /sbin /usr/sbin /bin /usr/bin -maxdepth 1 -type f \( -name "ls" -o -name "ps" -o -name "netstat" -o -name "top" -o -name "id" -o -name "who" \) -perm -0002 2>/dev/null)
    if [[ -n "$hijack_hits" ]]; then
        log_crit "CORE SYSTEM BINARIES ARE WORLD-WRITABLE (trojanized binary risk):\n$hijack_hits"
        indicators=$((indicators + 1))
    else
        log_pass "Core system binaries are not world-writable."
    fi

    # 6. Kernel module anomalies: modules present in /sys/module but hidden from lsmod
    echo -e "\n${CYAN}6. Kernel Module Anomalies (lsmod vs /sys/module):${NC}"
    if command -v lsmod &>/dev/null; then
        local lsmod_mods sys_mods hidden_mods
        lsmod_mods=$(lsmod 2>/dev/null | awk 'NR>1 {print $1}' | sort)
        sys_mods=$(ls /sys/module 2>/dev/null | sort)
        hidden_mods=$(comm -23 <(echo "$sys_mods") <(echo "$lsmod_mods") | head -n 20)
        if [[ -n "$hidden_mods" ]]; then
            log_warn "Loaded kernel modules present in /sys/module but missing from lsmod (possible module-hiding rootkit; built-in modules also show here, verify manually):\n$hidden_mods"
            indicators=$((indicators + 1))
        else
            log_pass "No hidden kernel modules detected."
        fi
    fi

    if [[ "$indicators" -eq 0 ]]; then
        log_pass "Behavioral rootkit scan: no anomalous process, preload, module or interface indicators found."
    else
        log_crit "Behavioral rootkit scan: ${indicators} behavioral indicator(s) of compromise detected. Investigate the findings above (compare with chkrootkit/rkhunter output in section 6)."
    fi
}

audit_behavioral_rootkit_indicators

# ==============================================================================
# Post-Audit Cleanup: remove the script's own footprint
# ==============================================================================
cleanup_audit_footprint() {
    echo -e "\n${YELLOW}=== Post-Audit Cleanup: Removing Script Footprint ===${NC}"

    # 1. Report packages that this script installed during this run.
    #    They are KEPT installed (security scanners stay available for future runs);
    #    the list is only printed so the operator knows what changed on the system.
    local installed_list=()
    local pkg
    for pkg in "${!AUDIT_INSTALLED_PKGS[@]}"; do
        installed_list+=("$pkg")
    done

    if [[ ${#installed_list[@]} -gt 0 ]]; then
        echo -e "  Packages installed by this audit run (KEPT on the system):"
        for pkg in "${installed_list[@]}"; do
            local pkg_ver=""
            if [[ "${TOOL_FOUND['dpkg-query']}" -eq 1 ]]; then
                pkg_ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)
            elif [[ "${TOOL_FOUND['rpm']}" -eq 1 ]]; then
                pkg_ver=$(rpm -q --qf '%{VERSION}' "$pkg" 2>/dev/null)
            fi
            echo -e "    - ${CYAN}${pkg}${NC}${pkg_ver:+ (${pkg_ver})}"
        done
        echo -e "  ${YELLOW}Tip: to remove them later:${NC} apt purge ${installed_list[*]}  (or: dnf remove ${installed_list[*]})"
    else
        echo -e "  No packages were installed by this audit run - the system package set is unchanged."
    fi

    # 2. Clean the package-manager cache downloaded during this run
    if [[ "${TOOL_FOUND['apt-get']}" -eq 1 ]]; then
        if run_sudo "${TOOL_BIN['apt-get']}" clean 2>/dev/null; then
            echo -e "  ${GREEN}OK${NC} APT archive cache cleaned (/var/cache/apt/archives)."
        fi
    elif [[ "${TOOL_FOUND['dnf']}" -eq 1 ]]; then
        if run_sudo "${TOOL_BIN['dnf']}" clean all 2>/dev/null; then
            echo -e "  ${GREEN}OK${NC} DNF cache cleaned."
        fi
    fi

    # 3. Safety net: remove any leftover mktemp/temp files created by this script
    find "$REPORT_DIR" -maxdepth 1 -name "*.tmp" -type f -delete 2>/dev/null || true
    find /tmp -maxdepth 1 -name "tmp.*" -user root -mmin -120 -size -100k -type f -delete 2>/dev/null || true

    # 4. Summarize what intentionally REMAINS after cleanup
    echo -e "  ${CYAN}Kept intentionally:${NC}"
    echo -e "    - Audit report        : ${CYAN}${REPORT_FILE}${NC}"
    echo -e "    - Password dictionary : ${CYAN}${DICT_FILE}${NC} (cached for future runs)"
    echo -e "    - Installed scanners  : security tools installed by this run (listed above)"
    echo -e "    - History backups    : *.audit-backup files created before history cleaning"
    echo -e "    - Security fixes     : permission/config remediations applied during the audit"
    echo -e "${GREEN}[OK] Post-audit cleanup completed.${NC}\n"
}

cleanup_audit_footprint

print_scorecard() {
    AUDIT_END_TIME_SEC=$(date +%s)
    AUDIT_END_TIME_STR=$(date "+%Y-%m-%d %H:%M:%S %Z")
    local duration_sec=$(( AUDIT_END_TIME_SEC - AUDIT_START_TIME_SEC ))
    local mins=$(( duration_sec / 60 ))
    local secs=$(( duration_sec % 60 ))
    local duration_fmt=""
    if [[ $mins -gt 0 ]]; then
        duration_fmt="${mins}m ${secs}s"
    else
        duration_fmt="${secs}s"
    fi

    # Weighted score: critical findings hurt much more than warnings.
    local score=100
    if [[ $TOTAL_CHECKS -gt 0 ]]; then
        score=$(( 100 - (CRITICAL_COUNT * 10 + WARNING_COUNT * 2) ))
        [[ $score -lt 0 ]] && score=0
        [[ $score -gt 100 ]] && score=100
    fi

    printf "  %-30s : %s\n" "Audit Started At" "$AUDIT_START_TIME_STR"
    printf "  %-30s : %s\n" "Audit Completed At" "$AUDIT_END_TIME_STR"
    printf "  %-30s : %s\n" "Total Execution Duration" "$duration_fmt"
    echo -e "-----------------------------------------------------"
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
    echo -e "${GREEN}[OK] System Audit & Remediation Completed Successfully!${NC}"
    echo -e "  Detailed Markdown Report Log: ${CYAN}${REPORT_FILE}${NC}"
    echo -e "${CYAN}=====================================================${NC}"
}

print_scorecard