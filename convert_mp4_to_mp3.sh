#!/bin/bash

# Default CPU limit per process
CPU_LIMIT=${CPU_LIMIT:-60}
# Max parallel jobs based on CPU cores
MAX_JOBS=$(nproc)

# Function to check and install dependencies based on OS
check_dependencies() {
    local pkgs=("ffmpeg" "cpulimit")
    local missing_pkgs=()
    local ID=""
    local ID_LIKE=""
    local OS_ID=""
    local OS_LIKE=""
    local OS_FAMILY=""
    local pkg
    local response

    # Detect OS and OS Family using /etc/os-release
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
        OS_LIKE=$ID_LIKE
    else
        OS_ID=$(uname -s | tr '[:upper:]' '[:lower:]')
        OS_LIKE=""
    fi

    # Normalize OS Family
    case "$OS_ID" in
        ubuntu|debian|mint|pop|elementary|neon|devuan)
            OS_FAMILY="debian"
            ;;
        fedora|rhel|centos|rocky|almalinux|amzn|ol)
            OS_FAMILY="redhat"
            ;;
        opensuse*|sles)
            OS_FAMILY="suse"
            ;;
        arch|manjaro|endeavouros|artix)
            OS_FAMILY="arch"
            ;;
        alpine)
            OS_FAMILY="alpine"
            ;;
    esac

    # If OS_FAMILY is not set, try OS_LIKE
    if [ -z "$OS_FAMILY" ] && [ -n "$OS_LIKE" ]; then
        for like in $OS_LIKE; do
            case "$like" in
                ubuntu|debian)
                    OS_FAMILY="debian"
                    break
                    ;;
                fedora|rhel|centos)
                    OS_FAMILY="redhat"
                    break
                    ;;
                suse|opensuse)
                    OS_FAMILY="suse"
                    break
                    ;;
                arch)
                    OS_FAMILY="arch"
                    break
                    ;;
                alpine)
                    OS_FAMILY="alpine"
                    break
                    ;;
            esac
        done
    fi

    echo "[i] Detected OS: $OS_ID (Family: ${OS_FAMILY:-unknown})"

    for pkg in "${pkgs[@]}"; do
        # 1. First, check if the executable is already available in PATH
        if command -v "$pkg" >/dev/null 2>&1; then
            continue
        fi

        # 2. If not in PATH, check if package is installed in system package manager
        local is_installed=false
        case "$OS_FAMILY" in
            debian)
                if dpkg -s "$pkg" >/dev/null 2>&1; then
                    is_installed=true
                fi
                ;;
            redhat|suse)
                if rpm -q "$pkg" >/dev/null 2>&1; then
                    is_installed=true
                fi
                ;;
            arch)
                if pacman -Qi "$pkg" >/dev/null 2>&1; then
                    is_installed=true
                fi
                ;;
            alpine)
                if apk info -e "$pkg" >/dev/null 2>&1; then
                    is_installed=true
                fi
                ;;
        esac

        if [ "$is_installed" = true ]; then
            echo "[!] Warning: Package '$pkg' is installed, but command '$pkg' is not in PATH."
            echo "    Please verify your PATH environment variable."
        else
            missing_pkgs+=("$pkg")
        fi
    done

    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        echo "[!] Missing packages: ${missing_pkgs[*]}"
        echo "[?] Would you like to install them? (requires sudo) [y/N]"
        read -r response
        if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            case "$OS_FAMILY" in
                debian)
                    sudo apt-get update && sudo apt-get install -y "${missing_pkgs[@]}"
                    ;;
                redhat)
                    local pm="yum"
                    if command -v dnf >/dev/null 2>&1; then
                        pm="dnf"
                    fi
                    if ! sudo $pm install -y "${missing_pkgs[@]}"; then
                        echo "[!] Installation failed."
                        if [[ " ${missing_pkgs[*]} " =~ " ffmpeg " ]]; then
                            echo "[i] Note: 'ffmpeg' on RHEL/CentOS/Rocky Linux requires EPEL and RPM Fusion repositories."
                            echo "    You can enable them by running:"
                            echo "    sudo dnf install -y epel-release"
                            echo "    sudo dnf config-manager --set-enabled crb"
                            echo "    sudo dnf install -y https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-\$(rpm -E %rhel).noarch.rpm"
                        fi
                        exit 1
                    fi
                    ;;
                suse)
                    sudo zypper install -y "${missing_pkgs[@]}"
                    ;;
                arch)
                    sudo pacman -Sy --noconfirm "${missing_pkgs[@]}"
                    ;;
                alpine)
                    sudo apk add "${missing_pkgs[@]}"
                    ;;
                *)
                    # Fallback if OS family detection was inconclusive
                    if command -v apt-get >/dev/null 2>&1; then
                        sudo apt-get update && sudo apt-get install -y "${missing_pkgs[@]}"
                    elif command -v dnf >/dev/null 2>&1; then
                        sudo dnf install -y "${missing_pkgs[@]}"
                    elif command -v yum >/dev/null 2>&1; then
                        sudo yum install -y "${missing_pkgs[@]}"
                    elif command -v pacman >/dev/null 2>&1; then
                        sudo pacman -Sy --noconfirm "${missing_pkgs[@]}"
                    else
                        echo "[!] Unknown package manager. Please install manually: ${missing_pkgs[*]}"
                        exit 1
                    fi
                    ;;
            esac
        else
            echo "[!] Cannot proceed without dependencies."; exit 1
        fi
    fi
}

check_dir_mp4() {
    [[ ! -d "mp4" ]] && mkdir -p "mp4"
}

# Function to handle individual file conversion (runs in background)
convert_file() {
    local f="$1"
    local idx="$2"
    local total="$3"
    local name="${f%.mp4}"
    local output="$name.mp3"

    echo "[${idx}/${total}] Starting: $f"

    # Run ffmpeg
    ffmpeg -i "$f" -vn -ar 44100 -ac 2 -ab 192k -f mp3 "$output" -loglevel error -y &
    local f_pid=$!

    # Attach cpulimit if available
    local cp_pid=""
    if command -v cpulimit > /dev/null 2>&1; then
        cpulimit -p "$f_pid" -l "${CPU_LIMIT}" -z > /dev/null 2>&1 &
        cp_pid=$!
    fi

    wait "$f_pid"
    local status=$?

    # Cleanup cpulimit
    [[ -n "$cp_pid" ]] && kill "$cp_pid" 2>/dev/null

    if [ $status -eq 0 ] && [ -f "$output" ]; then
        echo "[${idx}/${total}] DONE: $f"
        mv "$f" mp4/
    else
        echo "[${idx}/${total}] FAILED: $f (Exit code: $status)"
        [[ -f "$output" ]] && rm "$output"
    fi
}

# Main Execution
check_dependencies

shopt -s nullglob
files=(*.mp4)

if [ ${#files[@]} -eq 0 ]; then
    echo "[i] No *.mp4 files found in the current directory. Exiting."
    exit 0
fi

echo "=================================="
date
echo "=================================="
echo -e "[i] CPU Limit per job = ${CPU_LIMIT}%"
echo -e "[i] Parallel jobs     = ${MAX_JOBS}"
echo -e "[i] Total files       = ${#files[@]}"
echo "=================================="

check_dir_mp4

count=0
for f in "${files[@]}"; do
    ((count++))
    
    # Launch conversion in background
    convert_file "$f" "$count" "${#files[@]}" &

    # Manage process pool
    # Get count of current background jobs
    while [[ $(jobs -r -p | wc -l) -ge $MAX_JOBS ]]; do
        wait -n
    done
done

# Wait for all remaining jobs to finish
wait

echo "=================================="
uptime
echo "=================================="

# Final report
mp3_files=(*.mp3)
echo -e "[+] Conversion finished. Total mp3 files: ${#mp3_files[@]}"
[[ ${#mp3_files[@]} -gt 0 ]] && ls -lh *.mp3
date
