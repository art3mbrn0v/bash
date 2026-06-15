#!/bin/bash

# Default CPU limit per process
CPU_LIMIT=${CPU_LIMIT:-60}
# Max parallel jobs based on CPU cores
MAX_JOBS=$(nproc)

# Function to check and install dependencies based on OS
check_dependencies() {
    local pkgs=("ffmpeg" "cpulimit")
    local missing_pkgs=()

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi

    echo "[i] Detected OS: $OS"

    for pkg in "${pkgs[@]}"; do
        case "$OS" in
            ubuntu|debian)
                if ! dpkg -l | grep -q "^ii  $pkg "; then missing_pkgs+=("$pkg"); fi
                ;;
            fedora|rhel|centos)
                if ! rpm -q "$pkg" > /dev/null 2>&1; then missing_pkgs+=("$pkg"); fi
                ;;
            *)
                if ! command -v "$pkg" > /dev/null 2>&1; then missing_pkgs+=("$pkg"); fi
                ;;
        esac
    done

    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        echo "[!] Missing packages: ${missing_pkgs[*]}"
        echo "[?] Would you like to install them? (requires sudo) [y/N]"
        read -r response
        if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            case "$OS" in
                ubuntu|debian) sudo apt-get update && sudo apt-get install -y "${missing_pkgs[@]}" ;;
                fedora) sudo dnf install -y "${missing_pkgs[@]}" ;;
                rhel|centos) sudo yum install -y "${missing_pkgs[@]}" ;;
                *) echo "[!] Unknown OS. Please install manually."; exit 1 ;;
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
