#!/usr/bin/env bash
# SubdomainFinder v0.5.4 (Cyberpunk Edition)
# Usage: ./subdomainfinder.sh -i domains.txt -o outputs/all-subdomains.txt
# Requires: curl, awk, sort, uniq. jq recommended.

set -euo pipefail
IFS=$'\n\t'

INPUT_FILE=""
OUTFILE="outputs/all-subdomains.txt"
QUIET=0
USER_AGENT="SubdomainFinder/0.5.4"

# Cyberpunk Color Scheme
NEON_GREEN='\033[1;32m'
NEON_BLUE='\033[1;34m'
NEON_PURPLE='\033[1;35m'
NEON_CYAN='\033[1;36m'
NEON_RED='\033[1;31m'
NEON_YELLOW='\033[1;33m'
DARK_GRAY='\033[1;90m'
WHITE='\033[1;37m'
RESET='\033[0m'

# Cyberpunk Icons
TERMINAL="🖥️"
SCAN="🔍"
ROCKET="🚀"
FOLDER="📂"
FILE="📄"
CALENDAR="🕐"
GLOBE="🌐"
WARNING="⚠️"
SUCCESS="✅"
ERROR="❌"
LIST="📑"
COUNT="🔢"
NETWORK="🛜"
LOCK="🔒"
HACKER="👨💻"

print() {
    [ "$QUIET" -eq 0 ] && printf '%s\n' "$*";
}

print_color() {
    [ "$QUIET" -eq 0 ] && printf '%b\n' "$1$2$RESET";
}

# Cyberpunk Banner
print_banner() {
    clear
    print_color "$NEON_BLUE" "╔══════════════════════════════════════════════════════════════╗"
    print_color "$NEON_BLUE" "║                                                              ║"
    print_color "$NEON_CYAN" "║    ███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗     ║"
    print_color "$NEON_CYAN" "║    ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║     ║"
    print_color "$NEON_CYAN" "║    ███████╗██║   ██║██║  ██║██████╔╝██║   ██║██╔████╔██║     ║"
    print_color "$NEON_CYAN" "║    ╚════██║██║   ██║██║  ██║██╔══██╗██║   ██║██║╚██╔╝██║     ║"
    print_color "$NEON_CYAN" "║    ███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║     ║"
    print_color "$NEON_CYAN" "║    ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝     ║"
    print_color "$NEON_BLUE" "║                                                              ║"
    print_color "$NEON_PURPLE" "║              C Y B E R P U N K   E D I T I O N              ║"
    print_color "$NEON_BLUE" "║                     v0.5.4 • $(date +%Y)                    ║"
    print_color "$NEON_BLUE" "║                                                              ║"
    print_color "$NEON_BLUE" "╚══════════════════════════════════════════════════════════════╝"
    echo
}

# Matrix-style progress bar
progress_bar() {
    local duration=${1}
    local width=40
    local increment=$((duration / width))
    local chars=("█" "▓" "▒" "░")
    
    for ((i=0; i<=width; i++)); do
        percentage=$((i * 100 / width))
        printf "\r${DARK_GRAY}[${NEON_GREEN}"
        for ((j=0; j<i; j++)); do
            printf "%s" "${chars[0]}"
        done
        printf "${DARK_GRAY}"
        for ((j=i; j<width; j++)); do
            printf "%s" "${chars[3]}"
        done
        printf "${DARK_GRAY}] ${NEON_CYAN}%3d%%${RESET}" "$percentage"
        sleep $increment
    done
    printf "\n"
}

# Hacker-style spinner
spinner() {
    local pid=$1
    local delay=0.08
    local spinstr='⣷⣯⣟⡿⢿⣻⣽⣾'
    
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " ${NEON_CYAN}[%c]${RESET}" "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "      \b\b\b\b\b\b"
}

# Cyberpunk table header
print_table_header() {
    printf '%b' "$NEON_BLUE"
    printf '┌─────────────────────────────────────────┬─────────────┐\n'
    printf '│ %-39s │ %-11s │\n' "DOMAIN" "COUNT"
    printf '├─────────────────────────────────────────┼─────────────┤\n'
    printf '%b' "$RESET"
}

# Cyberpunk table row
print_table_row() {
    local domain="$1"
    local count="$2"
    local icon="$3"
    
    if [ "$count" -eq 0 ]; then
        printf '│ %b%-39s%b │ %b%-11s%b │\n' "$icon" "$domain" "$RESET" "$NEON_RED" "$count" "$RESET"
    elif [ "$count" -lt 10 ]; then
        printf '│ %b%-39s%b │ %b%-11s%b │\n' "$icon" "$domain" "$RESET" "$NEON_YELLOW" "$count" "$RESET"
    else
        printf '│ %b%-39s%b │ %b%-11s%b │\n' "$icon" "$domain" "$RESET" "$NEON_GREEN" "$count" "$RESET"
    fi
}

# Cyberpunk table footer
print_table_footer() {
    local total="$1"
    printf '%b' "$NEON_BLUE"
    printf '├─────────────────────────────────────────┼─────────────┤\n'
    printf '│ %-39s │ %b%-11s%b │\n' "TOTAL UNIQUE SUBDOMAINS" "$NEON_GREEN" "$total" "$NEON_BLUE"
    printf '└─────────────────────────────────────────┴─────────────┘\n'
    printf '%b' "$RESET"
}

# Domain status with cyberpunk icons
get_domain_icon() {
    local count="$1"
    if [ "$count" -eq 0 ]; then
        echo "$ERROR"
    elif [ "$count" -lt 5 ]; then
        echo "$WARNING"
    elif [ "$count" -lt 15 ]; then
        echo "$NETWORK"
    else
        echo "$SUCCESS"
    fi
}

usage() {
    cat <<EOF
${NEON_CYAN}SubdomainFinder - Cyberpunk Subdomain Enumeration Tool${RESET}

${NEON_GREEN}Usage:${RESET} $0 -i domains.txt [-o output_file] [-q]

${NEON_YELLOW}Options:${RESET}
  ${NEON_CYAN}-i input_file${RESET}    File containing list of domains (one per line)
  ${NEON_CYAN}-o output_file${RESET}   Save combined results (default: outputs/all-subdomains.txt)
  ${NEON_CYAN}-q${RESET}               Quiet mode
  ${NEON_CYAN}-h${RESET}               Show this help message

${NEON_GREEN}Examples:${RESET}
  $0 -i domains.txt
  $0 -i targets.txt -o results/all-found.txt
  $0 -i domains.txt -q

${NEON_PURPLE}Requirements:${RESET} curl, awk, sort, uniq. jq recommended for better parsing.
EOF
    exit 1
}

# Parse command line arguments
while getopts ":i:o:qh" opt; do
    case ${opt} in
        i) INPUT_FILE=$OPTARG ;;
        o) OUTFILE=$OPTARG ;;
        q) QUIET=1 ;;
        h) usage ;;
        \?) echo -e "${ERROR} ${NEON_RED}Invalid option: -$OPTARG${RESET}" >&2; usage ;;
        :) echo -e "${ERROR} ${NEON_RED}Option -$OPTARG requires an argument.${RESET}" >&2; usage ;;
    esac
done
shift $((OPTIND -1))

# Validation
[ -z "$INPUT_FILE" ] && echo -e "${ERROR} ${NEON_RED}Please specify -i domains.txt${RESET}" >&2 && usage
[ ! -f "$INPUT_FILE" ] && echo -e "${ERROR} ${NEON_RED}Input file $INPUT_FILE not found!${RESET}" >&2 && exit 1

# Create directories
mkdir -p "$(dirname "$OUTFILE")"
TMP_DIR=$(mktemp -d -t subfinder.XXXXXX)
CACHE="${TMP_DIR}/cachelista"
DATA="${TMP_DIR}/data.json"
trap 'rm -rf "$TMP_DIR"' EXIT

normalize_file() {
    awk '{print tolower($0)}' "$1" \
    | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^\*\.//; s/^\*//' \
    | sort -u
}

: > "$OUTFILE"

# Show banner
print_banner

print_color "$NEON_CYAN" "${TERMINAL} Initializing Cyberpunk Scanner..."
print_color "$DARK_GRAY" "${CALENDAR} System Time: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
print_color "$DARK_GRAY" "${GLOBE} Target File: $INPUT_FILE"
print_color "$DARK_GRAY" "${FOLDER} Output Path: $(dirname "$OUTFILE")"
echo

# Show initialization progress
print_color "$NEON_YELLOW" "${ROCKET} Booting up scanning systems..."
progress_bar 3

# temp summary (domain|count)
SUMMARY="${TMP_DIR}/summary.tsv"
: > "$SUMMARY"

TOTAL_DOMAINS=$(grep -c '^[^#]' "$INPUT_FILE" | tr -d ' ' || echo "0")
CURRENT_DOMAIN=0

print_color "$NEON_GREEN" "${SCAN} Scanning $TOTAL_DOMAINS target domains..."
echo

# Array untuk menyimpan hasil sementara
declare -a DOMAIN_RESULTS=()

while IFS= read -r DOMAIN || [ -n "$DOMAIN" ]; do
    DOMAIN="${DOMAIN%%#*}"
    DOMAIN="${DOMAIN//[[:space:]]/}"
    [ -z "$DOMAIN" ] && continue
    
    CURRENT_DOMAIN=$((CURRENT_DOMAIN + 1))
    
    # Print domain header with cyberpunk style
    print_color "$NEON_BLUE" "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
    printf "%b ${NEON_CYAN}%s${RESET} ${DARK_GRAY}[%d/%d]${RESET}\n" "$HACKER" "SCANNING: $DOMAIN" "$CURRENT_DOMAIN" "$TOTAL_DOMAINS"
    print_color "$NEON_BLUE" "▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
    
    : > "$CACHE"
    
    # Show scanning animation
    print_color "$NEON_YELLOW" "${LOCK} Querying certificate transparency logs..."
    (curl -sS -A "$USER_AGENT" --max-time 15 "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$DATA" || true) &
    spinner $!
    
    if [ -s "$DATA" ]; then
        if command -v jq >/dev/null 2>&1; then
            jq -r '.[].name_value' "$DATA" >> "$CACHE" 2>/dev/null || true
        else
            grep -oP '"name_value"\s*:\s*"(.*?)"' "$DATA" | sed -E 's/.*"name_value"\s*:\s*"//; s/"$//' | tr ',' '\n' >> "$CACHE" 2>/dev/null || true
        fi
        print_color "$NEON_GREEN" "${SUCCESS} CRT.SH database queried"
    fi
    
    print_color "$NEON_YELLOW" "${NETWORK} Accessing HackerTarget API..."
    (curl -sS -A "$USER_AGENT" --max-time 15 "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" -o "$DATA" || true) &
    spinner $!
    
    [ -s "$DATA" ] && cut -d',' -f1 "$DATA" >> "$CACHE" || true
    print_color "$NEON_GREEN" "${SUCCESS} HackerTarget API response received"
    
    # normalize and dedupe for this domain
    PERDOMAIN_TMP="${TMP_DIR}/${DOMAIN//[^a-zA-Z0-9_.-]/_}.txt"
    normalize_file "$CACHE" > "$PERDOMAIN_TMP" || true
    
    DOMAIN_COUNT=$(wc -l < "$PERDOMAIN_TMP" 2>/dev/null | tr -d ' ' || echo "0")
    
    # Get appropriate icon for domain results
    DOMAIN_ICON=$(get_domain_icon "$DOMAIN_COUNT")
    
    # Simpan hasil ke array untuk ditampilkan nanti
    DOMAIN_RESULTS+=("$DOMAIN" "$DOMAIN_COUNT" "$DOMAIN_ICON")
    
    if [ "$DOMAIN_COUNT" -eq 0 ]; then
        print_color "$NEON_RED" "${ERROR} Zero subdomains detected for $DOMAIN"
        echo -e "${DOMAIN}\t0" >> "$SUMMARY"
    else
        print_color "$NEON_GREEN" "${SUCCESS} $DOMAIN_COUNT subdomains identified"
        
        # Print subdomains in cyberpunk box
        print_color "$NEON_BLUE" "┌───────────────── SUBDOMAIN LIST ─────────────────┐"
        nl -ba -w2 -s'. ' "$PERDOMAIN_TMP" | sed "s/^/ ${DARK_GRAY}│${WHITE} /" | while IFS= read -r line; do
            print "$line"
        done
        print_color "$NEON_BLUE" "└──────────────────────────────────────────────────┘"
        
        # save per-domain result, and append to combined outfile
        mkdir -p "outputs"
        cp "$PERDOMAIN_TMP" "outputs/${DOMAIN}-subdomains.txt" 2>/dev/null || true
        cat "$PERDOMAIN_TMP" >> "$OUTFILE"
        echo -e "${DOMAIN}\t${DOMAIN_COUNT}" >> "$SUMMARY"
    fi
    
    echo
    print_color "$DARK_GRAY" "──────────────────────────────────────────────────────────"
    echo
    
done < "$INPUT_FILE"

# Final dedupe for combined file
if [ -f "$OUTFILE" ]; then
    print_color "$NEON_YELLOW" "${SCAN} Finalizing data analysis..."
    sort -u "$OUTFILE" -o "$OUTFILE" || true
fi

# Print final summary dalam 1 tabel cyberpunk
echo
print_color "$NEON_PURPLE" "╔══════════════════════════════════════════════════════════════╗"
print_color "$NEON_PURPLE" "║                     SCAN SUMMARY REPORT                     ║"
print_color "$NEON_PURPLE" "╚══════════════════════════════════════════════════════════════╝"
echo

print_table_header

# Print semua hasil sekaligus dari array
TOTAL_SUBDOMAINS=0
for ((i=0; i<${#DOMAIN_RESULTS[@]}; i+=3)); do
    domain="${DOMAIN_RESULTS[i]}"
    count="${DOMAIN_RESULTS[i+1]}"
    icon="${DOMAIN_RESULTS[i+2]}"
    print_table_row "$domain" "$count" "$icon"
    TOTAL_SUBDOMAINS=$((TOTAL_SUBDOMAINS + count))
done

print_table_footer "$TOTAL_SUBDOMAINS"

echo
print_color "$NEON_GREEN" "${SUCCESS} Mission accomplished!"
print_color "$DARK_GRAY" "${FILE} Combined results: $PWD/$OUTFILE"
print_color "$DARK_GRAY" "${FOLDER} Individual reports: outputs/<domain>-subdomains.txt"

FINAL_COUNT=$(wc -l < "$OUTFILE" 2>/dev/null | tr -d ' ' || echo "0")
print_color "$NEON_CYAN" "${COUNT} Total unique subdomains discovered: $FINAL_COUNT"

echo
print_color "$DARK_GRAY" "Cyberpunk Scanner v0.5.4 - System shutdown complete"
print_color "$DARK_GRAY" "Stay anonymous. Stay secure. 🏴‍☠️"