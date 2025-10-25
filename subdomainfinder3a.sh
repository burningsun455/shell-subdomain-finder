#!/usr/bin/env bash
# SubdomainFinder v0.5.4 (Modern UI Edition)
# Usage: ./subdomainfinder.sh -i domains.txt -o outputs/all-subdomains.txt
# Requires: curl, awk, sort, uniq. jq recommended.

set -euo pipefail
IFS=$'\n\t'

INPUT_FILE=""
OUTFILE="outputs/all-subdomains.txt"
QUIET=0
USER_AGENT="SubdomainFinder/0.5.4 (+https://example.local)"

# Modern Colors with better compatibility
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# UI Elements
CHECK="✅"
SCAN="🔍"
ROCKET="🚀"
FOLDER="📁"
FILE="📄"
CALENDAR="📅"
GLOBE="🌐"
WARNING="⚠️"
SUCCESS="🎉"
ERROR="❌"
LIST="📋"
COUNT="🔢"

print() {
    [ "$QUIET" -eq 0 ] && printf '%s\n' "$*";
}

print_color() {
    [ "$QUIET" -eq 0 ] && printf '%b\n' "$1$2$RESET";
}

# Modern gradient-like banner
print_banner() {
    clear
    print_color "$BLUE$BOLD" "╔══════════════════════════════════════════════════════════════╗"
    print_color "$BLUE$BOLD" "║                                                              ║"
    print_color "$BLUE$BOLD" "║    ███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗     ║"
    print_color "$BLUE$BOLD" "║    ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║     ║"
    print_color "$BLUE$BOLD" "║    ███████╗██║   ██║██║  ██║██████╔╝██║   ██║██╔████╔██║     ║"
    print_color "$BLUE$BOLD" "║    ╚════██║██║   ██║██║  ██║██╔══██╗██║   ██║██║╚██╔╝██║     ║"
    print_color "$BLUE$BOLD" "║    ███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║     ║"
    print_color "$BLUE$BOLD" "║    ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝     ║"
    print_color "$BLUE$BOLD" "║                                                              ║"
    print_color "$CYAN$BOLD" "║                SubdomainFinder v0.5.4 (Modern UI)            ║"
    print_color "$BLUE$BOLD" "║                     Enhanced Security Scanner                ║"
    print_color "$BLUE$BOLD" "║                                                              ║"
    print_color "$BLUE$BOLD" "╚══════════════════════════════════════════════════════════════╝"
    echo
}

# Modern progress bar
progress_bar() {
    local duration=${1}
    local width=50
    local increment=$((duration / width))
    
    for ((i=0; i<=width; i++)); do
        percentage=$((i * 2))
        completed=$((i * width / width))
        remaining=$((width - i))
        
        printf "\r${BLUE}[${GREEN}"
        printf "%0.s█" $(seq 1 $i)
        printf "%0.s░" $(seq 1 $remaining)
        printf "${BLUE}] ${percentage}%%${RESET}"
        sleep $increment
    done
    printf "\n"
}

# Animated scanning indicator
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c] " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Modern table header
print_table_header() {
    printf '%b' "$BLUE$BOLD"
    printf '╔═══════════════════════════════════════╦═════════════╗\n'
    printf '║ %-35s ║ %-11s ║\n' "DOMAIN" "COUNT"
    printf '╠═══════════════════════════════════════╬═════════════╣\n'
    printf '%b' "$RESET"
}

# Modern table row
print_table_row() {
    local domain="$1"
    local count="$2"
    local icon="$3"
    
    if [ "$count" -eq 0 ]; then
        printf '║ %b%-35s%b ║ %b%-11s%b ║\n' "$icon" "$domain" "$RESET" "$RED$BOLD" "$count" "$RESET"
    elif [ "$count" -lt 10 ]; then
        printf '║ %b%-35s%b ║ %b%-11s%b ║\n' "$icon" "$domain" "$RESET" "$YELLOW$BOLD" "$count" "$RESET"
    else
        printf '║ %b%-35s%b ║ %b%-11s%b ║\n' "$icon" "$domain" "$RESET" "$GREEN$BOLD" "$count" "$RESET"
    fi
}

# Modern table footer
print_table_footer() {
    local total="$1"
    printf '%b' "$BLUE$BOLD"
    printf '╠═══════════════════════════════════════╬═════════════╣\n'
    printf '║ %-35s ║ %b%-11s%b ║\n' "TOTAL UNIQUE SUBDOMAINS" "$GREEN$BOLD" "$total" "$BLUE$BOLD"
    printf '╚═══════════════════════════════════════╩═════════════╝\n'
    printf '%b' "$RESET"
}

# Domain status with icons
get_domain_icon() {
    local count="$1"
    if [ "$count" -eq 0 ]; then
        echo "$ERROR"
    elif [ "$count" -lt 5 ]; then
        echo "$WARNING"
    elif [ "$count" -lt 15 ]; then
        echo "$LIST"
    else
        echo "$SUCCESS"
    fi
}

usage() {
    cat <<EOF
${BOLD}${BLUE}SubdomainFinder - Modern Subdomain Enumeration Tool${RESET}

${GREEN}Usage:${RESET} $0 -i domains.txt [-o output_file] [-q]

${YELLOW}Options:${RESET}
  ${CYAN}-i input_file${RESET}    File containing list of domains (one per line)
  ${CYAN}-o output_file${RESET}   Save combined results (default: outputs/all-subdomains.txt)
  ${CYAN}-q${RESET}               Quiet mode
  ${CYAN}-h${RESET}               Show this help message

${GREEN}Examples:${RESET}
  $0 -i domains.txt
  $0 -i targets.txt -o results/all-found.txt
  $0 -i domains.txt -q

${PURPLE}Requirements:${RESET} curl, awk, sort, uniq. jq recommended for better parsing.
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
        \?) echo -e "${ERROR} ${RED}Invalid option: -$OPTARG${RESET}" >&2; usage ;;
        :) echo -e "${ERROR} ${RED}Option -$OPTARG requires an argument.${RESET}" >&2; usage ;;
    esac
done
shift $((OPTIND -1))

# Validation
[ -z "$INPUT_FILE" ] && echo -e "${ERROR} ${RED}Please specify -i domains.txt${RESET}" >&2 && usage
[ ! -f "$INPUT_FILE" ] && echo -e "${ERROR} ${RED}Input file $INPUT_FILE not found!${RESET}" >&2 && exit 1

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

print_color "$CYAN$BOLD" "${ROCKET} SubdomainFinder v0.5.4 starting..."
print_color "$BLUE" "${CALENDAR} Run timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
print_color "$BLUE" "${GLOBE} Target file: $INPUT_FILE"
print_color "$BLUE" "${FOLDER} Output directory: $(dirname "$OUTFILE")"
echo

# Show initialization progress
print_color "$YELLOW" "${SCAN} Initializing scan environment..."
progress_bar 2

# temp summary (domain|count)
SUMMARY="${TMP_DIR}/summary.tsv"
: > "$SUMMARY"

TOTAL_DOMAINS=$(grep -c '^[^#]' "$INPUT_FILE" | tr -d ' ' || echo "0")
CURRENT_DOMAIN=0

print_color "$GREEN$BOLD" "${LIST} Scanning $TOTAL_DOMAINS domains..."
echo

# Array untuk menyimpan hasil sementara
declare -a DOMAIN_RESULTS=()

while IFS= read -r DOMAIN || [ -n "$DOMAIN" ]; do
    DOMAIN="${DOMAIN%%#*}"
    DOMAIN="${DOMAIN//[[:space:]]/}"
    [ -z "$DOMAIN" ] && continue
    
    CURRENT_DOMAIN=$((CURRENT_DOMAIN + 1))
    
    # Print domain header with progress
    print_color "$CYAN$BOLD" "┌─────────────────────────────────────────────────────────┐"
    printf "%b ${BOLD}%s${RESET} ${DIM}(%d/%d)${RESET}\n" "$SCAN" "Scanning: $DOMAIN" "$CURRENT_DOMAIN" "$TOTAL_DOMAINS"
    print_color "$CYAN$BOLD" "└─────────────────────────────────────────────────────────┘"
    
    : > "$CACHE"
    
    # Show scanning animation
    print_color "$YELLOW" "Querying certificate transparency logs (crt.sh)..."
    (curl -sS -A "$USER_AGENT" --max-time 15 "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$DATA" || true) &
    spinner $!
    
    if [ -s "$DATA" ]; then
        if command -v jq >/dev/null 2>&1; then
            jq -r '.[].name_value' "$DATA" >> "$CACHE" 2>/dev/null || true
        else
            grep -oP '"name_value"\s*:\s*"(.*?)"' "$DATA" | sed -E 's/.*"name_value"\s*:\s*"//; s/"$//' | tr ',' '\n' >> "$CACHE" 2>/dev/null || true
        fi
        print_color "$GREEN" "${CHECK} crt.sh query completed"
    fi
    
    print_color "$YELLOW" "Querying HackerTarget API..."
    (curl -sS -A "$USER_AGENT" --max-time 15 "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" -o "$DATA" || true) &
    spinner $!
    
    [ -s "$DATA" ] && cut -d',' -f1 "$DATA" >> "$CACHE" || true
    print_color "$GREEN" "${CHECK} HackerTarget query completed"
    
    # normalize and dedupe for this domain
    PERDOMAIN_TMP="${TMP_DIR}/${DOMAIN//[^a-zA-Z0-9_.-]/_}.txt"
    normalize_file "$CACHE" > "$PERDOMAIN_TMP" || true
    
    DOMAIN_COUNT=$(wc -l < "$PERDOMAIN_TMP" 2>/dev/null | tr -d ' ' || echo "0")
    
    # Get appropriate icon for domain results
    DOMAIN_ICON=$(get_domain_icon "$DOMAIN_COUNT")
    
    # Simpan hasil ke array untuk ditampilkan nanti
    DOMAIN_RESULTS+=("$DOMAIN" "$DOMAIN_COUNT" "$DOMAIN_ICON")
    
    if [ "$DOMAIN_COUNT" -eq 0 ]; then
        print_color "$RED" "${ERROR} No subdomains found for $DOMAIN"
        echo -e "${DOMAIN}\t0" >> "$SUMMARY"
    else
        print_color "$GREEN" "${SUCCESS} Found $DOMAIN_COUNT subdomains for $DOMAIN"
        
        # Print subdomains in a nice box
        print_color "$BLUE" "┌───────────────────── SUBDOMAINS ─────────────────────┐"
        nl -ba -w3 -s'. ' "$PERDOMAIN_TMP" | sed "s/^/ ${DIM}│ ${RESET}/" | while IFS= read -r line; do
            print "$line"
        done
        print_color "$BLUE" "└──────────────────────────────────────────────────────┘"
        
        # save per-domain result, and append to combined outfile
        mkdir -p "outputs"
        cp "$PERDOMAIN_TMP" "outputs/${DOMAIN}-subdomains.txt" 2>/dev/null || true
        cat "$PERDOMAIN_TMP" >> "$OUTFILE"
        echo -e "${DOMAIN}\t${DOMAIN_COUNT}" >> "$SUMMARY"
    fi
    
    echo
    print_color "$DIM" "──────────────────────────────────────────────────────────"
    echo
    
done < "$INPUT_FILE"

# Final dedupe for combined file
if [ -f "$OUTFILE" ]; then
    print_color "$YELLOW" "${SCAN} Deduplicating final results..."
    sort -u "$OUTFILE" -o "$OUTFILE" || true
fi

# Print final summary dalam 1 tabel saja
print_color "$CYAN$BOLD" "╔══════════════════════════════════════════════════════════════╗"
print_color "$CYAN$BOLD" "║                       SCAN SUMMARY                          ║"
print_color "$CYAN$BOLD" "╚══════════════════════════════════════════════════════════════╝"
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
print_color "$GREEN$BOLD" "${SUCCESS} Scan completed successfully!"
print_color "$GREEN" "${FILE} Combined results: $PWD/$OUTFILE"
print_color "$GREEN" "${FOLDER} Per-domain files: outputs/<domain>-subdomains.txt"

FINAL_COUNT=$(wc -l < "$OUTFILE" 2>/dev/null | tr -d ' ' || echo "0")
print_color "$CYAN$BOLD" "${COUNT} Total unique subdomains found: $FINAL_COUNT"

echo
print_color "$DIM" "Thank you for using SubdomainFinder v0.5.4"