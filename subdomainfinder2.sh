#!/usr/bin/env bash
# SubdomainFinder v0.5.4 (Enhanced Cool Version with Sound Alert)
# Usage: ./subdomainfinder.sh -i domains.txt -o outputs/all-subdomains.txt
# Requires: curl, awk, sort, uniq. jq recommended.

set -euo pipefail
IFS=$'\n\t'

INPUT_FILE=""
OUTFILE="outputs/all-subdomains.txt"
QUIET=0
USER_AGENT="SubdomainFinder/0.5.4 (+https://example.local)"
SOUND_ENABLED=1

# Colors dengan lebih banyak variasi
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# Icons yang lebih keren
ICON_SCAN="🔬"
ICON_FOUND="🎯"
ICON_WARNING="⚠️"
ICON_SUCCESS="✅"
ICON_ERROR="❌"
ICON_START="🚀"
ICON_COMPLETE="🏁"
ICON_SOUND="🔊"

print() { [ "$QUIET" -eq 0 ] && printf '%s\n' "$*"; }
print_color() { [ "$QUIET" -eq 0 ] && printf '%b\n' "$1$2$RESET"; }

# Fungsi untuk memainkan suara
play_sound() {
    if [ "$SOUND_ENABLED" -eq 1 ]; then
        case "$(uname -s)" in
            Linux*)
                # Untuk Linux - menggunakan beep atau speaker-test
                if command -v beep >/dev/null 2>&1; then
                    beep -f 1000 -l 200 -r 3 2>/dev/null || true
                elif command -v speaker-test >/dev/null 2>&1; then
                    speaker-test -t sine -f 1000 -l 1 >/dev/null 2>&1 || true
                fi
                ;;
            Darwin*)
                # Untuk macOS
                afplay /System/Library/Sounds/Submarine.aiff 2>/dev/null || \
                say "Multiple subdomains found" 2>/dev/null || true
                ;;
            MINGW*|CYGWIN*|MSYS*)
                # Untuk Windows Git Bash
                echo -e '\a\a\a'
                ;;
        esac
    fi
}

# Banner keren
show_banner() {
    clear
    print_color "$CYAN$BOLD" "
    ╔═══════════════════════════════════════════════╗
    ║           🚀 SUBDOMAIN FINDER v0.5.4 🚀       ║
    ║              Enhanced Cool Version            ║
    ║                                               ║
    ║    🔬 Scanning | 🎯 Results | 🔊 Sound Alert   ║
    ╚═══════════════════════════════════════════════╝
    "
}

usage() {
    cat <<EOF
Usage: $0 -i domains.txt [-o output_file] [-q] [--no-sound]
  -i input_file    File containing list of domains (one per line)
  -o output_file   Save combined results (default: outputs/all-subdomains.txt)
  -q               Quiet mode
  --no-sound       Disable sound alerts
EOF
    exit 1
}

# Progress bar animation
show_progress() {
    local duration=$1
    local steps=20
    local step_delay=$(echo "scale=3; $duration/$steps" | bc -l)
    
    for i in $(seq 1 $steps); do
        printf "\r${CYAN}${ICON_SCAN} Scanning ["
        for j in $(seq 1 $steps); do
            if [ $j -le $i ]; then
                printf "█"
            else
                printf "░"
            fi
        done
        printf "] %d%%" $((i * 100 / steps))
        sleep $step_delay
    done
    printf "\r${GREEN}${ICON_SUCCESS} Complete ["
    for j in $(seq 1 $steps); do
        printf "█"
    done
    printf "] 100%%${RESET}\n"
}

while getopts ":i:o:qh-:" opt; do
    case ${opt} in
        i) INPUT_FILE=$OPTARG ;;
        o) OUTFILE=$OPTARG ;;
        q) QUIET=1 ;;
        -)
            case "${OPTARG}" in
                no-sound) SOUND_ENABLED=0 ;;
                *) echo "Invalid option: --${OPTARG}" >&2; usage ;;
            esac
            ;;
        h) usage ;;
        \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
        :) echo "Option -$OPTARG requires an argument." >&2; usage ;;
    esac
done
shift $((OPTIND -1))

[ -z "$INPUT_FILE" ] && echo "Please specify -i domains.txt" >&2 && usage
[ ! -f "$INPUT_FILE" ] && echo "Input file $INPUT_FILE not found!" >&2 && exit 1

show_banner
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
print_color "$CYAN$BOLD" "${ICON_START} SubdomainFinder v0.5.4 starting..."
print_color "$BLUE" "📅 Run timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
print_color "$BLUE" "🔊 Sound alerts: $([ "$SOUND_ENABLED" -eq 1 ] && echo "ENABLED" || echo "DISABLED")"
echo

# temp summary (domain|count)
SUMMARY="${TMP_DIR}/summary.tsv"
: > "$SUMMARY"

TOTAL_DOMAINS=$(grep -c '^[^#]' "$INPUT_FILE" | tr -d ' ' || echo "0")
CURRENT_DOMAIN=0

while IFS= read -r DOMAIN || [ -n "$DOMAIN" ]; do
    DOMAIN="${DOMAIN%%#*}"
    DOMAIN="${DOMAIN//[[:space:]]/}"
    [ -z "$DOMAIN" ] && continue
    
    CURRENT_DOMAIN=$((CURRENT_DOMAIN + 1))
    print_color "$YELLOW$BOLD" "\n${ICON_SCAN} Scanning domain: $DOMAIN ($CURRENT_DOMAIN/$TOTAL_DOMAINS)"
    
    # Show progress animation
    show_progress 2 &
    PROGRESS_PID=$!
    
    : > "$CACHE"

    # --- 1) crt.sh ---
    curl -sS -A "$USER_AGENT" --max-time 15 "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$DATA" || true
    if [ -s "$DATA" ]; then
        if command -v jq >/dev/null 2>&1; then
            jq -r '.[].name_value' "$DATA" >> "$CACHE" || true
        else
            grep -oP '"name_value"\s*:\s*"(.*?)"' "$DATA" | sed -E 's/.*"name_value"\s*:\s*"//; s/"$//' | tr ',' '\n' >> "$CACHE" || true
        fi
    fi

    # --- 2) hackertarget ---
    curl -sS -A "$USER_AGENT" --max-time 15 "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" -o "$DATA" || true
    [ -s "$DATA" ] && cut -d',' -f1 "$DATA" >> "$CACHE" || true

    # Wait for progress bar to finish
    wait $PROGRESS_PID 2>/dev/null || true

    # normalize and dedupe for this domain
    PERDOMAIN_TMP="${TMP_DIR}/${DOMAIN//[^a-zA-Z0-9_.-]/_}.txt"
    normalize_file "$CACHE" > "$PERDOMAIN_TMP" || true

    DOMAIN_COUNT=$(wc -l < "$PERDOMAIN_TMP" | tr -d ' ')
    
    # Check if more than 5 subdomains found and play sound
    if [ "$DOMAIN_COUNT" -gt 5 ] && [ "$SOUND_ENABLED" -eq 1 ]; then
        print_color "$PURPLE$BOLD" "${ICON_SOUND} Multiple subdomains found! Playing alert..."
        play_sound &
    fi

    if [ "$DOMAIN_COUNT" -eq 0 ]; then
        print_color "$RED" "${ICON_WARNING} No subdomains found for $DOMAIN"
        echo -e "${DOMAIN}\t0" >> "$SUMMARY"
        print_color "$BLUE" "─────────────────────────────────────────"
        continue
    fi

    # Color code based on number of subdomains found
    if [ "$DOMAIN_COUNT" -gt 10 ]; then
        COUNT_COLOR=$PURPLE
        ICON=$ICON_FOUND
    elif [ "$DOMAIN_COUNT" -gt 5 ]; then
        COUNT_COLOR=$YELLOW
        ICON=$ICON_FOUND
    else
        COUNT_COLOR=$GREEN
        ICON=$ICON_SUCCESS
    fi

    # print nice header + enumerated subdomains
    print_color "$BOLD$COUNT_COLOR" "
╔═══════════════════════════════════════════════╗
║  $ICON $DOMAIN - Found: $DOMAIN_COUNT subdomains $ICON  ║
╚═══════════════════════════════════════════════╝"
    
    nl -ba -w2 -s'. ' "$PERDOMAIN_TMP" | while IFS= read -r line; do
        print_color "$CYAN" "   $line"
    done
    print_color "$BLUE" "─────────────────────────────────────────"

    # save per-domain result, and append to combined outfile
    cp "$PERDOMAIN_TMP" "outputs/${DOMAIN}-subdomains.txt"
    cat "$PERDOMAIN_TMP" >> "$OUTFILE"

    echo -e "${DOMAIN}\t${DOMAIN_COUNT}" >> "$SUMMARY"

done < "$INPUT_FILE"

# final dedupe for combined file
if [ -f "$OUTFILE" ]; then
    sort -u "$OUTFILE" -o "$OUTFILE" || true
fi

# print summary table dengan styling yang lebih keren
print_color "$CYAN$BOLD" "\n${ICON_COMPLETE} SCAN COMPLETE! SUMMARY REPORT"
print_color "$BLUE" "╔═══════════════════════════════════════════════╗"
printf "║${BOLD}%-35s ${BLUE}│${BOLD}%10s${BLUE}║\n" "DOMAIN" "COUNT"
print_color "$BLUE" "╟─────────────────────────────────────────────────╢"

TOTAL_SUBDOMAINS=0
while IFS=$'\t' read -r d c; do
    if [ "$c" -gt 10 ]; then
        COLOR=$PURPLE
    elif [ "$c" -gt 5 ]; then
        COLOR=$YELLOW
    elif [ "$c" -gt 0 ]; then
        COLOR=$GREEN
    else
        COLOR=$RED
    fi
    printf "║%-35s ${BLUE}│ ${COLOR}%8s ${BLUE}║\n" "$d" "$c"
    TOTAL_SUBDOMAINS=$((TOTAL_SUBDOMAINS + c))
done < "$SUMMARY"

print_color "$BLUE" "╟─────────────────────────────────────────────────╢"
printf "║${BOLD}%-35s ${BLUE}│${GREEN}%10s${BLUE}║\n" "TOTAL UNIQUE SUBDOMAINS" "$(wc -l < "$OUTFILE" | tr -d ' ')"
print_color "$BLUE" "╚═══════════════════════════════════════════════╝"

print_color "$GREEN$BOLD" "\n${ICON_SUCCESS} Results saved to: $PWD/$OUTFILE"
print_color "$GREEN" "${ICON_SUCCESS} Per-domain files: outputs/<domain>-subdomains.txt"

# Final sound alert if many subdomains found overall
if [ "$TOTAL_SUBDOMAINS" -gt 20 ] && [ "$SOUND_ENABLED" -eq 1 ]; then
    print_color "$PURPLE$BOLD" "\n${ICON_SOUND} Excellent results! Multiple subdomains discovered!"
    play_sound
fi
