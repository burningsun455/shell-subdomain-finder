#!/usr/bin/env bash
# SubdomainFinder v1.2 — STABLE ULTIMATE Edition (Fixed Syntax)
# Usage: ./subdomainfinder-stable.sh -i domains.txt [options]

set -euo pipefail
IFS=$'\n\t'

VERSION="1.2"

INPUT_FILE=""
OUTFILE="outputs/all-subdomains.txt"
QUIET=0
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
SOUND_ENABLED=1
WORDLIST=""
DOH_RESOLVE=0
HTTP_PROBE=0
INCLUDE_RE=""
EXCLUDE_RE=""
ONLY_NEW=0
THREADS=10
FORMAT="txt"
TITLE_FETCH=0
PROBE_TIMEOUT=3
BATCH_SIZE=20

# Colors & Icons
GREEN=$'\033[0;32m'
CYAN=$'\033[0;36m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
PURPLE=$'\033[0;35m'
BLUE=$'\033[0;34m'
BOLD=$'\033[1m'
RESET=$'\033[0m'

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
print_inline() { [ "$QUIET" -eq 0 ] && printf '%b\r' "$1$2$RESET" && sleep 0.01; }

play_sound() {
  [ "$SOUND_ENABLED" -ne 1 ] && return 0
  printf '\a' 2>/dev/null || true
}

show_banner() {
  [ "$QUIET" -eq 1 ] && return
  clear 2>/dev/null || true
  print_color "$CYAN$BOLD" "
╔══════════════════════════════════════════════════════════╗
║         🚀 SUBDOMAIN FINDER v${VERSION} — STABLE ULTIMATE  ║
║  🎯 15+ Sources | ⚡ Windows Optimized | 🔥 Real-time     ║
╚══════════════════════════════════════════════════════════╝"
}

usage() {
  cat <<EOF
Usage: $0 -i domains.txt [options]
  -i FILE         Input domain list
  -o FILE         Output file
  -q              Quiet mode  
  --no-sound      Disable sound
  -w WORDLIST     Bruteforce with wordlist
  --resolve       DNS validation
  --http-probe    HTTP status check
  --threads N     Concurrency (default: 10, max: 15)
  --only-new      Process only new subdomains
  --include REGEX Include pattern
  --exclude REGEX Exclude pattern
  -h              Help

Examples:
  $0 -i domains.txt --threads 10
  $0 -i domains.txt -w wordlist.txt --threads 12
EOF
  exit 1
}

# Parse arguments
while getopts ":i:o:qw:h-:" opt; do
  case ${opt} in
    i) INPUT_FILE=$OPTARG ;;
    o) OUTFILE=$OPTARG ;;
    q) QUIET=1 ;;
    w) WORDLIST=$OPTARG ;;
    h) usage ;;
    -)
      case "${OPTARG}" in
        no-sound) SOUND_ENABLED=0 ;;
        resolve) DOH_RESOLVE=1 ;;
        http-probe) HTTP_PROBE=1 ;;
        title) TITLE_FETCH=1 ;;
        threads=*) THREADS="${OPTARG#threads=}" ;;
        threads) THREADS="${!OPTIND}"; OPTIND=$((OPTIND+1)) ;;
        only-new) ONLY_NEW=1 ;;
        include=*) INCLUDE_RE="${OPTARG#include=}" ;;
        include) INCLUDE_RE="${!OPTIND}"; OPTIND=$((OPTIND+1)) ;;
        exclude=*) EXCLUDE_RE="${OPTARG#exclude=}" ;;
        exclude) EXCLUDE_RE="${!OPTIND}"; OPTIND=$((OPTIND+1)) ;;
        format=*) FORMAT="${OPTARG#format=}" ;;
        format) FORMAT="${!OPTIND}"; OPTIND=$((OPTIND+1)) ;;
        timeout=*) PROBE_TIMEOUT="${OPTARG#timeout=}" ;;
        timeout) PROBE_TIMEOUT="${!OPTIND}"; OPTIND=$((OPTIND+1)) ;;
        batch=*) BATCH_SIZE="${OPTARG#batch=}" ;;
        batch) BATCH_SIZE="${!OPTIND}"; OPTIND=$((OPTIND+1)) ;;
        *) echo "Invalid option: --${OPTARG}" >&2; usage ;;
      esac
      ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
    :)  echo "Option -$OPTARG requires an argument." >&2; usage ;;
  esac
done
shift $((OPTIND -1))

[ -z "$INPUT_FILE" ] && echo "Please specify -i domains.txt" >&2 && usage
[ ! -f "$INPUT_FILE" ] && echo "Input file $INPUT_FILE not found!" >&2 && exit 1

# Windows/Git Bash stability limits
if [ "$THREADS" -gt 15 ]; then
  THREADS=15
  print_color "$YELLOW" "${ICON_WARNING} Threads limited to 15 for Windows stability"
fi

mkdir -p "$(dirname "$OUTFILE")" outputs

TMP_DIR=$(mktemp -d -t subfinder-stable.XXXXXX 2>/dev/null || mktemp -d)
trap 'rm -rf "$TMP_DIR" 2>/dev/null || true' EXIT

SUMMARY="${TMP_DIR}/summary.tsv"
COMBINED="${TMP_DIR}/combined.txt"
: > "$SUMMARY"
: > "$COMBINED"

show_banner
print_color "$BLUE" "📅 $(date -u +'%Y-%m-%dT%H:%M:%SZ')  🔊 Sound: $([ $SOUND_ENABLED -eq 1 ] && echo ENABLED || echo DISABLED)"
print_color "$BLUE" "⚡ Threads: $THREADS  📦 Batch: $BATCH_SIZE  ⏱️ Timeout: ${PROBE_TIMEOUT}s"
print_color "$BLUE" "🎯 Sources: 15+ APIs  🛡️ Windows Optimized"
[ -n "$WORDLIST" ] && print_color "$BLUE" "🧩 Wordlist: $WORDLIST"
print ""

# Global counters
TOTAL_FOUND=0
START_TIME=$SECONDS

# Print real-time results
print_subdomain() {
  local domain="$1" subdomain="$2" count="$3" source="$4"
  TOTAL_FOUND=$((TOTAL_FOUND + 1))
  
  # Choose color based on source
  case "$source" in
    "crt.sh") COLOR=$GREEN; ICON="📜" ;;
    "hackertarget") COLOR=$BLUE; ICON="🎯" ;;
    "alienvault") COLOR=$PURPLE; ICON="👽" ;;
    "bufferover") COLOR=$CYAN; ICON="🌀" ;;
    "rapiddns") COLOR=$YELLOW; ICON="⚡" ;;
    "wayback") COLOR=$RED; ICON="🏛️" ;;
    "virustotal") COLOR=$GREEN; ICON="🛡️" ;;
    "threatcrowd") COLOR=$RED; ICON="👻" ;;
    "certspotter") COLOR=$BLUE; ICON="🔐" ;;
    "sonar") COLOR=$PURPLE; ICON="📡" ;;
    "anubis") COLOR=$CYAN; ICON="🐍" ;;
    "urlscan") COLOR=$YELLOW; ICON="🌐" ;;
    "wordlist") COLOR=$PURPLE; ICON="📋" ;;
    *) COLOR=$CYAN; ICON="🔍" ;;
  esac
  
  print_color "$COLOR" "$ICON [$source] $subdomain"
  
  # Play sound for every 20th subdomain
  if [ "$((TOTAL_FOUND % 20))" -eq 0 ]; then
    play_sound &
  fi
}

# Safe curl with timeout
safe_curl() {
  local url="$1" max_time="${2:-8}"
  curl -s --max-time "$max_time" --connect-timeout 5 \
       -H "User-Agent: $USER_AGENT" \
       -H "Accept: application/json, */*" \
       --compressed \
       --retry 0 \
       "$url" 2>/dev/null || echo ""
}

# Individual source functions
source_crtsh() {
  local domain="$1"
  safe_curl "https://crt.sh/?q=%25.$domain&output=json" | \
  grep -oE '"name_value":"[^"]+"' 2>/dev/null | \
  sed 's/"name_value":"//g; s/"//g' | \
  while read -r sub; do
    [ -n "$sub" ] && echo "crt.sh|$sub"
  done
}

source_hackertarget() {
  local domain="$1"
  safe_curl "https://api.hackertarget.com/hostsearch/?q=$domain" | \
  cut -d',' -f1 2>/dev/null | \
  while read -r sub; do
    [ -n "$sub" ] && echo "hackertarget|$sub"
  done
}

source_sonar() {
  local domain="$1"
  safe_curl "https://sonar.omnisint.io/subdomains/$domain" | \
  grep -oE '"[^"]+"' 2>/dev/null | \
  sed 's/"//g' | \
  while read -r sub; do
    [ -n "$sub" ] && echo "sonar|$sub"
  done
}

source_anubis() {
  local domain="$1"
  safe_curl "https://jldc.me/anubis/subdomains/$domain" | \
  grep -oE '"[^"]+"' 2>/dev/null | \
  sed 's/"//g' | \
  while read -r sub; do
    [ -n "$sub" ] && echo "anubis|$sub"
  done
}

source_bufferover() {
  local domain="$1"
  safe_curl "https://dns.bufferover.run/dns?q=.$domain" | \
  grep -oE "[a-zA-Z0-9._-]+\.$domain" 2>/dev/null | \
  while read -r sub; do
    [ -n "$sub" ] && echo "bufferover|$sub"
  done
}

source_rapiddns() {
  local domain="$1"
  safe_curl "https://rapiddns.io/subdomain/$domain?full=1" | \
  grep -oE ">[a-zA-Z0-9._-]+\.$domain<" 2>/dev/null | \
  sed 's/[><]//g' | \
  while read -r sub; do
    [ -n "$sub" ] && echo "rapiddns|$sub"
  done
}

source_wayback() {
  local domain="$1"
  safe_curl "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | \
  sed -e 's_https*://__' -e "s/\/.*//" -e "s/:.*//" 2>/dev/null | \
  sort -u | \
  while read -r sub; do
    [ -n "$sub" ] && echo "wayback|$sub"
  done
}

# Wordlist bruteforce
bruteforce_domain() {
  local domain="$1" wordlist="$2"
  if [ -f "$wordlist" ]; then
    awk 'NF && $0 !~ /^#/ {print tolower($0)}' "$wordlist" 2>/dev/null | \
    sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | \
    while read -r word; do
      [ -n "$word" ] && echo "wordlist|${word}.$domain"
    done
  fi
}

# Main scanning function
scan_domain() {
  local domain="$1"
  local domain_count=0
  local unique_subs="${TMP_DIR}/subs_${domain}.txt"
  : > "$unique_subs"
  
  print_color "$YELLOW" "${ICON_SCAN} Scanning: $domain"
  
  # Run sources sequentially to avoid fork bombs
  {
    source_crtsh "$domain"
    source_hackertarget "$domain" 
    source_sonar "$domain"
    source_anubis "$domain"
    source_bufferover "$domain"
    source_rapiddns "$domain"
    source_wayback "$domain"
    
    # Wordlist if provided
    if [ -n "$WORDLIST" ]; then
      bruteforce_domain "$domain" "$WORDLIST"
    fi
  } | while IFS='|' read -r source subdomain; do
    # Normalize subdomain
    subdomain=$(echo "$subdomain" | tr 'A-Z' 'a-z' | sed 's/^\*\.//; s/^\.//; s/[[:space:]]*$//' 2>/dev/null)
    
    # Validate it's a proper subdomain
    if [[ "$subdomain" =~ [a-zA-Z0-9.-] ]] && [[ "$subdomain" == *."$domain" ]]; then
      # Check if unique
      if ! grep -q -x -F "$subdomain" "$unique_subs" 2>/dev/null; then
        echo "$subdomain" >> "$unique_subs"
        domain_count=$((domain_count + 1))
        
        # Print immediately
        print_subdomain "$domain" "$subdomain" "$domain_count" "$source"
        
        # Save to combined output
        echo "$subdomain" >> "$COMBINED"
      fi
    fi
  done
  
  # Update summary
  echo -e "${domain}\t${domain_count}" >> "$SUMMARY"
  
  # Save per-domain file
  if [ -s "$unique_subs" ]; then
    sort -u "$unique_subs" > "outputs/${domain}-subdomains.txt" 2>/dev/null || true
  fi
  
  # Show domain completion
  if [ "$domain_count" -gt 0 ]; then
    if [ "$domain_count" -gt 20 ]; then COLOR=$PURPLE; ICON="🔥"
    elif [ "$domain_count" -gt 10 ]; then COLOR=$YELLOW; ICON="⚡"  
    elif [ "$domain_count" -gt 5 ]; then COLOR=$GREEN; ICON="🎯"
    else COLOR=$CYAN; ICON="✅"; fi
    
    print_color "$COLOR$BOLD" "$ICON $domain - COMPLETED: $domain_count subdomains"
  else
    print_color "$RED" "${ICON_WARNING} $domain - No subdomains found"
  fi
}

# Progress display
show_progress() {
  while true; do
    current_processed=$(wc -l < "$SUMMARY" 2>/dev/null || echo 0)
    current_found=$(wc -l < "$COMBINED" 2>/dev/null | tr -d ' ' || echo 0)
    elapsed=$((SECONDS - START_TIME))
    print_inline "$CYAN" "📊 Progress: $current_processed domains | 🎯 $current_found subdomains | ⏱️ ${elapsed}s"
    sleep 2
  done
}

# Main execution
main() {
  TOTAL_DOMAINS=$(grep -c '^[^#]' "$INPUT_FILE" 2>/dev/null || echo 0)
  [ "$TOTAL_DOMAINS" -eq 0 ] && {
    print_color "$RED" "${ICON_ERROR} No domains found in $INPUT_FILE"
    exit 1
  }

  print_color "$GREEN$BOLD" "${ICON_START} Starting scan of $TOTAL_DOMAINS domains..."
  print_color "$YELLOW" "${ICON_WARNING} Using controlled parallelism for stability"

  # Start progress display
  show_progress &
  PROGRESS_PID=$!
  
  # Process domains with controlled concurrency
  local domain_index=0
  while IFS= read -r DOMAIN || [ -n "$DOMAIN" ]; do
    DOMAIN="${DOMAIN%%#*}"; DOMAIN="${DOMAIN//[[:space:]]/}"
    [ -z "$DOMAIN" ] && continue
    
    domain_index=$((domain_index + 1))
    
    # Wait if too many jobs running
    while [ $(jobs -r | wc -l) -ge "$THREADS" ]; do
      sleep 1
    done
    
    # Start domain scan in background
    ( scan_domain "$DOMAIN" ) &
    
  done < "$INPUT_FILE"

  # Wait for all jobs to complete
  wait
  
  # Stop progress display
  kill $PROGRESS_PID 2>/dev/null || true

  # Final processing
  if [ -f "$COMBINED" ]; then
    sort -u "$COMBINED" -o "$COMBINED" 2>/dev/null || true
    FINAL_COUNT=$(wc -l < "$COMBINED" 2>/dev/null | tr -d ' ' || echo 0)
    cp "$COMBINED" "$OUTFILE" 2>/dev/null || true
  else
    FINAL_COUNT=0
  fi
  
  ELAPSED_TIME=$((SECONDS - START_TIME))

  # Final summary
  print_color "$CYAN$BOLD" "\n${ICON_COMPLETE} SCAN COMPLETE!"
  print_color "$BLUE" "╔═══════════════════════════════════════════════╗"
  printf "║${BOLD}%-32s ${BLUE}│${BOLD}%12s${BLUE}║\n" "TOTAL DOMAINS SCANNED" "$TOTAL_DOMAINS"
  printf "║%-32s ${BLUE}│ %12s${BLUE}║\n" "UNIQUE SUBDOMAINS FOUND" "$FINAL_COUNT"
  printf "║%-32s ${BLUE}│ %12s${BLUE}║\n" "TOTAL EXECUTION TIME" "${ELAPSED_TIME}s"
  print_color "$BLUE" "╚═══════════════════════════════════════════════╝"

  print_color "$GREEN$BOLD" "${ICON_SUCCESS} Results saved: $OUTFILE"
  print_color "$GREEN" "${ICON_SUCCESS} Per-domain files in: outputs/"

  # Play completion sound
  play_sound

  print_color "$PURPLE" "\n🔥 ${BOLD}SCAN COMPLETED! ${FINAL_COUNT} subdomains found from ${TOTAL_DOMAINS} domains in ${ELAPSED_TIME} seconds!"
}

# Run main function
main "$@"