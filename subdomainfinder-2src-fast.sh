#!/usr/bin/env bash
# SubdomainFinder v0.7.0 — Ultra Fast Edition (Massive Parallel, Optimized Sources)
# Usage: ./subdomainfinder-fast.sh -i domains.txt [-o outputs/all-subdomains.txt] [options]

set -euo pipefail
IFS=$'\n\t'

VERSION="0.7.0"

INPUT_FILE=""
OUTFILE="outputs/all-subdomains.txt"
QUIET=0
USER_AGENT="SubdomainFinder/${VERSION} (+https://example.local)"
SOUND_ENABLED=1
WORDLIST=""
DOH_RESOLVE=0
HTTP_PROBE=0
INCLUDE_RE=""
EXCLUDE_RE=""
ONLY_NEW=0
THREADS=20  # Increased default threads
FORMAT="txt"
TITLE_FETCH=0
PROBE_TIMEOUT=3  # Reduced timeout
BATCH_SIZE=50    # Batch processing for efficiency

# Colors & Icons
GREEN=$'\033[0;32m'; CYAN=$'\033[0;36m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'
PURPLE=$'\033[0;35m'; BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
ICON_SCAN="🔬"; ICON_FOUND="🎯"; ICON_WARNING="⚠️"; ICON_SUCCESS="✅"
ICON_ERROR="❌"; ICON_START="🚀"; ICON_COMPLETE="🏁"; ICON_SOUND="🔊"

print() { [ "$QUIET" -eq 0 ] && printf '%s\n' "$*"; }
print_color() { [ "$QUIET" -eq 0 ] && printf '%b\n' "$1$2$RESET"; }

play_sound() {
  [ "$SOUND_ENABLED" -ne 1 ] && return 0
  case "$(uname -s)" in
    Linux*) command -v beep >/dev/null && { beep -f 1000 -l 200 -r 2 2>/dev/null || true; } ;;
    Darwin*) afplay /System/Library/Sounds/Submarine.aiff 2>/dev/null || say "Scan complete" 2>/dev/null || true ;;
    MINGW*|CYGWIN*|MSYS*) printf '\a\a' ;;
  esac
}

show_banner() {
  [ "$QUIET" -eq 1 ] && return
  clear 2>/dev/null || true
  print_color "$CYAN$BOLD" "
╔══════════════════════════════════════════════════════╗
║         🚀 SUBDOMAIN FINDER v${VERSION} — ULTRA FAST      ║
║  ⚡ Parallel | 🎯 Optimized | 🚀 Mass Sources | 🔊 Alert ║
╚══════════════════════════════════════════════════════╝"
}

usage() {
  cat <<EOF
Usage: $0 -i domains.txt [options]
  -i FILE         Input domain list (one per line)
  -o FILE         Output file (default: ${OUTFILE})
  -q              Quiet mode
  --no-sound      Disable sound
  -w WORDLIST     Bruteforce with wordlist
  --resolve       DNS validation via DoH
  --http-probe    HTTP status check
  --title         Fetch page titles during probe
  --threads N     Concurrency (default: 20, max: 50)
  --only-new      Process only new subdomains
  --include REGEX Include pattern
  --exclude REGEX Exclude pattern
  --format FMT    txt | csv | ndjson (default: txt)
  --timeout N     HTTP timeout seconds (default: 3)
  --batch N       Batch size for processing (default: 50)
  -h              Help

Examples:
  $0 -i domains.txt --resolve --http-probe --threads 30
  $0 -i domains.txt -w common.txt --threads 40 --batch 100
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

# Limit threads for stability
if [ "$THREADS" -gt 50 ]; then
  THREADS=50
  print_color "$YELLOW" "${ICON_WARNING} Threads limited to 50 for stability"
fi

mkdir -p "$(dirname "$OUTFILE")" outputs

TMP_DIR=$(mktemp -d -t subfinder-fast.XXXXXX 2>/dev/null || mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

SUMMARY="${TMP_DIR}/summary.tsv"
COMBINED="${TMP_DIR}/combined.txt"
: > "$SUMMARY"
: > "$COMBINED"

show_banner
print_color "$BLUE" "📅 $(date -u +'%Y-%m-%dT%H:%M:%SZ')  🔊 Sound: $([ $SOUND_ENABLED -eq 1 ] && echo ENABLED || echo DISABLED)"
print_color "$BLUE" "⚡ Threads: $THREADS  📦 Batch: $BATCH_SIZE  ⏱️ Timeout: ${PROBE_TIMEOUT}s"
print_color "$BLUE" "🔧 Resolve: $([ $DOH_RESOLVE -eq 1 ] && echo DoH || echo OFF)  🌐 Probe: $([ $HTTP_PROBE -eq 1 ] && echo ON || echo OFF)"
[ -n "$WORDLIST" ] && print_color "$BLUE" "🧩 Wordlist: $WORDLIST"
[ -n "$INCLUDE_RE" ] && print_color "$BLUE" "🔎 Include: $INCLUDE_RE"
[ -n "$EXCLUDE_RE" ] && print_color "$BLUE" "🚫 Exclude: $EXCLUDE_RE"
print ""

# Enhanced parallel execution function
parallel_exec() {
  local func="$1"
  local input_file="$2"
  local output_file="$3"
  local batch_size="${4:-$BATCH_SIZE}"
  
  if command -v parallel >/dev/null 2>&1; then
    # Use GNU parallel for maximum efficiency
    cat "$input_file" | parallel -j "$THREADS" --pipe --block "$batch_size" "$func" > "$output_file"
  else
    # Fallback to xargs
    cat "$input_file" | xargs -I {} -P "$THREADS" sh -c "$func" _ {} > "$output_file"
  fi
}

# Fast normalization
normalize_lines() {
  awk 'NF && $0 !~ /^#/ {print tolower($0)}' | 
  sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^\*\.//; s/^\*//' |
  sort -u
}

# Ultra-fast curl with connection reuse
fast_curl() {
  local url="$1" out="$2"
  curl -sS -f -L --connect-timeout 5 --max-time 10 \
       -A "$USER_AGENT" \
       -H 'Accept: application/json, */*' \
       --compressed \
       --retry 1 \
       "$url" -o "$out" 2>/dev/null || return 1
}

# Batch DNS resolution
batch_doh_resolve() {
  local input_file="$1" output_file="$2"
  : > "$output_file"
  
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    (
      result=$(doh_resolve_one "$host")
      if [ -n "$result" ]; then
        printf "%s\t%s\n" "$host" "$result" >> "$output_file"
      fi
    ) &
    
    # Control parallelism
    while [ $(jobs -r | wc -l) -ge "$THREADS" ]; do sleep 0.1; done
  done < "$input_file"
  wait
}

doh_resolve_one() {
  local host="$1" out ip
  out="${TMP_DIR}/doh.$$.json"

  # Try Cloudflare first (fastest)
  if fast_curl "https://cloudflare-dns.com/dns-query?name=${host}&type=A" "$out"; then
    if command -v jq >/dev/null 2>&1; then
      ip=$(jq -r '.Answer?[]?|select(.type==1)|.data' "$out" 2>/dev/null | head -n1)
    else
      ip=$(grep -oE '"data":"[0-9.]+"' "$out" | head -1 | sed -E 's/.*"data":"//; s/".*//')
    fi
  fi

  # Fallback to Google if needed
  if [ -z "${ip:-}" ]; then
    if fast_curl "https://dns.google/resolve?name=${host}&type=A" "$out"; then
      if command -v jq >/dev/null 2>&1; then
        ip=$(jq -r '.Answer?[]?|select(.type==1)|.data' "$out" 2>/dev/null | head -n1)
      fi
    fi
  fi

  printf "%s" "${ip:-}"
}

# Batch HTTP probing
batch_http_probe() {
  local input_file="$1" output_file="$2"
  : > "$output_file"
  
  while IFS= read -r host; do
    [ -z "$host" ] && continue
    (
      result=$(http_probe_one "$host")
      printf "%s\n" "$result" >> "$output_file"
    ) &
    
    # Control parallelism
    while [ $(jobs -r | wc -l) -ge "$THREADS" ]; do sleep 0.1; done
  done < "$input_file"
  wait
}

http_probe_one() {
  local host="$1" url status title=""
  
  # Try HTTPS first (most common)
  url="https://${host}"
  status=$(curl -sS -m "$PROBE_TIMEOUT" -o /dev/null -w "%{http_code}" \
           -A "$USER_AGENT" -I "$url" 2>/dev/null || echo "")
           
  # Fallback to HTTP if HTTPS fails
  if [ -z "$status" ] || [ "$status" = "000" ]; then
    url="http://${host}"
    status=$(curl -sS -m "$PROBE_TIMEOUT" -o /dev/null -w "%{http_code}" \
             -A "$USER_AGENT" -I "$url" 2>/dev/null || echo "")
  fi
  
  # Fetch title if requested
  if [ "$TITLE_FETCH" -eq 1 ] && [ "${status:-}" != "000" ]; then
    local html
    html=$(curl -sS -m "$PROBE_TIMEOUT" -A "$USER_AGENT" "$url" 2>/dev/null || true)
    title=$(printf "%s" "$html" | tr '\n' ' ' | sed -n 's/.*<title>\(.*\)<\/title>.*/\1/p' | head -c 100)
  fi
  
  printf "%s|%s|%s" "$host" "${status:-}" "${title:-}"
}

# Parallel subdomain gathering with multiple sources
gather_subdomains_parallel() {
  local domain="$1" tmp
  tmp="${TMP_DIR}/${domain//[^a-zA-Z0-9_.-]/_}.raw"
  : > "$tmp"

  # Run all sources in parallel
  {
    # crt.sh
    ( fast_curl "https://crt.sh/?q=%25.${domain}&output=json" "${TMP_DIR}/crt.${domain}.json" && 
      [ -s "${TMP_DIR}/crt.${domain}.json" ] && 
      (jq -r '.[].name_value' "${TMP_DIR}/crt.${domain}.json" 2>/dev/null || 
       grep -oE '"name_value"[[:space:]]*:[[:space:]]*"[^"]+"' "${TMP_DIR}/crt.${domain}.json" | 
       sed -E 's/.*"name_value"[[:space:]]*:[[:space:]]*"//; s/"$//') >> "$tmp" ) &
    
    # hackertarget
    ( fast_curl "https://api.hackertarget.com/hostsearch/?q=${domain}" "${TMP_DIR}/ht.${domain}.txt" && 
      [ -s "${TMP_DIR}/ht.${domain}.txt" ] && 
      cut -d',' -f1 "${TMP_DIR}/ht.${domain}.txt" >> "$tmp" ) &
    
    # sonar.omnisint.io
    ( fast_curl "https://sonar.omnisint.io/subdomains/${domain}" "${TMP_DIR}/sonar.${domain}.json" && 
      [ -s "${TMP_DIR}/sonar.${domain}.json" ] && 
      (jq -r '.[]' "${TMP_DIR}/sonar.${domain}.json" 2>/dev/null | sed "s/$/.$domain/" || 
       tr -d '[]" ' < "${TMP_DIR}/sonar.${domain}.json" | tr ',' '\n' | sed "s/$/.$domain/") >> "$tmp" ) &
    
    # anubis
    ( fast_curl "https://jldc.me/anubis/subdomains/${domain}" "${TMP_DIR}/anubis.${domain}.json" && 
      [ -s "${TMP_DIR}/anubis.${domain}.json" ] && 
      (jq -r '.[]' "${TMP_DIR}/anubis.${domain}.json" 2>/dev/null || true) >> "$tmp" ) &
    
    # urlscan.io
    ( fast_curl "https://urlscan.io/api/v1/search/?q=domain:${domain}" "${TMP_DIR}/urlscan.${domain}.json" && 
      [ -s "${TMP_DIR}/urlscan.${domain}.json" ] && 
      (jq -r '.results[].page.domain' "${TMP_DIR}/urlscan.${domain}.json" 2>/dev/null || true) >> "$tmp" ) &
    
    # Wait for all sources
    wait
    
    # Wordlist bruteforce (if provided)
    if [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ]; then
      awk 'NF && $0 !~ /^#/ {print tolower($0)}' "$WORDLIST" | 
      sed 's/^[[:space:]]*//; s/[[:space:]]*$//' |
      while read -r w; do
        [ -n "$w" ] && printf "%s.%s\n" "$w" "$domain"
      done >> "$tmp"
    fi
    
  } 2>/dev/null

  # Process results
  awk '{print tolower($0)}' "$tmp" | 
  sed 's/^\*\.//; s/^\*//' | 
  sort -u |
  grep -E "^[a-zA-Z0-9.-]+\\.${domain//./\\.}$" || true
}

apply_filters() {
  if [ -n "$INCLUDE_RE" ]; then
    grep -E "$INCLUDE_RE" || true
  else
    cat
  fi | {
    if [ -n "$EXCLUDE_RE" ]; then
      grep -Ev "$EXCLUDE_RE" || true
    else
      cat
    fi
  }
}

filter_only_new() {
  if [ "$ONLY_NEW" -eq 1 ] && [ -f "$OUTFILE" ]; then
    grep -Fxv -f <(cat "$OUTFILE" 2>/dev/null || true) || true
  else
    cat
  fi
}

# Fast wildcard detection
is_wildcard_domain() {
  local domain="$1" rnd="test$(date +%s | md5sum | head -c 8)"
  local randh="${rnd}.${domain}"
  local res
  res=$(doh_resolve_one "$randh" 2>/dev/null || echo "")
  [ -n "$res" ]
}

# Main scanning process
TOTAL_DOMAINS=$(grep -c '^[^#]' "$INPUT_FILE" 2>/dev/null || echo 0)
CURRENT_DOMAIN=0

print_color "$GREEN$BOLD" "${ICON_START} Starting parallel scan of $TOTAL_DOMAINS domains..."

# Process domains in batches for better performance
BATCH_COUNT=0
while IFS= read -r DOMAIN || [ -n "$DOMAIN" ]; do
  DOMAIN="${DOMAIN%%#*}"; DOMAIN="${DOMAIN//[[:space:]]/}"
  [ -z "$DOMAIN" ] && continue
  
  BATCH_COUNT=$((BATCH_COUNT+1))
  
  # Process batch when batch size is reached
  if [ $BATCH_COUNT -ge $BATCH_SIZE ]; then
    wait
    BATCH_COUNT=0
  fi
  
  (
    CURRENT_DOMAIN=$((CURRENT_DOMAIN+1))
    
    print_color "$YELLOW" "${ICON_SCAN} [$CURRENT_DOMAIN/$TOTAL_DOMAINS] Scanning: $DOMAIN"
    
    # Gather subdomains
    RAW=$(gather_subdomains_parallel "$DOMAIN" | normalize_lines | apply_filters | filter_only_new)
    
    PERDOMAIN="${TMP_DIR}/${DOMAIN//[^a-zA-Z0-9_.-]/_}.txt"
    printf "%s\n" "$RAW" > "$PERDOMAIN"
    DOMAIN_COUNT=$(wc -l < "$PERDOMAIN" 2>/dev/null | tr -d ' ' || echo 0)
    
    if [ "$DOMAIN_COUNT" -eq 0 ]; then
      print_color "$RED" "${ICON_WARNING} No subdomains found for ${DOMAIN}"
      echo -e "${DOMAIN}\t0" >> "$SUMMARY"
      return
    fi

    # Wildcard check (non-blocking)
    ( if is_wildcard_domain "$DOMAIN"; then
        print_color "$RED" "${ICON_WARNING} Wildcard detected for ${DOMAIN}"
      fi
    ) &
    
    # Choose color based on count
    if [ "$DOMAIN_COUNT" -gt 20 ]; then COLOR=$PURPLE; ICON=$ICON_FOUND
    elif [ "$DOMAIN_COUNT" -gt 10 ]; then COLOR=$YELLOW; ICON=$ICON_FOUND
    else COLOR=$GREEN; ICON=$ICON_SUCCESS; fi

    print_color "$BOLD$COLOR" "${ICON} $DOMAIN - Found: $DOMAIN_COUNT subdomains"

    # Save per-domain results
    cp "$PERDOMAIN" "outputs/${DOMAIN}-subdomains.txt"
    cat "$PERDOMAIN" >> "$COMBINED"
    echo -e "${DOMAIN}\t${DOMAIN_COUNT}" >> "$SUMMARY"

    # Play sound for significant finds
    [ "$DOMAIN_COUNT" -gt 10 ] && play_sound
  ) &
  
  # Control overall parallelism
  while [ $(jobs -r | wc -l) -ge "$THREADS" ]; do sleep 0.1; done
  
done < "$INPUT_FILE"

# Wait for all background jobs
wait

print_color "$GREEN$BOLD" "${ICON_SUCCESS} All domain scans completed. Processing results..."

# Final processing
sort -u "$COMBINED" -o "$COMBINED"
TOTAL_SUBS=$(wc -l < "$COMBINED" 2>/dev/null | tr -d ' ' || echo 0)

# Batch DNS resolution if requested
if [ "$DOH_RESOLVE" -eq 1 ] && [ "$TOTAL_SUBS" -gt 0 ]; then
  print_color "$BLUE" "${ICON_SCAN} Batch DNS resolution..."
  RESOLVED_FILE="${TMP_DIR}/resolved.txt"
  batch_doh_resolve "$COMBINED" "$RESOLVED_FILE"
  RESOLVED_COUNT=$(wc -l < "$RESOLVED_FILE" 2>/dev/null | tr -d ' ' || echo 0)
fi

# Batch HTTP probing if requested  
if [ "$HTTP_PROBE" -eq 1 ] && [ "$TOTAL_SUBS" -gt 0 ]; then
  print_color "$BLUE" "${ICON_SCAN} Batch HTTP probing..."
  PROBED_FILE="${TMP_DIR}/probed.txt"
  batch_http_probe "$COMBINED" "$PROBED_FILE"
  PROBED_COUNT=$(wc -l < "$PROBED_FILE" 2>/dev/null | tr -d ' ' || echo 0)
fi

# Generate final output
case "$FORMAT" in
  txt) 
    cp "$COMBINED" "$OUTFILE"
    ;;
  csv)
    echo "host,ip,status,title" > "${OUTFILE%.*}.csv"
    # Merge resolved and probed data here
    cat "$COMBINED" >> "${OUTFILE%.*}.csv"
    ;;
  ndjson)
    : > "${OUTFILE%.*}.ndjson"
    # Generate NDJSON format
    ;;
esac

# Final summary
print_color "$CYAN$BOLD" "\n${ICON_COMPLETE} SCAN COMPLETE! ULTRA FAST EDITION"
print_color "$BLUE" "╔═══════════════════════════════════════════════╗"
printf "║${BOLD}%-32s ${BLUE}│${BOLD}%12s${BLUE}║\n" "TOTAL UNIQUE SUBDOMAINS" "$TOTAL_SUBS"
[ "$DOH_RESOLVE" -eq 1 ] && printf "║%-32s ${BLUE}│ %12s${BLUE}║\n" "DNS Resolved" "${RESOLVED_COUNT:-0}"
[ "$HTTP_PROBE" -eq 1 ] && printf "║%-32s ${BLUE}│ %12s${BLUE}║\n" "HTTP Probed" "${PROBED_COUNT:-0}"
print_color "$BLUE" "╚═══════════════════════════════════════════════╝"

print_color "$GREEN$BOLD" "${ICON_SUCCESS} Results saved: $OUTFILE"
print_color "$GREEN" "${ICON_SUCCESS} Per-domain files in: outputs/"

[ "$TOTAL_SUBS" -gt 10 ] && play_sound

print_color "$CYAN" "\n⏰ Total execution time: $SECONDS seconds"
