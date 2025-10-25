#!/usr/bin/env bash
# SubdomainFinder v0.6.1 — Pro Edition (No-API, DoH, Probe, Concurrency) — Git Bash Friendly
# Quick:
#   ./subdomainfinder3.sh -i domains.txt [-o outputs/all-subdomains.txt] [options]

set -euo pipefail
IFS=$'\n\t'

VERSION="0.6.1"

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
THREADS=10
FORMAT="txt" # txt|csv|ndjson
TITLE_FETCH=0
PROBE_TIMEOUT=5

# Colors & Icons (aman di Git Bash)
GREEN=$'\033[0;32m'; CYAN=$'\033[0;36m'; YELLOW=$'\033[1;33m'; RED=$'\033[0;31m'
PURPLE=$'\033[0;35m'; BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
ICON_SCAN="🔬"; ICON_FOUND="🎯"; ICON_WARNING="⚠️"; ICON_SUCCESS="✅"
ICON_ERROR="❌"; ICON_START="🚀"; ICON_COMPLETE="🏁"; ICON_SOUND="🔊"

print() { [ "$QUIET" -eq 0 ] && printf '%s\n' "$*"; }
print_color() { [ "$QUIET" -eq 0 ] && printf '%b\n' "$1$2$RESET"; }

play_sound() {
  [ "$SOUND_ENABLED" -ne 1 ] && return 0
  case "$(uname -s)" in
    Linux*) command -v beep >/dev/null && { beep -f 1000 -l 200 -r 2 2>/dev/null || true; } || true ;;
    Darwin*) afplay /System/Library/Sounds/Submarine.aiff 2>/dev/null || say "Subdomains found" 2>/dev/null || true ;;
    MINGW*|CYGWIN*|MSYS*) printf '\a\a' ;;
  esac
}

show_banner() {
  [ "$QUIET" -eq 1 ] && return
  clear 2>/dev/null || true
  print_color "$CYAN$BOLD" "
╔══════════════════════════════════════════════════╗
║         🚀 SUBDOMAIN FINDER v${VERSION} — Pro        ║
║    🔬 Sources | 🎯 Resolve | 🌐 Probe | 🔊 Alerts     ║
╚══════════════════════════════════════════════════╝"
}

usage() {
  cat <<EOF
Usage: $0 -i domains.txt [options]
  -i FILE         Input list domain (satu per baris)
  -o FILE         Output gabungan (default: ${OUTFILE})
  -q              Quiet mode
  --no-sound      Matikan suara
  -w WORDLIST     Bruteforce subdomain pakai wordlist
  --resolve       Validasi DNS via DoH Cloudflare (+ fallback Google)
  --http-probe    HEAD check (status); tambah --title untuk ambil <title>
  --title         Saat probe, GET singkat ambil <title>
  --threads N     Konkurensi resolve/probe (default: 10)
  --only-new      Hanya proses subdomain yang belum ada di outfile lama
  --include REGEX Filter hanya yang cocok regex ini
  --exclude REGEX Skip yang cocok regex ini
  --format FMT    txt | csv | ndjson (default: txt)
  --timeout N     Timeout detik HTTP probe (default: 5)
  -h              Help
Examples:
  $0 -i domains.txt --resolve --http-probe --threads 20 --format csv
  $0 -i domains.txt -w common.txt --include 'api|cdn' --exclude 'dev|stg'
EOF
  exit 1
}

# parse opts (long options via getopts -)
while getopts ":i:o:qw:h-:" opt; do
  case ${opt} in
    i) INPUT_FILE=$OPTARG ;;
    o) OUTFILE=$OPTARG ;;
    q) QUIET=1 ;;
    w) WORDLIST=$OPTARG ;;
    h) usage ;;
    -)
      # dukung --opt=val dan --opt val
      case "${OPTARG}" in
        no-sound) SOUND_ENABLED=0 ;;
        resolve) DOH_RESOLVE=1 ;;
        http-probe) HTTP_PROBE=1 ;;
        title) TITLE_FETCH=1 ;;
        threads=*)
          THREADS="${OPTARG#threads=}"
          ;;
        threads)
          THREADS="${!OPTIND}"; OPTIND=$((OPTIND+1))
          ;;
        only-new) ONLY_NEW=1 ;;
        include=*)
          INCLUDE_RE="${OPTARG#include=}"
          ;;
        include)
          INCLUDE_RE="${!OPTIND}"; OPTIND=$((OPTIND+1))
          ;;
        exclude=*)
          EXCLUDE_RE="${OPTARG#exclude=}"
          ;;
        exclude)
          EXCLUDE_RE="${!OPTIND}"; OPTIND=$((OPTIND+1))
          ;;
        format=*)
          FORMAT="${OPTARG#format=}"
          ;;
        format)
          FORMAT="${!OPTIND}"; OPTIND=$((OPTIND+1))
          ;;
        timeout=*)
          PROBE_TIMEOUT="${OPTARG#timeout=}"
          ;;
        timeout)
          PROBE_TIMEOUT="${!OPTIND}"; OPTIND=$((OPTIND+1))
          ;;
        *)
          echo "Invalid option: --${OPTARG}" >&2; usage ;;
      esac
      ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage ;;
    :)  echo "Option -$OPTARG requires an argument." >&2; usage ;;
  esac
done
shift $((OPTIND -1))


[ -z "$INPUT_FILE" ] && echo "Please specify -i domains.txt" >&2 && usage
[ ! -f "$INPUT_FILE" ] && echo "Input file $INPUT_FILE not found!" >&2 && exit 1
mkdir -p "$(dirname "$OUTFILE")" outputs

TMP_DIR=$(mktemp -d -t subfinder3.XXXXXX 2>/dev/null || mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
SUMMARY="${TMP_DIR}/summary.tsv"; : > "$SUMMARY"
COMBINED="${TMP_DIR}/combined.txt"; : > "$COMBINED"

show_banner
print_color "$BLUE" "📅 $(date -u +'%Y-%m-%dT%H:%M:%SZ')  🔊 Sound: $([ $SOUND_ENABLED -eq 1 ] && echo ENABLED || echo DISABLED)"
print_color "$BLUE" "🔧 Resolve: $([ $DOH_RESOLVE -eq 1 ] && echo DoH || echo OFF)  🌐 Probe: $([ $HTTP_PROBE -eq 1 ] && echo ON || echo OFF), Threads: ${THREADS}"
[ -n "$WORDLIST" ] && print_color "$BLUE" "🧩 Wordlist: $WORDLIST"
[ -n "$INCLUDE_RE" ] && print_color "$BLUE" "🔎 Include: $INCLUDE_RE"
[ -n "$EXCLUDE_RE" ] && print_color "$BLUE" "🚫 Exclude: $EXCLUDE_RE"
print ""

normalize_lines() {
  awk 'NF && $0 !~ /^#/' |
  awk '{print tolower($0)}' |
  sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^\*\.//; s/^\*//' |
  sort -u
}

# === PATCH: Accept header + --compressed + silence stderr ===
curl_json() {
  # $1=url  $2=outfile
  local url="$1" out="$2" tries=3 delay=1
  : > "$out"
  for _ in 1 2 3; do
    if curl -sS -f -L --connect-timeout 7 --max-time 20 \
         -A "$USER_AGENT" \
         -H 'Accept: application/json, application/dns-json;q=0.9, */*;q=0.1' \
         --compressed \
         "$url" -o "$out" 2>/dev/null; then
      [ -s "$out" ] && return 0
    fi
    sleep "$delay"; delay=$((delay*2))
  done
  return 1
}

rand_str() {
  local t="$(date +%s)$$RANDOM"
  echo "zz$(echo "$t" | md5sum 2>/dev/null | awk '{print $1}' 2>/dev/null || echo "$t")" | cut -c1-8
}

# === PATCH: DoH fallback ke Google jika Cloudflare gagal/400 ===
doh_resolve_one() {
  local host="$1" out ip cname ok=0
  out="${TMP_DIR}/doh.$RANDOM.json"

  # Cloudflare A
  if curl_json "https://cloudflare-dns.com/dns-query?name=${host}&type=A" "$out"; then
    ok=1
  fi
  if [ $ok -eq 1 ]; then
    if command -v jq >/dev/null 2>&1; then
      ip=$(jq -r '.Answer?[]?|select(.type==1)|.data' "$out" 2>/dev/null | head -n1 || true)
    else
      ip=$(grep -oE '"data":"[0-9.]+"' "$out" | sed -E 's/.*"data":"//; s/".*//' | head -n1 || true)
    fi
  fi

  # Cloudflare AAAA bila A kosong
  if [ -z "${ip:-}" ] && [ $ok -eq 1 ]; then
    if curl_json "https://cloudflare-dns.com/dns-query?name=${host}&type=AAAA" "$out"; then
      if command -v jq >/dev/null 2>&1; then
        ip=$(jq -r '.Answer?[]?|select(.type==28)|.data' "$out" 2>/dev/null | head -n1 || true)
      else
        ip=$(grep -oE '"data":"[0-9a-fA-F:]{2,}"' "$out" | sed -E 's/.*"data":"//; s/".*//' | head -n1 || true)
      fi
    fi
  fi

  # Cloudflare CNAME
  if [ -z "${ip:-}" ]; then
    if curl_json "https://cloudflare-dns.com/dns-query?name=${host}&type=CNAME" "$out"; then
      if command -v jq >/dev/null 2>&1; then
        cname=$(jq -r '.Answer?[]?|select(.type==5)|.data' "$out" 2>/dev/null | head -n1 || true)
      else
        cname=$(grep -oE '"data":"[^"]+"' "$out" | sed -E 's/.*"data":"//; s/".*//' | head -n1 || true)
      fi
    fi
  fi

  # Fallback Google DoH
  if [ -z "${ip:-}" ] && [ -z "${cname:-}" ]; then
    if curl_json "https://dns.google/resolve?name=${host}&type=A" "$out"; then
      if command -v jq >/dev/null 2>&1; then
        ip=$(jq -r '.Answer?[]?|select(.type==1)|.data' "$out" 2>/dev/null | head -n1 || true)
      else
        ip=$(grep -oE '"data":"[0-9.]+"' "$out" | sed -E 's/.*"data":"//; s/".*//' | head -n1 || true)
      fi
    fi
    if [ -z "${ip:-}" ]; then
      if curl_json "https://dns.google/resolve?name=${host}&type=CNAME" "$out"; then
        if command -v jq >/dev/null 2>&1; then
          cname=$(jq -r '.Answer?[]?|select(.type==5)|.data' "$out" 2>/dev/null | head -n1 || true)
        else
          cname=$(grep -oE '"data":"[^"]+"' "$out" | sed -E 's/.*"data":"//; s/".*//' | head -n1 || true)
        fi
      fi
    fi
  fi

  if [ -n "${ip:-}" ]; then
    printf "%s" "$ip"
  elif [ -n "${cname:-}" ]; then
    printf "%s" "$cname"
  else
    printf ""
  fi
}

is_wildcard_domain() {
  local domain="$1" rnd="$(rand_str)"
  local randh="${rnd}.${domain}"
  local res
  res=$(doh_resolve_one "$randh" || echo "")
  [ -n "$res" ]
}

http_probe_one() {
  local host="$1" url status title=""
  url="http://${host}"
  status=$(curl -sS -m "$PROBE_TIMEOUT" -o /dev/null -w "%{http_code}" -A "$USER_AGENT" -I "$url" 2>/dev/null || echo "")
  if [ -z "$status" ] || [ "$status" = "000" ]; then
    url="https://${host}"
    status=$(curl -sS -m "$PROBE_TIMEOUT" -o /dev/null -w "%{http_code}" -A "$USER_AGENT" -I "$url" 2>/dev/null || echo "")
  fi
  if [ "$TITLE_FETCH" -eq 1 ]; then
    local html
    html=$(curl -sS -m "$PROBE_TIMEOUT" -A "$USER_AGENT" "$url" 2>/dev/null || true)
    title=$(printf "%s" "$html" | tr '\n' ' ' | sed -n 's/.*<title>\(.*\)<\/title>.*/\1/p' | head -c 180 || true)
  fi
  printf "%s|%s|%s" "$host" "${status:-}" "${title:-}"
}

gather_subdomains_for() {
  local domain="$1" tmp
  tmp="${TMP_DIR}/${domain//[^a-zA-Z0-9_.-]/_}.raw"
  : > "$tmp"

  # === PATCH: crt.sh pakai --get + --data-urlencode (lebih stabil dari %25.) ===
  curl -sS -f -L -A "$USER_AGENT" --connect-timeout 7 --max-time 20 \
    --get --data-urlencode "q=%.${domain}" --data-urlencode "output=json" \
    "https://crt.sh/" -o "${TMP_DIR}/crt.$domain.json" 2>/dev/null || true
  if [ -s "${TMP_DIR}/crt.$domain.json" ]; then
    if command -v jq >/dev/null 2>&1; then
      jq -r '.[].name_value' "${TMP_DIR}/crt.$domain.json" 2>/dev/null >> "$tmp" || true
    else
      grep -oE '"name_value"\s*:\s*"[^"]*"' "${TMP_DIR}/crt.$domain.json" | sed -E 's/.*"name_value"\s*:\s*"//; s/"$//' >> "$tmp" || true
    fi
  fi

  # hackertarget
  curl -fsSL -A "$USER_AGENT" --connect-timeout 7 --max-time 20 \
    "https://api.hackertarget.com/hostsearch/?q=${domain}" -o "${TMP_DIR}/ht.$domain.txt" 2>/dev/null || true
  [ -s "${TMP_DIR}/ht.$domain.txt" ] && cut -d',' -f1 "${TMP_DIR}/ht.$domain.txt" >> "$tmp" || true

  # sonar.omnisint.io
  curl -fsSL -A "$USER_AGENT" --connect-timeout 7 --max-time 20 \
    "https://sonar.omnisint.io/subdomains/${domain}" -o "${TMP_DIR}/sonar.$domain.json" 2>/dev/null || true
  if [ -s "${TMP_DIR}/sonar.$domain.json" ]; then
    if command -v jq >/dev/null 2>&1; then
      jq -r '.[]' "${TMP_DIR}/sonar.$domain.json" 2>/dev/null | sed "s/$/.$domain/" >> "$tmp" || true
    else
      tr -d '[]" ' < "${TMP_DIR}/sonar.$domain.json" | tr ',' '\n' | sed "s/$/.$domain/" >> "$tmp" || true
    fi
  fi

  # rapiddns (best-effort)
  curl -fsSL -A "$USER_AGENT" --connect-timeout 7 --max-time 20 \
    "https://rapiddns.io/subdomain/${domain}?full=1" -o "${TMP_DIR}/rapid.$domain.html" 2>/dev/null || true
  if [ -s "${TMP_DIR}/rapid.$domain.html" ]; then
    grep -Eo "([a-zA-Z0-9_-]+\.)+${domain}" "${TMP_DIR}/rapid.$domain.html" | sort -u >> "$tmp" || true
  fi

  # wordlist
  if [ -n "$WORDLIST" ] && [ -f "$WORDLIST" ]; then
    awk 'NF && $0 !~ /^#/' "$WORDLIST" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | while read -r w; do
      [ -n "$w" ] && printf "%s.%s\n" "$w" "$domain"
    done >> "$tmp"
  fi

  awk '{print tolower($0)}' "$tmp" | sed 's/^\*\.//; s/^\*//' | sort -u
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

TOTAL_DOMAINS=$(grep -c '^[^#]' "$INPUT_FILE" 2>/dev/null || echo 0)
CURRENT_DOMAIN=0

: > "$COMBINED"

while IFS= read -r DOMAIN || [ -n "$DOMAIN" ]; do
  DOMAIN="${DOMAIN%%#*}"; DOMAIN="${DOMAIN//[[:space:]]/}"
  [ -z "$DOMAIN" ] && continue
  CURRENT_DOMAIN=$((CURRENT_DOMAIN+1))

  print_color "$YELLOW$BOLD" "\n${ICON_SCAN} ${DOMAIN}  ($CURRENT_DOMAIN/$TOTAL_DOMAINS)"

  RAW=$(gather_subdomains_for "$DOMAIN" | normalize_lines | apply_filters | filter_only_new || true)

  if is_wildcard_domain "$DOMAIN"; then
    print_color "$RED" "${ICON_WARNING} DNS wildcard terdeteksi di ${DOMAIN} (hasil mungkin noisy)."
  fi

  PERDOMAIN="${TMP_DIR}/${DOMAIN//[^a-zA-Z0-9_.-]/_}.txt"
  printf "%s\n" "$RAW" > "$PERDOMAIN"
  DOMAIN_COUNT=$(wc -l < "$PERDOMAIN" | tr -d ' ')

  if [ "$DOMAIN_COUNT" -eq 0 ]; then
    print_color "$RED" "${ICON_WARNING} Tidak ada subdomain ditemukan untuk ${DOMAIN}"
    echo -e "${DOMAIN}\t0" >> "$SUMMARY"
    continue
  fi

  if [ "$DOMAIN_COUNT" -gt 10 ]; then COLOR=$PURPLE; ICON=$ICON_FOUND
  elif [ "$DOMAIN_COUNT" -gt 5 ]; then COLOR=$YELLOW; ICON=$ICON_FOUND
  else COLOR=$GREEN; ICON=$ICON_SUCCESS; fi

  print_color "$BOLD$COLOR" "
╔═══════════════════════════════════════════════╗
║  $ICON $DOMAIN - Found: $DOMAIN_COUNT subdomains $ICON  ║
╚═══════════════════════════════════════════════╝"

  RESOLVED="${TMP_DIR}/${DOMAIN}.resolved.tsv"; : > "$RESOLVED"

  if [ "$DOH_RESOLVE" -eq 1 ] || [ "$HTTP_PROBE" -eq 1 ]; then
    sem_jobs=0
    while IFS= read -r host || [ -n "$host" ]; do
      [ -z "$host" ] && continue
      (
        ip_or_cname=""
        status=""
        title=""
        if [ "$DOH_RESOLVE" -eq 1 ]; then
          ip_or_cname=$(doh_resolve_one "$host" || true)
        fi
        if [ "$HTTP_PROBE" -eq 1 ]; then
          IFS='|' read -r _h status title <<<"$(http_probe_one "$host")"
        fi
        printf "%s\t%s\t%s\t%s\n" "$host" "${ip_or_cname:-}" "${status:-}" "${title:-}" >> "$RESOLVED"
      ) &

      sem_jobs=$((sem_jobs+1))
      if [ "$sem_jobs" -ge "$THREADS" ]; then
        wait -n 2>/dev/null || wait || true
        sem_jobs=$((sem_jobs-1))
      fi
    done < "$PERDOMAIN"
    wait || true
  else
    awk '{printf "%s\t\t\t\n",$0}' "$PERDOMAIN" > "$RESOLVED"
  fi

  nl -ba -w2 -s'. ' "$PERDOMAIN" | while IFS= read -r line; do
    print_color "$CYAN" "   $line"
  done

  cp "$PERDOMAIN" "outputs/${DOMAIN}-subdomains.txt"
  cat "$PERDOMAIN" >> "$COMBINED"
  echo -e "${DOMAIN}\t${DOMAIN_COUNT}" >> "$SUMMARY"

  case "$FORMAT" in
    txt) : ;;
    csv)
      {
        echo "host,addr_or_cname,status,title"
        awk -F'\t' 'BEGIN{OFS=","} {gsub(/"/,"\"",$4); print $1,$2,$3,"\"" $4 "\""}' "$RESOLVED"
      } > "outputs/${DOMAIN}-subdomains.csv"
      ;;
    ndjson)
      {
        while IFS=$'\t' read -r h a s t; do
          tt=$(printf '%s' "$t" | sed 's/\\/\\\\/g; s/"/\\"/g')
          printf '{"host":"%s","addr_or_cname":"%s","status":"%s","title":"%s"}\n' "$h" "$a" "$s" "$tt"
        done < "$RESOLVED"
      } > "outputs/${DOMAIN}-subdomains.ndjson"
      ;;
  esac

  [ "$DOMAIN_COUNT" -gt 5 ] && play_sound || true
done < "$INPUT_FILE"

sort -u "$COMBINED" -o "$COMBINED"
case "$FORMAT" in
  txt) cp "$COMBINED" "$OUTFILE" ;;
  csv)
    ALLCSV="${TMP_DIR}/all.csv"; echo "host,addr_or_cname,status,title" > "$ALLCSV"
    for f in outputs/*-subdomains.csv; do [ -f "$f" ] && tail -n +2 "$f" >> "$ALLCSV" || true; done
    cp "$ALLCSV" "${OUTFILE%.*}.csv"
    ;;
  ndjson)
    ALLND="${TMP_DIR}/all.ndjson"; : > "$ALLND"
    for f in outputs/*-subdomains.ndjson; do [ -f "$f" ] && cat "$f" >> "$ALLND" || true; done
    cp "$ALLND" "${OUTFILE%.*}.ndjson"
    ;;
esac

TOTAL_SUBS=$(wc -l < "$COMBINED" | tr -d ' ')
VALID_A=0; S2xx=0; S3xx=0; S4xx=0; S5xx=0
if [ "$DOH_RESOLVE" -eq 1 ] || [ "$HTTP_PROBE" -eq 1 ]; then
  ALLRES="${TMP_DIR}/all.res.tsv"; : > "$ALLRES"
  for f in "${TMP_DIR}"/*.resolved.tsv; do [ -f "$f" ] && cat "$f" >> "$ALLRES" || true; done
  VALID_A=$(awk -F'\t' 'length($2)>0{c++} END{print c+0}' "$ALLRES" 2>/dev/null || echo 0)
  S2xx=$(awk -F'\t' '$3 ~ /^2[0-9][0-9]$/{c++} END{print c+0}' "$ALLRES" 2>/dev/null || echo 0)
  S3xx=$(awk -F'\t' '$3 ~ /^3[0-9][0-9]$/{c++} END{print c+0}' "$ALLRES" 2>/dev/null || echo 0)
  S4xx=$(awk -F'\t' '$3 ~ /^4[0-9][0-9]$/{c++} END{print c+0}' "$ALLRES" 2>/dev/null || echo 0)
  S5xx=$(awk -F'\t' '$3 ~ /^5[0-9][0-9]$/{c++} END{print c+0}' "$ALLRES" 2>/dev/null || echo 0)
fi

print_color "$CYAN$BOLD" "\n${ICON_COMPLETE} SCAN COMPLETE! SUMMARY"
print_color "$BLUE" "╔═══════════════════════════════════════════════╗"
printf "║${BOLD}%-32s ${BLUE}│${BOLD}%12s${BLUE}║\n" "TOTAL UNIQUE SUBDOMAINS" "$TOTAL_SUBS"
[ "$DOH_RESOLVE" -eq 1 ] && printf "║%-32s ${BLUE}│ %12s${BLUE}║\n" "Resolved (A/AAAA/CNAME)" "$VALID_A"
[ "$HTTP_PROBE" -eq 1 ] && {
  printf "║%-32s ${BLUE}│ %12s${BLUE}║\n" "HTTP 2xx" "$S2xx"
  printf "║%-32s ${BLUE}│ %12s${BLUE}║\n" "HTTP 3xx" "$S3xx"
  printf "║%-32s ${BLUE}│ %12s${BLUE}║\n" "HTTP 4xx" "$S4xx"
  printf "║%-32s ${BLUE}│ %12s${BLUE}║\n" "HTTP 5xx" "$S5xx"
}
print_color "$BLUE" "╚═══════════════════════════════════════════════╝"

case "$FORMAT" in
  txt) print_color "$GREEN$BOLD" "${ICON_SUCCESS} Results saved: $PWD/$OUTFILE" ;;
  csv) print_color "$GREEN$BOLD" "${ICON_SUCCESS} Results saved: $PWD/${OUTFILE%.*}.csv" ;;
  ndjson) print_color "$GREEN$BOLD" "${ICON_SUCCESS} Results saved: $PWD/${OUTFILE%.*}.ndjson" ;;
esac
print_color "$GREEN" "${ICON_SUCCESS} Per-domain files in: outputs/"
[ "$TOTAL_SUBS" -gt 20 ] && play_sound || true
