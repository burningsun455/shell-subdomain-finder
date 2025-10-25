#!/usr/bin/env bash
# SubdomainFinder v2.0 — THEMEABLE (dark | monochrome | deepblue)
# One-file bash. Hard deps: curl. Optional: jq, idn2, gobuster, nc
# Use: ./neonfinder.sh -i domains.txt [options]

set -euo pipefail
IFS=$'\n\t'

VERSION="2.0"

# ---------- defaults ----------
INPUT_FILE=""
OUTFILE="outputs/all-subdomains.txt"
QUIET=0
SOUND=1
THREADS=12
FORMAT="txt"        # txt|csv|jsonl
WORDLIST=""
ACTIVE=0            # use gobuster if available
DOH=1               # DNS over HTTPS verify
PROBE=1             # HTTP probe by default
TITLE=1             # fetch <title> when probing
GROUP_IPS=1
PORTS=""            # e.g. "80,443,8080,8443"
TAKEOVER=1
TIMEOUT=4
SCHEME="https"
FILTER_WILDCARD=1
ONLY_NEW=0
THEME="dark"        # default theme: dark (original)

UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119 Safari/537.36"

# ---------- theme loader (monochrome / deepblue / dark matrix) ----------
# Call load_theme "$THEME" after arg parsing (before hud_header)
load_theme(){
  case "$1" in
    monochrome|mono)
      B=$'\033[1m'; R=$'\033[0m'
      BG_BLACK=$'\033[48;5;232m'    # dark background (works on dark terminals)
      FG_WHITE=$'\033[38;5;15m'     # white
      FG_BLACK=$'\033[38;5;232m'    # black-like text
      FG_GRAY=$'\033[38;5;244m'     # neutral gray
      FG_DARK_GRAY=$'\033[38;5;240m'

      BLUE_DARK=$FG_BLACK
      BLUE_NEON=$FG_WHITE
      BLUE_LIGHT=$FG_GRAY
      GREEN_NEON=$FG_WHITE
      RED_NEON=$FG_BLACK
      YELLOW_NEON=$FG_GRAY
      PURPLE_NEON=$FG_GRAY

      ic_scan="[*]"; ic_go="[>]"; ic_ok="[OK]"; ic_warn="[!]"
      ic_end="[END]"; ic_ip="[IP]"; ic_port="[P]"; ic_take="[TK]"
      ;;
    deepblue|blue)
      B=$'\033[1m'; R=$'\033[0m'
      BG_BLACK=$'\033[48;5;17m'   # near-black blue background (dark navy)
      FG_WHITE=$'\033[38;5;255m'  # bright white
      FG_GRAY=$'\033[38;5;250m'   # pale gray
      FG_DARK_GRAY=$'\033[38;5;238m'

      BLUE_DARK=$'\033[38;5;17m'   # deep navy
      BLUE_NEON=$'\033[38;5;20m'   # dark blue accent
      BLUE_LIGHT=$'\033[38;5;39m'  # brighter blue for highlights
      GREEN_NEON=$'\033[38;5;37m'  # teal-ish for ok
      RED_NEON=$'\033[38;5;196m'
      YELLOW_NEON=$'\033[38;5;220m'
      PURPLE_NEON=$'\033[38;5;99m'

      ic_scan="🔎"; ic_go="🚀"; ic_ok="✅"; ic_warn="⚠️"
      ic_end="🏁"; ic_ip="🔗"; ic_port="🔌"; ic_take="🎯"
      ;;
    dark|matrix|*)
      # original "DARK MATRIX" theme (default)
      B=$'\033[1m'; R=$'\033[0m'
      BG_BLACK=$'\033[48;5;232m'  # Dark background
      FG_WHITE=$'\033[38;5;255m'  # Bright white
      FG_GRAY=$'\033[38;5;245m'   # Light gray
      FG_DARK_GRAY=$'\033[38;5;240m' # Dark gray
      BLUE_DARK=$'\033[38;5;20m'  # Dark blue
      BLUE_NEON=$'\033[38;5;27m'  # Bright blue
      BLUE_LIGHT=$'\033[38;5;39m' # Light blue
      GREEN_NEON=$'\033[38;5;46m' # Matrix green
      RED_NEON=$'\033[38;5;196m'  # Bright red
      YELLOW_NEON=$'\033[38;5;226m' # Yellow
      PURPLE_NEON=$'\033[38;5;129m' # Purple

      ic_scan="🛰️"; ic_go="🚀"; ic_ok="✅"; ic_warn="⚠️"
      ic_end="🏁"; ic_ip="🔗"; ic_port="🔌"; ic_take="🎯"
      ;;
  esac
}

# load default theme now (in case we reference theme variables before arg parse completion)
load_theme "$THEME"

# ---------- small output helpers ----------
prt(){ [ "$QUIET" -eq 0 ] && printf '%s\n' "$*"; }
pcol(){ [ "$QUIET" -eq 0 ] && printf '%b%b%s%b%s%b\n' "$BG_BLACK" "$1" "$2" "$R" "$BG_BLACK" "$R"; }
pinl(){ [ "$QUIET" -eq 0 ] && printf '\r%b%b%s%b%s%b' "$BG_BLACK" "$1" "$2" "$R" "$BG_BLACK" "$R"; }
has(){ command -v "$1" >/dev/null 2>&1; }
bell(){ [ "$SOUND" -eq 1 ] && printf '\a' 2>/dev/null || true; }

usage(){
cat <<EOF
Usage: $0 -i domains.txt [options]
  -i FILE           Input domains (one per line)
  -o FILE           Output file (default: outputs/all-subdomains.txt)
  -q                Quiet
  --no-sound        Disable bell
  --threads N       Concurrency (default: 12; on Windows capped ~15)
  --format F        txt|csv|jsonl (default: txt)
  -w WORDLIST       Wordlist for bruteforce (requires --active to use gobuster if present)
  --active          Enable active bruteforce (gobuster required)
  --no-probe        Disable HTTP probing
  --no-title        Do not fetch <title> when probing
  --no-doh          Disable DoH verification
  --group-ips       Group subdomains by resolved IP (default on)
  --ports LIST      Port scan light, e.g. "80,443,8080,8443"
  --no-takeover     Disable takeover heuristic
  --scheme S        http|https (default: https)
  --timeout S       Curl/probe timeout (default: 4)
  --only-new        Skip results already in OUTFILE
  --theme NAME      Theme to use: dark (default), monochrome|mono, deepblue|blue
  -h                Help
EOF
exit 1; }

# --------- arg parse (support long) ----------
while getopts ":i:o:w:qh-:" o; do
  case "$o" in
    i) INPUT_FILE="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    w) WORDLIST="$OPTARG" ;;
    q) QUIET=1 ;;
    h) usage ;;
    -)
      case "${OPTARG}" in
        no-sound) SOUND=0 ;;
        threads=*) THREADS="${OPTARG#threads=}" ;;
        format=*)  FORMAT="${OPTARG#format=}" ;;
        active)    ACTIVE=1 ;;
        no-probe)  PROBE=0 ;;
        no-title)  TITLE=0 ;;
        no-doh)    DOH=0 ;;
        group-ips) GROUP_IPS=1 ;;
        ports=*)   PORTS="${OPTARG#ports=}" ;;
        no-takeover) TAKEOVER=0 ;;
        scheme=*)  SCHEME="${OPTARG#scheme=}" ;;
        timeout=*) TIMEOUT="${OPTARG#timeout=}" ;;
        only-new)  ONLY_NEW=1 ;;
        theme=*)   THEME="${OPTARG#theme=}" ;;
        *) usage ;;
      esac
      ;;
    *) usage ;;
  esac
done
shift $((OPTIND-1))

[ -z "${INPUT_FILE:-}" ] && usage
[ ! -f "$INPUT_FILE" ] && { echo "Input not found: $INPUT_FILE" >&2; exit 1; }

# reload theme after parsing (in case user supplied --theme)
load_theme "$THEME"

mkdir -p "$(dirname "$OUTFILE")" outputs
TMP=$(mktemp -d -t neon-XXXXXX 2>/dev/null || mktemp -d)
trap 'rm -rf "$TMP" 2>/dev/null || true' EXIT INT
COMB="$TMP/combined.txt"; :> "$COMB"
SUM="$TMP/summary.tsv"; :> "$SUM"
KNOWN="$TMP/known.txt"; :> "$KNOWN"

# limit threads on Windows
case "$OSTYPE" in msys*|cygwin*) [ "$THREADS" -gt 15 ] && THREADS=15 ;; esac

# load old results for only-new
if [ "$ONLY_NEW" -eq 1 ] && [ -f "$OUTFILE" ]; then
  awk 'NF{print tolower($0)}' "$OUTFILE" | sort -u > "$KNOWN" || true
fi

# --------- helpers ----------
scurl(){ # url [maxtime]
  local u="$1" t="${2:-10}"
  curl -sS --max-time "$t" --connect-timeout 5 \
    -H "User-Agent: $UA" -H "Accept: application/json, text/html;q=0.8, */*;q=0.5" \
    --compressed --retry 2 --retry-delay 1 --retry-connrefused "$u" 2>/dev/null || echo ""
}

jsonl(){ if has jq; then jq -r '.[]?' 2>/dev/null || true; else grep -oE '"[^"]+"' | sed 's/^"//; s/"$//' || true; fi; }

norm_domain(){
  local d="$1"; d="${d%%#*}"; d="${d//[$'\t\r\n ']/}"
  [ -z "$d" ] && return 0
  if has idn2; then idn2 -a --quiet "$d" 2>/dev/null || echo "$d"; else echo "$d"; fi
}

doh(){
  [ "$DOH" -ne 1 ] && { echo OK; return 0; }
  local h="$1" cf gg
  cf="$(curl -sS -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query' --get --data-urlencode "name=$h" --data-urlencode "type=A" --max-time 4 --connect-timeout 3 || true)"
  if echo "$cf" | grep -q '"Status":0'; then echo OK; return 0; fi
  gg="$(curl -sS 'https://dns.google/resolve' --get --data-urlencode "name=$h" --data-urlencode "type=A" --max-time 4 --connect-timeout 3 || true)"
  if echo "$gg" | grep -q '"Status":0'; then echo OK; return 0; fi
  return 1
}

rand8(){ tr -dc 'a-z0-9' </dev/urandom | head -c8; }

detect_wild(){
  local d="$1" a b; a="$(rand8).$d"; b="$(rand8).$d"
  doh "$a" >/dev/null 2>&1 && doh "$b" >/dev/null 2>&1 && echo WILD || echo NOWILD
}

probe(){
  [ "$PROBE" -ne 1 ] && { echo "|"; return 0; }
  local h="$1" url="${SCHEME}://${h}/" code t=""
  code="$(curl -sSI -m "$TIMEOUT" --connect-timeout "$TIMEOUT" -A "$UA" "$url" | awk 'tolower($1)~/^http/{print $2; exit}')"
  if [ -n "$code" ] && [ "$TITLE" -eq 1 ]; then
    t="$(curl -s -m "$TIMEOUT" --connect-timeout "$TIMEOUT" -A "$UA" "$url" | tr '\n' ' ' | sed -n 's/.*<title>[[:space:]]*\(.*\)[[:space:]]*<\/title>.*/\1/p' | head -c 200)"
  fi
  echo "${code}|${t}"
}

# Fungsi escape JSON yang diperbaiki
escape_json() {
    local str="$1"
    # Escape backslashes, quotes, dan karakter kontrol
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\t'/\\t}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    echo "$str"
}

save(){
  local host="$1" src="$2" code="${3:-}" title="${4:-}"
  case "$FORMAT" in
    txt)   echo "$host" >> "$COMB" ;;
    csv)   printf '%s,%s,%s,"%s"\n' "$host" "$src" "$code" "$title" >> "$COMB" ;;
    jsonl)
      local escaped_title
      escaped_title=$(escape_json "$title")
      printf '{"host":"%s","source":"%s","status":"%s","title":"%s"}\n' \
        "$host" "$src" "$code" "$escaped_title" >> "$COMB" ;;
    *) echo "$host" >> "$COMB" ;;
  esac
}

print_hit(){
  local src="$1" host="$2"
  local color="$BLUE_LIGHT" icon="🛰️"
  case "$src" in
    crt.sh) color="$GREEN_NEON"; icon="📜" ;;
    bufferover) color="$BLUE_LIGHT"; icon="🌀" ;;
    rapiddns) color="$YELLOW_NEON"; icon="⚡" ;;
    wayback) color="$FG_GRAY"; icon="🏛️" ;;
    sonar) color="$PURPLE_NEON"; icon="📡" ;;
    anubis) color="$BLUE_LIGHT"; icon="🐍" ;;
    hackertarget) color="$GREEN_NEON"; icon="🎯" ;;
    certspotter) color="$PURPLE_NEON"; icon="🔐" ;;
    urlscan) color="$YELLOW_NEON"; icon="🌐" ;;
    wordlist) color="$PURPLE_NEON"; icon="📋" ;;
  esac
  pcol "$color" "$icon [$src] $host"
}

# ---------- passive sources ----------
s_crt(){ local d="$1"
  local data; data="$(scurl "https://crt.sh/?q=%25.$d&output=json" 15)"
  [ -n "$data" ] || return 0
  if has jq; then echo "$data" | jq -r '.[].name_value' | tr '\r' '\n'
  else echo "$data" | grep -oE '"name_value":"[^"]+"' | sed 's/"name_value":"//;s/"$//' | tr '\r' '\n'; fi \
  | sed 's/^\*\.//' | awk -v s="crt.sh" 'NF{print s "|" $0}'
}

s_buff(){ local d="$1"
  scurl "https://dns.bufferover.run/dns?q=.$d" 12 | grep -oE "[a-zA-Z0-9._-]+\.$d" \
  | awk -v s="bufferover" 'NF{print s "|" $0}'
}
s_rapid(){ local d="$1"
  scurl "https://rapiddns.io/subdomain/$d?full=1" 12 | grep -oE ">[a-zA-Z0-9._-]+\.$d<" | sed 's/[<>]//g' \
  | awk -v s="rapiddns" 'NF{print s "|" $0}'
}
s_wayback(){ local d="$1"
  scurl "http://web.archive.org/cdx/search/cdx?url=*.$d/*&output=text&fl=original&collapse=urlkey" 18 \
  | sed -e 's_https\?://__' -e 's/\/.*//' -e 's/:.*//' | sort -u \
  | awk -v s="wayback" 'NF{print s "|" $0}'
}
s_sonar(){ local d="$1"
  scurl "https://sonar.omnisint.io/subdomains/$d" 12 | jsonl | awk -v s="sonar" 'NF{print s "|" $0}'
}
s_anubis(){ local d="$1"
  scurl "https://jldc.me/anubis/subdomains/$d" 12 | jsonl | awk -v s="anubis" 'NF{print s "|" $0}'
}
s_hacker(){ local d="$1"
  scurl "https://api.hackertarget.com/hostsearch/?q=$d" 12 | cut -d',' -f1 \
  | awk -v s="hackertarget" 'NF{print s "|" $0}'
}
s_certspot(){ local d="$1"
  scurl "https://api.certspotter.com/v1/issuances?domain=$d&include_subdomains=true&expand=dns_names&match_wildcards=true" 15 \
  | (has jq && jq -r '.[].dns_names[]?' || grep -oE '"dns_names":\[[^]]+\]' | tr ',' '\n' | grep -oE '"[^"]+"' | tr -d '"') \
  | sed 's/^\*\.//' | awk -v s="certspotter" 'NF{print s "|" $0}'
}
s_urlscan(){ local d="$1"
  scurl "https://urlscan.io/api/v1/search/?q=domain:$d" 12 \
  | (has jq && jq -r '.results[].page.domain' || grep -oE '"domain":"[^"]+"' | sed 's/"domain":"//;s/"//g') \
  | awk -v s="urlscan" 'NF{print s "|" $0}'
}

# ---------- active (gobuster) ----------
s_active(){
  local d="$1"
  [ "$ACTIVE" -ne 1 ] && return 0
  has gobuster || return 0
  [ -f "$WORDLIST" ] || return 0
  # wildcard aware gobuster (dns) - silent output host only
  gobuster dns -d "$d" -w "$WORDLIST" -q 2>/dev/null \
    | awk '{print $1}' | awk -v s="wordlist" 'NF{print s "|" $0}'
}

# ---------- takeover heuristic ----------
takeover_check(){
  [ "$TAKEOVER" -ne 1 ] && return 0
  local host="$1" cname
  cname="$(dig +short CNAME "$host" 2>/dev/null | tr -d '\r' | head -n1 || true)"
  [ -z "$cname" ] && return 0
  local msg=""
  case "$cname" in
    *.github.io.|*.githubusercontent.com.) msg="possible GitHub Pages takeover" ;;
    *.herokuapp.com.) msg="possible Heroku app takeover" ;;
    *.cloudfront.net.) msg="check CloudFront (S3/origin) mapping" ;;
    *.fastly.net.) msg="check Fastly service not found" ;;
    *.shopify.com.) msg="check Shopify not claimed" ;;
    *.wpengine.com.) msg="check WPEngine mapping" ;;
    *.azurewebsites.net.|*.trafficmanager.net.) msg="check Azure app/traffic manager" ;;
    *.amazonaws.com.) msg="check S3 bucket or ALB mapping" ;;
  esac
  [ -n "$msg" ] && pcol "$YELLOW_NEON" "$ic_take takeover hint: $host → $cname ($msg)"
}

# ---------- IP grouping & port scan ----------
resolve_ip(){
  local h="$1"
  getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | head -n1 \
   || dig +short A "$h" 2>/dev/null | head -n1 || true
}
scan_ports(){
  local ip="$1" plist="$2"
  [ -z "$plist" ] && return 0
  local p; for p in $(echo "$plist" | tr ',' ' '); do
    if has nc; then
      nc -z -w1 "$ip" "$p" >/dev/null 2>&1 || continue
    else
      # /dev/tcp fallback (may not be available everywhere)
      (echo >/dev/tcp/"$ip"/"$p") >/dev/null 2>&1 || continue
    fi
    pcol "$YELLOW_NEON" "$ic_port $ip:$p open"
  done
}

# ---------- semaphore ----------
sem_init(){ FIFO="$TMP/sem.fifo"; mkfifo "$FIFO"; exec 9<>"$FIFO"; rm -f "$FIFO"; for _ in $(seq 1 "$THREADS"); do echo >&9; done; }
sem_wait(){ read -r -u 9 _; }
sem_post(){ printf . >&9; }

# ---------- HUD ----------
hud_header(){
  [ "$QUIET" -eq 1 ] && return
  clear 2>/dev/null || true
  pcol "$BLUE_NEON$B" "╔══════════════════════════════════════════════════════════════════════╗"
  pcol "$BLUE_NEON$B" "║                  SUBDOMAIN FINDER v$VERSION                ║"
  pcol "$BLUE_NEON$B" "║                    Advanced OSINT • DoH • Recon                      ║"
  pcol "$BLUE_NEON$B" "╚══════════════════════════════════════════════════════════════════════╝"
  pcol "$FG_WHITE"   "▸ Date    : $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  pcol "$FG_WHITE"   "▸ Threads : $THREADS"
  pcol "$FG_WHITE"   "▸ UA      : Chrome"
  pcol "$FG_GRAY"    "▸ Mode    : Passive$( [ "$ACTIVE" -eq 1 ] && printf ' + Active(gobuster)')"
  pcol "$FG_GRAY"    "▸ Probe   : $PROBE  Title: $TITLE  DoH: $DOH"
  [ -n "$PORTS" ] && pcol "$FG_GRAY" "▸ Ports   : $PORTS"
  pcol "$FG_GRAY"    "▸ Group IP: $GROUP_IPS  Takeover: $TAKEOVER"
  prt ""
}

hud_progress(){
  local processed found elapsed; processed=$(wc -l < "$SUM" 2>/dev/null || echo 0)
  found=$(wc -l < "$COMB" 2>/dev/null | tr -d ' ' || echo 0)
  elapsed=$((SECONDS - START_TIME))
  pinl "$BLUE_LIGHT" "🛰️ Scanning... | Domains: ${processed} | Subs: ${found} | Time: ${elapsed}s"
}

# ---------- main per-domain ----------
scan_domain(){
  local base="$1"; local d; d="$(norm_domain "$base")"; [ -z "$d" ] && return 0
  pcol "$BLUE_LIGHT" "$ic_scan Scanning: $d"

  local wild="NOWILD"
  if [ "$DOH" -eq 1 ] && [ "$FILTER_WILDCARD" -eq 1 ]; then
    wild="$(detect_wild "$d")"
    [ "$wild" = "WILD" ] && pcol "$YELLOW_NEON" "$ic_warn Wildcard detected on $d (filtering noise)"
  fi

  local uniq="$TMP/$d.subs"; :> "$uniq"

  {
    s_crt "$d"
    s_buff "$d"
    s_rapid "$d"
    s_wayback "$d"
    s_sonar "$d"
    s_anubis "$d"
    s_hacker "$d"
    s_certspot "$d"
    s_urlscan "$d"
    s_active "$d"
  } | while IFS='|' read -r src host; do
        host="$(echo "$host" | tr 'A-Z' 'a-z' | sed 's/^\*\.//' )"
        [[ -z "$host" || "$host" != *."$d" ]] && continue
        [[ ! "$host" =~ [a-z0-9.-] ]] && continue

        if [ "$ONLY_NEW" -eq 1 ] && grep -Fxq "$host" "$KNOWN" 2>/dev/null; then
          continue
        fi

        if [ "$DOH" -eq 1 ] && [ "$FILTER_WILDCARD" -eq 1 ] && [ "$wild" = "WILD" ]; then
          doh "$host" >/dev/null 2>&1 || continue
        fi

        grep -Fxq "$host" "$uniq" 2>/dev/null && continue
        echo "$host" >> "$uniq"

        local status="" title=""
        if [ "$PROBE" -eq 1 ]; then
          IFS='|' read -r status title <<<"$(probe "$host")"
        fi

        print_hit "$src" "$host"
        save "$host" "$src" "$status" "$title"
        [ "$TAKEOVER" -eq 1 ] && takeover_check "$host"
        hud_progress
      done

  # per-domain save
  if [ -s "$uniq" ]; then
    sort -u "$uniq" > "outputs/${d}-subdomains.txt"
  fi

  # group IPs & port scan
  if [ "$GROUP_IPS" -eq 1 ] && [ -s "$uniq" ]; then
    pcol "$GREEN_NEON" "$ic_ip Grouping $d by IP"
    while read -r h; do
      ip="$(resolve_ip "$h" || true)"
      [ -n "$ip" ] && echo -e "${ip}\t${h}"
    done < "outputs/${d}-subdomains.txt" | sort -u > "outputs/${d}-vhosts.tsv" || true

    if [ -s "outputs/${d}-vhosts.tsv" ]; then
      awk -F'\t' '{print $1}' "outputs/${d}-vhosts.tsv" | sort -u | while read -r ip; do
        [ -n "$PORTS" ] && scan_ports "$ip" "$PORTS"
      done
    fi
  fi

  # summary line
  echo -e "$d\t$(wc -l < "${uniq}" 2>/dev/null || echo 0)" >> "$SUM"
  bell
}

# ---------- orchestrate ----------
START_TIME=$SECONDS

# initialize HUD and semaphores
hud_header
sem_init

# progress ticker
(
  while :; do hud_progress; sleep 1; done
) & TICK=$!

# dispatch
while read -r dom || [ -n "${dom:-}" ]; do
  dom="${dom%%#*}"; dom="${dom//[$'\t\r\n ']/}"
  [ -z "$dom" ] && continue
  sem_wait
  { scan_domain "$dom"; sem_post; } &
done < <(grep -E '^[^#[:space:]]' "$INPUT_FILE" || true)

wait
kill "$TICK" 2>/dev/null || true

# finalize
if [ -f "$COMB" ]; then
  sort -u "$COMB" -o "$COMB" || true
  cp "$COMB" "$OUTFILE" 2>/dev/null || true
fi
final=$(wc -l < "$COMB" 2>/dev/null | tr -d ' ' || echo 0)
domains=$(wc -l < "$SUM" 2>/dev/null | tr -d ' ' || echo 0)
elapsed=$((SECONDS - START_TIME))

prt ""
pcol "$BLUE_NEON$B" "╔══════════════════════════════════════════════════════════════╗"
pcol "$BLUE_NEON$B" "║                       SCAN COMPLETE                          ║"
pcol "$BLUE_NEON$B" "╠══════════════════════════════════════════════════════════════╣"
printf "%b║%-25s│%15s%b\n" "$BLUE_NEON$B" "Domains Processed" "$domains" "$R"
printf "%b║%-25s│%15s%b\n" "$BLUE_NEON$B" "Subdomains Found" "$final" "$R"
printf "%b║%-25s│%15ss%b\n" "$BLUE_NEON$B" "Execution Time" "$elapsed" "$R"
pcol "$BLUE_NEON$B" "╚══════════════════════════════════════════════════════════════╝"
prt ""
pcol "$GREEN_NEON$B" "$ic_ok Results saved: $OUTFILE"
pcol "$FG_GRAY"      "▸ Per-domain files: outputs/<domain>-subdomains.txt"
pcol "$FG_GRAY"      "▸ VHost mappings: outputs/<domain>-vhosts.tsv"
pcol "$FG_GRAY"      "▸ Use --format csv or jsonl for pipeline processing"
bell
