#!/usr/bin/env bash
set -euo pipefail

APP_NAME="scopewise"
APP_VER="0.2.4"

MODE="fast"
TARGET_SINGLE=""
TARGET_FILE=""

WEB_PORTS="80,443,8080,8443,8000,8888,3000,5000,9000"
EXTENSIONS="php,html,js,json,xml,txt,log,bak,backup,old,zip,tar,gz,tgz,sql,db,sqlite,env,config,conf,ini,yml,yaml,map"
FFUF_EXTENSIONS=".php,.html,.js,.json,.xml,.txt,.log,.bak,.backup,.old,.zip,.tar.gz,.tgz,.sql,.db,.sqlite,.env,.config,.conf,.ini,.yml,.yaml,.map"

WL_COMMON="/usr/share/seclists/Discovery/Web-Content/common.txt"
WL_DIR_SMALL="/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
WL_DIR_MEDIUM="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
WL_FILE_SMALL="/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt"
WL_FILE_MEDIUM="/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"

banner() {
cat <<'EOF_BANNER'

\u2584\u2588\u2588\u2588\u2588\u2588  \u2584\u2584\u2584\u2584  \u2584\u2584\u2584  \u2584\u2584\u2584\u2584  \u2584\u2584\u2584\u2584\u2584 \u2588\u2588     \u2588\u2588 \u2584\u2584  \u2584\u2584\u2584\u2584 \u2584\u2584\u2584\u2584\u2584
\u2580\u2580\u2580\u2584\u2584\u2584 \u2588\u2588\u2580\u2580\u2580 \u2588\u2588\u2580\u2588\u2588 \u2588\u2588\u2584\u2588\u2580 \u2588\u2588\u2584\u2584  \u2588\u2588 \u2584\u2588\u2584 \u2588\u2588 \u2588\u2588 \u2588\u2588\u2588\u2584\u2584 \u2588\u2588\u2584\u2584
\u2588\u2588\u2588\u2588\u2588\u2580 \u2580\u2588\u2588\u2588\u2588 \u2580\u2588\u2588\u2588\u2580 \u2588\u2588    \u2588\u2588\u2584\u2584\u2584  \u2580\u2588\u2588\u2580\u2588\u2588\u2580  \u2588\u2588 \u2584\u2584\u2588\u2588\u2580 \u2588\u2588\u2584\u2584\u2584

EOF_BANNER
printf '  %s v%s\n\n' "$APP_NAME" "$APP_VER"
}

SPIN_CHARS='|/-\'
SPIN_IDX=0
INT_SKIP=0

RED=$'\033[31m'
GRN=$'\033[32m'
YEL=$'\033[33m'
BLU=$'\033[34m'
RST=$'\033[0m'

usage() {
  cat <<EOF_USAGE
Usage:
  $0 -u <domain|url> [--fast|--deep|--passive]
  $0 -f <file_with_domains_or_urls> [--fast|--deep|--passive]

Modes:
  --fast      Default. Balanced first-pass bounty recon.
  --deep      More thorough content discovery and crawling.
  --passive   Passive/light mode. Skips active content discovery and heavier scans.

Examples:
  $0 -u example.com
  $0 -u example.com --deep
  $0 -f urls.txt --passive
EOF_USAGE
  exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

host_of() {
  local x="$1"
  x="$(trim "$x")"
  x="${x%$'\r'}"
  [[ -z "$x" ]] && return 1
  [[ "$x" =~ ^# ]] && return 1
  x="${x#http://}"
  x="${x#https://}"
  x="${x%%/*}"
  x="${x%%:*}"
  [[ -z "$x" ]] && return 1
  printf '%s' "$x"
}

url_host() {
  local u="${1#http://}"
  u="${u#https://}"
  u="${u%%/*}"
  u="${u%%:*}"
  printf '%s\n' "$u"
}

log_line() {
  local msg="$1"
  [[ -n "${LOG:-}" ]] || return 0
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$msg" >>"$LOG"
}

spin_tick() {
  local label="$1"
  local c="${SPIN_CHARS:$SPIN_IDX:1}"
  SPIN_IDX=$(( (SPIN_IDX + 1) % ${#SPIN_CHARS} ))
  printf '\r%s[IN PROGRESS]%s %s %s' "$BLU" "$RST" "$label" "$c"
}

print_done() { printf '\r\033[K%s[DONE]%s  %s\n' "$GRN" "$RST" "$1"; }
print_warn() { printf '\r\033[K%s[WARN]%s  %s\n' "$YEL" "$RST" "$1"; }
print_fail() { printf '\r\033[K%s[FAIL]%s  %s\n' "$RED" "$RST" "$1"; }
print_skip() { printf '\r\033[K%s[SKIP]%s  %s\n' "$YEL" "$RST" "$1"; }

trap_int() { INT_SKIP=1; }
trap 'trap_int' INT

run_step() {
  local label="$1"
  local tool="$2"
  local host_out="$3"
  shift 3

  local soft_rcs="${SOFT_RCS:-}"
  if [[ "${1:-}" == "--soft-rcs" ]]; then
    soft_rcs="$2"
    shift 2
  fi

  mkdir -p "${host_out}/debug"
  local stdout_file="${host_out}/debug/${tool}.stdout"
  local stderr_file="${host_out}/debug/${tool}.stderr"

  INT_SKIP=0
  log_line "START: ${label}"
  log_line "CMD: $*"

  ( "$@" >"$stdout_file" 2>"$stderr_file" ) &
  local pid=$!

  while kill -0 "$pid" 2>/dev/null; do
    if [[ "$INT_SKIP" -eq 1 ]]; then
      kill -INT "$pid" 2>/dev/null || true
      sleep 0.2
      kill -KILL "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      log_line "SKIP: ${label}"
      print_skip "$label"
      return 130
    fi
    spin_tick "$label"
    sleep 0.12
  done

  local rc=0
  wait "$pid" || rc=$?

  if [[ "$rc" -eq 0 ]]; then
    log_line "DONE: ${label}"
    print_done "$label"
    return 0
  fi

  local is_soft=0
  if [[ -n "$soft_rcs" ]]; then
    local s
    for s in $soft_rcs; do
      if [[ "$rc" -eq "$s" ]]; then
        is_soft=1
        break
      fi
    done
  fi

  if [[ -s "$stderr_file" ]]; then
    log_line "STDERR tail (${label}):"
    tail -n 10 "$stderr_file" | sed 's/^/  /' | while IFS= read -r line; do log_line "$line"; done
  fi

  if [[ "$is_soft" -eq 1 ]]; then
    log_line "SOFT-RC: ${label} rc=${rc}"
    print_done "${label} (soft rc=${rc})"
    return 0
  else
    log_line "RC: ${label} rc=${rc}"
    print_warn "${label} (rc=${rc})"
    return "$rc"
  fi
}

pick_best_url() {
  local urls_file="$1"
  local host="$2"
  local best=""
  if [[ -s "$urls_file" ]]; then
    best="$(grep -E "^https://${host}(:[0-9]+)?(/|$)" "$urls_file" | head -n 1 || true)"
    [[ -z "$best" ]] && best="$(grep -E "^http://${host}(:[0-9]+)?(/|$)" "$urls_file" | head -n 1 || true)"
    [[ -z "$best" ]] && best="$(head -n 1 "$urls_file" 2>/dev/null || true)"
  fi
  if [[ -z "$best" ]]; then
    best="https://${host}"
  fi
  printf '%s\n' "$best"
}

choose_wordlist() {
  local preferred="$1"
  local fallback="$2"
  if [[ -f "$preferred" ]]; then
    printf '%s\n' "$preferred"
  elif [[ -f "$fallback" ]]; then
    printf '%s\n' "$fallback"
  else
    printf '%s\n' "$preferred"
  fi
}

parse_args() {
  if [[ "$#" -eq 0 ]]; then
    usage
  fi

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      -u)
        shift
        [[ "$#" -gt 0 ]] || usage
        TARGET_SINGLE="$1"
        ;;
      -f)
        shift
        [[ "$#" -gt 0 ]] || usage
        TARGET_FILE="$1"
        ;;
      --fast)
        MODE="fast"
        ;;
      --deep)
        MODE="deep"
        ;;
      --passive)
        MODE="passive"
        ;;
      -h|--help)
        usage
        ;;
      *)
        print_fail "Unknown option: $1"
        usage
        ;;
    esac
    shift
  done
}

configure_mode() {
  case "$MODE" in
    fast)
      HTTPX_RL="80"
      NUCLEI_RL="30"
      NUCLEI_C="10"
      KATANA_DEPTH="3"
      FEROX_RL="30"
      FEROX_DEPTH="2"
      FFUF_RATE="30"
      DIR_WL="$(choose_wordlist "$WL_DIR_SMALL" "$WL_COMMON")"
      FILE_WL="$(choose_wordlist "$WL_FILE_SMALL" "$WL_COMMON")"
      ;;
    deep)
      HTTPX_RL="80"
      NUCLEI_RL="40"
      NUCLEI_C="15"
      KATANA_DEPTH="4"
      FEROX_RL="20"
      FEROX_DEPTH="3"
      FFUF_RATE="20"
      DIR_WL="$(choose_wordlist "$WL_DIR_MEDIUM" "$WL_COMMON")"
      FILE_WL="$(choose_wordlist "$WL_FILE_MEDIUM" "$WL_COMMON")"
      ;;
    passive)
      HTTPX_RL="50"
      NUCLEI_RL="15"
      NUCLEI_C="5"
      KATANA_DEPTH="2"
      FEROX_RL="0"
      FEROX_DEPTH="0"
      FFUF_RATE="0"
      DIR_WL="$(choose_wordlist "$WL_DIR_SMALL" "$WL_COMMON")"
      FILE_WL="$(choose_wordlist "$WL_FILE_SMALL" "$WL_COMMON")"
      ;;
    *)
      print_fail "Invalid mode: $MODE"
      exit 1
      ;;
  esac
}

normalize_httpx_urls() {
  local input="$1"
  local output="$2"
  if [[ -s "$input" ]]; then
    awk '{print $1}' "$input" | grep -E '^https?://' | sed 's/\r$//' | sort -u >"$output" || true
  else
    : >"$output"
  fi
}

extract_context_files() {
  local host_out="$1"
  local all_urls="$host_out/context/all_urls.txt"

  : >"$host_out/context/interesting_files.txt"
  : >"$host_out/context/interesting_params.txt"
  : >"$host_out/context/api_candidates.txt"
  : >"$host_out/context/js_files.txt"
  : >"$host_out/context/source_maps.txt"
  : >"$host_out/context/redirect_candidates.txt"
  : >"$host_out/context/lfi_candidates.txt"
  : >"$host_out/context/sqli_candidates.txt"

  [[ -s "$all_urls" ]] || return 0

  grep -Ei '\.env($|\?)|\.bak($|\?)|\.backup($|\?)|\.old($|\?)|\.zip($|\?)|\.tar($|\?)|\.gz($|\?)|\.tgz($|\?)|\.rar($|\?)|\.7z($|\?)|\.sql($|\?)|\.db($|\?)|\.sqlite($|\?)|\.log($|\?)|\.config($|\?)|\.conf($|\?)|\.ini($|\?)|\.yml($|\?)|\.yaml($|\?)|\.json($|\?)|\.map($|\?)' "$all_urls" \
    | sort -u >"$host_out/context/interesting_files.txt" || true

  grep -Ei 'redirect=|url=|next=|return=|dest=|destination=|continue=|callback=|file=|path=|folder=|doc=|document=|template=|page=|id=|user=|account=|debug=|token=|key=|secret=|api' "$all_urls" \
    | sort -u >"$host_out/context/interesting_params.txt" || true

  grep -Ei '/api/|/v1/|/v2/|/v3/|graphql|graphiql|swagger|openapi|api-docs|swagger-ui' "$all_urls" \
    | sort -u >"$host_out/context/api_candidates.txt" || true

  grep -Ei '\.js($|\?)' "$all_urls" \
    | sort -u >"$host_out/context/js_files.txt" || true

  grep -Ei '\.map($|\?)' "$all_urls" \
    | sort -u >"$host_out/context/source_maps.txt" || true

  grep -Ei 'redirect=|url=|next=|return=|dest=|destination=|continue=' "$all_urls" \
    | sort -u >"$host_out/context/redirect_candidates.txt" || true

  grep -Ei 'file=|path=|folder=|doc=|document=|template=|page=' "$all_urls" \
    | sort -u >"$host_out/context/lfi_candidates.txt" || true

  grep -Ei 'id=|user=|account=|product=|item=|category=|search=|q=' "$all_urls" \
    | sort -u >"$host_out/context/sqli_candidates.txt" || true
}

count_file() {
  local f="$1"
  if [[ -s "$f" ]]; then
    wc -l <"$f" | tr -d ' '
  else
    printf '0'
  fi
}

write_host_readme() {
  local host_out="$1"
  local host="$2"

  cat >"$host_out/README-FIRST.txt" <<EOF_README
ScopeWise host output: $host
Mode: $MODE

Review first:
  reports/nuclei_exposures.jsonl
  reports/nuclei_takeover.jsonl
  reports/nuclei.jsonl
  reports/nikto.json
  reports/nmap_web.xml
  reports/sslscan.xml
  context/interesting_files.txt
  context/interesting_params.txt
  context/api_candidates.txt
  context/js_files.txt
  context/source_maps.txt
  reports/feroxbuster.txt
  reports/ffuf_files.csv
  reports/ffuf_dirs.csv
  reports/subzy.json
  reports/gowitness/

Gowitness review:
  cd "$host_out"
  gowitness report server \
    --db-uri "sqlite://reports/gowitness/gowitness.sqlite3" \
    --screenshot-path "reports/gowitness/screenshots"

Then open:
  http://127.0.0.1:7171

Manual queues:
  context/redirect_candidates.txt
  context/lfi_candidates.txt
  context/sqli_candidates.txt

Context:
  context/all_urls.txt
  context/live_urls.txt
  context/katana_urls.txt
  context/waybackurls.txt
  context/subdomains.txt

Troubleshooting:
  debug/*.stdout
  debug/*.stderr
  tmp/
EOF_README
}

parse_args "$@"
banner
configure_mode

if [[ -z "${TARGET_SINGLE}" && -z "${TARGET_FILE}" ]]; then
  usage
fi

if [[ -n "${TARGET_SINGLE}" && -n "${TARGET_FILE}" ]]; then
  print_fail "Use either -u or -f, not both."
  exit 1
fi

if [[ -n "${TARGET_FILE}" && ! -f "${TARGET_FILE}" ]]; then
  print_fail "Input file not found: ${TARGET_FILE}"
  exit 1
fi

TMP_INPUT="$(mktemp)"
cleanup_tmp() { rm -f "$TMP_INPUT" 2>/dev/null || true; }
trap 'cleanup_tmp' EXIT

if [[ -n "${TARGET_SINGLE}" ]]; then
  printf '%s\n' "${TARGET_SINGLE}" >"$TMP_INPUT"
else
  cat "${TARGET_FILE}" >"$TMP_INPUT"
fi

mapfile -t RAW_LINES < <(awk 'NF{print}' "$TMP_INPUT" | sed 's/\r$//' | sed '/^\s*#/d')

if [[ "${#RAW_LINES[@]}" -eq 0 ]]; then
  print_fail "No valid targets provided."
  exit 1
fi

ROOT="${PWD}/${APP_NAME}"
mkdir -p "$ROOT"

RUN_DIR="${ROOT}/$(date '+%Y%m%d_%H%M%S')"
OUT_DIR="${RUN_DIR}/output"
mkdir -p "${OUT_DIR}"
LOG="${RUN_DIR}/${APP_NAME}.log"
touch "$LOG"
SUMMARY_MOVED_FEROX=0
SUMMARY_MISC_DIR=""

mapfile -t HOSTS < <(
  for line in "${RAW_LINES[@]}"; do
    h="$(host_of "$line" 2>/dev/null || true)"
    [[ -n "$h" ]] && printf '%s\n' "$h"
  done | sort -u
)

if [[ "${#HOSTS[@]}" -eq 0 ]]; then
  rm -rf "$RUN_DIR" 2>/dev/null || true
  print_fail "No usable hosts after parsing input."
  exit 1
fi

printf '%s\n' "${HOSTS[@]}" >"$RUN_DIR/hosts.txt"

TOTAL_HOSTS="${#HOSTS[@]}"
print_done "Targets: ${TOTAL_HOSTS} host(s)"
print_done "Mode: ${MODE}"
log_line "Targets: ${TOTAL_HOSTS} host(s)"
log_line "Mode: ${MODE}"
log_line "Dir wordlist: ${DIR_WL}"
log_line "File wordlist: ${FILE_WL}"

idx=0
for host in "${HOSTS[@]}"; do
  idx=$((idx + 1))
  (
    set -euo pipefail

    printf '\n%s[%s/%s] %s%s\n' "$BLU" "$idx" "$TOTAL_HOSTS" "$host" "$RST"
    log_line "HOST: ${host} (${idx}/${TOTAL_HOSTS})"

    host_out="$OUT_DIR/$host"
    mkdir -p "$host_out/reports" "$host_out/context" "$host_out/debug" "$host_out/tmp"
    log_line "HOST_OUT: $host_out"

    HOST_BASE_URLS="$host_out/context/urls_source.txt"
    {
      printf 'https://%s\n' "$host"
      printf 'http://%s\n' "$host"
    } | sort -u >"$HOST_BASE_URLS"

    HOST_HTTPX_RAW="$host_out/context/url_input.txt"
    HOST_URLS="$host_out/context/live_urls.txt"

    if have httpx; then
      run_step "httpx" "httpx" "$host_out" httpx \
        -l "$HOST_BASE_URLS" \
        -silent \
        -sc \
        -cl \
        -title \
        -tech-detect \
        -follow-host-redirects \
        -ports "$WEB_PORTS" \
        -rl "$HTTPX_RL" \
        -o "$HOST_HTTPX_RAW" || true
      normalize_httpx_urls "$HOST_HTTPX_RAW" "$HOST_URLS"
    else
      print_skip "httpx (not installed)"
      sort -u "$HOST_BASE_URLS" >"$HOST_URLS"
    fi

    if [[ ! -s "$HOST_URLS" ]]; then
      print_warn "httpx produced no URLs for ${host}; fallback to base urls"
      sort -u "$HOST_BASE_URLS" >"$HOST_URLS"
    fi

    printf '%s\n' "$host" >"$host_out/context/target_host.txt"
    BEST_URL="$(pick_best_url "$HOST_URLS" "$host")"
    printf '%s\n' "$BEST_URL" >"$host_out/context/target_url.txt"

    KATANA_RAW="$host_out/context/katana.txt"
    KATANA_URLS="$host_out/context/katana_urls.txt"
    KATANA_HTTPX="$host_out/context/katana_httpx.txt"
    : >"$KATANA_RAW"
    : >"$KATANA_URLS"
    : >"$KATANA_HTTPX"

    if have katana; then
      run_step "katana" "katana" "$host_out" katana \
        -u "$BEST_URL" \
        -silent \
        -jc \
        -kf all \
        -fx \
        -d "$KATANA_DEPTH" \
        -o "$KATANA_RAW" || true
      awk 'NF{print}' "$KATANA_RAW" | sed 's/\r$//' | grep -E '^https?://' | sort -u >"$KATANA_URLS" || true
    else
      print_skip "katana (not installed)"
    fi

    if have httpx && [[ -s "$KATANA_URLS" ]]; then
      run_step "httpx (katana urls)" "httpx_katana" "$host_out" httpx \
        -l "$KATANA_URLS" \
        -silent \
        -sc \
        -cl \
        -title \
        -tech-detect \
        -rl "$HTTPX_RL" \
        -o "$KATANA_HTTPX" || true
    fi

    if [[ -s "$KATANA_URLS" ]]; then
      kcnt="$(count_file "$KATANA_URLS")"
      print_done "katana urls: $kcnt"
      log_line "katana urls: $kcnt"
    fi

    WAYBACK_URLS="$host_out/context/waybackurls.txt"
    : >"$WAYBACK_URLS"

    if have waybackurls; then
      run_step "waybackurls" "waybackurls" "$host_out" \
        bash -c "printf '%s\n' '$host' | waybackurls | sort -u > '$WAYBACK_URLS'" || true
    else
      print_skip "waybackurls (not installed)"
    fi

    ALL_URLS="$host_out/context/all_urls.txt"
    cat "$HOST_URLS" "$KATANA_URLS" "$WAYBACK_URLS" 2>/dev/null \
      | awk 'NF{print}' \
      | sed 's/\r$//' \
      | sort -u >"$ALL_URLS"

    extract_context_files "$host_out"

    print_done "all urls: $(count_file "$ALL_URLS")"
    print_done "interesting files: $(count_file "$host_out/context/interesting_files.txt")"
    print_done "interesting params: $(count_file "$host_out/context/interesting_params.txt")"
    print_done "api candidates: $(count_file "$host_out/context/api_candidates.txt")"
    print_done "js files: $(count_file "$host_out/context/js_files.txt")"

    if have nuclei; then
      run_step "nuclei general" "nuclei_general" "$host_out" nuclei \
        -l "$HOST_URLS" \
        -severity low,medium,high,critical \
        -stats \
        -jsonl \
        -o "$host_out/reports/nuclei.jsonl" \
        -rl "$NUCLEI_RL" \
        -c "$NUCLEI_C" \
        -timeout 10 \
        -retries 2 || true

      run_step "nuclei exposures" "nuclei_exposures" "$host_out" nuclei \
        -l "$HOST_URLS" \
        -tags exposure,misconfig,files,logs,backup,config \
        -jsonl \
        -o "$host_out/reports/nuclei_exposures.jsonl" \
        -rl "$NUCLEI_RL" \
        -c "$NUCLEI_C" \
        -timeout 10 \
        -retries 2 || true

      run_step "nuclei takeover" "nuclei_takeover" "$host_out" nuclei \
        -l "$HOST_URLS" \
        -tags takeover \
        -jsonl \
        -o "$host_out/reports/nuclei_takeover.jsonl" \
        -rl "$NUCLEI_RL" \
        -c "$NUCLEI_C" \
        -timeout 10 \
        -retries 2 || true

      if [[ -s "$host_out/context/js_files.txt" ]]; then
        run_step "nuclei js exposure" "nuclei_js_exposure" "$host_out" nuclei \
          -l "$host_out/context/js_files.txt" \
          -tags exposure,token,secret \
          -jsonl \
          -o "$host_out/reports/nuclei_js_exposure.jsonl" \
          -rl "$NUCLEI_RL" \
          -c "$NUCLEI_C" \
          -timeout 10 \
          -retries 2 || true
      fi
    else
      print_skip "nuclei (not installed)"
    fi

    if [[ "$MODE" != "passive" ]]; then
      if have nmap; then
        run_step "nmap" "nmap" "$host_out" nmap \
          -sS \
          -sV \
          -sC \
          -T3 \
          -p "$WEB_PORTS" \
          -oA "$host_out/reports/nmap_web" \
          "$host" || true
      else
        print_skip "nmap (not installed)"
      fi
    else
      print_skip "nmap (passive mode)"
    fi

    if [[ "$MODE" != "passive" ]]; then
      if have nikto; then
        nikto_json="$host_out/reports/nikto.json"
        rm -f "$nikto_json" 2>/dev/null || true

        run_step "nikto" "nikto" "$host_out" --soft-rcs "1" \
          nikto -h "$BEST_URL" -Format json -output "$nikto_json" || true

        if [[ ! -s "$nikto_json" ]]; then
          print_warn "nikto json empty"
          log_line "WARN: nikto json empty"
        fi
      else
        print_skip "nikto (not installed)"
      fi
    else
      print_skip "nikto (passive mode)"
    fi

    if have sslscan; then
      if [[ "$BEST_URL" == https://* ]]; then
        ssl_h="$(url_host "$BEST_URL")"
        run_step "sslscan" "sslscan" "$host_out" sslscan \
          --xml="$host_out/reports/sslscan.xml" \
          "$ssl_h" || true
      else
        print_skip "sslscan (BEST_URL is not https)"
      fi
    else
      print_skip "sslscan (not installed)"
    fi

    if [[ "$MODE" != "passive" ]]; then
      if have ffuf; then
        run_step "ffuf dirs" "ffuf_dirs" "$host_out" ffuf \
          -u "${BEST_URL%/}/FUZZ" \
          -w "$DIR_WL" \
          -mc 200,204,301,302,307,308,401,403,405,500 \
          -ac \
          -rate "$FFUF_RATE" \
          -of csv \
          -o "$host_out/reports/ffuf_dirs.csv" || true

        run_step "ffuf files" "ffuf_files" "$host_out" ffuf \
          -u "${BEST_URL%/}/FUZZ" \
          -w "$FILE_WL" \
          -e "$FFUF_EXTENSIONS" \
          -mc 200,204,301,302,307,308,401,403,405,500 \
          -ac \
          -rate "$FFUF_RATE" \
          -of csv \
          -o "$host_out/reports/ffuf_files.csv" || true
      else
        print_skip "ffuf (not installed)"
      fi
    else
      print_skip "ffuf dirs/files (passive mode)"
    fi

    KATANA_DIRS="$host_out/context/katana_dirs.txt"
    : >"$KATANA_DIRS"

    if [[ -s "$KATANA_HTTPX" ]]; then
      awk -v h="$host" '
        NF {
          u=$1
          if (u ~ "^https?://" h "(:[0-9]+)?(/|$)" && $0 ~ /\[(200|204|301|302|307|308|401|403|405|500)\]/) {
            sub(/[?#].*$/,"",u)
            if (u ~ /\/[^\/]*$/) sub(/\/[^\/]*$/,"/",u)
            if (u ~ /^https?:\/\/[^\/]+\/.*/) print u
          }
        }
      ' "$KATANA_HTTPX" | sort -u | head -n 50 >"$KATANA_DIRS"
    fi

    if [[ "$MODE" != "passive" ]]; then
      if have ffuf && [[ -s "$KATANA_DIRS" ]]; then
        run_step "ffuf (katana dirs)" "ffuf_katana_dirs" "$host_out" ffuf \
          -u "FUZZFUZZ2" \
          -w "$KATANA_DIRS":FUZZ \
          -w "$WL_COMMON":FUZZ2 \
          -mc 200,204,301,302,307,308,401,403,405,500 \
          -ac \
          -rate "$FFUF_RATE" \
          -of csv \
          -o "$host_out/reports/ffuf_katana_dirs.csv" || true
      else
        print_skip "ffuf (katana dirs)"
      fi
    else
      print_skip "ffuf (katana dirs) (passive mode)"
    fi

    if [[ "$MODE" != "passive" ]]; then
      if have feroxbuster; then
        export STATE_FILENAME="$host_out/tmp/ferox-stdin-data.state"
        run_step "feroxbuster" "feroxbuster" "$host_out" feroxbuster \
          -u "$BEST_URL" \
          -w "$DIR_WL" \
          -x "$EXTENSIONS" \
          -s 200,204,301,302,307,308,401,403,405,500 \
          -k \
          --random-agent \
          --rate-limit "$FEROX_RL" \
          --depth "$FEROX_DEPTH" \
          --collect-words \
          --collect-backups \
          --quiet \
          -o "$host_out/reports/feroxbuster.txt" || true
        unset STATE_FILENAME
      else
        print_skip "feroxbuster (not installed)"
      fi
    else
      print_skip "feroxbuster (passive mode)"
    fi

    if have gowitness; then
      mkdir -p "$host_out/reports/gowitness/screenshots"
      run_step "gowitness" "gowitness" "$host_out" gowitness scan file \
        -f "$HOST_URLS" \
        --screenshot-path "$host_out/reports/gowitness/screenshots" \
        --write-db \
        --write-db-uri "sqlite://$host_out/reports/gowitness/gowitness.sqlite3" \
        --write-jsonl \
        --write-jsonl-file "$host_out/reports/gowitness/gowitness.jsonl" \
        --write-csv \
        --write-csv-file "$host_out/reports/gowitness/gowitness.csv" || true
    else
      print_skip "gowitness (not installed)"
    fi

    SUB_WORK="$host_out/tmp/subdomains_work"
    mkdir -p "$SUB_WORK"

    if have subfinder; then
      run_step "subfinder" "subfinder" "$host_out" subfinder \
        -d "$host" \
        -silent \
        -o "$SUB_WORK/subfinder.txt" || true
    else
      print_skip "subfinder (not installed)"
      : >"$SUB_WORK/subfinder.txt"
    fi

    BBOT_SUB="$SUB_WORK/bbot_subdomains.txt"
    : >"$BBOT_SUB"

    if have bbot; then
      BBOT_OUT="$SUB_WORK/bbot_out"
      mkdir -p "$BBOT_OUT"
      run_step "bbot" "bbot" "$host_out" bbot \
        -t "$host" \
        -f subdomain-enum \
        -rf passive \
        -y \
        -n "bbot" \
        -o "$BBOT_OUT" || true
      found_bbot_sub="$(find "$BBOT_OUT" -type f -name 'subdomains.txt' 2>/dev/null | head -n 1 || true)"
      if [[ -n "$found_bbot_sub" && -s "$found_bbot_sub" ]]; then
        sort -u "$found_bbot_sub" >"$BBOT_SUB"
        print_done "bbot subdomains -> bbot_subdomains.txt"
        log_line "DONE: bbot subdomains -> ${BBOT_SUB}"
      else
        print_warn "bbot subdomains (none found)"
        log_line "WARN: bbot subdomains none found"
      fi
    else
      print_skip "bbot (not installed)"
    fi

    SUBS_COMBINED="$host_out/context/subdomains.txt"
    {
      cat "$SUB_WORK/subfinder.txt" 2>/dev/null || true
      cat "$BBOT_SUB" 2>/dev/null || true
    } | awk 'NF{print}' | sed 's/\r$//' | sort -u >"$SUBS_COMBINED"

    cp -f "$SUB_WORK/subfinder.txt" "$host_out/context/subfinder.txt" 2>/dev/null || true
    cp -f "$BBOT_SUB" "$host_out/context/bbot_subdomains.txt" 2>/dev/null || true

    print_done "subdomains -> context/subdomains.txt"
    log_line "DONE: subdomains -> ${SUBS_COMBINED}"

    if have subzy; then
      if [[ -s "$SUBS_COMBINED" ]]; then
        run_step "subzy" "subzy" "$host_out" subzy run \
          --targets "$SUBS_COMBINED" \
          --output "$host_out/reports/subzy.json" || true
      else
        print_skip "subzy (no subdomains)"
      fi
    else
      print_skip "subzy (not installed)"
    fi

    write_host_readme "$host_out" "$host"
    print_done "Host report: $host_out"
  ) || {
    print_warn "Host failed: $host (see log)"
    log_line "HOST FAILED: $host"
  }
done

shopt -s nullglob
FEROX_LEFTOVERS=( "./ferox-"*.state "./ferox-stdin-data.state" )
if (( ${#FEROX_LEFTOVERS[@]} > 0 )); then
  SUMMARY_MISC_DIR="$RUN_DIR/misc"
  mkdir -p "$SUMMARY_MISC_DIR"
  mv -f "${FEROX_LEFTOVERS[@]}" "$SUMMARY_MISC_DIR/" 2>/dev/null || true
  SUMMARY_MOVED_FEROX=1
  log_line "INFO: moved ferox leftovers -> $SUMMARY_MISC_DIR"
fi
shopt -u nullglob

ABS_RUN_DIR="$(cd "$RUN_DIR" && pwd -P)"
ABS_LOG="$(cd "$(dirname "$LOG")" && pwd -P)/$(basename "$LOG")"

printf '\n%s==== SUMMARY ====%s\n' "$BLU" "$RST"
printf '%sTargets:%s %s host(s)\n' "$GRN" "$RST" "$TOTAL_HOSTS"
printf '%sMode:%s %s\n' "$GRN" "$RST" "$MODE"
printf '%sReport folder:%s %s\n' "$GRN" "$RST" "$ABS_RUN_DIR"
printf '%sLog:%s %s\n' "$GRN" "$RST" "$ABS_LOG"

if [[ "$SUMMARY_MOVED_FEROX" -eq 1 ]]; then
  printf '%sMisc leftovers:%s %s\n' "$YEL" "$RST" "$SUMMARY_MISC_DIR"
fi

printf '%s' "$RST"
