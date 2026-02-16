#!/usr/bin/env bash
set -euo pipefail

APP_NAME="scopewise"
APP_VER="0.1"

banner() {
cat <<'EOF'                            
                                                        
▄█████  ▄▄▄▄  ▄▄▄  ▄▄▄▄  ▄▄▄▄▄ ██     ██ ▄▄  ▄▄▄▄ ▄▄▄▄▄ 
▀▀▀▄▄▄ ██▀▀▀ ██▀██ ██▄█▀ ██▄▄  ██ ▄█▄ ██ ██ ███▄▄ ██▄▄  
█████▀ ▀████ ▀███▀ ██    ██▄▄▄  ▀██▀██▀  ██ ▄▄██▀ ██▄▄▄ 
                                                        
EOF
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
  echo "Usage:"
  echo "  $0 -u <domain|url>"
  echo "  $0 -f <file_with_domains_or_urls>"
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
  local outdir="$3"
  shift 3

  local soft_rcs="${SOFT_RCS:-}"
  if [[ "${1:-}" == "--soft-rcs" ]]; then
    soft_rcs="$2"
    shift 2
  fi

  local stdout_file="${outdir}/debug/${tool}.stdout"
  local stderr_file="${outdir}/debug/${tool}.stderr"

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
    best="$(grep -E "^https://${host}(/|$)" "$urls_file" | head -n 1 || true)"
    [[ -z "$best" ]] && best="$(grep -E "^http://${host}(/|$)" "$urls_file" | head -n 1 || true)"
    [[ -z "$best" ]] && best="$(head -n 1 "$urls_file" 2>/dev/null || true)"
  fi
  if [[ -z "$best" ]]; then
    best="https://${host}"
  fi
  printf '%s\n' "$best"
}

url_host() {
  local u="${1#http://}"
  u="${u#https://}"
  u="${u%%/*}"
  u="${u%%:*}"
  printf '%s\n' "$u"
}

TARGET_SINGLE=""
TARGET_FILE=""

while getopts ":u:f:" opt; do
  case "$opt" in
    u) TARGET_SINGLE="$OPTARG" ;;
    f) TARGET_FILE="$OPTARG" ;;
    *) usage ;;
  esac
done

banner

if [[ -z "${TARGET_SINGLE}" && -z "${TARGET_FILE}" ]]; then
  usage
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
log_line "Targets: ${TOTAL_HOSTS} host(s)"

idx=0
for host in "${HOSTS[@]}"; do
  idx=$((idx + 1))
  (
    set -euo pipefail

    printf '\n%s[%s/%s] %s%s\n' "$BLU" "$idx" "$TOTAL_HOSTS" "$host" "$RST"
    log_line "HOST: ${host} (${idx}/${TOTAL_HOSTS})"
    host_out="$OUT_DIR/$host"
    mkdir -p "$host_out/debug"
    log_line "HOST_OUT: $host_out"

  HOST_BASE_URLS="$host_out/urls_source.txt"
  {
    printf 'https://%s\n' "$host"
    printf 'http://%s\n' "$host"
  } | sort -u >"$HOST_BASE_URLS"

  HOST_URLS="$host_out/url_input.txt"
  if have httpx; then
    run_step "httpx" "httpx" "$host_out" httpx -l "$HOST_BASE_URLS" -silent -o "$HOST_URLS" || true
  else
    print_skip "httpx (not installed)"
    sort -u "$HOST_BASE_URLS" >"$HOST_URLS"
  fi

  if [[ ! -s "$HOST_URLS" ]]; then
    print_warn "httpx produced no URLs for ${host}; fallback to base urls"
    sort -u "$HOST_BASE_URLS" >"$HOST_URLS"
  fi

  printf '%s\n' "$host" >"$host_out/target_host.txt"
  BEST_URL="$(pick_best_url "$HOST_URLS" "$host")"
  printf '%s\n' "$BEST_URL" >"$host_out/target_url.txt"

KATANA_RAW="$host_out/katana.txt"
KATANA_URLS="$host_out/katana_urls.txt"
KATANA_HTTPX="$host_out/katana_httpx.txt"
: >"$KATANA_RAW"
: >"$KATANA_URLS"
: >"$KATANA_HTTPX"

if have katana; then
  run_step "katana" "katana" "$host_out" katana -u "$BEST_URL" -silent -jc -o "$KATANA_RAW" || true
  awk 'NF{print}' "$KATANA_RAW" | sed 's/\r$//' | sort -u >"$KATANA_URLS"
else
  print_skip "katana (not installed)"
fi

if have httpx && [[ -s "$KATANA_URLS" ]]; then
  run_step "httpx (katana urls)" "httpx_katana" "$host_out" \
    httpx -l "$KATANA_URLS" -silent -sc -cl -title -o "$KATANA_HTTPX" || true
fi

if [[ -s "$KATANA_URLS" ]]; then
  kcnt="$(wc -l <"$KATANA_URLS" | tr -d ' ')"
  print_done "katana urls: $kcnt"
  log_line "katana urls: $kcnt"
fi

  if have nuclei; then
    run_step "nuclei" "nuclei" "$host_out" nuclei \
      -l "$HOST_URLS" \
      -severity low,medium,high,critical \
      -stats \
      -jsonl \
      -o "$host_out/nuclei.jsonl" \
      -rl 150 \
      -c 50 \
      -timeout 10 \
      -retries 2 || true
  else
    print_skip "nuclei (not installed)"
  fi

  if have nmap; then
    run_step "nmap" "nmap" "$host_out" nmap -sS -sV -sC -T3 -p 80,443 -oA "$host_out/nmap_web" "$host" || true
  else
    print_skip "nmap (not installed)"
  fi

if have nikto; then
  nikto_json="$host_out/nikto.json"
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

if have sslscan; then
  if [[ "$BEST_URL" == https://* ]]; then
    ssl_h="$(url_host "$BEST_URL")"
    run_step "sslscan" "sslscan" "$host_out" sslscan --xml="$host_out/sslscan.xml" "$ssl_h" || true
  else
    print_skip "sslscan (BEST_URL is not https)"
  fi
else
  print_skip "sslscan (not installed)"
fi

  if have ffuf; then
    run_step "ffuf dirs" "ffuf_dirs" "$host_out" ffuf \
      -u "${BEST_URL%/}/FUZZ" \
      -w /usr/share/seclists/Discovery/Web-Content/common.txt \
      -mc 200,204,301,302,307,401,403 \
      -of csv -o "$host_out/ffuf_dirs.csv" || true

    run_step "ffuf files" "ffuf_files" "$host_out" ffuf \
      -u "${BEST_URL%/}/FUZZ" \
      -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt \
      -mc 200,204,301,302 \
      -of csv -o "$host_out/ffuf_files.csv" || true
  else
    print_skip "ffuf (not installed)"
  fi
  
if have ffuf && [[ -s "$KATANA_HTTPX" ]]; then
  KATANA_DIRS="$host_out/katana_dirs.txt"

  awk -v h="$host" '
    NF {
      u=$1
      if (u ~ "^https?://" h "(/|$)" && $0 ~ /\[(200|204|301|302|307|401|403)\]/) {
        sub(/[?#].*$/,"",u)
        if (u ~ /\/[^\/]*$/) sub(/\/[^\/]*$/,"/",u)
        if (u ~ /^https?:\/\/[^\/]+\/.*/) print u
      }
    }
  ' "$KATANA_HTTPX" | sort -u | head -n 50 >"$KATANA_DIRS"

  if [[ -s "$KATANA_DIRS" ]]; then
    run_step "ffuf (katana dirs)" "ffuf_katana_dirs" "$host_out" ffuf \
      -u "FUZZFUZZ2" \
      -w "$KATANA_DIRS":FUZZ \
      -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ2 \
      -mc 200,204,301,302,307,401,403 \
      -of csv -o "$host_out/ffuf_katana_dirs.csv" || true
  else
    print_warn "ffuf (katana dirs) no dirs extracted"
  fi
else
  print_skip "ffuf (katana dirs) (no katana_httpx)"
fi

  if have feroxbuster; then
    export STATE_FILENAME="$host_out/ferox-stdin-data.state"
    run_step "feroxbuster" "feroxbuster" "$host_out" feroxbuster \
      -u "$BEST_URL" \
      -w /usr/share/seclists/Discovery/Web-Content/common.txt \
      -s 200 204 301 302 307 401 403 \
      --quiet \
      -o "$host_out/feroxbuster.txt" || true
    unset STATE_FILENAME
  else
    print_skip "feroxbuster (not installed)"
  fi

  SUB_WORK="$host_out/subdomains_work"
  mkdir -p "$SUB_WORK"

  if have subfinder; then
    run_step "subfinder" "subfinder" "$host_out" subfinder -d "$host" -silent -o "$SUB_WORK/subfinder.txt" || true
  else
    print_skip "subfinder (not installed)"
    : >"$SUB_WORK/subfinder.txt"
  fi

  BBOT_SUB="$SUB_WORK/bbot_subdomains.txt"
  : >"$BBOT_SUB"

  if have bbot; then
    BBOT_OUT="$SUB_WORK/bbot_out"
    mkdir -p "$BBOT_OUT"
    run_step "bbot" "bbot" "$host_out" bbot -t "$host" -f subdomain-enum -rf passive -y -n "bbot" -o "$BBOT_OUT" || true
    found_bbot_sub="$(find "$BBOT_OUT" -type f -name 'subdomains.txt' 2>/dev/null | head -n 1 || true)"
    if [[ -n "$found_bbot_sub" && -s "$found_bbot_sub" ]]; then
      sort -u "$found_bbot_sub" >"$BBOT_SUB"
      print_done "bbot subdomains -> bbot_subdomains.txt"
      log_line "DONE: bbot subdomains -> ${BBOT_SUB}"
    else
      print_warn "bbot subdomains (none found)"
      log_line "WARN: bbot subdomains none found"
    fi
    rm -rf "$BBOT_OUT" 2>/dev/null || true
  else
    print_skip "bbot (not installed)"
  fi

  SUBS_COMBINED="$host_out/subdomains.txt"
  {
    cat "$SUB_WORK/subfinder.txt" 2>/dev/null || true
    cat "$BBOT_SUB" 2>/dev/null || true
  } | awk 'NF{print}' | sed 's/\r$//' | sort -u >"$SUBS_COMBINED"
  print_done "subdomains -> subdomains.txt"
  log_line "DONE: subdomains -> ${SUBS_COMBINED}"

  cp -f "$SUB_WORK/subfinder.txt" "$host_out/subfinder.txt" 2>/dev/null || true
  cp -f "$BBOT_SUB" "$host_out/bbot_subdomains.txt" 2>/dev/null || true
  rm -rf "$SUB_WORK" 2>/dev/null || true

  if have subzy; then
    run_step "subzy" "subzy" "$host_out" subzy run --targets "$SUBS_COMBINED" --output "$host_out/subzy.json" || true
  else
    print_skip "subzy (not installed)"
  fi

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
printf '%sReport folder:%s %s\n' "$GRN" "$RST" "$ABS_RUN_DIR"
printf '%sLog:%s %s\n' "$GRN" "$RST" "$ABS_LOG"
printf '%s' "$RST"
