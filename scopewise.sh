#!/usr/bin/env bash
set -euo pipefail

APP_NAME="scopewise"
APP_VER="0.3.6"

MODE="fast"
TARGET_SINGLE=""
TARGET_FILE=""
CONFIG_FILE=""
CHECK_ONLY=0
MODE_CLI=""
STEP_MAX_SECONDS="5400"
PARAM_CHECK_LIMIT="25"
DSSS_CMD="dsss"

WEB_PORTS="80,443"
WEB_PORTS_DEEP="80,443,8080,8443,8000,8888,3000,5000,9000"
NMAP_WEB_PORTS="80,443"
NMAP_RECON_PORTS="21,22,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5000,5432,5601,5900,5985,5986,6379,8000,8080,8081,8443,8888,9000,9200,9300,11211,27017"
EXTENSIONS="js,json,xml,txt,log,bak,backup,old,zip,tar,gz,tgz,sql,db,sqlite,env,config,conf,ini,yml,yaml,map"
FEROX_FAST_EXTENSIONS="json,txt,log,bak,backup,old,zip,sql,db,sqlite,env,config,conf,ini,yml,yaml,map"
FFUF_EXTENSIONS=".js,.json,.xml,.txt,.log,.bak,.backup,.old,.zip,.tar.gz,.tgz,.sql,.db,.sqlite,.env,.config,.conf,.ini,.yml,.yaml,.map"

WL_COMMON="/usr/share/seclists/Discovery/Web-Content/common.txt"
WL_DIR_SMALL="/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
WL_DIR_MEDIUM="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
WL_FILE_SMALL="/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt"
WL_FILE_MEDIUM="/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"

banner() {
cat <<'EOF_BANNER'

▄█████  ▄▄▄▄  ▄▄▄  ▄▄▄▄  ▄▄▄▄▄ ██     ██ ▄▄  ▄▄▄▄ ▄▄▄▄▄ 
▀▀▀▄▄▄ ██▀▀▀ ██▀██ ██▄█▀ ██▄▄  ██ ▄█▄ ██ ██ ███▄▄ ██▄▄  
█████▀ ▀████ ▀███▀ ██    ██▄▄▄  ▀██▀██▀  ██ ▄▄██▀ ██▄▄▄ 

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
  $0 -u <domain|url> [--fast|--deep|--passive] [--config scopewise.yml]
  $0 -f <file_with_domains_or_urls> [--fast|--deep|--passive] [--config scopewise.yml]
  $0 --check [--config scopewise.yml]

Modes:
  --fast      Default. Balanced first-pass bounty recon.
  --deep      More thorough content discovery and crawling.
  --passive   Passive/light mode. Skips active content discovery and heavier scans.
  --config    Optional config file. Defaults to ./scopewise.yml if present.
  --check     Check dependencies and configured wordlists, then exit.

Examples:
  $0 -u example.com
  $0 -u example.com --deep
  $0 -f urls.txt --passive
  $0 --check
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

record_tool_status() {
  local tool="${1:-unknown}"
  local status="${2:-unknown}"
  local details="${3:-}"
  [[ -n "${TOOL_STATUS_FILE:-}" ]] || return 0
  printf '%s\t%s\t%s\n' "$tool" "$status" "$details" >>"$TOOL_STATUS_FILE"
}

print_done() { printf '\r\033[K%s[DONE]%s  %s\n' "$GRN" "$RST" "$1"; }
print_warn() { printf '\r\033[K%s[WARN]%s  %s\n' "$YEL" "$RST" "$1"; }
print_fail() { printf '\r\033[K%s[FAIL]%s  %s\n' "$RED" "$RST" "$1"; }
print_skip() {
  printf '\r\033[K%s[SKIP]%s  %s\n' "$YEL" "$RST" "$1"
  if [[ -n "${TOOL_STATUS_FILE:-}" && "${PRINT_SKIP_RECORD_STATUS:-1}" == "1" ]]; then
    case "$1" in
      *"not installed"*) record_tool_status "$1" "missing" "$1" ;;
      *) record_tool_status "$1" "skipped" "$1" ;;
    esac
  fi
}

format_duration() {
  local total="${1:-0}"
  local h=$((total / 3600))
  local m=$(((total % 3600) / 60))
  local sec=$((total % 60))
  printf '%02d:%02d:%02d' "$h" "$m" "$sec"
}

write_fast_file_wordlist() {
  local output="$1"
  cat >"$output" <<'EOF_FAST_FILES'
.env
.env.local
.env.production
.git/HEAD
.git/config
config.json
config.yml
config.yaml
appsettings.json
web.config
backup.zip
backup.tar.gz
backup.sql
dump.sql
database.sql
debug.log
error.log
access.log
swagger.json
openapi.json
robots.txt
sitemap.xml
server-status
EOF_FAST_FILES
}

write_fast_katana_wordlist() {
  local output="$1"
  cat >"$output" <<'EOF_FAST_KATANA'
admin
login
api
assets
static
js
css
images
img
uploads
upload
backup
backups
config
debug
health
status
robots.txt
sitemap.xml
EOF_FAST_KATANA
}

write_fast_ferox_wordlist() {
  local output="$1"
  cat >"$output" <<'EOF_FAST_FEROX'
.env
.git/HEAD
.git/config
.htaccess
.htpasswd
admin
api
app
application
appsettings
backup
backups
cache
config
configuration
conf
db
database
debug
dev
dump
env
error
errors
files
local
log
logs
old
openapi
private
prod
production
public
robots
secret
secrets
server
settings
sitemap
staging
static
storage
test
upload
uploads
web
EOF_FAST_FEROX
}

filter_ferox_fast_output() {
  local input="$1"
  local output="$2"
  local filtered_403="$3"
  local cloudflare_detected="${4:-0}"

  : >"$output"
  : >"$filtered_403"

  [[ -s "$input" ]] || return 0

  awk -v dropped="$filtered_403" -v cf="$cloudflare_detected" '
    function url_path(u,   x) {
      x=u
      sub(/^https?:\/\/[^\/]+/, "", x)
      if (x == "") x="/"
      return x
    }
    function high_signal_403(path) {
      if (path ~ /^\/\.env([\.\/]|$)/) return 1
      if (path ~ /^\/\.git\/(HEAD|config|index|logs)([\.\/]|$)/) return 1
      if (path ~ /^\/\.ht(access|passwd)([\.\/]|$)/) return 1
      if (path ~ /(^|\/)(backup|backups|dump|database|db|config|configuration|conf|settings|secret|secrets|private|prod|production|staging|dev|debug|logs?|error|access|openapi|swagger|appsettings|web\.config)([\.\/]|$)/) return 1
      if (path ~ /\.(env|bak|backup|old|zip|sql|db|sqlite|config|conf|ini|ya?ml|log|map)([?#]?|$)/) return 1
      return 0
    }
    /^[0-9][0-9][0-9][[:space:]]/ {
      status=$1
      u=$NF
      path=url_path(u)

      # Empty basename extension probes: /.json, /.bak, /dir/.map, etc.
      if (path ~ /\/\.(json|txt|log|bak|backup|old|zip|sql|db|sqlite|config|conf|ini|yml|yaml|map)([?#]?|$)/) {
        print $0 >> dropped
        next
      }

      # Common generated package-manager backup/extension noise.
      if (path ~ /\/\.package-lock\.json\.(bak|backup|old|sql|db|sqlite|zip|map)([?#]?|$)/) {
        print $0 >> dropped
        next
      }

      if (status == "403" && cf == "1") {
        print $0 >> dropped
        next
      }

      if (status == "403" && !high_signal_403(path)) {
        print $0 >> dropped
        next
      }

      print $0
      next
    }
  ' "$input" >"$output" || cp -f "$input" "$output"
}

trap_int() { INT_SKIP=1; }
trap 'trap_int' INT

run_step() {
  local label="$1"
  local tool="$2"
  local host_out="$3"
  shift 3

  local soft_rcs="${SOFT_RCS:-}"
  local max_seconds="0"
  while [[ "${1:-}" == --* ]]; do
    case "$1" in
      --soft-rcs)
        soft_rcs="$2"
        shift 2
        ;;
      --max-seconds)
        max_seconds="$2"
        shift 2
        ;;
      *)
        break
        ;;
    esac
  done

  mkdir -p "${host_out}/debug"
  local stdout_file="${host_out}/debug/${tool}.stdout"
  local stderr_file="${host_out}/debug/${tool}.stderr"
  local start_ts
  local elapsed
  local pretty_elapsed
  local use_setsid=0
  start_ts="$(date +%s)"

  INT_SKIP=0
  log_line "START: ${label}"
  log_line "CMD: $*"

  if have setsid; then
    ( exec setsid "$@" >"$stdout_file" 2>"$stderr_file" ) &
    use_setsid=1
  else
    ( "$@" >"$stdout_file" 2>"$stderr_file" ) &
  fi
  local pid=$!

  while kill -0 "$pid" 2>/dev/null; do
    elapsed=$(( $(date +%s) - start_ts ))
    if [[ "$INT_SKIP" -eq 1 ]]; then
      if [[ "$use_setsid" -eq 1 ]]; then
        kill -INT -- "-$pid" 2>/dev/null || kill -INT "$pid" 2>/dev/null || true
      else
        kill -INT "$pid" 2>/dev/null || true
      fi
      sleep 0.2
      if [[ "$use_setsid" -eq 1 ]]; then
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
      else
        kill -KILL "$pid" 2>/dev/null || true
      fi
      wait "$pid" 2>/dev/null || true
      elapsed=$(( $(date +%s) - start_ts ))
      log_line "INTERRUPTED: ${label} ($(format_duration "$elapsed"))"
      record_tool_status "$tool" "interrupted" "$label $(format_duration "$elapsed")"
      PRINT_SKIP_RECORD_STATUS=0 print_skip "${label} (interrupted, $(format_duration "$elapsed"))"
      return 130
    fi
    if [[ "$max_seconds" =~ ^[0-9]+$ && "$max_seconds" -gt 0 && "$elapsed" -ge "$max_seconds" ]]; then
      if [[ "$use_setsid" -eq 1 ]]; then
        kill -INT -- "-$pid" 2>/dev/null || kill -INT "$pid" 2>/dev/null || true
      else
        kill -INT "$pid" 2>/dev/null || true
      fi
      sleep 0.5
      if [[ "$use_setsid" -eq 1 ]]; then
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
      else
        kill -KILL "$pid" 2>/dev/null || true
      fi
      wait "$pid" 2>/dev/null || true
      elapsed=$(( $(date +%s) - start_ts ))
      log_line "TIMEOUT: ${label} after $(format_duration "$elapsed")"
      record_tool_status "$tool" "timeout" "$label timeout $(format_duration "$elapsed")"
      print_warn "${label} (timeout, $(format_duration "$elapsed"))"
      return 124
    fi
    spin_tick "$label"
    sleep 0.12
  done

  local rc=0
  wait "$pid" || rc=$?
  elapsed=$(( $(date +%s) - start_ts ))
  pretty_elapsed="$(format_duration "$elapsed")"

  if [[ "$rc" -eq 0 ]]; then
    log_line "DONE: ${label} (${pretty_elapsed})"
    record_tool_status "$tool" "ok" "$label ${pretty_elapsed}"
    print_done "${label} (${pretty_elapsed})"
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
    log_line "SOFT-RC: ${label} rc=${rc} (${pretty_elapsed})"
    record_tool_status "$tool" "ok" "$label soft rc=${rc} ${pretty_elapsed}"
    print_done "${label} (soft rc=${rc}, ${pretty_elapsed})"
    return 0
  else
    log_line "RC: ${label} rc=${rc} (${pretty_elapsed})"
    record_tool_status "$tool" "failed" "$label rc=${rc} ${pretty_elapsed}"
    print_warn "${label} (rc=${rc}, ${pretty_elapsed})"
    return "$rc"
  fi
}

run_step_limited() {
  local label="$1"
  local tool="$2"
  local host_out="$3"
  shift 3
  run_step "$label" "$tool" "$host_out" --max-seconds "$STEP_MAX_SECONDS" "$@"
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

load_config() {
  local cfg="$1"
  local section=""
  local line=""
  local key=""
  local val=""
  [[ -f "$cfg" ]] || return 0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue

    if [[ "$line" == *":" && "$line" != *": "* ]]; then
      section="${line%:}"
      continue
    fi

    [[ "$line" == *":"* ]] || continue
    key="$(trim "${line%%:*}")"
    val="$(trim "${line#*:}")"
    val="${val%\"}"
    val="${val#\"}"
    val="${val%\'}"
    val="${val#\'}"

    case "${section}.${key}" in
      .mode) MODE="$val" ;;
      ports.fast) CONFIG_PORTS_FAST="$val" ;;
      ports.deep) CONFIG_PORTS_DEEP="$val" ;;
      ports.passive) CONFIG_PORTS_PASSIVE="$val" ;;
      ports.nmap_web) CONFIG_NMAP_WEB_PORTS="$val" ;;
      ports.nmap_recon) CONFIG_NMAP_RECON_PORTS="$val" ;;
      rates.httpx) CONFIG_HTTPX_RL="$val" ;;
      rates.nuclei) CONFIG_NUCLEI_RL="$val" ;;
      rates.nuclei_concurrency) CONFIG_NUCLEI_C="$val" ;;
      rates.ffuf) CONFIG_FFUF_RATE="$val" ;;
      rates.ferox) CONFIG_FEROX_RL="$val" ;;
      depths.katana_fast) CONFIG_KATANA_FAST="$val" ;;
      depths.katana_deep) CONFIG_KATANA_DEEP="$val" ;;
      depths.ferox_fast) CONFIG_FEROX_FAST_DEPTH="$val" ;;
      depths.ferox_deep) CONFIG_FEROX_DEEP_DEPTH="$val" ;;
      wordlists.common) WL_COMMON="$val" ;;
      wordlists.dir_fast) CONFIG_DIR_WL_FAST="$val" ;;
      wordlists.dir_deep) CONFIG_DIR_WL_DEEP="$val" ;;
      wordlists.file_deep) CONFIG_FILE_WL_DEEP="$val" ;;
      wordlists.dir_small) WL_DIR_SMALL="$val" ;;
      wordlists.dir_medium) WL_DIR_MEDIUM="$val" ;;
      wordlists.file_small) WL_FILE_SMALL="$val" ;;
      wordlists.file_medium) WL_FILE_MEDIUM="$val" ;;
      limits.katana_dirs_fast) CONFIG_KATANA_DIR_LIMIT_FAST="$val" ;;
      limits.katana_dirs_deep) CONFIG_KATANA_DIR_LIMIT_DEEP="$val" ;;
      limits.step_timeout_seconds) STEP_MAX_SECONDS="$val" ;;
      limits.param_check_urls) PARAM_CHECK_LIMIT="$val" ;;
      tools.dsss_cmd) DSSS_CMD="$val" ;;
    esac
  done <"$cfg"
}

apply_config_overrides() {
  case "$MODE" in
    fast)
      WEB_PORTS="${CONFIG_PORTS_FAST:-$WEB_PORTS}"
      DIR_WL="${CONFIG_DIR_WL_FAST:-$DIR_WL}"
      KATANA_DEPTH="${CONFIG_KATANA_FAST:-$KATANA_DEPTH}"
      FEROX_DEPTH="${CONFIG_FEROX_FAST_DEPTH:-$FEROX_DEPTH}"
      KATANA_DIR_LIMIT="${CONFIG_KATANA_DIR_LIMIT_FAST:-$KATANA_DIR_LIMIT}"
      ;;
    deep)
      WEB_PORTS="${CONFIG_PORTS_DEEP:-$WEB_PORTS}"
      DIR_WL="${CONFIG_DIR_WL_DEEP:-$DIR_WL}"
      FILE_WL="${CONFIG_FILE_WL_DEEP:-$FILE_WL}"
      KATANA_DEPTH="${CONFIG_KATANA_DEEP:-$KATANA_DEPTH}"
      FEROX_DEPTH="${CONFIG_FEROX_DEEP_DEPTH:-$FEROX_DEPTH}"
      KATANA_DIR_LIMIT="${CONFIG_KATANA_DIR_LIMIT_DEEP:-$KATANA_DIR_LIMIT}"
      ;;
    passive)
      WEB_PORTS="${CONFIG_PORTS_PASSIVE:-$WEB_PORTS}"
      DIR_WL="${CONFIG_DIR_WL_FAST:-$DIR_WL}"
      ;;
  esac
  HTTPX_RL="${CONFIG_HTTPX_RL:-$HTTPX_RL}"
  NUCLEI_RL="${CONFIG_NUCLEI_RL:-$NUCLEI_RL}"
  NUCLEI_C="${CONFIG_NUCLEI_C:-$NUCLEI_C}"
  FFUF_RATE="${CONFIG_FFUF_RATE:-$FFUF_RATE}"
  FEROX_RL="${CONFIG_FEROX_RL:-$FEROX_RL}"
  NMAP_WEB_PORTS="${CONFIG_NMAP_WEB_PORTS:-$NMAP_WEB_PORTS}"
  NMAP_RECON_PORTS="${CONFIG_NMAP_RECON_PORTS:-$NMAP_RECON_PORTS}"
}

check_file_status() {
  local label="$1"
  local path="$2"
  if [[ -f "$path" ]]; then
    printf '%-28s OK      %s\n' "$label" "$path"
  else
    printf '%-28s missing %s\n' "$label" "$path"
  fi
}

run_dependency_check() {
  local tools=(httpx katana nuclei nmap wafw00f nikto sslscan ffuf feroxbuster gowitness subfinder bbot subzy waybackurls dalfox)
  local t=""
  printf 'ScopeWise dependency check\n\n'
  printf 'Mode: %s\n' "$MODE"
  [[ -n "${CONFIG_FILE:-}" ]] && printf 'Config: %s\n' "$CONFIG_FILE"
  printf '\nTools:\n'
  for t in "${tools[@]}"; do
    if have "$t"; then
      printf '  %-14s OK\n' "$t"
    else
      printf '  %-14s missing\n' "$t"
    fi
  done
  if have "$DSSS_CMD"; then
    printf '  %-14s OK      %s\n' "dsss" "$DSSS_CMD"
  elif [[ -f "$DSSS_CMD" ]] && have python3; then
    printf '  %-14s OK      %s\n' "dsss" "$DSSS_CMD"
  else
    printf '  %-14s missing %s\n' "dsss" "$DSSS_CMD"
  fi
  printf '\nConfigured wordlists:\n'
  check_file_status "common" "$WL_COMMON"
  check_file_status "dir small" "$WL_DIR_SMALL"
  check_file_status "dir medium" "$WL_DIR_MEDIUM"
  check_file_status "file small" "$WL_FILE_SMALL"
  check_file_status "file medium" "$WL_FILE_MEDIUM"
  printf '\nEffective mode settings:\n'
  printf '  web ports: %s\n' "$WEB_PORTS"
  printf '  httpx rate: %s\n' "$HTTPX_RL"
  printf '  nuclei rate: %s\n' "$NUCLEI_RL"
  printf '  nuclei concurrency: %s\n' "$NUCLEI_C"
  printf '  ffuf rate: %s\n' "$FFUF_RATE"
  printf '  ferox rate: %s\n' "$FEROX_RL"
  printf '  katana depth: %s\n' "$KATANA_DEPTH"
  printf '  ferox depth: %s\n' "$FEROX_DEPTH"
  printf '  dir wordlist: %s\n' "$DIR_WL"
  printf '  file wordlist: %s\n' "$FILE_WL"
  printf '  nmap web ports: %s\n' "$NMAP_WEB_PORTS"
  printf '  nmap recon ports: %s\n' "$NMAP_RECON_PORTS"
  printf '  step timeout seconds: %s\n' "$STEP_MAX_SECONDS"
  printf '  param check url limit: %s\n' "$PARAM_CHECK_LIMIT"
  printf '  dsss command: %s\n' "$DSSS_CMD"
}

count_jsonl() {
  local f="$1"
  [[ -s "$f" ]] && awk 'NF{c++} END{print c+0}' "$f" || printf '0'
}

count_csv_data() {
  local f="$1"
  [[ -s "$f" ]] && awk 'NR>1 && NF{c++} END{print c+0}' "$f" || printf '0'
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
        MODE_CLI="fast"
        ;;
      --deep)
        MODE="deep"
        MODE_CLI="deep"
        ;;
      --passive)
        MODE="passive"
        MODE_CLI="passive"
        ;;
      --config)
        shift
        [[ "$#" -gt 0 ]] || usage
        CONFIG_FILE="$1"
        ;;
      --check)
        CHECK_ONLY=1
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
      WEB_PORTS="80,443"
      HTTPX_RL="80"
      NUCLEI_RL="30"
      NUCLEI_C="10"
      KATANA_DEPTH="2"
      FEROX_RL="25"
      FEROX_DEPTH="1"
      FFUF_RATE="50"
      DIR_WL="$(choose_wordlist "$WL_COMMON" "$WL_DIR_SMALL")"
      FILE_WL="__FAST_CRITICAL_FILES__"
      KATANA_DIR_LIMIT="15"
      ;;
    deep)
      WEB_PORTS="$WEB_PORTS_DEEP"
      HTTPX_RL="80"
      NUCLEI_RL="40"
      NUCLEI_C="15"
      KATANA_DEPTH="4"
      FEROX_RL="20"
      FEROX_DEPTH="3"
      FFUF_RATE="20"
      DIR_WL="$(choose_wordlist "$WL_DIR_SMALL" "$WL_COMMON")"
      FILE_WL="$(choose_wordlist "$WL_FILE_SMALL" "$WL_COMMON")"
      KATANA_DIR_LIMIT="50"
      ;;
    passive)
      WEB_PORTS="80,443"
      HTTPX_RL="50"
      NUCLEI_RL="15"
      NUCLEI_C="5"
      KATANA_DEPTH="2"
      FEROX_RL="0"
      FEROX_DEPTH="0"
      FFUF_RATE="0"
      DIR_WL="$(choose_wordlist "$WL_COMMON" "$WL_DIR_SMALL")"
      FILE_WL="__FAST_CRITICAL_FILES__"
      KATANA_DIR_LIMIT="10"
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

clean_url_list() {
  local input="$1"
  local output="$2"

  if [[ -s "$input" ]]; then
    awk 'NF{print $1}' "$input" \
      | sed 's/\r$//' \
      | grep -E '^https?://' \
      | grep -Eiv '(%5c|\\|[[:space:]])' \
      | sort -u >"$output" || true
  else
    : >"$output"
  fi
}

detect_cloudflare() {
  local input="$1"
  [[ -s "$input" ]] || return 1
  grep -Eiq 'cloudflare|cf-ray|cf-cache-status|cf-mitigated|__cf_bm|cf-chl|cdn-cgi' "$input"
}

extract_wafw00f_provider() {
  local input="$1"
  [[ -s "$input" ]] || { printf 'none\n'; return 1; }

  if grep -Eiq 'No WAF detected|generic detection|seems to be behind no WAF|not behind a WAF' "$input"; then
    printf 'none\n'
    return 1
  fi

  if grep -Eiq 'cloudflare' "$input"; then printf 'cloudflare\n'; return 0; fi
  if grep -Eiq 'akamai' "$input"; then printf 'akamai\n'; return 0; fi
  if grep -Eiq 'aws|amazon' "$input"; then printf 'aws_waf\n'; return 0; fi
  if grep -Eiq 'imperva|incapsula' "$input"; then printf 'imperva\n'; return 0; fi
  if grep -Eiq 'sucuri' "$input"; then printf 'sucuri\n'; return 0; fi
  if grep -Eiq 'fastly' "$input"; then printf 'fastly\n'; return 0; fi
  if grep -Eiq 'f5|big-ip' "$input"; then printf 'f5_bigip\n'; return 0; fi
  if grep -Eiq 'barracuda' "$input"; then printf 'barracuda\n'; return 0; fi
  if grep -Eiq 'mod.?security' "$input"; then printf 'modsecurity\n'; return 0; fi
  if grep -Eiq 'fortinet|fortiweb' "$input"; then printf 'fortinet\n'; return 0; fi

  if grep -Eiq 'is behind|behind .*WAF|WAF detected|protected by' "$input"; then
    printf 'generic_waf\n'
    return 0
  fi

  printf 'none\n'
  return 1
}

split_ffuf_403_csv() {
  local input="$1"
  local main_output="$2"
  local cf_output="$3"
  : >"$main_output"
  : >"$cf_output"
  [[ -s "$input" ]] || return 0
  awk -F',' -v main="$main_output" -v cf="$cf_output" '
    NR == 1 {
      header=$0
      status_idx=0
      for (i=1; i<=NF; i++) {
        h=$i
        gsub(/^"|"$/, "", h)
        if (h == "status_code" || h == "status") status_idx=i
      }
      print header > main
      print header > cf
      next
    }
    $0 == header { next }
    {
      status=""
      if (status_idx > 0) {
        status=$status_idx
        gsub(/^"|"$/, "", status)
      }
      if (status == "403") print $0 > cf
      else print $0 > main
    }
  ' "$input" || cp -f "$input" "$main_output"
}

validate_live_url_file() {
  local label="$1"
  local tool="$2"
  local host_out="$3"
  local input="$4"
  local live_output="$5"
  local httpx_output="$6"

  : >"$live_output"
  : >"$httpx_output"

  [[ -s "$input" ]] || return 0

  if have httpx; then
    run_step "$label" "$tool" "$host_out" httpx \
      -l "$input" \
      -silent \
      -sc \
      -cl \
      -title \
      -follow-host-redirects \
      -rl "$HTTPX_RL" \
      -o "$httpx_output" || true

    awk '$0 ~ /\[(200|204|206|301|302|307|308|401|403)\]/ {print $1}' "$httpx_output" \
      | grep -E '^https?://' \
      | sort -u >"$live_output" || true
  else
    cp -f "$input" "$live_output"
  fi
}

extract_context_files() {
  local host_out="$1"
  local all_urls_raw="$host_out/context/all_urls_raw.txt"

  : >"$host_out/context/interesting_files_raw.txt"
  : >"$host_out/context/interesting_files_live.txt"
  : >"$host_out/context/interesting_files.txt"
  : >"$host_out/context/interesting_params.txt"
  : >"$host_out/context/api_candidates_raw.txt"
  : >"$host_out/context/api_candidates_live.txt"
  : >"$host_out/context/api_candidates.txt"
  : >"$host_out/context/js_files_raw.txt"
  : >"$host_out/context/js_files.txt"
  : >"$host_out/context/source_maps.txt"
  : >"$host_out/context/xss_candidates.txt"
  : >"$host_out/context/xss_candidates_active.txt"
  : >"$host_out/context/sqli_candidates_active.txt"
  : >"$host_out/context/redirect_candidates.txt"
  : >"$host_out/context/lfi_candidates.txt"
  : >"$host_out/context/sqli_candidates.txt"

  [[ -s "$all_urls_raw" ]] || return 0

  grep -Ei '\.env($|\?)|\.bak($|\?)|\.backup($|\?)|\.old($|\?)|\.zip($|\?)|\.tar($|\?)|\.gz($|\?)|\.tgz($|\?)|\.rar($|\?)|\.7z($|\?)|\.sql($|\?)|\.db($|\?)|\.sqlite($|\?)|\.log($|\?)|\.config($|\?)|\.conf($|\?)|\.ini($|\?)|\.yml($|\?)|\.yaml($|\?)|\.json($|\?)|\.map($|\?)' "$all_urls_raw" \
    | sort -u >"$host_out/context/interesting_files_raw.txt" || true

  grep -Ei 'redirect=|url=|next=|return=|dest=|destination=|continue=|callback=|file=|path=|folder=|doc=|document=|template=|page=|id=|user=|account=|debug=|token=|key=|secret=|api' "$all_urls_raw" \
    | sort -u >"$host_out/context/interesting_params.txt" || true

  grep -Ei '[?&](q|s|search|query|keyword|term|message|comment|name|email|title|text|content|callback|return|next|url|redirect|dest|destination|continue)=' "$all_urls_raw" \
    | sort -u >"$host_out/context/xss_candidates.txt" || true

  grep -Ei '/api/|/v1/|/v2/|/v3/|graphql|graphiql|swagger|openapi|api-docs|swagger-ui' "$all_urls_raw" \
    | sort -u >"$host_out/context/api_candidates_raw.txt" || true

  grep -Ei '\.js($|\?)' "$all_urls_raw" \
    | sort -u >"$host_out/context/js_files_raw.txt" || true

  grep -Ei '\.map($|\?)' "$all_urls_raw" \
    | sort -u >"$host_out/context/source_maps.txt" || true

  grep -Ei 'redirect=|url=|next=|return=|dest=|destination=|continue=' "$all_urls_raw" \
    | sort -u >"$host_out/context/redirect_candidates.txt" || true

  grep -Ei 'file=|path=|folder=|doc=|document=|template=|page=' "$all_urls_raw" \
    | sort -u >"$host_out/context/lfi_candidates.txt" || true

  grep -Ei 'id=|user=|account=|product=|item=|category=|search=|q=' "$all_urls_raw" \
    | sort -u >"$host_out/context/sqli_candidates.txt" || true
}

validate_live_context_files() {
  local host_out="$1"
  local interesting_clean="$host_out/tmp/interesting_files_clean.txt"
  local api_clean="$host_out/tmp/api_candidates_clean.txt"

  clean_url_list "$host_out/context/interesting_files_raw.txt" "$interesting_clean"
  clean_url_list "$host_out/context/api_candidates_raw.txt" "$api_clean"

  validate_live_url_file "httpx (interesting files)" "httpx_interesting_files" "$host_out" \
    "$interesting_clean" \
    "$host_out/context/interesting_files_live.txt" \
    "$host_out/context/interesting_files_httpx.txt"

  validate_live_url_file "httpx (api candidates)" "httpx_api_candidates" "$host_out" \
    "$api_clean" \
    "$host_out/context/api_candidates_live.txt" \
    "$host_out/context/api_candidates_httpx.txt"

  cp -f "$host_out/context/interesting_files_live.txt" "$host_out/context/interesting_files.txt"
  cp -f "$host_out/context/api_candidates_live.txt" "$host_out/context/api_candidates.txt"
}

validate_live_js_files() {
  local host_out="$1"
  local raw_js="$host_out/context/js_files_raw.txt"
  local clean_js="$host_out/tmp/js_files_clean.txt"
  local live_js="$host_out/context/js_files.txt"
  local js_httpx="$host_out/context/js_httpx.txt"

  clean_url_list "$raw_js" "$clean_js"
  : >"$js_httpx"

  [[ -s "$clean_js" ]] || {
    : >"$live_js"
    return 0
  }

  if have httpx; then
    run_step "httpx (js files)" "httpx_js" "$host_out" httpx \
      -l "$clean_js" \
      -silent \
      -sc \
      -cl \
      -title \
      -follow-host-redirects \
      -rl "$HTTPX_RL" \
      -o "$js_httpx" || true

    awk '$0 ~ /\[(200|204|206|301|302|307|308)\]/ {print $1}' "$js_httpx" \
      | grep -Ei '\.js($|\?)' \
      | sort -u >"$live_js" || true
  else
    cp -f "$clean_js" "$live_js"
  fi
}

prepare_active_param_candidates() {
  local source_file="$1"
  local live_urls="$2"
  local output_file="$3"
  local limit="${4:-0}"
  local tmp_clean="${output_file}.clean.tmp"
  local tmp_live="${output_file}.live.tmp"

  : >"$output_file"
  : >"$tmp_clean"
  : >"$tmp_live"

  clean_url_list "$source_file" "$tmp_clean"
  [[ -s "$tmp_clean" ]] || {
    rm -f "$tmp_clean" "$tmp_live"
    return 0
  }

  if [[ -s "$live_urls" ]]; then
    grep -Fxf "$tmp_clean" "$live_urls" | sort -u >"$tmp_live" || true
  else
    cp -f "$tmp_clean" "$tmp_live"
  fi

  if [[ -s "$tmp_live" ]]; then
    if [[ "$limit" =~ ^[0-9]+$ && "$limit" -gt 0 ]]; then
      head -n "$limit" "$tmp_live" >"$output_file"
    else
      cp -f "$tmp_live" "$output_file"
    fi
  fi

  rm -f "$tmp_clean" "$tmp_live"
}

run_dalfox_check() {
  local host_out="$1"
  local input_file="$2"
  local output_file="$host_out/reports/dalfox_xss.txt"
  : >"$output_file"

  if [[ ! -s "$input_file" ]]; then
    print_skip "dalfox xss (no candidates)"
    return 0
  fi

  if have dalfox; then
    run_step_limited "dalfox xss" "dalfox_xss" "$host_out" dalfox file "$input_file" --silence --output "$output_file" || true
  else
    print_skip "dalfox xss (not installed)"
  fi
}

run_dsss_check() {
  local host_out="$1"
  local input_file="$2"
  local output_file="$host_out/reports/dsss_sqli.txt"
  : >"$output_file"

  if [[ ! -s "$input_file" ]]; then
    print_skip "dsss sqli (no candidates)"
    return 0
  fi

  if have "$DSSS_CMD" || { [[ -f "$DSSS_CMD" ]] && have python3; }; then
    run_step_limited "dsss sqli" "dsss_sqli" "$host_out" \
      bash -c '
        set -euo pipefail
        cmd="$1"
        input="$2"
        output="$3"
        : >"$output"
        while IFS= read -r url; do
          [[ -n "$url" ]] || continue
          printf "### %s\n" "$url" >>"$output"
          if [[ -f "$cmd" ]]; then
            python3 "$cmd" -u "$url" >>"$output" 2>&1 || true
          else
            "$cmd" -u "$url" >>"$output" 2>&1 || true
          fi
          printf "\n" >>"$output"
        done <"$input"
      ' bash "$DSSS_CMD" "$input_file" "$output_file" || true
  else
    print_skip "dsss sqli (not installed)"
  fi
}

count_file() {
  local f="$1"
  if [[ -s "$f" ]]; then
    wc -l <"$f" | tr -d ' '
  else
    printf '0'
  fi
}

write_host_summary() {
  local host_out="$1"
  local host="$2"
  local host_elapsed="${3:-0}"
  local summary="$host_out/reports/summary.md"
  local cf="no"
  local edge="unknown"
  local waf="no"
  local waf_provider="none"
  local nmap_mode="unknown"
  local nmap_ports=""
  local cf_note=""
  local status_file="$host_out/context/tool_status.tsv"
  local ok_count=0
  local missing_count=0
  local failed_count=0
  local skipped_count=0
  local empty_count=0
  local timeout_count=0
  local interrupted_count=0

  mkdir -p "$host_out/reports"
  local BT=$'\x60'

  [[ -f "$host_out/context/cloudflare_detected.txt" ]] && cf="$(cat "$host_out/context/cloudflare_detected.txt" 2>/dev/null | head -n 1)"
  [[ -f "$host_out/context/edge_provider.txt" ]] && edge="$(cat "$host_out/context/edge_provider.txt" 2>/dev/null | head -n 1)"
  [[ -f "$host_out/context/waf_detected.txt" ]] && waf="$(cat "$host_out/context/waf_detected.txt" 2>/dev/null | head -n 1)"
  [[ -f "$host_out/context/waf_provider.txt" ]] && waf_provider="$(cat "$host_out/context/waf_provider.txt" 2>/dev/null | head -n 1)"
  [[ -f "$host_out/context/nmap_mode.txt" ]] && nmap_mode="$(cat "$host_out/context/nmap_mode.txt" 2>/dev/null | head -n 1)"
  [[ -f "$host_out/context/nmap_ports.txt" ]] && nmap_ports="$(cat "$host_out/context/nmap_ports.txt" 2>/dev/null | head -n 1)"

  if [[ "$cf" == "yes" || "$waf" == "yes" ]]; then
    cf_note="Cloudflare/WAF/CDN was detected. Treat 403 results as low-confidence edge/WAF responses unless the body confirms a real resource. nmap and sslscan may describe the edge, not the origin."
  else
    cf_note="No Cloudflare/WAF/CDN signal detected by ScopeWise."
  fi

  if [[ -s "$status_file" ]]; then
    ok_count="$(awk -F'\t' '$2=="ok"{c++} END{print c+0}' "$status_file")"
    missing_count="$(awk -F'\t' '$2=="missing"{c++} END{print c+0}' "$status_file")"
    failed_count="$(awk -F'\t' '$2=="failed"{c++} END{print c+0}' "$status_file")"
    skipped_count="$(awk -F'\t' '$2=="skipped"{c++} END{print c+0}' "$status_file")"
    empty_count="$(awk -F'\t' '$2=="empty"{c++} END{print c+0}' "$status_file")"
    timeout_count="$(awk -F'\t' '$2=="timeout"{c++} END{print c+0}' "$status_file")"
    interrupted_count="$(awk -F'\t' '$2=="interrupted"{c++} END{print c+0}' "$status_file")"
  fi

  cat >"$summary" <<EOF_SUMMARY
# ScopeWise Summary: $host

## Overview

| Field | Value |
|---|---:|
| Host | $host |
| Mode | $MODE |
| Cloudflare | $cf |
| Edge provider | $edge |
| WAF/CDN detected | $waf |
| WAF/CDN provider | $waf_provider |
| Nmap mode | $nmap_mode |
| Nmap ports | $nmap_ports |
| Host time | $(format_duration "$host_elapsed") |
| Live URLs | $(count_file "$host_out/context/all_urls_live.txt") |
| Raw URLs | $(count_file "$host_out/context/all_urls_raw.txt") |
| Interesting files live | $(count_file "$host_out/context/interesting_files_live.txt") |
| Interesting files raw | $(count_file "$host_out/context/interesting_files_raw.txt") |
| API candidates live | $(count_file "$host_out/context/api_candidates_live.txt") |
| API candidates raw | $(count_file "$host_out/context/api_candidates_raw.txt") |
| Live JS files | $(count_file "$host_out/context/js_files.txt") |
| JS candidates raw | $(count_file "$host_out/context/js_files_raw.txt") |
| Subdomains | $(count_file "$host_out/context/subdomains.txt") |
| Live subdomains | $(count_file "$host_out/context/live_subdomains.txt") |
| Live subdomain URLs | $(count_file "$host_out/context/live_subdomain_urls.txt") |
| XSS candidates | $(count_file "$host_out/context/xss_candidates.txt") |
| XSS active candidates | $(count_file "$host_out/context/xss_candidates_active.txt") |
| SQLi candidates | $(count_file "$host_out/context/sqli_candidates.txt") |
| SQLi active candidates | $(count_file "$host_out/context/sqli_candidates_active.txt") |
| Nuclei findings | $(count_jsonl "$host_out/reports/nuclei.jsonl") |
| Nuclei exposure findings | $(count_jsonl "$host_out/reports/nuclei_exposures.jsonl") |
| Nuclei takeover findings | $(count_jsonl "$host_out/reports/nuclei_takeover.jsonl") |
| Nuclei JS findings | $(count_jsonl "$host_out/reports/nuclei_js_exposure.jsonl") |
| Dalfox output lines | $(count_file "$host_out/reports/dalfox_xss.txt") |
| DSSS output lines | $(count_file "$host_out/reports/dsss_sqli.txt") |
| FFUF dirs | $(count_csv_data "$host_out/reports/ffuf_dirs.csv") |
| FFUF dirs 403 | $(count_csv_data "$host_out/reports/ffuf_dirs_403.csv") |
| FFUF files | $(count_csv_data "$host_out/reports/ffuf_files.csv") |
| FFUF files 403 | $(count_csv_data "$host_out/reports/ffuf_files_403.csv") |
| FFUF katana dirs | $(count_csv_data "$host_out/reports/ffuf_katana_dirs.csv") |
| FFUF katana dirs 403 | $(count_csv_data "$host_out/reports/ffuf_katana_dirs_403.csv") |
| Ferox filtered | $(count_file "$host_out/reports/feroxbuster.txt") |
| Ferox raw | $(count_file "$host_out/reports/feroxbuster.raw.txt") |
| Ferox 403 filtered | $(count_file "$host_out/reports/feroxbuster_403_filtered.txt") |

## Cloudflare / WAF Note

$cf_note

## Interruption / Timeout Note

Ctrl+C skips the currently running step, preserves partial output when the underlying tool has already written it, and continues with the next step. Long non-core scan steps have a configurable timeout. Default step timeout: $STEP_MAX_SECONDS seconds.

## Review First

- ${BT}reports/nuclei_exposures.jsonl${BT} \u2013 exposed files, backups, configs, logs, misconfigs
- ${BT}reports/nuclei_takeover.jsonl${BT} \u2013 possible subdomain takeover findings
- ${BT}reports/nuclei.jsonl${BT} \u2013 general nuclei findings
- ${BT}reports/nikto.json${BT} \u2013 Nikto output, if available
- ${BT}reports/nmap_web.xml${BT} \u2013 nmap scan; ports depend on WAF/CDN detection and mode
- ${BT}reports/wafw00f.txt${BT} \u2013 WAF/CDN detection output, if available
- ${BT}reports/sslscan.xml${BT} \u2013 TLS scan
- ${BT}context/interesting_files_live.txt${BT} \u2013 live interesting files
- ${BT}context/api_candidates_live.txt${BT} \u2013 live API candidates
- ${BT}context/js_files.txt${BT} \u2013 live JavaScript files
- ${BT}context/interesting_params.txt${BT} \u2013 raw parameter review queue
- ${BT}context/source_maps.txt${BT} \u2013 source map candidates
- ${BT}reports/feroxbuster.txt${BT} \u2013 filtered ferox results
- ${BT}reports/ffuf_files.csv${BT} \u2013 file discovery results
- ${BT}reports/ffuf_dirs.csv${BT} \u2013 directory discovery results
- ${BT}reports/subzy.json${BT} \u2013 takeover checks
- ${BT}reports/gowitness/${BT} \u2013 screenshots and gowitness database/exports

## Raw / Historical Context

- ${BT}context/all_urls_raw.txt${BT}
- ${BT}context/all_urls.txt${BT}
- ${BT}context/interesting_files_raw.txt${BT}
- ${BT}context/api_candidates_raw.txt${BT}
- ${BT}context/js_files_raw.txt${BT}
- ${BT}context/xss_candidates.txt${BT}
- ${BT}context/xss_candidates_active.txt${BT}
- ${BT}context/sqli_candidates_active.txt${BT}
- ${BT}context/waybackurls.txt${BT}
- ${BT}context/subdomains.txt${BT}
- ${BT}context/subdomain_urls_source.txt${BT}
- ${BT}context/live_subdomains.txt${BT}
- ${BT}context/live_subdomain_urls.txt${BT}
- ${BT}context/waf_detected.txt${BT}
- ${BT}context/waf_provider.txt${BT}
- ${BT}context/nmap_mode.txt${BT}
- ${BT}context/nmap_ports.txt${BT}
- ${BT}reports/subdomains_httpx.txt${BT}
- ${BT}reports/wafw00f.txt${BT}
- ${BT}reports/feroxbuster.raw.txt${BT}

## Low-Confidence 403 Queues

- ${BT}reports/ffuf_dirs_403.csv${BT}
- ${BT}reports/ffuf_files_403.csv${BT}
- ${BT}reports/ffuf_katana_dirs_403.csv${BT}
- ${BT}reports/feroxbuster_403_filtered.txt${BT}

## Manual Queues

- ${BT}context/xss_candidates.txt${BT}
- ${BT}context/redirect_candidates.txt${BT}
- ${BT}context/lfi_candidates.txt${BT}
- ${BT}context/sqli_candidates.txt${BT}
- ${BT}context/interesting_params.txt${BT}

## Gowitness Review

From this host folder:

${BT}${BT}${BT}bash
gowitness report server \\\
  --db-uri "sqlite://reports/gowitness/gowitness.sqlite3" \\\
  --screenshot-path "reports/gowitness/screenshots"
${BT}${BT}${BT}

Then open:

${BT}${BT}${BT}text
http://127.0.0.1:7171
${BT}${BT}${BT}

## Tool Status

| Status | Count |
|---|---:|
| OK | $ok_count |
| Missing | $missing_count |
| Failed | $failed_count |
| Empty output | $empty_count |
| Timeout | $timeout_count |
| Interrupted | $interrupted_count |
| Skipped | $skipped_count |

Full status file: ${BT}context/tool_status.tsv${BT}

## Troubleshooting

- ${BT}debug/*.stdout${BT}
- ${BT}debug/*.stderr${BT}
- ${BT}tmp/${BT}
EOF_SUMMARY
}


parse_args "$@"
if [[ -z "$CONFIG_FILE" && -f "scopewise.yml" ]]; then
  CONFIG_FILE="scopewise.yml"
fi
if [[ -n "$CONFIG_FILE" ]]; then
  if [[ ! -f "$CONFIG_FILE" ]]; then
    print_fail "Config file not found: $CONFIG_FILE"
    exit 1
  fi
  load_config "$CONFIG_FILE"
fi
if [[ -n "$MODE_CLI" ]]; then
  MODE="$MODE_CLI"
fi
configure_mode
apply_config_overrides
if [[ "$CHECK_ONLY" -eq 1 ]]; then
  run_dependency_check
  exit 0
fi
banner
RUN_START_TS="$(date +%s)"

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

    host_start_ts="$(date +%s)"
    host_out="$OUT_DIR/$host"
    mkdir -p "$host_out/reports" "$host_out/context" "$host_out/debug" "$host_out/tmp"
    TOOL_STATUS_FILE="$host_out/context/tool_status.tsv"
    : >"$TOOL_STATUS_FILE"
    if [[ "$FILE_WL" == "__FAST_CRITICAL_FILES__" ]]; then
      FILE_WL="$host_out/tmp/critical-files.txt"
      write_fast_file_wordlist "$FILE_WL"
    fi
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

    CLOUDFLARE_DETECTED=0
    WAF_DETECTED=0
    EDGE_OR_WAF_DETECTED=0
    WAF_PROVIDER="none"
    EDGE_PROVIDER_FILE="$host_out/context/edge_provider.txt"
    CLOUDFLARE_FILE="$host_out/context/cloudflare_detected.txt"
    WAF_FILE="$host_out/context/waf_detected.txt"
    WAF_PROVIDER_FILE="$host_out/context/waf_provider.txt"
    if detect_cloudflare "$HOST_HTTPX_RAW"; then
      CLOUDFLARE_DETECTED=1
      EDGE_OR_WAF_DETECTED=1
      WAF_DETECTED=1
      WAF_PROVIDER="cloudflare"
      printf 'yes\n' >"$CLOUDFLARE_FILE"
      printf 'cloudflare\n' >"$EDGE_PROVIDER_FILE"
      print_warn "Cloudflare detected; 403, nmap, sslscan and nikto results may describe edge/WAF behavior"
      log_line "WARN: Cloudflare detected for ${host}"
    else
      printf 'no\n' >"$CLOUDFLARE_FILE"
      printf 'unknown\n' >"$EDGE_PROVIDER_FILE"
    fi

    if have wafw00f; then
      run_step_limited "wafw00f" "wafw00f" "$host_out" wafw00f "$BEST_URL" -a || true
      cp -f "$host_out/debug/wafw00f.stdout" "$host_out/reports/wafw00f.txt" 2>/dev/null || true
      waf_provider_found="$(extract_wafw00f_provider "$host_out/reports/wafw00f.txt" 2>/dev/null || true)"
      if [[ -n "$waf_provider_found" && "$waf_provider_found" != "none" ]]; then
        WAF_DETECTED=1
        EDGE_OR_WAF_DETECTED=1
        WAF_PROVIDER="$waf_provider_found"
        print_warn "WAF/CDN detected by wafw00f: $WAF_PROVIDER"
        log_line "WARN: wafw00f detected ${WAF_PROVIDER} for ${host}"
      fi
    else
      print_skip "wafw00f (not installed)"
    fi

    if [[ "$WAF_DETECTED" -eq 1 ]]; then
      printf 'yes\n' >"$WAF_FILE"
      printf '%s\n' "$WAF_PROVIDER" >"$WAF_PROVIDER_FILE"
    else
      printf 'no\n' >"$WAF_FILE"
      printf 'none\n' >"$WAF_PROVIDER_FILE"
    fi

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

    ALL_URLS_RAW="$host_out/context/all_urls_raw.txt"
    ALL_URLS_LIVE="$host_out/context/all_urls_live.txt"
    ALL_URLS="$host_out/context/all_urls.txt"
    ALL_URLS_CLEAN="$host_out/tmp/all_urls_clean.txt"
    ALL_URLS_HTTPX="$host_out/context/all_urls_httpx.txt"

    cat "$HOST_URLS" "$KATANA_URLS" "$WAYBACK_URLS" 2>/dev/null \
      | awk 'NF{print}' \
      | sed 's/\r$//' \
      | sort -u >"$ALL_URLS_RAW"

    cp -f "$ALL_URLS_RAW" "$ALL_URLS"

    clean_url_list "$ALL_URLS_RAW" "$ALL_URLS_CLEAN"
    validate_live_url_file "httpx (all urls)" "httpx_all_urls" "$host_out" \
      "$ALL_URLS_CLEAN" "$ALL_URLS_LIVE" "$ALL_URLS_HTTPX"

    extract_context_files "$host_out"
    validate_live_context_files "$host_out"
    validate_live_js_files "$host_out"

    print_done "all urls raw: $(count_file "$ALL_URLS_RAW")"
    print_done "all urls live: $(count_file "$ALL_URLS_LIVE")"
    print_done "interesting files raw: $(count_file "$host_out/context/interesting_files_raw.txt")"
    print_done "interesting files live: $(count_file "$host_out/context/interesting_files_live.txt")"
    print_done "interesting params: $(count_file "$host_out/context/interesting_params.txt")"
    print_done "api candidates raw: $(count_file "$host_out/context/api_candidates_raw.txt")"
    print_done "api candidates live: $(count_file "$host_out/context/api_candidates_live.txt")"
    print_done "js candidates: $(count_file "$host_out/context/js_files_raw.txt")"
    print_done "live js files: $(count_file "$host_out/context/js_files.txt")"
    PARAM_XSS_ACTIVE="$host_out/context/xss_candidates_active.txt"
    PARAM_SQLI_ACTIVE="$host_out/context/sqli_candidates_active.txt"
    prepare_active_param_candidates "$host_out/context/xss_candidates.txt" "$ALL_URLS_LIVE" "$PARAM_XSS_ACTIVE" "$PARAM_CHECK_LIMIT"
    prepare_active_param_candidates "$host_out/context/sqli_candidates.txt" "$ALL_URLS_LIVE" "$PARAM_SQLI_ACTIVE" "$PARAM_CHECK_LIMIT"

    print_done "xss candidates: $(count_file "$host_out/context/xss_candidates.txt")"
    print_done "xss active candidates: $(count_file "$PARAM_XSS_ACTIVE")"
    print_done "sqli candidates: $(count_file "$host_out/context/sqli_candidates.txt")"
    print_done "sqli active candidates: $(count_file "$PARAM_SQLI_ACTIVE")"

    run_dalfox_check "$host_out" "$PARAM_XSS_ACTIVE"
    run_dsss_check "$host_out" "$PARAM_SQLI_ACTIVE"

    if have nuclei; then
      run_step_limited "nuclei general" "nuclei_general" "$host_out" nuclei \
        -l "$HOST_URLS" \
        -severity medium,high,critical \
        -stats \
        -jsonl \
        -o "$host_out/reports/nuclei.jsonl" \
        -rl "$NUCLEI_RL" \
        -c "$NUCLEI_C" \
        -timeout 10 \
        -retries 2 || true

      run_step_limited "nuclei exposures" "nuclei_exposures" "$host_out" nuclei \
        -l "$HOST_URLS" \
        -tags exposure,misconfig,files,logs,backup,config \
        -jsonl \
        -o "$host_out/reports/nuclei_exposures.jsonl" \
        -rl "$NUCLEI_RL" \
        -c "$NUCLEI_C" \
        -timeout 10 \
        -retries 2 || true

      run_step_limited "nuclei takeover" "nuclei_takeover" "$host_out" nuclei \
        -l "$HOST_URLS" \
        -tags takeover \
        -jsonl \
        -o "$host_out/reports/nuclei_takeover.jsonl" \
        -rl "$NUCLEI_RL" \
        -c "$NUCLEI_C" \
        -timeout 10 \
        -retries 2 || true

      if [[ -s "$host_out/context/js_files.txt" ]]; then
        run_step_limited "nuclei js exposure" "nuclei_js_exposure" "$host_out" nuclei \
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
        if [[ "${EDGE_OR_WAF_DETECTED:-0}" -eq 1 ]]; then
          NMAP_PORTS_SELECTED="$NMAP_WEB_PORTS"
          NMAP_MODE="edge_web_ports"
        else
          NMAP_PORTS_SELECTED="$NMAP_RECON_PORTS"
          NMAP_MODE="recon_ports"
        fi
        printf '%s\n' "$NMAP_PORTS_SELECTED" >"$host_out/context/nmap_ports.txt"
        printf '%s\n' "$NMAP_MODE" >"$host_out/context/nmap_mode.txt"
        if [[ "$MODE" == "deep" ]]; then
          run_step_limited "nmap" "nmap" "$host_out" nmap \
            -sS \
            -sV \
            -sC \
            -T3 \
            -p "$NMAP_PORTS_SELECTED" \
            -oA "$host_out/reports/nmap_web" \
            "$host" || true
        else
          run_step_limited "nmap" "nmap" "$host_out" nmap \
            -sS \
            -sV \
            --version-light \
            -T3 \
            -p "$NMAP_PORTS_SELECTED" \
            -oA "$host_out/reports/nmap_web" \
            "$host" || true
        fi
      else
        print_skip "nmap (not installed)"
      fi
    else
      print_skip "nmap (passive mode)"
    fi

    if [[ "$MODE" != "passive" ]]; then
      if have nikto; then
        nikto_base="$host_out/reports/nikto"
        nikto_json="$host_out/reports/nikto.json"
        rm -f "$nikto_json" "$host_out/reports/nikto.json.json" 2>/dev/null || true

        run_step_limited "nikto" "nikto" "$host_out" --soft-rcs "1" \
          nikto -h "$BEST_URL" -Format json -output "$nikto_base" || true

        if [[ -s "$nikto_base.json" && "$nikto_base.json" != "$nikto_json" ]]; then
          mv -f "$nikto_base.json" "$nikto_json"
        elif [[ -s "$host_out/reports/nikto.json.json" && "$host_out/reports/nikto.json.json" != "$nikto_json" ]]; then
          mv -f "$host_out/reports/nikto.json.json" "$nikto_json"
        fi

        if [[ ! -s "$nikto_json" ]]; then
          print_warn "nikto json empty"
          record_tool_status "nikto" "empty" "nikto json empty"
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
        run_step_limited "sslscan" "sslscan" "$host_out" sslscan \
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
        run_step_limited "ffuf dirs" "ffuf_dirs" "$host_out" ffuf \
          -u "${BEST_URL%/}/FUZZ" \
          -w "$DIR_WL" \
          -mc 200,204,301,302,307,308,401,403,405,500 \
          -ac \
          -rate "$FFUF_RATE" \
          -of csv \
          -o "$host_out/reports/ffuf_dirs.csv" || true
        if [[ "${EDGE_OR_WAF_DETECTED:-0}" -eq 1 && -s "$host_out/reports/ffuf_dirs.csv" ]]; then
          split_ffuf_403_csv "$host_out/reports/ffuf_dirs.csv" "$host_out/reports/ffuf_dirs.no403.csv" "$host_out/reports/ffuf_dirs_403.csv"
          mv -f "$host_out/reports/ffuf_dirs.no403.csv" "$host_out/reports/ffuf_dirs.csv"
          print_done "ffuf dirs 403 split: $(count_file "$host_out/reports/ffuf_dirs_403.csv") lines"
        fi

        if [[ "$MODE" == "fast" || "$MODE" == "passive" ]]; then
          run_step_limited "ffuf files" "ffuf_files" "$host_out" ffuf \
            -u "${BEST_URL%/}/FUZZ" \
            -w "$FILE_WL" \
            -mc 200,204,301,302,307,308,401,403,405,500 \
            -ac \
            -rate "$FFUF_RATE" \
            -of csv \
            -o "$host_out/reports/ffuf_files.csv" || true
        else
          run_step_limited "ffuf files" "ffuf_files" "$host_out" ffuf \
            -u "${BEST_URL%/}/FUZZ" \
            -w "$FILE_WL" \
            -e "$FFUF_EXTENSIONS" \
            -mc 200,204,301,302,307,308,401,403,405,500 \
            -ac \
            -rate "$FFUF_RATE" \
            -of csv \
            -o "$host_out/reports/ffuf_files.csv" || true
        fi
        if [[ "${EDGE_OR_WAF_DETECTED:-0}" -eq 1 && -s "$host_out/reports/ffuf_files.csv" ]]; then
          split_ffuf_403_csv "$host_out/reports/ffuf_files.csv" "$host_out/reports/ffuf_files.no403.csv" "$host_out/reports/ffuf_files_403.csv"
          mv -f "$host_out/reports/ffuf_files.no403.csv" "$host_out/reports/ffuf_files.csv"
          print_done "ffuf files 403 split: $(count_file "$host_out/reports/ffuf_files_403.csv") lines"
        fi
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
          if (u ~ "^https?://" h "(:[0-9]+)?(/|$)" &&
              u !~ /(%5[Cc]|\\\\|[[:space:]])/ &&
              $0 ~ /\[(200|204|206|301|302|307|308|401|403)\]/) {
            sub(/[?#].*$/,"",u)
            if (u ~ /\/[^\/]*$/) sub(/\/[^\/]*$/,"/",u)
            if (u ~ /^https?:\/\/[^\/]+\/.*/) print u
          }
        }
      ' "$KATANA_HTTPX" | sort -u | head -n "$KATANA_DIR_LIMIT" >"$KATANA_DIRS"
    fi

    if [[ "$MODE" != "passive" ]]; then
      if have ffuf && [[ -s "$KATANA_DIRS" ]]; then
        if [[ "$MODE" == "fast" ]]; then
          KATANA_FFUF_WL="$host_out/tmp/katana-fast-wordlist.txt"
          write_fast_katana_wordlist "$KATANA_FFUF_WL"
        else
          KATANA_FFUF_WL="$WL_COMMON"
        fi

        run_step_limited "ffuf (katana dirs)" "ffuf_katana_dirs" "$host_out" \
          bash -c '
            set -euo pipefail
            out="$1"
            : > "$out"
            while IFS= read -r base_dir; do
              [[ -n "$base_dir" ]] || continue
              case "$base_dir" in
                *"%5C"*|*"%5c"*|*\\*) continue ;;
              esac
              tmp_out="${out}.tmp.$RANDOM.csv"
              ffuf -u "${base_dir%/}/FUZZ" -w "$2" \
                -mc 200,204,301,302,307,308,401,403,405,500 \
                -ac -rate "$3" -of csv -o "$tmp_out" >/dev/null 2>&1 || true
              if [[ -s "$tmp_out" ]]; then
                if [[ ! -s "$out" ]]; then
                  cat "$tmp_out" >> "$out"
                else
                  tail -n +2 "$tmp_out" >> "$out"
                fi
              fi
              rm -f "$tmp_out"
            done < "$4"
          ' bash "$host_out/reports/ffuf_katana_dirs.csv" "$KATANA_FFUF_WL" "$FFUF_RATE" "$KATANA_DIRS" || true
        if [[ "${EDGE_OR_WAF_DETECTED:-0}" -eq 1 && -s "$host_out/reports/ffuf_katana_dirs.csv" ]]; then
          split_ffuf_403_csv "$host_out/reports/ffuf_katana_dirs.csv" "$host_out/reports/ffuf_katana_dirs.no403.csv" "$host_out/reports/ffuf_katana_dirs_403.csv"
          mv -f "$host_out/reports/ffuf_katana_dirs.no403.csv" "$host_out/reports/ffuf_katana_dirs.csv"
          print_done "ffuf katana dirs 403 split: $(count_file "$host_out/reports/ffuf_katana_dirs_403.csv") lines"
        fi
      else
        print_skip "ffuf (katana dirs)"
      fi
    else
      print_skip "ffuf (katana dirs) (passive mode)"
    fi

    if [[ "$MODE" != "passive" ]]; then
      if have feroxbuster; then
        export STATE_FILENAME="$host_out/tmp/ferox-stdin-data.state"
        if [[ "$MODE" == "fast" ]]; then
          FEROX_FAST_WL="$host_out/tmp/ferox-fast-words.txt"
          FEROX_RAW="$host_out/reports/feroxbuster.raw.txt"
          FEROX_CLEAN="$host_out/reports/feroxbuster.txt"
          FEROX_403_FILTERED="$host_out/reports/feroxbuster_403_filtered.txt"
          write_fast_ferox_wordlist "$FEROX_FAST_WL"
          run_step_limited "feroxbuster" "feroxbuster" "$host_out" feroxbuster \
            -u "$BEST_URL" \
            -w "$FEROX_FAST_WL" \
            -x "$FEROX_FAST_EXTENSIONS" \
            -s 200,204,301,302,307,308,401,403,405 \
            -k \
            --random-agent \
            --rate-limit "$FEROX_RL" \
            --depth 1 \
            --dont-extract-links \
            --quiet \
            -o "$FEROX_RAW" || true
          filter_ferox_fast_output "$FEROX_RAW" "$FEROX_CLEAN" "$FEROX_403_FILTERED" "${EDGE_OR_WAF_DETECTED:-0}"
          if [[ -s "$FEROX_RAW" ]]; then
            print_done "feroxbuster filtered: $(count_file "$FEROX_CLEAN")/$(count_file "$FEROX_RAW") lines kept"
            log_line "DONE: feroxbuster filtered $(count_file "$FEROX_CLEAN")/$(count_file "$FEROX_RAW") lines kept; filtered_403=$(count_file "$FEROX_403_FILTERED")"
          fi
        else
          run_step_limited "feroxbuster" "feroxbuster" "$host_out" feroxbuster \
            -u "$BEST_URL" \
            -w "$DIR_WL" \
            -x "$EXTENSIONS" \
            -s 200,204,301,302,307,308,401,403,405,500 \
            -k \
            --random-agent \
            --rate-limit "$FEROX_RL" \
            --depth "$FEROX_DEPTH" \
            --quiet \
            -o "$host_out/reports/feroxbuster.txt" || true
        fi
        unset STATE_FILENAME
      else
        print_skip "feroxbuster (not installed)"
      fi
    else
      print_skip "feroxbuster (passive mode)"
    fi

    SUB_WORK="$host_out/tmp/subdomains_work"
    mkdir -p "$SUB_WORK"

    if have subfinder; then
      run_step_limited "subfinder" "subfinder" "$host_out" subfinder \
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
      run_step_limited "bbot" "bbot" "$host_out" bbot \
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

    SUBDOMAIN_URLS_SOURCE="$host_out/context/subdomain_urls_source.txt"
    LIVE_SUBDOMAIN_URLS="$host_out/context/live_subdomain_urls.txt"
    LIVE_SUBDOMAINS="$host_out/context/live_subdomains.txt"
    SUBDOMAINS_HTTPX="$host_out/reports/subdomains_httpx.txt"
    : >"$SUBDOMAIN_URLS_SOURCE"
    : >"$LIVE_SUBDOMAIN_URLS"
    : >"$LIVE_SUBDOMAINS"
    : >"$SUBDOMAINS_HTTPX"

    if [[ -s "$SUBS_COMBINED" ]]; then
      while IFS= read -r sub; do
        [[ -n "$sub" ]] || continue
        printf 'https://%s\n' "$sub"
        printf 'http://%s\n' "$sub"
      done <"$SUBS_COMBINED" | sort -u >"$SUBDOMAIN_URLS_SOURCE"

      if have httpx; then
        run_step_limited "httpx (subdomains)" "httpx_subdomains" "$host_out" httpx \
          -l "$SUBDOMAIN_URLS_SOURCE" \
          -silent \
          -sc \
          -cl \
          -title \
          -tech-detect \
          -follow-host-redirects \
          -ports "$WEB_PORTS" \
          -rl "$HTTPX_RL" \
          -o "$SUBDOMAINS_HTTPX" || true
        awk '$0 ~ /\[(200|204|206|301|302|307|308|401|403)\]/ {print $1}' "$SUBDOMAINS_HTTPX" \
          | grep -E '^https?://' \
          | sort -u >"$LIVE_SUBDOMAIN_URLS" || true
      else
        print_skip "httpx (subdomains) (not installed)"
      fi

      if [[ -s "$LIVE_SUBDOMAIN_URLS" ]]; then
        while IFS= read -r live_url; do
          url_host "$live_url"
        done <"$LIVE_SUBDOMAIN_URLS" | sort -u >"$LIVE_SUBDOMAINS"
      fi
    else
      print_skip "httpx (subdomains) (no subdomains)"
    fi

    print_done "live subdomains: $(count_file "$LIVE_SUBDOMAINS")"
    print_done "live subdomain urls: $(count_file "$LIVE_SUBDOMAIN_URLS")"

    GOWITNESS_TARGETS="$host_out/tmp/gowitness_targets.txt"
    {
      cat "$HOST_URLS" 2>/dev/null || true
      cat "$LIVE_SUBDOMAIN_URLS" 2>/dev/null || true
    } | awk 'NF{print}' | sort -u >"$GOWITNESS_TARGETS"

    if have gowitness; then
      mkdir -p "$host_out/reports/gowitness/screenshots"
      if [[ -s "$GOWITNESS_TARGETS" ]]; then
        run_step_limited "gowitness" "gowitness" "$host_out" gowitness scan file \
          -f "$GOWITNESS_TARGETS" \
          --screenshot-path "$host_out/reports/gowitness/screenshots" \
          --write-db \
          --write-db-uri "sqlite://$host_out/reports/gowitness/gowitness.sqlite3" \
          --write-jsonl \
          --write-jsonl-file "$host_out/reports/gowitness/gowitness.jsonl" \
          --write-csv \
          --write-csv-file "$host_out/reports/gowitness/gowitness.csv" || true
      else
        print_skip "gowitness (no targets)"
      fi
    else
      print_skip "gowitness (not installed)"
    fi

    if have subzy; then
      if [[ -s "$SUBS_COMBINED" ]]; then
        run_step_limited "subzy" "subzy" "$host_out" subzy run \
          --targets "$SUBS_COMBINED" \
          --output "$host_out/reports/subzy.json" || true
      else
        print_skip "subzy (no subdomains)"
      fi
    else
      print_skip "subzy (not installed)"
    fi

    host_elapsed=$(( $(date +%s) - host_start_ts ))
    write_host_summary "$host_out" "$host" "$host_elapsed"
    printf '%s	%s	%s	%s	%s	%s	%s	%s	%s
' "$host" "${CLOUDFLARE_DETECTED:-0}" "$(count_file "$host_out/context/all_urls_live.txt")" "$(count_file "$host_out/context/interesting_files_live.txt")" "$(count_file "$host_out/context/api_candidates_live.txt")" "$(count_file "$host_out/context/js_files.txt")" "$(count_jsonl "$host_out/reports/nuclei.jsonl")" "$(count_csv_data "$host_out/reports/ffuf_dirs.csv")" "$(count_file "$host_out/reports/feroxbuster.txt")" >>"$RUN_DIR/host_summary.tsv"
    print_done "Host summary: $host_out/reports/summary.md"
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
RUN_TOTAL_SECONDS=$(( $(date +%s) - RUN_START_TS ))
printf '%sTotal time:%s %s\n' "$GRN" "$RST" "$(format_duration "$RUN_TOTAL_SECONDS")"
printf '%sReport folder:%s %s\n' "$GRN" "$RST" "$ABS_RUN_DIR"
printf '%sLog:%s %s\n' "$GRN" "$RST" "$ABS_LOG"

if [[ "$SUMMARY_MOVED_FEROX" -eq 1 ]]; then
  printf '%sMisc leftovers:%s %s\n' "$YEL" "$RST" "$SUMMARY_MISC_DIR"
fi

printf '%s' "$RST"
