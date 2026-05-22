# ScopeWise

```text
▄█████  ▄▄▄▄  ▄▄▄  ▄▄▄▄  ▄▄▄▄▄ ██     ██ ▄▄  ▄▄▄▄ ▄▄▄▄▄
▀▀▀▄▄▄ ██▀▀▀ ██▀██ ██▄█▀ ██▄▄  ██ ▄█▄ ██ ██ ███▄▄ ██▄▄
█████▀ ▀████ ▀███▀ ██    ██▄▄▄  ▀██▀██▀  ██ ▄▄██▀ ██▄▄▄
```

**ScopeWise** is a fast, structured web recon orchestrator for bug bounty and first-pass triage.

It runs common recon tools, validates live data, separates raw context from confirmed live context, and writes clean per-host output.

It does not replace manual testing.

## Features

- single or multi-target recon
- `fast`, `deep`, and `passive` modes
- raw/live URL separation
- JavaScript validation before JS exposure scanning
- WAF/CDN-aware interpretation
- dynamic Nmap port selection
- live subdomain validation
- `gowitness` screenshots for main targets and live subdomain URLs
- low-confidence 403 separation
- lightweight XSS checks with Dalfox
- lightweight SQLi checks with SQLMap
- safe `Ctrl+C` per-step interruption
- automatic timeout for long-running non-core steps
- per-host `reports/summary.md`
- per-tool stdout/stderr logs

## Tools

ScopeWise is only an orchestrator. Install tools yourself.

Core tools:

- `httpx`
- `katana`
- `nuclei`
- `nmap`
- `nikto`
- `sslscan`
- `ffuf`
- `feroxbuster`
- `gowitness`
- `subfinder`
- `bbot`
- `subzy`
- `waybackurls`

Optional but recommended:

- `wafw00f`
- `dalfox`
- `sqlmap`

Check your setup:

```bash
./scopewise.sh --check
```

## Usage

Single target:

```bash
./scopewise.sh -u example.com
```

Multiple targets:

```bash
./scopewise.sh -f urls.txt
```

Modes:

```bash
./scopewise.sh -u example.com --fast
./scopewise.sh -u example.com --deep
./scopewise.sh -u example.com --passive
```

Custom config:

```bash
./scopewise.sh -u example.com --config scopewise.yml
```

## Modes

### `--fast`

Default mode for first-pass bounty recon.

Runs reduced crawling, live validation, nuclei, nmap, nikto, sslscan, ffuf, feroxbuster, subdomain enumeration, takeover checks, screenshots, Dalfox and SQLMap light checks when candidates exist.

### `--deep`

More thorough mode.

Uses deeper crawling, larger wordlists and keeps Nmap default NSE scripts enabled.

### `--passive`

Light mode.

Skips heavier active discovery such as nmap, nikto, ffuf and feroxbuster.

## Configuration

ScopeWise loads `./scopewise.yml` automatically if present.

Example:

```yaml
mode: fast

ports:
  fast: "80,443"
  deep: "80,443,8080,8443,8000,8888,3000,5000,9000"
  nmap_web: "80,443"
  nmap_recon: "21,22,25,53,80,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5000,5432,5601,5900,5985,5986,6379,8000,8080,8081,8443,8888,9000,9200,9300,11211,27017"

rates:
  httpx: 80
  nuclei: 30
  ffuf: 50
  ferox: 25

limits:
  katana_dirs_fast: 15
  katana_dirs_deep: 50
  step_timeout_seconds: 5400
  param_check_urls: 25

tools:
  sqlmap_cmd: sqlmap

wordlists:
  common: /usr/share/seclists/Discovery/Web-Content/common.txt
  dir_small: /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt
  dir_medium: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
  file_small: /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt
  file_medium: /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
```

Disable per-step timeout:

```yaml
limits:
  step_timeout_seconds: 0
```

If SQLMap is installed from GitHub:

```yaml
tools:
  sqlmap_cmd: /opt/sqlmap/sqlmap.py
```

## Output

Each run creates:

```text
scopewise/<RUN_ID>/
├── hosts.txt
├── scopewise.log
└── output/
    └── target.com/
        ├── reports/
        ├── context/
        ├── debug/
        └── tmp/
```

Most important files:

```text
reports/summary.md
context/tool_status.tsv
```

Review first:

```text
reports/nuclei_exposures.jsonl
reports/nuclei_takeover.jsonl
reports/nuclei.jsonl
reports/wafw00f.txt
reports/nmap_web.xml
reports/nikto.json
reports/sslscan.xml
reports/feroxbuster.txt
reports/ffuf_dirs.csv
reports/ffuf_files.csv
reports/dalfox_xss.txt
reports/sqlmap_sqli.txt
reports/subzy.json
reports/subdomains_httpx.txt
reports/gowitness/
```

Useful context:

```text
context/all_urls_live.txt
context/all_urls_raw.txt
context/interesting_files_live.txt
context/api_candidates_live.txt
context/js_files.txt
context/xss_candidates.txt
context/xss_candidates_active.txt
context/sqli_candidates.txt
context/sqli_candidates_active.txt
context/lfi_candidates.txt
context/redirect_candidates.txt
context/live_subdomain_urls.txt
context/live_subdomains.txt
context/waf_detected.txt
context/waf_provider.txt
context/nmap_mode.txt
context/nmap_ports.txt
context/nmap_anomaly.txt
context/ffuf_noise_note.txt
```

Low-confidence/noisy output:

```text
reports/ffuf_dirs_403.csv
reports/ffuf_files_403.csv
reports/ffuf_katana_dirs_403.csv
reports/feroxbuster_403_filtered.txt
reports/feroxbuster.raw.txt
```

Debug files:

```text
debug/*.stdout
debug/*.stderr
```

## Live Subdomain Follow-Up

ScopeWise validates discovered subdomains but does not automatically run the full pipeline against every live subdomain.

Run a second pass manually:

```bash
./scopewise.sh -f scopewise/<RUN_ID>/output/<HOST>/context/live_subdomain_urls.txt --fast
```

## WAF/CDN Handling

ScopeWise uses `httpx` and optionally `wafw00f` to detect Cloudflare/WAF/CDN behavior.

If WAF/CDN is detected:

- 403 results are treated as low-confidence
- Nmap is limited to web/edge ports
- `nmap`, `sslscan`, `nikto` may describe the edge, not the origin

If no WAF/CDN is detected:

- Nmap scans a broader high-value recon port list

## Parameter Checks

ScopeWise extracts parameterized URLs into queues:

```text
context/xss_candidates.txt
context/sqli_candidates.txt
context/lfi_candidates.txt
context/redirect_candidates.txt
context/interesting_params.txt
```

Automatic lightweight checks:

- XSS: `dalfox`
- SQLi: `sqlmap` light mode

SQLMap is run with low-risk options only:

```text
--batch --smart --level=1 --risk=1 --threads=1
```

ScopeWise does not run dumping options such as `--dbs`, `--tables` or `--dump`.

LFI remains a manual queue.

## Step Interruption and Timeout

Pressing `Ctrl+C` cancels the current step only. ScopeWise records it as `interrupted` and continues.

Long-running non-core steps have a default timeout of 90 minutes.

Tool status is saved in:

```text
context/tool_status.tsv
```

Possible statuses:

```text
ok
missing
failed
empty
skipped
timeout
interrupted
```

## Gowitness

Screenshots include main target URLs and live subdomain URLs.

View results from a host output folder:

```bash
gowitness report server \
  --db-uri "sqlite://reports/gowitness/gowitness.sqlite3" \
  --screenshot-path "reports/gowitness/screenshots"
```

Then open:

```text
http://127.0.0.1:7171
```

## Philosophy

ScopeWise is intentionally simple.

It gives you:

- live targets
- raw historical context
- scanner output
- parameter queues
- WAF/CDN context
- subdomain follow-up input
- screenshots
- debug logs

Manual validation is still required.

## Disclaimer

Use only on systems you are authorized to test.
