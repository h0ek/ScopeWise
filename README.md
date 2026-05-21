```bash
▄█████  ▄▄▄▄  ▄▄▄  ▄▄▄▄  ▄▄▄▄▄ ██     ██ ▄▄  ▄▄▄▄ ▄▄▄▄▄ 
▀▀▀▄▄▄ ██▀▀▀ ██▀██ ██▄█▀ ██▄▄  ██ ▄█▄ ██ ██ ███▄▄ ██▄▄  
█████▀ ▀████ ▀███▀ ██    ██▄▄▄  ▀██▀██▀  ██ ▄▄██▀ ██▄▄▄ 
```

**ScopeWise** – yet another recon script that orchestrates multiple well-known reconnaissance tools into a simple, structured workflow.

It is designed for **fast, structured web recon and bug bounty first-pass triage**, not as a full framework.

ScopeWise creates a clean per-host structure with three main areas:

- `reports/` – findings and scan outputs to review first
- `context/` – URLs, mapping, candidates and manual testing queues
- `debug/` – stdout/stderr logs for troubleshooting

It does **not** replace manual testing.

## Tools Used

ScopeWise is only an orchestrator. All credit goes to the original authors of these amazing tools:

- [httpx](https://github.com/projectdiscovery/httpx)
- [katana](https://github.com/projectdiscovery/katana)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [nmap](https://github.com/nmap/nmap)
- [nikto](https://github.com/sullo/nikto)
- [sslscan](https://github.com/rbsec/sslscan)
- [ffuf](https://github.com/ffuf/ffuf)
- [feroxbuster](https://github.com/epi052/feroxbuster)
- [gowitness](https://github.com/sensepost/gowitness)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [bbot](https://github.com/blacklanternsecurity/bbot)
- [subzy](https://github.com/PentestPad/subzy)
- [waybackurls](https://github.com/tomnomnom/waybackurls)
- [wafw00f](https://github.com/EnableSecurity/wafw00f)
- [Dalfox](https://github.com/hahwul/dalfox)
- [SQLMap](https://github.com/sqlmapproject/sqlmap)

Huge thanks to all tool authors.

## Requirements

You must install the tools yourself, best is to run it on Kali Linux.

ScopeWise does not install dependencies automatically.

Recommended environment:
- Linux
- Bash
- Standard recon toolchain installed and available in PATH

Some tools require:
- Go
- Python (for some utilities)
- Proper wordlists (e.g. [Seclists](https://github.com/danielmiessler/SecLists))

## Usage

Single target:

```bash
./scopewise.sh -u example.com
```

Multiple targets:

```bash
./scopewise.sh -f urls.txt
```

Fast mode, default:

```bash
./scopewise.sh -u example.com --fast
```

Deep mode:

```bash
./scopewise.sh -u example.com --deep
```

Passive/light mode:

```bash
./scopewise.sh -u example.com --passive
```
Dependency and wordlist check:

```bash
./scopewise.sh --check
```

Use custom config:

```bash
./scopewise.sh -u example.com --config scopewise.yml
```

## Configuration

ScopeWise can optionally load a simple configuration file.

By default, it tries to load:

```text
./scopewise.yml
```
You can also specify a custom config file:

```bash
./scopewise.sh -u example.com --config scopewise.yml
```

Example:

```bash
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

wordlists:
  dir: /usr/share/seclists/Discovery/Web-Content/common.txt
  dir_small: /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt
  dir_medium: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
  file_small: /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt
  file_medium: /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt

limits:
  katana_dirs_fast: 15
  katana_dirs_deep: 50
  step_timeout_seconds: 5400
  param_check_urls: 25

tools:
  sqlmap_cmd: sqlmap
```
`step_timeout_seconds` controls the automatic timeout for long-running non-core steps.

Default:

```yaml
limits:
  step_timeout_seconds: 5400
```

This equals 90 minutes.
To disable automatic step timeout:

```yaml
limits:
  step_timeout_seconds: 0
```

The config parser is intentionally simple and supports basic key/value style settings used by ScopeWise.

## Modes

### `--fast`

Default mode. Optimized first-pass bounty recon.

Fast mode is designed to collect useful context quickly without turning the run into a heavy recursive scan.

Main characteristics:

- checks only the main web ports, usually `80` and `443`
- uses reduced `katana` crawl depth
- validates JavaScript candidates before scanning them with `nuclei`
- uses live/raw URL separation
- uses a short critical-file list for `ffuf files`
- uses a reduced `feroxbuster` profile:
  - `--depth 1`
  - `--dont-extract-links`
  - smaller extension list
  - no JavaScript extension fuzzing
- excludes `low` severity from the general `nuclei` scan
- prints runtime for every step and total runtime at the end
- detects Cloudflare and marks edge/WAF-sensitive results
- separates low-confidence 403 results into dedicated files
- generates `reports/summary.md`
- tracks tool status in `context/tool_status.tsv`
- allows cancelling the current long-running step with `Ctrl+C`
- applies a default 90-minute timeout to long-running non-core steps
- continues the pipeline after manual interruption or timeout
- validates discovered subdomains with `httpx`
- prepares live subdomain URLs for manual follow-up scans
- includes live subdomain URLs in `gowitness` screenshots
- optionally runs `wafw00f` for additional WAF/CDN detection
- dynamically selects Nmap ports based on WAF/CDN detection
- runs fast-mode Nmap without default NSE scripts
- extracts XSS candidates from parameterized URLs
- extracts SQLi candidates from parameterized URLs
- runs lightweight `dalfox` checks when XSS candidates exist
- runs lightweight `sqlmap` checks when SQLi candidates exist
- keeps LFI candidates as manual review only

Runs:

- `httpx`
- `katana`
- `waybackurls`, if installed
- raw/live URL processing
- URL triage files
- `nuclei` general scan
- `nuclei` exposure/misconfig scan
- `nuclei` takeover scan
- `nuclei` JavaScript exposure scan against live JS files only
- `wafw00f`, if installed
- `nmap` with WAF/CDN-aware port selection
- `nikto`
- `sslscan`
- `ffuf` dirs/files
- `ffuf` on selected directories extracted from crawled URLs
- `dalfox`, if installed and XSS candidates were found
- `sqlmap`, if installed and SQLi candidates were found
- `feroxbuster` reduced fast profile
- `subfinder` and `bbot` for passive subdomain enumeration
- `httpx` on discovered subdomains
- `subzy` for subdomain takeover checks
- `gowitness`, if installed, for main target URLs and live subdomain URLs

### `--deep`

More thorough mode. Uses deeper crawling and larger wordlists if available.

Main differences:

- broader web port list
- deeper `katana` crawl
- deeper `feroxbuster`
- larger wordlists
- broader content discovery
- more suitable for promising targets or when program rules allow heavier recon

In `--deep`, Nmap keeps default NSE scripts enabled.

Use this only when you want a more complete scan and can accept longer runtime.

### `--passive`

Light/passive mode. Useful for first look or stricter programs.

Skips:

- `nmap`
- `nikto`
- `ffuf`
- `feroxbuster`

Still runs:

- `httpx`
- `katana`
- `waybackurls`, if installed
- URL triage
- raw/live context generation where applicable
- `sslscan`
- `nuclei` with lower rate
- `subfinder`, `bbot`, `subzy`
- `gowitness`, if installed

## Workflow Phases

For each host:

- Normalize host input.
- Build base `http://` and `https://` URLs.
- `httpx` – verify live base URLs and web ports.
- Pick best target URL.
- `katana` – crawl endpoints and JavaScript-discovered URLs.
- `httpx` on crawled URLs – validate discovered endpoints.
- `waybackurls` – collect archived URLs if installed.
- Build URL context:
   - `context/all_urls_raw.txt` – live URLs, crawled URLs and archived URLs
   - `context/all_urls_live.txt` – URLs validated with `httpx`
   - `context/all_urls.txt` – compatibility alias for raw URL context
- Generate triage files:
   - `context/interesting_files_raw.txt`
   - `context/interesting_files_live.txt`
   - `context/interesting_files.txt`
   - `context/api_candidates_raw.txt`
   - `context/api_candidates_live.txt`
   - `context/api_candidates.txt`
   - `context/js_files_raw.txt`
   - `context/js_files.txt`
   - `context/source_maps.txt`
   - `context/interesting_params.txt`
   - `context/redirect_candidates.txt`
   - `context/lfi_candidates.txt`
   - `context/sqli_candidates.txt`
   - `context/xss_candidates.txt`
   - `context/xss_candidates_active.txt`
   - `context/sqli_candidates_active.txt`
- Validate JavaScript candidates with `httpx`.
- Prepare limited active parameter-check input:
   - `context/xss_candidates_active.txt`
   - `context/sqli_candidates_active.txt`
- Run lightweight XSS checks with `dalfox`, if candidates exist and the tool is installed.
- Run lightweight SQLi checks with `sqlmap`, if candidates exist and the tool is installed.
- `nuclei` general scan.
- `nuclei` exposure/misconfig scan.
- `nuclei` takeover scan.
- `nuclei` JavaScript exposure scan, only if live JS files were found.
- `nmap` – service detection on common web ports.
    - WAF/CDN detected: scan web/edge ports only.
    - No WAF/CDN detected: scan popular recon ports.
- `nikto` – common web misconfiguration scan.
- `sslscan` – TLS analysis.
- `ffuf` – directory discovery.
- `ffuf` – file discovery.
- `ffuf` on selected directories extracted from crawled URLs.
- `feroxbuster` – content discovery.
- `subfinder` and `bbot` – passive subdomain enumeration.
- Build combined subdomain list:
   - `context/subdomains.txt`
- Validate discovered subdomains with `httpx`:
   - `context/subdomain_urls_source.txt`
   - `context/live_subdomains.txt`
   - `context/live_subdomain_urls.txt`
   - `reports/subdomains_httpx.txt`
- `subzy` – subdomain takeover checks.
- `gowitness` – screenshots for main target URLs and live subdomain URLs.
- Detect Cloudflare/edge behavior where applicable. Run `wafw00f`, if installed, for additional WAF/CDN detection.
- Split low-confidence Cloudflare/WAF-style 403 results into separate files.
- Track tool status in `context/tool_status.tsv`.
- Record interrupted or timed-out steps where applicable.
- Create `reports/summary.md` inside the host output folder.
- Print final summary with total runtime and host-level counts.

## Step Interruption and Timeout

ScopeWise is designed to continue running even if a single long-running tool gets stuck.

During a running step, pressing `Ctrl+C` cancels the current step only. ScopeWise records the step as `interrupted`, keeps any output already written by the tool, and continues with the next step.

Long-running non-core steps also have an automatic timeout. By default, the timeout is 90 minutes.

The timeout applies to heavier steps such as:

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

Core context-building steps are not automatically time-limited by default, because their output is used by later phases. These include:

- base `httpx`
- `katana`
- `httpx` on crawled URLs
- `waybackurls`
- `httpx` live URL validation
- JavaScript/API/interesting-file validation

If a step is interrupted or times out, its output may be partial. ScopeWise still creates the expected output files where possible so the rest of the pipeline can continue safely.

## Output Structure

Each run creates a timestamped directory:

```bash
scopewise/
 └── 20260516_120322/
      ├── scopewise.log
      ├── hosts.txt
      ├── misc/                       # internal leftovers, if any
      └── output/
           └── target.com/
                ├── reports/          # findings and scan outputs to review first
                |    ├── summary.md  # short per-host review guide
                │    ├── wafw00f.txt
                │    ├── nuclei.jsonl
                │    ├── nuclei_exposures.jsonl
                │    ├── nuclei_takeover.jsonl
                │    ├── nuclei_js_exposure.jsonl
                │    ├── nmap_web.nmap
                │    ├── nmap_web.gnmap
                │    ├── nmap_web.xml
                │    ├── nikto.json
                │    ├── sslscan.xml
                │    ├── ffuf_dirs.csv
                │    ├── ffuf_dirs_403.csv
                │    ├── ffuf_files.csv
                │    ├── ffuf_files_403.csv
                │    ├── ffuf_katana_dirs.csv
                │    ├── ffuf_katana_dirs_403.csv
                │    ├── feroxbuster.raw.txt
                │    ├── feroxbuster.txt
                │    ├── feroxbuster_403_filtered.txt
                │    ├── subzy.json
                │    ├── dalfox_xss.txt
                │    ├── sqlmap_sqli.txt
                │    ├── sqlmap_light/
                │    └── gowitness/
                │
                ├── context/          # mapping, URL collections and triage lists
                │    ├── target_host.txt
                │    ├── target_url.txt
                │    ├── urls_source.txt
                │    ├── url_input.txt
                │    ├── live_urls.txt
                │    ├── all_urls_raw.txt
                │    ├── all_urls_live.txt
                │    ├── all_urls.txt
                │    ├── katana.txt
                │    ├── katana_urls.txt
                │    ├── katana_httpx.txt
                │    ├── katana_dirs.txt
                │    ├── waybackurls.txt
                │    ├── interesting_files_raw.txt
                │    ├── interesting_files_live.txt
                │    ├── interesting_files.txt
                │    ├── interesting_params.txt
                │    ├── api_candidates_raw.txt
                │    ├── api_candidates_live.txt
                │    ├── api_candidates.txt
                │    ├── waf_detected.txt
                │    ├── waf_provider.txt
                │    ├── nmap_mode.txt
                │    ├── nmap_ports.txt
                │    ├── js_files_raw.txt
                │    ├── js_files.txt
                │    ├── source_maps.txt
                │    ├── redirect_candidates.txt
                │    ├── lfi_candidates.txt
                │    ├── sqli_candidates.txt
                │    ├── subdomains.txt
                │    ├── subfinder.txt
                │    ├── bbot_subdomains.txt
                │    ├── subdomain_urls_source.txt
                │    ├── live_subdomains.txt
                │    ├── live_subdomain_urls.txt
                │    ├── cloudflare_detected.txt
                │    ├── edge_provider.txt
                │    ├── xss_candidates.txt
                │    ├── xss_candidates_active.txt
                │    ├── sqli_candidates_active.txt
                │    ├── tool_status.tsv
                │    └── bbot_subdomains.txt
                │
                ├── debug/            # stdout/stderr for troubleshooting
                │    ├── *.stdout
                │    └── *.stderr
                │
                └── tmp/              # temporary working files
                     └── gowitness_targets.txt
```

## Important Files To Review

### Start Here

These are the first files worth opening after a run:

1. `reports/summary.md` – per-host summary with key counts, review pointers, Cloudflare/WAF notes and tool status

Scanner and finding reports:

- `reports/nuclei_exposures.jsonl` – exposed files, backups, configs, logs, misconfigs
- `reports/nuclei_takeover.jsonl` – possible subdomain takeover findings
- `reports/nuclei.jsonl` – general nuclei findings
- `reports/nikto.json` – Nikto output, if available
- `reports/nmap_web.xml` – nmap web-port scan
- `reports/sslscan.xml` – TLS scan
- `reports/feroxbuster.txt` – filtered content discovery results
- `reports/ffuf_files.csv` – file discovery results
- `reports/ffuf_dirs.csv` – directory discovery results
- `reports/ffuf_katana_dirs.csv` – selected directory fuzzing results
- `reports/dalfox_xss.txt` – lightweight XSS check results
- `reports/sqlmap_sqli.txt` – lightweight SQLi verification output
- `reports/sqlmap_light/` – SQLMap output directory
- `reports/subzy.json` – subdomain takeover checks
- `reports/subdomains_httpx.txt` – live subdomain HTTP probe output
- `reports/gowitness/` – screenshots and gowitness database/exports
- `reports/wafw00f.txt` – WAF/CDN detection output, if available

Validated context:

- `context/interesting_files_live.txt` – live URLs pointing to backups, configs, databases, logs, maps and similar files
- `context/api_candidates_live.txt` – live API, Swagger, OpenAPI and GraphQL candidates
- `context/js_files.txt` – live JavaScript files worth reviewing for endpoints/secrets
- `context/live_subdomain_urls.txt` – live subdomain URLs ready for manual follow-up scans
- `context/live_subdomains.txt` – live subdomain hostnames
- `context/xss_candidates.txt` – XSS-like parameter candidates
- `context/xss_candidates_active.txt` – limited XSS candidate list used by Dalfox
- `context/sqli_candidates.txt` – SQLi-like parameter candidates
- `context/sqli_candidates_active.txt` – limited SQLi candidate list used by SQLMap

Manual queues:

- `context/interesting_params.txt` – raw parameter review queue
- `context/source_maps.txt` – source map candidates

### Surface Mapping / Context

Useful for chaining further scans:

- `context/all_urls_live.txt`
- `context/all_urls_raw.txt`
- `context/live_urls.txt`
- `context/katana_urls.txt`
- `context/katana_httpx.txt`
- `context/waybackurls.txt`
- `context/subdomains.txt`
- `context/target_url.txt`
- `context/subdomains.txt`
- `context/target_url.txt`
- `context/waf_detected.txt`
- `context/waf_provider.txt`
- `context/nmap_mode.txt`
- `context/nmap_ports.txt`

### Live Subdomain Follow-Up

ScopeWise enumerates subdomains and validates which ones are alive, but it does not automatically run the full recon pipeline against every live subdomain.

Useful files:

- `context/subdomains.txt` – all discovered subdomains
- `context/live_subdomains.txt` – live subdomain hostnames
- `context/live_subdomain_urls.txt` – live subdomain URLs ready for a follow-up scan
- `reports/subdomains_httpx.txt` – full `httpx` output for discovered subdomains

To manually run ScopeWise against live subdomains:

```bash
./scopewise.sh -f scopewise/<RUN_ID>/output/<HOST>/context/live_subdomain_urls.txt --fast
```

### Gowitness Review

`gowitness` screenshots include the main target URLs and live subdomain URLs when live subdomains are found.

To review gowitness results from a host folder:

```bash
gowitness report server \
  --db-uri "sqlite://reports/gowitness/gowitness.sqlite3" \
  --screenshot-path "reports/gowitness/screenshots"
```

### Debug / Troubleshooting Only

Not intended for vulnerability analysis unless troubleshooting:

- `debug/*.stdout`
- `debug/*.stderr`
- `tmp/`
- `scopewise.log`

### WAF / CDN Context

If Cloudflare or another WAF/CDN is detected, ScopeWise keeps scanning normally but treats edge/WAF-sensitive results carefully.

Review:

- `context/cloudflare_detected.txt`
- `context/edge_provider.txt`
- `context/waf_detected.txt`
- `context/waf_provider.txt`
- `context/nmap_mode.txt`
- `context/nmap_ports.txt`
- `reports/wafw00f.txt`
- `reports/ffuf_dirs_403.csv`
- `reports/ffuf_files_403.csv`
- `reports/ffuf_katana_dirs_403.csv`
- `reports/feroxbuster_403_filtered.txt`

When a WAF/CDN is detected, `nmap`, `sslscan`, `nikto` and many 403 responses may describe edge/WAF behavior rather than the origin application.

In that case, ScopeWise limits Nmap to web/edge ports. If no WAF/CDN is detected, ScopeWise scans a broader list of common high-value recon ports.

### Parameter Testing Queues

ScopeWise extracts parameterized URLs into focused queues.

- `context/interesting_params.txt` – broad parameter review list
- `context/xss_candidates.txt` – XSS-like parameter candidates
- `context/sqli_candidates.txt` – SQLi-like parameter candidates
- `context/lfi_candidates.txt` – LFI/path traversal candidates
- `context/redirect_candidates.txt` – possible open redirect candidates

ScopeWise runs lightweight automatic checks only for XSS and SQLi:

- XSS: `dalfox`
- SQLi: `sqlmap` light mode

LFI remains a manual queue.

### Tool Status

ScopeWise tracks tool execution status in:

- `context/tool_status.tsv`

Possible statuses include:

- `ok`
- `missing`
- `failed`
- `empty`
- `skipped`
- `timeout`
- `interrupted`

`timeout` means the step exceeded the configured time limit.

`interrupted` means the user cancelled the current step with `Ctrl+C`.

## Philosophy

ScopeWise is intentionally simple.

It performs:

- fast reconnaissance
- broad surface mapping
- live/raw URL separation
- baseline checks
- quick bounty triage
- structured output for manual review
- WAF/CDN-aware interpretation and Nmap port selection

It does not replace manual testing.

ScopeWise separates two kinds of data:

- raw context – useful for history, mapping and manual analysis
- live validated context – better suited for review and follow-up checks

The most important output is not only scanner findings, but the triage queues:

- live interesting files
- live API candidates
- live JavaScript files
- interesting parameters
- redirect candidates
- LFI/path candidates
- SQLi-like parameter candidates
- source maps
- screenshots
- live subdomain URLs for controlled follow-up scans

After that, you are expected to manually validate findings and chain additional tools based on what ScopeWise discovered.

## Disclaimer

Use only on systems you are authorized to test.
