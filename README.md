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

```markdown
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

rates:
  httpx: 80
  nuclei: 30
  ffuf: 50
  ferox: 25

wordlists:
  dir: /usr/share/seclists/Discovery/Web-Content/common.txt
  dir_small: /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt
  dir_medium: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
  file_small: /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt
  file_medium: /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
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
- `nmap` on common web ports
- `nikto`
- `sslscan`
- `ffuf` dirs/files
- `ffuf` on selected directories extracted from crawled URLs
- `feroxbuster` reduced fast profile
- `gowitness`, if installed
- `subfinder`, `bbot`, `subzy`

### `--deep`

More thorough mode. Uses deeper crawling and larger wordlists if available.

Main differences:

- broader web port list
- deeper `katana` crawl
- deeper `feroxbuster`
- larger wordlists
- broader content discovery
- more suitable for promising targets or when program rules allow heavier recon

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

1. Normalize host input.
2. Build base `http://` and `https://` URLs.
3. `httpx` – verify live base URLs and web ports.
4. Pick best target URL.
5. `katana` – crawl endpoints and JavaScript-discovered URLs.
6. `httpx` on crawled URLs – validate discovered endpoints.
7. `waybackurls` – collect archived URLs if installed.
8. Build URL context:
   - `context/all_urls_raw.txt` – live URLs, crawled URLs and archived URLs
   - `context/all_urls_live.txt` – URLs validated with `httpx`
   - `context/all_urls.txt` – compatibility alias for raw URL context
9. Generate triage files:
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
10. Validate JavaScript candidates with `httpx`.
11. `nuclei` general scan.
12. `nuclei` exposure/misconfig scan.
13. `nuclei` takeover scan.
14. `nuclei` JavaScript exposure scan, only if live JS files were found.
15. `nmap` – service detection on common web ports.
16. `nikto` – common web misconfiguration scan.
17. `sslscan` – TLS analysis.
18. `ffuf` – directory discovery.
19. `ffuf` – file discovery.
20. `ffuf` on selected directories extracted from crawled URLs.
21. `feroxbuster` – content discovery.
22. `gowitness` – screenshots if installed.
23. `subfinder` and `bbot` – passive subdomain enumeration.
24. `subzy` – subdomain takeover checks.
25. Detect Cloudflare/edge behavior where applicable.
26. Split low-confidence Cloudflare/WAF-style 403 results into separate files.
27. Track tool status in `context/tool_status.tsv`.
28. Create `reports/summary.md` inside the host output folder.
29. Print final summary with total runtime and host-level counts.

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
                │    ├── js_files_raw.txt
                │    ├── js_files.txt
                │    ├── source_maps.txt
                │    ├── redirect_candidates.txt
                │    ├── lfi_candidates.txt
                │    ├── sqli_candidates.txt
                │    ├── subdomains.txt
                │    ├── subfinder.txt
                │    ├── cloudflare_detected.txt
                │    ├── edge_provider.txt
                │    ├── tool_status.tsv
                │    └── bbot_subdomains.txt
                │
                ├── debug/            # stdout/stderr for troubleshooting
                │    ├── *.stdout
                │    └── *.stderr
                │
                └── tmp/              # temporary working files
```

## Important Files To Review

### Start Here

These are the first files worth opening after a run:

- `reports/summary.md` – per-host summary with key counts, review pointers, Cloudflare/WAF notes and tool status
- `reports/nuclei_exposures.jsonl` – exposed files, backups, configs, logs, misconfigs
- `reports/nuclei_takeover.jsonl` – possible subdomain takeover findings
- `reports/nuclei.jsonl` – general nuclei findings
- `context/interesting_files_live.txt` – live URLs pointing to backups, configs, databases, logs, maps and similar files
- `context/api_candidates_live.txt` – live API, Swagger, OpenAPI and GraphQL candidates
- `context/js_files.txt` – live JavaScript files worth reviewing for endpoints/secrets
- `context/source_maps.txt` – source map candidates
- `reports/feroxbuster.txt` – filtered content discovery results
- `reports/ffuf_files.csv` – file discovery results
- `reports/ffuf_dirs.csv` – directory discovery results
- `reports/ffuf_katana_dirs.csv` – selected directory fuzzing results
- `reports/subzy.json` – subdomain takeover checks
- `reports/gowitness/` – screenshots and gowitness database/exports

### Raw / Historical Context

These files may contain archived or dead URLs. They are useful for context, but should not be treated as confirmed live findings:

- `context/all_urls_raw.txt`
- `context/all_urls.txt`
- `context/interesting_files_raw.txt`
- `context/api_candidates_raw.txt`
- `context/js_files_raw.txt`
- `context/waybackurls.txt`
- `reports/feroxbuster.raw.txt`

### Manual Testing Queues

These files are not findings by themselves. Treat them as queues for manual validation:

- `context/interesting_params.txt` – broad parameter review list
- `context/redirect_candidates.txt` – possible open redirect candidates
- `context/lfi_candidates.txt` – possible file/path/include candidates
- `context/sqli_candidates.txt` – possible SQLi-like parameter candidates

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

### Gowitness Review

To review gowitness results from a host folder:

```bash
gowitness report server \
  --db-uri "sqlite://reports/gowitness/gowitness.sqlite3" \
  --screenshot-path "reports/gowitness/screenshots"
```

Then open:

```bash
http://127.0.0.1:7171
```

### Debug / Troubleshooting Only

Not intended for vulnerability analysis unless troubleshooting:

- `debug/*.stdout`
- `debug/*.stderr`
- `tmp/`
- `scopewise.log`

### Cloudflare / WAF Context

If Cloudflare is detected, ScopeWise keeps scanning normally but separates low-confidence 403 results.

Review:

- `context/cloudflare_detected.txt`
- `context/edge_provider.txt`
- `reports/ffuf_dirs_403.csv`
- `reports/ffuf_files_403.csv`
- `reports/ffuf_katana_dirs_403.csv`
- `reports/feroxbuster_403_filtered.txt`

When Cloudflare is detected, `nmap`, `sslscan`, `nikto` and many 403 responses may describe edge/WAF behavior rather than the origin application.

### Tool Status

ScopeWise tracks tool execution status in:

- `context/tool_status.tsv`

Possible statuses include:

- `ok`
- `missing`
- `failed`
- `empty`
- `skipped`

## Philosophy

ScopeWise is intentionally simple.

It performs:

- fast reconnaissance
- broad surface mapping
- live/raw URL separation
- baseline checks
- quick bounty triage
- structured output for manual review

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

After that, you are expected to manually validate findings and chain additional tools based on what ScopeWise discovered.

## Disclaimer

Use only on systems you are authorized to test.
