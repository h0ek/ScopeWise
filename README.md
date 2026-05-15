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

## 3. Zamień `Usage` na:

```markdown
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

## Modes

### `--fast`

Default mode. Balanced first-pass bounty recon.

Runs:

- `httpx` on common web ports
- `katana`
- `waybackurls`, if installed
- URL triage files
- `nuclei` general scan
- `nuclei` exposure/misconfig scan
- `nuclei` takeover scan
- `nmap` on common web ports
- `nikto`
- `sslscan`
- `ffuf` dirs/files
- `feroxbuster` recursive content discovery
- `gowitness` screenshots, if installed
- `subfinder`, `bbot`, `subzy`

### `--deep`

More thorough mode. Uses deeper crawling and larger wordlists if available.

Main differences:

- deeper `katana` crawl
- deeper `feroxbuster`
- medium raft wordlists, if present
- lower rates for content discovery

Use this only on promising targets or when program rules allow heavier recon.

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
- `sslscan`
- `nuclei` with lower rate
- `subfinder`, `bbot`, `subzy`
- `gowitness`, if installed

## Workflow Phases

For each host:

1. Normalize host input.
2. Build base `http://` and `https://` URLs.
3. `httpx` – verify live URLs and check alternative web ports.
4. Pick best target URL.
5. `katana` – crawl endpoints and JavaScript-discovered URLs.
6. `httpx` on crawled URLs – validate discovered endpoints.
7. `waybackurls` – collect archived URLs if installed.
8. Merge all discovered URLs into `context/all_urls.txt`.
9. Generate triage files:
   - `context/interesting_files.txt`
   - `context/interesting_params.txt`
   - `context/api_candidates.txt`
   - `context/js_files.txt`
   - `context/source_maps.txt`
   - `context/redirect_candidates.txt`
   - `context/lfi_candidates.txt`
   - `context/sqli_candidates.txt`
10. `nuclei` general scan.
11. `nuclei` exposure/misconfig scan.
12. `nuclei` takeover scan.
13. `nuclei` JavaScript exposure scan, if JS files were found.
14. `nmap` – service detection on common web ports.
15. `nikto` – common web misconfiguration scan.
16. `sslscan` – TLS analysis.
17. `ffuf` – directory and file fuzzing with extensions and auto-calibration.
18. `ffuf` on directories extracted from crawled URLs.
19. `feroxbuster` – recursive content discovery with extensions and backup collection.
20. `gowitness` – screenshots if installed.
21. `subfinder` and `bbot` – passive subdomain enumeration.
22. `subzy` – subdomain takeover checks.
23. Create `README-FIRST.txt` inside the host output folder.

## Output Structure

Each run creates a timestamped directory:

```bash
scopewise/
 └── 20260216_210948/
      ├── scopewise.log
      ├── hosts.txt
      ├── misc/                       # internal leftovers, if any
      └── output/
           └── target.com/
                ├── README-FIRST.txt  # short per-host review guide
                ├── reports/          # findings and scan outputs to review first
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
                │    ├── ffuf_files.csv
                │    ├── ffuf_katana_dirs.csv
                │    ├── feroxbuster.txt
                │    ├── subzy.json
                │    └── gowitness/
                │
                ├── context/          # mapping, URL collections and triage lists
                │    ├── target_host.txt
                │    ├── target_url.txt
                │    ├── urls_source.txt
                │    ├── url_input.txt
                │    ├── live_urls.txt
                │    ├── all_urls.txt
                │    ├── katana.txt
                │    ├── katana_urls.txt
                │    ├── katana_httpx.txt
                │    ├── katana_dirs.txt
                │    ├── waybackurls.txt
                │    ├── interesting_files.txt
                │    ├── interesting_params.txt
                │    ├── api_candidates.txt
                │    ├── js_files.txt
                │    ├── source_maps.txt
                │    ├── redirect_candidates.txt
                │    ├── lfi_candidates.txt
                │    ├── sqli_candidates.txt
                │    ├── subdomains.txt
                │    ├── subfinder.txt
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

- `README-FIRST.txt` – short per-host guide generated by ScopeWise
- `reports/nuclei_exposures.jsonl` – exposed files, backups, configs, logs, misconfigs
- `reports/nuclei_takeover.jsonl` – possible subdomain takeover findings
- `reports/nuclei.jsonl` – general nuclei findings
- `context/interesting_files.txt` – URLs pointing to backups, configs, databases, logs, maps and similar files
- `context/interesting_params.txt` – URLs with parameters useful for manual testing
- `context/api_candidates.txt` – possible API, Swagger, OpenAPI and GraphQL endpoints
- `context/js_files.txt` – JavaScript files worth reviewing for endpoints/secrets
- `context/source_maps.txt` – source map candidates
- `reports/feroxbuster.txt` – recursive content discovery results
- `reports/ffuf_files.csv` – file discovery results
- `reports/ffuf_dirs.csv` – directory discovery results
- `reports/subzy.json` – subdomain takeover checks
- `reports/gowitness/` – screenshots and gowitness database/exports

To review gowitness results from a host folder:

```bash
gowitness report server \
  --db-uri "sqlite://reports/gowitness/gowitness.sqlite3" \
  --screenshot-path "reports/gowitness/screenshots"
```

Then open:

```text
http://127.0.0.1:7171
```

### Manual Testing Queues

These files are not findings by themselves. Treat them as queues for manual validation:

- `context/redirect_candidates.txt` – possible open redirect candidates
- `context/lfi_candidates.txt` – possible file/path/include candidates
- `context/sqli_candidates.txt` – possible SQLi-ish parameter candidates
- `context/interesting_params.txt` – broad parameter review list
- `context/api_candidates.txt` – API manual testing candidates

### Surface Mapping / Context

Useful for chaining further scans:

- `context/all_urls.txt`
- `context/live_urls.txt`
- `context/katana_urls.txt`
- `context/katana_httpx.txt`
- `context/waybackurls.txt`
- `context/subdomains.txt`
- `context/target_url.txt`

### Debug / Troubleshooting Only

Not intended for vulnerability analysis unless troubleshooting:

- `debug/*.stdout`
- `debug/*.stderr`
- `tmp/`
- `scopewise.log`

## Philosophy

ScopeWise is intentionally simple.

It performs:

- fast reconnaissance
- broad surface mapping
- baseline checks
- quick bounty triage
- structured output for manual review

It does not replace manual testing.

The most important output is not only scanner findings, but the triage queues:

- interesting files
- interesting parameters
- API candidates
- JavaScript files
- source maps
- screenshots

After that, you are expected to manually validate findings and chain additional tools based on what ScopeWise discovered.

## Disclaimer

Use only on systems you are authorized to test.
