```bash
▄█████  ▄▄▄▄  ▄▄▄  ▄▄▄▄  ▄▄▄▄▄ ██     ██ ▄▄  ▄▄▄▄ ▄▄▄▄▄ 
▀▀▀▄▄▄ ██▀▀▀ ██▀██ ██▄█▀ ██▄▄  ██ ▄█▄ ██ ██ ███▄▄ ██▄▄  
█████▀ ▀████ ▀███▀ ██    ██▄▄▄  ▀██▀██▀  ██ ▄▄██▀ ██▄▄▄ 
```

**ScopeWise** – yet another recon script that orchestrates multiple well-known reconnaissance tools into a simple, structured workflow.

It is designed for **fast, structured web recon**, not as a full framework.

## What It Does

ScopeWise runs multiple reconnaissance tools in phases and stores results per-host in a clean directory structure.

It is meant to:

- Quickly scan target domains
- Collect URLs and endpoints
- Perform basic web & SSL enumeration
- Run common content discovery
- Enumerate subdomains
- Produce structured output for manual analysis

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
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [bbot](https://github.com/blacklanternsecurity/bbot)
- [subzy](https://github.com/PentestPad/subzy)

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

## Workflow Phases

For each host:

1. Normalize host input
2. httpx – verify live URLs
3. katana – crawl endpoints
4. httpx (katana URLs) – validate discovered endpoints
5. nuclei – vulnerability scan
6. nmap – basic web port scan
7. nikto – web misconfig scan
8. sslscan – TLS analysis
9. ffuf – directory & file fuzzing
10. ffuf (katana dirs) – targeted fuzzing
11. feroxbuster – recursive content discovery
12. subfinder + bbot – subdomain enumeration
13. subzy – subdomain takeover check

## Output Structure

Each run creates a timestamped directory:

```bash
scopewise/
 └── 20260216_210948/
      ├── scopewise.log
      ├── hosts.txt
      ├── misc/                # internal leftovers (e.g. ferox state files)
      └── output/
           └── target.com/
                ├── target_host.txt
                ├── target_url.txt
                ├── urls_source.txt
                ├── url_input.txt
                │
                ├── nuclei.jsonl
                ├── nmap_web.nmap
                ├── nmap_web.gnmap
                ├── nmap_web.xml
                ├── nikto.json
                ├── sslscan.xml
                │
                ├── ffuf_dirs.csv
                ├── ffuf_files.csv
                ├── ffuf_katana_dirs.csv
                ├── feroxbuster.txt
                │
                ├── katana.txt
                ├── katana_urls.txt
                ├── katana_httpx.txt
                ├── katana_dirs.txt
                │
                ├── subdomains.txt
                ├── subfinder.txt
                ├── bbot_subdomains.txt
                ├── subzy.json
                │
                └── debug/
                     ├── *.stdout
                     └── *.stderr
```

## Important Files To Review

### High Value

These should be reviewed first:

- `nuclei.jsonl` – vulnerability findings
- `nmap_web.xml` – service & version detection
- `nikto.json` – common web misconfigurations
- `sslscan.xml` – TLS weaknesses
- `ffuf_*.csv` – discovered directories/files
- `feroxbuster.txt` – recursive content discovery
- `subdomains.txt` – combined subdomain list
- `subzy.json` – takeover findings

### Surface Mapping / Context

Useful for chaining further scans:

- `katana_urls.txt`
- `katana_httpx.txt`
- `katana_dirs.txt`
- `url_input.txt`
- `target_url.txt`

### Debug / Troubleshooting Only

Not intended for analysis unless troubleshooting:

- `debug/*.stdout`
- `debug/*.stderr`
- `scopewise.log`

## Philosophy

ScopeWise is intentionally simple.

It performs:

- Fast reconnaissance
- Broad surface mapping
- Baseline checks

After that, you are expected to:

- Manually analyze outputs
- Chain additional tools
- Run targeted scans based on findings

It is a starting point, not an autopilot.

## Disclaimer

Use only on systems you are authorized to test.
