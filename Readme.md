# 🔍 ReconX v8.6

### Sequential Bug-Bounty Reconnaissance & Vulnerability Pipeline

ReconX is a stage-based, automation-first recon and scanning framework for
**authorized** bug-bounty and penetration-testing engagements. One command
takes a domain from zero to an interactive HTML report: subdomains, live
hosts, URL corpus, parameter discovery, XSS, nuclei (templates **+ DAST
fuzzing**), SQL injection, JS-secret mining, tech fingerprinting and API
discovery.

```
Recon → Subdomains → Alive → URLs → Params → Categorise →
XSS/Dalfox → Nuclei + DAST → Auth-Crawl → JS-Secrets →
Tech-Priority → Extra-Checks → API-Discovery → SQLi/sqlmap
```

---

## ⚠️ Legal

Use only on targets you are **explicitly authorized** to test (a live bug
bounty program scope, or written pentest authorization). Unauthorized
scanning is illegal. `--auto` / `--no-legal` skip the interactive
confirmation — by passing them you assert you already have authorization.

---

## ✨ What's new in v8.x

- **Nuclei DAST pass** (`-dast`) — after the normal template scan, every
  parameterised URL is fuzzed for reflected/stored XSS, error- and time-based
  SQLi, SSTI, LFI, OS-command injection, CRLF and open redirect. This is the
  pass that produces findings on bespoke, vulnerable-by-design targets that
  match no CVE template.
- **Stage 14 — SQL injection (sqlmap)** — active injection testing on the
  deduped parameterised-URL set; DBMS fingerprint + technique per confirmed
  point. Interactive-gated, auto-runs under `--auto`.
- **Stage 13 — API discovery now probes** — GraphQL / Swagger / OpenAPI
  well-known paths are actually requested; a live introspectable GraphQL
  endpoint or exposed schema is reported as a concrete hit, not a guess.
- **DNS resilience** — on networks that block outbound UDP/53 (labs, VPNs,
  cloud sandboxes) ReconX detects the broken resolver and transparently
  routes lookups through a bundled DoH forwarder (`reconx_dns.py`), so tools
  stop silently failing with "could not resolve host".
- Curated `xss-payloads.txt` (WAF-bypass / context-breakout vectors) fed to
  Dalfox `--custom-payload` on top of its built-in set.
- Authenticated scanning: `--login-*`, `--cookie`, or replay a raw Burp/ZAP
  request with `-r`.

---

## 🧱 Pipeline stages

| # | Stage | Tools / action |
|---|-------|----------------|
| 1 | Initial Recon | whois, whatweb, wafw00f, nmap, TheHarvester, Shodan, HTTP probe |
| 2 | Subdomain Enumeration | subfinder, assetfinder, amass, crt.sh fallback |
| 3 | Alive Detection | httpx probe + fingerprint (status/title/tech/IP/CDN) |
| 4 | URL Discovery | gau, waybackurls, katana (+ dead-URL pruning) |
| 5 | Categorisation | reflection detection, XSS-target prioritisation, param extraction |
| 6 | XSS | Dalfox (standard + DOM mining + custom payloads + blind/interactsh) |
| 7 | Nuclei | template scan (tech fastpass + severity filter) **+ DAST fuzzing pass** |
| 8 | Authenticated Crawl | re-crawl behind a logged-in session (if `--login`/`--cookie`) |
| 9 | Param Discovery | paramspider + arjun (hidden parameters) |
| 10 | JS Secrets | download + scan JS for keys/tokens/endpoints (trufflehog + regex) |
| 11 | Tech Priority | normalise detected tech → risk-ranked summary |
| 12 | Extra Checks | CORS misconfig, subdomain takeover, open cloud buckets |
| 13 | API Discovery | GraphQL / Swagger / OpenAPI pattern match **+ live probe** |
| 14 | SQL Injection | ranks likely injection points (+ nuclei-DAST SQLi hits) with a ready sqlmap command each; runs sqlmap itself only with `--stage14` or `sqli_active: true` |

---

## 📦 Installation

```bash
git clone https://github.com/2u1fuk4r/ReconX
cd ReconX
sudo bash install.sh          # installs every external tool, idempotent
python3 -m pip install --break-system-packages -r requirements.txt
cp config.example.yaml config.yaml     # then add your API keys (or use env vars)
```

`config.yaml` is git-ignored (it holds keys); ReconX also auto-generates a
default one on first run if it's missing.

External tools used (installed by `install.sh`): `httpx`, `subfinder`,
`nuclei` (+ templates), `katana`, `gau`, `waybackurls`, `dalfox`, `sqlmap`,
`arjun`, `paramspider`, `interactsh-client`, `trufflehog`, `nmap`, `whatweb`,
`wafw00f`.

Optional — XSS `alert()` verification screenshots:

```bash
python3 -m pip install --break-system-packages playwright && playwright install chromium
```

---

## 🖥️ Web control panel

```bash
python3 reconx_web.py            # http://127.0.0.1:8711
# or, keep it running in the background:
./start-web.sh                   # sudo ./start-web.sh for SYN nmap scans
```

Start / Stop / Pause / Resume scans from the browser, watch the log live,
pick individual stages, fill the auth fields, browse past scans and open their
reports, edit `config.yaml`, check which tools are installed. One scan at a
time. Flask only.

---

## 🚀 CLI usage

```bash
# Full 14-stage pipeline (interactive confirmations for XSS / Nuclei / active SQLi)
sudo python3 reconX.py -d example.com

# Deep SQLi: also run sqlmap on the candidates (slow)
sudo python3 reconX.py -d example.com --stage14

# Fully unattended — no prompts (CI / scheduled / background)
sudo python3 reconX.py -d example.com --auto

# Single URL / URL list (skips subdomain enum, seeds from the URL)
python3 reconX.py --single https://example.com/
python3 reconX.py -U targets.txt

# Specific stages only
python3 reconX.py -d example.com -s 4 5 6 7

# Resume an interrupted scan
python3 reconX.py -d example.com --resume

# Authenticated scan
python3 reconX.py -d example.com \
  --login-url https://example.com/login \
  --login-user me@example.com --login-pass 'secret' \
  --login-success-indicator Logout
python3 reconX.py -d example.com --cookie 'session=abc; csrf=xyz'
python3 reconX.py -d example.com -r captured_login.txt
```

---

## ⚙️ Configuration (`config.yaml`)

Loaded from the project root; override with `--config`. Every secret can also
come from the environment (`RECONX_SHODAN_KEY`, …) — **do not commit real
keys**.

```yaml
settings:
  threads: 25
  rate_limit: 10
  timeout: 20
  use_curl_cffi: true          # Cloudflare-friendly TLS fingerprint
  adaptive_rate: true          # back off automatically on 403/429 spikes
  prune_dead_urls: true

tools:
  nuclei_severity: critical,high,medium
  nuclei_dast: true            # Stage 7 DAST fuzzing pass
  dalfox_custom_payload: "xss-payloads.txt"
  blind_xss_auto: true         # auto-provision an interactsh OOB callback

  sqli_enabled: true           # Stage 14 runs (candidate listing always)
  sqli_active: false           # also run sqlmap? (slow — 10-30 min). --stage14 forces it
  sqli_max_targets: 25
  sqli_level: 3                # sqlmap --level  (only when active)
  sqli_risk: 2                 # sqlmap --risk
```

### DNS on restricted networks

If your box can reach HTTPS but not public DNS (`dig @1.1.1.1` times out),
ReconX auto-starts `reconx_dns.py`. To make it permanent yourself:

```bash
sudo python3 reconx_dns.py --port 53 &
sudo chattr -i /etc/resolv.conf 2>/dev/null; echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf
```

Disable the auto-behaviour with `RECONX_NO_DNS_FIX=1`.

---

## 📁 Output structure

```
output/<target>_<timestamp>/
├── 01_recon/        05_categorized/   09_params/       13_api/
├── 02_subdomains/   06_authenticated/ 10_js_secrets/   14_sqli/
├── 03_alive/        07_nuclei/        11_tech/         checkpoints/
├── 04_urls/         07_xss/           12_extra/        pipeline.log
├── report.html      ← interactive dashboard (opens automatically)
└── SUMMARY.json     ← machine-readable results
```

---

## ⌨️ Interrupt behaviour

- **First Ctrl+C** → stop the current tool, continue to the next stage.
- **Rapid second Ctrl+C** → stop everything, still write the report.

---

## 📄 License

MIT

## 👤 Author

**Zulfukar Karabulut** — Security Researcher | Pentester | eWPTX & eCPPT
[linkedin.com/in/2u1fuk4r](https://linkedin.com/in/2u1fuk4r)

Use responsibly.
