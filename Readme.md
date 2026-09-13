# 🔍 ReconX v8.9

### Sequential Bug-Bounty Reconnaissance & Vulnerability Pipeline

<p align="center">
  <img src="docs/reconx-demo.gif" alt="ReconX: scan, interrupt with Ctrl+C, resume from the checkpoint, and open the report" width="100%">
</p>

<p align="center">
  <sub>
    One run: recon → live XSS hits → <b>Ctrl+C</b> → <b>--resume</b> picks up from the
    checkpoint → the interactive report.<br>
    Walkthrough of the workflow with sample findings, rendered through the real
    report builder — not a recording of a scan against a live third party.
  </sub>
</p>

ReconX is a stage-based, automation-first recon and scanning framework for
**authorized** bug-bounty and penetration-testing engagements. One command
takes a domain from zero to an interactive HTML report: subdomains, live
hosts, URL corpus, parameter discovery, XSS, nuclei (templates **+ DAST
fuzzing**), JS-secret mining, tech fingerprinting and API
discovery. Every stage is checkpointed, so an interrupted scan can be picked
up exactly where it stopped.

```
Recon → Subdomains → Alive → URLs → Params → Categorise →
XSS/Dalfox → Nuclei + DAST → Auth-Crawl → JS-Secrets →
Tech-Priority → Extra-Checks → API-Discovery
```

---

## ⚠️ Authorized use only

Use only on targets you are **explicitly authorized** to test (a live bug
bounty program scope, or written pentest authorization). Unauthorized
scanning is illegal. There is no startup confirmation prompt — running the
tool is itself the assertion that you have authorization.

---

## ✨ What's new in v8.9

- **Stage checkpointing & resume** — every stage transition is flushed to
  `checkpoints/state.json` (atomically), so Ctrl+C, SIGTERM, a crash or the
  time budget always leaves an accurate record of what finished. The next run
  finds the unfinished session, shows a table of what it already produced, and
  on `--resume` skips the completed stages and reloads their saved results
  into the report instead of re-scanning.
- **`--max-time MIN`** — a global wall-clock budget. When it expires the
  running tool is killed, the scan is checkpointed and a report is written;
  continue later with `--resume`. Ideal for cron and CI.
- **`--doctor`** — full environment preflight: every external binary, Python
  package, path and DNS resolution, each annotated with the stage it affects
  and whether it is critical. Exits 1 when something critical is missing, so
  it works as a CI gate. A short non-blocking version runs before every scan.
- **Scan delta** — the results are compared against the previous scan of the
  same target (subdomains, alive hosts, URLs, parameterised URLs). New and
  disappeared entries land in `DIFF.json`, in the console, and in the report —
  continuous recon without diffing files by hand.
- **Honest report state** — an unfinished scan is badged `SCAN INCOMPLETE`
  with the reason and the stage list, instead of presenting a partial scan as
  a clean result.
- The startup legal-confirmation prompt was removed (`--no-legal` is still
  accepted and ignored, so existing wrappers keep working).
- The UI and all tool output are English.

---

## 🕰️ Earlier — v8.x

- **Nuclei DAST pass** (`-dast`) — after the normal template scan, every
  parameterised URL is fuzzed for reflected/stored XSS, error- and time-based
  SQLi, SSTI, LFI, OS-command injection, CRLF and open redirect. This is the
  pass that produces findings on bespoke, vulnerable-by-design targets that
  match no CVE template.
- **Stage 13 — API discovery now probes** — GraphQL / Swagger / OpenAPI
  well-known paths are actually requested; a live introspectable GraphQL
  endpoint or exposed schema is reported as a concrete hit, not a guess.
- **DNS resilience** — on networks that block outbound UDP/53 (labs, VPNs,
  cloud sandboxes) ReconX detects the broken resolver and transparently
  routes lookups through a bundled DoH forwarder (`reconx_dns.py`), so tools
  stop silently failing with "could not resolve host".
- Curated `xss-payloads.txt` (WAF-bypass / context-breakout vectors) shipped for
  Dalfox `--custom-payload`. **Off by default** since v8.6: feeding 65 extra
  payloads per parameter made stage 6 ~5x slower without finding more than
  dalfox's own built-ins. Opt in with `tools.dalfox_custom_payload:
  "xss-payloads.txt"`.
- Authenticated scanning: `--login-*`, `--cookie`, or replay a raw Burp/ZAP
  request with `-r`.

---

## 🧱 Pipeline stages

| # | Stage | Tools / action |
|---|-------|----------------|
| 1 | Initial Recon | whois, whatweb, wafw00f, nmap, HTTP probe |
| 2 | Subdomain Enumeration | subfinder, assetfinder, findomain, crt.sh fallback |
| 3 | Alive Detection | httpx probe + fingerprint (status/title/tech/IP/CDN) |
| 4 | URL Discovery | gau (wayback/commoncrawl/otx/urlscan) + katana (+ dead-URL pruning) |
| 5 | Categorisation | reflection detection, XSS-target prioritisation, param extraction |
| 6 | XSS | Dalfox (standard + DOM mining + custom payloads + blind/interactsh) |
| 7 | Nuclei | template scan (tech fastpass + severity filter) **+ DAST fuzzing pass** |
| 8 | Authenticated Crawl | re-crawl behind a logged-in session (if `--login`/`--cookie`) |
| 9 | Param Discovery | paramspider + arjun (hidden parameters) |
| 10 | JS Secrets | download + scan JS for keys/tokens/endpoints (trufflehog + regex) |
| 11 | Tech Priority | normalise detected tech → risk-ranked summary |
| 12 | Extra Checks | CORS misconfig, subdomain takeover, open cloud buckets |
| 13 | API Discovery | GraphQL / Swagger / OpenAPI pattern match **+ live probe** |

---

## 📦 Installation

```bash
git clone https://github.com/2u1fuk4r/ReconX
cd ReconX
sudo bash install.sh          # installs every external tool, idempotent
python3 -m pip install --break-system-packages -r requirements.txt
python3 reconX.py --doctor    # verifies the install; also writes a default config.yaml
```

`config.yaml` is git-ignored (it holds API keys) and is **not** shipped in the
repo in any form. If it is missing, ReconX writes a working default from its
built-in template on first run — every knob at its default value, with the
non-obvious ones commented. Edit that file, or supply secrets through the
environment instead (`RECONX_CENSYS_KEY`, …).

External tools used (installed by `install.sh`): `httpx`, `subfinder`,
`assetfinder`, `findomain`, `dnsx`, `nuclei` (+ templates), `katana`, `gau`,
`dalfox`, `arjun`, `paramspider`, `interactsh-client`, `trufflehog`, `nmap`,
`whatweb`, `wafw00f`, `tor`.

Run `python3 reconX.py --doctor` at any time to see which of them are present
and which stage each missing one would degrade.

Optional — XSS `alert()` verification screenshots (stage 6 replays every dalfox
candidate in a headless browser and only marks it CONFIRMED when a real dialog
fires). Uses Selenium against the system Chromium/Chrome:

```bash
python3 -m pip install --break-system-packages selenium
sudo apt install -y chromium chromium-driver     # or: chromedriver
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
# Check the environment first (tools, packages, paths, DNS) — exits 1 if broken
python3 reconX.py --doctor

# Full 13-stage pipeline (interactive confirmations for XSS / Nuclei)
sudo python3 reconX.py -d example.com

# Fully unattended — no prompts (CI / scheduled / background)
sudo python3 reconX.py -d example.com --auto

# Stop after 90 minutes, checkpoint, report — then continue later
sudo python3 reconX.py -d example.com --auto --max-time 90
sudo python3 reconX.py -d example.com --auto --resume

# Single URL / URL list (skips subdomain enum, seeds from the URL)
python3 reconX.py --single https://example.com/
python3 reconX.py -U targets.txt

# Specific stages only
python3 reconX.py -d example.com -s 4 5 6 7

# Resume an interrupted scan (skips completed stages, reloads their results)
python3 reconX.py -d example.com --resume

# Never resume — force a brand-new session
python3 reconX.py -d example.com --fresh

# Skip the delta comparison against the previous scan
python3 reconX.py -d example.com --no-diff

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
come from the environment (`RECONX_CENSYS_KEY`, …) — **do not commit real
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
  dalfox_custom_payload: ""    # "" = dalfox built-ins only (default, ~5x faster)
  blind_xss_auto: true         # auto-provision an interactsh OOB callback
  dalfox_max_targets: 40       # hard cap on the dalfox target list
  dalfox_time_budget_sec: 1500 # per-stage wall-clock budget for dalfox
```

Checkpointing, resume, the delta pass and the time budget are all CLI-side
(`--resume` / `--fresh` / `--no-diff` / `--max-time`) and need no config.

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
├── 02_subdomains/   06_authenticated/ 10_js_secrets/   pipeline.log
├── 03_alive/        07_nuclei/        11_tech/
├── 04_urls/         07_xss/           12_extra/
├── checkpoints/
│   ├── state.json          ← stage-level resume state (what finished, what it produced)
│   └── stageN_*.txt        ← the per-stage result sets
├── report.html      ← interactive dashboard (opens automatically)
├── DIFF.json        ← delta vs the previous scan of this target
└── SUMMARY.json     ← machine-readable results (+ resume state + delta)
```

---

## ⌨️ Interrupt behaviour & resume

Ctrl+C opens a menu instead of killing the run:

| Choice | Effect |
|--------|--------|
| 1 | Skip this stage — what it collected is saved, the pipeline moves on |
| 2 | Skip only the running tool — the rest of the stage carries on |
| 3 | Stop the tool — checkpoint everything and write a report |

With no TTY (cron, the web panel, a pipe) a `SIGINT`/`SIGTERM` behaves as
choice 3. Either way the state file is current, so:

```bash
python3 reconX.py -d example.com --resume
```

prints what the previous session finished, skips those stages, reloads their
saved results and continues from the interrupted one. Only stages recorded as
`done` are skipped — a `partial` or `failed` stage is deliberately re-run,
because its output is incomplete by definition.

```
UNFINISHED SCAN FOUND — example.com
  Session   : example.com_20260913_153906
  Stopped by: ctrl-c / hard stop
  ────────────────────────────────────────────────
  DONE      stage  2  Subdomain Enumeration   count=29,107  (198.7s)
  PARTIAL   stage  3  Host Validation — httpx count=29,107  (39.9s)
```

---

## 📄 License

MIT

## 👤 Author

**Zulfukar Karabulut** — Security Researcher | Pentester | eWPTX & eCPPT & eCIR
[linkedin.com/in/2u1fuk4r](https://linkedin.com/in/2u1fuk4r)

Use responsibly.
