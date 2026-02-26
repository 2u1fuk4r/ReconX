
# 🔍 ReconX v5.0  
### Sequential Bug Bounty Reconnaissance Pipeline

ReconX is a stage-based, automation-first reconnaissance framework designed for authorized bug bounty and penetration testing engagements.

Pipeline:
Recon → Subdomains → Alive → URLs → Categorize → Nuclei → XSS

---

## ⚠️ Legal Disclaimer

This tool must only be used on targets you are explicitly authorized to test.  
Unauthorized scanning is illegal.

Use `--no-legal` only in CI or fully authorized automated environments.

<img width="593" height="298" alt="1" src="https://github.com/user-attachments/assets/a17de6aa-4c45-43d7-9932-69a9a4ba060b" />

==== The Proccess will working for each tools and steages ====

<img width="622" height="773" alt="image" src="https://github.com/user-attachments/assets/8ae92230-ca41-4ada-a77c-4b1846b81e18" />

====== The Last Report Will create and showing on browser =====
<img width="1783" height="680" alt="image" src="https://github.com/user-attachments/assets/84c88537-30c3-4960-9647-9ebaa9549bfa" />

==== Alive Hosts ====
<img width="1770" height="691" alt="image" src="https://github.com/user-attachments/assets/bd060c62-e975-43c4-9c27-7483e3b12f61" />

---

# ✨ Features

- Stage-based automated recon workflow
- Resume support via checkpoints
- RAM-safe streaming URL processing
- Integrated Nuclei scanning
- Integrated Dalfox (3 XSS modes)
- Automatic SUMMARY.json generation
- Optional HTML report builder
- Clean structured output
- Safe Ctrl+C handling

---

# 🧱 Pipeline Stages

| Stage | Name | Description |
|-------|------|-------------|
| 1 | Initial Recon | Whois, WhatWeb, WAF detection, Nmap, TheHarvester, Shodan |
| 2 | Subdomain Enumeration | Subfinder, Assetfinder, Amass, etc |
| 3 | Alive Detection | httpx probing & fingerprinting |
| 4 | URL Discovery | gau, waybackurls, katana |
| 5 | Categorization | Reflection detection & XSS prioritization |
| 6 | Nuclei Scan | Template-based vulnerability scanning |
| 7 | XSS Scan | Dalfox standard + DOM + redirect modes |

---

# 📦 Installation

```bash
git clone https://github.com/2u1fuk4r/ReconX
cd ReconX
sudo bash install.sh

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Ensure required external tools are installed and available in `$PATH`:
httpx, nuclei, dalfox, subfinder, assetfinder, amass, gau, waybackurls, katana

---

# ⚙️ Configuration (config.yaml)

ReconX loads `config.yaml` from the project root by default.  
You can override it with:

```bash
sudo python reconx.py -d example.com
python3 reconx.py -d example.com --config ./custom_config.yaml
```

---

## 🔧 settings

```yaml
settings:
  threads: 50
  rate_limit: 5
  timeout: 10
```

### threads
- Controls worker/thread count for httpx, nuclei and dalfox.
- Higher = faster scans, more CPU/RAM usage.
- Recommended:
  - VPS: 80–150
  - Local machine: 30–80
  - Stealth mode: 10–30

### rate_limit
- Controls request rate limiting for nuclei and dalfox.
- Lower values reduce detection risk.
- Example:
  - 1–3 → stealth
  - 5–10 → balanced
  - 20+ → aggressive

### timeout
- HTTP timeout in seconds (used mainly by Dalfox).
- Increase if scanning slow endpoints.
- Default 10 is usually safe.

---

## 🛠 tools

```yaml
tools:
  nuclei_severity: "critical,high,medium"
```

### nuclei_severity
- Defines which severities Nuclei will scan for.
- Available:
  - info
  - low
  - medium
  - high
  - critical
- Example configurations:
  - Fast triage: "critical,high"
  - Deep scan: "critical,high,medium,low"

---

## 🔑 api_keys

```yaml
api_keys:
  shodan: "YOUR_SHODAN_KEY"
```

### shodan
- Enables Shodan integration in Stage 1 (if binary installed).
- Leave empty to disable.

---

# 🚀 Usage

## Full Pipeline
```bash
sudo python reconx.py -d example.com
```

## Run Specific Stages
```bash
python3 reconx.py -d example.com -s 1 2 3
```

## Resume Scan
```bash
python3 reconx.py -d example.com --resume
```

## Non-Interactive Mode
```bash
python3 reconx.py -d example.com --no-legal --auto-nuclei --auto-xss
```

---

# 📁 Output Structure

```
output/<domain>_<timestamp>/
├── 01_recon/
├── 02_subdomains/
├── 03_alive/
├── 04_urls/
├── 05_categorized/
├── 06_nuclei/
├── 07_xss/
├── checkpoints/
├── pipeline.log
└── SUMMARY.json
```

- checkpoints → enables resume mode
- SUMMARY.json → final statistics
- HTML report generated if report_builder.py exists

---

# ⌨️ Interrupt Behavior

- First Ctrl+C → Stops current tool and continues pipeline
- Rapid second Ctrl+C → Safe exit + report generation

---

# 🔒 Security Philosophy

ReconX is designed for:

- Professional bug bounty workflows
- Reproducible recon methodology
- Reduced manual tool chaining
- Clean report-ready output

---

# 📄 License

MIT License

---

# 👤 Author

Zulfukar Karabulut  
Security Researcher | Pentester | eWPTX & eCPPT
Linkedin : https://linkedin.com/in/2u1fuk4r

---

Use responsibly.
