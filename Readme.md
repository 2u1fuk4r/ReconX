
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

<img width="665" height="791" alt="image" src="https://github.com/user-attachments/assets/e8e71d50-10fb-44d4-a283-d106bb02780a" />


==== The Proccess will working for each tools and steages ====

<img width="655" height="793" alt="image" src="https://github.com/user-attachments/assets/def8eba7-a40e-40b0-8a0d-da76367a9a4b" />


====== The Last Report Will create and showing on browser =====
<img width="1742" height="717" alt="image" src="https://github.com/user-attachments/assets/46cc1b1a-e5f1-4d50-98f1-cd521ccb8f2f" />


===== Thread Map for all subdoamins ======
<img width="949" height="721" alt="image" src="https://github.com/user-attachments/assets/eca77a6a-99c3-4b92-a5c2-ee6046471020" />



==== Alive Hosts ====
<img width="1777" height="738" alt="image" src="https://github.com/user-attachments/assets/f37423b3-8dd8-4a56-8887-8e2db3b33e54" />


==== All Urls =====
<img width="1779" height="719" alt="image" src="https://github.com/user-attachments/assets/3960b8d1-5bd3-4739-85b3-1e9e44f6c3cd" />


==== Parameters ====
<img width="1802" height="737" alt="image" src="https://github.com/user-attachments/assets/51ac21ca-79d2-4fc7-97d2-3e059fe31b12" />


==== Categorised =====
<img width="1760" height="741" alt="image" src="https://github.com/user-attachments/assets/c07d1fac-e24a-4e27-a04a-d38aa8b2a208" />


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
sudo python reconx.py -d example.com --single
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
## Sinle Target
```bash
sudo python reconx.py -d example.com --single
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
