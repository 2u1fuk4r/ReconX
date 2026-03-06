
# 🔍 ReconX v6.0  
### Sequential Bug Bounty Reconnaissance Pipeline

ReconX is a stage-based, automation-first reconnaissance framework designed for authorized bug bounty and penetration testing engagements.

Pipeline:
Recon → Subdomains → Alive → URLs → Categorize → Nuclei → XSS

---

## ⚠️ Legal Disclaimer

This tool must only be used on targets you are explicitly authorized to test.  
Unauthorized scanning is illegal.

Use `--no-legal` only in CI or fully authorized automated environments.


![Screenshot 2026-03-07 002457 py](https://github.com/user-attachments/assets/ead8ef26-9225-48fd-b5e1-1d55c0cd7811)

<img width="725" height="362" alt="1" src="https://github.com/user-attachments/assets/a3648e9c-27f1-415f-9f1d-f4d882abf94a" />


==== The Proccess will working for each tools and steages ====

<img width="1004" height="739" alt="2" src="https://github.com/user-attachments/assets/06486d95-3b6d-4e03-9c66-8431bebcfca7" />



====== The Last Report Will create and showing on browser =====

![dashboard](https://github.com/user-attachments/assets/8598948a-5633-4875-95bb-a17197ea949e)


===== Thread Map for all subdoamins ======
<img width="949" height="721" alt="image" src="https://github.com/user-attachments/assets/eca77a6a-99c3-4b92-a5c2-ee6046471020" />



==== Alive Hosts ====
<img width="1777" height="738" alt="alive" src="https://github.com/user-attachments/assets/b388072f-d995-4e50-8887-5d7a8272abb9" />


==== All Urls =====

<img width="1779" height="719" alt="all urls" src="https://github.com/user-attachments/assets/ac04d77b-e7c0-496e-9200-58282a6702c0" />


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
