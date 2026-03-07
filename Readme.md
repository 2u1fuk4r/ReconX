
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


![s0](https://github.com/user-attachments/assets/3e2bbcc1-75c2-4e75-9aaa-16e367a808f4)



==== The Proccess will working for each tools and steages ====

![process](https://github.com/user-attachments/assets/36e22773-8408-451d-a4d7-568f11b68dae)


=== Founds Xss ===
<img width="1289" height="748" alt="3" src="https://github.com/user-attachments/assets/1f27ac99-8d51-431a-bc81-f707f1b125db" />


====== The Last Report Will create and showing on browser =====

![dashboard](https://github.com/user-attachments/assets/8598948a-5633-4875-95bb-a17197ea949e)


===== Thread Map for all subdoamins ======
![s2](https://github.com/user-attachments/assets/9c92fbad-fb9c-43de-aa18-a6e7e4fc1469)




==== Alive Hosts ====
![s5](https://github.com/user-attachments/assets/c03bac8a-ae72-4370-882a-2290b040fc1d)



==== All Urls =====

![s6](https://github.com/user-attachments/assets/3d19b0c4-4075-4b3a-a699-26ce5e77052b)


==== Parameters ====
![s7](https://github.com/user-attachments/assets/214d418e-a28e-4a57-ab87-5fec514f498d)



==== Categorised =====
![s8](https://github.com/user-attachments/assets/36856679-894e-4cb7-99b5-96f6d48d2bda)

=====  Founds Xss && Poc =====

![s9](https://github.com/user-attachments/assets/51c48778-211a-46ed-8953-27aff252c2f7)
<img width="1603" height="746" alt="image" src="https://github.com/user-attachments/assets/97177540-00e7-4632-bbf6-31e1d615b7f1" />


==== Nuclei Vulns =====

![s10](https://github.com/user-attachments/assets/ea43bd00-41ef-49fa-a976-aab867bb4f08)



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
sudo python reconx.py -u example.com 
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
