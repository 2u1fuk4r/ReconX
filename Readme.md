# 🔍 ReconX – Bug Bounty Reconnaissance Framework

> **Professional, modular, fully automated recon platform for authorized bug bounty hunting.**

---

## ⚠️ Legal Disclaimer

This tool is intended **exclusively** for use against systems you are **authorized** to test, within the scope of a valid bug bounty program or with explicit written permission from the target organization. Unauthorized use violates the Computer Fraud and Abuse Act (CFAA), GDPR, KVKK, and similar laws worldwide.

**By using ReconX, you accept full legal responsibility for your actions.**

---

## ✨ Features

| Category | Tools |
|---|---|
| DNS Discovery | Sublist3r, amass, subfinder, assetfinder, altdns, dnscan, Knockpy |
| Port Scanning | nmap, masscan, naabu |
| Web Discovery | gobuster, dirsearch, ffuf, dirb, nuclei, EyeWitness, httpx |
| GitHub Secrets | truffleHog, gitrob, gitleaks, git-secrets |
| Cloud Storage | cloudbrute, bucket_finder, s3scanner |
| Wayback / History | waybackurls, gau, hakrawler |
| Google Dorks | GoogD0rker, auto-generated dork list |
| Asset ID | Shodan, Censys, theHarvester, whois |

**Other highlights:** parallel execution, HTML/Markdown/JSON reports, rate limiting, modular CLI menu, API key management, update mechanism.

---

## 📦 Installation

```bash
git clone <your-repo-url> reconx
cd reconx
chmod +x install.sh
sudo ./install.sh
```

The installer will:
- Install system packages (nmap, dirb, python3, go, ruby…)
- Clone and configure all git-based tools into `/opt/`
- Install Go tools via `go install`
- Download SecLists wordlists
- Set up Python dependencies

---

## ⚙️ Configuration

Edit `config.yaml` before first use:

```yaml
api_keys:
  shodan: "YOUR_SHODAN_KEY"
  censys_id: "YOUR_CENSYS_ID"
  github: "YOUR_GITHUB_TOKEN"
```

---

## 🚀 Usage

### Interactive mode (recommended)
```bash
python3 main.py
```
Enter your target domain and select modules from the menu.

### CLI flags
```bash
# Run all modules against a target
python3 main.py -d example.com -m A

# Run only DNS + Port scan modules
python3 main.py -d example.com -m 1 2

# Update all tools
python3 main.py --update

# Skip legal warning (for CI pipelines)
python3 main.py -d example.com -m A --no-legal
```

### Module numbers
| # | Module |
|---|--------|
| 1 | DNS Discovery |
| 2 | Port Scanning |
| 3 | Web Discovery |
| 4 | GitHub Secrets |
| 5 | Cloud Storage |
| 6 | Wayback / Old Content |
| 7 | Google Dorks |
| 8 | Asset Identification |
| A | All modules |

---

## 📁 Output Structure

```
output/
└── example.com_20241201_143022/
    ├── dns/
    │   ├── sublist3r.txt
    │   ├── amass.txt
    │   └── subfinder.txt
    ├── ports/
    │   ├── nmap_scan.nmap
    │   └── masscan.json
    ├── web/
    │   ├── gobuster.txt
    │   ├── nuclei.txt
    │   └── eyewitness/
    ├── github/
    │   └── trufflehog.txt
    ├── cloud/
    │   └── cloudbrute.txt
    ├── wayback/
    │   └── waybackurls.txt
    ├── assets/
    │   ├── shodan.txt
    │   └── whois.txt
    ├── results.json      ← machine-readable summary
    ├── report.html       ← visual HTML report
    ├── report.md         ← Markdown report
    └── recon.log         ← full execution log
```

---

## 🔄 Updating Tools

```bash
python3 main.py --update
```

---

## 💡 Effective Bug Bounty Recon Workflow

1. **DNS Discovery** → build subdomain list
2. **Port Scanning** → identify exposed services
3. **Web Discovery** → find hidden endpoints
4. **Wayback** → uncover old/forgotten content
5. **GitHub Secrets** → look for leaked credentials
6. **Cloud Storage** → find misconfigured S3 buckets
7. **Asset ID** → Shodan/Censys passive intel
8. Manually investigate findings using the HTML report

---

## 🤝 Contributing

Pull requests welcome! Please ensure new modules follow the `(name, cmd, output_file)` tuple pattern used throughout the framework.

---

## 📄 License

MIT – Use responsibly.
