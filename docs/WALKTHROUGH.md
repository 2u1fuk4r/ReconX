# Walkthrough — local lab (`harbor.lab:8088`)

This is one finished run against the local lab, not a third-party target.
The command was:

```bash
python3 reconX.py -d harbor.lab:8088 --auto
```

The session is `output/harbor.lab_20260928_073026`. Open Redirect was
re-checked afterwards with `--stage15`. Screenshots below are that report.

The dashboard score is **84 / CRITICAL**. That number is confirmed findings
only: 12 XSS and 4 open redirects. Nuclei, CORS, takeover and cloud buckets
contributed 0. Tech fingerprints are listed, and they do not move the score.

---

## 1. What the terminal captured, step by step

Each stage prints its tool, then writes a checkpoint. This is what this run
actually kept.

| Step | Stage | Tool | Captured |
|---|---|---|---|
| 1 | Recon | whois, whatweb, wafw00f, nmap | IP `127.0.0.1`. HTTP 200, server `HarborSupply/1.0`, client `curl_cffi`. No WAF. whois had nothing to say about a lab name (exit 1). |
| 2 | Subdomains | subfinder, assetfinder, findomain, crt.sh, `/etc/hosts` | Public resolvers returned **0**. `/etc/hosts` added **5** names: `harbor.lab`, `api`, `legacy`, `dev`, `files`. |
| 3 | Alive hosts | httpx on ports including **8088** | **5** live URLs, all `http://<name>:8088`. Block ratio 0. |
| 4 | URLs | gau, katana, then httpx prune | gau (archives) returned 0. katana crawled **127** lines. Prune dropped HTTP 404: **113 → 84** live URLs (25.7% removed, trusted). |
| 5 | Categorise | in-pipeline | params 20, reflection 8, forms 0, admin 4, login 8, api 15, sensitive 12, other 26, XSS targets **19**. |
| 6 | XSS | dalfox, 19 targets | **12 findings** in 81.3s. All 19 targets finished. Blind callback registered, **0** interactions. |
| 7 | Nuclei | templates + DAST | **0 findings**. The template pass was interrupted (Ctrl+C), so this stage is incomplete. |
| 8 | Auth crawl | login session | **Skipped** — no auth session was configured. |
| 9 | Parameters | arjun | **0** new hidden parameters. |
| 10 | JS secrets | download + grade | 6 JS files. **20** endpoints, **9** candidate rows in the summary (24 REAL / 8 public-by-design / 4 unclassified across hosts). |
| 11 | Tech priority | fingerprint rank | **5** hosts ranked, all medium. High-tech count is 0, and it is not a finding. |
| 12 | API discovery | patterns + live probe | **51** API-shaped URLs, 13 pattern hits, 38 answered live. The report badge shows 68 because it also counts related URL rows. |
| 13 | Network | naabu top ports, then nmap | **5** hosts, **0** open ports. The lab listens on 8088, which is outside the top-100 set, so this pass stays empty unless you point it at that port. |
| 14 | Open redirect | OpenRedireX + canary check | **4** confirmed. Parameter `redirect`, status 302, `Location: https://s1ber.com`. 4 URLs tested, 58s. |

CORS, subdomain takeover and cloud buckets were not run. They stay on the
Scan Center until you press Run.

---

## 2. Report, section by section

### Dashboard

Risk score 84, scan complete, delta against the previous lab session
(subdomains 5 → 5, alive 5 → 5, URLs +84). **Look here first** groups the
queue: XSS, one open redirect, then JS secrets. JS no longer fills the list
by itself.

![Dashboard](screens/01-dashboard.png)

### Threat Map

Five hosts. `harbor.lab` is the root. `api`, `dev` and `files` are high
(XSS). `legacy` is alive and quiet on findings.

![Threat Map](screens/02-threat-map.png)

### Recon

HTTP probe of the base URL: status 200, `Server: HarborSupply/1.0`,
`Content-Type: text/html`, client `curl_cffi`, WAF none. The other tabs on
this screen are WHOIS, Nmap, WhatWeb and WAF — the same four tools from
step 1.

![Recon](screens/03-recon.png)

### Subdomains

The five names from `/etc/hosts`. Public subdomain tools contributed none.

![Subdomains](screens/04-subdomains.png)

### Alive Hosts

The same five names, each answering on port 8088.

![Alive hosts](screens/05-alive.png)

### All URLs

84 URLs kept after the 404 prune. This is the corpus every later stage reads.

![All URLs](screens/06-urls.png)

### Parameters

Parameters already present on those URLs (20 URLs in the params bucket).
Arjun did not add hidden ones on this run.

![Parameters](screens/07-parameters.png)

### Categorised

The step-5 buckets: admin, login, api, sensitive, reflection, XSS targets,
and the rest.

![Categorised](screens/08-categorised.png)

### JS Secrets

20 endpoints, 9 candidates, 24 rows graded REAL, 4 unclassified, 8
public-by-design. The REAL rows in this lab are fixtures planted in the
test site (the AWS example key id, a placeholder private-key block, and
similar stand-ins). They are not credentials from a real engagement.

![JS Secrets](screens/09-js-secrets.png)

### API Discovery

API-shaped paths and the ones that answered.

![API Discovery](screens/10-api.png)

### Tech Priority

Five hosts, medium. This is a queue for what to test next, not a vulnerability
count. It does not change the CRITICAL badge.

![Tech Priority](screens/11-tech-priority.png)

### Scan Center

On-demand cards. XSS, Nuclei, Open Redirect and Network already have a result
on this session. CORS, Subdomain Takeover and Cloud Bucket are still
"press Run".

![Scan Center](screens/12-scan-center.png)

### Nuclei

0 findings. The card says the run was interrupted, so an empty table here is
not the same as a finished clean scan.

![Nuclei](screens/13-nuclei.png)

### XSS

12 findings, risk HIGH. 4 dialogs confirmed in a headless replay (screenshot
in the section), 6 marked verified by the scanner without a captured dialog,
2 reflected only.

![XSS](screens/14-xss.png)

### Open Redirect

4 confirmed, 4 tested. Each row is `redirect` → `https://s1ber.com` with
HTTP 302. Copy PoC opens that URL; the browser lands on s1ber.com.

![Open Redirect](screens/15-open-redirect.png)

### Extra Checks

CORS, takeover and bucket results. All three are 0 because those scans were
not started.

![Extra Checks](screens/16-extra-checks.png)

### AI Analysis

The panel is ready. Nothing on this page has been sent to the model until
you press **Run AI Analysis**. Leads that appear afterwards are unverified.

![AI Analysis](screens/17-ai-analysis.png)
