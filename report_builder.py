#!/usr/bin/env python3

import json, re, html
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs


# ── File helpers ───────────────────────────────────────────────────────────────
def _read(p) -> str:
    try:
        return Path(p).read_text(errors="ignore") if p and Path(p).exists() else ""
    except:
        return ""

def _lines(p) -> list:
    return [l.strip() for l in _read(p).splitlines() if l.strip()]

def _json_lines(p) -> list:
    out = []
    for line in _lines(p):
        try:
            parsed = json.loads(line)
            if isinstance(parsed, list):
                out.extend(d for d in parsed if isinstance(d, dict))
            elif isinstance(parsed, dict):
                out.append(parsed)
        except:
            pass
    return out

def _e(s) -> str:
    return html.escape(str(s) if s is not None else "", quote=True)

def _safe_content(s: str) -> str:
    return html.escape(str(s or ""), quote=True)

def _safe_json(data) -> str:
    raw = json.dumps(data, ensure_ascii=False, default=str)
    raw = raw.replace('<', r'\u003c').replace('>', r'\u003e').replace('&', r'\u0026')
    return raw

# ── XSS URL safety ────────────────────────────────────────────────────────────
_UNSAFE_PROTO = re.compile(r'^\s*(javascript|data|vbscript)\s*:', re.I)

def _safe_href(url: str) -> str:
    """
    Normal https:// URL → tıklanabilir link döndür.
    javascript: / data: / vbscript: → boş string (sadece metin göster).
    """
    s = url.strip()
    if _UNSAFE_PROTO.match(s):
        return ""
    if s.startswith(("https://", "http://")):
        return s
    return ""


# ── Data parsers ───────────────────────────────────────────────────────────────
def _parse_recon(d: Path) -> dict:
    probe = {}
    probe_f = d / "01_recon" / "http_probe.json"
    if probe_f.exists():
        try:
            probe = json.loads(probe_f.read_text(errors="ignore")) or {}
        except:
            pass
    return {
        "whois":     _read(d / "01_recon" / "whois.txt"),
        "nmap":      _read(d / "01_recon" / "nmap.txt"),
        "whatweb":   _read(d / "01_recon" / "whatweb.txt"),
        "wafw00f":   _read(d / "01_recon" / "wafw00f.txt"),
        "harvester": _read(d / "01_recon" / "theharvester.xml") or _read(d / "01_recon" / "theharvester.json"),
        "shodan":    _read(d / "01_recon" / "shodan.txt"),
        "probe":     probe,
    }

def _clean_subdomain(line: str) -> str:
    line = re.sub(r'\x1b\[[0-9;]*m', '', line)
    line = re.sub(r'\[\[?[0-9;]*m\]?', '', line)
    parts = line.split()
    line = parts[0] if parts else ""
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', line):
        return ""
    return line.lower()

def _parse_subdomains(d: Path) -> dict:
    tools = {}
    all_s = set()
    sd = d / "02_subdomains"
    if sd.exists():
        for f in sd.glob("*.txt"):
            if f.name == "all_raw.txt":
                continue
            ls = [_clean_subdomain(l) for l in _lines(f)]
            ls = [x for x in ls if x]
            if ls:
                tools[f.stem] = ls
                all_s.update(ls)
    cleaned = [_clean_subdomain(l) for l in _lines(d / "checkpoints" / "stage2_subdomains.txt")]
    all_s.update(x for x in cleaned if x)
    return {"by_tool": tools, "all": sorted(all_s)}

def _parse_alive(d: Path) -> list:
    hosts = []
    seen = set()
    httpx_json = d / "03_alive" / "httpx_full.json"
    if httpx_json.exists() and httpx_json.stat().st_size > 0:
        for line in httpx_json.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except:
                continue
            url = rec.get("url") or rec.get("input") or ""
            if not url or not url.startswith("http"):
                continue
            if url in seen:
                continue
            seen.add(url)
            tech_raw = rec.get("tech") or rec.get("technologies") or []
            tech = ", ".join(str(t) for t in tech_raw[:8]) if isinstance(tech_raw, list) else str(tech_raw)[:120]
            ip = rec.get("host") or rec.get("a") or rec.get("ip") or ""
            if isinstance(ip, list):
                ip = ip[0] if ip else ""
            rt = rec.get("time") or rec.get("response-time") or ""
            cl = rec.get("content-length") or rec.get("content_length") or ""
            hosts.append({
                "url":    url,
                "status": str(rec.get("status-code") or rec.get("status_code") or ""),
                "title":  (rec.get("title") or "")[:80],
                "ip":     str(ip)[:22],
                "tech":   tech[:120],
                "size":   str(cl),
                "server": (rec.get("webserver") or rec.get("server") or "")[:50],
                "rt":     str(rt)[:12],
            })
        if hosts:
            return hosts

    hd = d / "03_alive" / "hosts_detail.json"
    if hd.exists():
        try:
            data = json.loads(hd.read_text(errors="ignore"))
            if isinstance(data, list):
                return data
        except:
            pass

    for line in _lines(d / "checkpoints" / "stage3_alive.txt"):
        if line not in seen:
            seen.add(line)
            hosts.append({"url": line, "status": "", "title": "", "ip": "",
                          "tech": "", "size": "", "server": "", "rt": ""})
    return hosts

def _parse_url_categories(d: Path) -> dict:
    cats = {}
    for name in ["params", "reflection", "forms", "admin", "login", "api", "sensitive", "other"]:
        cats[name] = _lines(d / "05_categorized" / f"{name}.txt")
    cats["_all"]        = _lines(d / "checkpoints" / "stage4_urls.txt")
    cats["_gau"]        = _lines(d / "04_urls" / "gau.txt")
    cats["_wayback"]    = _lines(d / "04_urls" / "waybackurls.txt")
    cats["_katana"]     = _lines(d / "04_urls" / "katana.txt")
    cats["_hakrawler"]  = _lines(d / "04_urls" / "hakrawler_clean.txt") or _lines(d / "04_urls" / "hakrawler.txt")
    cats["_linkfinder"] = _lines(d / "04_urls" / "linkfinder.txt")
    cats["_priority"]   = _lines(d / "05_categorized" / "reflection_priority.txt")
    return cats

def _parse_nuclei(d: Path) -> dict:
    results = []
    nd = d / "07_nuclei"
    if not nd.exists():
        nd = d / "06_nuclei"

    if nd.exists():
        json_files = list(nd.glob("*.json"))
        for f in json_files:
            for rec in _json_lines(f):
                if not isinstance(rec, dict):
                    continue
                info_block     = rec.get("info", {}) or {}
                classification = info_block.get("classification", {}) or {}
                cve_ids = classification.get("cve-id", []) or []
                if isinstance(cve_ids, str):
                    cve_ids = [cve_ids]
                cvss = classification.get("cvss-score") or classification.get("cvss_score") or ""
                refs = info_block.get("reference") or []
                if isinstance(refs, str):
                    refs = [refs]
                results.append({
                    "severity":  (info_block.get("severity") or "info").lower(),
                    "name":      info_block.get("name") or rec.get("template-id", ""),
                    "template":  rec.get("template-id", ""),
                    "host":      rec.get("host", ""),
                    "url":       rec.get("matched-at", ""),
                    "tags":      ", ".join((info_block.get("tags") or [])[:5]),
                    "cve":       ", ".join(cve_ids[:3]),
                    "cvss":      str(cvss) if cvss else "",
                    "refs":      refs[:3],
                    "raw":       "",
                })

    if not results and nd.exists():
        for f in nd.glob("*.txt"):
            for line in _lines(f):
                sm  = re.search(r'\[(critical|high|medium|low|info)\]', line, re.I)
                sev = sm.group(1).lower() if sm else "info"
                um  = re.search(r'(https?://\S+)', line)
                tm  = re.search(r'\[([a-z0-9\-]+:[a-z0-9\-]+)\]', line, re.I)
                cve = re.search(r'(CVE-\d{4}-\d+)', line, re.I)
                results.append({
                    "severity": sev,
                    "name":     (tm.group(1) if tm else line[:80]),
                    "template": tm.group(1) if tm else "",
                    "host":     "",
                    "url":      um.group(1) if um else "",
                    "tags":     "",
                    "cve":      cve.group(1) if cve else "",
                    "cvss":     "",
                    "refs":     [],
                    "raw":      line,
                })

    seen = set(); unique = []
    for r in results:
        k = r.get("url") or r.get("raw") or r.get("name")
        if k not in seen:
            seen.add(k); unique.append(r)

    by_sev = {s: [] for s in ["critical", "high", "medium", "low", "info", "other"]}
    for r in unique:
        by_sev.get(r["severity"], by_sev["other"]).append(r)

    return {"all": unique, "by_severity": by_sev}

def _extract_url_from_dalfox_line(line: str) -> str:
    m = re.search(r'(https?://\S+)', line)
    if m:
        url = m.group(1).rstrip('.,;)')
        return url
    return ""

def _parse_xss(d: Path) -> dict:
    # v6.6: tier dosyaları + eski dosyalar
    xd = d / "06_xss"
    if not xd.exists():
        xd = d / "07_xss"
    if not xd.exists():
        return {"all": [], "pocs": [], "poc_urls": [], "r1": [], "r2": [], "r3": []}

    all_lines = []
    # v6.6 tier dosyaları önce
    for fname in [
        "dalfox_findings_tier1.txt",
        "dalfox_findings_tier2.txt",
        "dalfox_findings_tier3.txt",
        "dalfox_all_findings.txt",
        # eski isimler (geriye dönük uyumluluk)
        "dalfox_findings.txt",
        "dalfox_all.txt",
        "dalfox_findings_rerun.txt",
        "dalfox_all_rerun.txt",
    ]:
        p = xd / fname
        if p.exists():
            all_lines.extend(_lines(p))

    seen = set(); final = []
    for l in all_lines:
        if l not in seen:
            seen.add(l); final.append(l)

    pocs = [l for l in final if re.search(r'\[poc\]|\[vuln\]', l, re.I)]

    poc_urls = []
    seen_urls = set()
    for l in pocs:
        url = _extract_url_from_dalfox_line(l)
        if url and url not in seen_urls:
            seen_urls.add(url)
            poc_urls.append({"raw": l, "url": url})

    return {
        "all":      final,
        "pocs":     pocs,
        "poc_urls": poc_urls,
        "r1":       _lines(xd / "dalfox_r1.txt"),
        "r2":       _lines(xd / "dalfox_r2.txt"),
        "r3":       _lines(xd / "dalfox_r3.txt"),
    }

def _parse_summary_json(d: Path) -> dict:
    sf = d / "SUMMARY.json"
    if sf.exists():
        try:
            return json.loads(sf.read_text(errors="ignore")) or {}
        except:
            pass
    return {}


# ── HTML components ────────────────────────────────────────────────────────────
def _badge(text: str, color: str = "blue") -> str:
    colors = {
        "red":    ("#2d0d0d", "#ff6b6b"),
        "orange": ("#2d1a00", "#ffa94d"),
        "yellow": ("#2a1f00", "#ffd43b"),
        "blue":   ("#0d1f2d", "#74c0fc"),
        "green":  ("#0d2414", "#69db7c"),
        "purple": ("#1a0d2d", "#cc5de8"),
        "gray":   ("#1a1f26", "#868e96"),
        "cyan":   ("#001f26", "#3bc9db"),
        "pink":   ("#2d0d1a", "#f783ac"),
    }
    bg, fg = colors.get(color, colors["blue"])
    return (f'<span style="background:{bg};color:{fg};padding:2px 10px;border-radius:20px;'
            f'font-size:11px;font-weight:700;letter-spacing:.4px;white-space:nowrap">'
            f'{_e(text)}</span>')

def _sev_badge(sev: str) -> str:
    m = {"critical": "red", "high": "orange", "medium": "yellow", "low": "blue", "info": "gray"}
    return _badge((sev or "info").upper(), m.get(sev, "gray"))

def _stat(val, label: str, color: str, icon: str) -> str:
    cols = {
        "red": "#ff6b6b", "orange": "#ffa94d", "blue": "#74c0fc",
        "green": "#69db7c", "yellow": "#ffd43b", "purple": "#cc5de8", "gray": "#868e96"
    }
    c = cols.get(color, "#74c0fc")
    n = f"{val:,}" if isinstance(val, int) else str(val)
    return (f'<div class="stat-card">'
            f'<div class="stat-icon">{icon}</div>'
            f'<div class="stat-val" style="color:{c}">{n}</div>'
            f'<div class="stat-lbl">{_e(label)}</div>'
            f'</div>')

def _empty(msg: str = "No data recorded") -> str:
    return f'<div class="empty-state">📭 {_e(msg)}</div>'

def _code_block(text: str, max_lines: int = 400) -> str:
    if not text.strip():
        return _empty()
    lines = text.splitlines()
    shown = "\n".join(lines[:max_lines])
    extra = f"\n\n... {len(lines) - max_lines:,} more lines in output file" if len(lines) > max_lines else ""
    return f'<pre class="code-block">{_safe_content(shown + extra)}</pre>'

def _vscroll(data: list, uid: str, kind: str = "URL") -> str:
    safe = _safe_json(data)
    return f'''<div class="vs-wrap">
  <div class="vs-toolbar">
    <span class="vs-counter" id="{_e(uid)}-cnt"></span>
    <input class="vs-search" id="{_e(uid)}-q" placeholder="Filter {_e(kind)}s..." oninput="vsFilter('{_e(uid)}')">
    <button class="btn-sm" onclick="vsCopy('{_e(uid)}')">Copy all</button>
    <button class="btn-sm" onclick="vsExport('{_e(uid)}')">Export .txt</button>
  </div>
  <div class="vs-scroll" id="{_e(uid)}-scroll" onscroll="vsRender('{_e(uid)}')">
    <div class="vs-vp" id="{_e(uid)}-vp"></div>
  </div>
</div>
<script>(function(){{
  var R=window._VS=window._VS||{{}};
  R['{_e(uid)}']={{raw:{safe},filtered:{safe}}};
  (window._VSQ=window._VSQ||[]).push('{_e(uid)}');
}})();</script>'''

def _vtable(headers: list, rows: list, uid: str) -> str:
    if not rows:
        return _empty()
    safe = _safe_json(rows)
    hdr  = "".join(f"<th>{_e(h)}</th>" for h in headers)
    return f'''<div class="vt-wrap">
  <div class="vs-toolbar">
    <span class="vs-counter" id="{_e(uid)}-cnt"></span>
    <input class="vs-search" id="{_e(uid)}-q" placeholder="Filter..." oninput="vtFilter('{_e(uid)}')">
    <button class="btn-sm" onclick="vtCopy('{_e(uid)}')">Copy</button>
    <button class="btn-sm" onclick="vtExportCSV('{_e(uid)}')">CSV</button>
  </div>
  <div class="tbl-scroll">
    <table><thead><tr>{hdr}</tr></thead><tbody id="{_e(uid)}-body"></tbody></table>
    <div class="vt-more" id="{_e(uid)}-more"></div>
  </div>
</div>
<script>(function(){{
  var R=window._VT=window._VT||{{}};
  R['{_e(uid)}']={{raw:{safe},filtered:{safe},page:0,headers:{_safe_json(headers)}}};
  (window._VTQ=window._VTQ||[]).push('{_e(uid)}');
}})();</script>'''

def _tabs(items: list, prefix: str) -> str:
    if not items:
        return _empty()
    tabs  = []
    panes = []
    for i, (tid, label, content) in enumerate(items):
        active = "active" if i == 0 else ""
        tabs.append(
            f'<button class="tab {active}" onclick="tab(this,\'{_e(prefix)}-{_e(tid)}\')">{label}</button>'
        )
        panes.append(
            f'<div class="pane {active}" id="{_e(prefix)}-{_e(tid)}">{content}</div>'
        )
    return (f'<div class="tab-row">{"".join(tabs)}</div>'
            f'<div class="panes">{"".join(panes)}</div>')


# ── Section builders ───────────────────────────────────────────────────────────
def _section_overview(target, ts, recon, subs, alive, urls, nuclei, xss, summary, smry_json):
    sc_n    = len(subs["all"])
    alive_n = len(alive)
    url_n   = len(urls.get("_all", []))
    par_n   = len(urls.get("params", []))
    sens_n  = len(urls.get("sensitive", []))
    refl_n  = len(urls.get("reflection", []))
    nuc_n   = len(nuclei["all"])
    xss_n   = len(xss["all"])
    poc_n   = len(xss["pocs"])
    by_sev  = nuclei["by_severity"]

    # Nuclei sayısı: info hariç önemli bulgular
    nuc_important = sum(len(by_sev.get(s, [])) for s in ["critical","high","medium","low"])

    stats_html = "".join([
        _stat(sc_n,    "Subdomains",   "green",  "🌐"),
        _stat(alive_n, "Alive Hosts",  "blue",   "💻"),
        _stat(url_n,   "URLs Found",   "purple", "🔗"),
        _stat(par_n,   "Param URLs",   "orange", "🧩"),
        _stat(refl_n,  "Reflection",   "yellow", "🪞"),
        _stat(sens_n,  "Sensitive",    "red",    "⚠️"),
        _stat(nuc_important, "Nuclei Hits", "red", "🎯"),
        _stat(len(by_sev.get("critical", [])) + len(by_sev.get("high", [])),
              "Crit+High",    "red",    "🔴"),
        _stat(xss_n,  "XSS Findings", "orange", "💉"),
        _stat(poc_n,  "XSS PoCs",     "red",    "🔥"),
    ])

    probe = recon.get("probe", {})
    waf_list = smry_json.get("waf_fingerprint") or probe.get("waf_fingerprint") or []
    waf_html = ""
    if waf_list:
        waf_badges = " ".join(_badge(w.upper(), "orange") for w in waf_list)
        waf_html = f'<div class="panel" style="margin-top:12px"><h3>🛡️ WAF / CDN Detected</h3><div style="margin-top:8px">{waf_badges}</div></div>'
    else:
        waf_html = '<div class="panel" style="margin-top:12px"><h3>🛡️ WAF / CDN</h3><div style="color:var(--mu);font-size:13px;margin-top:6px">No WAF detected</div></div>'

    block_ratio = smry_json.get("block_ratio_httpx") or smry_json.get("stages", {}).get("stage3", {}).get("block_ratio") or 0
    adapt_mult  = smry_json.get("adaptive_multiplier") or 1.0
    adapt_html  = ""
    if float(block_ratio) > 0.05:
        pct = f"{float(block_ratio)*100:.1f}%"
        col = "red" if float(block_ratio) > 0.3 else "orange" if float(block_ratio) > 0.1 else "yellow"
        adapt_html = (f'<div style="margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">'
                      f'{_badge(f"Block ratio: {pct}", col)}'
                      f'{_badge(f"Rate mult: {float(adapt_mult):.2f}x", "blue")}'
                      f'</div>')

    stages = [
        ("Recon",      bool(recon["whois"] or recon["nmap"]), "🔍"),
        ("Subdomains", bool(subs["all"]),                     "🌐"),
        ("Alive",      bool(alive),                           "💻"),
        ("URLs",       bool(url_n),                           "🔗"),
        ("Categorise", bool(par_n or refl_n),                 "📂"),
        ("XSS",        bool(xss_n),                           "💉"),
        ("Nuclei",     bool(nuc_n),                           "🎯"),
    ]
    tl = '<div class="timeline">'
    for lbl, done, icon in stages:
        cls = "tl-done" if done else "tl-skip"
        tl += (f'<div class="tl-step {cls}">'
               f'<div class="tl-dot">{icon}</div>'
               f'<div class="tl-lbl">{_e(lbl)}</div>'
               f'</div>')
    tl += "</div>"

    sev_bar = '<div class="sev-bar">'
    for sev, col in [("critical", "#ff6b6b"), ("high", "#ffa94d"),
                     ("medium", "#ffd43b"), ("low", "#74c0fc"), ("info", "#868e96")]:
        c = len(by_sev.get(sev, []))
        if c:
            sev_bar += (f'<div style="flex:{c};background:{col};min-width:3px;'
                        f'border-radius:2px" title="{_e(sev)}: {c}"></div>')
    sev_bar += "</div>"
    sev_leg = '<div class="sev-legend">'
    for sev, col in [("Critical", "#ff6b6b"), ("High", "#ffa94d"),
                     ("Medium", "#ffd43b"), ("Low", "#74c0fc"), ("Info", "#868e96")]:
        c = len(by_sev.get(sev.lower(), []))
        sev_leg += (f'<span class="sev-item">'
                    f'<span style="background:{col};width:8px;height:8px;border-radius:50%;'
                    f'display:inline-block;margin-right:5px"></span>'
                    f'{_e(sev)}: <b>{c}</b></span>')
    sev_leg += "</div>"

    cat_data = {
        "params": par_n, "reflection": refl_n, "admin": len(urls.get("admin",[])),
        "login": len(urls.get("login",[])), "api": len(urls.get("api",[])),
        "sensitive": sens_n, "forms": len(urls.get("forms",[])),
    }
    cat_max = max(cat_data.values()) if any(cat_data.values()) else 1
    cat_colors = {"params":"#ffa94d","reflection":"#ff6b6b","admin":"#ff453a",
                  "login":"#ffd43b","api":"#cc5de8","sensitive":"#f85149","forms":"#74c0fc"}
    cat_bars = ""
    for k, v in sorted(cat_data.items(), key=lambda x: -x[1]):
        if v == 0:
            continue
        pct = max(4, int(v / cat_max * 100))
        cat_bars += (f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'
                     f'<div style="width:75px;font-size:11px;color:var(--mu);text-align:right">{_e(k)}</div>'
                     f'<div style="flex:1;background:var(--s3);border-radius:4px;height:16px;overflow:hidden">'
                     f'<div style="width:{pct}%;background:{cat_colors.get(k,"#74c0fc")};height:100%;'
                     f'border-radius:4px;min-width:4px;transition:width .5s"></div></div>'
                     f'<div style="width:50px;font-size:11px;font-family:var(--mono);color:var(--tx)">{v:,}</div>'
                     f'</div>')

    adapt_events = smry_json.get("adaptive_events") or []
    adapt_tl = ""
    if adapt_events:
        adapt_tl = '<div style="margin-top:8px">'
        for ev in adapt_events[:8]:
            reason = _e(ev.get("reason", ""))
            ts_ev  = _e(ev.get("ts", ""))
            mb = ev.get("mult_before", 1.0)
            ma = ev.get("mult_after", 1.0)
            col = "red" if float(ma) < 0.3 else "orange"
            adapt_tl += (f'<div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:8px;'
                         f'padding:8px 10px;background:var(--s3);border-radius:6px;border-left:3px solid #{("ff453a" if col=="red" else "ffa94d")}">'
                         f'<div style="flex:1"><div style="font-size:11px;color:var(--tx)">{reason}</div>'
                         f'<div style="font-size:10px;color:var(--mu);margin-top:2px">{ts_ev}</div></div>'
                         f'<div style="white-space:nowrap">{_badge(f"{mb:.2f}→{ma:.2f}x", col)}</div>'
                         f'</div>')
        if len(adapt_events) > 8:
            adapt_tl += f'<div style="font-size:11px;color:var(--mu)">... +{len(adapt_events)-8} more events</div>'
        adapt_tl += "</div>"

    return f'''
<div id="s-overview" class="section active">
  <div class="sec-hdr"><h2>Dashboard</h2><p class="sec-sub">Target: <code>{_e(target)}</code> · {_e(ts)}</p></div>
  {adapt_html}
  <div class="stat-grid">{stats_html}</div>

  <div class="two-col" style="margin-top:20px">
    <div class="panel"><h3>Pipeline</h3>{tl}</div>
    <div class="panel"><h3>Nuclei Severity</h3>{sev_bar}{sev_leg}
      <div class="mini-grid" style="margin-top:14px">
        <div class="mini-num" style="color:#ff6b6b">{len(by_sev.get("critical",[]))}<span>Critical</span></div>
        <div class="mini-num" style="color:#ffa94d">{len(by_sev.get("high",[]))}<span>High</span></div>
        <div class="mini-num" style="color:#ffd43b">{len(by_sev.get("medium",[]))}<span>Medium</span></div>
        <div class="mini-num" style="color:#74c0fc">{len(by_sev.get("low",[]))}<span>Low</span></div>
      </div>
    </div>
  </div>

  <div class="two-col" style="margin-top:14px">
    <div class="panel">
      <h3>URL Categories</h3>
      <div style="margin-top:12px">{cat_bars if cat_bars else "<div style='color:var(--mu);font-size:13px'>No categorised URLs yet</div>"}</div>
    </div>
    <div>
      {waf_html}
      {"<div class='panel' style='margin-top:12px'><h3>⚡ Adaptive Rate Events</h3>" + adapt_tl + "</div>" if adapt_events else ""}
    </div>
  </div>
</div>'''

def _section_recon(recon):
    probe = recon.get("probe", {})
    probe_html = ""
    if probe.get("ok"):
        sc  = probe.get("status", "")
        srv = probe.get("server", "")
        ct  = probe.get("content_type", "")
        cl  = probe.get("client", "")
        waf = ", ".join(probe.get("waf_fingerprint", [])) or "None detected"
        probe_html = (f'<div class="probe-card">'
                      f'<div class="probe-row"><span>Status</span><b>{_e(str(sc))}</b></div>'
                      f'<div class="probe-row"><span>Server</span><b>{_e(srv)}</b></div>'
                      f'<div class="probe-row"><span>Content-Type</span><b>{_e(ct)}</b></div>'
                      f'<div class="probe-row"><span>HTTP Client</span><b>{_e(cl)}</b></div>'
                      f'<div class="probe-row"><span>WAF</span><b>{_e(waf)}</b></div>'
                      f'</div>')

    items = [
        ("probe",   "HTTP Probe", probe_html or _empty("Probe data not available")),
        ("whois",   "WHOIS",     _code_block(recon["whois"])),
        ("nmap",    "Nmap",      _code_block(recon["nmap"])),
        ("whatweb", "WhatWeb",   _code_block(recon["whatweb"])),
        ("waf",     "WAF",       _code_block(recon["wafw00f"])),
        ("harvest", "Harvester", _code_block(recon["harvester"])),
        ("shodan",  "Shodan",    _code_block(recon["shodan"])),
    ]
    tab_items = [(tid, lbl, c) for tid, lbl, c in items if c != _empty()]
    body = _tabs(tab_items, "recon") if tab_items else _empty()
    return f'<div id="s-recon" class="section"><div class="sec-hdr"><h2>🔍 Reconnaissance</h2></div>{body}</div>'

def _section_subdomains(subs):
    all_s = subs["all"]
    tool_rows = sorted(
        [[t, str(len(u)), "; ".join(u[:3]) + ("…" if len(u) > 3 else "")]
         for t, u in subs["by_tool"].items() if u],
        key=lambda r: -int(r[1])
    )
    body = (f'{_vscroll(all_s, "vs-subs", "subdomain")}'
            f'<div style="margin-top:24px"><h3 style="color:#868e96;font-size:12px;'
            f'text-transform:uppercase;letter-spacing:.8px;margin-bottom:12px">Tool Breakdown</h3>'
            f'{_vtable(["Tool", "Count", "Sample"], tool_rows, "vt-sub-tools")}</div>'
            if all_s else _empty())
    return (f'<div id="s-subdomains" class="section">'
            f'<div class="sec-hdr"><h2>🌐 Subdomains</h2>'
            f'<p class="sec-sub">{len(all_s):,} unique subdomains discovered</p></div>'
            f'{body}</div>')

def _section_alive(alive):
    if not alive:
        return (f'<div id="s-alive" class="section">'
                f'<div class="sec-hdr"><h2>💻 Alive Hosts</h2></div>{_empty()}</div>')

    sc_dist: dict = {}
    for h in alive:
        sc = str(h.get("status","") or "")
        if sc:
            grp = sc[0] + "xx"
            sc_dist[grp] = sc_dist.get(grp, 0) + 1

    sc_colors = {"2xx": "#34c759", "3xx": "#74c0fc", "4xx": "#ffd43b", "5xx": "#ff453a"}
    sc_pills = " ".join(
        f'<span style="background:{sc_colors.get(g,"#6e8098")}22;color:{sc_colors.get(g,"#6e8098")};'
        f'padding:3px 10px;border-radius:20px;font-size:12px;font-weight:700;font-family:var(--mono)">'
        f'{_e(g)}: {c}</span>'
        for g, c in sorted(sc_dist.items())
    )

    rows = [
        [h.get("url",""), str(h.get("status","")), (h.get("title","") or "")[:60],
         (h.get("ip","") or "")[:20], (h.get("tech","") or "")[:80],
         str(h.get("size","") or ""), (h.get("server","") or "")[:40],
         (h.get("rt","") or "")]
        for h in alive
    ]
    safe = _safe_json(rows)
    return f'''<div id="s-alive" class="section">
  <div class="sec-hdr"><h2>💻 Alive Hosts</h2>
    <p class="sec-sub">{len(alive):,} responsive hosts</p>
  </div>
  <div style="margin-bottom:12px">{sc_pills}</div>
  <div class="vt-wrap">
    <div class="vs-toolbar">
      <span class="vs-counter" id="alive-cnt"></span>
      <input class="vs-search" id="alive-q" placeholder="Filter hosts..." oninput="aliveFilter()">
      <button class="btn-sm" onclick="aliveCopy()">Copy URLs</button>
      <button class="btn-sm" onclick="aliveCSV()">Export CSV</button>
    </div>
    <div class="tbl-scroll">
      <table><thead><tr>
        <th>URL</th><th>Status</th><th>Title</th>
        <th>IP</th><th>Tech</th><th>Size</th><th>Server</th><th>RT</th>
      </tr></thead>
      <tbody id="alive-body"></tbody></table>
      <div class="vt-more" id="alive-more"></div>
    </div>
  </div>
</div>
<script>(function(){{
  window._AR={safe};window._AF={safe};window._AP=0;window._AliveReady=true;
}})();</script>'''

def _section_urls(urls):
    all_u = urls.get("_all", [])
    tool_tabs = [
        ("all",        f"All ({len(all_u):,})",                           all_u),
        ("gau",        f"gau ({len(urls.get('_gau',[])):,})",             urls.get("_gau",[])),
        ("wayback",    f"Wayback ({len(urls.get('_wayback',[])):,})",      urls.get("_wayback",[])),
        ("katana",     f"Katana ({len(urls.get('_katana',[])):,})",        urls.get("_katana",[])),
        ("hakrawler",  f"Hakrawler ({len(urls.get('_hakrawler',[])):,})",  urls.get("_hakrawler",[])),
        ("linkfinder", f"LinkFinder ({len(urls.get('_linkfinder',[])):,})",urls.get("_linkfinder",[])),
    ]
    tab_items = [(tid, label, _vscroll(data, f"vs-url-{tid}"))
                 for tid, label, data in tool_tabs if data]
    body = _tabs(tab_items, "url") if tab_items else _empty()
    return (f'<div id="s-urls" class="section">'
            f'<div class="sec-hdr"><h2>🔗 URL Discovery</h2>'
            f'<p class="sec-sub">{len(all_u):,} unique URLs</p></div>'
            f'{body}</div>')

def _section_categorised(urls):
    cats = [
        ("reflection", "🪞 Reflection", "red",    "XSS candidates — high-signal params"),
        ("params",     "🧩 Params",     "orange", "All URLs with query strings"),
        ("sensitive",  "⚠️ Sensitive",  "red",    ".env · .git · backups · credentials"),
        ("admin",      "🔑 Admin",      "red",    "Admin/dashboard/management panels"),
        ("login",      "🚪 Login",      "yellow", "Authentication & SSO endpoints"),
        ("api",        "⚡ API",        "purple", "REST · GraphQL · RPC · webhooks"),
        ("forms",      "📝 Forms",      "blue",   "PHP · ASP · JSP form handlers"),
        ("other",      "📄 Other",      "gray",   "Uncategorised"),
    ]
    tab_items = []
    for key, label, color, desc in cats:
        data  = urls.get(key, [])
        cnt   = len(data)
        badge = _badge(f"{cnt:,}", color)
        content = (f'<div class="cat-desc">{_e(desc)}</div>'
                   f'{_vscroll(data, f"vs-cat-{key}")}')
        tab_items.append((key, f"{label} {badge}", content))
    body = _tabs(tab_items, "cat") if tab_items else _empty()
    return (f'<div id="s-categorised" class="section">'
            f'<div class="sec-hdr"><h2>📂 Categorised URLs</h2></div>'
            f'{body}</div>')

def _section_params(urls):
    params_map = {}
    for u in urls.get("params", []):
        for k in parse_qs(urlparse(u).query):
            params_map.setdefault(k, []).append(u)
    high_xss = {"q","query","search","s","keyword","input","text","name","value","data","content",
                 "msg","message","title","url","uri","redirect","return","ref","callback","cmd",
                 "exec","action","view","mode","page","id","file","path","token","key"}
    rows = sorted(
        [[k, str(len(v)),
          "🔴 High"   if k.lower() in high_xss else
          "🟡 Medium" if any(w in k.lower() for w in ["search","filter","cat","type","sort"]) else
          "⚪ Low",
          v[0][:100]]
         for k, v in params_map.items()],
        key=lambda r: -int(r[1])
    )
    note = '<p style="color:#868e96;font-size:12px;margin-bottom:16px">🔴 High = common XSS/injection target · 🟡 Medium = filter/search params · ⚪ Low = general params</p>'
    return (f'<div id="s-params" class="section">'
            f'<div class="sec-hdr"><h2>🧩 Parameters</h2>'
            f'<p class="sec-sub">{len(params_map):,} unique params across {len(urls.get("params",[])):,} URLs</p></div>'
            f'{note}'
            f'{_vtable(["Parameter", "Occurrences", "XSS Risk", "Example URL"], rows, "vt-params")}'
            f'</div>')

# ── Nuclei section — INFO varsayılan gizli ────────────────────────────────────
def _section_nuclei(nuclei):
    all_r  = nuclei["all"]
    by_sev = nuclei["by_severity"]

    # "All" tab: sadece critical/high/medium/low göster, info hariç
    important_sevs = ["critical", "high", "medium", "low"]
    all_important  = [r for r in all_r if r.get("severity","info") in important_sevs]

    def _rows(lst):
        out = []
        for r in lst:
            cve_html = ""
            if r.get("cve"):
                for cve in r["cve"].split(","):
                    cve = cve.strip()
                    if cve:
                        cve_html += (f'<a href="https://nvd.nist.gov/vuln/detail/{_e(cve)}" '
                                     f'target="_blank" rel="noopener" '
                                     f'style="color:#ff6b6b;font-family:var(--mono);font-size:10px;margin-right:4px">'
                                     f'{_e(cve)}</a>')
            cvss = r.get("cvss", "")
            cvss_badge = (f'<span style="color:#ffa94d;font-family:var(--mono);font-size:10px">'
                          f'{_e(cvss)}</span>') if cvss else ""
            name_cell = _e(r.get("name","")[:80] or r.get("raw","")[:80])
            if cve_html or cvss_badge:
                name_cell += f'<br><small>{cve_html}{cvss_badge}</small>'
            out.append([
                r.get("severity","info").upper(),
                name_cell,
                _e(r.get("url","") or r.get("host","")),
                _e(r.get("template","")[:60]),
                _e(r.get("tags","")[:60]),
            ])
        return out

    # Tab listesi: All (info hariç), sonra severity'ler, INFO en sona ve kapalı
    tab_items = []

    # All tab — info hariç
    all_label = f"All ({len(all_important)})" + (
        f' <span style="color:#3a4d60;font-size:10px">+{len(by_sev.get("info",[]))} info hidden</span>'
        if by_sev.get("info") else ""
    )
    tab_items.append(("all", all_label, _vtable(
        ["Severity", "Finding", "URL/Host", "Template", "Tags"],
        _rows(all_important), "vt-nuc-all"
    )))

    # critical / high / medium / low — normal tab
    for sev, col in [("critical","red"),("high","orange"),("medium","yellow"),("low","blue")]:
        lst = by_sev.get(sev, [])
        if not lst:
            continue
        tab_items.append((sev, f"{_badge(sev.upper(), col)} {len(lst)}",
                          _vtable(["Finding","URL/Host","Template","Tags","CVE"],
                                  [[_e(r.get("name","")[:80] or r.get("raw","")[:80]),
                                    _e(r.get("url","") or r.get("host","")),
                                    _e(r.get("template","")[:60]),
                                    _e(r.get("tags","")[:60]),
                                    _e(r.get("cve",""))]
                                   for r in lst],
                                  f"vt-nuc-{sev}")))

    # INFO — ayrı collapsible bölüm olarak (tab değil), tab sonuna ekliyoruz
    info_lst = by_sev.get("info", [])
    info_section = ""
    if info_lst:
        info_table = _vtable(
            ["Finding","URL/Host","Template","Tags"],
            [[_e(r.get("name","")[:80] or r.get("raw","")[:80]),
              _e(r.get("url","") or r.get("host","")),
              _e(r.get("template","")[:60]),
              _e(r.get("tags","")[:60])]
             for r in info_lst],
            "vt-nuc-info"
        )
        info_section = (
            f'<details style="margin-top:20px">'
            f'<summary style="cursor:pointer;padding:10px 14px;background:var(--s2);'
            f'border:1px solid var(--bd);border-radius:8px;font-size:12px;'
            f'color:#3a4d60;user-select:none;list-style:none">'
            f'▶ INFO findings — {len(info_lst):,} items (click to expand · genellikle gürültü)</summary>'
            f'<div style="margin-top:8px">{info_table}</div>'
            f'</details>'
        )

    n_crit = len(by_sev.get("critical", []))
    n_high = len(by_sev.get("high", []))
    alert  = (f'<div class="alert-box alert-red">🔴 {n_crit} Critical and {n_high} High findings — '
              f'verify and report immediately!</div>' if n_crit or n_high else "")

    body = _tabs(tab_items, "nuc") if tab_items else _empty("No significant findings")

    return (f'<div id="s-nuclei" class="section">'
            f'<div class="sec-hdr"><h2>🎯 Nuclei Findings</h2>'
            f'<p class="sec-sub">{len(all_important):,} significant findings'
            f'{f" · {len(info_lst)} info (hidden)" if info_lst else ""}</p></div>'
            f'{alert}{body}{info_section}</div>')


# ── XSS section — PoC URL'leri doğrudan tıklanabilir ─────────────────────────
def _section_xss(xss):
    all_x    = xss["all"]
    pocs     = xss["pocs"]
    poc_urls = xss.get("poc_urls", [])
    total    = len(all_x)

    alert = (f'<div class="alert-box alert-red">🔴 {total} XSS finding{"s" if total!=1 else ""} — '
             f'{len(pocs)} confirmed PoC{"s" if len(pocs)!=1 else ""} — verify manually before reporting</div>'
             if total
             else '<div class="alert-box alert-blue">ℹ️ No XSS findings confirmed</div>')

    poc_html = ""
    if poc_urls:
        rows_html = ""
        for i, item in enumerate(poc_urls):
            raw_line = item["raw"]
            url      = item["url"]

            prefix_m = re.match(r'^(\[.*?\]\s*)+', raw_line)
            prefix   = prefix_m.group(0).strip() if prefix_m else ""

            # javascript: / data: → sadece kopyalanabilir metin, tıklanamaz
            href = _safe_href(url)

            if href:
                url_cell = (
                    f'<a href="{_e(href)}" target="_blank" rel="noopener" class="poc-link">'
                    f'{_e(url)}</a>'
                )
            else:
                # javascript: veya data: payload — kopyalanabilir metin, tıklanamaz
                url_cell = (
                    f'<code class="poc-link" style="cursor:text;color:#f87171" '
                    f'title="javascript:/data: — cannot be opened as link, select to copy">'
                    f'{_e(url)}</code>'
                    f'<span style="font-size:10px;color:#506070;margin-left:6px">[copy manually]</span>'
                )

            rows_html += f'''<tr class="poc-tr">
  <td style="width:28px;text-align:center;color:#ff6b6b;font-size:13px">🔥</td>
  <td>
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      {url_cell}
      <button class="btn-sm" style="padding:3px 10px;font-size:10px;flex-shrink:0"
        onclick="navigator.clipboard.writeText(this.dataset.url).then(function(){{toast('URL copied!')}});"
        data-url="{_e(url)}">Copy</button>
    </div>
    {f'<div class="poc-prefix">{_e(prefix)}</div>' if prefix else ""}
  </td>
</tr>'''

        poc_html = f'''<div style="margin-bottom:12px">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap">
    <span style="color:#ff6b6b;font-weight:700;font-size:13px">🔥 {len(poc_urls)} confirmed PoC URLs</span>
    <button class="btn-sm" onclick="copyAllPocUrls()">Copy all URLs</button>
    <button class="btn-sm" onclick="exportPocUrls()">Export .txt</button>
  </div>
  <div class="tbl-scroll poc-table-wrap">
    <table style="width:100%">
      <thead><tr>
        <th style="width:28px"></th>
        <th>PoC URL — click to open in new tab</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
</div>
<script>
var _POC_URLS = {_safe_json([item["url"] for item in poc_urls])};
function copyAllPocUrls() {{
  navigator.clipboard.writeText(_POC_URLS.join("\\n"))
    .then(function(){{ toast("Copied " + _POC_URLS.length + " PoC URLs"); }});
}}
function exportPocUrls() {{
  var a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([_POC_URLS.join("\\n")], {{type:"text/plain"}}));
  a.download = "xss_poc_urls.txt"; a.click(); URL.revokeObjectURL(a.href);
}}
</script>'''

    raw_tab = _vscroll(all_x, "vs-xss-all")

    tab_items = [
        ("pocs", f"🔥 PoCs ({len(poc_urls)} URLs)",  poc_html if poc_html else _empty("No PoC lines detected")),
        ("raw",  f"Raw Output ({total})",             raw_tab),
    ]
    body = _tabs(tab_items, "xss")
    return (f'<div id="s-xss" class="section">'
            f'<div class="sec-hdr"><h2>💉 XSS Testing (Dalfox)</h2>'
            f'<p class="sec-sub">{total} findings · {len(poc_urls)} confirmed PoC URLs</p></div>'
            f'{alert}{body}</div>')


# ── Threat Map ─────────────────────────────────────────────────────────────────
def _section_threatmap(target: str, subs: dict, alive: list, nuclei: dict, xss: dict) -> str:
    all_subs  = subs.get("all", [])
    alive_set = set()
    for h in alive:
        u = h.get("url","")
        try:
            alive_set.add(urlparse(u).hostname or "")
        except:
            pass

    vuln_map: dict = {}
    for r in nuclei.get("all", []):
        h = r.get("host") or ""
        try:
            h = urlparse(h).hostname or h
        except:
            pass
        if h:
            vuln_map.setdefault(h, {"severity": "info", "count": 0})
            vuln_map[h]["count"] += 1
            sev_order = {"critical":5,"high":4,"medium":3,"low":2,"info":1}
            if sev_order.get(r.get("severity","info"),1) > sev_order.get(vuln_map[h]["severity"],1):
                vuln_map[h]["severity"] = r.get("severity","info")

    xss_set: set = set()
    for u in xss.get("all",[]):
        try:
            xss_set.add(urlparse(u).hostname or "")
        except:
            pass

    MAX_DIRECT = 300
    nodes = [{"id": target, "type": "root", "label": target,
               "alive": True, "severity": "none", "vuln_count": 0, "xss": False}]
    links = []

    group_map: dict = {}
    singletons: list = []

    for s in all_subs:
        if s == target:
            continue
        suffix = "." + target
        local  = s[:-len(suffix)] if s.endswith(suffix) else s
        parts  = local.split(".")
        if len(parts) >= 2:
            grp = parts[-1]
            group_map.setdefault(grp, []).append(s)
        else:
            singletons.append(s)

    total_nodes_est = len(singletons) + sum(
        1 if len(v) == 1 else 1 + len(v)
        for v in group_map.values()
    )
    CLUSTER_THRESHOLD = 400
    big_group_limit = 8 if total_nodes_est > CLUSTER_THRESHOLD else 999

    for s in singletons[:MAX_DIRECT]:
        nodes.append({
            "id": s, "type": "subdomain", "label": s,
            "alive": s in alive_set,
            "severity": vuln_map.get(s, {}).get("severity","none"),
            "vuln_count": vuln_map.get(s,{}).get("count",0),
            "xss": s in xss_set,
        })
        links.append({"source": target, "target": s, "type": "sub"})

    for grp, members in group_map.items():
        if len(members) == 1:
            s = members[0]
            nodes.append({
                "id": s, "type": "subdomain", "label": s,
                "alive": s in alive_set,
                "severity": vuln_map.get(s,{}).get("severity","none"),
                "vuln_count": vuln_map.get(s,{}).get("count",0),
                "xss": s in xss_set,
            })
            links.append({"source": target, "target": s, "type": "sub"})
        else:
            grp_id = f"_grp_{grp}"
            grp_sev = "none"; grp_vuln = 0; grp_xss = False
            sev_order = {"critical":5,"high":4,"medium":3,"low":2,"info":1,"none":0}
            for m in members:
                mv = vuln_map.get(m,{})
                if sev_order.get(mv.get("severity","none"),0) > sev_order.get(grp_sev,0):
                    grp_sev = mv.get("severity","none")
                grp_vuln += mv.get("count",0)
                if m in xss_set:
                    grp_xss = True
            nodes.append({"id": grp_id, "type": "group",
                           "label": f"*.{grp}", "count": len(members),
                           "alive": any(m in alive_set for m in members),
                           "severity": grp_sev, "vuln_count": grp_vuln, "xss": grp_xss})
            links.append({"source": target, "target": grp_id, "type": "group"})
            for s in members[:big_group_limit]:
                nodes.append({"id": s, "type": "subdomain", "label": s,
                               "alive": s in alive_set,
                               "severity": vuln_map.get(s,{}).get("severity","none"),
                               "vuln_count": vuln_map.get(s,{}).get("count",0),
                               "xss": s in xss_set})
                links.append({"source": grp_id, "target": s, "type": "sub"})
            if len(members) > big_group_limit:
                hidden_id = f"_hidden_{grp}"
                nodes.append({"id": hidden_id, "type": "collapsed",
                               "label": f"+{len(members)-big_group_limit} more",
                               "count": len(members)-big_group_limit,
                               "alive": False, "severity": "none", "vuln_count": 0, "xss": False})
                links.append({"source": grp_id, "target": hidden_id, "type": "collapsed"})

    graph_json = _safe_json({"nodes": nodes, "links": links,
                              "total_subs": len(all_subs), "rendered": len(nodes)})

    return f'''<div id="s-threatmap" class="section">
  <div class="sec-hdr">
    <h2>🗺️ Threat Map</h2>
    <p class="sec-sub">{len(all_subs):,} subdomains · {len(alive_set):,} alive · {len(nodes):,} nodes · drag · scroll zoom</p>
  </div>
  <div class="tm-legend">
    <span class="tm-leg-item"><span class="tm-dot" style="background:#4fa8e8"></span>Root</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#2d4a62;border:1px dashed #4fa8e8"></span>Group</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#7c7c7c"></span>Collapsed (+N)</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#34c759"></span>Alive</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#6e8098"></span>Dead</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#ff453a"></span>Crit/High Vuln</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#ffa94d"></span>Medium Vuln</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#ff6b6b;border:2px solid #fff"></span>XSS</span>
  </div>
  <div class="tm-toolbar">
    <button class="btn-sm" onclick="tmResetZoom()">⊙ Reset</button>
    <button class="btn-sm" onclick="tmToggleLabels()">🏷 Labels</button>
    <button class="btn-sm" onclick="tmFilterAlive()">💚 Alive only</button>
    <button class="btn-sm" onclick="tmFilterVuln()">🔴 Vuln only</button>
    <button class="btn-sm" onclick="tmFilterAll()">🌐 All</button>
    <input id="tm-search" class="vs-search" style="max-width:200px" placeholder="Search node..." oninput="tmSearch()">
    <span id="tm-info" style="font-size:12px;color:var(--mu);margin-left:auto"></span>
  </div>
  <div class="tm-wrap">
    <svg id="tm-svg"></svg>
    <div id="tm-tooltip" class="tm-tooltip"></div>
  </div>
  <script>
  (function(){{
    window._TM_DATA = {graph_json};
    if (document.readyState === 'loading') {{
      document.addEventListener('DOMContentLoaded', function(){{ setTimeout(initThreatMap, 80); }}, {{once:true}});
    }} else {{
      setTimeout(initThreatMap, 80);
    }}
  }})();
  </script>
</div>'''


# ── CSS ────────────────────────────────────────────────────────────────────────
_CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Outfit:wght@300;400;500;700;800&display=swap');
:root{
  --bg:#080c10;--s1:#0d1117;--s2:#111820;--s3:#161d27;
  --bd:#1e2a36;--bd2:#243040;
  --tx:#cdd9e5;--mu:#6e8098;
  --ac:#4fa8e8;--green:#34c759;--red:#ff453a;
  --orange:#ff9f0a;--yellow:#f5a623;--purple:#bf5af2;
  --mono:'JetBrains Mono',monospace;
  --sans:'Outfit',sans-serif;
  --sw:252px;--rh:34px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:var(--sans);font-size:14px;
     display:flex;min-height:100vh;line-height:1.5}
.sidebar{width:var(--sw);min-width:var(--sw);background:var(--s1);
         border-right:1px solid var(--bd);position:fixed;top:0;left:0;
         height:100vh;overflow-y:auto;z-index:100;display:flex;flex-direction:column}
.sidebar::-webkit-scrollbar{width:3px}
.sidebar::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:2px}
.sb-brand{padding:20px 18px 16px;border-bottom:1px solid var(--bd);
          background:linear-gradient(135deg,#0d1117 60%,#0d1f2d)}
.sb-brand h1{font-size:15px;font-weight:800;color:var(--ac);letter-spacing:-.3px}
.sb-target{font-family:var(--mono);font-size:11px;color:var(--mu);
           margin-top:6px;word-break:break-all;line-height:1.4}
.sb-ts{font-size:10px;color:#404d5c;margin-top:3px}
.nav-grp{padding:10px 0 4px}
.nav-lbl{color:#3a4d60;font-size:10px;font-weight:700;text-transform:uppercase;
         letter-spacing:1.2px;padding:4px 18px 6px}
.nav-a{display:flex;align-items:center;gap:9px;padding:9px 18px;color:var(--mu);
       cursor:pointer;font-size:13px;border-left:2px solid transparent;
       transition:all .12s;text-decoration:none}
.nav-a:hover{color:var(--tx);background:rgba(79,168,232,.05)}
.nav-a.active{color:var(--ac);background:rgba(79,168,232,.08);
              border-left-color:var(--ac);font-weight:500}
.nav-ico{font-size:15px;width:18px;text-align:center;flex-shrink:0}
.nav-cnt{margin-left:auto;background:var(--s2);color:#506070;font-size:10px;
         padding:1px 7px;border-radius:20px;font-family:var(--mono)}
.nav-hr{border:none;border-top:1px solid var(--bd);margin:6px 0}
.main{margin-left:var(--sw);flex:1;padding:28px 36px 60px;max-width:1500px}
.section{display:none}.section.active{display:block}
.sec-hdr{margin-bottom:22px}
.sec-hdr h2{font-size:21px;font-weight:800;color:var(--ac);letter-spacing:-.4px}
.sec-sub{color:var(--mu);font-size:12px;margin-top:4px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(108px,1fr));gap:10px;margin-top:10px}
.stat-card{background:var(--s1);border:1px solid var(--bd);border-radius:12px;
           padding:16px 10px;text-align:center;transition:transform .15s,border-color .15s;cursor:default}
.stat-card:hover{transform:translateY(-3px);border-color:var(--bd2)}
.stat-icon{font-size:22px;margin-bottom:6px}
.stat-val{font-size:24px;font-weight:800;line-height:1;font-family:var(--mono)}
.stat-lbl{font-size:10px;color:var(--mu);margin-top:4px;text-transform:uppercase;letter-spacing:.8px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.panel{background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:18px 20px}
.panel h3{font-size:12px;font-weight:700;color:var(--mu);text-transform:uppercase;
          letter-spacing:.8px;margin-bottom:14px}
.mini-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:14px}
.mini-num{background:var(--s2);border:1px solid var(--bd);border-radius:8px;
          padding:10px 14px;display:flex;flex-direction:column;align-items:center;gap:2px;
          font-size:20px;font-weight:800;font-family:var(--mono)}
.mini-num span{font-size:10px;color:var(--mu);font-weight:400;font-family:var(--sans)}
.timeline{display:flex;gap:0;overflow-x:auto;padding-bottom:2px}
.tl-step{display:flex;flex-direction:column;align-items:center;min-width:70px;position:relative;flex:1}
.tl-step:not(:last-child)::after{content:'';position:absolute;top:20px;left:56%;width:88%;height:2px;background:var(--bd2)}
.tl-step.tl-done:not(:last-child)::after{background:var(--green)}
.tl-dot{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;
        justify-content:center;font-size:18px;background:var(--s2);border:2px solid var(--bd2);position:relative;z-index:1}
.tl-step.tl-done .tl-dot{background:rgba(52,199,89,.15);border-color:var(--green)}
.tl-step.tl-skip .tl-dot{opacity:.35;filter:grayscale(1)}
.tl-lbl{font-size:10px;color:var(--mu);margin-top:6px;text-align:center}
.tl-step.tl-done .tl-lbl{color:var(--tx)}
.sev-bar{display:flex;gap:1px;height:8px;border-radius:8px;overflow:hidden;background:var(--s2);margin-bottom:12px}
.sev-legend{display:flex;gap:14px;flex-wrap:wrap}
.sev-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--mu)}
.tab-row{display:flex;gap:2px;border-bottom:1px solid var(--bd);margin-bottom:16px;flex-wrap:wrap}
.tab{background:none;border:none;color:var(--mu);padding:9px 14px;cursor:pointer;
     font-size:12px;font-family:var(--sans);font-weight:500;
     border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .12s;white-space:nowrap}
.tab:hover{color:var(--tx)}.tab.active{color:var(--ac);border-bottom-color:var(--ac)}
.panes .pane{display:none}.panes .pane.active{display:block}
.code-block{background:var(--s2);border:1px solid var(--bd);border-radius:8px;
            padding:16px;font-family:var(--mono);font-size:12px;line-height:1.65;
            overflow:auto;white-space:pre-wrap;word-break:break-all;max-height:550px;color:#b0bec5}
.code-block::-webkit-scrollbar{width:6px;height:6px}
.code-block::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:3px}
.vs-wrap,.vt-wrap{position:relative}
.vs-toolbar{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap}
.vs-counter{font-family:var(--mono);font-size:12px;color:var(--mu);white-space:nowrap;min-width:80px}
.vs-search{background:var(--s2);border:1px solid var(--bd);color:var(--tx);
           padding:8px 13px;border-radius:8px;font-size:13px;flex:1;min-width:180px;
           outline:none;font-family:var(--sans);transition:border-color .12s}
.vs-search:focus{border-color:var(--ac)}
.btn-sm{background:var(--s2);border:1px solid var(--bd2);color:var(--mu);
        padding:7px 14px;border-radius:8px;cursor:pointer;font-size:12px;
        font-family:var(--sans);white-space:nowrap;transition:all .12s}
.btn-sm:hover{color:var(--ac);border-color:var(--ac)}
.vs-scroll{height:520px;overflow-y:auto;background:var(--s2);border:1px solid var(--bd);border-radius:8px;position:relative}
.vs-scroll::-webkit-scrollbar{width:6px}
.vs-scroll::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:3px}
.vs-vp{position:relative}
.vs-row{height:var(--rh);display:flex;align-items:center;padding:0 14px;
        border-bottom:1px solid rgba(30,42,54,.8);position:absolute;width:100%}
.vs-row:hover{background:rgba(79,168,232,.05)}
.vs-row a{font-family:var(--mono);font-size:12px;color:var(--mu);text-decoration:none;
          white-space:nowrap;overflow:hidden;text-overflow:ellipsis;width:100%}
.vs-row a:hover{color:var(--ac)}
.url-host{color:#506070}.url-path{color:var(--tx)}.url-qs{color:var(--orange)}
.tbl-scroll{overflow-x:auto;border:1px solid var(--bd);border-radius:8px}
.tbl-scroll::-webkit-scrollbar{height:6px}
.tbl-scroll::-webkit-scrollbar-thumb{background:var(--bd2)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--s2);color:var(--mu);padding:10px 14px;text-align:left;
   font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;
   white-space:nowrap;position:sticky;top:0;z-index:1}
td{padding:8px 14px;border-bottom:1px solid var(--bd);vertical-align:middle;
   max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
   font-family:var(--mono);font-size:12px}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(79,168,232,.03)}
.vt-more{padding:10px 14px;font-size:12px;color:var(--mu);background:var(--s2);
         border-top:1px solid var(--bd);display:flex;align-items:center;gap:10px}
.load-btn{background:none;border:1px solid var(--bd2);color:var(--ac);
          padding:4px 14px;border-radius:20px;cursor:pointer;font-size:12px;
          font-family:var(--sans);transition:all .12s}
.load-btn:hover{background:rgba(79,168,232,.1)}
.alert-box{border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:13px;font-weight:500;border:1px solid}
.alert-red{background:rgba(255,69,58,.08);border-color:rgba(255,69,58,.25);color:var(--red)}
.alert-blue{background:rgba(79,168,232,.07);border-color:rgba(79,168,232,.2);color:var(--ac)}
.cat-desc{color:var(--mu);font-size:12px;margin-bottom:12px;padding:8px 12px;
          background:var(--s2);border-radius:6px;border-left:3px solid var(--bd2)}
.empty-state{color:var(--mu);font-style:italic;padding:32px;text-align:center;
             background:var(--s2);border-radius:8px;border:1px dashed var(--bd)}
code{font-family:var(--mono);font-size:12px;color:var(--ac)}
.footer{margin-top:48px;padding-top:16px;border-top:1px solid var(--bd);color:#3a4d60;font-size:11px}
.probe-card{background:var(--s2);border:1px solid var(--bd);border-radius:8px;overflow:hidden;margin-bottom:16px}
.probe-row{display:flex;padding:9px 14px;border-bottom:1px solid var(--bd);align-items:center;gap:12px}
.probe-row:last-child{border-bottom:none}
.probe-row span{color:var(--mu);font-size:12px;width:120px;flex-shrink:0}
.probe-row b{font-family:var(--mono);font-size:12px;color:var(--tx);font-weight:500}
/* XSS PoC Table */
.poc-table-wrap{max-height:600px;overflow-y:auto;border-radius:8px}
.poc-table-wrap::-webkit-scrollbar{width:6px}
.poc-table-wrap::-webkit-scrollbar-thumb{background:rgba(255,69,58,.3);border-radius:3px}
.poc-tr td{white-space:normal;word-break:break-all;max-width:none}
.poc-link{font-family:var(--mono);font-size:12px;color:#ff9f9f;text-decoration:none;
          flex:1;min-width:0;word-break:break-all;line-height:1.5;
          transition:color .12s;padding:2px 0}
.poc-link:hover{color:#ff6b6b;text-decoration:underline}
.poc-prefix{font-family:var(--mono);font-size:10px;color:#506070;margin-top:3px;letter-spacing:.3px}
/* details/summary INFO collapse */
details summary::-webkit-details-marker{display:none}
details[open] summary{border-radius:8px 8px 0 0}
@media(max-width:900px){
  .sidebar{display:none}.main{margin-left:0;padding:16px}
  .two-col{grid-template-columns:1fr}
}
.tm-wrap{position:relative;background:var(--s1);border:1px solid var(--bd);
         border-radius:12px;overflow:hidden;height:680px;margin-top:12px}
#tm-svg{width:100%;height:100%;cursor:grab}
#tm-svg:active{cursor:grabbing}
.tm-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.tm-legend{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;
           padding:10px 14px;background:var(--s2);border-radius:8px;border:1px solid var(--bd)}
.tm-leg-item{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--mu)}
.tm-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.tm-tooltip{position:absolute;pointer-events:none;background:rgba(13,17,23,.97);
            border:1px solid var(--bd2);border-radius:8px;padding:10px 14px;
            font-size:12px;color:var(--tx);max-width:300px;display:none;
            z-index:50;box-shadow:0 8px 32px rgba(0,0,0,.6);line-height:1.7}
.tm-tooltip strong{color:var(--ac);font-family:var(--mono);font-size:11px;
                   word-break:break-all;display:block;margin-bottom:4px}
.tm-tt-badge{display:inline-block;padding:1px 8px;border-radius:20px;
             font-size:10px;font-weight:700;margin:1px 2px}
"""

_JS = r"""
function showSection(id, el) {
  document.querySelectorAll('.section').forEach(function(s){ s.classList.remove('active'); });
  document.querySelectorAll('.nav-a').forEach(function(n){ n.classList.remove('active'); });
  var sec = document.getElementById('s-' + id);
  if (sec) sec.classList.add('active');
  if (el)  el.classList.add('active');
  if (sec) {
    sec.querySelectorAll('.vs-vp').forEach(function(vp){
      try { vsRender(vp.id.replace('-vp', '')); } catch(e) {}
    });
  }
  if (id === 'threatmap' && window._TM_DATA && typeof d3 !== 'undefined') {
    setTimeout(function() {
      if (!_TM.initialized) { initThreatMap(); }
      else {
        var wrap = document.querySelector('.tm-wrap');
        if (wrap) {
          var W = wrap.clientWidth, H = wrap.clientHeight;
          if (Math.abs(W - _TM.W) > 20 || Math.abs(H - _TM.H) > 20) {
            _TM.W = W; _TM.H = H;
            _TM.svg.attr('viewBox', [0, 0, W, H]);
          }
        }
      }
    }, 80);
  }
}
function tab(btn, paneId) {
  var cont = btn.closest('.section');
  cont.querySelectorAll('.tab').forEach(function(b){ b.classList.remove('active'); });
  cont.querySelectorAll('.pane').forEach(function(p){ p.classList.remove('active'); });
  btn.classList.add('active');
  var pane = document.getElementById(paneId);
  if (pane) {
    pane.classList.add('active');
    pane.querySelectorAll('.vs-vp').forEach(function(vp){
      try { vsRender(vp.id.replace('-vp', '')); } catch(e) {}
    });
  }
}
var VS_H = 34, VS_OS = 8;
function vsInit(uid) {
  var d = window._VS && window._VS[uid]; if (!d) return;
  vsCnt(uid); vsRender(uid);
}
function vsRender(uid) {
  var d = window._VS && window._VS[uid]; if (!d) return;
  var c = document.getElementById(uid + '-scroll');
  var vp = document.getElementById(uid + '-vp');
  if (!c || !vp) return;
  var tot = d.filtered.length;
  vp.style.height = (tot * VS_H) + 'px';
  var st = c.scrollTop, vis = Math.ceil(c.clientHeight / VS_H);
  var si = Math.max(0, Math.floor(st / VS_H) - VS_OS);
  var ei = Math.min(tot, si + vis + VS_OS * 2);
  vp.querySelectorAll('.vs-row').forEach(function(r){ r.remove(); });
  for (var i = si; i < ei; i++) {
    var url = d.filtered[i], row = document.createElement('div');
    row.className = 'vs-row'; row.style.top = (i * VS_H) + 'px';
    var p = parseURL(url);
    row.innerHTML = '<a href="' + esc(url) + '" target="_blank" rel="noopener"><span class="url-host">'
      + esc(p.host) + '</span><span class="url-path">' + esc(p.path)
      + '</span><span class="url-qs">' + esc(p.qs) + '</span></a>';
    vp.appendChild(row);
  }
}
function vsFilter(uid) {
  var d = window._VS && window._VS[uid]; if (!d) return;
  var q = document.getElementById(uid + '-q').value.toLowerCase();
  d.filtered = q ? d.raw.filter(function(u){ return u.toLowerCase().indexOf(q) >= 0; }) : d.raw;
  vsCnt(uid);
  var c = document.getElementById(uid + '-scroll'); if (c) c.scrollTop = 0;
  vsRender(uid);
}
function vsCnt(uid) {
  var d = window._VS && window._VS[uid], el = document.getElementById(uid + '-cnt');
  if (el && d) el.textContent = num(d.filtered.length) + ' / ' + num(d.raw.length);
}
function vsCopy(uid) {
  var d = window._VS && window._VS[uid];
  if (d) navigator.clipboard.writeText(d.filtered.join('\n'))
    .then(function(){ toast('Copied ' + num(d.filtered.length) + ' items'); });
}
function vsExport(uid) {
  var d = window._VS && window._VS[uid];
  if (d) dl(d.filtered.join('\n'), uid + '.txt', 'text/plain');
}
var VT_PG = 200;
function vtInit(uid) {
  var d = window._VT && window._VT[uid]; if (!d) return;
  d.page = 0; vtCnt(uid); vtRender(uid);
}
function vtRender(uid) {
  var d = window._VT && window._VT[uid];
  var tbody = document.getElementById(uid + '-body');
  var more  = document.getElementById(uid + '-more');
  if (!d || !tbody) return;
  var slice = d.filtered.slice(0, (d.page + 1) * VT_PG);
  tbody.innerHTML = slice.map(function(r){
    return '<tr>' + r.map(function(c){ return '<td title="' + esc(String(c||'')) + '">' + esc(String(c || '')); }).join('') + '</tr>';
  }).join('');
  if (more) {
    var s = slice.length, t = d.filtered.length;
    more.innerHTML = s < t
      ? 'Showing ' + num(s) + ' of ' + num(t)
        + ' &nbsp;<button class="load-btn" onclick="vtMore(\'' + uid + '\')">+' + VT_PG + '</button>'
        + '&nbsp;<button class="load-btn" onclick="vtAll(\'' + uid + '\')">Load all</button>'
      : 'All ' + num(t) + ' rows shown';
  }
}
function vtFilter(uid) {
  var d = window._VT && window._VT[uid]; if (!d) return;
  var q = document.getElementById(uid + '-q').value.toLowerCase();
  d.filtered = q ? d.raw.filter(function(r){
    return r.some(function(c){ return String(c).toLowerCase().indexOf(q) >= 0; });
  }) : d.raw;
  d.page = 0; vtCnt(uid); vtRender(uid);
}
function vtMore(uid){ window._VT[uid].page++; vtRender(uid); }
function vtAll(uid){ window._VT[uid].page = 9999; vtRender(uid); }
function vtCnt(uid) {
  var d = window._VT && window._VT[uid], el = document.getElementById(uid + '-cnt');
  if (el && d) el.textContent = num(d.filtered.length) + ' / ' + num(d.raw.length) + ' rows';
}
function vtCopy(uid) {
  var d = window._VT && window._VT[uid];
  if (d) navigator.clipboard.writeText(
    d.filtered.map(function(r){ return r.join('\t'); }).join('\n')
  ).then(function(){ toast('Copied ' + num(d.filtered.length) + ' rows'); });
}
function vtExportCSV(uid) {
  var d = window._VT && window._VT[uid];
  if (!d) return;
  var hdr = (d.headers || []).join(',');
  var rows = d.filtered.map(function(r){
    return r.map(function(c){ return '"' + String(c).replace(/"/g,'""') + '"'; }).join(',');
  });
  dl([hdr].concat(rows).join('\n'), uid + '.csv', 'text/csv');
}
var AP = 150;
var SC_COL = {'2':'#3fb950','3':'#74c0fc','4':'#e3b341','5':'#f85149'};
function aliveInit() { window._AP = 0; aliveCnt(); aliveRender(); }
function aliveFilter() {
  var q = document.getElementById('alive-q').value.toLowerCase();
  window._AF = q ? window._AR.filter(function(r){
    return r.some(function(c){ return String(c).toLowerCase().indexOf(q) >= 0; });
  }) : window._AR;
  window._AP = 0; aliveCnt(); aliveRender();
}
function aliveRender() {
  var data = window._AF || [], tbody = document.getElementById('alive-body'), more = document.getElementById('alive-more');
  if (!tbody) return;
  var slice = data.slice(0, (window._AP + 1) * AP);
  tbody.innerHTML = slice.map(function(r) {
    var url=r[0],sc=r[1],title=r[2],ip=r[3],tech=r[4],sz=r[5],srv=r[6],rt=r[7]||'';
    var col = SC_COL[String(sc)[0]] || '#6e8098';
    return '<tr>'
      + '<td title="' + esc(url) + '"><a href="' + esc(url) + '" target="_blank" rel="noopener" style="color:#74c0fc;font-family:var(--mono);font-size:11.5px">' + esc(url) + '</a></td>'
      + '<td><b style="color:' + col + '">' + esc(sc) + '</b></td>'
      + '<td style="font-family:var(--sans)" title="' + esc(title) + '">' + esc(title) + '</td>'
      + '<td>' + esc(ip) + '</td>'
      + '<td style="font-size:11px;color:#6e8098" title="' + esc(tech) + '">' + esc(tech) + '</td>'
      + '<td>' + esc(sz) + '</td>'
      + '<td style="font-size:11px;color:#6e8098">' + esc(srv) + '</td>'
      + '<td style="color:var(--mu);font-size:11px">' + esc(rt) + '</td>'
      + '</tr>';
  }).join('');
  if (more) {
    var s = slice.length, t = data.length;
    more.innerHTML = s < t
      ? 'Showing ' + num(s) + ' of ' + num(t)
        + ' &nbsp;<button class="load-btn" onclick="window._AP++;aliveRender()">+' + AP + '</button>'
        + '&nbsp;<button class="load-btn" onclick="window._AP=999;aliveRender()">Load all</button>'
      : 'All ' + num(t) + ' hosts shown';
  }
}
function aliveCnt() {
  var el = document.getElementById('alive-cnt');
  if (el) el.textContent = num((window._AF||[]).length) + ' / ' + num((window._AR||[]).length) + ' hosts';
}
function aliveCopy() {
  var u = (window._AF||[]).map(function(r){ return r[0]; }).join('\n');
  navigator.clipboard.writeText(u).then(function(){ toast('Copied ' + num((window._AF||[]).length) + ' URLs'); });
}
function aliveCSV() {
  var hdr = 'URL,Status,Title,IP,Tech,Size,Server,ResponseTime';
  var rows = (window._AF||[]).map(function(r){
    return r.map(function(c){ return '"' + String(c).replace(/"/g,'""') + '"'; }).join(',');
  });
  dl([hdr].concat(rows).join('\n'), 'alive_hosts.csv', 'text/csv');
}
function parseURL(url) {
  try { var u = new URL(url); return {host:u.hostname, path:u.pathname, qs:u.search?u.search.slice(0,80):''}; }
  catch(e) { return {host:'', path:url, qs:''}; }
}
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function num(n) { return Number(n).toLocaleString(); }
function dl(content, filename, mime) {
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], {type:mime}));
  a.download = filename; a.click(); URL.revokeObjectURL(a.href);
}
var _tt;
function toast(msg) {
  var t = document.getElementById('_toast');
  if (!t) {
    t = document.createElement('div'); t.id = '_toast';
    t.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#1e2a36;color:#cdd9e5;'
      + 'padding:9px 16px;border-radius:8px;font-size:12px;border:1px solid #243040;z-index:9999;'
      + 'transition:opacity .3s;font-family:Outfit,sans-serif;pointer-events:none';
    document.body.appendChild(t);
  }
  t.textContent = '\u2713 ' + msg; t.style.opacity = '1';
  clearTimeout(_tt); _tt = setTimeout(function(){ t.style.opacity = '0'; }, 2500);
}
document.addEventListener('keydown', function(e) {
  if (e.key === '/' && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)) {
    e.preventDefault();
    var inp = document.querySelector('.section.active .vs-search');
    if (inp) inp.focus();
  }
});
(function() {
  function flush() {
    (window._VSQ || []).forEach(function(uid){ try { vsInit(uid); } catch(e){} });
    window._VSQ = [];
    (window._VTQ || []).forEach(function(uid){ try { vtInit(uid); } catch(e){} });
    window._VTQ = [];
    if (window._AliveReady && window._AR) { try { aliveInit(); } catch(e){} }
    window._AliveReady = false;
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', flush, {once:true});
  } else {
    flush();
  }
})();
var _TM = {sim:null,zoom:null,svg:null,g:null,W:0,H:0,showLabels:true,filter:'all',allNodes:[],allLinks:[],initialized:false,rendering:false};
function initThreatMap() {
  var data = window._TM_DATA;
  if (!data || typeof d3 === 'undefined') return;
  var svgEl = document.getElementById('tm-svg');
  var wrap  = document.querySelector('.tm-wrap');
  if (!svgEl || !wrap) return;
  var W = wrap.clientWidth || 900, H = wrap.clientHeight || 680;
  _TM.W = W; _TM.H = H;
  _TM.svg = d3.select(svgEl).attr('viewBox', [0, 0, W, H]);
  _TM.allNodes = data.nodes.map(function(n){ return Object.assign({}, n); });
  _TM.allLinks = data.links.map(function(l){ return Object.assign({}, l); });
  _TM.initialized = true;
  var infoEl = document.getElementById('tm-info');
  if (infoEl && data.total_subs !== undefined) infoEl.textContent = data.total_subs + ' total subs \u00b7 ' + data.rendered + ' nodes rendered';
  _tmApplyFilter();
}
function _tmApplyFilter() {
  if (!_TM.initialized) return;
  var nodes, links;
  var sev_order = {critical:5,high:4,medium:3,low:2,info:1,none:0};
  if (_TM.filter === 'alive') {
    var ids = new Set(_TM.allNodes.filter(function(n){ return n.alive || n.type==='root'; }).map(function(n){ return n.id; }));
    nodes = _TM.allNodes.filter(function(n){ return ids.has(n.id); }).map(function(n){ return Object.assign({},n); });
    links = _TM.allLinks.filter(function(l){ return ids.has(l.source) && ids.has(l.target); }).map(function(l){ return Object.assign({},l); });
  } else if (_TM.filter === 'vuln') {
    var ids2 = new Set(_TM.allNodes.filter(function(n){ return n.type==='root' || (n.severity && sev_order[n.severity]>=3); }).map(function(n){ return n.id; }));
    nodes = _TM.allNodes.filter(function(n){ return ids2.has(n.id); }).map(function(n){ return Object.assign({},n); });
    links = _TM.allLinks.filter(function(l){ return ids2.has(l.source) && ids2.has(l.target); }).map(function(l){ return Object.assign({},l); });
  } else {
    nodes = _TM.allNodes.map(function(n){ return Object.assign({},n); });
    links = _TM.allLinks.map(function(l){ return Object.assign({},l); });
  }
  renderThreatMap(nodes, links);
}
function renderThreatMap(nodes, links) {
  if (_TM.rendering) return;
  _TM.rendering = true;
  if (_TM.sim) { _TM.sim.stop(); _TM.sim.on('tick', null); _TM.sim = null; }
  var svg = _TM.svg, W = _TM.W, H = _TM.H;
  var tooltip = document.getElementById('tm-tooltip');
  svg.selectAll('*').remove();
  var g = svg.append('g'); _TM.g = g;
  var zoom = d3.zoom().scaleExtent([0.04, 5]).on('zoom', function(event){ g.attr('transform', event.transform); });
  svg.on('.zoom', null).call(zoom); _TM.zoom = zoom;
  function nodeColor(d) {
    if (d.type==='root') return '#4fa8e8';
    if (d.type==='collapsed') return '#4a4a4a';
    if (d.type==='group') return d.xss ? '#8b1a1a' : ({critical:'#5c1a1a',high:'#5c3a1a',medium:'#4a4a1a',none:'#1e3347'}[d.severity]||'#1e3347');
    if (d.xss) return '#ff453a';
    return {critical:'#ff453a',high:'#ff6b35',medium:'#ffa94d',low:'#74c0fc'}[d.severity] || (d.alive?'#34c759':'#3a4d60');
  }
  function nodeRadius(d) {
    if (d.type==='root') return 22;
    if (d.type==='group') return Math.min(18, 10 + Math.log2(d.count||1)*2);
    if (d.type==='collapsed') return 10;
    return d.alive ? 8 : 5;
  }
  function nodeStroke(d) {
    return {root:'#74c0fc',group:'#3d6080',collapsed:'#555'}[d.type] || (d.alive?'#27a447':'#2a3d50');
  }
  var nodeById = {};
  nodes.forEach(function(n){ nodeById[n.id] = n; });
  var resolvedLinks = links.filter(function(l){ return nodeById[l.source] && nodeById[l.target]; }).map(function(l){ return {source:l.source,target:l.target,type:l.type}; });
  var defs = svg.append('defs');
  [['glow-b','#4fa8e8'],['glow-r','#ff453a'],['glow-g','#34c759']].forEach(function(p){
    var f = defs.append('filter').attr('id',p[0]).attr('x','-30%').attr('y','-30%').attr('width','160%').attr('height','160%');
    f.append('feGaussianBlur').attr('stdDeviation','3').attr('result','blur');
    var m = f.append('feMerge'); m.append('feMergeNode').attr('in','blur'); m.append('feMergeNode').attr('in','SourceGraphic');
  });
  var link = g.append('g').selectAll('line').data(resolvedLinks).join('line')
    .attr('stroke', function(d){ return d.type==='group'?'#243040':d.type==='collapsed'?'#333':'#1e2a36'; })
    .attr('stroke-width', function(d){ return d.type==='group'?1.5:1; })
    .attr('stroke-dasharray', function(d){ return d.type==='group'?'6,3':d.type==='collapsed'?'3,3':''; })
    .attr('opacity', 0.55);
  var node = g.append('g').selectAll('g').data(nodes).join('g')
    .style('cursor','pointer')
    .call(d3.drag()
      .on('start', function(e,d){ if(!e.active) _TM.sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag',  function(e,d){ d.fx=e.x; d.fy=e.y; })
      .on('end',   function(e,d){ if(!e.active) _TM.sim.alphaTarget(0); d.fx=null; d.fy=null; })
    );
  node.append('circle').attr('r', nodeRadius).attr('fill', nodeColor).attr('stroke', nodeStroke)
    .attr('stroke-width', function(d){ return d.xss||d.type==='root'?2.5:1.5; })
    .attr('filter', function(d){
      if (d.type==='root') return 'url(#glow-b)';
      if (d.xss||d.severity==='critical'||d.severity==='high') return 'url(#glow-r)';
      if (d.alive&&d.type==='subdomain') return 'url(#glow-g)';
      return '';
    });
  node.filter(function(d){ return d.type==='group' && d.vuln_count>0; }).append('circle')
    .attr('r', function(d){ return nodeRadius(d)+4; }).attr('fill','none').attr('stroke','#ff6b6b').attr('stroke-width',1.5).attr('stroke-dasharray','4,2').attr('opacity',0.7);
  node.filter(function(d){ return d.xss&&d.type!=='group'; }).append('circle')
    .attr('r', function(d){ return nodeRadius(d)+4; }).attr('fill','none').attr('stroke','#ff453a').attr('stroke-width',1).attr('stroke-dasharray','3,2').attr('opacity',0.5);
  node.filter(function(d){ return (d.type==='group'||d.type==='collapsed')&&(d.count||0)>0; }).append('text')
    .text(function(d){ return d.type==='collapsed'?'+'+d.count:d.count; })
    .attr('text-anchor','middle').attr('dy','0.35em').attr('fill','#cdd9e5').attr('font-size','9px').attr('font-weight','700').attr('font-family','JetBrains Mono,monospace').style('pointer-events','none');
  var labels = node.append('text').attr('class','tm-label')
    .attr('dy', function(d){ return nodeRadius(d)+13; }).attr('text-anchor','middle')
    .attr('fill', function(d){ return {root:'#4fa8e8',group:'#5a7a90',collapsed:'#505050'}[d.type]||(d.alive?'#cdd9e5':'#404d5c'); })
    .attr('font-size', function(d){ return {root:'12px',group:'10px',collapsed:'9px'}[d.type]||'9px'; })
    .attr('font-family','JetBrains Mono,monospace').attr('font-weight', function(d){ return d.type==='root'?'700':'400'; })
    .text(function(d){
      if (d.type==='root'||d.type==='group'||d.type==='collapsed') return d.label;
      var p=d.label.split('.'); return p.length>2?p.slice(0,-2).join('.'):d.label;
    })
    .style('display', _TM.showLabels?'':'none').style('pointer-events','none');
  node
    .on('mouseover', function(e,d){
      var sc={critical:'#ff443a',high:'#ff6b35',medium:'#ffd43b',low:'#74c0fc',info:'#868e96',none:'#868e96'};
      var h = '<strong>' + esc(d.label) + '</strong>';
      if (d.type==='group') {
        h += '<span class="tm-tt-badge" style="background:#1a2d3d;color:#4fa8e8">GROUP \u00b7 '+d.count+' subs</span>';
        if (d.vuln_count>0) h += '<span class="tm-tt-badge" style="background:#2d0d0d;color:#ff6b6b">'+d.vuln_count+' vuln</span>';
      } else if (d.type==='collapsed') {
        h += '<span class="tm-tt-badge" style="background:#222;color:#6e8098">'+d.count+' hidden</span>';
      } else if (d.type!=='root') {
        h += '<span class="tm-tt-badge" style="background:'+(d.alive?'#0d2414':'#1a1f26')+';color:'+(d.alive?'#34c759':'#6e8098')+'">'+(d.alive?'\u2713 ALIVE':'\u2717 DEAD')+'</span>';
        if (d.severity&&d.severity!=='none'&&d.severity!=='info') h+='<span class="tm-tt-badge" style="background:#2d0d0d;color:'+sc[d.severity]+'">'+esc(d.severity.toUpperCase())+' \u00b7 '+d.vuln_count+' finding'+(d.vuln_count>1?'s':'')+'</span>';
        if (d.xss) h+='<span class="tm-tt-badge" style="background:#2d0d0d;color:#ff453a">\u26a0 XSS</span>';
      }
      if (tooltip){ tooltip.innerHTML=h; tooltip.style.display='block'; }
    })
    .on('mousemove', function(e){
      if (!tooltip) return;
      var wr=document.querySelector('.tm-wrap'), rc=wr.getBoundingClientRect();
      var x=e.clientX-rc.left+14, y=e.clientY-rc.top+14;
      if (x+310>wr.clientWidth) x-=320;
      tooltip.style.left=x+'px'; tooltip.style.top=y+'px';
    })
    .on('mouseout', function(){ if(tooltip) tooltip.style.display='none'; });
  var infoEl = document.getElementById('tm-info');
  if (infoEl) infoEl.textContent = nodes.length + ' nodes \u00b7 ' + resolvedLinks.length + ' edges';
  var nodeCount = nodes.length;
  var alphaDecay = nodeCount > 500 ? 0.06 : nodeCount > 200 ? 0.035 : 0.02;
  var chargeStr  = function(d){ return d.type==='root'?-800:d.type==='group'?-200:-60; };
  var sim = d3.forceSimulation(nodes).alphaDecay(alphaDecay).velocityDecay(0.4)
    .force('link', d3.forceLink(resolvedLinks).id(function(d){ return d.id; }).distance(function(d){ return d.type==='group'?90:50; }).strength(function(d){ return d.type==='collapsed'?0.3:0.7; }))
    .force('charge', d3.forceManyBody().strength(chargeStr).distanceMax(nodeCount > 300 ? 200 : 400))
    .force('center', d3.forceCenter(W/2, H/2).strength(0.08))
    .force('collision', d3.forceCollide().radius(function(d){ return nodeRadius(d)+4; }).strength(0.7));
  _TM.sim = sim;
  sim.on('tick', function(){
    link.attr('x1',function(d){ return d.source.x; }).attr('y1',function(d){ return d.source.y; }).attr('x2',function(d){ return d.target.x; }).attr('y2',function(d){ return d.target.y; });
    node.attr('transform', function(d){ return 'translate('+d.x+','+d.y+')'; });
  });
  _TM.rendering = false;
}
function tmResetZoom() { if (!_TM.svg||!_TM.zoom) return; _TM.svg.transition().duration(500).call(_TM.zoom.transform, d3.zoomIdentity.translate(_TM.W/2,_TM.H/2).scale(0.7)); }
function tmToggleLabels() { _TM.showLabels=!_TM.showLabels; if (_TM.g) _TM.g.selectAll('.tm-label').style('display',_TM.showLabels?'':'none'); }
function tmFilterAlive() { _TM.filter='alive'; _tmApplyFilter(); }
function tmFilterVuln()  { _TM.filter='vuln';  _tmApplyFilter(); }
function tmFilterAll()   { _TM.filter='all';   _tmApplyFilter(); }
function tmSearch() {
  var q = document.getElementById('tm-search').value.toLowerCase().trim();
  if (!_TM.g) return;
  if (!q) { _TM.g.selectAll('g').each(function(){ d3.select(this).selectAll('circle,text').attr('opacity',1); }); return; }
  _TM.g.selectAll('g').each(function(d){
    if (!d) return;
    var match = d.label && d.label.toLowerCase().indexOf(q)>=0;
    d3.select(this).selectAll('circle').attr('opacity',match?1:0.08);
    d3.select(this).selectAll('text').attr('opacity',match?1:0.06);
  });
}
"""


# ── Builder ────────────────────────────────────────────────────────────────────
def build_report(scan_dir, target: str, summary: dict = None) -> Path:
    scan_dir = Path(scan_dir)
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M")

    recon    = _parse_recon(scan_dir)
    subs     = _parse_subdomains(scan_dir)
    alive    = _parse_alive(scan_dir)
    urls     = _parse_url_categories(scan_dir)
    nuclei   = _parse_nuclei(scan_dir)
    xss      = _parse_xss(scan_dir)
    smry_json= _parse_summary_json(scan_dir)
    smry     = summary or {}

    def _nav(icon, label, sid, count=None):
        cnt = (f'<span class="nav-cnt">{count:,}</span>' if isinstance(count, int) else
               f'<span class="nav-cnt">{count}</span>' if count is not None else "")
        return (f'<a class="nav-a" onclick="showSection(\'{_e(sid)}\',this)">'
                f'<span class="nav-ico">{icon}</span>{_e(label)}{cnt}</a>')

    sidebar = f'''<div class="sb-brand">
  <h1>&#9889; ReconX</h1>
  <div class="sb-target">&#127919; {_e(target)}</div>
  <div class="sb-ts">&#128197; {_e(ts)}</div>
</div>
<div class="nav-grp"><div class="nav-lbl">Overview</div>
  {_nav("🏠","Dashboard","overview")}
  {_nav("🗺️","Threat Map","threatmap", len(subs["all"]))}
</div>
<div class="nav-grp"><div class="nav-lbl">Reconnaissance</div>
  {_nav("🔍","Recon","recon")}
  {_nav("🌐","Subdomains","subdomains", len(subs["all"]))}
  {_nav("💻","Alive Hosts","alive", len(alive))}
</div>
<div class="nav-grp"><div class="nav-lbl">Discovery</div>
  {_nav("🔗","All URLs","urls", len(urls.get("_all",[])))}
  {_nav("🧩","Parameters","params")}
  {_nav("📂","Categorised","categorised")}
</div>
<div class="nav-grp"><div class="nav-lbl">Vulnerabilities</div>
  {_nav("💉","XSS / Dalfox","xss", len(xss["all"]))}
  {_nav("🎯","Nuclei","nuclei", len(nuclei["all"]))}
</div>
<hr class="nav-hr">
<div style="padding:8px 16px 16px;font-size:10px;color:#2d3f50;line-height:2">
  <kbd style="background:#1e2a36;padding:1px 5px;border-radius:3px;color:#6e8098">/</kbd> to search<br>
  Virtual scroll · No truncation<br>
  v6.6
</div>'''

    sections = "".join([
        _section_overview(target, ts, recon, subs, alive, urls, nuclei, xss, smry, smry_json),
        _section_threatmap(target, subs, alive, nuclei, xss),
        _section_recon(recon),
        _section_subdomains(subs),
        _section_alive(alive),
        _section_urls(urls),
        _section_params(urls),
        _section_categorised(urls),
        _section_xss(xss),
        _section_nuclei(nuclei),
    ])

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconX &mdash; {_e(target)}</title>
<style>{_CSS}</style>
</head>
<body>
<nav class="sidebar">{sidebar}</nav>
<main class="main">
{sections}
<div class="footer">
  ReconX v6.6 &middot; {_e(target)} &middot; {_e(ts)}<br>
  Use only on authorized targets under a valid bug bounty program.
</div>
</main>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<script>{_JS}</script>
</body>
</html>"""

    out = scan_dir / "report.html"
    out.write_text(page, encoding="utf-8")
    return out


build_full_report = build_report


def open_in_browser(path):
    import subprocess, sys, os
    path = Path(path).resolve()
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        elif sys.platform.startswith("linux"):
            for br in ["xdg-open","firefox","chromium","chromium-browser","google-chrome"]:
                if subprocess.run(["which", br], capture_output=True).returncode == 0:
                    subprocess.Popen([br, str(path)]); break
        elif sys.platform == "win32":
            os.startfile(str(path))
    except Exception as e:
        print(f"[!] Could not open browser: {e}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        p = build_report(Path(sys.argv[1]), sys.argv[2])
        print(f"Report -> {p}")
        open_in_browser(p)
    else:
        print("Usage: python3 report_builder.py <scan_output_dir> <target>")
