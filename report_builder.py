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

def _e(s) -> str:
    return html.escape(str(s) if s is not None else "", quote=True)

def _safe_content(s: str) -> str:
    return html.escape(str(s or ""), quote=True)

def _safe_json(data) -> str:
    raw = json.dumps(data, ensure_ascii=False, default=str)
    raw = raw.replace('<', r'\u003c').replace('>', r'\u003e').replace('&', r'\u0026')
    return raw

def _safe_href(url: str) -> str:
    s = url.strip()
    if re.match(r'^\s*(javascript|data|vbscript)\s*:', s, re.I):
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
            if f.name in ("all_raw.txt", "_all_before_dnsx.txt"):
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
    _IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    seen = set()
    hosts = []

    def _norm(rec):
        if not isinstance(rec, dict): return None
        url = (rec.get("url") or rec.get("input") or "").strip()
        if not url or not url.startswith("http"): return None
        sc = (rec.get("status-code") or rec.get("status_code") or
              rec.get("statusCode") or rec.get("code") or rec.get("status") or 0)
        try: sc = int(sc)
        except: sc = 0
        title = (rec.get("title") or rec.get("page-title") or "")[:80]
        ip = ""
        for _c in (rec.get("a") or []):
            if isinstance(_c, str) and _IP_RE.match(_c.strip()):
                ip = _c.strip(); break
        if not ip:
            _r = rec.get("ip") or ""
            if isinstance(_r, list): _r = _r[0] if _r else ""
            if _r and _IP_RE.match(str(_r).strip()): ip = str(_r).strip()
        tech_raw = (rec.get("tech") or rec.get("technologies") or
                    rec.get("detected-technologies") or [])
        if isinstance(tech_raw, list):
            tech = ", ".join(str(t).split(":")[0].strip() for t in tech_raw[:8] if t)
        else:
            tech = str(tech_raw)[:120]
        cl     = rec.get("content-length") or rec.get("content_length") or ""
        server = (rec.get("webserver") or rec.get("server") or "")[:50]
        rt     = (rec.get("time") or rec.get("response-time") or "")
        return {"url": url, "status": str(sc) if sc else "",
                "title": title, "ip": ip[:22], "tech": tech[:120],
                "size": str(cl), "server": str(server)[:50], "rt": str(rt)[:12]}

    def _add(rec):
        if isinstance(rec, str):
            rec = {"url": rec.strip()}
        h = _norm(rec)
        if h and h["url"] not in seen:
            seen.add(h["url"]); hosts.append(h)

    detail_f = d / "03_alive" / "hosts_detail.json"
    if detail_f.exists() and detail_f.stat().st_size > 0:
        try:
            data = json.loads(detail_f.read_text(errors="ignore"))
            if isinstance(data, list):
                for rec in data: _add(rec)
            if hosts: return hosts
        except Exception:
            pass

    httpx_f = d / "03_alive" / "httpx_full.json"
    if httpx_f.exists() and httpx_f.stat().st_size > 0:
        with httpx_f.open(errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try: _add(json.loads(line))
                except: continue
        if hosts: return hosts

    for line in _lines(d / "checkpoints" / "stage3_alive.txt"):
        _add(line)
    return hosts


def _parse_url_categories(d):
    d = Path(d)
    cats = {}
    for name in ["params", "reflection", "forms", "admin", "login", "api", "sensitive", "other",
                 "sqli", "lfi", "rce", "ssrf", "idor",
                 "upload", "debug_exposure", "auth_tokens",
                 "cors_jsonp", "graphql", "websocket", "ssti", "xxe"]:
        cats[name] = _lines(d / "05_categorized" / f"{name}.txt")

    cats["_all"]        = _lines(d / "checkpoints" / "stage4_urls.txt")
    cats["_gau"]        = _lines(d / "04_urls" / "gau.txt")
    cats["_wayback"]    = _lines(d / "04_urls" / "waybackurls.txt")
    cats["_katana"]     = _lines(d / "04_urls" / "katana.txt")
    cats["_hakrawler"]  = _lines(d / "04_urls" / "hakrawler_clean.txt") or _lines(d / "04_urls" / "hakrawler.txt")
    cats["_gospider"]   = _lines(d / "04_urls" / "gospider.txt")
    cats["_commoncrawl"]= _lines(d / "04_urls" / "commoncrawl.txt")
    cats["_urlscan"]    = _lines(d / "04_urls" / "urlscan.txt")
    cats["_otx"]        = _lines(d / "04_urls" / "otx.txt")
    return cats


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
        "red":    ("rgba(239,68,68,.15)", "#f87171"),
        "orange": ("rgba(249,115,22,.15)", "#fb923c"),
        "yellow": ("rgba(234,179,8,.15)", "#facc15"),
        "blue":   ("rgba(59,130,246,.15)", "#60a5fa"),
        "green":  ("rgba(34,197,94,.15)", "#4ade80"),
        "purple": ("rgba(168,85,247,.15)", "#c084fc"),
        "gray":   ("rgba(107,114,128,.15)", "#9ca3af"),
        "cyan":   ("rgba(6,182,212,.15)", "#22d3ee"),
    }
    bg, fg = colors.get(color, colors["blue"])
    return (f'<span style="background:{bg};color:{fg};padding:2px 10px;border-radius:6px;'
            f'font-size:11px;font-weight:600;letter-spacing:.3px;white-space:nowrap;'
            f'border:1px solid {fg}22">'
            f'{_e(text)}</span>')

def _stat(val, label: str, color: str, icon: str) -> str:
    cols = {"red":"#f87171","orange":"#fb923c","blue":"#60a5fa","green":"#4ade80",
            "yellow":"#facc15","purple":"#c084fc","gray":"#9ca3af"}
    bgs  = {"red":"rgba(239,68,68,.08)","orange":"rgba(249,115,22,.08)","blue":"rgba(59,130,246,.08)",
            "green":"rgba(34,197,94,.08)","yellow":"rgba(234,179,8,.08)","purple":"rgba(168,85,247,.08)",
            "gray":"rgba(107,114,128,.08)"}
    c  = cols.get(color, "#60a5fa")
    bg = bgs.get(color, "rgba(59,130,246,.08)")
    n  = f"{val:,}" if isinstance(val, int) else str(val)
    return (f'<div class="stat-card" style="--accent:{c};--accent-bg:{bg}">'
            f'<div class="stat-icon">{icon}</div>'
            f'<div class="stat-val">{n}</div>'
            f'<div class="stat-lbl">{_e(label)}</div>'
            f'</div>')

def _empty(msg: str = "No data recorded") -> str:
    return f'<div class="empty-state"><span class="empty-icon">◌</span><span>{_e(msg)}</span></div>'

def _code_block(text: str, max_lines: int = 400) -> str:
    if not text.strip():
        return _empty()
    lines = text.splitlines()
    shown = "\n".join(lines[:max_lines])
    extra = f"\n\n... {len(lines) - max_lines:,} more lines" if len(lines) > max_lines else ""
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


# ── Stat helpers ───────────────────────────────────────────────────────────────
# ── Section: Overview ─────────────────────────────────────────────────────────
def _section_overview(target, ts, recon, subs, alive, urls, smry_json):
    sc_n    = len(subs["all"])
    alive_n = len(alive)
    url_n   = len(urls.get("_all", []))
    par_n   = len(urls.get("params", []))
    sens_n  = len(urls.get("sensitive", []))
    refl_n  = len(urls.get("reflection", []))

    # URL kaynak sayıları
    src_counts = {
        "gau": len(urls.get("_gau",[])),
        "wayback": len(urls.get("_wayback",[])),
        "katana": len(urls.get("_katana",[])),
        "hakrawler": len(urls.get("_hakrawler",[])),
        "gospider": len(urls.get("_gospider",[])),
        "commoncrawl": len(urls.get("_commoncrawl",[])),
        "urlscan": len(urls.get("_urlscan",[])),
        "otx": len(urls.get("_otx",[])),
    }

    stats_html = "".join([
        _stat(sc_n,    "Subdomains",   "green",  "🌐"),
        _stat(alive_n, "Alive Hosts",  "blue",   "💻"),
        _stat(url_n,   "Total URLs",   "purple", "🔗"),
        _stat(par_n,   "Param URLs",   "orange", "⚙️"),
        _stat(refl_n,  "Reflection",   "yellow", "🪞"),
        _stat(sens_n,  "Sensitive",    "red",    "⚠️"),
        _stat(len(urls.get("api",[])),   "API Endpoints", "cyan",   "⚡"),
        _stat(len(urls.get("admin",[])), "Admin/Login",   "red",    "🔑"),
        _stat(sum(src_counts.values()), "Raw URL Sources", "gray", "📡"),
    ])

    probe = recon.get("probe", {})
    waf_list = smry_json.get("waf_fingerprint") or probe.get("waf_fingerprint") or []
    if waf_list:
        waf_badges = " ".join(_badge(w.upper(), "orange") for w in waf_list)
        waf_html = (f'<div class="panel" style="margin-top:14px"><div class="panel-header">'
                    f'<span class="panel-icon">🛡️</span><h3>WAF / CDN Detected</h3></div>'
                    f'<div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px">{waf_badges}</div></div>')
    else:
        waf_html = (f'<div class="panel" style="margin-top:14px"><div class="panel-header">'
                    f'<span class="panel-icon">🛡️</span><h3>WAF / CDN</h3></div>'
                    f'<div style="color:var(--muted);font-size:13px;margin-top:8px;display:flex;align-items:center;gap:8px">'
                    f'<span style="width:8px;height:8px;border-radius:50%;background:#4ade80;display:inline-block"></span>'
                    f'No WAF detected</div></div>')

    block_ratio = (smry_json.get("block_ratio_httpx") or
                   smry_json.get("stages", {}).get("stage3", {}).get("block_ratio") or 0)
    adapt_mult  = smry_json.get("adaptive_multiplier") or 1.0
    adapt_html  = ""
    if float(block_ratio) > 0.05:
        pct = f"{float(block_ratio)*100:.1f}%"
        col = "red" if float(block_ratio) > 0.3 else "orange" if float(block_ratio) > 0.1 else "yellow"
        adapt_html = (f'<div class="info-banner info-{col}" style="margin-bottom:16px">'
                      f'<span>⚡ Block ratio: <strong>{pct}</strong> · Rate multiplier: <strong>{float(adapt_mult):.2f}x</strong></span>'
                      f'</div>')

    stages_tl = [
        ("Recon",      bool(recon["whois"] or recon["nmap"]), "🔍"),
        ("Subdomains", bool(subs["all"]),                     "🌐"),
        ("Alive",      bool(alive),                           "💻"),
        ("URLs",       bool(url_n),                           "🔗"),
        ("Categorise", bool(par_n or refl_n),                 "📂"),
    ]
    tl = '<div class="timeline">'
    for lbl, done, icon in stages_tl:
        cls = "tl-done" if done else "tl-skip"
        tl += (f'<div class="tl-step {cls}"><div class="tl-dot">{icon}</div>'
               f'<div class="tl-lbl">{_e(lbl)}</div></div>')
    tl += "</div>"

    # URL kaynak bar chart
    src_max = max(src_counts.values()) if any(src_counts.values()) else 1
    src_colors = {"gau":"#fb923c","wayback":"#60a5fa","katana":"#4ade80","hakrawler":"#c084fc",
                  "gospider":"#facc15","commoncrawl":"#22d3ee","urlscan":"#f472b6","otx":"#f87171"}
    src_bars = ""
    for k, v in sorted(src_counts.items(), key=lambda x: -x[1]):
        if v == 0: continue
        pct = max(4, int(v / src_max * 100))
        col = src_colors.get(k, "#60a5fa")
        src_bars += (f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">'
                     f'<div style="width:90px;font-size:12px;color:var(--muted);text-align:right">{_e(k)}</div>'
                     f'<div style="flex:1;background:var(--surface3);border-radius:4px;height:14px;overflow:hidden">'
                     f'<div style="width:{pct}%;background:{col};height:100%;border-radius:4px;opacity:.85"></div></div>'
                     f'<div style="width:52px;font-size:12px;font-family:var(--mono);color:var(--text-dim);text-align:right">{v:,}</div>'
                     f'</div>')

    # URL kategori bar chart
    cat_data = {
        "params": par_n, "reflection": refl_n, "admin": len(urls.get("admin",[])),
        "login": len(urls.get("login",[])), "api": len(urls.get("api",[])),
        "sensitive": sens_n, "forms": len(urls.get("forms",[])),
    }
    cat_max = max(cat_data.values()) if any(cat_data.values()) else 1
    cat_colors = {"params":"#fb923c","reflection":"#f87171","admin":"#ef4444",
                  "login":"#facc15","api":"#c084fc","sensitive":"#f87171","forms":"#60a5fa"}
    cat_icons  = {"params":"⚙️","reflection":"🪞","admin":"🔑","login":"🚪","api":"⚡",
                  "sensitive":"⚠️","forms":"📝"}
    cat_bars = ""
    for k, v in sorted(cat_data.items(), key=lambda x: -x[1]):
        if v == 0: continue
        pct = max(4, int(v / cat_max * 100))
        col = cat_colors.get(k, "#60a5fa")
        ico = cat_icons.get(k, "")
        cat_bars += (f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">'
                     f'<div style="width:90px;font-size:12px;color:var(--muted);text-align:right;display:flex;align-items:center;justify-content:flex-end;gap:4px">{ico} {_e(k)}</div>'
                     f'<div style="flex:1;background:var(--surface3);border-radius:4px;height:14px;overflow:hidden">'
                     f'<div style="width:{pct}%;background:{col};height:100%;border-radius:4px;opacity:.85"></div></div>'
                     f'<div style="width:52px;font-size:12px;font-family:var(--mono);color:var(--text-dim);text-align:right">{v:,}</div>'
                     f'</div>')

    adapt_events = smry_json.get("adaptive_events") or []
    adapt_tl = ""
    if adapt_events:
        adapt_tl = '<div style="margin-top:10px;display:flex;flex-direction:column;gap:6px">'
        for ev in adapt_events[:8]:
            reason = _e(ev.get("reason", ""))
            ts_ev  = _e(ev.get("ts", ""))
            mb = ev.get("mult_before", 1.0)
            ma = ev.get("mult_after", 1.0)
            col = "red" if float(ma) < 0.3 else "orange"
            bdr = "#ef4444" if col=="red" else "#f97316"
            adapt_tl += (f'<div style="display:flex;align-items:center;gap:10px;padding:8px 12px;'
                         f'background:var(--surface3);border-radius:8px;border-left:3px solid {bdr}">'
                         f'<div style="flex:1"><div style="font-size:12px;color:var(--text)">{reason}</div>'
                         f'<div style="font-size:11px;color:var(--muted);margin-top:2px">{ts_ev}</div></div>'
                         f'<div>{_badge(f"{mb:.2f}→{ma:.2f}x", col)}</div>'
                         f'</div>')
        if len(adapt_events) > 8:
            adapt_tl += f'<div style="font-size:11px;color:var(--muted);padding:4px 12px">+{len(adapt_events)-8} more</div>'
        adapt_tl += "</div>"

    return f'''
<div id="s-overview" class="section active">
  <div class="sec-hdr">
    <div class="sec-hdr-inner">
      <div>
        <h2>Dashboard</h2>
        <p class="sec-sub">Target: <code class="target-code">{_e(target)}</code> &nbsp;·&nbsp; {_e(ts)}</p>
      </div>
      <div class="sec-hdr-badge">{_badge("RECON COMPLETE", "green")}</div>
    </div>
  </div>
  {adapt_html}
  <div class="stat-grid">{stats_html}</div>

  <div class="two-col" style="margin-top:20px">
    <div class="panel">
      <div class="panel-header"><span class="panel-icon">🚀</span><h3>Pipeline Status</h3></div>
      {tl}
    </div>
    <div class="panel">
      <div class="panel-header"><span class="panel-icon">📡</span><h3>URL Sources</h3></div>
      <div style="margin-top:14px">{src_bars if src_bars else "<div style='color:var(--muted);font-size:13px'>No URL source data yet</div>"}</div>
    </div>
  </div>

  <div class="two-col" style="margin-top:14px">
    <div class="panel">
      <div class="panel-header"><span class="panel-icon">📊</span><h3>URL Categories</h3></div>
      <div style="margin-top:14px">{cat_bars if cat_bars else "<div style='color:var(--muted);font-size:13px'>No categorised URLs yet</div>"}</div>
    </div>
    <div>
      {waf_html}
    </div>
  </div>
</div>
'''

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
    return (f'<div id="s-recon" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div><h2>Reconnaissance</h2></div></div></div>'
            f'{body}</div>')


# ── Section: Subdomains ───────────────────────────────────────────────────────
def _section_subdomains(subs):
    all_s = subs["all"]
    tool_rows = sorted(
        [[t, str(len(u)), "; ".join(u[:3]) + ("…" if len(u) > 3 else "")]
         for t, u in subs["by_tool"].items() if u],
        key=lambda r: -int(r[1])
    )
    body = (f'{_vscroll(all_s, "vs-subs", "subdomain")}'
            f'<div style="margin-top:28px"><div class="subsection-label">Tool Breakdown</div>'
            f'{_vtable(["Tool", "Count", "Sample"], tool_rows, "vt-sub-tools")}</div>'
            if all_s else _empty())
    return (f'<div id="s-subdomains" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>Subdomains</h2>'
            f'<p class="sec-sub">{len(all_s):,} unique subdomains discovered</p>'
            f'</div></div></div>{body}</div>')


# ── Section: Alive ────────────────────────────────────────────────────────────
def _section_alive(alive):
    if not alive:
        return (f'<div id="s-alive" class="section">'
                f'<div class="sec-hdr"><div class="sec-hdr-inner"><div><h2>Alive Hosts</h2></div></div></div>'
                f'{_empty()}</div>')

    sc_dist: dict = {}
    for h in alive:
        sc = str(h.get("status","") or "")
        if sc:
            grp = sc[0] + "xx"
            sc_dist[grp] = sc_dist.get(grp, 0) + 1

    sc_colors = {"2xx": "#4ade80", "3xx": "#60a5fa", "4xx": "#facc15", "5xx": "#f87171"}
    sc_pills = " ".join(
        f'<span style="background:{sc_colors.get(g,"#6b7280")}18;color:{sc_colors.get(g,"#6b7280")};'
        f'padding:4px 12px;border-radius:6px;font-size:12px;font-weight:600;font-family:var(--mono);'
        f'border:1px solid {sc_colors.get(g,"#6b7280")}30">'
        f'{_e(g)}: {c}</span>'
        for g, c in sorted(sc_dist.items())
    )

    rows = [[h.get("url",""), str(h.get("status","")), (h.get("title","") or "")[:60],
             (h.get("ip","") or "")[:20], (h.get("tech","") or "")[:80],
             str(h.get("size","") or ""), (h.get("server","") or "")[:40],
             (h.get("rt","") or "")]
            for h in alive]
    safe = _safe_json(rows)
    return f'''<div id="s-alive" class="section">
  <div class="sec-hdr"><div class="sec-hdr-inner"><div>
    <h2>Alive Hosts</h2>
    <p class="sec-sub">{len(alive):,} responsive hosts</p>
  </div></div></div>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">{sc_pills}</div>
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


# ── Section: URLs ─────────────────────────────────────────────────────────────
def _section_urls(urls):
    all_u = urls.get("_all", [])
    tool_tabs = [
        ("all",          f"All ({len(all_u):,})",                                 all_u),
        ("gau",          f"gau ({len(urls.get('_gau',[])):,})",                   urls.get("_gau",[])),
        ("wayback",      f"Wayback ({len(urls.get('_wayback',[])):,})",           urls.get("_wayback",[])),
        ("katana",       f"Katana ({len(urls.get('_katana',[])):,})",             urls.get("_katana",[])),
        ("hakrawler",    f"Hakrawler ({len(urls.get('_hakrawler',[])):,})",       urls.get("_hakrawler",[])),
        ("gospider",     f"GoSpider ({len(urls.get('_gospider',[])):,})",         urls.get("_gospider",[])),
        ("commoncrawl",  f"CommonCrawl ({len(urls.get('_commoncrawl',[])):,})",   urls.get("_commoncrawl",[])),
        ("urlscan",      f"URLScan ({len(urls.get('_urlscan',[])):,})",           urls.get("_urlscan",[])),
        ("otx",          f"OTX ({len(urls.get('_otx',[])):,})",                   urls.get("_otx",[])),
    ]
    tab_items = [(tid, label, _vscroll(data, f"vs-url-{tid}"))
                 for tid, label, data in tool_tabs if data]
    body = _tabs(tab_items, "url") if tab_items else _empty()
    return (f'<div id="s-urls" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>URL Discovery</h2>'
            f'<p class="sec-sub">{len(all_u):,} unique URLs · {len([t for t,_,d in tool_tabs if d])-1} sources</p>'
            f'</div></div></div>{body}</div>')


# ── Section: Categorised ──────────────────────────────────────────────────────
def _section_categorised(urls):
    base_cats = [
        ("reflection", "🪞 Reflection", "red",    "XSS candidates — high-signal params"),
        ("params",     "⚙️ Params",     "orange", "All URLs with query strings"),
        ("sensitive",  "⚠️ Sensitive",  "red",    ".env · .git · backups · credentials"),
        ("admin",      "🔑 Admin",      "red",    "Admin/dashboard/management panels"),
        ("login",      "🚪 Login",      "yellow", "Authentication & SSO endpoints"),
        ("api",        "⚡ API",        "purple", "REST · GraphQL · RPC · webhooks"),
        ("forms",      "📝 Forms",      "blue",   "PHP · ASP · JSP form handlers"),
        ("other",      "📄 Other",      "gray",   "Uncategorised"),
    ]
    vuln_cats = [
        ("sqli",           "💉 SQLi",       "red",    "SQL Injection candidates — ID/sort/filter params"),
        ("lfi",            "📂 LFI",        "orange", "Local File Inclusion — file/path/template params"),
        ("rce",            "💥 RCE",        "red",    "Remote Code Execution — cmd/exec/system params"),
        ("ssrf",           "🌐 SSRF",       "orange", "SSRF — url/host/endpoint params"),
        ("idor",           "🔑 IDOR",       "yellow", "IDOR — id/uid/order_id numeric/hash params"),
        ("upload",         "📤 Upload",     "yellow", "File upload endpoints"),
        ("debug_exposure", "🐛 Debug",      "yellow", "Debug/Swagger/Actuator/phpinfo pages"),
        ("auth_tokens",    "🔐 Auth",       "blue",   "Token/API key/JWT param URLs"),
        ("cors_jsonp",     "🔄 CORS/JSONP", "purple", "JSONP callback param URLs"),
        ("graphql",        "⚡ GraphQL",    "purple", "GraphQL endpoints"),
        ("websocket",      "🔌 WebSocket",  "blue",   "WebSocket/Realtime endpoints"),
        ("ssti",           "📝 SSTI",       "orange", "Server-Side Template Injection candidates"),
        ("xxe",            "📄 XXE",        "orange", "XML/XXE potential endpoints"),
    ]

    all_tab_items = []
    for key, label, color, desc in base_cats:
        data  = urls.get(key, [])
        cnt   = len(data)
        badge = _badge(f"{cnt:,}", color)
        content = (f'<div class="cat-desc">{_e(desc)}</div>'
                   f'{_vscroll(data, f"vs-cat-{key}")}')
        all_tab_items.append((key, f"{label} {badge}", content))

    has_vuln = any(len(urls.get(k, [])) > 0 for k, *_ in vuln_cats)
    if has_vuln:
        all_tab_items.append(("_sep", "┆", '<div></div>'))

    for key, label, color, desc in vuln_cats:
        data = urls.get(key, [])
        cnt  = len(data)
        if cnt == 0: continue
        badge = _badge(f"{cnt:,}", color)
        content = (f'<div class="cat-desc" style="border-left-color:{"#ef4444" if color=="red" else "#fb923c" if color=="orange" else "#6b7280"}">'
                   f'⚠️ {_e(desc)}</div>'
                   f'{_vscroll(data, f"vs-cat-{key}")}')
        all_tab_items.append((key, f"{label} {badge}", content))

    tab_row_items = []; pane_items = []; first_active = True
    for tid, label, content in all_tab_items:
        if tid == "_sep":
            tab_row_items.append(
                f'<span style="color:var(--border2);padding:9px 6px;font-size:16px;align-self:center;cursor:default;user-select:none">┆</span>'
            )
            continue
        active = "active" if first_active else ""
        first_active = False
        tab_row_items.append(
            f'<button class="tab {active}" onclick="tab(this,\'cat-{_e(tid)}\')">{label}</button>'
        )
        pane_items.append(
            f'<div class="pane {active}" id="cat-{_e(tid)}">{content}</div>'
        )

    body = (f'<div class="tab-row">{"".join(tab_row_items)}</div>'
            f'<div class="panes">{"".join(pane_items)}</div>') if tab_row_items else _empty()

    return (f'<div id="s-categorised" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>Categorised URLs</h2>'
            f'<p class="sec-sub">URL pattern analysis · {len(urls.get("_all", [])):,} total URLs'
            f'<span style="margin-left:12px;color:#6b7280;font-size:11px">┆ after separator = vulnerability patterns</span>'
            f'</p></div></div></div>{body}</div>')


# ── Section: Parameters ───────────────────────────────────────────────────────
def _section_params(urls):
    params_map = {}
    for u in urls.get("params", []):
        for k in parse_qs(urlparse(u).query):
            params_map.setdefault(k, []).append(u)
    high_risk = {"q","query","search","s","keyword","input","text","name","value","data","content",
                 "msg","message","title","url","uri","redirect","return","ref","callback","cmd",
                 "exec","action","view","mode","page","id","file","path","token","key"}
    rows = sorted(
        [[k, str(len(v)),
          "🔴 High"   if k.lower() in high_risk else
          "🟡 Medium" if any(w in k.lower() for w in ["search","filter","cat","type","sort"]) else
          "⚪ Low",
          v[0][:100]]
         for k, v in params_map.items()],
        key=lambda r: -int(r[1])
    )
    note = ('<p style="color:var(--muted);font-size:12px;margin-bottom:16px;padding:8px 12px;'
            'background:var(--surface2);border-radius:6px;border-left:3px solid var(--border)">'
            '🔴 High = common injection target &nbsp;·&nbsp; 🟡 Medium = filter/search params &nbsp;·&nbsp; ⚪ Low = general params</p>')
    return (f'<div id="s-params" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>Parameters</h2>'
            f'<p class="sec-sub">{len(params_map):,} unique params across {len(urls.get("params",[])):,} URLs</p>'
            f'</div></div></div>'
            f'{note}'
            f'{_vtable(["Parameter", "Occurrences", "Risk", "Example URL"], rows, "vt-params")}'
            f'</div>')


# ── Section: Threat Map ───────────────────────────────────────────────────────

def _section_threatmap(target: str, subs: dict, alive: list) -> str:
    all_subs  = subs.get("all", [])
    alive_set = set()
    for h in alive:
        u = h.get("url","")
        try:
            alive_set.add(urlparse(u).hostname or "")
        except:
            pass

    vuln_map: dict = {}

    MAX_DIRECT = 300
    nodes = [{"id": target, "type": "root", "label": target,
               "alive": True, "severity": "none", "vuln_count": 0}]
    links = []

    group_map: dict = {}
    singletons: list = []

    for s in all_subs:
        if s == target: continue
        suffix = "." + target
        local  = s[:-len(suffix)] if s.endswith(suffix) else s
        parts  = local.split(".")
        if len(parts) >= 2:
            grp = parts[-1]
            group_map.setdefault(grp, []).append(s)
        else:
            singletons.append(s)

    CLUSTER_THRESHOLD = 400
    big_group_limit = 8 if sum(len(v) for v in group_map.values()) > CLUSTER_THRESHOLD else 999

    for s in singletons[:MAX_DIRECT]:
        nodes.append({"id": s, "type": "subdomain", "label": s,
                       "alive": s in alive_set,
                       "severity": vuln_map.get(s,{}).get("severity","none"),
                       "vuln_count": vuln_map.get(s,{}).get("count",0)})
        links.append({"source": target, "target": s, "type": "sub"})

    for grp, members in group_map.items():
        if len(members) == 1:
            s = members[0]
            nodes.append({"id": s, "type": "subdomain", "label": s,
                           "alive": s in alive_set,
                           "severity": vuln_map.get(s,{}).get("severity","none"),
                           "vuln_count": vuln_map.get(s,{}).get("count",0)})
            links.append({"source": target, "target": s, "type": "sub"})
        else:
            grp_id = f"_grp_{grp}"
            grp_sev = "none"; grp_vuln = 0
            sev_order = {"high":4,"medium":3,"low":2,"info":1,"none":0}
            for m in members:
                mv = vuln_map.get(m,{})
                if sev_order.get(mv.get("severity","none"),0) > sev_order.get(grp_sev,0):
                    grp_sev = mv.get("severity","none")
                grp_vuln += mv.get("count",0)
            nodes.append({"id": grp_id, "type": "group",
                           "label": f"*.{grp}", "count": len(members),
                           "alive": any(m in alive_set for m in members),
                           "severity": grp_sev, "vuln_count": grp_vuln})
            links.append({"source": target, "target": grp_id, "type": "group"})
            for s in members[:big_group_limit]:
                nodes.append({"id": s, "type": "subdomain", "label": s,
                               "alive": s in alive_set,
                               "severity": vuln_map.get(s,{}).get("severity","none"),
                               "vuln_count": vuln_map.get(s,{}).get("count",0)})
                links.append({"source": grp_id, "target": s, "type": "sub"})
            if len(members) > big_group_limit:
                hidden_id = f"_hidden_{grp}"
                nodes.append({"id": hidden_id, "type": "collapsed",
                               "label": f"+{len(members)-big_group_limit} more",
                               "count": len(members)-big_group_limit,
                               "alive": False, "severity": "none", "vuln_count": 0})
                links.append({"source": grp_id, "target": hidden_id, "type": "collapsed"})

    graph_json = _safe_json({"nodes": nodes, "links": links,
                              "total_subs": len(all_subs), "rendered": len(nodes)})

    return f'''<div id="s-threatmap" class="section">
  <div class="sec-hdr"><div class="sec-hdr-inner"><div>
    <h2>Threat Map</h2>
    <p class="sec-sub">{len(all_subs):,} subdomains · {len(alive_set):,} alive · {len(nodes):,} nodes · drag &amp; scroll to zoom</p>
  </div></div></div>
  <div class="tm-legend">
    <span class="tm-leg-item"><span class="tm-dot" style="background:#3b82f6"></span>Root</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#1e3a50;border:1px dashed #3b82f6"></span>Group</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#374151"></span>Collapsed</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#22c55e"></span>Alive</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#475569"></span>Dead</span>
  </div>
  <div class="tm-toolbar">
    <button class="btn-sm" onclick="tmResetZoom()">⊙ Reset</button>
    <button class="btn-sm" onclick="tmToggleLabels()">🏷 Labels</button>
    <button class="btn-sm" onclick="tmFilterAlive()">💚 Alive only</button>
    <button class="btn-sm" onclick="tmFilterAll()">🌐 All</button>
    <input id="tm-search" class="vs-search" style="max-width:200px" placeholder="Search node..." oninput="tmSearch()">
    <span id="tm-info" style="font-size:12px;color:var(--muted);margin-left:auto"></span>
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


# ── CSS ───────────────────────────────────────────────────────────────────────
_CSS = "\n@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Syne:wght@400;500;600;700;800&family=Inter:wght@300;400;500;600&display=swap');\n:root{--bg:#080b10;--surface1:#0d1117;--surface2:#131920;--surface3:#1a2235;--border:#1f2d42;--border2:#2a3f5c;--text:#e2eaf4;--text-dim:#a8bfd4;--muted:#6b8aaa;--accent:#3b82f6;--accent2:#7ab8ff;--green:#22c55e;--red:#ef4444;--orange:#f97316;--yellow:#eab308;--purple:#a855f7;--mono:'IBM Plex Mono',monospace;--sans:'Inter',sans-serif;--display:'Syne',sans-serif;--sw:240px;--rh:36px;--radius:10px}\n*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}\nbody{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;display:flex;min-height:100vh;line-height:1.6;-webkit-font-smoothing:antialiased}\n.sidebar{width:var(--sw);min-width:var(--sw);background:var(--surface1);border-right:1px solid var(--border);position:fixed;top:0;left:0;height:100vh;overflow-y:auto;z-index:100;display:flex;flex-direction:column}\n.sidebar::-webkit-scrollbar{width:3px}.sidebar::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}\n.sb-brand{padding:20px 18px 18px;border-bottom:1px solid var(--border);background:linear-gradient(160deg,#0f1318 0%,#111827 100%)}\n.sb-logo{display:flex;align-items:center;gap:10px;margin-bottom:12px}\n.sb-logo-mark{width:32px;height:32px;background:linear-gradient(135deg,#3b82f6,#1d4ed8);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;box-shadow:0 0 16px rgba(59,130,246,.3);flex-shrink:0}\n.sb-brand h1{font-family:var(--display);font-size:16px;font-weight:800;color:#fff;letter-spacing:-.3px}\n.sb-brand h1 span{color:var(--accent2)}\n.sb-target{font-family:var(--mono);font-size:11px;color:var(--text-dim);padding:6px 10px;background:var(--surface3);border-radius:6px;border:1px solid var(--border);word-break:break-all;line-height:1.5}\n.sb-ts{font-size:10px;color:#6a8aaa;margin-top:6px}\n.nav-grp{padding:8px 0 4px}\n.nav-lbl{color:#5a7a9a;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;padding:4px 16px 6px;font-family:var(--display)}\n.nav-a{display:flex;align-items:center;gap:9px;padding:8px 16px;color:#8aaac8;cursor:pointer;font-size:13px;border-left:2px solid transparent;transition:all .15s;text-decoration:none;font-weight:400}\n.nav-a:hover{color:#c8dff0;background:rgba(59,130,246,.07)}\n.nav-a.active{color:#7ab8ff;background:rgba(59,130,246,.12);border-left-color:#3b82f6;font-weight:600}\n.nav-ico{font-size:14px;width:18px;text-align:center;flex-shrink:0}\n.nav-cnt{margin-left:auto;background:var(--surface3);color:#7ab8ff;font-size:10px;padding:1px 7px;border-radius:20px;font-family:var(--mono);border:1px solid var(--border2)}\n.nav-cnt.cnt-red{background:rgba(239,68,68,.18);color:#ff8080;border:1px solid rgba(239,68,68,.3)}\n.nav-cnt.cnt-orange{background:rgba(249,115,22,.18);color:#ffab6e;border:1px solid rgba(249,115,22,.3)}\n.nav-hr{border:none;border-top:1px solid var(--border);margin:6px 0}\n.sb-hint{padding:10px 16px 16px;font-size:10px;color:#6a8aaa;line-height:1.8}\n.sb-hint kbd{background:var(--surface3);padding:1px 5px;border-radius:4px;color:#a0bfd6;border:1px solid var(--border2);font-family:var(--mono);font-size:10px}\n.main{margin-left:var(--sw);flex:1;padding:32px 40px 72px;max-width:none;min-width:0;}\n.section{display:none}.section.active{display:block}\n.sec-hdr{margin-bottom:24px}\n.sec-hdr-inner{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}\n.sec-hdr h2{font-family:var(--display);font-size:24px;font-weight:800;color:#fff;letter-spacing:-.5px}\n.sec-sub{color:#7a9ab8;font-size:13px;margin-top:4px}\n.sec-hdr-badge{margin-top:4px}\n.target-code{font-family:var(--mono);font-size:12px;color:var(--accent2);background:rgba(59,130,246,.1);padding:2px 8px;border-radius:4px}\n.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(112px,1fr));gap:10px;margin-top:12px}\n.stat-card{background:var(--surface1);border:1px solid var(--border);border-radius:var(--radius);padding:16px 12px;text-align:center;transition:transform .15s,border-color .15s,box-shadow .15s;cursor:default;position:relative;overflow:hidden}\n.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);opacity:.5}\n.stat-card:hover{transform:translateY(-3px);border-color:var(--accent);box-shadow:0 8px 24px rgba(0,0,0,.3)}\n.stat-icon{font-size:22px;margin-bottom:8px}\n.stat-val{font-size:22px;font-weight:800;line-height:1;font-family:var(--mono);color:var(--accent2)}\n.stat-lbl{font-size:10px;color:#7a9ab8;margin-top:5px;text-transform:uppercase;letter-spacing:.8px;font-weight:600}\n.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}\n.panel{background:var(--surface1);border:1px solid var(--border);border-radius:var(--radius);padding:18px 20px}\n.panel-header{display:flex;align-items:center;gap:8px;margin-bottom:14px}\n.panel-icon{font-size:16px}\n.panel h3{font-family:var(--display);font-size:13px;font-weight:700;color:#90b0cc;text-transform:uppercase;letter-spacing:.6px}\n.mini-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}\n.mini-num{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;display:flex;flex-direction:column;align-items:center;gap:2px;font-size:20px;font-weight:800;font-family:var(--mono);color:var(--nc,var(--accent))}\n.mini-num span{font-size:10px;color:#7a9ab8;font-weight:500;font-family:var(--sans);text-transform:uppercase;letter-spacing:.5px}\n.timeline{display:flex;gap:0;overflow-x:auto;padding-bottom:4px}\n.tl-step{display:flex;flex-direction:column;align-items:center;min-width:70px;position:relative;flex:1}\n.tl-step:not(:last-child)::after{content:'';position:absolute;top:20px;left:56%;width:88%;height:2px;background:var(--border2)}\n.tl-step.tl-done:not(:last-child)::after{background:var(--green)}\n.tl-dot{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:17px;background:var(--surface2);border:2px solid var(--border2);position:relative;z-index:1}\n.tl-step.tl-done .tl-dot{background:rgba(34,197,94,.12);border-color:var(--green)}\n.tl-step.tl-skip .tl-dot{opacity:.3;filter:grayscale(1)}\n.tl-lbl{font-size:10px;color:#7a9ab8;margin-top:6px;text-align:center;font-weight:500}\n.tl-step.tl-done .tl-lbl{color:#a8c8e0}\n.tab-row{display:flex;gap:2px;border-bottom:1px solid var(--border);margin-bottom:16px;flex-wrap:wrap;align-items:center}\n.tab{background:none;border:none;color:#7a9ab8;padding:9px 14px;cursor:pointer;font-size:12px;font-weight:500;font-family:var(--sans);border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .12s;white-space:nowrap;letter-spacing:.2px}\n.tab:hover{color:#c0d8ee}.tab.active{color:#7ab8ff;border-bottom-color:var(--accent)}\n.panes .pane{display:none}.panes .pane.active{display:block}\n.code-block{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:16px 18px;font-family:var(--mono);font-size:12.5px;line-height:1.7;overflow:auto;white-space:pre-wrap;word-break:break-all;max-height:550px;color:#b8d0e4}\n.code-block::-webkit-scrollbar{width:6px;height:6px}.code-block::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}\n.vs-wrap,.vt-wrap{position:relative}\n.vs-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap}\n.vs-counter{font-family:var(--mono);font-size:12px;color:#7a9ab8;white-space:nowrap;min-width:80px}\n.vs-search{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px 13px;border-radius:8px;font-size:13px;flex:1;min-width:180px;outline:none;font-family:var(--sans);transition:border-color .12s}\n.vs-search::placeholder{color:var(--muted)}.vs-search:focus{border-color:var(--accent);background:var(--surface3)}\n.btn-sm{background:var(--surface2);border:1px solid var(--border2);color:#a0bfd6;padding:7px 14px;border-radius:8px;cursor:pointer;font-size:12px;font-family:var(--sans);white-space:nowrap;transition:all .12s;font-weight:500}\n.btn-sm:hover{color:#7ab8ff;border-color:var(--accent);background:rgba(59,130,246,.08)}\n.vs-scroll{height:520px;overflow-y:auto;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);position:relative}\n.vs-scroll::-webkit-scrollbar{width:6px}.vs-scroll::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}\n.vs-vp{position:relative}\n.vs-row{height:var(--rh);display:flex;align-items:center;padding:0 14px;border-bottom:1px solid rgba(30,40,56,.7);position:absolute;width:100%}\n.vs-row:hover{background:rgba(59,130,246,.04)}\n.vs-row a{font-family:var(--mono);font-size:12px;color:#8aaac8;text-decoration:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;width:100%}\n.vs-row a:hover{color:#7ab8ff}\n.url-host{color:#5a8fb5}.url-path{color:#b0ccde}.url-qs{color:#f5a55a}\n.tbl-scroll{overflow-x:auto;max-width:100%;border:1px solid var(--border);border-radius:var(--radius)}\n.tbl-scroll::-webkit-scrollbar{height:6px}.tbl-scroll::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}\ntable{min-width:1200px;width:min(100%,max-content);border-collapse:collapse;font-size:13px}\nth{background:var(--surface2);color:#7a9ab8;padding:10px 14px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;white-space:nowrap;position:sticky;top:0;z-index:1;font-family:var(--display);border-bottom:1px solid var(--border2)}\ntd{padding:9px 14px;border-bottom:1px solid var(--border);vertical-align:middle;max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono);font-size:12px;color:#c0d4e8}\ntr:last-child td{border-bottom:none}\ntr:hover td{background:rgba(59,130,246,.05);color:#e2eaf4}\n.vt-more{padding:10px 14px;font-size:12px;color:#7a9ab8;background:var(--surface2);border-top:1px solid var(--border);display:flex;align-items:center;gap:10px}\n.load-btn{background:none;border:1px solid var(--border2);color:var(--accent2);padding:4px 14px;border-radius:20px;cursor:pointer;font-size:12px;font-family:var(--sans);transition:all .12s}\n.load-btn:hover{background:rgba(59,130,246,.1);border-color:var(--accent)}\n.alert-box{border-radius:var(--radius);padding:12px 16px;margin-bottom:16px;font-size:13px;font-weight:500;border:1px solid;display:flex;align-items:center;gap:8px}\n.alert-red{background:rgba(239,68,68,.06);border-color:rgba(239,68,68,.25);color:#fca5a5}\n.alert-blue{background:rgba(59,130,246,.06);border-color:rgba(59,130,246,.2);color:var(--accent2)}\n.info-banner{padding:10px 16px;border-radius:8px;font-size:13px;border:1px solid}\n.info-red{background:rgba(239,68,68,.06);border-color:rgba(239,68,68,.2);color:#fca5a5}\n.info-orange{background:rgba(249,115,22,.06);border-color:rgba(249,115,22,.2);color:#fdba74}\n.info-yellow{background:rgba(234,179,8,.06);border-color:rgba(234,179,8,.2);color:#fde047}\n.cat-desc{color:#8aaac8;font-size:12px;margin-bottom:12px;padding:8px 12px;background:var(--surface2);border-radius:6px;border-left:3px solid var(--border2)}\n.subsection-label{font-family:var(--display);color:#7a9ab8;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1.2px;margin-bottom:10px}\n.empty-state{display:flex;align-items:center;justify-content:center;gap:10px;color:#6a8aaa;font-size:13px;padding:40px;background:var(--surface2);border-radius:var(--radius);border:1px dashed var(--border2)}\n.empty-icon{font-size:20px;opacity:.4}\n.probe-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:16px}\n.probe-row{display:flex;padding:10px 16px;border-bottom:1px solid var(--border);align-items:center;gap:14px}\n.probe-row:last-child{border-bottom:none}\n.probe-row span{color:#8aaac8;font-size:12px;width:130px;flex-shrink:0;font-weight:500}\n.probe-row b{font-family:var(--mono);font-size:12px;color:#ddeeff;font-weight:500}\ndetails summary::-webkit-details-marker{display:none}\ndetails summary{transition:background .12s}\ndetails[open] summary{border-radius:8px 8px 0 0}\n.tm-wrap{position:relative;background:var(--surface1);border:1px solid var(--border);border-radius:12px;overflow:hidden;height:680px;margin-top:12px}\n#tm-svg{width:100%;height:100%;cursor:grab}\n#tm-svg:active{cursor:grabbing}\n.tm-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}\n.tm-legend{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;padding:10px 14px;background:var(--surface2);border-radius:8px;border:1px solid var(--border)}\n.tm-leg-item{display:flex;align-items:center;gap:7px;font-size:12px;color:#8aaac8}\n.tm-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}\n.tm-tooltip{position:absolute;pointer-events:none;background:rgba(10,13,18,.97);border:1px solid var(--border2);border-radius:10px;padding:12px 14px;font-size:12px;color:var(--text);max-width:300px;display:none;z-index:50;box-shadow:0 12px 40px rgba(0,0,0,.7);line-height:1.7}\n.tm-tooltip strong{color:var(--accent2);font-family:var(--mono);font-size:11px;word-break:break-all;display:block;margin-bottom:5px}\n.tm-tt-badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:10px;font-weight:600;margin:1px 2px}\n.footer{margin-top:56px;padding-top:16px;border-top:1px solid var(--border);color:#6a8aaa;font-size:11px;line-height:1.8}\ncode{font-family:var(--mono);font-size:12px;color:var(--accent2)}\n@media(max-width:900px){.sidebar{display:none}.main{margin-left:0;padding:16px}.two-col{grid-template-columns:1fr}}\n.export-btn-wrap{position:fixed;top:14px;right:20px;z-index:9999;display:flex;align-items:center;gap:8px}\n.export-btn{display:flex;align-items:center;gap:8px;background:linear-gradient(135deg,#1a2e4a,#0f1f35);border:1px solid #2a4060;color:#7ab8ff;padding:9px 18px;border-radius:10px;cursor:pointer;font-size:13px;font-family:var(--sans);font-weight:600;white-space:nowrap;transition:all .18s;box-shadow:0 4px 20px rgba(0,0,0,.5);letter-spacing:.2px}\n.export-btn:hover{background:linear-gradient(135deg,#1e3a5f,#152840);border-color:#3b82f6;color:#93c5fd;box-shadow:0 6px 28px rgba(59,130,246,.25);transform:translateY(-1px)}\n.export-btn:active{transform:translateY(0);box-shadow:0 2px 10px rgba(59,130,246,.2)}\n.export-btn svg{flex-shrink:0;opacity:.85}\n.export-dropdown{position:fixed;top:52px;right:20px;z-index:9999;background:#0d1520;border:1px solid #1f3050;border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.7);overflow:hidden;min-width:220px;display:none;animation:dropIn .15s ease}\n.export-dropdown.open{display:block}\n@keyframes dropIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}\n.export-opt{display:flex;align-items:center;gap:10px;padding:11px 16px;color:#a8c8e8;font-size:13px;cursor:pointer;border:none;background:none;width:100%;text-align:left;font-family:var(--sans);transition:background .1s;border-bottom:1px solid #1a2840}\n.export-opt:last-child{border-bottom:none}\n.export-opt:hover{background:rgba(59,130,246,.1);color:#7ab8ff}\n.export-opt-icon{font-size:15px;width:20px;text-align:center;flex-shrink:0}\n.export-opt-desc{font-size:11px;color:#4a6a8a;margin-top:1px}\n@media print{.export-btn-wrap,.export-dropdown,.sidebar{display:none!important}.main{margin-left:0!important}}\n"

_JS = '\nfunction showSection(id, el) {\n  document.querySelectorAll(\'.section\').forEach(function(s){ s.classList.remove(\'active\'); });\n  document.querySelectorAll(\'.nav-a\').forEach(function(n){ n.classList.remove(\'active\'); });\n  var sec = document.getElementById(\'s-\' + id);\n  if (sec) sec.classList.add(\'active\');\n  if (el)  el.classList.add(\'active\');\n  if (sec) {\n    sec.querySelectorAll(\'.vs-vp\').forEach(function(vp){\n      try { vsRender(vp.id.replace(\'-vp\', \'\')); } catch(e) {}\n    });\n  }\n  if (id === \'threatmap\' && window._TM_DATA && typeof d3 !== \'undefined\') {\n    setTimeout(function() {\n      if (!_TM.initialized) { initThreatMap(); }\n      else {\n        var wrap = document.querySelector(\'.tm-wrap\');\n        if (wrap) {\n          var W = wrap.clientWidth, H = wrap.clientHeight;\n          if (Math.abs(W - _TM.W) > 20 || Math.abs(H - _TM.H) > 20) {\n            _TM.W = W; _TM.H = H;\n            _TM.svg.attr(\'viewBox\', [0, 0, W, H]);\n          }\n        }\n      }\n    }, 80);\n  }\n}\nfunction tab(btn, paneId) {\n  var cont = btn.closest(\'.section\');\n  cont.querySelectorAll(\'.tab\').forEach(function(b){ b.classList.remove(\'active\'); });\n  cont.querySelectorAll(\'.pane\').forEach(function(p){ p.classList.remove(\'active\'); });\n  btn.classList.add(\'active\');\n  var pane = document.getElementById(paneId);\n  if (pane) {\n    pane.classList.add(\'active\');\n    pane.querySelectorAll(\'.vs-vp\').forEach(function(vp){\n      try { vsRender(vp.id.replace(\'-vp\', \'\')); } catch(e) {}\n    });\n  }\n}\nvar VS_H = 34, VS_OS = 8;\nfunction vsInit(uid) {\n  var d = window._VS && window._VS[uid]; if (!d) return;\n  vsCnt(uid); vsRender(uid);\n}\nfunction vsRender(uid) {\n  var d = window._VS && window._VS[uid]; if (!d) return;\n  var c = document.getElementById(uid + \'-scroll\');\n  var vp = document.getElementById(uid + \'-vp\');\n  if (!c || !vp) return;\n  var tot = d.filtered.length;\n  vp.style.height = (tot * VS_H) + \'px\';\n  var st = c.scrollTop, vis = Math.ceil(c.clientHeight / VS_H);\n  var si = Math.max(0, Math.floor(st / VS_H) - VS_OS);\n  var ei = Math.min(tot, si + vis + VS_OS * 2);\n  vp.querySelectorAll(\'.vs-row\').forEach(function(r){ r.remove(); });\n  for (var i = si; i < ei; i++) {\n    var url = d.filtered[i], row = document.createElement(\'div\');\n    row.className = \'vs-row\'; row.style.top = (i * VS_H) + \'px\';\n    var p = parseURL(url);\n    row.innerHTML = \'<a href="\' + esc(url) + \'" target="_blank" rel="noopener"><span class="url-host">\'\n      + esc(p.host) + \'</span><span class="url-path">\' + esc(p.path)\n      + \'</span><span class="url-qs">\' + esc(p.qs) + \'</span></a>\';\n    vp.appendChild(row);\n  }\n}\nfunction vsFilter(uid) {\n  var d = window._VS && window._VS[uid]; if (!d) return;\n  var q = document.getElementById(uid + \'-q\').value.toLowerCase();\n  d.filtered = q ? d.raw.filter(function(u){ return u.toLowerCase().indexOf(q) >= 0; }) : d.raw;\n  vsCnt(uid);\n  var c = document.getElementById(uid + \'-scroll\'); if (c) c.scrollTop = 0;\n  vsRender(uid);\n}\nfunction vsCnt(uid) {\n  var d = window._VS && window._VS[uid], el = document.getElementById(uid + \'-cnt\');\n  if (el && d) el.textContent = num(d.filtered.length) + \' / \' + num(d.raw.length);\n}\nfunction vsCopy(uid) {\n  var d = window._VS && window._VS[uid];\n  if (d) navigator.clipboard.writeText(d.filtered.join(\'\\n\'))\n    .then(function(){ toast(\'Copied \' + num(d.filtered.length) + \' items\'); });\n}\nfunction vsExport(uid) {\n  var d = window._VS && window._VS[uid];\n  if (d) dl(d.filtered.join(\'\\n\'), uid + \'.txt\', \'text/plain\');\n}\nvar VT_PG = 200;\nfunction vtInit(uid) {\n  var d = window._VT && window._VT[uid]; if (!d) return;\n  d.page = 0; vtCnt(uid); vtRender(uid);\n}\nfunction vtRender(uid) {\n  var d = window._VT && window._VT[uid];\n  var tbody = document.getElementById(uid + \'-body\');\n  var more  = document.getElementById(uid + \'-more\');\n  if (!d || !tbody) return;\n  var slice = d.filtered.slice(0, (d.page + 1) * VT_PG);\n  tbody.innerHTML = slice.map(function(r){\n    return \'<tr>\' + r.map(function(c){ return \'<td title="\' + esc(String(c||\'\')) + \'">\' + esc(String(c || \'\')); }).join(\'\') + \'</tr>\';\n  }).join(\'\');\n  if (more) {\n    var s = slice.length, t = d.filtered.length;\n    more.innerHTML = s < t\n      ? \'Showing \' + num(s) + \' of \' + num(t)\n        + \' \\u00a0<button class="load-btn" onclick="vtMore(\\\'\' + uid + \'\\\')">+\' + VT_PG + \'</button>\'\n        + \'\\u00a0<button class="load-btn" onclick="vtAll(\\\'\' + uid + \'\\\')">Load all</button>\'\n      : \'All \' + num(t) + \' rows shown\';\n  }\n}\nfunction vtFilter(uid) {\n  var d = window._VT && window._VT[uid]; if (!d) return;\n  var q = document.getElementById(uid + \'-q\').value.toLowerCase();\n  d.filtered = q ? d.raw.filter(function(r){\n    return r.some(function(c){ return String(c).toLowerCase().indexOf(q) >= 0; });\n  }) : d.raw;\n  d.page = 0; vtCnt(uid); vtRender(uid);\n}\nfunction vtMore(uid){ window._VT[uid].page++; vtRender(uid); }\nfunction vtAll(uid){ window._VT[uid].page = 9999; vtRender(uid); }\nfunction vtCnt(uid) {\n  var d = window._VT && window._VT[uid], el = document.getElementById(uid + \'-cnt\');\n  if (el && d) el.textContent = num(d.filtered.length) + \' / \' + num(d.raw.length) + \' rows\';\n}\nfunction vtCopy(uid) {\n  var d = window._VT && window._VT[uid];\n  if (d) navigator.clipboard.writeText(\n    d.filtered.map(function(r){ return r.join(\'\\t\'); }).join(\'\\n\')\n  ).then(function(){ toast(\'Copied \' + num(d.filtered.length) + \' rows\'); });\n}\nfunction vtExportCSV(uid) {\n  var d = window._VT && window._VT[uid];\n  if (!d) return;\n  var hdr = (d.headers || []).join(\',\');\n  var rows = d.filtered.map(function(r){\n    return r.map(function(c){ return \'"\' + String(c).replace(/"/g,\'""\') + \'"\'; }).join(\',\');\n  });\n  dl([hdr].concat(rows).join(\'\\n\'), uid + \'.csv\', \'text/csv\');\n}\nvar AP = 150;\nvar SC_COL = {\'2\':\'#4ade80\',\'3\':\'#60a5fa\',\'4\':\'#facc15\',\'5\':\'#f87171\'};\nfunction aliveInit() { window._AP = 0; aliveCnt(); aliveRender(); }\nfunction aliveFilter() {\n  var q = document.getElementById(\'alive-q\').value.toLowerCase();\n  window._AF = q ? window._AR.filter(function(r){\n    return r.some(function(c){ return String(c).toLowerCase().indexOf(q) >= 0; });\n  }) : window._AR;\n  window._AP = 0; aliveCnt(); aliveRender();\n}\nfunction aliveRender() {\n  var data = window._AF || [], tbody = document.getElementById(\'alive-body\'), more = document.getElementById(\'alive-more\');\n  if (!tbody) return;\n  var slice = data.slice(0, (window._AP + 1) * AP);\n  tbody.innerHTML = slice.map(function(r) {\n    var url=r[0],sc=r[1],title=r[2],ip=r[3],tech=r[4],sz=r[5],srv=r[6],rt=r[7]||\'\';\n    var col = SC_COL[String(sc)[0]] || \'#6b7280\';\n    return \'<tr>\'\n      + \'<td title="\' + esc(url) + \'"><a href="\' + esc(url) + \'" target="_blank" rel="noopener" style="color:#60b0f0;font-family:var(--mono);font-size:11.5px">\' + esc(url) + \'</a></td>\'\n      + \'<td><b style="color:\' + col + \';font-family:var(--mono)">\' + esc(sc) + \'</b></td>\'\n      + \'<td style="font-family:var(--sans);color:var(--text)" title="\' + esc(title) + \'">\' + esc(title) + \'</td>\'\n      + \'<td>\' + esc(ip) + \'</td>\'\n      + \'<td style="font-size:11px;color:var(--muted)" title="\' + esc(tech) + \'">\' + esc(tech) + \'</td>\'\n      + \'<td>\' + esc(sz) + \'</td>\'\n      + \'<td style="font-size:11px;color:var(--muted)">\' + esc(srv) + \'</td>\'\n      + \'<td style="color:var(--muted);font-size:11px">\' + esc(rt) + \'</td>\'\n      + \'</tr>\';\n  }).join(\'\');\n  if (more) {\n    var s = slice.length, t = data.length;\n    more.innerHTML = s < t\n      ? \'Showing \' + num(s) + \' of \' + num(t)\n        + \' \\u00a0<button class="load-btn" onclick="window._AP++;aliveRender()">+\' + AP + \'</button>\'\n        + \'\\u00a0<button class="load-btn" onclick="window._AP=999;aliveRender()">Load all</button>\'\n      : \'All \' + num(t) + \' hosts shown\';\n  }\n}\nfunction aliveCnt() {\n  var el = document.getElementById(\'alive-cnt\');\n  if (el) el.textContent = num((window._AF||[]).length) + \' / \' + num((window._AR||[]).length) + \' hosts\';\n}\nfunction aliveCopy() {\n  var u = (window._AF||[]).map(function(r){ return r[0]; }).join(\'\\n\');\n  navigator.clipboard.writeText(u).then(function(){ toast(\'Copied \' + num((window._AF||[]).length) + \' URLs\'); });\n}\nfunction aliveCSV() {\n  var hdr = \'URL,Status,Title,IP,Tech,Size,Server,ResponseTime\';\n  var rows = (window._AF||[]).map(function(r){\n    return r.map(function(c){ return \'"\' + String(c).replace(/"/g,\'""\') + \'"\'; }).join(\',\');\n  });\n  dl([hdr].concat(rows).join(\'\\n\'), \'alive_hosts.csv\', \'text/csv\');\n}\nfunction parseURL(url) {\n  try { var u = new URL(url); return {host:u.hostname, path:u.pathname, qs:u.search?u.search.slice(0,80):\'\'}; }\n  catch(e) { return {host:\'\', path:url, qs:\'\'}; }\n}\nfunction esc(s) {\n  return String(s).replace(/&/g,\'&amp;\').replace(/</g,\'&lt;\').replace(/>/g,\'&gt;\').replace(/"/g,\'&quot;\').replace(/\'/g,\'&#39;\');\n}\nfunction num(n) { return Number(n).toLocaleString(); }\nfunction dl(content, filename, mime) {\n  var a = document.createElement(\'a\');\n  a.href = URL.createObjectURL(new Blob([content], {type:mime}));\n  a.download = filename; a.click(); URL.revokeObjectURL(a.href);\n}\nvar _tt;\nfunction toast(msg) {\n  var t = document.getElementById(\'_toast\');\n  if (!t) {\n    t = document.createElement(\'div\'); t.id = \'_toast\';\n    t.style.cssText = \'position:fixed;bottom:24px;right:24px;background:#1a2338;color:#d4dde8;\'\n      + \'padding:10px 18px;border-radius:10px;font-size:12px;border:1px solid #243044;z-index:9999;\'\n      + \'transition:opacity .3s;font-family:Inter,sans-serif;pointer-events:none;\'\n      + \'box-shadow:0 8px 32px rgba(0,0,0,.5);font-weight:500;letter-spacing:.2px\';\n    document.body.appendChild(t);\n  }\n  t.textContent = \'\\u2713 \' + msg; t.style.opacity = \'1\';\n  clearTimeout(_tt); _tt = setTimeout(function(){ t.style.opacity = \'0\'; }, 2500);\n}\ndocument.addEventListener(\'keydown\', function(e) {\n  if (e.key === \'/\' && ![\'INPUT\',\'TEXTAREA\'].includes(document.activeElement.tagName)) {\n    e.preventDefault();\n    var inp = document.querySelector(\'.section.active .vs-search\');\n    if (inp) inp.focus();\n  }\n});\n(function() {\n  function flush() {\n    (window._VSQ || []).forEach(function(uid){ try { vsInit(uid); } catch(e){} });\n    window._VSQ = [];\n    (window._VTQ || []).forEach(function(uid){ try { vtInit(uid); } catch(e){} });\n    window._VTQ = [];\n    if (window._AliveReady && window._AR) { try { aliveInit(); } catch(e){} }\n    window._AliveReady = false;\n  }\n  if (document.readyState === \'loading\') {\n    document.addEventListener(\'DOMContentLoaded\', flush, {once:true});\n  } else {\n    flush();\n  }\n})();\nvar _TM = {sim:null,zoom:null,svg:null,g:null,W:0,H:0,showLabels:true,filter:\'all\',allNodes:[],allLinks:[],initialized:false,rendering:false};\nfunction initThreatMap() {\n  var data = window._TM_DATA;\n  if (!data || typeof d3 === \'undefined\') return;\n  var svgEl = document.getElementById(\'tm-svg\');\n  var wrap  = document.querySelector(\'.tm-wrap\');\n  if (!svgEl || !wrap) return;\n  var W = wrap.clientWidth || 900, H = wrap.clientHeight || 680;\n  _TM.W = W; _TM.H = H;\n  _TM.svg = d3.select(svgEl).attr(\'viewBox\', [0, 0, W, H]);\n  _TM.allNodes = data.nodes.map(function(n){ return Object.assign({}, n); });\n  _TM.allLinks = data.links.map(function(l){ return Object.assign({}, l); });\n  _TM.initialized = true;\n  var infoEl = document.getElementById(\'tm-info\');\n  if (infoEl && data.total_subs !== undefined) infoEl.textContent = data.total_subs + \' total subs \\u00b7 \' + data.rendered + \' nodes rendered\';\n  _tmApplyFilter();\n}\nfunction _tmApplyFilter() {\n  if (!_TM.initialized) return;\n  var nodes, links;\n  var sev_order = {high:4,medium:3,low:2,info:1,none:0};\n  if (_TM.filter === \'alive\') {\n    var ids = new Set(_TM.allNodes.filter(function(n){ return n.alive || n.type===\'root\'; }).map(function(n){ return n.id; }));\n    nodes = _TM.allNodes.filter(function(n){ return ids.has(n.id); }).map(function(n){ return Object.assign({},n); });\n    links = _TM.allLinks.filter(function(l){ return ids.has(l.source) && ids.has(l.target); }).map(function(l){ return Object.assign({},l); });\n  } else if (_TM.filter === \'vuln\') {\n    var ids2 = new Set(_TM.allNodes.filter(function(n){ return n.type===\'root\' || (n.severity && sev_order[n.severity]>=3); }).map(function(n){ return n.id; }));\n    nodes = _TM.allNodes.filter(function(n){ return ids2.has(n.id); }).map(function(n){ return Object.assign({},n); });\n    links = _TM.allLinks.filter(function(l){ return ids2.has(l.source) && ids2.has(l.target); }).map(function(l){ return Object.assign({},l); });\n  } else {\n    nodes = _TM.allNodes.map(function(n){ return Object.assign({},n); });\n    links = _TM.allLinks.map(function(l){ return Object.assign({},l); });\n  }\n  renderThreatMap(nodes, links);\n}\nfunction renderThreatMap(nodes, links) {\n  if (_TM.rendering) return;\n  _TM.rendering = true;\n  if (_TM.sim) { _TM.sim.stop(); _TM.sim.on(\'tick\', null); _TM.sim = null; }\n  var svg = _TM.svg, W = _TM.W, H = _TM.H;\n  var tooltip = document.getElementById(\'tm-tooltip\');\n  svg.selectAll(\'*\').remove();\n  var g = svg.append(\'g\'); _TM.g = g;\n  var zoom = d3.zoom().scaleExtent([0.04, 5]).on(\'zoom\', function(event){ g.attr(\'transform\', event.transform); });\n  svg.on(\'.zoom\', null).call(zoom); _TM.zoom = zoom;\n  function nodeColor(d) {\n    if (d.type===\'root\') return \'#3b82f6\';\n    if (d.type===\'collapsed\') return \'#374151\';\n    if (d.type===\'group\') return ({high:\'#4c1d1d\',medium:\'#3d3000\',none:\'#1e3347\'}[d.severity]||\'#1e3347\');\n    return {high:\'#ef4444\',medium:\'#f97316\',low:\'#3b82f6\'}[d.severity] || (d.alive?\'#22c55e\':\'#334155\');\n  }\n  function nodeRadius(d) {\n    if (d.type===\'root\') return 22;\n    if (d.type===\'group\') return Math.min(18, 10 + Math.log2(d.count||1)*2);\n    if (d.type===\'collapsed\') return 10;\n    return d.alive ? 8 : 5;\n  }\n  function nodeStroke(d) {\n    return {root:\'#60a5fa\',group:\'#2d5070\',collapsed:\'#4b5563\'}[d.type] || (d.alive?\'#16a34a\':\'#1e293b\');\n  }\n  var nodeById = {};\n  nodes.forEach(function(n){ nodeById[n.id] = n; });\n  var resolvedLinks = links.filter(function(l){ return nodeById[l.source] && nodeById[l.target]; }).map(function(l){ return {source:l.source,target:l.target,type:l.type}; });\n  var defs = svg.append(\'defs\');\n  [[\'glow-b\',\'#3b82f6\'],[\'glow-r\',\'#ef4444\'],[\'glow-g\',\'#22c55e\']].forEach(function(p){\n    var f = defs.append(\'filter\').attr(\'id\',p[0]).attr(\'x\',\'-30%\').attr(\'y\',\'-30%\').attr(\'width\',\'160%\').attr(\'height\',\'160%\');\n    f.append(\'feGaussianBlur\').attr(\'stdDeviation\',\'3\').attr(\'result\',\'blur\');\n    var m = f.append(\'feMerge\'); m.append(\'feMergeNode\').attr(\'in\',\'blur\'); m.append(\'feMergeNode\').attr(\'in\',\'SourceGraphic\');\n  });\n  var link = g.append(\'g\').selectAll(\'line\').data(resolvedLinks).join(\'line\')\n    .attr(\'stroke\', function(d){ return d.type===\'group\'?\'#1e2838\':d.type===\'collapsed\'?\'#2a3040\':\'#151d28\'; })\n    .attr(\'stroke-width\', function(d){ return d.type===\'group\'?1.5:1; })\n    .attr(\'stroke-dasharray\', function(d){ return d.type===\'group\'?\'6,3\':d.type===\'collapsed\'?\'3,3\':\'\'; })\n    .attr(\'opacity\', 0.5);\n  var node = g.append(\'g\').selectAll(\'g\').data(nodes).join(\'g\')\n    .style(\'cursor\',\'pointer\')\n    .call(d3.drag()\n      .on(\'start\', function(e,d){ if(!e.active) _TM.sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })\n      .on(\'drag\',  function(e,d){ d.fx=e.x; d.fy=e.y; })\n      .on(\'end\',   function(e,d){ if(!e.active) _TM.sim.alphaTarget(0); d.fx=null; d.fy=null; })\n    );\n  node.append(\'circle\').attr(\'r\', nodeRadius).attr(\'fill\', nodeColor).attr(\'stroke\', nodeStroke)\n    .attr(\'stroke-width\', function(d){ return d.type===\'root\'?2.5:1.5; })\n    .attr(\'filter\', function(d){\n      if (d.type===\'root\') return \'url(#glow-b)\';\n      if (d.severity===\'high\'||d.severity===\'medium\') return \'url(#glow-r)\';\n      if (d.alive&&d.type===\'subdomain\') return \'url(#glow-g)\';\n      return \'\';\n    });\n  node.filter(function(d){ return d.type===\'group\' && d.vuln_count>0; }).append(\'circle\')\n    .attr(\'r\', function(d){ return nodeRadius(d)+4; }).attr(\'fill\',\'none\').attr(\'stroke\',\'#ef4444\').attr(\'stroke-width\',1.5).attr(\'stroke-dasharray\',\'4,2\').attr(\'opacity\',0.6);\n  node.filter(function(d){ return (d.type===\'group\'||d.type===\'collapsed\')&&(d.count||0)>0; }).append(\'text\')\n    .text(function(d){ return d.type===\'collapsed\'?\'+\'+d.count:d.count; })\n    .attr(\'text-anchor\',\'middle\').attr(\'dy\',\'0.35em\').attr(\'fill\',\'#d4dde8\').attr(\'font-size\',\'9px\').attr(\'font-weight\',\'700\').attr(\'font-family\',\'IBM Plex Mono,monospace\').style(\'pointer-events\',\'none\');\n  var labels = node.append(\'text\').attr(\'class\',\'tm-label\')\n    .attr(\'dy\', function(d){ return nodeRadius(d)+13; }).attr(\'text-anchor\',\'middle\')\n    .attr(\'fill\', function(d){ return {root:\'#60a5fa\',group:\'#4a7090\',collapsed:\'#4b5563\'}[d.type]||(d.alive?\'#d4dde8\':\'#374151\'); })\n    .attr(\'font-size\', function(d){ return {root:\'12px\',group:\'10px\',collapsed:\'9px\'}[d.type]||\'9px\'; })\n    .attr(\'font-family\',\'IBM Plex Mono,monospace\').attr(\'font-weight\', function(d){ return d.type===\'root\'?\'700\':\'400\'; })\n    .text(function(d){\n      if (d.type===\'root\'||d.type===\'group\'||d.type===\'collapsed\') return d.label;\n      var p=d.label.split(\'.\'); return p.length>2?p.slice(0,-2).join(\'.\'):d.label;\n    })\n    .style(\'display\', _TM.showLabels?\'\':\'none\').style(\'pointer-events\',\'none\');\n  node\n    .on(\'mouseover\', function(e,d){\n      var sc={high:\'#f87171\',medium:\'#fb923c\',low:\'#60a5fa\',info:\'#9ca3af\',none:\'#9ca3af\'};\n      var h = \'<strong>\' + esc(d.label) + \'</strong>\';\n      if (d.type===\'group\') {\n        h += \'<span class="tm-tt-badge" style="background:#0d2237;color:#60a5fa">GROUP \\u00b7 \'+d.count+\' subs</span>\';\n        if (d.vuln_count>0) h += \'<span class="tm-tt-badge" style="background:#1f0808;color:#f87171">\'+d.vuln_count+\' nikto finding\'+(d.vuln_count>1?\'s\':\'\')+\'</span>\';\n      } else if (d.type===\'collapsed\') {\n        h += \'<span class="tm-tt-badge" style="background:#1f2937;color:#6b7280">\'+d.count+\' hidden</span>\';\n      } else if (d.type!==\'root\') {\n        h += \'<span class="tm-tt-badge" style="background:\'+(d.alive?\'#052e14\':\'#111827\')+\';color:\'+(d.alive?\'#22c55e\':\'#6b7280\')+\'">\'+(d.alive?\'\\u2713 ALIVE\':\'\\u2717 DEAD\')+\'</span>\';\n        if (d.severity&&d.severity!==\'none\'&&d.severity!==\'info\') h+=\'<span class="tm-tt-badge" style="background:#1f0808;color:\'+sc[d.severity]+\'">\'+esc(d.severity.toUpperCase())+\' \\u00b7 \'+d.vuln_count+\' finding\'+(d.vuln_count>1?\'s\':\'\')+\'</span>\';\n      }\n      if (tooltip){ tooltip.innerHTML=h; tooltip.style.display=\'block\'; }\n    })\n    .on(\'mousemove\', function(e){\n      if (!tooltip) return;\n      var wr=document.querySelector(\'.tm-wrap\'), rc=wr.getBoundingClientRect();\n      var x=e.clientX-rc.left+14, y=e.clientY-rc.top+14;\n      if (x+310>wr.clientWidth) x-=320;\n      tooltip.style.left=x+\'px\'; tooltip.style.top=y+\'px\';\n    })\n    .on(\'mouseout\', function(){ if(tooltip) tooltip.style.display=\'none\'; });\n  var infoEl = document.getElementById(\'tm-info\');\n  if (infoEl) infoEl.textContent = nodes.length + \' nodes \\u00b7 \' + resolvedLinks.length + \' edges\';\n  var nodeCount = nodes.length;\n  var alphaDecay = nodeCount > 500 ? 0.06 : nodeCount > 200 ? 0.035 : 0.02;\n  var chargeStr  = function(d){ return d.type===\'root\'?-800:d.type===\'group\'?-200:-60; };\n  var sim = d3.forceSimulation(nodes).alphaDecay(alphaDecay).velocityDecay(0.4)\n    .force(\'link\', d3.forceLink(resolvedLinks).id(function(d){ return d.id; }).distance(function(d){ return d.type===\'group\'?90:50; }).strength(function(d){ return d.type===\'collapsed\'?0.3:0.7; }))\n    .force(\'charge\', d3.forceManyBody().strength(chargeStr).distanceMax(nodeCount > 300 ? 200 : 400))\n    .force(\'center\', d3.forceCenter(W/2, H/2).strength(0.08))\n    .force(\'collision\', d3.forceCollide().radius(function(d){ return nodeRadius(d)+4; }).strength(0.7));\n  _TM.sim = sim;\n  sim.on(\'tick\', function(){\n    link.attr(\'x1\',function(d){ return d.source.x; }).attr(\'y1\',function(d){ return d.source.y; }).attr(\'x2\',function(d){ return d.target.x; }).attr(\'y2\',function(d){ return d.target.y; });\n    node.attr(\'transform\', function(d){ return \'translate(\'+d.x+\',\'+d.y+\')\'; });\n  });\n  _TM.rendering = false;\n}\nfunction tmResetZoom() { if (!_TM.svg||!_TM.zoom) return; _TM.svg.transition().duration(500).call(_TM.zoom.transform, d3.zoomIdentity.translate(_TM.W/2,_TM.H/2).scale(0.7)); }\nfunction tmToggleLabels() { _TM.showLabels=!_TM.showLabels; if (_TM.g) _TM.g.selectAll(\'.tm-label\').style(\'display\',_TM.showLabels?\'\':\'none\'); }\nfunction tmFilterAlive() { _TM.filter=\'alive\'; _tmApplyFilter(); }\nfunction tmFilterVuln()  { _TM.filter=\'vuln\';  _tmApplyFilter(); }\nfunction tmFilterAll()   { _TM.filter=\'all\';   _tmApplyFilter(); }\nfunction tmSearch() {\n  var q = document.getElementById(\'tm-search\').value.toLowerCase().trim();\n  if (!_TM.g) return;\n  if (!q) { _TM.g.selectAll(\'g\').each(function(){ d3.select(this).selectAll(\'circle,text\').attr(\'opacity\',1); }); return; }\n  _TM.g.selectAll(\'g\').each(function(d){\n    if (!d) return;\n    var match = d.label && d.label.toLowerCase().indexOf(q)>=0;\n    d3.select(this).selectAll(\'circle\').attr(\'opacity\',match?1:0.06);\n    d3.select(this).selectAll(\'text\').attr(\'opacity\',match?1:0.05);\n  });\n}\n// ── Export Report ─────────────────────────────────────────────────────────────\nvar _exportMenuOpen = false;\nfunction toggleExportMenu() {\n  var dd = document.getElementById(\'export-dropdown\');\n  _exportMenuOpen = !_exportMenuOpen;\n  if (_exportMenuOpen) {\n    dd.classList.add(\'open\');\n  } else {\n    dd.classList.remove(\'open\');\n  }\n}\ndocument.addEventListener(\'click\', function(e) {\n  var btn = document.getElementById(\'export-main-btn\');\n  var dd  = document.getElementById(\'export-dropdown\');\n  if (!btn || !dd) return;\n  if (!btn.contains(e.target) && !dd.contains(e.target)) {\n    dd.classList.remove(\'open\');\n    _exportMenuOpen = false;\n  }\n});\nfunction exportFullHTML() {\n  var dd = document.getElementById(\'export-dropdown\');\n  if (dd) { dd.classList.remove(\'open\'); _exportMenuOpen = false; }\n  var wrap = document.querySelector(\'.export-btn-wrap\');\n  var dropEl = document.getElementById(\'export-dropdown\');\n  if (wrap) wrap.style.display = \'none\';\n  if (dropEl) dropEl.style.display = \'none\';\n  var html = \'<!DOCTYPE html>\\n\' + document.documentElement.outerHTML;\n  if (wrap) wrap.style.display = \'\';\n  if (dropEl) dropEl.style.display = \'\';\n  var ts = new Date().toISOString().slice(0,19).replace(/[:T]/g, \'-\');\n  var target = document.querySelector(\'.sb-target\');\n  var tname  = target ? target.textContent.trim().replace(/[^a-z0-9._-]/gi,\'_\') : \'report\';\n  var fname  = \'reconx_\' + tname + \'_\' + ts + \'.html\';\n  var blob = new Blob([html], {type: \'text/html;charset=utf-8\'});\n  var url  = URL.createObjectURL(blob);\n  var a = document.createElement(\'a\');\n  a.href = url; a.download = fname;\n  document.body.appendChild(a); a.click();\n  setTimeout(function(){ URL.revokeObjectURL(url); document.body.removeChild(a); }, 1000);\n  toast(\'\\u2193 Saved as \' + fname);\n}\nfunction printReport() {\n  var dd = document.getElementById(\'export-dropdown\');\n  if (dd) { dd.classList.remove(\'open\'); _exportMenuOpen = false; }\n  window.print();\n}\nfunction copyReportLink() {\n  var dd = document.getElementById(\'export-dropdown\');\n  if (dd) { dd.classList.remove(\'open\'); _exportMenuOpen = false; }\n  navigator.clipboard.writeText(window.location.href)\n    .then(function(){ toast(\'\\u2713 Location copied to clipboard\'); })\n    .catch(function(){ toast(\'Could not copy \\u2014 use Ctrl+S to save manually\'); });\n}\n'


# ── Builder ────────────────────────────────────────────────────────────────────
def build_report(scan_dir, target: str, summary: dict = None) -> Path:
    scan_dir = Path(scan_dir)
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M")

    recon    = _parse_recon(scan_dir)
    subs     = _parse_subdomains(scan_dir)
    alive    = _parse_alive(scan_dir)
    urls     = _parse_url_categories(scan_dir)
    smry_json= _parse_summary_json(scan_dir)

    def _nav(icon, label, sid, count=None, color=None):
        if count is not None:
            cnt_cls = f" cnt-{color}" if color else ""
            cnt_html = (f'<span class="nav-cnt{cnt_cls}">{count:,}</span>'
                        if isinstance(count, int) else
                        f'<span class="nav-cnt{cnt_cls}">{count}</span>')
        else:
            cnt_html = ""
        return (f'<a class="nav-a" data-sid="{_e(sid)}" onclick="showSection(\'{_e(sid)}\',this)">'
                f'<span class="nav-ico">{icon}</span>{_e(label)}{cnt_html}</a>')

    sidebar = f'''<div class="sb-brand">
  <div class="sb-logo">
    <div class="sb-logo-mark">⚡</div>
    <h1>Recon<span>X</span></h1>
  </div>
  <div class="sb-target">{_e(target)}</div>
  <div class="sb-ts">📅 {_e(ts)}</div>
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
  {_nav("⚙️","Parameters","params")}
  {_nav("📂","Categorised","categorised")}
</div>
<hr class="nav-hr">
<div class="sb-hint">
  <kbd>/</kbd> to search &nbsp;·&nbsp; Virtual scroll<br>
  Pure Recon Edition v7.0
</div>'''

    sections = "".join([
        _section_overview(target, ts, recon, subs, alive, urls, smry_json),
        _section_threatmap(target, subs, alive),
        _section_recon(recon),
        _section_subdomains(subs),
        _section_alive(alive),
        _section_urls(urls),
        _section_params(urls),
        _section_categorised(urls),
    ])

    # ── Export Button HTML (fixed top-right) ──────────────────────────────────
    export_html = '''<!-- Export Button (fixed top-right) -->
<div class="export-btn-wrap">
  <button class="export-btn" onclick="toggleExportMenu()" id="export-main-btn">
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
    Export Report
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><polyline points="6 9 12 15 18 9"/></svg>
  </button>
</div>
<div class="export-dropdown" id="export-dropdown">
  <button class="export-opt" onclick="exportFullHTML()">
    <span class="export-opt-icon">📄</span>
    <div>
      <div>Save as HTML</div>
      <div class="export-opt-desc">Full interactive report &middot; offline</div>
    </div>
  </button>
  <button class="export-opt" onclick="printReport()">
    <span class="export-opt-icon">🖨️</span>
    <div>
      <div>Print / Save as PDF</div>
      <div class="export-opt-desc">Browser print dialog</div>
    </div>
  </button>
  <button class="export-opt" onclick="copyReportLink()">
    <span class="export-opt-icon">🔗</span>
    <div>
      <div>Copy file path</div>
      <div class="export-opt-desc">Share local file location</div>
    </div>
  </button>
</div>'''

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
  ReconX Pure Recon Edition v7.0 &nbsp;&middot;&nbsp; {_e(target)} &nbsp;&middot;&nbsp; {_e(ts)}<br>
  Use only on authorized targets under a valid bug bounty program.
</div>
</main>
{export_html}
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
