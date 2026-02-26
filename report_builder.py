#!/usr/bin/env python3
"""
ReconX Report Builder v5.0
Professional dark-theme HTML report with:
  - Virtual scroll for large URL lists (RAM-safe rendering)
  - Tabbed interface per section
  - Nuclei findings table with severity badges
  - XSS findings from dalfox standard output
  - Alive hosts table with status/tech/IP
  - Clean snippet-based approach (no heavy frameworks)
"""

import json, re, html
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs


# ── File helpers ──────────────────────────────────────────────────────────────
def _read(p) -> str:
    try:
        return Path(p).read_text(errors="ignore") if p and Path(p).exists() else ""
    except:
        return ""

def _lines(p) -> list:
    return [l.strip() for l in _read(p).splitlines() if l.strip()]

def _json_lines(p) -> list:
    """Parse newline-delimited JSON or a JSON array file. Always returns list of dicts."""
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
    return html.escape(str(s) if s is not None else "")


# ── Data parsers ──────────────────────────────────────────────────────────────
def _parse_recon(d: Path) -> dict:
    return {
        "whois":     _read(d / "01_recon" / "whois.txt"),
        "nmap":      _read(d / "01_recon" / "nmap.txt"),
        "whatweb":   _read(d / "01_recon" / "whatweb.txt"),
        "wafw00f":   _read(d / "01_recon" / "wafw00f.txt"),
        "harvester": _read(d / "01_recon" / "theharvester.xml") or _read(d / "01_recon" / "theharvester.json"),
        "shodan":    _read(d / "01_recon" / "shodan.txt"),
    }

def _clean_subdomain(line: str) -> str:
    """Strip ANSI escape codes, IP/record suffixes, return only the hostname."""
    # Remove real ESC sequences e.g. \x1b[32m
    line = re.sub(r'\x1b\[[0-9;]*m', '', line)
    # Remove literal bracket variants e.g. [[32m or [0m
    line = re.sub(r'\[\[?[0-9;]*m\]?', '', line)
    # Keep only first token (hostname), discard IP / record type / etc.
    parts = line.split()
    line = parts[0] if parts else ""
    # Validate: must be a plausible hostname
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', line):
        return ""
    return line.lower()

def _parse_subdomains(d: Path) -> dict:
    tools = {}
    all_s = set()
    sd    = d / "02_subdomains"
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
    hd    = d / "03_alive" / "hosts_detail.json"
    if hd.exists():
        try:
            data = json.loads(hd.read_text(errors="ignore"))
            if isinstance(data, list):
                return data
        except:
            pass
    for line in _lines(d / "checkpoints" / "stage3_alive.txt"):
        hosts.append({"url": line, "status": "", "title": "", "ip": "", "tech": "", "size": "", "server": ""})
    return hosts

def _parse_url_categories(d: Path) -> dict:
    cats = {}
    for name in ["params", "reflection", "forms", "admin", "login", "api", "sensitive", "other"]:
        cats[name] = _lines(d / "05_categorized" / f"{name}.txt")
    cats["_all"]       = _lines(d / "checkpoints" / "stage4_urls.txt")
    cats["_gau"]       = _lines(d / "04_urls" / "gau.txt")
    cats["_wayback"]   = _lines(d / "04_urls" / "waybackurls.txt")
    cats["_katana"]    = _lines(d / "04_urls" / "katana.txt")
    cats["_hakrawler"] = _lines(d / "04_urls" / "hakrawler_clean.txt") or _lines(d / "04_urls" / "hakrawler.txt")
    cats["_linkfinder"] = _lines(d / "04_urls" / "linkfinder.txt")
    cats["_priority"]  = _lines(d / "05_categorized" / "reflection_priority.txt")
    return cats

def _parse_nuclei(d: Path) -> dict:
    results = []
    nd = d / "06_nuclei"

    if nd.exists():
        for f in nd.glob("*.json"):
            for rec in _json_lines(f):
                if not isinstance(rec, dict):
                    continue
                info = rec.get("info", {}) or {}
                results.append({
                    "severity": (info.get("severity") or "info").lower(),
                    "name":     info.get("name") or rec.get("template-id", ""),
                    "template": rec.get("template-id", ""),
                    "host":     rec.get("host", ""),
                    "url":      rec.get("matched-at", ""),
                    "tags":     ", ".join(info.get("tags", [])[:5]),
                    "raw":      "",
                })

    if not results:
        for f in (nd.glob("*.txt") if nd.exists() else []):
            for line in _lines(f):
                sm = re.search(r'\[(critical|high|medium|low|info)\]', line, re.I)
                sev = sm.group(1).lower() if sm else "info"
                um = re.search(r'(https?://\S+)', line)
                tm = re.search(r'\[([a-z0-9\-]+:[a-z0-9\-]+)\]', line, re.I)
                results.append({
                    "severity": sev,
                    "name":     (tm.group(1) if tm else line[:80]),
                    "template": tm.group(1) if tm else "",
                    "host":     "",
                    "url":      um.group(1) if um else "",
                    "tags":     "",
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

def _parse_xss(d: Path) -> dict:
    xd = d / "07_xss"
    return {
        "all": _lines(xd / "dalfox_all.txt") if xd.exists() else [],
        "r1":  _lines(xd / "dalfox_r1.txt")  if xd.exists() else [],
        "r2":  _lines(xd / "dalfox_r2.txt")  if xd.exists() else [],
        "r3":  _lines(xd / "dalfox_r3.txt")  if xd.exists() else [],
    }


# ── HTML components ───────────────────────────────────────────────────────────
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
            f'<div class="stat-lbl">{label}</div>'
            f'</div>')

def _empty(msg: str = "No data recorded") -> str:
    return f'<div class="empty-state">📭 {_e(msg)}</div>'

def _code_block(text: str, max_lines: int = 400) -> str:
    if not text.strip():
        return _empty()
    lines = text.splitlines()
    shown = "\n".join(lines[:max_lines])
    extra = f"\n\n... {len(lines) - max_lines:,} more lines in output file" if len(lines) > max_lines else ""
    return f'<pre class="code-block">{_e(shown)}{_e(extra)}</pre>'

def _vscroll(data: list, uid: str, kind: str = "URL") -> str:
    safe = json.dumps(data)
    return f'''<div class="vs-wrap">
  <div class="vs-toolbar">
    <span class="vs-counter" id="{uid}-cnt"></span>
    <input class="vs-search" id="{uid}-q" placeholder="Filter {_e(kind)}s..." oninput="vsFilter('{uid}')">
    <button class="btn-sm" onclick="vsCopy('{uid}')">Copy all</button>
    <button class="btn-sm" onclick="vsExport('{uid}')">Export .txt</button>
  </div>
  <div class="vs-scroll" id="{uid}-scroll" onscroll="vsRender('{uid}')">
    <div class="vs-vp" id="{uid}-vp"></div>
  </div>
</div>
<script>(function(){{
  var R=window._VS=window._VS||{{}};
  R['{uid}']={{raw:{safe},filtered:{safe}}};
  (window._VSQ=window._VSQ||[]).push('{uid}');
}})();</script>'''

def _vtable(headers: list, rows: list, uid: str) -> str:
    if not rows:
        return _empty()
    safe = json.dumps(rows)
    hdr  = "".join(f"<th>{_e(h)}</th>" for h in headers)
    return f'''<div class="vt-wrap">
  <div class="vs-toolbar">
    <span class="vs-counter" id="{uid}-cnt"></span>
    <input class="vs-search" id="{uid}-q" placeholder="Filter..." oninput="vtFilter('{uid}')">
    <button class="btn-sm" onclick="vtCopy('{uid}')">Copy</button>
  </div>
  <div class="tbl-scroll">
    <table><thead><tr>{hdr}</tr></thead><tbody id="{uid}-body"></tbody></table>
    <div class="vt-more" id="{uid}-more"></div>
  </div>
</div>
<script>(function(){{
  var R=window._VT=window._VT||{{}};
  R['{uid}']={{raw:{safe},filtered:{safe},page:0}};
  (window._VTQ=window._VTQ||[]).push('{uid}');
}})();</script>'''

def _tabs(items: list, prefix: str) -> str:
    if not items:
        return _empty()
    tabs  = []
    panes = []
    for i, (tid, label, content) in enumerate(items):
        active = "active" if i == 0 else ""
        tabs.append(
            f'<button class="tab {active}" onclick="tab(this,\'{prefix}-{tid}\')">{label}</button>'
        )
        panes.append(
            f'<div class="pane {active}" id="{prefix}-{tid}">{content}</div>'
        )
    return (f'<div class="tab-row">{"".join(tabs)}</div>'
            f'<div class="panes">{"".join(panes)}</div>')


# ── Section builders ──────────────────────────────────────────────────────────
def _section_overview(target, ts, recon, subs, alive, urls, nuclei, xss, summary):
    sc_n    = len(subs["all"])
    alive_n = len(alive)
    url_n   = len(urls.get("_all", []))
    par_n   = len(urls.get("params", []))
    sens_n  = len(urls.get("sensitive", []))
    refl_n  = len(urls.get("reflection", []))
    nuc_n   = len(nuclei["all"])
    xss_n   = len(xss["all"])
    by_sev  = nuclei["by_severity"]

    stats_html = "".join([
        _stat(sc_n,   "Subdomains",   "green",  "🌐"),
        _stat(alive_n, "Alive Hosts",  "blue",   "💻"),
        _stat(url_n,  "URLs Found",   "purple", "🔗"),
        _stat(par_n,  "Param URLs",   "orange", "🧩"),
        _stat(refl_n, "Reflection",   "yellow", "🪞"),
        _stat(sens_n, "Sensitive",    "red",    "⚠️"),
        _stat(nuc_n,  "Nuclei Hits",  "red",    "🎯"),
        _stat(len(by_sev.get("critical", [])) + len(by_sev.get("high", [])),
              "Crit+High",    "red",    "🔴"),
        _stat(xss_n,  "XSS Findings", "orange", "💉"),
    ])

    # ── Pipeline timeline  ── FIX: emoji icons restored ──
    stages = [
        ("Recon",      bool(recon["whois"] or recon["nmap"]), "🔍"),
        ("Subdomains", bool(subs["all"]),                     "🌐"),
        ("Alive",      bool(alive),                           "💻"),
        ("URLs",       bool(url_n),                           "🔗"),
        ("Categorise", bool(par_n or refl_n),                 "📂"),
        ("Nuclei",     bool(nuc_n),                           "🎯"),
        ("XSS",        bool(xss_n),                           "💉"),
    ]
    tl = '<div class="timeline">'
    for lbl, done, icon in stages:
        cls = "tl-done" if done else "tl-skip"
        tl += (f'<div class="tl-step {cls}">'
               f'<div class="tl-dot">{icon}</div>'
               f'<div class="tl-lbl">{lbl}</div>'
               f'</div>')
    tl += "</div>"

    # Nuclei severity bar
    total_n = max(len(nuclei["all"]), 1)
    sev_bar = '<div class="sev-bar">'
    for sev, col in [("critical", "#ff6b6b"), ("high", "#ffa94d"),
                     ("medium", "#ffd43b"), ("low", "#74c0fc"), ("info", "#868e96")]:
        c = len(by_sev.get(sev, []))
        if c:
            sev_bar += (f'<div style="flex:{c};background:{col};min-width:3px;'
                        f'border-radius:2px" title="{sev}: {c}"></div>')
    sev_bar += "</div>"
    sev_leg = '<div class="sev-legend">'
    for sev, col in [("Critical", "#ff6b6b"), ("High", "#ffa94d"),
                     ("Medium", "#ffd43b"), ("Low", "#74c0fc"), ("Info", "#868e96")]:
        c = len(by_sev.get(sev.lower(), []))
        sev_leg += (f'<span class="sev-item">'
                    f'<span style="background:{col};width:8px;height:8px;border-radius:50%;'
                    f'display:inline-block;margin-right:5px"></span>'
                    f'{sev}: <b>{c}</b></span>')
    sev_leg += "</div>"

    return f'''
<div id="s-overview" class="section active">
  <div class="sec-hdr"><h2>Dashboard</h2><p class="sec-sub">Target: <code>{_e(target)}</code> · {_e(ts)}</p></div>
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
</div>'''

def _section_recon(recon):
    items = [
        ("whois",   "WHOIS",     recon["whois"]),
        ("nmap",    "Nmap",      recon["nmap"]),
        ("whatweb", "WhatWeb",   recon["whatweb"]),
        ("waf",     "WAF",       recon["wafw00f"]),
        ("harvest", "Harvester", recon["harvester"]),
        ("shodan",  "Shodan",    recon["shodan"]),
    ]
    tab_items = [(tid, f"{lbl} ({len(c.splitlines())} ln)" if c.strip() else lbl, _code_block(c))
                 for tid, lbl, c in items if c.strip()]
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

    rows = [
        [h.get("url",""), str(h.get("status","")), (h.get("title","") or "")[:60],
         (h.get("ip","") or "")[:20], (h.get("tech","") or "")[:80],
         str(h.get("size","") or ""), (h.get("server","") or "")[:40]]
        for h in alive
    ]
    safe = json.dumps(rows)

    return f'''<div id="s-alive" class="section">
  <div class="sec-hdr"><h2>💻 Alive Hosts</h2>
    <p class="sec-sub">{len(alive):,} responsive hosts validated by httpx</p></div>
  <div class="vt-wrap">
    <div class="vs-toolbar">
      <span class="vs-counter" id="alive-cnt"></span>
      <input class="vs-search" id="alive-q" placeholder="Filter hosts..." oninput="aliveFilter()">
      <button class="btn-sm" onclick="aliveCopy()">Copy URLs</button>
      <button class="btn-sm" onclick="aliveCSV()">Export CSV</button>
    </div>
    <div class="tbl-scroll">
      <table><thead><tr><th>URL</th><th>Status</th><th>Title</th>
        <th>IP</th><th>Tech</th><th>Size</th><th>Server</th></tr></thead>
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
            f'<p class="sec-sub">{len(all_u):,} unique URLs — full list, no truncation</p></div>'
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

def _section_nuclei(nuclei):
    all_r  = nuclei["all"]
    by_sev = nuclei["by_severity"]

    def _rows(lst):
        return [[r.get("severity","info").upper(), r.get("name","")[:80] or r.get("raw","")[:80],
                 r.get("url","") or r.get("host",""), r.get("template","")[:60], r.get("tags","")[:60]]
                for r in lst]

    tab_items = [("all", f"All ({len(all_r)})", _vtable(
        ["Severity", "Finding", "URL/Host", "Template", "Tags"],
        _rows(all_r), "vt-nuc-all"
    ))]
    for sev, col in [("critical","red"),("high","orange"),("medium","yellow"),("low","blue"),("info","gray")]:
        lst = by_sev.get(sev, [])
        if not lst:
            continue
        tab_items.append((sev, f"{_badge(sev.upper(), col)} {len(lst)}",
                          _vtable(["Finding","URL/Host","Template","Tags"],
                                  [[r.get("name","")[:80] or r.get("raw","")[:80],
                                    r.get("url","") or r.get("host",""),
                                    r.get("template","")[:60], r.get("tags","")[:60]]
                                   for r in lst],
                                  f"vt-nuc-{sev}")))

    n_crit = len(by_sev.get("critical", []))
    n_high = len(by_sev.get("high", []))
    alert  = (f'<div class="alert-box alert-red">🔴 {n_crit} Critical and {n_high} High findings — '
              f'verify and report immediately!</div>' if n_crit or n_high else "")

    body = _tabs(tab_items, "nuc")
    return (f'<div id="s-nuclei" class="section">'
            f'<div class="sec-hdr"><h2>🎯 Nuclei Findings</h2>'
            f'<p class="sec-sub">{len(all_r):,} vulnerabilities detected</p></div>'
            f'{alert}{body}</div>')

def _section_xss(xss):
    all_x = xss["all"]
    r1    = xss["r1"]
    r2    = xss["r2"]
    r3    = xss["r3"]
    total = len(all_x)

    alert = (f'<div class="alert-box alert-red">🔴 {total} potential XSS finding{"s" if total!=1 else ""} '
             f'— verify manually before reporting</div>' if total
             else '<div class="alert-box alert-blue">ℹ️ No XSS findings confirmed</div>')

    tab_items = [
        ("all", f"All ({total})",        _vscroll(all_x, "vs-xss-all")),
        ("r1",  f"Standard ({len(r1)})", _vscroll(r1, "vs-xss-r1")),
        ("r2",  f"DOM XSS ({len(r2)})",  _vscroll(r2, "vs-xss-r2")),
        ("r3",  f"Redirect ({len(r3)})", _vscroll(r3, "vs-xss-r3")),
    ]
    body = _tabs(tab_items, "xss")
    return (f'<div id="s-xss" class="section">'
            f'<div class="sec-hdr"><h2>💉 XSS Testing</h2>'
            f'<p class="sec-sub">Dalfox pipe — {total} findings across 3 rounds</p></div>'
            f'{alert}{body}</div>')


def _section_threatmap(target: str, subs: dict, alive: list, nuclei: dict, xss: dict) -> str:
    """Interactive D3.js force-directed threat map — drag, zoom, hover."""
    from urllib.parse import urlparse as _up

    all_subs  = subs.get("all", [])
    alive_urls = [h.get("url", "") for h in alive if h.get("url")]
    alive_set  = set()
    for u in alive_urls:
        try: alive_set.add(_up(u).hostname or "")
        except: pass

    # Nuclei findings per host
    vuln_map: dict = {}
    for r in nuclei.get("all", []):
        h = r.get("host") or ""
        try: h = _up(h).hostname or h
        except: pass
        if h:
            vuln_map.setdefault(h, {"severity": "info", "count": 0})
            vuln_map[h]["count"] += 1
            sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
            if sev_order.get(r.get("severity","info"), 1) > sev_order.get(vuln_map[h]["severity"], 1):
                vuln_map[h]["severity"] = r.get("severity", "info")

    # XSS per host
    xss_set: set = set()
    for u in xss.get("all", []):
        try: xss_set.add(_up(u).hostname or "")
        except: pass

    # Build graph nodes/links
    nodes = [{"id": target, "type": "root", "label": target,
               "alive": True, "severity": "none", "vuln_count": 0, "xss": False}]
    links = []

    # Group by second-level (one level below root)
    import re as _re
    esc_target = _re.escape(target)
    group_map: dict = {}
    singletons: list = []

    for s in all_subs:
        if s == target:
            continue
        # strip root suffix
        suffix = "." + target
        local  = s[:-len(suffix)] if s.endswith(suffix) else s
        parts  = local.split(".")
        if len(parts) >= 2:
            grp = parts[-1]  # e.g. "api" from "v1.api.example.com"
            group_map.setdefault(grp, []).append(s)
        else:
            singletons.append(s)

    # Add singleton subdomains directly
    for s in singletons:
        nodes.append({
            "id": s, "type": "subdomain",
            "label": s,
            "alive": s in alive_set,
            "severity": vuln_map.get(s, {}).get("severity", "none"),
            "vuln_count": vuln_map.get(s, {}).get("count", 0),
            "xss": s in xss_set,
        })
        links.append({"source": target, "target": s, "type": "sub"})

    # Add group nodes + their children
    for grp, members in group_map.items():
        if len(members) == 1:
            s = members[0]
            nodes.append({
                "id": s, "type": "subdomain",
                "label": s,
                "alive": s in alive_set,
                "severity": vuln_map.get(s, {}).get("severity", "none"),
                "vuln_count": vuln_map.get(s, {}).get("count", 0),
                "xss": s in xss_set,
            })
            links.append({"source": target, "target": s, "type": "sub"})
        else:
            grp_id = f"_grp_{grp}"
            grp_alive = any(m in alive_set for m in members)
            nodes.append({"id": grp_id, "type": "group",
                          "label": f"*.{grp}.{target}", "count": len(members),
                          "alive": grp_alive, "severity": "none", "vuln_count": 0, "xss": False})
            links.append({"source": target, "target": grp_id, "type": "group"})
            for s in members:
                nodes.append({
                    "id": s, "type": "subdomain",
                    "label": s,
                    "alive": s in alive_set,
                    "severity": vuln_map.get(s, {}).get("severity", "none"),
                    "vuln_count": vuln_map.get(s, {}).get("count", 0),
                    "xss": s in xss_set,
                })
                links.append({"source": grp_id, "target": s, "type": "sub"})

    graph_json = json.dumps({"nodes": nodes, "links": links})
    total_subs  = len(all_subs)
    alive_count = len(alive_set)

    return f'''<div id="s-threatmap" class="section">
  <div class="sec-hdr">
    <h2>🗺️ Threat Map</h2>
    <p class="sec-sub">{total_subs:,} subdomains · {alive_count:,} alive · drag to move · scroll to zoom</p>
  </div>
  <div class="tm-legend">
    <span class="tm-leg-item"><span class="tm-dot" style="background:#4fa8e8"></span>Root</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#3d5a72"></span>Group</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#34c759"></span>Alive</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#6e8098"></span>Dead</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#ff453a"></span>Critical/High Vuln</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#ffa94d"></span>Medium Vuln</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#ff6b6b;border:2px solid #fff"></span>XSS</span>
  </div>
  <div class="tm-toolbar">
    <button class="btn-sm" onclick="tmResetZoom()">⊙ Reset Zoom</button>
    <button class="btn-sm" onclick="tmToggleLabels()">🏷 Toggle Labels</button>
    <button class="btn-sm" onclick="tmFilterAlive()">💚 Alive Only</button>
    <button class="btn-sm" onclick="tmFilterAll()">🌐 Show All</button>
    <input id="tm-search" class="vs-search" style="max-width:220px" placeholder="Search node..." oninput="tmSearch()">
    <span id="tm-info" style="font-size:12px;color:var(--mu);margin-left:auto"></span>
  </div>
  <div class="tm-wrap">
    <svg id="tm-svg"></svg>
    <div id="tm-tooltip" class="tm-tooltip"></div>
  </div>
  <script>
  (function(){{
    window._TM_DATA = {graph_json};
    window._TM_SHOW_LABELS = true;
    window._TM_FILTER = 'all';
    if (document.readyState === 'loading') {{
      document.addEventListener('DOMContentLoaded', initThreatMap, {{once:true}});
    }} else {{
      setTimeout(initThreatMap, 50);
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

/* ── Sidebar ──────────────────────────────────────────────── */
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

/* ── Main ─────────────────────────────────────────────────── */
.main{margin-left:var(--sw);flex:1;padding:28px 36px 60px;max-width:1500px}
.section{display:none}.section.active{display:block}
.sec-hdr{margin-bottom:22px}
.sec-hdr h2{font-size:21px;font-weight:800;color:var(--ac);letter-spacing:-.4px}
.sec-sub{color:var(--mu);font-size:12px;margin-top:4px}

/* ── Stat Cards ───────────────────────────────────────────── */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(115px,1fr));gap:12px}
.stat-card{background:var(--s1);border:1px solid var(--bd);border-radius:12px;
           padding:18px 12px;text-align:center;
           transition:transform .15s,border-color .15s;cursor:default}
.stat-card:hover{transform:translateY(-3px);border-color:var(--bd2)}
.stat-icon{font-size:24px;margin-bottom:8px}
.stat-val{font-size:26px;font-weight:800;line-height:1;font-family:var(--mono)}
.stat-lbl{font-size:10px;color:var(--mu);margin-top:5px;
          text-transform:uppercase;letter-spacing:.8px}

/* ── Panels ───────────────────────────────────────────────── */
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.panel{background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:18px 20px}
.panel h3{font-size:12px;font-weight:700;color:var(--mu);text-transform:uppercase;
          letter-spacing:.8px;margin-bottom:14px}
.mini-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:14px}
.mini-num{background:var(--s2);border:1px solid var(--bd);border-radius:8px;
          padding:10px 14px;display:flex;flex-direction:column;align-items:center;gap:2px;
          font-size:20px;font-weight:800;font-family:var(--mono)}
.mini-num span{font-size:10px;color:var(--mu);font-weight:400;font-family:var(--sans)}

/* ── Timeline ─────────────────────────────────────────────── */
.timeline{display:flex;gap:0;overflow-x:auto;padding-bottom:2px}
.tl-step{display:flex;flex-direction:column;align-items:center;
         min-width:70px;position:relative;flex:1}
.tl-step:not(:last-child)::after{content:'';position:absolute;top:20px;
  left:56%;width:88%;height:2px;background:var(--bd2)}
.tl-step.tl-done:not(:last-child)::after{background:var(--green)}
.tl-dot{width:40px;height:40px;border-radius:50%;display:flex;align-items:center;
        justify-content:center;font-size:18px;background:var(--s2);
        border:2px solid var(--bd2);position:relative;z-index:1}
.tl-step.tl-done .tl-dot{background:rgba(52,199,89,.15);border-color:var(--green)}
.tl-step.tl-skip .tl-dot{opacity:.35;filter:grayscale(1)}
.tl-lbl{font-size:10px;color:var(--mu);margin-top:6px;text-align:center}
.tl-step.tl-done .tl-lbl{color:var(--tx)}

/* ── Severity Bar ─────────────────────────────────────────── */
.sev-bar{display:flex;gap:1px;height:8px;border-radius:8px;overflow:hidden;
         background:var(--s2);margin-bottom:12px}
.sev-legend{display:flex;gap:14px;flex-wrap:wrap}
.sev-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--mu)}

/* ── Tabs ─────────────────────────────────────────────────── */
.tab-row{display:flex;gap:2px;border-bottom:1px solid var(--bd);
         margin-bottom:16px;flex-wrap:wrap}
.tab{background:none;border:none;color:var(--mu);padding:9px 14px;cursor:pointer;
     font-size:12px;font-family:var(--sans);font-weight:500;
     border-bottom:2px solid transparent;margin-bottom:-1px;
     transition:all .12s;white-space:nowrap}
.tab:hover{color:var(--tx)}.tab.active{color:var(--ac);border-bottom-color:var(--ac)}
.panes .pane{display:none}.panes .pane.active{display:block}

/* ── Code block ───────────────────────────────────────────── */
.code-block{background:var(--s2);border:1px solid var(--bd);border-radius:8px;
            padding:16px;font-family:var(--mono);font-size:12px;line-height:1.65;
            overflow:auto;white-space:pre-wrap;word-break:break-all;
            max-height:550px;color:#b0bec5}
.code-block::-webkit-scrollbar{width:6px;height:6px}
.code-block::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:3px}

/* ── Virtual Scroll ───────────────────────────────────────── */
.vs-wrap,.vt-wrap{position:relative}
.vs-toolbar{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap}
.vs-counter{font-family:var(--mono);font-size:12px;color:var(--mu);
            white-space:nowrap;min-width:80px}
.vs-search{background:var(--s2);border:1px solid var(--bd);color:var(--tx);
           padding:8px 13px;border-radius:8px;font-size:13px;flex:1;
           min-width:200px;outline:none;font-family:var(--sans);transition:border-color .12s}
.vs-search:focus{border-color:var(--ac)}
.btn-sm{background:var(--s2);border:1px solid var(--bd2);color:var(--mu);
        padding:7px 14px;border-radius:8px;cursor:pointer;font-size:12px;
        font-family:var(--sans);white-space:nowrap;transition:all .12s}
.btn-sm:hover{color:var(--ac);border-color:var(--ac)}
.vs-scroll{height:520px;overflow-y:auto;background:var(--s2);
           border:1px solid var(--bd);border-radius:8px;position:relative}
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

/* ── Table ────────────────────────────────────────────────── */
.tbl-scroll{overflow-x:auto;border:1px solid var(--bd);border-radius:8px}
.tbl-scroll::-webkit-scrollbar{height:6px}
.tbl-scroll::-webkit-scrollbar-thumb{background:var(--bd2)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--s2);color:var(--mu);padding:10px 14px;text-align:left;
   font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;
   white-space:nowrap;position:sticky;top:0;z-index:1}
td{padding:8px 14px;border-bottom:1px solid var(--bd);vertical-align:middle;
   max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
   font-family:var(--mono);font-size:12px}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(79,168,232,.03)}
.vt-more{padding:10px 14px;font-size:12px;color:var(--mu);background:var(--s2);
         border-top:1px solid var(--bd);display:flex;align-items:center;gap:10px}
.load-btn{background:none;border:1px solid var(--bd2);color:var(--ac);
          padding:4px 14px;border-radius:20px;cursor:pointer;font-size:12px;
          font-family:var(--sans);transition:all .12s}
.load-btn:hover{background:rgba(79,168,232,.1)}

/* ── Misc ─────────────────────────────────────────────────── */
.alert-box{border-radius:8px;padding:12px 16px;margin-bottom:16px;
           font-size:13px;font-weight:500;border:1px solid}
.alert-red{background:rgba(255,69,58,.08);border-color:rgba(255,69,58,.25);color:var(--red)}
.alert-blue{background:rgba(79,168,232,.07);border-color:rgba(79,168,232,.2);color:var(--ac)}
.cat-desc{color:var(--mu);font-size:12px;margin-bottom:12px;padding:8px 12px;
          background:var(--s2);border-radius:6px;border-left:3px solid var(--bd2)}
.empty-state{color:var(--mu);font-style:italic;padding:32px;text-align:center;
             background:var(--s2);border-radius:8px;border:1px dashed var(--bd)}
code{font-family:var(--mono);font-size:12px;color:var(--ac)}
.footer{margin-top:48px;padding-top:16px;border-top:1px solid var(--bd);
        color:#3a4d60;font-size:11px}

@media(max-width:900px){
  .sidebar{display:none}.main{margin-left:0;padding:16px}
  .two-col{grid-template-columns:1fr}
}

/* ── Threat Map ───────────────────────────────────────────── */
.tm-wrap{position:relative;background:var(--s1);border:1px solid var(--bd);
         border-radius:12px;overflow:hidden;height:680px;margin-top:12px}
#tm-svg{width:100%;height:100%;cursor:grab}
#tm-svg:active{cursor:grabbing}
.tm-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.tm-legend{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;
           padding:10px 14px;background:var(--s2);border-radius:8px;
           border:1px solid var(--bd)}
.tm-leg-item{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--mu)}
.tm-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.tm-tooltip{position:absolute;pointer-events:none;background:rgba(13,17,23,.97);
            border:1px solid var(--bd2);border-radius:8px;padding:10px 14px;
            font-size:12px;color:var(--tx);max-width:280px;display:none;
            z-index:50;box-shadow:0 8px 32px rgba(0,0,0,.6);line-height:1.7}
.tm-tooltip strong{color:var(--ac);font-family:var(--mono);font-size:11px;
                   word-break:break-all;display:block;margin-bottom:4px}
.tm-tt-badge{display:inline-block;padding:1px 8px;border-radius:20px;
             font-size:10px;font-weight:700;margin:1px 2px}
"""

# ── JS ────────────────────────────────────────────────────────────────────────
_JS = r"""
// Navigation
function showSection(id, el) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-a').forEach(n => n.classList.remove('active'));
  var sec = document.getElementById('s-' + id);
  if (sec) sec.classList.add('active');
  if (el) el.classList.add('active');
  sec && sec.querySelectorAll('.vs-vp').forEach(function(vp) {
    try { vsRender(vp.id.replace('-vp', '')); } catch(e) {}
  });
}
// Tabs
function tab(btn, paneId) {
  var cont = btn.closest('.section');
  cont.querySelectorAll('.tab').forEach(function(b){ b.classList.remove('active'); });
  cont.querySelectorAll('.pane').forEach(function(p){ p.classList.remove('active'); });
  btn.classList.add('active');
  var pane = document.getElementById(paneId);
  if (pane) {
    pane.classList.add('active');
    pane.querySelectorAll('.vs-vp').forEach(function(vp) {
      try { vsRender(vp.id.replace('-vp', '')); } catch(e) {}
    });
  }
}
// Virtual scroll
var VS_H = 34, VS_OS = 8;
function vsInit(uid) {
  var d = window._VS && window._VS[uid]; if (!d) return;
  vsCnt(uid);
  var c = document.getElementById(uid + '-scroll'); if (!c) return;
  vsRender(uid);
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
  if (d) navigator.clipboard.writeText(d.filtered.join('\n')).then(function(){ toast('Copied ' + num(d.filtered.length) + ' items'); });
}
function vsExport(uid) {
  var d = window._VS && window._VS[uid];
  if (d) dl(d.filtered.join('\n'), uid + '.txt', 'text/plain');
}
// Virtual table
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
    return '<tr>' + r.map(function(c){ return '<td>' + esc(String(c || '')); }).join('') + '</tr>';
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
  d.filtered = q ? d.raw.filter(function(r){ return r.some(function(c){ return String(c).toLowerCase().indexOf(q) >= 0; }); }) : d.raw;
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
  if (d) navigator.clipboard.writeText(d.filtered.map(function(r){ return r.join('\t'); }).join('\n'))
    .then(function(){ toast('Copied ' + num(d.filtered.length) + ' rows'); });
}
// Alive table
var AP = 150;
var SC_COL = {'2':'#3fb950','3':'#74c0fc','4':'#e3b341','5':'#f85149'};
function aliveInit() {
  window._AP = 0; aliveCnt(); aliveRender();
}
function aliveFilter() {
  var q = document.getElementById('alive-q').value.toLowerCase();
  window._AF = q ? window._AR.filter(function(r){ return r.some(function(c){ return String(c).toLowerCase().indexOf(q) >= 0; }); }) : window._AR;
  window._AP = 0; aliveCnt(); aliveRender();
}
function aliveRender() {
  var data = window._AF || [], tbody = document.getElementById('alive-body'), more = document.getElementById('alive-more');
  if (!tbody) return;
  var slice = data.slice(0, (window._AP + 1) * AP);
  tbody.innerHTML = slice.map(function(r) {
    var url=r[0],sc=r[1],title=r[2],ip=r[3],tech=r[4],sz=r[5],srv=r[6];
    var col = SC_COL[String(sc)[0]] || '#6e8098';
    return '<tr>'
      + '<td><a href="' + esc(url) + '" target="_blank" style="color:#74c0fc;font-family:var(--mono);font-size:11.5px">' + esc(url) + '</a></td>'
      + '<td><b style="color:' + col + '">' + esc(sc) + '</b></td>'
      + '<td style="font-family:var(--sans)">' + esc(title) + '</td>'
      + '<td>' + esc(ip) + '</td>'
      + '<td style="font-size:11px;color:#6e8098">' + esc(tech) + '</td>'
      + '<td>' + esc(sz) + '</td>'
      + '<td style="font-size:11px;color:#6e8098">' + esc(srv) + '</td>'
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
  var hdr = 'URL,Status,Title,IP,Tech,Size,Server';
  var rows = (window._AF||[]).map(function(r){ return r.map(function(c){ return '"' + String(c).replace(/"/g,'""') + '"'; }).join(','); });
  dl([hdr].concat(rows).join('\n'), 'alive_hosts.csv', 'text/csv');
}
// Utilities
function parseURL(url) {
  try { var u = new URL(url); return {host:u.hostname,path:u.pathname,qs:u.search?u.search.slice(0,80):''}; }
  catch { return {host:'',path:url,qs:''}; }
}
function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
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
      + 'transition:opacity .3s;font-family:Inter,sans-serif;pointer-events:none';
    document.body.appendChild(t);
  }
  t.textContent = '✓ ' + msg; t.style.opacity = '1';
  clearTimeout(_tt); _tt = setTimeout(function(){ t.style.opacity = '0'; }, 2500);
}
// Keyboard shortcut: / → focus search
document.addEventListener('keydown', function(e) {
  if (e.key === '/' && !['INPUT','TEXTAREA'].includes(document.activeElement.tagName)) {
    e.preventDefault();
    var inp = document.querySelector('.section.active .vs-search');
    if (inp) inp.focus();
  }
});
// Init queue flush
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

// ── Threat Map (D3 force-directed) ─────────────────────────────────────────
function initThreatMap() {
  var data = window._TM_DATA;
  if (!data || typeof d3 === 'undefined') return;

  var svg = d3.select('#tm-svg');
  var wrap = document.querySelector('.tm-wrap');
  if (!svg.node() || !wrap) return;

  var W = wrap.clientWidth  || 900;
  var H = wrap.clientHeight || 680;
  svg.attr('viewBox', [0, 0, W, H]);

  var g = svg.append('g');
  var tooltip = document.getElementById('tm-tooltip');

  // Color helpers
  function nodeColor(d) {
    if (d.type === 'root')  return '#4fa8e8';
    if (d.type === 'group') return '#2d4a62';
    var sevMap = {critical:'#ff453a', high:'#ff6b35', medium:'#ffa94d', low:'#74c0fc', none:'', info:''};
    if (d.xss) return '#ff453a';
    if (sevMap[d.severity]) return sevMap[d.severity];
    return d.alive ? '#34c759' : '#3a4d60';
  }
  function nodeRadius(d) {
    if (d.type === 'root')  return 22;
    if (d.type === 'group') return 16;
    return d.alive ? 9 : 6;
  }
  function nodeStroke(d) {
    if (d.xss) return '#fff';
    if (d.type === 'root') return '#74c0fc';
    if (d.type === 'group') return '#3d6080';
    return d.alive ? '#27a447' : '#2a3d50';
  }
  function linkColor(d) {
    return d.type === 'group' ? '#243040' : '#1e2a36';
  }

  // Clone data for filtering
  window._TM_ALL_NODES = data.nodes.slice();
  window._TM_ALL_LINKS = data.links.slice();
  window._TM_SIM = null;
  window._TM_G = g;
  window._TM_SVG = svg;
  window._TM_W = W;
  window._TM_H = H;
  window._TM_NODE_COLOR = nodeColor;
  window._TM_NODE_RADIUS = nodeRadius;
  window._TM_NODE_STROKE = nodeStroke;
  window._TM_LINK_COLOR = linkColor;

  renderThreatMap(data.nodes, data.links);
}

function renderThreatMap(nodes, links) {
  var svg    = window._TM_SVG;
  var g      = window._TM_G;
  var W      = window._TM_W;
  var H      = window._TM_H;
  var nodeColor  = window._TM_NODE_COLOR;
  var nodeRadius = window._TM_NODE_RADIUS;
  var nodeStroke = window._TM_NODE_STROKE;
  var linkColor  = window._TM_LINK_COLOR;
  var tooltip    = document.getElementById('tm-tooltip');

  g.selectAll('*').remove();
  if (window._TM_SIM) window._TM_SIM.stop();

  // Zoom
  var zoom = d3.zoom()
    .scaleExtent([0.05, 4])
    .on('zoom', function(event){ g.attr('transform', event.transform); });
  svg.call(zoom);
  window._TM_ZOOM = zoom;

  // Build node map for link resolution
  var nodeById = {};
  nodes.forEach(function(n){ nodeById[n.id] = n; });

  var resolvedLinks = links
    .filter(function(l){ return nodeById[l.source] && nodeById[l.target]; })
    .map(function(l){ return {source: l.source, target: l.target, type: l.type}; });

  var sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(resolvedLinks)
      .id(function(d){ return d.id; })
      .distance(function(d){ return d.type === 'group' ? 120 : 70; })
    )
    .force('charge', d3.forceManyBody()
      .strength(function(d){ return d.type === 'root' ? -800 : d.type === 'group' ? -300 : -80; })
    )
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collision', d3.forceCollide().radius(function(d){ return nodeRadius(d) + 5; }))
    .alphaDecay(0.02);

  window._TM_SIM = sim;

  // Defs: glow filters
  var defs = svg.select('defs');
  if (defs.empty()) defs = svg.append('defs');
  ['glow-blue','glow-red','glow-green'].forEach(function(id, i) {
    var colors = ['#4fa8e8','#ff453a','#34c759'];
    var filt = defs.append('filter').attr('id', id).attr('x','-30%').attr('y','-30%').attr('width','160%').attr('height','160%');
    filt.append('feGaussianBlur').attr('stdDeviation','3').attr('result','blur');
    var merge = filt.append('feMerge');
    merge.append('feMergeNode').attr('in','blur');
    merge.append('feMergeNode').attr('in','SourceGraphic');
  });

  // Links
  var link = g.append('g').selectAll('line')
    .data(resolvedLinks).join('line')
    .attr('stroke', linkColor)
    .attr('stroke-width', function(d){ return d.type === 'group' ? 1.5 : 1; })
    .attr('stroke-dasharray', function(d){ return d.type === 'group' ? '6,3' : ''; })
    .attr('opacity', 0.6);

  // Node groups
  var node = g.append('g').selectAll('g')
    .data(nodes).join('g')
    .attr('class', 'tm-node')
    .style('cursor', 'pointer')
    .call(d3.drag()
      .on('start', function(event, d) {
        if (!event.active) sim.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on('drag', function(event, d) { d.fx = event.x; d.fy = event.y; })
      .on('end', function(event, d) {
        if (!event.active) sim.alphaTarget(0);
        d.fx = null; d.fy = null;
      })
    );

  // Circles
  node.append('circle')
    .attr('r', nodeRadius)
    .attr('fill', nodeColor)
    .attr('stroke', nodeStroke)
    .attr('stroke-width', function(d){ return d.xss ? 2.5 : 1.5; })
    .attr('filter', function(d){
      if (d.type === 'root') return 'url(#glow-blue)';
      if (d.xss || d.severity === 'critical' || d.severity === 'high') return 'url(#glow-red)';
      if (d.alive && d.type === 'subdomain') return 'url(#glow-green)';
      return '';
    });

  // XSS ring
  node.filter(function(d){ return d.xss; })
    .append('circle')
    .attr('r', function(d){ return nodeRadius(d) + 4; })
    .attr('fill', 'none')
    .attr('stroke', '#ff453a')
    .attr('stroke-width', 1)
    .attr('stroke-dasharray', '3,2')
    .attr('opacity', 0.6);

  // Vuln count badge
  node.filter(function(d){ return d.vuln_count > 0; })
    .append('text')
    .text(function(d){ return d.vuln_count; })
    .attr('dy', function(d){ return -nodeRadius(d) + 2; })
    .attr('text-anchor', 'middle')
    .attr('fill', '#ff6b6b')
    .attr('font-size', '9px')
    .attr('font-weight', '700')
    .attr('font-family', 'JetBrains Mono, monospace');

  // Labels
  var labels = node.append('text')
    .attr('class', 'tm-label')
    .attr('dy', function(d){ return nodeRadius(d) + 13; })
    .attr('text-anchor', 'middle')
    .attr('fill', function(d){
      if (d.type === 'root') return '#4fa8e8';
      if (d.type === 'group') return '#6e8098';
      return d.alive ? '#cdd9e5' : '#506070';
    })
    .attr('font-size', function(d){ return d.type === 'root' ? '12px' : d.type === 'group' ? '10px' : '9px'; })
    .attr('font-family', 'JetBrains Mono, monospace')
    .attr('font-weight', function(d){ return d.type === 'root' ? '700' : '400'; })
    .text(function(d){
      if (d.type === 'root') return d.label;
      if (d.type === 'group') return d.label;
      // Shorten label: show only first part
      var parts = d.label.split('.');
      return parts.length > 2 ? parts.slice(0, -2).join('.') : d.label;
    })
    .style('display', window._TM_SHOW_LABELS ? '' : 'none')
    .style('pointer-events', 'none');

  // Tooltip
  node.on('mouseover', function(event, d) {
    var sevColors = {critical:'#ff443a',high:'#ff6b35',medium:'#ffd43b',low:'#74c0fc',info:'#868e96',none:'#868e96'};
    var sev = d.severity || 'none';
    var html = '<strong>' + d.label + '</strong>';
    if (d.type === 'group') {
      html += '<span class="tm-tt-badge" style="background:#1a2d3d;color:#4fa8e8">GROUP · ' + d.count + ' subs</span>';
    } else if (d.type !== 'root') {
      html += '<span class="tm-tt-badge" style="background:' + (d.alive ? '#0d2414' : '#1a1f26') + ';color:' + (d.alive ? '#34c759' : '#6e8098') + '">' + (d.alive ? '✓ ALIVE' : '✗ DEAD') + '</span>';
      if (sev !== 'none' && sev !== 'info') {
        html += '<span class="tm-tt-badge" style="background:#2d0d0d;color:' + sevColors[sev] + '">' + sev.toUpperCase() + ' · ' + d.vuln_count + ' finding' + (d.vuln_count > 1 ? 's' : '') + '</span>';
      }
      if (d.xss) {
        html += '<span class="tm-tt-badge" style="background:#2d0d0d;color:#ff453a">⚠ XSS</span>';
      }
    }
    tooltip.innerHTML = html;
    tooltip.style.display = 'block';
  })
  .on('mousemove', function(event) {
    var wrap = document.querySelector('.tm-wrap');
    var rect = wrap.getBoundingClientRect();
    var x = event.clientX - rect.left + 12;
    var y = event.clientY - rect.top + 12;
    if (x + 290 > wrap.clientWidth) x -= 300;
    tooltip.style.left = x + 'px';
    tooltip.style.top  = y + 'px';
  })
  .on('mouseout', function() { tooltip.style.display = 'none'; });

  // Update info
  var infoEl = document.getElementById('tm-info');
  if (infoEl) infoEl.textContent = nodes.length + ' nodes · ' + resolvedLinks.length + ' edges';

  sim.on('tick', function() {
    link
      .attr('x1', function(d){ return d.source.x; })
      .attr('y1', function(d){ return d.source.y; })
      .attr('x2', function(d){ return d.target.x; })
      .attr('y2', function(d){ return d.target.y; });
    node.attr('transform', function(d){ return 'translate(' + d.x + ',' + d.y + ')'; });
  });
}

function tmResetZoom() {
  if (!window._TM_SVG || !window._TM_ZOOM) return;
  window._TM_SVG.transition().duration(500).call(
    window._TM_ZOOM.transform, d3.zoomIdentity.translate(window._TM_W/2, window._TM_H/2).scale(0.8)
  );
}
function tmToggleLabels() {
  window._TM_SHOW_LABELS = !window._TM_SHOW_LABELS;
  d3.selectAll('.tm-label').style('display', window._TM_SHOW_LABELS ? '' : 'none');
}
function tmFilterAlive() {
  window._TM_FILTER = 'alive';
  var all = window._TM_ALL_NODES;
  var aliveIds = new Set(all.filter(function(n){ return n.alive || n.type === 'root'; }).map(function(n){ return n.id; }));
  var nodes = all.filter(function(n){ return aliveIds.has(n.id); });
  var links = window._TM_ALL_LINKS.filter(function(l){ return aliveIds.has(l.source) && aliveIds.has(l.target); });
  renderThreatMap(nodes.map(function(n){ return Object.assign({}, n); }), links);
}
function tmFilterAll() {
  window._TM_FILTER = 'all';
  var nodes = window._TM_ALL_NODES.map(function(n){ return Object.assign({}, n); });
  renderThreatMap(nodes, window._TM_ALL_LINKS);
}
function tmSearch() {
  var q = document.getElementById('tm-search').value.toLowerCase();
  if (!q) { d3.selectAll('.tm-node circle').attr('opacity', 1); return; }
  d3.selectAll('.tm-node').each(function(d) {
    var match = d.label && d.label.toLowerCase().indexOf(q) >= 0;
    d3.select(this).selectAll('circle').attr('opacity', match ? 1 : 0.15);
    d3.select(this).selectAll('text').attr('opacity', match ? 1 : 0.1);
  });
}

// Re-init threat map when its section becomes visible
var _origShowSection = typeof showSection !== 'undefined' ? showSection : null;
function showSection(id, el) {
  document.querySelectorAll('.section').forEach(function(s){ s.classList.remove('active'); });
  document.querySelectorAll('.nav-a').forEach(function(n){ n.classList.remove('active'); });
  var sec = document.getElementById('s-' + id);
  if (sec) sec.classList.add('active');
  if (el) el.classList.add('active');
  if (sec) sec.querySelectorAll('.vs-vp').forEach(function(vp){
    try { vsRender(vp.id.replace('-vp', '')); } catch(e) {}
  });
  if (id === 'threatmap' && window._TM_DATA && typeof d3 !== 'undefined') {
    setTimeout(function() {
      if (!window._TM_SIM || window._TM_SIM.alpha() < 0.001) {
        initThreatMap();
      }
    }, 80);
  }
}
"""


# ── Builder ───────────────────────────────────────────────────────────────────
def build_report(scan_dir, target: str, summary: dict = None) -> Path:
    scan_dir = Path(scan_dir)
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M")

    recon   = _parse_recon(scan_dir)
    subs    = _parse_subdomains(scan_dir)
    alive   = _parse_alive(scan_dir)
    urls    = _parse_url_categories(scan_dir)
    nuclei  = _parse_nuclei(scan_dir)
    xss     = _parse_xss(scan_dir)
    smry    = summary or {}

    def _nav(icon, label, sid, count=None):
        cnt = (f'<span class="nav-cnt">{count:,}</span>' if isinstance(count, int) else
               f'<span class="nav-cnt">{count}</span>' if count is not None else "")
        return (f'<a class="nav-a" onclick="showSection(\'{sid}\',this)">'
                f'<span class="nav-ico">{icon}</span>{_e(label)}{cnt}</a>')

    sidebar = f'''<div class="sb-brand">
  <h1>⚡ ReconX</h1>
  <div class="sb-target">🎯 {_e(target)}</div>
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
  {_nav("🧩","Parameters","params")}
  {_nav("📂","Categorised","categorised")}
</div>
<div class="nav-grp"><div class="nav-lbl">Vulnerabilities</div>
  {_nav("🎯","Nuclei","nuclei", len(nuclei["all"]))}
  {_nav("💉","XSS / Dalfox","xss", len(xss["all"]))}
</div>
<hr class="nav-hr">
<div style="padding:8px 16px 16px;font-size:10px;color:#2d3f50;line-height:2">
  <kbd style="background:#1e2a36;padding:1px 5px;border-radius:3px;color:#6e8098">/</kbd> to search<br>
  Virtual scroll · No truncation
</div>'''

    sections = "".join([
        _section_overview(target, ts, recon, subs, alive, urls, nuclei, xss, smry),
        _section_threatmap(target, subs, alive, nuclei, xss),
        _section_recon(recon),
        _section_subdomains(subs),
        _section_alive(alive),
        _section_urls(urls),
        _section_params(urls),
        _section_categorised(urls),
        _section_nuclei(nuclei),
        _section_xss(xss),
    ])

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconX — {_e(target)}</title>
<style>{_CSS}</style>
</head>
<body>
<nav class="sidebar">{sidebar}</nav>
<main class="main">
{sections}
<div class="footer">
  ReconX v5.0 · {_e(target)} · {_e(ts)}<br>
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


# Alias
build_full_report = build_report


def open_in_browser(path):
    import subprocess, sys, os
    path = Path(path).resolve()
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        elif sys.platform.startswith("linux"):
            for br in ["xdg-open", "firefox", "chromium", "chromium-browser", "google-chrome"]:
                if subprocess.run(["which", br], capture_output=True).returncode == 0:
                    subprocess.Popen([br, str(path)])
                    break
        elif sys.platform == "win32":
            os.startfile(str(path))
    except Exception as e:
        print(f"[!] Could not open browser: {e}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 3:
        p = build_report(Path(sys.argv[1]), sys.argv[2])
        print(f"Report → {p}")
        open_in_browser(p)
    else:
        print("Usage: python3 report_builder.py <scan_output_dir> <target>")
