#!/usr/bin/env python3


import json, math, re, html, shlex
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs, parse_qsl

from reconx_labels import public_activity


# ── File helpers ───────────────────────────────────────────────────────────────
def _read(p) -> str:
    try:
        return Path(p).read_text(errors="ignore") if p and Path(p).exists() else ""
    except:
        return ""

def _read_json(p) -> dict:
    try:
        if p and Path(p).exists():
            data = json.loads(Path(p).read_text(errors="ignore"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}

def _lines(p) -> list:
    return [l.strip() for l in _read(p).splitlines() if l.strip()]

def _url_identity(url: str) -> str:
    """Same key stage 4 uses when it merges tool output into all_urls_raw.txt."""
    fn = getattr(_url_identity, "fn", None)
    if fn is None:
        from reconX import canonicalize_url
        _url_identity.fn = canonicalize_url
        fn = canonicalize_url
    try:
        return fn((url or "").strip()) or ""
    except Exception:
        return (url or "").strip()

# Tool files that feed the URL Discovery tabs. The tab count is not the raw
# line count: gau/Katana reprint the same URL and also emit out-of-scope or
# static URLs that stage 4 drops. Each tab keeps only URLs that survived into
# the unique collected set, so a source cannot outgrow All.
_URL_SOURCE_KEYS = (
    "_gau", "_wayback", "_katana", "_hakrawler", "_gospider",
    "_commoncrawl", "_urlscan", "_otx",
)

def _align_url_sources(cats: dict, d: Path) -> dict:
    """Make All the unique collected set and every source tab a subset of it.

    Stage 4 writes two different files: all_urls_raw.txt (unique, in scope,
    before dead-URL pruning) and checkpoints/stage4_urls.txt (what stayed
    alive). The report used to label the smaller live file "All" and the raw
    tool files with their line counts, so All could read 9,371 while Katana
    read 288,216.
    """
    d = Path(d)
    raw_counts = {}
    key_to_url = {}
    corpus = []
    for u in _lines(d / "04_urls" / "all_urls_raw.txt"):
        k = _url_identity(u)
        if not k or k in key_to_url:
            continue
        key_to_url[k] = u
        corpus.append(u)

    if key_to_url:
        cats["_collected_src"] = "04_urls/all_urls_raw.txt"
        for key in _URL_SOURCE_KEYS:
            seen = set()
            kept = []
            raw = cats.get(key) or []
            raw_counts[key] = len(raw)
            for u in raw:
                k = _url_identity(u)
                if k in key_to_url and k not in seen:
                    seen.add(k)
                    kept.append(key_to_url[k])
            cats[key] = kept
        cats["_collected"] = corpus
    else:
        cats["_collected_src"] = ""
        union = {}
        order = []
        for key in _URL_SOURCE_KEYS:
            seen = set()
            kept = []
            raw = cats.get(key) or []
            raw_counts[key] = len(raw)
            for u in raw:
                if not u.startswith(("http://", "https://")):
                    continue
                k = _url_identity(u)
                if not k or k in seen:
                    continue
                seen.add(k)
                kept.append(k)
                if k not in union:
                    union[k] = k
                    order.append(k)
            cats[key] = kept
        if order:
            cats["_collected"] = order
        else:
            # No tool files and no raw union — the live checkpoint is the set.
            seen = set()
            order = []
            for u in cats.get("_all") or []:
                k = _url_identity(u)
                if not k or k in seen:
                    continue
                seen.add(k)
                order.append(u)
            cats["_collected"] = order
            cats["_collected_src"] = "checkpoints/stage4_urls.txt"
    cats["_raw_counts"] = raw_counts
    return cats

def _e(s) -> str:
    return html.escape(str(s) if s is not None else "", quote=True)

def _safe_content(s: str) -> str:
    return html.escape(str(s or ""), quote=True)

def _safe_json(data) -> str:
    try:
        raw = json.dumps(data, ensure_ascii=False, default=str)
    except Exception:
        return "[]"
    raw = raw.replace('<', r'\u003c').replace('>', r'\u003e').replace('&', r'\u0026')
    raw = raw.replace('\u2028', r'\u2028').replace('\u2029', r'\u2029')
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
        "whatweb_hosts": _read(d / "01_recon" / "whatweb_hosts.txt"),
        "wafw00f":   _read(d / "01_recon" / "wafw00f.txt"),
        "harvester": _read(d / "01_recon" / "theharvester.xml") or _read(d / "01_recon" / "theharvester.json"),
        "dns":       _read(d / "01_recon" / "dns.txt"),
        "contacts":  _read_json(d / "01_recon" / "contacts.json"),
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
        title = str((rec.get("title") or rec.get("page-title") or "") or "")[:80]
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
        server = str((rec.get("webserver") or rec.get("server") or "") or "")[:50]
        rt     = (rec.get("time") or rec.get("response-time") or "")
        # v8.1: settings.enable_screenshots=true iken httpx -screenshot -srd
        # 03_alive/screenshots yazar ve her kayda "screenshot_path_rel" ekler
        # (o dizine gore relative). report.html hep scan_dir kokunde oldugu icin
        # buradan gorece yolu 03_alive/screenshots/ ile birlestiriyoruz.
        shot_rel = rec.get("screenshot_path_rel") or rec.get("screenshot-path-rel") or ""
        shot = f"03_alive/screenshots/{shot_rel}" if shot_rel else ""
        return {"url": url, "status": str(sc) if sc else "",
                "title": title, "ip": ip[:22], "tech": tech[:120],
                "size": str(cl), "server": server[:50], "rt": str(rt)[:12],
                "shot": shot}

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
    for name in ["params", "reflection", "openredirect", "sqli", "forms", "admin", "login", "api", "sensitive", "other",
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
    return _align_url_sources(cats, d)


def _parse_summary_json(d: Path) -> dict:
    sf = d / "SUMMARY.json"
    if sf.exists():
        try:
            return json.loads(sf.read_text(errors="ignore")) or {}
        except:
            pass
    return {}


def _as_list(v) -> list:
    """Nuclei's stringslice fields (cve-id, cwe-id, tags, reference) serialize as
    either a single string or a JSON array depending on cardinality — normalize
    both shapes to a list."""
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if x]
    if isinstance(v, str):
        v = v.strip()
        return [v] if v else []
    return [str(v)]


def _parse_nuclei(d) -> dict:
    d = Path(d)
    findings = []
    # v8.6: read BOTH the template scan and the DAST/fuzzing pass. DAST findings
    # are tagged source="dast" so the report can badge them (these are the
    # injection findings — XSS/SQLi/SSTI/LFI/cmdi — on custom targets).
    for jsonl, _src in ((d / "07_nuclei" / "nuclei_scan.json", "template"),
                        (d / "07_nuclei" / "nuclei_dast.json", "dast")):
        if not jsonl.exists():
            continue
        try:
            with jsonl.open(errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    info = rec.get("info") or {}
                    # v8.1: nuclei'nin info.classification bloğu CVE/CWE/CVSS/EPSS
                    # tasiyor ama hic okunmuyordu — bulgular sadece isim+severity
                    # olarak gorunuyordu. Ayrica info.reference / info.tags de
                    # (aksiyona gecirilebilir baglam icin) simdi yakalaniyor.
                    cls = info.get("classification") or {}
                    findings.append({
                        "template":   rec.get("template-id") or info.get("name") or "",
                        "name":       info.get("name") or rec.get("template-id") or "",
                        "severity":   info.get("severity") or rec.get("severity") or "",
                        "matched_at": rec.get("matched-at") or rec.get("matched_at") or rec.get("url") or "",
                        "type":       rec.get("type") or "",
                        "host":       rec.get("host") or "",
                        "cve":        _as_list(cls.get("cve-id")),
                        "cwe":        _as_list(cls.get("cwe-id")),
                        "cvss_score": cls.get("cvss-score") or 0,
                        "cvss_metrics": cls.get("cvss-metrics") or "",
                        "epss_score": cls.get("epss-score") or 0,
                        "tags":       _as_list(info.get("tags")),
                        "reference":  _as_list(info.get("reference")),
                        "description": info.get("description") or "",
                        "remediation": info.get("remediation") or "",
                        "source":     _src,
                    })
                    findings[-1]["severity"] = _cap_template_severity(findings[-1])
        except Exception:
            pass

    severity_counts = {}
    for f in findings:
        s = str(f.get("severity") or "info").lower() or "info"
        severity_counts[s] = severity_counts.get(s, 0) + 1
    if not severity_counts and findings:
        severity_counts["info"] = len(findings)

    raw_txt = _read(d / "07_nuclei" / "nuclei_scan.txt")
    _dast_txt = _read(d / "07_nuclei" / "nuclei_dast.txt")
    if _dast_txt:
        raw_txt = (raw_txt + "\n" if raw_txt else "") + "# ── DAST / fuzzing pass ──\n" + _dast_txt

    meta = {}
    sm  = _parse_summary_json(d)
    st7 = sm.get("stages", {}).get("stage7") or {}
    n7  = sm.get("nuclei") if isinstance(sm.get("nuclei"), dict) else {}
    meta["template_path"] = st7.get("template_path") or n7.get("template_path") or ""
    meta["status"]        = st7.get("status") or n7.get("status") or ""
    meta["tool_failed"]   = bool(st7.get("tool_failed") or n7.get("tool_failed"))
    meta["tool_error"]    = st7.get("tool_error") or n7.get("tool_error") or ""
    meta["interrupted"]   = bool(st7.get("interrupted") or n7.get("interrupted"))
    meta["duration_sec"]  = st7.get("duration_sec", n7.get("duration_sec", 0))
    meta["severity_filter"] = st7.get("severity_filter") or n7.get("severity_filter") or "none"
    meta["targets_count"] = st7.get("targets_count", n7.get("targets_count", 0))
    meta["tags_used"]     = st7.get("tech_fastpass_tags") or n7.get("tags_used") or ""
    meta["findings_dast"] = st7.get("findings_dast", sum(1 for f in findings if f.get("source") == "dast"))
    meta["findings_template"] = st7.get("findings_template", sum(1 for f in findings if f.get("source") != "dast"))
    meta["dast_targets_count"] = st7.get("dast_targets_count", 0)
    meta["ran"]           = meta["status"] not in ("", "skipped", "not-run")
    return {"findings": findings, "severity_counts": severity_counts,
            "raw_txt": raw_txt, "meta": meta}


def _issue_blob(finding: dict) -> str:
    tags = finding.get("tags") or []
    if isinstance(tags, (list, tuple)):
        tags = " ".join(str(t) for t in tags)
    return " ".join(str(finding.get(k) or "") for k in (
        "template", "name", "description", "type")).lower() + " " + str(tags).lower()


def _cap_template_severity(finding: dict) -> str:
    """Critical is only for code execution and SQL injection.

    A template tagged critical still counts as high when it is XSS, and as
    medium when it is an open redirect. Anything else marked critical is
    high until it matches those two classes.
    """
    sev = str(finding.get("severity") or "info").strip().lower()
    if sev not in ("critical", "high", "medium", "low", "info", "unknown"):
        sev = "info"
    text = _issue_blob(finding)
    if any(m in text for m in ("xss", "cross-site scripting", "cross site scripting")):
        return "high" if sev in ("critical", "high") else sev
    if any(m in text for m in ("open-redirect", "open redirect", "openredirect")):
        return "medium" if sev in ("critical", "high") else (sev if sev != "critical" else "medium")
    if any(m in text for m in (
            "rce", "remote code", "command-injection", "command injection",
            "os-command", "sqli", "sql-injection", "sql injection",
            "ssti", "server-side template", "deserialization")):
        return "critical"
    if sev == "critical":
        return "high"
    return sev


def _risk_level_from_severity(sev_counts: dict) -> tuple:
    """Nuclei severity counts -> single-word English RISK label + color.
    v6.17: replaces any 'no findings' style empty-state text with a
    consistent RISK badge across every report surface."""
    sev_counts = sev_counts or {}
    if int(sev_counts.get("critical", 0)) > 0:
        return "CRITICAL", "red"
    if int(sev_counts.get("high", 0)) > 0:
        return "HIGH", "red"
    if int(sev_counts.get("medium", 0)) > 0:
        return "MEDIUM", "orange"
    if int(sev_counts.get("low", 0)) > 0 or int(sev_counts.get("info", 0)) > 0:
        return "LOW", "blue"
    return "NONE", "green"


# dalfox v2's PoC "type" is a single-letter internal code — friendlier label for the report.
# "RV" (v8.5) isn't a dalfox code at all: reconx.py sets it when a "R"
# (Reflected) finding gets replayed through a headless browser and ReconX
# itself catches the payload actually firing — see capture_xss_alert_
# screenshots()'s confirmed_upgrade in reconx.py. Kept distinguishable from
# dalfox's own "V" so the report is honest about who did the confirming.
_DALFOX_TYPE_LABELS = {"V": "Verified (scanner)", "R": "Reflected", "G": "Grep match",
                        "RV": "Verified (ReconX replay)"}

def _xss_severity(raw_type: str, severity: str) -> str:
    """A verified XSS is high. A reflection is at least medium. Dalfox sometimes
    labels both low, which made two real findings look like noise."""
    order = ["info", "low", "medium", "high", "critical"]
    sev = (severity or "").strip().lower()
    if sev not in order:
        sev = "info"
    floor = {"V": "high", "RV": "high", "R": "medium"}.get((raw_type or "").strip().upper(), "")
    if floor and order.index(sev) < order.index(floor):
        sev = floor
    # XSS is not a critical class. RCE and SQL injection are.
    if order.index(sev) > order.index("high"):
        sev = "high"
    return sev[:1].upper() + sev[1:]

def _xss_rec(rec):
    # v8.1-fix: gercek dalfox v2 PoC JSON semasi (pkg/model/result.go) su alanlari
    # kullanir: type, inject_type, poc_type, method, data, param, payload, evidence,
    # cwe, severity, message_str. "data" NESTED BIR DICT DEGIL, bulgunun bulundugu
    # URL'i iceren duz bir STRING'dir; ust seviyede ayrica bir "url" alani da hic
    # yoktur. Eski kod "data"nin dict oldugunu varsayiyordu (hicbir zaman dogru
    # degildi) ve top-level "url" alanini ariyordu (hicbir zaman var olmadi) — bu
    # yuzden her XSS bulgusunun URL'i raporda hep bos gorunuyordu.
    if not isinstance(rec, dict):
        return None
    url = str(rec.get("data") or "")
    payload = str(rec.get("payload") or "")
    param = str(rec.get("param") or "")
    raw_type = str(rec.get("type") or "")
    typ = _DALFOX_TYPE_LABELS.get(raw_type, raw_type)
    severity = _xss_severity(raw_type, str(rec.get("severity") or ""))
    cwe = str(rec.get("cwe") or "")
    evidence = str(rec.get("evidence") or "").strip()
    if not url and not payload:
        return None
    return {"url": url, "payload": payload, "param": param, "type": typ,
            "severity": severity, "cwe": cwe, "evidence": evidence}


def _parse_xss(d) -> dict:
    d = Path(d)
    findings = []
    xdir = d / "07_xss"
    jf = xdir / "dalfox.json"
    if not (jf.exists() and jf.stat().st_size > 0):
        # v6.9: stage6 dalfox_scan.json uretir — ilk eslesen dalfox_*.json
        cands = sorted(xdir.glob("dalfox_*.json")) if xdir.exists() else []
        if cands:
            jf = cands[0]
    sources = []
    if jf.exists() and jf.stat().st_size > 0:
        sources.append(jf)
    per_url = xdir / "dalfox_per_url"
    if per_url.is_dir():
        sources.extend(sorted(p for p in per_url.glob("dalfox_*.json") if p.stat().st_size > 0))
    seen_hits = set()
    for src in sources:
        try:
            raw = src.read_text(errors="ignore").lstrip()
            if raw[:1] == "[":
                data = json.loads(raw)
                if isinstance(data, list):
                    for rec in data:
                        if isinstance(rec, dict):
                            g = _xss_rec(rec)
                            if g and (g.get("url"), g.get("payload"), g.get("param")) not in seen_hits:
                                seen_hits.add((g.get("url"), g.get("payload"), g.get("param")))
                                findings.append(g)
            else:
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        if isinstance(rec, dict):
                            g = _xss_rec(rec)
                            if g and (g.get("url"), g.get("payload"), g.get("param")) not in seen_hits:
                                seen_hits.add((g.get("url"), g.get("payload"), g.get("param")))
                                findings.append(g)
                    except Exception:
                        continue
        except Exception:
            pass

    meta = {}
    sm  = _parse_summary_json(d)
    st6 = sm.get("stages", {}).get("stage6") or {}
    meta["status"] = st6.get("status") or ""
    meta["tool_failed"] = bool(st6.get("tool_failed"))
    meta["tool_error"]  = st6.get("tool_error") or ""
    meta["interrupted"] = bool(st6.get("interrupted"))
    meta["budget_hit"] = bool(st6.get("budget_hit"))
    meta["duration_sec"] = st6.get("duration_sec", 0)
    meta["targets_count"] = st6.get("targets_count", 0)
    meta["ran"] = meta["status"] not in ("", "skipped") or bool(findings)
    if findings and not meta["status"]:
        meta["status"] = "partial"
    # v8.2: auto-provisioned interactsh blind-XSS callback + any confirmed
    # out-of-band interactions (see reconx.py stage6_xss / start_interactsh_session).
    meta["suspicious_empty"] = bool(st6.get("suspicious_empty"))
    meta["blind_callback_used"] = st6.get("blind_callback_used") or ""
    meta["blind_interactions"] = st6.get("blind_interactions") or []
    # v8.2: screenshots of headless-verified ("V" type) XSS findings, replayed
    # and captured by reconx.py's capture_xss_alert_screenshots().
    meta["screenshots"] = st6.get("screenshots") or []
    # v8.6-fix: also read the on-disk sidecar — survives a partial re-run that
    # rewrites SUMMARY.json without a stage6 entry.
    if not meta["screenshots"]:
        _vf = d / "07_xss" / "xss_verified.json"
        if _vf.exists():
            try:
                meta["screenshots"] = json.loads(_vf.read_text(errors="ignore")) or []
            except Exception:
                pass

    # v8.5-fix: promote a "Reflected" finding to "Verified (ReconX replay)"
    # when reconx.py's screenshot replay ACTUALLY caught it firing a real
    # dialog (confirmed_upgrade — see capture_xss_alert_screenshots() and its
    # v8.5 docstring in reconx.py). Requested directly: dalfox's own "R" type
    # only means the payload text came back unescaped, never that it
    # executes — most of a real scan's "R" hits turned out to just be inert
    # text on screen. This is the actual confirmation step (a real headless
    # browser replay), not a relabel — an "R" finding that wasn't replayed
    # (past the screenshot budget) or was replayed but didn't fire stays
    # exactly "Reflected", untouched.
    _upgraded = {s["url"] for s in meta["screenshots"] if s.get("confirmed_upgrade") and s.get("url")}
    if _upgraded:
        for f in findings:
            if f.get("url") in _upgraded and f.get("type") == _DALFOX_TYPE_LABELS["R"]:
                f["type"] = _DALFOX_TYPE_LABELS["RV"]
    # stage6 dalfox_scan.txt uretir; varsa onu, yoksa sabit ad
    raw_txt = _read(xdir / "dalfox.txt")
    if not raw_txt:
        t_cands = sorted(xdir.glob("dalfox_*.txt")) if xdir.exists() else []
        if t_cands:
            raw_txt = _read(t_cands[0])

    # v8.3: full "all tested URLs & payloads" list, requested by the user —
    # every URL dalfox was actually pointed at (07_xss/xss_targets_tested.txt,
    # written by reconx.py's stage6_xss right before the scan), cross-
    # referenced against the findings parsed above so the report can mark
    # each one vulnerable (red) or clean (green). A finding's own "data"
    # field is the REQUEST url dalfox actually sent (i.e. WITH the payload
    # already substituted into the parameter value), not the original clean
    # target URL, so an exact string match against the tested-URL list would
    # almost never hit. Matching is done on (scheme+host+path) instead —
    # stable across payload substitution and good enough to attribute a
    # finding back to the target URL it came from.
    tested_urls = _lines(xdir / "xss_targets_tested.txt")

    def _path_key(u: str) -> str:
        try:
            p = urlparse(u)
            return f"{p.scheme}://{p.netloc}{p.path}"
        except Exception:
            return u

    def _params_of(u: str) -> set:
        try:
            return {k.lower() for k, _ in parse_qsl(urlparse(u).query) if k}
        except Exception:
            return set()

    # index (path -> list of findings on that path). Attribution to a specific
    # tested URL additionally requires the finding's injected parameter to
    # actually be present on that URL — otherwise every ?a=1 / ?b=2 variant of
    # the same .jsp inherited the same hit and got painted red (seen on
    # demo.testfire.net: index.jsp?uid=123 flagged for a content= XSS).
    hits_by_path = {}
    for f in findings:
        hits_by_path.setdefault(_path_key(f.get("url", "")), []).append(f)

    _V = (_DALFOX_TYPE_LABELS["V"], _DALFOX_TYPE_LABELS["RV"])
    finished_set = set(_lines(xdir / "xss_targets_finished.txt"))
    incomplete_set = set(_lines(xdir / "xss_targets_incomplete.txt"))
    skipped_set = set(_lines(xdir / "xss_targets_skipped_same_param.txt"))
    coverage_known = ((xdir / "xss_targets_finished.txt").exists()
                      or (xdir / "xss_targets_incomplete.txt").exists())
    scan_cut = bool(meta.get("interrupted") or meta.get("budget_hit")
                    or meta.get("status") == "partial")
    tested = []
    for u in tested_urls:
        key = _path_key(u)
        u_params = _params_of(u)
        hits = []
        for f in hits_by_path.get(key, []):
            fp = (f.get("param") or "").lower()
            f_params = _params_of(f.get("url", ""))
            if not fp:
                # v8.7-fix: no injected param on this finding (path/DOM hit) —
                # only attach it to the bare, query-less tested URL for this
                # path, not to every ?a=1/?b=2 query variant that happens to
                # share the same path.
                if not u_params:
                    hits.append(f)
            elif f_params:
                # v8.7-fix: the finding's own request URL carries a full query
                # key set — require an EXACT match against this tested URL's
                # keys, not just "the injected param is somewhere in there".
                # Two crawled variants of the same path/param (e.g.
                # index.jsp?uid=1 and index.jsp?uid=1&debug=true) would both
                # satisfy the old "param in u_params" check and both get
                # painted red for a single real hit; exact key-set equality
                # tells them apart.
                if f_params == u_params:
                    hits.append(f)
            elif fp in u_params:
                hits.append(f)
        # one-piece PoC per hit: dalfox's "url" (its "data" field) IS the full
        # request URL with the payload already substituted into the parameter —
        # exactly what you paste into a browser. Dedup + keep payload alongside.
        pocs, seen = [], set()
        for h in hits:
            pu = h.get("url", "")
            if pu and pu not in seen:
                seen.add(pu)
                pocs.append({"poc_url": pu, "payload": h.get("payload", ""),
                             "param": h.get("param", ""), "type": h.get("type", ""),
                             "confirmed": h.get("type", "") in _V})
        if u in skipped_set:
            # Another value of this same parameter already produced a finding.
            # Do not paint every leftover value as its own vulnerability.
            hits, pocs = [], []
            coverage = "same_param"
        elif hits:
            coverage = "vulnerable"
        elif u in finished_set:
            coverage = "clean"
        elif u in incomplete_set:
            coverage = "incomplete"
        elif coverage_known or scan_cut:
            # No sidecar from an older run, or this URL was never started.
            # A stopped scan must not paint the remainder green.
            coverage = "not_scanned"
        else:
            coverage = "clean"
        tested.append({
            "url": u,
            "vulnerable": bool(hits),
            "coverage": coverage,
            "confirmed": any(p["confirmed"] for p in pocs),
            "payloads": [h.get("payload", "") for h in hits],
            "pocs": pocs,
            "types": sorted({h.get("type", "") for h in hits if h.get("type")}),
            "severities": sorted({h.get("severity", "") for h in hits if h.get("severity")}),
        })

    return {"findings": findings, "raw_txt": raw_txt, "meta": meta, "tested": tested}


def _parse_js_secrets(d) -> dict:
    d = Path(d)
    endpoints  = _lines(d / "10_js_secrets" / "endpoints.txt")
    secret_txt = _lines(d / "10_js_secrets" / "secrets.txt")
    detail = []
    sj = d / "10_js_secrets" / "secrets.json"
    if sj.exists():
        try:
            data = json.loads(sj.read_text(errors="ignore"))
            if isinstance(data, list):
                detail = data
            elif isinstance(data, dict):
                for v in data.values():
                    if isinstance(v, list):
                        detail.extend(v)
                    else:
                        detail.append(v)
        except Exception:
            pass

    # v8.4-fix: this used to (a) join EVERY field of every detail record —
    # including "endpoint"-type records, which don't belong in the secrets
    # list at all — into one "url secret value context" string, and (b)
    # append that alongside the plain bare value already pulled from
    # secrets.txt above. Since those are two different-looking strings for
    # the SAME underlying finding, the dedupe below never collapsed them —
    # every secret effectively showed up twice in the report: once as a
    # clean bare value, once as a garbled concatenated duplicate. Confirmed
    # on a real scan report (10 rows for what was really ~6 distinct
    # secrets). Now: only type=="secret" detail records contribute, and
    # they contribute their plain "value" (the same string secrets.txt has)
    # so the existing value-based dedupe actually catches the duplicate.
    secrets = list(secret_txt)
    for item in detail:
        if isinstance(item, dict):
            if item.get("type") and item.get("type") != "secret":
                continue
            v = item.get("value")
            secrets.append(str(v) if v else " ".join(str(vv) for k, vv in item.items() if vv))
        elif isinstance(item, str) and item.strip():
            secrets.append(item)
    # dedupe preserving order — also flatten any embedded newline/CR so one
    # logical secret (e.g. a multi-line PEM block) can never look like
    # several broken rows in the report table.
    seen = set(); uniq = []
    for s in secrets:
        s = re.sub(r"[\r\n]+", " ", s).strip()
        if s and s not in seen:
            seen.add(s); uniq.append(s)
    ran = sj.exists() or (d / "10_js_secrets" / "endpoints.txt").exists()
    return {"endpoints": endpoints, "secrets": uniq, "detail": detail, "ran": ran}


def _parse_tech(d) -> list:
    d = Path(d)
    raw = []
    jf = d / "11_tech" / "tech_priority.json"
    if jf.exists():
        try:
            data = json.loads(jf.read_text(errors="ignore"))
            if isinstance(data, list):
                raw = data
        except Exception:
            pass
    if not raw:
        st11 = _parse_summary_json(d).get("stages", {}).get("stage11") or {}
        cand = st11.get("data") or st11.get("techs") or st11.get("priority") or st11.get("results")
        if isinstance(cand, list):
            raw = cand

    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        techs = item.get("techs") if isinstance(item.get("techs"), list) else []
        top   = item.get("top_techs") if isinstance(item.get("top_techs"), list) else []
        out.append({
            "url":        item.get("url") or item.get("host") or item.get("matched_at") or "",
            "status":     item.get("status") or item.get("status_code") or "",
            "techs":      techs,
            "score":      item.get("score", 0) or 0,
            "risk_label": str(item.get("risk_label") or item.get("risk") or "low").lower(),
            "top_techs":  top,
            "findings":   item.get("findings") or [],
        })
    try:
        out.sort(key=lambda x: -(int(x["score"]) if str(x["score"]).lstrip("-").isdigit() else 0))
    except Exception:
        pass
    return out


def _parse_params(d) -> dict:
    d = Path(d)
    new_params = (_lines(d / "checkpoints" / "stage9_params.txt")
                  or _lines(d / "09_params" / "all.txt"))
    return {"new_params": new_params}


def _parse_extra(d) -> dict:
    """v6.13+: stage12 (CORS misconfig / subdomain takeover / cloud bucket) sonuclarini okur."""
    d = Path(d)
    f = d / "12_extra" / "extra_results.json"
    out = {"cors": [], "takeover": [], "buckets": []}
    if f.exists():
        try:
            data = json.loads(f.read_text(errors="ignore")) or {}
            if isinstance(data, dict):
                out["cors"]     = [_norm_extra(r, "url", "detail", "acao", "acac")
                                   for r in (data.get("cors") or []) if isinstance(r, dict)]
                out["takeover"] = [_norm_extra(r, "host", "service", "cname", "detail")
                                   for r in (data.get("takeover") or []) if isinstance(r, dict)]
                out["buckets"]  = [_norm_extra(r, "url", "provider", "status", "detail")
                                   for r in (data.get("buckets") or []) if isinstance(r, dict)]
                meta = data.get("bucket_meta") or {}
                out["bucket_meta"] = meta if isinstance(meta, dict) else {}
        except Exception:
            pass
    return out


def _norm_extra(r: dict, *keys: str) -> dict:
    """Stage12 sonuclarinda null/eksik alanlari bos string'e cevirir.
    Boylece asagidaki slice'lar (None[:140] gibi) TypeError firlatmaz."""
    out = dict(r)
    for k in keys:
        v = out.get(k)
        if v is None or not isinstance(v, (str, int, float)):
            out[k] = ""
        else:
            out[k] = str(v)
    return out


def _host_of(u: str) -> str:
    u = (u or "").strip()
    if not u:
        return ""
    try:
        if "://" not in u:
            u = "https://" + u
        return (urlparse(u).hostname or "").lower()
    except Exception:
        return ""


def _build_vuln_map(nuc: dict, xss: dict, extra: dict, oredir: dict = None) -> dict:
    """Nuclei/XSS/Extra-checks bulgularini hostname'e gore birlestirip Threat Map'in
    zafiyet katmanini besler (high/medium/low/info + kumulatif sayim)."""
    order = {"high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}
    vmap: dict = {}

    def _bump(host: str, sev: str):
        if not host:
            return
        raw = str(sev or "info").lower()
        points = {"critical": 24, "high": 16, "medium": 8, "low": 3, "info": 1}
        if raw not in points:
            raw = "info"
        norm = "high" if raw in ("critical", "high") else raw
        cur = vmap.setdefault(host, {"severity": "none", "count": 0, "points": 0})
        cur["count"] += 1
        cur["points"] = min(88, int(cur.get("points") or 0) + points[raw])
        if order.get(norm, 0) > order.get(cur["severity"], 0):
            cur["severity"] = norm

    for f in (nuc.get("findings") or []):
        _bump(_host_of(f.get("matched_at", "")), str(f.get("severity", "info")).lower())
    for f in (xss.get("findings") or []):
        _bump(_host_of(f.get("url", "")), "high")
    for r in (extra.get("takeover") or []):
        if r.get("vulnerable"):
            _bump(_host_of(r.get("host", "")), "high")
    for r in (extra.get("cors") or []):
        if r.get("vulnerable"):
            _bump(_host_of(r.get("url", "")), "medium")
    for r in (extra.get("buckets") or []):
        if r.get("public_listing"):
            _bump(_host_of(r.get("url", "")), "medium")
    for f in ((oredir or {}).get("findings") or []):
        _bump(_host_of(f.get("url") or f.get("test_url") or ""), "medium")
    return vmap


# ── HTML components ────────────────────────────────────────────────────────────
# The report used to hard-code "v8.6" in two places, which silently went stale
# as the scanner moved on. Read it from reconX.py instead.
def _reconx_version() -> str:
    try:
        src = (Path(__file__).parent / "reconX.py").read_text(errors="ignore")
        m = re.search(r'^VERSION\s*=\s*["\']([^"\']+)', src, re.M)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def _badge(text: str, color: str = "blue") -> str:
    colors = {
        "red":    ("#fde8ea", "#9f1239"),
        "orange": ("#fff6ee", "#9a3412"),
        "yellow": ("#fef6d8", "#854d0e"),
        "blue":   ("#e7f1fb", "#1e4d73"),
        "green":  ("#e7f6ee", "#067647"),
        "purple": ("#f3eefe", "#5925dc"),
        "gray":   ("#f3f4f6", "#4b5563"),
        "cyan":   ("#e7f6f8", "#0e7490"),
    }
    bg, fg = colors.get(color, colors["blue"])
    return (f'<span style="background:{bg};color:{fg};padding:2px 10px;border-radius:6px;'
            f'font-size:11px;font-weight:600;letter-spacing:.3px;white-space:nowrap;'
            f'border:1px solid {fg}22">'
            f'{_e(text)}</span>')

def _stat(val, label: str, color: str, icon: str) -> str:
    cols = {"red":"#9f1239","orange":"#9a3412","blue":"#1e4d73","green":"#067647",
            "yellow":"#854d0e","purple":"#5925dc","gray":"#4b5563"}
    bgs  = {"red":"#fde8ea","orange":"#fff6ee","blue":"#e7f1fb",
            "green":"#e7f6ee","yellow":"#fef6d8","purple":"#f3eefe",
            "gray":"#f3f4f6"}
    c  = cols.get(color, "#1e4d73")
    bg = bgs.get(color, "#e7f1fb")
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


def _poc_field(value: str, label: str = "PoC URL") -> str:
    """A full string (URL + payload, curl line, ...) shown in one selectable
    box with a single 'Copy' button — copies the WHOLE thing in one click,
    never a CSS-truncated fragment."""
    v = value or ""
    return (f'<div class="poc-field"><span class="poc-lbl">{_e(label)}</span>'
            f'<code class="poc-val">{_e(v)}</code>'
            f'<button class="poc-copy" data-copy="{_e(v)}" onclick="copyOne(this)">Copy</button></div>')

VSCROLL_MAX = 25_000   # entries embedded per list; see _vscroll()


def _vscroll(data: list, uid: str, kind: str = "URL", source: str = "") -> str:
    """Virtual-scrolling list. At most VSCROLL_MAX entries are embedded; when
    the list is longer the overflow is stated in the toolbar (and `source`, if
    given, names the on-disk file holding the complete set) so a truncated view
    can never be mistaken for the whole result."""
    def _as_line(x):
        """Every entry must be a plain string — see vsRender()."""
        if isinstance(x, str):
            return x
        if isinstance(x, dict):
            for k in ("url", "endpoint", "host", "name", "value"):
                if x.get(k):
                    extra = x.get("status") or x.get("severity") or ""
                    return f"{x[k]}  [{extra}]" if extra else str(x[k])
            return json.dumps(x, ensure_ascii=False)
        return str(x)

    data = [_as_line(x) for x in (data or [])]
    total = len(data)
    truncated = total > VSCROLL_MAX
    if truncated:
        data = data[:VSCROLL_MAX]
    safe = _safe_json(data)
    trunc_html = ""
    if truncated:
        src = f' &middot; full list: <code>{_e(source)}</code>' if source else ""
        trunc_html = (f'<div class="vs-trunc">⚠ showing the first '
                      f'{VSCROLL_MAX:,} of {total:,} {_e(kind)}s in this viewer'
                      f'{src}</div>')
    return f'''<div class="vs-wrap">
  {trunc_html}
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

def _vtable(headers: list, rows: list, uid: str, row_class: bool = False, copy_cols: list = None) -> str:
    """row_class=True: each row array's LAST element is a CSS class name for
    that <tr> (e.g. 'row-red'/'row-green') rather than a displayed/searched/
    exported column — used by the XSS 'all tested URLs' table (v8.3) to
    color-code vulnerable vs clean rows. Existing callers never set this and
    never pass a trailing class element, so behavior for them is unchanged.
    copy_cols: v8.5-fix — zero-based column indexes that get a hover-reveal
    per-cell copy button (⧉), so a single URL+payload PoC row can be grabbed
    without selecting text out of a CSS-ellipsis-truncated table cell. The
    cell's FULL (untruncated) value is what gets copied — see vtRender()."""
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
  R['{_e(uid)}']={{raw:{safe},filtered:{safe},page:0,headers:{_safe_json(headers)},rowClass:{str(row_class).lower()},copyCols:{_safe_json(copy_cols or [])}}};
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
def _fmt_dur(sec) -> str:
    try:
        sec = float(sec)
    except (TypeError, ValueError):
        return ""
    if sec <= 0:
        return ""
    if sec < 90:
        return f"{sec:.0f}s"
    minutes = int(sec // 60)
    if minutes < 90:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def _pipeline_timeline(scan_dir) -> str:
    """Stage strip driven by checkpoints/state.json — status and duration,
    not just 'this folder has a file'."""
    steps = [
        (1, "Recon", "🔍"), (2, "Subs", "🌐"), (3, "Alive", "💻"),
        (4, "URLs", "🔗"), (5, "Sort", "📂"), (6, "XSS", "💥"),
        (7, "Templates", "🧨"), (9, "Params", "⚙️"),
        (10, "JS", "🔑"), (11, "Tech", "🧩"), (13, "API", "⚡"),
    ]
    stages = {}
    try:
        p = Path(scan_dir) / "checkpoints" / "state.json"
        if p.exists():
            data = json.loads(p.read_text(errors="ignore")) or {}
            stages = data.get("stages") if isinstance(data.get("stages"), dict) else {}
    except Exception:
        stages = {}
    cls_for = {
        "done": "tl-done", "partial": "tl-partial", "failed": "tl-fail",
        "running": "tl-run", "skipped": "tl-skip",
    }
    tl = '<div class="timeline">'
    for num, lbl, icon in steps:
        rec = stages.get(str(num)) if isinstance(stages.get(str(num)), dict) else {}
        status = str(rec.get("status") or "")
        cls = cls_for.get(status, "tl-skip")
        dur = _fmt_dur(rec.get("duration_sec"))
        if status == "skipped":
            dur = "skip"
        elif status == "running":
            dur = dur or "live"
        tl += (f'<div class="tl-step {cls}"><div class="tl-dot">{icon}</div>'
               f'<div class="tl-lbl">{_e(lbl)}</div>'
               f'<div class="tl-dur">{_e(dur)}</div></div>')
    tl += "</div>"
    return tl


def _retest_btn(url: str) -> str:
    if not url:
        return ""
    return (f'<button class="btn-sm" type="button" data-retest="{_e(url)}" '
            f'onclick="rxRetest(this)">Recheck</button>')


def _priority_where(url: str, extra: str = "") -> str:
    bits = []
    if url:
        bits.append(f'<span style="font-family:var(--mono);word-break:break-all">{_e(url)}</span>')
    if extra:
        bits.append(f'<span style="color:var(--muted)">{_e(extra)}</span>')
    if not bits:
        return '<span style="color:var(--muted)">see section</span>'
    return " ".join(bits)


def _priority_row(sev: str, title: str, url: str, section: str, extra: str = "") -> str:
    return (
        '<tr>'
        f'<td style="padding:7px 10px">{_badge(sev.upper(), {"critical":"red","high":"red","medium":"orange","low":"yellow","info":"gray"}.get(sev,"gray"))}</td>'
        f'<td style="padding:7px 10px;color:var(--text)">{_e(title)}</td>'
        f'<td style="padding:7px 10px">{_priority_where(url, extra)}</td>'
        f'<td style="padding:7px 10px">{_retest_btn(url)}</td>'
        '</tr>')


def _priority_group(icon: str, title: str, section: str, rows: list, cap: int = 8) -> str:
    """One category block. The same finding copied onto every vhost stays one
    row, and a long JS list cannot push XSS off the panel."""
    if not rows:
        return ""
    shown, rest = rows[:cap], rows[cap:]
    head = (
        '<tr><td colspan="4" style="padding:12px 10px 4px">'
        f'<a style="cursor:pointer;color:var(--text);font-weight:700;text-decoration:none" '
        f'onclick="showSection(\'{section}\')">{icon} {_e(title)}</a>'
        f'<span class="nav-cnt" style="margin-left:8px">{len(rows)}</span>'
        '</td></tr>')
    more = ""
    if rest:
        more = (
            '<tr><td colspan="4" style="padding:2px 10px 8px;font-size:12px;color:var(--muted)">'
            f'<a style="cursor:pointer;color:var(--accent2,#8ab4ff)" '
            f'onclick="showSection(\'{section}\')">{len(rest):,} more in this section</a>'
            '</td></tr>')
    return head + "".join(shown) + more


def _priority_panel(nuc, xss, oredir, js) -> str:
    """Grouped short list. Each category is its own block, and a secret that
    shows up in four copies of the same file is one row — not four."""
    blocks = []

    nuc_rows = []
    groups = {}
    for f in (nuc or {}).get("findings") or []:
        sev = str(f.get("severity") or "info").lower()
        key = (sev, f.get("template") or f.get("name") or "", f.get("source") or "template")
        g = groups.setdefault(key, {"n": 0, "url": "", "name": f.get("name") or key[1]})
        g["n"] += 1
        if not g["url"]:
            g["url"] = f.get("matched_at") or ""
    for (sev, _tpl, src), g in sorted(groups.items(), key=lambda kv: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(kv[0][0], 9), kv[0][1])):
        label = g["name"] or _tpl or "template"
        if src == "dast":
            label = f"{label} · DAST"
        extra = f"{g['n']} URLs" if g["n"] > 1 else ""
        nuc_rows.append(_priority_row(sev, label, g["url"], "nuclei", extra))
    blocks.append(_priority_group("🧨", "Template findings", "nuclei", nuc_rows))

    verified = {_DALFOX_TYPE_LABELS["V"], _DALFOX_TYPE_LABELS["RV"]}
    xss_g = {}
    for f in (xss or {}).get("findings") or []:
        url = f.get("url") or ""
        param = f.get("param") or ""
        typ = f.get("type") or "XSS"
        try:
            path = urlparse(url).path or "/"
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            path, host = "/", ""
        g = xss_g.setdefault((typ, param, path), {"url": url, "hosts": set(), "type": typ, "param": param, "path": path})
        if host:
            g["hosts"].add(host)
        if not g["url"]:
            g["url"] = url
    xss_rows = []
    for g in sorted(xss_g.values(), key=lambda x: (0 if x["type"] in verified else 1, x["path"], x["param"])):
        sev = "high" if g["type"] in verified else "medium"
        title = g["type"] or "XSS"
        if g["param"]:
            title = f"{title} · {g['param']}"
        if g["path"] and g["path"] != "/":
            title = f"{title} · {g['path']}"
        n_hosts = len(g["hosts"])
        extra = f"{n_hosts} hosts" if n_hosts > 1 else ""
        xss_rows.append(_priority_row(sev, title, g["url"], "xss", extra))
    blocks.append(_priority_group("💥", "XSS", "xss", xss_rows))

    redir_g = {}
    for f in (oredir or {}).get("findings") or []:
        url = f.get("test_url") or f.get("url") or ""
        param = f.get("param") or "redirect"
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            host = ""
        g = redir_g.setdefault(param, {"url": url, "hosts": set(), "param": param})
        if host:
            g["hosts"].add(host)
        if not g["url"]:
            g["url"] = url
    redir_rows = []
    for g in redir_g.values():
        n_hosts = len(g["hosts"])
        extra = f"{n_hosts} hosts" if n_hosts > 1 else ""
        redir_rows.append(_priority_row("medium", g["param"], g["url"], "openredirect", extra))
    blocks.append(_priority_group("↪️", "Open redirect", "openredirect", redir_rows))

    secret_g = {}
    for d in (js or {}).get("detail") or []:
        if not isinstance(d, dict) or d.get("type") != "secret":
            continue
        if d.get("verdict") not in ("REAL", "UNKNOWN"):
            continue
        value = str(d.get("value") or "")
        reason = str(d.get("verdict_reason") or d.get("name") or d.get("rule") or d.get("verdict") or "secret")
        g = secret_g.setdefault(value or reason, {
            "verdict": d.get("verdict") or "",
            "reason": reason,
            "files": set(),
        })
        src = str(d.get("source_js") or "")
        if src:
            g["files"].add(src)
    js_rows = []
    ordered = sorted(secret_g.values(), key=lambda x: (0 if x["verdict"] == "REAL" else 1, x["reason"]))
    for g in ordered:
        sev = "high" if g["verdict"] == "REAL" else "low"
        files = sorted(g["files"])
        where = files[0] if len(files) == 1 else ""
        extra = f"{len(files)} files" if len(files) > 1 else ""
        js_rows.append(_priority_row(sev, g["reason"], where, "js", extra))
    blocks.append(_priority_group("🔑", "JS secrets", "js", js_rows, cap=12))

    blocks = [b for b in blocks if b]
    if not blocks:
        return ""
    n_findings = len(nuc_rows) + len(xss_rows) + len(redir_rows) + len(js_rows)
    return (
        '<div class="panel" style="margin-bottom:16px">'
        '<div class="panel-header"><span class="panel-icon">🎯</span>'
        f'<h3>Look here first</h3><span style="margin-left:auto;color:var(--muted);font-size:12px">'
        f'{n_findings:,}</span></div>'
        '<div style="overflow:auto"><table style="width:100%;border-collapse:collapse;font-size:12px">'
        '<thead><tr style="text-align:left;color:var(--muted)">'
        '<th style="padding:7px 10px">Severity</th>'
        '<th style="padding:7px 10px">Finding</th><th style="padding:7px 10px">Where</th>'
        '<th style="padding:7px 10px"></th></tr></thead>'
        f'<tbody>{"".join(blocks)}</tbody></table></div></div>')


def _coverage_note(smry) -> str:
    stages = (smry or {}).get("stages") or {}
    bits = []
    targets = (stages.get("stage7") or {}).get("targets") or {}
    if targets.get("capped"):
        bits.append(f"The template scan left out {int(targets['capped']):,} path URLs because a target cap was set")
    dropped = int(targets.get("shape_deduped") or 0)
    if dropped:
        bits.append(f"{dropped:,} URLs collapsed as the same shape (?id=1 and ?id=2)")
    inc = int((stages.get("stage6") or {}).get("targets_incomplete") or 0)
    if inc:
        bits.append(f"{inc:,} XSS URLs did not finish — they are not clean")
    if not bits:
        return ""
    return ('<div class="info-banner info-orange" style="margin-bottom:16px"><span>'
            + " &nbsp;·&nbsp; ".join(_e(b) for b in bits) + "</span></div>")


def _section_overview(target, ts, recon, subs, alive, urls, smry_json,
                      nuc=None, xss=None, js=None, tech=None, extra=None,
                      scan_dir=None, oredir=None):
    nuc = nuc or {}; xss = xss or {}; tech = tech or []; extra = extra or {}
    # One host is often stored twice (http and https). Technology priority is
    # a queue of places to look, not a confirmed issue.
    tech_high_hosts = set()
    for _t in tech:
        if _t.get("risk_label") != "high":
            continue
        try:
            _host = (urlparse(_t.get("url") or "").hostname or "").lower()
        except Exception:
            _host = ""
        if _host:
            tech_high_hosts.add(_host)
    tech_high_n = len(tech_high_hosts)
    sc_n    = len(subs["all"])
    alive_n = len(alive)
    # Total URLs is the unique collected set (All). The live checkpoint is
    # smaller after dead-URL pruning and is its own stat, not the total.
    url_n   = len(urls.get("_collected") or urls.get("_all") or [])
    live_n  = len(urls.get("_all") or [])
    par_n   = len(urls.get("params", []))
    sens_n  = len(urls.get("sensitive", []))
    refl_n  = len(urls.get("reflection", []))
    src_n   = sum(1 for k in _URL_SOURCE_KEYS if urls.get(k))
    if live_n and url_n and live_n != url_n:
        tail_stat = _stat(live_n, "Live URLs", "gray", "📡")
    else:
        tail_stat = _stat(src_n, "URL Sources", "gray", "📡")

    stats_html = "".join([
        _stat(sc_n,    "Subdomains",   "green",  "🌐"),
        _stat(alive_n, "Alive Hosts",  "blue",   "💻"),
        _stat(url_n,   "Total URLs",   "purple", "🔗"),
        _stat(par_n,   "Param URLs",   "orange", "⚙️"),
        _stat(refl_n,  "Reflection",   "yellow", "🪞"),
        _stat(sens_n,  "Sensitive",    "red",    "⚠️"),
        _stat(len(urls.get("api",[])),   "API Endpoints", "cyan",   "⚡"),
        _stat(len(urls.get("admin",[])), "Admin/Login",   "red",    "🔑"),
        tail_stat,
    ])

    extra_stats = []
    if nuc and nuc.get("findings"):
        extra_stats.append(_stat(len(nuc["findings"]), "Template Findings", "red", "🧨"))
    if xss and xss.get("findings"):
        extra_stats.append(_stat(len(xss["findings"]), "XSS Findings", "orange", "💥"))
    if js and js.get("secrets"):
        extra_stats.append(_stat(len(js["secrets"]), "JS Secrets", "purple", "🔑"))
    if tech_high_n:
        extra_stats.append(_stat(tech_high_n, "Tech Priority", "gray", "⚙️"))
    if extra:
        _extra_n = (sum(1 for r in extra.get("cors", []) if r.get("vulnerable")) +
                    sum(1 for r in extra.get("takeover", []) if r.get("vulnerable")) +
                    sum(1 for r in extra.get("buckets", []) if r.get("public_listing")))
        if _extra_n:
            extra_stats.append(_stat(_extra_n, "CORS/Takeover/Bucket", "red", "🛡️"))
    if extra_stats:
        stats_html += "".join(extra_stats)

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
                    f'<span style="width:8px;height:8px;border-radius:50%;background:#067647;display:inline-block"></span>'
                    f'No WAF detected</div></div>')

    block_ratio = (smry_json.get("block_ratio_httpx") or
                   smry_json.get("stages", {}).get("stage3", {}).get("block_ratio") or 0)
    adapt_mult  = smry_json.get("adaptive_multiplier") or 1.0
    def _f(x, default=0.0):
        try: return float(x)
        except Exception: return default
    br = _f(block_ratio); am = _f(adapt_mult, 1.0)
    adapt_html  = ""
    if br > 0.05:
        pct = f"{br*100:.1f}%"
        col = "red" if br > 0.3 else "orange" if br > 0.1 else "yellow"
        adapt_html = (f'<div class="info-banner info-{col}" style="margin-bottom:16px">'
                      f'<span>⚡ Block ratio: <strong>{pct}</strong> · Rate multiplier: <strong>{am:.2f}x</strong></span>'
                      f'</div>')

    # v8.9: checkpoint/resume + scan-delta banners.
    # An interrupted scan must never present itself as a finished one: "0
    # findings" because a stage was cut short is a completely different claim
    # from "0 findings" after the stage ran to the end. SUMMARY.json["resume"]
    # is written by reconX.py's ScanState, ["scan_diff"] by its delta pass.
    resume_meta = smry_json.get("resume") if isinstance(smry_json.get("resume"), dict) else {}
    # Default True so reports from older scans (no "resume" block) stay green.
    incomplete  = not bool(resume_meta.get("completed", True))
    done_stages = list(resume_meta.get("completed_stages") or [])
    state_badge = (_badge("STOPPED EARLY", "orange") if incomplete
                   else _badge("SCAN COMPLETE", "green"))
    resume_html = ""
    if incomplete:
        reason = _e(str(resume_meta.get("interrupt_reason") or "interrupted"))
        done_txt = ", ".join(str(s) for s in done_stages) if done_stages else "none"
        resume_html = (f'<div class="info-banner info-orange" style="margin-bottom:16px">'
                       f'<span>⏸ This scan did not finish every stage '
                       f'(<strong>{reason}</strong>) — stages fully completed: '
                       f'<strong>{_e(done_txt)}</strong>. Anything missing below may simply '
                       f'not have been scanned yet; resume with '
                       f'<code>python3 reconX.py -d {_e(target)} --resume</code>.</span></div>')

    diff_html = ""
    sd = smry_json.get("scan_diff") if isinstance(smry_json.get("scan_diff"), dict) else {}
    sd_sets = sd.get("sets") if isinstance(sd.get("sets"), dict) else {}
    if sd_sets:
        bits = []
        for label, d in sd_sets.items():
            if not isinstance(d, dict):
                continue
            piece = f"{_e(label.replace('_', ' '))} {d.get('previous', 0):,} → {d.get('current', 0):,}"
            if d.get("new"):
                piece += f' <strong class="ink-ok">+{d["new"]:,} new</strong>'
            if d.get("gone"):
                piece += f' <span style="opacity:.7">-{d["gone"]:,} gone</span>'
            bits.append(piece)
        base = ""
        baselines = sd.get("baselines") if isinstance(sd.get("baselines"), dict) else {}
        for _lbl, meta in baselines.items():
            if isinstance(meta, dict) and meta.get("session"):
                base = f" (baseline: <code>{_e(str(meta['session']))}</code>)"
                break
        if bits:
            diff_html = (f'<div class="info-banner info-blue" style="margin-bottom:16px">'
                         f'<span>📈 Delta vs previous scan{base}: '
                         + " &nbsp;·&nbsp; ".join(bits) + '</span></div>')

    tl = _pipeline_timeline(scan_dir) if scan_dir else ""

    # URL kategori bar chart
    cat_data = {
        "params": par_n, "reflection": refl_n,
        "openredirect": len(urls.get("openredirect", [])),
        "sqli": len(urls.get("sqli", [])),
        "admin": len(urls.get("admin",[])),
        "login": len(urls.get("login",[])), "api": len(urls.get("api",[])),
        "sensitive": sens_n, "forms": len(urls.get("forms",[])),
    }
    cat_max = max(cat_data.values()) if any(cat_data.values()) else 1
    cat_colors = {"params":"#fb923c","reflection":"#f87171","openredirect":"#fb923c","sqli":"#ef4444",
                  "admin":"#ef4444",
                  "login":"#facc15","api":"#c084fc","sensitive":"#f87171","forms":"#60a5fa"}
    cat_icons  = {"params":"⚙️","reflection":"🪞","openredirect":"↪️","sqli":"💉","admin":"🔑","login":"🚪","api":"⚡",
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
            mb = _f(ev.get("mult_before", 1.0))
            ma = _f(ev.get("mult_after", 1.0))
            col = "red" if ma < 0.3 else "orange"
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

    # ── v6.13+: Executive risk summary — Nuclei + XSS + Extra-checks + Tech ─────
    sev = nuc.get("severity_counts", {}) if nuc else {}
    crit_n = int(sev.get("critical", 0)); high_n = int(sev.get("high", 0))
    med_n = int(sev.get("medium", 0)); low_n = int(sev.get("low", 0))
    # v8.6-fix: the score used the RAW dalfox finding count for XSS — one
    # reflected search box that echoes 20 payloads counted as 20 * 5 = 100,
    # which alone pushed a Medium-at-most site to "410 CRITICAL". Score the
    # XSS surface by verified findings (heavy) + unique unconfirmed injection
    # points (light).
    _xf = xss.get("findings", []) if xss else []
    _verified_labels = {_DALFOX_TYPE_LABELS["V"], _DALFOX_TYPE_LABELS["RV"]}
    xss_n = len(_xf)
    _verified_keys, _reflected_keys = set(), set()
    for f in _xf:
        try:
            pp = urlparse(f.get("url") or "")
            key = (pp.netloc, pp.path, f.get("param") or "")
        except Exception:
            key = ("", "", f.get("param") or "")
        if f.get("type") in _verified_labels:
            _verified_keys.add(key)
        else:
            _reflected_keys.add(key)
    _reflected_keys -= _verified_keys
    xss_verified_points = len(_verified_keys) or (1 if any(f.get("type") in _verified_labels for f in _xf) else 0)
    xss_reflected_points = len(_reflected_keys)
    cors_n = sum(1 for r in extra.get("cors", []) if r.get("vulnerable"))
    take_n = sum(1 for r in extra.get("takeover", []) if r.get("vulnerable"))
    bucket_n = sum(1 for r in extra.get("buckets", []) if r.get("public_listing"))
    extra_vuln_n = cors_n + take_n + bucket_n
    oredir_n = len((oredir or {}).get("findings") or [])
    # Label is the highest finding class. The number never promotes a class:
    # two verified XSS findings used to score 40 and the gauge said CRITICAL.
    # Recon (URLs, hosts, technology) adds nothing. Critical is RCE / SQLi
    # class templates only. XSS stays high, open redirect and CORS stay medium.
    risk_score = (crit_n * 12
                  + (high_n + xss_verified_points + take_n + bucket_n) * 6
                  + (med_n + xss_reflected_points + oredir_n + cors_n) * 3
                  + low_n)
    if crit_n:
        risk_lvl, risk_cls = "CRITICAL", "risk-critical"
    elif high_n or xss_verified_points or take_n or bucket_n:
        risk_lvl, risk_cls = "HIGH", "risk-high"
    elif med_n or xss_reflected_points or oredir_n or cors_n:
        risk_lvl, risk_cls = "MEDIUM", "risk-medium"
    elif low_n:
        risk_lvl, risk_cls = "LOW", "risk-low"
    else:
        risk_lvl, risk_cls = "NONE", "risk-none"
    # v8.1: dairesel risk göstergesi — .risk-gauge/.risk-gauge-circle CSS'i daha
    # önce tanımlıydı ama hiç kullanılmıyordu. risk_score'u bir SVG halkaya
    # çeviriyoruz (60+ skor = halka tam dolu kabul edilir).
    _RING_R = 30.0
    _RING_C = 2 * 3.14159265 * _RING_R
    gauge_pct = max(0.0, min(1.0, risk_score / 60.0)) if risk_score > 0 else 0.0
    gauge_offset = _RING_C * (1 - gauge_pct)
    risk_gauge_svg = f'''<svg width="72" height="72" viewBox="0 0 72 72">
    <circle class="risk-ring-track" cx="36" cy="36" r="{_RING_R}" fill="none" stroke-width="8"/>
    <circle class="risk-ring" cx="36" cy="36" r="{_RING_R}" fill="none" stroke-width="8"
            stroke-linecap="round" stroke-dasharray="{_RING_C:.2f}" stroke-dashoffset="{gauge_offset:.2f}"/>
  </svg>'''
    exec_html = f'''<div class="panel risk-panel {risk_cls}">
  <div class="risk-gauge" style="background:transparent;border:none;padding:0;margin-bottom:0">
    <div class="risk-gauge-circle">
      {risk_gauge_svg}
      <div class="risk-score-num">{risk_score}</div>
    </div>
    <div class="risk-gauge-label">
      <strong>{_e(risk_lvl)}</strong>
      <span class="risk-pct">&nbsp;&middot; risk score {risk_score} / 60+</span>
      <div style="font-size:12px;color:var(--muted);margin-top:4px">
        {('No Scan Center findings yet. URLs, hosts, and technology do not change this score.<br>' if risk_lvl == 'NONE' else '')}
        Templates: {crit_n} critical &middot; {high_n} high &middot; {med_n} medium &middot; {low_n} low &nbsp;|&nbsp;
        XSS: {xss_n} &nbsp;|&nbsp; CORS/Takeover/Bucket: {extra_vuln_n} &nbsp;|&nbsp;
        Open redirect: {oredir_n}
        {f' &nbsp;|&nbsp; Tech priority: {tech_high_n} host(s) — not a finding' if tech_high_n else ''}
      </div>
    </div>
  </div>
</div>'''

    return f'''
<div id="s-overview" class="section active">
  <div class="sec-hdr">
    <div class="sec-hdr-inner">
      <div>
        <h2>Dashboard</h2>
        <p class="sec-sub">Target: <code class="target-code">{_e(target)}</code> &nbsp;·&nbsp; {_e(ts)}</p>
      </div>
      <div class="sec-hdr-badge">{state_badge}</div>
    </div>
  </div>
  {exec_html}
  {resume_html}
  {diff_html}
  {adapt_html}
  {_coverage_note(smry_json)}
  {_priority_panel(nuc, xss, oredir, js)}
  <div class="stat-grid">{stats_html}</div>

  <div class="panel panel-pipeline" style="margin-top:20px">
    <div class="panel-header"><span class="panel-icon">🚀</span><h3>Pipeline Status</h3></div>
    {tl}
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
                      f'<div class="probe-row"><span>WAF</span><b>{_e(waf)}</b></div>'
                      f'</div>')
    items = [
        ("probe",   "HTTP Probe", probe_html or _empty("Probe data not available")),
        ("whois",   "Registration", _code_block(recon["whois"])),
        ("nmap",    "Service detection", _code_block(recon["nmap"])),
        ("whatweb", "Technology fingerprint", _code_block(recon["whatweb"])),
        ("waf",     "WAF detection", _code_block(recon["wafw00f"])),
        ("harvest", "Passive OSINT", _code_block(recon["harvester"])),
    ]
    tab_items = [(tid, lbl, c) for tid, lbl, c in items if c != _empty()]
    body = _tabs(tab_items, "recon") if tab_items else _empty()
    return (f'<div id="s-recon" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div><h2>Reconnaissance</h2></div></div></div>'
            f'{body}</div>')


# ── Section: Subdomains ───────────────────────────────────────────────────────
def _section_subdomains(subs):
    all_s = subs["all"]
    grouped = {}
    for stem, hosts in (subs.get("by_tool") or {}).items():
        label = public_activity(stem)
        bucket = grouped.setdefault(label, [])
        for host in hosts:
            if host not in bucket:
                bucket.append(host)
    tool_rows = sorted(
        [[label, str(len(hosts)), "; ".join(hosts[:3]) + ("…" if len(hosts) > 3 else "")]
         for label, hosts in grouped.items() if hosts],
        key=lambda r: -int(r[1])
    )
    body = (f'{_vscroll(all_s, "vs-subs", "subdomain", "the saved subdomain list")}'
            f'<div style="margin-top:28px"><div class="subsection-label">Discovery sources</div>'
            f'{_vtable(["Work", "Count", "Sample"], tool_rows, "vt-sub-tools")}</div>'
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

    sc_colors = {"2xx": "#067647", "3xx": "#1e4d73", "4xx": "#854d0e", "5xx": "#b42318"}
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

    # v8.1: settings.enable_screenshots=true ile httpx her host icin ekran
    # goruntusu topluyorsa, buradaki kucuk galeri hizli gorsel triage sagliyor.
    # Ozellik kapaliysa (varsayilan) hicbir host'ta "shot" olmaz ve bu blok
    # sessizce atlanir.
    shots = [h for h in alive if h.get("shot", "").startswith("03_alive/screenshots/")]
    gallery_html = ""
    if shots:
        tiles = "".join(
            f'<a class="shot-tile" href="{_e(h["shot"])}" target="_blank" rel="noopener" title="{_e(h["url"])}">'
            f'<img src="{_e(h["shot"])}" loading="lazy" alt="{_e(h["url"])}">'
            f'<span class="shot-cap">{_e(h["url"][:44])}</span></a>'
            for h in shots
        )
        gallery_html = (f'<div class="subsection-label" style="margin:16px 0 8px">'
                         f'Screenshots <span style="color:var(--muted);font-weight:400">'
                         f'({len(shots):,} of {len(alive):,} hosts)</span></div>'
                         f'<div class="shot-grid">{tiles}</div>')

    return f'''<div id="s-alive" class="section">
  <div class="sec-hdr"><div class="sec-hdr-inner"><div>
    <h2>Alive Hosts</h2>
    <p class="sec-sub">{len(alive):,} responsive hosts</p>
  </div></div></div>
  <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">{sc_pills}</div>
  {gallery_html}
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
def _section_urls(urls, prune=None):
    collected = urls.get("_collected") or urls.get("_all") or []
    live = urls.get("_all") or []
    prune = prune or {}
    show_live = bool(live) and len(live) != len(collected)
    raw_counts = urls.get("_raw_counts") or {}
    tool_tabs = [
        ("all",          f"All ({len(collected):,})",                             collected),
        ("live",         f"Live ({len(live):,})",                                 live if show_live else []),
        ("gau",          f"Historical URLs ({len(urls.get('_gau',[])):,})",          urls.get("_gau",[])),
        ("wayback",      f"Archive URLs ({len(urls.get('_wayback',[])):,})",       urls.get("_wayback",[])),
        ("katana",       f"Deep URL discovery ({len(urls.get('_katana',[])):,})",  urls.get("_katana",[])),
        ("hakrawler",    f"Crawl URLs ({len(urls.get('_hakrawler',[])):,})",       urls.get("_hakrawler",[])),
        ("gospider",     f"Spider URLs ({len(urls.get('_gospider',[])):,})",       urls.get("_gospider",[])),
        ("commoncrawl",  f"Common crawl URLs ({len(urls.get('_commoncrawl',[])):,})", urls.get("_commoncrawl",[])),
        ("urlscan",      f"Indexed URLs ({len(urls.get('_urlscan',[])):,})",       urls.get("_urlscan",[])),
        ("otx",          f"Threat-intel URLs ({len(urls.get('_otx',[])):,})",      urls.get("_otx",[])),
    ]
    _url_src = {"all": "the saved URL list",
                "live": "the live URL list",
                "gau": "Historical URL discovery",
                "katana": "Deep URL discovery", "wayback": "Archive URL discovery",
                "commoncrawl": "Common crawl URLs", "urlscan": "Indexed URLs",
                "otx": "Threat-intel URLs", "gospider": "Deep URL discovery",
                "hakrawler": "Deep URL discovery"}
    tab_items = [(tid, label, _vscroll(data, f"vs-url-{tid}", "URL", _url_src.get(tid, "")))
                 for tid, label, data in tool_tabs if data]
    n_sources = sum(1 for tid, _, data in tool_tabs if data and tid not in ("all", "live"))

    dropped_bits = []
    for key, label in (("_gau", "Historical URL discovery"), ("_katana", "Deep URL discovery"),
                       ("_wayback", "Archive URL discovery"),
                       ("_hakrawler", "Crawl URL discovery"), ("_gospider", "Spider URL discovery"),
                       ("_commoncrawl", "Common crawl"), ("_urlscan", "Indexed URL discovery"),
                       ("_otx", "Threat-intel URL discovery")):
        raw_n = int(raw_counts.get(key) or 0)
        kept = len(urls.get(key) or [])
        if raw_n > kept:
            dropped_bits.append(
                f"{label} wrote {raw_n:,} lines; {kept:,} are unique URLs in All"
            )
    account = ("All is the unique in-scope set (each URL once). "
               "A source tab lists only URLs from that pass that are also in All, "
               "so a source cannot be larger than All.")
    if dropped_bits:
        account += " " + ". ".join(dropped_bits) + "."
    account_html = (f'<div style="font-size:11px;color:var(--muted);margin-bottom:14px;padding:8px 12px;'
                    f'background:var(--surface2);border-radius:6px;border-left:3px solid var(--border)">'
                    f'{_e(account)}</div>')

    note = ""
    if prune.get("rejected"):
        # reconX.py refused to trust this prune (it removed so much of the
        # corpus that the target was almost certainly throttling the probe).
        # Say so where the numbers are read, not just in the scan log.
        note = (f'<div class="info-banner info-orange" style="margin-bottom:14px">'
                f'<span>⚠ Dead-URL pruning was <strong>discarded</strong>: it reported '
                f'{prune.get("removed",0):,} of {prune.get("before",0):,} URLs '
                f'({prune.get("removed_pct",0)}%) as dead. '
                f'{_e(prune.get("reject_reason") or "The target most likely rate-limited the liveness probe.")} '
                f'The <strong>All</strong> tab is the full unpruned list, so it may include '
                f'dead/404 URLs. Lower <code>settings.threads</code> or set '
                f'<code>settings.prune_dead_urls: false</code> if this repeats.</span></div>')
    elif prune.get("enabled"):
        if prune.get("ran") and prune.get("removed", 0) > 0:
            why = ""
            if prune.get("trusted_high_removal") and prune.get("trust_reason"):
                why = f' {_e(prune.get("trust_reason"))}.'
            live_where = ("The <strong>Live</strong> tab is that shorter list. "
                          "<strong>All</strong> stays the unique set from every source.")
            note = (f'<div style="font-size:11px;color:var(--muted);margin-bottom:14px;padding:8px 12px;'
                    f'background:var(--surface2);border-radius:6px;border-left:3px solid var(--border)">'
                    f'✓ Dead-URL pruning: {prune.get("before",0):,} URLs collected &rarr; '
                    f'<strong style="color:var(--text-dim)">{prune.get("removed",0):,} removed</strong> '
                    f'(filtered: {_e(prune.get("filter_codes","404"))} or unreachable) &rarr; '
                    f'{prune.get("after",0):,} live. {live_where}{why} '
                    f'<span style="opacity:.7">(settings.prune_dead_urls in config.yaml)</span></div>')
        elif not prune.get("ran"):
            note = (f'<div style="font-size:11px;color:var(--muted);margin-bottom:14px;padding:8px 12px;'
                    f'background:var(--surface2);border-radius:6px;border-left:3px solid var(--border)">'
                    f'⚠ Dead-URL pruning was enabled but did not run (HTTP probing was unavailable) — '
                    f'All may include dead/404 URLs.</div>')
    else:
        note = (f'<div style="font-size:11px;color:var(--muted);margin-bottom:14px;padding:8px 12px;'
                f'background:var(--surface2);border-radius:6px;border-left:3px solid var(--border)">'
                f'Dead-URL pruning is disabled (tools.prune_dead_urls: false in config.yaml) — '
                f'All may include dead/404 URLs.</div>')

    live_bit = f" · {len(live):,} live" if show_live else ""
    body = account_html + note + (_tabs(tab_items, "url") if tab_items else _empty())
    return (f'<div id="s-urls" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>URL Discovery</h2>'
            f'<p class="sec-sub">{len(collected):,} unique URLs · {n_sources} sources{live_bit}</p>'
            f'</div></div></div>{body}</div>')


def _section_proxy(urls) -> str:
    """Burp-style history of the live URL list. The rows reuse the URL list
    already embedded for URL Discovery, so this section does not copy it."""
    live = urls.get("_all") or urls.get("_collected") or []
    n = len(live)
    return (
        f'<div id="s-proxy" class="section">'
        f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
        f'<h2>Proxy</h2>'
        f'<p class="sec-sub">{n:,} live URLs · click one for the request and response</p>'
        f'</div></div></div>'
        f'<div class="proxy-split">'
        f'<div class="vs-wrap"><div class="vs-toolbar">'
        f'<span class="vs-counter" id="vs-proxy-cnt"></span>'
        f'<input class="vs-search" id="vs-proxy-q" placeholder="Filter URLs..." oninput="vsFilter(\'vs-proxy\')">'
        f'</div>'
        f'<div class="vs-scroll" id="vs-proxy-scroll" onscroll="vsRender(\'vs-proxy\')">'
        f'<div class="vs-vp" id="vs-proxy-vp"></div></div></div>'
        f'<div class="proxy-pane">'
        f'<div class="proxy-hd" style="font-weight:700">Request <span id="proxy-url" style="font-weight:500;color:var(--muted)"></span></div>'
        f'<pre id="proxy-req" class="proxy-pre">Select a URL on the left.</pre>'
        f'<div class="proxy-hd" style="font-weight:700">Response</div>'
        f'<pre id="proxy-res" class="proxy-pre"></pre>'
        f'</div></div></div>')


# ── Section: Categorised ──────────────────────────────────────────────────────
def _section_categorised(urls):
    base_cats = [
        ("reflection",   "🪞 XSS",          "red",    "Reflected, DOM and stored candidates. One URL per parameter."),
        ("openredirect", "↪️ Open redirect", "orange", "Redirect parameters, one URL each. These are not sent to the XSS scan."),
        ("sqli",         "💉 SQLi",          "red",    "One URL per parameter that looks like a query, or a URL that already shows a SQL error."),
        ("params",       "⚙️ Params",       "orange", "All URLs with query strings"),
        ("sensitive",  "⚠️ Sensitive",  "red",    ".env · .git · backups · credentials"),
        ("admin",      "🔑 Admin",      "red",    "Admin/dashboard/management panels"),
        ("login",      "🚪 Login",      "yellow", "Authentication & SSO endpoints"),
        ("api",        "⚡ API",        "purple", "REST · GraphQL · RPC · webhooks"),
        ("forms",      "📝 Forms",      "blue",   "PHP · ASP · JSP form handlers"),
        ("other",      "📄 Other",      "gray",   "Uncategorised"),
    ]
    vuln_cats = [
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

def _asset_lookup(target, alive, recon, network, vuln_map):
    """Per-host footprint for the map tooltip: IP, WAF, server, tech, ports, risk."""
    recon = recon or {}
    network = network or {}
    vuln_map = vuln_map or {}
    apex = (target or "").strip().lower()
    probe = recon.get("probe") or {}
    waf_map = _waf_by_host(recon.get("wafw00f") or "", apex, probe.get("waf_fingerprint") or [])
    ww = _whatweb_bits(recon.get("whatweb") or "")
    ww_hosts = _whatweb_by_host(recon.get("whatweb_hosts") or "")
    ports_by = {}
    for h in (network.get("hosts") or []):
        name = str(h.get("host") or "").lower()
        bits = []
        for pt in (h.get("ports") or []):
            if not isinstance(pt, dict):
                continue
            svc = str(pt.get("service") or "").strip()
            label = f"{pt.get('port')}/{pt.get('proto') or 'tcp'}"
            if svc and svc not in ("unknown",):
                label = f"{label} {svc}"
            bits.append(label)
        if name:
            ports_by[name] = bits[:8]
    if apex and apex not in ports_by:
        nmap_bits = []
        for pt in _nmap_ports(recon.get("nmap") or ""):
            svc = str(pt.get("service") or "").strip()
            label = f"{pt.get('port')}/{pt.get('proto') or 'tcp'}"
            if svc:
                label = f"{label} {svc}"
            nmap_bits.append(label)
        if nmap_bits:
            ports_by[apex] = nmap_bits[:8]
    alive_by = {}
    for h in alive or []:
        try:
            name = (urlparse(h.get("url") or "").hostname or "").lower()
        except Exception:
            name = ""
        if name and name not in alive_by:
            alive_by[name] = h

    def lookup(host, is_alive):
        host = (host or "").strip().lower()
        rec = alive_by.get(host) or {}
        tech = []
        for part in str(rec.get("tech") or "").split(","):
            label = part.strip()
            if label and label not in tech:
                tech.append(label)
        for label in (ww_hosts.get(host) or []):
            if label and label not in tech:
                tech.append(label)
        if host == apex:
            for label in (ww.get("techs") or []):
                if label and label not in tech:
                    tech.append(label)
        waf_names = list(waf_map.get(host) or [])
        points = int((vuln_map.get(host) or {}).get("points") or 0)
        base = 16 if is_alive else 6
        exposed = 8 if is_alive and not waf_names else 0
        score = min(100, base + points + exposed)
        return {
            "ip": rec.get("ip") or (probe.get("ip") if host == apex else "") or "",
            "waf": waf_names[0] if waf_names else "",
            "server": rec.get("server") or (probe.get("server") if host == apex else "") or "",
            "tech": tech[:8],
            "ports": list(ports_by.get(host) or [])[:8],
            "score": score,
            "title": rec.get("title") or "",
        }
    return lookup


def _section_threatmap(target: str, subs: dict, alive: list, vuln_map: dict = None,
                       recon=None, network=None) -> str:
    all_subs  = subs.get("all", [])
    alive_set = set()
    for h in alive:
        u = h.get("url","")
        try:
            alive_set.add(urlparse(u).hostname or "")
        except:
            pass

    # v6.13+: gercek Nuclei/XSS/Extra-checks bulgularindan uretilen host->severity
    # haritasi. Daha once bu her zaman bos birakiliyordu; harita hep notr renkte
    # goruniyordu. Artik zafiyetli subdomain'ler kirmizi/turuncu olarak isaretleniyor.
    vuln_map = vuln_map or {}
    _root_hit = vuln_map.get(target) or {}

    MAX_DIRECT = 300
    nodes = [{"id": target, "type": "root", "label": target,
               "alive": True,
               "severity": _root_hit.get("severity", "none"),
               "vuln_count": _root_hit.get("count", 0)}]
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

    lookup = _asset_lookup(target, alive, recon, network, vuln_map)
    by_id = {}
    for n in nodes:
        if n.get("type") in ("root", "subdomain"):
            n.update(lookup(n["id"], bool(n.get("alive"))))
        by_id[n["id"]] = n
    for n in nodes:
        if n.get("type") != "group":
            continue
        scores = [int((by_id.get(l.get("target")) or {}).get("score") or 0)
                  for l in links if l.get("source") == n["id"]]
        n["score"] = max(scores) if scores else 0
    for l in links:
        tgt = by_id.get(l.get("target")) or {}
        l["crit"] = int(tgt.get("score") or 0) >= 80

    graph_json = _safe_json({"nodes": nodes, "links": links,
                              "total_subs": len(all_subs), "rendered": len(nodes),
                              "target": target})

    return f'''<div id="s-threatmap" class="section">
  <div class="sec-hdr"><div class="sec-hdr-inner"><div>
    <h2>Threat Map</h2>
    <p class="sec-sub">{len(all_subs):,} subdomains · {len(alive_set):,} alive · {len(nodes):,} nodes · drag, scroll, hover a host for IP, WAF, technology and ports</p>
  </div></div></div>
  <div class="tm-legend">
    <span class="tm-leg-item"><span class="tm-dot" style="background:#ff4d5e"></span>Critical</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#ff9838"></span>High</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#ffcf3f"></span>Medium</span>
    <span class="tm-leg-item"><span class="tm-dot" style="background:#39d98a"></span>Low</span>
    <span class="tm-leg-item">node size = risk · ⛉ = WAF</span>
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
    // v8.1-fix: the map used to force-init on DOMContentLoaded, before the user
    // ever opened this tab. At that point the .section is display:none, so the
    // SVG measured 0x0, the simulation rendered nothing, and _TM.initialized
    // was left true — meaning showSection()'s lazy re-init never ran either.
    // Data is stashed here; the actual d3 init now happens lazily, only once
    // the Threat Map tab is actually visible (see showSection()/tm nav click).
    window._TM_DATA = {graph_json};
  }})();
  </script>
</div>'''


# ── Section: Nuclei ──────────────────────────────────────────────────────────

def _parse_api(d) -> dict:
    d = Path(d)
    jf = d / "13_api" / "api_discovery.json"
    if jf.exists():
        try:
            data = json.loads(jf.read_text(errors="ignore")) or {}
            return {"found": data.get("found") or {}, "probes": data.get("probes") or [],
                    "live_hits": data.get("live_hits") or [], "ran": True}
        except Exception:
            pass
    return {"found": {}, "probes": [], "live_hits": [], "ran": False}

def _section_api(api_data):
    found = api_data.get("found") or {}
    probes = api_data.get("probes") or []
    live_hits = api_data.get("live_hits") or []
    total_hits = sum(len(v) for v in found.values())
    if total_hits == 0 and not probes and not live_hits:
        if not api_data.get("ran"):
            msg = ("Not scanned yet. Run <strong>API Discovery</strong> from the Scan Center "
                   "once the URL corpus is in this report.")
        else:
            msg = "Scanned — no GraphQL, Swagger or OpenAPI endpoints in the collected URLs."
        return (f'<div id="s-api" class="section">'
                f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
                f'<h2>API Discovery</h2>'
                f'<p class="sec-sub">{"not scanned yet" if not api_data.get("ran") else "0 hits"}</p>'
                f'</div></div></div>'
                f'<div class="cat-desc">{msg}</div></div>')
    live_html = ""
    if live_hits:
        lrows = [[h.get("url", ""), str(h.get("status", "")),
                  h.get("kind", ""), (h.get("content_type") or "")[:40],
                  (h.get("snippet") or "")[:200]]
                 for h in live_hits]
        live_html = ('<div class="alert-box alert-red" style="margin-bottom:14px">'
                     f'<b>{len(live_hits)} live API endpoint(s) confirmed</b> — exposed schema / '
                     'introspectable GraphQL. Verify what they leak and whether auth is required.</div>'
                     + _vtable(["URL", "Status", "Kind", "Content-Type", "Snippet"], lrows, "vt-api-live",
                               copy_cols=[0]))
    # stats
    stat_html = "".join([
        _stat(len(live_hits), "Live Endpoints", "red" if live_hits else "gray", "✅"),
        _stat(len(found.get("graphql",[])), "GraphQL", "purple", "⚡"),
        _stat(len(found.get("swagger",[])), "Swagger", "blue", "📜"),
        _stat(len(found.get("openapi",[])), "OpenAPI", "cyan", "🔗"),
        _stat(len(probes), "Probed", "gray", "🎯"),
    ])
    tabs=[]
    for key,label in [("graphql","GraphQL"),("swagger","Swagger"),("openapi","OpenAPI"),("api_versioned","Versioned API"),("api_v","API /v*")]:
        data = found.get(key,[])
        if data:
            tabs.append((key, f"{label} ({len(data)})", _vscroll(data, f"vs-api-{key}", label)))
    if probes:
        tabs.append(("probes", f"Probes ({len(probes)})", _vscroll(probes, "vs-api-probes", "probe")))
    body = f'<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">{stat_html}</div>'
    body += live_html
    body += _tabs(tabs, "api") if tabs else _empty()
    return (f'<div id="s-api" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div><h2>API Discovery</h2>'
            f'<p class="sec-sub">{len(live_hits)} live · {total_hits} pattern hits · {len(probes)} probed — GraphQL / Swagger / OpenAPI</p>'
            f'</div></div></div>{body}</div>')

def _section_nuclei(nuc):
    findings = nuc.get("findings", [])
    sev = nuc.get("severity_counts", {})
    meta = nuc.get("meta", {})
    tool_failed = bool(meta.get("tool_failed"))
    interrupted = bool(meta.get("interrupted")) and not tool_failed
    ran = bool(meta.get("ran"))
    risk_label, risk_color = _risk_level_from_severity(sev)

    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_color = {"critical": "red", "high": "red", "medium": "orange",
                 "low": "yellow", "info": "gray"}
    # Always print every severity the scan records, including a zero. A run
    # that only matched "high" used to hide critical/medium/low entirely.
    badges = " ".join(_badge(f"{s.upper()} {int(sev.get(s, 0) or 0)}", sev_color.get(s, "gray"))
                      for s in sev_order)

    body = ""
    if tool_failed:
        body += (f'<div class="alert-box alert-red" style="margin-bottom:14px">'
                 f'⚠ <strong>The template scan exited with an error:</strong>&nbsp;{_e(meta.get("tool_error",""))} '
                 f'— this does NOT necessarily mean the target is clean; the scan may not have completed.</div>')
    elif interrupted:
        body += (f'<div class="alert-box info-orange" style="margin-bottom:14px">'
                 f'⚠ <strong>Scan was interrupted (Ctrl+C):</strong>&nbsp;{_e(meta.get("tool_error","") or "not all targets/templates were tested")}</div>')

    # v6.17: RISK badge is always shown, in place of any "no findings" wording,
    # and scan context (duration, target count, severity filter, tags) is
    # always visible — a completed 0-finding scan should never look like it
    # "did not run".
    stat_row = [_stat(len(findings), "Findings", "red", "🧨"),
                _stat(risk_label, "Risk Level", risk_color, "🎯")]
    if meta.get("findings_dast"):
        stat_row.append(_stat(meta["findings_dast"], "DAST / fuzzing", "orange", "💉"))
    body += (f'<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;'
            f'margin-bottom:14px">{"".join(stat_row)}{" " + badges if badges else ""}</div>')
    body += ('<div class="cat-desc" style="margin-bottom:16px">'
             'Template vulnerability scan over the full live URL corpus '
             '(alive host roots + every live URL found by the crawl)</div>')

    if ran:
        parts = [f"status: {_e(meta.get('status',''))}"]
        if meta.get("duration_sec"):
            parts.append(f"duration: {meta['duration_sec']}s")
        if meta.get("targets_count"):
            parts.append(f"targets: {meta['targets_count']:,}")
        parts.append(f"severity filter: {_e(meta.get('severity_filter','none'))}")
        if meta.get("tags_used"):
            parts.append(f"fastpass tags: {_e(meta['tags_used'])}")
        if meta.get("template_path"):
            parts.append(f"templates: {_e(str(meta['template_path']))}")
        body += (f'<div style="font-size:11px;color:var(--muted);margin:6px 0 12px">'
                 f'{" &middot; ".join(parts)}</div>')

    if findings:
        # v8.1: CVE/CVSS/tags artik nuclei'nin kendi info.classification blogundan
        # gerekten okunuyor (bkz. _parse_nuclei) — tabloya ekleniyor.
        # One table per severity so a long high list cannot push medium and
        # low off the first screen.
        grouped = {s: [] for s in sev_order}
        other = []
        for f in findings:
            s = str(f.get("severity") or "info").lower()
            (grouped[s] if s in grouped else other).append(f)
        def _nuc_table(items, uid):
            groups = {}
            for f in items:
                key = (f.get("template") or f.get("name") or "", f.get("source") or "template")
                g = groups.setdefault(key, {"n": 0, "f": f, "urls": []})
                g["n"] += 1
                if f.get("matched_at"):
                    g["urls"].append(f["matched_at"])
            trs = []
            for (_tpl, src), g in groups.items():
                f = g["f"]
                example = g["urls"][0] if g["urls"] else ""
                extra_n = f" <span style='color:var(--muted)'>+{g['n'] - 1}</span>" if g["n"] > 1 else ""
                trs.append(
                    '<tr>'
                    f'<td style="padding:8px 10px">{_e((f.get("severity") or "info").upper())}</td>'
                    f'<td style="padding:8px 10px">{_e("DAST" if src == "dast" else "tpl")}</td>'
                    f'<td style="padding:8px 10px;color:var(--text)">{_e((f.get("name") or "")[:80])}</td>'
                    f'<td style="padding:8px 10px;font-family:var(--mono);word-break:break-all">{_e(example[:180])}{extra_n}</td>'
                    f'<td style="padding:8px 10px;font-family:var(--mono)">{_e((f.get("template") or "")[:60])}</td>'
                    f'<td style="padding:8px 10px">{g["n"]}</td>'
                    f'<td style="padding:8px 10px">{_retest_btn(example)}</td>'
                    '</tr>')
            return (
                f'<div style="overflow:auto" id="{_e(uid)}"><table style="width:100%;border-collapse:collapse;font-size:12px">'
                '<thead><tr style="text-align:left;color:var(--muted)">'
                '<th style="padding:8px 10px">Severity</th><th style="padding:8px 10px">Source</th>'
                '<th style="padding:8px 10px">Name</th><th style="padding:8px 10px">Example</th>'
                '<th style="padding:8px 10px">Template</th><th style="padding:8px 10px">Hits</th>'
                '<th style="padding:8px 10px"></th></tr></thead>'
                f'<tbody>{"".join(trs)}</tbody></table></div>')

        for s in sev_order:
            items = grouped[s]
            if not items:
                continue
            n_groups = len({(f.get("template") or f.get("name") or "", f.get("source") or "") for f in items})
            body += (f'<div class="subsection-label" style="margin-top:16px">'
                     f'{_e(s.upper())} &middot; {len(items):,} hits &middot; {n_groups:,} templates</div>')
            body += _nuc_table(items, f"nuc-{s}")
        if other:
            body += (f'<div class="subsection-label" style="margin-top:16px">'
                     f'OTHER &middot; {len(other):,}</div>')
            body += _nuc_table(other, "nuc-other")
        cve_n = sum(1 for f in findings if f.get("cve"))
        if cve_n:
            body += (f'<div style="font-size:11px;color:var(--muted);margin-top:8px">'
                     f'{cve_n:,} finding(s) map to a known CVE — cross-reference with '
                     f'<a href="https://nvd.nist.gov/vuln/search" target="_blank" rel="noopener" '
                     f'style="color:var(--accent2)">NVD</a> for exploit/patch details.</div>')
    elif ran:
        body += _empty("Scan completed — 0 findings.")
    else:
        body += _empty("Template scan not run.")

    raw_txt = (nuc.get("raw_txt") or "").strip()
    if raw_txt:
        body += (f'<div class="subsection-label" style="margin-top:20px">Collected output</div>'
                 f'<details><summary style="cursor:pointer;color:var(--muted);font-size:12px;'
                 f'margin-bottom:8px">Show the scanner text output ({len(raw_txt.splitlines()):,} lines)</summary>'
                 f'{_code_block(raw_txt)}</details>')

    return (f'<div id="s-nuclei" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>Template Scan</h2>'
            f'<p class="sec-sub">{len(findings):,} findings &middot; RISK: {risk_label}</p>'
            f'</div></div></div>{body}</div>')


# ── Section: XSS ─────────────────────────────────────────────────────────────
def _section_xss(xss):
    findings = xss.get("findings", [])
    meta = xss.get("meta", {})
    tool_failed = bool(meta.get("tool_failed"))
    budget_hit = bool(meta.get("budget_hit")) and not tool_failed
    interrupted = bool(meta.get("interrupted")) and not tool_failed and not budget_hit
    ran = bool(meta.get("ran"))
    _verified = {_DALFOX_TYPE_LABELS["V"], _DALFOX_TYPE_LABELS["RV"]}
    if any(f.get("type") in _verified for f in findings):
        risk_label, risk_color = "HIGH", "red"
    elif findings:
        risk_label, risk_color = "MEDIUM", "orange"
    else:
        risk_label, risk_color = "NONE", "green"

    # v8.5-fix: sort so the genuinely-confirmed findings (dalfox's own "V", or
    # ReconX's own replay-confirmed "RV") lead the table, "Reflected" (payload
    # echoed back but never confirmed to execute) after, weaker "Grep match"
    # last — requested directly: most of a real scan's raw findings turned
    # out to be unconfirmed text matches, and the confirmed ones were getting
    # lost in the noise at whatever position dalfox happened to report them.
    _TYPE_RANK = {_DALFOX_TYPE_LABELS["V"]: 0, _DALFOX_TYPE_LABELS["RV"]: 0,
                  _DALFOX_TYPE_LABELS["R"]: 1, _DALFOX_TYPE_LABELS["G"]: 2}
    findings = sorted(findings, key=lambda f: _TYPE_RANK.get(f.get("type", ""), 1))

    _dialog_urls = {s.get("url") for s in (meta.get("screenshots") or [])
                    if (s.get("dialog_confirmed") or s.get("confirmed_upgrade")) and s.get("url")}
    dialog_n = sum(1 for f in findings if f.get("type") == _DALFOX_TYPE_LABELS["RV"] or f.get("url") in _dialog_urls)
    scanner_n = sum(1 for f in findings if f.get("type") == _DALFOX_TYPE_LABELS["V"] and f.get("url") not in _dialog_urls)
    unconfirmed_n = len(findings) - dialog_n - scanner_n

    body = ""
    if tool_failed:
        body += (f'<div class="alert-box alert-red" style="margin-bottom:14px">'
                 f'⚠ <strong>XSS testing exited with an error:</strong>&nbsp;{_e(meta.get("tool_error",""))} '
                 f'— this does NOT necessarily mean the target is clean; the scan may not have completed.</div>')
    elif budget_hit:
        body += (f'<div class="alert-box info-blue" style="margin-bottom:14px">'
                 f'ℹ <strong>XSS testing reached its time budget and was stopped.</strong>&nbsp;'
                 f'Findings written so far are complete and kept (dalfox streams them to disk), '
                 f'but not every target was necessarily finished — raise '
                 f'<code>tools.dalfox_time_budget_sec</code> for full coverage.</div>')
    elif interrupted:
        body += (f'<div class="alert-box info-orange" style="margin-bottom:14px">'
                 f'⚠ <strong>Scan was interrupted (Ctrl+C):</strong>&nbsp;{_e(meta.get("tool_error","") or "not all targets were tested")}</div>')

    body += (f'<div style="display:flex;gap:8px;margin-bottom:16px">'
            f'{_stat(len(findings), "XSS Findings", "orange", "💥")}'
            f'{_stat(dialog_n, "Dialog confirmed", "red", "✅")}'
            f'{_stat(scanner_n, "Scanner verified (no dialog capture)", "orange", "🔴")}'
            f'{_stat(unconfirmed_n, "Unconfirmed (reflected/grep only)", "gray", "❔")}'
            f'{_stat(risk_label, "Risk Level", risk_color, "🎯")}</div>'
            f'<div class="cat-desc" style="margin-bottom:16px">'
            f'Reflected &amp; DOM XSS candidates from dalfox scan. <strong>Dialog confirmed</strong> means a '
            f'headless replay actually fired a dialog. <strong>Scanner verified</strong> means dalfox marked '
            f'the payload as breaking out of context, but this run has no dialog screenshot. '
            f'<strong>Reflected/Grep match</strong> only means the payload text came back unescaped — open '
            f'the PoC URL yourself before reporting it.</div>')

    if ran:
        parts = [f"status: {_e(meta.get('status',''))}"]
        if meta.get("duration_sec"):
            parts.append(f"duration: {meta['duration_sec']}s")
        if meta.get("targets_count"):
            parts.append(f"targets: {meta['targets_count']:,}")
        body += (f'<div style="font-size:11px;color:var(--muted);margin:-8px 0 16px">'
                 f'{" &middot; ".join(parts)}</div>')

    # v8.2: screenshots of headless-verified ("V" type — dalfox itself caught a
    # real alert()/confirm()/prompt() firing) findings, replayed and captured
    # by reconx.py's capture_xss_alert_screenshots(). Shown before the raw
    # findings table since a picture of the alert firing is far more
    # convincing evidence than a text row.
    shots = meta.get("screenshots") or []
    confirmed_shots = [s for s in shots if s.get("dialog_confirmed")]

    # ── 1. CONFIRMED XSS — proof cards (headless Chrome fired a real dialog) ──
    if confirmed_shots:
        cards = ""
        for s in confirmed_shots:
            poc = s.get("url", "")
            cards += (
                '<div class="poc-card">'
                '<div class="poc-card-hd"><span class="tag">PROVEN</span>'
                f'alert() fired in headless Chrome &nbsp;·&nbsp; param <code>{_e(s.get("param","") or "?")}</code>'
                f'{" &nbsp;·&nbsp; dialog text: <code>" + _e(str(s.get("dialog_text",""))[:60]) + "</code>" if s.get("dialog_text") else ""}'
                '</div>'
                + _poc_field(poc, "PoC URL")
                + '<div class="poc-meta">Open this URL in a browser — the JavaScript dialog fires on load. '
                  'Screenshot below is the headless-Chrome replay ReconX captured.</div>'
                + (f'<img src="{_e(s["screenshot"])}" alt="XSS proof screenshot" loading="lazy">'
                   if s.get("screenshot") else "")
                + '</div>')
        body += ('<div class="subsection-label" style="margin-bottom:10px">'
                 f'✅ Confirmed XSS <span style="color:var(--muted);font-weight:400">'
                 f'({len(confirmed_shots)} injection point(s) — a real dialog fired on replay, screenshot below)'
                 '</span></div>' + cards)

    pictured = [s for s in shots if s.get("screenshot") and not s.get("dialog_confirmed")]
    if pictured:
        cards = ""
        for s in pictured:
            poc = s.get("url", "")
            cards += (
                '<div class="poc-card">'
                '<div class="poc-card-hd"><span class="tag">VERIFIED</span>'
                f'scanner verified &nbsp;·&nbsp; param <code>{_e(s.get("param","") or "?")}</code>'
                '</div>'
                + _poc_field(poc, "PoC URL")
                + '<div class="poc-meta">Headless Chrome opened this URL. The banner in the screenshot '
                  'marks the verified payload on the page.</div>'
                + f'<img src="{_e(s["screenshot"])}" alt="XSS verified screenshot" loading="lazy">'
                + '</div>')
        body += ('<div class="subsection-label" style="margin:18px 0 10px">'
                 f'🔴 Verified XSS <span style="color:var(--muted);font-weight:400">'
                 f'({len(pictured)} — screenshot of the payload in the page)'
                 '</span></div>' + cards)

    # ── 2. Injection points — one row per (path, param), with a copyable PoC ──
    if findings:
        _grp = {}
        _confirmed_urls = {s.get("url") for s in confirmed_shots}
        for f in findings:
            try:
                pp = urlparse(f.get("url") or "")
                base = f"{pp.scheme}://{pp.netloc}{pp.path}"
            except Exception:
                base = f.get("url") or ""
            k = (base, f.get("param") or "")
            g = _grp.setdefault(k, {"payloads": set(), "types": set(), "sev": set(),
                                    "poc": f.get("url") or "", "confirmed": False, "evidence": ""})
            g["payloads"].add(f.get("payload") or "")
            g["types"].add(f.get("type") or "")
            g["sev"].add(f.get("severity") or "")
            if f.get("evidence") and not g["evidence"]:
                g["evidence"] = f["evidence"]
            if f.get("url") in _dialog_urls or f.get("type") == _DALFOX_TYPE_LABELS["RV"]:
                g["confirmed"] = True
                g["dialog"] = True
                g["poc"] = f.get("url") or g["poc"]
            elif f.get("type") == _DALFOX_TYPE_LABELS["V"]:
                g["scanner"] = True
                g["poc"] = f.get("url") or g["poc"]
        grows = []
        for (base, param), g in sorted(_grp.items(),
                                       key=lambda kv: (0 if kv[1].get("dialog") else (1 if kv[1].get("scanner") else 2),
                                                       -len(kv[1]["payloads"]))):
            grows.append([
                ("✅ CONFIRMED (dialog fired)" if g.get("dialog")
                 else ("scanner verified" if g.get("scanner") else "unconfirmed — check context")),
                param,
                base,
                str(len(g["payloads"])),
                (g["evidence"] or "")[:180],
                g["poc"],
            ])
        body += ('<div class="subsection-label" style="margin:18px 0 8px">Injection points '
                 f'<span style="color:var(--muted);font-weight:400">({len(_grp)} unique · '
                 f'{len(findings)} raw payload hits — dialog fired only when a headless replay proved it; '
                 f'"scanner verified" has no dialog capture; "unconfirmed" is a reflection, check the '
                 f'evidence column)</span></div>'
                 + _vtable(["Status", "Parameter", "URL", "# payloads", "Reflection context (dalfox evidence)",
                            "PoC URL — click ⧉ to copy"],
                           grows, "vt-xss-grp", copy_cols=[5]))

        # ── 3. every payload hit — full PoC URL copyable per row ──
        body += '<div class="subsection-label" style="margin:18px 0 8px">All payload hits</div>'
        rows = [[(f.get("url") or ""),
                 (f.get("payload") or ""),
                 (f.get("param") or "")[:40],
                 (f.get("type") or "")[:24],
                 (f.get("severity") or "")[:16]]
                for f in findings]
        body += _vtable(["PoC URL (full — copy button →)", "Payload", "Param", "Type", "Severity"],
                        rows, "vt-xss", copy_cols=[0, 1])
    elif ran:
        if meta.get("suspicious_empty"):
            body += ('<div class="alert-box info-orange" style="margin-bottom:14px">⚠ <b>XSS testing found 0 — but the run '
                     'took real time across several targets.</b> On a target the pre-scan probe confirmed '
                     'alive, that usually means the site rate-limited the payload burst (a CDN/ALB '
                     'wrapping the reflections in 403/429 so dalfox can\'t see them). <b>Treat this as '
                     '"inconclusive", not "clean"</b> — re-run later, from another IP, or lower '
                     '<code>tools.dalfox_workers</code> / raise <code>tools.dalfox_delay_ms</code>.</div>')
        else:
            body += _empty("XSS testing completed — 0 reflected/DOM XSS on the tested parameters.")
    else:
        body += _empty("XSS scan not run.")

    # non-confirmed replay attempts (transparency: what was checked and didn't fire)
    checked_only = [s for s in shots if not s.get("dialog_confirmed")]
    if checked_only:
        body += (f'<div style="font-size:11px;color:var(--muted);margin-top:10px">'
                 f'{len(checked_only)} other candidate(s) were replayed in headless Chrome and did '
                 f'<strong>not</strong> auto-fire a dialog — they stay listed above as unconfirmed '
                 f'(could still be exploitable in the right context / with user interaction).</div>')

    # v8.2: blind XSS (interactsh) — a confirmed out-of-band callback means the
    # injected payload actually EXECUTED somewhere (e.g. an admin viewing a
    # stored payload later), which is a much stronger signal than a reflected/
    # DOM finding above. Surface it prominently, separate from the table.
    blind_cb = (meta.get("blind_callback_used") or "").strip()
    blind_hits = meta.get("blind_interactions") or []
    if blind_hits:
        rows_b = [[_e(h.get("protocol","")), _e(h.get("remote_address","")),
                   _e(h.get("timestamp","")), _e((h.get("raw_request","") or "")[:200])]
                  for h in blind_hits]
        rows_html = "".join(
            f'<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td>'
            f'<td style="font-family:var(--mono);font-size:11px;white-space:pre-wrap">{r[3]}</td></tr>'
            for r in rows_b
        )
        body += (f'<div class="alert-box alert-red" style="margin-bottom:16px;border-width:2px">'
                 f'🔥 <strong>Blind XSS CONFIRMED</strong> — {len(blind_hits)} out-of-band callback'
                 f'{"s" if len(blind_hits) != 1 else ""} received on <code>{_e(blind_cb)}</code>. '
                 f'A payload actually executed somewhere reachable by this callback — treat this as a '
                 f'confirmed, exploitable XSS regardless of what the table below shows.'
                 f'<div class="tbl-scroll" style="margin-top:10px"><table><thead><tr>'
                 f'<th>Protocol</th><th>Remote Address</th><th>Timestamp</th><th>Raw Request</th>'
                 f'</tr></thead><tbody>{rows_html}</tbody></table></div></div>')
    elif blind_cb:
        body += (f'<div style="font-size:11px;color:var(--muted);margin-bottom:16px;padding:8px 12px;'
                 f'background:var(--surface2);border-radius:6px;border-left:3px solid var(--border)">'
                 f'Blind XSS callback <code>{_e(blind_cb)}</code> was active during this scan — no '
                 f'out-of-band callbacks received. This does not rule out blind XSS: a stored payload '
                 f'may still fire later (e.g. when an admin views it) after the callback stopped listening.</div>')

    # v8.3: consolidated "all tested URLs & payloads" table — every URL dalfox
    # was actually pointed at, in one place, red if it turned out vulnerable
    # and green if it was tested and came back clean. Requested by the user
    # so they don't have to infer "was this URL even tested?" from the
    # findings table alone (which only ever lists hits).
    tested = xss.get("tested") or []
    if tested:
        vuln = [t for t in tested if t.get("coverage") == "vulnerable" or t["vulnerable"]]
        clean_n = sum(1 for t in tested if t.get("coverage") == "clean")
        incomplete_n = sum(1 for t in tested if t.get("coverage") == "incomplete")
        not_scanned_n = sum(1 for t in tested if t.get("coverage") == "not_scanned")
        same_param_n = sum(1 for t in tested if t.get("coverage") == "same_param")
        vuln_n = len(vuln)

        # ── VULNERABLE — one row per ready-to-open PoC URL (full, one-piece) ──
        poc_rows, _seen_poc = [], set()
        for t in vuln:
            for p in (t.get("pocs") or []):
                pu = p.get("poc_url", "")
                if not pu or pu in _seen_poc:
                    continue
                _seen_poc.add(pu)
                p = dict(p)
                p["dialog"] = pu in _dialog_urls
                if p.get("dialog"):
                    st = "✅ CONFIRMED (dialog fired)"
                elif p["confirmed"]:
                    st = "🔴 scanner verified (no dialog capture)"
                else:
                    st = "🔴 reflected — verify context"
                poc_rows.append([st, p.get("param", ""), p.get("payload", ""), pu, "row-red"])
        # sort confirmed first
        poc_rows.sort(key=lambda r: 0 if r[0].startswith("✅") else 1)
        if poc_rows:
            body += ('<div class="subsection-label" style="margin-top:22px;margin-bottom:6px">'
                     f'🔴 Vulnerable — ready-to-open PoC URLs '
                     f'<span style="color:var(--muted);font-weight:400">({len(poc_rows)} — '
                     f'each row is a full URL with the payload already in it; click ⧉ to copy the '
                     f'whole thing, or open it in a browser)</span></div>'
                     + _vtable(["Status", "Param", "Payload", "Full PoC URL — click ⧉ to copy"],
                               poc_rows, "vt-xss-poc", row_class=True, copy_cols=[2, 3]))

        # ── all tested (was it even scanned?) ──
        _cov_label = {
            "vulnerable": "🔴 VULNERABLE",
            "clean": "🟢 clean",
            "incomplete": "🟡 time ran out — this URL did not finish",
            "not_scanned": "⚪ not started",
            "same_param": "↪ same parameter already confirmed",
        }
        _cov_row = {"vulnerable": "row-red", "clean": "row-green"}
        rows_t = []
        for t in tested:
            cov = t.get("coverage") or ("vulnerable" if t["vulnerable"] else "clean")
            rows_t.append([t["url"], _cov_label.get(cov, cov),
                           "; ".join(p for p in t["payloads"] if p),
                           ", ".join(t["types"]), ", ".join(t["severities"]),
                           _cov_row.get(cov, "")])
        body += (f'<div class="subsection-label" style="margin-top:20px;margin-bottom:8px">'
                 f'All targeted URLs <span style="color:var(--muted);font-weight:400">'
                 f'({len(tested):,} queued — '
                 f'<span style="color:var(--red)">{vuln_n:,} vulnerable</span> / '
                 f'<span style="color:var(--green)">{clean_n:,} clean</span> / '
                 f'{incomplete_n:,} time ran out / {not_scanned_n:,} not started'
                 f' / {same_param_n:,} same parameter skipped)'
                 f'</span></div>'
                 f'<div class="cat-desc" style="margin-bottom:10px">Only a URL dalfox finished with '
                 f'no finding is clean. If the time budget hit mid-URL, that row says the URL did not '
                 f'finish. A URL the scan never reached says not started. Extra values of a '
                 f'parameter that already has a finding are skipped.</div>')
        body += _vtable(["Base URL", "Status", "Payload(s) that hit", "Type", "Severity"],
                        rows_t, "vt-xss-all", row_class=True, copy_cols=[0, 2])

    raw_txt = (xss.get("raw_txt") or "").strip()
    if raw_txt:
        body += (f'<div class="subsection-label" style="margin-top:20px">Collected output</div>'
                 f'<details><summary style="cursor:pointer;color:var(--muted);font-size:12px;'
                 f'margin-bottom:8px">Show dalfox\'s own text output ({len(raw_txt.splitlines()):,} lines)</summary>'
                 f'{_code_block(raw_txt)}</details>')

    risk_label2 = "HIGH" if blind_hits else risk_label
    return (f'<div id="s-xss" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>XSS</h2>'
            f'<p class="sec-sub">{len(findings):,} findings &middot; RISK: {risk_label2}</p>'
            f'</div></div></div>{body}</div>')


# ── Section: JS Secrets ──────────────────────────────────────────────────────
_VERDICT_STYLE = {
    "REAL":    ("row-red",    "REAL — treat as leaked"),
    "UNKNOWN": ("row-yellow", "unclassified — review"),
    "PUBLIC":  ("row-blue",   "public by design"),
    "FALSE":   ("row-dim",    "not a credential"),
}
_VERDICT_RANK = {"REAL": 0, "UNKNOWN": 1, "PUBLIC": 2, "FALSE": 3}


def _section_js(js):
    endpoints = js.get("endpoints", [])
    secrets   = js.get("secrets", [])
    if not js.get("ran") and not endpoints and not secrets:
        return (f'<div id="s-js" class="section">'
                f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
                f'<h2>JS Secrets</h2>'
                f'<p class="sec-sub">not scanned yet</p>'
                f'</div></div></div>'
                f'<div class="cat-desc">Not scanned yet. Run <strong>JS Analysis</strong> '
                f'from the Scan Center — it downloads every in-scope script and reads it '
                f'without the recon time cap.</div></div>')
    detail    = [d for d in (js.get("detail") or []) if isinstance(d, dict)
                 and d.get("type") == "secret"]
    # reconx_secrets classified each candidate during stage 10 (REAL / PUBLIC /
    # FALSE / UNKNOWN). Without this the section was one flat "Secrets" list in
    # which a Stripe PUBLISHABLE key and a leaked AWS key looked identical.
    graded = [d for d in detail if d.get("verdict")]
    counts = {}
    for d in graded:
        counts[d["verdict"]] = counts.get(d["verdict"], 0) + 1

    body = (f'<div style="display:flex;flex-wrap:wrap;margin-bottom:16px">'
            f'{_stat(len(endpoints), "Endpoints", "blue", "🔗")}'
            f'{_stat(len(secrets), "Candidates", "purple", "🔑")}')
    if counts:
        body += _stat(counts.get("REAL", 0), "Real credentials", "red", "🚨")
        body += _stat(counts.get("UNKNOWN", 0), "Unclassified", "yellow", "❓")
    body += '</div>'

    if graded:
        body += ('<div class="info-banner info-blue" style="margin-bottom:14px"><span>'
                 'Each candidate is graded by an auditable pattern table '
                 '(<code>reconx_secrets.py</code>): <b>REAL</b> grants access, '
                 '<b>public by design</b> is meant to ship in client-side JS '
                 '(Stripe pk_, Google Maps/Firebase browser keys, reCAPTCHA site keys), '
                 '<b>not a credential</b> is a hash/uuid/placeholder. Anything the table '
                 'cannot identify stays <b>unclassified</b> rather than being guessed.'
                 '</span></div>')

    tabs = []
    if graded:
        rows = []
        for d in sorted(graded, key=lambda x: (_VERDICT_RANK.get(x.get("verdict"), 9),
                                               x.get("value", ""))):
            row_cls, label = _VERDICT_STYLE.get(d.get("verdict"),
                                                ("row-dim", str(d.get("verdict", ""))))
            rows.append([label,
                         str(d.get("value", ""))[:160],
                         str(d.get("verdict_reason", "")),
                         str(d.get("source_js", ""))[:120],
                         row_cls])            # last element = <tr> class, not shown
        tabs.append(("graded", f"Graded ({len(rows)})",
                     _vtable(["Verdict", "Value", "Why", "Source JS"], rows, "vt-js-graded",
                             row_class=True, copy_cols=[1, 3])))
    if endpoints:
        tabs.append(("endpoints", f"Endpoints ({len(endpoints)})",
                     _vtable(["Endpoint"], [[e] for e in endpoints], "vt-js-ep")))
    if secrets:
        tabs.append(("secrets", f"All candidates ({len(secrets)})",
                     _vtable(["Secret"], [[s] for s in secrets], "vt-js-sec")))
    body += _tabs(tabs, "js") if tabs else _empty("No JS secrets found")
    sub_txt = "Endpoints &amp; secrets harvested from JavaScript"
    if counts:
        sub_txt += (f" &middot; {counts.get('REAL', 0)} real &middot; "
                    f"{counts.get('UNKNOWN', 0)} unclassified &middot; "
                    f"{counts.get('PUBLIC', 0)} public-by-design &middot; "
                    f"{counts.get('FALSE', 0)} not a credential")
    return (f'<div id="s-js" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>JS Secrets</h2>'
            f'<p class="sec-sub">{sub_txt}</p>'
            f'</div></div></div>{body}</div>')


# ── Section: Tech Priority ───────────────────────────────────────────────────
def _parse_ai(d) -> dict:
    """A previous run's AI analysis, if one was saved next to the report."""
    f = Path(d) / "ai_analysis.json"
    if f.exists() and f.stat().st_size > 0:
        try:
            data = json.loads(f.read_text(errors="replace"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}
    return {}


def _section_ai(ai_result: dict, scan_dir) -> str:
    """The AI Analysis panel.

    Rendering happens in JS, from JSON, for both paths — the result baked into
    this file by an earlier run and a live one fetched from the bridge. One
    renderer means the two can't drift, and it keeps every model-authored
    string going through textContent instead of an f-string into innerHTML.
    """
    cached = _safe_json(ai_result or {})
    cmd = f"python3 reconx_ai.py serve {shlex.quote(str(scan_dir))}"
    n_leads = len(((ai_result or {}).get("leads")) or [])
    sub_txt = (f"{n_leads} lead(s) from the last run" if ai_result
               else "Claude checks the scan data against itself, then keeps only the links that survive")
    return f'''<div id="s-ai" class="section">
<div class="sec-hdr"><div class="sec-hdr-inner"><div>
<h2>AI Analysis</h2>
<p class="sec-sub">{_e(sub_txt)}</p>
</div></div></div>
<div class="ai-bar">
  <button class="ai-btn" id="ai-run" onclick="aiRun(false)">✨ Run AI Analysis</button>
  <button class="ai-btn ai-btn-ghost" id="ai-rerun" onclick="aiRun(true)" hidden>Re-run</button>
  <span class="ai-status" id="ai-status"></span>
</div>
<div class="ai-note" id="ai-offline" hidden>
  This report is open as a plain file, so the button has no backend to call —
  the Anthropic API key deliberately never gets written into the HTML.
  Start the local bridge and it reopens this report with the button live:
  <div style="margin-top:9px"><code>{_e(cmd)}</code></div>
</div>
<div class="ai-note" style="border-color:var(--border);font-size:12.5px">
  Each lead has to survive a check against the other scan data. It is still a
  <strong>hypothesis</strong>: nothing here was sent to the target. Confirm it before you report.
</div>
<div class="ai-term" id="ai-term">
  <div class="ai-term-hd">
    <span class="ai-term-dot"></span><span id="ai-term-lbl">analysing</span>
    <span class="ai-term-el" id="ai-term-el">0s</span>
    <button class="btn-stop" id="ai-stop" onclick="aiStop()" hidden>Stop</button>
  </div>
  <div class="ai-term-body" id="ai-term-body"></div>
</div>
<div id="ai-out"></div>
<div class="ai-ask" id="ai-ask" hidden>
  <input id="ai-q" placeholder="Ask about this scan — e.g. &quot;expand lead #2&quot; or &quot;what did the scan miss on api.*?&quot;">
  <button class="ai-btn ai-btn-ghost" onclick="aiAsk()">Ask</button>
</div>
<script>window.__RECONX_AI_RESULT = {cached};</script>
</div>'''


def _section_tech(tech):
    if not tech:
        return (f'<div id="s-tech" class="section">'
                f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
                f'<h2>Tech Priority</h2></div></div></div>'
                f'{_empty("Technology scan not performed")}</div>')
    high = sum(1 for t in tech if t.get("risk_label") == "high")
    rows = [[(t.get("url") or "")[:150],
             str(t.get("status") or ""),
             str(t.get("score") or ""),
             str(t.get("risk_label") or "low").upper(),
             ", ".join((t.get("techs") or t.get("top_techs") or []))[:140]]
            for t in tech]
    body = (f'<div style="display:flex;margin-bottom:16px">'
            f'{_stat(len(tech), "Targets", "blue", "⚙️")}'
            f'{_stat(high, "High Risk", "orange", "🔴")}</div>')
    body += _vtable(["URL", "Status", "Score", "Risk", "Technologies"], rows, "vt-tech")

    tech_risk = {}
    for t in tech:
        if t.get("risk_label") == "high":
            for tec in (t.get("techs") or t.get("top_techs") or []):
                tech_risk[str(tec)] = tech_risk.get(str(tec), 0) + 1
    if tech_risk:
        risk_rows = sorted([[k, str(v)] for k, v in tech_risk.items()],
                           key=lambda r: -int(r[1]))
        body += (f'<div style="margin-top:28px"><div class="subsection-label">'
                 f'High-Risk Technologies</div>'
                 f'{_vtable(["Technology", "Hosts"], risk_rows, "vt-tech-risk")}</div>')
    return (f'<div id="s-tech" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>Tech Priority</h2>'
            f'<p class="sec-sub">{len(tech):,} hosts by tech score</p>'
            f'</div></div></div>{body}</div>')


# ── Section: Extra Checks (v6.13+ — CORS / Subdomain Takeover / Cloud Bucket) ──
def _section_extra(extra):
    cors    = extra.get("cors", [])
    tko     = extra.get("takeover", [])
    buckets = extra.get("buckets", [])
    cors_vuln   = [r for r in cors if r.get("vulnerable")]
    tko_vuln    = [r for r in tko if r.get("vulnerable")]
    bucket_vuln = [r for r in buckets if r.get("public_listing")]
    bucket_closed = [r for r in buckets if r.get("status") == "exists_protected"]
    bucket_meta = extra.get("bucket_meta") or {}
    total_checked = len(cors) + len(tko) + len(buckets) + (1 if bucket_meta.get("checked") else 0)
    total_vuln    = len(cors_vuln) + len(tko_vuln) + len(bucket_vuln)

    if total_checked == 0:
        return (f'<div id="s-extra" class="section">'
                f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
                f'<h2>Extra Security Checks</h2></div></div></div>'
                f'{_empty("Extra checks (stage 12) not performed")}</div>')

    stats_html = "".join([
        _stat(len(cors_vuln),   "CORS Misconfig",     "orange", "🔀"),
        _stat(len(tko_vuln),    "Subdomain Takeover", "red",    "🏴"),
        _stat(len(bucket_vuln), "Public Buckets",     "red",    "🪣"),
    ])

    cors_rows = [[(r.get("url") or "")[:140], (r.get("detail") or "")[:120],
                  r.get("acao") or "", r.get("acac") or ""] for r in cors_vuln]
    tko_rows  = [[(r.get("host") or "")[:80], r.get("service") or "",
                  (r.get("cname") or "")[:80], (r.get("detail") or "")[:140]] for r in tko_vuln]
    bkt_rows  = [[(r.get("url") or "")[:140], r.get("provider") or "",
                  "public" if r.get("public_listing") else "protected",
                  (r.get("detail") or "")[:120]]
                 for r in (bucket_vuln + bucket_closed)]

    tabs = [
        ("cors", f"CORS ({len(cors_vuln)})",
         (f'<div class="cat-desc" style="border-left-color:#fb923c">⚠️ Origin yansitma / wildcard+credentials kombinasyonu — sadece header incelendi, exploit denenmedi</div>'
          + (_vtable(["URL", "Detail", "ACAO", "ACAC"], cors_rows, "vt-extra-cors") if cors_rows else _empty("No CORS misconfiguration found")))),
        ("takeover", f"Takeover ({len(tko_vuln)})",
         (f'<div class="cat-desc" style="border-left-color:#ef4444">⚠️ CNAME fingerprint + HTTP govde imzasi eslesti — devralma denenmedi, sadece tespit</div>'
          + (_vtable(["Host", "Service", "CNAME", "Detail"], tko_rows, "vt-extra-tko") if tko_rows else _empty("No subdomain takeover risk found")))),
        ("bucket", f"Cloud Buckets ({len(bucket_vuln)})",
         (f'<div class="cat-desc" style="border-left-color:#ef4444">'
          f'cloud_enum searched AWS S3, Azure and Google Cloud for '
          f'{_e(", ".join(bucket_meta.get("keywords") or []) or "the target name")}. '
          f'{int(bucket_meta.get("checked") or 0)} name(s) had a hit worth recording. '
          f'Only a public listing is read — nothing is uploaded or deleted.</div>'
          + (_vtable(["URL", "Provider", "Access", "Detail"], bkt_rows, "vt-extra-bucket") if bkt_rows else _empty("No open or protected bucket for these names")))),
    ]
    body = f'<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px">{stats_html}</div>'
    body += _tabs(tabs, "extra")
    return (f'<div id="s-extra" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>Extra Security Checks</h2>'
            f'<p class="sec-sub">{total_checked:,} checks · {total_vuln} finding(s) — CORS / Subdomain Takeover / Cloud Bucket</p>'
            f'</div></div></div>{body}</div>')


# ── CSS ───────────────────────────────────────────────────────────────────────
_CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Source+Sans+3:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap');
:root{
  --bg:#f4efe6;
  --bg-2:#fbf7f1;
  --surface1:#fbf7f1;
  --surface2:#f3ece2;
  --surface3:#e8dfd2;
  --surface4:#ddd2c2;
  --border:#ddd2c0;
  --border2:#c9bba6;
  --border-glass:#ddd2c0;
  --text:#1a1814;
  --text-dim:#2c2822;
  --muted:#4a433a;
  --muted2:#5c5348;
  --accent:#1e3a5f;
  --accent-fill:#1e3a5f;
  --accent2:#1a4468;
  --accent-glow:rgba(30,58,95,.14);
  --green:#0b5c38;
  --green-bg:#e5f4eb;
  --green-border:#8fcfad;
  --chip-green-bg:#e5f4eb;
  --chip-green-fg:#0b5c38;
  --chip-green-bd:#8fcfad;
  --red:#9f1239;
  --red-bg:#fde8ea;
  --orange:#9a3412;
  --orange-bg:#fff6ee;
  --yellow:#854d0e;
  --purple:#5925dc;
  --cyan:#0e7490;
  --hairline:rgba(30,58,95,.22);
  --grid:rgba(30,58,95,.055);
  --mono:'IBM Plex Mono',ui-monospace,monospace;
  --sans:'Source Sans 3','Segoe UI',sans-serif;
  --display:'Source Sans 3','Segoe UI',sans-serif;
  --sw:268px;
  --radius:14px;
  --radius-sm:10px;
  --shadow:0 8px 24px rgba(28,36,48,.08);
  --shadow-sm:0 1px 2px rgba(28,36,48,.05);
  --nav-active:#e8dfd2;
  color-scheme:light;
}
html[data-theme="dark"]{
  --bg:#161311;
  --bg-2:#1e1a17;
  --surface1:#241f1b;
  --surface2:#2c2622;
  --surface3:#352f29;
  --surface4:#403932;
  --border:#4a4338;
  --border2:#5c5346;
  --border-glass:#4a4338;
  --text:#f7f3ec;
  --text-dim:#e7e0d4;
  --muted:#c9bfb1;
  --muted2:#b3a898;
  --accent:#c5d9f2;
  --accent-fill:#1c4e8c;
  --accent2:#e4eef9;
  --accent-glow:rgba(110,162,224,.22);
  --green:#d2f5e3;
  --green-bg:#17352a;
  --green-border:#3d7a58;
  --chip-green-bg:#17352a;
  --chip-green-fg:#d2f5e3;
  --chip-green-bd:#3d7a58;
  --red:#f3c1ba;
  --red-bg:#3a2422;
  --orange:#f0c9a4;
  --orange-bg:#3a2c20;
  --yellow:#ead392;
  --purple:#ddd0ff;
  --cyan:#b7e4ee;
  --hairline:rgba(247,243,236,.16);
  --grid:rgba(247,243,236,.045);
  --shadow:0 8px 24px rgba(0,0,0,.35);
  --shadow-sm:0 1px 2px rgba(0,0,0,.28);
  --nav-active:#322c26;
  color-scheme:dark;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{
  background:var(--bg);
  color:var(--text);
  font-family:var(--sans);
  font-size:16px;
  font-weight:400;
  display:flex;
  min-height:100vh;
  line-height:1.6;
  letter-spacing:.005em;
  text-rendering:optimizeLegibility;
  -webkit-font-smoothing:antialiased;
  -moz-osx-font-smoothing:grayscale;
}
button,input,select,textarea{font-family:inherit;color:inherit}
/* Scrollbar */
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--surface1)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#3a5a7e}
/* Sidebar - glass + sticky */
.sidebar{
  width:var(--sw);min-width:var(--sw);
  background:var(--bg-2);
  border-right:1px solid var(--border);
  position:fixed;top:0;left:0;height:100vh;overflow-y:auto;z-index:100;
  display:flex;flex-direction:column;
}
.sidebar::-webkit-scrollbar{width:4px}
.sb-brand{
  padding:22px 18px 18px;
  border-bottom:1px solid var(--border);
  background:var(--bg-2);
  position:sticky;top:0;z-index:2;
}
.sb-logo{display:flex;align-items:center;gap:11px;margin-bottom:13px}
.sb-logo-mark{
  width:36px;height:36px;
  background:var(--accent-fill);color:#fff;
  border-radius:10px;display:flex;align-items:center;justify-content:center;
  font-size:17px;flex-shrink:0;
}
.sb-brand h1{font-family:var(--display);font-size:17px;font-weight:700;color:var(--text);letter-spacing:-.4px}
.sb-brand h1 span{color:var(--accent2);font-weight:700}
.sb-target{
  font-family:var(--mono);font-size:11px;color:var(--text-dim);
  padding:7px 10px;background:var(--surface2);border-radius:8px;
  border:1px solid var(--border);word-break:break-all;line-height:1.5;color:var(--text);
}
.sb-ts{font-size:10.5px;color:var(--muted);margin-top:7px;display:flex;align-items:center;gap:6px}
.sb-ts::before{content:'●';color:var(--green);font-size:7px}
.nav-grp{padding:10px 0 5px}
.nav-lbl{
  color:var(--muted2);font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:1.1px;padding:6px 18px 7px;font-family:var(--display);
  display:flex;align-items:center;gap:6px;
}
.nav-lbl::after{content:'';flex:1;height:1px;background:var(--border);opacity:.5;margin-left:8px}
.nav-a{
  display:flex;align-items:center;gap:10px;
  padding:9px 18px;color:var(--text-dim);cursor:pointer;font-size:14.5px;
  border-left:2.5px solid transparent;transition:background .18s,color .18s,border-color .18s;
  text-decoration:none;font-weight:500;position:relative;
}
.nav-a:hover{color:var(--text);background:var(--surface2);border-left-color:var(--border2)}
.nav-a.active{
  color:var(--accent);background:var(--nav-active);
  border-left-color:var(--accent);font-weight:600;
}
.nav-a.active::after{
  content:'';position:absolute;right:12px;top:50%;transform:translateY(-50%);
  width:6px;height:6px;background:var(--accent);border-radius:50%;box-shadow:0 0 8px var(--accent-glow);
}
.nav-ico{font-size:14px;width:20px;text-align:center;flex-shrink:0;filter:saturate(1.1)}
.nav-cnt{
  margin-left:auto;background:var(--surface3);color:var(--text-dim);
  font-size:12px;padding:2px 8px;border-radius:20px;font-family:var(--mono);
  border:1px solid var(--border);font-weight:500;min-width:22px;text-align:center;
}
.nav-cnt.cnt-red{background:var(--red-bg);color:var(--red);border-color:var(--red)}
.nav-cnt.cnt-orange{background:var(--orange-bg);color:var(--orange);border-color:var(--orange)}
.nav-cnt.cnt-green{background:var(--chip-green-bg);color:var(--chip-green-fg);border-color:var(--chip-green-bd)}
.nav-cnt.cnt-blue{background:var(--accent-glow);color:var(--accent2);border-color:var(--border2)}
.nav-cnt.cnt-purple{background:var(--surface3);color:var(--purple);border-color:var(--border2)}
/* ── On-demand Scan Center ── */
.scan-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px;margin:16px 0}
.scan-card{background:var(--surface1);border:1px solid var(--border);border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:8px;transition:border-color .2s,box-shadow .2s}
.scan-card:hover{border-color:var(--border2)}
.scan-card.scan-flash{border-color:var(--accent);box-shadow:0 0 0 3px rgba(96,165,250,.18)}
.scan-card h4{margin:0;font-size:16px;font-weight:650;letter-spacing:-.01em;display:flex;align-items:center;gap:8px}
.scan-card .scan-desc{font-size:14.5px;color:var(--text-dim);line-height:1.55;flex:1;font-weight:400}
.scan-card .scan-res{font-size:12px;color:var(--text-dim);font-family:var(--mono)}
.scan-card .scan-actions{display:flex;gap:8px;align-items:center;margin-top:4px}
.btn-run{background:var(--accent-fill);color:#fff;border:none;border-radius:7px;padding:7px 14px;font-size:14px;font-weight:600;cursor:pointer;font-family:var(--sans)}
.btn-run:hover{filter:brightness(1.08)}
.btn-run:disabled{opacity:.45;cursor:not-allowed}
.btn-stop{background:#fde8ea;color:#9f1239;border:1px solid #f3c3c9;border-radius:7px;padding:7px 12px;font-size:12.5px;font-weight:600;cursor:pointer}
.scan-console{background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;font-family:var(--mono);font-size:13px;line-height:1.6;color:var(--text);white-space:pre-wrap;word-break:break-word;max-height:420px;overflow:auto;margin-top:10px}
#scan-dock{position:fixed;left:calc(var(--sw) + 14px);right:14px;bottom:0;z-index:80;background:var(--surface1);border:1px solid var(--border2);border-radius:14px 14px 0 0;box-shadow:0 12px 40px rgba(0,0,0,.35);display:flex;flex-direction:column;max-height:42vh}
#scan-dock[hidden]{display:none!important}
#scan-dock .scan-console{max-height:26vh;margin:0 12px 12px}
#scan-dock.collapsed .scan-console,#scan-dock.collapsed .scan-meter{display:none}
body.scan-dock-on .main{padding-bottom:46vh}
#s-proxy.section{max-width:none;width:100%;margin:0;padding:8px 12px 0}
#s-proxy .sec-hdr{margin-bottom:6px}
.proxy-split{display:grid;grid-template-columns:minmax(220px,28%) minmax(0,1fr);gap:10px;height:calc(100vh - 118px)}
body.scan-dock-on .proxy-split{height:calc(100vh - 168px)}
.proxy-split .vs-wrap{display:flex;flex-direction:column;min-height:0;height:100%}
.proxy-split .vs-scroll{height:100%;flex:1}
.proxy-pane{display:flex;flex-direction:column;gap:6px;min-width:0;min-height:0;height:100%}
.proxy-hd{font-size:13px;line-height:1.3}
#proxy-url{display:block;margin-top:2px;font-family:var(--mono);font-size:12px;word-break:break-all}
.proxy-pre{flex:1;margin:0;padding:12px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;color:var(--text);font-family:var(--mono);font-size:12.5px;line-height:1.45;white-space:pre-wrap;word-break:break-word;overflow:auto;min-height:140px;max-height:none}
.vs-row.proxy-hit{background:var(--surface3)}
@media(max-width:860px){#scan-dock{left:10px;right:10px}.proxy-split{grid-template-columns:1fr}}
.scan-line{padding:1px 0}
.scan-hit-verified{color:#fff;background:#8f1d1d;border-left:4px solid #ff5a5a;padding:6px 10px;margin:6px 0;font-weight:700;border-radius:6px}
.scan-hit-reflected{color:#1a1206;background:#ffb020;border-left:4px solid #c2410c;padding:6px 10px;margin:6px 0;font-weight:700;border-radius:6px}
.scan-hit-payload{color:var(--text);background:var(--surface3);padding:2px 10px 6px 14px;margin:-4px 0 6px;border-left:4px solid var(--border2);border-radius:0 0 6px 6px}
.scan-meter{margin-top:12px;padding:12px 14px;background:var(--surface1);border:1px solid var(--border);border-radius:10px;display:flex;flex-direction:column;gap:8px}
.scan-meter[hidden]{display:none !important}
.scan-meter-top{display:flex;align-items:baseline;gap:12px;font-family:var(--mono);font-size:13px}
#scan-meter-label{font-weight:650;color:var(--text)}
#scan-meter-frac{color:var(--text-dim)}
#scan-meter-pct{margin-left:auto;font-weight:650;color:var(--accent2,#8ab4ff)}
.scan-meter-track{height:8px;border-radius:99px;background:var(--surface3);overflow:hidden}
.scan-meter-fill{height:100%;width:0;border-radius:99px;background:var(--accent);transition:width .35s ease}
.scan-meter-fill.ind{width:32%;animation:scanInd 1.15s ease-in-out infinite}
@keyframes scanInd{0%{transform:translateX(0)}50%{transform:translateX(210%)}100%{transform:translateX(0)}}
.scan-meter-meta{display:flex;flex-wrap:wrap;gap:8px 14px;font-family:var(--mono);font-size:12px;color:var(--text-dim)}
.scan-meter-meta b{color:var(--text);font-weight:650}
.scan-meter-item{font-family:var(--mono);font-size:12px;color:var(--text);word-break:break-all}
.scan-meter-item[hidden]{display:none !important}
.scan-stat-badge{font-size:11px;font-weight:600;padding:2px 9px;border-radius:20px;font-family:var(--mono)}
.nav-hr{border:none;border-top:1px solid var(--border);margin:10px 14px;opacity:.6}
.sb-hint{
  padding:12px 18px 16px;color:var(--muted);font-size:11px;line-height:1.6;
  border-top:1px solid var(--border);margin-top:auto;background:transparent;
}
.sb-hint kbd{
  background:var(--surface3);border:1px solid var(--border2);border-bottom-width:2px;
  padding:1px 5px;border-radius:5px;font-family:var(--mono);font-size:10px;color:var(--text-dim);
}
/* Main */
.main{margin-left:var(--sw);flex:1;min-width:0;padding:0 0 40px;max-width:calc(100vw - var(--sw))}
.section{display:none;padding:16px 14px 20px;max-width:none;margin:0;width:100%;animation:fadeIn .25s ease}
.section.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.sec-hdr{margin-bottom:18px}
.sec-hdr-inner{
  display:flex;align-items:flex-start;justify-content:space-between;gap:16px;
  padding:20px 22px;background:var(--surface1);
  border:1px solid var(--border);border-radius:var(--radius);
  box-shadow:var(--shadow-sm);position:relative;overflow:hidden;
}
.sec-hdr-inner::before{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:var(--accent);opacity:.85;
}
.sec-hdr h2{font-family:var(--display);font-size:22px;font-weight:650;letter-spacing:-.02em;color:var(--text);display:flex;align-items:center;gap:10px}
.sec-hdr h2::before{content:'';width:3px;height:20px;background:var(--accent);border-radius:2px}
.sec-sub{color:var(--text-dim);font-size:15px;margin-top:4px;font-weight:400;line-height:1.5}
/* .export-btn-wrap is position:fixed at top-right; without this the floating
   Export button sits directly on top of the section-header badge. */
.sec-hdr-badge{margin-right:300px;flex-shrink:0}
.target-code{
  background:var(--accent-glow);color:var(--accent2);padding:2px 7px;border-radius:6px;
  font-family:var(--mono);font-size:12.5px;border:1px solid var(--border2);
}
/* Panels */
.panel{
  background:var(--surface1);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px 20px;box-shadow:var(--shadow-sm);position:relative;overflow:hidden;
  transition:border-color .2s, box-shadow .2s;
}
.panel:hover{border-color:var(--border2);box-shadow:var(--shadow)}
.panel-header{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.panel-header h3{font-family:var(--display);font-size:13px;font-weight:600;color:var(--text);letter-spacing:-.2px}
.panel-icon{width:28px;height:28px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:14px;background:var(--accent-glow);border:1px solid var(--border2)}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.panel-pipeline{overflow:visible}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
.stat-card{
  background:var(--surface1);border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:14px 14px 12px;position:relative;overflow:hidden;
  transition:transform .18s, border-color .18s, box-shadow .18s;
}
.stat-card::before{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);opacity:.9;
}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent);box-shadow:var(--shadow)}
.stat-icon{font-size:18px;margin-bottom:6px;opacity:.9}
.stat-val{font-family:var(--display);font-size:24px;font-weight:650;color:var(--text);line-height:1;letter-spacing:-.03em;font-variant-numeric:tabular-nums}
.stat-lbl{font-size:12px;color:var(--muted);margin-top:6px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
/* Timeline */
.timeline{display:flex;align-items:flex-start;width:100%;margin-top:6px;padding:8px 0 2px}
.tl-step{display:flex;flex-direction:column;align-items:center;gap:6px;flex:1 1 0;min-width:0;position:relative}
.tl-step::after{content:'';position:absolute;top:14px;left:50%;width:100%;height:2px;background:var(--border)}
.tl-step:last-child::after{display:none}
.tl-dot{width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;border:2px solid var(--border);background:var(--surface2);z-index:1}
.tl-step.tl-done .tl-dot{background:var(--green-bg);border-color:var(--green);color:var(--green)}
.tl-step.tl-partial .tl-dot{background:var(--orange-bg);border-color:var(--orange);color:var(--orange)}
.tl-step.tl-fail .tl-dot{background:var(--red-bg);border-color:var(--red);color:var(--red)}
.tl-step.tl-run .tl-dot{background:var(--accent-glow);border-color:var(--accent);color:var(--accent);animation:tlpulse 1.4s ease-in-out infinite}
.tl-step.tl-skip .tl-dot{opacity:.45}
.tl-lbl{font-size:11px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.2px;white-space:nowrap;text-align:center}
.tl-dur{font-size:9px;color:var(--text-dim);font-family:var(--mono);letter-spacing:0}
@keyframes tlpulse{50%{box-shadow:0 0 12px var(--accent-glow)}}
/* Code block */
.code-block{
  background:var(--surface2);border:1px solid var(--border);border-radius:10px;
  padding:14px 16px;font-family:var(--mono);font-size:13px;line-height:1.65;
  color:var(--text);overflow:auto;max-height:420px;white-space:pre-wrap;word-break:break-all;
}
.empty-state{
  display:flex;align-items:center;gap:10px;padding:22px;
  background:var(--surface1);border:1px dashed var(--border);border-radius:var(--radius-sm);
  color:var(--muted);font-size:13px;justify-content:center;
}
.empty-icon{width:28px;height:28px;border-radius:50%;background:var(--surface3);display:flex;align-items:center;justify-content:center;font-size:14px}
/* Tables + virtual scroll */
.vs-wrap,.vt-wrap{background:var(--surface1);border:1px solid var(--border);border-radius:var(--radius-sm);overflow:hidden;box-shadow:var(--shadow-sm)}
.vs-toolbar{
  display:flex;align-items:center;gap:8px;padding:10px 12px;
  background:var(--surface2);border-bottom:1px solid var(--border);flex-wrap:wrap;
}
.vs-counter{font-family:var(--mono);font-size:11px;color:var(--muted);background:var(--surface3);padding:4px 8px;border-radius:6px;border:1px solid var(--border)}
.vs-search{
  flex:1;min-width:160px;max-width:320px;
  background:var(--surface1);border:1px solid var(--border);border-radius:8px;
  padding:7px 12px;color:var(--text);font-size:12.5px;outline:none;transition:border-color .18s, box-shadow .18s;
}
.vs-search:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
.vs-search::placeholder{color:var(--muted)}
.btn-sm{
  background:var(--surface3);border:1px solid var(--border);color:var(--text-dim);
  padding:6px 11px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;
  transition:all .18s;
}
.btn-sm:hover{background:var(--accent-fill);color:#fff;border-color:var(--accent-fill)}
.vs-scroll{height:360px;overflow:auto;position:relative;background:var(--surface1)}
.vs-vp{position:relative}
.vs-row{
  position:absolute;left:0;right:0;height:34px;display:flex;align-items:center;
  padding:0 12px;font-family:var(--mono);font-size:12.5px;font-weight:500;color:var(--text);
  border-bottom:1px solid var(--border);overflow:hidden;white-space:nowrap;text-overflow:ellipsis;
  transition:background .12s;
}
.vs-row:hover{background:var(--surface3);color:var(--text)}
.vs-trunc{font-size:11px;color:#9a3412;background:#fff6ee;
  border:1px solid #f3d3b8;border-radius:8px;padding:7px 11px;margin-bottom:8px}
.vs-trunc code{font-family:var(--mono);color:#9a3412}
.vs-row .vs-val{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.vs-row .vs-copy{margin-left:8px}
.vs-row:hover .cell-copy{opacity:1}
.tbl-scroll{overflow:auto;max-height:420px}
.tbl-scroll table{width:100%;border-collapse:collapse;font-size:12.5px}
.tbl-scroll th{
  position:sticky;top:0;background:var(--surface2);color:var(--text);
  font-weight:700;text-transform:uppercase;letter-spacing:.6px;font-size:11px;
  padding:9px 12px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;
}
.tbl-scroll td{padding:9px 12px;border-bottom:1px solid var(--border);color:var(--text);font-family:var(--mono);font-size:13px;font-weight:400;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tbl-scroll tr:hover td{background:var(--surface3);color:var(--text)}
/* v8.5: per-cell copy button (URL/payload PoC columns) — hidden until the row
   is hovered, so it doesn't clutter every row visually. Copies the cell's
   FULL untruncated value (see vtRender), not the CSS-ellipsis-clipped text. */
/* v8.6-fix: display:flex on a <td> breaks table column layout (two copy-cells
   in one row would stack). Keep the td a normal table cell; lay out its
   content with an inner flex wrapper instead. */
.tbl-scroll td.has-copy{white-space:nowrap}
.tbl-scroll td.has-copy .cell-wrap{display:flex;align-items:center;gap:6px}
.tbl-scroll td.has-copy .cell-txt{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;flex:1}
.cell-copy{flex:0 0 auto;opacity:0;width:20px;height:20px;padding:0;border:1px solid var(--border);
  border-radius:4px;background:var(--surface2);color:var(--muted);font-size:11px;line-height:1;cursor:pointer;
  transition:opacity .12s,color .12s,border-color .12s}
.tbl-scroll tr:hover .cell-copy{opacity:1}
.cell-copy:hover{color:var(--accent2);border-color:var(--accent2)}
.cell-copy.copied{opacity:1;color:var(--green);border-color:var(--green)}
/* v8.3: row-level color coding for the XSS "all tested URLs" table — red for
   a URL dalfox actually flagged, green for one tested and found clean. */
.row-yellow td{background:var(--orange-bg);border-bottom-color:var(--border)}
.row-yellow td:first-child{border-left:3px solid var(--yellow);font-weight:600;color:var(--text)}
.row-blue td{background:var(--surface2);border-bottom-color:var(--border)}
.row-blue td:first-child{border-left:3px solid var(--accent);color:var(--text)}
.row-dim td{opacity:.62}
.row-dim td:first-child{border-left:3px solid var(--border)}
.row-red td{background:var(--red-bg);border-bottom-color:var(--border);color:var(--text)}
.row-red td:first-child{border-left:3px solid var(--red);color:var(--text)}
.row-red:hover td{background:var(--red-bg) !important;color:var(--text) !important}
.row-green td{background:var(--green-bg);border-bottom-color:var(--border);color:var(--text)}
.row-green td:first-child{border-left:3px solid var(--green);color:var(--text)}
.row-green:hover td{background:var(--green-bg) !important;color:var(--text) !important}
.rx-tip{position:fixed;z-index:4000;max-width:min(720px,82vw);background:var(--surface1);color:var(--text);border:1px solid var(--border2);padding:8px 10px;border-radius:8px;font-family:var(--mono);font-size:12px;line-height:1.45;word-break:break-all;box-shadow:var(--shadow);pointer-events:none}
.vt-more{padding:10px 12px;text-align:center;color:var(--muted);font-size:11px}
/* Tabs */
.tab-row{display:flex;gap:4px;overflow-x:auto;padding:4px 4px 0;background:var(--surface2);border:1px solid var(--border);border-bottom:none;border-radius:var(--radius-sm) var(--radius-sm) 0 0}
.tab{
  padding:8px 14px;border-radius:8px 8px 0 0;font-size:12.5px;font-weight:600;
  color:var(--muted);background:transparent;border:1px solid transparent;border-bottom:none;cursor:pointer;white-space:nowrap;transition:all .18s;
}
.tab:hover{color:var(--text);background:var(--surface3)}
.tab.active{color:var(--accent2);background:var(--surface1);border-color:var(--border);box-shadow:0 -2px 8px rgba(0,0,0,.2)}
.panes{border:1px solid var(--border);border-radius:0 0 var(--radius-sm) var(--radius-sm);overflow:hidden;background:var(--surface1)}
.pane{display:none;padding:16px}
.pane.active{display:block;animation:fadeIn .2s ease}
.cat-desc{
  font-size:12px;color:var(--muted);padding:8px 12px;background:var(--surface2);
  border-radius:8px;border-left:3px solid var(--accent);margin-bottom:12px;line-height:1.6;
}
.subsection-label{font-family:var(--display);font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px}
/* Screenshot gallery */
.shot-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin-bottom:20px}
.shot-tile{display:block;background:var(--surface1);border:1px solid var(--border);border-radius:var(--radius-sm);overflow:hidden;text-decoration:none;transition:border-color .18s, transform .18s}
.shot-tile:hover{border-color:var(--accent);transform:translateY(-2px)}
.shot-tile img{width:100%;height:110px;object-fit:cover;object-position:top;display:block;background:var(--surface2)}
.shot-cap{display:block;padding:6px 8px;font-size:10.5px;font-family:var(--mono);color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
/* One-piece copy field */
.poc-field{display:flex;align-items:stretch;gap:0;margin:8px 0;border:1px solid var(--border2);border-radius:8px;overflow:hidden;background:var(--surface1)}
.poc-lbl{flex:0 0 auto;padding:8px 10px;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);background:var(--surface2);display:flex;align-items:center;border-right:1px solid var(--border)}
.poc-val{flex:1 1 auto;padding:8px 10px;font-family:var(--mono);font-size:12px;color:var(--accent2);overflow-x:auto;white-space:nowrap;user-select:all}
.poc-copy{flex:0 0 auto;padding:8px 14px;border:0;border-left:1px solid var(--border);background:var(--accent-fill);color:#fff;font-weight:650;font-size:13px;cursor:pointer;transition:filter .15s;font-family:var(--sans)}
.poc-copy:hover{filter:brightness(1.1)}
/* Confirmed-XSS proof card */
.poc-card{border:1.5px solid #dc2626;border-radius:12px;background:rgba(220,38,38,.06);padding:16px;margin-bottom:16px}
.poc-card-hd{display:flex;align-items:center;gap:10px;font-weight:700;font-size:14px;color:#9f1239;margin-bottom:10px}
.poc-card-hd .tag{background:#dc2626;color:#fff;font-size:10.5px;padding:2px 8px;border-radius:6px;letter-spacing:.5px}
.poc-card img{width:100%;max-width:760px;border:1px solid var(--border2);border-radius:8px;margin-top:10px;display:block}
.poc-meta{font-size:11.5px;color:var(--muted);font-family:var(--mono);margin-top:6px}
/* Alerts */
.alert-box{padding:12px 14px;border-radius:10px;font-size:12.5px;line-height:1.6;border:1px solid}
.alert-red{background:var(--red-bg);border-color:var(--red);color:var(--red)}
.info-banner{padding:10px 14px;border-radius:10px;font-size:14.5px;line-height:1.55;display:flex;align-items:center;gap:8px;border:1px solid}
.info-red{background:var(--red-bg);border-color:var(--red);color:var(--red)}
.info-orange{background:var(--orange-bg);border-color:var(--orange);color:var(--orange)}
.info-yellow{background:var(--orange-bg);border-color:var(--yellow);color:var(--yellow)}
.info-blue{background:var(--accent-glow);border-color:var(--accent);color:var(--accent2)}
.info-green,.alert-ok,.toast-ok{background:var(--chip-green-bg);border-color:var(--chip-green-bd);color:var(--chip-green-fg)}
.ink-ok{color:var(--green);font-weight:650}
.toast{padding:10px 14px;border-radius:10px;font-size:14px;font-weight:600;border:1px solid;box-shadow:var(--shadow)}
.toast-warn{background:var(--orange-bg);color:var(--orange);border-color:var(--orange)}
/* Threat Map */
.tm-legend{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.tm-leg-item{display:flex;align-items:center;gap:6px;font-size:11.5px;color:var(--muted);background:var(--surface1);padding:5px 10px;border-radius:20px;border:1px solid var(--border)}
.tm-dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.tm-toolbar{display:flex;align-items:center;gap:6px;flex-wrap:wrap;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:8px}
.tm-wrap{
  background:
    radial-gradient(900px 480px at 50% 46%, rgba(53,208,192,.07), transparent 68%),
    linear-gradient(rgba(39,55,79,.45) 1px, transparent 1px),
    linear-gradient(90deg, rgba(39,55,79,.45) 1px, transparent 1px),
    #0a0e16;
  background-size: auto, 48px 48px, 48px 48px, auto;
  border:1px solid #27374f;border-radius:14px;height:680px;
  position:relative;overflow:hidden;
}
#tm-svg{width:100%;height:100%;display:block;cursor:grab}
#tm-svg:active{cursor:grabbing}
.tm-label{font-size:11px;fill:#d6e2f0;pointer-events:none;paint-order:stroke;stroke:#0a0e16;stroke-width:3px;stroke-linejoin:round}
.tm-tooltip{position:fixed;pointer-events:none;background:rgba(8,12,20,.96);border:1px solid #27374f;padding:10px 12px;border-radius:9px;font-size:11.5px;color:#d6e2f0;box-shadow:0 12px 40px rgba(0,0,0,.5);opacity:0;transition:opacity .12s;min-width:220px;max-width:320px;z-index:80;line-height:1.7}
.tm-tooltip .th{font-size:12.5px;color:#fff;margin-bottom:4px;font-weight:650}
.tm-tooltip .r{display:flex;justify-content:space-between;gap:14px}
.tm-tooltip .r span:first-child{color:#6b7c94}
.estate{position:relative;height:560px;border-radius:16px;overflow:hidden;margin-bottom:14px;
  background:
    radial-gradient(720px 420px at 50% 48%, rgba(53,208,192,.09), transparent 70%),
    linear-gradient(rgba(39,55,79,.4) 1px, transparent 1px),
    linear-gradient(90deg, rgba(39,55,79,.4) 1px, transparent 1px),
    #0a0e16;
  background-size:auto, 46px 46px, 46px 46px, auto;
  border:1px solid #27374f}
.estate-svg{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}
.estate-pin{position:absolute;transform:translate(-50%,-50%);z-index:2;width:max-content;max-width:160px;text-align:center}
.estate-pin:hover{z-index:6}
.estate-dot{margin:0 auto;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;color:#0a0e16;font-weight:700;box-shadow:0 0 0 6px rgba(255,255,255,.04)}
.estate-dot.root{width:46px;height:46px;background:#0f2a2e;color:#35d0c0;border:2px solid #35d0c0;box-shadow:0 0 0 8px rgba(53,208,192,.12)}
.estate-dot.host{width:28px;height:28px}
.estate-dot.bare{box-shadow:0 0 0 5px rgba(255,77,94,.18)}
.estate-name{margin-top:5px;font-family:var(--mono);font-size:11px;color:#d6e2f0;text-shadow:0 1px 2px #0a0e16;word-break:break-all}
.estate-tip{display:none;position:absolute;left:50%;top:100%;transform:translate(-50%,8px);text-align:left;min-width:210px;background:rgba(8,12,20,.96);border:1px solid #27374f;border-radius:9px;padding:10px 12px;font-size:11.5px;color:#d6e2f0;line-height:1.7;box-shadow:0 12px 40px rgba(0,0,0,.5)}
.estate-pin:hover .estate-tip{display:block}
.estate-tip b{display:block;color:#fff;margin-bottom:3px}
.estate-tip .r{display:flex;justify-content:space-between;gap:12px}
.estate-tip .r span:first-child{color:#6b7c94}
.estate-districts{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
@media(max-width:980px){.estate-districts{grid-template-columns:1fr 1fr}.estate{height:480px}}
/* Risk gauge */
.risk-gauge{display:flex;align-items:center;gap:16px;padding:14px;background:var(--surface2);border-radius:12px;border:1px solid var(--border);margin-bottom:14px}
.risk-panel{background:var(--surface1);border-left:4px solid var(--border2);margin-bottom:16px}
.risk-panel .risk-gauge-label div{color:var(--text-dim)}
.risk-score-num{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-family:var(--display);font-weight:700;font-size:16px;color:var(--text)}
.risk-ring-track{stroke:var(--border2)}
.risk-ring{fill:none;stroke:currentColor;transition:stroke-dashoffset .6s ease}
.risk-none{border-left-color:var(--green)}
.risk-none .risk-gauge-label strong,.risk-none .risk-score-num,.risk-none .risk-ring{color:var(--green)}
.risk-low{border-left-color:var(--accent-fill)}
.risk-low .risk-gauge-label strong,.risk-low .risk-score-num,.risk-low .risk-ring{color:var(--accent2)}
.risk-medium{border-left-color:var(--yellow)}
.risk-medium .risk-gauge-label strong,.risk-medium .risk-score-num,.risk-medium .risk-ring{color:var(--yellow)}
.risk-high{border-left-color:var(--orange)}
.risk-high .risk-gauge-label strong,.risk-high .risk-score-num,.risk-high .risk-ring{color:var(--orange)}
.risk-critical{border-left-color:var(--red)}
.risk-critical .risk-gauge-label strong,.risk-critical .risk-score-num,.risk-critical .risk-ring{color:var(--red)}
.risk-gauge-circle{width:72px;height:72px;flex-shrink:0;position:relative}
.risk-gauge-circle svg{transform:rotate(-90deg)}
.risk-gauge-label{flex:1}
.risk-gauge-label strong{font-family:var(--display);font-size:15px}
.risk-pct{font-family:var(--mono);font-size:11px;color:var(--muted)}
/* Export dropdown */
.export-btn-wrap{position:fixed;top:16px;right:16px;z-index:90;display:flex;align-items:center;gap:8px}
.theme-switch{display:flex;border:1px solid var(--border2);border-radius:10px;overflow:hidden;background:var(--surface1)}
.theme-btn{
  background:transparent;border:0;color:var(--text);padding:8px 12px;
  font-size:12.5px;font-weight:700;cursor:pointer;font-family:var(--sans);
}
.theme-btn.on{background:var(--accent-fill);color:#fff}
.theme-btn:hover:not(.on){background:var(--surface3)}
.export-btn{
  display:flex;align-items:center;gap:8px;
  background:var(--accent-fill);color:#fff;
  border:none;padding:9px 14px;border-radius:10px;font-size:14px;font-weight:650;
  cursor:pointer;box-shadow:0 4px 14px var(--accent-glow);transition:transform .18s,box-shadow .18s;
}
.export-btn:hover{transform:translateY(-1px);box-shadow:0 6px 18px var(--accent-glow)}
.export-dropdown{
  position:fixed;top:56px;right:16px;background:var(--surface1);border:1px solid var(--border);
  border-radius:12px;box-shadow:var(--shadow);padding:6px;min-width:240px;display:none;z-index:90;
}
.export-dropdown.open{display:block;animation:fadeIn .18s ease}
.export-opt{
  display:flex;align-items:center;gap:10px;width:100%;padding:10px 12px;
  background:transparent;border:none;border-radius:8px;cursor:pointer;text-align:left;transition:background .15s;
}
.export-opt:hover{background:var(--surface2)}
.export-opt-icon{width:28px;height:28px;border-radius:7px;background:var(--surface3);display:flex;align-items:center;justify-content:center;font-size:14px}
.export-opt div{font-size:12.5px;color:var(--text)}
.export-opt-desc{font-size:11px;color:var(--muted)!important}
.footer{
  margin-top:28px;padding:14px 14px;text-align:center;color:var(--muted);font-size:11px;
  border-top:1px solid var(--border);background:transparent;
}
/* Mobile menu toggle (hamburger) + scrim */
.sb-toggle{
  display:none;position:fixed;top:14px;left:14px;z-index:110;
  width:38px;height:38px;align-items:center;justify-content:center;
  background:var(--surface1);border:1px solid var(--border2);border-radius:10px;color:var(--text);
  cursor:pointer;box-shadow:0 4px 18px rgba(0,0,0,.4);
}
.sb-scrim{
  display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:99;
  opacity:0;pointer-events:none;transition:opacity .2s;
}
.sb-scrim.show{opacity:1;pointer-events:auto}
/* Responsive */
@media(max-width:900px){
  .sb-toggle{display:flex}
  .sb-scrim{display:block}
  .sidebar{transform:translateX(-100%);transition:transform .25s;z-index:101}
  .sidebar.open{transform:translateX(0)}
  .main{margin-left:0;max-width:100vw;padding-top:52px}
  .two-col{grid-template-columns:1fr}
  .stat-grid{grid-template-columns:repeat(2,1fr)}
  .export-btn-wrap{top:10px;right:10px}
  /* the button moves up into its own strip here, so drop the reserved gap */
  .sec-hdr-badge{margin-right:0}
}
@media print{
  .sidebar,.export-btn-wrap,.export-dropdown,.tm-toolbar,.vs-toolbar,.sb-toggle,.sb-scrim{display:none!important}
  .main{margin-left:0}
  .section{display:block!important;page-break-inside:avoid}
}
/* Command palette */
.cmdk-overlay{position:fixed;inset:0;background:rgba(0,0,0,.45);backdrop-filter:blur(4px);display:none;z-index:200;align-items:flex-start;justify-content:center;padding-top:18vh}
.cmdk-overlay.open{display:flex}
.cmdk{
  background:var(--surface1);border:1px solid var(--border2);border-radius:16px;
  width:90%;max-width:560px;box-shadow:0 24px 64px rgba(0,0,0,.6);overflow:hidden;
}
.cmdk-input{
  width:100%;padding:14px 16px;background:var(--surface2);border:none;border-bottom:1px solid var(--border);
  color:var(--text);font-size:14px;outline:none;font-family:var(--sans);
}
.cmdk-list{max-height:320px;overflow:auto;padding:6px}
.cmdk-item{padding:9px 12px;border-radius:8px;cursor:pointer;display:flex;align-items:center;gap:10px;font-size:13px;color:var(--text-dim)}
.cmdk-item:hover,.cmdk-item.active{background:var(--surface2);color:var(--text)}

/* ── AI Analysis ───────────────────────────────────────────────────────── */
/* The panel toggles controls with the `hidden` attribute, but a class that
   sets `display` outranks the UA stylesheet's [hidden]{display:none} — so
   .ai-btn (inline-flex) and .ai-ask (flex) stayed visible while hidden. That
   showed a dead "Re-run" button and an ask box with no backend on a report
   opened as a plain file. Re-assert it for these elements. */
.ai-btn[hidden],.ai-ask[hidden],.ai-note[hidden]{display:none !important}
.ai-bar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.ai-btn{
  display:inline-flex;align-items:center;gap:9px;padding:11px 20px;border:none;
  border-radius:var(--radius-sm);cursor:pointer;font-family:var(--sans);
  font-size:15px;font-weight:600;color:#fff;
  background:var(--accent-fill);
  box-shadow:0 4px 18px var(--accent-glow);transition:transform .12s,box-shadow .12s;
}
.ai-btn:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 6px 26px var(--accent-glow)}
.ai-btn:disabled{opacity:.55;cursor:default;transform:none}
.ai-btn-ghost{
  background:var(--surface2);color:var(--text-dim);border:1px solid var(--border2);
  box-shadow:none;font-weight:500;
}
.ai-btn-ghost:hover:not(:disabled){background:var(--surface3);color:var(--text);transform:none;box-shadow:none}
.ai-status{font-size:12.5px;color:var(--muted);font-family:var(--mono)}
.ai-spin{
  display:inline-block;width:12px;height:12px;margin-right:7px;vertical-align:-1px;
  border:2px solid var(--border2);border-top-color:var(--accent);border-radius:50%;
  animation:ai-rot .7s linear infinite;
}
@keyframes ai-rot{to{transform:rotate(360deg)}}
.ai-note{
  border:1px solid var(--border2);background:var(--surface1);border-radius:var(--radius-sm);
  padding:14px 16px;font-size:13px;color:var(--text-dim);line-height:1.65;margin-bottom:18px;
}
.ai-note code{
  font-family:var(--mono);font-size:12px;background:var(--surface3);
  padding:2px 7px;border-radius:5px;color:var(--accent2);
}
.ai-note-err{border-color:var(--red);background:var(--red-bg);color:var(--red)}
.ai-verdict{
  border:1px solid var(--border2);border-left:3px solid var(--accent);
  background:var(--surface2);
  border-radius:var(--radius-sm);padding:16px 18px;margin-bottom:18px;
  font-size:14.5px;line-height:1.7;color:var(--text);
}
.ai-block-lbl{
  font-family:var(--mono);font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--muted2);margin:22px 0 10px;
}
.ai-gaps{
  border:1px solid var(--orange);background:var(--orange-bg);border-radius:var(--radius-sm);
  padding:13px 18px;margin-bottom:6px;
}
.ai-gaps li,.ai-plain li{font-size:13px;line-height:1.75;color:var(--text-dim);margin-left:18px}
.ai-lead{
  border:1px solid var(--border);border-radius:var(--radius-sm);background:var(--surface1);
  margin-bottom:12px;overflow:hidden;
}
.ai-lead-hd{
  display:flex;align-items:center;gap:11px;padding:13px 16px;cursor:pointer;
  border-left:3px solid var(--muted2);
}
.ai-lead-hd:hover{background:var(--surface2)}
.ai-lead[data-sev="critical"] .ai-lead-hd{border-left-color:var(--red)}
.ai-lead[data-sev="high"]     .ai-lead-hd{border-left-color:var(--red)}
.ai-lead[data-sev="medium"]   .ai-lead-hd{border-left-color:var(--orange)}
.ai-lead[data-sev="low"]      .ai-lead-hd{border-left-color:var(--yellow)}
.ai-lead[data-sev="info"]     .ai-lead-hd{border-left-color:var(--muted2)}
.ai-rank{font-family:var(--mono);font-size:12px;color:var(--muted2);min-width:26px}
.ai-sev{
  font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.08em;
  padding:3px 8px;border-radius:5px;text-transform:uppercase;
}
.ai-sev-critical,.ai-sev-high{background:#fde8ea;color:#9f1239;border:1px solid #f3c3c9}
.ai-sev-medium{background:#fff6ee;color:#9a3412;border:1px solid #f3d3b8}
.ai-sev-low{background:#fef6d8;color:#854d0e;border:1px solid #ead48a}
.ai-sev-info{background:var(--surface3);color:var(--muted);border:1px solid var(--border2)}
.ai-lead-ttl{font-size:14px;font-weight:600;color:var(--text);flex:1;min-width:0}
.ai-conf{font-family:var(--mono);font-size:10.5px;color:var(--muted2);white-space:nowrap}
.ai-caret{color:var(--muted2);font-size:11px;transition:transform .15s}
.ai-lead.open .ai-caret{transform:rotate(90deg)}
.ai-lead-bd{display:none;padding:2px 18px 18px;border-top:1px solid var(--border)}
.ai-lead.open .ai-lead-bd{display:block}
.ai-row{display:flex;gap:14px;padding:9px 0;border-bottom:1px dashed var(--border);font-size:13px}
.ai-row:last-child{border-bottom:none}
.ai-row-k{
  font-family:var(--mono);font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--muted2);min-width:96px;padding-top:2px;flex-shrink:0;
}
.ai-row-v{color:var(--text-dim);line-height:1.7;min-width:0;flex:1;word-break:break-word}
.ai-ev{
  font-family:var(--mono);font-size:11.5px;color:var(--text-dim);background:var(--surface2);
  border-radius:6px;padding:7px 10px;margin-bottom:5px;word-break:break-all;
}
.ai-cmd{
  display:flex;align-items:flex-start;gap:8px;font-family:var(--mono);font-size:11.5px;
  color:var(--green);background:var(--green-bg);border:1px solid var(--green-border);
  border-radius:6px;padding:8px 10px;margin-bottom:5px;word-break:break-all;
}
.ai-cmd button{
  margin-left:auto;flex-shrink:0;background:var(--surface3);border:1px solid var(--border2);
  color:var(--muted);border-radius:5px;padding:2px 8px;font-size:10px;cursor:pointer;
  font-family:var(--mono);
}
.ai-cmd button:hover{color:var(--text);background:var(--surface4)}
.ai-dismissed{font-size:12.5px;color:var(--muted);line-height:1.8}
.ai-dismissed b{color:var(--text-dim);font-weight:500}
.ai-ask{display:flex;gap:9px;margin-top:26px}
.ai-ask input{
  flex:1;padding:11px 14px;background:var(--surface1);border:1px solid var(--border2);
  border-radius:var(--radius-sm);color:var(--text);font-family:var(--sans);font-size:13px;outline:none;
}
.ai-ask input:focus{border-color:var(--accent)}
.ai-answer{
  border:1px solid var(--border2);border-radius:var(--radius-sm);background:var(--surface1);
  padding:16px 18px;margin-top:12px;font-size:13.5px;line-height:1.75;color:var(--text-dim);
  white-space:pre-wrap;word-break:break-word;
}
.ai-usage{font-family:var(--mono);font-size:11px;color:var(--muted2);margin-top:20px}

/* Live stream pane — the analysis as it is produced */
.ai-term{
  display:none;border:1px solid var(--border2);border-radius:var(--radius-sm);
  background:var(--surface2);margin-bottom:18px;overflow:hidden;
}
.ai-term.on{display:block}
.ai-term-hd{
  display:flex;align-items:center;gap:8px;padding:8px 13px;
  background:var(--surface1);border-bottom:1px solid var(--border);
  font-family:var(--mono);font-size:11px;color:var(--muted);
}
.ai-term-dot{width:8px;height:8px;border-radius:50%;background:var(--green);
  box-shadow:0 0 8px var(--green);animation:ai-pulse 1.4s ease-in-out infinite}
@keyframes ai-pulse{50%{opacity:.35}}
.ai-term-el{margin-left:auto;color:var(--muted2)}
.ai-term-hd .btn-stop{margin-left:10px}
.ai-draft{
  white-space:pre-wrap;font-family:var(--mono);font-size:12px;line-height:1.55;
  color:var(--text-dim);border:1px solid var(--border);background:var(--surface1);
  border-radius:var(--radius-sm);padding:12px 14px;max-height:420px;overflow:auto;
  margin-bottom:8px;
}
.ai-term-body{
  max-height:340px;overflow-y:auto;padding:12px 15px;
  font-family:var(--mono);font-size:11.5px;line-height:1.65;
  white-space:pre-wrap;word-break:break-word;
}
.ai-term-body .th{color:var(--muted2);font-style:italic}
.ai-term-body .tx{color:var(--text-dim)}
.ai-term-body .st{color:var(--accent);display:block;margin:4px 0}
.ai-term-cur{
  display:inline-block;width:7px;height:13px;background:var(--accent);
  vertical-align:-2px;animation:ai-blink .9s step-end infinite;
}
@keyframes ai-blink{50%{opacity:0}}
.sm-hero{background:linear-gradient(180deg,var(--surface1),var(--surface2));border:1px solid var(--border);border-radius:18px;padding:22px 24px 18px;margin-bottom:18px}
.sm-kicker{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--accent2);font-weight:700}
.sm-hero h3{margin:6px 0 2px;font-size:28px;letter-spacing:-.5px;font-weight:700}
.sm-lead{margin:0 0 12px;color:var(--text-dim);font-size:15px;line-height:1.45}
.sm-pills{display:flex;flex-wrap:wrap;gap:6px}
.sm-pill{font-family:var(--mono);font-size:11.5px;padding:4px 9px;border-radius:999px;background:var(--surface1);border:1px solid var(--border);color:var(--text)}
.sm-step{display:grid;grid-template-columns:28px minmax(0,1fr);gap:14px}
.sm-rail{display:flex;flex-direction:column;align-items:center}
.sm-dot{width:28px;height:28px;border-radius:50%;background:var(--accent-fill);color:#fff;font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.sm-line{width:2px;flex:1;background:var(--border2);min-height:18px;margin:4px 0}
.sm-card{background:var(--surface1);border:1px solid var(--border);border-radius:14px;padding:14px 16px 12px;margin-bottom:12px}
.sm-card h4{margin:0 0 10px;font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:700}
.sm-kv{display:grid;grid-template-columns:148px minmax(0,1fr);gap:6px 12px;font-size:13.5px}
.sm-kv span{color:var(--muted)}
.sm-kv b{font-weight:600;color:var(--text);word-break:break-word}
.sm-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:4px}
.sm-chip{display:inline-flex;align-items:center;padding:3px 9px;border-radius:999px;background:var(--surface2);border:1px solid var(--border);font-size:12px;margin:0 6px 6px 0;color:var(--text)}
.sm-chip.edge{background:var(--orange-bg);border-color:transparent;color:var(--orange)}
.sm-hosts{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin-top:8px}
.sm-host{border:1px solid var(--border);border-radius:14px;padding:14px 14px 10px;background:var(--surface1)}
.sm-host h5{margin:0;font-family:var(--mono);font-size:12.5px;word-break:break-all;font-weight:600}
.sm-host .sm-sub{color:var(--muted);font-size:12px;margin:4px 0 8px}
@media(max-width:860px){.sm-grid,.sm-kv{grid-template-columns:1fr}}
"""
_JS = r"""
function showSection(id, el) {
  document.querySelectorAll('.section').forEach(function(s){ s.classList.remove('active'); });
  document.querySelectorAll('.nav-a').forEach(function(n){ n.classList.remove('active'); });
  var sec = document.getElementById('s-' + id);
  if (!sec) { id = 'overview'; sec = document.getElementById('s-overview'); }
  if (!el) el = document.querySelector('.nav-a[data-sid="'+id+'"]');
  if (sec) sec.classList.add('active');
  if (el)  el.classList.add('active');
  window.scrollTo({top:0, behavior:'smooth'});
  if (sec) {
    sec.querySelectorAll('.vs-vp').forEach(function(vp){
      try { vsRender(vp.id.replace('-vp','')); } catch(e) {}
    });
  }
  history.replaceState(null,'','#'+id);
  if (id === 'scans') {
    if (_scanLive && !_scanUserStop) scanShowDock();
  } else {
    scanHideDock();
  }
  if (id === 'proxy') { try { proxyBind(); } catch(e){} }
  // close the off-canvas sidebar on mobile after picking a section
  closeSidebar();
  if (id === 'threatmap' && window._TM_DATA) {
    setTimeout(function(){
      if (_TM.initialized) return;
      if (typeof d3 === 'undefined') { showThreatMapError(); return; }
      initThreatMap();
    }, 80);
  }
  // v8.2-fix: defensive re-render — belt-and-suspenders alongside the
  // DOMContentLoaded-time render, so the table is never stuck empty even if
  // something else about the load-time flag/timing changes later.
  if (id === 'alive' && window._AR && window._AR.length) {
    try { renderAlive(); } catch (e) {}
  }
}
function toggleSidebar(){
  var sb = document.querySelector('.sidebar');
  var scrim = document.querySelector('.sb-scrim');
  if (sb) sb.classList.toggle('open');
  if (scrim) scrim.classList.toggle('show', sb && sb.classList.contains('open'));
}
function closeSidebar(){
  var sb = document.querySelector('.sidebar');
  var scrim = document.querySelector('.sb-scrim');
  if (sb) sb.classList.remove('open');
  if (scrim) scrim.classList.remove('show');
}
function jumpToHost(hostLabel){
  // Threat Map node click -> Subdomains list, pre-filtered to that host.
  // Subdomains always contains every node (alive or not), so this never dead-ends.
  showSection('subdomains', document.querySelector('.nav-a[data-sid="subdomains"]'));
  setTimeout(function(){
    var q = document.getElementById('vs-subs-q');
    if (q) {
      q.value = hostLabel;
      vsFilter('vs-subs');
      q.scrollIntoView({behavior:'smooth', block:'center'});
      q.focus();
    }
  }, 200);
}
function showThreatMapError(){
  var wrap = document.querySelector('.tm-wrap');
  if (!wrap || wrap.dataset.errShown) return;
  wrap.dataset.errShown = '1';
  var msg = document.createElement('div');
  msg.style.cssText = 'position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:10px;color:var(--muted);font-size:13px;text-align:center;padding:24px';
  msg.innerHTML = '<span style="font-size:26px">⚠️</span><span>Threat Map needs the d3.js library, which could not be loaded (no internet access from this browser).<br>Everything else in this report works fully offline.</span>';
  wrap.appendChild(msg);
}
function tab(btn, paneId){
  var cont = btn.closest('.section');
  cont.querySelectorAll('.tab').forEach(function(b){ b.classList.remove('active'); });
  cont.querySelectorAll('.pane').forEach(function(p){ p.classList.remove('active'); });
  btn.classList.add('active');
  var pane = document.getElementById(paneId);
  if(pane){
    pane.classList.add('active');
    pane.querySelectorAll('.vs-vp').forEach(function(vp){
      try{ vsRender(vp.id.replace('-vp','')); }catch(e){}
    });
  }
}
// Toast
function toast(msg, type){
  var c = document.getElementById('toast-container');
  if(!c){ c=document.createElement('div'); c.id='toast-container'; c.style.cssText='position:fixed;bottom:18px;right:18px;z-index:9999;display:flex;flex-direction:column;gap:8px'; document.body.appendChild(c); }
  var el=document.createElement('div');
  el.textContent=msg;
  el.className = type==='ok' ? 'toast toast-ok' : 'toast toast-warn';
  c.appendChild(el);
  setTimeout(function(){ el.style.opacity='0'; el.style.transform='translateY(6px)'; el.style.transition='all .3s'; },2200);
  setTimeout(function(){ try{el.remove()}catch(e){} },2600);
}
// ── clipboard ───────────────────────────────────────────────────────────────
// Single entry point for every copy button in the report. navigator.clipboard
// only exists in a secure context — file:// is not one in every browser, and
// the web panel serves the report over plain http — so fall back to the
// hidden-textarea + execCommand route instead of failing silently.
function rxCopyRaw(text){
  text = (text == null) ? '' : String(text);
  if(navigator.clipboard && navigator.clipboard.writeText){
    return navigator.clipboard.writeText(text);
  }
  return new Promise(function(resolve, reject){
    try{
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly','');
      ta.style.cssText = 'position:fixed;top:-1000px;left:-1000px;opacity:0';
      document.body.appendChild(ta);
      ta.select(); ta.setSelectionRange(0, ta.value.length);
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      ok ? resolve() : reject(new Error('execCommand refused'));
    }catch(e){ reject(e); }
  });
}
// Full URL on hover. The browser's native tooltip follows color-scheme and
// disappears on this dark theme (light text on a light bubble, or the reverse).
function rxTipMove(ev){
  var tip = document.getElementById('rx-tip');
  if (!tip || tip.hidden) return;
  var pad = 12;
  var x = ev.clientX + 14;
  var y = ev.clientY + 18;
  var w = tip.offsetWidth || 320;
  var h = tip.offsetHeight || 40;
  if (x + w > window.innerWidth - pad) x = Math.max(pad, ev.clientX - w - 14);
  if (y + h > window.innerHeight - pad) y = Math.max(pad, ev.clientY - h - 12);
  tip.style.left = x + 'px';
  tip.style.top = y + 'px';
}
function rxTip(el, text){
  if (!el || !text) return;
  el.addEventListener('mouseenter', function(ev){
    var tip = document.getElementById('rx-tip');
    if (!tip){
      tip = document.createElement('div');
      tip.id = 'rx-tip';
      tip.className = 'rx-tip';
      document.body.appendChild(tip);
    }
    tip.textContent = text;
    tip.hidden = false;
    rxTipMove(ev);
  });
  el.addEventListener('mousemove', rxTipMove);
  el.addEventListener('mouseleave', function(){
    var tip = document.getElementById('rx-tip');
    if (tip) tip.hidden = true;
  });
}
// rxCopy(text, okMsg, onOk) — copies, toasts, and never leaves a rejected
// promise dangling. onOk is the per-button "turned into a tick" feedback.
function rxCopy(text, okMsg, onOk){
  rxCopyRaw(text).then(function(){
    if(okMsg) toast(okMsg, 'ok');
    if(onOk) try{ onOk(); }catch(e){}
  }).catch(function(){
    toast('Copy blocked by the browser — select the value and press Ctrl+C', 'warn');
  });
}
// One-piece copy for a PoC field (URL+payload as a single string).
function copyOne(btn){
  var v = btn.getAttribute('data-copy') || '';
  var o = btn.textContent;
  rxCopy(v, 'PoC copied to clipboard', function(){
    btn.textContent = '✓ copied';
    setTimeout(function(){ btn.textContent = o; }, 1400);
  });
}
// Is this cell worth its own one-click copy button? URLs and hostnames always
// are (they are the thing people paste into Burp), and so is any long unbroken
// value — payloads, secrets, template ids — since those are exactly the cells
// CSS truncates.
function rxCopyable(v){
  if(!v) return false;
  v = String(v);
  if(v.indexOf('://') !== -1) return true;                     // any URL
  if(/^[a-z0-9_.-]+\.[a-z]{2,}$/i.test(v)) return true;        // bare hostname
  if(/^\//.test(v) && v.length > 3) return true;               // path / endpoint
  if(v.length > 48 && v.indexOf(' ') === -1) return true;       // payload/secret/id
  return false;
}
// Columns whose CONTENT is meant to be taken elsewhere (pasted into Burp, a
// curl line, a report) get the button even when a single value happens to be
// short — an endpoint like /api/v2/users or a 20-char AWS key id would
// otherwise miss the length/URL heuristics above.
var RX_COPY_HDR = /url|uri|endpoint|secret|token|payload|poc|host|cname|matched|template|param|path|snippet|key|technolog/i;
function rxCopyableCol(headers, ci){
  if(!headers || !headers.length) return false;
  if(headers.length === 1) return true;          // single-column list: always
  return RX_COPY_HDR.test(String(headers[ci] || ''));
}
// Virtual scroll (kept + improved)
var VS_H=34, VS_OS=8;
function vsInit(uid){ var d=window._VS && window._VS[uid]; if(!d) return; vsCnt(uid); vsRender(uid); }
// A scroll gesture fires many events per frame; render at most once per frame.
var _VS_RAF = {};
function vsRender(uid){
  if(_VS_RAF[uid]) return;
  _VS_RAF[uid] = (window.requestAnimationFrame || function(f){ return setTimeout(f, 16); })(function(){
    _VS_RAF[uid] = 0;
    vsRenderNow(uid);
  });
}
function vsRenderNow(uid){
  var d=window._VS && window._VS[uid]; if(!d) return;
  var c=document.getElementById(uid+'-scroll');
  var vp=document.getElementById(uid+'-vp');
  if(!c||!vp) return;
  var tot=d.filtered.length;
  vp.style.height=(tot*VS_H)+'px';
  var st=c.scrollTop, vh=c.clientHeight;
  var start=Math.max(0, Math.floor(st/VS_H)-VS_OS);
  var end=Math.min(tot, Math.ceil((st+vh)/VS_H)+VS_OS);
  var frag=document.createDocumentFragment();
  for(var i=start;i<end;i++){
    var row=document.createElement('div');
    row.className='vs-row'; row.style.top=(i*VS_H)+'px';
    var txt=d.filtered[i];
    if(typeof txt!=='string') txt = (txt==null) ? '' : String(txt);
    if(txt.indexOf('http')===0){
      var a=document.createElement('a'); a.href=txt; a.target='_blank'; a.rel='noopener';
      a.textContent=txt; a.className='vs-val'; a.style.color='var(--accent2)'; a.style.textDecoration='none';
      rxTip(a, txt);
      if(uid==='vs-proxy'){
        a.removeAttribute('target');
        a.href = '#proxy';
        (function(value){
          a.addEventListener('click', function(ev){
            ev.preventDefault();
            ev.stopPropagation();
            proxyOpen(value);
          });
        })(txt);
      }
      row.appendChild(a);
    } else {
      var esc=document.createElement('span'); esc.className='vs-val'; esc.textContent=txt;
      rxTip(esc, txt);
      row.appendChild(esc);
    }
    // one-click copy of the FULL line, not the ellipsis-truncated render
    (function(value){
      var btn=document.createElement('button');
      btn.type='button'; btn.className='cell-copy vs-copy'; btn.textContent='⧉';
      btn.title='Copy this line';
      btn.onclick=function(ev){
        ev.preventDefault(); ev.stopPropagation();
        rxCopy(value, 'Copied', function(){
          btn.classList.add('copied'); btn.textContent='✓';
          setTimeout(function(){ btn.classList.remove('copied'); btn.textContent='⧉'; }, 900);
        });
      };
      row.appendChild(btn);
    })(txt);
    frag.appendChild(row);
  }
  vp.innerHTML=''; vp.appendChild(frag);
  var cnt=document.getElementById(uid+'-cnt');
  if(cnt) cnt.textContent= d.filtered.length.toLocaleString() + ' / ' + d.raw.length.toLocaleString();
}
function vsCnt(uid){}
function vsFilter(uid){
  var d=window._VS && window._VS[uid]; if(!d) return;
  var q=(document.getElementById(uid+'-q')||{}).value||''; q=q.toLowerCase().trim();
  d.filtered = q ? d.raw.filter(function(x){ return x.toLowerCase().includes(q); }) : d.raw.slice();
  var c=document.getElementById(uid+'-scroll'); if(c) c.scrollTop=0;
  vsRender(uid);
}
function vsCopy(uid){
  var d=window._VS && window._VS[uid]; if(!d) return;
  var txt=d.filtered.join('\n');
  rxCopy(txt, 'Copied ' + d.filtered.length.toLocaleString() + ' lines');
}
function vsExport(uid){
  var d=window._VS && window._VS[uid]; if(!d) return;
  var blob=new Blob([d.filtered.join('\n')],{type:'text/plain'});
  var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=uid+'.txt'; a.click();
}
// Table virtual
function vtFilter(uid){
  var d=window._VT && window._VT[uid]; if(!d) return;
  var q=(document.getElementById(uid+'-q')||{}).value||''; q=q.toLowerCase().trim();
  d.filtered = q ? d.raw.filter(function(r){ var cells = d.rowClass ? r.slice(0,-1) : r; return cells.join(' ').toLowerCase().includes(q); }) : d.raw.slice();
  d.page=0; vtRender(uid);
}
function vtRender(uid){
  var d=window._VT && window._VT[uid]; if(!d) return;
  var body=document.getElementById(uid+'-body');
  var more=document.getElementById(uid+'-more');
  if(!body) return;
  var pageSize=60;
  var end=Math.min(d.filtered.length, (d.page+1)*pageSize);
  // build via DOM to keep textContent safe
  body.innerHTML='';
  for(var i=0;i<end;i++){
    var full=d.filtered[i];
    var cells = d.rowClass ? full.slice(0,-1) : full;
    var cls = d.rowClass ? full[full.length-1] : '';
    var tr=document.createElement('tr');
    if(cls) tr.className=cls;
    var copyCols=d.copyCols||[];
    cells.forEach(function(c,ci){
      var td=document.createElement('td');
      if((copyCols.indexOf(ci)!==-1 || rxCopyable(c) || rxCopyableCol(d.headers, ci)) && c){
        td.className='has-copy';
        var span=document.createElement('span'); span.className='cell-txt'; span.textContent=c; rxTip(span, c);
        var btn=document.createElement('button'); btn.type='button'; btn.className='cell-copy'; btn.textContent='⧉'; btn.title='Copy full value';
        btn.onclick=function(ev){
          ev.stopPropagation();
          rxCopy(c, 'Copied', function(){
            btn.classList.add('copied'); btn.textContent='✓';
            setTimeout(function(){ btn.classList.remove('copied'); btn.textContent='⧉'; },900);
          });
        };
        var wrap=document.createElement('div'); wrap.className='cell-wrap';
        wrap.appendChild(span); wrap.appendChild(btn);
        td.appendChild(wrap);
      } else {
        td.textContent=c;
      }
      tr.appendChild(td);
    });
    body.appendChild(tr);
  }
  if(more) more.textContent = end < d.filtered.length ? (d.filtered.length-end)+' more — scroll to load' : d.filtered.length.toLocaleString()+' rows';
  var cnt=document.getElementById(uid+'-cnt'); if(cnt) cnt.textContent=d.filtered.length.toLocaleString()+' rows';
}
function vtCopy(uid){
  var d=window._VT && window._VT[uid]; if(!d) return;
  var txt=d.filtered.map(function(r){ var cells = d.rowClass ? r.slice(0,-1) : r; return cells.join('\t')}).join('\n');
  rxCopy(txt, 'Copied ' + d.filtered.length.toLocaleString() + ' rows');
}
function vtExportCSV(uid){
  var d=window._VT && window._VT[uid]; if(!d) return;
  var csv=[d.headers.join(',')].concat(d.filtered.map(function(r){ var cells = d.rowClass ? r.slice(0,-1) : r; return cells.map(function(c){return '"'+String(c).replace(/"/g,'""')+'"'}).join(',')})).join('\n');
  var blob=new Blob([csv],{type:'text/csv'}); var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=uid+'.csv'; a.click();
}
// Alive filter
// v8.2-fix: this used to also declare "var _AliveReady=false;" here at global
// script scope. That line ran AFTER the per-section inline <script> (emitted
// inside _section_alive()'s own HTML, earlier in the page) had already set
// window._AliveReady=true — and since a bare "var" at a script's top level
// becomes a property of window, this second declaration silently overwrote it
// back to false. The DOMContentLoaded handler below only calls renderAlive()
// when window._AliveReady is true, so the alive-hosts table's rows (URL/
// Status/Title/IP/Tech/Size/Server/RT) never rendered even though the data
// (window._AR) was present the whole time — confirmed by testing: _AR had 11
// entries, _AliveReady read back false, 0 <tr> rendered. Removed the dead
// re-declaration; showSection() below also now renders defensively so
// clicking into the section always works even if the load-time flag timing
// is ever off again.
function aliveFilter(){
  var q=(document.getElementById('alive-q')||{}).value||''; q=q.toLowerCase();
  window._AF = q ? window._AR.filter(function(r){ return r.join(' ').toLowerCase().includes(q); }) : window._AR.slice();
  window._AP=0; renderAlive();
}
function renderAlive(){
  var body=document.getElementById('alive-body'); if(!body||!window._AF) return;
  var pageSize=60;
  var end=Math.min(window._AF.length, (window._AP+1)*pageSize);
  body.innerHTML='';
  for(var i=0;i<end;i++){
    var r=window._AF[i];
    var tr=document.createElement('tr');
    r.forEach(function(c){ var td=document.createElement('td'); td.textContent=c; tr.appendChild(td); });
    body.appendChild(tr);
  }
  var more=document.getElementById('alive-more');
  if(more) more.textContent = end < window._AF.length ? (window._AF.length-end)+' more' : window._AF.length+' hosts';
  var cnt=document.getElementById('alive-cnt'); if(cnt) cnt.textContent=window._AF.length+' hosts';
}
function aliveCopy(){
  var txt=(window._AF||window._AR||[]).map(function(r){return r[0]}).join('\n');
  rxCopy(txt, 'Copied URLs');
}
function aliveCSV(){
  var rows=window._AF||window._AR||[];
  var csv=['URL,Status,Title,IP,Tech,Size,Server,RT'].concat(rows.map(function(r){return r.map(function(c){return '"'+String(c).replace(/"/g,'""')+'"'}).join(',')})).join('\n');
  var blob=new Blob([csv],{type:'text/csv'}); var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='alive_hosts.csv'; a.click();
}
// Threat Map
var _TM={initialized:false,W:0,H:0};
var _TM_SEV={crit:'#ff4d5e',high:'#ff9838',med:'#ffcf3f',low:'#39d98a'};
var _TM_SEV_L={crit:'CRITICAL',high:'HIGH',med:'MEDIUM',low:'LOW'};
function tmEsc(s){
  return String(s==null?'':s).replace(/[&<>"']/g,function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function tmSev(score){
  score=+score||0;
  return score>=80?'crit':score>=60?'high':score>=40?'med':'low';
}
function initThreatMap(){
  if(_TM.initialized) return;
  if(!window._TM_DATA||typeof d3==='undefined') return;
  var wrap0=document.querySelector('.tm-wrap');
  if(!wrap0 || wrap0.clientWidth<20) return;
  _TM.initialized=true;
  var wrap=document.querySelector('.tm-wrap');
  var svg=d3.select('#tm-svg');
  var W=wrap.clientWidth, H=wrap.clientHeight; _TM.W=W; _TM.H=H; _TM.svg=svg;
  svg.attr('viewBox',[0,0,W,H]);
  var g=svg.append('g');
  var zoom=d3.zoom().scaleExtent([0.35,3.2]).on('zoom',function(e){ g.attr('transform',e.transform); });
  svg.call(zoom);
  var data=window._TM_DATA;
  function sizeOf(d){
    if(d.type==='root') return 22;
    if(d.type==='group') return 13;
    if(d.type==='collapsed') return 8;
    return 7+((+d.score||0)/100)*16;
  }
  function fillOf(d){
    if(d.type==='root') return '#35d0c0';
    if(d.type==='collapsed') return '#44566e';
    if(d.type==='group') return '#6b7c94';
    return _TM_SEV[tmSev(d.score)];
  }
  function shortName(d){
    if(d.type==='group'||d.type==='collapsed') return d.label;
    var base=(data.target||'');
    var label=d.label||d.id||'';
    if(base && label.slice(-(base.length+1))==='.'+base) return label.slice(0,-(base.length+1))||label;
    return label.length>28 ? label.slice(0,28)+'…' : label;
  }
  function tipHTML(d){
    if(d.type!=='root' && d.type!=='subdomain'){
      return '<div class="th">'+tmEsc(d.label)+'</div><div class="r"><span>hosts</span><b>'+tmEsc(d.count||d.vuln_count||0)+'</b></div>';
    }
    var sev=tmSev(d.score);
    var tech=(d.tech&&d.tech.length)?d.tech.map(tmEsc).join(', '):'not recorded';
    var ports=(d.ports&&d.ports.length)?d.ports.map(tmEsc).join(', '):'not recorded';
    return '<div class="th">'+tmEsc(d.label||d.id)+'</div>'
      +'<div class="r"><span>risk</span><b style="color:'+_TM_SEV[sev]+'">'+tmEsc(d.score)+' · '+_TM_SEV_L[sev]+'</b></div>'
      +'<div class="r"><span>IP</span><b>'+tmEsc(d.ip||'not recorded')+'</b></div>'
      +'<div class="r"><span>WAF</span><b style="color:'+(d.waf?'#6b7c94':'#ff9838')+'">'+tmEsc(d.waf||'none')+'</b></div>'
      +'<div class="r"><span>server</span><b>'+tmEsc(d.server||'not recorded')+'</b></div>'
      +'<div class="r"><span>technology</span><b>'+tech+'</b></div>'
      +'<div class="r"><span>ports</span><b>'+ports+'</b></div>'
      +'<div class="r"><span>findings</span><b>'+tmEsc(d.vuln_count||0)+'</b></div>';
  }
  [0.18,0.32,0.46].forEach(function(f){
    g.append('circle').attr('cx',W/2).attr('cy',H/2).attr('r',Math.min(W,H)*f)
      .attr('fill','none').attr('stroke','#1e2b3f').attr('stroke-dasharray','3 6');
  });
  var sim=d3.forceSimulation(data.nodes)
    .force('link', d3.forceLink(data.links).id(function(d){return d.id}).distance(function(d){return d.crit?150:118;}).strength(0.5))
    .force('charge', d3.forceManyBody().strength(-340))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('collide', d3.forceCollide().radius(function(d){ return sizeOf(d)+22; }))
    .force('x', d3.forceX(W/2).strength(function(d){ return d.type==='root'?0.22:0.04; }))
    .force('y', d3.forceY(H/2).strength(function(d){ return d.type==='root'?0.22:0.04; }));
  var link=g.append('g').selectAll('line').data(data.links).enter().append('line')
    .attr('stroke',function(d){ return d.crit?'#ff4d5e':'#27374f'; })
    .attr('stroke-opacity',function(d){ return d.crit?0.55:0.95; })
    .attr('stroke-width',function(d){ return d.crit?1.6:1; });
  var node=g.append('g').selectAll('g').data(data.nodes).enter().append('g')
    .style('cursor',function(d){ return (d.type==='subdomain'||d.type==='root')?'pointer':'default'; })
    .on('click',function(e,d){ if(d.type==='subdomain'||d.type==='root') jumpToHost(d.label||d.id); })
    .call(d3.drag()
      .on('start',function(e,d){ if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag',function(e,d){ d.fx=e.x; d.fy=e.y; })
      .on('end',function(e,d){ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }));
  node.filter(function(d){ return d.type==='root'; }).append('circle')
    .attr('r',22).attr('fill','#0f2a2e').attr('stroke','#35d0c0').attr('stroke-width',2);
  node.filter(function(d){ return d.type==='root'; }).append('circle')
    .attr('r',7).attr('fill','#35d0c0');
  node.filter(function(d){ return d.type!=='root' && !d.waf; }).append('circle')
    .attr('r',function(d){ return sizeOf(d)+5; }).attr('fill','none')
    .attr('stroke',fillOf).attr('stroke-opacity',0.28).attr('stroke-width',2);
  node.filter(function(d){ return d.type!=='root'; }).append('circle')
    .attr('r',sizeOf).attr('fill',fillOf).attr('fill-opacity',0.92)
    .attr('stroke',function(d){ return d.waf?'#172232':'#0a0e16'; }).attr('stroke-width',2);
  node.filter(function(d){ return d.type!=='root' && d.waf; }).append('text')
    .text('⛉').attr('text-anchor','middle').attr('dy',4).attr('font-size',11)
    .attr('fill','#0a0e16').style('pointer-events','none');
  var label=node.append('text').attr('class','tm-label')
    .attr('x',function(d){ return sizeOf(d)+6; }).attr('dy',4)
    .text(function(d){ return d.type==='root' ? '● '+shortName(d) : shortName(d); });
  var tip=document.getElementById('tm-tooltip');
  node.on('mousemove',function(e,d){
    tip.innerHTML=tipHTML(d); tip.style.opacity='1';
    var tx=e.clientX+16, ty=e.clientY+16;
    if(tx+280>window.innerWidth) tx=e.clientX-280;
    if(ty+210>window.innerHeight) ty=e.clientY-210;
    tip.style.left=tx+'px'; tip.style.top=ty+'px';
  }).on('mouseleave',function(){ tip.style.opacity='0'; });
  sim.on('tick',function(){
    link.attr('x1',function(d){return d.source.x}).attr('y1',function(d){return d.source.y})
        .attr('x2',function(d){return d.target.x}).attr('y2',function(d){return d.target.y});
    node.attr('transform',function(d){ return 'translate('+d.x+','+d.y+')'; });
  });
  window.tmResetZoom=function(){ svg.transition().duration(400).call(zoom.transform, d3.zoomIdentity); };
  window.tmToggleLabels=function(){ var v=label.style('display'); label.style('display', v==='none'?'block':'none'); };
  window.tmFilterAlive=function(){
    node.style('opacity',function(d){ return (d.alive||d.type==='root')?1:0.12; });
    link.style('opacity',function(d){
      var t=d.target||{}; return (t.alive||t.type==='root')?1:0.12;
    });
  };
  window.tmFilterAll=function(){ node.style('opacity',1); link.style('opacity',1); };
  window.tmSearch=function(){
    var q=(document.getElementById('tm-search')||{}).value||''; q=q.toLowerCase().trim();
    node.select('circle').attr('stroke',function(d){
      return q && String(d.label||'').toLowerCase().indexOf(q)!==-1 ? '#35d0c0' : (d.waf?'#172232':'#0a0e16');
    }).attr('stroke-width',function(d){
      return q && String(d.label||'').toLowerCase().indexOf(q)!==-1 ? 3 : 2;
    });
  };
}
// Export + print
function toggleExportMenu(){ document.getElementById('export-dropdown').classList.toggle('open'); }
function exportFullHTML(){
  var blob=new Blob([document.documentElement.outerHTML],{type:'text/html'});
  var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='reconx-report.html'; a.click();
  toast('Report exported','ok');
}
function printReport(){ window.print(); }
function setReportTheme(mode){
  if(mode!=='dark') mode='light';
  document.documentElement.setAttribute('data-theme', mode);
  try{ localStorage.setItem('reconx-report-theme', mode); }catch(e){}
  document.querySelectorAll('.theme-btn').forEach(function(b){
    b.classList.toggle('on', b.getAttribute('data-theme-set')===mode);
    b.setAttribute('aria-pressed', b.classList.contains('on') ? 'true' : 'false');
  });
}
(function(){
  var mode='dark';
  try{ var saved=localStorage.getItem('reconx-report-theme'); if(saved==='dark'||saved==='light') mode=saved; }catch(e){}
  setReportTheme(mode);
})();
window.addEventListener('beforeprint', function(){
  document.documentElement.dataset.themePrint = document.documentElement.getAttribute('data-theme') || 'dark';
  document.documentElement.setAttribute('data-theme','light');
});
window.addEventListener('afterprint', function(){
  var back=document.documentElement.dataset.themePrint;
  if(back) setReportTheme(back);
});
function copyReportLink(){ rxCopy(location.href, 'Link copied'); }
document.addEventListener('click',function(e){
  var dd=document.getElementById('export-dropdown');
  var btn=document.getElementById('export-main-btn');
  if(dd && !dd.contains(e.target) && !btn.contains(e.target)) dd.classList.remove('open');
  // mobile: tap outside the open sidebar (and not the hamburger) closes it
  var sb=document.querySelector('.sidebar');
  var sbBtn=document.getElementById('sb-toggle-btn');
  if(sb && sb.classList.contains('open') && !sb.contains(e.target) && !(sbBtn && sbBtn.contains(e.target))){
    closeSidebar();
  }
});
// Command palette (Ctrl+K / /)
(function(){
  var sections=[
    {id:'overview', label:'Dashboard', icon:'🏠'},
    {id:'sitemap', label:'Site Map', icon:'🧭'},
    {id:'threatmap', label:'Threat Map', icon:'🗺️'},
    {id:'recon', label:'Reconnaissance', icon:'🔍'},
    {id:'subdomains', label:'Subdomains', icon:'🌐'},
    {id:'alive', label:'Alive Hosts', icon:'💻'},
    {id:'urls', label:'All URLs', icon:'🔗'},
    {id:'params', label:'Parameters', icon:'⚙️'},
    {id:'categorised', label:'Categorised', icon:'📂'},
    {id:'nuclei', label:'Templates', icon:'🧨'},
    {id:'xss', label:'XSS', icon:'💥'},
    {id:'extra', label:'Extra Checks', icon:'🛡️'},
    {id:'js', label:'JS Secrets', icon:'🔑'},
    {id:'tech', label:'Tech Priority', icon:'⚙️'},
    {id:'api', label:'API Discovery', icon:'⚡'},
  ];
  function openPalette(){
    var ov=document.getElementById('cmdk-overlay');
    if(!ov){
      ov=document.createElement('div'); ov.id='cmdk-overlay'; ov.className='cmdk-overlay';
      ov.innerHTML='<div class="cmdk"><input class="cmdk-input" id="cmdk-input" placeholder="Type a command or search… (ESC to close)"><div class="cmdk-list" id="cmdk-list"></div></div>';
      document.body.appendChild(ov);
      ov.addEventListener('click',function(e){ if(e.target===ov) closePalette(); });
      document.getElementById('cmdk-input').addEventListener('input', renderList);
      document.getElementById('cmdk-input').addEventListener('keydown',function(e){
        if(e.key==='Enter'){ var sel=document.querySelector('.cmdk-item.active'); if(sel) sel.click(); }
        if(e.key==='ArrowDown' || e.key==='ArrowUp'){ e.preventDefault(); moveSel(e.key==='ArrowDown'?1:-1); }
      });
    }
    ov.classList.add('open');
    var inp=document.getElementById('cmdk-input'); inp.value=''; inp.focus(); renderList();
  }
  function closePalette(){ var ov=document.getElementById('cmdk-overlay'); if(ov) ov.classList.remove('open'); }
  // v8.1: sadece bolum isimlerini degil, tablolarda zaten bellekte duran
  // gercek bulgu/host verisini de arar (URL, isim, sonuc metni). Sekmeli
  // (tab icindeki) tablolar kasten disarida birakildi — o pane aktif olmadan
  // deger orada gorunmez, yaniltici olur.
  var DATA_UID_SECTIONS = [
    ['vs-subs','subdomains'], ['vt-sub-tools','subdomains'], ['vt-params','params'],
    ['vt-nuclei','nuclei'], ['vt-xss','xss'], ['vt-js-','js'],
    ['vt-tech','tech'], ['vt-extra-','extra']
  ];
  function sectionForUid(uid){
    for (var i=0;i<DATA_UID_SECTIONS.length;i++){
      if (uid.indexOf(DATA_UID_SECTIONS[i][0])===0) return DATA_UID_SECTIONS[i][1];
    }
    return null;
  }
  function searchAllData(q){
    var out=[]; if(!q||q.length<2) return out;
    if (window._VS) Object.keys(window._VS).forEach(function(uid){
      if (out.length>=6) return;
      var sid=sectionForUid(uid); if(!sid) return;
      var hit=(window._VS[uid].raw||[]).find(function(x){ return String(x).toLowerCase().indexOf(q)!==-1; });
      if (hit) out.push({sid:sid, uid:uid, kind:'vs', text:String(hit)});
    });
    if (window._VT) Object.keys(window._VT).forEach(function(uid){
      if (out.length>=6) return;
      var sid=sectionForUid(uid); if(!sid) return;
      var hit=(window._VT[uid].raw||[]).find(function(r){ return r.join(' ').toLowerCase().indexOf(q)!==-1; });
      if (hit) out.push({sid:sid, uid:uid, kind:'vt', text:hit.join(' · ').slice(0,90)});
    });
    if (window._AR && out.length<6) {
      var hitA=window._AR.find(function(r){ return r.join(' ').toLowerCase().indexOf(q)!==-1; });
      if (hitA) out.push({sid:'alive', uid:'alive', kind:'alive', text:hitA.join(' · ').slice(0,90)});
    }
    return out;
  }
  function jumpToMatch(m, q){
    closePalette();
    showSection(m.sid, document.querySelector('.nav-a[data-sid="'+m.sid+'"]'));
    setTimeout(function(){
      if (m.kind==='alive'){ var qi=document.getElementById('alive-q'); if(qi){ qi.value=q; aliveFilter(); } return; }
      var qi=document.getElementById(m.uid+'-q');
      if (qi){ qi.value=q; if(m.kind==='vs') vsFilter(m.uid); else vtFilter(m.uid); }
    }, 200);
  }
  function renderList(){
    var qRaw=(document.getElementById('cmdk-input').value||'').trim();
    var q=qRaw.toLowerCase();
    var list=document.getElementById('cmdk-list'); list.innerHTML='';
    var first=true;
    sections.filter(function(s){ return !q || s.label.toLowerCase().includes(q) || s.id.includes(q); }).forEach(function(s){
      var div=document.createElement('div'); div.className='cmdk-item'+(first?' active':''); first=false;
      div.innerHTML='<span>'+s.icon+'</span> '+s.label+' <span style="margin-left:auto;color:var(--muted);font-family:var(--mono);font-size:11px">'+s.id+'</span>';
      div.onclick=function(){ closePalette(); var el=document.querySelector('.nav-a[data-sid=\"'+s.id+'\"]'); showSection(s.id, el); };
      list.appendChild(div);
    });
    searchAllData(q).forEach(function(m){
      var div=document.createElement('div'); div.className='cmdk-item'+(first?' active':''); first=false;
      div.innerHTML='<span>🔎</span> <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+
        m.text.replace(/</g,'&lt;')+'</span> <span style="margin-left:auto;color:var(--muted);font-family:var(--mono);font-size:11px;flex-shrink:0">'+m.sid+'</span>';
      div.onclick=function(){ jumpToMatch(m, qRaw); };
      list.appendChild(div);
    });
  }
  function moveSel(dir){
    var items=document.querySelectorAll('.cmdk-item');
    var idx=Array.from(items).findIndex(function(el){return el.classList.contains('active')});
    if(idx>=0){ items[idx].classList.remove('active'); var nxt=Math.max(0,Math.min(items.length-1, idx+dir)); items[nxt].classList.add('active'); }
  }
  document.addEventListener('keydown',function(e){
    if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==='k'){ e.preventDefault(); openPalette(); }
    else if(e.key==='/' && !e.ctrlKey && !e.metaKey && e.target.tagName!=='INPUT'){ e.preventDefault(); openPalette(); }
    else if(e.key==='Escape'){ closePalette(); document.getElementById('export-dropdown')?.classList.remove('open'); closeSidebar(); }
  });
})();
// Auto init virtual scroll + alive
document.addEventListener('DOMContentLoaded',function(){
  (window._VSQ||[]).forEach(function(uid){ try{ vsInit(uid);}catch(e){} });
  (window._VTQ||[]).forEach(function(uid){ try{ d=window._VT[uid]; if(d){ vtRender(uid); }}catch(e){} });
  if(window._AliveReady){ renderAlive(); }
  // Restore section from URL hash on load/refresh (deep link support)
  var initial=(location.hash||'').replace('#','');
  if(initial && document.getElementById('s-'+initial)){
    showSection(initial, document.querySelector('.nav-a[data-sid="'+initial+'"]'));
  }
  window.addEventListener('hashchange',function(){
    var hid=(location.hash||'').replace('#','');
    if(hid && document.getElementById('s-'+hid)){
      showSection(hid, document.querySelector('.nav-a[data-sid="'+hid+'"]'));
    }
  });
  // Tables: load the next page when the scroll nears the bottom. Without this
  // d.page stayed at 0 forever and everything past row 60 was unreachable.
  document.querySelectorAll('.vt-wrap .tbl-scroll').forEach(function(el){
    var body = el.querySelector('tbody[id$="-body"]');
    if(!body) return;
    var uid = body.id.replace(/-body$/, '');
    el.addEventListener('scroll', function(){
      var d = window._VT && window._VT[uid];
      if(!d) return;
      if(el.scrollTop + el.clientHeight < el.scrollHeight - 120) return;
      if((d.page + 1) * 60 >= d.filtered.length) return;     // everything shown
      d.page++;
      vtRender(uid);
    }, {passive:true});
  });
  // .vs-scroll already carries an inline onscroll="vsRender(uid)" from
  // _vscroll(); adding a second listener here ran the whole windowed render
  // twice per scroll event.
});

/* ══════════════════════════════════════════════════════════════════════════
   AI Analysis panel

   Everything rendered here comes from a model that read data collected from a
   third-party target, so every string goes in through textContent / a text
   node and never through innerHTML. One renderer serves both paths: the
   result baked into this file by a previous run, and a live one from the
   bridge.
   ══════════════════════════════════════════════════════════════════════════ */
function aiBridge(){ return (window.__RECONX_AI && window.__RECONX_AI.live) ? window.__RECONX_AI : null; }

function aiEl(tag, cls, text){
  var e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}

function aiCopy(btn, text){
  try {
    navigator.clipboard.writeText(text);
    var old = btn.textContent; btn.textContent = 'copied';
    setTimeout(function(){ btn.textContent = old; }, 1200);
  } catch(e) { /* clipboard blocked (file://, no permission) — nothing to do */ }
}

function aiRow(key, buildValue){
  var r = aiEl('div','ai-row');
  r.appendChild(aiEl('div','ai-row-k', key));
  var v = aiEl('div','ai-row-v');
  buildValue(v);
  r.appendChild(v);
  return r;
}

function aiRenderLead(ld){
  var sev = String(ld.severity || 'info').toLowerCase();
  var wrap = aiEl('div','ai-lead');
  wrap.setAttribute('data-sev', sev);

  var hd = aiEl('div','ai-lead-hd');
  hd.appendChild(aiEl('span','ai-rank','#' + (ld.rank != null ? ld.rank : '?')));
  hd.appendChild(aiEl('span','ai-sev ai-sev-' + sev, sev));
  hd.appendChild(aiEl('span','ai-lead-ttl', ld.title || '(untitled)'));
  hd.appendChild(aiEl('span','ai-conf', 'confidence ' + (ld.confidence || '?')));
  hd.appendChild(aiEl('span','ai-caret','▶'));
  hd.onclick = function(){ wrap.classList.toggle('open'); };
  wrap.appendChild(hd);

  var bd = aiEl('div','ai-lead-bd');
  bd.appendChild(aiRow('Asset', function(v){ v.appendChild(aiEl('span','', ld.asset || '—')); }));
  bd.appendChild(aiRow('Class', function(v){
    v.appendChild(document.createTextNode(ld.vuln_class || '—'));
  }));
  bd.appendChild(aiRow('Why', function(v){ v.appendChild(document.createTextNode(ld.why || '')); }));
  if (ld.chain){
    bd.appendChild(aiRow('Chain', function(v){ v.appendChild(document.createTextNode(ld.chain)); }));
  }
  if (ld.data_check && ld.data_check.length){
    bd.appendChild(aiRow('Data check', function(v){
      ld.data_check.forEach(function(e){ v.appendChild(aiEl('div','ai-ev', e)); });
    }));
  }

  if (ld.evidence && ld.evidence.length){
    bd.appendChild(aiRow('Evidence', function(v){
      ld.evidence.forEach(function(e){ v.appendChild(aiEl('div','ai-ev', e)); });
    }));
  }
  if (ld.verify && ld.verify.length){
    bd.appendChild(aiRow('Verify', function(v){
      ld.verify.forEach(function(c){
        var row = aiEl('div','ai-cmd');
        row.appendChild(aiEl('span','', c));
        var b = aiEl('button','','copy');
        b.onclick = function(ev){ ev.stopPropagation(); aiCopy(b, c); };
        row.appendChild(b);
        v.appendChild(row);
      });
    }));
  }
  bd.appendChild(aiRow('Proves it', function(v){
    v.appendChild(document.createTextNode(ld.proves_it || ''));
  }));
  bd.appendChild(aiRow('N/A if', function(v){
    v.appendChild(document.createTextNode(ld.false_positive_if || ''));
  }));
  wrap.appendChild(bd);
  return wrap;
}

function aiRender(res){
  var out = document.getElementById('ai-out');
  if (!out) return;
  out.textContent = '';

  if (res.stopped){
    var note = 'Stopped. This is everything produced up to that moment — not a finished review.';
    if (res.stopped_during === 'evidence')
      note = 'Stopped while the evidence pack was still being built. The model had not started writing.';
    out.appendChild(aiEl('div','ai-note', note));
  }
  if (res.thinking){
    out.appendChild(aiEl('div','ai-block-lbl','Reasoning so far'));
    out.appendChild(aiEl('div','ai-draft', res.thinking));
  }
  if (res.stopped_during === 'evidence'){
    aiUsage(out, res.meta, res.cached);
    return;
  }

  if (res.kind === 'answer'){
    out.appendChild(aiEl('div','ai-block-lbl', 'Answer'));
    out.appendChild(aiEl('div','ai-answer', res.answer || ''));
    if (res.draft){
      out.appendChild(aiEl('div','ai-block-lbl','Still being written'));
      out.appendChild(aiEl('div','ai-draft', res.draft));
    }
    aiUsage(out, res.meta);
    return;
  }

  if (res.verdict) out.appendChild(aiEl('div','ai-verdict', res.verdict));

  var gaps = res.coverage_gaps || [];
  if (gaps.length){
    out.appendChild(aiEl('div','ai-block-lbl','Coverage gaps — what this scan did NOT establish'));
    var g = aiEl('div','ai-gaps'), gl = aiEl('ul');
    gaps.forEach(function(x){ gl.appendChild(aiEl('li','', x)); });
    g.appendChild(gl); out.appendChild(g);
  }

  var leads = res.leads || [];
  if (leads.length || !res.stopped){
    out.appendChild(aiEl('div','ai-block-lbl',
      leads.length ? ('Leads (' + leads.length + ') — checked against the scan data, not yet tested on the target')
                   : 'Leads — none'));
    if (!leads.length){
      out.appendChild(aiEl('div','ai-note',
        'Nothing in the evidence supported a lead worth testing. That is an answer, not a failure.'));
    }
    leads.forEach(function(ld){ out.appendChild(aiRenderLead(ld)); });
    if (leads.length === 1) out.querySelector('.ai-lead').classList.add('open');
  }

  var dis = res.dismissed || [];
  if (dis.length){
    out.appendChild(aiEl('div','ai-block-lbl','Dismissed (' + dis.length + ') — checked and ruled out'));
    var d = aiEl('div','ai-dismissed');
    dis.forEach(function(x){
      var line = aiEl('div');
      var b = aiEl('b','', x.item || ''); line.appendChild(b);
      line.appendChild(document.createTextNode(' — ' + (x.why || '')));
      d.appendChild(line);
    });
    out.appendChild(d);
  }

  var nxt = res.next_recon || [];
  if (nxt.length){
    out.appendChild(aiEl('div','ai-block-lbl','Next recon'));
    var n = aiEl('div','ai-plain'), nl = aiEl('ul');
    nxt.forEach(function(x){ nl.appendChild(aiEl('li','', x)); });
    n.appendChild(nl); out.appendChild(n);
  }
  if (res.draft){
    out.appendChild(aiEl('div','ai-block-lbl','Still being written'));
    out.appendChild(aiEl('div','ai-draft', res.draft));
  }
  aiUsage(out, res.meta, res.cached);
}

function aiUsage(out, meta, cached){
  if (!meta) return;
  var u = meta.usage || {};
  var parts = [meta.model || '', (meta.duration_sec || '?') + 's'];
  // Which backend answered: the API, or the claude CLI on a subscription.
  if (meta.backend === 'claude-cli') parts.splice(1, 0, 'via claude CLI (subscription)');
  if (u.input_tokens != null) parts.push('in ' + u.input_tokens.toLocaleString());
  if (u.cache_read_input_tokens) parts.push('cache read ' + u.cache_read_input_tokens.toLocaleString());
  if (u.output_tokens != null) parts.push('out ' + u.output_tokens.toLocaleString());
  if (meta.evidence_bytes) parts.push('evidence ' + Math.round(meta.evidence_bytes/1024) + 'KB');
  if (meta.stop_reason === 'stopped') parts.push('stopped early');
  if (meta.generated) parts.push(meta.generated);
  if (cached) parts.push('cached result');
  out.appendChild(aiEl('div','ai-usage', parts.filter(Boolean).join('  ·  ')));
}

var _aiTimer = null;
function aiBusy(on, label){
  var btn = document.getElementById('ai-run');
  var re  = document.getElementById('ai-rerun');
  var st  = document.getElementById('ai-status');
  if (btn) btn.disabled = on;
  if (re)  re.disabled = on;
  if (_aiTimer) { clearInterval(_aiTimer); _aiTimer = null; }
  if (!st) return;
  st.textContent = '';
  if (!on) return;
  var t0 = Date.now();
  var tick = function(){
    var s = Math.round((Date.now() - t0) / 1000);
    st.textContent = '';
    st.appendChild(aiEl('span','ai-spin'));
    st.appendChild(document.createTextNode((label || 'analysing') + '… ' + s + 's'));
  };
  tick();
  _aiTimer = setInterval(tick, 1000);
}

function aiError(msg){
  var out = document.getElementById('ai-out');
  if (!out) return;
  out.textContent = '';
  var e = aiEl('div','ai-note ai-note-err');
  e.appendChild(aiEl('strong','','AI analysis failed: '));
  e.appendChild(document.createTextNode(msg));
  out.appendChild(e);
}

/* ── Live stream pane ────────────────────────────────────────────────────
   A full review runs for minutes. Without live output the panel is a spinner
   and a counter, which reads as a hang — so the analysis is streamed token by
   token and shown as it is produced. */
var _aiTerm = {on:false, t0:0, timer:null, last:null};

function aiTermOpen(label){
  var box = document.getElementById('ai-term');
  var body = document.getElementById('ai-term-body');
  var lbl = document.getElementById('ai-term-lbl');
  if (!box || !body) return;
  body.textContent = '';
  box.classList.add('on');
  if (lbl) lbl.textContent = label || 'analysing';
  var stop = document.getElementById('ai-stop');
  if (stop){ stop.hidden = false; stop.disabled = false; stop.textContent = 'Stop'; }
  _aiTerm.on = true; _aiTerm.t0 = Date.now(); _aiTerm.last = null;
  _aiTerm.stopped = false;
  var cur = aiEl('span','ai-term-cur'); body.appendChild(cur);
  if (_aiTerm.timer) clearInterval(_aiTerm.timer);
  _aiTerm.timer = setInterval(function(){
    var el = document.getElementById('ai-term-el');
    if (el) el.textContent = Math.round((Date.now() - _aiTerm.t0)/1000) + 's';
  }, 1000);
}

function aiTermWrite(kind, text){
  var body = document.getElementById('ai-term-body');
  if (!body) return;
  var cur = body.querySelector('.ai-term-cur');
  var cls = kind === 'thinking' ? 'th' : (kind === 'status' ? 'st' : 'tx');
  // Append into the previous run of the same kind so the DOM does not grow a
  // node per token on a 40k-token answer.
  if (_aiTerm.last && _aiTerm.last.className === cls){
    _aiTerm.last.appendChild(document.createTextNode(text));
  } else {
    var span = aiEl('span', cls, text);
    body.insertBefore(span, cur || null);
    _aiTerm.last = span;
  }
  var near = body.scrollHeight - body.scrollTop - body.clientHeight < 60;
  if (near) body.scrollTop = body.scrollHeight;
}

function aiTermClose(label){
  if (_aiTerm.timer) { clearInterval(_aiTerm.timer); _aiTerm.timer = null; }
  var cur = document.querySelector('#ai-term-body .ai-term-cur');
  if (cur) cur.remove();
  var dot = document.querySelector('.ai-term-dot');
  if (dot) dot.style.animation = 'none';
  var lbl = document.getElementById('ai-term-lbl');
  if (lbl) lbl.textContent = label || 'done';
  var stop = document.getElementById('ai-stop');
  if (stop) stop.hidden = true;
  _aiTerm.on = false;
}

function aiStop(){
  var br = aiBridge();
  if (!br || _aiTerm.stopped) return;
  _aiTerm.stopped = true;
  var btn = document.getElementById('ai-stop');
  if (btn){ btn.disabled = true; btn.textContent = 'Stopping…'; }
  var lbl = document.getElementById('ai-term-lbl');
  if (lbl) lbl.textContent = 'stopping';
  fetch(br.base + '/api/analyze/stop', {
    method: 'POST',
    headers: {'Content-Type':'application/json','X-ReconX-Token': br.token},
    body: '{}'
  }).catch(function(){});
}

function aiStream(body, label){
  var br = aiBridge();
  if (!br) return;
  aiBusy(true, label);
  aiTermOpen(label);
  var out = document.getElementById('ai-out');
  if (out) out.textContent = '';

  fetch(br.base + '/api/analyze/stream', {
    method: 'POST',
    headers: {'Content-Type':'application/json','X-ReconX-Token': br.token},
    body: JSON.stringify(body)
  }).then(function(r){
    if (!r.ok) return r.json().then(function(j){ throw new Error(j.error || ('HTTP ' + r.status)); });
    var reader = r.body.getReader();
    var dec = new TextDecoder();
    var buf = '';
    var finished = false;
    function pump(){
      return reader.read().then(function(res){
        if (res.done) {
          aiBusy(false);
          if (!finished) {
            aiTermClose('failed');
            aiError('the analysis stopped before a result came back');
          }
          return;
        }
        buf += dec.decode(res.value, {stream:true});
        var lines = buf.split('\n');
        buf = lines.pop();
        lines.forEach(function(line){
          if (!line.trim()) return;
          var ev;
          try { ev = JSON.parse(line); } catch(e) { return; }
          if (ev.t === 'thinking' || ev.t === 'text') aiTermWrite(ev.t, ev.v);
          else if (ev.t === 'status') aiTermWrite('status', '\n' + ev.v + '\n');
          else if (ev.t === 'error') { finished = true; aiBusy(false); aiTermClose('failed'); aiError(ev.v); }
          else if (ev.t === 'done') {
            finished = true;
            aiBusy(false);
            aiTermClose(ev.v && ev.v.stopped ? 'stopped' : 'done');
            aiRender(ev.v);
            var re = document.getElementById('ai-rerun');
            var ask = document.getElementById('ai-ask');
            if (re) re.hidden = false;
            if (ask) ask.hidden = false;
          }
        });
        return pump();
      });
    }
    return pump();
  }).catch(function(e){
    aiBusy(false); aiTermClose('failed');
    aiError('could not reach the local AI bridge (' + e.message + ')');
  });
}

function aiPost(body, label){
  var br = aiBridge();
  if (!br) return;
  aiBusy(true, label);
  fetch(br.base + '/api/analyze', {
    method: 'POST',
    headers: {'Content-Type':'application/json','X-ReconX-Token': br.token},
    body: JSON.stringify(body)
  }).then(function(r){
    return r.json().then(function(j){ return {ok: r.ok, body: j}; });
  }).then(function(r){
    aiBusy(false);
    if (!r.ok || r.body.error) { aiError(r.body.error || ('HTTP ' + r.status)); return; }
    aiRender(r.body);
    var re = document.getElementById('ai-rerun');
    var ask = document.getElementById('ai-ask');
    if (re) re.hidden = false;
    if (ask) ask.hidden = false;
  }).catch(function(e){
    aiBusy(false);
    aiError('could not reach the local AI bridge (' + e + ')');
  });
}

function aiRun(refresh){
  // A cached result comes straight back; anything that really runs is streamed.
  if (!refresh && window.__RECONX_AI_RESULT && Object.keys(window.__RECONX_AI_RESULT).length){
    aiPost({refresh:false}, 'loading');
    return;
  }
  aiStream({refresh:true}, refresh ? 're-analysing' : 'analysing');
}

function aiAsk(){
  var inp = document.getElementById('ai-q');
  if (!inp || !inp.value.trim()) return;
  var q = inp.value.trim();
  inp.value = '';
  aiStream({question: q}, 'thinking');
}

document.addEventListener('DOMContentLoaded', function(){
  var cached = window.__RECONX_AI_RESULT;
  var live = aiBridge();
  var offline = document.getElementById('ai-offline');
  var run = document.getElementById('ai-run');
  var re = document.getElementById('ai-rerun');
  var ask = document.getElementById('ai-ask');

  if (cached && Object.keys(cached).length){
    cached.cached = true;
    aiRender(cached);
    if (re && live) re.hidden = false;
    if (ask && live) ask.hidden = false;
    if (run) run.textContent = live ? '✨ Run AI Analysis again' : '✨ Run AI Analysis';
  }
  if (!live){
    if (run) run.disabled = true;
    if (offline) offline.hidden = false;
  }
  var q = document.getElementById('ai-q');
  if (q) q.addEventListener('keydown', function(e){ if (e.key === 'Enter') aiAsk(); });
});

// ── On-demand Scan Center ───────────────────────────────────────────────────
function scanBridge(){ return (window.__RECONX_AI && window.__RECONX_AI.live) ? window.__RECONX_AI : null; }
function rxRetest(btn){
  var url = btn.getAttribute('data-retest') || '';
  var br = (typeof scanBridge === 'function') ? scanBridge() : null;
  if (!br){
    btn.textContent = 'open via bridge';
    return;
  }
  var old = btn.textContent;
  btn.disabled = true;
  btn.textContent = '…';
  fetch(br.base + '/api/retest', {
    method:'POST',
    headers:{'Content-Type':'application/json','X-ReconX-Token': br.token},
    body: JSON.stringify({url: url})
  }).then(function(r){ return r.json().then(function(j){ return {ok:r.ok, j:j}; }); })
    .then(function(res){
      btn.disabled = false;
      if (!res.ok){ btn.textContent = res.j.error || 'failed'; return; }
      var loc = res.j.location ? (' → ' + res.j.location) : '';
      btn.textContent = 'HTTP ' + res.j.status + loc;
    }).catch(function(){ btn.disabled = false; btn.textContent = old; });
}
function scanFocus(t){
  showSection('scans');
  var c = document.getElementById('scard-' + t);
  if (c){ c.scrollIntoView({behavior:'smooth', block:'center'});
          c.classList.add('scan-flash'); setTimeout(function(){ c.classList.remove('scan-flash'); }, 1300); }
}
function scanLogKey(){
  var id = (document.body && document.body.getAttribute('data-scan')) || 'scan';
  return 'reconx-scan-log:' + id;
}
var _scanUserStop = false, _scanLive = false, _scanAbort = null, _scanStopTimer = null;
function scanOnCenter(){
  var sec = document.getElementById('s-scans');
  return !!(sec && sec.classList.contains('active'));
}
function scanHideDock(){
  var dock = document.getElementById('scan-dock');
  if (dock) dock.hidden = true;
  document.body.classList.remove('scan-dock-on');
}
function scanShowDock(){
  var dock = document.getElementById('scan-dock');
  if (!dock) return;
  if (_scanUserStop || !scanOnCenter()) { scanHideDock(); return; }
  dock.hidden = false;
  document.body.classList.toggle('scan-dock-on', !dock.classList.contains('collapsed'));
}
function scanDockToggle(){
  var dock = document.getElementById('scan-dock'); if (!dock) return;
  dock.classList.toggle('collapsed');
  var btn = dock.querySelector('button');
  if (btn) btn.textContent = dock.classList.contains('collapsed') ? 'Show' : 'Hide';
  document.body.classList.toggle('scan-dock-on', !dock.classList.contains('collapsed'));
}
function scanRemember(line){
  try {
    var key = scanLogKey();
    var arr = JSON.parse(sessionStorage.getItem(key) || '[]');
    if (!Array.isArray(arr)) arr = [];
    arr.push(String(line));
    if (arr.length > 1500) arr = arr.slice(arr.length - 1500);
    sessionStorage.setItem(key, JSON.stringify(arr));
  } catch(e){}
}
function scanLog(s, remember){
  var c = document.getElementById('scan-console'); if(!c) return;
  if (remember !== false) scanRemember(s);
  var line = document.createElement('div');
  line.className = 'scan-line';
  var text = String(s || '');
  if (text.indexOf('[XSS VERIFIED]') !== -1) line.className += ' scan-hit-verified';
  else if (text.indexOf('[XSS REFLECTED]') !== -1) line.className += ' scan-hit-reflected';
  else if (/payload:/i.test(text)) line.className += ' scan-hit-payload';
  line.textContent = text;
  c.appendChild(line);
  c.scrollTop = c.scrollHeight;
}
var _scanT0 = 0, _scanTimer = null, _scanProg = null, _scanType = '';
function scanClock(sec){
  sec = Math.max(0, sec|0);
  var h = Math.floor(sec/3600), m = Math.floor((sec%3600)/60), s = sec%60;
  function p(n){ return (n<10?'0':'') + n; }
  return h ? (h + ':' + p(m) + ':' + p(s)) : (p(m) + ':' + p(s));
}
function scanClockStart(keep){
  if (!keep){ _scanT0 = Date.now(); _scanProg = null; }
  else if (!_scanT0) _scanT0 = Date.now();
  if (_scanTimer) clearInterval(_scanTimer);
  _scanTimer = setInterval(scanPaintMeter, 1000);
  scanPaintMeter();
}
function scanClockStop(){ if (_scanTimer){ clearInterval(_scanTimer); _scanTimer = null; } }
function scanPaintMeter(){
  var meter = document.getElementById('scan-meter');
  if (!meter || meter.hidden) return;
  var p = _scanProg || {};
  var elapsed = _scanT0 ? Math.round((Date.now() - _scanT0) / 1000) : (p.elapsed_sec || 0);
  var el = document.getElementById('scan-elapsed');
  if (el) el.textContent = scanClock(elapsed);
  var label = document.getElementById('scan-meter-label');
  if (label){
    var stage = (p.stage != null && p.stage !== '') ? ('Stage ' + p.stage + ' · ') : '';
    label.textContent = stage + (p.label || _scanType || 'scan');
  }
  var hasFrac = p.done != null && p.total;
  var pct = (p.pct != null) ? p.pct : (hasFrac ? Math.round(100 * p.done / p.total) : null);
  var frac = document.getElementById('scan-meter-frac');
  if (frac){
    if (hasFrac) frac.textContent = Number(p.done).toLocaleString() + ' / ' + Number(p.total).toLocaleString() + (p.unit ? (' ' + p.unit) : '');
    else if (p.lines) frac.textContent = Number(p.lines).toLocaleString() + (p.lines === 1 ? ' line' : ' lines');
    else frac.textContent = 'waiting for results…';
  }
  var pctEl = document.getElementById('scan-meter-pct');
  if (pctEl) pctEl.textContent = pct != null ? (pct + '%') : '';
  var fill = document.getElementById('scan-meter-fill');
  if (fill){
    if (pct != null){ fill.classList.remove('ind'); fill.style.width = Math.max(0, Math.min(100, pct)) + '%'; }
    else { fill.classList.add('ind'); fill.style.width = ''; }
  }
  var leftEl = document.getElementById('scan-left');
  var eta = null;
  if (p.eta_sec != null && p.at) eta = Math.max(0, p.eta_sec - Math.round((Date.now() - p.at) / 1000));
  var still = hasFrac && p.done < p.total;
  if (leftEl) leftEl.textContent = (eta && still) ? ('left ' + scanClock(eta)) : '';
  var rate = document.getElementById('scan-rate');
  if (rate) rate.textContent = p.rate || '';
  var note = document.getElementById('scan-note');
  if (note){
    var bits = [];
    if (p.note) bits.push(p.note);
    if (p.stall_sec) bits.push('no new output for ' + scanClock(p.stall_sec));
    note.textContent = bits.join('  ·  ');
  }
  var item = document.getElementById('scan-item');
  if (item){ item.textContent = p.item || ''; item.hidden = !p.item; }
  var res = _scanType && document.getElementById('sres-' + _scanType);
  if (res && _scanTimer){
    var parts = [];
    if (hasFrac) parts.push(Number(p.done).toLocaleString() + '/' + Number(p.total).toLocaleString() + (p.unit ? (' ' + p.unit) : ''));
    else if (p.lines) parts.push(Number(p.lines).toLocaleString() + ' lines');
    if (pct != null) parts.push(pct + '%');
    if (eta && still) parts.push('left ' + scanClock(eta));
    parts.push(scanClock(elapsed));
    res.textContent = parts.join('  ·  ');
  }
  var stt = document.getElementById('scan-status');
  if (stt && _scanTimer) stt.textContent = 'running ' + (_scanType || '') + ' · ' + scanClock(elapsed);
}
function scanApplyProgress(p){
  if (!p || typeof p !== 'object') return;
  var meter = document.getElementById('scan-meter');
  if (meter) meter.hidden = false;
  p.at = Date.now();
  _scanProg = p;
  scanPaintMeter();
}
function scanBadge(t, txt, cls){
  ['sbadge-','cbadge-'].forEach(function(p){ var b = document.getElementById(p + t);
    if (b){ b.textContent = txt; b.className = 'nav-cnt ' + (cls || ''); } });
}
function scanBusy(active, on){
  var stop = document.getElementById('sstop-' + active);
  if (stop) stop.hidden = !on;
  document.querySelectorAll('[data-srun]').forEach(function(b){
    b.disabled = on && b.getAttribute('data-srun') !== active; });
}
var _scanTail = null, _scanTailN = 0, _scanFollow = false, _scanStream = false;
function scanTailStop(){
  _scanFollow = false;
  if (_scanTail){ clearTimeout(_scanTail); _scanTail = null; }
}
function scanStart(t){
  var br = scanBridge();
  if (!br){ alert('This report is open as a static file.\\nRun scans by opening it through the local bridge:\\n\\n  python3 reconx_ai.py serve <session-dir>'); return; }
  _scanUserStop = false;
  _scanLive = true;
  _scanStream = true;
  if (_scanStopTimer){ clearTimeout(_scanStopTimer); _scanStopTimer = null; }
  try { if (_scanAbort) _scanAbort.abort(); } catch(e){}
  _scanAbort = (typeof AbortController !== 'undefined') ? new AbortController() : null;
  scanFocus(t);
  _scanType = t;
  scanShowDock();
  var meter = document.getElementById('scan-meter'); if (meter) meter.hidden = false;
  var cons = document.getElementById('scan-console'); if (cons) cons.textContent = '';
  var res = document.getElementById('sres-' + t); if (res) res.textContent = 'running…';
  scanClockStart();
  scanBusy(t, true); scanBadge(t, '…', 'cnt-blue');
  fetch(br.base + '/api/scan/start', {
    method:'POST', headers:{'Content-Type':'application/json','X-ReconX-Token': br.token},
    body: JSON.stringify({type: t}),
    signal: _scanAbort ? _scanAbort.signal : undefined
  }).then(function(r){
    if (!r.ok) return r.json().then(function(j){ throw new Error(j.error || ('HTTP ' + r.status)); });
    scanTailStop();
    try { sessionStorage.removeItem(scanLogKey()); } catch(e){}
    var reader = r.body.getReader(), dec = new TextDecoder(), buf = '';
    function pump(){ return reader.read().then(function(res){
      if (res.done){ _scanStream = false; scanClockStop(); scanBusy(t, false); return; }
      if (_scanUserStop){
        _scanStream = false;
        try { reader.cancel(); } catch(e){}
        scanClockStop(); scanBusy(t, false); return;
      }
      buf += dec.decode(res.value, {stream:true});
      var lines = buf.split('\n'); buf = lines.pop();
      lines.forEach(function(line){ if (!line.trim()) return; var ev;
        try { ev = JSON.parse(line); } catch(e){ return; }
        if (ev.t === 'log') scanLog(ev.v);
        else if (ev.t === 'progress') scanApplyProgress(ev.v);
        else if (ev.t === 'status') scanLog('=== ' + ev.v + ' ===');
        else if (ev.t === 'error'){ scanLog('[error] ' + ev.v); scanClockStop(); scanBusy(t, false);
          scanBadge(t, 'ERR', 'cnt-red'); var s2 = document.getElementById('scan-status'); if (s2) s2.textContent = 'error'; }
        else if (ev.t === 'done') scanDone(t, ev.v);
      });
      return pump();
    }); }
    return pump();
  }).catch(function(e){
    _scanStream = false;
    scanClockStop(); scanBusy(t, false);
    if (_scanUserStop || (e && (e.name === 'AbortError' || /abort/i.test(String(e.message || e))))) return;
    scanLog('[bridge error] ' + e.message);
    var s3 = document.getElementById('scan-status'); if (s3) s3.textContent = 'bridge error';
    scanBadge(t, 'ERR', 'cnt-red');
  });
}
function scanReloadInPlace(){
  location.reload();
}
function scanWaitStoppedThenReload(){
  var br = scanBridge();
  if (!br){ setTimeout(scanReloadInPlace, 500); return; }
  var tries = 0;
  function tick(){
    tries += 1;
    fetch(br.base + '/api/scan/state', {headers:{'X-ReconX-Token': br.token}})
    .then(function(r){ return r.json(); })
    .then(function(j){
      if (!j.active || tries >= 60){
        scanReloadInPlace();
        return;
      }
      _scanStopTimer = setTimeout(tick, 500);
    })
    .catch(function(){
      if (tries >= 12) scanReloadInPlace();
      else _scanStopTimer = setTimeout(tick, 700);
    });
  }
  _scanStopTimer = setTimeout(tick, 350);
}
function scanDone(t, v){
  scanTailStop();
  scanClockStop();
  scanPaintMeter();
  scanBusy(t, false);
  _scanLive = false;
  var n = (v && v.state) ? (v.state.findings || 0) : 0;
  var err = (v && v.state && v.state.tool_error);
  var stopped = !!(v && v.stopped) || _scanUserStop;
  if (stopped){
    scanHideDock();
    scanBadge(t, err ? 'ERR' : (n ? String(n) : '⏹'), err ? 'cnt-red' : (n ? 'cnt-red' : 'cnt-orange'));
    if (_scanStopTimer) return;
    setTimeout(scanReloadInPlace, 600);
    return;
  }
  scanHideDock();
  scanBadge(t, err ? 'ERR' : (n ? String(n) : '✓'), err ? 'cnt-red' : (n ? 'cnt-red' : 'cnt-green'));
  setTimeout(scanReloadInPlace, 900);
}
function scanStop(){
  if (_scanUserStop) return;
  _scanUserStop = true;
  _scanLive = false;
  scanTailStop();
  scanClockStop();
  var t = _scanType;
  scanBusy(t, false);
  scanHideDock();
  try { sessionStorage.removeItem(scanLogKey()); } catch(e){}
  try { if (_scanAbort) _scanAbort.abort(); } catch(e){}
  scanBadge(t || 'scan', '⏹', 'cnt-orange');
  var br = scanBridge();
  if (!br){ setTimeout(scanReloadInPlace, 400); return; }
  fetch(br.base + '/api/scan/stop', {
    method:'POST', headers:{'Content-Type':'application/json','X-ReconX-Token': br.token}, body:'{}'
  }).catch(function(){});
  scanWaitStoppedThenReload();
}
function scanRefreshState(){
  var br = scanBridge(); if (!br) return;
  fetch(br.base + '/api/scan/state', {headers:{'X-ReconX-Token': br.token}})
  .then(function(r){ return r.json(); }).then(function(j){
    var s = j.scans || {};
    Object.keys(s).forEach(function(t){ var it = s[t];
      if (it.running) scanBadge(t, '…', 'cnt-blue');
      else if (it.tool_error) scanBadge(t, 'ERR', 'cnt-red');
      else if (it.ran) scanBadge(t, it.findings ? String(it.findings) : '✓', it.findings ? 'cnt-red' : 'cnt-green');
    });
    _scanLive = !!j.active;
    if (j.active && !_scanUserStop){ scanShowDock(); scanBusy(j.active, true); }
    else scanHideDock();
  }).catch(function(){});
}
function scanApplySnapshot(j){
  var lines = j.lines || [];
  var total = (j.total != null) ? j.total : lines.length;
  _scanLive = !!j.active;
  if (!j.active || _scanUserStop){ scanHideDock(); }
  else scanShowDock();
  if (!lines.length && !j.active && !j.progress) return;
  var cons = document.getElementById('scan-console');
  var fresh = total < _scanTailN;
  var add = fresh ? lines.length : (total - _scanTailN);
  if (fresh && cons) cons.textContent = '';
  if (add > 0){
    var chunk = add >= lines.length ? lines : lines.slice(lines.length - add);
    if (add >= lines.length && cons && _scanTailN) cons.textContent = '';
    chunk.forEach(function(line){ scanLog(line); });
  }
  _scanTailN = total;
  if (j.active) _scanType = j.active;
  if (j.progress){
    if (!_scanT0 && j.progress.elapsed_sec) _scanT0 = Date.now() - (j.progress.elapsed_sec * 1000);
    scanApplyProgress(j.progress);
  }
  if (j.active){
    scanBusy(j.active, true);
    scanClockStart(true);
    var stt = document.getElementById('scan-status');
    if (stt && !_scanTimer) stt.textContent = 'still running — ' + j.active;
  }
}
function scanTailTick(){
  if (!_scanFollow) return;
  var br = scanBridge(); if (!br) return;
  _scanTail = setTimeout(function(){
    if (!_scanFollow) return;
    fetch(br.base + '/api/scan/log', {headers:{'X-ReconX-Token': br.token}})
    .then(function(r){ return r.json(); }).then(function(j){
      var was = _scanFollow;
      scanApplySnapshot(j);
      if (j.active && !_scanUserStop) scanTailTick();
      else if (was && !_scanUserStop){
        _scanFollow = false;
        var stt = document.getElementById('scan-status');
        if (stt) stt.textContent = 'done — refreshing this report…';
        setTimeout(scanReloadInPlace, 900);
      } else if (was && _scanUserStop){
        _scanFollow = false;
        var stt2 = document.getElementById('scan-status');
        if (stt2) stt2.textContent = 'stopped — refreshing this report…';
        setTimeout(scanReloadInPlace, 700);
      }
    }).catch(function(){ if (_scanFollow) scanTailTick(); });
  }, 2000);
}
function scanRestoreLocal(){
  var cons0 = document.getElementById('scan-console');
  if (cons0 && cons0.childNodes.length) return;
  var arr = [];
  try { arr = JSON.parse(sessionStorage.getItem(scanLogKey()) || '[]'); } catch(e){ arr = []; }
  if (!arr || !arr.length) return;
  var cons = document.getElementById('scan-console');
  if (cons) cons.textContent = '';
  arr.forEach(function(line){ scanLog(line, false); });
  _scanTailN = arr.length;
}
function proxyBind(){
  var src = window._VS && (window._VS['vs-url-live'] || window._VS['vs-url-all']);
  if (!src) return;
  window._VS['vs-proxy'] = window._VS['vs-proxy'] || {raw: src.raw, filtered: src.filtered.slice()};
  vsCnt('vs-proxy');
  vsRender('vs-proxy');
}
function proxyRequestText(url){
  var path = '/', host = url;
  try {
    var u = new URL(url);
    path = (u.pathname || '/') + (u.search || '');
    host = u.host;
  } catch(e){}
  return 'GET ' + path + ' HTTP/1.1\nHost: ' + host + '\nUser-Agent: ReconX-proxy\nAccept: */*\n';
}
var _proxySeq = 0;
function proxyOpen(url){
  var seq = ++_proxySeq;
  var br = scanBridge();
  var req = document.getElementById('proxy-req');
  var res = document.getElementById('proxy-res');
  var cap = document.getElementById('proxy-url');
  if (cap) cap.textContent = url;
  if (req) req.textContent = proxyRequestText(url);
  if (res) res.textContent = 'waiting for the server…';
  document.querySelectorAll('#vs-proxy-vp .vs-row').forEach(function(row){
    var label = row.querySelector('a');
    row.classList.toggle('proxy-hit', !!(label && label.textContent === url));
  });
  if (!br){
    if (res) res.textContent = 'Open this report through the local bridge to load the response.';
    return;
  }
  fetch(br.base + '/api/exchange', {
    method:'POST',
    headers:{'Content-Type':'application/json','X-ReconX-Token': br.token},
    body: JSON.stringify({url: url})
  }).then(function(r){ return r.json().then(function(j){ return {ok:r.ok, j:j}; }); })
    .then(function(x){
      if (seq !== _proxySeq) return;
      if (!x.ok){ if (res) res.textContent = x.j.error || 'request failed'; return; }
      if (req && x.j.request) req.textContent = x.j.request;
      if (res) res.textContent = x.j.response || '(empty response)';
    }).catch(function(e){ if (seq === _proxySeq && res) res.textContent = String(e); });
}
function scanReplayLog(){
  if (_scanStream) return;
  scanRestoreLocal();
  var br = scanBridge(); if (!br) return;
  fetch(br.base + '/api/scan/log', {headers:{'X-ReconX-Token': br.token}})
  .then(function(r){ return r.json(); }).then(function(j){
    var lines = j.lines || [];
    var total = j.total || lines.length;
    if (lines.length && total !== _scanTailN){
      var cons = document.getElementById('scan-console');
      if (cons) cons.textContent = '';
      _scanTailN = 0;
      lines.forEach(function(line){ scanLog(line, false); });
      try { sessionStorage.setItem(scanLogKey(), JSON.stringify(lines.slice(-1500))); } catch(e){}
      _scanTailN = j.total || lines.length;
    }
    scanApplySnapshot(j);
    if (j.active && !_scanFollow && !_scanUserStop && !_scanStream){ _scanFollow = true; scanTailTick(); }
  }).catch(function(){});
}
document.addEventListener('visibilitychange', function(){
  if (!document.hidden) scanReplayLog();
});
document.addEventListener('DOMContentLoaded', function(){ try { scanRefreshState(); scanReplayLog(); } catch(e){} });
"""


# ══════════════════════════════════════════════════════════════════════════════
# Scan Center — deep analysis and active tests, run after the recon report.
# Network/port also runs during recon; its card re-runs that pass.
# Keep this list aligned with reconx_ai.SCAN_TYPES.
# ══════════════════════════════════════════════════════════════════════════════
#          type          icon   label                 summary-key  metric-key         description
SCAN_UI = [
    ("js",           "🔑", "JS Analysis",         "stage10", "secrets",
     "Download every in-scope JavaScript file and extract endpoints and secrets. No recon-time cap."),
    ("api",          "⚡", "API Discovery",       "stage13", "live_hits",
     "GraphQL, Swagger and OpenAPI against the URL corpus collected in recon."),
    ("xss",          "💥", "XSS Testing",         "stage6",  "findings",
     "Reflected / stored XSS on the high-value URLs, with headless alert proof."),
    ("nuclei",       "🧨", "Template Scan",       "stage7",  "findings",
     "CVE and injection templates over the full live-URL corpus."),
    ("openredirect", "↪️", "Open Redirect",       "stage15", "findings",
     "Redirect parameters checked with a canary host. Confirmed only when Location leaves the site."),
    ("network",      "📡", "Network / Port",      "stage14", "open_ports_total",
     "Runs during recon: port discovery, then service detection. Re-run here for a fresh pass."),
    ("cors",         "🌐", "CORS",                "stage12", "cors_vulnerable",
     "Cross-origin resource-sharing misconfiguration on the alive hosts."),
    ("takeover",     "🪝", "Subdomain Takeover",  "stage12", "takeover_vulnerable",
     "Dangling-CNAME takeover check across the discovered subdomains."),
    ("bucket",       "🪣", "Cloud Bucket",        "stage12", "bucket_public",
     "cloud_enum tries the target name on AWS S3, Azure and Google Cloud. Open listings are recorded. Nothing is uploaded."),
]
# scans whose full findings live in their own report section (link "View details")
_SCAN_SECTION = {"js": "js", "api": "api", "xss": "xss", "nuclei": "nuclei",
                 "openredirect": "openredirect",
                 "cors": "extra", "takeover": "extra", "bucket": "extra"}


def _parse_network(d: Path) -> dict:
    """stage14 naabu/nmap results — {hosts:[{host,ports:[{port,service,...}]}]}."""
    p = Path(d) / "14_network" / "network_results.json"
    if p.exists():
        try:
            return json.loads(p.read_text(errors="ignore")) or {"hosts": []}
        except Exception:
            pass
    return {"hosts": []}


def _parse_openredirect(d: Path) -> dict:
    """stage15 OpenRedireX + canary-verification results."""
    p = Path(d) / "15_open_redirect" / "open_redirect_results.json"
    if p.exists():
        try:
            return json.loads(p.read_text(errors="ignore")) or {}
        except Exception:
            pass
    return {}


def _scan_status_map(smry_json: dict) -> dict:
    """Per-scan-type status for the Scan Center cards + sidebar badges, from the
    session SUMMARY.json (regenerated after every stage run)."""
    stages = (smry_json or {}).get("stages") or {}
    out = {}
    for t, icon, label, skey, mkey, desc in SCAN_UI:
        s = stages.get(skey) or {}
        status = s.get("status") or ""
        if skey == "stage12" and status == "done":
            chk = {"cors": "cors_checked", "takeover": "takeover_checked",
                   "bucket": "bucket_checked"}[t]
            ran = int(s.get(chk, 0) or 0) > 0
        else:
            ran = status in ("done", "tool_error", "partial")
        out[t] = {
            "icon": icon, "label": label, "desc": desc,
            "ran": bool(ran), "status": status or "available",
            "findings": int(s.get(mkey, 0) or 0) if ran else 0,
            "tool_error": bool(s.get("tool_failed")),
            "interrupted": bool(s.get("interrupted")),
            "duration": s.get("duration_sec", 0),
        }
    return out


def _scan_badge_attrs(st: dict):
    """(text, css-color-class) for a scan's status badge."""
    if st.get("tool_error"):
        return "ERR", "cnt-red"
    if not st.get("ran"):
        return "•", ""
    n = st.get("findings", 0)
    return (str(n), "cnt-red") if n else ("✓", "cnt-green")


def _scan_sidebar(scan_map: dict) -> str:
    items = ['<div class="nav-grp"><div class="nav-lbl">More scans</div>',
             '  <a class="nav-a" data-sid="scans" onclick="showSection(\'scans\',this)">'
             '<span class="nav-ico">🎯</span>Scan Center</a>']
    for t, icon, label, *_ in SCAN_UI:
        txt, cls = _scan_badge_attrs(scan_map.get(t, {}))
        items.append(
            f'  <a class="nav-a" data-scan="{t}" onclick="scanFocus(\'{t}\')">'
            f'<span class="nav-ico">{icon}</span>{_e(label)}'
            f'<span class="nav-cnt {cls}" id="sbadge-{t}">{txt}</span></a>')
    items.append('</div>')
    return "\n".join(items)


def _network_table(network: dict) -> str:
    hosts = [h for h in (network.get("hosts") or []) if h.get("ports")]
    if not hosts:
        return ""
    rows = []
    for h in hosts:
        for pt in h.get("ports", []):
            svc = " ".join(x for x in (pt.get("service", ""), pt.get("product", ""),
                                       pt.get("version", "")) if x) or "—"
            rows.append(
                f'<tr><td style="font-family:var(--mono);color:var(--text)">{_e(h.get("host",""))}</td>'
                f'<td style="font-family:var(--mono);color:var(--accent2,#8ab4ff)">{pt.get("port","")}/{_e(pt.get("proto","tcp"))}</td>'
                f'<td style="color:var(--text-dim)">{_e(svc)}</td></tr>')
    return (
        '<div style="overflow:auto;margin-top:10px"><table style="width:100%;border-collapse:collapse;font-size:12px">'
        '<thead><tr style="text-align:left;color:var(--muted)">'
        '<th style="padding:6px 10px">Host</th><th style="padding:6px 10px">Port</th>'
        '<th style="padding:6px 10px">Service / Version</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div>')


def _section_openredirect(oredir: dict) -> str:
    findings = oredir.get("findings", []) or []
    # Older result files were written without "status". A file that lists
    # findings or a checked count is a finished scan; only a missing file
    # means the stage has not run.
    ran = bool(oredir) and (
        oredir.get("status") in ("done", "partial", "tool_error")
        or "findings" in oredir
        or oredir.get("checked") is not None
    )
    checked = int(oredir.get("checked", 0) or 0)
    canary = oredir.get("canary", "")
    tool = oredir.get("tool", "")

    if not ran:
        body = ('<div class="cat-desc" style="margin-bottom:10px">'
                'Not scanned yet — run <strong>Open Redirect</strong> from the '
                'Scan Center.</div>')
        return (f'<div id="s-openredirect" class="section">'
                f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
                f'<h2>↪️ Open Redirect</h2><p class="sec-sub">not scanned yet</p>'
                f'</div></div></div>{body}</div>')

    stat_row = [_stat(len(findings), "Confirmed", "orange" if findings else "green", "↪️"),
                _stat(checked, "URLs tested", "blue", "🎯")]
    body = (f'<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;'
            f'margin-bottom:14px">{"".join(stat_row)}</div>')
    meta_bits = []
    if canary:
        meta_bits.append(f"canary host: {_e(canary)}")
    if oredir.get("interrupted"):
        meta_bits.append("interrupted — coverage may be partial")
    if meta_bits:
        body += (f'<div style="font-size:11px;color:var(--muted);margin:-6px 0 14px">'
                 f'{" &middot; ".join(meta_bits)}</div>')
    body += ('<div class="cat-desc" style="margin-bottom:14px">'
             'Each redirect-like parameter is injected with a canary host; a finding '
             'is confirmed only when the target returns a <code>Location</code> header '
             'pointing off-domain to that canary — a replayable proof, not just '
             '"a redirect happened".</div>')

    if findings:
        rows = []
        for f in findings:
            poc = f.get("test_url", "")
            rows.append(
                '<tr>'
                f'<td style="padding:8px 10px;font-family:var(--mono);color:var(--text);word-break:break-all">{_e(f.get("url",""))}</td>'
                f'<td style="padding:8px 10px;font-family:var(--mono);color:var(--accent2,#8ab4ff)">{_e(f.get("param",""))}</td>'
                f'<td style="padding:8px 10px;font-family:var(--mono);color:#9f1239;word-break:break-all">{_e(f.get("location","")[:160])}</td>'
                f'<td style="padding:8px 10px;font-family:var(--mono);color:var(--text-dim)">{f.get("status","")}</td>'
                f'<td style="padding:8px 10px"><button class="btn-sm" onclick="copyOne(this)" '
                f'data-copy="{_e(poc)}">Copy PoC</button> {_retest_btn(poc)}</td>'
                '</tr>')
        body += (
            '<div style="overflow:auto"><table style="width:100%;border-collapse:collapse;font-size:12px">'
            '<thead><tr style="text-align:left;color:var(--muted)">'
            '<th style="padding:8px 10px">URL</th>'
            '<th style="padding:8px 10px">Parameter</th>'
            '<th style="padding:8px 10px">Confirmed redirect (Location)</th>'
            '<th style="padding:8px 10px">Status</th>'
            '<th style="padding:8px 10px">PoC</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')
    else:
        body += ('<div class="alert-box alert-ok">'
                 '✓ No parameter followed the canary off-domain — no confirmed open redirect.</div>')

    if oredir.get("tool_raw"):
        body += (f'<div style="font-size:11px;color:var(--muted);margin-top:12px">'
                 f'Raw scanner output: '
                 f'<code>{_e(str(oredir.get("tool_raw","")))}</code></div>')

    return (f'<div id="s-openredirect" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>↪️ Open Redirect</h2>'
            f'<p class="sec-sub">{len(findings):,} confirmed &middot; {checked:,} tested'
            f' &middot; RISK: {"MEDIUM" if findings else "NONE"}</p>'
            f'</div></div></div>{body}</div>')


def _section_scans(scan_map: dict, network: dict) -> str:
    cards = []
    for t, icon, label, skey, mkey, desc in SCAN_UI:
        st = scan_map.get(t, {})
        btxt, bcls = _scan_badge_attrs(st)
        ran = st.get("ran")
        if st.get("tool_error"):
            resline = '⚠ scan error — see the console'
        elif not ran:
            resline = 'Not scanned yet — press Run.'
        else:
            n = st.get("findings", 0)
            noun = {"network": "open port(s)", "js": "secret candidate(s)",
                    "api": "live endpoint(s)"}.get(t, "finding(s)")
            resline = (f'{n:,} {noun}' if n else 'Completed — no findings')
            dur = _fmt_dur(st.get("duration"))
            if dur:
                resline += f' · {dur}'
            if st.get("interrupted"):
                resline += ' (interrupted — may be incomplete)'
            elif st.get("status") == "partial":
                resline += ' · in progress'
        detail = _network_table(network) if (t == "network" and ran) else ""
        view = ""
        if _SCAN_SECTION.get(t) and ran:
            view = (f'<a class="scan-view" style="font-size:12px;color:var(--accent2,#8ab4ff);'
                    f'cursor:pointer" onclick="showSection(\'{_SCAN_SECTION[t]}\')">View details →</a>')
        run_label = "Re-run" if ran else "Run"
        cards.append(
            f'<div class="scan-card" id="scard-{t}">'
            f'<h4>{icon} {_e(label)}<span class="nav-cnt {bcls}" id="cbadge-{t}" '
            f'style="margin-left:auto">{btxt}</span></h4>'
            f'<div class="scan-desc">{_e(desc)}</div>'
            f'<div class="scan-res" id="sres-{t}">{resline}</div>'
            f'{detail}'
            f'<div class="scan-actions">'
            f'<button class="btn-run" id="srun-{t}" data-srun="{t}" '
            f'onclick="scanStart(\'{t}\')">{run_label}</button>'
            f'<button class="btn-stop" id="sstop-{t}" onclick="scanStop()" hidden>Stop</button>'
            f'{view}</div>'
            f'</div>')

    intro = (
        '<div class="cat-desc" style="margin-bottom:6px">'
        'Recon collects subdomains, URLs, technology and ports, then writes this report. '
        'These cards are the slow tests — JS analysis, API discovery, XSS, template scan, open '
        'redirect, CORS, takeover and cloud buckets — run one at a time against that corpus. '
        'Each writes back into this report; the page reloads when a scan finishes.</div>'
        '<div style="font-size:11px;color:var(--muted);margin-bottom:4px">'
        'Requires the report to be open through the local bridge '
        '(<code>reconx_ai.py serve</code>, started automatically after recon). '
        'Opened as a plain file, the Run buttons are inert.</div>')

    return (f'<div id="s-scans" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>🎯 Scan Center</h2>'
            f'<p class="sec-sub">On-demand active scans &middot; one click each</p>'
            f'</div></div></div>'
            f'{intro}<div class="scan-grid">{"".join(cards)}</div></div>')


_WHOIS_CREATED = ("creation date", "created", "registered", "registration time",
                  "domain registration date", "registered on")
_WHOIS_EXPIRES = ("registry expiry date", "registrar registration expiration date",
                  "expiry date", "expiration date", "paid-till", "expires", "expire")
_WHOIS_REGISTRAR = ("registrar",)
_WHOIS_ORG = ("registrant organization", "registrant org", "orgname", "org-name",
              "organization", "registrant")
_WHOIS_NS = ("name server", "nserver", "nameserver")
_NS_VENDORS = (
    ("cloudflare", "Cloudflare"),
    ("awsdns", "Amazon Web Services"),
    ("azure-dns", "Microsoft Azure"),
    ("googledomains", "Google"),
    ("google.com", "Google"),
    ("domaincontrol", "GoDaddy"),
    ("registrar-servers", "GoDaddy"),
    ("akam.net", "Akamai"),
    ("fastly", "Fastly"),
    ("dnsimple", "DNSimple"),
    ("nsone", "NS1"),
    ("digitalocean", "DigitalOcean"),
    ("hetzner", "Hetzner"),
    ("ovh.", "OVH"),
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_SKIP_EMAIL_HOSTS = {
    "example.com", "example.org", "domain.com", "sentry.io", "w3.org",
    "schema.org", "wordpress.org", "googleapis.com", "gstatic.com",
}


def _whois_card(text: str) -> dict:
    """Registration fields from a whois record, including nic.tr / TRABIS layout
    where the label is a section header and the value is the next line."""
    card = {"registrar": "", "org": "", "created": "", "expires": "",
            "nameservers": [], "emails": [], "phones": []}
    section = ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("**"):
            section = line.strip("* ").split(":", 1)[0].strip().lower()
            continue
        key, _, val = line.partition(":")
        norm = re.sub(r"[.\s]+", " ", key).strip().lower()
        val = val.strip().strip(".")
        if section.startswith("registrant") and ":" not in line and "hidden" not in line.lower():
            if not card["org"]:
                card["org"] = line.strip()
            continue
        if section.startswith("domain server") and ":" not in line:
            host = line.split()[0].strip().rstrip(".").lower()
            if "." in host and host not in card["nameservers"]:
                card["nameservers"].append(host)
            continue
        if not val:
            continue
        if norm in ("organization name", "registrant organization", "registrant org", "orgname", "org-name"):
            if section.startswith("registrar") and not card["registrar"]:
                card["registrar"] = val
            elif not card["org"]:
                card["org"] = val
        elif norm in _WHOIS_REGISTRAR or norm.startswith("registrar "):
            if norm != "registrar" or (val and "http" not in val.lower()):
                if not card["registrar"]:
                    card["registrar"] = val
        elif any(norm == k or norm.startswith(k + " ") for k in _WHOIS_CREATED):
            card["created"] = card["created"] or val
        elif any(norm == k or norm.startswith(k + " ") or k.startswith(norm) for k in _WHOIS_EXPIRES):
            card["expires"] = card["expires"] or val
        elif norm in _WHOIS_NS or norm.startswith("name server") or norm.startswith("nserver"):
            host = val.split()[0].strip().rstrip(".").lower()
            if host and host not in card["nameservers"]:
                card["nameservers"].append(host)
        elif "phone" in norm and "fax" not in norm and section.startswith("registrant") and not card["phones"]:
            card["phones"].append(val)
        elif "email" in norm or "e-mail" in norm:
            card["emails"].extend(_EMAIL_RE.findall(val))
    card["nameservers"] = card["nameservers"][:6]
    return card


def _whois_values(text: str, keys: tuple) -> list:
    found = []
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        if key.strip().lower() in keys:
            val = val.strip()
            if val and val not in found:
                found.append(val)
    return found


def _first(values: list, default: str = "") -> str:
    return values[0] if values else default


def _clean_emails(blobs) -> list:
    out, seen = [], set()
    for blob in blobs:
        if isinstance(blob, (list, tuple)):
            bits = blob
        else:
            bits = _EMAIL_RE.findall(str(blob or ""))
        for raw in bits:
            em = str(raw).lower().strip(".").strip()
            if "@" not in em or em in seen:
                continue
            host = em.rsplit("@", 1)[-1]
            if host in _SKIP_EMAIL_HOSTS or any(host.endswith("." + s) for s in _SKIP_EMAIL_HOSTS):
                continue
            if host.endswith((".png", ".jpg", ".gif", ".svg", ".css", ".js")):
                continue
            seen.add(em)
            out.append(em)
            if len(out) >= 16:
                return out
    return out


def _whatweb_bits(text: str) -> dict:
    """Pull short technology labels. Verbose WhatWeb dumps a prose plugin
    manual after Summary; only the summary (or a one-line scan row) is used."""
    techs, titles = [], []
    skip = {"country", "ip", "script", "x-powered-by", "uncommonheaders",
            "redirectlocation", "via", "cookies", "status", "title"}
    summaries = []
    for line in (text or "").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("["):
            continue
        low = raw.lower()
        if low.startswith("title"):
            val = raw.split(":", 1)[-1].strip()
            if val and val not in titles and len(val) < 90:
                titles.append(val)
            continue
        if low.startswith("summary"):
            summaries.append(raw.split(":", 1)[-1].strip())
    blobs = list(summaries)
    if not blobs:
        for line in (text or "").splitlines():
            line = line.strip()
            if line.startswith("http"):
                blobs.append(re.sub(r"^https?://\S+\s+", "", line))
    for blob in blobs:
        blob = re.sub(r"^\s*\[\d{3}[^\]]*\]\s*", "", blob)
        for part in blob.split(","):
            part = part.strip()
            if not part:
                continue
            name = part.split("[", 1)[0].strip()
            low = name.lower()
            if not name or low.startswith("country"):
                continue
            bracket = ""
            m = re.search(r"\[([^\]]+)\]", part)
            if m:
                bracket = m.group(1).strip()
            if low == "httpserver":
                brackets = re.findall(r"\[([^\]]+)\]", part)
                label = next((b.strip() for b in brackets if "/" in b), "")
                if not label and brackets:
                    label = brackets[-1].strip()
                if not label:
                    continue
            elif low in skip:
                continue
            elif bracket and bracket.lower() not in name.lower():
                ver = bracket.split()[0]
                label = f"{name} {ver}".strip() if ver else name
            else:
                label = name
            label = re.sub(r"\s+", " ", label).strip()
            if re.match(r"^\d{3}\b", name):
                continue
            if label and label not in techs and len(label) <= 48:
                techs.append(label)
    return {"techs": techs[:24], "title": titles[0] if titles else ""}


def _whatweb_by_host(text: str) -> dict:
    """Hostname -> technology labels, from one-line WhatWeb rows."""
    found = {}
    for line in (text or "").splitlines():
        line = line.strip()
        m = re.search(r"https?://\S+", line)
        if not m:
            continue
        try:
            host = (urlparse(m.group(0).rstrip(",")).hostname or "").lower()
        except Exception:
            host = ""
        if not host:
            continue
        for label in (_whatweb_bits(line).get("techs") or []):
            found.setdefault(host, [])
            if label not in found[host]:
                found[host].append(label)
    return found


def _waf_by_host(text: str, fallback_host: str, fallback: list) -> dict:
    found = {}
    for line in (text or "").splitlines():
        m = re.search(r"https?://[^\s'\"]+", line, re.I)
        host = ""
        if m:
            try:
                host = (urlparse(m.group(0)).hostname or "").lower()
            except Exception:
                host = ""
        behind = re.search(r"is behind\s+(.+?)(?:\s+WAF)?\.?\s*$", line, re.I)
        if host and behind:
            name = behind.group(1).strip(" .")
            if name and "no waf" not in name.lower():
                found.setdefault(host, [])
                if name not in found[host]:
                    found[host].append(name)
    if fallback and fallback_host and fallback_host not in found:
        found[fallback_host] = [str(x) for x in fallback if x]
    return found


def _dns_vendor(nameservers: list, apex: str = "") -> str:
    blob = " ".join(nameservers).lower()
    for needle, label in _NS_VENDORS:
        if needle in blob:
            return label
    apex = (apex or "").strip(".").lower()
    if apex and nameservers:
        own = [ns for ns in nameservers if ns == apex or ns.endswith("." + apex)]
        if own and len(own) == len(nameservers):
            return "In-house"
    return ""


def _nmap_ports(text: str) -> list:
    ports = []
    for line in (text or "").splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line.strip())
        if not m:
            continue
        ports.append({
            "port": m.group(1), "proto": m.group(2),
            "service": m.group(3) or "", "detail": (m.group(4) or "").strip(),
        })
    return ports[:24]


def _section_sitemap(target, recon, alive, tech, network, vuln_map=None) -> str:
    """Identity map: registration, edge, stack, contacts and per-host footprint."""
    apex = (target or "").strip().lower()
    probe = recon.get("probe") or {}
    whois = recon.get("whois") or ""
    ww = _whatweb_bits(recon.get("whatweb") or "")
    card = _whois_card(whois)
    created = card["created"] or _first(_whois_values(whois, _WHOIS_CREATED), "Not recorded")
    expires = card["expires"] or _first(_whois_values(whois, _WHOIS_EXPIRES), "Not recorded")
    registrar = card["registrar"] or _first(_whois_values(whois, _WHOIS_REGISTRAR), "Not recorded")
    org = card["org"] or _first(_whois_values(whois, _WHOIS_ORG), "Not recorded")
    nameservers = list(card["nameservers"] or _whois_values(whois, _WHOIS_NS))
    for line in (recon.get("dns") or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].upper() == "NS":
            host = parts[1].strip().rstrip(".").lower()
            if host and host not in nameservers:
                nameservers.append(host)
    nameservers = nameservers[:6]
    dns_vendor = _dns_vendor(nameservers, apex) or "Not identified"
    saved = recon.get("contacts") or {}
    emails = _clean_emails([
        saved.get("emails") or [],
        probe.get("emails") or [],
        card.get("emails") or [],
        whois,
        recon.get("harvester") or "",
    ])
    phones = []
    seen_ph = set()
    for raw in list(saved.get("phones") or []) + list(probe.get("phones") or []) + list(card.get("phones") or []):
        pretty = str(raw).strip()
        if pretty and pretty not in seen_ph:
            seen_ph.add(pretty)
            phones.append(pretty)
        if len(phones) >= 8:
            break
    title = (probe.get("title") or ww.get("title") or "")
    if not title:
        for host in alive or []:
            if host.get("title"):
                title = host["title"]
                break
    server = (probe.get("server") or "")
    if not server:
        for host in alive or []:
            if host.get("server"):
                server = host["server"]
                break
    status = str(probe.get("status") or "")
    ip = ""
    for host in alive or []:
        if host.get("ip"):
            ip = host["ip"]
            break
    apex = (target or "").strip().lower()
    waf_map = _waf_by_host(recon.get("wafw00f") or "", apex, probe.get("waf_fingerprint") or [])
    techs = list(ww.get("techs") or [])
    for item in tech or []:
        for name in (item.get("techs") or item.get("top_techs") or []):
            label = str(name).strip()
            if label and label not in techs:
                techs.append(label)
    for host in alive or []:
        for name in str(host.get("tech") or "").split(","):
            label = name.strip()
            if label and label not in techs:
                techs.append(label)
    techs = techs[:28]

    def _kv(rows):
        body = "".join(
            f"<span>{_e(k)}</span><b>{_e(v) if v else 'Not recorded'}</b>"
            for k, v in rows
        )
        return f'<div class="sm-kv">{body}</div>'

    def _chips(items, css=""):
        if not items:
            return '<div style="color:var(--muted);font-size:13px">Not recorded</div>'
        return "".join(f'<span class="sm-chip {css}">{_e(str(x))}</span>' for x in items)

    sev_color = {80: "#ff4d5e", 60: "#ff9838", 40: "#ffcf3f", 0: "#39d98a"}

    def _sev_color(score):
        score = int(score or 0)
        if score >= 80:
            return sev_color[80]
        if score >= 60:
            return sev_color[60]
        if score >= 40:
            return sev_color[40]
        return sev_color[0]

    def _tip_rows(rows):
        return "".join(
            f'<div class="r"><span>{_e(k)}</span><b>{_e(v) if v else "not recorded"}</b></div>'
            for k, v in rows
        )

    lookup = _asset_lookup(target, alive, recon, network, vuln_map)
    seen_hosts = []
    for host in alive or []:
        url = host.get("url") or ""
        try:
            name = (urlparse(url).hostname or "").lower()
        except Exception:
            name = ""
        if name and name not in seen_hosts:
            seen_hosts.append(name)
    if apex and apex not in seen_hosts:
        seen_hosts.insert(0, apex)
    seen_hosts = seen_hosts[:24]
    profiles = []
    for name in seen_hosts:
        prof = lookup(name, True)
        prof["host"] = name
        profiles.append(prof)
    spokes = [p for p in profiles if p["host"] != apex]
    if not spokes and profiles:
        spokes = profiles[1:]
    lines = []
    pins = []
    n = len(spokes) or 1
    for i, prof in enumerate(spokes):
        ang = -math.pi / 2 + (2 * math.pi * i / n)
        x = 50 + math.cos(ang) * 34
        y = 48 + math.sin(ang) * 30
        color = _sev_color(prof["score"])
        lines.append(
            f'<line x1="50" y1="48" x2="{x:.2f}" y2="{y:.2f}" '
            f'stroke="{color if prof["score"] >= 80 else "#27374f"}" '
            f'stroke-opacity="{"0.55" if prof["score"] >= 80 else "0.95"}" '
            f'stroke-width="{"0.35" if prof["score"] >= 80 else "0.22"}"/>'
        )
        short = prof["host"]
        if apex and short.endswith("." + apex):
            short = short[:-(len(apex) + 1)] or short
        mark = "⛉" if prof["waf"] else ""
        bare = "" if prof["waf"] else " bare"
        pins.append(
            f'<div class="estate-pin" style="left:{x:.2f}%;top:{y:.2f}%">'
            f'<div class="estate-dot host{bare}" style="background:{color}">{mark}</div>'
            f'<div class="estate-name">{_e(short)}</div>'
            f'<div class="estate-tip"><b>{_e(prof["host"])}</b>'
            f'{_tip_rows([("risk", str(prof["score"])), ("IP", prof["ip"]), ("WAF", prof["waf"] or "none"), ("server", prof["server"]), ("technology", ", ".join(prof["tech"])), ("ports", ", ".join(prof["ports"]))])}'
            f'</div></div>'
        )
    center = lookup(apex, True) if apex else {}
    center_pin = (
        f'<div class="estate-pin" style="left:50%;top:48%">'
        f'<div class="estate-dot root">●</div>'
        f'<div class="estate-name">{_e(target)}</div>'
        f'<div class="estate-tip"><b>{_e(target)}</b>'
        f'<div class="r"><span>title</span><b>{_e(title or "not recorded")}</b></div>'
        f'{_tip_rows([("IP", center.get("ip") or ip), ("WAF", center.get("waf") or "none"), ("server", center.get("server") or server), ("technology", ", ".join(center.get("tech") or techs[:6])), ("ports", ", ".join(center.get("ports") or []))])}'
        f'</div></div>'
    )
    districts = [
        ("Registration", _kv([
            ("Registrar", registrar),
            ("Organization", org),
            ("Published", created),
            ("Expires", expires),
        ])),
        ("Infrastructure", _kv([
            ("Address", ip or "Not recorded"),
            ("DNS provider", dns_vendor),
            ("Name servers", ", ".join(nameservers) or "Not recorded"),
            ("Edge server", server or "Not recorded"),
        ])),
        ("Technology", _chips(techs)),
        ("Contacts on the site", _kv([
            ("Email", ", ".join(emails) or "Not recorded"),
            ("Phone", ", ".join(phones) or "Not recorded"),
        ])),
    ]
    district_html = "".join(
        f'<div class="sm-card"><h4>{_e(heading)}</h4>{inner}</div>'
        for heading, inner in districts
    )
    edge_rows = [(host, ", ".join(names)) for host, names in sorted(waf_map.items()) if names]
    edge_html = (
        f'<div class="sm-card" style="margin-top:12px"><h4>Edge protection by host</h4>'
        f'{_kv(edge_rows) if edge_rows else _chips([])}</div>'
    )
    return (
        f'<div id="s-sitemap" class="section">'
        f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
        f'<h2>Site Map</h2>'
        f'<p class="sec-sub">{_e(title or target)} · hover a host for IP, WAF, technology and ports</p>'
        f'</div></div></div>'
        f'<div class="estate">'
        f'<svg class="estate-svg" viewBox="0 0 100 100" preserveAspectRatio="none">{"".join(lines)}</svg>'
        f'{center_pin}{"".join(pins)}'
        f'</div>'
        f'<div class="estate-districts">{district_html}</div>'
        f'{edge_html}</div>'
    )


def build_report(scan_dir, target: str, summary: dict = None) -> Path:
    scan_dir = Path(scan_dir)
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M")
    _RX_VER  = _reconx_version() or "?"

    recon    = _parse_recon(scan_dir)
    subs     = _parse_subdomains(scan_dir)
    alive    = _parse_alive(scan_dir)
    urls     = _parse_url_categories(scan_dir)
    smry_json= _parse_summary_json(scan_dir)
    nuc      = _parse_nuclei(scan_dir)
    xss      = _parse_xss(scan_dir)
    js       = _parse_js_secrets(scan_dir)
    tech     = _parse_tech(scan_dir)
    extra    = _parse_extra(scan_dir)
    api      = _parse_api(scan_dir)            # v6.13+: CORS / Takeover / Bucket
    network  = _parse_network(scan_dir)        # v9.4: stage14 naabu/nmap ports
    oredir   = _parse_openredirect(scan_dir)    # v9.4: stage15 open-redirect
    scan_map = _scan_status_map(smry_json)      # v9.4: on-demand scan status
    # A refresh mid-scan reads per-URL result files before SUMMARY is marked done.
    if xss.get("findings"):
        scan_map["xss"]["ran"] = True
        scan_map["xss"]["status"] = scan_map["xss"]["status"] if scan_map["xss"]["status"] not in ("", "available") else "partial"
        scan_map["xss"]["findings"] = max(int(scan_map["xss"].get("findings") or 0), len(xss["findings"]))
    try:
        _st_stages = (json.loads((Path(scan_dir) / "checkpoints" / "state.json")
                                 .read_text(errors="ignore")) or {}).get("stages") or {}
    except Exception:
        _st_stages = {}
    _stage_num = {"stage6": "6", "stage7": "7", "stage10": "10", "stage12": "12",
                  "stage13": "13", "stage14": "14", "stage15": "15"}
    for _t, _icon, _label, _skey, _mkey, _desc in SCAN_UI:
        _rec = _st_stages.get(_stage_num.get(_skey, "")) or {}
        if _rec.get("duration_sec") and not (scan_map.get(_t) or {}).get("duration"):
            scan_map[_t]["duration"] = _rec["duration_sec"]
    ai       = _parse_ai(scan_dir)             # v9.1: saved AI analysis, if any
    vuln_map = _build_vuln_map(nuc, xss, extra, oredir)   # feeds the Threat Map's severity layer
    extra_vuln_n = (sum(1 for r in extra.get("cors", []) if r.get("vulnerable")) +
                    sum(1 for r in extra.get("takeover", []) if r.get("vulnerable")) +
                    sum(1 for r in extra.get("buckets", []) if r.get("public_listing")))

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
  {_nav("🧭","Site Map","sitemap")}
  {_nav("🗺️","Threat Map","threatmap", len(subs["all"]))}
</div>
<div class="nav-grp"><div class="nav-lbl">Reconnaissance</div>
  {_nav("🔍","Recon","recon")}
  {_nav("🌐","Subdomains","subdomains", len(subs["all"]))}
  {_nav("💻","Alive Hosts","alive", len(alive))}
</div>
<div class="nav-grp"><div class="nav-lbl">Discovery</div>
  {_nav("🔗","All URLs","urls", len(urls.get("_collected") or urls.get("_all") or []))}
  {_nav("🔀","Proxy","proxy", len(urls.get("_all") or urls.get("_collected") or []))}
  {_nav("⚙️","Parameters","params")}
  {_nav("📂","Categorised","categorised")}
  {_nav("🔑","JS Secrets","js", len(js.get("secrets",[])), "purple")}
  {_nav("⚡","API Discovery","api", len(api.get("probes",[])) + sum(len(v) for v in api.get("found",{}).values()))}
  {_nav("⚙️","Tech Priority","tech", len(tech), "blue")}
</div>
{_scan_sidebar(scan_map)}
<div class="nav-grp"><div class="nav-lbl">Scan results</div>
  {_nav("🧨" if not nuc.get("meta",{}).get("tool_failed") else "⚠️","Templates","nuclei", len(nuc.get("findings",[])) if not nuc.get("meta",{}).get("tool_failed") else "ERR", "red")}
  {_nav("💥" if not xss.get("meta",{}).get("tool_failed") else "⚠️","XSS","xss", len(xss.get("findings",[])) if not xss.get("meta",{}).get("tool_failed") else "ERR", "orange" if not xss.get("meta",{}).get("tool_failed") else "red")}
  {_nav("↪️","Open Redirect","openredirect", len(oredir.get("findings",[])) if oredir else None, "red" if (oredir.get("findings") if oredir else None) else None)}
  {_nav("🛡️","Extra Checks","extra", extra_vuln_n, "red" if extra_vuln_n else None)}
</div>
<div class="nav-grp"><div class="nav-lbl">Analysis</div>
  {_nav("✨","AI Analysis","ai", len(ai.get("leads") or []) if ai else None, "purple")}
</div>
<hr class="nav-hr">
<div class="sb-hint">
  <kbd>/</kbd> to search &nbsp;·&nbsp; Virtual scroll<br>
  Professional Edition v{_RX_VER}
</div>'''

    sections = "".join([
        _section_overview(target, ts, recon, subs, alive, urls, smry_json,
                          nuc=nuc, xss=xss, js=js, tech=tech, extra=extra,
                          scan_dir=scan_dir, oredir=oredir),
        _section_sitemap(target, recon, alive, tech, network, vuln_map=vuln_map),
        _section_threatmap(target, subs, alive, vuln_map=vuln_map, recon=recon, network=network),
        _section_recon(recon),
        _section_subdomains(subs),
        _section_alive(alive),
        _section_urls(urls, prune=(smry_json.get("stages", {}).get("stage4") or {}).get("prune")),
        _section_proxy(urls),
        _section_params(urls),
        _section_categorised(urls),
        _section_scans(scan_map, network),
        _section_nuclei(nuc),
        _section_xss(xss),
        _section_openredirect(oredir),
        _section_extra(extra),
        _section_api(api),
        _section_js(js),
        _section_tech(tech),
        _section_ai(ai, scan_dir),
    ])

    # ── Export Button HTML (fixed top-right) ──────────────────────────────────
    export_html = '''<!-- Export Button (fixed top-right) -->
<div class="export-btn-wrap">
  <div class="theme-switch" role="group" aria-label="Report theme">
    <button type="button" class="theme-btn" data-theme-set="light" onclick="setReportTheme('light')">White</button>
    <button type="button" class="theme-btn on" data-theme-set="dark" aria-pressed="true" onclick="setReportTheme('dark')">Dark</button>
  </div>
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
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconX &mdash; {_e(target)}</title>
<script>
try{{var __rxTheme=localStorage.getItem('reconx-report-theme');if(__rxTheme==='dark'||__rxTheme==='light')document.documentElement.setAttribute('data-theme',__rxTheme);}}catch(e){{}}
</script>
<style>{_CSS}</style>
</head>
<body data-scan="{_e(target)}">
<button class="sb-toggle" id="sb-toggle-btn" onclick="toggleSidebar()" aria-label="Toggle menu">
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
</button>
<div class="sb-scrim" onclick="toggleSidebar()"></div>
<nav class="sidebar">{sidebar}</nav>
<main class="main">
{sections}
<div class="footer">
  ReconX Professional Edition v{_RX_VER} &nbsp;&middot;&nbsp; {_e(target)} &nbsp;&middot;&nbsp; {_e(ts)}<br>
  Use only on authorized targets under a valid bug bounty program.
</div>
</main>
<div id="scan-dock" hidden>
  <div style="display:flex;align-items:center;gap:10px;padding:16px 22px 12px 28px">
    <strong style="font-size:13px">Live output</strong>
    <span id="scan-status" style="font-size:12px;color:var(--muted)"></span>
    <button class="btn-sm" type="button" onclick="scanDockToggle()" style="margin-left:auto">Hide</button>
    <button class="btn-stop" onclick="scanStop()">Stop scan</button>
  </div>
  <div id="scan-meter" class="scan-meter" hidden style="margin:0 12px 8px">
    <div class="scan-meter-top"><span id="scan-meter-label">scan</span>
    <span id="scan-meter-frac"></span><span id="scan-meter-pct"></span></div>
    <div class="scan-meter-track"><div id="scan-meter-fill" class="scan-meter-fill ind"></div></div>
    <div class="scan-meter-meta"><span>elapsed <b id="scan-elapsed">00:00</b></span>
    <span id="scan-left"></span><span id="scan-rate"></span><span id="scan-note"></span></div>
    <div id="scan-item" class="scan-meter-item" hidden></div>
  </div>
  <pre class="scan-console" id="scan-console"></pre>
</div>
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
