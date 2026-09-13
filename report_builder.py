#!/usr/bin/env python3


import json, re, html
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs, parse_qsl


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
        "wafw00f":   _read(d / "01_recon" / "wafw00f.txt"),
        "harvester": _read(d / "01_recon" / "theharvester.xml") or _read(d / "01_recon" / "theharvester.json"),
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
_DALFOX_TYPE_LABELS = {"V": "Verified (headless)", "R": "Reflected", "G": "Grep match",
                        "RV": "Verified (ReconX replay)"}

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
    severity = str(rec.get("severity") or "")
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
    if jf.exists():
        try:
            raw = jf.read_text(errors="ignore").lstrip()
            if raw[:1] == "[":
                data = json.loads(raw)
                if isinstance(data, list):
                    for rec in data:
                        if isinstance(rec, dict):
                            g = _xss_rec(rec)
                            if g:
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
                            if g:
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
    meta["ran"] = meta["status"] not in ("", "skipped")
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
            return {k for k, _ in parse_qsl(urlparse(u).query)}
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
    tested = []
    for u in tested_urls:
        key = _path_key(u)
        u_params = _params_of(u)
        hits = []
        for f in hits_by_path.get(key, []):
            fp = f.get("param") or ""
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
        tested.append({
            "url": u,
            "vulnerable": bool(hits),
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
    return {"endpoints": endpoints, "secrets": uniq, "detail": detail}


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


def _build_vuln_map(nuc: dict, xss: dict, extra: dict) -> dict:
    """Nuclei/XSS/Extra-checks bulgularini hostname'e gore birlestirip Threat Map'in
    zafiyet katmanini besler (high/medium/low/info + kumulatif sayim)."""
    order = {"high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}
    vmap: dict = {}

    def _bump(host: str, sev: str):
        if not host:
            return
        norm = "high" if sev in ("critical", "high") else sev if sev in ("medium", "low", "info") else "info"
        cur = vmap.setdefault(host, {"severity": "none", "count": 0})
        cur["count"] += 1
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
    return vmap


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


def _poc_field(value: str, label: str = "PoC URL") -> str:
    """A full string (URL + payload, curl line, ...) shown in one selectable
    box with a single 'Copy' button — copies the WHOLE thing in one click,
    never a CSS-truncated fragment."""
    v = value or ""
    return (f'<div class="poc-field"><span class="poc-lbl">{_e(label)}</span>'
            f'<code class="poc-val">{_e(v)}</code>'
            f'<button class="poc-copy" data-copy="{_e(v)}" onclick="copyOne(this)">Copy</button></div>')

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
def _section_overview(target, ts, recon, subs, alive, urls, smry_json,
                      nuc=None, xss=None, js=None, tech=None, extra=None):
    nuc = nuc or {}; xss = xss or {}; tech = tech or []; extra = extra or {}
    sc_n    = len(subs["all"])
    alive_n = len(alive)
    url_n   = len(urls.get("_all", []))
    par_n   = len(urls.get("params", []))
    sens_n  = len(urls.get("sensitive", []))
    refl_n  = len(urls.get("reflection", []))

    # URL kaynak sayıları — reconx'in gerçekte ürettiği dosyalar üzerinden.
    # gau tüm pasif provider'lari (wayback/otx/commoncrawl/urlscan) tek dosyada
    # toplar; wayback/gospider/commoncrawl/urlscan/otx ayrı dosyalar şu an
    # reconx'ta üretilmiyor, o yüzden onlari chart'a katmıyoruz (0 görünmesin).
    src_counts = {"gau": len(urls.get("_gau", [])), "katana": len(urls.get("_katana", []))}
    _src_extra = {
        "hakrawler": len(urls.get("_hakrawler", [])),
        "wayback":   len(urls.get("_wayback", [])),
        "gospider":  len(urls.get("_gospider", [])),
        "commoncrawl": len(urls.get("_commoncrawl", [])),
        "urlscan":   len(urls.get("_urlscan", [])),
        "otx":       len(urls.get("_otx", [])),
    }
    for _k in ("hakrawler", "wayback", "gospider", "commoncrawl", "urlscan", "otx"):
        if _src_extra[_k] > 0:
            src_counts[_k] = _src_extra[_k]

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

    extra_stats = []
    if nuc and nuc.get("findings"):
        extra_stats.append(_stat(len(nuc["findings"]), "Nuclei Findings", "red", "🧨"))
    if xss and xss.get("findings"):
        extra_stats.append(_stat(len(xss["findings"]), "XSS Findings", "orange", "💥"))
    if js and js.get("secrets"):
        extra_stats.append(_stat(len(js["secrets"]), "JS Secrets", "purple", "🔑"))
    if tech:
        high = sum(1 for t in tech if t.get("risk_label") == "high")
        if high:
            extra_stats.append(_stat(high, "Tech High-Risk", "orange", "⚙️"))
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
                    f'<span style="width:8px;height:8px;border-radius:50%;background:#4ade80;display:inline-block"></span>'
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
    state_badge = (_badge("SCAN INCOMPLETE", "orange") if incomplete
                   else _badge("RECON COMPLETE", "green"))
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
                piece += f' <strong style="color:#4ade80">+{d["new"]:,} new</strong>'
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
    crit_n = int(sev.get("critical", 0)); high_n = int(sev.get("high", 0)); med_n = int(sev.get("medium", 0))
    # v8.6-fix: the score used the RAW dalfox finding count for XSS — one
    # reflected search box that echoes 20 payloads counted as 20 * 5 = 100,
    # which alone pushed a Medium-at-most site to "410 CRITICAL". Score the
    # XSS surface by verified findings (heavy) + unique unconfirmed injection
    # points (light).
    _xf = xss.get("findings", []) if xss else []
    _verified_labels = {_DALFOX_TYPE_LABELS["V"], _DALFOX_TYPE_LABELS["RV"]}
    xss_verified_n = sum(1 for f in _xf if f.get("type") in _verified_labels)
    _xss_points = set()
    for f in _xf:
        try:
            pp = urlparse(f.get("url") or ""); _xss_points.add((pp.netloc, pp.path, f.get("param") or ""))
        except Exception:
            pass
    xss_point_n = max(len(_xss_points), 1 if _xf else 0) - xss_verified_n
    xss_n = len(_xf)
    tech_high_n = sum(1 for t in tech if t.get("risk_label") == "high") if tech else 0
    extra_vuln_n = (sum(1 for r in extra.get("cors", []) if r.get("vulnerable")) +
                    sum(1 for r in extra.get("takeover", []) if r.get("vulnerable")) +
                    sum(1 for r in extra.get("buckets", []) if r.get("public_listing")))
    risk_score = (crit_n*10 + high_n*6 + med_n*3
                  + xss_verified_n*6 + max(0, xss_point_n)*2
                  + extra_vuln_n*7 + tech_high_n*2)
    if risk_score >= 40:
        risk_lvl, risk_col, risk_bg = "CRITICAL", "#dc2626", "rgba(220,38,38,.12)"
    elif risk_score >= 20:
        risk_lvl, risk_col, risk_bg = "HIGH", "#f97316", "rgba(249,115,22,.12)"
    elif risk_score >= 8:
        risk_lvl, risk_col, risk_bg = "MEDIUM", "#eab308", "rgba(234,179,8,.12)"
    elif risk_score > 0:
        risk_lvl, risk_col, risk_bg = "LOW", "#3b82f6", "rgba(59,130,246,.12)"
    else:
        risk_lvl, risk_col, risk_bg = "NONE", "#22c55e", "rgba(34,197,94,.12)"
    # v8.1: dairesel risk göstergesi — .risk-gauge/.risk-gauge-circle CSS'i daha
    # önce tanımlıydı ama hiç kullanılmıyordu. risk_score'u bir SVG halkaya
    # çeviriyoruz (60+ skor = halka tam dolu kabul edilir).
    _RING_R = 30.0
    _RING_C = 2 * 3.14159265 * _RING_R
    gauge_pct = max(0.0, min(1.0, risk_score / 60.0)) if risk_score > 0 else 0.0
    gauge_offset = _RING_C * (1 - gauge_pct)
    risk_gauge_svg = f'''<svg width="72" height="72" viewBox="0 0 72 72">
    <circle cx="36" cy="36" r="{_RING_R}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="8"/>
    <circle cx="36" cy="36" r="{_RING_R}" fill="none" stroke="{risk_col}" stroke-width="8"
            stroke-linecap="round" stroke-dasharray="{_RING_C:.2f}" stroke-dashoffset="{gauge_offset:.2f}"
            style="transition:stroke-dashoffset .6s ease"/>
  </svg>'''
    exec_html = f'''<div class="panel" style="border-color:{risk_col}44;margin-bottom:16px;background:linear-gradient(135deg,{risk_bg},var(--surface1) 70%)">
  <div class="risk-gauge" style="background:transparent;border:none;padding:0;margin-bottom:0">
    <div class="risk-gauge-circle" style="color:{risk_col}">
      {risk_gauge_svg}
      <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
                  font-family:var(--display);font-weight:800;font-size:15px;color:{risk_col}">{risk_score}</div>
    </div>
    <div class="risk-gauge-label">
      <strong style="color:{risk_col}">{_e(risk_lvl)}</strong>
      <span class="risk-pct">&nbsp;&middot; risk score {risk_score} / 60+</span>
      <div style="font-size:12px;color:var(--muted);margin-top:4px">
        Nuclei: {crit_n} critical &middot; {high_n} high &middot; {med_n} medium &nbsp;|&nbsp;
        XSS: {xss_n} &nbsp;|&nbsp; CORS/Takeover/Bucket: {extra_vuln_n} &nbsp;|&nbsp;
        High-risk technology: {tech_high_n} host(s)
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
    all_u = urls.get("_all", [])
    prune = prune or {}
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

    note = ""
    if prune.get("enabled"):
        if prune.get("ran") and prune.get("removed", 0) > 0:
            note = (f'<div style="font-size:11px;color:var(--muted);margin-bottom:14px;padding:8px 12px;'
                    f'background:var(--surface2);border-radius:6px;border-left:3px solid var(--border)">'
                    f'✓ Dead-URL pruning: {prune.get("before",0):,} URLs collected &rarr; '
                    f'<strong style="color:var(--text-dim)">{prune.get("removed",0):,} removed</strong> '
                    f'(filtered: {_e(prune.get("filter_codes","404"))} or unreachable) &rarr; '
                    f'{prune.get("after",0):,} live URLs remain below. '
                    f'<span style="opacity:.7">(tools.prune_dead_urls in config.yaml)</span></div>')
        elif not prune.get("ran"):
            note = (f'<div style="font-size:11px;color:var(--muted);margin-bottom:14px;padding:8px 12px;'
                    f'background:var(--surface2);border-radius:6px;border-left:3px solid var(--border)">'
                    f'⚠ Dead-URL pruning was enabled but did not run (httpx unavailable or errored) — '
                    f'the list below is unfiltered and may include dead/404 URLs.</div>')
    else:
        note = (f'<div style="font-size:11px;color:var(--muted);margin-bottom:14px;padding:8px 12px;'
                f'background:var(--surface2);border-radius:6px;border-left:3px solid var(--border)">'
                f'Dead-URL pruning is disabled (tools.prune_dead_urls: false in config.yaml) — '
                f'the list below is unfiltered and may include dead/404 URLs.</div>')

    body = note + (_tabs(tab_items, "url") if tab_items else _empty())
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

def _section_threatmap(target: str, subs: dict, alive: list, vuln_map: dict = None) -> str:
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
                    "live_hits": data.get("live_hits") or []}
        except Exception:
            pass
    return {"found": {}, "probes": [], "live_hits": []}

def _section_api(api_data):
    found = api_data.get("found") or {}
    probes = api_data.get("probes") or []
    live_hits = api_data.get("live_hits") or []
    total_hits = sum(len(v) for v in found.values())
    if total_hits == 0 and not probes and not live_hits:
        return (f'<div id="s-api" class="section">'
                f'<div class="sec-hdr"><div class="sec-hdr-inner"><div><h2>API Discovery</h2></div></div></div>'
                f'{_empty("No GraphQL / Swagger endpoints discovered — run Stage 13 or check URL sources")}</div>')
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
    badges = " ".join(_badge(f"{s.upper()} {sev.get(s,0)}", sev_color.get(s, "gray"))
                      for s in sev_order if sev.get(s, 0))

    body = ""
    if tool_failed:
        body += (f'<div class="alert-box alert-red" style="margin-bottom:14px">'
                 f'⚠ <strong>Nuclei exited with an error:</strong>&nbsp;{_e(meta.get("tool_error",""))} '
                 f'— this does NOT necessarily mean the target is clean; the scan may not have completed.</div>')
    elif interrupted:
        body += (f'<div class="alert-box" style="margin-bottom:14px;background:rgba(249,115,22,.08);'
                 f'border-color:rgba(249,115,22,.3);color:#fdba74">'
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
             'Nuclei vulnerability scan on alive hosts</div>')

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
        rows = [[(str(f.get("severity") or "info").upper()),
                 ("DAST" if f.get("source") == "dast" else "tpl"),
                 (f.get("name") or "")[:80],
                 (f.get("matched_at") or "")[:140],
                 (f.get("template") or "")[:60],
                 ", ".join(f.get("cve") or [])[:60],
                 (f"{f['cvss_score']:.1f}" if f.get("cvss_score") else ""),
                 ", ".join(f.get("tags") or [])[:60]]
                for f in findings]
        body += _vtable(["Severity", "Source", "Name", "Matched At", "Template", "CVE", "CVSS", "Tags"], rows, "vt-nuclei")
        cve_n = sum(1 for f in findings if f.get("cve"))
        if cve_n:
            body += (f'<div style="font-size:11px;color:var(--muted);margin-top:8px">'
                     f'{cve_n:,} finding(s) map to a known CVE — cross-reference with '
                     f'<a href="https://nvd.nist.gov/vuln/search" target="_blank" rel="noopener" '
                     f'style="color:var(--accent2)">NVD</a> for exploit/patch details.</div>')
    elif ran:
        body += _empty("Scan completed — 0 findings.")
    else:
        body += _empty("Nuclei scan not run.")

    raw_txt = (nuc.get("raw_txt") or "").strip()
    if raw_txt:
        body += (f'<div class="subsection-label" style="margin-top:20px">Raw Tool Output</div>'
                 f'<details><summary style="cursor:pointer;color:var(--muted);font-size:12px;'
                 f'margin-bottom:8px">Show nuclei\'s own text output ({len(raw_txt.splitlines()):,} lines)</summary>'
                 f'{_code_block(raw_txt)}</details>')

    return (f'<div id="s-nuclei" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>Nuclei</h2>'
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
    risk_label, risk_color = ("HIGH", "red") if findings else ("NONE", "green")

    # v8.5-fix: sort so the genuinely-confirmed findings (dalfox's own "V", or
    # ReconX's own replay-confirmed "RV") lead the table, "Reflected" (payload
    # echoed back but never confirmed to execute) after, weaker "Grep match"
    # last — requested directly: most of a real scan's raw findings turned
    # out to be unconfirmed text matches, and the confirmed ones were getting
    # lost in the noise at whatever position dalfox happened to report them.
    _TYPE_RANK = {_DALFOX_TYPE_LABELS["V"]: 0, _DALFOX_TYPE_LABELS["RV"]: 0,
                  _DALFOX_TYPE_LABELS["R"]: 1, _DALFOX_TYPE_LABELS["G"]: 2}
    findings = sorted(findings, key=lambda f: _TYPE_RANK.get(f.get("type", ""), 1))

    verified_n  = sum(1 for f in findings if f.get("type") in (_DALFOX_TYPE_LABELS["V"], _DALFOX_TYPE_LABELS["RV"]))
    unconfirmed_n = len(findings) - verified_n

    body = ""
    if tool_failed:
        body += (f'<div class="alert-box alert-red" style="margin-bottom:14px">'
                 f'⚠ <strong>Dalfox exited with an error:</strong>&nbsp;{_e(meta.get("tool_error",""))} '
                 f'— this does NOT necessarily mean the target is clean; the scan may not have completed.</div>')
    elif budget_hit:
        body += (f'<div class="alert-box" style="margin-bottom:14px;background:rgba(56,189,248,.08);'
                 f'border-color:rgba(56,189,248,.3);color:#7dd3fc">'
                 f'ℹ <strong>Dalfox reached its time budget and was stopped.</strong>&nbsp;'
                 f'Findings written so far are complete and kept (dalfox streams them to disk), '
                 f'but not every target was necessarily finished — raise '
                 f'<code>tools.dalfox_time_budget_sec</code> for full coverage.</div>')
    elif interrupted:
        body += (f'<div class="alert-box" style="margin-bottom:14px;background:rgba(249,115,22,.08);'
                 f'border-color:rgba(249,115,22,.3);color:#fdba74">'
                 f'⚠ <strong>Scan was interrupted (Ctrl+C):</strong>&nbsp;{_e(meta.get("tool_error","") or "not all targets were tested")}</div>')

    body += (f'<div style="display:flex;gap:8px;margin-bottom:16px">'
            f'{_stat(len(findings), "XSS Findings", "orange", "💥")}'
            f'{_stat(verified_n, "Verified (real execution proven)", "red", "✅")}'
            f'{_stat(unconfirmed_n, "Unconfirmed (reflected/grep only)", "gray", "❔")}'
            f'{_stat(risk_label, "Risk Level", risk_color, "🎯")}</div>'
            f'<div class="cat-desc" style="margin-bottom:16px">'
            f'Reflected &amp; DOM XSS candidates from dalfox scan. <strong>Verified</strong> means dalfox '
            f'itself (or ReconX, replaying it in a real headless browser) caught the payload actually '
            f'executing — treat these as real. <strong>Reflected/Grep match</strong> only means the payload '
            f'text came back unescaped somewhere in the response — dalfox did not confirm it runs, so double '
            f'check the context (e.g. open the PoC URL yourself) before reporting one as a finding.</div>')

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
            if f.get("url") in _confirmed_urls or f.get("type") in (
                    _DALFOX_TYPE_LABELS["V"], _DALFOX_TYPE_LABELS["RV"]):
                g["confirmed"] = True
                g["poc"] = f.get("url") or g["poc"]
        grows = []
        for (base, param), g in sorted(_grp.items(),
                                       key=lambda kv: (0 if kv[1]["confirmed"] else 1,
                                                       -len(kv[1]["payloads"]))):
            grows.append([
                "✅ CONFIRMED" if g["confirmed"] else "unconfirmed — check context",
                param,
                base,
                str(len(g["payloads"])),
                (g["evidence"] or "")[:180],
                g["poc"],
            ])
        body += ('<div class="subsection-label" style="margin:18px 0 8px">Injection points '
                 f'<span style="color:var(--muted);font-weight:400">({len(_grp)} unique · '
                 f'{len(findings)} raw payload hits — ✅ = a real dialog fired on headless replay; '
                 f'"unconfirmed" = payload reflected but did not execute on replay, check the '
                 f'evidence column for context)</span></div>'
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
            body += ('<div class="alert-box" style="margin-bottom:14px;background:rgba(249,115,22,.1);'
                     'border-color:rgba(249,115,22,.4);color:#fdba74">⚠ <b>Dalfox found 0 — but the run '
                     'took real time across several targets.</b> On a target the pre-scan probe confirmed '
                     'alive, that usually means the site rate-limited the payload burst (a CDN/ALB '
                     'wrapping the reflections in 403/429 so dalfox can\'t see them). <b>Treat this as '
                     '"inconclusive", not "clean"</b> — re-run later, from another IP, or lower '
                     '<code>tools.dalfox_workers</code> / raise <code>tools.dalfox_delay_ms</code>.</div>')
        else:
            body += _empty("Dalfox scan completed — 0 reflected/DOM XSS on the tested parameters.")
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
        vuln = [t for t in tested if t["vulnerable"]]
        vuln_n, clean_n = len(vuln), len(tested) - len([t for t in tested if t["vulnerable"]])

        # ── VULNERABLE — one row per ready-to-open PoC URL (full, one-piece) ──
        poc_rows, _seen_poc = [], set()
        for t in vuln:
            for p in (t.get("pocs") or []):
                pu = p.get("poc_url", "")
                if not pu or pu in _seen_poc:
                    continue
                _seen_poc.add(pu)
                st = ("✅ CONFIRMED (dialog fired)" if p["confirmed"]
                      else "🔴 reflected — verify context")
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
        rows_t = []
        for t in tested:
            status = "🔴 VULNERABLE" if t["vulnerable"] else "🟢 clean"
            rows_t.append([t["url"], status, "; ".join(p for p in t["payloads"] if p),
                           ", ".join(t["types"]), ", ".join(t["severities"]),
                           "row-red" if t["vulnerable"] else "row-green"])
        body += (f'<div class="subsection-label" style="margin-top:20px;margin-bottom:8px">'
                 f'All tested URLs <span style="color:var(--muted);font-weight:400">'
                 f'({len(tested):,} sent to dalfox — '
                 f'<span style="color:var(--red)">{vuln_n:,} vulnerable</span> / '
                 f'<span style="color:var(--green)">{clean_n:,} clean</span>)</span></div>'
                 f'<div class="cat-desc" style="margin-bottom:10px">Every URL dalfox scanned, so you '
                 f'can see what was covered. The copyable per-payload PoC URLs are in the red table '
                 f'above.</div>')
        body += _vtable(["Base URL", "Status", "Payload(s) that hit", "Type", "Severity"],
                        rows_t, "vt-xss-all", row_class=True, copy_cols=[0, 2])

    raw_txt = (xss.get("raw_txt") or "").strip()
    if raw_txt:
        body += (f'<div class="subsection-label" style="margin-top:20px">Raw Tool Output</div>'
                 f'<details><summary style="cursor:pointer;color:var(--muted);font-size:12px;'
                 f'margin-bottom:8px">Show dalfox\'s own text output ({len(raw_txt.splitlines()):,} lines)</summary>'
                 f'{_code_block(raw_txt)}</details>')

    risk_label2 = "CRITICAL" if blind_hits else risk_label
    return (f'<div id="s-xss" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>XSS</h2>'
            f'<p class="sec-sub">{len(findings):,} findings &middot; RISK: {risk_label2}</p>'
            f'</div></div></div>{body}</div>')


# ── Section: JS Secrets ──────────────────────────────────────────────────────
def _section_js(js):
    endpoints = js.get("endpoints", [])
    secrets   = js.get("secrets", [])
    body = (f'<div style="display:flex;margin-bottom:16px">'
            f'{_stat(len(endpoints), "Endpoints", "blue", "🔗")}'
            f'{_stat(len(secrets), "Secrets", "purple", "🔑")}</div>')
    tabs = []
    if endpoints:
        tabs.append(("endpoints", f"Endpoints ({len(endpoints)})",
                     _vtable(["Endpoint"], [[e] for e in endpoints], "vt-js-ep")))
    if secrets:
        tabs.append(("secrets", f"Secrets ({len(secrets)})",
                     _vtable(["Secret"], [[s] for s in secrets], "vt-js-sec")))
    body += _tabs(tabs, "js") if tabs else _empty("No JS secrets found")
    return (f'<div id="s-js" class="section">'
            f'<div class="sec-hdr"><div class="sec-hdr-inner"><div>'
            f'<h2>JS Secrets</h2>'
            f'<p class="sec-sub">Endpoints &amp; secrets harvested from JavaScript</p>'
            f'</div></div></div>{body}</div>')


# ── Section: Tech Priority ───────────────────────────────────────────────────
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
    total_checked = len(cors) + len(tko) + len(buckets)
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
                  r.get("status") or "", (r.get("detail") or "")[:120]] for r in bucket_vuln]

    tabs = [
        ("cors", f"CORS ({len(cors_vuln)})",
         (f'<div class="cat-desc" style="border-left-color:#fb923c">⚠️ Origin yansitma / wildcard+credentials kombinasyonu — sadece header incelendi, exploit denenmedi</div>'
          + (_vtable(["URL", "Detail", "ACAO", "ACAC"], cors_rows, "vt-extra-cors") if cors_rows else _empty("No CORS misconfiguration found")))),
        ("takeover", f"Takeover ({len(tko_vuln)})",
         (f'<div class="cat-desc" style="border-left-color:#ef4444">⚠️ CNAME fingerprint + HTTP govde imzasi eslesti — devralma denenmedi, sadece tespit</div>'
          + (_vtable(["Host", "Service", "CNAME", "Detail"], tko_rows, "vt-extra-tko") if tko_rows else _empty("No subdomain takeover risk found")))),
        ("bucket", f"Cloud Buckets ({len(bucket_vuln)})",
         (f'<div class="cat-desc" style="border-left-color:#ef4444">⚠️ Genel erisime acik (public listing) bucket — sadece okundu, yazma/silme denenmedi</div>'
          + (_vtable(["URL", "Provider", "Status", "Detail"], bkt_rows, "vt-extra-bucket") if bkt_rows else _empty("No public buckets found")))),
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
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@300;400;500;600;700;800&family=Space+Grotesk:wght@400;500;600;700&display=swap');
:root{
  --bg:#060a14;
  --bg-2:#0b1220;
  --surface1:#0f172a;
  --surface2:#162032;
  --surface3:#1e2e4a;
  --surface4:#243651;
  --border:#1e3a5f;
  --border2:#2a4a6e;
  --border-glass:rgba(255,255,255,.07);
  --text:#e6edf5;
  --text-dim:#b8c7dc;
  --muted:#7a92b0;
  --muted2:#5a7494;
  --accent:#38bdf8;
  --accent2:#7dd3fc;
  --accent-glow:rgba(56,189,248,.25);
  --green:#22c55e;
  --green-bg:rgba(34,197,94,.12);
  --red:#ef4444;
  --red-bg:rgba(239,68,68,.12);
  --orange:#f97316;
  --orange-bg:rgba(249,115,22,.12);
  --yellow:#eab308;
  --purple:#a855f7;
  --cyan:#06b6d4;
  --mono:'JetBrains Mono',monospace;
  --sans:'Inter',sans-serif;
  --display:'Space Grotesk',sans-serif;
  --sw:268px;
  --radius:14px;
  --radius-sm:10px;
  --shadow:0 8px 32px rgba(0,0,0,.45), 0 1px 0 rgba(255,255,255,.04) inset;
  --shadow-sm:0 2px 12px rgba(0,0,0,.3);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{
  background:var(--bg);
  background-image:
    radial-gradient(1200px 600px at 10% -10%, rgba(56,189,248,.08), transparent 55%),
    radial-gradient(900px 500px at 90% 0%, rgba(168,85,247,.06), transparent 60%),
    linear-gradient(180deg, var(--bg) 0%, var(--bg-2) 100%);
  color:var(--text);
  font-family:var(--sans);
  font-size:14px;
  display:flex;
  min-height:100vh;
  line-height:1.65;
  -webkit-font-smoothing:antialiased;
}
/* Scrollbar */
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--surface1)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#3a5a7e}
/* Sidebar - glass + sticky */
.sidebar{
  width:var(--sw);min-width:var(--sw);
  background:rgba(15,23,42,.92);
  backdrop-filter:blur(16px) saturate(1.2);
  -webkit-backdrop-filter:blur(16px) saturate(1.2);
  border-right:1px solid var(--border);
  position:fixed;top:0;left:0;height:100vh;overflow-y:auto;z-index:100;
  display:flex;flex-direction:column;
  box-shadow:4px 0 24px rgba(0,0,0,.4);
}
.sidebar::-webkit-scrollbar{width:4px}
.sb-brand{
  padding:22px 18px 18px;
  border-bottom:1px solid var(--border);
  background:linear-gradient(160deg, #0f172a 0%, #111c32 60%, #0f1e3a 100%);
  position:sticky;top:0;z-index:2;
}
.sb-logo{display:flex;align-items:center;gap:11px;margin-bottom:13px}
.sb-logo-mark{
  width:36px;height:36px;
  background:linear-gradient(135deg,#38bdf8 0%, #0ea5e9 55%, #0284c7 100%);
  border-radius:10px;display:flex;align-items:center;justify-content:center;
  font-size:17px;box-shadow:0 4px 18px rgba(56,189,248,.35), 0 1px 0 rgba(255,255,255,.3) inset;
  flex-shrink:0; position:relative;
}
.sb-logo-mark::after{
  content:'';position:absolute;inset:1px;border-radius:9px;
  background:linear-gradient(180deg, rgba(255,255,255,.18), transparent 60%);
}
.sb-brand h1{font-family:var(--display);font-size:17px;font-weight:700;color:#fff;letter-spacing:-.4px}
.sb-brand h1 span{color:var(--accent2);font-weight:700}
.sb-target{
  font-family:var(--mono);font-size:11px;color:var(--text-dim);
  padding:7px 10px;background:rgba(30,46,74,.85);border-radius:8px;
  border:1px solid rgba(255,255,255,.06);word-break:break-all;line-height:1.5;
  box-shadow:0 1px 0 rgba(255,255,255,.04) inset;
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
  padding:9px 18px;color:#8aaac8;cursor:pointer;font-size:13px;
  border-left:2.5px solid transparent;transition:all .18s cubic-bezier(.4,0,.2,1);
  text-decoration:none;font-weight:450;position:relative;
}
.nav-a:hover{color:var(--text);background:rgba(56,189,248,.06);border-left-color:rgba(56,189,248,.4)}
.nav-a.active{
  color:#fff;background:linear-gradient(90deg, rgba(56,189,248,.14) 0%, rgba(56,189,248,.03) 100%);
  border-left-color:var(--accent);font-weight:600;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.06);
}
.nav-a.active::after{
  content:'';position:absolute;right:12px;top:50%;transform:translateY(-50%);
  width:6px;height:6px;background:var(--accent);border-radius:50%;box-shadow:0 0 8px var(--accent-glow);
}
.nav-ico{font-size:14px;width:20px;text-align:center;flex-shrink:0;filter:saturate(1.1)}
.nav-cnt{
  margin-left:auto;background:rgba(255,255,255,.06);color:var(--text-dim);
  font-size:10.5px;padding:2px 8px;border-radius:20px;font-family:var(--mono);
  border:1px solid rgba(255,255,255,.07);font-weight:600;min-width:22px;text-align:center;
}
.nav-cnt.cnt-red{background:rgba(239,68,68,.15);color:#ff8f8f;border-color:rgba(239,68,68,.25)}
.nav-cnt.cnt-orange{background:rgba(249,115,22,.15);color:#ffb86a;border-color:rgba(249,115,22,.25)}
.nav-hr{border:none;border-top:1px solid var(--border);margin:10px 14px;opacity:.6}
.sb-hint{
  padding:12px 18px 16px;color:var(--muted);font-size:11px;line-height:1.6;
  border-top:1px solid var(--border);margin-top:auto;background:rgba(0,0,0,.15);
}
.sb-hint kbd{
  background:var(--surface3);border:1px solid var(--border2);border-bottom-width:2px;
  padding:1px 5px;border-radius:5px;font-family:var(--mono);font-size:10px;color:var(--text-dim);
}
/* Main */
.main{margin-left:var(--sw);flex:1;min-width:0;padding:0 0 40px;max-width:calc(100vw - var(--sw))}
.section{display:none;padding:18px 28px;max-width:1280px;margin:0 auto;width:100%;animation:fadeIn .25s ease}
.section.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.sec-hdr{margin-bottom:18px}
.sec-hdr-inner{
  display:flex;align-items:flex-start;justify-content:space-between;gap:16px;
  padding:20px 22px;background:linear-gradient(135deg, var(--surface1) 0%, var(--surface2) 100%);
  border:1px solid var(--border);border-radius:var(--radius);
  box-shadow:var(--shadow);position:relative;overflow:hidden;
}
.sec-hdr-inner::before{
  content:'';position:absolute;top:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg, transparent, rgba(56,189,248,.4), transparent);
}
.sec-hdr h2{font-family:var(--display);font-size:20px;font-weight:700;letter-spacing:-.5px;color:#fff;display:flex;align-items:center;gap:10px}
.sec-hdr h2::before{content:'';width:3px;height:20px;background:var(--accent);border-radius:2px;box-shadow:0 0 8px var(--accent-glow)}
.sec-sub{color:var(--muted);font-size:12.5px;margin-top:4px;font-weight:400}
.target-code{
  background:rgba(56,189,248,.1);color:var(--accent2);padding:2px 7px;border-radius:6px;
  font-family:var(--mono);font-size:11.5px;border:1px solid rgba(56,189,248,.2);
}
/* Panels */
.panel{
  background:var(--surface1);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px 20px;box-shadow:var(--shadow-sm);position:relative;overflow:hidden;
  transition:border-color .2s, box-shadow .2s;
}
.panel:hover{border-color:var(--border2);box-shadow:0 6px 24px rgba(0,0,0,.35)}
.panel-header{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.panel-header h3{font-family:var(--display);font-size:13px;font-weight:600;color:var(--text);letter-spacing:-.2px}
.panel-icon{width:28px;height:28px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:14px;background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.15)}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
.stat-card{
  background:var(--surface1);border:1px solid var(--border);border-radius:var(--radius-sm);
  padding:14px 14px 12px;position:relative;overflow:hidden;
  transition:transform .18s, border-color .18s, box-shadow .18s;
}
.stat-card::before{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);opacity:.9;
}
.stat-card:hover{transform:translateY(-2px);border-color:var(--accent);box-shadow:0 6px 20px rgba(0,0,0,.3)}
.stat-icon{font-size:18px;margin-bottom:6px;opacity:.9}
.stat-val{font-family:var(--display);font-size:22px;font-weight:700;color:#fff;line-height:1;letter-spacing:-.5px}
.stat-lbl{font-size:11px;color:var(--muted);margin-top:5px;font-weight:500;text-transform:uppercase;letter-spacing:.5px}
/* Timeline */
.timeline{display:flex;align-items:center;gap:0;margin-top:6px;overflow-x:auto;padding:8px 0}
.tl-step{display:flex;flex-direction:column;align-items:center;gap:6px;flex:1;min-width:58px;position:relative}
.tl-step::after{content:'';position:absolute;top:14px;left:55%;right:-45%;height:2px;background:var(--border)}
.tl-step:last-child::after{display:none}
.tl-dot{width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;border:2px solid var(--border);background:var(--surface2);z-index:1}
.tl-step.tl-done .tl-dot{background:var(--green-bg);border-color:var(--green);color:var(--green);box-shadow:0 0 10px rgba(34,197,94,.3)}
.tl-step.tl-skip .tl-dot{opacity:.5}
.tl-lbl{font-size:10px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.4px}
/* Code block */
.code-block{
  background:#0a0f1e;border:1px solid var(--border);border-radius:10px;
  padding:14px 16px;font-family:var(--mono);font-size:11.5px;line-height:1.7;
  color:#c9d8ea;overflow:auto;max-height:420px;white-space:pre-wrap;word-break:break-all;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.03);
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
.btn-sm:hover{background:var(--accent);color:#fff;border-color:var(--accent);box-shadow:0 2px 10px var(--accent-glow)}
.vs-scroll{height:360px;overflow:auto;position:relative;background:var(--surface1)}
.vs-vp{position:relative}
.vs-row{
  position:absolute;left:0;right:0;height:34px;display:flex;align-items:center;
  padding:0 12px;font-family:var(--mono);font-size:11.5px;color:var(--text-dim);
  border-bottom:1px solid rgba(255,255,255,.04);overflow:hidden;white-space:nowrap;text-overflow:ellipsis;
  transition:background .12s;
}
.vs-row:hover{background:rgba(56,189,248,.06);color:var(--text)}
.tbl-scroll{overflow:auto;max-height:420px}
.tbl-scroll table{width:100%;border-collapse:collapse;font-size:12.5px}
.tbl-scroll th{
  position:sticky;top:0;background:var(--surface2);color:var(--muted);
  font-weight:700;text-transform:uppercase;letter-spacing:.6px;font-size:10.5px;
  padding:9px 12px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;
}
.tbl-scroll td{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.04);color:var(--text-dim);font-family:var(--mono);font-size:11.5px;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tbl-scroll tr:hover td{background:rgba(56,189,248,.04);color:var(--text)}
/* v8.5: per-cell copy button (URL/payload PoC columns) — hidden until the row
   is hovered, so it doesn't clutter every row visually. Copies the cell's
   FULL untruncated value (see vtRender), not the CSS-ellipsis-clipped text. */
/* v8.6-fix: display:flex on a <td> breaks table column layout (two copy-cells
   in one row would stack). Keep the td a normal table cell; lay out its
   content with an inner flex wrapper instead. */
.tbl-scroll td.has-copy{max-width:420px;white-space:nowrap}
.tbl-scroll td.has-copy .cell-wrap{display:flex;align-items:center;gap:6px}
.tbl-scroll td.has-copy .cell-txt{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;flex:1}
.cell-copy{flex:0 0 auto;opacity:0;width:20px;height:20px;padding:0;border:1px solid var(--border);
  border-radius:4px;background:var(--surface2);color:var(--muted);font-size:11px;line-height:1;cursor:pointer;
  transition:opacity .12s,color .12s,border-color .12s}
.tbl-scroll tr:hover .cell-copy{opacity:1}
.cell-copy:hover{color:var(--accent2);border-color:var(--accent2)}
.cell-copy.copied{opacity:1;color:#4ade80;border-color:#4ade80}
/* v8.3: row-level color coding for the XSS "all tested URLs" table — red for
   a URL dalfox actually flagged, green for one tested and found clean. */
.row-red td{background:rgba(239,68,68,.10);border-bottom-color:rgba(239,68,68,.18)}
.row-red td:first-child{border-left:3px solid var(--red)}
.row-red:hover td{background:rgba(239,68,68,.18) !important;color:#fff !important}
.row-green td{background:rgba(34,197,94,.06);border-bottom-color:rgba(34,197,94,.14)}
.row-green td:first-child{border-left:3px solid var(--green)}
.row-green:hover td{background:rgba(34,197,94,.12) !important;color:var(--text) !important}
.vt-more{padding:10px 12px;text-align:center;color:var(--muted);font-size:11px}
/* Tabs */
.tab-row{display:flex;gap:4px;overflow-x:auto;padding:4px 4px 0;background:var(--surface2);border:1px solid var(--border);border-bottom:none;border-radius:var(--radius-sm) var(--radius-sm) 0 0}
.tab{
  padding:8px 14px;border-radius:8px 8px 0 0;font-size:12.5px;font-weight:600;
  color:var(--muted);background:transparent;border:1px solid transparent;border-bottom:none;cursor:pointer;white-space:nowrap;transition:all .18s;
}
.tab:hover{color:var(--text);background:rgba(255,255,255,.04)}
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
.poc-copy{flex:0 0 auto;padding:8px 14px;border:0;border-left:1px solid var(--border);background:var(--accent);color:#04121e;font-weight:700;font-size:11.5px;cursor:pointer;transition:filter .15s}
.poc-copy:hover{filter:brightness(1.1)}
/* Confirmed-XSS proof card */
.poc-card{border:1.5px solid #dc2626;border-radius:12px;background:rgba(220,38,38,.06);padding:16px;margin-bottom:16px}
.poc-card-hd{display:flex;align-items:center;gap:10px;font-weight:700;font-size:14px;color:#fca5a5;margin-bottom:10px}
.poc-card-hd .tag{background:#dc2626;color:#fff;font-size:10.5px;padding:2px 8px;border-radius:6px;letter-spacing:.5px}
.poc-card img{width:100%;max-width:760px;border:1px solid var(--border2);border-radius:8px;margin-top:10px;display:block}
.poc-meta{font-size:11.5px;color:var(--muted);font-family:var(--mono);margin-top:6px}
/* Alerts */
.alert-box{padding:12px 14px;border-radius:10px;font-size:12.5px;line-height:1.6;border:1px solid}
.alert-red{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.3);color:#ff9e9e}
.info-banner{padding:10px 14px;border-radius:10px;font-size:12.5px;display:flex;align-items:center;gap:8px;border:1px solid}
.info-red{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.25);color:#ff9e9e}
.info-orange{background:rgba(249,115,22,.08);border-color:rgba(249,115,22,.25);color:#ffb86a}
.info-yellow{background:rgba(234,179,8,.08);border-color:rgba(234,179,8,.25);color:#ffea80}
.info-blue{background:rgba(59,130,246,.08);border-color:rgba(59,130,246,.25);color:#93c5fd}
.info-green{background:rgba(34,197,94,.08);border-color:rgba(34,197,94,.25);color:#86efac}
/* Threat Map */
.tm-legend{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
.tm-leg-item{display:flex;align-items:center;gap:6px;font-size:11.5px;color:var(--muted);background:var(--surface1);padding:5px 10px;border-radius:20px;border:1px solid var(--border)}
.tm-dot{width:10px;height:10px;border-radius:50%;display:inline-block}
.tm-toolbar{display:flex;align-items:center;gap:6px;flex-wrap:wrap;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:8px}
.tm-wrap{background:var(--surface1);border:1px solid var(--border);border-radius:var(--radius-sm);height:520px;position:relative;overflow:hidden;box-shadow:var(--shadow-sm)}
#tm-svg{width:100%;height:100%;display:block}
.tm-tooltip{position:absolute;pointer-events:none;background:var(--surface2);border:1px solid var(--border2);padding:10px 12px;border-radius:10px;font-size:12px;color:var(--text);box-shadow:var(--shadow);opacity:0;transition:opacity .15s;max-width:280px;z-index:10}
/* Risk gauge */
.risk-gauge{display:flex;align-items:center;gap:16px;padding:14px;background:var(--surface2);border-radius:12px;border:1px solid var(--border);margin-bottom:14px}
.risk-gauge-circle{width:72px;height:72px;flex-shrink:0;position:relative}
.risk-gauge-circle svg{transform:rotate(-90deg)}
.risk-gauge-label{flex:1}
.risk-gauge-label strong{font-family:var(--display);font-size:15px}
.risk-pct{font-family:var(--mono);font-size:11px;color:var(--muted)}
/* Export dropdown */
.export-btn-wrap{position:fixed;top:16px;right:16px;z-index:90}
.export-btn{
  display:flex;align-items:center;gap:8px;
  background:linear-gradient(135deg, #38bdf8, #0ea5e9);color:#fff;
  border:none;padding:9px 14px;border-radius:10px;font-size:12.5px;font-weight:700;
  cursor:pointer;box-shadow:0 4px 18px rgba(56,189,248,.35);transition:all .18s;
}
.export-btn:hover{transform:translateY(-1px);box-shadow:0 6px 24px rgba(56,189,248,.45)}
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
  margin-top:28px;padding:14px 28px;text-align:center;color:var(--muted);font-size:11px;
  border-top:1px solid var(--border);background:rgba(0,0,0,.15);
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
  el.style.cssText='padding:10px 14px;border-radius:10px;font-size:12.5px;font-weight:600;box-shadow:0 4px 18px rgba(0,0,0,.4);border:1px solid;'+(type==='ok'?'background:#0f2a1a;color:#86efac;border-color:#22c55e':'background:#1e1a0f;color:#fde68a;border-color:#f59e0b');
  c.appendChild(el);
  setTimeout(function(){ el.style.opacity='0'; el.style.transform='translateY(6px)'; el.style.transition='all .3s'; },2200);
  setTimeout(function(){ try{el.remove()}catch(e){} },2600);
}
// One-piece copy for a PoC field (URL+payload as a single string).
function copyOne(btn){
  var v = btn.getAttribute('data-copy') || '';
  navigator.clipboard.writeText(v).then(function(){
    var o = btn.textContent; btn.textContent = '✓ copied';
    toast('PoC copied to clipboard','ok');
    setTimeout(function(){ btn.textContent = o; }, 1400);
  }).catch(function(){ toast('Copy failed','warn'); });
}
// Virtual scroll (kept + improved)
var VS_H=34, VS_OS=8;
function vsInit(uid){ var d=window._VS && window._VS[uid]; if(!d) return; vsCnt(uid); vsRender(uid); }
function vsRender(uid){
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
    var esc=document.createElement('span'); esc.textContent=txt;
    // make link clickable
    if(txt.startsWith('http')){
      var a=document.createElement('a'); a.href=txt; a.target='_blank'; a.rel='noopener';
      a.textContent=txt; a.style.color='var(--accent2)'; a.style.textDecoration='none'; a.style.overflow='hidden'; a.style.textOverflow='ellipsis';
      row.appendChild(a);
    } else { row.appendChild(esc); }
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
  navigator.clipboard.writeText(txt).then(function(){ toast('Copied '+d.filtered.length+' lines','ok'); });
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
      if(copyCols.indexOf(ci)!==-1 && c){
        td.className='has-copy';
        var span=document.createElement('span'); span.className='cell-txt'; span.textContent=c; span.title=c;
        var btn=document.createElement('button'); btn.type='button'; btn.className='cell-copy'; btn.textContent='⧉'; btn.title='Copy full value';
        btn.onclick=function(ev){
          ev.stopPropagation();
          navigator.clipboard.writeText(c).then(function(){
            btn.classList.add('copied'); btn.textContent='✓';
            toast('Copied','ok');
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
  navigator.clipboard.writeText(txt).then(function(){ toast('Copied '+d.filtered.length+' rows','ok'); });
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
  navigator.clipboard.writeText(txt).then(function(){ toast('Copied URLs','ok'); });
}
function aliveCSV(){
  var rows=window._AF||window._AR||[];
  var csv=['URL,Status,Title,IP,Tech,Size,Server,RT'].concat(rows.map(function(r){return r.map(function(c){return '"'+String(c).replace(/"/g,'""')+'"'}).join(',')})).join('\n');
  var blob=new Blob([csv],{type:'text/csv'}); var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='alive_hosts.csv'; a.click();
}
// Threat Map
var _TM={initialized:false,W:0,H:0};
function initThreatMap(){
  if(!window._TM_DATA||typeof d3==='undefined') return;
  _TM.initialized=true;
  var wrap=document.querySelector('.tm-wrap');
  var svg=d3.select('#tm-svg');
  var W=wrap.clientWidth, H=wrap.clientHeight; _TM.W=W; _TM.H=H; _TM.svg=svg;
  svg.attr('viewBox',[0,0,W,H]);
  var g=svg.append('g');
  var zoom=d3.zoom().scaleExtent([0.15,6]).on('zoom',function(e){ g.attr('transform',e.transform); });
  svg.call(zoom);
  var data=window._TM_DATA;
  var sim=d3.forceSimulation(data.nodes)
    .force('link', d3.forceLink(data.links).id(function(d){return d.id}).distance(70))
    .force('charge', d3.forceManyBody().strength(-220))
    .force('center', d3.forceCenter(W/2,H/2))
    .force('collide', d3.forceCollide().radius(22));
  var link=g.append('g').selectAll('line').data(data.links).enter().append('line')
    .attr('stroke','rgba(255,255,255,.12)').attr('stroke-width',1);
  var node=g.append('g').selectAll('circle').data(data.nodes).enter().append('circle')
    .attr('r',function(d){ return d.type==='root'?16:d.type==='group'?12:d.type==='collapsed'?9:7; })
    .attr('fill',function(d){
      if(d.type==='root') return '#38bdf8';
      if(d.type==='group') return '#1e3a5f';
      if(d.type==='collapsed') return '#334155';
      if(d.severity==='high') return '#ef4444';
      if(d.severity==='medium') return '#f97316';
      if(d.severity==='low') return '#eab308';
      return d.alive ? '#22c55e' : '#475569';
    })
    .attr('stroke','rgba(255,255,255,.15)').attr('stroke-width',1)
    .style('cursor',function(d){ return (d.type==='subdomain'||d.type==='root') ? 'pointer' : 'default'; })
    .on('click',function(e,d){
      if (d.type==='subdomain' || d.type==='root') { jumpToHost(d.label); }
    })
    .call(d3.drag().on('start',function(e,d){ if(!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; }).on('drag',function(e,d){ d.fx=e.x; d.fy=e.y; }).on('end',function(e,d){ if(!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }));
  var label=g.append('g').selectAll('text').data(data.nodes).enter().append('text')
    .text(function(d){ return d.label.length>22 ? d.label.slice(0,22)+'…' : d.label; })
    .attr('font-size',10).attr('dx',12).attr('dy',4).attr('fill','rgba(230,237,245,.85)').style('pointer-events','none').style('font-family','JetBrains Mono, monospace');
  var tip=document.getElementById('tm-tooltip');
  node.on('mouseenter',function(e,d){
    tip.style.opacity='1'; tip.innerHTML='<b>'+d.label+'</b><br><span style="color:#7a92b0">type: '+d.type+' | alive: '+(d.alive?'yes':'no')+' | severity: '+(d.severity||'none')+' | vuln: '+(d.vuln_count||0)+'</span>';
  }).on('mousemove',function(e){ tip.style.left=(e.offsetX+14)+'px'; tip.style.top=(e.offsetY+14)+'px'; }).on('mouseleave',function(){ tip.style.opacity='0'; });
  sim.on('tick',function(){
    link.attr('x1',function(d){return d.source.x}).attr('y1',function(d){return d.source.y}).attr('x2',function(d){return d.target.x}).attr('y2',function(d){return d.target.y});
    node.attr('cx',function(d){return d.x}).attr('cy',function(d){return d.y});
    label.attr('x',function(d){return d.x}).attr('y',function(d){return d.y});
  });
  window.tmResetZoom=function(){ svg.transition().duration(400).call(zoom.transform, d3.zoomIdentity); };
  window.tmToggleLabels=function(){ var v=label.style('display'); label.style('display', v==='none'?'block':'none'); };
  window.tmFilterAlive=function(){ node.style('opacity',function(d){ return d.alive||d.type==='root' ? 1 : 0.15; }); label.style('opacity',function(d){ return d.alive||d.type==='root' ? 1 : 0.15; }); };
  window.tmFilterAll=function(){ node.style('opacity',1); label.style('opacity',1); };
  window.tmSearch=function(){
    var q=(document.getElementById('tm-search')||{}).value||''; q=q.toLowerCase().trim();
    node.attr('stroke',function(d){ return q && d.label.toLowerCase().includes(q) ? '#38bdf8' : 'rgba(255,255,255,.15)'; }).attr('stroke-width',function(d){ return q && d.label.toLowerCase().includes(q) ? 2.5 : 1; });
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
function copyReportLink(){ navigator.clipboard.writeText(location.href).then(function(){ toast('Link copied','ok'); }); }
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
    {id:'threatmap', label:'Threat Map', icon:'🗺️'},
    {id:'recon', label:'Reconnaissance', icon:'🔍'},
    {id:'subdomains', label:'Subdomains', icon:'🌐'},
    {id:'alive', label:'Alive Hosts', icon:'💻'},
    {id:'urls', label:'All URLs', icon:'🔗'},
    {id:'params', label:'Parameters', icon:'⚙️'},
    {id:'categorised', label:'Categorised', icon:'📂'},
    {id:'nuclei', label:'Nuclei', icon:'🧨'},
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
  // scroll listeners for tables
  document.querySelectorAll('.vt-wrap .tbl-scroll').forEach(function(el){
    el.addEventListener('scroll',function(){
      // lazy load already handled by vtRender pagination - just trigger more
    });
  });
  document.querySelectorAll('.vs-scroll').forEach(function(el){
    el.addEventListener('scroll',function(){ var uid=el.id.replace('-scroll',''); vsRender(uid); });
  });
});
"""


def build_report(scan_dir, target: str, summary: dict = None) -> Path:
    scan_dir = Path(scan_dir)
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M")

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
    vuln_map = _build_vuln_map(nuc, xss, extra)   # feeds the Threat Map's severity layer
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
<div class="nav-grp"><div class="nav-lbl">Findings</div>
  {_nav("🧨" if not nuc.get("meta",{}).get("tool_failed") else "⚠️","Nuclei","nuclei", len(nuc.get("findings",[])) if not nuc.get("meta",{}).get("tool_failed") else "ERR", "red")}
  {_nav("💥" if not xss.get("meta",{}).get("tool_failed") else "⚠️","XSS","xss", len(xss.get("findings",[])) if not xss.get("meta",{}).get("tool_failed") else "ERR", "orange" if not xss.get("meta",{}).get("tool_failed") else "red")}
  {_nav("🛡️","Extra Checks","extra", extra_vuln_n, "red" if extra_vuln_n else None)}
  {_nav("🔑","JS Secrets","js", len(js.get("secrets",[])), "purple")}
  {_nav("⚡","API Discovery","api", len(api.get("probes",[])) + sum(len(v) for v in api.get("found",{}).values()))}
  {_nav("⚙️","Tech Priority","tech", len(tech), "blue")}
</div>
<hr class="nav-hr">
<div class="sb-hint">
  <kbd>/</kbd> to search &nbsp;·&nbsp; Virtual scroll<br>
  Professional Edition v8.6
</div>'''

    sections = "".join([
        _section_overview(target, ts, recon, subs, alive, urls, smry_json,
                          nuc=nuc, xss=xss, js=js, tech=tech, extra=extra),
        _section_threatmap(target, subs, alive, vuln_map=vuln_map),
        _section_recon(recon),
        _section_subdomains(subs),
        _section_alive(alive),
        _section_urls(urls, prune=(smry_json.get("stages", {}).get("stage4") or {}).get("prune")),
        _section_params(urls),
        _section_categorised(urls),
        _section_nuclei(nuc),
        _section_xss(xss),
        _section_extra(extra),
        _section_api(api),
        _section_js(js),
        _section_tech(tech),
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
<button class="sb-toggle" id="sb-toggle-btn" onclick="toggleSidebar()" aria-label="Toggle menu">
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
</button>
<div class="sb-scrim" onclick="toggleSidebar()"></div>
<nav class="sidebar">{sidebar}</nav>
<main class="main">
{sections}
<div class="footer">
  ReconX Professional Edition v8.6 &nbsp;&middot;&nbsp; {_e(target)} &nbsp;&middot;&nbsp; {_e(ts)}<br>
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
