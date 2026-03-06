#!/usr/bin/env python3

import atexit, os, sys, re, json, yaml, time, logging, argparse, html, sqlite3, random
import subprocess, shutil, threading, signal
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# ── HTTP Client (Cloudflare-friendly) ─────────────────────────────────────────
try:
    from curl_cffi import requests as _cf_requests  # type: ignore
    _HAS_CURL_CFFI = True
except Exception:
    _cf_requests = None
    _HAS_CURL_CFFI = False

try:
    import requests as _py_requests  # type: ignore
except Exception:
    _py_requests = None

# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"

def info(m):  print(f"{C.BLUE}[*]{C.RESET} {m}", flush=True)
def ok(m):    print(f"{C.GREEN}[✓]{C.RESET} {m}", flush=True)
def warn(m):  print(f"{C.YELLOW}[!]{C.RESET} {m}", flush=True)
def err(m):   print(f"{C.RED}[✗]{C.RESET} {m}", flush=True)
def sub(m):   print(f"  {C.DIM}→{C.RESET} {m}", flush=True)

def _spinner(stop_evt: threading.Event, label: str):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    i = 0
    if not sys.stdout.isatty():
        return
    while not stop_evt.is_set():
        sys.stdout.write(f"\r  {C.CYAN}{frames[i % len(frames)]}{C.RESET} {C.DIM}{label}{C.RESET}   ")
        sys.stdout.flush()
        i += 1
        time.sleep(0.08)
    sys.stdout.write(f"\r{' ' * (len(label) + 22)}\r")
    sys.stdout.flush()

def stage(n, t):
    print(f"\n{C.CYAN}{C.BOLD}{'═'*60}\n  STAGE {n}: {t}\n{'═'*60}{C.RESET}", flush=True)

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
CFG_FILE = BASE_DIR / "config.yaml"
VENV_PY  = BASE_DIR / ".venv" / "bin" / "python3"
ANSI_RE  = re.compile(r"\x1b\[[0-9;]*m")

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s or "")

# ── Config ────────────────────────────────────────────────────────────────────
def load_config(path=None):
    p = Path(path or CFG_FILE)
    defaults = {
        "settings": {
            "threads": 20,
            "rate_limit": 8,
            "timeout": 20,
            "use_curl_cffi": True,
            "curl_cffi_impersonate": "chrome110",
            "proxy": "",
            "jitter_max": 0.6,
            "default_scheme": "https",
            "use_referer": True,
            "adaptive_rate": True,
            "adaptive_threshold": 0.18,
            "adaptive_floor_mult": 0.25,
            "canonicalize_urls": True,
            "rerun_on_block": True,
            "rerun_max": 1,
            "rerun_backoff": 0.65,
            "rerun_pause_sec": 6,
        },
        "api_keys": {},
        "tools": {
            # v6.5: yeni alanlar
            "nuclei_severity": "critical,high,medium",   # boş bırakılırsa filtre yok
            "nuclei_templates": "",                       # boş = otomatik keşfet
            "nuclei_excluded_tags": "intrusive,dos",     # gürültülü/tehlikeli taglar
            "blind_xss_callback": "",                    # ör: https://your.interact.sh
            "dalfox_custom_payload": "",                 # ör: /root/xss-payloads.txt
        },
    }
    if not p.exists():
        return defaults
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace")) or {}
    except Exception:
        return defaults
    for k, v in defaults.items():
        if k not in data:
            data[k] = v
        elif isinstance(v, dict):
            for k2, v2 in v.items():
                data[k].setdefault(k2, v2)
    return data

def _cfg_get(cfg: dict, *keys, default=None):
    cur = cfg
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
        if cur is None:
            return default
    return cur

# ── Logger ────────────────────────────────────────────────────────────────────
def setup_logger(log_file):
    log = logging.getLogger(f"reconx_{Path(log_file).stem}")
    log.setLevel(logging.DEBUG)
    log.propagate = False
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    log.addHandler(fh)
    return log

def tool_exists(name):
    return shutil.which(name) is not None

def has_valid_api_key(cfg, key):
    v = cfg.get("api_keys", {}).get(key, "")
    bad = {"", "your_key_here", "change_me", "none", "null",
           "your_shodan_api_key", "your_censys_api_key"}
    return bool(v) and v.strip().lower() not in bad

# ══════════════════════════════════════════════════════════════════════════════
# v6.5: Nuclei template path discovery
# ══════════════════════════════════════════════════════════════════════════════
_NUCLEI_TEMPLATE_CANDIDATES = [
    "/root/nuclei-templates",
    "/root/nuclei_templates",
    Path.home() / "nuclei-templates",
    Path.home() / ".local" / "share" / "nuclei" / "templates",
    Path.home() / ".local" / "nuclei-templates",
    Path("/usr/local/share/nuclei-templates"),
    Path("/usr/share/nuclei-templates"),
    Path("/opt/nuclei-templates"),
]

def discover_nuclei_templates(cfg_override: str = "") -> str:
    """
    Returns the best nuclei template path found on the system.
    Priority: config.yaml > well-known paths > `nuclei -tl` query > empty (use built-in)
    """
    # 1. Config override
    if cfg_override and cfg_override.strip():
        p = Path(cfg_override.strip())
        if p.exists() and p.is_dir():
            ok(f"Nuclei templates (config): {p}")
            return str(p)
        else:
            warn(f"Nuclei template path in config not found: {p} — auto-detecting")

    # 2. Well-known paths
    for candidate in _NUCLEI_TEMPLATE_CANDIDATES:
        p = Path(candidate)
        if p.exists() and p.is_dir():
            # validate: at least a few .yaml files inside
            yamls = list(p.rglob("*.yaml"))[:5]
            if yamls:
                ok(f"Nuclei templates found: {p} ({len(list(p.rglob('*.yaml'))):,} templates)")
                return str(p)

    # 3. Ask nuclei itself
    try:
        r = subprocess.run(
            ["nuclei", "-tl"],
            capture_output=True, text=True, timeout=15
        )
        out = (r.stdout or "") + (r.stderr or "")
        for line in out.splitlines():
            line = line.strip()
            if "/" in line and Path(line).exists() and Path(line).is_dir():
                ok(f"Nuclei templates (nuclei -tl): {line}")
                return line
    except Exception:
        pass

    # 4. find command fallback
    try:
        r = subprocess.run(
            ["find", "/root", str(Path.home()), "/opt", "/usr",
             "-maxdepth", "6", "-type", "d", "-name", "nuclei-templates",
             "-not", "-path", "*/\\.git/*"],
            capture_output=True, text=True, timeout=20
        )
        for line in r.stdout.splitlines():
            line = line.strip()
            if line and Path(line).exists():
                ok(f"Nuclei templates (find): {line}")
                return line
    except Exception:
        pass

    warn("Nuclei template path not found — nuclei will use built-in/default templates")
    return ""


# ── Interactive prompt ─────────────────────────────────────────────────────────
def ask_yes_no(question, default="y"):
    is_yes = default.lower() in ("y", "e", "yes", "evet")
    if not sys.stdin.isatty():
        return is_yes
    hint = "[E/h]" if is_yes else "[e/H]"
    print(f"\n{C.MAGENTA}{'─'*60}{C.RESET}")
    print(f"{C.WHITE}{C.BOLD}  {question}{C.RESET}")
    print(f"{C.MAGENTA}{'─'*60}{C.RESET}")
    while True:
        try:
            ans = input(f"  {C.BOLD}{hint}: {C.RESET}").strip().lower() or default.lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if ans in ("e", "y", "evet", "yes", "1"):
            return True
        if ans in ("h", "n", "hayir", "no", "0"):
            return False
        warn("'e' veya 'h' girin.")

# ── Interrupt State ───────────────────────────────────────────────────────────
class _IS:
    _tool  = False
    _hard  = False
    _cnt   = 0
    _last  = 0.0
    _WIN   = 1.5
    _lock  = threading.Lock()

    @classmethod
    def reset(cls):
        with cls._lock:
            cls._tool = False
            cls._cnt  = 0
            cls._last = 0.0

    @classmethod
    def interrupted(cls): return cls._tool

    @classmethod
    def hard(cls): return cls._hard

    @classmethod
    def handle(cls, sig, frm):
        now = time.time()
        with cls._lock:
            elapsed = now - cls._last
            cls._last = now
            cls._cnt += 1
            if cls._cnt == 1 or elapsed > cls._WIN:
                cls._cnt  = 1
                cls._tool = True
                print(f"\n{C.YELLOW}[!]{C.RESET} Ctrl+C — tool stopped (press again to exit)", flush=True)
            else:
                cls._hard = True
                print(f"\n{C.RED}[✗] Force exit...{C.RESET}", flush=True)

_INT = _IS
signal.signal(signal.SIGINT,  _INT.handle)
signal.signal(signal.SIGTERM, lambda s, f: (
    setattr(_INT, "_hard", True),
    print(f"\n{C.RED}[✗] SIGTERM{C.RESET}", flush=True)
))

# ── Timeouts ──────────────────────────────────────────────────────────────────
T = {
    "whois": 120, "whatweb": 600, "wafw00f": 120, "nmap": 1800,
    "harvester": 900, "shodan": 120,
    "subfinder": 1800, "assetfinder": 900, "sublist3r": 1200, "findomain": 900,
    "httpx": 1800,
    "gau": 3600, "waybackurls": 3600, "katana": 3600, "hakrawler": 1800,
    "nuclei": 14400,   # v6.5: 4 saat (daha fazla template)
    "dalfox": 7200,    # v6.5: 2 saat
}

# ── URL Patterns ──────────────────────────────────────────────────────────────
_PAT_SENSITIVE = re.compile(
    r'\.(env|git|svn|htaccess|htpasswd|config|cfg|conf|ini|bak|backup|old|sql|db|log|'
    r'pem|key|cert|crt|ppk|p12|pfx|ovpn)(\?|$)|'
    r'/(phpinfo|phpmyadmin|adminer|shell|cmd|exec|eval|debug|trace|'
    r'dev|staging|internal|private|secret|credentials|password|passwd|shadow)', re.I)
_PAT_ADMIN  = re.compile(r'/(admin|administrator|wp-admin|cpanel|dashboard|panel|'
                          r'manage|management|cms|backend|control|webmaster|adm|manager)', re.I)
_PAT_LOGIN  = re.compile(r'/(login|signin|sign-in|auth|authenticate|session|'
                          r'account|member|portal|sso|oauth|saml)', re.I)
_PAT_API    = re.compile(r'/(api|v\d+|graphql|rest|rpc|endpoint|service|webhook|swagger|openapi)', re.I)
_PAT_FORM   = re.compile(r'\.(php|asp|aspx|jsp|cfm|cgi|pl)(\?|$)', re.I)
_PAT_PARAM  = re.compile(r'[?&][a-zA-Z0-9_\-%]+=', re.I)
_PAT_SKIP   = re.compile(
    r'\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|otf|css|'
    r'mp4|mp3|avi|pdf|zip|tar|gz|exe|dmg)(\?|$)', re.I)

# ── URL normalization / canonicalization ──────────────────────────────────────
_TRACKING_KEYS = {
    "utm_source","utm_medium","utm_campaign","utm_term","utm_content",
    "gclid","fbclid","yclid","mc_cid","mc_eid","igshid","ref","ref_src"
}
def canonicalize_url(u: str) -> str:
    try:
        u = (u or "").strip()
        if not u.startswith(("http://","https://")):
            return u
        p = urlparse(u)
        scheme = (p.scheme or "https").lower()
        netloc = (p.netloc or "").strip()
        if netloc.endswith(":80") and scheme == "http":
            netloc = netloc[:-3]
        if netloc.endswith(":443") and scheme == "https":
            netloc = netloc[:-4]
        path = re.sub(r"/{2,}", "/", p.path or "/")
        fragment = ""
        q = []
        for k, v in parse_qsl(p.query or "", keep_blank_values=False):
            if not k:
                continue
            kl = k.lower()
            if kl in _TRACKING_KEYS or kl.startswith("utm_"):
                continue
            q.append((k, v))
        q.sort(key=lambda kv: (kv[0].lower(), kv[1]))
        query = urlencode(q, doseq=True)
        params = p.params or ""
        return urlunparse((scheme, netloc, path, params, query, fragment))
    except Exception:
        return u

# ── Robust URL/domain parsing ─────────────────────────────────────────────────
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

def _normalize_url_like(s: str, default_scheme: str = "https") -> str:
    s = (s or "").strip()
    if not s:
        return ""
    if s.startswith(("http://", "https://")):
        return s
    if s.startswith("//"):
        return f"{default_scheme}:{s}"
    if _HOST_RE.match(s) or ("/" not in s and " " not in s):
        return f"{default_scheme}://{s}"
    return s

def _extract_domain_from_any(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    try:
        if not s.startswith(("http://","https://")):
            s2 = "https://" + s
        else:
            s2 = s
        h = urlparse(s2).hostname or ""
        h = re.sub(r"^[*]\.", "", h)
        return h
    except Exception:
        pass
    m = re.search(r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}", s)
    return re.sub(r"^[*]\.", "", m.group(0)) if m else ""

# ── v6.5: WAF bypass header strategies (genişletildi) ─────────────────────────
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

_FAKE_IPS = [
    "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
    "8.8.8.8", "1.1.1.1",
]

def _pick_ua() -> str:
    return random.choice(_UA_POOL)

def _base_headers(ua: str) -> dict:
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
    }

# v6.5: WAF bypass için ek headerlar
def _bypass_headers_extra() -> dict:
    fake_ip = random.choice(_FAKE_IPS)
    return {
        "X-Forwarded-For":   fake_ip,
        "X-Real-IP":         fake_ip,
        "X-Originating-IP":  fake_ip,
        "CF-Connecting-IP":  fake_ip,
        "True-Client-IP":    fake_ip,
        "X-Client-IP":       fake_ip,
    }

_HEADER_STRATEGIES = [
    lambda host, ua: {
        **_base_headers(ua),
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    },
    lambda host, ua: {
        **_base_headers(ua),
        **_bypass_headers_extra(),
        "Referer": f"https://{host}/",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    },
    lambda host, ua: {
        "User-Agent": ua,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "DNT": "1",
        **_bypass_headers_extra(),
    },
    # v6.5: scanner masquerade strateji
    lambda host, ua: {
        **_base_headers(ua),
        "X-Scanner": "Nessus",
        "X-Security-Scan": "true",
        "Referer": f"https://www.google.com/search?q={host}",
    },
]

def pick_header_strategy(host: str, cfg: dict) -> dict:
    ua = _pick_ua()
    strat = random.choice(_HEADER_STRATEGIES)
    h = strat(host, ua)
    if not bool(_cfg_get(cfg, "settings", "use_referer", default=True)):
        h.pop("Referer", None)
    return h

def _hdr_args_httpx(headers: dict) -> str:
    return "".join([f' -H "{k}: {v}"' for k, v in headers.items()])

def _hdr_args_nuclei(headers: dict) -> list:
    out = []
    for k, v in headers.items():
        out += ["-H", f"{k}: {v}"]
    return out

def _hdr_args_dalfox(headers: dict) -> list:
    out = []
    for k, v in headers.items():
        out += ["--header", f"{k}: {v}"]
    return out

# ── WAF fingerprinting ────────────────────────────────────────────────────────
def fingerprint_waf(headers: dict, status: int = 0, body_snip: str = "") -> list:
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    b = (body_snip or "").lower()
    out = set()
    if "cf-ray" in h or "cloudflare" in h.get("server","") or "__cf_bm" in h.get("set-cookie",""):
        out.add("cloudflare")
    if "akamai" in h.get("server","") or "akamai" in h.get("x-akamai-transformed","") or "akamai" in b:
        out.add("akamai")
    if "fastly" in h.get("via","") or "fastly" in h.get("server",""):
        out.add("fastly")
    if "incap_ses" in h.get("set-cookie","") or "incapsula" in h.get("set-cookie","") or "imperva" in b:
        out.add("imperva/incapsula")
    if "sucuri" in h.get("server","") or "sucuri" in b:
        out.add("sucuri")
    if "cloudfront" in h.get("via","") or "x-amz-cf-id" in h or "x-amz-cf-pop" in h:
        out.add("cloudfront")
    if status in (403, 429) and ("captcha" in b or "attention required" in b or "access denied" in b):
        out.add("waf_block_page")
    if "x-waf" in h or "x-sucuri" in h or "x-cdn" in h:
        out.add("waf_hint_header")
    return sorted(out)

# ── CF/WAF-friendly HTTP probe ─────────────────────────────────────────────────
def _get_http_client(cfg: dict):
    settings = (cfg or {}).get("settings", {}) if isinstance(cfg, dict) else {}
    prefer = bool(settings.get("use_curl_cffi", True))
    if prefer and _HAS_CURL_CFFI and _cf_requests is not None:
        return _cf_requests, True
    if _py_requests is not None:
        return _py_requests, False
    return None, False

def http_probe(url: str, cfg: dict, timeout: int = 15) -> dict:
    client, is_cffi = _get_http_client(cfg)
    if client is None:
        return {"ok": False, "error": "no_http_client"}
    settings = (cfg or {}).get("settings", {}) if isinstance(cfg, dict) else {}
    impersonate = settings.get("curl_cffi_impersonate", "chrome110")
    proxy = (settings.get("proxy") or "").strip()
    jitter_max = float(settings.get("jitter_max", 0.0) or 0.0)
    host = _extract_domain_from_any(url) or ""
    headers = pick_header_strategy(host, cfg)
    if jitter_max > 0:
        time.sleep(random.random() * jitter_max)
    try:
        kw = dict(timeout=timeout, allow_redirects=True, headers=headers)
        if proxy:
            kw["proxies"] = {"http": proxy, "https": proxy}
        if is_cffi:
            kw["impersonate"] = impersonate
        r = client.get(url, **kw)
        hdrs = dict(getattr(r, "headers", {}) or {})
        status = int(getattr(r, "status_code", 0) or 0)
        body = ""
        try:
            body = (getattr(r, "text", "") or "")[:1200]
        except Exception:
            body = ""
        waf = fingerprint_waf(hdrs, status=status, body_snip=body)
        return {
            "ok": True,
            "client": "curl_cffi" if is_cffi else "requests",
            "impersonate": impersonate if is_cffi else None,
            "url": url,
            "final_url": str(getattr(r, "url", url)),
            "status": status,
            "server": hdrs.get("server") or hdrs.get("Server") or "",
            "content_type": hdrs.get("content-type") or hdrs.get("Content-Type") or "",
            "len": int(getattr(r, "content", b"") and len(getattr(r, "content", b"")) or 0),
            "headers": {k: str(v)[:500] for k, v in list(hdrs.items())[:50]},
            "proxy": proxy or "",
            "waf_fingerprint": waf,
        }
    except Exception as e:
        return {"ok": False, "client": "curl_cffi" if is_cffi else "requests",
                "error": str(e), "url": url, "proxy": proxy or ""}

# ── File utilities ────────────────────────────────────────────────────────────
def _count_lines(path):
    if not path or not Path(path).exists():
        return 0
    try:
        n = 0
        with Path(path).open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    n += 1
        return n
    except:
        return 0

def write_lines(path, lines):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    clean = [strip_ansi((l or "").strip()) for l in lines if strip_ansi((l or "").strip())]
    Path(path).write_text("\n".join(clean) + ("\n" if clean else ""), encoding="utf-8")
    return len(clean)

def checkpoint(path, lines, label):
    n = write_lines(path, lines)
    ok(f"Checkpoint [{label}]: {n:,} entries → {Path(path).name}")
    return n

def _help_text(name):
    results = []
    for args in [[name, "-h"], [name, "--help"]]:
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=10)
            combined = (p.stdout or "") + (p.stderr or "")
            if combined.strip():
                results.append(combined)
        except:
            pass
    return "\n".join(results)

def dedup_files_normalized(src_paths, dst, filter_fn=None, normalize_fn=None):
    seen = set()
    count = 0
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    with Path(dst).open("w", encoding="utf-8") as out:
        for src in src_paths:
            if not src or not Path(src).exists():
                continue
            with Path(src).open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = strip_ansi(line.strip())
                    if not line or line.startswith("#"):
                        continue
                    if filter_fn and not filter_fn(line):
                        continue
                    key = normalize_fn(line) if normalize_fn else line
                    if not key:
                        continue
                    if key in seen:
                        continue
                    seen.add(key)
                    out.write(key + "\n")
                    count += 1
    return count

def merge_unique_lines(dest: Path, sources: list):
    seen = set()
    lines = []
    if dest.exists():
        for ln in dest.read_text(errors="replace").splitlines():
            ln = strip_ansi(ln.strip())
            if ln:
                seen.add(ln); lines.append(ln)
    for s in sources:
        if not s or not s.exists():
            continue
        for ln in s.read_text(errors="replace").splitlines():
            ln = strip_ansi(ln.strip())
            if not ln:
                continue
            if ln in seen:
                continue
            seen.add(ln); lines.append(ln)
    write_lines(dest, lines)
    return len(lines)

# ── URL Categorisation (SQLite streaming) ─────────────────────────────────────
def categorise_streaming(url_file, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cats = ["params", "reflection", "forms", "admin", "login", "api", "sensitive", "other", "xss_targets"]
    db_path = out_dir / ".categorise_dedup.sqlite"
    if db_path.exists():
        try: db_path.unlink()
        except: pass
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("CREATE TABLE IF NOT EXISTS seen (cat TEXT NOT NULL, url TEXT NOT NULL, PRIMARY KEY(cat, url));")
    conn.commit()
    handles = {c: (out_dir / f"{c}.txt").open("w", encoding="utf-8") for c in cats}
    counts  = {c: 0 for c in cats}

    def _w(cat, url):
        try:
            cur = conn.execute("INSERT OR IGNORE INTO seen(cat,url) VALUES(?,?)", (cat, url))
            if cur.rowcount == 1:
                handles[cat].write(url + "\n")
                counts[cat] += 1
        except Exception:
            handles[cat].write(url + "\n")
            counts[cat] += 1

    batch = 0
    try:
        with Path(url_file).open("r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                url = strip_ansi(raw.strip())
                if not url or not url.startswith("http"):
                    continue
                try:
                    parsed = urlparse(url)
                    path   = parsed.path
                    qs     = parsed.query
                except:
                    continue
                if _PAT_SKIP.search(path):
                    continue
                if _PAT_SENSITIVE.search(path): _w("sensitive", url)
                if _PAT_ADMIN.search(path):     _w("admin", url)
                if _PAT_LOGIN.search(path):     _w("login", url)
                if _PAT_API.search(path):       _w("api", url)
                if qs:
                    _w("params", url)
                    _w("xss_targets", url)
                    if _PAT_PARAM.search("?" + qs):
                        _w("reflection", url)
                elif _PAT_FORM.search(path):
                    _w("forms", url)
                elif not any([_PAT_SENSITIVE.search(path), _PAT_ADMIN.search(path),
                              _PAT_LOGIN.search(path), _PAT_API.search(path)]):
                    _w("other", url)
                batch += 1
                if batch % 2000 == 0:
                    conn.commit()
    finally:
        try:
            conn.commit()
            conn.close()
        except:
            pass
        for h in handles.values():
            try: h.close()
            except: pass
        try:
            db_path.unlink()
        except:
            pass
    return counts

# ── run_cmd ───────────────────────────────────────────────────────────────────
def run_cmd(cmd, out_file=None, timeout=120, log=None, label="",
            silent=False, stream=False, retries=2, retry_delay=5):
    if _INT.hard():
        return False, ""
    _attempt = 0
    while True:
        _ok, _txt = _run_once(cmd, out_file=out_file, timeout=timeout,
                              log=log, label=label, silent=silent, stream=stream,
                              attempt=_attempt)
        if _INT.hard() or _INT.interrupted():
            return _ok, _txt
        file_lines = _count_lines(out_file) if (out_file and Path(out_file).exists() and Path(out_file).stat().st_size > 0) else 0
        stdout_lines = len([l for l in (_txt or "").splitlines() if l.strip()])
        lc = file_lines or stdout_lines
        if lc > 0 or _attempt >= retries:
            return _ok, _txt
        _attempt += 1
        lbl = label or cmd.split()[0]
        print(
            f"  {C.YELLOW}↻{C.RESET} {C.DIM}{lbl}{C.RESET} — "
            f"{C.YELLOW}0 lines, retry {_attempt}/{retries}{C.RESET} "
            f"{C.DIM}(waiting {retry_delay}s...){C.RESET}",
            flush=True
        )
        if log:
            log.warning(f"RETRY {_attempt}/{retries}: {lbl} — 0 lines")
        time.sleep(retry_delay)
        if out_file and Path(out_file).exists():
            try: Path(out_file).unlink()
            except: pass

def _run_once(cmd, out_file=None, timeout=120, log=None, label="",
              silent=False, stream=False, attempt=0):
    if _INT.hard():
        return False, ""
    label = label or (cmd[0] if isinstance(cmd, list) else cmd.split()[0])
    start = time.time()
    if not silent:
        sub(f"{label}...")

    proc_ref    = [None]
    stdout_buf  = [b""]
    stderr_buf  = [b""]
    timed_out   = [False]
    ctrl_killed = [False]

    def _worker():
        try:
            shell = isinstance(cmd, str)
            p = subprocess.Popen(cmd, shell=shell,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc_ref[0] = p
            out, err_out = p.communicate()
            stdout_buf[0] = out or b""
            stderr_buf[0] = err_out or b""
        except Exception as ex:
            stderr_buf[0] = str(ex).encode()

    worker      = threading.Thread(target=_worker, daemon=True)
    stop_spin   = threading.Event()
    spin_thread = threading.Thread(target=_spinner, args=(stop_spin, label), daemon=True)
    worker.start()
    if not silent:
        spin_thread.start()
    for _ in range(int(timeout / 0.2)):
        worker.join(0.2)
        if not worker.is_alive():
            break
        if _INT.interrupted() or _INT.hard():
            ctrl_killed[0] = True
            if proc_ref[0]:
                try: proc_ref[0].kill(); proc_ref[0].wait(2)
                except: pass
            worker.join(2)
            break
    else:
        if worker.is_alive():
            timed_out[0] = True
            if proc_ref[0]:
                try: proc_ref[0].kill(); proc_ref[0].wait(3)
                except: pass
            worker.join(3)
    stop_spin.set()
    if not silent:
        spin_thread.join(0.5)
    elapsed = round(time.time() - start, 1)
    rc      = proc_ref[0].returncode if proc_ref[0] else -1
    txt     = stdout_buf[0].decode("utf-8", errors="replace")
    etxt    = stderr_buf[0].decode("utf-8", errors="replace")
    if out_file:
        Path(out_file).parent.mkdir(parents=True, exist_ok=True)
        if txt.strip():
            Path(out_file).write_text(txt, encoding="utf-8", errors="replace")
    lc = (_count_lines(out_file) if (out_file and Path(out_file).exists())
          else len([l for l in txt.splitlines() if l.strip()]))
    if log:
        log.info(f"CMD: {cmd} | rc={rc} | {elapsed}s | lines={lc}")
        if etxt.strip():
            log.debug(f"STDERR: {strip_ansi(etxt)[:900]}")
    if not silent:
        if ctrl_killed[0]:
            warn(f"{label} stopped ({elapsed}s)")
        elif timed_out[0]:
            warn(f"{label} timed out ({timeout}s) — skipping")
        elif rc == 0:
            ok(f"{label} ({elapsed}s) — {lc:,} lines")
        else:
            warn(f"{label} exit {rc} ({elapsed}s)")
    _INT.reset()
    return (not timed_out[0] and not ctrl_killed[0] and rc == 0), txt


# ── Streaming tool runner ─────────────────────────────────────────────────────
def _stream_tool(cmd, timeout: int, log=None, label: str = "",
                 line_cb=None) -> tuple:
    if _INT.hard():
        return -1, 0, True
    start       = time.time()
    total_lines = [0]
    rc          = [-1]
    killed      = [False]
    proc_ref    = [None]
    stop_spin  = threading.Event()
    spin_label = label or (cmd[0] if isinstance(cmd, list) else cmd.split()[0])

    def _spin_ticker():
        frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        i = 0
        if not sys.stdout.isatty():
            return
        while not stop_spin.is_set():
            elapsed = round(time.time() - start, 0)
            sys.stdout.write(
                f"\r  {C.CYAN}{frames[i % len(frames)]}{C.RESET} "
                f"{C.DIM}{spin_label}{C.RESET} "
                f"{C.DIM}processing {total_lines[0]:,} lines{C.RESET} "
                f"{C.DIM}{int(elapsed)}s{C.RESET}   "
            )
            sys.stdout.flush()
            i += 1
            time.sleep(0.12)
        sys.stdout.write(f"\r{' ' * 72}\r")
        sys.stdout.flush()

    spin_thread = threading.Thread(target=_spin_ticker, daemon=True)

    def _reader():
        try:
            _shell = isinstance(cmd, str)
            p = subprocess.Popen(
                cmd, shell=_shell,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=0,
                env={**os.environ, "PYTHONUNBUFFERED": "1", "TERM": "dumb"}
            )
            proc_ref[0] = p
            buf = b""
            while True:
                chunk = p.stdout.read(256)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line_b, buf = buf.split(b"\n", 1)
                    raw = line_b.decode("utf-8", errors="replace")
                    line = strip_ansi(raw.rstrip())
                    if not line:
                        continue
                    total_lines[0] += 1
                    if line_cb:
                        line_cb(line)
            p.wait()
            rc[0] = p.returncode
        except Exception as ex:
            if log:
                log.warning(f"_stream_tool reader error: {ex}")
            rc[0] = -1

    reader_thread = threading.Thread(target=_reader, daemon=True)
    if log:
        log.info(f"[START] {cmd}")
    reader_thread.start()
    spin_thread.start()
    deadline = start + timeout
    while reader_thread.is_alive():
        reader_thread.join(0.3)
        if _INT.interrupted() or _INT.hard():
            killed[0] = True
            if proc_ref[0]:
                try:
                    proc_ref[0].kill()
                    proc_ref[0].wait(3)
                except Exception:
                    pass
            break
        if time.time() > deadline:
            warn(f"{spin_label} timeout ({timeout}s) — stopping")
            killed[0] = True
            if proc_ref[0]:
                try:
                    proc_ref[0].kill()
                    proc_ref[0].wait(3)
                except Exception:
                    pass
            break
    stop_spin.set()
    spin_thread.join(1.0)
    reader_thread.join(2.0)
    elapsed = round(time.time() - start, 1)
    if log:
        log.info(f"[STREAM] {cmd} | rc={rc[0]} | {elapsed}s | lines={total_lines[0]}")
    if killed[0]:
        warn(f"{spin_label} stopped ({elapsed}s) — {total_lines[0]:,} lines read")
    else:
        ok(f"{spin_label} done ({elapsed}s) — {total_lines[0]:,} lines")
    _INT.reset()
    return rc[0], total_lines[0], killed[0]


# ══════════════════════════════════════════════════════════════════════════════
class ReconPipeline:
    def __init__(self, target, cfg, resume=False, auto_nuclei=False, auto_xss=False,
                 url_targets=None):
        self.target      = target.strip()
        self.cfg         = cfg
        self.ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.out         = BASE_DIR / "output" / f"{self.target}_{self.ts}"
        self.resume      = resume
        self.auto_nuclei = auto_nuclei
        self.auto_xss    = auto_xss
        self.url_targets = url_targets or []
        self.summary     = {}
        self.log         = None

        self.katana_needs_sudo = False
        self.katana_available  = tool_exists("katana")

        self.adapt_mult      = 1.0
        self.waf_fingerprint = []
        self.block_ratio     = 0.0
        self.adaptive_events = []
        self.reruns          = {"nuclei": 0, "dalfox": 0}

        # v6.5: nuclei template path (lazy-discovered in stage7)
        self._nuclei_tpl_path = None

        for d in ["01_recon", "02_subdomains", "03_alive", "04_urls",
                  "05_categorized", "06_xss", "07_nuclei", "checkpoints"]:
            (self.out / d).mkdir(parents=True, exist_ok=True)

        self.log = setup_logger(self.out / "pipeline.log")
        atexit.register(self._emergency_save)
        self._precheck_katana_permission()

    def _emergency_save(self):
        try:
            sf = self.out / "SUMMARY.json"
            if not sf.exists():
                sf.write_text(
                    json.dumps({"target": self.target, "stages": self.summary,
                                "adaptive_events": self.adaptive_events,
                                "note": "emergency"}, indent=2, default=str),
                    encoding="utf-8"
                )
        except:
            pass

    def _cp(self, name):    return self.out / "checkpoints" / f"{name}.txt"
    def _cp_ok(self, name):
        p = self._cp(name)
        return self.resume and p.exists() and p.stat().st_size > 0

    def _is_root(self) -> bool:
        try:
            return os.geteuid() == 0
        except Exception:
            return False

    def _precheck_katana_permission(self):
        if not self.katana_available:
            return
        try:
            r = subprocess.run("katana -version", shell=True, capture_output=True, text=True, timeout=5)
            out = (r.stdout or "") + (r.stderr or "")
            if "permission denied" in out.lower() or "could not read flags" in out.lower():
                self.katana_needs_sudo = True
                if not self._is_root():
                    warn("katana requires sudo on this system.")
        except Exception:
            pass

    def _resolve_ip(self, domain: str) -> str:
        for cmd in [
            f"dig +short {domain} | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | head -1",
            f"host {domain} | grep 'has address' | head -1 | awk '{{print $NF}}'",
        ]:
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                ip = r.stdout.strip()
                if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    return ip
            except:
                pass
        try:
            import socket
            ip = socket.gethostbyname(domain)
            if ip and ip != domain:
                return ip
        except:
            pass
        return ""

    # ── Adaptive tuning (v6.5: exponential backoff) ───────────────────────────
    def _apply_adaptive(self, reason: str, extra_backoff: float = 1.0):
        if not bool(_cfg_get(self.cfg, "settings", "adaptive_rate", default=True)):
            return
        floor = float(_cfg_get(self.cfg, "settings", "adaptive_floor_mult", default=0.25))
        before = float(self.adapt_mult)
        # v6.5: exponential — her çağrıda daha agresif düşüş
        decay = 0.65 * float(extra_backoff)
        self.adapt_mult = max(floor, min(self.adapt_mult, 1.0) * decay)
        after = float(self.adapt_mult)
        evt = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "reason": reason,
            "mult_before": round(before, 4),
            "mult_after": round(after, 4),
        }
        self.adaptive_events.append(evt)
        warn(f"Adaptive rate ({reason}). Multiplier: {before:.2f} → {after:.2f}")

    def _tuned_threads(self, base: int, cap: int) -> int:
        base = int(base); cap = int(cap)
        v = max(1, int(round(base * self.adapt_mult)))
        return min(max(1, v), cap)

    def _tuned_rate(self, base: int, cap: int) -> int:
        base = int(base); cap = int(cap)
        v = max(1, int(round(base * self.adapt_mult)))
        return min(max(1, v), cap)

    def _tuned_delay_ms(self, base_rate: int) -> int:
        base_rate = max(1, int(base_rate))
        base_delay = int(1000 / base_rate)
        if self.adapt_mult >= 0.99:
            return max(1, base_delay)
        scale = (1.0 / max(self.adapt_mult, 0.15))
        return int(max(1, base_delay * scale))

    def _should_rerun(self, tool_key: str) -> bool:
        if not bool(_cfg_get(self.cfg, "settings", "rerun_on_block", default=True)):
            return False
        max_r = int(_cfg_get(self.cfg, "settings", "rerun_max", default=1))
        return int(self.reruns.get(tool_key, 0)) < max_r

    def _pause_before_rerun(self):
        sec = int(_cfg_get(self.cfg, "settings", "rerun_pause_sec", default=6))
        if sec > 0:
            sub(f"Cooling down: {sec}s")
            time.sleep(sec)

    # ── Stage 1 ───────────────────────────────────────────────────────────────
    def stage1_recon(self):
        stage(1, "Initial Reconnaissance")
        d   = self.out / "01_recon"
        tgt = self.target
        target_ip = self._resolve_ip(tgt)
        if target_ip:
            ok(f"IP resolved: {tgt} → {target_ip}")
        else:
            warn("IP resolution failed — continuing with domain")
        try:
            probe = http_probe(f"https://{tgt}", self.cfg, timeout=12)
            (d / "http_probe.json").write_text(json.dumps(probe, ensure_ascii=False, indent=2), encoding="utf-8")
            if probe.get("ok"):
                ok(f"HTTP probe: {probe.get('status')} ({probe.get('client')}) "
                   f"server={probe.get('server','?')} len={probe.get('len','?')}")
                waf = probe.get("waf_fingerprint") or []
                if waf:
                    self.waf_fingerprint = list(waf)
                    sub(f"WAF fingerprint: {', '.join(waf)}")
                if int(probe.get("status") or 0) in (403, 429):
                    self._apply_adaptive("probe got 403/429")
            else:
                sub(f"HTTP probe failed: {probe.get('error')}")
        except Exception:
            pass
        run_cmd(
            f"whois {tgt} 2>/dev/null || whois -H {tgt} 2>/dev/null || true",
            out_file=d / "whois.txt", timeout=T["whois"],
            log=self.log, label="whois", retries=2, retry_delay=5
        )
        if tool_exists("whatweb"):
            run_cmd(
                f"whatweb {tgt} -a 3 --open-timeout=10 --read-timeout=30 --log-verbose={d}/whatweb.txt",
                timeout=T["whatweb"], log=self.log, label="whatweb"
            )
        else:
            sub("whatweb not found")
        if tool_exists("wafw00f"):
            ok1, o1 = run_cmd(f"wafw00f https://{tgt} -a",
                              timeout=T["wafw00f"], log=self.log, label="wafw00f")
            if not ok1 or not o1.strip():
                _, o1 = run_cmd(f"wafw00f http://{tgt} -a",
                                timeout=T["wafw00f"], log=self.log, label="wafw00f-http")
            if o1.strip():
                (d / "wafw00f.txt").write_text(o1, encoding="utf-8", errors="replace")
        else:
            sub("wafw00f not found")
        if tool_exists("nmap"):
            nmap_target = target_ip if target_ip else tgt
            run_cmd(
                f"nmap -sV -sC --open -T4 --top-ports 1000 {nmap_target} -oN {d}/nmap.txt",
                timeout=T["nmap"], log=self.log, label="nmap", retries=1, retry_delay=5
            )
        else:
            sub("nmap not found")
        if tool_exists("theHarvester"):
            run_cmd(
                f"theHarvester -d {tgt} -b bing,duckduckgo,crtsh,dnsdumpster,hackertarget -f {d}/theharvester",
                timeout=T["harvester"], log=self.log, label="theHarvester"
            )
        else:
            sub("theHarvester not found")
        if has_valid_api_key(self.cfg, "shodan") and tool_exists("shodan"):
            ok2, _ = run_cmd("shodan info", timeout=10, log=self.log, label="shodan-check", silent=True, retries=0)
            if ok2:
                st = target_ip if target_ip else f"$(dig +short {tgt} | head -1)"
                run_cmd(f"shodan host {st}", out_file=d / "shodan.txt", timeout=T["shodan"], log=self.log, label="shodan")
        else:
            sub("shodan not configured")
        self.summary["stage1"] = {"status": "done", "target_ip": target_ip or "unknown", "waf_fingerprint": self.waf_fingerprint}
        checkpoint(self._cp("stage1_done"), [tgt], "stage1")

    # ── Stage 2 ───────────────────────────────────────────────────────────────
    def stage2_subdomains(self):
        stage(2, "Subdomain Enumeration")
        d   = self.out / "02_subdomains"
        tgt = self.target
        if self._cp_ok("stage2_subdomains"):
            n = _count_lines(self._cp("stage2_subdomains"))
            self.summary["stage2"] = {"status": "done", "count": n, "note": "resumed"}
            ok(f"Stage 2 resumed — {n:,} subdomains")
            return
        out_files = []
        if tool_exists("subfinder"):
            f = d / "subfinder.txt"
            run_cmd(f"subfinder -d {tgt} -all -o {f}",
                    timeout=T["subfinder"], log=self.log, label="subfinder", retries=2, retry_delay=5)
            out_files.append(f)
        else:
            sub("subfinder not found")
        if tool_exists("assetfinder"):
            f = d / "assetfinder.txt"
            run_cmd(f"assetfinder --subs-only {tgt}", out_file=f,
                    timeout=T["assetfinder"], log=self.log, label="assetfinder", retries=2, retry_delay=5)
            out_files.append(f)
        else:
            sub("assetfinder not found")
        f = d / "sublist3r.txt"
        sl3r = next((p for p in [Path("/opt/Sublist3r/sublist3r.py")] if p.exists()), None)
        if tool_exists("sublist3r"):
            run_cmd(f"sublist3r -d {tgt} -o {f}", timeout=T["sublist3r"], log=self.log, label="sublist3r")
            out_files.append(f)
        elif sl3r:
            py = str(VENV_PY) if VENV_PY.exists() else "python3"
            run_cmd(f"{py} {sl3r} -d {tgt} -o {f}", timeout=T["sublist3r"], log=self.log, label="sublist3r")
            out_files.append(f)
        else:
            sub("sublist3r not found")
        if tool_exists("findomain"):
            f = d / "findomain.txt"
            run_cmd(f"findomain -t {tgt} -q", out_file=f,
                    timeout=T["findomain"], log=self.log, label="findomain", retries=2, retry_delay=5)
            out_files.append(f)
        else:
            sub("findomain not found")
        raw_f  = d / "all_raw.txt"
        dom_re = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9]$')
        def _okf(l: str) -> bool:
            if not dom_re.match(l): return False
            l = l.lower()
            t = tgt.lower()
            return (l == t) or l.endswith("." + t)
        seen = set()
        Path(raw_f).parent.mkdir(parents=True, exist_ok=True)
        with Path(raw_f).open("w", encoding="utf-8") as out:
            for src in out_files:
                if not src.exists(): continue
                for ln in src.read_text(errors="replace").splitlines():
                    ln = strip_ansi(ln.strip())
                    if not ln or ln.startswith("#"): continue
                    if not _okf(ln): continue
                    if ln in seen: continue
                    seen.add(ln)
                    out.write(ln + "\n")
        lines = [l.strip() for l in raw_f.read_text(errors="ignore").splitlines() if l.strip()]
        if tgt not in lines:
            lines.insert(0, tgt)
            write_lines(raw_f, lines)
        final = [l.strip() for l in raw_f.read_text(errors="ignore").splitlines() if l.strip()]
        n = checkpoint(self._cp("stage2_subdomains"), final, "subdomains")
        info(f"Total unique subdomains: {n:,}")
        self.summary["stage2"] = {"status": "done", "count": n}

    # ── Stage 3 ───────────────────────────────────────────────────────────────
    def stage3_alive(self):
        stage(3, "Host Validation — httpx")
        d = self.out / "03_alive"
        if self._cp_ok("stage3_alive"):
            n = _count_lines(self._cp("stage3_alive"))
            self.summary["stage3"] = {"status": "done", "count": n, "note": "resumed"}
            ok(f"Stage 3 resumed — {n:,} alive hosts")
            return
        sub_file = self._cp("stage2_subdomains")
        if not sub_file.exists() or sub_file.stat().st_size == 0:
            warn("No subdomain file — using domain directly")
            n = checkpoint(self._cp("stage3_alive"),
                           [f"https://{self.target}", f"http://{self.target}"],
                           "alive-fallback")
            self.summary["stage3"] = {"status": "done", "count": n, "note": "fallback"}
            return
        if not tool_exists("httpx"):
            warn("httpx not found — treating all subdomains as alive")
            subs = [l.strip() for l in sub_file.read_text(errors="ignore").splitlines() if l.strip()]
            urls = sorted({f"https://{s}" if not s.startswith("http") else s for s in subs})
            n = checkpoint(self._cp("stage3_alive"), urls, "alive-nohttpx")
            self.summary["stage3"] = {"status": "done", "count": n, "note": "no-httpx"}
            return
        base_threads = int(_cfg_get(self.cfg, "settings", "threads", default=50))
        threads = self._tuned_threads(min(base_threads, 120), 120)
        json_out = d / "httpx_full.json"
        headers = pick_header_strategy(self.target, self.cfg)
        # v6.5: -favicon, -hash eklendi
        httpx_cmd = (
            f"httpx -l {sub_file} -no-color "
            f"-threads {threads} -timeout 20 -retries 2 -follow-redirects "
            f"-status-code -title -tech-detect -ip -server -content-length -response-time "
            f"-favicon -hash md5 "
            f"-ports 80,443,8080,8443,8000,8888,9090,3000,5000 "
            + _hdr_args_httpx(headers)
            + f" -json -o {json_out}"
        )
        run_cmd(httpx_cmd, timeout=T["httpx"], log=self.log, label="httpx", retries=1, retry_delay=5)
        alive_urls = []
        status_cnt = {}
        if json_out.exists() and json_out.stat().st_size > 0:
            with json_out.open("r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except:
                        continue
                    url = rec.get("url") or rec.get("input") or ""
                    if not url.startswith("http"):
                        continue
                    alive_urls.append(url)
                    status = int(rec.get("status-code") or rec.get("status_code") or 0)
                    status_cnt[status] = status_cnt.get(status, 0) + 1
        total_scanned = sum(status_cnt.values()) if status_cnt else 0
        blocked = status_cnt.get(403, 0) + status_cnt.get(429, 0)
        if total_scanned > 0:
            self.block_ratio = blocked / max(1, total_scanned)
            thr = float(_cfg_get(self.cfg, "settings", "adaptive_threshold", default=0.18))
            if self.block_ratio >= thr:
                self._apply_adaptive(f"httpx block ratio {self.block_ratio:.2%}")
        if not alive_urls:
            warn("httpx no response — using subdomains as fallback")
            subs = [l.strip() for l in sub_file.read_text(errors="ignore").splitlines() if l.strip()]
            for s in subs:
                alive_urls.append(f"https://{s}" if not s.startswith("http") else s)
        alive_urls = sorted(set(alive_urls))
        n = checkpoint(self._cp("stage3_alive"), alive_urls, "alive-hosts")
        info(f"Alive hosts: {n:,}")
        self.summary["stage3"] = {"status": "done", "count": n, "block_ratio": round(self.block_ratio, 4)}

    # ── Stage 4 ───────────────────────────────────────────────────────────────
    def stage4_urls(self):
        stage(4, "URL Discovery")
        d = self.out / "04_urls"
        if self._cp_ok("stage4_urls"):
            n = _count_lines(self._cp("stage4_urls"))
            self.summary["stage4"] = {"status": "done", "count": n, "note": "resumed"}
            ok(f"Stage 4 resumed — {n:,} URLs")
            return
        sub_file   = self._cp("stage2_subdomains")
        alive_file = self._cp("stage3_alive")
        all_subs = []
        if sub_file.exists() and sub_file.stat().st_size > 0:
            all_subs = [l.strip() for l in sub_file.read_text(errors="ignore").splitlines() if l.strip()]
        if not all_subs:
            all_subs = [self.target]
        alive_hosts = []
        if alive_file.exists() and alive_file.stat().st_size > 0:
            for l in alive_file.read_text(errors="ignore").splitlines():
                l = l.strip()
                if l:
                    alive_hosts.append(l if l.startswith("http") else f"https://{l}")
        if not alive_hosts:
            alive_hosts = [f"https://{s}" if not s.startswith("http") else s for s in all_subs]
        url_files = []
        if tool_exists("gau"):
            f_gau    = d / "gau.txt"
            gau_help = _help_text("gau")
            is_v2    = ("--subs" in gau_help) or ("--blacklist" in gau_help)
            gau_in   = d / "gau_input.txt"
            write_lines(gau_in, all_subs)
            if is_v2:
                gau_cmd = (f"cat {gau_in} | gau --providers wayback,commoncrawl,otx,urlscan "
                           f"--subs --threads 10 --retries 3 --timeout 60 "
                           f"--blacklist ttf,woff,svg,png,jpg,jpeg,gif,ico,css,eot,woff2,otf")
            else:
                gau_cmd = (f"cat {gau_in} | gau -subs -threads 10 -retries 3 "
                           f"-b ttf,woff,svg,png,jpg,jpeg,gif,ico,css,eot,woff2,otf")
            run_cmd(gau_cmd, out_file=f_gau, timeout=T["gau"], log=self.log, label="gau", retries=2, retry_delay=15)
            url_files.append(f_gau)
        else:
            sub("gau not found")
        if tool_exists("waybackurls"):
            f_wb  = d / "waybackurls.txt"
            wb_in = d / "wayback_input.txt"
            write_lines(wb_in, all_subs)
            run_cmd(f"cat {wb_in} | waybackurls", out_file=f_wb,
                    timeout=T["waybackurls"], log=self.log, label="waybackurls", retries=2, retry_delay=15)
            url_files.append(f_wb)
        else:
            sub("waybackurls not found")
        if self.katana_available and alive_hosts:
            if self.katana_needs_sudo and not self._is_root():
                warn("katana skipped: permission denied without sudo.")
            else:
                f_kat = d / "katana.txt"
                kin   = d / "katana_input.txt"
                write_lines(kin, alive_hosts)
                kh = _help_text("katana")
                conc = self._tuned_threads(10, 20)
                flags = " ".join(filter(None, [
                    "-silent",
                    "-jc"      if "-jc"     in kh else "",
                    "-kf all"  if "-kf"     in kh else "",
                    "-fx"      if "-fx"     in kh else "",
                    "-retry 2" if "-retry"  in kh else "",
                    f"-concurrency {conc}" if "-concurrency" in kh else "",
                    "-timeout 15" if "-timeout" in kh else "",
                ]))
                run_cmd(f"katana -list {kin} -d 5 {flags} -o {f_kat}",
                        timeout=T["katana"], log=self.log, label="katana", retries=2, retry_delay=8)
                if not f_kat.exists() or f_kat.stat().st_size == 0:
                    run_cmd(f"katana -list {kin} -d 3 -silent -o {f_kat}",
                            timeout=T["katana"], log=self.log, label="katana-min", retries=0)
                url_files.append(f_kat)
        else:
            sub("katana not found")
        if tool_exists("hakrawler") and alive_hosts:
            f_hak = d / "hakrawler.txt"
            hin   = d / "hakrawler_input.txt"
            write_lines(hin, alive_hosts)
            hh    = _help_text("hakrawler")
            flags = " ".join(filter(None, [
                "-d 3",
                "-insecure" if "-insecure" in hh else "",
                "-timeout 10" if "-timeout" in hh else "",
            ]))
            ok1, _ = run_cmd(f"cat {hin} | hakrawler {flags} 2>/dev/null",
                             out_file=f_hak, timeout=T["hakrawler"], log=self.log, label="hakrawler", retries=2, retry_delay=5)
            if not ok1 or not f_hak.exists() or f_hak.stat().st_size == 0:
                run_cmd(f"cat {hin} | hakrawler -d 2 2>/dev/null",
                        out_file=f_hak, timeout=T["hakrawler"], log=self.log, label="hakrawler-min", retries=0)
            if f_hak.exists():
                clean = d / "hakrawler_clean.txt"
                seen = set()
                with f_hak.open(errors="replace") as fi, clean.open("w") as fo:
                    for ln in fi:
                        u = strip_ansi(ln.strip())
                        if not u.startswith("http"):
                            continue
                        if _cfg_get(self.cfg, "settings", "canonicalize_urls", default=True):
                            u = canonicalize_url(u)
                        if u not in seen:
                            seen.add(u)
                            fo.write(u + "\n")
                url_files.append(clean)
        else:
            sub("hakrawler not found")
        raw_all = d / "all_urls_raw.txt"
        def _url_ok(line):
            if not line.startswith("http"):   return False
            if len(line) > 3000:              return False
            if "javascript:" in line.lower(): return False
            if "mailto:" in line.lower():     return False
            try:
                return not _PAT_SKIP.search(urlparse(line).path)
            except:
                return False
        normalize = canonicalize_url if bool(_cfg_get(self.cfg, "settings", "canonicalize_urls", default=True)) else None
        n = dedup_files_normalized(url_files, raw_all, filter_fn=_url_ok, normalize_fn=normalize)
        if n == 0:
            base = [canonicalize_url(u) for u in alive_hosts] if normalize else alive_hosts
            write_lines(raw_all, base)
            n = _count_lines(raw_all)
        shutil.copy2(raw_all, self._cp("stage4_urls"))
        info(f"Total unique URLs: {n:,}")
        self.summary["stage4"] = {"status": "done", "count": n, "canonicalized": bool(normalize)}

    # ── Stage 5 ───────────────────────────────────────────────────────────────
    def stage5_categorise(self):
        stage(5, "URL Categorisation")
        d = self.out / "05_categorized"
        url_file = self._cp("stage4_urls")
        if not url_file.exists() or url_file.stat().st_size == 0:
            warn("No URLs from stage 4 — skipping categorisation")
            self.summary["stage5"] = {"status": "skipped", "reason": "no_urls"}
            return
        counts = categorise_streaming(url_file, d)

        # Checkpoint her kategoriyi ayrı kaydet
        for name in ["reflection", "xss_targets", "params", "forms"]:
            p = d / f"{name}.txt"
            if p.exists() and p.stat().st_size > 0:
                shutil.copy2(p, self._cp(f"stage5_{name}"))

        normalize = canonicalize_url if bool(_cfg_get(self.cfg, "settings", "canonicalize_urls", default=True)) else None

        def _xss_ok(u: str) -> bool:
            if not u.startswith("http"): return False
            if len(u) > 3000: return False
            # Parametre olmayan URL'leri XSS listesine alma
            try:
                parsed = urlparse(u)
                if not parsed.query:
                    # Form endpoint'leri (.php, .asp vb.) yine de kabul et
                    if not _PAT_FORM.search(parsed.path):
                        return False
                if _PAT_SKIP.search(parsed.path):
                    return False
            except:
                pass
            return True

        # ── v6.6: 3 ayrı öncelikli XSS dosyası oluştur ─────────────────────
        #  Tier-1: reflection.txt  → sunucuya yansıyan parametreler (en değerli)
        #  Tier-2: params.txt      → herhangi bir query parametresi olan URL'ler
        #  Tier-3: forms.txt       → .php/.asp gibi form endpoint'leri (parametresiz)

        tier1_src = d / "reflection.txt"
        tier2_src = d / "params.txt"
        tier3_src = d / "forms.txt"

        tier1_out = d / "xss_tier1_reflected.txt"
        tier2_out = d / "xss_tier2_params.txt"
        tier3_out = d / "xss_tier3_forms.txt"
        xss_all   = d / "xss-targets-all.txt"

        # Tier-1: reflected (parametre değeri response'a yansıyanlar)
        n1 = 0
        if tier1_src.exists() and tier1_src.stat().st_size > 0:
            n1 = dedup_files_normalized([tier1_src], tier1_out,
                                        filter_fn=_xss_ok, normalize_fn=normalize)
        ok(f"XSS Tier-1 (reflected):  {n1:,} URLs → {tier1_out.name}")

        # Tier-2: params (query string var ama reflection teyidi yok)
        #   reflection ile overlap'i çıkar
        tier1_seen = set()
        if tier1_out.exists():
            for ln in tier1_out.read_text(errors="replace").splitlines():
                ln = ln.strip()
                if ln: tier1_seen.add(ln)

        n2 = 0
        if tier2_src.exists() and tier2_src.stat().st_size > 0:
            tmp2 = d / "_tmp_params_raw.txt"
            dedup_files_normalized([tier2_src], tmp2, filter_fn=_xss_ok, normalize_fn=normalize)
            # tier1'de olanları çıkar
            with tmp2.open(errors="replace") as fi, tier2_out.open("w") as fo:
                for ln in fi:
                    ln = ln.strip()
                    if ln and ln not in tier1_seen:
                        fo.write(ln + "\n")
                        n2 += 1
            try: tmp2.unlink()
            except: pass
        ok(f"XSS Tier-2 (params):     {n2:,} URLs → {tier2_out.name}")

        # Tier-3: form endpoints (parametresiz ama XSS'e açık olabilir)
        tier12_seen = tier1_seen.copy()
        if tier2_out.exists():
            for ln in tier2_out.read_text(errors="replace").splitlines():
                ln = ln.strip()
                if ln: tier12_seen.add(ln)

        n3 = 0
        if tier3_src.exists() and tier3_src.stat().st_size > 0:
            tmp3 = d / "_tmp_forms_raw.txt"
            # forms için _xss_ok'u biraz gevşet (parametresiz olabilir)
            def _form_ok(u):
                if not u.startswith("http"): return False
                if len(u) > 3000: return False
                try:
                    if _PAT_SKIP.search(urlparse(u).path): return False
                except: pass
                return True
            dedup_files_normalized([tier3_src], tmp3, filter_fn=_form_ok, normalize_fn=normalize)
            with tmp3.open(errors="replace") as fi, tier3_out.open("w") as fo:
                for ln in fi:
                    ln = ln.strip()
                    if ln and ln not in tier12_seen:
                        fo.write(ln + "\n")
                        n3 += 1
            try: tmp3.unlink()
            except: pass
        ok(f"XSS Tier-3 (forms):      {n3:,} URLs → {tier3_out.name}")

        # Hepsinin birleşimi (öncelik sırasıyla: tier1 → tier2 → tier3)
        all_sources = [f for f in [tier1_out, tier2_out, tier3_out]
                       if f.exists() and f.stat().st_size > 0]
        if not all_sources:
            # Son çare: tüm URL'leri dene
            warn("No categorised XSS targets — falling back to all URLs with params")
            all_sources = [url_file]

        n_all = dedup_files_normalized(all_sources, xss_all,
                                       filter_fn=_xss_ok if all_sources != [url_file] else None,
                                       normalize_fn=normalize)

        # Checkpoint'lere yaz (stage6 bunları okuyacak)
        shutil.copy2(tier1_out if tier1_out.exists() and n1 > 0 else
                     (tier2_out if tier2_out.exists() and n2 > 0 else xss_all),
                     self._cp("stage5_xss_tier1"))
        if tier2_out.exists() and n2 > 0:
            shutil.copy2(tier2_out, self._cp("stage5_xss_tier2"))
        if tier3_out.exists() and n3 > 0:
            shutil.copy2(tier3_out, self._cp("stage5_xss_tier3"))
        shutil.copy2(xss_all, self._cp("stage5_xss_targets_all"))

        ok(f"Categorisation complete — {sum(counts.values()):,} URLs processed")
        info(f"XSS tiers: T1(reflected)={n1:,}  T2(params)={n2:,}  T3(forms)={n3:,}  total={n_all:,}")
        self.summary["stage5"] = {
            "status": "done",
            "xss_tier1_reflected": {"count": n1, "file": str(tier1_out)},
            "xss_tier2_params":    {"count": n2, "file": str(tier2_out)},
            "xss_tier3_forms":     {"count": n3, "file": str(tier3_out)},
            "xss_targets_all":     {"count": n_all, "file": str(xss_all)},
            "categories":          {cat: {"count": cnt, "file": str(d / f"{cat}.txt")}
                                    for cat, cnt in counts.items()},
        }

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 6 — Dalfox XSS  (v6.5: agresif mod + BXSS)
    # ══════════════════════════════════════════════════════════════════════════
    def _run_dalfox_once(self, xss_file: Path, d: Path, run_tag: str) -> dict:
        base_rate    = int(_cfg_get(self.cfg, "settings", "rate_limit", default=8))
        base_workers = int(_cfg_get(self.cfg, "settings", "threads", default=15))
        timeout_req  = int(_cfg_get(self.cfg, "settings", "timeout", default=20))
        workers  = self._tuned_threads(min(base_workers, 20), 20)  # v6.5: 15→20
        delay_ms = self._tuned_delay_ms(base_rate)
        delay_ms = max(200, delay_ms)  # min 200ms
        ua    = _pick_ua()
        proxy = (_cfg_get(self.cfg, "settings", "proxy", default="") or "").strip()

        blind_cb     = (_cfg_get(self.cfg, "tools", "blind_xss_callback", default="") or "").strip()
        custom_pl    = (_cfg_get(self.cfg, "tools", "dalfox_custom_payload", default="") or "").strip()

        out_all = d / f"dalfox_findings{run_tag}.txt"

        dalfox_args = [
            "dalfox", "file", str(xss_file),
            "--no-color",
            "--follow-redirects",
            "--deep-domxss",           # v6.5: kept
            "--mining-dom",            # v6.5: DOM parametre madenciliği
            "--mining-dict",           # v6.5: dict ile parametre keşfi
            "--delay",   str(delay_ms),
            "--worker",  str(workers),
            "--timeout", str(timeout_req),
            "--user-agent", ua,
            "--format", "plain",
            "--output", str(out_all),
        ]

        # v6.5: BXSS (blind XSS) callback
        if blind_cb:
            dalfox_args += ["--blind", blind_cb]
            info(f"  BXSS callback: {blind_cb}")

        # v6.5: custom payload dosyası
        if custom_pl and Path(custom_pl).exists():
            dalfox_args += ["--custom-payload", custom_pl]
            info(f"  Custom payloads: {custom_pl}")

        # v6.5: WAF bypass headerlar
        headers = pick_header_strategy(self.target, self.cfg)
        dalfox_args += _hdr_args_dalfox(headers)

        if proxy:
            dalfox_args += ["--proxy", proxy]

        info(f"Dalfox XSS{run_tag or ''} [workers={workers} delay={delay_ms}ms timeout={timeout_req}s | "
             f"targets={_count_lines(xss_file):,}]")
        print(f"  {C.DIM}{'─'*58}{C.RESET}", flush=True)

        if self.log:
            self.log.info(f"[DALFOX CMD] {dalfox_args}")

        block_hits  = [0]
        http_reqs   = [0]
        poc_found   = [0]

        def _on_line(line: str):
            lo = line.lower()
            if re.search(r'https?://', lo):
                http_reqs[0] += 1
            if "403" in lo or "429" in lo or "forbidden" in lo or "too many requests" in lo:
                block_hits[0] += 1
            if "[poc]" in lo or "[vuln]" in lo or "[G]" in line or "[R]" in line:
                poc_found[0] += 1
                if sys.stdout.isatty():
                    sys.stdout.write(f"\r{' ' * 72}\r")
                print(f"  {C.RED}{C.BOLD}[XSS FOUND]{C.RESET} {line}", flush=True)

        rc, total_lines, killed = _stream_tool(
            dalfox_args,
            timeout=T["dalfox"],
            log=self.log,
            label="dalfox",
            line_cb=_on_line,
        )
        print(f"  {C.DIM}{'─'*58}{C.RESET}", flush=True)
        findings = _count_lines(out_all)
        ratio    = (block_hits[0] / max(1, http_reqs[0])) if http_reqs[0] > 0 else 0.0
        info(f"Dalfox{run_tag or ''}: {findings} XSS findings | {total_lines:,} lines | "
             f"block={block_hits[0]} ({ratio:.1%}) | PoC live={poc_found[0]}")
        return {
            "workers":      workers,
            "delay_ms":     delay_ms,
            "blocked_hits": block_hits[0],
            "total_lines":  total_lines,
            "block_ratio":  round(ratio, 4),
            "findings":     findings,
            "poc_live":     poc_found[0],
            "file_txt":     str(out_all),
        }

    def stage6_xss(self):
        if _INT.hard():
            return
        stage(6, "XSS Testing — Dalfox (Tiered)")

        if not tool_exists("dalfox"):
            warn("dalfox not found — skipping XSS")
            self.summary["stage6"] = {"status": "skipped", "reason": "not_found"}
            return

        # ── Tier dosyalarını topla ────────────────────────────────────────────
        tier1 = self._cp("stage5_xss_tier1")   # reflected (öncelik 1)
        tier2 = self._cp("stage5_xss_tier2")   # params    (öncelik 2)
        tier3 = self._cp("stage5_xss_tier3")   # forms     (öncelik 3)
        all_f = self._cp("stage5_xss_targets_all")

        def _tier_count(p):
            return _count_lines(p) if (p and p.exists() and p.stat().st_size > 0) else 0

        n1 = _tier_count(tier1)
        n2 = _tier_count(tier2)
        n3 = _tier_count(tier3)
        n_all = _tier_count(all_f)

        # Kullanılabilir tier'ları belirle
        tiers = []
        if n1 > 0: tiers.append(("Tier-1 reflected", tier1, n1))
        if n2 > 0: tiers.append(("Tier-2 params",    tier2, n2))
        if n3 > 0: tiers.append(("Tier-3 forms",     tier3, n3))

        # Hiçbir tier yoksa all_f'e düş
        if not tiers:
            if n_all > 0:
                tiers = [("All URLs (fallback)", all_f, n_all)]
            else:
                warn("No XSS target files found — skipping XSS")
                self.summary["stage6"] = {"status": "skipped", "reason": "no_xss_targets"}
                return

        # ── Kullanıcıya özet göster ───────────────────────────────────────────
        print(f"\n  {C.CYAN}XSS Target Breakdown:{C.RESET}")
        for label, _, cnt in tiers:
            print(f"    {C.DIM}→{C.RESET} {label}: {C.BOLD}{cnt:,}{C.RESET} URLs")
        total_xss_targets = sum(cnt for _, _, cnt in tiers)
        print(f"    {C.DIM}→{C.RESET} Total: {C.BOLD}{total_xss_targets:,}{C.RESET}")

        if not self.auto_xss:
            if not ask_yes_no(f"Run Dalfox XSS test? ({total_xss_targets:,} targets, {len(tiers)} tiers)"):
                warn("XSS skipped")
                self.summary["stage6"] = {"status": "skipped", "reason": "user_choice"}
                return
        else:
            info("Dalfox starting (auto mode)")

        d = self.out / "06_xss"
        d.mkdir(parents=True, exist_ok=True)

        all_results   = []
        total_findings = 0
        last_out_file  = None

        # ── Her tier'ı sırayla tara ───────────────────────────────────────────
        for tier_label, tier_file, tier_count in tiers:
            if _INT.hard():
                warn("Hard interrupt — stopping XSS tiers")
                break

            info(f"{'─'*50}")
            info(f"Dalfox → {tier_label} ({tier_count:,} URLs)")

            # tier tag: "tier1", "tier2", "tier3" veya "fallback"
            run_tag = "_" + tier_label.split()[0].lower().replace("-", "")

            r = self._run_dalfox_once(tier_file, d, run_tag=run_tag)
            all_results.append({"tier": tier_label, "count": tier_count, **r})
            total_findings += r["findings"]
            last_out_file = r["file_txt"]

            # Adaptive: bu tier'da çok bloklandıysak sonraki tier'ı yavaşlat
            thr = float(_cfg_get(self.cfg, "settings", "adaptive_threshold", default=0.18))
            if r["total_lines"] > 0 and r["block_ratio"] >= thr:
                self._apply_adaptive(f"dalfox {tier_label} block {r['block_ratio']:.2%}")
                if _INT.hard():
                    break
                # tier2 ve tier3 varsa devam etmeden önce bekle
                remaining = [t for t in tiers if t[0] != tier_label]
                if remaining:
                    self._pause_before_rerun()

        # ── Tüm tier bulguları birleştir ──────────────────────────────────────
        merged_out = d / "dalfox_all_findings.txt"
        tier_files = [Path(r["file_txt"]) for r in all_results if r.get("file_txt")]
        if tier_files:
            merge_unique_lines(merged_out, tier_files)
            total_findings = _count_lines(merged_out)
            shutil.copy2(merged_out, self._cp("stage6_xss"))
            last_out_file = str(merged_out)

        print(f"\n  {C.DIM}{'─'*58}{C.RESET}")
        if total_findings:
            ok(f"XSS findings total: {total_findings} → {merged_out.name}")
        else:
            ok("No XSS findings across all tiers")

        # ── Tier bazlı özet ───────────────────────────────────────────────────
        print(f"\n  {C.CYAN}XSS Results by Tier:{C.RESET}")
        for r in all_results:
            cnt = r.get("findings", 0)
            col = C.RED + C.BOLD if cnt > 0 else C.DIM
            print(f"    {col}→ {r['tier']}: {cnt} findings "
                  f"(block={r.get('block_ratio',0):.1%}){C.RESET}")

        self.summary["stage6"] = {
            "status":          "done",
            "tiers_run":       len(all_results),
            "total_targets":   total_xss_targets,
            "total_findings":  total_findings,
            "file":            last_out_file or "",
            "tier_results":    all_results,
        }

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 7 — Nuclei  (v6.5: template discovery + severity + exclude tags)
    # ══════════════════════════════════════════════════════════════════════════
    def _get_nuclei_template_path(self) -> str:
        """Lazy-init nuclei template path."""
        if self._nuclei_tpl_path is None:
            cfg_tpl = (_cfg_get(self.cfg, "tools", "nuclei_templates", default="") or "").strip()
            self._nuclei_tpl_path = discover_nuclei_templates(cfg_override=cfg_tpl)
        return self._nuclei_tpl_path

    def _run_nuclei_once(self, targets: Path, d: Path, run_tag: str) -> dict:
        threads     = self._tuned_threads(min(int(_cfg_get(self.cfg,"settings","threads",default=15)), 25), 25)
        rate        = self._tuned_rate(min(int(_cfg_get(self.cfg,"settings","rate_limit",default=8)), 20), 20)
        timeout_req = min(int(_cfg_get(self.cfg,"settings","timeout",default=20)), 30)
        proxy       = (_cfg_get(self.cfg,"settings","proxy",default="") or "").strip()
        ua          = _pick_ua()

        # v6.5: severity + template path + exclude tags
        severity    = (_cfg_get(self.cfg,"tools","nuclei_severity",default="critical,high,medium") or "").strip()
        excl_tags   = (_cfg_get(self.cfg,"tools","nuclei_excluded_tags",default="intrusive,dos") or "").strip()
        tpl_path    = self._get_nuclei_template_path()

        nout  = d / f"nuclei_results{run_tag}.txt"
        njson = d / f"nuclei_results{run_tag}.json"
        target_count = _count_lines(targets)

        nuc_args = ["nuclei"]
        if target_count == 1:
            single = targets.read_text(errors="replace").strip().splitlines()[0].strip()
            nuc_args += ["-u", single]
        else:
            nuc_args += ["-l", str(targets)]

        # v6.5: template path
        if tpl_path:
            nuc_args += ["-t", tpl_path]
            sub(f"Nuclei templates: {tpl_path}")
        else:
            sub("Nuclei: using built-in/default templates")

        # v6.5: auto-scan mode (technology-based template selection)
        nuc_args += ["-as"]

        nuc_help = ""
        try:
            r = subprocess.run(["nuclei", "-h"], capture_output=True, timeout=5)
            nuc_help = (r.stdout + r.stderr).decode("utf-8", errors="replace")
        except Exception:
            pass

        _nl = "\n"
        flag_c  = "-c"  if ("-c "  in nuc_help or ("-c" + _nl)  in nuc_help) else "-concurrency"
        flag_rl = "-rl" if ("-rl " in nuc_help or ("-rl" + _nl) in nuc_help) else "-rate-limit"

        nuc_args += [
            flag_c,  str(threads),
            flag_rl, str(rate),
            "-timeout",  str(timeout_req),
            "-retries",  "2",
            "-follow-redirects",
            "-no-color",
            "-H", f"User-Agent: {ua}",
        ]

        # v6.5: bypass headers
        bypass_hdrs = _bypass_headers_extra()
        for k, v in list(bypass_hdrs.items())[:3]:  # sadece IP spoof headers
            nuc_args += ["-H", f"{k}: {v}"]

        # v6.5: severity filter
        if severity:
            nuc_args += ["-severity", severity]
            sub(f"Nuclei severity filter: {severity}")
        else:
            sub("Nuclei: no severity filter (all severities)")

        # v6.5: exclude noisy/dangerous tags
        if excl_tags:
            nuc_args += ["-etags", excl_tags]
            sub(f"Nuclei excluded tags: {excl_tags}")

        nuc_args += ["-o", str(nout)]

        # v6.5: JSON export
        if "-je " in nuc_help or ("-je" + _nl) in nuc_help:
            nuc_args += ["-je", str(njson)]
        elif "-json-export" in nuc_help:
            nuc_args += ["-json-export", str(njson)]

        if proxy:
            nuc_args += ["-proxy", proxy]

        info(f"Nuclei{run_tag or ''} [c={threads} rl={rate} sev={severity or 'all'} | {target_count:,} targets]")
        print(f"  {C.DIM}{'─'*58}{C.RESET}", flush=True)
        if self.log:
            self.log.info(f"[NUCLEI CMD] {nuc_args}")

        findings_live = [0]
        sev_counts    = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        stop_spin     = threading.Event()
        start_t       = time.time()
        frames        = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

        def _spin():
            if not sys.stdout.isatty():
                return
            i = 0
            while not stop_spin.is_set():
                elapsed = int(time.time() - start_t)
                crit = sev_counts["critical"]
                high = sev_counts["high"]
                sys.stdout.write(
                    f"\r  {C.CYAN}{frames[i%10]}{C.RESET} "
                    f"{C.DIM}nuclei{C.RESET} "
                    f"{C.RED if crit else C.DIM}{findings_live[0]} findings"
                    f"{'  CRIT:'+str(crit) if crit else ''}"
                    f"{'  HIGH:'+str(high) if high else ''}{C.RESET} "
                    f"{C.DIM}{elapsed}s{C.RESET}   "
                )
                sys.stdout.flush()
                i += 1
                time.sleep(0.12)
            sys.stdout.write(f"\r{chr(32)*80}\r")
            sys.stdout.flush()

        spin_t = threading.Thread(target=_spin, daemon=True)
        spin_t.start()

        blocked_hits   = 0
        http_responses = 0
        total_lines    = 0
        proc           = None

        try:
            proc = subprocess.Popen(
                nuc_args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env={**os.environ},
            )
            for raw in proc.stderr:
                line = strip_ansi(raw.decode("utf-8", errors="replace").rstrip())
                if not line:
                    continue
                total_lines += 1
                if _INT.hard() or _INT.interrupted():
                    proc.kill(); proc.wait(3); break
                lo = line.lower()
                if re.search(r'https?://', line):
                    http_responses += 1
                if "[403]" in lo or "[429]" in lo or "forbidden" in lo:
                    blocked_hits += 1

                # v6.5: daha iyi severity parsing
                msev = re.search(r'\[(critical|high|medium|low|info)\]', line, re.I)
                if msev:
                    s = msev.group(1).lower()
                    sev_counts[s] = sev_counts.get(s, 0) + 1
                    findings_live[0] += 1
                    col = {
                        "critical": C.RED + C.BOLD,
                        "high":     C.RED,
                        "medium":   C.YELLOW,
                        "low":      C.BLUE,
                        "info":     C.DIM,
                    }.get(s, C.DIM)
                    if sys.stdout.isatty():
                        sys.stdout.write(f"\r{chr(32)*80}\r")
                    print(f"  {col}[{s.upper()}]{C.RESET} {line}", flush=True)
                    if self.log:
                        self.log.info(f"[FINDING] [{s}] {line}")
                elif "[ERR]" in line or "error" in lo:
                    if sys.stdout.isatty():
                        sys.stdout.write(f"\r{chr(32)*80}\r")
                    warn(f"nuclei: {line}")
                    if self.log:
                        self.log.warning(f"[NUCLEI-ERR] {line}")
                elif self.log and ("[INF]" in line or "[WRN]" in line):
                    self.log.debug(f"[NUCLEI] {line}")
            proc.wait()
        except Exception as ex:
            warn(f"Nuclei error: {ex}")
            if self.log:
                self.log.exception("nuclei exception")
        finally:
            stop_spin.set()
            spin_t.join(1)
            if proc and proc.poll() is None:
                try: proc.kill(); proc.wait(2)
                except: pass

        print(f"  {C.DIM}{'─'*58}{C.RESET}", flush=True)
        findings = _count_lines(nout)
        ratio    = (blocked_hits / max(1, http_responses)) if http_responses > 0 else 0.0

        # v6.5: severity summary
        sev_str = " | ".join([f"{k}={v}" for k, v in sev_counts.items() if v > 0])
        info(f"Nuclei{run_tag or ''}: {findings} findings | {total_lines:,} lines | "
             f"block={blocked_hits} ({ratio:.1%})")
        if sev_str:
            sub(f"Severity breakdown: {sev_str}")

        return {
            "threads": threads, "rate": rate,
            "blocked_hits": blocked_hits, "total_lines": total_lines,
            "http_responses": http_responses, "block_ratio": round(ratio, 4),
            "findings": findings, "file_txt": str(nout), "file_json": str(njson),
            "severity_counts": sev_counts,
            "template_path": tpl_path or "built-in",
        }

    def stage7_nuclei(self):
        if _INT.hard():
            return
        if not self.auto_nuclei:
            if not ask_yes_no("Run Nuclei vulnerability scan?"):
                warn("Nuclei skipped")
                self.summary["stage7"] = {"status": "skipped", "reason": "user_choice"}
                return
        else:
            info("Nuclei starting (auto mode)")
        if not tool_exists("nuclei"):
            warn("nuclei not found")
            self.summary["stage7"] = {"status": "skipped", "reason": "not_found"}
            return

        stage(7, "Nuclei Vulnerability Scanning")
        d          = self.out / "07_nuclei"
        alive_file = self._cp("stage3_alive")
        urls_file  = self._cp("stage4_urls")
        targets    = d / "nuclei_targets.txt"

        src_files = [p for p in [alive_file, urls_file] if p and Path(p).exists() and p.stat().st_size > 0]
        for sf in src_files:
            sub(f"Nuclei source: {sf.name} ({_count_lines(sf):,} lines)")

        merged_count = dedup_files_normalized(
            src_files, targets,
            filter_fn=lambda u: u.startswith("http"),
            normalize_fn=(canonicalize_url if bool(_cfg_get(self.cfg, "settings", "canonicalize_urls", default=True)) else None)
        )

        if merged_count == 0 and alive_file.exists() and alive_file.stat().st_size > 0:
            shutil.copy2(alive_file, targets)
            merged_count = _count_lines(targets)

        if merged_count == 0:
            warn("Nuclei target list empty — skipping")
            self.summary["stage7"] = {"status": "skipped", "reason": "empty_targets"}
            return

        ok(f"Nuclei targets: {targets.name} — {merged_count:,} URLs")

        # v6.5: template update (optional, silently fail)
        sub("Updating nuclei templates (optional)...")
        try:
            subprocess.run(
                ["nuclei", "-update-templates", "-silent"],
                timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            ok("Templates updated")
        except Exception:
            sub("Template update skipped")

        r1 = self._run_nuclei_once(targets, d, run_tag="")
        thr = float(_cfg_get(self.cfg, "settings", "adaptive_threshold", default=0.18))

        did_rerun = False
        if r1["total_lines"] > 0 and r1["block_ratio"] >= thr:
            self._apply_adaptive(f"nuclei block ratio {r1['block_ratio']:.2%}")
            if self._should_rerun("nuclei") and not _INT.hard():
                self.reruns["nuclei"] += 1
                did_rerun = True
                backoff = float(_cfg_get(self.cfg, "settings", "rerun_backoff", default=0.65))
                self._apply_adaptive("nuclei rerun backoff", extra_backoff=backoff)
                self._pause_before_rerun()
                r2 = self._run_nuclei_once(targets, d, run_tag="_rerun")
                main_txt = Path(r1["file_txt"])
                merge_unique_lines(main_txt, [Path(r2["file_txt"])])
                r1["findings"] = _count_lines(main_txt)
                r1["rerun"] = r2
                ok(f"Nuclei rerun merged → {main_txt.name} (total: {r1['findings']})")

        checkpoint(self._cp("stage7_done"),
                   [f"targets:{merged_count}", f"findings:{r1['findings']}"], "nuclei")
        info(f"Nuclei targets: {merged_count:,}  | findings: {r1['findings']}")

        self.summary["stage7"] = {
            "status":          "done",
            "targets":         merged_count,
            "findings":        r1["findings"],
            "file":            r1["file_txt"],
            "file_json":       r1["file_json"],
            "threads":         r1["threads"],
            "rate":            r1["rate"],
            "block_ratio":     r1["block_ratio"],
            "severity_counts": r1.get("severity_counts", {}),
            "template_path":   r1.get("template_path", "?"),
            "did_rerun":       did_rerun,
        }
        if did_rerun:
            self.summary["stage7"]["rerun"] = r1.get("rerun", {})

    # ── HTML Report ───────────────────────────────────────────────────────────
    def _read_text_safe(self, p: Path, limit_bytes: int = 50_000_000) -> str:
        try:
            if not p or not p.exists():
                return ""
            if p.stat().st_size > limit_bytes:
                return f"[TRUNCATED: file too large ({p.stat().st_size} bytes)]\n"
            return p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return f"[ERROR reading {p}: {e}]\n"

    def _parse_nuclei_by_severity(self, txt: str) -> dict:
        """
        Nuclei çıktısını severity'e göre grupla.
        Her satırı yapısal dict'e çevir: {sev, template, host, line_raw}
        """
        groups = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "other": []}
        for raw_line in txt.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            m = re.search(r'\[(critical|high|medium|low|info)\]', line, re.I)
            sev = m.group(1).lower() if m else "other"
            # template adını çıkar: [template-name]
            tpl_m = re.search(r'^\[([^\]]+)\]', line)
            tpl   = tpl_m.group(1) if tpl_m else ""
            # URL çıkar
            url_m = re.search(r'https?://\S+', line)
            url   = url_m.group(0).rstrip("[]()") if url_m else ""
            groups[sev].append({"line": line, "template": tpl, "url": url})
        return groups

    def _parse_dalfox_findings(self, txt: str) -> list:
        """
        Dalfox çıktısını parse et.
        Her bulgu için: {line_raw, poc_url, param, payload_type}
        PoC URL'yi payload'dan arındırarak güvenli gösterim URL'si üret.
        """
        findings = []
        for raw_line in txt.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Dalfox çıktı formatları:
            # [POC][G] GET http://... / [POC][R] Reflected ...
            # [V] Verified ... http://...
            poc_type = ""
            if "[POC]" in line:
                if "[G]" in line:  poc_type = "GET"
                elif "[R]" in line: poc_type = "Reflected"
                elif "[V]" in line: poc_type = "Verified"
                else:               poc_type = "POC"
            elif line.startswith("[V]") or "[Verified]" in line:
                poc_type = "Verified"

            # Ham URL (payload içerebilir)
            url_m = re.search(r'https?://\S+', line)
            raw_url = url_m.group(0).rstrip("[](),") if url_m else ""

            # Güvenli görüntüleme URL'si: payload kısmını temizle
            # query param'daki XSS payload değerlerini "<PAYLOAD>" ile değiştir
            safe_url = raw_url
            if raw_url:
                try:
                    p = urlparse(raw_url)
                    qs = parse_qsl(p.query, keep_blank_values=True)
                    # XSS belirteçlerini içeren param değerlerini maskele
                    _xss_indicators = re.compile(
                        r'<|>|script|alert|onerror|onload|javascript|svg|img|'
                        r'&#|%3c|%3e|prompt|confirm|eval|document\.', re.I)
                    clean_qs = []
                    for k, v in qs:
                        if _xss_indicators.search(v):
                            clean_qs.append((k, "[XSS_PAYLOAD]"))
                        else:
                            clean_qs.append((k, v))
                    safe_url = urlunparse((
                        p.scheme, p.netloc, p.path, p.params,
                        urlencode(clean_qs), ""
                    ))
                except Exception:
                    safe_url = raw_url

            # Parametre adını çıkar
            param_m = re.search(r'(?:param|parameter)[=:\s]+([a-zA-Z0-9_\-]+)', line, re.I)
            if not param_m:
                # URL'den ilk değişen param'ı bul
                try:
                    p2 = urlparse(raw_url)
                    qs2 = parse_qsl(p2.query, keep_blank_values=True)
                    _xss_ind2 = re.compile(r'<|>|script|alert|onerror', re.I)
                    for k2, v2 in qs2:
                        if _xss_ind2.search(v2):
                            param_m = type("m", (), {"group": lambda self, n: k2})()
                            break
                except Exception:
                    pass
            param = param_m.group(1) if param_m and hasattr(param_m, "group") else ""

            findings.append({
                "line":     line,
                "poc_type": poc_type,
                "raw_url":  raw_url,
                "safe_url": safe_url,
                "param":    param,
            })
        return findings

    def build_full_report(self) -> Path:
        rp = self.out / "reconx_full_report.html"

        xss_file    = Path(self.summary.get("stage6", {}).get("file", "")) if isinstance(self.summary.get("stage6", {}), dict) else None
        nuclei_file = Path(self.summary.get("stage7", {}).get("file", "")) if isinstance(self.summary.get("stage7", {}), dict) else None

        xss_raw_txt  = self._read_text_safe(xss_file)    if xss_file    else ""
        nuclei_txt   = self._read_text_safe(nuclei_file) if nuclei_file else ""

        # Parse
        nuc_groups   = self._parse_nuclei_by_severity(nuclei_txt)
        nuc_severity = self.summary.get("stage7", {}).get("severity_counts", {})
        xss_findings = self._parse_dalfox_findings(xss_raw_txt)

        stage4   = self._cp("stage4_urls")
        urls_txt = self._read_text_safe(stage4)

        def esc(s): return html.escape(str(s) or "")

        def _safe_json(obj, indent=2):
            try:
                return json.dumps(obj, indent=indent, ensure_ascii=False, default=str)
            except Exception as e:
                return f"[JSON error: {e}]"

        _s3_count    = esc(str((self.summary.get("stage3") or {}).get("count", "?")))
        _s4_count    = esc(str((self.summary.get("stage4") or {}).get("count", "?")))
        _s6_findings = esc(str((self.summary.get("stage6") or {}).get("total_findings", "?")))
        _s7_findings = esc(str((self.summary.get("stage7") or {}).get("findings", "?")))
        _tpl_path    = esc(str((self.summary.get("stage7") or {}).get("template_path", "?")))

        meta = {
            "target":               self.target,
            "timestamp":            self.ts,
            "adaptive_multiplier":  self.adapt_mult,
            "block_ratio_httpx":    self.block_ratio,
            "waf_fingerprint":      self.waf_fingerprint,
            "adaptive_events":      self.adaptive_events,
            "stages":               self.summary,
        }

        sev_colors = {
            "critical": "#ff4444", "high": "#ff7700",
            "medium":   "#ffcc00", "low":  "#4499ff",
            "info":     "#666e7a", "other": "#555e6a",
        }

        def _sev_badge(sev: str, cnt: int) -> str:
            if cnt == 0:
                return ""
            col = sev_colors.get(sev, "#888")
            return (f'<span style="background:{col};color:#fff;padding:3px 10px;'
                    f'border-radius:999px;font-size:11px;font-weight:bold;margin:2px">'
                    f'{sev.upper()} {cnt}</span>')

        # Sadece critical/high/medium/low göster — info default gizli
        sev_badges = "".join([
            _sev_badge(s, nuc_severity.get(s, 0))
            for s in ["critical", "high", "medium", "low"]
        ])
        info_cnt = nuc_severity.get("info", 0)
        if info_cnt > 0:
            sev_badges += (
                f'<span style="background:#2a2a3a;color:#666e7a;padding:3px 10px;'
                f'border-radius:999px;font-size:11px;margin:2px" title="info findings hidden by default">'
                f'INFO {info_cnt} (hidden)</span>'
            )

        # ── Nuclei bölümü: info kapalı, diğerleri açık ───────────────────────
        def _nuclei_section_html() -> str:
            parts = []
            # Önemli severity'ler önce
            for sev in ["critical", "high", "medium", "low"]:
                items = nuc_groups.get(sev, [])
                if not items:
                    continue
                col      = sev_colors[sev]
                is_open  = "open" if sev in ("critical", "high", "medium") else ""
                rows = []
                for it in items:
                    tpl  = esc(it.get("template", ""))
                    url  = it.get("url", "")
                    line = esc(it.get("line", ""))
                    url_html = (
                        f'<a href="{esc(url)}" target="_blank" rel="noopener noreferrer" '
                        f'style="color:#7dd3fc;word-break:break-all">{esc(url)}</a>'
                    ) if url else ""
                    rows.append(
                        f'<tr>'
                        f'<td style="padding:4px 8px;color:{col};font-weight:bold;white-space:nowrap">'
                        f'[{sev.upper()}]</td>'
                        f'<td style="padding:4px 8px;color:#a8b4c4">{tpl}</td>'
                        f'<td style="padding:4px 8px">{url_html if url_html else f"<code>{line}</code>"}</td>'
                        f'</tr>'
                    )
                table = (
                    '<table style="width:100%;border-collapse:collapse;font-size:12px">'
                    '<thead><tr>'
                    '<th style="text-align:left;padding:4px 8px;color:#64748b">Sev</th>'
                    '<th style="text-align:left;padding:4px 8px;color:#64748b">Template</th>'
                    '<th style="text-align:left;padding:4px 8px;color:#64748b">URL / Detail</th>'
                    '</tr></thead><tbody>'
                    + "".join(rows)
                    + '</tbody></table>'
                )
                parts.append(
                    f'<details {is_open}>'
                    f'<summary style="color:{col};font-weight:bold;cursor:pointer;padding:6px 0">'
                    f'[{sev.upper()}] — {len(items)} findings</summary>'
                    f'<div style="margin-top:6px">{table}</div>'
                    f'</details>'
                )

            # info: varsayılan KAPALI, çok fazla gürültü
            info_items = nuc_groups.get("info", [])
            if info_items:
                rows_info = []
                for it in info_items:
                    tpl  = esc(it.get("template", ""))
                    url  = it.get("url", "")
                    line = esc(it.get("line", ""))
                    url_html = (
                        f'<a href="{esc(url)}" target="_blank" rel="noopener noreferrer" '
                        f'style="color:#7dd3fc">{esc(url)}</a>'
                    ) if url else f"<code>{line}</code>"
                    rows_info.append(
                        f'<tr><td style="padding:3px 8px;color:#666e7a">[INFO]</td>'
                        f'<td style="padding:3px 8px;color:#555e6a">{tpl}</td>'
                        f'<td style="padding:3px 8px;color:#555e6a">{url_html}</td></tr>'
                    )
                table_info = (
                    '<table style="width:100%;border-collapse:collapse;font-size:11px">'
                    '<thead><tr>'
                    '<th style="text-align:left;padding:3px 8px;color:#3a3a4a">Sev</th>'
                    '<th style="text-align:left;padding:3px 8px;color:#3a3a4a">Template</th>'
                    '<th style="text-align:left;padding:3px 8px;color:#3a3a4a">URL</th>'
                    '</tr></thead><tbody>'
                    + "".join(rows_info)
                    + '</tbody></table>'
                )
                parts.append(
                    f'<details>'  # kapalı başlıyor
                    f'<summary style="color:#555e6a;cursor:pointer;padding:6px 0;font-size:12px">'
                    f'[INFO] — {len(info_items)} findings (click to expand, usually noise)</summary>'
                    f'<div style="margin-top:4px">{table_info}</div>'
                    f'</details>'
                )

            return "\n".join(parts) if parts else '<p style="color:#555e6a">(no findings)</p>'

        # ── XSS bölümü ───────────────────────────────────────────────────────
        _UNSAFE_PROTO = re.compile(r'^(javascript|data|vbscript)\s*:', re.I)

        def _safe_href(url: str) -> str:
            """
            URL'yi href'e koymak güvenli mi?
            - https:// veya http:// ile başlıyorsa → doğrudan tıklanabilir link.
              Payload query string içinde olsa da href attribute'unda çalışmaz,
              browser URL'yi hedef siteye GETler — rapor içinde execute etmez.
            - javascript: / data: / vbscript: → href'e girmesin, sadece metin göster.
            """
            stripped = url.strip()
            if _UNSAFE_PROTO.match(stripped):
                return ""   # tıklanabilir yapma
            if stripped.startswith(("https://", "http://")):
                return stripped
            return ""

        def _xss_section_html() -> str:
            if not xss_findings:
                return '<p style="color:#555e6a">(no XSS findings)</p>'

            rows = []
            for idx, f in enumerate(xss_findings):
                poc_type = esc(f.get("poc_type", ""))
                param    = esc(f.get("param", ""))
                raw_url  = f.get("raw_url", "")
                line_raw = esc(f.get("line", ""))

                row_col = (
                    "#ff4444" if f.get("poc_type") == "Verified" else
                    "#ff7700" if f.get("poc_type") in ("GET", "Reflected") else
                    "#ffcc00"
                )

                # Ham PoC URL'yi doğrudan link yap — sadece javascript:/data: engelle
                clickable_href = _safe_href(raw_url)

                if clickable_href:
                    url_cell = (
                        f'<a href="{esc(clickable_href)}" target="_blank" '
                        f'rel="noopener noreferrer" '
                        f'style="color:#7dd3fc;word-break:break-all;font-size:11px">'
                        f'{esc(raw_url)}'
                        f'</a>'
                    )
                elif raw_url:
                    # javascript: veya data: payload — tıklanamaz metin olarak göster
                    url_cell = (
                        f'<code style="font-size:10px;color:#e06c75;word-break:break-all;'
                        f'user-select:all">{esc(raw_url)}</code>'
                        f'<span style="color:#555;font-size:10px;margin-left:6px">'
                        f'[javascript:/data: — copy manually]</span>'
                    )
                else:
                    url_cell = f'<code style="color:#555">{line_raw}</code>'

                rows.append(
                    f'<tr style="border-bottom:1px solid #1a2030">'
                    f'<td style="padding:8px;color:{row_col};font-weight:bold;'
                    f'white-space:nowrap;vertical-align:top">#{idx+1} {poc_type}</td>'
                    f'<td style="padding:8px;color:#a8b4c4;vertical-align:top">{param or "?"}</td>'
                    f'<td style="padding:8px;vertical-align:top">{url_cell}</td>'
                    f'</tr>'
                )

            return (
                '<table style="width:100%;border-collapse:collapse;font-size:12px">'
                '<thead style="background:#0b1220"><tr>'
                '<th style="text-align:left;padding:8px;color:#64748b">Type</th>'
                '<th style="text-align:left;padding:8px;color:#64748b">Param</th>'
                '<th style="text-align:left;padding:8px;color:#64748b">PoC URL</th>'
                '</tr></thead><tbody>'
                + "".join(rows)
                + '</tbody></table>'
            )

        html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none';
               img-src data:; connect-src 'none'; form-action 'none';" />
<title>ReconX v6.6 Report — {esc(self.target)}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
          margin: 0; padding: 20px 28px; background: #0b0f14; color: #e6edf3; }}
  .card {{ background: #0f1620; border: 1px solid #1f2a37; border-radius: 14px;
           padding: 18px 20px; margin: 14px 0;
           box-shadow: 0 4px 16px rgba(0,0,0,.3); }}
  h1 {{ margin: 0 0 4px 0; font-size: 22px; }}
  h2 {{ margin: 0 0 12px 0; font-size: 15px; color: #94a3b8; text-transform: uppercase;
        letter-spacing: .06em; }}
  .muted  {{ color: #4a5568; font-size: 12px; margin-top: 4px; }}
  .scroll {{ max-height: 540px; overflow: auto; }}
  .grid   {{ display: grid; gap: 12px;
             grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); }}
  .stat   {{ background: #0b1220; border: 1px solid #1f2a37; border-radius: 10px;
             padding: 14px 16px; }}
  .stat .label {{ font-size: 11px; color: #4a5568; text-transform: uppercase;
                  letter-spacing: .08em; margin-bottom: 4px; }}
  .stat .value {{ font-size: 28px; font-weight: 700; color: #e2e8f0; }}
  .pill   {{ display: inline-block; padding: 3px 10px; border-radius: 999px;
             background: #111b2a; border: 1px solid #1f2a37;
             font-size: 11px; color: #94a3b8; }}
  details summary {{ padding: 6px 0; user-select: none; }}
  details + details {{ margin-top: 4px; }}
  table   {{ border-spacing: 0; }}
  tr:hover td {{ background: rgba(255,255,255,.02); }}
  a {{ text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  code {{ background: #0b1220; padding: 2px 5px; border-radius: 4px; }}
  .xss-badge {{ display:inline-block; padding:2px 8px; border-radius:6px;
                font-size:10px; font-weight:bold; margin-right:4px; }}
</style>
</head>
<body>

<h1>ReconX v6.6 — Security Report</h1>
<div class="muted">
  Target: <strong style="color:#e2e8f0">{esc(self.target)}</strong>
  &nbsp;·&nbsp; {esc(self.ts)}
  &nbsp;·&nbsp; WAF: {esc(", ".join(self.waf_fingerprint) or "none detected")}
</div>

<!-- Stats -->
<div class="card grid" style="margin-top:18px">
  <div class="stat">
    <div class="label">Alive Hosts</div>
    <div class="value">{_s3_count}</div>
  </div>
  <div class="stat">
    <div class="label">Total URLs</div>
    <div class="value">{_s4_count}</div>
  </div>
  <div class="stat">
    <div class="value" style="color:{'#ff4444' if int((self.summary.get('stage6') or {{}}).get('total_findings') or 0) > 0 else '#e2e8f0'}">{_s6_findings}</div>
    <div class="label">XSS Findings</div>
  </div>
  <div class="stat">
    <div class="value" style="color:{'#ff4444' if int((self.summary.get('stage7') or {{}}).get('findings') or 0) > 0 else '#e2e8f0'}">{_s7_findings}</div>
    <div class="label">Nuclei Findings</div>
  </div>
</div>

<!-- Nuclei severity overview -->
<div class="card">
  <h2>Nuclei — Severity Overview</h2>
  <div style="margin: 4px 0 10px">{sev_badges if sev_badges else '<span class="muted">No findings</span>'}</div>
  <div class="muted">Templates: {_tpl_path} &nbsp;·&nbsp; Source: {esc(str(nuclei_file))}</div>
</div>

<!-- Nuclei findings (info collapsed) -->
<div class="card">
  <h2>Nuclei — Findings</h2>
  <div class="scroll">
    {_nuclei_section_html()}
  </div>
</div>

<!-- XSS findings — safe table, no live payloads -->
<div class="card">
  <h2>XSS — Dalfox Findings</h2>
  <div style="background:#1a0a0a;border:1px solid #3a1a1a;border-radius:8px;
              padding:8px 12px;margin-bottom:12px;font-size:12px;color:#f87171">
    ⚠ PoC URL'leri doğrudan tıklanabilir — yeni sekmede hedef siteye açılır.
    <code>javascript:</code> / <code>data:</code> payload'ları tıklanamaz metin olarak gösterilir.
    Rapor kendi içinde hiçbir payload execute etmez (CSP: script-src 'none').
  </div>
  <div class="scroll">
    {_xss_section_html()}
  </div>
</div>

<!-- URLs -->
<div class="card">
  <h2>All Discovered URLs</h2>
  <div class="muted">Source: {esc(str(stage4))}</div>
  <div class="scroll"><pre style="font-size:11px">{esc(urls_txt)}</pre></div>
</div>

<!-- Adaptive timeline -->
<div class="card">
  <h2>Adaptive Rate Timeline</h2>
  <div class="scroll"><pre style="font-size:11px">{esc(_safe_json(self.adaptive_events))}</pre></div>
</div>

<!-- Full metadata -->
<div class="card">
  <h2>Full Scan Metadata</h2>
  <div class="scroll"><pre style="font-size:11px">{esc(_safe_json(meta))}</pre></div>
</div>

</body>
</html>
"""
        rp.write_text(html_doc, encoding="utf-8", errors="replace")
        return rp

    # ── Report ────────────────────────────────────────────────────────────────
    def generate_report(self):
        stage("✦", "Generating Report")
        sf = self.out / "SUMMARY.json"
        try:
            summary_obj = {
                "target":              self.target,
                "timestamp":           self.ts,
                "adaptive_multiplier": self.adapt_mult,
                "block_ratio_httpx":   self.block_ratio,
                "waf_fingerprint":     self.waf_fingerprint,
                "adaptive_events":     self.adaptive_events,
                "stages":              self.summary,
                "output_dir":          str(self.out)
            }
            sf.write_text(
                json.dumps(summary_obj, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8"
            )
        except Exception as _je:
            sf.write_text(json.dumps({"error": str(_je), "target": self.target}), encoding="utf-8")

        full_report = None
        try:
            full_report = self.build_full_report()
            ok(f"FULL Report: {full_report}")
        except Exception as e:
            warn(f"FULL report error: {e}")

        report_path = None
        try:
            from report_builder import build_report
            report_path = build_report(self.out, self.target, self.summary)
            ok(f"Report: {report_path}")
        except ImportError:
            warn("report_builder.py not found — using FULL report")
        except Exception as e:
            warn(f"Report error: {e}")

        try:
            import webbrowser
            target_rp = report_path or full_report
            if target_rp:
                webbrowser.open(f"file://{target_rp}")
        except:
            pass

        print(f"\n{C.CYAN}{C.BOLD}{'═'*60}\n  SCAN COMPLETE — {self.target}\n{'═'*60}{C.RESET}")
        print(f"  {C.BLUE}Output      : {self.out}{C.RESET}")
        if report_path:
            print(f"  {C.BLUE}Report      : {report_path}{C.RESET}")
        if full_report:
            print(f"  {C.BLUE}FULL Report : {full_report}{C.RESET}")
        print(f"  {C.BLUE}Log         : {self.out}/pipeline.log{C.RESET}\n")

        # v6.5: findings özeti
        xss_cnt = (self.summary.get("stage6") or {}).get("total_findings", 0)
        nuc_cnt = (self.summary.get("stage7") or {}).get("findings", 0)
        nuc_sev = (self.summary.get("stage7") or {}).get("severity_counts", {})
        if xss_cnt or nuc_cnt:
            print(f"\n{C.RED}{C.BOLD}  ⚠  FINDINGS SUMMARY{C.RESET}")
            if xss_cnt:
                print(f"  {C.RED}XSS (Dalfox)  : {xss_cnt}{C.RESET}")
            if nuc_cnt:
                sev_str = " | ".join([f"{k.upper()}:{v}" for k, v in nuc_sev.items() if v > 0])
                print(f"  {C.RED}Nuclei        : {nuc_cnt}  [{sev_str}]{C.RESET}")
            print()

    # ── Stage 0 — URL seed ────────────────────────────────────────────────────
    def stage0_seed_urls(self):
        stage(0, "URL Seed Mode (-u/--single)")
        urls = []
        default_scheme = (_cfg_get(self.cfg, "settings", "default_scheme", default="https") or "https").strip()
        for u in self.url_targets:
            u = (u or "").strip()
            if not u:
                continue
            u = _normalize_url_like(u, default_scheme=default_scheme)
            if not u.startswith(("http://","https://")):
                u = f"{default_scheme}://{u}"
            if bool(_cfg_get(self.cfg, "settings", "canonicalize_urls", default=True)):
                u = canonicalize_url(u)
            urls.append(u)
        urls = [u for u in urls if u]
        urls = list(dict.fromkeys(urls))
        if not urls:
            err("No URLs found — exiting")
            sys.exit(1)
        ok(f"Seed URLs: {len(urls):,}")
        for u in urls[:10]:
            sub(u)
        if len(urls) > 10:
            sub(f"... and {len(urls)-10} more")
        hosts = []
        for u in urls:
            h = urlparse(u).hostname or ""
            h = re.sub(r"^[*]\.", "", h)
            if h:
                hosts.append(h)
        hosts = list(dict.fromkeys(hosts))
        write_lines(self._cp("stage2_subdomains"), hosts if hosts else [self.target])
        write_lines(self._cp("stage3_alive"),       urls)
        self.summary.setdefault("stage2", {"status": "done", "count": len(hosts), "note": "url_seed"})
        self.summary.setdefault("stage3", {"status": "done", "count": len(urls),  "note": "url_seed"})

    # ── Run ───────────────────────────────────────────────────────────────────
    def run(self, stages=None):
        all_s = {
            1: self.stage1_recon,      2: self.stage2_subdomains,
            3: self.stage3_alive,      4: self.stage4_urls,
            5: self.stage5_categorise, 6: self.stage6_xss,
            7: self.stage7_nuclei,
        }
        if self.url_targets:
            if (not self.resume or not self._cp_ok("stage1_done")) and (not stages or 1 in stages):
                self.stage1_recon()
            if not self.resume or not self._cp_ok("stage3_alive"):
                self.stage0_seed_urls()
            run_stages = stages or [4, 5, 6, 7]
        else:
            run_stages = stages or list(range(1, 8))
        try:
            for n in run_stages:
                if _INT.hard():
                    warn("Hard exit — writing report...")
                    break
                if n not in all_s:
                    warn(f"Unknown stage: {n}")
                    continue
                try:
                    all_s[n]()
                except SystemExit:
                    warn("Force exit — writing report...")
                    break
                except Exception as e:
                    err(f"Stage {n} crashed: {e}")
                    self.log.exception(f"Stage {n} fatal")
                    warn("Continuing to next stage...")
                _INT.reset()
        finally:
            self.generate_report()


# ── Legal ─────────────────────────────────────────────────────────────────────
def legal_warning():
    print(f"""{C.YELLOW}{C.BOLD}
  ⚠  LEGAL WARNING
  {'─'*56}
  This tool may only be used on AUTHORIZED targets under
  a valid bug bounty program. Unauthorized use is illegal.
  {'─'*56}{C.RESET}""")
    try:
        ans = input(f"  {C.BOLD}I confirm I have authorization (yes/no): {C.RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        sys.exit(0)
    if ans not in ("yes", "y", "evet", "e"):
        print("Cancelled.")
        sys.exit(0)

# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    print(f"""{C.CYAN}{C.BOLD}
    
                                                                                                                                                                                               
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗                                                                                                                                      
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝                                                                                                                                      
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝                                                                                                                                       
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗                                                                                                                                       
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗                                                                                                                                      
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ 
  ╔══════════════════════════════════════════════════════╗
  ║  ReconX Sequential Scanner v6.0                      ║
  ║  Recon → Subs → Alive → URLs → Cats → XSS → Nuclei   ║
  ║  +template-discovery · +severity-filter · +BXSS      ║
  ╚══════════════════════════════════════════════════════╝{C.RESET}""")

    p = argparse.ArgumentParser(description="ReconX Bug Bounty Scanner v6.5")
    p.add_argument("-d", "--domain",    required=False, default=None)
    p.add_argument("-u", "--url",       nargs="+", dest="urls", metavar="URL")
    p.add_argument("-U", "--url-file",  dest="url_file", metavar="FILE")
    p.add_argument("--single",          dest="single", metavar="TARGET")
    p.add_argument("-s", "--stages",    nargs="+", type=int)
    for i in range(1, 8):
        p.add_argument(f"--stage{i}", action="store_true", help=f"Run only stage {i}")
    p.add_argument("--resume",          action="store_true")
    p.add_argument("--no-legal",        action="store_true")
    p.add_argument("--auto-nuclei",     action="store_true")
    p.add_argument("--auto-xss",        action="store_true")
    p.add_argument("--config",          default=str(CFG_FILE))
    # v6.5: CLI overrides
    p.add_argument("--nuclei-templates", dest="nuclei_templates", default=None,
                   help="Override nuclei template path (e.g. /root/nuclei-templates)")
    p.add_argument("--severity",        dest="severity", default=None,
                   help="Nuclei severity filter (e.g. critical,high,medium)")
    p.add_argument("--blind",           dest="blind_cb", default=None,
                   help="Blind XSS callback URL for Dalfox")
    args = p.parse_args()

    cfg = load_config(Path(args.config))
    default_scheme = (_cfg_get(cfg, "settings", "default_scheme", default="https") or "https").strip()

    # v6.5: CLI → config override
    if args.nuclei_templates:
        cfg.setdefault("tools", {})["nuclei_templates"] = args.nuclei_templates
    if args.severity:
        cfg.setdefault("tools", {})["nuclei_severity"] = args.severity
    if args.blind_cb:
        cfg.setdefault("tools", {})["blind_xss_callback"] = args.blind_cb

    url_targets = []
    if args.single:
        url_targets.append(args.single)
    if args.urls:
        url_targets.extend(list(args.urls))
    if args.url_file:
        uf = Path(args.url_file)
        if not uf.exists():
            err(f"--url-file not found: {uf}"); sys.exit(1)
        for ln in uf.read_text(errors="replace").splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                url_targets.append(ln)

    url_targets = [(_normalize_url_like(u, default_scheme=default_scheme)) for u in url_targets if (u or "").strip()]
    url_targets = [u for u in url_targets if u]
    url_targets = list(dict.fromkeys(url_targets))

    stage_flags = [i for i in range(1, 8) if getattr(args, f"stage{i}")]
    if stage_flags and args.stages:
        stages = sorted(set(stage_flags + list(args.stages)))
    elif stage_flags:
        stages = sorted(set(stage_flags))
    else:
        stages = args.stages

    domain = args.domain
    if not domain:
        if url_targets:
            domain = _extract_domain_from_any(url_targets[0])
            if domain:
                info(f"Domain auto-detected: {domain}")
            else:
                err("Domain could not be detected — use -d"); sys.exit(1)
        else:
            err("-d / --domain required (or -u/--single with a URL)"); sys.exit(1)

    if not args.no_legal:
        legal_warning()

    ReconPipeline(
        domain, cfg,
        resume=args.resume,
        auto_nuclei=args.auto_nuclei,
        auto_xss=args.auto_xss,
        url_targets=url_targets if url_targets else None,
    ).run(stages=stages)

if __name__ == "__main__":
    main()
