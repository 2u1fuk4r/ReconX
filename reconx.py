#!/usr/bin/env python3
"""
ReconX Sequential Scanner v5.1
Recon → Subdomains → Alive → URLs → Categorise → Nuclei → XSS (Dalfox)

Changes v5.1:
  - Added --single flag: single-domain mode (no subdomain enumeration)
  - In single mode, Stage 2 is skipped; target domain used directly in all stages
  - All other stages (3-7) work identically

Changes v5.0:
  - Removed verbose dalfox progress bar component (non-functional)
  - Dalfox runs in standard pipe mode (clean output)
  - Removed old report_builder dependency — new professional report_builder.py
  - All verbose/debug prints eliminated — clean aesthetic output only
  - XSS snippet-based approach (dalfox pipe, no wrappers)
  - SIGTERM/atexit: report always written
  - RAM-safe streaming for large URL lists
"""


import atexit, os, sys, re, json, yaml, time, logging, argparse
import subprocess, shutil, threading, signal
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

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

def info(m):     print(f"{C.BLUE}[*]{C.RESET} {m}", flush=True)
def ok(m):       print(f"{C.GREEN}[✓]{C.RESET} {m}", flush=True)
def warn(m):     print(f"{C.YELLOW}[!]{C.RESET} {m}", flush=True)
def err(m):      print(f"{C.RED}[✗]{C.RESET} {m}", flush=True)
def sub(m):      print(f"  {C.DIM}→{C.RESET} {m}", flush=True)

# Global flag — büyük taramalarda spinner kapatılır (performans + temiz output)
_NO_SPINNER = False

def _spinner(stop_evt: threading.Event, label: str):
    """Braille spinner — runs in a daemon thread while a tool executes."""
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    i = 0
    if not sys.stdout.isatty() or _NO_SPINNER:
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
    p = path or CFG_FILE
    defaults = {
        "settings": {"threads": 10, "rate_limit": 5, "timeout": 30},
        "api_keys": {},
        "tools":    {"nuclei_severity": "critical,high,medium"},
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

# ── Logger ────────────────────────────────────────────────────────────────────
def setup_logger(log_file):
    log = logging.getLogger(f"reconx_{log_file.stem}")
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
                print(f"\n{C.RED}[✗] Force exit — writing report...{C.RESET}", flush=True)
                raise KeyboardInterrupt

_INT = _IS
signal.signal(signal.SIGINT,  _INT.handle)
signal.signal(signal.SIGTERM, lambda s, f: (
    setattr(_INT, "_hard", True),
    print(f"\n{C.RED}[✗] SIGTERM{C.RESET}", flush=True)
))

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

def dedup_files(src_paths, dst, filter_fn=None):
    """Stream-dedup multiple files into dst — RAM safe."""
    seen  = set()
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
                    if line in seen:
                        continue
                    if filter_fn and not filter_fn(line):
                        continue
                    seen.add(line)
                    out.write(line + "\n")
                    count += 1
    return count

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

# ── Timeouts ──────────────────────────────────────────────────────────────────
# ── Timeouts (seconds) ───────────────────────────────────────────────────────
# Gerçek dünya senaryolarına göre ayarlandı:
#   - Subdomain toolları büyük hedeflerde 20-30 dk sürebilir
#   - gau/waybackurls milyonlarca kayıt çekebilir → 45 dk
#   - Katana/gospider aktif crawler → hedef sayısına göre 30-60 dk
#   - Nuclei büyük hedef listesinde 2-4 saat sürebilir
#   - Dalfox reflection URL sayısına göre 30-60 dk

T = {
    # ── Recon ─────────────────────────────────────────────────────
    "whois":      120,    # genelde 10s ama bazen yavaş WHOIS sunucuları
    "whatweb":    600,    # -a 3 agresif mod + yavaş hedef
    "wafw00f":    120,    # 2 deneme (https + http)
    "nmap":       1800,   # --top-ports 1000 + -sV servis tespiti uzun sürer
    "harvester":  900,    # birden fazla kaynak sorgusu
    "shodan":     120,    # API çağrısı, bazen yavaş

    # ── Subdomain Enumeration ──────────────────────────────────────
    # Büyük hedeflerde (*.google.com gibi) 15-30 dk normal
    "subfinder":  1800,   # çok kaynak, -all flag ile daha uzun
    "amass":      2400,   # en yavaş tool — passive enum uzun sürer
    "assetfinder": 900,   # orta hız
    "sublist3r":  1200,   # birden fazla arama motoru
    "findomain":  900,    # hızlı ama büyük hedefte uzar

    # ── Host Validation ────────────────────────────────────────────
    # 1000+ subdomain → her biri test ediliyor
    "httpx":      1800,   # büyük listede 500+ host → 30 dk

    # ── URL Discovery ──────────────────────────────────────────────
    # Arşiv toolları (wayback/gau) hedef yaşına göre çok veri çeker
    "gau":        2700,   # 45 dk — eski/büyük hedeflerde milyonlarca URL
    "waybackurls": 2700,  # 45 dk — wayback arşivi çok büyük olabilir
    "katana":     3600,   # 60 dk — aktif crawler, d=5 ile çok sayfa
    "hakrawler":  1800,   # 30 dk — daha hızlı ama yine de uzayabilir
    "linkfinder": 300,    # her host için 5 dk limit
    "gospider":   2700,   # 45 dk — aktif crawler + sitemap + robots

    # ── Vulnerability / XSS ───────────────────────────────────────
    # Host sayısına ve template sayısına göre çok değişir
    "nuclei":     7200,   # 2 saat — büyük listede critical+high+medium uzun sürer
    "dalfox":     3600,   # 60 dk — reflection URL sayısına göre (her round için)
}

# ── Scale thresholds ─────────────────────────────────────────────────────────
# Bu eşikler subdomain/host sayısına göre davranışı otomatik ayarlar
LARGE_SUBS   = 5_000    # bu üstünde: gau/wayback sadece ana domain, httpx thread azalır
HUGE_SUBS    = 20_000   # bu üstünde: spinner kapatılır, katana/hakrawler host limiti düşer
MAX_GAU_SUBS = 500      # gau'ya gönderilecek max subdomain (daha fazlası timeout/0 sonuç)
MAX_KATANA_HOSTS = 200  # katana aktif crawler — büyük listede RAM patlatır
MAX_HAKRAWLER_HOSTS = 100

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
_PAT_PRIO   = re.compile(
    r'[?&](q|query|search|s|keyword|term|input|text|name|value|data|content|'
    r'msg|message|title|subject|url|uri|redirect|return|ref|callback|id|page|'
    r'p|n|num|next|item|type|mode|view|action|cmd|exec|run|code|lang|locale|'
    r'cat|category|tag|filter|sort|order|dir|nonce|token|key|hash|user|pass|'
    r'email|file|path)=', re.I)

# ── URL Categorisation (streaming) ────────────────────────────────────────────
def categorise_streaming(url_file, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cats    = ["params", "reflection", "forms", "admin", "login", "api", "sensitive", "other", "xss_targets"]
    handles = {c: (out_dir / f"{c}.txt").open("w", encoding="utf-8") for c in cats}
    seen    = {c: set() for c in cats}
    counts  = {c: 0 for c in cats}

    def _w(cat, url):
        if url not in seen[cat]:
            seen[cat].add(url)
            handles[cat].write(url + "\n")
            counts[cat] += 1

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
    finally:
        for h in handles.values():
            try: h.close()
            except: pass

    return counts

# ── run_cmd ───────────────────────────────────────────────────────────────────
def run_cmd(cmd, out_file=None, timeout=120, log=None, label="",
            silent=False, stream=False, retries=2, retry_delay=5):
    """
    Run shell command. Returns (success: bool, stdout: str).
    out_file: stdout written here (no shell redirect needed).
    stream:   live output (for nuclei/stream tools).
    retries:  how many times to retry on 0-line output (default=2, all tools).
    retry_delay: seconds between retries (default=5).
    """
    if _INT.hard():
        return False, ""

    _attempt = 0
    while True:
        _ok, _txt = _run_once(cmd, out_file=out_file, timeout=timeout,
                              log=log, label=label, silent=silent, stream=stream,
                              attempt=_attempt)
        if _INT.hard() or _INT.interrupted():
            return _ok, _txt

        lc = (_count_lines(out_file) if (out_file and Path(out_file).exists())
              else len([l for l in _txt.splitlines() if l.strip()]))

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
    label = label or cmd.split()[0]
    start = time.time()

    if not silent:
        sub(f"{label}...")

    # ── Stream mode ───────────────────────────────────────────────────────────
    if stream:
        lines = []; rc = -1; killed = False
        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=1, universal_newlines=True,
                env={**os.environ, "PYTHONUNBUFFERED": "1"}
            )
            for raw in iter(proc.stdout.readline, ""):
                if _INT.interrupted() or _INT.hard():
                    killed = True
                    try: proc.kill(); proc.wait(2)
                    except: pass
                    break
                line = strip_ansi(raw.rstrip("\n"))
                if line:
                    lines.append(line)
            else:
                proc.wait()
            rc = proc.returncode if not killed else -15
        except Exception as ex:
            lines.append(str(ex))

        elapsed = round(time.time() - start, 1)
        txt = "\n".join(lines)
        if out_file and txt.strip():
            Path(out_file).parent.mkdir(parents=True, exist_ok=True)
            Path(out_file).write_text(txt, encoding="utf-8", errors="replace")
        lc = _count_lines(out_file) if (out_file and Path(out_file).exists()) else len(lines)
        if log:
            log.info(f"[STREAM] {cmd} | rc={rc} | {elapsed}s | lines={lc}")
        if not silent:
            if killed:
                warn(f"{label} stopped ({elapsed}s) — {lc} lines")
            elif rc == 0:
                ok(f"{label} ({elapsed}s) — {lc:,} lines")
            else:
                warn(f"{label} exit {rc} ({elapsed}s) — {lc} lines")
        _INT.reset()
        return (not killed and rc == 0), txt

    # ── Normal mode ───────────────────────────────────────────────────────────
    proc_ref    = [None]
    stdout_buf  = [""]
    stderr_buf  = [""]
    timed_out   = [False]
    ctrl_killed = [False]

    def _worker():
        try:
            p = subprocess.Popen(cmd, shell=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc_ref[0] = p
            out, err_out = p.communicate()
            stdout_buf[0] = out.decode("utf-8", errors="replace")
            stderr_buf[0] = err_out.decode("utf-8", errors="replace")
        except Exception as ex:
            stderr_buf[0] = str(ex)

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
    txt     = stdout_buf[0]
    etxt    = stderr_buf[0]

    if out_file:
        Path(out_file).parent.mkdir(parents=True, exist_ok=True)
        if txt.strip():
            Path(out_file).write_text(txt, encoding="utf-8", errors="replace")

    lc = (_count_lines(out_file) if (out_file and Path(out_file).exists())
          else len([l for l in txt.splitlines() if l.strip()]))

    if log:
        log.info(f"CMD: {cmd} | rc={rc} | {elapsed}s | lines={lc}")
        if etxt.strip():
            log.debug(f"STDERR: {strip_ansi(etxt)[:400]}")

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


# ══════════════════════════════════════════════════════════════════════════════
class ReconPipeline:
    def __init__(self, target, cfg, resume=False, auto_nuclei=False, auto_xss=False,
                 single=False):
        self.target      = target.strip()
        self.cfg         = cfg
        self.ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.out         = BASE_DIR / "output" / f"{self.target}_{self.ts}"
        self.resume      = resume
        self.auto_nuclei = auto_nuclei
        self.auto_xss    = auto_xss
        self.single      = single          # ← YENİ: tek domain modu
        self.summary     = {}

        for d in ["01_recon", "02_subdomains", "03_alive", "04_urls",
                  "05_categorized", "06_nuclei", "07_xss", "checkpoints"]:
            (self.out / d).mkdir(parents=True, exist_ok=True)

        self.log = setup_logger(self.out / "pipeline.log")
        atexit.register(self._emergency_save)

    def _emergency_save(self):
        """atexit handler — sadece SUMMARY.json yazar. generate_report() run() finally'de çalışır."""
        try:
            sf = self.out / "SUMMARY.json"
            sf.write_text(
                json.dumps({"target": self.target, "stages": self.summary,
                            "note": "emergency_save", "timestamp": self.ts}, indent=2),
                encoding="utf-8"
            )
        except:
            pass

    def _cp(self, name):    return self.out / "checkpoints" / f"{name}.txt"
    def _cp_ok(self, name):
        p = self._cp(name)
        return self.resume and p.exists() and p.stat().st_size > 0

    def _cfg(self, *keys, default=None):
        cur = self.cfg
        for k in keys:
            if not isinstance(cur, dict):
                return default
            cur = cur.get(k, default)
            if cur is None:
                return default
        return cur

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

        run_cmd(
            f"whois {tgt} 2>/dev/null || whois -H {tgt} 2>/dev/null || true",
            out_file=d / "whois.txt", timeout=T["whois"],
            log=self.log, label="whois", retries=2, retry_delay=5
        )

        if tool_exists("whatweb"):
            run_cmd(
                f"whatweb {tgt} -a 3 --open-timeout=10 --read-timeout=30 "
                f"--log-verbose={d}/whatweb.txt",
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
                f"theHarvester -d {tgt} -b bing,duckduckgo,crtsh,dnsdumpster,hackertarget "
                f"-f {d}/theharvester",
                timeout=T["harvester"], log=self.log, label="theHarvester"
            )
        else:
            sub("theHarvester not found")

        if has_valid_api_key(self.cfg, "shodan") and tool_exists("shodan"):
            ok2, _ = run_cmd("shodan info", timeout=10, log=self.log,
                             label="shodan-check", silent=True, retries=0)
            if ok2:
                st = target_ip if target_ip else f"$(dig +short {tgt} | head -1)"
                run_cmd(f"shodan host {st}", out_file=d / "shodan.txt",
                        timeout=T["shodan"], log=self.log, label="shodan")
        else:
            sub("shodan not configured")

        self.summary["stage1"] = {"status": "done", "target_ip": target_ip or "unknown"}
        checkpoint(self._cp("stage1_done"), [tgt], "stage1")

    # ── Stage 2 ───────────────────────────────────────────────────────────────
    def stage2_subdomains(self):
        # ── SINGLE MODE: subdomain enumeration tamamen atlanır ────────────────
        if self.single:
            stage(2, "Subdomain Enumeration [SINGLE MODE — SKIPPED]")
            info(f"Single mode aktif — sadece hedef domain kullanılıyor: {self.target}")
            n = checkpoint(self._cp("stage2_subdomains"), [self.target], "subdomains-single")
            self.summary["stage2"] = {
                "status": "skipped",
                "reason": "single_mode",
                "count": n,
                "note": f"Only target domain used: {self.target}",
            }
            return

        # ── NORMAL MODE (değiştirilmedi) ──────────────────────────────────────
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
                    timeout=T["subfinder"], log=self.log, label="subfinder",
                    retries=2, retry_delay=5)
            out_files.append(f)
        else:
            sub("subfinder not found")

        if tool_exists("assetfinder"):
            f = d / "assetfinder.txt"
            run_cmd(f"assetfinder --subs-only {tgt}",
                    out_file=f, timeout=T["assetfinder"], log=self.log, label="assetfinder",
                    retries=2, retry_delay=5)
            out_files.append(f)
        else:
            sub("assetfinder not found")

        if tool_exists("amass"):
            f = d / "amass.txt"
            run_cmd(f"amass enum -passive -timeout {max(1, T['amass']//60)} -d {tgt} -o {f}",
                    timeout=T["amass"] + 30, log=self.log, label="amass",
                    retries=1, retry_delay=10)
            out_files.append(f)
        else:
            sub("amass not found")

        f = d / "sublist3r.txt"
        sl3r = next((p for p in [Path("/opt/Sublist3r/sublist3r.py")] if p.exists()), None)
        if tool_exists("sublist3r"):
            run_cmd(f"sublist3r -d {tgt} -o {f}",
                    timeout=T["sublist3r"], log=self.log, label="sublist3r")
            out_files.append(f)
        elif sl3r:
            py = str(VENV_PY) if VENV_PY.exists() else "python3"
            run_cmd(f"{py} {sl3r} -d {tgt} -o {f}",
                    timeout=T["sublist3r"], log=self.log, label="sublist3r")
            out_files.append(f)
        else:
            sub("sublist3r not found")

        if tool_exists("findomain"):
            f = d / "findomain.txt"
            run_cmd(f"findomain -t {tgt} -q",
                    out_file=f, timeout=T["findomain"], log=self.log, label="findomain",
                    retries=2, retry_delay=5)
            out_files.append(f)
        else:
            sub("findomain not found")

        raw_f  = d / "all_raw.txt"
        dom_re = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,61}[a-zA-Z0-9]?$')
        def _ok(l): return bool(dom_re.match(l) and tgt in l)
        dedup_files(out_files, raw_f, filter_fn=_ok)

        lines = [l.strip() for l in raw_f.read_text(errors="ignore").splitlines() if l.strip()]
        if tgt not in lines:
            lines.insert(0, tgt)
            write_lines(raw_f, lines)

        if tool_exists("dnsx"):
            sub("dnsx DNS verification...")
            dnsx_f = d / "dnsx_verified.txt"
            run_cmd(f"dnsx -l {raw_f} -silent -a -resp -o {dnsx_f}",
                    timeout=180, log=self.log, label="dnsx", retries=0)
            if dnsx_f.exists() and dnsx_f.stat().st_size > 0:
                verified = set()
                with dnsx_f.open() as fh:
                    for ln in fh:
                        host = strip_ansi(ln.strip()).split()[0].rstrip(".")
                        if host and not re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                            verified.add(host)
                if verified:
                    all_before = [l.strip() for l in raw_f.read_text(errors="ignore").splitlines() if l.strip()]
                    not_verified = [h for h in all_before if h not in verified]
                    write_lines(raw_f, sorted(verified) + not_verified)

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

        sub_count = _count_lines(sub_file)

        # Subdomain sayısına göre thread ve davranış ayarla
        if sub_count >= HUGE_SUBS:
            global _NO_SPINNER
            _NO_SPINNER = True
            threads = min(int(self._cfg("settings", "threads", default=50)), 50)
            warn(f"{sub_count:,} subdomain — spinner kapatıldı, thread {threads}'e düşürüldü")
        elif sub_count >= LARGE_SUBS:
            threads = min(int(self._cfg("settings", "threads", default=50)), 75)
            info(f"{sub_count:,} subdomain — thread {threads}'e ayarlandı")
        else:
            threads = min(int(self._cfg("settings", "threads", default=50)), 100)

        info(f"httpx: {sub_count:,} host → {threads} thread")
        json_out = d / "httpx_full.json"

        run_cmd(
            f"httpx -l {sub_file} -no-color "
            f"-threads {threads} -timeout 15 -retries 1 -follow-redirects "
            f"-status-code -title -tech-detect -ip -server -content-length "
            f"-ports 80,443,8080,8443 "
            f"-random-agent "
            f"-json -o {json_out}",
            timeout=T["httpx"], log=self.log, label="httpx",
            retries=1, retry_delay=5
        )

        alive_urls = []
        host_data  = []

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
                    ip_raw = rec.get("a") or rec.get("ip") or ""
                    if isinstance(ip_raw, list):
                        ip_raw = ip_raw[0] if ip_raw else ""
                    tech_raw = rec.get("tech") or rec.get("technologies") or []
                    tech = ", ".join(str(t) for t in (tech_raw[:5] if isinstance(tech_raw, list) else [str(tech_raw)]))
                    size = rec.get("content_length") or rec.get("length") or ""
                    try:
                        size = f"{int(size):,}" if size else ""
                    except:
                        size = str(size)
                    host_data.append({
                        "url":    url,
                        "status": str(rec.get("status_code") or ""),
                        "title":  (rec.get("title") or "")[:80],
                        "ip":     str(ip_raw)[:40],
                        "tech":   tech[:100],
                        "size":   size,
                        "server": (rec.get("webserver") or rec.get("server") or "")[:60],
                    })

        if not alive_urls:
            warn("httpx JSON empty — plain fallback...")
            plain_out = d / "httpx_plain.txt"
            _, plain_txt = run_cmd(
                f"httpx -l {sub_file} -silent -no-color "
                f"-threads {threads} -timeout 10 -retries 2",
                out_file=plain_out, timeout=T["httpx"], log=self.log, label="httpx-plain", retries=0
            )
            for src in [plain_txt,
                        (plain_out.read_text(errors="replace") if plain_out.exists() else "")]:
                for line in src.splitlines():
                    line = strip_ansi(line.strip())
                    if line.startswith("http"):
                        u = line.split()[0]
                        alive_urls.append(u)
                        host_data.append({"url": u, "status": "", "title": "",
                                          "ip": "", "tech": "", "size": "", "server": ""})

        if not alive_urls:
            warn("httpx no response — using subdomains")
            subs = [l.strip() for l in sub_file.read_text(errors="ignore").splitlines() if l.strip()]
            for s in subs:
                u = f"https://{s}" if not s.startswith("http") else s
                alive_urls.append(u)
                host_data.append({"url": u, "status": "", "title": "",
                                  "ip": "", "tech": "", "size": "", "server": ""})

        alive_urls = sorted(set(alive_urls))
        host_data  = list({h["url"]: h for h in host_data}.values())

        (d / "hosts_detail.json").write_text(
            json.dumps(host_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        n = checkpoint(self._cp("stage3_alive"), alive_urls, "alive-hosts")
        info(f"Alive hosts: {n:,}")
        self.summary["stage3"] = {"status": "done", "count": n}

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
                if not l:
                    continue
                alive_hosts.append(l if l.startswith("http") else f"https://{l}")

        if not alive_hosts:
            alive_hosts = [f"https://{s}" if not s.startswith("http") else s for s in all_subs]

        tgt          = self.target
        url_files    = []
        sub_count_s4 = len(all_subs)

        # ── Ölçek modu — kullanıcıya göster ──────────────────────────────────
        if sub_count_s4 >= HUGE_SUBS:
            global _NO_SPINNER
            _NO_SPINNER = True
            print(f"\n  {C.RED}⚡ HUGE MODE{C.RESET} {C.DIM}({sub_count_s4:,} subs){C.RESET} "
                  f"— gau/wayback: ana domain only, katana: top {MAX_KATANA_HOSTS}, spinner: kapalı")
        elif sub_count_s4 >= LARGE_SUBS:
            print(f"\n  {C.YELLOW}⚡ LARGE MODE{C.RESET} {C.DIM}({sub_count_s4:,} subs){C.RESET} "
                  f"— gau/wayback: top {MAX_GAU_SUBS}, katana: top {MAX_KATANA_HOSTS}")
        else:
            print(f"\n  {C.GREEN}✓ NORMAL MODE{C.RESET} {C.DIM}({sub_count_s4:,} subs){C.RESET} "
                  f"— tüm subdomain'ler işlenecek")

        # ── gau — adaptive: büyük listede sadece ana domain + top alive hosts ──
        if tool_exists("gau"):
            f_gau    = d / "gau.txt"
            gau_help = _help_text("gau")
            is_v2    = "--subs" in gau_help or "--blacklist" in gau_help
            gau_in   = d / "gau_input.txt"

            if sub_count_s4 > MAX_GAU_SUBS:
                # Büyük listede: sadece ana domain + alive host'lardan ilk N tanesi
                # Tüm subdomainleri gau'ya vermek → timeout + 0 sonuç
                alive_sample = alive_hosts[:min(50, len(alive_hosts))]
                gau_targets  = [tgt] + alive_sample
                warn(f"gau: {sub_count_s4:,} subdomain çok fazla → "
                     f"ana domain + {len(alive_sample)} alive host kullanılıyor")
                write_lines(gau_in, gau_targets)
            else:
                write_lines(gau_in, all_subs)

            blacklist = "ttf,woff,svg,png,jpg,jpeg,gif,ico,css,eot,woff2,otf,mp4,mp3,avi,zip,tar,gz"
            if is_v2:
                gau_cmd = (f"cat {gau_in} | gau --providers wayback,commoncrawl,otx,urlscan "
                           f"--subs --threads 5 --retries 2 --timeout 45 "
                           f"--blacklist {blacklist}")
            else:
                gau_cmd = (f"cat {gau_in} | gau -subs -threads 5 -retries 2 "
                           f"-b {blacklist}")
            run_cmd(gau_cmd, out_file=f_gau, timeout=T["gau"], log=self.log, label="gau",
                    stream=True, retries=0)
            url_files.append(f_gau)
        else:
            sub("gau not found")

        # ── waybackurls — adaptive: büyük listede sınırla ───────────────────
        if tool_exists("waybackurls"):
            f_wb  = d / "waybackurls.txt"
            wb_in = d / "wayback_input.txt"
            if sub_count_s4 > MAX_GAU_SUBS:
                wb_targets = [tgt] + alive_hosts[:min(30, len(alive_hosts))]
                warn(f"waybackurls: {sub_count_s4:,} subdomain → ana domain + {len(wb_targets)-1} alive host")
                write_lines(wb_in, wb_targets)
            else:
                write_lines(wb_in, all_subs)
            run_cmd(f"cat {wb_in} | waybackurls",
                    out_file=f_wb, timeout=T["waybackurls"], log=self.log, label="waybackurls",
                    stream=True, retries=0)
            url_files.append(f_wb)
        else:
            sub("waybackurls not found")

        # ── katana — büyük alive listesinde host sayısı sınırlanır ─────────
        if tool_exists("katana") and alive_hosts:
            f_kat = d / "katana.txt"
            kin   = d / "katana_input.txt"
            katana_hosts = alive_hosts[:MAX_KATANA_HOSTS]
            if len(alive_hosts) > MAX_KATANA_HOSTS:
                warn(f"katana: {len(alive_hosts):,} alive host → ilk {MAX_KATANA_HOSTS} kullanılıyor (RAM koruması)")
            write_lines(kin, katana_hosts)
            kh     = _help_text("katana")
            # Büyük listede depth ve concurrency düşür
            depth  = 3 if len(alive_hosts) > LARGE_SUBS else 5
            concur = 5 if len(alive_hosts) > LARGE_SUBS else 10
            flags  = " ".join(filter(None, [
                "-silent",
                "-jc"     if "-jc"     in kh else "",
                "-kf all" if "-kf"     in kh else "",
                "-fx"     if "-fx"     in kh else "",
                "-retry 1" if "-retry" in kh else "",
                f"-concurrency {concur}" if "-concurrency" in kh else "",
                "-timeout 10" if "-timeout" in kh else "",
            ]))
            run_cmd(f"katana -list {kin} -d {depth} {flags} -o {f_kat}",
                    timeout=T["katana"], log=self.log, label=f"katana (d={depth})", retries=1, retry_delay=8)
            if not f_kat.exists() or f_kat.stat().st_size == 0:
                run_cmd(f"katana -list {kin} -d 2 -silent -o {f_kat}",
                        timeout=T["katana"], log=self.log, label="katana-min", retries=0)
            url_files.append(f_kat)
        else:
            sub("katana not found")

        # ── hakrawler — büyük alive listesinde host sayısı sınırlanır ──────
        if tool_exists("hakrawler") and alive_hosts:
            f_hak = d / "hakrawler.txt"
            hin   = d / "hakrawler_input.txt"
            hak_hosts = alive_hosts[:MAX_HAKRAWLER_HOSTS]
            if len(alive_hosts) > MAX_HAKRAWLER_HOSTS:
                warn(f"hakrawler: {len(alive_hosts):,} host → ilk {MAX_HAKRAWLER_HOSTS} kullanılıyor")
            write_lines(hin, hak_hosts)
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
            # clean non-http lines
            if f_hak.exists():
                clean = d / "hakrawler_clean.txt"
                with f_hak.open() as fi, clean.open("w") as fo:
                    seen_hak = set()
                    for ln in fi:
                        u = strip_ansi(ln.strip())
                        if u.startswith("http") and u not in seen_hak:
                            seen_hak.add(u)
                            fo.write(u + "\n")
                url_files.append(clean)
        else:
            sub("hakrawler not found")

        # ── gospider ─────────────────────────────────────────────────────────
        if tool_exists("gospider") and alive_hosts:
            f_gs  = d / "gospider_raw.txt"
            f_gsu = d / "gospider_urls.txt"
            gs_in = d / "gospider_input.txt"
            write_lines(gs_in, alive_hosts[:30])
            gs_h = _help_text("gospider")
            extra = " ".join(filter(None, [
                "--sitemap"      if "--sitemap"      in gs_h else "",
                "--robots"       if "--robots"       in gs_h else "",
                "--other-source" if "--other-source" in gs_h else "",
            ]))
            run_cmd(f"gospider -S {gs_in} -d 3 -c 5 -t 5 --include-subs {extra} --quiet",
                    out_file=f_gs, timeout=T["gospider"], log=self.log, label="gospider")
            if f_gs.exists() and f_gs.stat().st_size > 0:
                with f_gs.open() as fi, f_gsu.open("w") as fo:
                    for ln in fi:
                        m = re.search(r'(https?://[^\s\[\]"\']+)', ln)
                        if m:
                            u = m.group(1).rstrip(".,;")
                            if u.startswith("http"):
                                fo.write(u + "\n")
                url_files.append(f_gsu)
        else:
            sub("gospider not found (optional)")

        # ── linkfinder ────────────────────────────────────────────────────────
        lf = next((p for p in [
            Path("/opt/LinkFinder/linkfinder.py"),
            Path(os.path.expanduser("~/LinkFinder/linkfinder.py")),
        ] if p.exists()), None)
        if (lf or tool_exists("linkfinder")) and alive_hosts:
            lf_out = d / "linkfinder.txt"
            py     = str(VENV_PY) if VENV_PY.exists() else "python3"
            lf_res = []
            for host in alive_hosts[:10]:
                cmd = (f"{py} {lf} -i {host} -o cli" if lf else f"linkfinder -i {host} -o cli")
                _, out_t = run_cmd(cmd, timeout=T["linkfinder"], log=self.log,
                                   label=f"lf:{host[:30]}", silent=True)
                lf_res.extend(ln.strip() for ln in out_t.splitlines()
                              if strip_ansi(ln.strip()).startswith("http"))
            if lf_res:
                write_lines(lf_out, sorted(set(lf_res)))
                url_files.append(lf_out)
        else:
            sub("linkfinder not found (optional)")

        # ── Dedup all ─────────────────────────────────────────────────────────
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

        n = dedup_files(url_files, raw_all, filter_fn=_url_ok)
        if n == 0:
            write_lines(raw_all, alive_hosts)
            n = _count_lines(raw_all)

        shutil.copy2(raw_all, self._cp("stage4_urls"))
        info(f"Total unique URLs: {n:,}")
        self.summary["stage4"] = {"status": "done", "count": n}

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

        refl_src = d / "reflection.txt"
        xss_src  = d / "xss_targets.txt"
        if refl_src.exists():
            shutil.copy2(refl_src, self._cp("stage5_reflection"))
        if xss_src.exists():
            shutil.copy2(xss_src, self._cp("stage5_xss_targets"))

        # Priority reflection
        pr_count = 0
        pr_out   = d / "reflection_priority.txt"
        if refl_src.exists():
            with refl_src.open() as fi, pr_out.open("w") as fo:
                for ln in fi:
                    ln = ln.strip()
                    try:
                        qs = urlparse(ln).query
                        if qs and _PAT_PRIO.search("?" + qs):
                            fo.write(ln + "\n")
                            pr_count += 1
                    except:
                        pass

        print(f"\n  {'Category':<20} {'Count':>8}")
        print(f"  {'─'*20} {'─'*8}")
        for cat, mark in [("sensitive", "⚠"), ("admin", "⚠"), ("reflection", "⚠"),
                          ("params", "~"), ("login", "~"), ("api", " "),
                          ("forms", " "), ("other", " ")]:
            c = counts.get(cat, 0)
            col = C.RED if mark == "⚠" else (C.YELLOW if mark == "~" else C.DIM)
            print(f"  {col}{mark}{C.RESET} {cat:<18} {c:>8,}")

        if pr_count:
            info(f"Priority reflection URLs: {pr_count:,}")

        ok(f"Categorisation complete — {sum(counts.values()):,} URLs processed")
        self.summary["stage5"] = {
            "status": "done",
            "categories": {cat: {"count": cnt, "file": str(d / f"{cat}.txt")}
                           for cat, cnt in counts.items()},
        }

    # ── Stage 6 — Nuclei ──────────────────────────────────────────────────────
    def stage6_nuclei(self):
        if _INT.hard():
            return

        if not self.auto_nuclei:
            cats = self.summary.get("stage5", {}).get("categories", {}) or {}
            def cc(n): return (cats.get(n, {}) or {}).get("count", 0)
            print(f"\n{C.CYAN}{'─'*60}{C.RESET}")
            print(f"  Alive: {self.summary.get('stage3', {}).get('count', '?')}  "
                  f"URLs: {self.summary.get('stage4', {}).get('count', '?')}  "
                  f"Sensitive: {cc('sensitive')}  Admin: {cc('admin')}  Reflection: {cc('reflection')}")
            print(f"{C.CYAN}{'─'*60}{C.RESET}")
            if not ask_yes_no("Run Nuclei vulnerability scan? (CVE, misconfig, secrets)"):
                warn("Nuclei skipped")
                self.summary["stage6"] = {"status": "skipped", "reason": "user_choice"}
                return
        else:
            info("Nuclei starting (auto mode)")

        if not tool_exists("nuclei"):
            warn("nuclei not found")
            self.summary["stage6"] = {"status": "skipped", "reason": "not_found"}
            return

        stage(6, "Nuclei Vulnerability Scanning")
        d          = self.out / "06_nuclei"
        alive_file = self._cp("stage3_alive")

        if not alive_file.exists() or alive_file.stat().st_size == 0:
            warn("No targets for nuclei")
            self.summary["stage6"] = {"status": "skipped", "reason": "no_targets"}
            return

        threads  = min(int(self._cfg("settings", "threads", default=10)), 20)
        severity = self._cfg("tools", "nuclei_severity", default="critical,high,medium")
        rate     = min(int(self._cfg("settings", "rate_limit", default=5)), 20)

        run_cmd("nuclei -update-templates -silent", timeout=60,
                log=self.log, label="nuclei-update", retries=0)

        nout  = d / "nuclei_results.txt"
        njson = d / "nuclei_results.json"

        run_cmd(
            f"nuclei -l {alive_file} -s {severity} -c {threads} -rl {rate} "
            f"-o {nout} -json-export {njson} -no-color -silent",
            timeout=T["nuclei"], log=self.log, label="nuclei", stream=True, retries=0
        )

        findings = _count_lines(nout)
        if findings > 0:
            sev_c = {}
            with nout.open(errors="ignore") as fh:
                for ln in fh:
                    m = re.search(r'\[(critical|high|medium|low|info)\]', ln, re.I)
                    if m:
                        s = m.group(1).lower()
                        sev_c[s] = sev_c.get(s, 0) + 1
            sev_cols = {"critical": C.RED, "high": C.RED, "medium": C.YELLOW, "low": C.BLUE, "info": C.DIM}
            for sv in ["critical", "high", "medium", "low", "info"]:
                if sv in sev_c:
                    print(f"    {sev_cols[sv]}{sv.upper():<12}{C.RESET} {sev_c[sv]}")

        checkpoint(self._cp("stage6_done"), [f"findings:{findings}"], "nuclei")
        info(f"Nuclei findings: {findings}")
        self.summary["stage6"] = {"status": "done", "findings": findings, "file": str(nout)}

    # ── Stage 7 — XSS (Dalfox, standard pipe mode) ───────────────────────────
    def stage7_xss(self):
        if _INT.hard():
            return

        refl_file  = self._cp("stage5_reflection")
        refl_count = _count_lines(refl_file)

        if not self.auto_xss:
            if not ask_yes_no(f"Run Dalfox XSS testing? ({refl_count:,} reflection URLs)"):
                warn("XSS skipped")
                self.summary["stage7"] = {"status": "skipped", "reason": "user_choice"}
                return
        else:
            info(f"Dalfox starting — {refl_count:,} URLs (auto mode)")

        if not tool_exists("dalfox"):
            warn("dalfox not found")
            self.summary["stage7"] = {"status": "skipped", "reason": "not_found"}
            return

        if refl_count == 0:
            warn("No reflection URLs — skipping XSS")
            self.summary["stage7"] = {"status": "skipped", "reason": "no_reflection_urls"}
            return

        stage(7, "XSS Testing — Dalfox")
        d = self.out / "07_xss"
        d.mkdir(parents=True, exist_ok=True)

        rate    = min(int(self._cfg("settings", "rate_limit", default=5)), 10)
        workers = min(int(self._cfg("settings", "threads", default=10)), 30)
        timeout = int(self._cfg("settings", "timeout", default=10))
        delay   = max(1, int(1000 / max(rate, 1)))

        # ── Dalfox standard pipe mode (clean, no wrappers) ───────────────────
        # Round 1: Standard XSS detection
        out_r1 = d / "dalfox_r1.txt"
        run_cmd(
            f"cat {refl_file} | dalfox pipe "
            f"--skip-bav --no-color "
            f"--delay {delay} --worker {workers} --timeout {timeout} "
            f"--format plain --output {out_r1}",
            timeout=T["dalfox"], log=self.log, label="dalfox-r1", retries=0
        )

        # Round 2: DOM XSS
        out_r2 = d / "dalfox_r2.txt"
        run_cmd(
            f"cat {refl_file} | dalfox pipe "
            f"--skip-bav --no-color --deep-domxss "
            f"--delay {delay} --worker {workers} --timeout {timeout} "
            f"--format plain --output {out_r2}",
            timeout=T["dalfox"], log=self.log, label="dalfox-r2 (DOM)", retries=0
        )

        # Round 3: Follow redirects
        out_r3 = d / "dalfox_r3.txt"
        run_cmd(
            f"cat {refl_file} | dalfox pipe "
            f"--skip-bav --no-color --follow-redirects "
            f"--delay {delay} --worker {workers} --timeout {timeout} "
            f"--format plain --output {out_r3}",
            timeout=T["dalfox"], log=self.log, label="dalfox-r3 (redirects)", retries=0
        )

        # Merge all findings
        all_xss = d / "dalfox_all.txt"
        xss_count = dedup_files(
            [f for f in [out_r1, out_r2, out_r3] if f.exists()],
            all_xss
        )
        if all_xss.exists():
            shutil.copy2(all_xss, self._cp("stage7_xss"))

        if xss_count:
            print(f"\n  {C.RED}{C.BOLD}XSS FINDINGS: {xss_count}{C.RESET}")
            with all_xss.open(errors="ignore") as fh:
                for i, ln in enumerate(fh):
                    if i >= 10:
                        break
                    print(f"  {C.RED}✗{C.RESET} {ln.strip()}")
            if xss_count > 10:
                print(f"  {C.DIM}... and {xss_count - 10} more → {all_xss}{C.RESET}")
        else:
            ok("No XSS findings")

        self.summary["stage7"] = {"status": "done", "total_findings": xss_count}

    # ── Report ────────────────────────────────────────────────────────────────
    def generate_report(self):
        # Çift çalışmayı önle (run() finally + atexit aynı anda tetiklenebilir)
        if getattr(self, "_report_written", False):
            return
        self._report_written = True

        stage("✦", "Generating Report")

        sf = self.out / "SUMMARY.json"
        sf.write_text(
            json.dumps({"target": self.target, "timestamp": self.ts,
                        "stages": self.summary, "output_dir": str(self.out)}, indent=2),
            encoding="utf-8"
        )

        report_path = None

        # ── report_builder.py — script ile aynı klasörde ara ─────────────────
        # BASE_DIR her zaman sys.path'te olmayabilir, manuel ekle
        import sys as _sys
        _rb_dirs = [BASE_DIR, Path(__file__).parent, Path.cwd()]
        for _d in _rb_dirs:
            if str(_d) not in _sys.path:
                _sys.path.insert(0, str(_d))

        try:
            # Önce cache'i temizle — eski import takılmasın
            if "report_builder" in _sys.modules:
                del _sys.modules["report_builder"]
            from report_builder import build_report
            report_path = build_report(self.out, self.target, self.summary)
            ok(f"Report: {report_path}")
        except ImportError:
            warn("report_builder.py bulunamadı — built-in HTML rapor kullanılıyor")
            try:
                report_path = self._build_html_report()
                ok(f"Report (built-in): {report_path}")
            except Exception as e:
                warn(f"Built-in report error: {e}")
                self.log.exception("built-in report error")
        except Exception as e:
            warn(f"report_builder error: {e}")
            self.log.exception("report_builder error")
            # Hata olsa bile built-in ile dene
            try:
                report_path = self._build_html_report()
                ok(f"Report (built-in fallback): {report_path}")
            except:
                pass

        if report_path:
            try:
                import webbrowser
                webbrowser.open(f"file://{report_path}")
            except:
                pass

        print(f"\n{C.CYAN}{C.BOLD}{'═'*60}\n  SCAN COMPLETE — {self.target}\n{'═'*60}{C.RESET}")
        for key, lbl in [
            ("stage1", "Recon"),     ("stage2", "Subdomains"), ("stage3", "Alive Hosts"),
            ("stage4", "URLs"),       ("stage5", "Categorised"),
            ("stage6", "Nuclei"),    ("stage7", "XSS (Dalfox)"),
        ]:
            s   = self.summary.get(key, {})
            if not isinstance(s, dict): s = {}
            st  = s.get("status", "not run")
            c   = s.get("count", s.get("findings", s.get("total_findings", "")))
            r   = s.get("reason", "")
            cs  = f" — {c:,}" if isinstance(c, int) else (f" — {c}" if c != "" else "")
            rs  = f" ({r})" if r else ""
            col = C.GREEN if st == "done" else (C.YELLOW if st == "skipped" else C.RED)
            ico = "✓" if st == "done" else ("⚠" if st == "skipped" else "✗")
            print(f"  {col}{ico}{C.RESET}  {lbl:<18}{cs}{C.DIM}{rs}{C.RESET}")

        print(f"\n  {C.BLUE}Output : {self.out}{C.RESET}")
        if report_path:
            print(f"  {C.BLUE}Report : {report_path}{C.RESET}")
        print(f"  {C.BLUE}Log    : {self.out}/pipeline.log{C.RESET}\n")


    # ── Built-in HTML Report ──────────────────────────────────────────────────
    def _build_html_report(self):
        """report_builder.py olmadan da çalışan built-in HTML raporu."""
        ts_human = datetime.strptime(self.ts, "%Y%m%d_%H%M%S").strftime("%d %b %Y %H:%M")

        # ── Veri topla ────────────────────────────────────────────────────────
        def _read(rel):
            p = self.out / rel
            return p.read_text(errors="ignore") if p.exists() else ""

        def _count(rel):
            return _count_lines(self.out / rel)

        alive_count = self.summary.get("stage3", {}).get("count", 0)
        url_count   = self.summary.get("stage4", {}).get("count", 0)
        cats        = self.summary.get("stage5", {}).get("categories", {}) or {}
        nuc_count   = self.summary.get("stage6", {}).get("findings", 0)
        xss_count   = self.summary.get("stage7", {}).get("total_findings", 0)

        # Nmap özeti
        nmap_raw  = _read("01_recon/nmap.txt")
        nmap_ports = []
        for ln in nmap_raw.splitlines():
            if re.match(r"^\d+/(tcp|udp)\s+open", ln):
                nmap_ports.append(ln.strip())
        nmap_html = "\n".join(f"<div class='port'>{p}</div>" for p in nmap_ports[:30]) or "<div class='dim'>Port taraması bulunamadı</div>"

        # Nuclei bulgular
        nuc_raw = _read("06_nuclei/nuclei_results.txt")
        nuc_rows = []
        for ln in nuc_raw.splitlines()[:50]:
            ln = ln.strip()
            if not ln: continue
            m_sev = re.search(r'\[(critical|high|medium|low|info)\]', ln, re.I)
            sev   = m_sev.group(1).lower() if m_sev else "info"
            nuc_rows.append(f"<tr class='sev-{sev}'><td class='sev-badge {sev}'>{sev.upper()}</td><td>{ln[:200]}</td></tr>")
        nuc_html = "\n".join(nuc_rows) if nuc_rows else "<tr><td colspan='2' class='dim'>Bulgu yok</td></tr>"

        # XSS bulgular
        xss_raw  = _read("07_xss/dalfox_all.txt")
        xss_rows = []
        for ln in xss_raw.splitlines()[:30]:
            ln = ln.strip()
            if ln:
                xss_rows.append(f"<tr><td class='sev-badge high'>XSS</td><td>{ln[:200]}</td></tr>")
        xss_html = "\n".join(xss_rows) if xss_rows else "<tr><td colspan='2' class='dim'>Bulgu yok</td></tr>"

        # Alive hosts tablosu
        hosts_json = self.out / "03_alive" / "hosts_detail.json"
        hosts_rows = []
        if hosts_json.exists():
            try:
                hosts = json.loads(hosts_json.read_text(errors="ignore"))
                for h in hosts[:100]:
                    sc = h.get("status",""); title = h.get("title",""); tech = h.get("tech",""); srv = h.get("server","")
                    col = "green" if sc.startswith("2") else ("yellow" if sc.startswith("3") else ("red" if sc.startswith(("4","5")) else "dim"))
                    hosts_rows.append(
                        f"<tr><td><a href='{h['url']}' target='_blank'>{h['url'][:60]}</a></td>"
                        f"<td class='{col}'>{sc}</td><td>{title[:40]}</td>"
                        f"<td class='dim'>{tech[:40]}</td><td class='dim'>{srv[:30]}</td></tr>"
                    )
            except: pass
        hosts_html = "\n".join(hosts_rows) if hosts_rows else "<tr><td colspan='5' class='dim'>Veri yok</td></tr>"

        # Kategori kartları
        cat_cards = ""
        cat_meta = [
            ("sensitive","⚠","red"),("admin","⚠","red"),("reflection","⚠","orange"),
            ("params","~","yellow"),("login","~","yellow"),("api"," ","blue"),
            ("forms"," ","blue"),("other"," ","dim"),
        ]
        for cat, icon, col in cat_meta:
            cnt = (cats.get(cat) or {}).get("count", 0)
            cat_cards += f"<div class='cat-card {col}'><div class='cat-icon'>{icon}</div><div class='cat-name'>{cat}</div><div class='cat-count'>{cnt:,}</div></div>"

        # Stage özeti
        stage_rows = ""
        for key, lbl in [("stage1","Recon"),("stage2","Subdomains"),("stage3","Alive Hosts"),
                         ("stage4","URLs"),("stage5","Categorised"),("stage6","Nuclei"),("stage7","XSS (Dalfox)")]:
            s  = self.summary.get(key, {}) or {}
            st = s.get("status","not run")
            c  = s.get("count", s.get("findings", s.get("total_findings","")))
            r  = s.get("reason","")
            cs = f"{c:,}" if isinstance(c,int) else (str(c) if c != "" else "—")
            rs = f"<span class='dim'>({r})</span>" if r else ""
            ico = "✓" if st=="done" else ("⚠" if st=="skipped" else "✗")
            col = "green" if st=="done" else ("yellow" if st=="skipped" else "red")
            stage_rows += f"<tr><td class='{col}'>{ico} {lbl}</td><td>{cs}</td><td>{rs}</td></tr>"

        # Severity sayımı
        sev_counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
        for ln in nuc_raw.splitlines():
            m = re.search(r'\[(critical|high|medium|low|info)\]', ln, re.I)
            if m: sev_counts[m.group(1).lower()] += 1

        html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconX Report — {self.target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0d1117;color:#e6edf3;font-family:'Courier New',monospace;font-size:13px;line-height:1.6}}
a{{color:#58a6ff;text-decoration:none}}a:hover{{text-decoration:underline}}
.wrap{{max-width:1200px;margin:0 auto;padding:20px}}
h1{{font-size:22px;color:#58a6ff;margin-bottom:4px}}
h2{{font-size:15px;color:#8b949e;border-bottom:1px solid #21262d;padding-bottom:6px;margin:28px 0 14px}}
.header{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px 24px;margin-bottom:24px;display:flex;justify-content:space-between;align-items:center}}
.header-meta{{color:#8b949e;font-size:12px}}
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}}
.stat{{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:14px 16px;text-align:center}}
.stat .num{{font-size:26px;font-weight:bold;color:#58a6ff}}
.stat.red .num{{color:#f85149}}
.stat.orange .num{{color:#d29922}}
.stat.green .num{{color:#3fb950}}
.stat .lbl{{color:#8b949e;font-size:11px;margin-top:2px}}
.cat-grid{{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:24px}}
.cat-card{{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:10px 14px;min-width:110px;text-align:center}}
.cat-card.red{{border-color:#f85149;color:#f85149}}
.cat-card.orange{{border-color:#d29922;color:#d29922}}
.cat-card.yellow{{border-color:#e3b341;color:#e3b341}}
.cat-card.blue{{border-color:#58a6ff;color:#58a6ff}}
.cat-card.dim{{border-color:#30363d;color:#8b949e}}
.cat-icon{{font-size:18px}}
.cat-name{{font-size:11px;margin:2px 0}}
.cat-count{{font-size:20px;font-weight:bold}}
table{{width:100%;border-collapse:collapse;margin-bottom:24px;background:#161b22;border-radius:6px;overflow:hidden}}
th{{background:#21262d;color:#8b949e;padding:8px 12px;text-align:left;font-size:11px;text-transform:uppercase}}
td{{padding:7px 12px;border-bottom:1px solid #21262d;font-size:12px;word-break:break-all}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#1c2128}}
.sev-badge{{border-radius:4px;padding:2px 7px;font-size:10px;font-weight:bold;white-space:nowrap}}
.critical{{background:#4d0000;color:#f85149}}
.high{{background:#3d1700;color:#f0883e}}
.medium{{background:#2d2000;color:#d29922}}
.low{{background:#001d3d;color:#58a6ff}}
.info{{background:#1c2128;color:#8b949e}}
.green{{color:#3fb950}}.red{{color:#f85149}}.yellow{{color:#d29922}}.orange{{color:#f0883e}}.blue{{color:#58a6ff}}.dim{{color:#8b949e}}
.port{{font-family:monospace;color:#3fb950;font-size:12px;padding:2px 0}}
.sev-row{{display:flex;gap:16px;margin-bottom:20px}}
.sev-item{{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:10px 18px;text-align:center}}
.sev-item .n{{font-size:22px;font-weight:bold}}
.footer{{color:#8b949e;font-size:11px;text-align:center;margin-top:30px;padding-top:16px;border-top:1px solid #21262d}}
</style>
</head>
<body>
<div class="wrap">

<div class="header">
  <div>
    <h1>🔍 ReconX Report</h1>
    <div style="color:#58a6ff;font-size:16px;font-weight:bold;margin-top:4px">{self.target}</div>
  </div>
  <div class="header-meta">
    <div>{ts_human}</div>
    <div style="margin-top:4px">ReconX Sequential Scanner v5.1</div>
  </div>
</div>

<div class="stat-grid">
  <div class="stat {'red' if nuc_count>0 else 'green'}"><div class="num">{nuc_count}</div><div class="lbl">Nuclei Findings</div></div>
  <div class="stat {'red' if xss_count>0 else 'green'}"><div class="num">{xss_count}</div><div class="lbl">XSS Findings</div></div>
  <div class="stat"><div class="num">{alive_count:,}</div><div class="lbl">Alive Hosts</div></div>
  <div class="stat"><div class="num">{url_count:,}</div><div class="lbl">URLs Discovered</div></div>
  <div class="stat orange"><div class="num">{(cats.get('sensitive') or {{}}).get('count',0):,}</div><div class="lbl">Sensitive URLs</div></div>
  <div class="stat orange"><div class="num">{(cats.get('reflection') or {{}}).get('count',0):,}</div><div class="lbl">Reflection URLs</div></div>
</div>

<h2>📊 Scan Summary</h2>
<table>
<thead><tr><th>Stage</th><th>Count</th><th>Note</th></tr></thead>
<tbody>{stage_rows}</tbody>
</table>

<h2>📂 URL Categories</h2>
<div class="cat-grid">{cat_cards}</div>

<h2>🔴 Nuclei Findings ({nuc_count})</h2>
<div class="sev-row">
  {''.join(f"<div class='sev-item'><div class='n {s}'>{sev_counts[s]}</div><div class='dim'>{s.upper()}</div></div>" for s in ['critical','high','medium','low','info'])}
</div>
<table>
<thead><tr><th>Severity</th><th>Finding</th></tr></thead>
<tbody>{nuc_html}</tbody>
</table>

<h2>💉 XSS Findings ({xss_count})</h2>
<table>
<thead><tr><th>Type</th><th>Payload / URL</th></tr></thead>
<tbody>{xss_html}</tbody>
</table>

<h2>🌐 Alive Hosts ({alive_count})</h2>
<table>
<thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th><th>Server</th></tr></thead>
<tbody>{hosts_html}</tbody>
</table>

<h2>🔌 Open Ports (Nmap)</h2>
{nmap_html}

<div class="footer">ReconX v5.1 — {ts_human} — {self.target} — Bu rapor yalnızca yetkili hedeflerde kullanılmak üzere oluşturulmuştur.</div>
</div>
</body>
</html>"""

        rp = self.out / "report.html"
        rp.write_text(html, encoding="utf-8")
        return rp

    # ── Run ───────────────────────────────────────────────────────────────────
    def run(self, stages=None):
        all_s = {
            1: self.stage1_recon,      2: self.stage2_subdomains,
            3: self.stage3_alive,      4: self.stage4_urls,
            5: self.stage5_categorise, 6: self.stage6_nuclei,
            7: self.stage7_xss,
        }
        try:
            for n in (stages or range(1, 8)):
                if _INT.hard():
                    warn("Hard exit — writing report...")
                    break
                if n not in all_s:
                    warn(f"Unknown stage: {n}")
                    continue
                try:
                    all_s[n]()
                except KeyboardInterrupt:
                    # Ctrl+C geldi — stage'i durdur ama raporu yaz
                    setattr(_INT, "_hard", True)
                    warn("Interrupted — writing report...")
                    break
                except SystemExit:
                    warn("Force exit — writing report...")
                    break
                except Exception as e:
                    err(f"Stage {n} crashed: {e}")
                    self.log.exception(f"Stage {n} fatal")
                    warn("Continuing to next stage...")
                _INT.reset()
        except KeyboardInterrupt:
            # run() döngüsünün dışında da yakalanır
            setattr(_INT, "_hard", True)
            warn("Interrupted — writing report...")
        finally:
            # Her koşulda rapor yazılır: normal bitiş, Ctrl+C, hata, SIGTERM
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
  ║  ReconX Sequential Scanner v5.1                      ║
  ║  Recon → Subs → Alive → URLs → Cats → Nuclei → XSS   ║
  ║  By Zulfukar Karabulut & Pentester | Comp. Engineer  ║
  ║  Linkedin : https://linkedin.com/in/2u1fuk4r         ║
  ╚══════════════════════════════════════════════════════╝{C.RESET}""")

    p = argparse.ArgumentParser(description="ReconX Bug Bounty Scanner v5.1")
    p.add_argument("-d", "--domain",     required=True,       help="Target domain")
    p.add_argument("-s", "--stages",     nargs="+", type=int, help="Stages to run (default: all)")
    p.add_argument("--resume",           action="store_true", help="Resume from checkpoints")
    p.add_argument("--no-legal",         action="store_true", help="Skip legal warning")
    p.add_argument("--auto-nuclei",      action="store_true", help="Skip nuclei prompt")
    p.add_argument("--auto-xss",         action="store_true", help="Skip XSS prompt")
    p.add_argument("--single",           action="store_true",
                   help="Single domain mode — skip subdomain enumeration, scan only the given domain")
    p.add_argument("--config",           default=str(CFG_FILE))
    args = p.parse_args()

    if not args.no_legal:
        legal_warning()

    if args.single:
        print(f"\n  {C.MAGENTA}[SINGLE MODE]{C.RESET} Subdomain enumeration disabled — "
              f"scanning only: {C.BOLD}{args.domain}{C.RESET}\n")

    cfg = load_config(Path(args.config))
    ReconPipeline(
        args.domain, cfg,
        resume=args.resume,
        auto_nuclei=args.auto_nuclei,
        auto_xss=args.auto_xss,
        single=args.single,
    ).run(stages=args.stages)


if __name__ == "__main__":
    main()
