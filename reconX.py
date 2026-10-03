#!/usr/bin/env python3

import atexit, os, sys, re, json, yaml, time, logging, argparse, html, sqlite3, random, ipaddress
import subprocess, shutil, threading, signal, shlex, csv, tempfile
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, unquote, urljoin
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait

# v6.9: stdout/stderr kodlamasini UTF-8'e zorla. cp1252 (Windows) veya C-locale
#       (Linux/CI) ortamlarinda unicode banner/turkce karakterler
#       UnicodeEncodeError ile tool'u en basta kilitliyordu — -h yardim bile yok.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

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

# recon scanner: TLS certs on targets are routinely expired / self-signed —
# every HTTP call below is made with verify=False, so silence the noise.
try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass
try:
    import warnings
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")
except Exception:
    pass

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

# What the operator sees. The binary name stays in the log file and on disk;
# the console, the progress line and Scan Center say what the step is doing.
from reconx_labels import public_activity as _public_activity, public_text as _public_text


def info(m):  print(f"{C.BLUE}[*]{C.RESET} {_public_text(m)}", flush=True)
def ok(m):    print(f"{C.GREEN}[✓]{C.RESET} {_public_text(m)}", flush=True)
def warn(m):  print(f"{C.YELLOW}[!]{C.RESET} {_public_text(m)}", flush=True)
def err(m):   print(f"{C.RED}[✗]{C.RESET} {_public_text(m)}", flush=True)
def sub(m):   print(f"  {C.DIM}→{C.RESET} {_public_text(m)}", flush=True)

# v8.3: shared with _stream_tool()'s spinner thread so a live XSS-hit print
# (see xss_live_hit below, called from a background reader thread while
# dalfox is still running) doesn't visually interleave/garble mid-write with
# the spinner's own \r-based redraw — both hold this before touching stdout.
_PRINT_LOCK = threading.Lock()

# dalfox v2's PoC "type" is a single-letter internal code (see pkg/model/result.go):
# "V" = Verified (its own headless browser caught alert/confirm/prompt firing —
# highest confidence), "R" = Reflected (payload echoed back unescaped), "G" =
# Grep match (a weaker heuristic pattern hit). Mirrors _DALFOX_TYPE_LABELS in
# report_builder.py, kept here too since this prints live during the scan.
_XSS_TYPE_LIVE = {"V": ("VERIFIED", C.RED), "R": ("REFLECTED", C.RED), "G": ("GREP MATCH", C.YELLOW)}

def xss_live_hit(rec: dict):
    """v8.3: called the MOMENT dalfox reports a finding (from its own jsonl
    PRINT line on stdout, streamed live via _stream_tool's line_cb — see
    _run_dalfox_once) — prints the URL + payload immediately, in red, while
    the scan just keeps running underneath. Purely a display side-effect:
    never raises, never touches control flow, never slows/blocks the reader
    thread beyond a single print. The full finding still also lands in the
    final findings table/report exactly as before; this is IN ADDITION to
    that, not a replacement for it."""
    try:
        if not isinstance(rec, dict):
            return
        url = str(rec.get("data") or "")
        payload = str(rec.get("payload") or "")
        param = str(rec.get("param") or "")
        raw_type = str(rec.get("type") or "")
        label, color = _XSS_TYPE_LIVE.get(raw_type, ("HIT", C.RED))
        if not url and not payload:
            return
        with _PRINT_LOCK:
            sys.stdout.write("\r" + " " * 100 + "\r")
            print(f"  {color}{C.BOLD}[XSS {label}]{C.RESET} {color}{url}{C.RESET}"
                  + (f" {C.DIM}(param: {param}){C.RESET}" if param else ""), flush=True)
            if payload:
                print(f"      {C.DIM}payload: {payload[:220]}{C.RESET}", flush=True)
    except Exception:
        pass

# v8.8: set while the Ctrl+C interrupt menu is on screen so every spinner
# (this one and _stream_tool's own _spin_ticker) stops redrawing instead of
# garbling the menu/input() prompt with a \r-based frame mid-write.
_SPINNER_PAUSE = threading.Event()

# Set by stage() so every tool spinner can say which stage it belongs to.
# Stages run one at a time, so a single slot is the current stage.
_STAGE_CTX = {"n": None, "title": ""}
# Pace of the current stage's per-item loop (arjun, nmap -sV). One run_cmd
# is one item, so this process's own elapsed is not the average.
_JOB_CLOCK = {"n": 0, "sec": 0.0}

# Tools whose own stats line is "hosts finished / hosts queued". Until the
# first stats line arrives, the input list size is a usable total.
_HOST_PROGRESS_TOOLS = {"httpx", "dnsx", "naabu"}

_HOSTS_PROGRESS_RE = re.compile(
    r"Hosts:\s*([\d,]+)\s*/\s*([\d,]+)", re.I)
_REQUESTS_PROGRESS_RE = re.compile(
    r"Requests:\s*([\d,]+)\s*/\s*([\d,]+)", re.I)
_RPS_RE = re.compile(r"\bRPS:\s*([\d,.]+)", re.I)
_MATCHED_RE = re.compile(r"Matched:\s*([\d,]+)", re.I)
_HOSTS_PLAIN_RE = re.compile(r"Hosts:\s*([\d,]+)(?!\s*/)", re.I)
_TEMPLATES_RE = re.compile(r"Templates:\s*([\d,]+)", re.I)
_BAR_PROGRESS_RE = re.compile(
    r"(\d[\d,]*)\s+/\s+(\d[\d,]*)\s+.*?(\d+(?:\.\d+)?)\s*%")
_NMAP_PHASE_RE = re.compile(r"Stats:.*undergoing\s+(.+)$", re.I)
_NMAP_PCT_RE = re.compile(r"About\s+([\d.]+)%\s+done", re.I)
_NMAP_INIT_RE = re.compile(r"^Initiating\s+(.+?)(?:\s+at\b|$)", re.I)
_ARJUN_CHUNK_RE = re.compile(r"Processing chunks:\s*(\d+)\s*/\s*(\d+)", re.I)
_NMAP_LEFT_RE = re.compile(r"\(([0-9:]+)\s+remaining\)", re.I)
_STATUS_FRAC_RE = re.compile(r"(\d+)\s*/\s*(\d+)")


class _Live:
    """One stage's current subprocess. The reader thread writes it; the
    spinner only reads it."""

    def __init__(self):
        self.lock = threading.Lock()
        self.done = None
        self.total = None
        self.unit = ""
        self.item = ""
        self.rate = ""
        self.note = ""
        self.lines = 0
        self.last_move = time.time()
        self.job_locked = False
        self.percent_only = False

    def set_job(self, index, total, unit="", item=""):
        with self.lock:
            self.job_locked = True
            self.percent_only = False
            self.done = max(0, int(index) - 1)
            self.total = max(0, int(total))
            self.unit = unit or ""
            self.item = (item or "")[:72]

    def set_tool(self, done, total, unit="", rate="", note=""):
        with self.lock:
            if self.job_locked:
                bits = []
                if total:
                    bits.append(f"{int(done):,}/{int(total):,}" + (f" {unit}" if unit else ""))
                if note:
                    bits.append(note)
                if bits:
                    self.note = " · ".join(bits)[:120]
                if rate:
                    self.rate = rate
                return
            self.percent_only = False
            self.done = int(done)
            self.total = int(total) if total else None
            if unit:
                self.unit = unit
            if rate:
                self.rate = rate
            if note is not None:
                self.note = (note or "")[:140]

    def set_percent(self, pct, note=""):
        with self.lock:
            if self.job_locked:
                extra = f"{float(pct):.0f}%"
                if note:
                    extra += "  " + note
                self.note = extra[:120]
                return
            self.percent_only = True
            self.done = int(round(float(pct)))
            self.total = 100
            if note:
                self.note = note[:140]

    def snapshot(self):
        with self.lock:
            return (self.done, self.total, self.unit, self.item,
                    self.rate, self.note, self.lines, self.percent_only,
                    self.job_locked, self.last_move)

    def bump_line(self):
        with self.lock:
            self.lines += 1
            self.last_move = time.time()


def _fmt_clock(sec) -> str:
    sec = max(0, int(sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def _parse_count(raw) -> int:
    return int(str(raw).replace(",", "").split(".", 1)[0] or 0)


def _cmd_argv(cmd):
    if isinstance(cmd, (list, tuple)):
        return [str(a) for a in cmd]
    try:
        return shlex.split(str(cmd))
    except Exception:
        return str(cmd).split()


def _tool_name(cmd) -> str:
    argv = _cmd_argv(cmd)
    return Path(argv[0]).name if argv else "cmd"


def _input_list_count(cmd, stdin_file=None) -> int:
    argv = _cmd_argv(cmd)
    for i, arg in enumerate(argv):
        if arg in ("-l", "-list", "--list") and i + 1 < len(argv):
            path = Path(argv[i + 1])
            if path.is_file():
                n = _count_lines(path)
                if n > 0:
                    return n
    if stdin_file:
        n = _count_lines(stdin_file)
        if n > 0:
            return n
    return 0


def _stats_cli(help_text: str, interval: int = 2) -> str:
    """Flags that make a ProjectDiscovery tool print a periodic stats line.
    -si is only added when this build actually documents it."""
    text = help_text or ""
    if "-stats" not in text:
        return ""
    flags = "-stats"
    if "-stats-interval" in text or "-si" in text:
        flags += f" -si {max(1, int(interval))}"
    return flags + " "


def _seed_live(live: _Live, cmd, stdin_file=None, job=None):
    if job and job.get("total"):
        live.set_job(job.get("index") or 1, job.get("total") or 0,
                     job.get("unit") or "", job.get("item") or "")
        return
    name = _tool_name(cmd)
    if name == "httpx-toolkit":
        name = "httpx"
    if name not in _HOST_PROGRESS_TOOLS:
        return
    total = _input_list_count(cmd, stdin_file)
    if total:
        live.set_tool(0, total, unit="hosts")


def _absorb_progress(line: str, live: _Live):
    """Pull done/total out of a tool's own stats line. Hosts win over raw
    request counts: httpx prints both, and the host counter is the one that
    matches 'how many targets are done'."""
    text = strip_ansi(line or "").strip()
    if not text:
        return
    hosts = _HOSTS_PROGRESS_RE.search(text)
    reqs = _REQUESTS_PROGRESS_RE.search(text)
    rps_m = _RPS_RE.search(text)
    rate = ""
    if rps_m and _parse_count(rps_m.group(1)) > 0:
        rate = f"RPS {rps_m.group(1)}"
    if hosts:
        done = _parse_count(hosts.group(1))
        total = _parse_count(hosts.group(2))
        plain_req = re.search(r"Requests:\s*([\d,]+)(?!\s*/)", text)
        req_n = _parse_count(reqs.group(1)) if reqs else (
            _parse_count(plain_req.group(1)) if plain_req else 0)
        note = f"requests {req_n:,}" if req_n else ""
        live.set_tool(done, total, unit="hosts", rate=rate, note=note)
        return
    if reqs:
        done = _parse_count(reqs.group(1))
        total = _parse_count(reqs.group(2))
        bits = []
        plain = _HOSTS_PLAIN_RE.search(text)
        if plain:
            bits.append(f"hosts {plain.group(1)}")
        matched = _MATCHED_RE.search(text)
        if matched:
            bits.append(f"matched {matched.group(1)}")
        templates = _TEMPLATES_RE.search(text)
        if templates:
            bits.append(f"templates {templates.group(1)}")
        live.set_tool(done, total, unit="requests", rate=rate, note=" · ".join(bits))
        return
    chunks = _ARJUN_CHUNK_RE.search(text)
    if chunks:
        live.set_tool(int(chunks.group(1)), int(chunks.group(2)), unit="chunks")
        return
    init = _NMAP_INIT_RE.search(text)
    if init:
        with live.lock:
            live.note = init.group(1).strip()[:80]
        return
    bar = _BAR_PROGRESS_RE.search(text)
    if bar:
        live.set_tool(_parse_count(bar.group(1)), _parse_count(bar.group(2)),
                      unit="", rate=rate, note="")
        return
    about = _NMAP_PCT_RE.search(text)
    if about:
        left = _NMAP_LEFT_RE.search(text)
        note = f"left {left.group(1)}" if left else ""
        live.set_percent(about.group(1), note)
        return
    phase = _NMAP_PHASE_RE.search(text)
    if phase:
        with live.lock:
            live.note = phase.group(1).strip()[:80]


def _absorb_status_text(status, live: _Live):
    """dalfox (and anything else) reports progress by writing status['text']
    as 'target 3/10 (30%) · …' instead of a stats line."""
    if not status:
        return
    text = str(status.get("text") or "").strip()
    if not text:
        return
    frac = _STATUS_FRAC_RE.search(text)
    if not frac:
        with live.lock:
            if live.done is None and not live.job_locked:
                live.note = text[:140]
        return
    total = int(frac.group(2))
    if total <= 0:
        return
    rest = re.sub(r"^\s*\(\s*[\d.]+%\s*\)\s*", "", text[frac.end():]).lstrip(" ·")
    live.set_tool(int(frac.group(1)), total, unit="targets", note=rest)


def _progress_payload(label: str, started: float, live: _Live) -> dict:
    """Numbers behind the progress line. The Scan Center reads the same dict
    as JSON (RXPROGRESS) so the report can pin done/total, remaining and elapsed
    instead of scrolling the line away."""
    elapsed = max(0.0, time.time() - started)
    done, total, unit, item, rate, note, lines, percent_only, job_locked, last_move = live.snapshot()
    pct = None
    eta = None
    done_out = None
    total_out = None
    if percent_only and done is not None:
        pct = int(round(float(done)))
    elif done is not None and total:
        done_out = int(done)
        total_out = int(total)
        pct = int(round(max(0.0, min(100.0, 100.0 * done_out / total_out)))) if total_out else 0
        if done_out < total_out:
            if job_locked and _JOB_CLOCK["n"] > 0:
                avg = _JOB_CLOCK["sec"] / _JOB_CLOCK["n"]
                remaining_after = max(0, total_out - (done_out + 1))
                eta = max(0.0, avg - elapsed) + avg * remaining_after
            elif done_out > 0 and elapsed >= 0.5:
                eta = elapsed * (total_out - done_out) / done_out
            if eta is not None and eta < 1:
                eta = None
    stall = 0
    if done is None and elapsed >= 15 and (time.time() - last_move) >= 15:
        stall = int(time.time() - last_move)
    return {
        "stage": _STAGE_CTX.get("n"),
        "label": _public_text(label or ""),
        "done": done_out,
        "total": total_out,
        "pct": pct,
        "unit": unit or "",
        "eta_sec": int(eta) if eta else None,
        "elapsed_sec": int(elapsed),
        "rate": _public_text(rate or ""),
        "note": _public_text(note or ""),
        "item": _public_text(item or ""),
        "lines": int(lines or 0),
        "stall_sec": stall,
        "percent_only": bool(percent_only),
    }


def _format_progress(p: dict) -> str:
    stage_n = p.get("stage")
    head = f"STAGE {stage_n}  {p.get('label') or ''}" if stage_n is not None else str(p.get("label") or "")
    bits = [head]
    if p.get("percent_only") and p.get("pct") is not None:
        bits.append(f"{p['pct']}%")
    elif p.get("done") is not None and p.get("total"):
        unit_s = f" {p['unit']}" if p.get("unit") else ""
        bits.append(f"{int(p['done']):,}/{int(p['total']):,}{unit_s}")
        if p.get("pct") is not None:
            bits.append(f"{p['pct']}%")
        if p.get("eta_sec"):
            bits.append(f"left {_fmt_clock(p['eta_sec'])}")
    bits.append(f"elapsed {_fmt_clock(p.get('elapsed_sec') or 0)}")
    if p.get("rate"):
        bits.append(p["rate"])
    if p.get("note"):
        bits.append(p["note"])
    if p.get("item"):
        bits.append(p["item"])
    elif not p.get("total") and p.get("lines"):
        n = int(p["lines"])
        low = str(p.get("label") or "").lower()
        if "url" in low:
            word = "url" if n == 1 else "urls"
        else:
            word = "line" if n == 1 else "lines"
        bits.append(f"{n:,} {word}")
    if p.get("stall_sec"):
        bits.append(f"no new output for {_fmt_clock(p['stall_sec'])}")
    return "   ".join(bits)


def _render_progress(label: str, started: float, live: _Live) -> str:
    return _format_progress(_progress_payload(label, started, live))


def _paint_progress(frame: str, text: str, tty: bool, payload: dict = None):
    body = f"  {C.CYAN}{frame}{C.RESET} {C.DIM}{text}{C.RESET}"
    with _PRINT_LOCK:
        if not tty and payload:
            # One JSON line per beat. The report's Scan Center pins this;
            # a pipe has no carriage-return, so the human line would scroll away.
            print("RXPROGRESS " + json.dumps(payload, ensure_ascii=False), flush=True)
        if tty:
            sys.stdout.write("\r" + body + "\033[K")
            sys.stdout.flush()
        else:
            print(body, flush=True)


def _show_progress(frame: str, label: str, started: float, live: _Live, tty: bool):
    payload = _progress_payload(label, started, live)
    _paint_progress(frame, _format_progress(payload), tty, None if tty else payload)


_PULSE_LOCK = threading.Lock()
_PULSE_AT = {"t": 0.0}


def _pulse_job(label: str, started: float, done: int, total: int,
               unit: str = "", item: str = "", note: str = "", force: bool = False):
    """Progress for an in-process loop (JS, CORS, API probes, canary checks).
    Throttled to about once a second so a tight loop does not flood the pipe."""
    now = time.time()
    finished = bool(total) and int(done) >= int(total)
    with _PULSE_LOCK:
        if (not force and not finished and int(done) > 1
                and (now - _PULSE_AT["t"]) < 1.0):
            return
        _PULSE_AT["t"] = now
    live = _Live()
    if total:
        live.set_tool(int(done), int(total), unit=unit, note=note or "")
    if item or not total:
        with live.lock:
            if item:
                live.item = str(item)[:72]
            if not total:
                live.lines = int(done or 0)
                live.note = (note or "")[:140]
    _show_progress("…", _public_activity(label), started, live, sys.stdout.isatty())


def _clear_progress(tty: bool):
    if not tty:
        return
    with _PRINT_LOCK:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()


def _spinner(stop_evt: threading.Event, label: str, started: float, live: _Live):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    i = 0
    tty = sys.stdout.isatty()
    # A pipe (the Scan Center live console) never sees a carriage-return
    # spinner. Print a fresh line when the count moves, and at least every
    # few seconds, so a long httpx/naabu run is visible there too.
    if not tty:
        last_beat = None
        last_sig = None
        while not stop_evt.is_set():
            now = time.time()
            snap = live.snapshot()
            sig = (snap[0], snap[6])
            moved = sig != last_sig and (snap[0] not in (None, 0) or snap[6])
            due = last_beat is None and now - started >= 0.6
            due = due or (last_beat is not None and moved and now - last_beat >= 1.0)
            due = due or (last_beat is not None and now - last_beat >= 3)
            if due:
                _show_progress("…", label, started, live, False)
                last_beat = now
                last_sig = sig
            time.sleep(0.3)
        # A tool that finished before the first heartbeat does not need a
        # progress line of its own — the result line printed next is enough.
        if last_beat is not None and (live.snapshot()[0], live.snapshot()[6]) != last_sig:
            _show_progress("…", label, started, live, False)
        return
    while not stop_evt.is_set():
        if _SPINNER_PAUSE.is_set():
            time.sleep(0.05)
            continue
        _show_progress(frames[i % len(frames)], label, started, live, True)
        i += 1
        time.sleep(0.12)
    _clear_progress(True)

def stage(n, t):
    t = _public_text(t)
    _STAGE_CTX["n"] = n
    _STAGE_CTX["title"] = t
    _JOB_CLOCK["n"] = 0
    _JOB_CLOCK["sec"] = 0.0
    print(f"\n{C.CYAN}{C.BOLD}{'═'*60}\n  STAGE {n}: {t}\n{'═'*60}{C.RESET}", flush=True)

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
CFG_FILE = BASE_DIR / "config.yaml"
VERSION = "9.5"
ANSI_RE  = re.compile(r"\x1b\[[0-9;]*m")

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s or "")

def _is_reconx_banner_line(text: str) -> bool:
    """The startup logo. Scan Center runs one process per button, so this
    block used to land in the live console on every click."""
    s = (text or "").strip()
    if not s:
        return False
    if any(ch in s for ch in "█╔╗╚╝║"):
        return True
    if s.startswith("ReconX") and "Sequential" in s:
        return True
    if "linkedin.com/in/2u1fuk4r" in s:
        return True
    return False

def _pipe_echo(line: str):
    """Copy one tool line to stdout when a pipe is listening (Scan Center).

    A real terminal keeps the single-line spinner instead; dumping every
    line there fights the redraw. JSON records stay out — a finding callback
    already prints those as a readable hit.
    """
    if sys.stdout.isatty():
        return
    text = strip_ansi(line or "").replace("\r", "").strip()
    if not text or _is_reconx_banner_line(text):
        return
    if text.startswith("{") and text.endswith("}"):
        return
    with _PRINT_LOCK:
        print(text, flush=True)

def _useful_stderr_lines(text: str, limit: int = 6) -> list:
    """The lines an operator needs from a failed tool. ASCII logos and blank
    padding are dropped; a fatal line wins over the banner that precedes it."""
    lines = []
    for raw in (text or "").splitlines():
        line = strip_ansi(raw).strip()
        if not line:
            continue
        if "projectdiscovery.io" in line.lower():
            continue
        if re.fullmatch(r"[_/\\|.\- \t]+", line):
            continue
        lines.append(line)
    fatal = [ln for ln in lines if re.search(
        r"\[(FTL|ERR|FATAL)\]|\berror\b|\bfailed\b|doesn't exist|not found|no valid",
        ln, re.I)]
    return (fatal or lines)[:limit]

# ── DNS resilience ────────────────────────────────────────────────────────────
# Labs / VPNs / cloud sandboxes routinely block outbound UDP/53 to public
# resolvers while leaving HTTPS/443 wide open. When that happens every tool in
# the pipeline (dalfox, nuclei, httpx, katana, curl_cffi, gau, ...) starts
# failing lookups intermittently with "could not resolve host", which silently
# guts the results — no XSS, no nuclei hits, empty subdomain lists — even on a
# deliberately-vulnerable target. reconx_dns.py (shipped next to this file) is a
# tiny UDP resolver that forwards over DoH; if the system resolver looks broken
# we start it and route lookups through it.
DNS_PROXY = {"proc": None, "resolv_backup": None, "port": None}
DNS_PROXY_SCRIPT = BASE_DIR / "reconx_dns.py"


def _system_nameservers(limit=3):
    """Nameservers from /etc/resolv.conf, in order."""
    out = []
    try:
        for line in Path("/etc/resolv.conf").read_text(errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) > 1:
                    out.append(parts[1])
    except Exception:
        pass
    return out[:limit]


def _dns_is_healthy(deadline=4.0):
    """Can the system's own nameservers answer over UDP/53?

    Deliberately a RAW UDP query rather than socket.getaddrinfo():

      * getaddrinfo is a blocking libc call that ignores
        socket.setdefaulttimeout(), so it only returns once glibc has burned
        the whole resolv.conf retry budget. Run serially over 3 hosts x 2
        attempts (the original implementation) that measured 13s of silent
        dead air right after the banner, and 117s when DNS was flaky — the
        "it hangs at the banner" report.
      * Running those lookups concurrently is WORSE, not better: measured on
        this box, three parallel getaddrinfo calls left two of them unreturned
        after 4s while the very same lookups took 0.05s each sequentially.
        glibc serialises concurrent resolver state.

    A raw query has a real socket timeout and tests precisely what the DoH
    fallback exists to work around: UDP/53 reachability. Total cost is bounded
    by `deadline` no matter how broken the network is."""
    servers = _system_nameservers()
    if not servers:
        return True          # nothing configured to probe — don't fight the system
    end = time.time() + deadline
    # Two short attempts per server: a single dropped UDP packet should not be
    # enough to flip the verdict and drag the whole run onto the DoH fallback.
    for attempt in range(2):
        for ns in servers:
            if time.time() >= end:
                return False
            budget = min(0.9, max(0.3, end - time.time()))
            if _udp_dns_answers(ns, 53, timeout=budget):
                return True
    return False


def _udp_dns_answers(server, port, name="cloudflare.com", timeout=4.0):
    """Fire one raw A query at server:port and return True if we get an answer."""
    import socket as _s, struct
    q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         + b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
         + b"\x00\x00\x01\x00\x01")
    try:
        sk = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        sk.settimeout(timeout)
        sk.sendto(q, (server, port))
        data, _ = sk.recvfrom(1024)
        return len(data) > 12 and struct.unpack(">H", data[6:8])[0] > 0
    except OSError:
        return False
    finally:
        try:
            sk.close()
        except Exception:
            pass


def _repoint_resolv_conf(server="127.0.0.1"):
    rc = Path("/etc/resolv.conf")
    try:
        subprocess.run(["chattr", "-i", str(rc)], capture_output=True, check=False)
        DNS_PROXY["resolv_backup"] = rc.read_text() if rc.exists() else ""
        rc.write_text(f"# ReconX: routed through bundled DoH resolver — restored on exit\nnameserver {server}\n")
        return True
    except Exception as e:  # noqa: BLE001
        warn(f"Could not update /etc/resolv.conf ({e}) — leaving it as-is")
        return False


def _restore_dns():
    p = DNS_PROXY.get("proc")
    if p and p.poll() is None:
        try:
            p.terminate()
        except Exception:
            pass
    if DNS_PROXY.get("resolv_backup") is not None:
        try:
            Path("/etc/resolv.conf").write_text(DNS_PROXY["resolv_backup"])
        except Exception:
            pass


def ensure_resilient_dns():
    if os.environ.get("RECONX_NO_DNS_FIX"):
        return
    _t0 = time.time()
    if _dns_is_healthy():
        # Only worth a line when it actually cost the operator some waiting.
        if time.time() - _t0 > 1.5:
            sub(f"DNS check: {time.time() - _t0:.1f}s (system resolver OK)")
        return
    warn("System DNS looks unreliable (UDP/53 likely blocked) — engaging DoH fallback")
    if not DNS_PROXY_SCRIPT.exists():
        warn(f"{DNS_PROXY_SCRIPT.name} not found beside reconX.py — cannot auto-fix DNS. "
             f"Results may be incomplete on this network.")
        return
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    port = 53 if is_root else 5300
    # Reuse an already-running proxy on this port instead of stacking another.
    if not _udp_dns_answers("127.0.0.1", port):
        try:
            DNS_PROXY["proc"] = subprocess.Popen(
                [sys.executable, str(DNS_PROXY_SCRIPT), "--host", "127.0.0.1", "--port", str(port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        except Exception as e:  # noqa: BLE001
            warn(f"Failed to start {DNS_PROXY_SCRIPT.name}: {e}")
            return
        for _ in range(12):
            time.sleep(0.5)
            if _udp_dns_answers("127.0.0.1", port):
                break
        else:
            warn("DoH resolver did not answer in time — continuing with system DNS")
            return
    DNS_PROXY["port"] = port
    atexit.register(_restore_dns)
    if is_root:
        if _repoint_resolv_conf("127.0.0.1"):
            ok("DNS: all lookups now routed through bundled DoH resolver (127.0.0.1:53)")
    else:
        os.environ["RECONX_RESOLVER"] = f"127.0.0.1:{port}"
        warn(f"DNS: DoH resolver up on 127.0.0.1:{port}, passed to httpx/nuclei/subfinder/dnsx. "
             f"katana/dalfox/gau still use system DNS — for a full fix run:\n"
             f"    sudo python3 {DNS_PROXY_SCRIPT} --port 53 &  && "
             f"echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf")


def dns_resolver_args(tool):
    """Resolver CLI args for a PD tool when the non-root DoH fallback is active."""
    r = os.environ.get("RECONX_RESOLVER")
    if not r:
        return []
    return {
        "httpx":     ["-r", r],
        "dnsx":      ["-r", r],
        "nuclei":    ["-resolvers", r],
        "subfinder": ["-rlist", r],
    }.get(tool, [])

# ── Config ────────────────────────────────────────────────────────────────────
def load_config(path=None):
    p = Path(path or CFG_FILE)
    defaults = {
        "settings": {
            "threads": 25,
            "rate_limit": 10,
            "timeout": 20,
            "use_curl_cffi": True,
            "curl_cffi_impersonate": "chrome120",
            "proxy": "",
            "jitter_max": 0.45,
            "default_scheme": "https",
            "use_referer": True,
            "adaptive_rate": True,
            "adaptive_threshold": 0.15,
            "adaptive_floor_mult": 0.25,
            "canonicalize_urls": True,
            "rerun_on_block": True,
            "rerun_max": 2,
            "rerun_backoff": 0.65,
            "rerun_pause_sec": 6,
            "auto_tor": True,
            "tor_socks_port": 9060,
            "tor_control_port": 9061,
            "tor_max_rotations_per_stage": 5,
            "tor_control_password": "",
            "user_agent_rotation": True,
            "respect_scope": True,
            "max_subdomains": 5000,
            "enable_crtsh_fallback": True,
            "enable_screenshots": False,
            "webhook_url": "",
            "prune_dead_urls": True,
            "prune_dead_urls_filter_codes": "404",
            "xss_alert_screenshots": True,
            "xss_alert_screenshots_max": 15,
            "xss_verify_payloads_per_point": 4,
            "xss_verify_max_checks": 60,
            "xss_verify_budget_sec": 3600,
        },
        "api_keys": {"anthropic": ""},
        "tools": {
            "nuclei_severity": "critical,high,medium,low",
            "nuclei_templates": "",
            "nuclei_excluded_tags": "intrusive,dos",
            "nuclei_stats_interval": 5,
            "nuclei_tech_fastpass": True,
            "nuclei_rate_limit": 150,
            "nuclei_concurrency": 25,
            "nuclei_retries": 1,
            "nuclei_max_targets": 0,
            "nuclei_dedup_url_shapes": True,
            "nuclei_max_host_error": 30,
            "nuclei_scan_strategy": "auto",
            "nuclei_stall_timeout_sec": 300,
            "blind_xss_callback": "",
            "dalfox_custom_payload": "",
            "dalfox_blind": False,
            "dalfox_test_path_only": False,
            "dalfox_path_only_max": 100,
            "dalfox_dedup_query_params": True,
            # XSS only runs on one example of each parameter, and only after a
            # live request shows that parameter's value coming back in the page.
            "xss_reflected_only": True,
            "xss_reflect_threads": 20,
            "xss_reflect_timeout": 8,
            # v9.3: skip dalfox's own parameter mining by default. ReconX already
            # feeds dalfox a corpus of real crawled/wayback URLs with their params
            # present, so dalfox re-guessing param names is mostly redundant — and
            # on targets that reflect ANY param name (e.g. testasp.vulnweb.com,
            # many search/error pages) dict+DOM mining discovers dozens of bogus
            # "reflected" params and tests the full payload set against each,
            # exploding per-URL time until the whole scan hits its budget and
            # surfaces nothing — even on a URL whose real param (already in the
            # corpus) is trivially vulnerable. Proven on testasp Search.asp?tfSearch:
            # full mining timed out at 90s+ with 0 completed targets; "all" finished
            # in 51s and still reported the tfSearch XSS. Values: "all" (skip
            # dict+DOM, fastest), "dom", "dict", "" / "none" (full mining, dalfox
            # default). Set to "" if you specifically want hidden-param discovery.
            "dalfox_skip_mining": "all",
            # v9.3: trim per-target cost for an XSS-focused stage. dalfox v2 scans
            # a target file strictly ONE URL at a time, so every request saved per
            # target compounds across the whole list. --skip-bav drops dalfox's
            # non-XSS "basic another vulnerability" probes; --skip-headless drops
            # its own chromedp DOM verification, which is redundant with ReconX's
            # separate headless XSS-proof step (verified findings still surface via
            # static+grep analysis). Set either False if you want dalfox's full
            # behavior back.
            "dalfox_skip_bav": True,
            "dalfox_skip_headless": True,
            "dalfox_max_targets": 0,
            "dalfox_time_budget_sec": 10800,
            # One URL must not consume the whole XSS stage. dalfox keeps
            # fuzzing a URL after the first verified hit; 180s keeps that hit
            # and moves on so the rest of the list is actually scanned.
            "dalfox_per_url_sec": 420,
            # 0 = one dalfox process per CPU, never two at once against the same host.
            "dalfox_parallel_jobs": 0,
            "dalfox_workers": 40,
            "dalfox_delay_ms": 0,
            "dalfox_stall_timeout_sec": 0,
            "dalfox_mass_workers": 10,
            "blind_xss_auto": True,
            "blind_xss_listen_after_sec": 90,
            "blind_xss_poll_interval": 5,
            "arjun_max_hosts": 10,
            "arjun_timeout_per_host": 600,
            "cors_test_origin": "https://reconx-cors-probe.invalid",
            "open_redirect_canary": "example.com",
            "cloud_bucket_timeout": 10,
            "cloud_enum_threads": 8,
            "cloud_enum_timeout": 900,
            # 0 = every in-scope JS file, no wall-clock cutoff. Stage 10 is a
            # Scan Center pass that runs after the report, so it can take the time.
            "js_secrets_max_files": 0,
            "js_secrets_concurrency": 15,
            "js_secrets_request_timeout": 12,
            "js_secrets_budget_sec": 0,
            "js_secrets_patterns": "aws,gcp,azure,slack,stripe,github,jwt,private_key",
            "crtsh_timeout": 20,
            "chaos_enabled": False,
            "dnsx_enabled": True,
            "asn_lookup": True,
            "report_title": "ReconX Professional Report",
            "report_author": "",
        },
        # v9.2: per-tool wall-clock ceilings, seconds. Empty = use the built-in
        # table (see T above); any subset can be overridden.
        "timeouts": {},
        # v9.1: Claude-backed analysis of the finished scan (reconx_ai.py).
        "ai": {
            "enabled": True,
            # auto = Anthropic API when a key is set, falling back to the
            # `claude` CLI (your Claude subscription) when there is no key OR
            # the API account is out of credit. api / cli force one backend.
            "backend": "auto",
            "model": "claude-opus-5",
            "cli_model": "opus",
            "cli_timeout_sec": 1800,
            "effort": "high",
            "max_tokens": 16000,
            "redact_secrets": True,
            "auto_bridge": True,
            "bridge_idle_timeout_sec": 0,
            "bridge_port": 0,
        },
    }
    if not p.exists():
        try:
            _write_default_config_yaml(p, defaults)
            info(f"config.yaml created from the built-in template: {p}")
        except Exception:
            pass
        return defaults
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace")) or {}
    except Exception:
        return defaults

    # config.yaml beklenen "dict" semasinda degilse (liste/string/int YAML),
    # default'lara dus — aksi halde asagidaki data[k]=v olmayan dict'i cokerir.
    if not isinstance(data, dict):
        warn(f"config.yaml is not a dict ({type(data).__name__}) — "
             f"falling back to built-in defaults")
        return defaults

    # v6.17: "yabanci" config.yaml tespiti + otomatik gocurme.
    # ReconX'in kendi semasi ust seviyede settings/api_keys/tools bekler.
    # Baska bir arac/sablondan gelen config.yaml (orn. providers/reconx/
    # database/cache/scope/advanced gibi anahtarlar) sessizce yok
    # sayiliyordu — arac hicbir hata da vermiyordu, sadece "not configured"
    # diyordu. Artik bu durum tespit edilip: (1) eski dosya .bak olarak
    # yedekleniyor, (2) doğru semali taze bir config.yaml yaziliyor,
    # (3) kullaniciya net bir uyari basiliyor.
    # v6.17-fix: sadece "tools" ortak olabilir (cok genel bir isim, baska
    # araclarin config'lerinde de gecebilir) — bu yuzden tek basina guvenilir
    # bir sinyal degil. "settings" VE "api_keys" ikisi birden HER ZAMAN
    # ReconX'in kendi semasinda bulunur; ikisi de yoksa dosya neredeyse
    # kesinlikle farkli bir araca/sablona ait demektir.
    looks_foreign = (isinstance(data, dict) and bool(data)
                      and "settings" not in data
                      and "api_keys" not in data)

    if looks_foreign:
        warn(f"config.yaml uses an unknown schema (ReconX expects top-level "
             f"settings/api_keys/tools). Keys found: "
             f"{', '.join(sorted(data.keys()))}")
        try:
            backup = p.with_suffix(p.suffix + ".bak")
            shutil.copy2(p, backup)
            warn(f"Old config.yaml backed up: {backup}")
        except Exception:
            pass

        new_cfg = json.loads(json.dumps(defaults))  # deep copy
        try:
            _write_default_config_yaml(p, new_cfg)
            ok(f"A fresh config.yaml with the correct schema was written: {p}")
        except Exception as e:
            warn(f"Could not write the new config.yaml: {e}")
        return new_cfg

    for k, v in defaults.items():
        if k not in data:
            data[k] = v
        elif isinstance(v, dict):
            for k2, v2 in v.items():
                data[k].setdefault(k2, v2)
    return data

def _write_default_config_yaml(p: Path, cfg: dict) -> None:
    """Write a readable, commented config.yaml for cfg (settings/api_keys/tools
    schema). Used both after a migration and as the first-run template — this
    is now the ONLY config template that ships, since config.example.yaml was
    dropped from the repo."""
    s = cfg.get("settings", {})
    t = cfg.get("tools", {})
    _ai = cfg.get("ai", {}) or {}
    _ak = cfg.get("api_keys", {}) or {}
    _tkeys = ", ".join(sorted(T))
    # Write the effective table out commented, so the file documents both the
    # current value and the knob, without silently pinning anything.
    _to = cfg.get("timeouts", {}) or {}
    _tdefaults = "\n".join(
        f"  {'' if k in _to else '# '}{k}: {_to.get(k, v)}"
        f"{'' if k in _to else '   # default'}"
        for k, v in sorted(T.items(), key=lambda kv: (-kv[1], kv[0])))
    def _yq(v):  # YAML-safe quoted string
        s_ = str(v)
        return '"' + s_.replace('\\', '\\\\').replace('"', '\\"') + '"'
    _tpl = f"""# ReconX config.yaml — schema: settings / api_keys / tools
# Auto-generated by ReconX (first run, or migrated from an unrecognised file).
# Safe to edit by hand; ReconX only rewrites it when it is missing or invalid.
# Every secret can also come from the environment instead (RECONX_CENSYS_KEY, ...).

settings:
  threads: {s.get('threads', 20)}
  rate_limit: {s.get('rate_limit', 8)}
  timeout: {s.get('timeout', 20)}
  use_curl_cffi: {str(s.get('use_curl_cffi', True)).lower()}
  curl_cffi_impersonate: {_yq(s.get('curl_cffi_impersonate', 'chrome120'))}
  proxy: {_yq(s.get('proxy', ''))}
  jitter_max: {s.get('jitter_max', 0.6)}
  default_scheme: {_yq(s.get('default_scheme', 'https'))}
  use_referer: {str(s.get('use_referer', True)).lower()}
  adaptive_rate: {str(s.get('adaptive_rate', True)).lower()}
  adaptive_threshold: {s.get('adaptive_threshold', 0.18)}
  adaptive_floor_mult: {s.get('adaptive_floor_mult', 0.25)}
  canonicalize_urls: {str(s.get('canonicalize_urls', True)).lower()}
  rerun_on_block: {str(s.get('rerun_on_block', True)).lower()}
  rerun_max: {s.get('rerun_max', 1)}
  rerun_backoff: {s.get('rerun_backoff', 0.65)}
  rerun_pause_sec: {s.get('rerun_pause_sec', 6)}
  # Tor-based automatic IP rotation — kicks in only when the target/WAF is
  # DETECTED as blocking (normal requests go out directly; Tor is the fallback).
  # Requires ./install.sh (installs tor + stem). Uses its own isolated
  # SOCKS/Control ports, so it does NOT clash with a system-wide Tor setup.
  auto_tor: {str(s.get('auto_tor', True)).lower()}
  tor_socks_port: {s.get('tor_socks_port', 9060)}
  tor_control_port: {s.get('tor_control_port', 9061)}
  tor_max_rotations_per_stage: {s.get('tor_max_rotations_per_stage', 5)}
  tor_control_password: {_yq(s.get('tor_control_password', ''))}
  prune_dead_urls: {str(s.get('prune_dead_urls', True)).lower()}
  prune_dead_urls_filter_codes: {_yq(s.get('prune_dead_urls_filter_codes', '404'))}
  xss_alert_screenshots: {str(s.get('xss_alert_screenshots', True)).lower()}
  xss_alert_screenshots_max: {s.get('xss_alert_screenshots_max', 15)}
  xss_verify_payloads_per_point: {s.get('xss_verify_payloads_per_point', 4)}
  xss_verify_max_checks: {s.get('xss_verify_max_checks', 60)}
  xss_verify_budget_sec: {s.get('xss_verify_budget_sec', 3600)}

api_keys:
  # Used by the AI analyst (reconx_ai.py). Leave empty and export
  # ANTHROPIC_API_KEY instead if you prefer to keep keys out of files.
  anthropic: {_yq(_ak.get('anthropic', ''))}

# Claude-backed review of the finished scan. After the pipeline ends, ReconX
# starts a localhost bridge and opens the report through it, so the report's
# "AI Analysis" button has a backend to call. The API key stays in that
# process and is NEVER written into report.html.
# Per-tool wall-clock ceiling in SECONDS. Hitting one kills that tool and the
# stage continues with whatever it produced — a ceiling set too low reads back
# as "the target has nothing", so these are generous by default. Only the keys
# you list here override the built-in table; delete a line to go back to the
# default. Valid keys: {_tkeys}
timeouts:
{_tdefaults}

ai:
  enabled: {str(_ai.get('enabled', True)).lower()}
  # A Claude Pro/Max subscription and the Anthropic API are billed SEPARATELY:
  # the subscription funds claude.ai and Claude Code, the API is prepaid credit
  # bought in the Console. A valid API key with an empty balance is common.
  #   auto = use the API when a key is set, and fall back to the `claude` CLI
  #          (your subscription) when there is no key or the API has no credit
  #   api  = Anthropic API only        cli = `claude` CLI only
  backend: {_yq(_ai.get('backend', 'auto'))}
  model: {_yq(_ai.get('model', 'claude-opus-5'))}
  # Model alias passed to the claude CLI (opus / sonnet / fable).
  cli_model: {_yq(_ai.get('cli_model', 'opus'))}
  cli_timeout_sec: {_ai.get('cli_timeout_sec', 1800)}
  # low | medium | high | xhigh | max — how deep the model reasons before
  # answering. Correlating a whole scan is what "high" is for.
  effort: {_yq(_ai.get('effort', 'high'))}
  max_tokens: {_ai.get('max_tokens', 16000)}
  # Send discovered secrets as class + length + first/last characters instead
  # of the real value. The evidence pack leaves this machine; keep this true
  # unless the target is your own.
  redact_secrets: {str(_ai.get('redact_secrets', True)).lower()}
  # Start the bridge automatically when a scan finishes.
  auto_bridge: {str(_ai.get('auto_bridge', True)).lower()}
  # Shut the bridge down after this many idle seconds (0 = stay up until stopped).
  bridge_idle_timeout_sec: {_ai.get('bridge_idle_timeout_sec', 0)}
  # 0 = pick a free port automatically.
  bridge_port: {_ai.get('bridge_port', 0)}

tools:
  nuclei_severity: {_yq(t.get('nuclei_severity', 'critical,high,medium,low'))}
  nuclei_templates: {_yq(t.get('nuclei_templates', ''))}
  nuclei_excluded_tags: {_yq(t.get('nuclei_excluded_tags', 'intrusive,dos'))}
  nuclei_stats_interval: {t.get('nuclei_stats_interval', 5)}
  nuclei_tech_fastpass: {str(t.get('nuclei_tech_fastpass', True)).lower()}
  nuclei_rate_limit: {t.get('nuclei_rate_limit', 150)}
  nuclei_concurrency: {t.get('nuclei_concurrency', 25)}
  nuclei_retries: {t.get('nuclei_retries', 1)}
  # v9.0: nuclei is fed the WHOLE live URL corpus (stage 4's pruned list +
  # param URLs + authenticated URLs), not just the alive host roots — a
  # path-matching template can only fire if it is given the path.
  # Hard cap on that list. Applied by priority: host roots and parameterised
  # URLs are kept first, only plain path URLs get trimmed. 0 = no cap.
  nuclei_max_targets: {t.get('nuclei_max_targets', 0)}
  # Collapse ?id=1 / ?id=2 and /post/1 / /post/2 down to one representative
  # each — the same template surface, so testing every one costs time for zero
  # extra coverage. Turn off only if a target routes on the literal value.
  nuclei_dedup_url_shapes: {str(t.get('nuclei_dedup_url_shapes', True)).lower()}
  # Drop a host from the scan after this many request errors (nuclei -mhe):
  # a host that is down or hard-blocking should not keep absorbing templates.
  nuclei_max_host_error: {t.get('nuclei_max_host_error', 30)}
  # nuclei -ss: auto | host-spray | template-spray. host-spray spreads the
  # load across hosts instead of finishing one at a time — gentler on a WAF
  # when the list covers many subdomains.
  nuclei_scan_strategy: {_yq(t.get('nuclei_scan_strategy', 'auto'))}
  # Kill nuclei if it prints nothing at all for this many seconds (hung on a
  # network block or its own update check). Must stay well above
  # nuclei_stats_interval.
  nuclei_stall_timeout_sec: {t.get('nuclei_stall_timeout_sec', 300)}
  nuclei_dast: {str(t.get('nuclei_dast', True)).lower()}
  nuclei_dast_max_urls: {t.get('nuclei_dast_max_urls', 0)}
  blind_xss_callback: {_yq(t.get('blind_xss_callback', ''))}
  dalfox_custom_payload: {_yq(t.get('dalfox_custom_payload', ''))}
  dalfox_blind: {str(t.get('dalfox_blind', False)).lower()}
  dalfox_test_path_only: {str(t.get('dalfox_test_path_only', False)).lower()}
  dalfox_path_only_max: {t.get('dalfox_path_only_max', 100)}
  dalfox_dedup_query_params: {str(t.get('dalfox_dedup_query_params', True)).lower()}
  xss_reflected_only: {str(t.get('xss_reflected_only', True)).lower()}
  xss_reflect_threads: {t.get('xss_reflect_threads', 20)}
  xss_reflect_timeout: {t.get('xss_reflect_timeout', 8)}
  # Skip dalfox's own param mining: "all" (fastest, skip dict+DOM) | "dom" | "dict" | "" (full mining)
  dalfox_skip_mining: {_yq(t.get('dalfox_skip_mining', 'all'))}
  # Per-target cost trims (XSS-focused): skip non-XSS probes / dalfox's own headless DOM check
  dalfox_skip_bav: {str(t.get('dalfox_skip_bav', True)).lower()}
  dalfox_skip_headless: {str(t.get('dalfox_skip_headless', True)).lower()}
  dalfox_max_targets: {t.get('dalfox_max_targets', 0)}
  dalfox_time_budget_sec: {t.get('dalfox_time_budget_sec', 10800)}
  dalfox_per_url_sec: {t.get('dalfox_per_url_sec', 420)}
  dalfox_parallel_jobs: {t.get('dalfox_parallel_jobs', 0)}
  dalfox_parallel_min: {t.get('dalfox_parallel_min', 8)}
  dalfox_workers: {t.get('dalfox_workers', 40)}
  dalfox_delay_ms: {t.get('dalfox_delay_ms', 0)}
  dalfox_stall_timeout_sec: {t.get('dalfox_stall_timeout_sec', 0)}
  dalfox_mass_workers: {t.get('dalfox_mass_workers', 10)}
  blind_xss_auto: {str(t.get('blind_xss_auto', True)).lower()}
  blind_xss_listen_after_sec: {t.get('blind_xss_listen_after_sec', 90)}
  blind_xss_poll_interval: {t.get('blind_xss_poll_interval', 5)}
  arjun_max_hosts: {t.get('arjun_max_hosts', 10)}
  arjun_timeout_per_host: {t.get('arjun_timeout_per_host', 600)}
  cors_test_origin: {_yq(t.get('cors_test_origin', 'https://reconx-cors-probe.invalid'))}
  open_redirect_canary: {_yq(t.get('open_redirect_canary', 'example.com'))}
  cloud_bucket_timeout: {t.get('cloud_bucket_timeout', 10)}
  cloud_enum_threads: {t.get('cloud_enum_threads', 8)}
  cloud_enum_timeout: {t.get('cloud_enum_timeout', 900)}
  js_secrets_max_files: {t.get('js_secrets_max_files', 0)}
  js_secrets_concurrency: {t.get('js_secrets_concurrency', 15)}
  js_secrets_request_timeout: {t.get('js_secrets_request_timeout', 12)}
  js_secrets_budget_sec: {t.get('js_secrets_budget_sec', 0)}
  crtsh_timeout: {t.get('crtsh_timeout', 20)}
  dnsx_enabled: {str(t.get('dnsx_enabled', True)).lower()}
"""
    p.write_text(_tpl, encoding="utf-8")

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

_DALFOX_CAPS_CACHE = {}
def _dalfox_caps() -> dict:
    r"""v8.5-fix: REPLACES the old version-string probe (previously named
    _dalfox_major_version — ran "dalfox --version"/"-V"/"version" and
    regex-matched a version number like v2.12.0/v3.2.2 out of whatever text
    came back, then used major>=3 to decide which flags to send).

    That approach caused a real, confirmed production bug: against the
    user's actual dalfox v2.12.0 (Go/cobra) install, it misdetected as v3+
    and sent v3-only flags (--headers plural, --state-file) that v2 doesn't
    recognize. cobra fails a scan like that IMMEDIATELY with a "unknown
    flag" parse error — prints the error plus full usage/help text (~80
    lines) to stderr and exits, without ever opening the -o/--output JSON
    file. Worse, because the SAME wrong detection also switched the
    "acceptable exit code" set to (0, 1, None) — v3 legitimately exits 1
    when it finds vulnerabilities — that flag-parse-error exit (cobra's
    default is 1) was silently accepted as a normal "ran clean, 0 findings"
    result instead of being flagged as a tool failure. That exactly matches
    every symptom from the real report: a "complete" (non-interrupted) scan
    finishing in ~0.1s, 0 findings, ~82 output lines, no dalfox_scan.json
    ever written — even against a target confirmed vulnerable by hand.
    Exactly what polluted the old version regex was never pinned down (a
    colored ASCII banner and/or an update-notifier line such as "a new
    version vX.Y.Z is available", which some Go CLIs print on every run
    before the real version, are the likely candidates) — but rather than
    patch that guesswork further, this probes the one thing that actually
    determines correctness: which flags "dalfox file --help" documents for
    THIS binary, on THIS machine, right now. That's the literal source of
    truth the real `dalfox file ...` command is built from, so there's
    nothing left for a stray banner/notifier line to corrupt.
    Only matches an actual flag DECLARATION line (e.g. "  -H, --headers
    <HEADERS>..." or "      --state-file <FILE>...") via ^\s*(-\w,\s*)?--x\b
    — never a bare substring — so a mention of "headers" in a description
    sentence elsewhere in the help text can't cause a false positive.
    Probed once (one subprocess call, with a -h fallback if --help itself
    errors) and cached. All fields default to the conservative,
    v2-compatible values if dalfox is missing or --help produced nothing
    usable — same fallback behavior as the old function had for "not found".
    """
    if "caps" in _DALFOX_CAPS_CACHE:
        return _DALFOX_CAPS_CACHE["caps"]
    caps = {"is_v3": False, "headers_flag": "--header", "state_file": False,
            "skip_mining_flags": set(), "skip_flags": set()}
    if tool_exists("dalfox"):
        txt = ""
        for args in (["dalfox", "file", "--help"], ["dalfox", "file", "-h"]):
            try:
                out = subprocess.run(args, capture_output=True, text=True, timeout=8)
                txt = (out.stdout or "") + (out.stderr or "")
                if txt.strip():
                    break
            except Exception:
                continue
        if re.search(r"(?m)^\s*(-\w,\s*)?--headers\b", txt):
            caps["is_v3"] = True
            caps["headers_flag"] = "--headers"
        if re.search(r"(?m)^\s*(-\w,\s*)?--state-file\b", txt):
            caps["state_file"] = True
        # v9.3: record which --skip-mining-* flags THIS binary documents, same
        # help-declaration probe as above — so passing one can never be an
        # "unknown flag" that kills the whole XSS stage on a version that
        # spelled them differently.
        for _mine in ("all", "dom", "dict"):
            if re.search(r"(?m)^\s*(-\w,\s*)?--skip-mining-" + _mine + r"\b", txt):
                caps["skip_mining_flags"].add(_mine)
        # v9.3: same probe for the two per-target cost trims we default on for an
        # XSS-focused stage — --skip-bav (dalfox's non-XSS "basic another vuln"
        # grep) and --skip-headless (its own chromedp DOM verification, which is
        # redundant with ReconX's separate headless XSS-proof step). Only added
        # when documented, so an absent flag can't kill the stage.
        for _sk in ("bav", "headless"):
            if re.search(r"(?m)^\s*(-\w,\s*)?--skip-" + _sk + r"\b", txt):
                caps["skip_flags"].add(_sk)
    _DALFOX_CAPS_CACHE["caps"] = caps
    return caps

_PRIVATE_HOST_CACHE = {}
# Names that are never in a public archive. .lab is not an ICANN TLD; the
# others are reserved for local use (RFC 6761 / RFC 6762).
_LOCAL_NAME_SUFFIXES = (
    ".local", ".localhost", ".lab", ".internal", ".lan", ".home",
    ".intranet", ".test", ".invalid", ".example",
)

def _is_private_or_local_host(host: str) -> bool:
    """True for a loopback/private/link-local address, a local-only name
    (.lab, .local, localhost), or a name whose every address is private.

    Archive tools (gau: wayback/commoncrawl/otx/urlscan) cannot have data
    for any of these. A previous run still spent 117s in gau against
    harbor.lab, because the check only looked at literal IP strings and
    the name itself is not an IP — it resolves to 127.0.0.1."""
    h = (host or "").strip().lower().rstrip(".")
    if not h or h in ("localhost", "localhost.localdomain"):
        return True
    if any(h.endswith(suf) for suf in _LOCAL_NAME_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified)
    except ValueError:
        pass
    cached = _PRIVATE_HOST_CACHE.get(h)
    if cached is not None:
        return cached
    private = False
    try:
        import socket
        infos = socket.getaddrinfo(h, None)
        flags = []
        for info in infos:
            try:
                ip = ipaddress.ip_address(info[4][0])
            except ValueError:
                continue
            flags.append(bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified))
        private = bool(flags) and all(flags)
    except Exception:
        private = False
    _PRIVATE_HOST_CACHE[h] = private
    return private

def _pd_httpx():
    for cand in ("httpx-toolkit", "httpx"):
        path = shutil.which(cand)
        if not path:
            continue
        hh = _help_text(cand)
        if re.search(r"-l\b\s*,?\s*-list|-l\s*,|--list|list\s*string", hh or ""):
            return cand
    return None

def _env_api_key(key: str) -> str:
    """Return an API key from the environment — e.g. RECONX_CENSYS_KEY."""
    env_map = {
        # The AI analyst reads the SDK's own standard variable first, so an
        # environment already set up for the Anthropic API just works.
        "anthropic": "ANTHROPIC_API_KEY",
        "censys": "RECONX_CENSYS_KEY",
        "chaos": "RECONX_CHAOS_KEY",
        "github": "RECONX_GITHUB_TOKEN",
        "securitytrails": "RECONX_SECURITYTRAILS_KEY",
        "virustotal": "RECONX_VT_KEY",
    }
    env_name = env_map.get(key.lower(), f"RECONX_{key.upper()}_KEY")
    return (os.environ.get(env_name) or "").strip()

def get_api_key(cfg, key: str) -> str:
    """Resolve an API key: config.yaml first, then the ENV fallback."""
    v = (cfg.get("api_keys", {}) or {}).get(key, "") or ""
    v = str(v).strip()
    if v and v.lower() not in {"", "your_key_here", "change_me", "none", "null"}:
        return v
    return _env_api_key(key)

def has_valid_api_key(cfg, key):
    v = get_api_key(cfg, key)
    bad = {"", "your_key_here", "change_me", "none", "null", "your_censys_api_key"}
    return bool(v) and v.strip().lower() not in bad

# ══════════════════════════════════════════════════════════════════════════════
# Nuclei template path discovery
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

def _dir_has_templates(p: Path, min_count: int = 1) -> bool:
    """En az bir gecerli .yaml template dosyasi iceriyor mu? Bos/bozuk dizinleri
    (orn. network kesintisi yuzunden nuclei'nin olusturdugu bos klasor) reddeder."""
    try:
        if not p.exists() or not p.is_dir():
            return False
        for i, _ in enumerate(p.rglob("*.yaml")):
            if i + 1 >= min_count:
                return True
        return False
    except Exception:
        return False

def discover_nuclei_templates(cfg_override: str = "") -> str:
    if cfg_override and cfg_override.strip():
        p = Path(cfg_override.strip())
        if _dir_has_templates(p):
            ok(f"Nuclei templates (config): {p}")
            return str(p)
        elif p.exists() and p.is_dir():
            warn(f"Nuclei template path in config is empty/invalid (no templates): {p} — auto-detecting")
        else:
            warn(f"Nuclei template path in config not found: {p} — auto-detecting")

    for candidate in _NUCLEI_TEMPLATE_CANDIDATES:
        p = Path(candidate)
        if _dir_has_templates(p):
            ok(f"Nuclei templates found: {p} ({len(list(p.rglob('*.yaml'))):,} templates)")
            return str(p)

    try:
        r = subprocess.run(
            ["nuclei", "-tl"],
            capture_output=True, text=True, timeout=15
        )
        out = (r.stdout or "") + (r.stderr or "")
        for line in out.splitlines():
            line = line.strip()
            if "/" in line and _dir_has_templates(Path(line)):
                ok(f"Template catalog: {line}")
                return line
    except Exception:
        pass

    try:
        r = subprocess.run(
            ["find", "/root", str(Path.home()), "/opt", "/usr",
             "-maxdepth", "6", "-type", "d", "-name", "nuclei-templates",
             "-not", "-path", "*/\\.git/*"],
            capture_output=True, text=True, timeout=20
        )
        for line in r.stdout.splitlines():
            line = line.strip()
            if line and _dir_has_templates(Path(line)):
                ok(f"Nuclei templates (find): {line}")
                return line
    except Exception:
        pass

    warn("Nuclei template path not found (or the ones found are empty) — nuclei "
         "will fall back to its own built-in template set")
    return ""


# v8.10: verdicts for the secret candidates stage 10 finds. Optional: a missing
# or broken reconx_secrets.py leaves the raw candidate list exactly as it was.
try:
    import reconx_secrets as _secret_triage
except Exception:
    _secret_triage = None


# ── Interactive prompt ─────────────────────────────────────────────────────────
def ask_yes_no(question, default="y"):
    is_yes = default.lower() in ("y", "e", "yes", "evet")
    if not sys.stdin.isatty():
        return is_yes
    hint = "[Y/n]" if is_yes else "[y/N]"
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
        warn("Please answer y or n.")

# ── Interrupt State ───────────────────────────────────────────────────────────
# v8.8: Ctrl+C artik "yumusak/sert" iki durumlu bir tahminden ibaret degil —
# her basisinda interaktif, 3 secenekli bir menu gosterir:
#   1) stage'i atla     -> o ana kadar toplanan veriler kaydedilir, bir sonraki
#                          stage'den normal akista devam edilir
#   2) sadece bu islemi atla -> yalnizca su an calisan tek arac/istek durur,
#                          mevcut stage'in geri kalani degismeden surer
#   3) araci tamamen durdur -> pipeline durur, toplanan kismi veriyle rapor
#                          yine de uretilir
# Eskiden tek olan `_tool` bayragi bu yuzden ikiye ayrildi:
#   _op_skip    -> GECICI: sadece "su an calisan tek islem" durdurulsun.
#                  Ilgili _run_once/_stream_tool cagrisi bittigi an
#                  reset_op() ile otomatik temizlenir.
#   _stage_skip -> STAGE BOYUNCA KALICI: mevcut stage'in KALAN tum
#                  donguleri/komutlari kirilir; pipeline bir sonraki
#                  stage'e gecince main driver reset_stage() ile temizler.
#   _hard       -> SUREC SONUNA KADAR KALICI: pipeline tamamen durur.
# Signal handler'in kendisi print()/input() YAPMAZ (sinyal-guvenli degil,
# ayrica _spinner/_stream_tool'un stdout yazmalariyla yarisa girer) — sadece
# bir Event set eder; asil menu ayri bir arka plan "watcher" thread'inde
# gosterilir.
class _IS:
    _op_skip    = False
    _stage_skip = False
    _hard       = False
    _raw_sigint = threading.Event()
    _watcher_started = False
    _last_sigint = 0.0
    _notice      = ""
    DOUBLE_TAP_SEC = 2.0

    @classmethod
    def reset_op(cls):
        cls._op_skip = False

    @classmethod
    def reset_stage(cls):
        cls._stage_skip = False

    @classmethod
    def reset(cls):
        # Also used well away from interrupts (e.g. defensive cleanup after a
        # declined y/n prompt), so it clears both flags.
        cls.reset_op()
        cls.reset_stage()

    @classmethod
    def op_skip(cls):
        return cls._op_skip

    @classmethod
    def stage_skip(cls):
        return cls._stage_skip or cls._hard

    @classmethod
    def interrupted(cls):
        return cls._op_skip or cls._stage_skip or cls._hard

    @classmethod
    def hard(cls):
        return cls._hard

    @classmethod
    def handle(cls, sig, frm):
        """SIGINT. Does the decision itself — no menu, no prompt, no stdin.

        The handler only flips flags and wakes the printer thread: it runs in
        the main thread between bytecodes, so anything slower (and stdin in
        particular) would stall whatever the scan was doing."""
        if cls._hard:
            return
        now = time.time()
        if now - cls._last_sigint <= cls.DOUBLE_TAP_SEC:
            cls._hard = True
            cls._notice = "hard"
        else:
            cls._notice = "skip"
        cls._op_skip = True
        cls._stage_skip = True
        cls._last_sigint = now
        cls._raw_sigint.set()

    @classmethod
    def _watch_loop(cls):
        """Prints what the handler decided. Printing is done here rather than in
        the handler so it can take _PRINT_LOCK and pause the spinner without
        doing that work inside a signal context."""
        while True:
            cls._raw_sigint.wait()
            cls._raw_sigint.clear()
            note = cls._notice
            cls._notice = ""
            _SPINNER_PAUSE.set()
            try:
                with _PRINT_LOCK:
                    sys.stdout.write("\r" + " " * 100 + "\r")
                    if note == "hard":
                        print(f"{C.RED}{C.BOLD}[✗] Ctrl+C again — stopping. Checkpointing and "
                              f"building a report from what was collected...{C.RESET}", flush=True)
                    elif note == "skip":
                        print(f"{C.YELLOW}{C.BOLD}[!] Ctrl+C — skipping this stage.{C.RESET} "
                              f"{C.DIM}Everything collected so far is saved; the pipeline continues "
                              f"with the next stage. Press Ctrl+C again within "
                              f"{cls.DOUBLE_TAP_SEC:.0f}s to stop the tool.{C.RESET}", flush=True)
            finally:
                _SPINNER_PAUSE.clear()

    @classmethod
    def start_watcher(cls):
        if cls._watcher_started:
            return
        cls._watcher_started = True
        threading.Thread(target=cls._watch_loop, daemon=True, name="reconx-interrupt-watcher").start()

_INT = _IS
_INT.start_watcher()
# signal.signal() is only legal on the main thread. The report bridge imports
# this module from a request thread (URL identity for the evidence pack). Doing
# the registration there used to raise ValueError and the AI run died instantly.
if threading.current_thread() is threading.main_thread():
    signal.signal(signal.SIGINT,  _INT.handle)
    def _sigterm_handler(s, f):
        if _INT._hard:
            return
        _INT._hard = True
        _INT._op_skip = True
        _INT._stage_skip = True
        _INT._notice = "hard"
        _INT._raw_sigint.set()
        print(f"\n{C.RED}[✗] Stop requested — checkpointing and writing findings into the report{C.RESET}",
              flush=True)
    signal.signal(signal.SIGTERM, _sigterm_handler)

# ── Tor-based auto IP rotation (block-triggered fallback) ────────────────────
# v8.8: normal, engellenmeyen istekler HER ZAMAN dogrudan (ya da kullanicinin
# kendi settings.proxy'si uzerinden) gider — Tor SADECE bir WAF/rate-limit
# engeli fiilen tespit edildiginde (bkz. ReconPipeline._apply_adaptive)
# devreye giren bir fallback'tir, varsayilan taramayi yavaslatmaz. Kendi
# izole SOCKS/Control portlarini ve kendi torrc/veri dizinini (.tor_data/)
# kullanir — sistem genelinde ayrica calisan bir Tor kurulumuyla CAKISMAZ.
_TOR_ACTIVE = threading.Event()

def _resolve_proxy(cfg: dict) -> str:
    """Her requests-tabanli cagrinin proxy secimi icin TEK dogru kaynak.
    Kullanicinin ayarladigi settings.proxy HER ZAMAN kazanir; o bos ve bu
    calistirmada Tor rotasyonu en az bir kez tetiklenmisse (_TOR_ACTIVE)
    yerel Tor SOCKS proxy'sine dusulur; ikisi de yoksa dogrudan baglanti
    kullanilir (bos string doner)."""
    explicit = str(_cfg_get(cfg, "settings", "proxy", default="") or "").strip()
    if explicit:
        return explicit
    if _TOR_ACTIVE.is_set():
        port = int(_cfg_get(cfg, "settings", "tor_socks_port", default=9060) or 9060)
        return f"socks5h://127.0.0.1:{port}"
    return ""

# Native proxy destegi --help ile DOGRULANMIS CLI araclari (bkz. plan) — bu
# aracin native proxy bayragi olmayan digerleri (assetfinder/findomain/gau/
# whatweb/nmap/wafw00f/...) icin bilerek dokunulmuyor: yanlis bir bayrak
# eklemek o araci komple cokertir.
_TOR_CLI_PROXY_FLAG = {"nuclei": "-proxy", "dalfox": "--proxy", "katana": "-proxy", "subfinder": "-proxy"}

_NUCLEI_SOCKS_REWRITTEN = False

def _nuclei_proxy(proxy: str) -> str:
    """nuclei 3.11 accepts only http[s]:// and socks5://. socks5h:// (remote DNS,
    what curl and the requests stack use) is rejected at startup:
    'invalid proxy format' and exit 1 in well under a second, before any
    template is loaded. The TCP connection still goes through the proxy;
    nuclei itself resolves the name."""
    global _NUCLEI_SOCKS_REWRITTEN
    p = (proxy or "").strip()
    if p.lower().startswith("socks5h://"):
        fixed = "socks5://" + p[len("socks5h://"):]
        if not _NUCLEI_SOCKS_REWRITTEN:
            _NUCLEI_SOCKS_REWRITTEN = True
            warn("Nuclei rejects socks5h:// — using socks5:// so the scan can start. "
                 "The connection still uses the proxy; nuclei resolves DNS itself.")
        return fixed
    return p

_NUCLEI_PROXY_SKIPPED = False

def _local_proxy_open(proxy: str) -> bool:
    """True unless this is a local proxy whose port is refusing connections.
    A dead Tor SOCKS port makes nuclei exit 1 in under a second ('all proxies
    are dead') and the stage then reports zero findings."""
    try:
        u = urlparse(proxy)
        host = (u.hostname or "").lower()
        port = u.port
        if host not in ("127.0.0.1", "localhost", "::1") or not port:
            return True
        import socket
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except Exception:
        return False

def _tor_cli_flag(tool: str, cfg: dict) -> list:
    """Tor aktif degilse veya proxy cozulemiyorsa bos liste (davranis degismez)."""
    global _NUCLEI_PROXY_SKIPPED
    if not _TOR_ACTIVE.is_set():
        return []
    proxy = _resolve_proxy(cfg)
    flag = _TOR_CLI_PROXY_FLAG.get(tool)
    if not (proxy and flag):
        return []
    if tool == "nuclei":
        proxy = _nuclei_proxy(proxy)
        if not _local_proxy_open(proxy):
            if not _NUCLEI_PROXY_SKIPPED:
                _NUCLEI_PROXY_SKIPPED = True
                warn(f"Nuclei proxy {proxy} is not accepting connections — "
                     "scanning directly so a dead proxy does not abort the stage.")
            return []
    return [flag, proxy]


def _nuclei_log_cb(path: Path, fatal: dict):
    """Append nuclei's own stdout/stderr to the run log and keep the fatal line."""
    def cb(line: str):
        text = strip_ansi(line or "").rstrip()
        if text and ("[FTL]" in text or "Program exiting" in text or "[ERR]" in text):
            fatal["line"] = text[:500]
        try:
            with path.open("a", encoding="utf-8") as fo:
                fo.write(text + "\n")
        except Exception:
            pass
    return cb


class _TorManager:
    """v8.8: hedef/WAF tarama aracini engelledigini tespit ettiginde (bkz.
    ReconPipeline._apply_adaptive), kendi yonettigi izole bir Tor sureci
    lazy olarak baslatir ve devreyi (ControlPort -> SIGNAL NEWNYM) degistirip
    IP'yi yeniler; tarama kaldigi yerden Tor SOCKS proxy'si uzerinden devam
    eder. Normal, hic engellenmeyen bir tarama Tor'a hic dokunmaz — sadece
    config'de auto_tor:true ve gercek bir blok sinyali oldugunda calisir.
    Gereksinim: `tor` (apt) + `stem` (pip) — ./install.sh kurar; ikisinden
    biri eksikse sessizce devre disi kalir, tarama normal (Tor'suz) devam eder.
    """

    def __init__(self, cfg: dict, log=None):
        self.cfg = cfg
        self.log = log
        self.enabled = bool(_cfg_get(cfg, "settings", "auto_tor", default=True))
        self.socks_port = int(_cfg_get(cfg, "settings", "tor_socks_port", default=9060) or 9060)
        self.control_port = int(_cfg_get(cfg, "settings", "tor_control_port", default=9061) or 9061)
        self.max_rotations = int(_cfg_get(cfg, "settings", "tor_max_rotations_per_stage", default=5) or 5)
        self.data_dir = BASE_DIR / ".tor_data"
        self.torrc_path = self.data_dir / "torrc"
        self.password = str(_cfg_get(cfg, "settings", "tor_control_password", default="") or "").strip()
        self._proc = None
        self._controller = None
        self.rotations_this_stage = 0
        self.total_rotations = 0
        self._last_rotation_ts = 0.0
        self._start_lock = threading.Lock()
        self._started = False
        self._start_failed = False

    def reset_stage_counter(self):
        self.rotations_this_stage = 0

    def _write_torrc(self) -> str:
        """.tor_data/torrc + HashedControlPassword'u ilk calistirmada uretir,
        sonraki calistirmalarda ayni parolayi tekrar kullanir."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "data").mkdir(parents=True, exist_ok=True)
        if not self.password:
            pw_f = self.data_dir / "control_password.txt"
            if pw_f.exists() and pw_f.stat().st_size > 0:
                self.password = pw_f.read_text(encoding="utf-8").strip()
            else:
                import secrets as _secrets
                self.password = _secrets.token_hex(16)
                pw_f.write_text(self.password, encoding="utf-8")
                try:
                    os.chmod(pw_f, 0o600)
                except Exception:
                    pass
        hashed = ""
        try:
            hp = subprocess.run(["tor", "--hash-password", self.password],
                                 capture_output=True, text=True, timeout=15)
            lines = [l.strip() for l in (hp.stdout or "").splitlines() if l.strip().startswith("16:")]
            if lines:
                hashed = lines[-1]
        except Exception:
            hashed = ""
        torrc = (
            f"SocksPort {self.socks_port}\n"
            f"ControlPort {self.control_port}\n"
            f"DataDirectory {self.data_dir / 'data'}\n"
            f"PidFile {self.data_dir / 'tor.pid'}\n"
            f"Log notice file {self.data_dir / 'tor.log'}\n"
        )
        torrc += f"HashedControlPassword {hashed}\n" if hashed else "CookieAuthentication 1\n"
        self.torrc_path.write_text(torrc, encoding="utf-8")
        return str(self.torrc_path)

    def ensure_started(self) -> bool:
        if self._started:
            return True
        if self._start_failed or not self.enabled:
            return False
        with self._start_lock:
            if self._started:
                return True
            if self._start_failed:
                return False
            if not tool_exists("tor"):
                warn("Tor is not installed (run ./install.sh) — automatic IP rotation disabled")
                self._start_failed = True
                return False
            try:
                from stem.control import Controller
                from stem import Signal  # noqa: F401
            except Exception:
                warn("Python package 'stem' is missing (pip install stem) — automatic IP rotation disabled")
                self._start_failed = True
                return False
            try:
                torrc = self._write_torrc()
                info(f"Starting Tor (isolated SOCKS:{self.socks_port} / Control:{self.control_port})...")
                self._proc = subprocess.Popen(["tor", "-f", torrc],
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                deadline = time.time() + 30
                bootstrapped = False
                log_f = self.data_dir / "tor.log"
                while time.time() < deadline:
                    if self._proc.poll() is not None:
                        break
                    if log_f.exists() and "Bootstrapped 100%" in log_f.read_text(errors="ignore"):
                        bootstrapped = True
                        break
                    time.sleep(0.5)
                if not bootstrapped:
                    warn("Tor 30s icinde bootstrap olamadi — otomatik IP rotasyonu devre disi")
                    self.stop()
                    self._start_failed = True
                    return False
                self._controller = Controller.from_port(port=self.control_port)
                try:
                    self._controller.authenticate(password=self.password)
                except Exception:
                    self._controller.authenticate()
                _TOR_ACTIVE.set()
                self._started = True
                ok(f"Tor ready — blocked requests will now go through socks5h://127.0.0.1:{self.socks_port}")
                return True
            except Exception as e:
                warn(f"Tor baslatilamadi: {e} — otomatik IP rotasyonu devre disi")
                if self.log:
                    self.log.warning(f"Tor start failed: {e}")
                self.stop()
                self._start_failed = True
                return False

    def rotate(self, reason: str) -> bool:
        if not self.ensure_started():
            return False
        if self.rotations_this_stage >= self.max_rotations:
            warn(f"Tor rotasyon limiti asildi (max={self.max_rotations}/stage) — "
                 f"rotasyon yapilmadan devam ediliyor")
            return False
        if (time.time() - self._last_rotation_ts) < 10:
            return False  # Tor kendi NEWNYM'ini zaten ~10s'de bir sinirliyor
        try:
            from stem import Signal
            self._controller.signal(Signal.NEWNYM)
            self._last_rotation_ts = time.time()
            self.rotations_this_stage += 1
            self.total_rotations += 1
            info(f"Tor circuit renewed (new exit IP) — reason: {reason}")
            time.sleep(2)  # yeni devrenin kurulmasi icin kisa bekleme
            return True
        except Exception as e:
            warn(f"Tor NEWNYM sinyali basarisiz: {e}")
            return False

    def stop(self):
        try:
            if self._controller:
                self._controller.close()
        except Exception:
            pass
        self._controller = None
        try:
            if self._proc and self._proc.poll() is None:
                self._proc.terminate()
                self._proc.wait(timeout=5)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass

# ── Timeouts ──────────────────────────────────────────────────────────────────
# Per-tool WALL-CLOCK ceiling in seconds. Hitting one kills that tool and the
# stage continues with whatever it produced — so a ceiling set too low reads
# back as "the target has nothing", which is the worst failure mode this tool
# has. v9.2 raised the real scanners to 2-3h (nuclei to 6h, since v9.0 feeds it
# the whole live-URL corpus instead of a handful of host roots).
#
# A few entries deliberately stay short. whois, the login POST and the
# interactsh registration are single request/response exchanges: they answer in
# seconds or they are broken, and a 3-hour ceiling on a broken one just hangs
# the stage for 3 hours before reaching the same conclusion. They are raised
# enough to survive a slow or rate-limited server, not more.
#
# Every value here is overridable from config.yaml under `timeouts:` — see
# apply_timeout_overrides(). Two other limits still apply on top and are NOT
# affected by raising these:
#   * --max-time, the global wall-clock budget for the whole scan;
#   * the stall watchdog on nuclei/dalfox, which stops a tool that has printed
#     nothing for N seconds regardless of how much of its ceiling is left.
T = {
    # quick metadata lookups — see the note above on why these stay short
    "whois": 300,                 # 5m
    "wafw00f": 900,               # 15m
    "login": 180,                 # 3m
    "interactsh_startup": 60,     # 1m
    # fingerprinting / enumeration
    "whatweb": 3600,              # 1h
    "assetfinder": 3600,          # 1h
    "findomain": 3600,            # 1h
    "subfinder": 7200,            # 2h — large estates with many sources
    "extra_checks": 7200,         # 2h
    # the heavy passes
    "nmap": 10800,                # 3h — a full port scan genuinely takes hours
    "httpx": 10800,               # 3h — probes every subdomain, prunes every URL
    "gau": 10800,                 # 3h — archive pulls are slow on big domains
    "katana": 10800,              # 3h — deep crawl
    "arjun": 10800,               # 3h
    "dalfox": 10800,              # 3h
    "nuclei_dast": 14400,         # 4h
    "nuclei": 21600,              # 6h — now scans the FULL live-URL corpus
}


def apply_timeout_overrides(cfg: dict) -> list:
    """Let config.yaml's `timeouts:` block override T, in seconds.

    Kept out of load_config() so T stays a plain module-level dict that any
    caller can read without a config in hand. Returns the keys that were
    actually changed, so the scan can say so instead of silently using a
    different ceiling than the code shows.
    """
    changed = []
    raw = (cfg or {}).get("timeouts")
    if not isinstance(raw, dict):
        return changed
    for key, val in raw.items():
        k = str(key).strip()
        if k not in T:
            warn(f"config timeouts.{k}: unknown tool — ignored "
                 f"(valid: {', '.join(sorted(T))})")
            continue
        try:
            sec = int(val)
        except (TypeError, ValueError):
            warn(f"config timeouts.{k}: '{val}' is not a number — ignored")
            continue
        if sec <= 0:
            warn(f"config timeouts.{k}: must be > 0 — ignored")
            continue
        if sec != T[k]:
            T[k] = sec
            changed.append(k)
    return changed

# ── Tecknoloji risk agirlik tablosu (stage 11) ────────────────────────────────
_TECH_RISK = [
    (r"wordpress",              40, "CMS — eklenti/tema yuzeyi genis, cok saldiri yuzeyi"),
    (r"joomla",                 32, "CMS — eklenti zafiyetleri yaygin"),
    (r"drupal",                 32, "CMS — core/module zafiyetleri"),
    (r"phpmyadmin",             50, "DB yonetim arayuzu — brute/loophole hedefi"),
    (r"adminer",                50, "Tek dosya DB yonetim — niche hedef"),
    (r"php\b",                  30, "PHP backend — eski surumler riskli"),
    (r"laravel",                30, "PHP framework — debug/public key riskleri"),
    (r"django",                 28, "Python framework — SECRET_KEY/DEBUG riski"),
    (r"flask",                  24, "Python micro-framework — SECRET_KEY"),
    (r"node\.js|nodejs",        26, "Node.js runtime"),
    (r"express",                22, "Node.js framework — header/route misconfig"),
    (r"java",                   24, "Java backend — eski surumler (log4j vb.) riskli"),
    (r"spring",                 30, "Spring framework — Actuator/SpEL"),
    (r"struts",                 40, "Apache Struts — RCE Gecmisi (CVE arastirilmali)"),
    (r"log4j",                  46, "Log4Shell ailesi — eski surumler kritik RCE"),
    (r"tomcat",                 30, "Servlet kapsayici — manager/exploit yuzeyi"),
    (r"jenkins",                48, "CI/CD — script console/ACL riski yuksek"),
    (r"gitlab",                 42, "Kod barindirma — auth/RCE gecmisi"),
    (r"confluence",             38, "Atlassian wiki — CVE yuzeyi zengin"),
    (r"elasticsearch",          34, "ES — gpgz auth + Kibana RCE kombinasyonu"),
    (r"kibana",                 34, "Vis. panel — eski surum RCE"),
    (r"grafana",                34, "Panel — auth bypass/SQLi gecmisi"),
    (r"cpanel",                 42, "Panel — auth/ecsploit hedefi"),
    (r"plesk",                  40, "Panel — genis saldiri yuzeyi"),
    (r"apache",                 10, "Web sunucusu — misconfig/alt dizinler"),
    (r"nginx",                   8, "Web sunucusu — ters proxy config"),
    (r"iis",                    12, "Microsoft web sunucusu — legacy handlerlar"),
    (r"jquery",                  5, "JS kutuphanesi — eski surum <3.5 XSS"),
    (r"angular",                10, "JS framework — template injection riski"),
    (r"react",                   6, "JS framework — genel guvenli, ama client-secret riski"),
    (r"vue",                     5, "JS framework"),
    (r"bootstrap",               3, "CSS framework — dusuk risk"),
    (r"next\.js|nextjs",          18, "Next.js — SSR/route leakage, .env exposure"),
    (r"nuxt",                     16, "Nuxt.js — SSR config exposure"),
    (r"graphql",                  38, "GraphQL — introspection / batching / DoS riski"),
    (r"swagger|openapi",          36, "API docs — endpoint enumeration, auth bypass"),
    (r"oauth|saml|oidc",          30, "Auth provider — token/redirect misconfig"),
    (r"aws|amazon",               34, "AWS — bucket/key exposure, metadata SSRF"),
    (r"azure",                    32, "Azure — blob/SAS token exposure"),
    (r"gcp|google cloud",         30, "GCP — bucket/token exposure"),
    (r"firebase",                 36, "Firebase — open DB / auth misconfig"),
    (r"supabase",                 32, "Supabase — open anon key"),
    (r"vercel",                   12, "Vercel — deployment metadata"),
    (r"cloudflare",               10, "CDN — bypass headers, cache deception"),
]

# v6.13: teknoloji adindan nuclei -tags degerine esleme (hizli on-tarama icin)
_TECH_TO_NUCLEI_TAGS = [
    (r"wordpress",         "wordpress,wp-plugin,wp-theme"),
    (r"joomla",             "joomla"),
    (r"drupal",             "drupal"),
    (r"phpmyadmin",         "phpmyadmin"),
    (r"adminer",            "adminer"),
    (r"laravel",            "laravel"),
    (r"django",             "django"),
    (r"flask",              "flask"),
    (r"node\.js|nodejs|express", "nodejs,express"),
    (r"spring",             "springboot,spring"),
    (r"struts",             "struts"),
    (r"log4j",              "log4j"),
    (r"tomcat",             "tomcat"),
    (r"jenkins",            "jenkins"),
    (r"gitlab",             "gitlab"),
    (r"confluence",         "confluence,atlassian"),
    (r"elasticsearch",      "elasticsearch"),
    (r"kibana",             "kibana"),
    (r"grafana",            "grafana"),
    (r"cpanel",             "cpanel"),
    (r"plesk",              "plesk"),
    (r"apache",             "apache"),
    (r"nginx",              "nginx"),
    (r"iis",                "iis"),
]

_SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret": re.compile(r"(?i)aws_secret_access_key.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "gcp_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "github_token": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "slack_token": re.compile(r"xox[bpras]-[0-9A-Za-z-]{10,48}"),
    "stripe_key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    # v8.3-fix: this was "\\." (regex for a LITERAL BACKSLASH followed by
    # ANY character) instead of "\." (regex for a literal dot) — a raw
    # Python string r"\\." contains two backslash characters plus a period,
    # which the regex engine reads as "\\" (escaped backslash → matches one
    # literal '\') then "." (matches anything). A real JWT embedded in a JS/
    # HTML file uses plain periods as its 3-part separator ("eyJ...HEADER
    # ...PAYLOAD...SIGNATURE"), never a literal backslash — so this pattern
    # could NEVER match an actual JWT in the wild, silently. Verified: the
    # old pattern returns no match against a real sample JWT string; the
    # single-backslash version below (correct escaped-dot regex) matches it.
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----", re.I),
}
_TECH_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----", re.I)

# ── v6.13: Subdomain takeover fingerprint DB ──────────────────────────────────
# Her girdi: (cname_icerir, hizmet_adi, body_icinde_aranan_imzalar)
_TAKEOVER_FINGERPRINTS = [
    ("github.io",                 "GitHub Pages",        ["there isn't a github pages site here"]),
    ("herokuapp.com",             "Heroku",               ["no such app", "heroku | no such app"]),
    ("herokudns.com",             "Heroku",               ["no such app"]),
    ("s3.amazonaws.com",          "AWS S3",               ["nosuchbucket", "the specified bucket does not exist"]),
    ("s3-website",                "AWS S3 (website)",     ["nosuchbucket", "the specified bucket does not exist"]),
    ("azurewebsites.net",         "Azure App Service",    ["404 web site not found"]),
    ("cloudapp.net",              "Azure Cloud Service",  ["404 not found"]),
    ("blob.core.windows.net",     "Azure Blob Storage",   ["blobnotfound", "the specified blob does not exist"]),
    ("trafficmanager.net",        "Azure Traffic Manager",["the resource you are looking for has been removed"]),
    ("wordpress.com",             "WordPress.com",        ["do you want to register"]),
    ("ghost.io",                  "Ghost",                ["the thing you were looking for is no longer here"]),
    ("shopify.com",               "Shopify",              ["sorry, this shop is currently unavailable"]),
    ("myshopify.com",             "Shopify",              ["sorry, this shop is currently unavailable"]),
    ("unbounce.com",              "Unbounce",             ["the requested url was not found on this server"]),
    ("surge.sh",                  "Surge.sh",             ["project not found"]),
    ("bitbucket.io",              "Bitbucket Pages",      ["repository not found"]),
    ("zendesk.com",               "Zendesk",              ["help center closed"]),
    ("helpjuice.com",             "Helpjuice",            ["we could not find what you're looking for"]),
    ("wpengine.com",              "WP Engine",            ["the site you were looking for couldn't be found"]),
    ("pantheonsite.io",           "Pantheon",              ["404 error unknown site"]),
    ("fastly.net",                "Fastly",               ["fastly error: unknown domain"]),
    ("statuspage.io",             "Statuspage.io",        ["you are being"]),
    ("teamwork.com",              "Teamwork",              ["oops - we didn't find your site"]),
    ("desk.com",                  "Desk.com",              ["please try again or try zendesk"]),
    ("readme.io",                 "ReadMe.io",             ["project doesnt exist... yet!"]),
    ("uservoice.com",             "UserVoice",             ["this uservoice subdomain is currently available"]),
    ("cargocollective.com",       "Cargo Collective",      ["404 not found"]),
    ("smugmug.com",               "SmugMug",               ["not found"]),
    ("strikinglydns.com",         "Strikingly",            ["page not found - strikingly"]),
    ("tumblr.com",                "Tumblr",                ["there's nothing here"]),
    ("webflow.io",                "Webflow",               ["the page you are looking for doesn't exist"]),
    ("netlify.app",               "Netlify",               ["not found - request id"]),
    ("s3-website",                "AWS S3 Website",      ["nosuchbucket", "no such bucket"]),
    ("elasticbeanstalk.com",      "AWS Elastic Beanstalk", ["404 not found"]),
    ("cloudfront.net",            "AWS CloudFront",      ["bad request", "404 not found"]),
    ("azureedge.net",             "Azure CDN",           ["404 web site not found"]),
    ("azure-api.net",             "Azure API Mgmt",      ["404 not found"]),
    ("acm-validations.aws",       "AWS ACM Validation",  ["404 not found"]),
    ("hatenablog.com",            "HatenaBlog",          ["404 not found"]),
    ("helpscoutdocs.com",         "HelpScout",           ["no settings were found"]),
    ("agilecrm.com",              "AgileCRM",            ["sorry, this page is no longer available"]),
    ("proxydns.com",              "ProxyDNS",            ["404 not found"]),
]

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

# v8.5-fix: "reflection" was declared as a category (opened, written to
# report.html's "Categorised URLs" tabs) in categorise_streaming() below, but
# NOTHING in that function ever called _w("reflection", ...) — the file was
# created empty on every single scan and stayed that way, which is exactly
# why the report's Reflection tab showed 0 URLs even on a target (the vuln-lab)
# that has several genuinely reflection-prone endpoints (?q=, ?name=, ?host=).
# This is a parameter-NAME heuristic (not an actual reflection probe — ReconX
# doesn't send a probe request per URL at this stage) flagging query params
# commonly echoed back unescaped into HTML: search/text fields, redirect/
# callback targets, name/message/comment fields, etc. — i.e. exactly the
# "XSS candidates — high-signal params" the report tab already claims to be.
_REFLECTION_PARAM_NAMES = {
    "q", "s", "search", "query", "keyword", "keywords", "term", "text", "txt",
    "msg", "message", "comment", "comments", "name", "username", "uname", "email",
    "subject", "title", "content", "body", "desc", "description",
    "jsonp", "ref", "referrer", "referer", "host", "page", "view",
    "template", "lang", "locale", "tag",
    "input", "value", "error", "err", "feedback", "note", "reason",
}

def _has_reflection_param(qs: str) -> bool:
    try:
        pairs = parse_qsl(qs, keep_blank_values=True)
    except Exception:
        return False
    for k, _ in pairs:
        kl = (k or "").strip().lower()
        if kl in _REFLECTION_PARAM_NAMES:
            return True
        # tfSearch, searchQuery — the echoed field is the suffix, not the
        # whole name. Only the longer names, so "q"/"id" don't match everything.
        if _is_open_redirect_name(kl):
            continue
        if any(len(n) >= 5 and kl.endswith(n) for n in _REFLECTION_PARAM_NAMES):
            return True
    return False


_OPEN_REDIRECT_PARAM_NAMES = {
    "url", "next", "redirect", "redirect_uri", "redirect_url", "redirect_to",
    "return", "returl", "returnurl", "returnuri", "return_uri", "return_url",
    "returnto", "return_to", "dest", "destination", "continue", "continue_url",
    "goto", "target", "redir", "redir_url", "out", "to", "callback", "forward",
    "rurl", "go", "back", "backurl", "origin", "success_url", "checkout_url",
    "location", "next_url", "u", "image_url",
}

# One example per name. id=1 and id=2 are the same test. Search boxes stay in
# the XSS list; these names are the ones that usually hit a query.
_SQLI_PARAM_NAMES = {
    "id", "uid", "pid", "cid", "nid", "tid", "fid", "gid", "aid", "bid",
    "cat", "category", "item", "itemid", "product", "productid", "prod",
    "artist", "sort", "order", "orderby", "sortby", "filter", "column",
    "col", "table", "where", "news", "newsid", "thread", "forum", "num",
    "no", "pageid", "userid", "groupid",
}

_SQL_ERROR_RE = re.compile(
    r"(union(?:[\s/+]|%20)+all(?:[\s/+]|%20)+select|union(?:[\s/+]|%20)+select|"
    r"you have an error in your sql|sql syntax|mysql_|ora-\d{4,5}|"
    r"pg_query\(|sqlstate|odbc sql|ole db|microsoft jet database|"
    r"warning:\s*mysql|sqlexception|xp_cmdshell|information_schema)",
    re.I)


def _is_open_redirect_name(name: str) -> bool:
    n = (name or "").strip().lower()
    if not n or _is_xss_param_name(n):
        return False
    if n in _OPEN_REDIRECT_PARAM_NAMES or "redirect" in n:
        return True
    return n.endswith("url") or n.endswith("uri")


def _is_xss_param_name(name: str) -> bool:
    n = (name or "").strip().lower()
    if not n:
        return False
    if n in _REFLECTION_PARAM_NAMES:
        return True
    return any(len(tok) >= 5 and n.endswith(tok) for tok in _REFLECTION_PARAM_NAMES)


_DOM_PARAM_NAMES = {
    "callback", "jsonp", "hash", "fragment", "src", "href", "html", "template",
    "location", "dom", "redirect", "url", "next", "return", "returnurl", "returl",
    "return_url", "goto", "dest", "redir", "source", "document", "innerhtml",
}

_STORED_PARAM_NAMES = {
    "comment", "comments", "message", "msg", "content", "body", "title",
    "post", "review", "feedback", "desc", "description", "subject", "name",
    "note", "reply", "text", "guestbook",
}

_STORED_PATH_RE = re.compile(
    r"(comment|guestbook|forum|message|feedback|review|profile|contact|"
    r"register|reply|board|post|thread)",
    re.I)


def _is_dom_param_name(name: str) -> bool:
    n = (name or "").strip().lower()
    if not n:
        return False
    if n in _DOM_PARAM_NAMES or "redirect" in n or n.endswith("callback"):
        return True
    return n.endswith("url") or n.endswith("uri")


def _is_stored_param_name(name: str) -> bool:
    n = (name or "").strip().lower()
    return bool(n) and n in _STORED_PARAM_NAMES


def _is_stored_path(path: str) -> bool:
    return bool(_STORED_PATH_RE.search(path or ""))


def _xss_param_label(url: str) -> str:
    try:
        names = _xss_param_names(urlparse(url).query)
    except Exception:
        names = ()
    if names:
        return ", ".join(names)
    try:
        return urlparse(url).path or "/"
    except Exception:
        return url


def _xss_kind_label(url: str) -> str:
    try:
        pr = urlparse(url)
        names = _xss_param_names(pr.query)
        path = pr.path or ""
    except Exception:
        names, path = (), ""
    kinds = []
    if any(_is_xss_param_name(n) for n in names):
        kinds.append("reflected")
    if any(_is_dom_param_name(n) for n in names):
        kinds.append("dom")
    if any(_is_stored_param_name(n) for n in names) or (not names and _is_stored_path(path)):
        kinds.append("stored")
    return "+".join(kinds) or "parameter"


def _is_sqli_param_name(name: str) -> bool:
    n = (name or "").strip().lower()
    if not n:
        return False
    if n in _SQLI_PARAM_NAMES:
        return True
    return n.endswith("_id") and len(n) <= 24


def _url_has_sql_error(url: str) -> bool:
    try:
        blob = unquote(unquote(url or ""))
    except Exception:
        blob = url or ""
    return bool(_SQL_ERROR_RE.search(blob))


def _static_asset_path(path: str) -> bool:
    return bool(re.search(
        r"\.(txt|xml|jpg|jpeg|png|gif|css|ico|svg|map|pdf|zip|woff2?)$",
        path or "", re.I))

# v6.13: cloud storage bucket URL/hostname deseni
_PAT_CLOUD_BUCKET = re.compile(
    r'(?P<full>(?:https?:)?//?)?'
    r'(?P<bucket>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com'
    r'|s3\.amazonaws\.com/(?P<bucket2>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])'
    r'|storage\.googleapis\.com/(?P<bucket3>[a-z0-9][a-z0-9.\-_]{1,61}[a-z0-9])'
    r'|(?P<bucket4>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.blob\.core\.windows\.net',
    re.I,
)

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


def _split_host_port(s: str) -> tuple:
    """('harbor.lab', 8088) from 'harbor.lab:8088' or a URL. Port is None when
    the user did not name one. The bare host stays the scope key; the port is
    what HTTP probes must actually connect to."""
    raw = (s or "").strip()
    if not raw:
        return "", None
    probe = raw if "://" in raw else "http://" + raw
    try:
        parsed = urlparse(probe)
        host = (parsed.hostname or "").lower().rstrip(".")
        return host, parsed.port
    except Exception:
        return _extract_domain_from_any(raw), None


def _canon_url(url: str) -> str:
    """Same page with or without a trailing slash is one row."""
    parsed = urlparse((url or "").strip())
    host = (parsed.hostname or "").lower()
    if not host:
        return (url or "").strip().rstrip("/")
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or ""
    if path.endswith("/") and path != "/":
        path = path.rstrip("/")
    if path == "/":
        path = ""
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme}://{host}{port}{path}{query}"


def _etc_hosts_names(domain: str) -> list:
    """Names in /etc/hosts that are the target or a subdomain of it.

    Passive enum (subfinder, crt.sh) only sees public DNS. A lab or an
    internal name that exists solely in the hosts file is invisible to those
    tools, so the file is read as one more source."""
    dom = (domain or "").lower().rstrip(".")
    if not dom:
        return []
    path = Path("/etc/hosts")
    if not path.is_file():
        return []
    found = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    for line in lines:
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        for name in line.split()[1:]:
            name = name.rstrip(".")
            if name == dom or name.endswith("." + dom):
                found.append(name)
    return list(dict.fromkeys(found))

# ── WAF bypass header strategies ───────────────────────────────────────────────
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
    if not headers:
        return ""
    parts = []
    for k, v in headers.items():
        vv = _clean_hdr(v)
        kk = k.strip()
        if not kk or not vv:
            continue
        parts.append(f' -H "{kk}: {vv}"')
    return "".join(parts)

def _clean_hdr(v) -> str:
    return str(v).replace('"', '').replace("'", "").replace("$", "").replace("`", "")

def _hdr_args_nuclei(headers: dict) -> list:
    out = []
    for k, v in headers.items():
        kk = k.strip()
        vv = _clean_hdr(v)
        if not kk or not vv:
            continue
        out += ["-H", f"{kk}: {vv}"]
    return out

def _hdr_args_dalfox(headers: dict) -> list:
    # v8.4-fix: dalfox v3.x (Rust) renamed the repeatable custom-header flag
    # from "--header" (v2/Go) to "--headers" (v3) — confirmed against a real
    # v3.2.2 build: "--header" is REJECTED outright with a clap usage error
    # (exit code 2, instant failure, no scanning happens at all) while
    # "--headers" works identically (still repeatable, one per header).
    # Picking the wrong one on v3 would silently break the entire XSS stage
    # on every single run.
    # v8.5-fix: was gated on the old (buggy) version-string probe; now uses
    # a direct capability probe of "dalfox file --help" — see _dalfox_caps().
    flag = _dalfox_caps()["headers_flag"]
    out = []
    for k, v in headers.items():
        kk = k.strip()
        vv = _clean_hdr(v)
        if not kk or not vv:
            continue
        out += [flag, f"{kk}: {vv}"]
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

_PAGE_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PAGE_OBFUSCATED_RE = re.compile(
    r"([A-Za-z0-9._%+\-]{1,64})\s*(?:\[at\]|\(at\)|\{at\}|\sat\s)\s*([A-Za-z0-9.\-]+\.[A-Za-z]{2,})",
    re.I,
)
_PAGE_TEL_RE = re.compile(r"""(?:href=["']tel:|tel:)([^"'<>\s]+)""", re.I)
_PAGE_MAILTO_RE = re.compile(r"""mailto:([^"'?\s>]+)""", re.I)
_PAGE_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+\d{1,3}[\s.\-]?)?(?:\(?\d{2,4}\)?[\s.\-])\d{3,4}[\s.\-]\d{3,4}(?!\d)"
)
_SKIP_EMAIL_HOSTS = {
    "example.com", "example.org", "domain.com", "email.com", "sentry.io",
    "wixpress.com", "schema.org", "w3.org", "jquery.com", "github.com",
    "googleapis.com", "gstatic.com", "cloudflare.com", "wordpress.org",
}


def _page_identity(html_text: str) -> dict:
    """Title, public emails and phone numbers from a page already fetched."""
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html_text or "")
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if m:
        title = re.sub(r"<[^>]+>", " ", m.group(1))
        title = re.sub(r"\s+", " ", title).strip()[:180]
    emails, seen_e = [], set()
    found_emails = list(_PAGE_EMAIL_RE.findall(text))
    found_emails += [f"{a}@{b}" for a, b in _PAGE_OBFUSCATED_RE.findall(text)]
    found_emails += [unquote(m) for m in _PAGE_MAILTO_RE.findall(text)]
    for raw in found_emails:
        em = raw.lower().strip(".").strip()
        host = em.rsplit("@", 1)[-1]
        if host in _SKIP_EMAIL_HOSTS or host.endswith((
                ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js")):
            continue
        if any(host.endswith("." + skip) for skip in _SKIP_EMAIL_HOSTS):
            continue
        if em in seen_e:
            continue
        seen_e.add(em)
        emails.append(em)
        if len(emails) >= 12:
            break
    phones, seen_p = [], set()

    def _keep_phone(raw):
        digits = re.sub(r"\D", "", raw or "")
        if len(digits) < 10 or len(digits) > 15:
            return ""
        if not digits.startswith(("0", "90")):
            return ""
        if len(set(digits)) < 3:
            return ""
        pretty = re.sub(r"\s+", " ", (raw or "").strip())[:32]
        if pretty in seen_p:
            return ""
        seen_p.add(pretty)
        return pretty

    for raw in _PAGE_TEL_RE.findall(text):
        pretty = _keep_phone(unquote(raw))
        if pretty:
            phones.append(pretty)
    if len(phones) < 8:
        for raw in _PAGE_PHONE_RE.findall(text):
            pretty = _keep_phone(raw)
            if pretty:
                phones.append(pretty)
            if len(phones) >= 8:
                break
    if len(phones) < 8:
        for raw in re.findall(r"(?<!\d)(?:\+90[\s.\-]?)?0?\d{3}[\s.\-]?\d{3}[\s.\-]?\d{2}[\s.\-]?\d{2}(?!\d)", text):
            pretty = _keep_phone(raw)
            if pretty:
                phones.append(pretty)
            if len(phones) >= 8:
                break
    return {"title": title, "emails": emails, "phones": phones}


_CONTACT_PATHS = (
    "/iletisim", "/iletisim/", "/contact", "/contact/", "/contact-us",
    "/kunye", "/hakkimizda", "/about", "/about-us", "/communication",
    "/tr/iletisim", "/en/contact",
)
_CONTACT_URL_RE = re.compile(r"iletisim|contact|kunye|hakkimizda|about-us|reach-us|bize-ulas", re.I)


def lookup_nameservers(domain: str) -> list:
    """Public NS records. dig, then host. Empty when DNS has no answer."""
    domain = (domain or "").strip().rstrip(".")
    if not domain or _is_private_or_local_host(domain):
        return []
    found = []

    def _add(token):
        token = (token or "").strip().rstrip(".").lower()
        if token and "." in token and token not in found and not token[0].isdigit():
            found.append(token)

    for argv in (["dig", "+short", "NS", domain], ["host", "-t", "NS", domain]):
        if not tool_exists(argv[0]):
            continue
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        except Exception:
            continue
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            if "name server" in line.lower():
                _add(line.split()[-1])
            else:
                _add(line.split()[0])
        if found:
            break
    return found[:8]


def harvest_public_contacts(bases, cfg, extra_urls=None, blobs=None, limit=8) -> dict:
    """Emails and phone numbers published on the site: mailto/tel plus a few
    contact pages. Stops after `limit` page fetches."""
    emails, phones, sources = [], [], []
    seen_e, seen_p, seen_u = set(), set(), set()

    def _take_ident(ident, src):
        added = False
        for em in ident.get("emails") or []:
            if em not in seen_e:
                seen_e.add(em)
                emails.append(em)
                added = True
        for ph in ident.get("phones") or []:
            if ph not in seen_p:
                seen_p.add(ph)
                phones.append(ph)
                added = True
        if added and src and src not in sources:
            sources.append(src)

    for blob in blobs or []:
        _take_ident(_page_identity(str(blob)), "")
    urls = []
    for base in bases or []:
        base = (base or "").strip().rstrip("/")
        if not base.startswith("http"):
            continue
        urls.append(base + "/")
        urls.extend(base + path for path in _CONTACT_PATHS)
    for extra in extra_urls or []:
        if isinstance(extra, str) and extra.startswith("http"):
            urls.append(extra.split("#", 1)[0])
    fetched = 0
    for url in urls:
        if fetched >= limit:
            break
        if url in seen_u:
            continue
        seen_u.add(url)
        probe = http_probe(url, cfg or {}, timeout=8)
        fetched += 1
        if not probe.get("ok"):
            continue
        before = (len(emails), len(phones))
        _take_ident({"emails": probe.get("emails") or [], "phones": probe.get("phones") or []}, url)
        if (len(emails), len(phones)) != before and url not in sources:
            sources.append(url)
        # The homepage usually links the real contact page under a path we
        # did not guess. Queue a few of those before the fetch budget ends.
        if fetched == 1:
            try:
                client, is_cffi = _get_http_client(cfg or {})
                if client is not None:
                    kw = dict(timeout=8, allow_redirects=True, verify=False, headers=pick_header_strategy("", cfg or {}))
                    if is_cffi:
                        kw["impersonate"] = (cfg or {}).get("settings", {}).get("curl_cffi_impersonate", "chrome110")
                    page = client.get(url, **kw)
                    html = getattr(page, "text", "") or ""
                    for href in re.findall(r"""href=["']([^"'#]+)""", html, re.I):
                        if not _CONTACT_URL_RE.search(href):
                            continue
                        abs_u = urljoin(url, href).split("#", 1)[0]
                        if abs_u.startswith("http") and abs_u not in seen_u:
                            urls.insert(fetched, abs_u)
                            if sum(1 for u in urls if _CONTACT_URL_RE.search(u)) > 6:
                                break
            except Exception:
                pass
    return {"emails": emails[:16], "phones": phones[:8], "sources": sources[:12]}


def _merge_contacts(*parts) -> dict:
    emails, phones, sources = [], [], []
    seen_e, seen_p = set(), set()
    for part in parts:
        if not isinstance(part, dict):
            continue
        for em in part.get("emails") or []:
            em = str(em).strip().lower()
            if em and em not in seen_e:
                seen_e.add(em)
                emails.append(em)
        for ph in part.get("phones") or []:
            ph = str(ph).strip()
            if ph and ph not in seen_p:
                seen_p.add(ph)
                phones.append(ph)
        for src in part.get("sources") or []:
            if src and src not in sources:
                sources.append(src)
    return {"emails": emails[:16], "phones": phones[:8], "sources": sources[:12]}


def http_probe(url: str, cfg: dict, timeout: int = 15) -> dict:
    client, is_cffi = _get_http_client(cfg)
    if client is None:
        return {"ok": False, "error": "no_http_client"}
    settings = (cfg or {}).get("settings", {}) if isinstance(cfg, dict) else {}
    impersonate = settings.get("curl_cffi_impersonate", "chrome110")
    proxy = _resolve_proxy(cfg)
    jitter_max = float(settings.get("jitter_max", 0.0) or 0.0)
    host = _extract_domain_from_any(url) or ""
    headers = pick_header_strategy(host, cfg)
    if jitter_max > 0:
        time.sleep(random.random() * jitter_max)
    try:
        # v8.6: a recon scanner must not fail on a target's TLS cert —
        # expired / self-signed / hostname-mismatch certs are common on
        # staging + deliberately-vulnerable test sites (demo.testfire.net).
        kw = dict(timeout=timeout, allow_redirects=True, headers=headers, verify=False)
        if proxy:
            kw["proxies"] = {"http": proxy, "https": proxy}
        if is_cffi:
            kw["impersonate"] = impersonate
        r = client.get(url, **kw)
        hdrs = dict(getattr(r, "headers", {}) or {})
        status = int(getattr(r, "status_code", 0) or 0)
        body = ""
        try:
            body = (getattr(r, "text", "") or "")[:500000]
        except Exception:
            body = ""
        ident = _page_identity(body)
        waf = fingerprint_waf(hdrs, status=status, body_snip=body[:1200])
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
            "title": ident.get("title") or "",
            "emails": ident.get("emails") or [],
            "phones": ident.get("phones") or [],
        }
    except Exception as e:
        return {"ok": False, "client": "curl_cffi" if is_cffi else "requests",
                "error": str(e), "url": url, "proxy": proxy or ""}


def _flip_scheme(url: str) -> str:
    """http://host <-> https://host, path dropped. Empty when there is no scheme."""
    p = urlparse(url or "")
    if p.scheme not in ("http", "https") or not p.netloc:
        return ""
    other = "http" if p.scheme == "https" else "https"
    return urlunparse((other, p.netloc, "", "", "", ""))


_WW_SKIP = {
    "country", "ip", "script", "x-powered-by", "uncommonheaders",
    "redirectlocation", "via", "cookies", "status", "title",
}


def _techs_from_whatweb_blob(blob: str) -> list:
    """Plugin labels from one WhatWeb summary or one-line scan row."""
    blob = re.sub(r"^\s*\[\d{3}[^\]]*\]\s*", "", blob or "")
    out = []
    for part in blob.split(","):
        part = part.strip()
        if not part:
            continue
        name = part.split("[", 1)[0].strip()
        low = name.lower()
        if not name or low in _WW_SKIP or low.startswith("country"):
            continue
        if re.match(r"^\d{3}\b", name):
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
        elif bracket and bracket.lower() not in name.lower():
            ver = bracket.split()[0]
            label = f"{name} {ver}".strip() if ver else name
        else:
            label = name
        label = re.sub(r"\s+", " ", label).strip()
        if label and label not in out and len(label) <= 48:
            out.append(label)
    return out

# ── Webhook notification (v8.1) ────────────────────────────────────────────────
def send_webhook_notification(cfg: dict, target: str, summary: dict) -> bool:
    """Tarama bitince Slack/Discord-uyumlu bir webhook'a ozet gonderir.
    settings.webhook_url bos ise (varsayilan) tamamen sessiz kalir. Ag hatasi /
    yanlis URL taramayi ASLA dusurmemeli — bu yuzden her adim try/except icinde."""
    url = (_cfg_get(cfg, "settings", "webhook_url", default="") or "").strip()
    if not url:
        return False
    client, is_cffi = _get_http_client(cfg)
    if client is None:
        return False
    try:
        s7 = (summary or {}).get("stage7") or {}
        s6 = (summary or {}).get("stage6") or {}
        sev = s7.get("severity_counts") or {}
        crit = int(sev.get("critical", 0)); high = int(sev.get("high", 0))
        med  = int(sev.get("medium", 0))
        xss_n = int(s6.get("findings", 0) or 0)
        dast_n = int(s7.get("findings_dast", 0) or 0)
        alert = "🔴" if (crit or high) else ("🟡" if (med or xss_n or dast_n) else "🟢")
        lines = [
            f"{alert} *ReconX scan complete* — `{target}`",
            f"Nuclei: {crit} critical, {high} high, {med} medium ({dast_n} via DAST)  ·  "
            f"XSS: {xss_n}",
        ]
        text = "\n".join(lines)
        payload = {"text": text, "content": text}  # Slack uses "text", Discord uses "content"
        kw = dict(timeout=10, json=payload)
        kw["verify"] = False
        if is_cffi:
            kw["impersonate"] = (_cfg_get(cfg, "settings", "curl_cffi_impersonate", default="chrome120") or "chrome120")
        r = client.post(url, **kw)
        ok_ = int(getattr(r, "status_code", 0) or 0) < 400
        if ok_:
            ok("Webhook bildirimi gonderildi")
        else:
            warn(f"Webhook bildirimi basarisiz (HTTP {getattr(r, 'status_code', '?')})")
        return ok_
    except Exception as e:
        warn(f"Webhook bildirimi gonderilemedi: {e}")
        return False

# ── Blind XSS OOB callback (interactsh) ────────────────────────────────────────
# v8.2: Dalfox's "--blind" flag needs an internet-reachable callback URL that a
# victim's browser can call back to when a stored/blind XSS payload actually
# fires later (e.g. an admin viewing a payload in a dashboard). Self-hosting a
# listener would require a public IP + open inbound port on the tester's own
# machine, which is exactly what most home/office networks don't have (NAT/
# CGNAT) and isn't something ReconX should try to set up automatically anyway
# (that would mean poking a hole in the user's firewall). Instead we use
# interactsh (github.com/projectdiscovery/interactsh) — the same free, public,
# out-of-band interaction service already used across the ProjectDiscovery
# ecosystem (nuclei's own OOB templates rely on it). Its client only makes
# OUTBOUND connections to register a random subdomain and poll for hits, so it
# works from behind any NAT/firewall with zero configuration.
#
# We drive the real `interactsh-client` binary (not a hand-rolled re-implementation
# of its client-side crypto/registration protocol — verified against the actual
# source at github.com/projectdiscovery/interactsh, cmd/interactsh-client/main.go
# and pkg/server: the client.URL() output is a bare domain like
# "<id>.oast.fun" — no scheme prefix needed, dalfox accepts that directly — and
# "-json -o <file>" writes one JSON object per received interaction with fields
# {protocol, unique-id, full-id, remote-address, timestamp, raw-request,
# raw-response, ...}).
_INTERACTSH_DOMAIN_RE = re.compile(r'^[a-z0-9][a-z0-9.\-]{3,}\.[a-z]{2,}$', re.I)

def start_interactsh_session(work_dir: Path, poll_interval: int = 5):
    """Starts `interactsh-client` in the background and returns a session dict:
    {"available": bool, "process": Popen|None, "domain": str, "log_file": Path,
     "payload_file": Path, "error": str}.
    Non-fatal by design — any failure just returns available=False so the XSS
    stage can continue without a blind-XSS callback instead of aborting the scan."""
    session = {"available": False, "process": None, "domain": "", "log_file": None,
               "payload_file": None, "error": ""}
    if not tool_exists("interactsh-client"):
        session["error"] = "interactsh-client not found on PATH"
        return session
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
        payload_file = work_dir / "interactsh_url.txt"
        log_file = work_dir / "interactsh_interactions.jsonl"
        for f in (payload_file, log_file):
            try:
                if f.exists():
                    f.unlink()
            except Exception:
                pass
        cmd = [
            "interactsh-client",
            "-n", "1",
            "-poll-interval", str(max(1, int(poll_interval or 5))),
            "-keep-alive-interval", "1m",
            "-json", "-o", str(log_file),
            "-payload-store", "-payload-store-file", str(payload_file),
            "-disable-update-check",
        ]
        proc = subprocess.Popen(
            cmd, shell=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        session["process"] = proc
        # The client writes its generated domain to payload_file as soon as
        # registration with the interactsh server succeeds. Poll for it with a
        # short timeout instead of parsing banner text off stdout/stderr — far
        # more robust across client versions.
        deadline = time.time() + T.get("interactsh_startup", 20)
        domain = ""
        while time.time() < deadline:
            if proc.poll() is not None:
                session["error"] = f"interactsh-client exited early (code {proc.returncode})"
                return session
            if payload_file.exists():
                try:
                    domain = payload_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()[0].strip()
                except Exception:
                    domain = ""
                if domain and _INTERACTSH_DOMAIN_RE.match(domain):
                    break
            time.sleep(0.3)
        if not domain or not _INTERACTSH_DOMAIN_RE.match(domain):
            session["error"] = "timed out waiting for interactsh-client to register a domain"
            _kill_tree(proc, grace=1.0)
            return session
        session.update(available=True, domain=domain, log_file=log_file, payload_file=payload_file)
        return session
    except Exception as e:
        session["error"] = str(e)
        return session


def stop_interactsh_session(session: dict, extra_listen_sec: int = 0):
    """Optionally keeps polling for `extra_listen_sec` more seconds (to catch a
    delayed/stored XSS callback that fires after dalfox's own request phase is
    done), then terminates the background client. Interruptible via _INT so
    Ctrl+C during this grace period doesn't hang the shutdown."""
    if not session or not session.get("available") or not session.get("process"):
        return
    proc = session["process"]
    if extra_listen_sec > 0:
        info(f"Listening for delayed blind XSS callbacks for {extra_listen_sec}s more...")
        deadline = time.time() + extra_listen_sec
        while time.time() < deadline:
            if _INT.hard() or _INT.interrupted():
                break
            if proc.poll() is not None:
                break
            time.sleep(0.5)
    _kill_tree(proc, grace=5.0)


def parse_interactsh_interactions(log_file: Path) -> list:
    """Parses the JSONL interaction log written by `-json -o`. Each line is one
    server.Interaction object (see comment above for the verified schema)."""
    hits = []
    if not log_file or not Path(log_file).exists():
        return hits
    try:
        with Path(log_file).open("r", encoding="utf-8", errors="replace") as fh:
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
                hits.append({
                    "protocol": str(rec.get("protocol") or ""),
                    "unique_id": str(rec.get("unique-id") or ""),
                    "full_id": str(rec.get("full-id") or ""),
                    "remote_address": str(rec.get("remote-address") or ""),
                    "timestamp": str(rec.get("timestamp") or ""),
                    "raw_request": str(rec.get("raw-request") or "")[:4000],
                })
    except Exception:
        pass
    return hits


def _yaml_quote(v) -> str:
    """Minimal safe double-quoted YAML scalar (same rule the config template
    writer uses locally) — escapes backslashes and double quotes only."""
    s_ = str(v)
    return '"' + s_.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _write_config_auto_state(config_path: Path, updates: dict):
    """Persists small pieces of auto-generated runtime state (e.g. which
    interactsh domain was used for the most recent blind-XSS run) into the
    user's config.yaml WITHOUT touching any of their hand-written settings or
    comments. Appends/updates a clearly-marked block at the very end of the
    file instead of round-tripping the whole file through a YAML dumper (which
    would strip every comment). Best-effort / non-fatal: a failure here should
    never affect the scan itself."""
    marker = "# ── ReconX auto-generated runtime state — DO NOT EDIT BY HAND, overwritten every run ──"
    try:
        text = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    except Exception:
        return
    lines = [marker, "auto_state:"]
    for k, v in updates.items():
        if isinstance(v, bool):
            lines.append(f"  {k}: {str(v).lower()}")
        elif isinstance(v, (int, float)):
            lines.append(f"  {k}: {v}")
        else:
            lines.append(f"  {k}: {_yaml_quote(str(v))}")
    block = "\n".join(lines) + "\n"
    idx = text.find(marker)
    if idx != -1:
        text = text[:idx] + block
    else:
        if text and not text.endswith("\n"):
            text += "\n"
        text = text + "\n" + block
    try:
        config_path.write_text(text, encoding="utf-8")
    except Exception:
        pass

# ── XSS verification & alert screenshots (headless Chrome via Selenium) ────────
# The single most important quality signal in this report: a dalfox "R"
# (Reflected) finding only means the payload text came back unescaped
# somewhere — it does NOT mean it executes. Most of a real scan's raw XSS
# rows are inert (payload landed in a JS string, an HTML comment, an attribute
# that gets re-encoded, ...). To separate the real ones we replay every
# candidate PoC URL in a real headless Chromium: a hook installed *before*
# any page script records every alert()/confirm()/prompt() call, and after
# load we also fire a battery of synthetic events for handler-triggered
# payloads (onmouseover/onfocus/...). If a dialog actually fires -> the
# finding is ReconX-CONFIRMED and we screenshot the page with a red banner
# showing the exact message. That screenshot is the proof.
_HEADLESS_CACHE = {}
_XSS_HOOK_JS = r"""
(() => {
  if (window.__xssHooked) return; window.__xssHooked = true;
  window.__xssHits = [];
  for (const fn of ['alert','confirm','prompt']) {
    const orig = window[fn];
    try {
      Object.defineProperty(window, fn, {configurable:true, writable:true, value:function(m){
        try { window.__xssHits.push({fn: fn, m: String(m === undefined ? '' : m)}); } catch(e){}
        if (fn === 'confirm') return true;
        if (fn === 'prompt')  return '';
        return undefined;
      }});
    } catch(e) {}
  }
  // some payloads use these as exf/ sink markers
  const _op = window.open;
  try { window.open = function(){ window.__xssHits.push({fn:'open', m:String(arguments[0]||'')}); return null; }; } catch(e){}
})();
"""

_XSS_TRIGGER_JS = r"""
(() => {
  const evs = ['focus','blur','click','dblclick','mouseover','mouseenter','mouseout',
    'mousedown','mouseup','mousemove','cut','paste','copy','input','change',
    'keydown','keyup','keypress','animationstart','animationend','transitionend',
    'pointerover','pointerenter','pointerdown','touchstart','load','error','toggle',
    'play','playing','loadstart','loadeddata','canplay','canplaythrough',
    'wheel','scroll','select','drag','dragstart'];
  const els = document.querySelectorAll('*');
  els.forEach(el => {
    try { if (el.focus) el.focus(); } catch(e){}
    const attrs = el.getAttributeNames ? el.getAttributeNames() : [];
    const hasHandler = attrs.some(a => a.startsWith('on')) ||
      (el.className && String(el.className).toLowerCase().indexOf('dalfox') >= 0);
    if (!hasHandler) return;
    evs.forEach(name => { try {
      el.dispatchEvent(new Event(name, {bubbles:true, cancelable:true}));
    } catch(e){} });
  });
  ['online','offline','resize','scroll','hashchange','popstate','pageshow','message']
    .forEach(name => { try { window.dispatchEvent(new Event(name)); } catch(e){} });
})();
"""


def _headless_chrome(nav_timeout_sec=15):
    """Return a ready selenium webdriver backed by the system Chromium/Chrome,
    or None if none can be launched. Result cached per process."""
    if "driver_ok" in _HEADLESS_CACHE and not _HEADLESS_CACHE["driver_ok"]:
        return None
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
    except Exception:
        _HEADLESS_CACHE["driver_ok"] = False
        return None

    bin_candidates = [shutil.which("chromium"), shutil.which("chromium-browser"),
                      shutil.which("google-chrome"), shutil.which("google-chrome-stable"),
                      "/usr/bin/chromium", "/usr/bin/google-chrome"]
    drv_candidates = [shutil.which("chromedriver"), "/usr/bin/chromedriver",
                      "/usr/lib/chromium/chromedriver", "/usr/local/bin/chromedriver"]
    browser_bin = next((b for b in bin_candidates if b and Path(b).exists()), None)
    driver_bin  = next((d for d in drv_candidates if d and Path(d).exists()), None)

    _profile = tempfile.mkdtemp(prefix="reconx-xssv-")
    _HEADLESS_CACHE.setdefault("profiles", []).append(_profile)
    o = Options()
    for a in ("--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
              "--window-size=1366,900", "--disable-extensions", "--disable-popup-blocking",
              "--ignore-certificate-errors", "--disable-features=IsolateOrigins,site-per-process",
              "--disable-blink-features=AutomationControlled", "--mute-audio",
              "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
              f"--user-data-dir={_profile}"):
        o.add_argument(a)
    o.add_argument("--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
    if browser_bin:
        o.binary_location = browser_bin
    o.set_capability("unhandledPromptBehavior", "ignore")
    o.set_capability("pageLoadStrategy", "eager")
    try:
        drv = webdriver.Chrome(service=Service(executable_path=driver_bin) if driver_bin else Service(), options=o)
        drv.set_page_load_timeout(nav_timeout_sec)
        drv.set_script_timeout(10)
        try:
            drv.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": _XSS_HOOK_JS})
        except Exception:
            pass
        _HEADLESS_CACHE["driver_ok"] = True
        return drv
    except Exception as e:  # noqa: BLE001
        warn(f"Headless Chrome for XSS verification unavailable ({str(e)[:120]}) — "
             f"install it with:  sudo apt install chromium chromium-driver  "
             f"(XSS findings still appear as text). ")
        _HEADLESS_CACHE["driver_ok"] = False
        return None


def _load_xss_verified(out_dir: Path) -> list:
    vf = Path(out_dir) / "xss_verified.json"
    if not vf.exists():
        return []
    try:
        data = json.loads(vf.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_xss_verified(out_dir: Path, rows: list) -> None:
    try:
        (Path(out_dir) / "xss_verified.json").write_text(
            json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def capture_xss_alert_screenshots(findings: list, out_dir: Path, max_shots: int = 15,
                                   nav_timeout_sec: int = 15, budget_sec: int = 900,
                                   payloads_per_point: int = 4, max_checks: int = 60,
                                   honor_skip: bool = True) -> list:
    """Replay each XSS candidate PoC in headless Chromium; screenshot the ones
    where a real alert()/confirm()/prompt() actually fires. Never raises, never
    blocks the pipeline — returns [] on any setup failure.

    Return: list of dicts {url, param, payload, screenshot, dialog_confirmed,
    dialog_text, orig_type, confirmed_upgrade} — same contract the report and
    stage6 already consume."""
    try:
        from selenium.common.exceptions import UnexpectedAlertPresentException, TimeoutException
    except Exception:
        UnexpectedAlertPresentException = TimeoutException = Exception  # type: ignore

    prior = _load_xss_verified(out_dir)
    with_url = [f for f in (findings or []) if str(f.get("url", "")).startswith("http")]
    if not with_url:
        return prior

    # Prioritise: dalfox "V" first, then one representative per (base-path, param)
    # so we don't spend the whole budget on 20 near-identical search-box hits.
    def _key(f):
        try:
            pr = urlparse(f.get("url", ""))
            return (pr.scheme + "://" + pr.netloc + pr.path, f.get("param", ""))
        except Exception:
            return (f.get("url", ""), f.get("param", ""))

    def _score(f):
        # payloads most likely to actually execute, tried first
        p = (f.get("payload") or "").lower()
        s = 0
        if str(f.get("type", "")).strip().upper() == "V":
            s += 100
        for tok, w in (("onerror=", 8), ("onload=", 8), ("<script", 7), ("autofocus", 6),
                       ("onfocus=", 5), ("onmouseover=", 4), ("ontoggle=", 4), ("\\';", 9),
                       ("\\\";", 9), ("</script>", 6), ("onbegin=", 3), ("onanimation", 3)):
            if tok in p:
                s += w
        for tok, w in (("${", -4), ("javascript:", -3), ("`-alert", -4), ("`;alert", -3)):
            if tok in p:
                s += w
        return -s

    v_type = "V"
    # group by injection point; keep the top-N payloads per point, best-scoring first
    per_point = int(payloads_per_point)
    groups = {}
    for f in sorted(with_url, key=_score):
        groups.setdefault(_key(f), []).append(f)
    picked = []
    for k, fs in groups.items():
        picked.extend(fs[:per_point])
    picked.sort(key=_score)
    max_checks = max(max_shots, min(len(picked), int(max_checks)))

    drv = _headless_chrome(nav_timeout_sec)
    if drv is None:
        warn(f"XSS verification skipped (no headless browser) — {len(with_url):,} candidate(s) "
             f"remain in the report as unconfirmed text.")
        return prior

    shots_dir = out_dir / "screenshots"
    shots_dir.mkdir(parents=True, exist_ok=True)
    info(f"Verifying {min(len(picked), max_checks):,} XSS candidate(s) across "
         f"{len(groups):,} injection point(s) in headless Chromium "
         f"(real dialog detection + screenshot proof)...")

    results = []
    confirmed_points = set()
    t0 = time.time()
    shots_taken = 0
    checks = 0
    for i, f in enumerate(picked):
        if checks >= max_checks or (time.time() - t0) > budget_sec:
            break
        # A single stop ends the fuzzer. The proof pass still runs for findings
        # already collected (honor_skip=False). A second Ctrl+C aborts that too.
        if _INT.hard() or (honor_skip and _INT.stage_skip()):
            break
        # once an injection point is proven, don't burn budget on its other payloads
        if _key(f) in confirmed_points:
            continue
        checks += 1
        url = f["url"]
        confirmed = False
        dtext = ""
        try:
            try:
                drv.get(url)
            except (UnexpectedAlertPresentException,):
                confirmed = True
                try:
                    al = drv.switch_to.alert
                    dtext = (al.text or "")[:200]
                    al.dismiss()
                except Exception:
                    pass
            except TimeoutException:
                pass
            except Exception:
                pass

            if not confirmed:
                time.sleep(0.7)
                try:
                    hits = drv.execute_script("return window.__xssHits || []") or []
                except UnexpectedAlertPresentException:
                    hits = [{"fn": "alert", "m": ""}]
                    confirmed = True
                except Exception:
                    hits = []
                if hits:
                    confirmed = True
                    dtext = str((hits[0] or {}).get("m", ""))[:200]

            if not confirmed:
                # handler-triggered payloads (onmouseover / onfocus / ...)
                try:
                    drv.execute_script(_XSS_TRIGGER_JS)
                    time.sleep(0.5)
                    hits = drv.execute_script("return window.__xssHits || []") or []
                    if hits:
                        confirmed = True
                        dtext = str((hits[0] or {}).get("m", ""))[:200]
                except UnexpectedAlertPresentException:
                    confirmed = True
                    try:
                        al = drv.switch_to.alert
                        dtext = (al.text or "")[:200]
                        al.dismiss()
                    except Exception:
                        pass
                except Exception:
                    pass

            seq = len(list(shots_dir.glob("xss_*.png"))) + 1
            fname = f"xss_{'confirmed' if confirmed else 'verified'}_{seq}.png"
            fpath = shots_dir / fname
            # Dalfox type V already broke out of context. Keep a picture of that
            # page even when the dialog hook does not fire (media handlers).
            save_shot = confirmed or str(f.get("type", "")).strip().upper() == v_type
            if save_shot:
                banner = ("XSS CONFIRMED — dialog fired: " + (dtext or "(empty)")
                          if confirmed else
                          "XSS VERIFIED — payload rendered in the page")
                try:
                    drv.execute_script(
                        "var b=document.createElement('div');"
                        "b.textContent=arguments[0];"
                        "b.style.cssText='position:fixed;top:0;left:0;right:0;z-index:2147483647;"
                        "background:#dc2626;color:#fff;font:bold 15px sans-serif;padding:10px 14px;"
                        "text-align:center';document.documentElement.appendChild(b);",
                        banner)
                except Exception:
                    pass
                try:
                    drv.save_screenshot(str(fpath))
                    shots_taken += 1
                except Exception:
                    pass

            orig_type = str(f.get("type", "")).strip().upper()
            if confirmed:
                confirmed_points.add(_key(f))
            results.append({
                "url": url, "param": f.get("param", ""), "payload": f.get("payload", ""),
                "screenshot": (f"07_xss/screenshots/{fname}" if (save_shot and fpath.exists()) else ""),
                "dialog_confirmed": confirmed, "dialog_text": dtext,
                "orig_type": orig_type,
                "confirmed_upgrade": bool(confirmed and orig_type != v_type),
            })
        except Exception:
            continue

    try:
        drv.quit()
    except Exception:
        pass
    for _p in _HEADLESS_CACHE.get("profiles", []):
        try:
            shutil.rmtree(_p, ignore_errors=True)
        except Exception:
            pass
    _HEADLESS_CACHE["profiles"] = []

    # A stop that lands before the first page load must not wipe proofs
    # already written for earlier verified hits.
    if checks == 0:
        return prior
    merged = []
    seen = set()
    for row in list(prior) + results:
        if not isinstance(row, dict):
            continue
        key = (row.get("url"), row.get("payload"))
        if key in seen:
            merged = [r for r in merged if (r.get("url"), r.get("payload")) != key]
        seen.add(key)
        merged.append(row)
    _save_xss_verified(out_dir, merged)

    confirmed_n = sum(1 for r in merged if r.get("dialog_confirmed"))
    shot_n = sum(1 for r in merged if r.get("screenshot"))
    if confirmed_n:
        ok(f"XSS VERIFIED: {confirmed_n:,} finding(s) fired a real dialog in headless Chromium "
           f"(screenshots saved) — treat these as proven.")
    elif shot_n:
        ok(f"XSS verification: {shot_n:,} verified page(s) captured. "
           f"No dialog fired on its own — the screenshot still shows the payload in the page.")
    elif results:
        ok(f"XSS verification: replayed {len(results):,} candidate(s), none auto-fired a dialog "
           f"(may still be exploitable in the right context — check manually).")
    return merged


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
    def _clean(l):
        s = strip_ansi((l or "").strip())
        # v8.4-fix: some callers (e.g. stage10_js's PEM-block secret
        # extraction, which deliberately captures a full multi-line
        # "-----BEGIN...-----END-----" block as ONE logical value) can hand
        # us a single entry that itself contains real newline/CR characters.
        # This file format is strictly one-entry-per-line (read back via
        # report_builder.py's line-splitting _lines() helper) — an embedded
        # newline silently fragmented that one entry into several bogus,
        # unreadable "separate" entries in the report (confirmed on a real
        # scan: a genuine PEM private key showed up as 3 broken partial rows
        # instead of one usable finding). Collapse internal line breaks to a
        # single space so one logical value always survives as one line.
        return re.sub(r"[\r\n]+", " ", s).strip()
    clean = [c for c in (_clean(l) for l in lines) if c]
    body = "\n".join(clean) + ("\n" if clean else "")
    # v9.0: atomic. These files ARE the resume contract — checkpoints/*.txt is
    # what a --resume reads back to decide a stage is done and to feed the next
    # one. A Ctrl+C, an OOM kill or the --max-time watchdog landing in the
    # middle of a multi-megabyte write used to leave a half-written list behind
    # that looked perfectly valid to the next run, silently shrinking the URL
    # corpus with no error anywhere. Write to a temp file in the same directory
    # (so os.replace stays on one filesystem and really is atomic) and swap.
    dst = Path(path)
    # pid+thread in the name so two writers can never share a temp file;
    # the ".txt.tmpN" suffix also keeps it out of every "*.txt" glob.
    tmp = dst.with_name(f"{dst.name}.tmp{os.getpid()}_{threading.get_ident()}")
    try:
        tmp.write_text(body, encoding="utf-8")
        os.replace(tmp, dst)
    except Exception:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass
        dst.write_text(body, encoding="utf-8")   # last-resort direct write
    return len(clean)

def checkpoint(path, lines, label):
    n = write_lines(path, lines)
    ok(f"Checkpoint [{label}]: {n:,} entries → {Path(path).name}")
    return n


# ══════════════════════════════════════════════════════════════════════════════
# Stage-level checkpoint / resume
# ══════════════════════════════════════════════════════════════════════════════
# Every scan session owns exactly one state file:
#
#     <output-dir>/checkpoints/state.json
#
# It is rewritten (atomically: temp file + os.replace, so a Ctrl+C *during* the
# write can never leave a half-parsed file behind) at three moments:
#
#   1. when a stage starts          -> status "running"
#   2. when a stage ends            -> status "done" / "partial" / "failed" /
#                                      "skipped", plus that stage's summary
#                                      block and wall-clock duration
#   3. when the run is interrupted  -> "interrupted": true + the reason
#
# Because the file is flushed after EVERY stage transition, a Ctrl+C (or a
# SIGTERM, a crash, or the --max-time budget firing) always leaves behind an
# accurate record of which stages finished and what they produced. The next run
# reads it back, offers to resume, skips the stages already marked "done" and
# restores their stored results into the in-memory summary so the final report
# still contains them (see ReconPipeline._restore_stage).
#
# Note the deliberate split: only "done" is skipped on resume. A "partial"
# stage (interrupted mid-way) or a "failed" one is re-run from scratch, because
# its on-disk artefacts are by definition incomplete; a "skipped" stage (the
# operator declined the XSS/Nuclei prompt) is offered again.
STATE_SCHEMA = 1
STATE_FILE   = "state.json"

STAGE_TITLES = {
    0:  "URL Seed Mode",
    1:  "Initial Reconnaissance",
    2:  "Subdomain Enumeration",
    3:  "Host Validation",
    4:  "URL Discovery",
    5:  "URL Categorisation",
    6:  "XSS Testing",
    7:  "Template Vulnerability Scan",
    8:  "Authenticated Crawl",
    9:  "Param Discovery",
    10: "JS Endpoint / Secret Analysis",
    11: "Tech-Based Prioritisation",
    12: "Extra Security Checks",
    13: "API Discovery",
}

# Checkpoint files whose first lines are shown back to the operator when a
# stage is restored from an earlier run ("here is what you already have").
_STAGE_ARTEFACTS = {
    1:  ["stage1_done"],
    2:  ["stage2_subdomains"],
    3:  ["stage3_alive"],
    4:  ["stage4_urls"],
    5:  ["stage5_xss_targets", "stage5_params"],
    8:  ["stage8_authenticated_urls"],
    9:  ["stage9_params"],
    13: ["stage13_api"],
}

_STATE_STATUS_COLOR = {
    "done":        (C.GREEN,   "DONE"),
    "partial":     (C.YELLOW,  "PARTIAL"),
    "failed":      (C.RED,     "FAILED"),
    "skipped":     (C.DIM,     "SKIPPED"),
    "running":     (C.YELLOW,  "INTERRUPTED"),
}


class ScanState:
    """Durable, stage-level scan state backed by checkpoints/state.json.

    Thread-safe (the --max-time watchdog and the main thread can both touch it)
    and failure-tolerant by design: every persistence call is best-effort and
    never raises into the pipeline — a scan must not die because a checkpoint
    could not be written, it should just lose the ability to resume.
    """

    def __init__(self, out_dir, target: str, argv=None):
        self.dir  = Path(out_dir)
        self.path = self.dir / "checkpoints" / STATE_FILE
        self._lock = threading.Lock()
        now = datetime.now().isoformat(timespec="seconds")
        self.data = {
            "schema":      STATE_SCHEMA,
            "version":     VERSION,
            "target":      target,
            "output_dir":  str(self.dir),
            "created":     now,
            "updated":     now,
            "completed":   False,
            "interrupted": False,
            "finalized":   False,   # set once the run ends in a known way
            "interrupt_reason": "",
            "argv":        list(argv or sys.argv[1:]),
            "stages":      {},
        }

    # ── persistence ──────────────────────────────────────────────────────────
    def load(self) -> bool:
        """Read an existing state file into memory. True if one was found."""
        data = read_state_file(self.dir)
        if not data:
            return False
        stages = data.get("stages")
        if not isinstance(stages, dict):
            data["stages"] = {}
        # keep the *original* creation metadata, adopt everything else
        self.data.update(data)
        self.data["schema"]  = STATE_SCHEMA
        self.data["version"] = VERSION
        return True

    def save(self):
        """Atomic write — a crash mid-save can never corrupt the state file."""
        with self._lock:
            self.data["updated"] = datetime.now().isoformat(timespec="seconds")
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps(self.data, indent=2, ensure_ascii=False, default=str),
                               encoding="utf-8")
                os.replace(tmp, self.path)   # atomic on POSIX and Windows
            except Exception:
                pass                          # never break a scan over a checkpoint

    # ── stage bookkeeping ────────────────────────────────────────────────────
    def stage_info(self, n) -> dict:
        rec = self.data.get("stages", {}).get(str(n))
        return rec if isinstance(rec, dict) else {}

    def stage_status(self, n) -> str:
        return str(self.stage_info(n).get("status") or "")

    def is_done(self, n) -> bool:
        return self.stage_status(n) == "done"

    def done_stages(self) -> list:
        out = []
        for k, v in (self.data.get("stages") or {}).items():
            if isinstance(v, dict) and v.get("status") == "done":
                try:
                    out.append(int(k))
                except (TypeError, ValueError):
                    continue
        return sorted(out)

    def start_stage(self, n, title=""):
        self.data.setdefault("stages", {})[str(n)] = {
            "status":  "running",
            "title":   title or STAGE_TITLES.get(n, ""),
            "started": datetime.now().isoformat(timespec="seconds"),
        }
        self.data["last_stage"] = n
        # A recon-only run is marked completed. An on-demand scan that then
        # dies must not leave that "completed" flag standing over a stage
        # that is still "running" — the report would call a half-scan finished.
        self.data["completed"] = False
        self.data["finalized"] = False
        self.data["interrupted"] = False
        self.data["interrupt_reason"] = ""
        self.save()

    def reclaim_orphan_running(self):
        """A stage left 'running' belongs to a process that is already gone
        (kill -9, a dead terminal). This process has not started it yet, so
        downgrade it to partial before deciding what to re-run."""
        changed = []
        for k, v in (self.data.get("stages") or {}).items():
            if isinstance(v, dict) and v.get("status") == "running":
                v["status"] = "partial"
                v["finished"] = datetime.now().isoformat(timespec="seconds")
                changed.append(str(k))
        if changed:
            warn("A previous run left stage(s) "
                 + ", ".join(changed)
                 + " marked running — treating them as partial so this run can continue.")
            self.save()
        return changed

    def finish_stage(self, n, status, summary=None, duration=None):
        rec = self.data.setdefault("stages", {}).get(str(n)) or {}
        rec.update({
            "status":   status,
            "title":    rec.get("title") or STAGE_TITLES.get(n, ""),
            "finished": datetime.now().isoformat(timespec="seconds"),
        })
        if duration is not None:
            rec["duration_sec"] = round(float(duration), 1)
        if isinstance(summary, dict):
            rec["summary"] = summary
        self.data["stages"][str(n)] = rec
        self.data["last_stage"] = n
        self.save()

    def mark_interrupted(self, reason=""):
        self.data["interrupted"]      = True
        self.data["completed"]        = False
        self.data["finalized"]        = True
        self.data["interrupt_reason"] = reason or "interrupted"
        # a stage still flagged "running" was killed mid-flight — its artefacts
        # are incomplete, so downgrade it to "partial" and re-run it on resume.
        for k, v in (self.data.get("stages") or {}).items():
            if isinstance(v, dict) and v.get("status") == "running":
                v["status"] = "partial"
        self.save()

    def mark_completed(self):
        """A run counts as completed only when no stage is left in a state that
        would benefit from being re-run. A crashed stage, or one cut short by a
        skip/budget, keeps the session resumable rather than letting the scan
        quietly declare itself finished with a hole in it."""
        # Only stages this invocation planned to run can keep the session
        # incomplete. An on-demand nuclei left "partial" must not make the
        # next recon-only finish look like it failed, and the reverse.
        planned = {str(x) for x in (self.data.get("planned_stages") or [])}
        pending = sorted(
            (k for k, v in (self.data.get("stages") or {}).items()
             if isinstance(v, dict) and v.get("status") in ("failed", "partial", "running")
             and (not planned or str(k) in planned)),
            key=lambda k: int(k) if str(k).isdigit() else 99)
        self.data["interrupted"] = False
        self.data["finalized"]   = True
        self.data["incomplete_stages"] = pending
        if pending:
            self.data["completed"]        = False
            self.data["interrupt_reason"] = f"stage(s) incomplete: {', '.join(pending)}"
        else:
            self.data["completed"]        = True
            self.data["interrupt_reason"] = ""
        self.save()

    def planned(self, stages):
        """Record which stages this invocation intends to run."""
        self.data["planned_stages"] = list(stages or [])
        self.save()


def read_state_file(session_dir) -> dict:
    """Best-effort read of one session's state.json. {} when absent/corrupt."""
    try:
        p = Path(session_dir) / "checkpoints" / STATE_FILE
        if not p.exists() or p.stat().st_size == 0:
            return {}
        data = json.loads(p.read_text(errors="ignore"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def find_sessions(out_root, target_slug, completed=None) -> list:
    """All session dirs for a target, newest first.

    completed=None  -> every session
    completed=False -> only resumable ones (interrupted / never finished)
    completed=True  -> only sessions that ran to the end (used by --diff)
    """
    root = Path(out_root)
    if not root.is_dir():
        return []
    out = []
    for d in root.glob(f"{target_slug}_*"):
        if not d.is_dir():
            continue
        st = read_state_file(d)
        if completed is True and not st.get("completed"):
            continue
        if completed is False:
            # resumable = has state, did not complete, and actually got somewhere
            if not st or st.get("completed") or not st.get("stages"):
                continue
        out.append((d, st))
    def _sort_key(entry):
        d, st = entry
        try:
            mtime = d.stat().st_mtime
        except OSError:
            mtime = 0
        return (st.get("updated") or "", mtime)
    out.sort(key=_sort_key, reverse=True)
    return out


def print_state_table(session_dir, state: dict):
    """Show what an earlier, interrupted run already finished."""
    stages = state.get("stages") or {}
    print(f"\n{C.CYAN}{C.BOLD}{'═'*66}")
    print(f"  UNFINISHED SCAN FOUND — {state.get('target', '?')}")
    print(f"{'═'*66}{C.RESET}")
    print(f"  {C.BLUE}Session   : {Path(session_dir).name}{C.RESET}")
    print(f"  {C.BLUE}Started   : {state.get('created', '?')}{C.RESET}")
    print(f"  {C.BLUE}Last write: {state.get('updated', '?')}{C.RESET}")
    if state.get("interrupt_reason"):
        print(f"  {C.BLUE}Stopped by: {state['interrupt_reason']}{C.RESET}")
    print(f"  {C.DIM}{'─'*64}{C.RESET}")
    for key in sorted(stages, key=lambda k: int(k) if str(k).isdigit() else 99):
        rec = stages[key] or {}
        status = str(rec.get("status") or "?")
        color, label = _STATE_STATUS_COLOR.get(status, (C.DIM, status.upper()))
        title = rec.get("title") or STAGE_TITLES.get(int(key) if str(key).isdigit() else -1, "")
        summ  = rec.get("summary") if isinstance(rec.get("summary"), dict) else {}
        detail = _summary_headline(summ)
        dur = f" {C.DIM}({rec['duration_sec']}s){C.RESET}" if rec.get("duration_sec") else ""
        print(f"  {color}{label:<12}{C.RESET} stage {str(key):>2}  {title:<32}"
              f"{C.DIM}{detail}{C.RESET}{dur}")
    print(f"  {C.DIM}{'─'*64}{C.RESET}")


def _summary_headline(summary: dict) -> str:
    """One compact 'what did this stage produce' line from its summary block."""
    if not isinstance(summary, dict) or not summary:
        return ""
    bits = []
    for key in ("count", "findings", "endpoints", "secrets", "high", "live_hits",
                "js_files", "pattern_hits", "target_ip"):
        val = summary.get(key)
        if isinstance(val, (int, float)) and val:
            bits.append(f"{key}={val:,}" if isinstance(val, int) else f"{key}={val}")
        elif isinstance(val, str) and val and val != "unknown":
            bits.append(f"{key}={val}")
    if not bits and summary.get("status"):
        bits.append(str(summary["status"]))
    return "  " + " · ".join(bits[:4]) if bits else ""

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

# v8.2: dalfox kendisi her aldigi URL icin OTOMATIK path-reflection testi yapar
# (her path segmentini "dalfoxpathtest" ile degistirip yansiyor mu diye bakar —
# bkz. dalfox pkg/scanning/staticAnlaysis.go:StaticAnalysis) ve mining-dict/
# mining-dom ile query string'i olmayan URL'lerde bile parametre kesfetmeye
# calisir (bu ikisi dalfox'ta varsayilan olarak ACIK). Ama eskiden ReconX
# xss_targets.txt'ye SADECE query string'i olan URL'leri yaziyordu — path-only
# URL'ler (or. /blog/123) dalfox'a hic ulasmiyordu, path-based XSS firsatlari
# tamamen atlanmis oluyordu. Asagidaki _path_shape() path-only URL'leri "sekil"
# bazinda (sayisal/hex/uuid segmentleri {id} ile) dedup eder — boylece
# /product/1, /product/2, /product/3... gibi binlerce neredeyse-ozdes route
# icin dalfox'u tekrar tekrar tetiklemeyiz, her benzersiz route sekli icin
# path_only_max limitine kadar TEK ornek test edilir.
_PAT_ID_SEG = re.compile(r'^(?:[0-9]+|[0-9a-fA-F]{8,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$')

def _path_shape(path: str) -> str:
    """Path'i ID-benzeri segmentleri {id} ile degistirerek 'route sekline' indirger."""
    return "/".join(("{id}" if seg and _PAT_ID_SEG.match(seg) else seg) for seg in path.split("/"))

def _query_param_shape(qs: str) -> str:
    """v8.2: /search?q=1 and /search?q=2 test the exact same injection point
    for dalfox — the parameter NAME 'q' is what determines where dalfox
    probes, the VALUE is irrelevant to that. A site with a paginated/listing
    endpoint can produce thousands of URLs that only differ by that value
    (?id=1, ?id=2, ?id=3, ...), and sending every single one to dalfox is
    pure wasted scan time for zero extra coverage. This reduces a query
    string down to its sorted, de-duplicated parameter NAMES only, so
    categorise_streaming() below can keep just one representative URL per
    unique (host, path-shape, param-names) combination."""
    try:
        pairs = parse_qsl(qs, keep_blank_values=True)
    except Exception:
        return qs
    names = sorted({_xss_param_name(k) for k, _ in pairs if _xss_param_name(k)})
    return ",".join(names) if names else qs


def _xss_param_name(key: str) -> str:
    name = (key or "").strip().lower()
    if name.endswith("[]"):
        name = name[:-2]
    return name


def _xss_test_rank(url: str) -> tuple:
    """Search and text parameters before redirect parameters.

    Alphabetical order put Register.asp?RetURL ahead of Search.asp?tfSearch,
    so the obvious reflected XSS waited behind a long redirect check.
    """
    try:
        names = _xss_param_names(urlparse(url).query)
    except Exception:
        names = ()
    high = {
        "q", "s", "search", "query", "keyword", "keywords", "term", "text", "txt",
        "name", "comment", "comments", "msg", "message", "input", "content",
        "body", "title", "tfsearch",
    }
    rank = 1
    for name in names:
        if name in high or name.endswith("search") or name.endswith("query") or name.endswith("keyword"):
            rank = 0
            break
        if name in {"url", "next", "redirect", "redirect_uri", "redirect_url", "return",
                    "returnurl", "returl", "goto", "dest", "destination", "continue",
                    "callback", "redir"} or "redirect" in name or name.endswith("url"):
            rank = 2
    return (rank, len(url or ""))


def _xss_param_names(qs: str) -> tuple:
    found = set()
    for key, _val in parse_qsl(qs or "", keep_blank_values=True):
        name = _xss_param_name(key)
        if name:
            found.add(name)
    return tuple(sorted(found))


def _xss_injection_point(url: str):
    """Host, path, and parameter names. The value does not matter.

    Search.asp?tfSearch=a and Search.asp?tfSearch=Mert are one injection
    point. A finding on the first value covers the rest."""
    try:
        pr = urlparse(url)
    except Exception:
        return None
    names = _xss_param_names(pr.query)
    if not pr.hostname or not names:
        return None
    return ((pr.hostname or "").lower(), (pr.path or "/").lower(), names)


def _xss_example_rank(url: str) -> tuple:
    """Prefer a short, plain value over a payload already sitting in the query."""
    try:
        q = urlparse(url).query or ""
    except Exception:
        q = url or ""
    decoded = q
    for _ in range(3):
        nxt = unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    dirty = any(tok in decoded.lower() for tok in (
        "<script", "alert(", "javascript:", "onerror=", "onload="))
    return (1 if dirty else 0, len(url or ""))


def unique_xss_urls(urls: list) -> list:
    """One URL per injection point.

    page=1 and page=2 are the same parameter. /item/1 and /item/2 are the
    same route. A second URL is kept only when it adds a parameter name that
    route has not already covered, so each name is tested once.
    """
    grouped = {}
    for url in urls or []:
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        names = _xss_param_names(parsed.query)
        if not names or not parsed.hostname:
            continue
        route = ((parsed.hostname or "").lower(),
                 _path_shape(parsed.path or "/").rstrip("/") or "/")
        grouped.setdefault(route, []).append((names, url))
    chosen = []
    for items in grouped.values():
        items.sort(key=lambda item: (-len(item[0]), len(item[1])))
        covered = set()
        for names, url in items:
            if not any(name not in covered for name in names):
                continue
            covered.update(names)
            chosen.append(url)
    return chosen


def unique_xss_params(urls: list) -> list:
    """One URL per parameter name on a host.

    Search.asp?tfSearch=a and Forum.asp?tfSearch=Mert are the same parameter,
    so only the cleaner example is tested. A path with no query is a stored
    form and is kept once per route.
    """
    ranked = sorted(urls or [], key=lambda u: (_xss_test_rank(u), _xss_example_rank(u), len(u)))
    covered = {}
    paths = set()
    chosen = []
    for url in ranked:
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        names = _xss_param_names(parsed.query)
        if not names:
            shape = (host, (_path_shape(parsed.path or "/").rstrip("/") or "/").lower())
            if shape in paths:
                continue
            paths.add(shape)
            chosen.append(url)
            continue
        have = covered.setdefault(host, set())
        if not any(name not in have for name in names):
            continue
        have.update(names)
        chosen.append(url)
    return chosen


def probe_live_reflected(urls, cfg, threads: int = 20, timeout: int = 8,
                         header_for=None) -> tuple:
    """Keep a URL only when it answers and a parameter value comes back.

    Each parameter is sent with its own marker in one request. Parameters
    whose marker is absent are dropped, so XSS testing does not repeat a
    dead or non-reflecting name. Returns (kept_urls, stats).
    """
    stats = {"probed": len(urls or []), "live": 0, "reflected": 0, "dead": 0, "error": ""}
    # Plain requests: a burst of canary checks must honor the timeout. The
    # browser-impersonation client stacks up and stops respecting it.
    client = _py_requests if _py_requests is not None else None
    is_cffi = False
    if client is None:
        client, is_cffi = _get_http_client(cfg)
    if client is None:
        stats["error"] = "no_http_client"
        return [], stats
    if not urls:
        return [], stats
    settings = (cfg or {}).get("settings", {}) if isinstance(cfg, dict) else {}
    impersonate = settings.get("curl_cffi_impersonate", "chrome110")
    proxy = _resolve_proxy(cfg)
    connect_timeout = min(3, max(1, int(timeout or 8)))
    workers = max(1, min(int(threads or 1), len(urls)))

    def _one(url):
        try:
            parsed = urlparse(url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
        except Exception:
            return "dead", None
        seen = set()
        targets = []
        for key, value in pairs:
            name = _xss_param_name(key)
            if not name or name in seen:
                continue
            seen.add(name)
            targets.append((key, value))
        if not targets:
            return "dead", None
        host = parsed.hostname or ""
        headers = header_for(url) if header_for else pick_header_strategy(host, cfg)
        kw = dict(timeout=(connect_timeout, timeout), allow_redirects=True,
                  headers=headers, verify=False)
        if proxy:
            kw["proxies"] = {"http": proxy, "https": proxy}
        if is_cffi:
            kw["impersonate"] = impersonate
        # One parameter per request. Replacing every value at once hides a
        # real reflection: a non-numeric id makes this ASP.NET page return an
        # empty body, so NewsAd (which does echo) never gets rendered.
        reflected = []
        saw_page = False
        for key, value in targets:
            token = f"rx{len(reflected)}{random.randrange(100000, 999999)}"
            probe_pairs = []
            replaced = False
            for k, v in pairs:
                if not replaced and k == key:
                    probe_pairs.append((k, token))
                    replaced = True
                else:
                    probe_pairs.append((k, v))
            probe_url = urlunparse(parsed._replace(query=urlencode(probe_pairs), fragment=""))
            try:
                response = client.get(probe_url, **kw)
                status = int(getattr(response, "status_code", 0) or 0)
                body = (getattr(response, "text", "") or "")[:400000]
            except Exception:
                continue
            if status not in (0, 404, 410) and body.strip():
                saw_page = True
            if token and token in body:
                kept_value = value.strip() if (value or "").strip() and len(value) <= 80 else "1"
                reflected.append((key, kept_value))
        if reflected:
            kept = urlunparse(parsed._replace(query=urlencode(reflected), fragment=""))
            return "hit", kept
        if saw_page:
            return "live", None
        return "dead", None

    kept = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, url) for url in urls]
        for future in as_completed(futures):
            try:
                kind, url = future.result()
            except Exception:
                stats["dead"] += 1
                continue
            if kind == "hit" and url:
                stats["live"] += 1
                stats["reflected"] += 1
                kept.append(url)
            elif kind == "live":
                stats["live"] += 1
            else:
                stats["dead"] += 1
    return kept, stats

# ── URL Categorisation (SQLite streaming) ─────────────────────────────────────
def categorise_streaming(url_file, out_dir, test_path_only: bool = True, path_only_max: int = 100,
                          dedup_query_params: bool = True):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    cats = ["params", "reflection", "forms", "admin", "login", "api", "sensitive", "other",
            "xss_targets", "openredirect", "sqli"]
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
    counts["xss_targets_path_only"] = 0
    counts["xss_targets_query_dedup_skipped"] = 0
    _mem_seen = set()
    _path_shapes_seen = set()
    _query_shapes_seen = set()
    xss_best, redir_best, sqli_best = {}, {}, {}

    def _remember(bucket, url, key, rank):
        if not key or _static_asset_path(urlparse(url).path or ""):
            return
        cur = bucket.get(key)
        if cur is None or rank(url) < rank(cur):
            bucket[key] = url

    def _sqli_rank(url):
        return (0 if _url_has_sql_error(url) else 1, _xss_example_rank(url))

    def _w(cat, url):
        try:
            cur = conn.execute("INSERT OR IGNORE INTO seen(cat,url) VALUES(?,?)", (cat, url))
            if cur.rowcount == 1:
                handles[cat].write(url + "\n")
                counts[cat] += 1
        except Exception:
            # v6.17-fix: SQLite hatasinda dedup'i in-memory set ile koru
            # (eskiden bu yolda URL'ler tekrar tekrar yaziliyordu).
            key = (cat, url)
            if key in _mem_seen:
                return
            _mem_seen.add(key)
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
                    names = _xss_param_names(qs)
                    host = (parsed.hostname or parsed.netloc or "").lower()
                    path_key = (parsed.path or "/").lower()
                    xss_names = tuple(n for n in names if _is_xss_param_name(n))
                    dom_names = tuple(n for n in names if _is_dom_param_name(n))
                    stored_names = tuple(n for n in names if _is_stored_param_name(n))
                    redir_names = tuple(n for n in names if _is_open_redirect_name(n))
                    sqli_names = tuple(n for n in names if _is_sqli_param_name(n))
                    keep_names = tuple(dict.fromkeys([*xss_names, *dom_names, *stored_names]))
                    if redir_names:
                        _remember(redir_best, url, (host, path_key, redir_names), _xss_example_rank)
                    if keep_names:
                        # Key is the parameter names, not the path. A second URL
                        # with the same parameter does not get its own row.
                        _remember(xss_best, url, (host, keep_names), _xss_example_rank)
                    if sqli_names:
                        _remember(sqli_best, url, (host, path_key, sqli_names), _sqli_rank)
                    elif _url_has_sql_error(url):
                        _remember(sqli_best, url, (host, path_key, ("__sql_error__",)), _sqli_rank)
                    # XSS targets are the unique reflection examples, written
                    # once after the file is scanned. Every extra value of the
                    # same parameter used to land here and the XSS scan walked
                    # all of them.
                    if dedup_query_params:
                        q_shape = (f"{(parsed.netloc or '').lower()}"
                                   f"{_path_shape(path).lower()}?{_query_param_shape(qs)}")
                        if q_shape in _query_shapes_seen:
                            counts["xss_targets_query_dedup_skipped"] += 1
                        else:
                            _query_shapes_seen.add(q_shape)
                else:
                    # v8.2: query string'i olmayan (path-only) URL'ler de dalfox'a
                    # gonderilir — dalfox kendi path-reflection + mining motoruyla
                    # bunlari test edebilir. Ayni route "sekli"nden (or. /product/{id})
                    # sadece ilk gorulen ornek gonderilir, tekrarlari atlanir.
                    if test_path_only and counts["xss_targets_path_only"] < path_only_max:
                        shape = _path_shape(path)
                        if shape not in _path_shapes_seen:
                            _path_shapes_seen.add(shape)
                            before = counts["xss_targets"]
                            _w("xss_targets", url)
                            if counts["xss_targets"] > before:
                                counts["xss_targets_path_only"] += 1
                    host_only = (parsed.hostname or "").lower()
                    if _is_stored_path(path):
                        _remember(xss_best, url,
                                  (host_only, ("__stored__", (_path_shape(path).rstrip("/") or "/").lower())),
                                  _xss_example_rank)
                    if _PAT_FORM.search(path):
                        _w("forms", url)
                    elif not any([_PAT_SENSITIVE.search(path), _PAT_ADMIN.search(path),
                                  _PAT_LOGIN.search(path), _PAT_API.search(path)]):
                        _w("other", url)
                batch += 1
                if batch % 2000 == 0:
                    conn.commit()
        xss_urls = unique_xss_params(list(xss_best.values()))
        for url in xss_urls:
            _w("reflection", url)
            _w("xss_targets", url)
        for url in redir_best.values():
            _w("openredirect", url)
        for url in sqli_best.values():
            _w("sqli", url)
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
def _kill_tree(proc, grace: float = 3.0):
    """Stop a tool AND everything it spawned.

    v9.0: every external tool is now started with start_new_session=True, which
    makes it the leader of its own process group. That matters because
    proc.kill() only ever signals that ONE pid — and a good share of the
    commands here do not run the scanner as that pid:

      * _stream_tool() passes plain strings, so Popen(shell=True) makes /bin/sh
        the child and nuclei/dalfox a grandchild;
      * katana and dalfox fork workers of their own.

    So a timeout, a stall watchdog firing or a Ctrl+C used to kill the wrapper
    and leave the actual scanner running: still hammering the target, still
    holding sockets and CPU, and completely invisible to a pipeline that
    believed it had stopped it. Signalling the whole group is what actually
    ends the work.

    SIGTERM first, so a tool gets the chance to flush its own -o output file
    (nuclei writes findings incrementally, but dalfox/httpx buffer), then
    SIGKILL for whatever ignored it.
    """
    if proc is None:
        return
    try:
        pgid = os.getpgid(proc.pid)
    except Exception:
        pgid = None
    # If start_new_session somehow did not take effect, pgid is OUR group —
    # signalling it would kill ReconX itself. Fall back to the single pid.
    try:
        if pgid is not None and pgid == os.getpgrp():
            pgid = None
    except Exception:
        pgid = None
    def _signal(sig):
        try:
            if pgid is not None:
                os.killpg(pgid, sig)
            else:
                proc.send_signal(sig)
        except Exception:
            pass          # already gone (ESRCH) — nothing to do

    # SIGTERM the whole group, then wait for the process we actually hold a
    # handle on. Note the SIGKILL below is NOT conditional on that wait timing
    # out: the leader here is often just the /bin/sh wrapper, and it dies
    # instantly while the scanner it forked keeps running. Returning as soon as
    # the leader exits is exactly how an orphan survives, so the group always
    # gets the follow-up SIGKILL — on an already-empty group that is a no-op.
    _signal(signal.SIGTERM)
    try:
        proc.wait(grace)
    except Exception:
        pass
    _signal(signal.SIGKILL)
    try:
        proc.wait(2.0)
    except Exception:
        pass


def run_cmd(cmd, out_file=None, timeout=120, log=None, label="",
            silent=False, stream=False, retries=2, retry_delay=5, stdin_file=None,
            cwd=None, job=None):
    # v8.8: stage_skip() zaten hard()'i de kapsar — "stage'i atla" secildiginde
    # bu stage'in KALAN cagrilari hic baslatilmadan atlanir (once baslatilip
    # hemen ardindan oldurulmesini beklemek yerine).
    if _INT.stage_skip():
        return False, ""
    _attempt = 0
    while True:
        _ok, _txt = _run_once(cmd, out_file=out_file, timeout=timeout,
                              log=log, label=label, silent=silent, stream=stream,
                              attempt=_attempt, stdin_file=stdin_file, cwd=cwd,
                              job=job)
        if _INT.hard() or _INT.interrupted():
            return _ok, _txt
        file_lines = _count_lines(out_file) if (out_file and Path(out_file).exists() and Path(out_file).stat().st_size > 0) else 0
        stdout_lines = len([l for l in (_txt or "").splitlines() if l.strip()])
        lc = file_lines or stdout_lines
        # v8.6-fix: a tool that exited cleanly (rc==0) with 0 lines gave a
        # VALID empty answer — subfinder finding no subdomains, gau finding no
        # archived URLs, dnsx validating nothing. Retrying it 2-3× (68s each
        # for subfinder) just burns minutes and, in the web UI, looks like a
        # hang. Only retry on 0 lines when the tool actually FAILED (rc!=0 /
        # timed out) — a real transient error.
        if lc > 0 or _attempt >= retries or _ok:
            return _ok, _txt
        _attempt += 1
        if label:
            lbl = label
        elif isinstance(cmd, (list, tuple)):
            lbl = cmd[0] if cmd else "cmd"
        else:
            try:
                lbl = shlex.split(cmd)[0]
            except Exception:
                lbl = cmd.split()[0] if cmd.strip() else "cmd"
        lbl = _public_activity(lbl)
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
              silent=False, stream=False, attempt=0, stdin_file=None, cwd=None,
              job=None):
    if _INT.stage_skip():
        return False, ""
    if label:
        pass
    elif isinstance(cmd, (list, tuple)):
        label = cmd[0] if cmd else "cmd"
    else:
        try:
            label = shlex.split(cmd)[0]
        except Exception:
            label = cmd.split()[0] if str(cmd).strip() else "cmd"
    label = _public_activity(label)
    start = time.time()
    if not silent:
        sub(f"{label}...")

    proc_ref    = [None]
    stdout_buf  = [b""]
    stderr_buf  = [b""]
    timed_out   = [False]
    ctrl_killed = [False]
    live        = _Live()
    _seed_live(live, cmd, stdin_file=stdin_file, job=job)

    def _drain(pipe, parts):
        # BufferedReader.read(n) waits until n bytes or EOF, so a stats line
        # would sit invisible until the tool exited. A raw read returns
        # whatever is already there.
        fd = pipe.fileno()
        buf = b""
        try:
            while True:
                try:
                    chunk = os.read(fd, 1024)
                except OSError:
                    break
                if not chunk:
                    break
                parts.append(chunk)
                buf += chunk
                while True:
                    npos = buf.find(b"\n")
                    rpos = buf.find(b"\r")
                    if npos < 0 and rpos < 0:
                        break
                    # A carriage return is the tool redrawing one status line.
                    # The meter already tracks that. A newline is a finished
                    # line of tool output and belongs in the live console.
                    if npos >= 0 and (rpos < 0 or npos <= rpos):
                        split_at = npos
                        finished = True
                    else:
                        split_at = rpos
                        finished = False
                    line_b = buf[:split_at]
                    buf = buf[split_at + 1:]
                    if not line_b.strip():
                        continue
                    decoded = line_b.decode("utf-8", "replace")
                    try:
                        _absorb_progress(decoded, live)
                    except Exception:
                        pass
                    live.bump_line()
                    if finished:
                        _pipe_echo(decoded)
            if buf.strip():
                try:
                    _absorb_progress(buf.decode("utf-8", "replace"), live)
                except Exception:
                    pass
        finally:
            try:
                pipe.close()
            except Exception:
                pass

    def _worker():
        try:
            argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
            stdin_handle = None
            try:
                if stdin_file:
                    stdin_handle = open(stdin_file, "rb")
                p = subprocess.Popen(argv, shell=False, stdin=stdin_handle,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True, cwd=cwd)
                proc_ref[0] = p
                out_parts, err_parts = [], []
                t_out = threading.Thread(target=_drain, args=(p.stdout, out_parts), daemon=True)
                t_err = threading.Thread(target=_drain, args=(p.stderr, err_parts), daemon=True)
                t_out.start()
                t_err.start()
                p.wait()
                t_out.join(3)
                t_err.join(3)
                stdout_buf[0] = b"".join(out_parts)
                stderr_buf[0] = b"".join(err_parts)
            finally:
                if stdin_handle:
                    stdin_handle.close()
        except Exception as ex:
            stderr_buf[0] = str(ex).encode()

    worker      = threading.Thread(target=_worker, daemon=True)
    stop_spin   = threading.Event()
    spin_thread = threading.Thread(
        target=_spinner, args=(stop_spin, label, start, live), daemon=True)
    worker.start()
    if not silent:
        spin_thread.start()
    for _ in range(int(timeout / 0.2)):
        worker.join(0.2)
        if not worker.is_alive():
            break
        if _INT.interrupted() or _INT.hard():
            ctrl_killed[0] = True
            _kill_tree(proc_ref[0], grace=2.0)
            worker.join(2)
            break
    else:
        if worker.is_alive():
            timed_out[0] = True
            _kill_tree(proc_ref[0])
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
            unit = "line" if lc == 1 else "lines"
            ok(f"{label} ({elapsed}s) — {lc:,} {unit}")
        else:
            warn(f"{label} exit {rc} ({elapsed}s)")
            # On a pipe those stderr lines were already echoed as they arrived.
            if sys.stdout.isatty():
                for _sl in _useful_stderr_lines(etxt):
                    print(f"  {C.DIM}  └ {_public_text(_sl[:160])}{C.RESET}", flush=True)
    if live.job_locked and not ctrl_killed[0]:
        _JOB_CLOCK["n"] += 1
        _JOB_CLOCK["sec"] += elapsed
    _INT.reset_op()
    return (not timed_out[0] and not ctrl_killed[0] and rc == 0), txt


# ── Streaming tool runner ─────────────────────────────────────────────────────
def _stream_tool(cmd, timeout: int, log=None, label: str = "",
                 line_cb=None, stall_timeout: int = 0, ok_exit_codes=(0, None),
                 status: dict = None, stop_check=None) -> tuple:
    """stall_timeout: eger > 0 ve o kadar saniye boyunca TEK BIR YENI SATIR bile
    gelmezse (arac askida kalmis / network'e sessizce takilmis olabilir), sureci
    zorla durdurur. v6.17: nuclei gibi araclarin bazen kendi ic guncelleme/
    telemetri kontrolleri yuzunden (once hicbir stdout uretmeden) tamamen
    askida kalabildigi gozlemlendi — bu onceden saatlerce (T['nuclei']=14400s)
    sessizce beklemeye yol aciyordu. Artik boyle bir durum acikca tespit edilip
    kullaniciya raporlanir.
    status: an optional dict the CALLER owns and its line_cb writes into. The
    spinner renders status["text"] next to the label on every redraw, so a tool
    that reports its own progress on stdout (dalfox prints
    "[SID:n][done/total][pct%]" per target) can show real progress instead of
    just a line counter.
    ok_exit_codes: v8.4-fix — which exit codes count as "success" for THIS
    tool, default (0, None) preserves the original behavior for every
    existing caller. Added because dalfox v3.x (Rust) uses a grep-style
    convention where exit 1 means "vulnerabilities WERE found" (confirmed
    against a real v3.2.2 build), not a crash — without this, a fully
    successful scan that found real XSS printed a scary "HATA ILE SONLANDI"
    (ended with error) console line right above the correct "found N
    findings" line that follows it, which is confusing/alarming even though
    the results themselves were never affected by this cosmetic bug."""
    if _INT.stage_skip():
        return -1, 0, True, False
    start       = time.time()
    total_lines = [0]
    rc          = [-1]
    killed      = [False]
    stalled     = [False]
    proc_ref    = [None]
    stop_spin  = threading.Event()
    spin_label = _public_activity(label or (cmd[0] if isinstance(cmd, list) else cmd.split()[0]))
    live = _Live()
    _seed_live(live, cmd)

    def _spin_ticker():
        frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        i = 0
        tty = sys.stdout.isatty()
        # v8.3: shared _PRINT_LOCK with xss_live_hit() — a live finding
        # print (from a dalfox line_cb, also running on the reader
        # thread) and this spinner redraw both touch stdout with \r; the
        # lock keeps one from garbling mid-write into the other.
        if not tty:
            last_beat = None
            last_sig = None
            while not stop_spin.is_set():
                _absorb_status_text(status, live)
                now = time.time()
                snap = live.snapshot()
                sig = (snap[0], snap[6])
                moved = sig != last_sig and (snap[0] not in (None, 0) or snap[6])
                due = last_beat is None and now - start >= 0.6
                due = due or (last_beat is not None and moved and now - last_beat >= 1.0)
                due = due or (last_beat is not None and now - last_beat >= 3)
                if due:
                    _show_progress("…", spin_label, start, live, False)
                    last_beat = now
                    last_sig = sig
                time.sleep(0.3)
            if last_beat is not None and (live.snapshot()[0], live.snapshot()[6]) != last_sig:
                _show_progress("…", spin_label, start, live, False)
            return
        while not stop_spin.is_set():
            if _SPINNER_PAUSE.is_set():
                time.sleep(0.05)
                continue
            _absorb_status_text(status, live)
            _show_progress(frames[i % len(frames)], spin_label, start, live, True)
            i += 1
            time.sleep(0.12)
        _clear_progress(True)

    spin_thread = threading.Thread(target=_spin_ticker, daemon=True)

    def _reader():
        try:
            _shell = isinstance(cmd, str)
            p = subprocess.Popen(
                cmd, shell=_shell,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=0, start_new_session=True,
                env={**os.environ, "PYTHONUNBUFFERED": "1", "TERM": "dumb"}
            )
            proc_ref[0] = p
            buf = b""
            out_fd = p.stdout.fileno()
            while True:
                try:
                    chunk = os.read(out_fd, 1024)
                except OSError:
                    break
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
                    live.bump_line()
                    try:
                        _absorb_progress(line, live)
                    except Exception:
                        pass
                    if line_cb:
                        line_cb(line)
                    _pipe_echo(line)
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
    last_count = 0
    last_progress_ts = start
    while reader_thread.is_alive():
        reader_thread.join(0.3)
        if _INT.interrupted() or _INT.hard():
            killed[0] = True
            _kill_tree(proc_ref[0])
            break
        now = time.time()
        if total_lines[0] != last_count:
            last_count = total_lines[0]
            last_progress_ts = now
        if stall_timeout and (now - last_progress_ts) > stall_timeout:
            warn(f"{spin_label}: no progress for {stall_timeout}s "
                 f"(stuck at {total_lines[0]} lines) — the tool may be hung "
                 f"(network block, its own update check, ...), stopping it")
            stalled[0] = True
            killed[0] = True
            _kill_tree(proc_ref[0])
            break
        if stop_check is not None:
            try:
                _stop_now = bool(stop_check())
            except Exception:
                _stop_now = False
            if _stop_now:
                warn(f"{spin_label}: finding already saved — moving on")
                killed[0] = True
                _kill_tree(proc_ref[0])
                break
        if now > deadline:
            warn(f"{spin_label} timeout ({timeout}s) — stopping")
            killed[0] = True
            _kill_tree(proc_ref[0])
            break
    stop_spin.set()
    spin_thread.join(1.0)
    reader_thread.join(2.0)
    elapsed = round(time.time() - start, 1)
    if log:
        log.info(f"[STREAM] {cmd} | rc={rc[0]} | {elapsed}s | lines={total_lines[0]} | stalled={stalled[0]}")
    if stalled[0]:
        warn(f"{spin_label} ASKIDA KALDI ({elapsed}s, {stall_timeout}s ilerlemesiz) — "
             f"durduruldu, sonuclar EKSIK olabilir")
    elif killed[0]:
        warn(f"{spin_label} stopped ({elapsed}s) — {total_lines[0]:,} lines read")
    elif rc[0] not in ok_exit_codes:
        # v6.14: arac hata koduyla cikti (orn. nuclei 'no templates provided',
        # dalfox gecersiz argüman). Bunu "basarili" gibi gostermek, sahte bir
        # "0 bulgu = temiz" izlenimi verip gercek bir arac cokmesini gizleyebilir.
        warn(f"{spin_label} FAILED (exit code {rc[0]}, {elapsed}s) — "
             f"results may be INCOMPLETE/INVALID, check the log file")
    else:
        ok(f"{spin_label} done ({elapsed}s) — {total_lines[0]:,} lines")
    _INT.reset_op()
    return rc[0], total_lines[0], killed[0], stalled[0]


# ══════════════════════════════════════════════════════════════════════════════
# AUTH / LOGIN — authenticated session support
# ══════════════════════════════════════════════════════════════════════════════
_CSRF_PATTERNS = [
    re.compile(r'name=["\']csrf[_-]?token["\']\s+[^>]*?value=["\']([^"\']+)["\']', re.I),
    re.compile(r'name=["\']_token["\']\s+[^>]*?value=["\']([^"\']+)["\']', re.I),
    re.compile(r'name=["\']authenticity_token["\']\s+[^>]*?value=["\']([^"\']+)["\']', re.I),
    re.compile(r'name=["\']__RequestVerificationToken["\']\s+[^>]*?value=["\']([^"\']+)["\']', re.I),
    re.compile(r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', re.I),
]

def _extract_csrf_token(html_body: str):
    body = html_body or ""
    patterns = [
        re.compile(r'name=["\'](csrf[_-]?token)["\']\s+[^>]*?value=["\']([^"\']+)["\']', re.I),
        re.compile(r'name=["\'](_token)["\']\s+[^>]*?value=["\']([^"\']+)["\']', re.I),
        re.compile(r'name=["\'](authenticity_token)["\']\s+[^>]*?value=["\']([^"\']+)["\']', re.I),
        re.compile(r'name=["\'](__RequestVerificationToken)["\']\s+[^>]*?value=["\']([^"\']+)["\']', re.I),
        re.compile(r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', re.I),
    ]
    for i, pat in enumerate(patterns):
        m = pat.search(body)
        if m:
            if i == 4:
                return "csrf-token", m.group(1)
            return m.group(1), m.group(2)
    return "", ""

def perform_login(login_url: str, username: str, password: str, cfg: dict,
                   user_field: str = "username", pass_field: str = "password",
                   extra_fields: dict = None, method: str = "POST",
                   success_indicator: str = "", failure_indicator: str = "",
                   csrf_field: str = "", timeout: int = 30, log=None) -> dict:
    client, is_cffi = _get_http_client(cfg)
    result = {
        "ok": False, "status": 0, "cookies": {}, "cookie_header": "",
        "final_url": "", "error": "", "csrf_used": False,
    }
    if client is None:
        result["error"] = "no_http_client"
        return result

    settings = (cfg or {}).get("settings", {}) if isinstance(cfg, dict) else {}
    impersonate = settings.get("curl_cffi_impersonate", "chrome110")
    proxy = _resolve_proxy(cfg)
    host = _extract_domain_from_any(login_url) or ""
    headers = pick_header_strategy(host, cfg)

    try:
        session = client.Session()
    except Exception as e:
        result["error"] = f"session_init_failed: {e}"
        return result

    kw_common = {}
    if proxy:
        kw_common["proxies"] = {"http": proxy, "https": proxy}
    if is_cffi:
        kw_common["impersonate"] = impersonate

    csrf_val = ""
    csrf_field_found = ""
    try:
        r_get = session.get(login_url, headers=headers, timeout=timeout,
                             allow_redirects=True, **kw_common)
        body = getattr(r_get, "text", "") or ""
        csrf_field_found, csrf_val = _extract_csrf_token(body)
        if log:
            log.info(f"[LOGIN] GET {login_url} -> {getattr(r_get, 'status_code', '?')} "
                     f"csrf_found={bool(csrf_val)} field={csrf_field_found or 'none'}")
    except Exception as e:
        if log:
            log.warning(f"[LOGIN] GET login page failed: {e}")

    form = {user_field: username, pass_field: password}
    if extra_fields:
        form.update(extra_fields)
    if csrf_val:
        field_name = csrf_field or csrf_field_found or "csrf_token"
        form[field_name] = csrf_val
        result["csrf_used"] = True

    post_headers = dict(headers)
    post_headers["Content-Type"] = "application/x-www-form-urlencoded"
    post_headers["Referer"] = login_url
    post_headers["Origin"] = f"{urlparse(login_url).scheme}://{urlparse(login_url).netloc}"

    try:
        if method.upper() == "GET":
            r = session.get(login_url, params=form, headers=post_headers,
                             timeout=timeout, allow_redirects=True, **kw_common)
        else:
            r = session.post(login_url, data=form, headers=post_headers,
                              timeout=timeout, allow_redirects=True, **kw_common)
        status = int(getattr(r, "status_code", 0) or 0)
        body = getattr(r, "text", "") or ""
        final_url = str(getattr(r, "url", login_url))

        cookies = {}
        try:
            jar = getattr(session, "cookies", None)
            if jar is not None:
                items = jar.items() if hasattr(jar, "items") else []
                for k, v in items:
                    cookies[k] = v
        except Exception:
            pass

        cookie_header = "; ".join([f"{k}={v}" for k, v in cookies.items()])

        success = status in (200, 301, 302, 303) and bool(cookies)
        if success_indicator:
            # v6.17-fix: basari isareti (success_indicator) acikca belirtilmisse
            # cookie'ler bos olsa bile basarili say — JWT/header-auth veya
            # cookie'siz session donen uygulamalarda cookied kontrolu yanlis
            # negatif veriyordu (oturum "acilamadi" diye tarama auth'suz giderdi).
            ind_matched = (success_indicator.lower() in body.lower()
                           or success_indicator.lower() in final_url.lower())
            success = ind_matched and status in (200, 301, 302, 303)
        if failure_indicator and (failure_indicator.lower() in body.lower()):
            success = False

        result.update({
            "ok": success,
            "status": status,
            "cookies": cookies,
            "cookie_header": cookie_header,
            "final_url": final_url,
            "session": session,
        })
        if log:
            log.info(f"[LOGIN] {method.upper()} {login_url} -> {status} "
                     f"cookies={list(cookies.keys())} success={success}")
    except Exception as e:
        result["error"] = str(e)
        if log:
            log.warning(f"[LOGIN] request failed: {e}")

    return result


def parse_request_file(path: str, default_scheme: str = "https") -> dict:
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"request file not found: {p}")

    raw = p.read_text(encoding="utf-8", errors="replace")
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        raise ValueError("empty request file")

    request_line = lines[0].strip()
    m = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?$",
                 request_line, re.I)
    if not m:
        raise ValueError(f"invalid HTTP request line: {request_line}")

    method = m.group(1).upper()
    path_part = m.group(2)
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()

    host = headers.get("Host") or headers.get("host") or ""
    if not host:
        raise ValueError("request file must contain a Host header")

    if path_part.startswith(("http://", "https://")):
        url = path_part
    else:
        url = f"{default_scheme}://{host}{path_part if path_part.startswith('/') else '/' + path_part}"

    headers = {
        k: v for k, v in headers.items()
        if k.lower() not in {"content-length", "host", "connection"}
    }

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "host": host,
        "request_line": request_line,
    }


def perform_request_login(request_file: str, cfg: dict, timeout: int = 60, log=None) -> dict:
    client, is_cffi = _get_http_client(cfg)
    result = {
        "ok": False, "status": 0, "cookies": {}, "cookie_header": "",
        "final_url": "", "error": "", "request_url": "", "method": "",
    }
    if client is None:
        result["error"] = "no_http_client"
        return result

    settings = (cfg or {}).get("settings", {}) if isinstance(cfg, dict) else {}
    impersonate = settings.get("curl_cffi_impersonate", "chrome110")
    proxy = _resolve_proxy(cfg)

    try:
        req = parse_request_file(
            request_file,
            default_scheme=(_cfg_get(cfg, "settings", "default_scheme", default="https") or "https")
        )
    except Exception as e:
        result["error"] = f"request_parse_failed: {e}"
        return result

    result["request_url"] = req["url"]
    result["method"] = req["method"]

    try:
        session = client.Session()
    except Exception as e:
        result["error"] = f"session_init_failed: {e}"
        return result

    headers = dict(req["headers"])
    kw = {"timeout": timeout, "allow_redirects": True, "headers": headers}
    kw["verify"] = False
    if proxy:
        kw["proxies"] = {"http": proxy, "https": proxy}
    if is_cffi:
        kw["impersonate"] = impersonate

    try:
        if req["method"] in {"GET", "HEAD", "OPTIONS"}:
            r = session.request(req["method"], req["url"], **kw)
        else:
            r = session.request(
                req["method"], req["url"],
                data=req["body"].encode("utf-8"), **kw
            )

        status = int(getattr(r, "status_code", 0) or 0)
        final_url = str(getattr(r, "url", req["url"]))

        cookies = {}
        jar = getattr(session, "cookies", None)
        if jar is not None:
            try:
                cookies = dict(jar.items())
            except Exception:
                pass

        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        success = status in (200, 201, 202, 204, 301, 302, 303, 307, 308) and bool(cookies)

        result.update({
            "ok": success,
            "status": status,
            "cookies": cookies,
            "cookie_header": cookie_header,
            "final_url": final_url,
            "session": session,
        })
        if log:
            log.info(
                f"[REQUEST-AUTH] {req['method']} {req['url']} -> {status} "
                f"cookies={list(cookies.keys())} success={success}"
            )
    except Exception as e:
        result["error"] = str(e)
        if log:
            log.warning(f"[REQUEST-AUTH] request failed: {e}")

    return result


# ══════════════════════════════════════════════════════════════════════════════
# v6.13: CORS / Subdomain Takeover / Cloud Bucket helper functions
# ══════════════════════════════════════════════════════════════════════════════
def _timed_get(url: str, cfg: dict, headers: dict, timeout: int = 12):
    """One GET with a connect timeout that is actually honored.

    The browser-impersonation client stacks calls and stops respecting
    timeout=, which made CORS and bucket checks look stuck. These checks
    only need the status and a header or a short body."""
    client = _py_requests if _py_requests is not None else None
    is_cffi = False
    if client is None:
        client, is_cffi = _get_http_client(cfg)
    if client is None:
        return None
    connect = min(3, max(1, int(timeout or 12)))
    kw = dict(timeout=(connect, int(timeout or 12)), allow_redirects=True,
              headers=headers, verify=False)
    proxy = _resolve_proxy(cfg)
    if proxy:
        kw["proxies"] = {"http": proxy, "https": proxy}
    if is_cffi:
        kw["impersonate"] = _cfg_get(cfg, "settings", "curl_cffi_impersonate", default="chrome110")
    return client.get(url, **kw)


def check_cors_misconfig(url: str, cfg: dict, log=None) -> dict:
    """Origin header'i yansitilan/wildcard+credentials birlesimini test eder.
    Sadece header inceler; hicbir exploit/veri sizdirma denemesi yapmaz."""
    res = {"url": url, "vulnerable": False, "detail": "", "acao": "", "acac": "", "checked": False}
    test_origin = (_cfg_get(cfg, "tools", "cors_test_origin",
                             default="https://reconx-cors-probe.invalid") or "").strip()
    host = _extract_domain_from_any(url) or ""
    headers = pick_header_strategy(host, cfg)
    headers["Origin"] = test_origin
    try:
        r = _timed_get(url, cfg, headers, timeout=12)
        if r is None:
            res["detail"] = "no HTTP client"
            return res
        res["checked"] = True
        hdrs = {str(k).lower(): str(v) for k, v in (getattr(r, "headers", {}) or {}).items()}
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "").lower()
        res["acao"] = acao
        res["acac"] = acac
        if acao == test_origin:
            res["vulnerable"] = True
            res["detail"] = ("Origin reflected + credentials allowed (critical)"
                              if acac == "true" else "Origin reflected (any origin accepted)")
        elif acao == "*" and acac == "true":
            res["vulnerable"] = True
            res["detail"] = "Wildcard ACAO + Allow-Credentials:true (invalid combo, but a misconfiguration signal)"
    except Exception as e:
        if log:
            log.debug(f"[CORS] {url} check failed: {e}")
    return res


def _resolve_cname(domain: str, timeout: int = 8) -> str:
    try:
        r = subprocess.run(["dig", "+short", "CNAME", domain], shell=False,
                           capture_output=True, text=True, timeout=timeout)
        for line in (r.stdout or "").splitlines():
            line = line.strip().rstrip(".")
            if line:
                return line.lower()
    except Exception:
        pass
    return ""


def check_subdomain_takeover(host_url: str, cfg: dict, log=None) -> dict:
    """CNAME kaydini bilinen servis fingerprint'leriyle karsilastirir; eslesirse
    HTTP govde imzasiyla dogrular. Sadece tespit — devralma denemesi yapmaz."""
    res = {"host": host_url, "vulnerable": False, "service": "", "cname": "", "detail": ""}
    domain = _extract_domain_from_any(host_url)
    if not domain:
        return res
    cname = _resolve_cname(domain)
    if not cname:
        return res
    res["cname"] = cname
    match = None
    for frag, service, sigs in _TAKEOVER_FINGERPRINTS:
        if frag in cname:
            match = (service, sigs)
            break
    if not match:
        return res
    service, sigs = match
    try:
        r = _timed_get(f"https://{domain}", cfg, pick_header_strategy(domain, cfg), timeout=10)
        if r is None:
            res["detail"] = f"CNAME -> {service} detected but HTTP verification could not run"
            return res
        body = (getattr(r, "text", "") or "").lower()
        for sig in sigs:
            if sig in body:
                res["vulnerable"] = True
                res["service"] = service
                res["detail"] = f"CNAME -> {cname} ({service}); body signature matched: '{sig}'"
                return res
        res["service"] = service
        res["detail"] = f"CNAME -> {cname} ({service}) but body signature did not match (low probability)"
    except Exception as e:
        res["service"] = service
        res["detail"] = f"CNAME -> {cname} ({service}); HTTP verification error: {e}"
        if log:
            log.debug(f"[TAKEOVER] {domain} check failed: {e}")
    return res


def find_cloud_bucket_candidates(url_files: list) -> list:
    """Kesfedilen URL/domain havuzunda gecen cloud storage bucket adaylarini bulur."""
    found = set()
    for f in url_files:
        if not f or not Path(f).exists():
            continue
        try:
            text = Path(f).read_text(errors="replace")
        except Exception:
            continue
        for m in _PAT_CLOUD_BUCKET.finditer(text):
            bucket = m.group("bucket") or m.group("bucket2") or m.group("bucket3") or m.group("bucket4")
            if not bucket:
                continue
            full = m.group(0)
            if "amazonaws.com" in full:
                if ".s3" in full:
                    candidate_url = f"https://{bucket}.s3.amazonaws.com/"
                else:
                    candidate_url = f"https://s3.amazonaws.com/{bucket}/"
                found.add((candidate_url, "AWS S3"))
            elif "storage.googleapis.com" in full:
                found.add((f"https://storage.googleapis.com/{bucket}/", "Google Cloud Storage"))
            elif "blob.core.windows.net" in full:
                found.add((f"https://{bucket}.blob.core.windows.net/?comp=list", "Azure Blob Storage"))
    return sorted(found)


def _cloud_enum_script() -> tuple:
    """(argv0..., cwd) for cloud_enum. Empty argv0 means it is not installed."""
    system = shutil.which("cloud_enum") or shutil.which("cloud_enum.py")
    if system:
        return [system], None
    local = Path.home() / ".local" / "share" / "reconx" / "cloud_enum" / "cloud_enum.py"
    if local.exists():
        return [sys.executable, str(local)], str(local.parent)
    return [], None


def _bucket_keywords(target: str) -> list:
    """The name a bucket is usually built from: the organisation label, not every host."""
    host = (target or "").strip().lower()
    host = host.split("://")[-1].split("/")[0].split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    skip = {"www", "com", "net", "org", "edu", "gov", "ac", "co", "io", "lab",
            "local", "tr", "uk", "de", "fr", "app", "dev", "www2"}
    labels = [p for p in host.split(".") if p and p not in skip]
    keys = []
    for label in labels[:2]:
        key = re.sub(r"[^a-z0-9-]", "", label)
        if len(key) >= 3 and key not in keys:
            keys.append(key)
    return keys[:2]


def run_cloud_enum(keywords: list, out_dir: Path, cfg: dict) -> dict:
    """Find open and protected buckets for these names. Read-only.

    cloud_enum probes AWS S3, Azure and Google Cloud. Hits are returned for
    the report; the tool is not asked to download object bodies.
    """
    out = {"ran": False, "error": "", "hits": [], "keywords": list(keywords or [])}
    argv0, cwd = _cloud_enum_script()
    if not argv0:
        out["error"] = "cloud_enum is not installed"
        return out
    if not keywords:
        out["error"] = "no keyword could be derived from the target"
        return out
    threads = int(_cfg_get(cfg, "tools", "cloud_enum_threads", default=8) or 8)
    threads = max(1, min(threads, 20))
    budget = int(_cfg_get(cfg, "tools", "cloud_enum_timeout", default=900) or 900)
    budget = max(30, budget)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    logf = out_dir / "cloud_enum.jsonl"
    try:
        logf.write_text("", encoding="utf-8")
    except OSError:
        pass
    argv = list(argv0)
    for key in keywords:
        argv += ["-k", key]
    argv += ["-t", str(threads), "-f", "json", "-l", str(logf)]
    info(f"Cloud bucket: cloud_enum keywords {', '.join(keywords)} "
         f"(AWS S3, Azure, Google Cloud, {threads} threads, {budget}s cap)")
    try:
        proc = subprocess.Popen(
            argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True)
    except Exception as exc:
        out["error"] = str(exc)
        return out
    t0 = time.time()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if _INT.stage_skip() or (time.time() - t0) > budget:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    proc.kill()
                break
            text = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
            if not text or text.endswith("complete..."):
                continue
            if text.startswith("FILES:") or text.startswith("->"):
                continue
            sub(text[:200])
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    finally:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
    out["ran"] = True
    hits = []
    seen = set()
    try:
        for line in logf.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if not isinstance(rec, dict):
                continue
            url = str(rec.get("target") or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)
            access = str(rec.get("access") or "").lower()
            platform = str(rec.get("platform") or "").lower()
            provider = {"aws": "AWS S3", "azure": "Azure", "gcp": "Google Cloud"}.get(platform, platform or "cloud")
            public = access == "public"
            hits.append({
                "url": url,
                "provider": provider,
                "status": "exists_public" if public else "exists_protected",
                "public_listing": public,
                "detail": str(rec.get("msg") or ("public listing" if public else "exists, access denied")),
            })
    except OSError:
        pass
    out["hits"] = hits
    return out


def check_cloud_bucket(bucket_url: str, provider: str, cfg: dict, log=None) -> dict:
    """Bucket'in var olup olmadigini ve genel listelemeye acik olup olmadigini kontrol eder.
    Yalnizca GET/HEAD ile okur — yazma/silme denemesi asla yapilmaz."""
    res = {"url": bucket_url, "provider": provider, "status": "unknown", "public_listing": False, "detail": ""}
    timeout = int(_cfg_get(cfg, "tools", "cloud_bucket_timeout", default=10))
    try:
        r = _timed_get(bucket_url, cfg, {"User-Agent": _pick_ua()}, timeout=timeout)
        if r is None:
            res["detail"] = "no HTTP client"
            return res
        status = int(getattr(r, "status_code", 0) or 0)
        body = (getattr(r, "text", "") or "")[:4000]
        bl = body.lower()
        if status == 200 and ("<listbucketresult" in bl or "<enumerationresults" in bl or "<blobs" in bl):
            res["status"] = "exists_public"
            res["public_listing"] = True
            res["detail"] = "Bucket is publicly listable — SENSITIVE"
        elif "nosuchbucket" in bl or "the specified bucket does not exist" in bl or status == 404:
            res["status"] = "not_found"
            res["detail"] = "Bucket not found"
        elif "accessdenied" in bl or status == 403:
            res["status"] = "exists_protected"
            res["detail"] = "Bucket exists but access denied (protected)"
        else:
            res["status"] = f"http_{status}"
            res["detail"] = f"Ambiguous response (status={status})"
    except Exception as e:
        res["detail"] = f"request error: {e}"
        if log:
            log.debug(f"[BUCKET] {bucket_url} check failed: {e}")
    return res


# ══════════════════════════════════════════════════════════════════════════════

def _crtsh_enum(domain: str, timeout: int = 20) -> list:
    """crt.sh fallback — passive subdomain discovery, needs no API key."""
    try:
        client, is_cffi = _get_http_client({"settings": {"use_curl_cffi": False}})
        if client is None:
            import requests as _rq
            client = _rq
            is_cffi = False
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        kw = dict(timeout=timeout, headers={"User-Agent": _pick_ua()})
        kw["verify"] = False
        if is_cffi:
            kw["impersonate"] = "chrome120"
        r = client.get(url, **kw)
        data = r.json() if hasattr(r, "json") else []
        subs = set()
        for e in data or []:
            name = (e.get("name_value") or e.get("common_name") or "")
            for n in str(name).splitlines():
                n = n.strip().lower().lstrip("*.").strip()
                if n and (n == domain or n.endswith("." + domain)):
                    subs.add(n)
        return sorted(subs)
    except Exception:
        return []

def evaluate_prune(before, after, elapsed, threads, req_timeout, max_pct,
                   survivor_positions=None):
    """Decide whether a high-removal httpx prune is a dead corpus or a throttle.

    A blunt "removed more than 70%" rule treats a real Wayback corpus — where
    most archived URLs are long gone — as a rate-limit, and then every later
    stage scans the dead list. The throttle signature observed in the field is
    different: survivors clustered in the first part of the input, nothing past
    that point. A probe that finishes far faster than a timeout storm is the
    other half of the evidence.

    Returns (trust, reason). trust=True means keep the pruned file.
    """
    if before <= 0:
        return False, "empty input"
    removed_pct = (before - after) / before * 100.0
    if before < 50 or removed_pct <= float(max_pct):
        return True, "within the removal limit"

    positions = list(survivor_positions or [])
    if after > 0 and positions and len(positions) >= after * 0.5:
        npos = len(positions)
        in_first = sum(1 for p in positions if p < before * 0.25)
        in_last_half = sum(1 for p in positions if p >= before * 0.5)
        last = max(positions)
        if (in_first / npos >= 0.90 and in_last_half / npos < 0.02
                and last < before * 0.40):
            return False, (
                f"removed {removed_pct:.1f}% and the live URLs all sit in the "
                f"first part of the list — the probe was rate-limited, not a dead corpus")
        if in_last_half / npos >= 0.10:
            return True, (
                f"removed {removed_pct:.1f}%, and live URLs are spread through the "
                f"list — dead archive URLs, not a prefix-only probe")

    floor = (before / max(int(threads) or 1, 1)) * max(float(req_timeout), 1.0)
    if elapsed > 0 and elapsed < floor * 0.35:
        return True, (
            f"probe finished in {elapsed:.0f}s; a timeout storm of {before:,} URLs "
            f"on {int(threads)} threads would take at least {floor:.0f}s, so the "
            f"dropped URLs answered with a filtered status")
    return False, (
        f"removed {removed_pct:.1f}% (over the {float(max_pct):.0f}% limit) and the "
        f"probe was slow enough that throttling cannot be ruled out")


def _survivor_positions(raw_path: Path, live_path: Path) -> list:
    """Indexes in the raw URL file of lines that also appear in the live file."""
    live = set()
    try:
        for line in live_path.read_text(errors="ignore").splitlines():
            s = line.strip()
            if s:
                live.add(s)
                live.add(s.rstrip("/"))
    except Exception:
        return []
    positions = []
    try:
        for i, line in enumerate(raw_path.read_text(errors="ignore").splitlines()):
            s = line.strip()
            if s and (s in live or s.rstrip("/") in live):
                positions.append(i)
    except Exception:
        return []
    return positions


class ReconPipeline:
    def __init__(self, target, cfg, resume=False, auto_mode=False,
                 url_targets=None, login_url=None, login_user=None, login_pass=None,
                 login_user_field="username", login_pass_field="password",
                 login_extra_fields=None, login_method="POST",
                 login_success_indicator="", login_failure_indicator="",
                 login_csrf_field="", raw_cookie=None, request_file=None,
                 nuclei_templates_override=None, nuclei_severity_override=None,
                 blind_cb=None, config_path=None, session_dir=None,
                 max_time_min=0, scan_diff=True, xss_payloads=None,
                 ai_bridge_disabled=False, only_checks=None,
                 service_port=None):
        self.target      = target.strip()
        try:
            self.service_port = int(service_port) if service_port else None
        except (TypeError, ValueError):
            self.service_port = None
        if self.service_port is not None and not (1 <= self.service_port <= 65535):
            self.service_port = None
        self.cfg         = cfg
        self._config_path = Path(config_path) if config_path else CFG_FILE
        self.ai_bridge_disabled = bool(ai_bridge_disabled)
        # stage12 passive-check sub-selection (report exposes these as separate
        # buttons); None / empty means run all three checks.
        self.only_checks = set(only_checks) if only_checks else None
        self.ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
        _out_root = (os.environ.get("RECONX_OUTPUT_DIR") or "").strip()
        self._out_root = Path(_out_root) if _out_root else BASE_DIR / "output"
        self.resume      = resume
        target_slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.target).strip("._") or "target"
        self._target_slug = target_slug
        # Resume writes back into the ORIGINAL session directory so the stages
        # already on disk keep their artefacts. main() normally resolves that
        # directory (it needs the state to prompt the operator anyway) and
        # hands it over as session_dir; the glob below is the fallback for
        # callers that only pass resume=True.
        if resume and session_dir:
            self.out = Path(session_dir)
        elif resume:
            found = find_sessions(self._out_root, target_slug, completed=False)
            if not found:
                found = [(d, {}) for d in sorted(self._out_root.glob(f"{target_slug}_*"),
                                                 key=lambda x: x.stat().st_mtime if x.exists() else 0,
                                                 reverse=True) if d.is_dir()]
            self.out = found[0][0] if found else self._out_root / f"{target_slug}_{self.ts}"
        else:
            self.out = self._out_root / f"{target_slug}_{self.ts}"
        # --auto: run the entire pipeline unattended — never block on the
        # legal-authorization prompt or the stage 6 (XSS/Dalfox) / stage 7
        # (Nuclei) "do you want to run this?" confirmations, so the tool can
        # be launched from a scheduler/CI/background job with zero stdin.
        self.auto_mode   = bool(auto_mode)
        self._blind_cb   = (blind_cb or "").strip()
        self._xss_payloads = (xss_payloads or "").strip()
        self.url_targets = url_targets or []
        self.summary     = {}
        self.log         = None

        self.login_url             = (login_url or "").strip()
        self.login_user            = login_user or ""
        self.login_pass            = login_pass or ""
        self.login_user_field      = login_user_field or "username"
        self.login_pass_field      = login_pass_field or "password"
        self.login_extra_fields    = login_extra_fields or {}
        self.login_method          = (login_method or "POST").upper()
        self.login_success_indicator = login_success_indicator or ""
        self.login_failure_indicator = login_failure_indicator or ""
        self.login_csrf_field      = login_csrf_field or ""
        self.raw_cookie            = (raw_cookie or "").strip()
        self.request_file           = (request_file or "").strip()
        self.auth_cookie_header    = ""
        self.auth_cookies          = {}
        self.auth_status           = "not_attempted"

        self.katana_needs_sudo = False
        self.katana_available  = tool_exists("katana")

        self.adapt_mult      = 1.0
        self.waf_fingerprint = []
        self.block_ratio     = 0.0
        self.adaptive_events = []

        self.xss_results     = None
        self.xss_asked       = False
        self.xss_chosen      = False
        self.js_results      = None
        self.tech_summary    = []
        self.extra_results   = None  # v6.13: CORS/takeover/bucket sonuclari
        self.network_results = None  # v9.4: stage14 naabu/nmap port scan
        self.open_redirect_results = None  # v9.4: stage15 nuclei open-redirect

        self._nuclei_tpl_path = None
        self._nuclei_tpl_override = nuclei_templates_override or ""
        self._nuclei_severity_override = nuclei_severity_override or ""
        self.nuclei_results = None
        self.nuclei_asked = False
        self.nuclei_chosen = False
        self.nuclei_dast_results = None

        for d in ["01_recon", "02_subdomains", "03_alive", "04_urls",
                  "05_categorized", "06_authenticated", "07_nuclei",
                  "07_xss", "09_params", "10_js_secrets", "11_tech",
                  "12_extra", "13_api", "checkpoints"]:
            (self.out / d).mkdir(parents=True, exist_ok=True)

        self.log = setup_logger(self.out / "pipeline.log")

        # ── checkpoint/resume state ──────────────────────────────────────────
        # Created AFTER the directory tree exists so the very first save() has
        # somewhere to land. On a resume run the previous state is read back and
        # every completed stage's stored summary is seeded into self.summary, so
        # the final report contains the whole scan and not just the stages this
        # particular invocation happened to execute.
        self.state = ScanState(self.out, self.target)
        if self.resume and self.state.load():
            for n in self.state.done_stages():
                saved = self.state.stage_info(n).get("summary")
                if isinstance(saved, dict):
                    self.summary[f"stage{n}"] = dict(saved)
        self.state.data["interrupted"] = False
        self.state.data["interrupt_reason"] = ""
        self.state.save()

        # ── global wall-clock budget (--max-time) ────────────────────────────
        # 0 = unlimited. When the deadline passes the watchdog raises the same
        # "hard stop" flag Ctrl+C option 3 raises: running tools are killed, the
        # state file is flagged interrupted, and a report is produced from what
        # was collected — the run stays resumable.
        self.max_time_min  = max(0, int(max_time_min or 0))
        self.deadline      = (time.time() + self.max_time_min * 60) if self.max_time_min else None
        self._budget_fired = False
        self._watchdog     = None
        self._wd_stop      = None

        # ── scan diff (--no-diff to disable) ─────────────────────────────────
        self.want_diff = bool(scan_diff)
        self.scan_diff = {}

        atexit.register(self._emergency_save)
        self.tor = _TorManager(self.cfg, log=self.log)
        atexit.register(self.tor.stop)
        self._precheck_katana_permission()

    def _emergency_save(self):
        """atexit hook — last line of defence for an unexpected death (SIGKILL
        of a child, an uncaught exception, the terminal going away). The state
        file is normally already current; this just makes sure the run is not
        left claiming to be 'running' and that a SUMMARY.json exists."""
        try:
            if getattr(self, "state", None) and not self.state.data.get("finalized"):
                self.state.mark_interrupted(self.state.data.get("interrupt_reason") or "process exit")
        except Exception:
            pass
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
        """Legacy in-stage resume shortcut — now gated by the checkpoint state.

        A checkpoint FILE existing is not proof its stage finished: a stage
        killed mid-run (Ctrl+C, --max-time, a crash) leaves a PARTIAL file
        behind, and the old "file exists -> resumed, done" rule then adopted
        that truncated set as the stage's final answer — a scan silently
        continuing on 6 subdomains instead of 29,000. So the file must exist
        AND state.json must record that stage as done."""
        p = self._cp(name)
        if not (self.resume and p.exists() and p.stat().st_size > 0):
            return False
        m = re.match(r"stage(\d+)", name)
        if m and not self.state.is_done(int(m.group(1))):
            return False
        return True

    def _is_root(self) -> bool:
        try:
            return os.geteuid() == 0
        except Exception:
            return False

    def _precheck_katana_permission(self):
        if not self.katana_available:
            return
        try:
            r = subprocess.run(["katana", "-version"], shell=False, capture_output=True, text=True, timeout=5)
            out = (r.stdout or "") + (r.stderr or "")
            if "permission denied" in out.lower() or "could not read flags" in out.lower():
                self.katana_needs_sudo = True
                if not self._is_root():
                    warn("katana requires sudo on this system.")
        except Exception:
            pass

    def _resolve_ip(self, domain: str) -> str:
        try:
            import socket
            ip = socket.gethostbyname(domain)
            if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return ip
        except Exception:
            pass
        for argv in (["dig", "+short", domain], ["host", domain]):
            try:
                r = subprocess.run(argv, shell=False, capture_output=True, text=True, timeout=10)
                text = (r.stdout or "") + "\n" + (r.stderr or "")
                m = re.search(r"(?m)^\s*(\d+\.\d+\.\d+\.\d+)\s*$", text)
                if not m:
                    m = re.search(r"has address\s+(\d+\.\d+\.\d+\.\d+)", text)
                if m:
                    return m.group(1)
            except Exception:
                pass
        return ""

    def _apply_adaptive(self, reason: str, extra_backoff: float = 1.0):
        if bool(_cfg_get(self.cfg, "settings", "adaptive_rate", default=True)):
            floor = float(_cfg_get(self.cfg, "settings", "adaptive_floor_mult", default=0.25))
            before = float(self.adapt_mult)
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
        # v8.8: hiz dusurmenin yaninda/yerine, engelleme gercekten fiiliyse
        # (bkz. cagiran yerler) yerel Tor uzerinden IP/devre rotasyonu dener.
        # _hard (kullanici "tamamen durdur" secti) sirasinda asla tetiklenmez.
        # Rotasyon olayi, report_builder'in zaten cizdigi "Adaptive Rate"
        # zaman cizelgesine eklenir — ayri bir rapor alani gerekmez.
        if not _INT.hard() and self.tor.rotate(reason):
            self.adaptive_events.append({
                "ts": datetime.now().isoformat(timespec="seconds"),
                "reason": f"Tor IP rotasyonu ({reason}) — devre #{self.tor.total_rotations}",
                "mult_before": round(float(self.adapt_mult), 4),
                "mult_after": round(float(self.adapt_mult), 4),
            })

    def _tuned_threads(self, base: int, cap: int) -> int:
        base = int(base); cap = int(cap)
        v = max(1, int(round(base * self.adapt_mult)))
        return min(max(1, v), cap)

    def _tuned_rate(self, base: int, cap: int) -> int:
        base = int(base); cap = int(cap)
        v = max(1, int(round(base * self.adapt_mult)))
        return min(max(1, v), cap)

    # ── Scope enforcement ─────────────────────────────────────────────────────
    def _scope_hosts(self):
        hosts = set()
        for value in [self.target, self.login_url, *self.url_targets]:
            h = _extract_domain_from_any(value)
            if h:
                hosts.add(h.lower().rstrip("."))
        return hosts

    def _is_in_scope_url(self, url: str) -> bool:
        try:
            host = (urlparse(url).hostname or "").lower().rstrip(".")
        except Exception:
            return False
        if not host:
            return False
        allowed = self._scope_hosts()
        # scope dışı hostları sessizce filtrele — bug bounty kapsamında kritik
        return any(host == base or host.endswith("." + base) for base in allowed)

    def _auth_headers_for_url(self, url: str, base_headers: dict = None) -> dict:
        h = dict(base_headers or {})
        if self.auth_cookie_header and self._is_in_scope_url(url):
            h["Cookie"] = self.auth_cookie_header
        return h

    def _auth_headers(self, base_headers: dict = None) -> dict:
        h = dict(base_headers or {})
        if self.auth_cookie_header and (not self.target or self._is_in_scope_url(self.login_url or f"https://{self.target}")):
            h["Cookie"] = self.auth_cookie_header
        return h

    def has_auth(self) -> bool:
        return bool(self.auth_cookie_header)

    # ── Stage L — Login / Authenticated session ────────────────────────────────
    def stageL_login(self):
        stage("L", "Authenticated Session (Login)")
        d = self.out / "06_authenticated"

        if self.request_file:
            info(f"Replaying authenticated request: {self.request_file}")
            res = perform_request_login(
                request_file=self.request_file,
                cfg=self.cfg,
                timeout=T.get("login", 60),
                log=self.log,
            )
            if res.get("ok") and res.get("cookie_header"):
                self.auth_cookie_header = res["cookie_header"]
                self.auth_cookies = res.get("cookies", {})
                self.auth_status = "request_file_success"
                ok(f"Request login successful — {len(self.auth_cookies)} cookie(s) captured "
                   f"(status={res.get('status')})")
            else:
                self.auth_status = "request_file_failed"
                warn(f"Request login failed or no session cookie obtained "
                    f"(status={res.get('status')}, error={res.get('error','')})")

            safe_dump = {
                "mode": "request_file",
                "request_file": str(Path(self.request_file).name),
                "request_url": res.get("request_url"),
                "method": res.get("method"),
                "status": res.get("status"),
                "ok": res.get("ok"),
                "final_url": res.get("final_url"),
                "cookie_names": list(self.auth_cookies.keys()),
                "error": res.get("error", ""),
            }
            (d / "auth_info.json").write_text(
                json.dumps(safe_dump, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            self.summary["stageL"] = {
                "status": self.auth_status,
                "mode": "request_file",
                "cookie_names": list(self.auth_cookies.keys()),
            }
            return

        if self.raw_cookie and not self.login_url:
            self.auth_cookie_header = self.raw_cookie
            self.auth_status = "cookie_provided"
            ok("Raw cookie provided — skipping login request")
            (d / "auth_info.json").write_text(json.dumps({
                "mode": "raw_cookie", "cookie_header": "***redacted***"
            }, indent=2), encoding="utf-8")
            self.summary["stageL"] = {"status": "done", "mode": "raw_cookie"}
            return

        if not self.login_url:
            self.summary["stageL"] = {"status": "skipped", "reason": "no_login_url"}
            return

        if not self.login_user or not self.login_pass:
            warn("Login URL verildi ama kullanici adi/sifre eksik — login atlaniyor")
            self.summary["stageL"] = {"status": "skipped", "reason": "missing_credentials"}
            return

        info(f"Logging in: {self.login_url} (user field={self.login_user_field})")
        res = perform_login(
            login_url=self.login_url,
            username=self.login_user,
            password=self.login_pass,
            cfg=self.cfg,
            user_field=self.login_user_field,
            pass_field=self.login_pass_field,
            extra_fields=self.login_extra_fields,
            method=self.login_method,
            success_indicator=self.login_success_indicator,
            failure_indicator=self.login_failure_indicator,
            csrf_field=self.login_csrf_field,
            timeout=T.get("login", 60),
            log=self.log,
        )

        if self.raw_cookie:
            extra_pairs = []
            for part in self.raw_cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    extra_pairs.append(part)
            if res.get("cookie_header"):
                res["cookie_header"] = res["cookie_header"] + "; " + "; ".join(extra_pairs)
            else:
                res["cookie_header"] = "; ".join(extra_pairs)

        if res.get("ok") and res.get("cookie_header"):
            self.auth_cookie_header = res["cookie_header"]
            self.auth_cookies       = res.get("cookies", {})
            self.auth_status        = "success"
            ok(f"Login successful — {len(self.auth_cookies)} cookie(s) captured "
               f"(status={res.get('status')}, csrf_used={res.get('csrf_used')})")
        else:
            self.auth_status = "failed"
            warn(f"Login failed or no session cookie obtained "
                 f"(status={res.get('status')}, error={res.get('error','')}) "
                 f"— continuing as unauthenticated scan")

        safe_dump = {
            "login_url": self.login_url,
            "status": res.get("status"),
            "ok": res.get("ok"),
            "final_url": res.get("final_url"),
            "csrf_used": res.get("csrf_used"),
            "cookie_names": list(self.auth_cookies.keys()),
            "error": res.get("error", ""),
        }
        (d / "auth_info.json").write_text(json.dumps(safe_dump, indent=2, ensure_ascii=False), encoding="utf-8")
        self.summary["stageL"] = {"status": self.auth_status,
                                   "cookie_names": list(self.auth_cookies.keys())}

    # ── Stage 8 — Authenticated crawl (post-login internal recon) ──────────────
    def stage8_authenticated_crawl(self):
        stage(8, "Authenticated Crawl (post-login)")
        d = self.out / "06_authenticated"
        if not self.has_auth():
            warn("No authenticated session available — skipping authenticated crawl")
            self.summary["stage8"] = {"status": "skipped", "reason": "no_auth_session"}
            return

        alive_file = self._cp("stage3_alive")
        seed_hosts = []
        if alive_file.exists() and alive_file.stat().st_size > 0:
            seed_hosts = [l.strip() for l in alive_file.read_text(errors="ignore").splitlines() if l.strip()]
        if not seed_hosts:
            seed_hosts = [self.login_url or f"https://{self.target}"]
        auth_info_f = d / "auth_info.json"
        if auth_info_f.exists():
            try:
                info_j = json.loads(auth_info_f.read_text(errors="replace"))
                fu = info_j.get("final_url")
                if fu and fu not in seed_hosts:
                    seed_hosts.insert(0, fu)
            except Exception:
                pass

        seed_file = d / "authenticated_seed_hosts.txt"
        write_lines(seed_file, seed_hosts)

        auth_headers = self._auth_headers_for_url(seed_hosts[0] if seed_hosts else f"https://{self.target}",
                                                   pick_header_strategy(self.target, self.cfg))
        found_files = []

        httpx_bin = _pd_httpx()
        if httpx_bin:
            base_threads = int(_cfg_get(self.cfg, "settings", "threads", default=50))
            threads = self._tuned_threads(min(base_threads, 80), 80)
            httpx_json = d / "httpx_authenticated.json"
            httpx_cmd = (
                f"{httpx_bin} -l {seed_file} -no-color {_stats_cli(_help_text(httpx_bin), 2)}"
                f"-threads {threads} -timeout 20 -retries 2 "
                f"-follow-redirects -status-code -title -tech-detect -content-length "
                + (f"-http-proxy {_resolve_proxy(self.cfg)} " if _TOR_ACTIVE.is_set() else "")
                + _hdr_args_httpx(auth_headers)
                + f" -json -o {httpx_json}"
            )
            run_cmd(httpx_cmd, timeout=T["httpx"], log=self.log, label=httpx_bin, retries=1, retry_delay=5)
            found_files.append(httpx_json)

        katana_urls = d / "katana_authenticated.txt"
        if self.katana_available and not (self.katana_needs_sudo and not self._is_root()):
            kh = _help_text("katana")
            conc = self._tuned_threads(10, 20)
            hdr_flags = " ".join([f'-H "{k}: {v}"' for k, v in auth_headers.items()])
            flags = " ".join(filter(None, [
                "-silent",
                "-jc" if "-jc" in kh else "",
                "-d 5",
                f"-concurrency {conc}" if "-concurrency" in kh else "",
                "-timeout 15" if "-timeout" in kh else "",
                " ".join(_tor_cli_flag("katana", self.cfg)),
            ]))
            run_cmd(f"katana -list {seed_file} {flags} {hdr_flags} -o {katana_urls}",
                    timeout=T["katana"], log=self.log, label="katana-auth", retries=1, retry_delay=8)
            found_files.append(katana_urls)
        else:
            sub("katana not available for authenticated crawl")

        merged = d / "authenticated_urls.txt"
        def _url_ok(line):
            if not line.startswith("http"): return False
            if not self._is_in_scope_url(line): return False
            try:
                return not _PAT_SKIP.search(urlparse(line).path)
            except Exception:
                return False
        normalize = canonicalize_url if bool(_cfg_get(self.cfg, "settings", "canonicalize_urls", default=True)) else None
        text_sources = [f for f in found_files if f.suffix == ".txt"]
        dedup_files_normalized(text_sources, merged, filter_fn=_url_ok, normalize_fn=normalize)

        httpx_json = d / "httpx_authenticated.json"
        extra_urls = []
        if httpx_json.exists() and httpx_json.stat().st_size > 0:
            with httpx_json.open(errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        u = rec.get("url") or ""
                        if u.startswith("http"):
                            extra_urls.append(u)
                    except Exception:
                        continue
        if extra_urls:
            existing = set(l.strip() for l in merged.read_text(errors="ignore").splitlines() if l.strip()) if merged.exists() else set()
            with merged.open("a", encoding="utf-8") as fo:
                for u in extra_urls:
                    uu = canonicalize_url(u) if normalize else u
                    if uu not in existing:
                        existing.add(uu)
                        fo.write(uu + "\n")

        checkpoint(self._cp("stage8_authenticated_urls"),
                   [l.strip() for l in merged.read_text(errors="ignore").splitlines() if l.strip()] if merged.exists() else [],
                   "authenticated-urls")

        if merged.exists() and merged.stat().st_size > 0:
            cat_dir = d / "categorized"
            counts = categorise_streaming(merged, cat_dir)
            self.summary["stage8"] = {
                "status": "done",
                "count": _count_lines(merged),
                "categories": {k: v for k, v in counts.items() if v > 0},
            }
            ok(f"Authenticated crawl complete — {_count_lines(merged):,} URLs behind login")
        else:
            self.summary["stage8"] = {"status": "done", "count": 0, "note": "no_urls_found"}
            warn("Authenticated crawl produced no URLs — check login success / seed hosts")

    def _host_url(self, host: str) -> str:
        """URL for one hostname. An explicit -d host:port is kept; otherwise
        the historical default is https on 443."""
        host = (host or "").strip()
        if host.startswith(("http://", "https://")):
            return host
        port = self.service_port
        if port in (443, 8443):
            return f"https://{host}" if port == 443 else f"https://{host}:{port}"
        if port == 80:
            return f"http://{host}"
        if port:
            return f"http://{host}:{port}"
        return f"https://{host}"

    # ── Stage 1 ───────────────────────────────────────────────────────────────
    def stage1_recon(self):
        stage(1, "Initial Reconnaissance")
        d   = self.out / "01_recon"
        tgt = self.target
        # v8.3-fix: self.target is always the BARE host (port stripped — see
        # "Domain auto-detected: <host>" at startup), even in -u/--single/-U
        # seed-URL mode where the real target has an explicit non-standard
        # port (e.g. http://192.168.x.x:4000/). Every HTTP-based check below
        # used to hardcode "https://{tgt}" (implying :443) or bare "{tgt}"
        # (whatweb defaults to :80) — against a target that's ONLY listening
        # on some other port, that's a guaranteed-wrong connection attempt,
        # not a real "target down" signal. Confirmed against a real scan log:
        # the initial HTTPS probe failed to connect on :443, and whatweb
        # returned 0 lines three times in a row (with retry waits burning
        # ~15s) — both against a site that was actually up the whole time on
        # :4000. Reusing the real seed URL's scheme+host+port here (when one
        # was given) fixes all of that; subdomain-enum mode (no url_targets)
        # is completely unaffected since _probe_base then falls back to the
        # exact old "https://{tgt}" default.
        _seed_parsed = urlparse(self.url_targets[0]) if self.url_targets else None
        if self.service_port and not self.url_targets:
            _probe_base = self._host_url(tgt)
            _seed_parsed = urlparse(_probe_base)
        _probe_netloc = (_seed_parsed.netloc if (_seed_parsed and _seed_parsed.netloc) else tgt)
        _probe_scheme = (_seed_parsed.scheme if (_seed_parsed and _seed_parsed.scheme) else "https")
        _probe_base = f"{_probe_scheme}://{_probe_netloc}"
        target_ip = self._resolve_ip(tgt)
        if target_ip:
            ok(f"IP resolved: {tgt} → {target_ip}")
        else:
            warn("IP resolution failed — continuing with domain")
        probe = {}
        try:
            probe = http_probe(_probe_base, self.cfg, timeout=12)
            # A scheme that never connects (HTTPS on an HTTP-only test app, or
            # the reverse) used to be recorded as a failed probe and then every
            # later stage kept using it — httpx returned 0 hosts, whatweb 0
            # lines, the crawl hit a dead port. Try the other scheme once
            # before giving up.
            if not probe.get("ok"):
                alt = _flip_scheme(_probe_base)
                if alt:
                    sub(f"HTTP probe failed on {_probe_base} — trying {alt}")
                    alt_probe = http_probe(alt, self.cfg, timeout=8)
                    if alt_probe.get("ok"):
                        probe = alt_probe
                        _probe_base = alt
                        self._retarget_scheme(urlparse(alt).scheme, urlparse(alt).hostname or "")
                        ok(f"Scheme fallback: continuing on {_probe_base} "
                           f"(the other scheme did not connect)")
            (d / "http_probe.json").write_text(json.dumps(probe, ensure_ascii=False, indent=2), encoding="utf-8")
            if probe.get("ok"):
                ok(f"HTTP probe: {probe.get('status')} "
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
        # v6.17: eskiden "whois {tgt} || whois -H {tgt} || true" tek bir string
        # olarak run_cmd'ye veriliyordu. run_cmd, guvenlik sertlestirmesinden beri
        # (v6.11) komutlari ASLA shell uzerinden calistirmiyor — shlex.split()
        # sadece bosluklara gore boluyor, yani "||" ve "true" kelimeleri whois'e
        # DOGRUDAN GECERSIZ ARGUMAN olarak gidiyordu ve whois her seferinde
        # cakiliyordu (exit 1). Duzeltme: fallback mantigi Python tarafinda.
        # whois exits 1 even when it printed a record, so a non-empty body is
        # the result. A hostname with no registration of its own
        # ("No match for testasp.vulnweb.com") is looked up one label higher.
        def _whois_miss(text: str) -> bool:
            head = (text or "").lower()[:500]
            if not head.strip():
                return True
            return any(s in head for s in ("no match for", "not found", "no data found", "no entries found"))

        if _is_private_or_local_host(tgt):
            sub(f"whois skipped: {tgt} is local or private — a public whois record does not exist")
            whois_out = ""
        else:
            _, whois_out = run_cmd(["whois", tgt], timeout=T["whois"], log=self.log,
                                   label="whois", retries=0)
        if _whois_miss(whois_out) and not _is_private_or_local_host(tgt):
            labels = [p for p in tgt.split(".") if p]
            parent = ".".join(labels[-2:]) if len(labels) > 2 else ""
            if parent and parent != tgt:
                sub(f"whois has no record for {tgt} — trying {parent}")
                _, parent_out = run_cmd(["whois", parent], timeout=T["whois"], log=self.log,
                                        label=f"whois {parent}", retries=0)
                if not _whois_miss(parent_out):
                    whois_out = parent_out
            if _whois_miss(whois_out):
                _, alt = run_cmd(["whois", "-H", parent or tgt], timeout=T["whois"],
                                 log=self.log, label="whois-H", retries=0)
                if not _whois_miss(alt):
                    whois_out = alt
        if whois_out.strip() and not _whois_miss(whois_out):
            (d / "whois.txt").write_text(whois_out, encoding="utf-8", errors="replace")
        nameservers = lookup_nameservers(tgt)
        if nameservers:
            (d / "dns.txt").write_text("\n".join(f"NS {ns}" for ns in nameservers) + "\n", encoding="utf-8")
            sub(f"DNS lookup: {', '.join(nameservers[:4])}")
        contact_bases = []
        if probe.get("ok") and probe.get("final_url"):
            contact_bases.append(probe["final_url"])
        elif probe.get("ok") and probe.get("url"):
            contact_bases.append(probe["url"])
        contact_bases.append(f"https://{tgt}")
        contact_bases.append(f"https://www.{tgt}")
        contact_bases.append(f"http://www.{tgt}")
        found = harvest_public_contacts(contact_bases, self.cfg, limit=8)
        if probe.get("emails") or probe.get("phones"):
            found = _merge_contacts(found, {"emails": probe.get("emails") or [],
                                            "phones": probe.get("phones") or [],
                                            "sources": [probe.get("final_url") or probe.get("url") or ""]})
        if found.get("emails") or found.get("phones"):
            (d / "contacts.json").write_text(json.dumps(found, ensure_ascii=False, indent=2), encoding="utf-8")
            sub(f"Site contacts: {len(found.get('emails') or [])} email, {len(found.get('phones') or [])} phone")
        if tool_exists("whatweb"):
            # v8.3-fix: was bare "{tgt}" (no scheme/port -> whatweb assumes
            # :80) — now the real seed scheme+port when one is known (see
            # _probe_base above).
            run_cmd(
                f"whatweb {_probe_base} -a 3 --open-timeout=10 --read-timeout=30 --log-verbose={d}/whatweb.txt",
                timeout=T["whatweb"], log=self.log, label="whatweb"
            )
        else:
            sub("whatweb not found")
        if tool_exists("wafw00f"):
            # v8.3-fix: try the seed's own scheme+port first (was always
            # "https://{tgt}" i.e. :443, wrong for a non-standard-port seed
            # URL); fall back to the OTHER scheme on the SAME host:port
            # (was falling back to bare "http://{tgt}" i.e. :80 — still the
            # wrong port for a seed URL like http://host:4000/).
            ok1, o1 = run_cmd(f"wafw00f {_probe_base} -a",
                              timeout=T["wafw00f"], log=self.log, label="wafw00f")
            if not ok1 or not o1.strip():
                _alt_scheme = "http" if _probe_scheme == "https" else "https"
                _, o1 = run_cmd(f"wafw00f {_alt_scheme}://{_probe_netloc} -a",
                                timeout=T["wafw00f"], log=self.log, label="wafw00f-alt")
            if o1.strip():
                (d / "wafw00f.txt").write_text(o1, encoding="utf-8", errors="replace")
        else:
            sub("wafw00f not found")
        if tool_exists("nmap"):
            nmap_target = target_ip if target_ip else tgt
            run_cmd(
                f"nmap -v -sV -sC --open -T4 --top-ports 1000 --min-rate 250 --version-intensity 2 "
                f"--stats-every 5s {nmap_target} -oN {d}/nmap.txt",
                timeout=T["nmap"], log=self.log, label="nmap", retries=1, retry_delay=5
            )
        else:
            sub("nmap not found")
        # v6.17: theHarvester kaldirildi — subfinder/assetfinder/findomain
        # (subdomain) + whatweb/wafw00f/nmap (fingerprint) zaten ayni isi
        # yapiyor; theHarvester genelde API anahtari gerektiren motorlar
        # yuzunden tutarsiz sekilde cakiyordu (exit 1).
        # v8.7: shodan kaldirildi — asil odak subdomain enum + URL kesfi
        # oldugu icin API-key gerektiren, sik sik 403/rate-limit yiyen bu
        # adim gereksiz gurultu uretiyordu.
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
            # Not: subfinder cogunlukla ucuncu-parti pasif API'leri sorgular
            # (hedefin kendisine degil) — Tor rotasyonu burada hedefin WAF'ini
            # degil, olsa olsa o API'lerin rate-limit'ini etkiler; yine de
            # tutarlilik icin diger araclarla ayni sekilde eklenir.
            _sf_tor = " ".join(_tor_cli_flag("subfinder", self.cfg))
            run_cmd(f"subfinder -d {tgt} -all {_sf_tor} -o {f}".replace("  ", " "),
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
        # v8.0: crt.sh passive fallback — API key gerektirmez, her zaman çalışır
        if bool(_cfg_get(self.cfg, "settings", "enable_crtsh_fallback", default=True)):
            try:
                crt_timeout = int(_cfg_get(self.cfg, "tools", "crtsh_timeout", default=20))
                crt_subs = _crtsh_enum(tgt, timeout=crt_timeout)
                if crt_subs:
                    info(f"crt.sh: {len(crt_subs):,} subdomains found")
                    existing = set(l.strip() for l in raw_f.read_text(errors="ignore").splitlines() if l.strip()) if raw_f.exists() else set()
                    with raw_f.open("a", encoding="utf-8") as fo:
                        for s in crt_subs:
                            if s not in existing:
                                fo.write(s + "\n")
                                existing.add(s)
            except Exception as e:
                if self.log:
                    self.log.debug(f"crt.sh fallback failed: {e}")

        local_names = _etc_hosts_names(tgt)
        if local_names:
            existing = set(l.strip().lower() for l in raw_f.read_text(errors="ignore").splitlines() if l.strip()) if raw_f.exists() else set()
            added = [n for n in local_names if n not in existing]
            if added:
                with raw_f.open("a", encoding="utf-8") as fo:
                    for n in added:
                        fo.write(n + "\n")
                info(f"/etc/hosts: {len(added):,} name(s) under {tgt}")
        lines = [l.strip() for l in raw_f.read_text(errors="ignore").splitlines() if l.strip()]
        if tgt not in lines:
            lines.insert(0, tgt)
            write_lines(raw_f, lines)
        final = [l.strip() for l in raw_f.read_text(errors="ignore").splitlines() if l.strip()]
        n = checkpoint(self._cp("stage2_subdomains"), final, "subdomains")
        info(f"Total unique subdomains: {n:,}")
        self.summary["stage2"] = {"status": "done", "count": n}

    def _fingerprint_target_list(self, urls) -> tuple:
        """One origin per live host. The apex is always first, then www, then
        the rest. A dead apex is still included so -d fingerprints the main
        domain the same way -u does, and falls through to www when that is
        the host that actually answered."""
        by_host = {}
        for raw in urls or []:
            raw = (raw or "").strip()
            if not raw:
                continue
            if not raw.startswith(("http://", "https://")):
                raw = self._host_url(raw)
            try:
                parsed = urlparse(raw)
            except Exception:
                continue
            host = (parsed.hostname or "").lower()
            if not host or not parsed.scheme or not parsed.netloc:
                continue
            origin = f"{parsed.scheme}://{parsed.netloc}"
            prev = by_host.get(host)
            if prev is None or (parsed.scheme == "https" and prev.startswith("http://")):
                by_host[host] = origin
        apex = (self.target or "").strip().lower()
        ordered = []
        if apex and apex in by_host:
            ordered.append(by_host.pop(apex))
        elif apex:
            ordered.append(self._host_url(apex))
        www = f"www.{apex}" if apex else ""
        if www and www in by_host:
            ordered.append(by_host.pop(www))
        ordered.extend(sorted(by_host.values()))
        seen = set()
        unique = []
        for origin in ordered:
            if origin in seen:
                continue
            seen.add(origin)
            unique.append(origin)
        cap = int(_cfg_get(self.cfg, "settings", "fingerprint_host_cap", default=60) or 60)
        cap = max(1, cap)
        return unique[:cap], max(0, len(unique) - cap)

    def _main_fingerprint_url(self, urls) -> str:
        """Prefer the apex when it answered. Otherwise the www host, which is
        the site most apex names redirect to. Last resort is the apex URL
        itself so the main domain is still tested."""
        by_host = {}
        for raw in urls or []:
            raw = (raw or "").strip()
            if not raw.startswith(("http://", "https://")):
                continue
            try:
                parsed = urlparse(raw)
            except Exception:
                continue
            host = (parsed.hostname or "").lower()
            if host and host not in by_host:
                by_host[host] = f"{parsed.scheme}://{parsed.netloc}"
        apex = (self.target or "").strip().lower()
        if apex and apex in by_host:
            return by_host[apex]
        www = f"www.{apex}" if apex else ""
        if www and www in by_host:
            return by_host[www]
        return self._host_url(apex or self.target)

    def _fingerprint_web_estate(self, urls):
        """whatweb/wafw00f for every live host. Stage 1 only ever sees the
        apex, and an apex that does not answer on :443 leaves an empty
        technology log while www and the subdomains are up. This pass runs
        after host validation, always includes the main domain, and writes a
        one-line record per host plus a detailed report for the main site."""
        targets, omitted = self._fingerprint_target_list(urls)
        if not targets:
            return
        d = self.out / "01_recon"
        d.mkdir(parents=True, exist_ok=True)
        listing = d / "fingerprint_targets.txt"
        write_lines(listing, targets)
        main = self._main_fingerprint_url(urls)
        if main not in targets:
            main = targets[0]
        info(f"Fingerprinting {len(targets):,} host(s), main site {main}")
        if omitted:
            sub(f"{omitted:,} further hosts left for a later pass "
                f"(settings.fingerprint_host_cap)")
        probe_path = d / "http_probe.json"
        probe = {}
        if probe_path.exists():
            try:
                probe = json.loads(probe_path.read_text(encoding="utf-8", errors="replace")) or {}
            except Exception:
                probe = {}
        if not probe.get("ok"):
            fresh = http_probe(main, self.cfg, timeout=12)
            if not fresh.get("ok"):
                alt = _flip_scheme(main)
                if alt:
                    alt_probe = http_probe(alt, self.cfg, timeout=8)
                    if alt_probe.get("ok"):
                        fresh = alt_probe
                        main = alt
            if fresh.get("ok"):
                probe_path.write_text(json.dumps(fresh, ensure_ascii=False, indent=2), encoding="utf-8")
                ok(f"HTTP probe: {fresh.get('status')} server={fresh.get('server', '?')} ({main})")
        if tool_exists("whatweb"):
            ww = d / "whatweb.txt"
            already = ""
            if ww.exists() and ww.stat().st_size > 40:
                already = ww.read_text(encoding="utf-8", errors="replace")
            if main not in already:
                if ww.exists():
                    try:
                        ww.unlink()
                    except Exception:
                        pass
                run_cmd(
                    ["whatweb", main, "-a", "3", "--open-timeout=10", "--read-timeout=30",
                     f"--log-verbose={ww}"],
                    timeout=T["whatweb"], log=self.log, label="whatweb", retries=0,
                )
            brief = d / "whatweb_hosts.txt"
            if brief.exists():
                try:
                    brief.unlink()
                except Exception:
                    pass
            run_cmd(
                ["whatweb", f"--input-file={listing}", "-a", "1",
                 "--open-timeout=8", "--read-timeout=20",
                 f"--log-brief={brief}"],
                timeout=T["whatweb"], log=self.log, label="whatweb", retries=0,
            )
            if brief.exists() and brief.stat().st_size > 0:
                ok(f"Technology fingerprint: {_count_lines(brief):,} hosts → {brief.name}")
        else:
            sub("whatweb not found")
        if tool_exists("wafw00f"):
            waf_out = d / "wafw00f_hosts.txt"
            run_cmd(
                ["wafw00f", "-i", str(listing), "-a", "--no-colors", "-o", str(waf_out)],
                timeout=min(3600, max(T["wafw00f"], 25 * len(targets))),
                log=self.log, label="wafw00f", retries=0,
            )
            if waf_out.exists() and waf_out.stat().st_size > 0:
                prev = ""
                existing = d / "wafw00f.txt"
                if existing.exists():
                    prev = existing.read_text(encoding="utf-8", errors="replace")
                fresh = waf_out.read_text(encoding="utf-8", errors="replace")
                existing.write_text((prev.rstrip() + "\n" + fresh).strip() + "\n",
                                    encoding="utf-8", errors="replace")
                ok(f"WAF detection: {len(targets):,} hosts")
        else:
            sub("wafw00f not found")

    # ── Stage 3 ───────────────────────────────────────────────────────────────
    def _run_httpx_alive_probe(self, target_file: Path, out_dir: Path, label: str = "httpx",
                                probe_ports: bool = True) -> tuple:
        """Shared httpx probe used by BOTH stage3_alive() (subdomain-enum flow)
        and stage0_seed_urls() (-u/--single/-U direct-URL flow) so both paths
        populate the same rich {out_dir}/httpx_full.json that the report reads
        to fill in the Alive Hosts table (Status/Title/IP/Tech/Size/Server/RT).
        Keeping the httpx invocation in one place means a future flag change
        only needs to happen once, instead of the two call sites drifting.
        target_file: newline-delimited hosts OR full URLs (httpx -l accepts
        either). Returns (alive_urls, status_cnt); alive_urls is [] if httpx
        isn't installed or produced no usable output — the caller decides its
        own fallback in that case.
        probe_ports: whether to pass -ports (a fixed candidate port list) to
        httpx. VERIFIED against a real httpx run: when -ports is set, httpx
        ONLY tries that fixed list and completely ignores any port already
        present in the input — e.g. an input line "http://host:8901/" never
        gets port 8901 probed at all, only 80/443/8080/etc, and shows up as
        dead if none of those happen to be open. That's exactly what
        subdomain-enum mode wants (bare hostnames with an unknown port, so a
        few common ones are worth trying) but exactly wrong for seed-URL mode
        (stage0), where the input is already a specific, known-good full URL
        that should just be requested as given — pass probe_ports=False there.
        """
        httpx_bin = _pd_httpx()
        if not httpx_bin:
            return [], {}
        base_threads = int(_cfg_get(self.cfg, "settings", "threads", default=50))
        threads = self._tuned_threads(min(base_threads, 120), 120)
        json_out = out_dir / "httpx_full.json"
        headers = pick_header_strategy(self.target, self.cfg)
        if self.has_auth():
            headers = self._auth_headers(headers)
            sub(f"Using authenticated session for {label} (alive check)")
        hh = _help_text(httpx_bin)
        fr_flag = "-follow-redirects" if "-follow-redirects" in hh else "-fr"
        fav_flag = ("-favicon -hash md5" if ("-hash" in hh and "-favicon" in hh)
                    else ("-favicon" if "-favicon" in hh else ""))
        noc_flag = "-no-color" if "-no-color" in hh else ""
        json_flag = "-json" if "-json" in hh else "-j"
        # v8.1: optional visual triage — httpx's own headless-chrome screenshot
        # feature (-screenshot). Lets you eyeball hundreds/thousands of alive
        # hosts quickly. DEFAULT OFF: rendering a headless page per host is
        # significantly slower and needs a local Chrome/Chromium — only kicks
        # in when config.yaml has settings.enable_screenshots=true AND the
        # installed httpx version supports the -screenshot flag.
        shot_flag = ""
        shot_dir = out_dir / "screenshots"
        if bool(_cfg_get(self.cfg, "settings", "enable_screenshots", default=False)) and "-screenshot" in hh:
            shot_dir.mkdir(parents=True, exist_ok=True)
            shot_flag = f"-screenshot -srd {shot_dir} "
            info("Screenshot mode active (settings.enable_screenshots=true) — this stage may be slower")
        if probe_ports:
            ports = ["80", "443", "8080", "8443", "8000", "8888", "9090", "3000", "5000"]
            if self.service_port and str(self.service_port) not in ports:
                ports.append(str(self.service_port))
            ports_flag = "-ports " + ",".join(ports) + " "
        else:
            ports_flag = ""
        tor_flag = f"-http-proxy {_resolve_proxy(self.cfg)} " if _TOR_ACTIVE.is_set() else ""
        stats_flag = _stats_cli(hh, 2)
        httpx_cmd = (
            f"{httpx_bin} -l {target_file} {noc_flag} {stats_flag}"
            f"-threads {threads} -timeout 20 -retries 2 {fr_flag} "
            f"-status-code -title -tech-detect -ip -server -content-length -response-time "
            f"{fav_flag} "
            f"{ports_flag}"
            f"{shot_flag}"
            f"{tor_flag}"
            + _hdr_args_httpx(headers)
            + f" {json_flag} -o {json_out}"
        )
        run_cmd(httpx_cmd, timeout=T["httpx"], log=self.log, label=label, retries=1, retry_delay=5)

        def _read_httpx_json():
            found, counts = [], {}
            if not json_out.exists() or json_out.stat().st_size == 0:
                return found, counts
            with json_out.open("r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    url = rec.get("url") or rec.get("input") or ""
                    if not url.startswith("http"):
                        continue
                    found.append(url)
                    status = int(rec.get("status-code") or rec.get("status_code") or 0)
                    counts[status] = counts.get(status, 0) + 1
            return found, counts

        alive_urls, status_cnt = _read_httpx_json()
        # A rich probe (favicon, tech, extra headers) can exit 0 with an empty
        # file even when the host answers a normal GET — seen on the HTTP-only
        # vulnweb test app, where curl and a plain httpx both returned 200 and
        # this command returned nothing. One plain retry, no extra headers.
        if not alive_urls and _count_lines(target_file) > 0:
            warn(f"{label} returned no hosts — retrying with a plain request")
            plain = (
                f"{httpx_bin} -l {target_file} -silent {noc_flag} {stats_flag}"
                f"-timeout 15 -retries 1 {fr_flag} "
                f"-status-code -title -tech-detect -ip -server -content-length "
                f"-response-time {json_flag} -o {json_out}"
            )
            run_cmd(plain, timeout=T["httpx"], log=self.log,
                    label=f"{label} plain", retries=0)
            alive_urls, status_cnt = _read_httpx_json()
        return alive_urls, status_cnt

    def stage3_alive(self):
        stage(3, "Host Validation")
        d = self.out / "03_alive"
        if self._cp_ok("stage3_alive"):
            n = _count_lines(self._cp("stage3_alive"))
            self.summary["stage3"] = {"status": "done", "count": n, "note": "resumed"}
            ok(f"Stage 3 resumed — {n:,} alive hosts")
            return
        sub_file = self._cp("stage2_subdomains")
        if not sub_file.exists() or sub_file.stat().st_size == 0:
            warn("No subdomain file — using domain directly")
            fallback = [self._host_url(self.target)]
            n = checkpoint(self._cp("stage3_alive"), fallback, "alive-fallback")
            self.summary["stage3"] = {"status": "done", "count": n, "note": "fallback"}
            self._fingerprint_web_estate(fallback)
            return
        httpx_bin = _pd_httpx()
        if not httpx_bin:
            warn("httpx (ProjectDiscovery) not found — treating every subdomain "
                 "as alive")
            subs = [l.strip() for l in sub_file.read_text(errors="ignore").splitlines() if l.strip()]
            urls = sorted({s if s.startswith("http") else self._host_url(s) for s in subs})
            n = checkpoint(self._cp("stage3_alive"), urls, "alive-nohttpx")
            self.summary["stage3"] = {"status": "done", "count": n, "note": "no-httpx"}
            self._fingerprint_web_estate(urls)
            return
        alive_urls, status_cnt = self._run_httpx_alive_probe(sub_file, d, label=httpx_bin)
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
                alive_urls.append(s if s.startswith("http") else self._host_url(s))
        # v8.0: dnsx doğrulaması (opsiyonel) — brute-force değil, sadece passive DNS check
        if bool(_cfg_get(self.cfg, "tools", "dnsx_enabled", default=True)) and tool_exists("dnsx"):
            try:
                dnsx_tmp = d / "dnsx_validated.txt"
                run_cmd(f"dnsx -l {self._cp('stage3_alive')} {_stats_cli(_help_text('dnsx'), 2)}-silent -o {dnsx_tmp}",
                        timeout=300, log=self.log, label="dnsx", retries=1, retry_delay=3)
                if dnsx_tmp.exists() and dnsx_tmp.stat().st_size > 0:
                    dnsx_valid = [l.strip() for l in dnsx_tmp.read_text(errors="ignore").splitlines() if l.strip()]
                    if dnsx_valid:
                        info(f"dnsx validated: {len(dnsx_valid):,} hosts")
            except Exception:
                pass

        alive_urls = sorted(set(alive_urls))
        n = checkpoint(self._cp("stage3_alive"), alive_urls, "alive-hosts")
        info(f"Alive hosts: {n:,}")
        self.summary["stage3"] = {"status": "done", "count": n, "block_ratio": round(self.block_ratio, 4)}
        self._fingerprint_web_estate(alive_urls)

    def _prune_dead_urls(self, raw_all: Path, out_dir: Path) -> tuple:
        """v8.2: gau/katana bring back URLs from historical archives (Wayback,
        CommonCrawl, OTX, urlscan) as well as live crawling — a large share of
        the archive-sourced ones are long gone (404, redirected away, or don't
        even respond anymore). Left unfiltered, that dead weight flows straight
        into every downstream stage (categorisation, XSS/param targets, the
        report's URL list) and drowns out the URLs that actually matter.
        This re-checks every collected URL with httpx and keeps only the ones
        that still respond with something other than the filtered codes
        (default: 404). URLs that fail to connect at all (timeout/DNS/refused)
        are automatically absent from httpx's own output — verified against
        httpx's runner.go: a failed request's `resp.str` is never populated, so
        the output loop's `if resp.str == "" { continue }` silently drops it —
        so we don't need to handle that case separately here.
        Returns (pruned_path, stats_dict). Never destructive: on any failure
        (tool missing, all URLs errored, etc.) this returns the ORIGINAL raw_all
        path unchanged so the scan always has a URL list to work with."""
        stats = {"enabled": False, "ran": False, "before": _count_lines(raw_all),
                 "after": 0, "removed": 0, "filter_codes": ""}
        if not bool(_cfg_get(self.cfg, "settings", "prune_dead_urls", default=True)):
            return raw_all, stats
        stats["enabled"] = True
        httpx_bin = _pd_httpx()
        if not httpx_bin:
            warn("httpx not found — skipping dead-URL pruning, keeping the raw (unfiltered) URL list")
            return raw_all, stats
        if stats["before"] == 0:
            return raw_all, stats
        codes = (_cfg_get(self.cfg, "settings", "prune_dead_urls_filter_codes", default="404") or "404").strip()
        stats["filter_codes"] = codes
        # The prune is the heaviest burst the pipeline aims at a single host —
        # one request per collected URL. Running it at the full thread budget is
        # what trips a CDN/WAF into throttling, and a throttled probe reads back
        # as "everything is dead". Capped well below the general budget.
        base_threads = int(_cfg_get(self.cfg, "settings", "threads", default=50))
        prune_cap = int(_cfg_get(self.cfg, "settings",
                                 "prune_dead_urls_threads", default=25) or 25)
        threads = self._tuned_threads(min(base_threads, prune_cap), prune_cap)
        headers = pick_header_strategy(self.target, self.cfg)
        if self.has_auth():
            headers = self._auth_headers(headers)
        pruned_file = out_dir / "all_urls_live.txt"
        hh = _help_text(httpx_bin)
        noc_flag = "-no-color" if "-no-color" in hh else ""
        fc_flag = f"-fc {codes}" if codes else ""
        prune_http_timeout = 15
        cmd = (
            f"{httpx_bin} -l {raw_all} {noc_flag} -silent {_stats_cli(hh, 2)}"
            f"-threads {threads} -timeout {prune_http_timeout} -retries 1 {fc_flag} "
            + _hdr_args_httpx(headers)
            + f" -o {pruned_file}"
        )
        info(f"Checking {stats['before']:,} collected URLs for a live response "
             f"(filtering out: {codes or 'nothing'}) — this can take a while on large sites...")
        # NOTE: deliberately NOT passing out_file= here. httpx's CLI writes
        # matching results to BOTH the "-o" file AND stdout (verified against
        # runner.go: the stdout print via gologger.Silent() isn't gated on -o
        # being set) — run_cmd's own 0-lines retry check reads that stdout, so
        # it works correctly without us pointing it at pruned_file. Passing
        # out_file here would additionally make _run_once overwrite pruned_file
        # with raw captured stdout on a non-empty read, which risks diverging
        # from what httpx itself already wrote to disk (e.g. if -no-color isn't
        # supported by the installed version and ANSI codes leak into stdout).
        # We read pruned_file directly below regardless, as the source of truth.
        t_prune = time.time()
        run_cmd(cmd, timeout=T["httpx"], log=self.log, label="httpx-url-prune",
                retries=1, retry_delay=5)
        stats["elapsed_sec"] = round(time.time() - t_prune, 1)
        if not pruned_file.exists() or pruned_file.stat().st_size == 0:
            warn("URL pruning produced no output (httpx error or every URL was unreachable) — "
                 "keeping the raw (unfiltered) URL list instead of risking an empty result")
            return raw_all, stats
        stats["ran"] = True
        stats["after"] = _count_lines(pruned_file)
        stats["removed"] = max(0, stats["before"] - stats["after"])
        removed_pct = (stats["removed"] / stats["before"] * 100) if stats["before"] else 0.0
        stats["removed_pct"] = round(removed_pct, 1)

        # A liveness probe only proves death if the target was actually
        # answering. One real scan dropped 97.8% of a corpus, but every
        # survivor sat in the first quarter of the input and nothing past that
        # point answered — a WAF throttling the probe. A later scan dropped
        # 98.8% of a Wayback-heavy corpus that httpx walked in ~30 minutes
        # (tens of URLs/sec, not 15s timeouts) with hits spread across the
        # file — those URLs really were dead, and keeping all 100k of them
        # flooded every stage after this one.
        #
        # Past the removal threshold, tell those two apart. Only a clustered
        # or too-slow probe is discarded; a fast or well-spread one is kept.
        max_pct = float(_cfg_get(self.cfg, "settings",
                                 "prune_dead_urls_max_removal_pct", default=70) or 70)
        positions = _survivor_positions(raw_all, pruned_file) if removed_pct > max_pct else None
        trust, why = evaluate_prune(
            stats["before"], stats["after"], stats.get("elapsed_sec") or 0,
            threads, prune_http_timeout, max_pct, positions)
        stats["trust_reason"] = why
        if not trust:
            stats["rejected"] = True
            stats["reject_reason"] = why
            warn(f"Dead-URL pruning claimed {stats['removed']:,} of {stats['before']:,} URLs "
                 f"({removed_pct:.1f}%) are dead — not trusting that.")
            sub(why)
            sub(f"Keeping the full {stats['before']:,}-URL list. Lower settings.threads, or set "
                f"settings.prune_dead_urls: false, if this repeats.")
            return raw_all, stats

        stats["rejected"] = False
        stats["trusted_high_removal"] = bool(removed_pct > max_pct)
        ok(f"Dead-URL pruning: {stats['before']:,} → {stats['after']:,} live URLs "
           f"({stats['removed']:,} removed as {codes or 'dead'})")
        if stats["trusted_high_removal"]:
            sub(why)
        return pruned_file, stats

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
        # v8.3-fix: gau only ever pulls from PUBLIC internet archives (Wayback
        # Machine, CommonCrawl, OTX, urlscan) — against a private/loopback
        # target (192.168.x.x, 10.x.x.x, 127.0.0.1, localhost — e.g. a local
        # dev box or the vuln-lab test site), it is 100% guaranteed to return
        # nothing, ever, no matter how many times it's retried. Confirmed
        # against a real scan log: 3 attempts (62s + 37s + 33s) plus two 15s
        # retry waits — ~160s spent to learn what was already knowable in
        # advance. Skip it outright for such targets; katana (an actual live
        # crawler, not an archive lookup) still runs normally right below and
        # is what actually finds URLs on a local target anyway.
        if tool_exists("gau") and _is_private_or_local_host(self.target):
            sub(f"gau skipped: {self.target} is a private/loopback address — "
                f"archive-based URL discovery (Wayback/CommonCrawl/OTX/urlscan) can "
                f"never have data for a non-public target, so it would only waste time")
        elif tool_exists("gau"):
            f_gau    = d / "gau.txt"
            gau_help = _help_text("gau")
            is_v2    = ("--subs" in gau_help) or ("--blacklist" in gau_help)
            gau_in   = d / "gau_input.txt"
            write_lines(gau_in, all_subs)
            if is_v2:
                gau_cmd = ["gau", "--providers", "wayback,commoncrawl,otx,urlscan",
                           "--subs", "--threads", "10", "--retries", "3", "--timeout", "60",
                           "--blacklist", "ttf,woff,svg,png,jpg,jpeg,gif,ico,css,eot,woff2,otf"]
            else:
                gau_cmd = ["gau", "-subs", "-threads", "10", "-retries", "3",
                           "-b", "ttf,woff,svg,png,jpg,jpeg,gif,ico,css,eot,woff2,otf"]
            run_cmd(gau_cmd, out_file=f_gau, timeout=T["gau"], log=self.log, label="gau",
                    retries=2, retry_delay=15, stdin_file=gau_in)
            url_files.append(f_gau)
        else:
            sub("gau not found")
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
                    " ".join(_tor_cli_flag("katana", self.cfg)),
                ]))
                kat_hdr_flags = ""
                if self.has_auth():
                    auth_h = self._auth_headers({})
                    kat_hdr_flags = " ".join([f'-H "{k}: {v}"' for k, v in auth_h.items()])
                    sub("Using authenticated session for katana (URL discovery)")
                run_cmd(f"katana -list {kin} -d 5 {flags} {kat_hdr_flags} -o {f_kat}",
                        timeout=T["katana"], log=self.log, label="katana", retries=2, retry_delay=8)
                if not f_kat.exists() or f_kat.stat().st_size == 0:
                    run_cmd(f"katana -list {kin} -d 3 -silent {kat_hdr_flags} -o {f_kat}",
                            timeout=T["katana"], log=self.log, label="katana-min", retries=0)
                url_files.append(f_kat)
        else:
            sub("katana not found")
        raw_all = d / "all_urls_raw.txt"
        def _url_ok(line):
            if not line.startswith("http"):   return False
            if len(line) > 3000:              return False
            if "javascript:" in line.lower(): return False
            if "mailto:" in line.lower():     return False
            if not self._is_in_scope_url(line): return False
            try:
                return not _PAT_SKIP.search(urlparse(line).path)
            except Exception:
                return False
        normalize = canonicalize_url if bool(_cfg_get(self.cfg, "settings", "canonicalize_urls", default=True)) else None
        n = dedup_files_normalized(url_files, raw_all, filter_fn=_url_ok, normalize_fn=normalize)
        if n == 0:
            base = [canonicalize_url(u) for u in alive_hosts] if normalize else alive_hosts
            write_lines(raw_all, base)
            n = _count_lines(raw_all)

        # v8.2: raw_all (all_urls_raw.txt) is kept on disk as-is for reference —
        # everything downstream (categorisation, XSS/param targets, the report's
        # URL list) uses the pruned, live-only list instead so dead archive URLs
        # don't clutter every stage after this one.
        final_file, prune_stats = self._prune_dead_urls(raw_all, d)
        n_final = _count_lines(final_file)
        shutil.copy2(final_file, self._cp("stage4_urls"))
        info(f"Total unique URLs: {n:,}" + (f" — {n_final:,} live after pruning" if final_file != raw_all else ""))
        self._harvest_contacts_from_urls(url_files, alive_hosts)
        self.summary["stage4"] = {
            "status": "done", "count": n_final, "count_before_pruning": n,
            "canonicalized": bool(normalize), "prune": prune_stats,
        }

    def _harvest_contacts_from_urls(self, url_files, alive_hosts):
        """Pull mailto/tel out of discovery output, then open a few contact pages."""
        blobs = []
        contact_urls = []
        for src in url_files or []:
            try:
                text = Path(src).read_text(errors="ignore") if Path(src).exists() else ""
            except Exception:
                text = ""
            if not text:
                continue
            blobs.append(text)
            for line in text.splitlines():
                low = line.lower()
                if low.startswith("http") and _CONTACT_URL_RE.search(line) and self._is_in_scope_url(line):
                    contact_urls.append(line.strip())
                if len(contact_urls) >= 12:
                    break
        bases = []
        for host in alive_hosts or []:
            if host.startswith("http"):
                p = urlparse(host)
                if p.scheme and p.netloc:
                    bases.append(f"{p.scheme}://{p.netloc}")
            if len(bases) >= 3:
                break
        bases.append(f"https://{self.target}")
        bases.append(f"https://www.{self.target}")
        found = harvest_public_contacts(bases, self.cfg, extra_urls=contact_urls[:6], blobs=blobs, limit=6)
        dest = self.out / "01_recon" / "contacts.json"
        prev = {}
        if dest.exists():
            try:
                prev = json.loads(dest.read_text(errors="ignore")) or {}
            except Exception:
                prev = {}
        merged = _merge_contacts(prev, found)
        if merged.get("emails") or merged.get("phones"):
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
            sub(f"Site contacts: {len(merged['emails'])} email, {len(merged['phones'])} phone")

    # ── Stage 5 ───────────────────────────────────────────────────────────────
    def stage5_categorise(self):
        stage(5, "URL Categorisation")
        d = self.out / "05_categorized"
        url_file = self._cp("stage4_urls")
        if not url_file.exists() or url_file.stat().st_size == 0:
            warn("No URLs from stage 4 — skipping categorisation")
            self.summary["stage5"] = {"status": "skipped", "reason": "no_urls"}
            return
        test_path_only = bool(_cfg_get(self.cfg, "tools", "dalfox_test_path_only", default=False))
        path_only_max = int(_cfg_get(self.cfg, "tools", "dalfox_path_only_max", default=100) or 100)
        dedup_query = bool(_cfg_get(self.cfg, "tools", "dalfox_dedup_query_params", default=True))
        counts = categorise_streaming(url_file, d, test_path_only=test_path_only, path_only_max=path_only_max,
                                       dedup_query_params=dedup_query)
        path_only_added = counts.pop("xss_targets_path_only", 0)
        query_dedup_skipped = counts.pop("xss_targets_query_dedup_skipped", 0)

        for name in ["reflection", "xss_targets", "params", "forms", "openredirect", "sqli"]:
            p = d / f"{name}.txt"
            if p.exists() and p.stat().st_size > 0:
                shutil.copy2(p, self._cp(f"stage5_{name}"))

        self.summary["stage5"] = {
            "status": "done",
            "categories":          {cat: {"count": cnt, "file": str(d / f"{cat}.txt")}
                                    for cat, cnt in counts.items()},
            "xss_targets_path_only": path_only_added,
            "xss_targets_path_only_enabled": test_path_only,
            "xss_targets_query_dedup_skipped": query_dedup_skipped,
            "xss_targets_query_dedup_enabled": dedup_query,
        }
        if test_path_only and path_only_added:
            sub(f"Path-only (query'siz) {path_only_added:,} benzersiz route sekli de dalfox hedeflerine eklendi")
        if dedup_query and query_dedup_skipped:
            sub(f"Skipped {query_dedup_skipped:,} URL(s) from dalfox targets that share an already-covered "
                f"query parameter shape (one example per unique parameter combination is enough)")
        ok(f"Categorisation complete — {sum(counts.values()):,} URLs processed")

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 6 — XSS (Dalfox) taramasi
    # ══════════════════════════════════════════════════════════════════════════
    def _run_dalfox_once(self, xss_file: Path, d: Path, run_tag: str, timeout_sec: int = 0) -> dict:
        res = {
            "workers": 0, "delay_ms": 0, "blocked_hits": 0, "total_lines": 0,
            "block_ratio": 0.0, "findings": 0, "poc_live": 0, "count": 0,
            "file_txt": "", "file_json": "",
            "tool_failed": False, "exit_code": None, "tool_error": "",
            "interrupted": False, "stalled": False, "duration_sec": 0.0,
            "targets_count": _count_lines(xss_file),
        }
        if not tool_exists("dalfox"):
            warn("dalfox not found — skipping XSS scan")
            return res

        d.mkdir(parents=True, exist_ok=True)
        json_f = d / f"dalfox_{run_tag}.json"
        txt_f  = d / f"dalfox_{run_tag}.txt"

        # v6.12: --silence kaldirildi — ilerleme goruntulenir, "0 lines" yaniltmasi biter.
        # v8.1-fix: "-oJ <json_f> -o <txt_f>" GECERSIZ bir bayrak kombinasyonuydu ve
        # dalfox bulgularinin raporda HER ZAMAN 0 gorunmesine yol aciyordu. Dalfox'ta
        # "-oJ" diye bir bayrak yok — dalfox'un tek dosya cikisi vardir: "-o/--output"
        # (kisaltma "o") + "--format" (plain/json/jsonl, kisaltmasi yok). pflag "-oJ"
        # token'ini "-o" + inline deger "J" olarak ayristirir; hemen ardindan gelen
        # token (asil json_f yolu) bir sonraki bayrağa baglanamadigi icin sessizce
        # ekstra bir positional argument olarak yutulur ve dalfox tarafindan yok
        # sayilir. Sondaki "-o <txt_f>" ise gecerli oldugu icin calisir ama --format
        # hic verilmedigi icin varsayilan "plain" ile yazar — yani json_f dosyasi
        # FİİLEN HİÇ OLUŞMUYORDU. Sonuc: bu fonksiyonun birazasagisindaki
        # "if json_f.exists()..." kontrolu dogal olarak hep False donuyor, findings=0
        # kaliyordu — dalfox gercekte bulgu bulmus olsa bile.
        # Duzeltme: dalfox'un TEK seferde TEK dosyaya/TEK formata yazabildigi icin
        # (Output+Format = bir cift), makine-okunur JSONL burada aliniyor; nuclei'de
        # oldugu gibi okunabilir .txt ozeti asagida bulgulardan reconx'in kendisi
        # uretiyor (txt_f artik dalfox'tan degil, bu fonksiyondan yaziliyor).
        # v8.2-fix: explicitly pin dalfox's own per-request HTTP timeout to our
        # configured settings.timeout instead of leaving it on dalfox's own
        # built-in default (10s) — keeps every tool in the pipeline bounded by
        # the same, single, user-tunable timeout knob.
        _dalfox_req_timeout = int(_cfg_get(self.cfg, "settings", "timeout", default=20) or 20)
        cmd = ["dalfox", "file", str(xss_file),
               "-o", str(json_f), "--format", "jsonl", "--no-color",
               "--timeout", str(_dalfox_req_timeout)]
        # v8.6: cap dalfox's own concurrency (default 100 workers) and add a
        # small inter-request delay. dalfox's default burst trips per-IP rate
        # limiting on CDN/ALB-fronted targets — when that happens the reflected
        # payloads come back inside 403/429 bodies and dalfox reports 0
        # findings even on a target it flagged fine a minute earlier. Tunable.
        # v8.8: raised default/cap (25/40 -> 40/60) per user request for a
        # faster scan — still well under dalfox's own 100-worker default, so
        # the WAF-trip risk this cap was originally added for stays bounded.
        # Lower tools.dalfox_workers back down if a specific target's WAF
        # starts returning 403/429 bursts (visible as a suspiciously fast,
        # 0-finding scan on a site you know is vulnerable).
        _dfx_workers = int(_cfg_get(self.cfg, "tools", "dalfox_workers",
                                    default=_cfg_get(self.cfg, "settings", "threads", default=40)) or 40)
        _dfx_delay = int(_cfg_get(self.cfg, "tools", "dalfox_delay_ms", default=0) or 0)
        _dfx_worker_n = max(1, min(_dfx_workers, 60))
        cmd += ["--worker", str(_dfx_worker_n)]
        if _dfx_delay > 0:
            cmd += ["--delay", str(_dfx_delay)]
        # v9.3: skip parameter mining (see dalfox_skip_mining default for the full
        # rationale — ReconX already supplies the param corpus, and mining explodes
        # per-URL time on any target that reflects arbitrary param names). The flag
        # is only added when THIS binary's own --help documents it (via _dalfox_caps),
        # so an off-name spelling can never become an "unknown flag" that kills the
        # stage; if unavailable we silently fall back to full mining.
        _dfx_skip = str(_cfg_get(self.cfg, "tools", "dalfox_skip_mining", default="all") or "").strip().lower()
        if _dfx_skip in ("all", "dom", "dict"):
            if _dfx_skip in _dalfox_caps().get("skip_mining_flags", set()):
                cmd += ["--skip-mining-" + _dfx_skip]
            else:
                warn(f"dalfox has no --skip-mining-{_dfx_skip} flag — using full mining "
                     f"(scan may be slow on param-reflecting targets)")
        elif _dfx_skip not in ("", "none", "off", "false"):
            warn(f"Unknown tools.dalfox_skip_mining={_dfx_skip!r} — using full mining "
                 f"(valid: all | dom | dict | '')")
        # v9.3: per-target cost trims, each caps-gated the same way.
        _skip_avail = _dalfox_caps().get("skip_flags", set())
        if bool(_cfg_get(self.cfg, "tools", "dalfox_skip_bav", default=True)) and "bav" in _skip_avail:
            cmd += ["--skip-bav"]
        if bool(_cfg_get(self.cfg, "tools", "dalfox_skip_headless", default=True)) and "headless" in _skip_avail:
            cmd += ["--skip-headless"]
        cmd += _tor_cli_flag("dalfox", self.cfg)

        # v8.4-fix: dalfox v3.x (Rust rewrite) adds --state-file — it records
        # which targets FULLY finished and skips them on a re-run with the
        # same state file, so a scan cut short by Ctrl+C (or the 2h hard
        # timeout) can be resumed instead of starting over from zero. v2.x
        # (Go) doesn't have this flag at all, so it's only added when it was
        # actually found in this binary's own --help output — passing an
        # unknown flag to v2 would make it exit immediately with a usage
        # error and kill the whole XSS stage (this is exactly the bug the
        # v8.5-fix below replaced the old version-string probe to fix).
        # v8.5-fix: gate on the direct --help capability probe (_dalfox_caps),
        # not a version-number guess — see that function's docstring for why.
        _dalfox_caps_v = _dalfox_caps()
        if _dalfox_caps_v["is_v3"]:
            if _dalfox_caps_v["state_file"]:
                state_f = d / f"dalfox_{run_tag}.state"
                cmd += ["--state-file", str(state_f)]
                if state_f.exists():
                    info(f"Resuming previous dalfox run — already-completed targets in "
                         f"{state_f.name} will be skipped")
        else:
            # v8.4-fix: confirmed against the real v2.12.0 (Go) source
            # (cmd/file.go's runFileMode): "dalfox file" with NEITHER --mass
            # nor --multicast calls runSingleMode, which scans every target
            # in the file ONE AT A TIME, fully sequentially — with no
            # concurrency across targets at all (per-target parameter/
            # payload concurrency via -w/--worker is separate and unaffected
            # either way). On a real 28-target scan this is exactly the
            # "feels stuck, tempted to Ctrl+C" scenario that was reported.
            # --mass (a v2-only flag; v3 dropped it in favor of always-on
            # --max-concurrent-targets) switches to runMulticastMode, which
            # runs --mass-worker (v2 default 10) targets in parallel. Two
            # things worth knowing, both verified against the same source:
            # (1) --mass internally forces options.Silence=true, but that
            # does NOT suppress the JSONL finding lines our live-hit reader
            # depends on — DalLog's level=="PRINT" case does an unconditional
            # fmt.Println for json/jsonl format regardless of Silence, only
            # OTHER log levels are gated by it. (2) --mass does not reduce
            # per-target scan depth — runMulticastMode calls the exact same
            # scanning.Scan() per URL as the sequential path, just more of
            # them at once, so this is a pure concurrency win, not a
            # thoroughness trade-off.
            # v8.4-fix #2 (found after a real scan came back suspiciously
            # fast with 0 findings): dalfox v2's own multicast.go groups
            # targets by internal/utils.MakeTargetSlice(), which buckets by
            # HOSTNAME. --mass-worker controls how many of THOSE per-host
            # buckets run in parallel — it does NOT parallelize multiple
            # URLs within the SAME host. A typical bug-bounty scan (many
            # URLs/params on ONE target) puts everything in a single bucket,
            # so only one of the N mass-workers ever does anything — --mass
            # gives ZERO speedup for exactly this session's own use case,
            # while adding an untested code path. Only worth enabling when
            # the target list actually spans multiple distinct hosts (e.g.
            # a subdomain-enum-mode scan), where the buckets are real.
            _dalfox_hosts = set()
            try:
                for _ln in xss_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    _ln = _ln.strip()
                    if _ln:
                        _dalfox_hosts.add(urlparse(_ln).hostname or _ln)
            except Exception:
                pass
            _mass_workers = int(_cfg_get(self.cfg, "tools", "dalfox_mass_workers", default=10) or 10)
            if _mass_workers > 1 and len(_dalfox_hosts) > 1:
                cmd += ["--mass", "--mass-worker", str(_mass_workers)]

        hdr_set = pick_header_strategy(self.target, self.cfg)
        if self.has_auth():
            hdr_set = self._auth_headers(hdr_set)
            sub("Using authenticated session for dalfox")
        cmd += _hdr_args_dalfox(hdr_set)

        try:
            blind = (_cfg_get(self.cfg, "tools", "blind_xss_callback", default="") or "")
            if not blind:
                blind = getattr(self, "_blind_cb", "") or ""
            if blind:
                cmd += ["--blind", blind]
        except Exception:
            pass

        try:
            # --xss-payloads overrides the config for this run
            cpl = (self._xss_payloads
                   or _cfg_get(self.cfg, "tools", "dalfox_custom_payload", default="") or "")
            if cpl:
                # v8.2: resolve a relative path against BASE_DIR (where
                # reconx.py itself lives) if it doesn't resolve from the
                # current working directory — so "xss-payloads.txt" in
                # config.yaml works whether the tool is launched from its
                # own folder or from somewhere else.
                cpl_path = Path(cpl)
                if not cpl_path.exists() and not cpl_path.is_absolute():
                    alt = BASE_DIR / cpl
                    if alt.exists():
                        cpl_path = alt
                if cpl_path.exists():
                    cmd += ["--custom-payload", str(cpl_path)]
                    info(f"Using custom XSS payload list: {cpl_path} "
                         f"({_count_lines(cpl_path):,} payload(s), added on top of dalfox's own)")
                else:
                    warn(f"dalfox_custom_payload not found: {cpl}")
        except Exception:
            pass

        try:
            # v8.7-fix: this config key was documented in the shipped config
            # template but never actually read anywhere — setting it had no
            # effect. Wire it to dalfox's own -W/--mining-dict-word flag.
            mdict = (_cfg_get(self.cfg, "tools", "dalfox_mining_dict", default="") or "")
            if mdict:
                mdict_path = Path(mdict)
                if not mdict_path.exists() and not mdict_path.is_absolute():
                    alt = BASE_DIR / mdict
                    if alt.exists():
                        mdict_path = alt
                if mdict_path.exists():
                    cmd += ["--mining-dict-word", str(mdict_path)]
                    info(f"Using custom mining-dict wordlist: {mdict_path}")
                else:
                    warn(f"dalfox_mining_dict not found: {mdict}")
        except Exception:
            pass

        # v8.2-fix: this used to be a hardcoded 240s, then a configurable
        # 480s. Verified against dalfox's own source (cmd/file.go /
        # cmd/pipe.go): without --mass/--multicast, "dalfox file" scans
        # targets ONE AT A TIME (runSingleMode), and each target already
        # runs StaticAnalysis + ParameterAnalysis (mining-dict/mining-dom,
        # both on by default) — plus this session added path-only URL
        # targets, the auto-provisioned blind-XSS callback, AND a ~120-entry
        # custom payload list tested in 4 encodings per parameter. All of
        # that is legitimate extra work, and on a real scan (37 targets) it
        # kept going quiet for 480s+ while still genuinely making progress
        # (169 lines and climbing) — the stall-kill was firing on a slow
        # scan, not a stuck one, and cutting results short every time.
        # v8.3-fix: stall-based auto-kill is now DISABLED by default
        # (dalfox_stall_timeout_sec: 0 = disabled, _stream_tool treats any
        # falsy stall_timeout as "off"). The only remaining ceiling is the
        # overall T["dalfox"] = 7200s (2h) hard timeout below, which is a
        # real safety net against a genuinely hung process without cutting
        # off slow-but-working scans. Set dalfox_stall_timeout_sec to a
        # positive number in config.yaml if you want the old quiet-period
        # auto-kill back (e.g. for much smaller/faster scans).
        _dalfox_stall_sec = int(_cfg_get(self.cfg, "tools", "dalfox_stall_timeout_sec", default=0) or 0)
        _cap_note = (f" (per-URL cap {int(timeout_sec)}s)" if timeout_sec
                     else ("" if _dalfox_stall_sec else " (no stall limit — only the stage time ceiling applies)"))
        if _count_lines(xss_file) != 1:
            info(f"Dalfox is running against {_count_lines(xss_file):,} targets "
                 f"— progress streams below, runtime scales with the target count{_cap_note}")

        # v8.3: live XSS-hit display. On dalfox v2.x (Go), DalLog("PRINT", ...)
        # writes each finding's raw JSON both to its -o output file AND to
        # stdout the instant it's found (verified against v2's own source:
        # internal/printing/logger.go — level=="PRINT" always does
        # fmt.Println(text) for json/jsonl format, unconditionally).
        # _stream_tool's reader thread already sees every stdout line as it
        # streams in, so a finding line is just one more line — this line_cb
        # tries to json.loads() each one and, if it parses as a dalfox PoC
        # record, prints it live via xss_live_hit() and continues; anything
        # that isn't a JSON finding line (the vast majority — progress/status
        # text) is a no-op cost of one failed json.loads() per line.
        # v8.4-caveat: on dalfox v3.x (Rust rewrite), this is best-effort
        # only — verified against a real v3.2.2 build that ALL stdout
        # (findings included) is buffered and written out in one shot right
        # at the very end of the scan, regardless of --format/--stream-
        # findings/-o. So on v3 this callback will typically fire a burst of
        # "live" hits all at once when the scan finishes, not progressively
        # while it runs — harmless (still faster than waiting for the final
        # report) but don't expect a steady trickle during a long v3 scan.
        # Live progress. dalfox (with --silence OFF, which it already is here)
        # prints its own per-target markers on stdout alongside the jsonl
        # findings — verified against v2.12.0:
        #   [*] Starting scan [SID:0][0/3][0.00%] / URL: http://...
        #   [*] [ Created 100 workers ] [ Allocated 672 queries ]
        #   [*] [duration: 20.0s][issues: 5] Finish Scan!
        # Those were already streaming past unparsed, so the spinner could only
        # say "processing N lines" — useless for judging how far along a 40
        # target scan is. Completed targets are counted off "Finish Scan!"
        # rather than the [x/y] index, because the index is printed when a
        # target STARTS.
        _dfx_total = max(1, _count_lines(xss_file))
        # dalfox only prints its own "[ Created N workers ]" line when --worker
        # is NOT given, and we always give it — so seed the count from the value
        # we set rather than waiting for a line that never arrives.
        dfx_status = {"text": f"target 0/{_dfx_total} (0%) · {_dfx_worker_n}w"}
        prog = {"done": 0, "workers": _dfx_worker_n, "hits": 0, "cur": "", "hit_at": 0.0}
        live_findings = []

        def _dfx_status_text():
            pct = prog["done"] * 100.0 / _dfx_total
            bits = [f"target {prog['done']}/{_dfx_total} ({pct:.0f}%)"]
            if prog["workers"]:
                bits.append(f"{prog['workers']}w")
            if prog["hits"]:
                bits.append(f"{prog['hits']} hit{'s' if prog['hits'] > 1 else ''}")
            # v9.3: show the target dalfox is CURRENTLY grinding on. dalfox v2 emits
            # nothing between a target's start and its "Finish Scan!" (~1min each on
            # a slow host), so without this the counter sits at the same "N/total"
            # for a full minute and reads as frozen — showing the live URL makes it
            # obvious the scan is alive and working, just sequential.
            if prog["cur"]:
                bits.append(f"scanning {prog['cur']}")
            return " · ".join(bits)

        def _dalfox_line_cb(line: str):
            s = line.strip()
            if not s:
                return
            if s[0] != "{":
                low = s.lower()
                if "finish scan" in low:
                    prog["done"] = min(_dfx_total, prog["done"] + 1)
                    dfx_status["text"] = _dfx_status_text()
                elif "created" in low and "workers" in low:
                    m = re.search(r"created\s+(\d+)\s+workers", low)
                    if m:
                        prog["workers"] = int(m.group(1))
                        dfx_status["text"] = _dfx_status_text()
                elif "starting scan" in low:
                    m = re.search(r"\[sid:\d+\]\[(\d+)/(\d+)\]", low)
                    if m:
                        # trust dalfox's own total when it disagrees with our count
                        try:
                            tot = int(m.group(2))
                            if tot > 0:
                                prog["done"] = max(prog["done"], int(m.group(1)))
                        except ValueError:
                            pass
                    # capture the URL dalfox is starting on (case-preserved from the
                    # raw line), shortened to path+query so the status stays one line
                    um = re.search(r"URL:\s*(\S+)", s)
                    if um:
                        try:
                            _p = urlparse(um.group(1))
                            prog["cur"] = ((_p.path or "/") + ("?" + _p.query if _p.query else ""))[:60]
                        except Exception:
                            prog["cur"] = um.group(1)[:60]
                    dfx_status["text"] = _dfx_status_text()
                return
            try:
                rec = json.loads(s)
            except Exception:
                return
            if isinstance(rec, dict) and ("payload" in rec or "data" in rec) and "type" in rec:
                prog["hits"] += 1
                if not prog["hit_at"]:
                    prog["hit_at"] = time.time()
                live_findings.append(rec)
                dfx_status["text"] = _dfx_status_text()
                xss_live_hit(rec)

        def _stop_after_hit():
            # A verified hit is already on stdout. Give dalfox a few seconds to
            # flush sibling payloads for this parameter, then move on. Without
            # this, one URL keeps fuzzing for many minutes after the first hit
            # and the rest of the list is never scanned.
            return bool(prog["hits"] and prog["hit_at"] and (time.time() - prog["hit_at"]) >= 20)

        # v8.4-fix: only dalfox v3.x uses exit 1 == "vulnerabilities found";
        # v2.x's exit-code convention on a normal findings run is 0, so this
        # extra "ok" code is only added when a v3+ binary was detected —
        # otherwise a genuine v2 error would be silently treated as success.
        # v8.5-fix: gate on the direct --help capability probe (_dalfox_caps),
        # not the old version-string guess — see that function's docstring.
        # This was the second half of the real bug: the old probe's false
        # "v3" positive didn't just send v3-only flags, it ALSO widened the
        # accepted exit codes to include 1, which is exactly the exit code
        # cobra (v2) uses for an "unknown flag" parse error — so the crash
        # caused by those wrong flags was itself silently swallowed as a
        # normal "clean scan, 0 findings" result instead of being reported
        # as a tool failure.
        _dalfox_ok_codes = (0, 1, None) if _dalfox_caps()["is_v3"] else (0, None)
        # v8.6: real wall-clock budget. dalfox writes findings to the -o file
        # incrementally, so a run cut off at the budget still keeps everything
        # found so far — far better than a 2h open-ended run that the user
        # ends up Ctrl+C-ing anyway.
        _dfx_budget = int(_cfg_get(self.cfg, "tools", "dalfox_time_budget_sec", default=10800) or 10800)
        _dfx_budget = min(_dfx_budget, T["dalfox"]) if _dfx_budget > 0 else T["dalfox"]
        if timeout_sec and int(timeout_sec) > 0:
            _dfx_budget = min(_dfx_budget, int(timeout_sec))
        _t0 = time.time()
        rc, lines, killed, stalled = _stream_tool(
            cmd, timeout=_dfx_budget, log=self.log, label=f"dalfox-{run_tag}",
            line_cb=_dalfox_line_cb, stall_timeout=_dalfox_stall_sec, status=dfx_status,
            ok_exit_codes=_dalfox_ok_codes, stop_check=_stop_after_hit
        )
        res["duration_sec"] = round(time.time() - _t0, 1)
        # distinguish "we stopped dalfox at its time budget" (expected, findings
        # so far are kept) from a real user Ctrl+C — the report wording differs.
        # --max-time raises the same hard-stop flag as Ctrl+C, so a duration
        # check alone used to label a budget stop as a user interrupt.
        _time_budget = bool(getattr(self, "_budget_fired", False))
        _per_url_cap = bool(killed) and not _INT.interrupted() and not _time_budget and \
            res["duration_sec"] >= max(1, _dfx_budget - 15)
        _stopped_after_hit = bool(
            killed and prog["hits"] and not _time_budget and not _per_url_cap and not _INT.interrupted())
        _budget_hit = bool(killed) and (_time_budget or _per_url_cap)
        res["budget_hit"] = _budget_hit
        res["per_url_capped"] = _per_url_cap
        res["stopped_after_hit"] = _stopped_after_hit
        res["interrupted"] = bool(killed) and not _budget_hit and not _stopped_after_hit
        res["stalled"] = bool(stalled)
        res["total_lines"] = lines
        res["exit_code"] = rc

        # v8.4-fix: parse json_f BEFORE deciding tool_failed, so that decision
        # can use what dalfox actually produced instead of exit-code guessing
        # alone. This also fixes two real bugs found while diagnosing a real
        # scan report:
        #  1) dalfox v3.x (Rust) prepends one summary line per scan, e.g.
        #     {"meta":{"dalfox_version":"3.2.2","findings_count":1,...}}.
        #     It has no "data"/"payload"/"type" — previously it still passed
        #     the (too-loose) "isinstance(rec, dict)" check and became one
        #     bogus, entirely-empty "finding" per scan (blank url/payload/
        #     type, severity defaulting to "info"), inflating the finding
        #     count by 1 and adding a blank row to the report even on a
        #     100% clean scan. Now explicitly recognised and skipped.
        #  2) dalfox v3.x's error envelope is a *different* shape entirely:
        #     {"code":"...","error":true,"message":"..."} — also previously
        #     misread as a bogus empty "finding" instead of a real error.
        findings = []
        blocked = 0
        _dalfox_meta = None
        _dalfox_hard_error = ""
        # Stopping dalfox right after a hit can land before -o is flushed.
        # The same JSON lines already arrived on stdout; keep those.
        if live_findings and not (json_f.exists() and json_f.stat().st_size > 0):
            try:
                with json_f.open("w", encoding="utf-8") as fh:
                    for rec in live_findings:
                        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            except Exception:
                pass
        if json_f.exists() and json_f.stat().st_size > 0:
            with json_f.open("r", encoding="utf-8", errors="replace") as fh:
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
                    if rec.get("error") is True:
                        _dalfox_hard_error = str(rec.get("message") or rec.get("code") or "unknown dalfox error")
                        continue
                    if "meta" in rec and isinstance(rec.get("meta"), dict):
                        _dalfox_meta = rec["meta"]
                        continue
                    # v8.1-fix: gercek dalfox v2 PoC JSON semasi (pkg/model/result.go):
                    # {"type","inject_type","poc_type","method","data","param","payload",
                    #  "evidence","cwe","severity","message_str"}. "data" bir NESTED DICT
                    # DEGIL, bulgunun bulundugu URL'i iceren bir STRING'dir; ust seviyede
                    # "url" diye bir alan da hic yok. Eski kod "data"nin dict oldugunu
                    # varsayiyordu — bu hicbir zaman dogru olmadigi icin url/payload/type
                    # her zaman bos kaliyordu ve bulgular fiilen "kayboluyordu". dalfox
                    # v3.x uses the same key names (data/param/payload/type/severity/cwe)
                    # for its (richer) finding schema, so this extraction works unchanged
                    # on both versions — but only for records that actually look like a
                    # finding (guard below), not the meta/error lines handled above.
                    if not (("data" in rec or "payload" in rec) and "type" in rec):
                        continue
                    url     = str(rec.get("data") or "")
                    payload = str(rec.get("payload") or "")
                    param   = str(rec.get("param") or "")
                    typ     = str(rec.get("type") or "")
                    sev = rec.get("severity") or "info"
                    findings.append({
                        "url": url,
                        "payload": payload,
                        "param": param,
                        "type": typ,
                        "cwe": rec.get("cwe") or "",
                        "severity": sev,
                    })
                    if url.startswith("http"):
                        s_code = int(rec.get("status-code") or rec.get("status") or 0)
                        if s_code in (403, 429):
                            blocked += 1

        if not killed and stalled:
            res["tool_failed"] = True
            res["tool_error"] = (f"Dalfox made no progress for {_dalfox_stall_sec}s and was stopped "
                                  f"automatically (you have tools.dalfox_stall_timeout_sec set to a "
                                  f"positive value in config.yaml) — it may genuinely be stuck (network "
                                  f"block etc.), or a single slow/WAF-protected target just needs more "
                                  f"time. Set tools.dalfox_stall_timeout_sec: 0 to disable this auto-kill "
                                  f"entirely and rely only on the overall 2h ceiling (this is the default).")
        elif killed and _stopped_after_hit:
            pass
        elif killed and getattr(self, "_budget_fired", False):
            res["tool_error"] = (
                "Scan stopped because --max-time was reached. Findings saved so far are kept; "
                "targets that did not finish are not clean.")
        elif killed and res.get("per_url_capped"):
            res["tool_error"] = (
                f"This URL hit the per-URL cap ({_dfx_budget}s). Findings saved so far are kept.")
        elif killed:
            res["tool_error"] = (
                "Scan stopped early (Ctrl+C). Findings may be incomplete; "
                "targets that did not finish are not clean.")
        elif _dalfox_hard_error:
            res["tool_failed"] = True
            res["tool_error"] = f"dalfox reported an error: {_dalfox_hard_error}"
        elif rc not in (0, 1, None):
            # v8.4-fix: exit code 1 alone is NOT a failure on dalfox v3.x —
            # confirmed against a real v3.2.2 build, it uses a grep-style
            # convention (0 = clean/no findings, 1 = vulnerabilities WERE
            # found, 2+ = a real error) — the old "any rc != 0" check here
            # was misreporting every single successful scan that actually
            # found XSS as a failed tool run. Only an exit code outside
            # {0, 1} (and not already explained by stall/Ctrl+C/a structured
            # error record above) is now treated as a genuine failure.
            res["tool_failed"] = True
            res["tool_error"] = f"dalfox exited with code {rc} — sonuclar eksik/gecersiz olabilir"

        res["findings"] = len(findings)
        res["count"] = len(findings)
        res["findings_list"] = findings
        res["dalfox_meta"] = _dalfox_meta
        if lines:
            res["block_ratio"] = round(blocked / max(1, lines), 4)

        # v8.6: dalfox finished cleanly, spent real time on several targets, and
        # still found nothing — on a target the pre-scan HTTP probe confirmed
        # alive this is often the CDN/ALB rate-limiting the payload burst
        # (reflections come back wrapped in 403/429 so dalfox can't see them).
        # Flag it so the report doesn't present a throttled run as "clean".
        res["suspicious_empty"] = bool(
            not findings and not killed and not res["tool_failed"]
            and res["duration_sec"] > 45 and (res.get("targets_count", 0) or 0) >= 3)
        if res["suspicious_empty"]:
            warn("Dalfox finished with 0 findings but spent real time — the target most "
                 "likely rate-limited the payload stream (too many scans from one IP, CDN/ALB). "
                 "Retry later, or lower tools.dalfox_workers in config.yaml.")

        # v8.1: dalfox artik dogrudan --format jsonl ile TEK dosyaya (json_f) yaziyor;
        # okunabilir .txt ozetini nuclei'deki ayni desenle biz kendimiz uretiyoruz.
        try:
            with txt_f.open("w", encoding="utf-8") as fo:
                for f in findings:
                    fo.write(f"[{f.get('severity','info')}] {f.get('type','')} "
                             f"@ {f.get('url','')} :: {f.get('payload','')}\n")
        except Exception:
            pass

        res["file_txt"] = str(txt_f)
        res["file_json"] = str(json_f)
        return res

    def _flush_xss_progress(self, d: Path, results, finished, incomplete, total: int, started: float):
        """Write findings collected so far so a report refresh mid-scan can see them.

        The merged file is otherwise written only when every URL has finished.
        A refresh before that used to open the old report, with an empty XSS section.
        """
        try:
            lines = []
            findings_n = 0
            for _url, record in results:
                if not record:
                    continue
                findings_n += int(record.get("findings") or 0)
                pj = record.get("file_json") or ""
                if pj and Path(pj).exists():
                    for ln in Path(pj).read_text(encoding="utf-8", errors="replace").splitlines():
                        if ln.strip():
                            lines.append(ln.rstrip("\n"))
            out = d / "dalfox_scan.json"
            out.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")
            stage = {
                "status": "partial",
                "findings": findings_n,
                "count": findings_n,
                "file_json": str(out),
                "tool_failed": False,
                "interrupted": False,
                "budget_hit": False,
                "duration_sec": round(time.time() - started, 1),
                "targets_count": total,
                "targets_finished": len(finished),
                "targets_incomplete": len(incomplete),
            }
            self.summary["stage6"] = {**self.summary.get("stage6", {}), **stage}
            sf = self.out / "SUMMARY.json"
            prior = {}
            if sf.exists():
                try:
                    prior = json.loads(sf.read_text(encoding="utf-8", errors="replace")) or {}
                except Exception:
                    prior = {}
            stages = dict(prior.get("stages") or {})
            stages["stage6"] = {**stages.get("stage6", {}), **stage}
            prior["stages"] = stages
            prior.setdefault("target", self.target)
            tmp = sf.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(prior, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(sf)
        except Exception:
            pass

    def _dalfox_job_count(self, host_count: int) -> int:
        """How many XSS URLs to run at once. 0 in config means one per CPU.
        Never more than the number of distinct hosts, so one host is not
        fuzzed by two processes at the same time."""
        raw = _cfg_get(self.cfg, "tools", "dalfox_parallel_jobs", default=0)
        try:
            jobs = int(0 if raw is None else raw)
        except (TypeError, ValueError):
            jobs = 0
        if jobs <= 0:
            jobs = os.cpu_count() or 4
        jobs = max(1, min(jobs, 8))
        if host_count > 0:
            jobs = min(jobs, host_count)
        return jobs

    def _run_dalfox_per_url(self, xss_file: Path, d: Path, run_tag: str) -> dict:
        """Scan each URL in its own dalfox process with a wall-clock cap.

        dalfox file mode walks the list one URL at a time and keeps fuzzing a
        URL long after the first verified hit. A single slow URL then eats the
        stage budget and every later URL is never scanned — while the report
        used to mark those later URLs clean. A per-URL cap keeps findings
        already written and moves on."""
        try:
            urls = [l.strip() for l in xss_file.read_text(errors="ignore").splitlines() if l.strip()]
        except Exception:
            urls = []
        if len(urls) <= 1:
            return self._run_dalfox_once(xss_file, d, run_tag)

        per = int(_cfg_get(self.cfg, "tools", "dalfox_per_url_sec", default=420) or 420)
        stage_budget = int(_cfg_get(self.cfg, "tools", "dalfox_time_budget_sec", default=10800) or 10800)
        stage_budget = min(stage_budget, T["dalfox"]) if stage_budget > 0 else T["dalfox"]
        one_dir = d / "dalfox_per_url"
        one_dir.mkdir(parents=True, exist_ok=True)
        hosts = {(urlparse(u).hostname or "").lower() for u in urls}
        jobs = self._dalfox_job_count(len(hosts))
        if jobs == 1:
            info(f"XSS testing {len(urls)} URL(s), one at a time, {per}s cap per URL "
                 f"(stage ceiling {stage_budget}s)")
        else:
            info(f"XSS testing {len(urls)} URL(s), {jobs} at a time across {len(hosts)} hosts, "
                 f"{per}s cap per URL (stage ceiling {stage_budget}s)")

        finished, incomplete, skipped = [], [], []
        hit_points = set()
        results = []
        t0 = time.time()
        pending = list(enumerate(urls))
        busy = set()
        futures = {}
        stop = False

        def _drop_same_point(point):
            if not point:
                return
            kept, n = [], 0
            for item in pending:
                if _xss_injection_point(item[1]) == point:
                    skipped.append(item[1])
                    n += 1
                else:
                    kept.append(item)
            pending[:] = kept
            if n:
                names = ", ".join(point[2]) or "parameter"
                info(f"XSS: {names} on {point[1]} already has a finding — "
                     f"skipping {n} more value(s) of the same parameter")

        def _take(record, url):
            if record.get("stopped_after_hit"):
                finished.append(url)
                return False
            if getattr(self, "_budget_fired", False) or record.get("interrupted"):
                incomplete.append(url)
                return True
            if record.get("per_url_capped") or record.get("budget_hit") or record.get("tool_failed"):
                incomplete.append(url)
                return False
            finished.append(url)
            return False

        with ThreadPoolExecutor(max_workers=jobs) as pool:
            while pending or futures:
                if _INT.hard() or _INT.interrupted() or getattr(self, "_budget_fired", False):
                    stop = True
                remaining = stage_budget - (time.time() - t0)
                if remaining < 20:
                    stop = True
                if not stop:
                    looked = 0
                    limit = len(pending)
                    while pending and len(futures) < jobs and looked < limit:
                        i, u = pending.pop(0)
                        looked += 1
                        point = _xss_injection_point(u)
                        if point and point in hit_points:
                            skipped.append(u)
                            continue
                        host = (urlparse(u).hostname or "").lower()
                        if host in busy:
                            pending.append((i, u))
                            continue
                        busy.add(host)
                        cap = max(20, min(per, int(remaining)))
                        cf = one_dir / f"u{i}.txt"
                        write_lines(cf, [u])
                        param = _xss_param_label(u)
                        kind = _xss_kind_label(u)
                        info(f"XSS testing {i + 1}/{len(urls)} — parameter {param} — {kind} — {u[:160]}")
                        _pulse_job("XSS testing", t0, i, len(urls), unit="urls",
                                   item=f"{i + 1}/{len(urls)} parameter {param}",
                                   note=kind, force=True)
                        fut = pool.submit(self._run_dalfox_once, cf, one_dir, f"u{i}", cap)
                        futures[fut] = (u, host)
                if not futures:
                    break
                done, _pending_futs = wait(set(futures), timeout=0.5, return_when=FIRST_COMPLETED)
                for fut in done:
                    u, host = futures.pop(fut)
                    busy.discard(host)
                    try:
                        record = fut.result()
                    except Exception as exc:
                        record = {"tool_failed": True, "tool_error": str(exc)}
                    results.append((u, record))
                    if _take(record, u):
                        stop = True
                    if int(record.get("findings") or 0) > 0 or record.get("stopped_after_hit"):
                        point = _xss_injection_point(u)
                        if point and point not in hit_points:
                            hit_points.add(point)
                            _drop_same_point(point)
                    self._flush_xss_progress(d, results, finished, incomplete, len(urls), t0)
                    v_hits = [f for f in (record.get("findings_list") or [])
                              if str(f.get("type", "")).strip().upper() == "V"
                              and str(f.get("url", "")).startswith("http")]
                    if v_hits and not _INT.hard():
                        capture_xss_alert_screenshots(
                            v_hits, d, max_shots=len(v_hits), max_checks=len(v_hits),
                            nav_timeout_sec=int(_cfg_get(self.cfg, "settings", "timeout", default=15) or 15),
                            budget_sec=180, payloads_per_point=len(v_hits))
        for _i, u in pending:
            if u in skipped or u in finished or u in incomplete:
                continue
            incomplete.append(u)

        write_lines(d / "xss_targets_finished.txt", finished)
        write_lines(d / "xss_targets_incomplete.txt", incomplete)
        write_lines(d / "xss_targets_skipped_same_param.txt", skipped)

        merged = {
            "workers": 0, "delay_ms": 0, "blocked_hits": 0, "total_lines": 0,
            "block_ratio": 0.0, "findings": 0, "poc_live": 0, "count": 0,
            "tool_failed": False, "exit_code": 0, "tool_error": "",
            "interrupted": False, "stalled": False, "budget_hit": False,
            "duration_sec": round(time.time() - t0, 1),
            "targets_count": len(urls),
            "targets_finished": len(finished),
            "targets_incomplete": len(incomplete),
            "targets_skipped_same_param": len(skipped),
            "findings_list": [], "dalfox_meta": None, "suspicious_empty": False,
        }
        json_f = d / f"dalfox_{run_tag}.json"
        txt_f = d / f"dalfox_{run_tag}.txt"
        with json_f.open("w", encoding="utf-8") as jout, txt_f.open("w", encoding="utf-8") as tout:
            for _u, r in results:
                if not r:
                    continue
                merged["findings"] += r.get("findings", 0)
                merged["count"] += r.get("count", 0)
                merged["total_lines"] += r.get("total_lines", 0)
                merged["findings_list"].extend(r.get("findings_list", []) or [])
                merged["stalled"] = merged["stalled"] or bool(r.get("stalled"))
                if r.get("tool_failed") and not r.get("per_url_capped"):
                    merged["tool_failed"] = True
                    merged["tool_error"] = merged["tool_error"] or r.get("tool_error", "")
                pj = r.get("file_json", "")
                if pj and Path(pj).exists():
                    for ln in Path(pj).read_text(errors="ignore").splitlines():
                        if ln.strip():
                            jout.write(ln.rstrip("\n") + "\n")
                pt = r.get("file_txt", "")
                if pt and Path(pt).exists():
                    tout.write(Path(pt).read_text(errors="ignore"))
        not_started = len(urls) - len(finished) - len(incomplete) - len(skipped)
        if getattr(self, "_budget_fired", False):
            merged["budget_hit"] = True
            merged["tool_error"] = (
                "Scan stopped because --max-time was reached. Findings saved so far are kept; "
                "targets that did not finish are not clean.")
        elif _INT.interrupted():
            merged["interrupted"] = True
            merged["tool_error"] = (
                "Scan stopped early (Ctrl+C). Findings may be incomplete; "
                "targets that did not finish are not clean.")
        elif incomplete or not_started:
            merged["budget_hit"] = True
            merged["tool_error"] = (
                f"{len(incomplete)} URL(s) hit the per-URL cap and {not_started} were not started. "
                f"Those are not clean — raise tools.dalfox_per_url_sec for a deeper pass.")
        merged["file_json"] = str(json_f)
        merged["file_txt"] = str(txt_f)
        return merged

    def _run_dalfox(self, xss_file: Path, d: Path, run_tag: str) -> dict:
        """v8.6: dispatcher. dalfox v2 scans a target file strictly one URL at
        a time. ReconX can split the list into N chunks and run N dalfox
        processes at once — but ONLY safely when the chunks hit DIFFERENT
        hosts; parallel processes against one host just multiply the request
        rate and trip its throttling/WAF, which silently degrades results.
        So parallelisation only kicks in when (a) the user raised
        dalfox_parallel_jobs above 1 AND (b) the target list actually spans
        several hosts. Everything else — single host, v3, small list — takes
        the plain sequential path."""
        n = _count_lines(xss_file)
        per_url = int(_cfg_get(self.cfg, "tools", "dalfox_per_url_sec", default=420) or 0)
        # Per-URL cap is the normal path. Parallelism lives inside it: several
        # hosts at once, still one process per host, each with its own cap.
        if per_url > 0 and n > 1:
            return self._run_dalfox_per_url(xss_file, d, run_tag)
        jobs = self._dalfox_job_count(n)
        min_targets = int(_cfg_get(self.cfg, "tools", "dalfox_parallel_min", default=8) or 8)
        if jobs <= 1 or n < min_targets or not tool_exists("dalfox"):
            return self._run_dalfox_once(xss_file, d, run_tag)

        try:
            targets = [l.strip() for l in xss_file.read_text(errors="ignore").splitlines() if l.strip()]
        except Exception:
            return self._run_dalfox_once(xss_file, d, run_tag)

        # group by host — a chunk must never split one host's URLs across two
        # concurrent dalfox processes (that's the rate-limit-tripping case).
        by_host = {}
        for u in targets:
            by_host.setdefault(urlparse(u).hostname or u, []).append(u)
        if len(by_host) < 2:
            info("Dalfox: single host — parallel execution skipped (parallel requests to one "
                 "host trip its rate-limit/WAF and corrupt the result), scanning sequentially")
            if per_url > 0 and n > 1:
                return self._run_dalfox_per_url(xss_file, d, run_tag)
            return self._run_dalfox_once(xss_file, d, run_tag)

        host_groups = sorted(by_host.values(), key=len, reverse=True)
        jobs = max(2, min(jobs, len(host_groups)))
        chunks = [[] for _ in range(jobs)]
        for i, grp in enumerate(host_groups):     # largest-first round-robin
            chunks[i % jobs].extend(grp)
        chunks = [c for c in chunks if c]
        info(f"Dalfox: {n} targets / {len(by_host)} hosts split into {len(chunks)} parallel jobs "
             f"(each job hits a different set of hosts)")

        chunk_dir = d / f"dalfox_{run_tag}_chunks"
        chunk_dir.mkdir(parents=True, exist_ok=True)
        results = [None] * len(chunks)

        def _worker(i, cl):
            cf = chunk_dir / f"chunk_{i}.txt"
            write_lines(cf, cl)
            results[i] = self._run_dalfox_once(cf, chunk_dir, f"{run_tag}_p{i}")

        with ThreadPoolExecutor(max_workers=len(chunks)) as ex:
            futs = [ex.submit(_worker, i, cl) for i, cl in enumerate(chunks)]
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception as e:  # noqa: BLE001
                    err(f"dalfox chunk crashed: {e}")

        merged = {
            "workers": 0, "delay_ms": 0, "blocked_hits": 0, "total_lines": 0,
            "block_ratio": 0.0, "findings": 0, "poc_live": 0, "count": 0,
            "tool_failed": False, "exit_code": 0, "tool_error": "",
            "interrupted": False, "stalled": False, "duration_sec": 0.0,
            "targets_count": n, "findings_list": [], "dalfox_meta": None,
        }
        json_f = d / f"dalfox_{run_tag}.json"
        txt_f = d / f"dalfox_{run_tag}.txt"
        with json_f.open("w", encoding="utf-8") as jout, txt_f.open("w", encoding="utf-8") as tout:
            for r in results:
                if not r:
                    merged["tool_failed"] = True
                    continue
                merged["findings"] += r.get("findings", 0)
                merged["count"] += r.get("count", 0)
                merged["total_lines"] += r.get("total_lines", 0)
                merged["findings_list"].extend(r.get("findings_list", []) or [])
                merged["duration_sec"] = max(merged["duration_sec"], r.get("duration_sec", 0.0))
                merged["interrupted"] = merged["interrupted"] or bool(r.get("interrupted"))
                merged["budget_hit"] = merged.get("budget_hit", False) or bool(r.get("budget_hit"))
                merged["stalled"] = merged["stalled"] or bool(r.get("stalled"))
                if r.get("tool_failed"):
                    merged["tool_failed"] = True
                    merged["tool_error"] = merged["tool_error"] or r.get("tool_error", "")
                pj = r.get("file_json", "")
                if pj and Path(pj).exists():
                    for ln in Path(pj).read_text(errors="ignore").splitlines():
                        if ln.strip():
                            jout.write(ln.rstrip("\n") + "\n")
                pt = r.get("file_txt", "")
                if pt and Path(pt).exists():
                    tout.write(Path(pt).read_text(errors="ignore"))
        if merged["total_lines"]:
            merged["block_ratio"] = round(
                sum(r.get("block_ratio", 0.0) * max(1, r.get("total_lines", 0))
                    for r in results if r) / max(1, merged["total_lines"]), 4)
        merged["file_json"] = str(json_f)
        merged["file_txt"] = str(txt_f)
        return merged

    def stage6_xss(self):
        stage(6, "XSS Testing")
        candidates = [
            self._cp("stage5_xss_targets"),
            self.out / "05_categorized" / "xss_targets.txt",
            self.out / "05_categorized" / "params.txt",
            self._cp("stage5_params"),
            self.out / "09_params" / "all.txt",
            self.out / "04_urls" / "all_urls_raw.txt",
        ]
        xss_file = None
        for c in candidates:
            if c.exists() and c.stat().st_size > 0:
                xss_file = c
                break
        if xss_file is None:
            warn("No XSS target file found (no xss_targets/params) — stage skipped")
            self.summary["stage6"] = {"status": "skipped", "reason": "no_target_file"}
            self.xss_results = {"findings": [], "file_txt": "", "file_json": "",
                                "count": 0}
            return

        if not tool_exists("dalfox"):
            warn("dalfox not installed — XSS stage skipped")
            self.summary["stage6"] = {"status": "skipped", "reason": "not_installed"}
            self.xss_results = {"findings": [], "file_txt": "", "file_json": "",
                                "count": 0}
            return

        d = self.out / "07_xss"
        d.mkdir(parents=True, exist_ok=True)

        # v8.6: clean + hard-cap the target list. dalfox v2 scans one URL at a
        # time — 126 targets (seen on demo.testfire.net) is ~1h and often
        # doesn't finish. Drop malformed URLs (literal \n, control chars,
        # crawler junk), dedup by (host, path, sorted-param-names), rank
        # param'd URLs above path-only, and keep the top N.
        try:
            _dfx_max = int(_cfg_get(self.cfg, "tools", "dalfox_max_targets", default=0))
        except (TypeError, ValueError):
            _dfx_max = 0
        _dfx_path_only = bool(_cfg_get(self.cfg, "tools", "dalfox_test_path_only", default=False))
        try:
            raw = [l.strip() for l in xss_file.read_text(errors="ignore").splitlines() if l.strip()]
        except Exception:
            raw = []
        reflection_urls = set()
        ref_file = self.out / "05_categorized" / "reflection.txt"
        if ref_file.exists():
            reflection_urls = {ln.strip() for ln in ref_file.read_text(errors="ignore").splitlines() if ln.strip()}
        raw = list(reflection_urls) + [u for u in raw if u not in reflection_urls]
        clean, seen_shape = [], {}
        for u in raw:
            if not u.startswith(("http://", "https://")):
                continue
            if any(c in u for c in ("\\n", "\\t", "\n", "\t", " ", "<", ">", "{", "}", "|", "^")):
                continue
            try:
                pr = urlparse(u)
                if not pr.hostname or not self._is_in_scope_url(u):
                    continue
                # Wayback concatenates unrelated URLs onto a static file
                # (t/fit.txt?.com/search, %00.jpg). Dalfox then spends its
                # whole budget on target 0 and never reaches a real parameter.
                qs_l = (pr.query or "").lower()
                if "%00" in u.lower() or qs_l.startswith(".") or qs_l.startswith("%2e"):
                    continue
                if re.search(r"\.(txt|xml|jpg|jpeg|png|gif|css|ico|svg|map|pdf|zip)$",
                             pr.path or "", re.I):
                    continue
                params = _xss_param_names(pr.query)
                in_reflection = u in reflection_urls
                if not in_reflection:
                    decoded_q = pr.query or ""
                    for _ in range(4):
                        nxt = unquote(decoded_q)
                        if nxt == decoded_q:
                            break
                        decoded_q = nxt
                    decoded_q = decoded_q.lower()
                    if any(tok in decoded_q for tok in (
                            "<script", "onerror=", "javascript:", "alert(",
                            "createelement(", "union select", "xp_cmdshell",
                            "/etc/passwd")):
                        continue
            except Exception:
                continue
            # One row per parameter. Search.asp?tfSearch=a and
            # Search.asp?tfSearch=Mert are the same injection point, so the
            # XSS list keeps a single example. The full reflection file stays
            # untouched for the categorised view.
            if not params:
                # Stored pages (contact-us, forum, register) have no query.
                # Locale copies of the same route are one test.
                if in_reflection or _is_stored_path(pr.path or ""):
                    parts = [s for s in (pr.path or "/").split("/") if s]
                    tail = "/".join(parts[-2:]) if len(parts) >= 2 else (parts[0] if parts else "/")
                    shape = ((pr.hostname or "").lower(), tail.lower(), ())
                    if shape not in seen_shape:
                        seen_shape[shape] = len(clean)
                        clean.append((u, 0, True))
                    continue
                shape = ((pr.hostname or "").lower(),
                         _path_shape(pr.path or "/").rstrip("/") or "/",
                         ())
                if shape not in seen_shape:
                    seen_shape[shape] = len(clean)
                    clean.append((u, 0, False))
                continue
            point = _xss_injection_point(u)
            shape = point or ((pr.hostname or "").lower(),
                              (pr.path or "/").lower(),
                              params)
            if shape in seen_shape:
                i = seen_shape[shape]
                prev = clean[i]
                if _xss_example_rank(u) < _xss_example_rank(prev[0]):
                    clean[i] = (u, len(params), in_reflection or prev[2])
                elif in_reflection and not prev[2]:
                    clean[i] = (prev[0], prev[1], True)
                continue
            seen_shape[shape] = len(clean)
            clean.append((u, len(params), in_reflection))
        reflect_kept = [u for u, n, is_ref in clean if is_ref and n]
        stored_kept = [u for u, n, is_ref in clean if is_ref and not n]
        other_params = [u for u, n, is_ref in clean if n and not is_ref]
        unique = unique_xss_urls(other_params)
        unique.sort(key=_xss_test_rank)
        reflect_kept.sort(key=_xss_test_rank)
        require_reflection = bool(_cfg_get(self.cfg, "tools", "xss_reflected_only", default=True))
        try:
            reflect_threads = int(_cfg_get(self.cfg, "tools", "xss_reflect_threads", default=20) or 20)
        except (TypeError, ValueError):
            reflect_threads = 20
        try:
            reflect_timeout = int(_cfg_get(self.cfg, "tools", "xss_reflect_timeout", default=8) or 8)
        except (TypeError, ValueError):
            reflect_timeout = 8

        def _xss_headers(url):
            host = urlparse(url).hostname or self.target
            headers = pick_header_strategy(host, self.cfg)
            if self.has_auth():
                headers = self._auth_headers(headers)
            return headers

        if require_reflection and unique:
            probed, reflect_stats = probe_live_reflected(
                unique, self.cfg, threads=reflect_threads, timeout=reflect_timeout,
                header_for=_xss_headers)
            if reflect_stats.get("error") == "no_http_client":
                warn("Reflection check skipped — no HTTP client, testing the unique parameter list")
                probed = unique
            else:
                sub(f"Other parameters: {len(unique):,} unique "
                    f"→ {reflect_stats['live']:,} live, {reflect_stats['reflected']:,} reflected")
        else:
            probed = unique
        seen_final = set()
        final = []
        for u in reflect_kept + stored_kept + probed:
            if u in seen_final:
                continue
            seen_final.add(u)
            final.append(u)
        before_unique = len(final)
        final = unique_xss_params(final)
        if before_unique != len(final):
            sub(f"XSS list {before_unique} → {len(final)} (same parameter on another URL is not tested again)")
        sub(f"XSS targets: {len(reflection_urls):,} reflection URLs → {len(reflect_kept):,} parameters"
            f" + {len(stored_kept):,} stored routes + {len(probed):,} other parameters")
        if _dfx_max > 0:
            final = final[:_dfx_max]
        info(f"XSS testing {len(final)} URL(s) — reflected, DOM and stored, one URL per parameter")
        if final:
            for n, queued in enumerate(final, 1):
                sub(f"{n}/{len(final)} parameter {_xss_param_label(queued)} "
                    f"({_xss_kind_label(queued)}) {queued[:140]}")
            _pulse_job("XSS testing", time.time(), 0, len(final), unit="urls",
                       item=f"1/{len(final)} parameter {_xss_param_label(final[0])}",
                       note=_xss_kind_label(final[0]), force=True)
        tested_f = d / "xss_targets_tested.txt"
        if _dfx_path_only:
            path_only = [u for u, n, _r in clean if not n]
            room = _dfx_path_only and (path_only[:int(_cfg_get(
                self.cfg, "tools", "dalfox_path_only_max", default=100) or 100)])
            if room:
                final = list(final) + [u for u in room if u not in set(final)]
        if not final and not require_reflection:
            final = [u for u in raw
                     if u.startswith(("http://", "https://")) and self._is_in_scope_url(u)]
            if _dfx_max > 0:
                final = final[:_dfx_max]
        tested_f = d / "xss_targets_tested.txt"
        write_lines(tested_f, final)
        xss_file = tested_f
        if not final:
            warn("No live reflected parameters — XSS stage skipped")
            self.summary["stage6"] = {
                "status": "skipped", "reason": "no_reflected_params",
                "collected": len(raw), "unique": len(unique),
            }
            self.xss_results = {"findings": [], "file_txt": "", "file_json": "", "count": 0}
            return
        if len(raw) > len(final):
            why = "unique, live, reflected parameters"
            if _dfx_max > 0:
                why += f" + tools.dalfox_max_targets={_dfx_max} cap"
            sub(f"Dalfox targets {len(raw)} → {len(final)} ({why})")

        # v8.2: auto-provision a blind XSS OOB callback (interactsh) if the user
        # hasn't manually configured one. A manually-set config.blind_xss_callback
        # or --blind CLI flag always takes priority and disables auto mode — we
        # only fill the gap, never override an explicit choice.
        manual_blind = (_cfg_get(self.cfg, "tools", "blind_xss_callback", default="") or "").strip()
        manual_blind = manual_blind or (getattr(self, "_blind_cb", "") or "").strip()
        interactsh_session = None
        if not manual_blind and bool(_cfg_get(self.cfg, "tools", "blind_xss_auto", default=True)):
            poll_iv = int(_cfg_get(self.cfg, "tools", "blind_xss_poll_interval", default=5) or 5)
            interactsh_session = start_interactsh_session(d / "interactsh", poll_interval=poll_iv)
            if interactsh_session.get("available"):
                self._blind_cb = interactsh_session["domain"]
                sub(f"Blind XSS callback auto-provisioned via interactsh: {interactsh_session['domain']}")
            else:
                warn(f"Blind XSS auto-callback unavailable ({interactsh_session.get('error','?')}) "
                     f"— install interactsh-client (go install github.com/projectdiscovery/"
                     f"interactsh/cmd/interactsh-client@latest) to enable it, or set "
                     f"tools.blind_xss_callback manually. Continuing without a blind-XSS callback.")

        run = self._run_dalfox(xss_file, d, "scan")

        xss_screenshots = []
        if bool(_cfg_get(self.cfg, "settings", "xss_alert_screenshots", default=True)):
            max_shots = int(_cfg_get(self.cfg, "settings", "xss_alert_screenshots_max", default=15) or 15)
            xss_screenshots = capture_xss_alert_screenshots(
                run.get("findings_list") or [], d, max_shots=max_shots,
                nav_timeout_sec=int(_cfg_get(self.cfg, "settings", "timeout", default=15) or 15),
                budget_sec=int(_cfg_get(self.cfg, "settings", "xss_verify_budget_sec", default=3600) or 3600),
                payloads_per_point=int(_cfg_get(self.cfg, "settings", "xss_verify_payloads_per_point", default=4) or 4),
                max_checks=int(_cfg_get(self.cfg, "settings", "xss_verify_max_checks", default=60) or 60),
                honor_skip=False)
            # v8.5-fix: the "R"→"RV" promotion (a Reflected finding ReconX
            # itself proved fires a real dialog on headless replay) happens in
            # report_builder.py's _parse_xss() instead of here — the report
            # re-derives its findings list FRESH from the raw dalfox_*.json
            # file on disk (see build_report()/_parse_xss()), completely
            # independent of this in-memory run["findings_list"], so mutating
            # it here would have had zero effect on the actual report. The
            # screenshots list below (which DOES reach the report, via
            # SUMMARY.json's stage6.screenshots) carries everything
            # _parse_xss() needs: url + confirmed_upgrade.

        blind_interactions = []
        if interactsh_session and interactsh_session.get("available"):
            listen_after = int(_cfg_get(self.cfg, "tools", "blind_xss_listen_after_sec", default=90) or 90)
            if _INT.hard():
                listen_after = 0
            stop_interactsh_session(interactsh_session, extra_listen_sec=listen_after)
            blind_interactions = parse_interactsh_interactions(interactsh_session.get("log_file"))
            if blind_interactions:
                ok(f"Blind XSS CONFIRMED — {len(blind_interactions)} out-of-band callback(s) received "
                   f"on {interactsh_session['domain']}")
            try:
                _write_config_auto_state(self._config_path, {
                    "blind_callback_last_used": interactsh_session["domain"],
                    "blind_callback_last_target": self.target,
                    "blind_callback_last_used_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "blind_callback_interactions_confirmed": len(blind_interactions),
                })
            except Exception:
                pass

        run["blind_interactions"] = blind_interactions
        run["blind_callback_used"] = (interactsh_session or {}).get("domain", "") or manual_blind
        run["screenshots"] = xss_screenshots
        disk_findings = 0
        try:
            for pj in (d / "dalfox_per_url").glob("dalfox_*.json"):
                if pj.stat().st_size <= 0:
                    continue
                for line in pj.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(rec, dict) and str(rec.get("type") or "").upper() in ("V", "R", "RV"):
                        disk_findings += 1
        except Exception:
            disk_findings = 0
        if disk_findings > int(run.get("findings") or 0):
            run["findings"] = disk_findings
            run["count"] = disk_findings
        self.xss_results = run
        _stage6_status = "tool_error" if run.get("tool_failed") else (
            "partial" if (run.get("interrupted") or run.get("budget_hit")) else "done")
        self.summary["stage6"] = {
            "status": _stage6_status,
            "findings": run["findings"],
            "count": run["findings"],
            "file_txt": run["file_txt"],
            "file_json": run["file_json"],
            "tool_failed": run.get("tool_failed", False),
            "tool_error": run.get("tool_error", ""),
            "interrupted": run.get("interrupted", False),
            "budget_hit": run.get("budget_hit", False),
            "stalled": run.get("stalled", False),
            "duration_sec": run.get("duration_sec", 0.0),
            "targets_count": run.get("targets_count", 0),
            "targets_finished": run.get("targets_finished", 0),
            "targets_incomplete": run.get("targets_incomplete", 0),
            "blind_callback_used": run["blind_callback_used"],
            "blind_interactions": blind_interactions,
            "screenshots": xss_screenshots,
            "suspicious_empty": run.get("suspicious_empty", False),
        }
        if run.get("tool_failed"):
            err(f"Dalfox FAILED — {run.get('tool_error','')} "
                f"('0 findings' here does NOT necessarily mean 'clean')")
        elif run.get("budget_hit"):
            warn(f"Dalfox hit its time budget ({run.get('duration_sec',0)}s) and was stopped — "
                 f"the {run['findings']} findings collected so far were saved, but not every target "
                 f"was necessarily scanned (raise tools.dalfox_time_budget_sec)")
        elif run.get("interrupted"):
            warn(f"Dalfox stopped early ({run.get('duration_sec',0)}s, "
                 f"{run.get('total_lines',0)} lines processed) — findings may be INCOMPLETE")
        elif run["findings"]:
            ok(f"Dalfox found {run['findings']:,} findings")
        else:
            ok("Dalfox completed — no findings")

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 7 — Nuclei Vulnerability Scan (full live URL corpus)
    # ══════════════════════════════════════════════════════════════════════════
    def _get_nuclei_template_path(self) -> str:
        # v8.7-fix: memoization was lost in a refactor — discover_nuclei_
        # templates() recursively walks up to 8 candidate directories, and
        # this is called 3x per scan (fastpass, full nuclei, dast-dir pick).
        # self._nuclei_tpl_path was still being initialized in __init__ but
        # never read/written here, making it dead. Cache it again.
        if self._nuclei_tpl_path is not None:
            return self._nuclei_tpl_path
        override = _cfg_get(self.cfg, "tools", "nuclei_templates", default="") or ""
        if not override and self._nuclei_tpl_override:
            override = self._nuclei_tpl_override
        self._nuclei_tpl_path = discover_nuclei_templates(override)
        return self._nuclei_tpl_path

    def _get_nuclei_dast_dir(self) -> str:
        """v8.6-fix: the fuzzing pass needs a `dast/` template dir that is
        actually POPULATED. `discover_nuclei_templates()` picks the first root
        with any *.yaml — but on this box `/root/nuclei-templates` wins that
        race while its `dast/` subdir is empty/stale, so nuclei -dast loads 0
        fuzz templates and silently reports "0 findings" on a target with a
        blatant reflected XSS. Scan every known root for a dast/ subdir with a
        real template count and take the richest one."""
        cands = []
        primary = self._get_nuclei_template_path()
        if primary:
            cands.append(Path(primary) / "dast")
        for c in _NUCLEI_TEMPLATE_CANDIDATES:
            cands.append(Path(c) / "dast")
        # running as root, root can read every user's checkout too
        try:
            for home in Path("/home").iterdir():
                cands.append(home / "nuclei-templates" / "dast")
        except Exception:
            pass
        best, best_n = "", 0
        seen = set()
        for p in cands:
            sp = str(p)
            if sp in seen:
                continue
            seen.add(sp)
            try:
                if not p.is_dir():
                    continue
                n = sum(1 for _ in p.rglob("*.yaml"))
            except Exception:
                continue
            if n > best_n:
                best, best_n = sp, n
        if best_n >= 10:
            ok(f"Nuclei DAST templates: {best} ({best_n} fuzzing templates)")
            return best
        warn(f"Nuclei DAST: no populated dast/ template dir found (best={best or 'none'}, "
             f"{best_n} templates) — fuzzing pass will be unreliable")
        return best

    def _nuclei_tech_tags(self) -> str:
        """v6.13: stage11'de tespit edilen teknolojilerden nuclei -tags degeri uretir."""
        techs = set()
        for r in (self.tech_summary or []):
            for t in r.get("techs", []):
                techs.add(t)
        tags = set()
        for pat, tag_list in _TECH_TO_NUCLEI_TAGS:
            for t in techs:
                if re.search(pat, t):
                    tags.update(tag_list.split(","))
                    break
        return ",".join(sorted(tags))

    def _build_nuclei_targets(self, tgt_file: Path) -> dict:
        """v9.0: nuclei's target list is the FULL live URL corpus, not just the
        alive host roots.

        Feeding it only "https://host/" (the pre-9.0 behaviour) meant every
        template that matches on a PATH — an exposed /.git/config, a
        /actuator/env, a /wp-json/ endpoint, a parameterised injection point —
        could only ever fire if that path happened to be the site root. Every
        URL the crawl stages actually proved to be live was thrown away before
        the scan. Now stage 4's pruned live-URL list, the categorised param
        URLs and any authenticated URLs all go into one -l file.

        Two guards keep "everything" from turning into a scan that never ends:

          * shape dedup — ?id=1 / ?id=2 / ?id=3 and /post/1 /post/2 /post/3 are
            the same template surface, so ONE representative per
            (scheme, host, path-shape, param-names) is kept. On a real corpus
            this is where most of the reduction comes from, and it costs no
            coverage.
          * a hard cap (tools.nuclei_max_targets) applied BY PRIORITY, so the
            alive host roots and the parameterised URLs always survive it and
            only plain path URLs get trimmed.

        Returns a stats dict; the file itself is written to tgt_file.
        """
        dedup = bool(_cfg_get(self.cfg, "tools", "nuclei_dedup_url_shapes", default=True))
        buckets = {0: [], 1: [], 2: []}     # 0 = host roots, 1 = param/auth URLs, 2 = path URLs
        seen_url = {}                        # url -> tier already assigned
        seen_shape = set()
        counters = {"raw": 0, "out_of_scope": 0, "shape_dropped": 0}

        def _add(raw: str, tier: int):
            u = strip_ansi((raw or "").strip())
            if not u or u.startswith("#"):
                return
            counters["raw"] += 1
            if not u.startswith(("http://", "https://")):
                u = f"https://{u}"
            if len(u) > 2000:
                return
            if not self._is_in_scope_url(u):
                counters["out_of_scope"] += 1
                return
            try:
                pr = urlparse(u)
            except Exception:
                return
            if not pr.hostname:
                return
            if u in seen_url:
                return
            # Host roots are never shape-deduped against each other: one root
            # per alive host is exactly what we want and they are the highest
            # value targets in the list.
            if dedup and tier > 0:
                shape = (pr.scheme, pr.hostname, pr.port,
                         _path_shape(pr.path or "/"),
                         _query_param_shape(pr.query) if pr.query else "")
                if shape in seen_shape:
                    counters["shape_dropped"] += 1
                    return
                seen_shape.add(shape)
            seen_url[u] = tier
            buckets[tier].append(u)

        def _lines(path: Path):
            try:
                if path.exists() and path.stat().st_size > 0:
                    return path.read_text(errors="replace").splitlines()
            except Exception:
                pass
            return []

        # ── tier 0: every alive host root ────────────────────────────────────
        for ln in _lines(self._cp("stage3_alive")):
            _add(ln, 0)

        # ── tier 1: authenticated URLs (behind a login = the interesting half)
        for ln in _lines(self._cp("stage8_authenticated_urls")):
            _add(ln, 1)

        # ── tiers 1/2: the live URL corpus. Anything carrying a query string
        # is a candidate injection point, so it outranks a plain path URL.
        url_sources = [
            self._cp("stage4_urls"),
            self.out / "04_urls" / "all_urls_live.txt",
            self.out / "05_categorized" / "params.txt",
            self.out / "05_categorized" / "xss_targets.txt",
            self._cp("stage5_params"),
            self._cp("stage9_params"),
            self._cp("stage13_api"),
        ]
        for src in url_sources:
            for ln in _lines(src):
                s = ln.strip()
                if not s:
                    continue
                _add(s, 1 if "?" in s else 2)

        ordered = buckets[0] + buckets[1] + buckets[2]
        total_unique = len(ordered)
        try:
            cap = int(_cfg_get(self.cfg, "tools", "nuclei_max_targets", default=0) or 0)
        except (TypeError, ValueError):
            cap = 0
        capped = 0
        if cap > 0 and total_unique > cap:
            keep = []
            for tier in (0, 1, 2):
                room = cap - len(keep)
                if room <= 0:
                    break
                keep.extend(buckets[tier][:room])
            capped = total_unique - len(keep)
            ordered = keep

        write_lines(tgt_file, ordered)
        stats = {
            "total": len(ordered),
            "hosts": sum(1 for u in ordered if seen_url.get(u) == 0),
            "param_urls": sum(1 for u in ordered if seen_url.get(u) == 1),
            "path_urls": sum(1 for u in ordered if seen_url.get(u) == 2),
            "raw_seen": counters["raw"],
            "shape_deduped": counters["shape_dropped"],
            "out_of_scope": counters["out_of_scope"],
            "capped": capped,
            "cap": cap,
            "shape_dedup": dedup,
        }
        return stats

    def _run_nuclei_once(self, targets: Path, d: Path, run_tag: str, extra_tags: str = "") -> dict:
        res = {
            "threads": 0, "rate": 0, "blocked_hits": 0, "total_lines": 0,
            "http_responses": 0, "block_ratio": 0.0, "findings": 0,
            "file_txt": "", "file_json": "", "severity_counts": {},
            "template_path": "unknown",
            "tool_failed": False, "exit_code": None, "tool_error": "",
            "interrupted": False, "duration_sec": 0.0, "tags_used": extra_tags,
            "severity_filter": "", "targets_count": _count_lines(targets), "stalled": False,
        }
        # v8.6-fix: the main nuclei pass was reading settings.threads /
        # settings.rate_limit (tuned for the crawl/probe stages — often 10-25)
        # and completely IGNORING tools.nuclei_concurrency / tools.nuclei_rate_limit,
        # so a config that says "nuclei_rate_limit: 150" still crawled templates
        # at ~10 req/s and a full-template scan on one host took 40+ minutes.
        # Now nuclei's own knobs win, with the generic settings as fallback.
        base_threads = int(_cfg_get(self.cfg, "tools", "nuclei_concurrency",
                                    default=_cfg_get(self.cfg, "settings", "threads", default=25)) or 25)
        threads = self._tuned_threads(min(base_threads, 100), 100)
        base_rate = int(_cfg_get(self.cfg, "tools", "nuclei_rate_limit",
                                 default=_cfg_get(self.cfg, "settings", "rate_limit", default=150)) or 150)
        rate = self._tuned_rate(base_rate, 300)
        res["threads"] = threads
        res["rate"] = rate

        dbg = d / "nuclei_run.log"
        if not tool_exists("nuclei"):
            warn("nuclei not found — skipping nuclei scan")
            res["template_path"] = "not_installed"
            return res

        tpl = self._get_nuclei_template_path()
        res["template_path"] = tpl or "built-in"

        d.mkdir(parents=True, exist_ok=True)
        json_f = d / f"nuclei_{run_tag}.json"
        txt_f  = d / f"nuclei_{run_tag}.txt"

        severity = (_cfg_get(self.cfg, "tools", "nuclei_severity", default="") or "").strip()
        if self._nuclei_severity_override:
            severity = self._nuclei_severity_override
        res["severity_filter"] = severity or "none"
        ex_tags = (_cfg_get(self.cfg, "tools", "nuclei_excluded_tags", default="") or "").strip()
        stats_interval = str(int(_cfg_get(self.cfg, "tools", "nuclei_stats_interval", default=5) or 5))
        # "No output for N seconds" is only evidence of a hang if nuclei would
        # normally have printed something by then — and what it prints on a
        # quiet scan is its -stats line. Derive the watchdog from that interval
        # instead of hardcoding 300s, so raising nuclei_stats_interval can no
        # longer make a healthy scan look stalled.
        stall_sec = int(_cfg_get(self.cfg, "tools", "nuclei_stall_timeout_sec",
                                 default=max(300, int(stats_interval) * 12)) or 300)

        hdr_set = pick_header_strategy(self.target, self.cfg)
        if self.has_auth():
            hdr_set = self._auth_headers(hdr_set)
            sub("Using authenticated session for nuclei")
        hdr_args = _hdr_args_nuclei(hdr_set)

        # v6.12: "-silent" kaldirildi; "-stats" + "-stats-interval" ile periyodik
        # ilerleme ciktisi eklendi. Boylece spinner gercek zamanli guncellenir ve
        # tarama "takilmis" gibi gorunmez.
        # v6.17: "-duc" (disable-update-check) eklendi — nuclei varsayilan olarak
        # baslarken kendi surum/template guncelleme kontrolu icin projectdiscovery
        # bulut altyapisina baglanmayi dener; kisitli/duvarli aglarda bu kontrol
        # hicbir cikti uretmeden askida kalabiliyor (tespit edildi). -duc bu riski
        # buyuk olcude azaltir; ek guvence olarak stall_timeout watchdog'u da devrede.
        # v9.0: the main pass and the adaptive re-run used to build their argv
        # separately, so a flag added to one silently never reached the other.
        # One builder now owns both.
        nh = _help_text("nuclei")
        retries = int(_cfg_get(self.cfg, "tools", "nuclei_retries", default=1) or 1)
        max_host_err = int(_cfg_get(self.cfg, "tools", "nuclei_max_host_error", default=30) or 30)
        strategy = (_cfg_get(self.cfg, "tools", "nuclei_scan_strategy", default="auto") or "auto").strip()
        req_timeout = int(_cfg_get(self.cfg, "settings", "timeout", default=20))

        def _build(out_path: Path, conc: int, rl: int) -> list:
            c = ["nuclei", "-l", str(targets), "-nc", "-duc",
                 "-jsonl", "-o", str(out_path),
                 "-stats", "-stats-interval", stats_interval,
                 "-c", str(conc), "-rl", str(rl), "-timeout", str(req_timeout)]
            # Every entry in the list is a full scheme://host/path URL, so
            # nuclei's own httpx pre-probe round has nothing left to resolve —
            # skipping it saves one request per target on a list this size.
            if "-no-httpx" in nh:
                c += ["-nh"]
            if "-retries" in nh:
                c += ["-retries", str(max(0, retries))]
            # A host that has already errored out N times is down or blocking;
            # continuing to aim thousands of templates at it only slows the run.
            if "-max-host-error" in nh:
                c += ["-mhe", str(max(1, max_host_err))]
            if strategy and strategy != "auto" and "-scan-strategy" in nh:
                c += ["-ss", strategy]
            # The JSONL is parsed for template-id / severity / matched-at only —
            # nothing downstream reads the raw request/response pair or the
            # base64 template body, and on a multi-thousand-URL corpus those two
            # fields are what turn the output into a multi-GB file.
            if "-omit-raw" in nh:
                c += ["-or"]
            if "-omit-template" in nh:
                c += ["-ot"]
            if tpl:
                c += ["-t", tpl]
            if severity:
                c += ["-severity", severity]
            if ex_tags:
                c += ["-exclude-tags", ex_tags]
            if extra_tags:
                c += ["-tags", extra_tags]
            c += hdr_args
            c += _tor_cli_flag("nuclei", self.cfg)
            return c

        cmd = _build(json_f, threads, rate)
        fatal = {"line": ""}
        try:
            dbg.write_text(
                f"# {time.strftime('%Y-%m-%d %H:%M:%S')} {shlex.join(cmd)}\n",
                encoding="utf-8")
        except Exception:
            pass

        info(f"Nuclei is running against {_count_lines(targets):,} targets "
             f"(templates={res['template_path']}"
             f"{', tags=' + extra_tags if extra_tags else ''})")
        _t0 = time.time()
        rc, lines, killed, stalled = _stream_tool(
            cmd, timeout=T["nuclei"], log=self.log, label="nuclei",
            line_cb=_nuclei_log_cb(dbg, fatal),
            stall_timeout=stall_sec
        )
        res["duration_sec"] = round(time.time() - _t0, 1)
        res["interrupted"] = bool(killed)
        res["stalled"] = bool(stalled)
        res["total_lines"] = lines
        res["exit_code"] = rc
        if not killed and rc not in (0, None):
            res["tool_failed"] = True
            detail = f" — {fatal['line']}" if fatal.get("line") else ""
            res["tool_error"] = (
                f"nuclei exited with code {rc}{detail} — results may be incomplete (log: {dbg})")
        elif stalled:
            res["tool_failed"] = True
            res["tool_error"] = ("Nuclei 300s boyunca hicbir ilerleme kaydetmedi ve otomatik "
                                  "durduruldu — arac askida kalmis olabilir (network engeli, "
                                  "kendi guncelleme kontrolu vb.)")
        elif killed:
            res["tool_error"] = ("Tarama kullanici tarafindan erken durduruldu (Ctrl+C) — "
                                  "bulgular EKSIK olabilir, tum hedefler taranmamis olabilir")

        findings = []
        sev_counts = {}
        http_responses = 0
        blocked = 0
        if json_f.exists() and json_f.stat().st_size > 0:
            with json_f.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    matched = rec.get("matched-at") or rec.get("host") or ""
                    sev = (rec.get("info", {}) or {}).get("severity", "info") or "info"
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                    name = (rec.get("info", {}) or {}).get("name", "")
                    template = rec.get("template-id", "")
                    findings.append({
                        "template": template,
                        "name": name,
                        "severity": sev,
                        "matched_at": matched,
                        "type": rec.get("type", ""),
                    })
                    if rec.get("type") == "http":
                        http_responses += 1
                    if int(rec.get("status-code") or 0) in (403, 429):
                        blocked += 1
        res["findings"] = len(findings)
        res["http_responses"] = http_responses
        res["severity_counts"] = sev_counts
        if lines:
            res["block_ratio"] = round(blocked / max(1, lines), 4)

        rerun_on_block = bool(_cfg_get(self.cfg, "settings", "rerun_on_block", default=True))
        rerun_max = int(_cfg_get(self.cfg, "settings", "rerun_max", default=1))
        thr = float(_cfg_get(self.cfg, "settings", "adaptive_threshold", default=0.18))
        if rerun_on_block and rerun_max > 0 and lines and res["block_ratio"] >= thr \
                and not killed and not res["tool_failed"] and not _INT.hard():
            info(f"Nuclei block ratio {res['block_ratio']:.2%} — starting an adaptive re-run (max={rerun_max})")
            self._apply_adaptive("nuclei high block ratio")
            initial_f = d / f"nuclei_{run_tag}_initial.json"
            try:
                shutil.copy2(json_f, initial_f)
            except Exception:
                initial_f = json_f
            rerun_files = []
            pause_sec = float(_cfg_get(self.cfg, "settings", "rerun_pause_sec", default=2))
            backoff = float(_cfg_get(self.cfg, "settings", "rerun_backoff", default=0.5))
            for idx in range(1, max(1, rerun_max) + 1):
                if _INT.stage_skip():
                    break
                rerun_rate = self._tuned_rate(max(1, int(rate * (backoff ** idx))), 30)
                rerun_f = d / f"nuclei_{run_tag}_rerun_{idx}.json"
                rerun_cmd = _build(rerun_f, max(1, threads // 2), rerun_rate)
                _rc2, _lines2, killed2, _stalled2 = _stream_tool(
                    rerun_cmd, timeout=T["nuclei"], log=self.log, label=f"nuclei-rerun-{idx}",
                    line_cb=None, stall_timeout=stall_sec
                )
                res["reruns"] = idx
                res["rate"] = rerun_rate
                if rerun_f.exists() and rerun_f.stat().st_size > 0:
                    rerun_files.append(rerun_f)
                if killed2:
                    break
                if idx < rerun_max and pause_sec > 0:
                    time.sleep(pause_sec * max(0.0, backoff ** (idx - 1)))

            sources = [initial_f] + rerun_files
            records = {}
            for src in sources:
                if not src.exists():
                    continue
                for line in src.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    key = (rec.get("template-id", ""),
                           rec.get("matched-at") or rec.get("host") or "",
                           rec.get("type", ""))
                    records[key] = rec
            if records:
                with json_f.open("w", encoding="utf-8") as fh:
                    for rec in records.values():
                        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                findings = []
                sev_counts = {}
                http_responses = 0
                blocked = 0
                for rec in records.values():
                    matched = rec.get("matched-at") or rec.get("host") or ""
                    sev = (rec.get("info", {}) or {}).get("severity", "info") or "info"
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                    findings.append({
                        "template": rec.get("template-id", ""),
                        "name": (rec.get("info", {}) or {}).get("name", ""),
                        "severity": sev, "matched_at": matched, "type": rec.get("type", ""),
                    })
                    if rec.get("type") == "http":
                        http_responses += 1
                    if int(rec.get("status-code") or 0) in (403, 429):
                        blocked += 1
                res["findings"] = len(findings)
                res["http_responses"] = http_responses
                res["severity_counts"] = sev_counts
                res["total_lines"] = len(records)
                res["block_ratio"] = round(blocked / max(1, len(records)), 4)
                res["rerun_files"] = [str(x) for x in rerun_files]

        try:
            with json_f.open("r", encoding="utf-8", errors="replace") as fh, \
                 txt_f.open("w", encoding="utf-8") as fo:
                for line in fh:
                    try:
                        rec = json.loads(line.strip())
                        info_ = rec.get("info", {}) or {}
                        sev = info_.get("severity", "?")
                        name = info_.get("name", "")
                        tplid = rec.get("template-id", "")
                        matched = rec.get("matched-at", "")
                        fo.write(f"[{sev}] {name} ({tplid}) @ {matched}\n")
                    except Exception:
                        continue
        except Exception:
            pass

        res["file_txt"] = str(txt_f)
        res["file_json"] = str(json_f)
        return res

    def _collect_param_urls(self, limit=1500):
        """Every URL that carries at least one query parameter, deduped by
        (host, path, sorted-param-names) — the shape that actually matters for
        injection fuzzing. Feeds nuclei -dast."""
        srcs = [
            self._cp("stage5_params"),
            self.out / "05_categorized" / "params.txt",
            self.out / "05_categorized" / "xss_targets.txt",
            self.out / "09_params" / "all.txt",
            self._cp("stage4_urls"),
            self.out / "04_urls" / "all_urls_live.txt",
        ]
        seen_shape, out = set(), []
        for s in srcs:
            if not s.exists():
                continue
            for ln in s.read_text(errors="ignore").splitlines():
                u = strip_ansi(ln.strip())
                if not u.startswith(("http://", "https://")) or "?" not in u:
                    continue
                try:
                    pr = urlparse(u)
                    params = tuple(sorted(k for k, _ in parse_qsl(pr.query)))
                except Exception:
                    continue
                if not params or not self._is_in_scope_url(u):
                    continue
                shape = (pr.hostname, pr.path, params)
                if shape in seen_shape:
                    continue
                seen_shape.add(shape)
                out.append(u)
                if limit and len(out) >= limit:
                    return out
        return out

    def _run_nuclei_dast(self, d: Path):
        """v8.6: nuclei DAST/fuzzing pass. The normal template scan matches
        known CVEs/misconfigs on a host; it finds nothing on a bespoke app that
        is vulnerable by design. -dast fuzzes each query parameter for XSS,
        SQLi, SSTI, LFI, cmdi, CRLF, redirect, etc. — this is the pass that
        actually produces injection findings on custom targets."""
        res = {"findings": 0, "severity_counts": {}, "file_json": "", "file_txt": "",
               "targets_count": 0, "tool_failed": False, "tool_error": "", "duration_sec": 0.0}
        if not bool(_cfg_get(self.cfg, "tools", "nuclei_dast", default=True)):
            return res
        try:
            dast_max = int(_cfg_get(self.cfg, "tools", "nuclei_dast_max_urls", default=0) or 0)
        except (TypeError, ValueError):
            dast_max = 0
        param_urls = self._collect_param_urls(limit=dast_max)
        if not param_urls:
            sub("Nuclei DAST skipped — no parameterised URLs")
            return res
        tgt = d / "nuclei_dast_targets.txt"
        write_lines(tgt, param_urls)
        res["targets_count"] = len(param_urls)
        json_f = d / "nuclei_dast.json"
        txt_f = d / "nuclei_dast.txt"
        threads = self._tuned_threads(min(int(_cfg_get(self.cfg, "settings", "threads", default=20)), 25), 25)
        rate = self._tuned_rate(int(_cfg_get(self.cfg, "tools", "nuclei_rate_limit", default=150) or 150), 150)
        cmd = ["nuclei", "-l", str(tgt), "-dast", "-nc", "-duc", "-jsonl", "-o", str(json_f),
               "-stats", "-stats-interval", "10", "-c", str(threads), "-rl", str(rate),
               "-timeout", str(int(_cfg_get(self.cfg, "settings", "timeout", default=20)))]
        dast_dir = self._get_nuclei_dast_dir()
        if dast_dir:
            cmd += ["-t", dast_dir]
            res["dast_template_dir"] = dast_dir
        else:
            res["tool_error"] = "no populated dast/ template dir"
        hdr_set = pick_header_strategy(self.target, self.cfg)
        if self.has_auth():
            hdr_set = self._auth_headers(hdr_set)
        cmd += _hdr_args_nuclei(hdr_set)
        cmd += dns_resolver_args("nuclei")
        cmd += _tor_cli_flag("nuclei", self.cfg)
        dast_log = d / "nuclei_dast.log"
        fatal = {"line": ""}
        try:
            dast_log.write_text(
                f"# {time.strftime('%Y-%m-%d %H:%M:%S')} {shlex.join(cmd)}\n",
                encoding="utf-8")
        except Exception:
            pass
        info(f"Nuclei DAST (fuzzing) on {len(param_urls):,} parameterised URLs — "
             f"XSS/SQLi/SSTI/LFI/cmdi/redirect fuzzing")
        _t0 = time.time()
        rc = lines = killed = stalled = None
        # A fast empty pass right after dalfox is often a brief throttle, so
        # retry once. A non-zero exit is a startup failure (bad flag, dead
        # proxy, missing templates) — waiting 15s does not fix it.
        for _try in (1, 2):
            rc, lines, killed, stalled = _stream_tool(
                cmd, timeout=T.get("nuclei_dast", 7200), log=self.log,
                label=f"nuclei-dast{'' if _try == 1 else '-retry'}",
                line_cb=_nuclei_log_cb(dast_log, fatal), stall_timeout=600)
            _elapsed = time.time() - _t0
            _empty = not (json_f.exists() and json_f.stat().st_size > 0)
            if killed or rc not in (0, None) or not _empty or _elapsed > 25 or _try == 2:
                break
            warn(f"Nuclei DAST finished in {_elapsed:.0f}s with no findings — "
                 f"the target may have throttled the first requests. Waiting 15s and retrying once.")
            time.sleep(15)
        res["duration_sec"] = round(time.time() - _t0, 1)
        if not killed and rc not in (0, None):
            res["tool_failed"] = True
            detail = f" — {fatal['line']}" if fatal.get("line") else ""
            res["tool_error"] = f"nuclei -dast exited {rc}{detail} (log: {dast_log})"
        findings, sev_counts = [], {}
        if json_f.exists() and json_f.stat().st_size > 0:
            for line in json_f.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                info_ = rec.get("info", {}) or {}
                sev = info_.get("severity", "info") or "info"
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                findings.append({
                    "template": rec.get("template-id", ""),
                    "name": info_.get("name", ""),
                    "severity": sev,
                    "matched_at": rec.get("matched-at") or rec.get("host") or "",
                    "type": rec.get("type", ""),
                })
            try:
                with txt_f.open("w", encoding="utf-8") as fo:
                    for f in findings:
                        fo.write(f"[{f['severity']}] {f['name']} ({f['template']}) @ {f['matched_at']}\n")
            except Exception:
                pass
        res["findings"] = len(findings)
        res["findings_list"] = findings
        res["severity_counts"] = sev_counts
        res["file_json"] = str(json_f)
        res["file_txt"] = str(txt_f)
        if findings:
            ok(f"Nuclei DAST: {len(findings):,} findings — "
               f"{', '.join(f'{k}={v}' for k, v in sev_counts.items() if v)}")
        elif res["tool_failed"]:
            warn(f"Nuclei DAST failed — {res['tool_error']}")
        else:
            ok("Nuclei DAST complete — no findings")
        return res

    def stage7_nuclei(self):
        stage(7, "Template Vulnerability Scan")
        d = self.out / "07_nuclei"
        d.mkdir(parents=True, exist_ok=True)
        tgt_file = d / "nuclei_targets.txt"
        # v9.0: the target list is every live URL we proved exists, not just
        # the alive host roots — see _build_nuclei_targets() for why.
        tstats = self._build_nuclei_targets(tgt_file)
        if not tgt_file.exists() or tgt_file.stat().st_size == 0:
            warn("No live URLs or alive hosts — skipping nuclei")
            self.summary["stage7"] = {"status": "skipped", "reason": "no_alive",
                                      "targets": tstats}
            return
        ok(f"Nuclei target list: {tstats['total']:,} URLs "
           f"({tstats['hosts']:,} host roots, {tstats['param_urls']:,} parameterised, "
           f"{tstats['path_urls']:,} path-only)")
        if tstats["shape_deduped"]:
            sub(f"{tstats['shape_deduped']:,} URLs collapsed as duplicate shapes "
                f"(?id=1 / ?id=2, /post/1 / /post/2 test the same surface)")
        if tstats["capped"]:
            warn(f"{tstats['capped']:,} path-only URLs dropped by the "
                 f"tools.nuclei_max_targets={tstats['cap']:,} cap — raise it for deeper coverage")
        if not tool_exists("nuclei"):
            warn("nuclei not installed — skipping scan")
            self.summary["stage7"] = {"status": "skipped", "reason": "not_installed",
                                      "targets": tstats}
            return

        # Injection fuzzing before the CVE sweep. That sweep is hundreds of
        # thousands of requests; stopping it used to skip DAST, so a custom
        # vulnerable app was reported clean.
        dast = {"findings": 0, "severity_counts": {}}
        if not _INT.hard():
            try:
                dast = self._run_nuclei_dast(d)
            except Exception as e:  # noqa: BLE001
                err(f"Nuclei DAST pass crashed: {e}")
                self.log.exception("nuclei dast fatal")
        else:
            dast["interrupted"] = True

        # v6.13: teknoloji-bazli hizli on-tarama. Tespit edilen teknolojilere
        # (wordpress, php, jenkins, vb.) ozel nuclei taglariyla kucuk ama
        # isabetli bir on-gecis yapar; boylece ilk anlamli bulgular cok daha
        # erken gorunur. Ardindan mevcut tam-kapsamli (severity filtreli)
        # genel tarama calisir.
        # v6.15: stage7 artik sirali akista stage11'den ONCE calisiyor; tech_summary
        # henuz doldurulmamissa burada sessizce (banner basmadan) hesaplanir.
        fastpass_enabled = bool(_cfg_get(self.cfg, "tools", "nuclei_tech_fastpass", default=True)) and not _INT.hard()
        if fastpass_enabled and not self.tech_summary:
            self._compute_tech_summary()
        tech_tags = self._nuclei_tech_tags() if fastpass_enabled else ""
        fastpass_run = None
        if tech_tags:
            info(f"Technology-based fast pre-scan: tags={tech_tags}")
            fastpass_run = self._run_nuclei_once(tgt_file, d, "fastpass", extra_tags=tech_tags)
            if fastpass_run["findings"]:
                ok(f"Fast pre-scan found {fastpass_run['findings']:,} findings "
                   f"({', '.join(f'{k}={v}' for k,v in fastpass_run['severity_counts'].items() if v)})")
            else:
                ok("Fast pre-scan complete — no findings")

        if _INT.hard():
            run = {"findings": 0, "severity_counts": {}, "interrupted": True,
                   "tool_failed": False, "tool_error": dast.get("tool_error", ""),
                   "duration_sec": 0.0, "file_txt": "", "file_json": "",
                   "template_path": self._get_nuclei_template_path() or "",
                   "threads": 0, "rate": 0, "severity_filter": "",
                   "targets_count": 0, "stalled": False}
        else:
            run = self._run_nuclei_once(tgt_file, d, "scan")

        # Fastpass + tam tarama bulgularini birlestir (dedup)
        if fastpass_run and fastpass_run.get("findings"):
            all_found = {}
            for src_path in [fastpass_run.get("file_json"), run.get("file_json")]:
                if not src_path or not Path(src_path).exists():
                    continue
                for line in Path(src_path).read_text(errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    key = (rec.get("template-id", ""),
                           rec.get("matched-at") or rec.get("host") or "",
                           rec.get("type", ""))
                    all_found[key] = rec
            if all_found:
                # v6.13: report_builder.py hep kanonik "nuclei_scan.json" dosyasini
                # arar. Ayri bir "nuclei_combined.json" yazmak yerine, birlestirilmis
                # sonucu dogrudan run("scan")'in kendi json/txt dosyalarinin uzerine
                # yaziyoruz — boylece iki arac arasinda dosya adi uyusmazligi olmaz.
                canonical_json = Path(run["file_json"]) if run.get("file_json") else (d / "nuclei_scan.json")
                canonical_txt  = Path(run["file_txt"])  if run.get("file_txt")  else (d / "nuclei_scan.txt")
                with canonical_json.open("w", encoding="utf-8") as fh:
                    for rec in all_found.values():
                        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                sev_counts = {}
                for rec in all_found.values():
                    sev = (rec.get("info", {}) or {}).get("severity", "info") or "info"
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                # okunabilir txt raporunu da birlesmis sonuca gore yeniden uret
                try:
                    with canonical_txt.open("w", encoding="utf-8") as fo:
                        for rec in all_found.values():
                            info_ = rec.get("info", {}) or {}
                            fo.write(f"[{info_.get('severity','?')}] {info_.get('name','')} "
                                     f"({rec.get('template-id','')}) @ {rec.get('matched-at','')}\n")
                except Exception:
                    pass
                run["findings"] = len(all_found)
                run["severity_counts"] = sev_counts
                run["file_json"] = str(canonical_json)
                run["file_txt"] = str(canonical_txt)

        self.nuclei_dast_results = dast

        tool_failed = bool(run.get("tool_failed")) or bool(fastpass_run and fastpass_run.get("tool_failed"))
        tool_error = run.get("tool_error") or (fastpass_run.get("tool_error") if fastpass_run else "") or ""
        interrupted = bool(run.get("interrupted")) or bool(fastpass_run and fastpass_run.get("interrupted"))
        total_duration = round(run.get("duration_sec", 0.0) + (fastpass_run.get("duration_sec", 0.0) if fastpass_run else 0.0)
                               + dast.get("duration_sec", 0.0), 1)
        combined_findings = run["findings"] + dast.get("findings", 0)
        combined_sev = dict(run["severity_counts"])
        for k, v in dast.get("severity_counts", {}).items():
            combined_sev[k] = combined_sev.get(k, 0) + v
        stage_status = "tool_error" if tool_failed else "done"
        if interrupted or _INT.hard() or dast.get("interrupted"):
            stage_status = "partial"
        self.summary["stage7"] = {
            "status": stage_status,
            "findings": combined_findings,
            "findings_template": run["findings"],
            "findings_dast": dast.get("findings", 0),
            "severity_counts": combined_sev,
            "template_path": run["template_path"],
            "threads": run["threads"],
            "rate": run["rate"],
            "file_txt": run["file_txt"],
            "file_json": run["file_json"],
            "dast_file_json": dast.get("file_json", ""),
            "dast_file_txt": dast.get("file_txt", ""),
            "dast_targets_count": dast.get("targets_count", 0),
            "tech_fastpass_tags": tech_tags,
            "targets": tstats,
            "tool_failed": tool_failed,
            "tool_error": tool_error,
            "interrupted": interrupted,
            "stalled": bool(run.get("stalled")) or bool(fastpass_run and fastpass_run.get("stalled")),
            "duration_sec": total_duration,
            "severity_filter": run.get("severity_filter", "none"),
            "targets_count": run.get("targets_count", 0),
        }
        run = dict(run)
        run["findings"] = combined_findings
        run["severity_counts"] = combined_sev
        run["findings_dast"] = dast.get("findings", 0)
        self.nuclei_results = run
        if tool_failed:
            err(f"Nuclei FAILED — {tool_error} "
                f"('0 findings' here does NOT necessarily mean 'clean')")
        elif interrupted:
            warn(f"Nuclei stopped early ({total_duration}s) — findings may be INCOMPLETE, "
                 f"not every target was necessarily scanned")
        elif run["findings"]:
            ok(f"Nuclei found {run['findings']:,} findings — "
               f"{', '.join(f'{k}={v}' for k,v in run['severity_counts'].items() if v)}")
        else:
            ok("Nuclei completed — no findings")

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 9 — Param/Endpoint Discovery (arjun)
    # ══════════════════════════════════════════════════════════════════════════
    def stage9_params(self):
        stage(9, "Parameter Discovery")
        d = self.out / "09_params"
        all_params = []
        seen = set()

        if tool_exists("arjun"):
            alive_file = self._cp("stage3_alive")
            hosts = []
            if alive_file.exists() and alive_file.stat().st_size > 0:
                hosts = [l.strip() for l in alive_file.read_text(errors="ignore").splitlines()
                         if l.strip()]
            if not hosts:
                hosts = [f"https://{self.target}"]
            arjun_out = d / "arjun.json"
            arjun_res = []
            max_hosts = int(_cfg_get(self.cfg, "tools", "arjun_max_hosts", default=10))
            ph_conf = int(_cfg_get(self.cfg, "tools", "arjun_timeout_per_host", default=180))
            per_host_t = min(max(30, ph_conf), T["arjun"])
            batch = hosts[:max_hosts]
            info(f"arjun: probing the first {len(batch)} alive hosts "
                 f"({per_host_t}s/host)")
            for i, h in enumerate(batch, 1):
                if _INT.stage_skip():
                    break
                host_name = urlparse(h).hostname or "unknown"
                run_cmd(f"arjun -u {h} -oJ {arjun_out}",
                        timeout=per_host_t, log=self.log,
                        label=f"arjun-{host_name}", retries=0,
                        job={"index": i, "total": len(batch), "unit": "hosts",
                             "item": host_name})
                if arjun_out.exists() and arjun_out.stat().st_size > 0:
                    try:
                        rec = json.loads(arjun_out.read_text(errors="replace"))
                    except Exception:
                        rec = None
                    if isinstance(rec, dict):
                        for base, params in rec.items():
                            if not isinstance(params, list) or not params:
                                continue
                            urls = []
                            for prm in params[:50]:
                                sep = "?" if "?" not in base else "&"
                                urls.append(f"{base}{sep}{prm}=1")
                            arjun_res.extend(urls)
                    try:
                        arjun_out.unlink()
                    except Exception:
                        pass
            if arjun_res:
                write_lines(d / "arjun.txt", arjun_res)
                ok(f"arjun: {len(arjun_res):,} parameterised URLs")
                for u in arjun_res:
                    if self._is_in_scope_url(u) and u not in seen:
                        seen.add(u)
                        all_params.append(u)
        else:
            sub("arjun not found — skipping")

        if not all_params:
            sub("Param discovery produced no results (no new URLs found)")
            self.summary["stage9"] = {"status": "done", "count": 0}
            return

        n = checkpoint(self._cp("stage9_params"), all_params, "params-new")
        write_lines(d / "all.txt", all_params)
        self.summary["stage9"] = {"status": "done", "count": n}
        ok(f"Param discovery complete — {n:,} new parameterised URLs")

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 10 — JS endpoint / secret analizi
    # ══════════════════════════════════════════════════════════════════════════
    _JS_ENDPOINT_RE = re.compile(
        r"""['"`](\/[a-zA-Z0-9_\-\/\.]{3,}?)(?:\?|['"`])""")
    _JS_SECRET_RE = re.compile(
        r"""(?i)(?:['"]?(api[_-]?key|secret|token|password|authorization|username)['"]?\s*[:=]\s*['"])([^'"]{4,})(?:['"])""")
    # Path tokens that usually belong to first-party code (secrets, API routes).
    _JS_PRIORITY_HIGH_RE = re.compile(
        r"(?:^|[^\w])("
        r"config|settings|env|secret|credential|apikey|api[_-]?key|"
        r"auth|login|session|oauth|sso|"
        r"admin|dashboard|internal|"
        r"main|app|bundle|chunk|runtime|webpack|index|"
        r"api|graphql|client"
        r")(?:[^\w]|$)",
        re.I,
    )
    # Webpack / Vite / Next content-hashed bundles (main.a1b2c3d4.js).
    _JS_PRIORITY_BUNDLE_RE = re.compile(
        r"(?:^|[/_-])(?:main|app|index|runtime|chunk|page|pages|framework)"
        r"[.-][a-f0-9]{6,}(?:\.chunk)?\.js(?:$|\?)",
        re.I,
    )
    _JS_PRIORITY_DIR_RE = re.compile(
        r"/(?:_next/static|static/js|assets(?:/js)?|build/static|dist(?:/js)?)/",
        re.I,
    )
    # Third-party libraries and analytics. These dominate a raw URL list and
    # almost never contain the target's own keys.
    _JS_PRIORITY_LOW_RE = re.compile(
        r"(?:^|[^\w])("
        r"jquery|react(?:-dom)?|vue|angular|lodash|moment|bootstrap|popper|"
        r"font-?awesome|core-js|regenerator-runtime|polyfill|"
        r"gtag|google-analytics|googletagmanager|gtm|"
        r"hotjar|mixpanel|fbevents|recaptcha|hcaptcha|"
        r"sentry|newrelic|datadog|intercom|crisp|zendesk|"
        r"cookieconsent|onetrust|clarity|mathjax|highlight\.js|"
        r"chart\.js|chartjs|d3|three|swiper|slick"
        r")(?:[^\w]|$)",
        re.I,
    )
    _JS_PRIORITY_CDN_RE = re.compile(
        r"(?:^|\.)("
        r"cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|"
        r"ajax\.googleapis\.com|fonts\.googleapis\.com|www\.google-analytics\.com|"
        r"www\.googletagmanager\.com|stackpath\.bootstrapcdn\.com|"
        r"maxcdn\.bootstrapcdn\.com|code\.jquery\.com"
        r")$",
        re.I,
    )

    def _js_url_priority(self, url: str) -> int:
        """Higher score = scan sooner. Used so the file cap and time budget
        spend themselves on app code instead of the first URLs discovered."""
        try:
            parsed = urlparse(url)
        except Exception:
            return 0
        path = parsed.path or ""
        host = (parsed.hostname or "").lower()
        score = 0
        if self._JS_PRIORITY_HIGH_RE.search(path):
            score += 50
        if self._JS_PRIORITY_BUNDLE_RE.search(path):
            score += 30
        if self._JS_PRIORITY_DIR_RE.search(path):
            score += 20
        low_path = path.lower()
        if "node_modules" in low_path or "/vendor/" in low_path or "/vendors/" in low_path:
            score -= 40
        if self._JS_PRIORITY_LOW_RE.search(path):
            score -= 80
        if host and self._JS_PRIORITY_CDN_RE.search(host):
            score -= 60
        return score

    def _prioritize_js_urls(self, urls: list) -> list:
        ranked = sorted(
            enumerate(urls),
            key=lambda iv: (-self._js_url_priority(iv[1]), iv[0]),
        )
        return [u for _, u in ranked]

    def _scan_js_url(self, js_url: str, scanned: set, details: list) -> None:
        if not js_url or not js_url.startswith(("http://", "https://")):
            return
        if js_url in scanned:
            return
        scanned.add(js_url)
        if not self._is_in_scope_url(js_url):
            return
        body = ""
        try:
            client, is_cffi = _get_http_client(self.cfg)
            if client is None:
                return
            host = urlparse(js_url).hostname or self.target
            req_timeout = int(_cfg_get(self.cfg, "tools", "js_secrets_request_timeout", default=10))
            kw = dict(timeout=req_timeout, allow_redirects=True,
                      headers=self._auth_headers_for_url(js_url, pick_header_strategy(host, self.cfg)))
            kw["verify"] = False
            proxy = _resolve_proxy(self.cfg)
            if proxy:
                kw["proxies"] = {"http": proxy, "https": proxy}
            if is_cffi:
                kw["impersonate"] = _cfg_get(self.cfg, "settings", "curl_cffi_impersonate", default="chrome110")
            r = client.get(js_url, **kw)
            body = (getattr(r, "text", "") or "")[:2_000_000]
        except Exception:
            return
        if not body:
            return

        for m in self._JS_ENDPOINT_RE.finditer(body):
            ep = m.group(1)
            if not ep.startswith("/"):
                continue
            if ".." in ep or ep.startswith("//"):
                continue
            details.append({
                "source_js": js_url,
                "type": "endpoint",
                "value": ep,
                "context": body[max(0, m.start()-40):m.end()+40],
            })
        for m in self._JS_SECRET_RE.finditer(body):
            if not m.group(2):
                continue
            details.append({
                "source_js": js_url,
                "type": "secret",
                "value": m.group(2),
                "context": body[max(0, m.start()-40):m.end()+40],
            })
        # v8.3-fix: _JS_SECRET_RE above only catches secrets that happen to
        # sit right next to a generic label like "token:"/"secret:"/"api_key:"
        # — it does nothing for an actual AWS/GCP/GitHub/Slack/Stripe/JWT
        # value stored under an unrelated-looking variable name (e.g.
        # `awsAccessKeyId: "AKIA..."` — "AccessKeyId" isn't one of the six
        # generic labels, so that key was silently never flagged), and it
        # completely misses minified bundles where everything is named `a`,
        # `_0x1`, etc. — arguably the MORE common real-world case. The
        # format-specific regexes in module-level _SECRET_PATTERNS (added
        # earlier, matching exactly what config.yaml's tools.js_secrets_
        # patterns documents: aws/gcp/github/slack/stripe/jwt/private_key)
        # were defined but never actually wired into any scan — dead code.
        # Verified against a real fake-but-format-valid JS bundle: with only
        # _JS_SECRET_RE running, an embedded AWS key/Stripe key/JWT (each
        # under a plausible but non-generic variable name) were missed
        # entirely; adding this loop catches all of them. private_key is
        # skipped here since the dedicated loop below already extracts the
        # full PEM block (BEGIN...END), which is more useful than just the
        # BEGIN line this pattern alone would capture.
        for _sec_name, _sec_pat in _SECRET_PATTERNS.items():
            if _sec_name == "private_key":
                continue
            for m in _sec_pat.finditer(body):
                details.append({
                    "source_js": js_url,
                    "type": "secret",
                    "value": m.group(0)[:300],
                    "context": body[max(0, m.start()-40):m.end()+40],
                })
        for m in _TECH_PRIVATE_KEY_RE.finditer(body):
            end = body.find("-----END", m.start())
            val = body[m.start():end+10] if end != -1 else body[m.start():m.start()+80]
            details.append({
                "source_js": js_url,
                "type": "secret",
                "value": val,
                "context": body[max(0, m.start()-20):m.end()+20],
            })

    def stage10_js(self):
        stage(10, "JS Endpoint / Secret Analysis")
        d = self.out / "10_js_secrets"
        seen_js = set()
        details = []

        js_sources = [
            self._cp("stage4_urls"),
            self.out / "04_urls" / "all_urls_raw.txt",
            self.out / "04_urls" / "katana.txt",
            self._cp("stage9_params"),
            self.out / "09_params" / "all.txt",
        ]
        js_urls = []
        for src in js_sources:
            if not src or not src.exists():
                continue
            for ln in src.read_text(errors="replace").splitlines():
                ln = strip_ansi(ln.strip())
                if not ln:
                    continue
                path = urlparse(ln).path if ln.startswith("http") else ""
                if path.lower().endswith(".js"):
                    if ln not in seen_js and self._is_in_scope_url(ln):
                        seen_js.add(ln)
                        js_urls.append(ln)

        info(f"{len(js_urls):,} JS files found")
        if not js_urls:
            sub("No JS files found")
            self.js_results = {"details": [], "endpoints": 0, "secrets": 0, "files": []}
            self.summary["stage10"] = {"status": "done", "endpoints": 0, "secrets": 0}
            return

        # This stage runs from the Scan Center, after the report, so it can
        # read every in-scope script. 0 in config means "no cap". A positive
        # js_secrets_max_files / js_secrets_budget_sec restores a limit, and
        # that limit is spent in priority order: app bundles, config, auth
        # and API clients before libraries and CDN scripts.
        max_files   = int(_cfg_get(self.cfg, "tools", "js_secrets_max_files", default=0) or 0)
        concurrency = max(1, int(_cfg_get(self.cfg, "tools", "js_secrets_concurrency", default=12) or 12))
        budget_sec  = int(_cfg_get(self.cfg, "tools", "js_secrets_budget_sec", default=0) or 0)
        ranked_js = self._prioritize_js_urls(js_urls)
        if max_files > 0 and len(ranked_js) > max_files:
            truncated = True
            js_urls_scan = ranked_js[:max_files]
            sub(f"JS file count ({len(js_urls):,}) hit the cap ({max_files}) — "
                f"analysing the {max_files} highest-priority files "
                f"(app bundles, config/auth/api first; libraries and CDN last)")
        else:
            truncated = False
            js_urls_scan = ranked_js
            sub(f"Deep JS pass: all {len(js_urls_scan):,} in-scope scripts, no file cap")

        # ── TruffleHog — same file set as the regex pass, downloaded in parallel
        th_cap = len(js_urls_scan)
        if tool_exists("trufflehog") and th_cap:
            js_dir = d / "js_downloads"
            js_dir.mkdir(parents=True, exist_ok=True)
            saved = [0]

            def _dl_for_trufflehog(js_url):
                try:
                    client, is_cffi = _get_http_client(self.cfg)
                    if client is None:
                        return
                    host = urlparse(js_url).hostname or self.target
                    kw = dict(timeout=10, headers=self._auth_headers_for_url(
                        js_url, pick_header_strategy(host, self.cfg)))
                    kw["verify"] = False
                    proxy = _resolve_proxy(self.cfg)
                    if proxy:
                        kw["proxies"] = {"http": proxy, "https": proxy}
                    if is_cffi:
                        kw["impersonate"] = _cfg_get(self.cfg, "settings", "curl_cffi_impersonate", default="chrome110")
                    r = client.get(js_url, **kw)
                    content = getattr(r, "content", b"")
                    if content and getattr(r, "status_code", 0) == 200:
                        fn = js_dir / (re.sub(r"[^A-Za-z0-9_.-]", "_", js_url)[:120] + ".js")
                        fn.write_bytes(content)
                        saved[0] += 1
                except Exception:
                    pass

            dl_t0 = time.time()
            dl_list = js_urls_scan[:th_cap]
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                dl_futs = {ex.submit(_dl_for_trufflehog, u): u for u in dl_list}
                for n, fut in enumerate(as_completed(dl_futs), 1):
                    fut.result()
                    _pulse_job("js download", dl_t0, n, len(dl_list),
                               unit="files", item=dl_futs[fut])

            if saved[0]:
                th_out = d / "trufflehog.txt"
                th_timeout = max(900, min(7200, 12 * saved[0]))
                run_cmd(f"trufflehog filesystem {js_dir} --json",
                        out_file=th_out, timeout=th_timeout, log=self.log,
                        label="trufflehog", retries=0)
                if th_out.exists():
                    for ln in th_out.read_text(errors="replace").splitlines():
                        ln = strip_ansi(ln.strip())
                        if not ln:
                            continue
                        try:
                            rec = json.loads(ln)
                        except Exception:
                            continue
                        if isinstance(rec, dict):
                            raw = rec.get("Raw") or rec.get("raw") or ""
                            secret_t = rec.get("DetectorName") or rec.get("SourceMetadata") or ""
                            details.append({
                                "source_js": js_dir.name,
                                "type": "secret",
                                "value": str(raw)[:300],
                                "context": f"trufflehog:{secret_t}",
                            })
                sub(f"trufflehog: {saved[0]} JS files scanned")
            else:
                sub("trufflehog: JS indirilemedi")
        else:
            sub("trufflehog not found — skipping")

        # ── Python regex analizi — paralel + zaman butceli + canli ilerleme ─────
        scanned_js = set()
        start_t = time.time()
        completed = [0]
        budget_hit = [False]
        results_lock = threading.Lock()

        def _worker(js_url):
            if _INT.hard() or budget_hit[0]:
                return
            local = []
            self._scan_js_url(js_url, scanned_js, local)
            with results_lock:
                details.extend(local)
                completed[0] += 1

        budget_note = f"{budget_sec}s budget" if budget_sec > 0 else "no time cap"
        info(f"JS analysis starting: {len(js_urls_scan):,} files, "
             f"{concurrency} in parallel, {budget_note}")
        ex = ThreadPoolExecutor(max_workers=concurrency)
        try:
            futures = {ex.submit(_worker, u): u for u in js_urls_scan}
            for fut in as_completed(futures):
                now = time.time()
                if _INT.stage_skip():
                    budget_hit[0] = True
                    break
                if budget_sec > 0 and now - start_t > budget_sec:
                    if not budget_hit[0]:
                        warn(f"JS analiz zaman butcesi ({budget_sec}s) asildi — kalan "
                             f"{len(js_urls_scan) - completed[0]:,} dosya atlaniyor "
                             f"(config: js_secrets_budget_sec ile arttirilabilir)")
                    budget_hit[0] = True
                    break
                _pulse_job("js", start_t, completed[0], len(js_urls_scan),
                           unit="files", item=futures.get(fut) or "")
            _pulse_job("js", start_t, completed[0], len(js_urls_scan),
                       unit="files", force=True)
        finally:
            # v6.15: wait=False + cancel_futures — henuz baslamamis istekleri
            # iptal eder ve fonksiyon HEMEN doner; halihazirda calisan birkac
            # thread kendi timeout'unda (en fazla ~request_timeout saniye)
            # arka planda sessizce biter, sonraki stage'i bloklamaz.
            ex.shutdown(wait=False, cancel_futures=True)
        _INT.reset_op()

        # v8.3-fix: with the format-specific _SECRET_PATTERNS loop added above
        # (alongside the pre-existing generic keyword regex), the exact same
        # secret string can now legitimately be matched twice by two
        # different detectors (e.g. a GitHub token under a key literally
        # named "githubToken" hits both the generic "token:" pattern and the
        # ghp_-specific one) — dedupe the full detail records here so
        # secrets.json / the report don't show the identical (file, value)
        # pair twice. endpoints/secrets.txt were already deduped by value
        # alone via dict.fromkeys below; this just extends the same idea to
        # the full JSON detail list.
        seen_detail = set()
        deduped_details = []
        for x in details:
            key = (x.get("source_js", ""), x.get("type", ""), x.get("value", ""))
            if key in seen_detail:
                continue
            seen_detail.add(key)
            deduped_details.append(x)
        details = deduped_details

        # ── triage ───────────────────────────────────────────────────────────
        # The regexes above answer "does this look like a key?", which on a real
        # site is mostly noise: a Stripe PUBLISHABLE key, a Google Maps browser
        # key and a reCAPTCHA site key all belong in client-side JS. Listing
        # those next to a genuinely leaked AWS key teaches the operator to skip
        # the section. reconx_secrets classifies each candidate as
        # REAL / PUBLIC / FALSE / UNKNOWN so the report can lead with the ones
        # that matter and still show the rest.
        verdicts = {}
        if _secret_triage is not None:
            try:
                verdicts = _secret_triage.summarise(details)
            except Exception as _e:
                warn(f"Secret triage failed ({_e}) — showing the raw candidate list")
                verdicts = {}

        endpoints = list(dict.fromkeys(
            [x["value"] for x in details if x["type"] == "endpoint"]))
        secrets = list(dict.fromkeys(
            [x["value"] for x in details if x["type"] == "secret"]))
        real_secrets = list(dict.fromkeys(
            [x["value"] for x in details
             if x["type"] == "secret" and x.get("verdict") == "REAL"]))

        write_lines(d / "endpoints.txt", endpoints)
        write_lines(d / "secrets.txt", secrets)
        if real_secrets:
            write_lines(d / "secrets_real.txt", real_secrets)
        (d / "secrets.json").write_text(
            json.dumps(details, indent=2, ensure_ascii=False), encoding="utf-8")

        self.js_results = {
            "details": details,
            "endpoints": len(endpoints),
            "secrets": len(secrets),
            "secrets_real": len(real_secrets),
            "verdicts": verdicts,
            "files": js_urls,
            "files_scanned": completed[0],
            "truncated": truncated or budget_hit[0],
        }
        self.summary["stage10"] = {
            "status": "done",
            "endpoints": len(endpoints),
            "secrets": len(secrets),
            "secrets_real": len(real_secrets),
            "secret_verdicts": verdicts,
            "js_files": len(js_urls),
            "js_files_scanned": completed[0],
            "truncated": truncated or budget_hit[0],
        }
        elapsed = round(time.time() - start_t, 1)
        ok(f"JS analysis complete ({elapsed}s, {completed[0]:,}/{len(js_urls_scan):,} files) — "
           f"{len(endpoints):,} endpoints, {len(secrets):,} secret candidates")
        if verdicts:
            _r, _u = verdicts.get("REAL", 0), verdicts.get("UNKNOWN", 0)
            _p, _f = verdicts.get("PUBLIC", 0), verdicts.get("FALSE", 0)
            if _r:
                err(f"  {_r} look like REAL credentials → {d / 'secrets_real.txt'}")
                for _x in details:
                    if _x.get("verdict") == "REAL":
                        sub(f"{C.RED}{_x.get('verdict_reason','')}{C.RESET}: "
                            f"{str(_x.get('value',''))[:60]}  {C.DIM}({_x.get('source_js','')[:70]}){C.RESET}")
            sub(f"Triage: {_r} real · {_u} unclassified · {_p} public-by-design · "
                f"{_f} not a credential")

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 11 — Teknoloji bazli onceliklendirme
    # ══════════════════════════════════════════════════════════════════════════
    def _normalize_tech(self, t: str) -> str:
        t = (t or "").lower().strip()
        if ":" in t:
            t = t.split(":", 1)[0]
        return t.strip()

    def _risk_for_tech(self, tech: str):
        for pat, score, desc in _TECH_RISK:
            if re.search(pat, tech):
                return score, desc
        return 0, ""

    def _compute_tech_summary(self) -> list:
        """httpx/whatweb ciktilarindan teknoloji risk siralamasini hesaplar ve
        self.tech_summary'yi doldurur. v6.15: stage7 (nuclei tech-fastpass)
        artik sirali akista stage11'den ONCE calisiyor; bu yuzden hesaplama
        buraya cikarildi ki stage7 gerektiginde sessizce (banner basmadan)
        cagirabilsin. stage11_tech_priority bu fonksiyonu kullanip ustune
        dosya yazma + konsol ciktisini ekliyor."""
        host_techs = {}

        hx = self.out / "03_alive" / "httpx_full.json"
        if hx.exists() and hx.stat().st_size > 0:
            with hx.open("r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    url = rec.get("url") or ""
                    if not url.startswith("http"):
                        continue
                    status = int(rec.get("status-code") or rec.get("status_code") or 0)
                    techs = rec.get("tech") or rec.get("technologies") or \
                            rec.get("detected-technologies") or []
                    host_techs.setdefault(url, {"status": status, "techs": set()})
                    for t in techs:
                        host_techs[url]["techs"].add(self._normalize_tech(str(t)))

        current_url = ""
        for name in ("whatweb.txt", "whatweb_hosts.txt"):
            ww = self.out / "01_recon" / name
            if not ww.exists() or ww.stat().st_size == 0:
                continue
            for ln in ww.read_text(errors="replace").splitlines():
                ln = strip_ansi(ln.strip())
                if not ln:
                    continue
                m = re.search(r"(https?://[^\s]+)", ln)
                if m:
                    url = m.group(1).rstrip(",").rstrip("]")
                    # Plugin blurbs cite their own homepages
                    # ("Website: https://www.php.net/"). Those are not the target.
                    if self._is_in_scope_url(url):
                        current_url = url
                if not current_url:
                    continue
                blob = ""
                low = ln.lower()
                if low.startswith("summary"):
                    blob = ln.split(":", 1)[-1]
                elif ln.startswith("http"):
                    blob = re.sub(r"^https?://\S+\s*", "", ln)
                    blob = re.sub(r"^\[\d{3}[^\]]*\]\s*", "", blob)
                if not blob:
                    continue
                host_techs.setdefault(current_url, {"status": 0, "techs": set()})
                for label in _techs_from_whatweb_blob(blob):
                    host_techs[current_url]["techs"].add(self._normalize_tech(label))

        merged = {}
        for url, info_ in host_techs.items():
            key = _canon_url(url)
            slot = merged.get(key)
            if slot is None:
                merged[key] = {"url": url, "status": info_["status"], "techs": set(info_["techs"])}
                continue
            slot["techs"].update(info_["techs"])
            if info_["status"] and not slot["status"]:
                slot["status"] = info_["status"]
                slot["url"] = url
        ranked = []
        for info_ in merged.values():
            url = info_["url"]
            techs = sorted(t for t in info_["techs"] if t)
            score = 0
            top = []
            for t in techs:
                s, desc = self._risk_for_tech(t)
                if s:
                    score += s
                    top.append({"tech": t, "score": s, "desc": desc})
            top.sort(key=lambda x: x["score"], reverse=True)
            label = "high" if score >= 60 else ("medium" if score >= 25 else "low")
            ranked.append({
                "url": url,
                "status": info_["status"],
                "techs": techs,
                "score": score,
                "risk_label": label,
                "top_techs": top[:6],
                "findings": [t["desc"] for t in top if t["score"] >= 25][:5],
            })
        ranked.sort(key=lambda x: x["score"], reverse=True)
        self.tech_summary = ranked
        return ranked

    def stage11_tech_priority(self):
        stage(11, "Tech-Based Prioritisation")
        d = self.out / "11_tech"
        ranked = self._compute_tech_summary()

        (d / "tech_priority.json").write_text(
            json.dumps(ranked, indent=2, ensure_ascii=False), encoding="utf-8")
        with (d / "tech.csv").open("w", encoding="utf-8", newline="") as fo:
            writer = csv.writer(fo)
            writer.writerow(["url", "status", "score", "risk_label", "techs"])
            for r in ranked:
                writer.writerow([r["url"], r["status"], r["score"],
                                 r["risk_label"], ";".join(r["techs"])])

        high = sum(1 for r in ranked if r["risk_label"] == "high")
        medium = sum(1 for r in ranked if r["risk_label"] == "medium")
        self.summary["stage11"] = {
            "status": "done",
            "ranked": len(ranked),
            "high": high,
            "medium": medium,
        }
        if not ranked:
            sub("No technology information available (httpx/whatweb missing)")
            return
        noun = "host" if len(ranked) == 1 else "hosts"
        ok(f"Tech prioritisation: {len(ranked):,} {noun} — {high} high, {medium} medium")
        for r in ranked[:5]:
            sub(f"{r['risk_label'].upper():6} score={r['score']:3}  {r['url']}")

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 12 — v6.13: Ekstra Guvenlik Kontrolleri (CORS / Takeover / Bucket)
    # ══════════════════════════════════════════════════════════════════════════
    def _check_on(self, name: str) -> bool:
        """stage12 passive-check gate: True when the report/CLI asked for this
        check (or asked for none, meaning run them all)."""
        return (not self.only_checks) or (name in self.only_checks)

    def stage12_extra_checks(self):
        _sel = ("/".join(sorted(self.only_checks)) if self.only_checks
                else "CORS / Takeover / Cloud Bucket")
        stage(12, f"Extra Security Checks ({_sel})")
        d = self.out / "12_extra"
        results = {"cors": [], "takeover": [], "buckets": []}

        # ── CORS misconfig — alive hostlarin ana sayfalarinda test ─────────────
        alive_file = self._cp("stage3_alive")
        alive_urls = []
        if self._check_on("cors") and alive_file.exists() and alive_file.stat().st_size > 0:
            alive_urls = [l.strip() for l in alive_file.read_text(errors="ignore").splitlines() if l.strip()]
        cors_probed = 0
        if alive_urls:
            info(f"CORS testi: {len(alive_urls):,} alive host")
            jitter = float(_cfg_get(self.cfg, "settings", "jitter_max", default=0.6) or 0)
            cors_t0 = time.time()
            for i, u in enumerate(alive_urls, 1):
                _pulse_job("cors", cors_t0, i, len(alive_urls), unit="hosts", item=u)
                if _INT.stage_skip():
                    break
                if i > 1:
                    time.sleep(random.random() * jitter)  # v6.17-fix: hedef/yuk koruma
                r = check_cors_misconfig(u, self.cfg, log=self.log)
                if r.get("checked"):
                    cors_probed += 1
                if r.get("acao") or r.get("vulnerable"):
                    results["cors"].append(r)
            vuln_cors = [r for r in results["cors"] if r.get("vulnerable")]
            if vuln_cors:
                ok(f"CORS: {len(vuln_cors)} possible misconfiguration(s) found")
            else:
                ok("CORS: no misconfiguration found")
        else:
            sub("No alive host to test CORS against — skipped")

        # ── Subdomain takeover — subdomain listesi uzerinde CNAME kontrolu ─────
        subs_file = self._cp("stage2_subdomains")
        subs = []
        if self._check_on("takeover") and subs_file.exists() and subs_file.stat().st_size > 0:
            subs = [l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()]
        takeover_probed = 0
        if subs and tool_exists("dig"):
            info(f"Subdomain takeover check: {len(subs):,} subdomains (CNAME based)")
            jitter2 = float(_cfg_get(self.cfg, "settings", "jitter_max", default=0.6) or 0)
            tko_t0 = time.time()
            for i, s in enumerate(subs, 1):
                _pulse_job("takeover", tko_t0, i, len(subs), unit="hosts", item=s)
                if _INT.stage_skip():
                    break
                if i > 1:
                    time.sleep(random.random() * jitter2)  # v6.17-fix: hedef/yuk koruma
                r = check_subdomain_takeover(s, self.cfg, log=self.log)
                takeover_probed += 1
                if r.get("cname"):
                    results["takeover"].append(r)
            vuln_tko = [r for r in results["takeover"] if r.get("vulnerable")]
            if vuln_tko:
                ok(f"Subdomain takeover: {len(vuln_tko)} potentially takeoverable subdomain(s)!")
            else:
                ok("Subdomain takeover: no risk found")
        else:
            sub("No subdomains / no dig binary for the takeover check — skipped")

        # ── Cloud bucket exposure — kesfedilen URL/subdomain havuzunda ─────────
        candidate_files = [
            self._cp("stage2_subdomains"), self._cp("stage4_urls"),
            self.out / "04_urls" / "all_urls_raw.txt",
            self._cp("stage9_params"), self.out / "09_params" / "all.txt",
        ]
        bucket_meta = {"checked": 0, "public": 0, "protected": 0, "tool": "", "keywords": [], "error": ""}
        if self._check_on("bucket"):
            d.mkdir(parents=True, exist_ok=True)
            keywords = _bucket_keywords(self.target)
            enum = run_cloud_enum(keywords, d, self.cfg)
            seen = set()
            for hit in enum.get("hits") or []:
                url = hit.get("url") or ""
                if not url or url in seen:
                    continue
                seen.add(url)
                verified = check_cloud_bucket(url, hit.get("provider") or "", self.cfg, log=self.log)
                if verified.get("status") in ("", "unknown") or verified.get("detail", "").startswith("request error"):
                    verified = hit
                results["buckets"].append(verified)
            for bucket_url, provider in find_cloud_bucket_candidates(candidate_files):
                if _INT.stage_skip():
                    break
                if bucket_url in seen:
                    continue
                seen.add(bucket_url)
                results["buckets"].append(check_cloud_bucket(bucket_url, provider, self.cfg, log=self.log))
            public_n = sum(1 for r in results["buckets"] if r.get("public_listing"))
            protected_n = sum(1 for r in results["buckets"] if r.get("status") == "exists_protected")
            bucket_meta = {
                "checked": max(len(seen), 1 if enum.get("ran") else 0),
                "public": public_n,
                "protected": protected_n,
                "tool": "cloud_enum" if enum.get("ran") else "",
                "keywords": keywords,
                "error": enum.get("error") or "",
            }
            if enum.get("error") and not enum.get("ran"):
                err(f"Cloud bucket: {enum['error']}")
            elif public_n:
                ok(f"Cloud bucket: {public_n} publicly listable bucket(s), {protected_n} protected")
            elif protected_n:
                ok(f"Cloud bucket: no public listing. {protected_n} name(s) exist but are closed")
            elif enum.get("ran"):
                ok("Cloud bucket: cloud_enum finished — no open or protected bucket for these names")
        else:
            sub("Cloud bucket check not selected — skipped")
        results["bucket_meta"] = bucket_meta

        # v9.4: when the report runs a single passive check on demand (--check),
        # keep the other categories' prior results instead of clobbering them —
        # the three checks are separate report buttons that build up one file.
        if self.only_checks:
            prior = {}
            pf = d / "extra_results.json"
            if pf.exists():
                try:
                    prior = json.loads(pf.read_text(encoding="utf-8", errors="replace")) or {}
                except Exception:
                    prior = {}
            for cat in ("cors", "takeover", "buckets"):
                ran = {"cors": "cors", "takeover": "takeover", "buckets": "bucket"}[cat]
                if not self._check_on(ran) and prior.get(cat):
                    results[cat] = prior[cat]
            if not self._check_on("bucket") and prior.get("bucket_meta"):
                results["bucket_meta"] = prior["bucket_meta"]

        (d / "extra_results.json").write_text(
            json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

        self.extra_results = results
        n_cors_vuln = sum(1 for r in results["cors"] if r.get("vulnerable"))
        n_tko_vuln = sum(1 for r in results["takeover"] if r.get("vulnerable"))
        n_bucket_vuln = sum(1 for r in results["buckets"] if r.get("public_listing"))
        if self.only_checks:
            prev12 = {}
            sf = self.out / "SUMMARY.json"
            if sf.exists():
                try:
                    prev12 = ((json.loads(sf.read_text(encoding="utf-8", errors="replace")) or {})
                              .get("stages") or {}).get("stage12") or {}
                except Exception:
                    prev12 = {}
            if not self._check_on("cors"):
                cors_probed = int(prev12.get("cors_checked") or 0)
            if not self._check_on("takeover"):
                takeover_probed = int(prev12.get("takeover_checked") or 0)
        bucket_checked = int((results.get("bucket_meta") or {}).get("checked") or 0)
        if not bucket_checked:
            bucket_checked = len(results["buckets"])
        if self.only_checks and not self._check_on("bucket"):
            bucket_checked = int(prev12.get("bucket_checked") or bucket_checked)
        self.summary["stage12"] = {
            "status": "done",
            "cors_checked": cors_probed,
            "cors_vulnerable": n_cors_vuln,
            "takeover_checked": takeover_probed,
            "takeover_vulnerable": n_tko_vuln,
            "bucket_checked": bucket_checked,
            "bucket_public": n_bucket_vuln,
        }
        total_vuln = n_cors_vuln + n_tko_vuln + n_bucket_vuln
        if total_vuln:
            warn(f"Extra checks: {total_vuln} possible finding(s) in total (CORS={n_cors_vuln}, "
                 f"Takeover={n_tko_vuln}, Bucket={n_bucket_vuln})")
        else:
            ok("Extra checks complete — no findings")

    # ── Stage 14 — Network / Port Scan (naabu → nmap -sV) ──────────────────────
    @staticmethod
    def _bare_host(line: str) -> str:
        """A URL or host line → bare hostname/IP (no scheme, no port, no path)."""
        s = (line or "").strip()
        if not s:
            return ""
        if "://" not in s:
            s = "//" + s
        h = (urlparse(s).hostname or "").strip().rstrip(".")
        return h.lower()

    def _parse_nmap_xml(self, xmlf: Path, host: str, ports: list) -> dict:
        """nmap -oX output → {host, ports:[{port, proto, state, service,
        product, version}]}. Falls back to the naabu port list on any parse
        error so a host is never dropped just because nmap XML was malformed."""
        entry = {"host": host, "ports": [{"port": p, "proto": "tcp", "state": "open",
                                          "service": "", "product": "", "version": ""}
                                         for p in ports]}
        try:
            import xml.etree.ElementTree as ET
            if not xmlf.exists() or xmlf.stat().st_size == 0:
                return entry
            root = ET.parse(str(xmlf)).getroot()
            found = []
            for h in root.findall("host"):
                for port in h.findall("./ports/port"):
                    svc = port.find("service")
                    state = port.find("state")
                    found.append({
                        "port": int(port.get("portid", 0) or 0),
                        "proto": port.get("protocol", "tcp"),
                        "state": (state.get("state") if state is not None else "open"),
                        "service": (svc.get("name") if svc is not None else "") or "",
                        "product": (svc.get("product") if svc is not None else "") or "",
                        "version": (svc.get("version") if svc is not None else "") or "",
                    })
            if found:
                entry["ports"] = sorted(found, key=lambda x: x["port"])
        except Exception as e:  # noqa: BLE001
            self.log.warning(f"nmap XML parse failed for {host}: {e}")
        return entry

    def stage14_network(self):
        stage(14, "Network / Port Scan")
        d = self.out / "14_network"
        d.mkdir(parents=True, exist_ok=True)

        alive_file = self._cp("stage3_alive")
        hosts, seen = [], set()
        if alive_file.exists() and alive_file.stat().st_size > 0:
            for line in alive_file.read_text(errors="ignore").splitlines():
                h = self._bare_host(line)
                if h and h not in seen:
                    seen.add(h)
                    hosts.append(h)
        if not hosts:
            warn("No alive hosts — skipping network scan")
            self.summary["stage14"] = {"status": "skipped", "reason": "no_alive"}
            return
        max_hosts = int(_cfg_get(self.cfg, "tools", "nmap_max_hosts", default=50) or 50)
        if len(hosts) > max_hosts:
            warn(f"{len(hosts):,} hosts — capping the port scan at {max_hosts} "
                 f"(tools.nmap_max_hosts). Raise it for wider coverage.")
            hosts = hosts[:max_hosts]

        if not tool_exists("naabu"):
            warn("naabu not installed — skipping network scan")
            self.summary["stage14"] = {"status": "skipped", "reason": "naabu_not_installed"}
            return

        # naabu's own resolver rejects some local names ("no valid ipv4")
        # even when /etc/hosts answers them. Scan the addresses we resolved.
        ip_to_names = {}
        scan_targets = []
        for h in hosts:
            ip = self._resolve_ip(h)
            key = ip or h
            ip_to_names.setdefault(key, [])
            if h not in ip_to_names[key]:
                ip_to_names[key].append(h)
            if key not in scan_targets:
                scan_targets.append(key)
        hosts_file = d / "hosts.txt"
        hosts_file.write_text("\n".join(scan_targets) + "\n", encoding="utf-8")
        # Ports the target actually answered on. top-100 does not include
        # 8088, so a lab on that port used to end as "no open ports" after
        # nmap had already printed 8088/tcp open.
        extra_ports = set()
        if self.service_port:
            extra_ports.add(int(self.service_port))
        if alive_file.exists():
            for line in alive_file.read_text(errors="ignore").splitlines():
                try:
                    port = urlparse(line.strip()).port
                except Exception:
                    port = None
                if port:
                    extra_ports.add(int(port))
        top  = int(_cfg_get(self.cfg, "tools", "naabu_top_ports", default=100) or 100)
        rate = int(_cfg_get(self.cfg, "tools", "naabu_rate", default=1000) or 1000)
        naabu_timeout = int(_cfg_get(self.cfg, "tools", "naabu_timeout_sec", default=1800) or 1800)
        naabu_json = d / "naabu.json"
        if naabu_json.exists():
            try: naabu_json.unlink()
            except Exception: pass
        info(f"naabu: {len(scan_targets):,} address(es), top-{top} ports @ {rate}/s"
             + (f", plus explicit port(s) {', '.join(str(p) for p in sorted(extra_ports))}"
                if extra_ports else ""))
        naabu_stats = _stats_cli(_help_text("naabu"), 5)
        # -silent hides the stats line this stage's progress meter reads.
        # -p and -top-ports together make this naabu build abort with
        # "no valid ipv4", so the explicit ports are a second pass.
        naabu_quiet = "" if naabu_stats else "-silent "
        naabu_ok, _ = run_cmd(
            f"naabu -list {hosts_file} -top-ports {top} -rate {rate} {naabu_quiet}"
            f"{naabu_stats}-json -o {naabu_json}",
            timeout=naabu_timeout, log=self.log, label="naabu", stream=True, retries=0)
        if extra_ports:
            extra_json = d / "naabu_explicit.json"
            run_cmd(f"naabu -list {hosts_file} -p {','.join(str(p) for p in sorted(extra_ports))} "
                    f"-rate {rate} -silent -json -o {extra_json}",
                    timeout=naabu_timeout, log=self.log, label="naabu-ports", retries=0)

        def _take_naabu(path: Path, into: dict):
            if not path.exists():
                return
            for line in path.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                port = rec.get("port")
                if not port:
                    continue
                ip = rec.get("ip") or ""
                names = ip_to_names.get(ip) or ip_to_names.get(rec.get("host") or "")
                if not names:
                    names = [rec.get("host") or ip or ""]
                for name in names:
                    if name:
                        into.setdefault(name, set()).add(int(port))

        open_map = {}
        _take_naabu(naabu_json, open_map)
        if extra_ports:
            _take_naabu(d / "naabu_explicit.json", open_map)
        if not open_map and not naabu_ok:
            imported = []
            nmap_txt = self.out / "01_recon" / "nmap.txt"
            if nmap_txt.exists():
                for line in nmap_txt.read_text(errors="ignore").splitlines():
                    m = re.match(r"(\d+)/tcp\s+open\b", line.strip())
                    if m:
                        imported.append(int(m.group(1)))
            if imported:
                warn("naabu failed — keeping the open ports stage 1 already found")
                for h in hosts:
                    open_map[h] = set(imported)
            else:
                warn("naabu failed — this is not a clean 'no open ports' result")
                self.network_results = {"hosts": []}
                self.summary["stage14"] = {"status": "tool_error", "hosts_scanned": len(hosts),
                                           "hosts_with_open": 0, "open_ports_total": 0,
                                           "reason": "naabu_failed"}
                return
        open_map = {h: sorted(ps) for h, ps in open_map.items()}
        seen_ip_port = set()
        for h, ps in open_map.items():
            ip = self._resolve_ip(h) or h
            for p in ps:
                seen_ip_port.add((ip, int(p)))
        total_open = len(seen_ip_port)

        if not open_map:
            ok("naabu completed — no open ports found")
            self.network_results = {"hosts": []}
            self.summary["stage14"] = {"status": "done", "hosts_scanned": len(hosts),
                                       "hosts_with_open": 0, "open_ports_total": 0}
            return
        ok(f"naabu: {total_open:,} open port(s) across {len(open_map):,} host(s)")

        have_nmap = tool_exists("nmap")
        if not have_nmap:
            warn("nmap not installed — reporting open ports without service detection")
        nmap_timeout = int(_cfg_get(self.cfg, "tools", "nmap_timeout_sec", default=1800) or 1800)
        services = []
        open_hosts = list(open_map.items())
        nmap_done = {}
        for i, (h, ports) in enumerate(open_hosts, 1):
            if _INT.stage_skip():
                break
            ip_key = (self._resolve_ip(h) or h, tuple(ports))
            if ip_key in nmap_done:
                copied = dict(nmap_done[ip_key])
                copied["host"] = h
                services.append(copied)
                continue
            if have_nmap:
                xmlf = d / f"nmap_{re.sub(r'[^A-Za-z0-9_.-]+', '_', h)}.xml"
                pcsv = ",".join(str(p) for p in ports)
                info(f"nmap -sV {h} ({len(ports)} port(s))")
                run_cmd(f"nmap -v -sV -Pn -T4 --stats-every 5s -p {pcsv} -oX {xmlf} {h}",
                        timeout=nmap_timeout, log=self.log, label=f"nmap:{h}", stream=True,
                        job={"index": i, "total": len(open_hosts), "unit": "hosts", "item": h})
                entry = self._parse_nmap_xml(xmlf, h, ports)
                nmap_done[ip_key] = entry
                services.append(entry)
            else:
                entry = {"host": h, "ports": [{"port": p, "proto": "tcp",
                         "state": "open", "service": "", "product": "",
                         "version": ""} for p in ports]}
                nmap_done[ip_key] = entry
                services.append(entry)

        (d / "network_results.json").write_text(
            json.dumps({"hosts": services}, indent=2, ensure_ascii=False), encoding="utf-8")
        self.network_results = {"hosts": services}
        self.summary["stage14"] = {
            "status": "done",
            "hosts_scanned": len(hosts),
            "hosts_with_open": len(open_map),
            "open_ports_total": total_open,
            "services": services,
        }
        ok(f"Network scan complete — {total_open:,} open port(s) on {len(open_map):,} host(s)")

    # ── Stage 15 — Open Redirect (OpenRedireX fuzz + canary verification) ───────
    # Parameter names that commonly carry a redirect target.
    _REDIR_PARAMS = {
        "url", "next", "redirect", "redirect_uri", "redirect_url", "redir",
        "redirecturl", "return", "returnurl", "return_url", "returnto",
        "return_to", "dest", "destination", "continue", "continueto", "goto",
        "target", "out", "view", "to", "image_url", "callback", "forward",
        "r", "u", "link", "go", "rurl", "checkout_url", "success_url", "back",
        "backurl", "origin", "path", "file", "page", "domain",
        "returl", "returnuri", "return_uri", "redirect_to", "next_url",
        "continue_url", "redir_url", "location",
    }
    # Host injected during verification. The scanner reads Location and does not
    # follow it. example.com answers, so opening the PoC lands somewhere real.
    # Override with tools.open_redirect_canary in the local config (gitignored).
    _OREDIR_CANARY = "example.com"

    def _canary_host(self) -> str:
        raw = str(_cfg_get(self.cfg, "tools", "open_redirect_canary", default="") or "").strip().lower()
        raw = re.sub(r"^https?://", "", raw).split("/")[0].split(":")[0].strip(".")
        return raw or self._OREDIR_CANARY

    def _oredir_payloads(self, target_host: str) -> list:
        """Canary payloads across the common open-redirect bypass shapes. A hit
        is unambiguous: the target must return a Location whose HOST is our
        canary — a value that only appears because we injected it."""
        c = self._canary_host()
        pays = [
            f"https://{c}", f"https://{c}/", f"http://{c}",
            f"//{c}", f"//{c}/", f"/\\{c}", f"\\/{c}", f"/%2f{c}",
            f"https:/{c}", f"https:\\{c}", f"////{c}",
            f"/%2f%2f{c}", f"/%09/{c}", f"/.{c}", f"https://{c}/%2e%2e",
        ]
        if target_host:
            # @-trick + confusion payloads that keep the real host in front.
            pays += [f"https://{target_host}@{c}", f"//{target_host}@{c}",
                     f"https://{target_host}.{c}"]
        return pays

    def _verify_open_redirect(self, url: str, timeout: int = 12) -> dict:
        """Inject canary payloads into each redirect-like param of `url` and read
        the Location header WITHOUT following it. Returns the first confirmed
        redirect off-domain to the canary host, or {} if none — this is the
        replayable proof a triager needs, not just 'a redirect happened'."""
        client, is_cffi = _get_http_client(self.cfg)
        if client is None:
            return {}
        try:
            pr = urlparse(url)
            params = parse_qsl(pr.query, keep_blank_values=True)
        except Exception:
            return {}
        redir_idxs = [i for i, (k, _) in enumerate(params)
                      if k.lower() in self._REDIR_PARAMS]
        if not redir_idxs:
            return {}
        target_host = (pr.hostname or "").lower()
        settings = (self.cfg or {}).get("settings", {}) if isinstance(self.cfg, dict) else {}
        impersonate = settings.get("curl_cffi_impersonate", "chrome120")
        proxy = _resolve_proxy(self.cfg)
        jitter = float(settings.get("jitter_max", 0.0) or 0.0)
        headers = pick_header_strategy(target_host, self.cfg)
        payloads = self._oredir_payloads(target_host)

        for idx in redir_idxs:
            pname = params[idx][0]
            for payload in payloads:
                if _INT.stage_skip():
                    return {}
                new_params = list(params)
                new_params[idx] = (pname, payload)
                test_url = urlunparse(pr._replace(query=urlencode(new_params, safe="/:@\\%")))
                if jitter > 0:
                    time.sleep(random.random() * jitter)
                try:
                    kw = dict(timeout=timeout, allow_redirects=False,
                              headers=headers, verify=False)
                    if proxy:
                        kw["proxies"] = {"http": proxy, "https": proxy}
                    if is_cffi:
                        kw["impersonate"] = impersonate
                    r = client.get(test_url, **kw)
                except Exception:
                    continue
                status = int(getattr(r, "status_code", 0) or 0)
                loc = ""
                try:
                    loc = (dict(getattr(r, "headers", {}) or {}).get("location")
                           or dict(getattr(r, "headers", {}) or {}).get("Location") or "")
                except Exception:
                    loc = ""
                if not loc:
                    continue
                # Resolve the Location against the request URL, then compare host.
                try:
                    loc_host = (urlparse(loc if "//" in loc else "//" + loc.lstrip("/\\")).hostname or "").lower()
                except Exception:
                    loc_host = ""
                canary = self._canary_host()
                off_canary = loc_host == canary or loc_host.endswith("." + canary)
                if loc_host and off_canary and loc_host != target_host:
                    return {"url": url, "param": pname, "payload": payload,
                            "test_url": test_url, "status": status, "location": loc}
        return {}

    def stage15_open_redirect(self):
        stage(15, "Open Redirect Scan")
        d = self.out / "15_open_redirect"
        d.mkdir(parents=True, exist_ok=True)

        # Target URLs: those whose params look like a redirect sink.
        redir_re = re.compile(
            r"[?&](?:url|next|redirect|redirect_uri|redirect_url|redirect_to|return|"
            r"returl|returnurl|returnuri|return_uri|return_url|returnto|return_to|"
            r"dest|destination|continue|continue_url|goto|target|redir|redir_url|"
            r"out|view|to|image_url|callback|forward|rurl|go|back|backurl|"
            r"origin|success_url|checkout_url|location|next_url)=", re.I)
        try:
            cap = int(_cfg_get(self.cfg, "tools", "open_redirect_max_targets", default=0) or 0)
        except (TypeError, ValueError):
            cap = 0
        seen, redir_targets = set(), []
        listed = self.out / "05_categorized" / "openredirect.txt"
        if listed.exists() and listed.stat().st_size > 0:
            for line in listed.read_text(errors="ignore").splitlines():
                u = line.strip()
                if u and u not in seen:
                    seen.add(u)
                    redir_targets.append(u)
        else:
            for key in ("stage4_urls", "stage9_params"):
                uf = self._cp(key)
                if not (uf.exists() and uf.stat().st_size > 0):
                    continue
                for line in uf.read_text(errors="ignore").splitlines():
                    u = line.strip()
                    if not u or not redir_re.search(u):
                        continue
                    point = _xss_injection_point(u)
                    key_u = point or u
                    if key_u in seen:
                        continue
                    seen.add(key_u)
                    redir_targets.append(u)

        if not redir_targets:
            ok("No URLs with redirect-like parameters — nothing to test")
            empty = {"status": "done", "findings": [], "targets_count": 0,
                     "checked": 0, "tool": "", "tool_raw": "",
                     "canary": self._canary_host(), "reason": "no_redirect_params"}
            (d / "open_redirect_results.json").write_text(
                json.dumps(empty, indent=2, ensure_ascii=False), encoding="utf-8")
            self.open_redirect_results = empty
            self.summary["stage15"] = {"status": "done", "findings": 0,
                                       "targets_count": 0, "reason": "no_redirect_params"}
            return

        if cap > 0:
            redir_targets = redir_targets[:cap]
        tgt_file = d / "openredirect_targets.txt"
        tgt_file.write_text("\n".join(redir_targets) + "\n", encoding="utf-8")
        ok(f"Open-redirect targets: {len(redir_targets):,} URL(s) with redirect-like params")

        # ── 1) OpenRedireX — the dedicated fuzzer (broad bypass payloads) ───────
        raw_file = d / "openredirex_raw.txt"
        tool_used = ""
        if tool_exists("openredirex"):
            tool_used = "openredirex"
            # OpenRedireX has a built-in payload list, so -p is optional; use a
            # bundled payloads.txt if we can find one, otherwise fall back to it.
            pfile = next((p for p in (
                Path(_cfg_get(self.cfg, "tools", "openredirex_payloads", default="") or "x"),
                Path.home() / "Desktop" / "openredirex" / "payloads.txt",
                BASE_DIR / "openredirex" / "payloads.txt",
            ) if p.exists()), None)
            conc = int(_cfg_get(self.cfg, "tools", "openredirex_concurrency", default=50) or 50)
            ptimeout = int(_cfg_get(self.cfg, "tools", "openredirex_timeout_sec", default=1800) or 1800)
            popt = f"-p {pfile} " if pfile else ""
            info(f"OpenRedireX: fuzzing {len(redir_targets):,} URL(s) (concurrency {conc})")
            # OpenRedireX reads the URL list on stdin.
            run_cmd(f"openredirex {popt}-c {conc}", out_file=str(raw_file),
                    timeout=ptimeout, log=self.log, label="openredirex",
                    stream=True, stdin_file=str(tgt_file))
        else:
            warn("openredirex not installed — running verification pass only "
                 "(install: go/pip OpenRedireX). See install.sh")

        # ── 2) Canary verification — the part that PROVES a real open redirect ──
        # OpenRedireX flags any redirect; a triager needs a redirect that lands
        # on an attacker-chosen host. We confirm that here.
        budget = int(_cfg_get(self.cfg, "tools", "open_redirect_budget_sec", default=1200) or 1200)
        t0 = time.time()
        info(f"Verifying redirects against canary host {self._canary_host()} …")
        findings, checked = [], 0
        for u in redir_targets:
            if _INT.stage_skip():
                break
            if budget and (time.time() - t0) > budget:
                warn(f"Open-redirect verification budget ({budget}s) reached — "
                     f"checked {checked:,}/{len(redir_targets):,}")
                break
            checked += 1
            _pulse_job("open-redirect", t0, checked, len(redir_targets),
                       unit="urls", item=u)
            hit = self._verify_open_redirect(u)
            if hit:
                findings.append(hit)
                ok(f"CONFIRMED open redirect: {hit['param']} → {hit['location'][:80]}")

        interrupted = _INT.stage_skip() or (budget and (time.time() - t0) > budget)
        self.open_redirect_results = {
            "status": "done",
            "findings": findings, "targets_count": len(redir_targets),
            "checked": checked, "tool": tool_used,
            "tool_raw": str(raw_file) if raw_file.exists() else "",
            "canary": self._canary_host(), "interrupted": bool(interrupted),
        }
        (d / "open_redirect_results.json").write_text(
            json.dumps(self.open_redirect_results, indent=2, ensure_ascii=False),
            encoding="utf-8")
        self.summary["stage15"] = {
            "status": "done",
            "findings": len(findings),
            "targets_count": len(redir_targets),
            "checked": checked,
            "tool": tool_used,
            "duration_sec": round(time.time() - t0, 1),
            "interrupted": bool(interrupted),
        }
        if findings:
            ok(f"Open-redirect: {len(findings):,} CONFIRMED finding(s)")
        else:
            ok(f"Open-redirect scan complete — no confirmed redirect "
               f"(checked {checked:,} URL(s))")

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

    def _risk_level_from_severity(self, sev_counts: dict) -> tuple:
        """Nuclei severity sayimlarindan tek kelimelik, Ingilizce RISK etiketi
        (ve rengi) uretir. v6.17: onceki 'bulgu yok' turkce metni yerine her
        yerde tutarli 'RISK: NONE/LOW/MEDIUM/HIGH/CRITICAL' kullanilir."""
        sev_counts = sev_counts or {}
        if int(sev_counts.get("critical", 0)) > 0:
            return "CRITICAL", "#dc2626"
        if int(sev_counts.get("high", 0)) > 0:
            return "HIGH", "#f97316"
        if int(sev_counts.get("medium", 0)) > 0:
            return "MEDIUM", "#eab308"
        if int(sev_counts.get("low", 0)) > 0 or int(sev_counts.get("info", 0)) > 0:
            return "LOW", "#3b82f6"
        return "NONE", "#22c55e"

    def _severity_svg_chart(self, sev_counts: dict) -> str:
        """v6.13: harici JS/CDN kullanmadan, saf inline SVG bar chart uretir
        (CSP script-src 'none' ile uyumlu)."""
        order = ["critical", "high", "medium", "low", "info", "unknown"]
        colors = {
            "critical": "#dc2626", "high": "#f97316", "medium": "#eab308",
            "low": "#3b82f6", "info": "#6b7280", "unknown": "#4b5563",
        }
        items = [(k, int(sev_counts.get(k, 0))) for k in order if sev_counts.get(k)]
        if not items:
            return ""
        max_v = max(v for _, v in items) or 1
        bar_h = 26
        gap = 10
        chart_w = 420
        label_w = 90
        total_h = len(items) * (bar_h + gap) + gap
        bars = []
        for i, (name, val) in enumerate(items):
            y = gap + i * (bar_h + gap)
            w = int((chart_w - label_w - 50) * (val / max_v))
            color = colors.get(name, "#6b7280")
            bars.append(
                f'<text x="0" y="{y + bar_h*0.68:.0f}" fill="#94a3b8" '
                f'font-size="12" font-family="ui-sans-serif">{html.escape(name)}</text>'
                f'<rect x="{label_w}" y="{y}" width="{max(w,2)}" height="{bar_h}" '
                f'rx="4" fill="{color}" />'
                f'<text x="{label_w + max(w,2) + 8}" y="{y + bar_h*0.68:.0f}" '
                f'fill="#e2e8f0" font-size="12" font-family="ui-sans-serif">{val}</text>'
            )
        svg = (
            f'<svg viewBox="0 0 {chart_w} {total_h}" width="100%" '
            f'style="max-width:480px" xmlns="http://www.w3.org/2000/svg">'
            + "".join(bars) + "</svg>"
        )
        return svg

    def _findings_table_html(self, findings: list, kind: str) -> str:
        """Ham JSON dokumu yerine okunabilir, siddete-gore-siralanmis tablo uretir."""
        if not findings:
            return ""
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        rows = sorted(findings, key=lambda f: sev_order.get((f.get("severity") or "info").lower(), 5))
        sev_colors = {
            "critical": "#dc2626", "high": "#f97316", "medium": "#eab308",
            "low": "#3b82f6", "info": "#6b7280",
        }

        def esc(s): return html.escape(str(s) or "")

        trs = []
        for r in rows[:500]:
            sev = (r.get("severity") or "info").lower()
            color = sev_colors.get(sev, "#6b7280")
            if kind == "nuclei":
                trs.append(
                    f'<tr><td><span style="background:{color};color:#0b0f14;'
                    f'padding:2px 8px;border-radius:6px;font-weight:600;'
                    f'font-size:11px;text-transform:uppercase">{esc(sev)}</span></td>'
                    f'<td>{esc(r.get("name",""))}</td>'
                    f'<td><code>{esc(r.get("template",""))}</code></td>'
                    f'<td style="word-break:break-all">{esc(r.get("matched_at",""))}</td></tr>'
                )
            else:  # dalfox
                trs.append(
                    f'<tr><td><span style="background:{color};color:#0b0f14;'
                    f'padding:2px 8px;border-radius:6px;font-weight:600;'
                    f'font-size:11px;text-transform:uppercase">{esc(sev)}</span></td>'
                    f'<td>{esc(r.get("type",""))}</td>'
                    f'<td style="word-break:break-all">{esc(r.get("url",""))}</td>'
                    f'<td style="word-break:break-all"><code>{esc(r.get("payload",""))}</code></td></tr>'
                )
        headers = (
            '<tr><th>Severity</th><th>Name</th><th>Template</th><th>Matched At</th></tr>'
            if kind == "nuclei" else
            '<tr><th>Severity</th><th>Type</th><th>URL</th><th>Payload</th></tr>'
        )
        more = f'<div class="muted" style="margin-top:6px">+ {len(rows)-500} more (see raw file)</div>' if len(rows) > 500 else ""
        return (
            '<table class="findings-table"><thead>' + headers + '</thead><tbody>'
            + "".join(trs) + '</tbody></table>' + more
        )

    def _extra_checks_table_html(self) -> str:
        er = self.extra_results or {}
        if not er:
            return ""

        def esc(s): return html.escape(str(s) or "")

        parts = []
        cors_vuln = [r for r in er.get("cors", []) if r.get("vulnerable")]
        if cors_vuln:
            rows = "".join(
                f'<tr><td style="word-break:break-all">{esc(r.get("url",""))}</td>'
                f'<td>{esc(r.get("detail",""))}</td></tr>' for r in cors_vuln)
            parts.append(
                '<h3 style="color:#f97316;font-size:13px;margin:14px 0 6px">CORS Misconfiguration</h3>'
                '<table class="findings-table"><thead><tr><th>URL</th><th>Detail</th></tr></thead>'
                f'<tbody>{rows}</tbody></table>'
            )
        tko_vuln = [r for r in er.get("takeover", []) if r.get("vulnerable")]
        if tko_vuln:
            rows = "".join(
                f'<tr><td style="word-break:break-all">{esc(r.get("host",""))}</td>'
                f'<td>{esc(r.get("service",""))}</td>'
                f'<td>{esc(r.get("detail",""))}</td></tr>' for r in tko_vuln)
            parts.append(
                '<h3 style="color:#dc2626;font-size:13px;margin:14px 0 6px">Subdomain Takeover</h3>'
                '<table class="findings-table"><thead><tr><th>Host</th><th>Service</th><th>Detail</th></tr></thead>'
                f'<tbody>{rows}</tbody></table>'
            )
        bucket_vuln = [r for r in er.get("buckets", []) if r.get("public_listing")]
        if bucket_vuln:
            rows = "".join(
                f'<tr><td style="word-break:break-all">{esc(r.get("url",""))}</td>'
                f'<td>{esc(r.get("provider",""))}</td>'
                f'<td>{esc(r.get("detail",""))}</td></tr>' for r in bucket_vuln)
            parts.append(
                '<h3 style="color:#dc2626;font-size:13px;margin:14px 0 6px">Cloud Bucket Exposure</h3>'
                '<table class="findings-table"><thead><tr><th>URL</th><th>Provider</th><th>Detail</th></tr></thead>'
                f'<tbody>{rows}</tbody></table>'
            )
        if not parts:
            return ""
        return "".join(parts)

    def build_full_report(self) -> Path:
        rp = self.out / "reconx_full_report.html"

        stage4   = self._cp("stage4_urls")
        urls_txt = self._read_text_safe(stage4)
        auth_urls_txt = self._read_text_safe(self._cp("stage8_authenticated_urls"))

        def esc(s): return html.escape(str(s) or "")

        def _safe_json(obj, indent=2):
            try:
                return json.dumps(obj, indent=indent, ensure_ascii=False, default=str)
            except Exception as e:
                return f"[JSON error: {e}]"

        _s3_count    = esc(str((self.summary.get("stage3") or {}).get("count", "?")))
        _s4_count    = esc(str((self.summary.get("stage4") or {}).get("count", "?")))
        _s8_count    = esc(str((self.summary.get("stage8") or {}).get("count", "?")))
        _auth_status = esc(self.auth_status)

        # Nuclei durumu
        _nuc = self.nuclei_results or {}
        _st7 = self.summary.get("stage7") or {}
        _nuc_status = _st7.get("status", "not-run")
        _nuc_count  = int(_nuc.get("findings") or 0)
        _nuc_sev    = _nuc.get("severity_counts") or {}
        _nuc_failed = bool(_st7.get("tool_failed"))
        _nuc_error  = esc(_st7.get("tool_error", ""))
        _nuc_interrupted = bool(_st7.get("interrupted"))
        _nuc_ran = _nuc_status not in ("not-run", "skipped")
        _nuc_risk_level, _nuc_risk_color = self._risk_level_from_severity(_nuc_sev)
        if _nuc_failed:
            _security_label = "⚠ TOOL ERROR"
        elif self.nuclei_asked and not self.nuclei_chosen:
            _security_label = "Skipped"
        elif _nuc_status == "skipped" or _nuc_status == "not-run":
            _security_label = "Not run"
        elif _nuc_interrupted:
            _security_label = "⚠ Interrupted"
        else:
            _security_label = f"{_nuc_count} finding(s)"
        _s7_sev_txt = esc(", ".join(f"{k}: {v}" for k, v in dict(_nuc_sev).items() if v) or "none")
        _nuc_chart = self._severity_svg_chart(_nuc_sev)
        _nuc_meta_html = ""
        if _nuc_ran:
            _parts = [
                f"RISK: <strong style='color:{_nuc_risk_color}'>{_nuc_risk_level}</strong>",
                f"duration: {_nuc.get('duration_sec', _st7.get('duration_sec', 0))}s",
                f"targets: {_st7.get('targets_count', 0):,}",
                f"severity filter: {esc(_st7.get('severity_filter','none'))}",
            ]
            if _st7.get("tech_fastpass_tags"):
                _parts.append(f"fastpass tags: {esc(_st7['tech_fastpass_tags'])}")
            if _nuc.get("template_path"):
                _parts.append(f"templates: {esc(str(_nuc.get('template_path')))}")
            _nuc_meta_html = (f'<div style="font-size:12px;color:#94a3b8;margin:8px 0 14px;'
                              f'display:flex;flex-wrap:wrap;gap:14px">'
                              + "".join(f"<span>{p}</span>" for p in _parts) + "</div>")

        # Nuclei bulgu listesi -> tablo (json'dan parse)
        _nuc_findings_list = []
        if _nuc.get("file_json") and Path(_nuc["file_json"]).exists():
            for line in Path(_nuc["file_json"]).read_text(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                _nuc_findings_list.append({
                    "template": rec.get("template-id", ""),
                    "name": (rec.get("info", {}) or {}).get("name", ""),
                    "severity": (rec.get("info", {}) or {}).get("severity", "info"),
                    "matched_at": rec.get("matched-at") or rec.get("host") or "",
                })
        _nuc_table = self._findings_table_html(_nuc_findings_list, "nuclei")

        # XSS (Dalfox) durumu
        _xss = self.xss_results or {}
        _st6 = self.summary.get("stage6") or {}
        _xss_count = int(_xss.get("count") or _xss.get("findings") or 0)
        _xss_failed = bool(_st6.get("tool_failed"))
        _xss_error  = esc(_st6.get("tool_error", ""))
        _xss_interrupted = bool(_st6.get("interrupted"))
        _xss_ran = _st6.get("status") not in (None, "skipped")
        _xss_risk_level, _xss_risk_color = ("HIGH", "#f97316") if _xss_count else ("NONE", "#22c55e")
        _xss_meta_html = ""
        if _xss_ran:
            _parts = [
                f"RISK: <strong style='color:{_xss_risk_color}'>{_xss_risk_level}</strong>",
                f"duration: {_st6.get('duration_sec', 0)}s",
                f"targets: {_st6.get('targets_count', 0):,}",
            ]
            _xss_meta_html = (f'<div style="font-size:12px;color:#94a3b8;margin:8px 0 14px;'
                              f'display:flex;flex-wrap:wrap;gap:14px">'
                              + "".join(f"<span>{p}</span>" for p in _parts) + "</div>")
        _xss_findings_list = []
        if _xss.get("file_json") and Path(_xss["file_json"]).exists():
            for line in Path(_xss["file_json"]).read_text(errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict):
                    continue
                data = rec.get("data") or rec
                if isinstance(data, dict):
                    url = data.get("url") or rec.get("url") or ""
                    payload = data.get("payload") or data.get("param") or ""
                    typ = data.get("type") or rec.get("type") or ""
                else:
                    url, payload, typ = "", "", ""
                _xss_findings_list.append({
                    "url": url, "payload": payload, "type": typ,
                    "severity": rec.get("severity") or rec.get("confidence") or "info",
                })
        _xss_table = self._findings_table_html(_xss_findings_list, "dalfox")

        # JS secrets
        _js = self.js_results or {}
        _js_endpoints = int(_js.get("endpoints") or 0)
        _js_secrets = int(_js.get("secrets") or 0)
        _js_txt = ""
        if self.out and (self.out / "10_js_secrets" / "secrets.txt").exists():
            _js_txt = self._read_text_safe(self.out / "10_js_secrets" / "secrets.txt")

        # Tech priority ciktilari
        _tech_txt = ""
        if self.out and (self.out / "11_tech" / "tech.csv").exists():
            _tech_txt = self._read_text_safe(self.out / "11_tech" / "tech.csv")

        # v6.13: Ekstra kontroller (CORS/Takeover/Bucket)
        _extra = self.summary.get("stage12") or {}
        _extra_table = self._extra_checks_table_html()
        _extra_total_vuln = (int(_extra.get("cors_vulnerable", 0)) +
                              int(_extra.get("takeover_vulnerable", 0)) +
                              int(_extra.get("bucket_public", 0)))

        # v6.13: Yonetici ozeti icin genel risk skoru
        _crit = int(_nuc_sev.get("critical", 0))
        _high = int(_nuc_sev.get("high", 0))
        _med  = int(_nuc_sev.get("medium", 0))
        _tech_high = int((self.summary.get("stage11") or {}).get("high", 0))
        _overall_score = (_crit*10 + _high*6 + _med*3 + _xss_count*5 +
                           _extra_total_vuln*7 + _tech_high*2)
        if _overall_score >= 40:
            _risk_level, _risk_color = "CRITICAL", "#dc2626"
        elif _overall_score >= 20:
            _risk_level, _risk_color = "HIGH", "#f97316"
        elif _overall_score >= 8:
            _risk_level, _risk_color = "MEDIUM", "#eab308"
        elif _overall_score > 0:
            _risk_level, _risk_color = "LOW", "#3b82f6"
        else:
            _risk_level, _risk_color = "NONE", "#22c55e"

        meta = {
            "target":               self.target,
            "timestamp":            self.ts,
            "adaptive_multiplier":  self.adapt_mult,
            "block_ratio_httpx":    self.block_ratio,
            "waf_fingerprint":      self.waf_fingerprint,
            "adaptive_events":      self.adaptive_events,
            "auth_status":          self.auth_status,
            "auth_cookie_names":    list(self.auth_cookies.keys()),
            "nuclei_asked":         self.nuclei_asked,
            "nuclei_chosen":        self.nuclei_chosen,
            "nuclei":               _nuc,
            "xss_asked":            self.xss_asked,
            "xss_chosen":           self.xss_chosen,
            "xss":                  self.xss_results,
            "js":                   self.js_results,
            "tech_summary":         self.tech_summary,
            "extra_checks":         self.extra_results,
            "stages":               self.summary,
        }

        html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none';
               img-src data:; connect-src 'none'; form-action 'none';" />
<title>ReconX v{VERSION} Report — {esc(self.target)}</title>
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
  code {{ background: #0b1220; padding: 2px 5px; border-radius: 4px; }}
  .findings-table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
  .findings-table th {{ text-align: left; color: #94a3b8; font-weight: 600;
                        padding: 8px 10px; border-bottom: 1px solid #1f2a37;
                        text-transform: uppercase; font-size: 10.5px; letter-spacing: .04em; }}
  .findings-table td {{ padding: 8px 10px; border-bottom: 1px solid #161e29; vertical-align: top; }}
  .findings-table tr:hover td {{ background: #0b1220; }}
  .exec-banner {{ display: flex; align-items: center; gap: 18px; }}
  .exec-badge {{ font-size: 26px; font-weight: 800; padding: 10px 22px; border-radius: 12px;
                color: #0b0f14; letter-spacing: .04em; }}
</style>
</head>
<body>

<h1>ReconX v{VERSION} — Security Report</h1>
<div class="muted">
  Target: <strong style="color:#e2e8f0">{esc(self.target)}</strong>
  &nbsp;·&nbsp; {esc(self.ts)}
  &nbsp;·&nbsp; WAF: {esc(", ".join(self.waf_fingerprint) or "none detected")}
  &nbsp;·&nbsp; Auth session: <strong>{_auth_status}</strong>
</div>

<!-- v6.17: Executive Summary -->
<div class="card">
  <h2>Executive Summary</h2>
  <div class="exec-banner">
    <div class="exec-badge" style="background:{_risk_color}">{esc(_risk_level)}</div>
    <div>
      <div style="font-size:13px;color:#cbd5e1">Total risk score: <strong>{_overall_score}</strong></div>
      <div class="muted" style="margin-top:4px">
        Nuclei: {_crit} critical, {_high} high, {_med} medium &nbsp;·&nbsp;
        XSS: {_xss_count} &nbsp;·&nbsp;
        CORS/Takeover/Bucket: {_extra_total_vuln} &nbsp;·&nbsp;
        High-risk technology: {_tech_high} host(s)
      </div>
    </div>
  </div>
</div>

<!-- Stats -->
<div class="card grid">
  <div class="stat">
    <div class="label">Alive Hosts</div>
    <div class="value">{_s3_count}</div>
  </div>
  <div class="stat">
    <div class="label">Total URLs</div>
    <div class="value">{_s4_count}</div>
  </div>
  <div class="stat">
    <div class="label">Authenticated URLs</div>
    <div class="value">{_s8_count}</div>
  </div>
  <div class="stat">
    <div class="label">Nuclei Risk</div>
    <div class="value" style="color:{_nuc_risk_color}">{_nuc_risk_level if _nuc_ran and not _nuc_failed else _security_label}</div>
  </div>
</div>

<!-- Nuclei findings -->
<div class="card">
  <h2>Nuclei Scan (alive hosts)</h2>
  {f'<div style="background:rgba(220,38,38,.12);border:1px solid #dc2626;border-radius:8px;padding:10px 14px;margin-bottom:10px;color:#fca5a5;font-size:13px"><strong>⚠ Nuclei exited with an error:</strong> {_nuc_error} — the result below does NOT necessarily mean the target is clean; the scan may not have completed.</div>' if _nuc_failed else ''}
  {f'<div style="background:rgba(249,115,22,.12);border:1px solid #f97316;border-radius:8px;padding:10px 14px;margin-bottom:10px;color:#fdba74;font-size:13px"><strong>⚠ Scan was interrupted (Ctrl+C):</strong> {_nuc_error} — not all targets/templates may have been tested.</div>' if (_nuc_interrupted and not _nuc_failed) else ''}
  <div class="muted">Status: {_nuc_status} — severity breakdown: {_s7_sev_txt}</div>
  {_nuc_meta_html}
  {f'<div style="margin:14px 0">{_nuc_chart}</div>' if _nuc_chart else ''}
  {_nuc_table or ('<div class="muted">Scan completed — 0 findings.</div>' if _nuc_ran else '<div class="muted">Nuclei scan not run.</div>')}
</div>

<!-- XSS findings -->
<div class="card">
  <h2>XSS Scan (Dalfox)</h2>
  {f'<div style="background:rgba(220,38,38,.12);border:1px solid #dc2626;border-radius:8px;padding:10px 14px;margin-bottom:10px;color:#fca5a5;font-size:13px"><strong>⚠ Dalfox exited with an error:</strong> {_xss_error} — the result below does NOT necessarily mean the target is clean; the scan may not have completed.</div>' if _xss_failed else ''}
  {f'<div style="background:rgba(249,115,22,.12);border:1px solid #f97316;border-radius:8px;padding:10px 14px;margin-bottom:10px;color:#fdba74;font-size:13px"><strong>⚠ Scan was interrupted (Ctrl+C):</strong> {_xss_error} — not all targets may have been tested.</div>' if (_xss_interrupted and not _xss_failed) else ''}
  <div class="muted">Findings: {_xss_count} — RISK: <strong style="color:{_xss_risk_color}">{_xss_risk_level if _xss_ran else 'N/A'}</strong></div>
  {_xss_meta_html}
  {_xss_table or ('<div class="muted">Scan completed — 0 findings.</div>' if _xss_ran else '<div class="muted">XSS scan not run.</div>')}
</div>

<!-- Extra checks -->
<div class="card">
  <h2>Extra Security Checks — CORS / Subdomain Takeover / Cloud Bucket</h2>
  <div class="muted">
    CORS: {esc(str(_extra.get('cors_checked','?')))} checked, {esc(str(_extra.get('cors_vulnerable',0)))} finding(s) &nbsp;·&nbsp;
    Takeover: {esc(str(_extra.get('takeover_checked','?')))} checked, {esc(str(_extra.get('takeover_vulnerable',0)))} finding(s) &nbsp;·&nbsp;
    Bucket: {esc(str(_extra.get('bucket_checked','?')))} checked, {esc(str(_extra.get('bucket_public',0)))} public
  </div>
  {_extra_table or '<div class="muted" style="margin-top:10px">No findings.</div>'}
</div>

<!-- JS secrets -->
<div class="card">
  <h2>JS Endpoints / Secrets</h2>
  <div class="muted">Endpoints: {_js_endpoints} — Secrets: {_js_secrets}</div>
  <div class="scroll"><pre style="font-size:11px">{esc(_js_txt) or "JS analysis not run."}</pre></div>
</div>

<!-- Tech priority -->
<div class="card">
  <h2>Technology-Based Priority (stage 11)</h2>
  <div class="muted">Ranked hosts by cumulative tech risk score</div>
  <div class="scroll"><pre style="font-size:11px">{esc(_tech_txt) or "Tech prioritisation not run."}</pre></div>
</div>

<!-- Authenticated URLs -->
<div class="card">
  <h2>Authenticated (Post-Login) URLs</h2>
  <div class="muted">Login status: {_auth_status} — cookies: {esc(", ".join(self.auth_cookies.keys()) or "none")}</div>
  <div class="scroll"><pre style="font-size:11px">{esc(auth_urls_txt) or "(no authenticated URLs collected)"}</pre></div>
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

    def _open_report_with_ai_bridge(self, report_path) -> bool:
        """Open the report THROUGH the local AI bridge instead of over file://.

        The report's "AI Analysis" button needs a backend, and the one thing it
        must never contain is the Anthropic API key — a report gets shared, and
        a key baked into the HTML travels with it. So reconx_ai.py serves the
        report from 127.0.0.1 and holds the key in its own process; the page
        and the API then share an origin, which also removes the CORS problem
        a file:// page would have had.

        The bridge runs detached with an idle timeout, so the scan still exits
        and returns the terminal. Returns True if the bridge took over opening
        the report; False means the caller should fall back to file://, which
        is a fully working report minus the button.
        """
        if not bool(_cfg_get(self.cfg, "ai", "enabled", default=True)):
            return False
        if not bool(_cfg_get(self.cfg, "ai", "auto_bridge", default=True)):
            return False
        if self.ai_bridge_disabled:
            return False

        script = BASE_DIR / "reconx_ai.py"
        if not script.exists():
            return False

        # Two independent backends can answer the button, so the gate has to
        # mirror reconx_ai.run_analysis(): the Anthropic API (SDK + key, and
        # credit we cannot check from here), or the `claude` CLI, which runs on
        # a Claude subscription and needs neither. Requiring an API key here —
        # as this did before the CLI backend existed — would hand a
        # subscription-only user a report with a permanently dead button.
        backend = str(_cfg_get(self.cfg, "ai", "backend", default="auto") or "auto").lower()
        try:
            import anthropic  # noqa: F401
            has_sdk = True
        except ImportError:
            has_sdk = False
        api_ok = has_sdk and bool(get_api_key(self.cfg, "anthropic"))
        cli_path = shutil.which("claude") or ""
        if not cli_path:
            _guess = Path.home() / ".local" / "bin" / "claude"
            cli_path = str(_guess) if _guess.is_file() else ""
        cli_ok = bool(cli_path)

        if backend == "api" and not api_ok:
            warn("AI Analysis unavailable — ai.backend is 'api' but "
                 + ("no API key is set (export ANTHROPIC_API_KEY, or set "
                    "api_keys.anthropic in config.yaml)" if has_sdk
                    else "the 'anthropic' package is missing (pip install anthropic)"))
            sub("The report still opens normally; everything except the AI panel works.")
            return False
        if backend == "cli" and not cli_ok:
            warn("AI Analysis unavailable — ai.backend is 'cli' but the "
                 "`claude` CLI was not found (install Claude Code).")
            sub("The report still opens normally; everything except the AI panel works.")
            return False
        if not api_ok and not cli_ok:
            warn("AI Analysis unavailable — no usable backend. Either add an "
                 "Anthropic API key, or install Claude Code to run it on a "
                 "Claude subscription.")
            sub("The report still opens normally; everything except the AI panel works.")
            return False

        idle = int(_cfg_get(self.cfg, "ai", "bridge_idle_timeout_sec", default=0) or 0)
        port = int(_cfg_get(self.cfg, "ai", "bridge_port", default=0) or 0)
        cmd = [sys.executable, str(script), "serve", str(Path(report_path).parent),
               "--config", str(self._config_path), "--idle-timeout", str(idle),
               "--port", str(port)]
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, start_new_session=True)
        except Exception as e:  # noqa: BLE001
            warn(f"Could not start the AI bridge: {e}")
            return False

        # The bridge writes .ai_bridge.json once it is actually listening, and
        # it opens the browser itself. Waiting for that file is what tells us
        # it bound a port rather than died on startup.
        handshake = Path(report_path).parent / ".ai_bridge.json"
        deadline = time.time() + 12
        while time.time() < deadline:
            if handshake.exists():
                try:
                    url = json.loads(handshake.read_text(errors="replace")).get("url", "")
                except Exception:
                    url = ""
                if url:
                    ok(f"AI Analysis ready: {url}")
                    if idle:
                        sub(f"The report opened through the local bridge — click "
                            f"'Run AI Analysis'. Idle timeout {idle}s.")
                    else:
                        sub("The report opened through the local bridge — click "
                            "'Run AI Analysis'. The bridge stays up until you stop it.")
                    return True
                break
            time.sleep(0.25)
        warn("AI bridge did not come up in time — opening the report directly")
        return False

    # ── Report ────────────────────────────────────────────────────────────────
    def generate_report(self):
        stage("✦", "Generating Report")
        # Delta against the previous completed scan of this target (--no-diff
        # disables it). Runs before SUMMARY.json is written so the result can be
        # embedded there as well as in DIFF.json.
        self._compute_scan_diff()
        sf = self.out / "SUMMARY.json"
        try:
            # v8.6-fix: a partial run (--resume, -s 7, --stageN) only populated
            # self.summary for the stages it actually ran. Overwriting
            # SUMMARY.json wholesale then WIPED every earlier stage's data —
            # e.g. re-running just stage 7 erased stage 6's XSS findings +
            # screenshot metadata from the report. Merge onto whatever is
            # already on disk instead: stages this run touched win, the rest
            # are kept.
            prior_stages = {}
            if sf.exists():
                try:
                    prev = json.loads(sf.read_text(errors="ignore"))
                    if isinstance(prev.get("stages"), dict):
                        prior_stages = prev["stages"]
                except Exception:
                    pass
            merged_stages = {**prior_stages, **self.summary}
            summary_obj = {
                "target":              self.target,
                "timestamp":           self.ts,
                "adaptive_multiplier": self.adapt_mult,
                "block_ratio_httpx":   self.block_ratio,
                "waf_fingerprint":     self.waf_fingerprint,
                "adaptive_events":     self.adaptive_events,
                "auth_status":         self.auth_status,
                "auth_cookie_names":   list(self.auth_cookies.keys()),
                "stages":              merged_stages,
                "scan_diff":           self.scan_diff,
                "resume": {
                    "state_file":       str(self.state.path),
                    "completed":        bool(self.state.data.get("completed")),
                    "interrupted":      bool(self.state.data.get("interrupted")),
                    "interrupt_reason": self.state.data.get("interrupt_reason", ""),
                    "completed_stages": self.state.done_stages(),
                },
                "output_dir":          str(self.out)
            }
            sf.write_text(
                json.dumps(summary_obj, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8"
            )
        except Exception as _je:
            sf.write_text(json.dumps({"error": str(_je), "target": self.target}), encoding="utf-8")

        # v8.1-fix: "FULL Report" (build_full_report, asagida) ve interaktif
        # report_builder.py raporu daha once HER TARAMADA IKISI DE uretiliyordu —
        # ayni veriyi iki kez isleyip iki ayri HTML dosyasi yaziyordu, ama pratikte
        # sadece report_builder'in raporu aciliyordu (target_rp = report_path or
        # full_report → report_path her zaman kazaniyor). Bu, kullanicinin "gereksiz
        # kod/bloat kaldirilsin" istegiyle dogrudan cakisan, olcumlenebilir bir israftı.
        # Artik report_builder ONCE deneniyor; FULL Report SADECE report_builder
        # gercekten basarisiz olursa (import hatasi VEYA calisirken exception) devreye
        # giren gercek bir fallback — normal/basarili akiste hic calismiyor.
        report_path = None
        try:
            from report_builder import build_report
            report_path = build_report(self.out, self.target, self.summary)
            ok(f"Report: {report_path}")
        except ImportError:
            warn("report_builder.py not found — falling back to FULL report")
        except Exception as e:
            warn(f"Report error: {e} — falling back to FULL report")

        full_report = None
        if not report_path:
            try:
                full_report = self.build_full_report()
                ok(f"FULL Report (fallback): {full_report}")
            except Exception as e:
                warn(f"FULL report error: {e}")

        target_rp = report_path or full_report
        # A scan started from the open report rewrites that same file. The
        # page reloads itself. Opening a browser here would add a second tab.
        in_place = os.environ.get("RECONX_REPORT_IN_PLACE") == "1"
        if target_rp and not in_place and not self._open_report_with_ai_bridge(target_rp):
            try:
                import webbrowser
                # Windows'ta dogru file URI: file:///C:/... (file://C:\... okunmaz)
                webbrowser.open(Path(target_rp).as_uri())
            except Exception:
                pass

        try:
            send_webhook_notification(self.cfg, self.target, self.summary)
        except Exception:
            pass

        # Be honest in the closing banner: an interrupted run is NOT a complete
        # scan, and saying so is the difference between "we found nothing" and
        # "we stopped before looking".
        _stopped = bool(self.state.data.get("interrupted")) or _INT.hard()
        _col     = C.YELLOW if _stopped else C.CYAN
        _title   = "SCAN STOPPED (resumable)" if _stopped else "SCAN COMPLETE"
        print(f"\n{_col}{C.BOLD}{'═'*60}\n  {_title} — {self.target}\n{'═'*60}{C.RESET}")
        print(f"  {C.BLUE}Output      : {self.out}{C.RESET}")
        if report_path:
            print(f"  {C.BLUE}Report      : {report_path}{C.RESET}")
        if full_report:
            print(f"  {C.BLUE}FULL Report : {full_report}{C.RESET}")
        print(f"  {C.BLUE}Log         : {self.out}/pipeline.log{C.RESET}")
        if self.scan_diff:
            print(f"  {C.BLUE}Delta       : {self.out}/DIFF.json{C.RESET}")
        if _stopped:
            print(f"  {C.YELLOW}Resume      : python3 reconX.py -d {self.target} --resume{C.RESET}")
        print()

    # ── Stage 0 — URL seed ────────────────────────────────────────────────────
    def _retarget_scheme(self, scheme: str, hostname: str):
        """Point seed URLs for this host at the scheme that actually answered."""
        if not scheme or not hostname or not self.url_targets:
            return
        host = hostname.lower()
        rewritten = []
        changed = False
        for u in self.url_targets:
            p = urlparse(u)
            if (p.hostname or "").lower() == host and p.scheme and p.scheme != scheme:
                rewritten.append(urlunparse((
                    scheme, p.netloc, p.path or "/", p.params, p.query, p.fragment)))
                changed = True
            else:
                rewritten.append(u)
        if changed:
            self.url_targets = rewritten
            for u in rewritten[:5]:
                sub(f"seed now {u}")

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
        if urls:
            seed = urlparse(urls[0])
            known = {(urlparse(u).hostname or "").lower() for u in urls}
            siblings = []
            for name in _etc_hosts_names(self.target):
                if name in known:
                    continue
                known.add(name)
                if seed.port:
                    siblings.append(f"{seed.scheme}://{name}:{seed.port}/")
                else:
                    siblings.append(f"{seed.scheme}://{name}/")
            if siblings:
                info(f"/etc/hosts: {len(siblings)} related name(s) on the same port as the seed")
                urls.extend(siblings)
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
        self.summary.setdefault("stage2", {"status": "done", "count": len(hosts), "note": "url_seed"})

        # v8.2: -u/--single/-U (URL seed mode) used to write the seed URLs
        # straight to the stage3_alive checkpoint as bare strings and stop —
        # unlike the normal -d/domain flow, it never actually probed them
        # with httpx. The report's Alive Hosts table (Status/Title/IP/Tech/
        # Size/Server/RT) only has data to show when an httpx JSON probe
        # exists (03_alive/httpx_full.json); without it every seeded URL
        # showed up with every column but URL blank. Run the same rich httpx
        # probe stage3_alive() uses (shared via _run_httpx_alive_probe) here
        # too, so seed-mode scans get the exact same report detail.
        d = self.out / "03_alive"
        seed_input = d / "seed_urls_probe_input.txt"
        write_lines(seed_input, urls)
        alive_urls, status_cnt = self._run_httpx_alive_probe(seed_input, d, label="httpx (seed URLs)",
                                                              probe_ports=False)
        total_scanned = sum(status_cnt.values()) if status_cnt else 0
        blocked = status_cnt.get(403, 0) + status_cnt.get(429, 0)
        if total_scanned > 0:
            self.block_ratio = blocked / max(1, total_scanned)
        if alive_urls:
            write_lines(self._cp("stage3_alive"), sorted(set(alive_urls)))
            self.summary.setdefault("stage3", {"status": "done", "count": len(alive_urls), "note": "url_seed_httpx"})
        else:
            # httpx missing or every seed URL failed to respond — fall back to
            # the raw seed list so the scan can still proceed. Alive Hosts
            # will only show the URL column in this case, same as before this
            # fix, instead of blocking the whole run over it.
            warn("httpx probe of seed URLs produced no results — falling back to the raw "
                 "seed list (Alive Hosts table will only show the URL column for these)")
            write_lines(self._cp("stage3_alive"), urls)
            self.summary.setdefault("stage3", {"status": "done", "count": len(urls), "note": "url_seed"})

    # ── Run ───────────────────────────────────────────────────────────────────

    def stage13_api_discovery(self):
        """v8.0: GraphQL / Swagger / OpenAPI endpoint discovery — from the passive URL pool."""
        stage(13, "API Discovery (GraphQL/Swagger/OpenAPI)")
        d = self.out / "13_api"
        d.mkdir(parents=True, exist_ok=True)
        url_file = self._cp("stage4_urls")
        if not url_file.exists() or url_file.stat().st_size == 0:
            url_file = self._cp("stage3_alive")
        if not url_file.exists() or url_file.stat().st_size == 0:
            self.summary["stage13"] = {"status": "skipped", "reason": "no_urls"}
            return
        urls = [l.strip() for l in url_file.read_text(errors="ignore").splitlines() if l.strip()]
        api_patterns = [
            (re.compile(r"/graphql", re.I), "graphql"),
            (re.compile(r"/swagger", re.I), "swagger"),
            (re.compile(r"/openapi", re.I), "openapi"),
            (re.compile(r"/api/v\d+", re.I), "api_versioned"),
            (re.compile(r"/v\d+/", re.I), "api_v"),
            (re.compile(r"\.well-known/openapi", re.I), "wellknown"),
        ]
        found = {k: [] for _, k in api_patterns}
        for u in urls:
            for pat, key in api_patterns:
                if pat.search(u):
                    found[key].append(u)
        # v8.6: actually PROBE the well-known API paths instead of only listing
        # candidate URLs. A hit here (200 + JSON/HTML body, or a GraphQL error
        # envelope) is a concrete, reportable finding — an exposed API schema or
        # an introspectable GraphQL endpoint — not just a guess.
        swagger_candidates = ["/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
                              "/v2/api-docs", "/v3/api-docs", "/api-docs", "/swagger-ui.html",
                              "/graphql", "/api/graphql", "/graphql/console", "/.well-known/openapi.json"]
        probe_results = []
        live_hits = []
        base_hosts = list({f"{urlparse(u).scheme}://{urlparse(u).netloc}"
                           for u in urls if urlparse(u).netloc and self._is_in_scope_url(u)})[:8]
        client, is_cffi = _get_http_client(self.cfg)
        hdrs = pick_header_strategy(self.target, self.cfg)
        if self.has_auth():
            hdrs = self._auth_headers(hdrs)
        _imp = _cfg_get(self.cfg, "settings", "curl_cffi_impersonate", default="chrome120") or "chrome120"
        probe_total = len(base_hosts) * len(swagger_candidates)
        probe_n = 0
        api_t0 = time.time()
        for base in base_hosts:
            if _INT.stage_skip():
                break
            for cand in swagger_candidates:
                if _INT.stage_skip():
                    break
                cu = base + cand
                probe_n += 1
                _pulse_job("api", api_t0, probe_n, probe_total, unit="probes", item=cu)
                probe_results.append(cu)
                if client is None:
                    continue
                try:
                    kw = dict(timeout=10, headers=hdrs, allow_redirects=True)
                    kw["verify"] = False
                    _tor_proxy = _resolve_proxy(self.cfg)
                    if _tor_proxy:
                        kw["proxies"] = {"http": _tor_proxy, "https": _tor_proxy}
                    if is_cffi:
                        kw["impersonate"] = _imp
                    if "graphql" in cand:
                        r = client.post(cu, json={"query": "{__schema{queryType{name}}}"}, **kw)
                    else:
                        r = client.get(cu, **kw)
                    sc = int(getattr(r, "status_code", 0) or 0)
                    body = (getattr(r, "text", "") or "")[:2000]
                    ct = (getattr(r, "headers", {}) or {}).get("content-type", "")
                    interesting = (
                        (sc == 200 and ("graphql" in cand or "swagger" in body.lower()
                                        or "openapi" in body.lower() or '"paths"' in body
                                        or "__schema" in body or "application/json" in ct))
                        or (("graphql" in cand) and sc in (200, 400) and ("errors" in body or "data" in body))
                    )
                    if interesting:
                        live_hits.append({"url": cu, "status": sc, "content_type": ct,
                                          "kind": ("graphql" if "graphql" in cand else "schema"),
                                          "snippet": body[:300]})
                        sub(f"API endpoint LIVE: {cu} [{sc}]")
                except Exception:
                    continue
        out_json = d / "api_discovery.json"
        out_json.write_text(json.dumps({"found": found, "probes": probe_results, "live_hits": live_hits},
                                       indent=2, ensure_ascii=False), encoding="utf-8")
        total = sum(len(v) for v in found.values())
        checkpoint(self._cp("stage13_api"),
                   [u for vals in found.values() for u in vals] + [h["url"] for h in live_hits], "api-discovery")
        self.summary["stage13"] = {
            "status": "done",
            "count": total + len(live_hits),
            "pattern_hits": total,
            "probe_candidates": len(probe_results),
            "live_hits": len(live_hits),
            "categories": {k: len(v) for k, v in found.items() if v},
        }
        if live_hits:
            ok(f"API discovery: {total} pattern hits · {len(live_hits)} LIVE endpoint(s) confirmed "
               f"({', '.join(sorted({h['kind'] for h in live_hits}))})")
        else:
            ok(f"API discovery: {total} pattern hits, {len(probe_results)} candidates probed — none live")

    # ══════════════════════════════════════════════════════════════════════════
    # Checkpoint / resume helpers
    # ══════════════════════════════════════════════════════════════════════════
    def _restore_stage(self, n):
        """Resume path for a stage already completed in an earlier run.

        The stage is NOT executed again. Instead its stored summary block is
        copied back into self.summary (so the report reflects the full scan,
        not only the stages this invocation ran) and a short preview of the
        artefacts it left on disk is printed, so the operator can see what is
        already in hand before the pipeline moves on."""
        rec   = self.state.stage_info(n)
        saved = rec.get("summary") if isinstance(rec.get("summary"), dict) else {}
        if saved:
            self.summary[f"stage{n}"] = dict(saved)
        title = rec.get("title") or STAGE_TITLES.get(n, "")
        print(f"\n{C.GREEN}{C.BOLD}{'═'*60}\n"
              f"  STAGE {n}: {title}  ·  RESTORED FROM CHECKPOINT\n"
              f"{'═'*60}{C.RESET}", flush=True)
        when = rec.get("finished") or rec.get("started") or "?"
        dur  = f" in {rec['duration_sec']}s" if rec.get("duration_sec") else ""
        ok(f"Already completed at {when}{dur} — skipping (use --fresh to force a new scan)")
        for line in self._stage_result_preview(n, saved):
            sub(line)

    def _stage_result_preview(self, n, saved: dict) -> list:
        """Human-readable recap of a restored stage: the numbers it recorded
        plus the first few lines of the checkpoint files it produced."""
        out = []
        if isinstance(saved, dict) and saved:
            bits = [f"{k}={v:,}" if isinstance(v, int) else f"{k}={v}"
                    for k, v in saved.items()
                    if isinstance(v, (int, str, float)) and k != "status" and v not in ("", 0)]
            if bits:
                out.append("Saved results: " + " · ".join(bits[:6]))
        for cp_name in _STAGE_ARTEFACTS.get(n, []):
            p = self._cp(cp_name)
            if not (p.exists() and p.stat().st_size > 0):
                continue
            total = _count_lines(p)
            out.append(f"{p.name}: {total:,} entries")
            try:
                head = [l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip()][:3]
            except Exception:
                head = []
            for h in head:
                out.append(f"  {C.DIM}· {h[:110]}{C.RESET}")
            if total > len(head):
                out.append(f"  {C.DIM}· ... +{total - len(head):,} more{C.RESET}")
        if not out:
            out.append("No stored artefacts for this stage (summary only)")
        return out

    def _print_resume_hint(self):
        """Printed whenever a run stops early — tells the operator, in one
        copy-pasteable line, how to pick the scan up where it left off."""
        done = self.state.done_stages()
        print(f"\n{C.YELLOW}{C.BOLD}{'─'*60}{C.RESET}")
        print(f"  {C.YELLOW}{C.BOLD}SCAN INTERRUPTED — progress saved{C.RESET}")
        print(f"  {C.BLUE}Completed stages : {', '.join(map(str, done)) if done else 'none'}{C.RESET}")
        print(f"  {C.BLUE}Checkpoint file  : {self.state.path}{C.RESET}")
        print(f"  {C.BLUE}Resume with      : python3 reconX.py -d {self.target} --resume{C.RESET}")
        print(f"{C.YELLOW}{C.BOLD}{'─'*60}{C.RESET}\n")

    # ── carry-forward for re-run stages ──────────────────────────────────────
    # Checkpoints whose content is a DISCOVERED SET (pure accumulation): when a
    # stage that was cut short is re-run, the second pass must never be allowed
    # to SHRINK what the first one already found. Stage 3 (alive) and stage 4
    # (URLs) are deliberately absent: they carry authoritative liveness/pruning
    # semantics where a smaller answer can be the correct one, and both are
    # recomputed from stage 2 anyway.
    _UNION_SAFE_CP = {
        2:  ["stage2_subdomains"],
        5:  ["stage5_xss_targets", "stage5_params"],
        8:  ["stage8_authenticated_urls"],
        9:  ["stage9_params"],
        13: ["stage13_api"],
    }

    def _snapshot_stage_sets(self, n) -> dict:
        """Contents of a stage's set-valued checkpoints BEFORE it (re-)runs."""
        snap = {}
        for cp in self._UNION_SAFE_CP.get(n, []):
            existing = self._read_cp_set(self.out, cp)
            if existing:
                snap[cp] = existing
        return snap

    def _merge_stage_sets(self, n, snapshot: dict):
        """Re-running a previously interrupted stage must not lose what that
        partial pass already found. Without this, a second pass that a tool
        timeout or a rate-limit cut even shorter would overwrite 29,000
        subdomains with 6 — and every later stage would quietly work off the
        truncated list. Only applied when the new pass is actually smaller."""
        for cp, before in (snapshot or {}).items():
            after = self._read_cp_set(self.out, cp)
            if len(after) >= len(before):
                continue                      # healthy re-run — leave it alone
            merged = before | after
            write_lines(self._cp(cp), sorted(merged))
            sub(f"Carried forward {len(merged) - len(after):,} entries from the interrupted "
                f"pass — {cp}.txt now holds {len(merged):,}")
            key = f"stage{n}"
            if isinstance(self.summary.get(key), dict) and "count" in self.summary[key]:
                self.summary[key]["count"] = len(merged)
                self.summary[key]["merged_with_partial"] = True

    # ══════════════════════════════════════════════════════════════════════════
    # Global wall-clock budget (--max-time)
    # ══════════════════════════════════════════════════════════════════════════
    def _budget_exceeded(self) -> bool:
        return bool(self.deadline and time.time() >= self.deadline)

    def _start_budget_watchdog(self):
        """Without this, a single long-running tool (nuclei against thousands of
        hosts) could blow straight through --max-time, since the deadline is only
        re-checked between stages. The watchdog raises the same hard-stop flag
        Ctrl+C option 3 raises, which kills the running child process."""
        if not self.deadline:
            return
        self._wd_stop = threading.Event()

        def _tick():
            while not self._wd_stop.wait(5):
                if self._budget_exceeded() and not self._budget_fired:
                    self._budget_fired = True
                    warn(f"Time budget of {self.max_time_min} min reached — stopping the "
                         f"running tool and checkpointing.")
                    _INT._hard = True
                    _INT._raw_sigint.set()
                    return

        self._watchdog = threading.Thread(target=_tick, daemon=True, name="reconx-time-budget")
        self._watchdog.start()

    def _stop_budget_watchdog(self):
        try:
            if getattr(self, "_wd_stop", None):
                self._wd_stop.set()
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════════
    # Scan diff — what changed since the last completed scan of this target
    # ══════════════════════════════════════════════════════════════════════════
    # Continuous recon is only useful if you can see the delta. This compares the
    # current session's checkpoint files against the newest *completed* earlier
    # session for the same target and writes DIFF.json next to the report.
    _DIFF_SETS = {
        "subdomains":  "stage2_subdomains",
        "alive_hosts": "stage3_alive",
        "urls":        "stage4_urls",
        "param_urls":  "stage9_params",
    }

    def _read_cp_set(self, session_dir, cp_name) -> set:
        p = Path(session_dir) / "checkpoints" / f"{cp_name}.txt"
        try:
            if not (p.exists() and p.stat().st_size > 0):
                return set()
            return {l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip()}
        except Exception:
            return set()

    def _compute_scan_diff(self):
        """Populate self.scan_diff + DIFF.json. Silent no-op on a first scan.

        The baseline is resolved PER SET rather than per session: the newest
        earlier session that actually produced that artefact wins. Without
        that, one partial re-run (`-s 13`, which writes no subdomain file)
        would become the baseline and hide every real delta."""
        if not self.want_diff:
            return
        try:
            here     = Path(self.out).resolve()
            previous = [(d, st) for d, st in find_sessions(self._out_root, self._target_slug)
                        if Path(d).resolve() != here]
            if not previous:
                return
            diff = {"baselines": {}, "sets": {}}
            any_change = False
            for label, cp_name in self._DIFF_SETS.items():
                now_set = self._read_cp_set(self.out, cp_name)
                if not now_set:
                    # This run never produced the artefact (partial re-run) —
                    # calling the whole baseline "gone" would be a plain lie.
                    continue
                prev_dir = prev_state = None
                prev_set = set()
                for cand_dir, cand_state in previous:
                    cand_set = self._read_cp_set(cand_dir, cp_name)
                    if cand_set:
                        prev_dir, prev_state, prev_set = cand_dir, cand_state, cand_set
                        break
                if not prev_set:
                    continue
                new_items  = sorted(now_set - prev_set)
                gone_items = sorted(prev_set - now_set)
                diff["baselines"][label] = {
                    "session": Path(prev_dir).name,
                    "date":    (prev_state or {}).get("updated") or (prev_state or {}).get("created") or "",
                }
                diff["sets"][label] = {
                    "current":  len(now_set),
                    "previous": len(prev_set),
                    "new":      len(new_items),
                    "gone":     len(gone_items),
                    "new_items":  new_items[:200],   # capped: DIFF.json stays readable
                    "gone_items": gone_items[:200],
                }
                any_change = any_change or bool(new_items or gone_items)
            if not diff["sets"]:
                return
            self.scan_diff = diff
            (self.out / "DIFF.json").write_text(
                json.dumps(diff, indent=2, ensure_ascii=False), encoding="utf-8")

            print(f"\n{C.CYAN}{C.BOLD}{'─'*60}\n"
                  f"  DELTA vs PREVIOUS SCAN\n"
                  f"{'─'*60}{C.RESET}")
            if not any_change:
                ok("No change since the previous scan")
            for label, d in diff["sets"].items():
                base  = diff["baselines"].get(label, {})
                arrow = f"{d['previous']:,} → {d['current']:,}"
                line  = f"{label:<12} {arrow:<20}"
                if d["new"]:
                    line += f" {C.GREEN}+{d['new']:,} new{C.RESET}"
                if d["gone"]:
                    line += f" {C.DIM}-{d['gone']:,} gone{C.RESET}"
                print(f"  {line}  {C.DIM}(vs {base.get('session', '?')}){C.RESET}", flush=True)
                for item in d["new_items"][:5]:
                    print(f"      {C.GREEN}+{C.RESET} {item[:110]}", flush=True)
                if d["new"] > 5:
                    print(f"      {C.DIM}... +{d['new'] - 5:,} more in DIFF.json{C.RESET}", flush=True)
            ok(f"Delta written: {self.out / 'DIFF.json'}")
        except Exception as e:
            warn(f"Scan diff failed: {e}")

    def run(self, stages=None):
        all_s = {
            1: self.stage1_recon,      2: self.stage2_subdomains,
            3: self.stage3_alive,      4: self.stage4_urls,
            5: self.stage5_categorise, 6: self.stage6_xss,
            7: self.stage7_nuclei,     8: self.stage8_authenticated_crawl,
            9: self.stage9_params,     10: self.stage10_js,
            11: self.stage11_tech_priority, 12: self.stage12_extra_checks,
            13: self.stage13_api_discovery,
            14: self.stage14_network,  15: self.stage15_open_redirect,
        }

        wants_login = bool(self.login_url or self.raw_cookie or self.request_file)
        if wants_login:
            self.stageL_login()

        # v6.17: stage 8 (authenticated crawl) artik varsayilan tam taramada
        # HER ZAMAN listede — daha once sadece login/cookie verildiyse ekleniyordu,
        # bu da normal (auth'suz) taramalarda "STAGE 7 -> STAGE 9" gibi numarik
        # bir bosluk/atlama izlenimi veriyordu. stage8_authenticated_crawl()
        # zaten auth yoksa kendi icinde net bir mesajla guvenle atlaniyor, o
        # yuzden her zaman dahil etmek numarayi hep ardisik tutar.
        if self.url_targets:
            # URL-seed mode runs the seeder and stage 1 OUTSIDE the main loop.
            # The seed goes first so the console order is 0 then 1, and so the
            # host fingerprint uses a port the seed URL actually answered on.
            self.stage0_seed_urls()
            if (not stages or 1 in stages):
                if self.resume and self.state.is_done(1):
                    self._restore_stage(1)
                else:
                    self.state.start_stage(1)
                    _t1 = time.time()
                    try:
                        self.stage1_recon()
                    except Exception as e:
                        err(f"Stage 1 crashed: {e}")
                        self.log.exception("Stage 1 fatal")
                        self.state.finish_stage(1, "failed", {"status": "failed", "error": str(e)},
                                                time.time() - _t1)
                    else:
                        self.state.finish_stage(
                            1, "partial" if (_INT.stage_skip() or _INT.hard()) else "done",
                            self.summary.get("stage1"), time.time() - _t1)
                    _INT.reset()
            # Recon only. XSS, Nuclei, JS, API and open redirect stay on the
            # Scan Center so they run after the report, against this corpus.
            run_stages = stages or [4, 5, 8, 9, 11, 14]
        else:
            run_stages = stages or [1, 2, 3, 4, 5, 8, 9, 11, 14]

        # -s ile acikca stage secildiyse kullanicinin secimi aynen kullanilir
        # (stage 8 istemeden zorla eklenmez); yalniz login/cookie verilip de
        # -s ile 8 disaridandi acikca istenmisse yine calistirilir.
        if wants_login and self.has_auth() and stages is not None and 8 in stages:
            if 8 not in run_stages:
                run_stages = list(run_stages) + [8]

        # v6.15: hangi kaynaktan gelirse gelsin (varsayilan liste, -s kombinasyonu,
        # kosullu stage8 eklemesi), calistirma sirasi HER ZAMAN artan numarik
        # sirada olsun. Onceden nuclei(7)/dalfox(6) onaylari en sona (stage 12
        # bittikten sonra) sorulup calistiriliyordu; bu, akisin "1,2,3,4,5,9,
        # 10,11,12" gibi sirasiz gorunmesine yol aciyordu. Artik onaylar da
        # kendi numarik sirasinda (6 ve 7'ye gelindiginde) soruluyor.
        run_stages = sorted(set(run_stages))
        # -s ile acikca stage secildiyse onay istenmez (secim zaten niyet
        # bildirimidir); sadece varsayilan tam taramada (stages=None) sorulur.
        # --auto ("auto_mode") ise varsayilan tam taramada bile bu sorulari
        # tamamen bypass eder — full pipeline hicbir onay beklemeden calisir.
        interactive = stages is None and not self.auto_mode
        if stages is None:
            info("Recon pass: subdomains, URLs, parameters, technology, IPs and ports. "
                 "XSS, Nuclei, JS analysis, API discovery, open redirect, CORS, "
                 "takeover and cloud buckets run afterwards from the report Scan Center.")
        if self.auto_mode:
            info("Auto mode (--auto): all stages will run without interactive prompts.")

        # Record the plan so a later resume knows what the run was aiming at.
        self.state.planned(run_stages)
        self.state.reclaim_orphan_running()
        self._start_budget_watchdog()

        stopped_early = False
        try:
            for n in run_stages:
                # ── global time budget (--max-time) ──────────────────────────
                if self._budget_exceeded():
                    warn(f"Time budget ({self.max_time_min} min) reached — stopping before stage {n}. "
                         f"Resume later with: python3 reconX.py -d {self.target} --resume")
                    self.state.mark_interrupted(f"time budget {self.max_time_min}min")
                    stopped_early = True
                    break
                if _INT.hard():
                    warn("Hard exit — checkpointing and writing report...")
                    self.state.mark_interrupted("ctrl-c / hard stop")
                    stopped_early = True
                    break
                if n not in all_s:
                    warn(f"Unknown stage: {n}")
                    continue

                # ── RESUME: never re-run a stage already marked "done" ───────
                # Its artefacts are on disk and its summary lives in state.json,
                # so restore + display them instead of burning the time again.
                # "partial"/"failed" stages are deliberately NOT skipped: their
                # output is incomplete by definition, so they run from scratch.
                # v9.4: EXPLICIT selection (-s / --stageN) is an intent to run —
                # so an on-demand scan button (`--stageN --resume`) re-runs the
                # scan every click instead of restoring the previous result.
                explicitly_requested = stages is not None and n in stages
                if (self.resume and self.state.is_done(n)
                        and not explicitly_requested):
                    self._restore_stage(n)
                    continue

                if n == 6:
                    if interactive:
                        self.xss_asked = True
                        if not ask_yes_no("Run XSS testing against the high-value URLs?", default="y"):
                            self.state.finish_stage(n, "skipped", {"status": "skipped",
                                                                   "reason": "declined"})
                            _INT.reset()
                            continue
                    self.xss_chosen = True
                if n == 7:
                    if interactive:
                        self.nuclei_asked = True
                        if not ask_yes_no("Run a template vulnerability scan against every live URL?", default="y"):
                            self.state.finish_stage(n, "skipped", {"status": "skipped",
                                                                   "reason": "declined"})
                            _INT.reset()
                            continue
                    self.nuclei_chosen = True

                # ── run the stage, then persist its outcome immediately ──────
                # _snap holds whatever a previous, interrupted pass of this same
                # stage already wrote, so a shorter second pass cannot lose it.
                _snap = self._snapshot_stage_sets(n) if self.resume else {}
                self.state.start_stage(n)
                _t0 = time.time()
                try:
                    all_s[n]()
                except SystemExit:
                    warn("Force exit — checkpointing and writing report...")
                    self.state.finish_stage(n, "partial", self.summary.get(f"stage{n}"),
                                            time.time() - _t0)
                    self.state.mark_interrupted("force exit")
                    stopped_early = True
                    break
                except Exception as e:
                    err(f"Stage {n} crashed: {e}")
                    self.log.exception(f"Stage {n} fatal")
                    self.state.finish_stage(n, "failed",
                                            {"status": "failed", "error": str(e)},
                                            time.time() - _t0)
                    warn("Continuing to next stage...")
                else:
                    if _snap:
                        self._merge_stage_sets(n, _snap)
                    # A stage that finished while a skip/hard flag was raised only
                    # produced partial data — mark it so, so resume re-runs it.
                    status = "partial" if (_INT.stage_skip() or _INT.hard()
                                           or self._budget_exceeded()) else "done"
                    self.state.finish_stage(n, status, self.summary.get(f"stage{n}"),
                                            time.time() - _t0)
                _INT.reset()
                self.tor.reset_stage_counter()

            if not stopped_early and not _INT.hard():
                self.state.mark_completed()
        finally:
            self._stop_budget_watchdog()
            if stopped_early or _INT.hard():
                self.state.mark_interrupted(self.state.data.get("interrupt_reason") or "interrupted")
                self._print_resume_hint()
            self.generate_report()


# ══════════════════════════════════════════════════════════════════════════════
# Resume decision
# ══════════════════════════════════════════════════════════════════════════════
def target_slug(target: str) -> str:
    """Filesystem-safe session-directory prefix for a target."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", (target or "").strip()).strip("._") or "target"


def resolve_resume(out_root, target, force_resume=False, fresh=False, auto=False):
    """Decide whether this invocation continues an interrupted scan.

    Returns (resume: bool, session_dir: Path|None).

    Interactive runs are shown exactly what the unfinished session already
    produced and asked. Unattended runs (--auto, or no TTY) never silently
    adopt an old session — stale recon data reused without anyone looking is
    worse than a clean re-scan — they print the hint and start fresh unless
    --resume was passed explicitly.
    """
    slug     = target_slug(target)
    sessions = find_sessions(out_root, slug, completed=False)
    if not sessions:
        if force_resume:
            warn("--resume: no unfinished session found for this target — starting a fresh scan.")
        return False, None

    session_dir, state = sessions[0]
    if fresh:
        info(f"--fresh: ignoring the unfinished session {Path(session_dir).name}")
        return False, None

    print_state_table(session_dir, state)

    if force_resume:
        ok("--resume: continuing this session — completed stages will be skipped.")
        return True, Path(session_dir)

    if auto or not sys.stdin.isatty():
        warn("Unattended run — starting a FRESH scan. Add --resume to continue the session above.")
        return False, None

    if ask_yes_no("Resume this scan? (completed stages are skipped, their results are reloaded)",
                  default="y"):
        return True, Path(session_dir)
    info("Starting a fresh scan instead.")
    return False, None


# ══════════════════════════════════════════════════════════════════════════════
# Preflight doctor (--doctor)
# ══════════════════════════════════════════════════════════════════════════════
# A recon pipeline that silently degrades is worse than one that refuses to
# start: a missing subfinder does not crash anything, it just quietly produces
# a scan with no subdomains. The doctor makes that visible up front — every
# external binary, Python dependency and path the pipeline depends on, and what
# specifically breaks when each is absent.
#
#   critical    -> a core stage produces nothing without it
#   recommended -> a stage still runs, but with noticeably less coverage
#   optional    -> a bonus capability (Tor rotation, OOB callbacks, ...)
_TOOL_CHECKS = [
    ("subfinder",         "critical",    "Stage 2 — main subdomain enumeration"),
    ("httpx",             "critical",    "Stage 3/4/11 — alive-host validation + fingerprinting"),
    ("katana",            "recommended", "Stage 4 — active crawling"),
    ("gau",               "recommended", "Stage 4 — passive URL discovery"),
    ("assetfinder",       "recommended", "Stage 2 — extra subdomain source"),
    ("findomain",         "recommended", "Stage 2 — extra subdomain source"),
    ("dnsx",              "recommended", "Stage 3 — DNS validation"),
    ("dig",               "recommended", "Stage 12 — CNAME / subdomain-takeover checks"),
    ("dalfox",            "recommended", "Scan Center — XSS, after the recon report"),
    ("nuclei",            "recommended", "Scan Center — vulnerability scan, after the recon report"),
    ("arjun",             "recommended", "Stage 9 — hidden parameter brute force"),
    ("whatweb",           "recommended", "Stage 1/11 — technology fingerprinting"),
    ("wafw00f",           "optional",    "Stage 1 — WAF fingerprinting"),
    ("naabu",             "recommended", "Stage 14 — network/port discovery during recon"),
    ("nmap",              "recommended", "Stage 1 + Stage 14 — port/service + version detection"),
    ("openredirex",       "recommended", "Stage 15 — open-redirect fuzzing"),
    ("trufflehog",        "recommended", "Scan Center — JS secret detection on the downloaded scripts"),
    ("interactsh-client", "optional",    "Stage 6 — blind-XSS OOB callback"),
    ("tor",               "optional",    "Automatic IP rotation when blocked"),
]

_PY_CHECKS = [
    ("yaml",      "critical",    "config.yaml parsing"),
    ("requests",  "critical",    "HTTP fallback client"),
    ("curl_cffi", "recommended", "Primary HTTP client (Cloudflare-friendly TLS)"),
    ("stem",      "optional",    "Tor control port — automatic IP rotation"),
    ("selenium",  "optional",    "Stage 6 — headless XSS proof screenshots (needs chromedriver too)"),
    ("anthropic", "optional",    "AI Analysis panel in the report (reconx_ai.py)"),
]

_SEV_STYLE = {
    "critical":    (C.RED,    "CRITICAL"),
    "recommended": (C.YELLOW, "RECOMMENDED"),
    "optional":    (C.DIM,    "OPTIONAL"),
}


def _doctor_row(present, name, severity, why):
    mark  = f"{C.GREEN}✓{C.RESET}" if present else (
            f"{C.RED}✗{C.RESET}" if severity == "critical" else f"{C.YELLOW}○{C.RESET}")
    color, label = _SEV_STYLE[severity]
    tail = "" if present else f"  {color}[{label}]{C.RESET} {C.DIM}{why}{C.RESET}"
    print(f"  {mark} {name:<20}{tail}", flush=True)


def run_doctor(cfg, config_path=None) -> int:
    """Print a full environment report. Exit code 1 if anything critical is
    missing, so it is usable as a CI/pre-scan gate."""
    print(f"\n{C.CYAN}{C.BOLD}{'═'*60}\n  RECONX DOCTOR — environment preflight\n{'═'*60}{C.RESET}")
    missing_critical = []

    print(f"\n{C.BOLD}External tools{C.RESET}")
    for name, severity, why in _TOOL_CHECKS:
        present = bool(_pd_httpx()) if name == "httpx" else tool_exists(name)
        _doctor_row(present, name, severity, why)
        if not present and severity == "critical":
            missing_critical.append(name)

    print(f"\n{C.BOLD}Python packages{C.RESET}")
    for mod, severity, why in _PY_CHECKS:
        try:
            __import__(mod)
            present = True
        except Exception:
            present = False
        _doctor_row(present, mod, severity, why)
        if not present and severity == "critical":
            missing_critical.append(mod)

    print(f"\n{C.BOLD}Configuration & paths{C.RESET}")
    cfg_p = Path(config_path) if config_path else CFG_FILE
    _doctor_row(cfg_p.exists(), cfg_p.name, "recommended",
                "config.yaml missing — built-in defaults will be used")

    out_root = Path((os.environ.get("RECONX_OUTPUT_DIR") or "").strip() or (BASE_DIR / "output"))
    writable = True
    try:
        out_root.mkdir(parents=True, exist_ok=True)
        probe = out_root / ".doctor_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except Exception:
        writable = False
    _doctor_row(writable, "output dir", "critical", f"{out_root} is not writable")
    if not writable:
        missing_critical.append("output dir")

    try:
        free_gb = shutil.disk_usage(out_root).free / (1024 ** 3)
        _doctor_row(free_gb >= 1.0, f"disk free ({free_gb:.1f} GB)", "recommended",
                    "under 1 GB free — large scans may fail to write results")
    except Exception:
        pass

    try:
        tpl = discover_nuclei_templates(str(_cfg_get(cfg, "tools", "nuclei_templates", default="") or ""))
    except Exception:
        tpl = ""
    _doctor_row(bool(tpl), "nuclei templates", "recommended",
                "no populated template directory found — nuclei falls back to built-ins")

    # The AI panel needs BOTH the SDK and a key; having one without the other
    # is the case worth naming, because the button then only ever errors.
    try:
        import anthropic  # noqa: F401
        _ai_sdk = True
    except ImportError:
        _ai_sdk = False
    _ai_key = bool(get_api_key(cfg, "anthropic"))
    _ai_on = bool(_cfg_get(cfg, "ai", "enabled", default=True))
    if _ai_on:
        # Two independent backends. The claude CLI runs on a Claude
        # subscription and needs no API key at all, so "no key" is only a
        # problem when the CLI is missing too.
        _ai_backend = str(_cfg_get(cfg, "ai", "backend", default="auto") or "auto").lower()
        _cli = shutil.which("claude") or ""
        if not _cli:
            _guess = Path.home() / ".local" / "bin" / "claude"
            _cli = str(_guess) if _guess.is_file() else ""
        _api_ok = _ai_sdk and _ai_key
        _cli_ok = bool(_cli)
        _usable = (_api_ok if _ai_backend == "api" else
                   _cli_ok if _ai_backend == "cli" else (_api_ok or _cli_ok))
        _doctor_row(_usable, "AI analysis", "optional",
                    "no usable backend — either add an Anthropic API key, or "
                    "install Claude Code to run it on a Claude subscription")
        sub(f"backend: {_ai_backend} · "
            f"API {'ready' if _api_ok else ('no key' if _ai_sdk else 'no sdk')} · "
            f"claude CLI {'ready' if _cli_ok else 'not found'}")
        if _usable:
            sub(f"model: {_cfg_get(cfg, 'ai', 'model', default='claude-opus-5')}"
                f"{' / cli ' + str(_cfg_get(cfg, 'ai', 'cli_model', default='opus')) if _cli_ok else ''} · "
                f"secrets redacted: "
                f"{str(bool(_cfg_get(cfg, 'ai', 'redact_secrets', default=True))).lower()}")

    # v9.0-fix: this used to test the SYSTEM resolver only (socket.gethostbyname),
    # and report CRITICAL + exit 1 whenever UDP/53 was blocked — even though
    # main() had already started the bundled DoH proxy and every ProjectDiscovery
    # tool in the pipeline was about to be handed "-r 127.0.0.1:<port>". On a
    # UDP/53-blocked box (labs, VPNs, cloud sandboxes) that made --doctor fail
    # a perfectly scannable environment and, used as a CI gate, block the run.
    # Check the path ReconX will ACTUALLY resolve through instead.
    try:
        import socket
        socket.setdefaulttimeout(5)
        socket.gethostbyname("example.com")
        system_dns_ok = True
    except Exception:
        system_dns_ok = False
    resolver = (os.environ.get("RECONX_RESOLVER") or "").strip()
    doh_ok = False
    if resolver:
        try:
            _h, _, _p = resolver.partition(":")
            doh_ok = bool(_udp_dns_answers(_h or "127.0.0.1", int(_p or 53)))
        except Exception:
            doh_ok = False
    dns_ok = system_dns_ok or doh_ok
    _doctor_row(dns_ok, "DNS resolution", "critical",
                "cannot resolve names — see reconx_dns.py (DoH proxy) if UDP/53 is blocked")
    if dns_ok and not system_dns_ok:
        sub(f"System DNS is down; resolving through the bundled DoH proxy at {resolver}. "
            f"httpx/nuclei/subfinder/dnsx get it via -r — katana/dalfox/gau still use "
            f"system DNS, so run the proxy on port 53 as root for full coverage.")
    if not dns_ok:
        missing_critical.append("DNS")

    # ── effective tool timeouts ──────────────────────────────────────────────
    # Printed because a ceiling that is too low doesn't look like an error: the
    # tool is killed, the stage continues, and the report reads "0 findings".
    # Seeing the real numbers is the only way to tell a quiet target from a
    # truncated scan.
    print(f"\n{C.BOLD}Tool timeouts{C.RESET} {C.DIM}(config.yaml → timeouts:){C.RESET}")
    _over = set(k for k in (cfg.get("timeouts") or {}) if k in T)
    def _hms(s):
        h, m = divmod(int(s) // 60, 60)
        return (f"{h}h{m:02d}m" if h else f"{m}m") if s >= 60 else f"{s}s"
    _row = []
    for k, v in sorted(T.items(), key=lambda kv: (-kv[1], kv[0])):
        mark = f"{C.YELLOW}*{C.RESET}" if k in _over else " "
        _row.append(f"{mark}{k} {C.DIM}{_hms(v)}{C.RESET}")
    for i in range(0, len(_row), 4):
        print("  " + "".join(f"{c:<34}" for c in _row[i:i + 4]))
    if _over:
        print(f"  {C.DIM}{C.YELLOW}*{C.RESET}{C.DIM} = overridden in config.yaml{C.RESET}")

    print(f"\n{C.DIM}{'─'*60}{C.RESET}")
    if missing_critical:
        err(f"{len(missing_critical)} critical item(s) missing: {', '.join(missing_critical)}")
        warn("Run ./install.sh (tools) and pip install -r requirements.txt (packages).")
        return 1
    ok("Environment looks good — every critical dependency is present.")
    return 0


def preflight_warn(cfg):
    """Short, non-blocking version of the doctor, printed at scan start: only
    names what is missing, so nobody discovers mid-run that stage 7 was a no-op."""
    gaps = []
    for name, severity, why in _TOOL_CHECKS:
        if severity == "optional":
            continue
        present = bool(_pd_httpx()) if name == "httpx" else tool_exists(name)
        if not present:
            gaps.append((name, severity, why))
    if not gaps:
        return
    crit = [g for g in gaps if g[1] == "critical"]
    warn(f"Preflight: {len(gaps)} tool(s) missing — run --doctor for the full report")
    for name, severity, why in (crit or gaps)[:6]:
        color, label = _SEV_STYLE[severity]
        sub(f"{color}{name}{C.RESET} — {why}")

# ── CLI ───────────────────────────────────────────────────────────────────────
def main():
    # Scan Center starts one process per button. The logo would otherwise
    # fill the live console on every click; the stage header is the label.
    show_banner = not any(a in sys.argv for a in ("-h", "--help", "--session-dir"))
    if show_banner:
        _bw = 55
        _lines = [
            f"ReconX  ·  Sequential Bug-Bounty Scanner  ·  v{VERSION}",
            "",
            "Recon → subs, URLs, tech, IPs, ports",
            "XSS, templates, JS, API, redirect: after",
            "the report, from Scan Center",
            "AI Analysis: Claude ranks what to test, in the report",
            "",
            "linkedin.com/in/2u1fuk4r",
        ]
        _box = "\n".join(f"  ║ {ln.ljust(_bw)} ║" for ln in _lines)
        print(f"""{C.CYAN}{C.BOLD}
    ██████╗ ███████╗ ██████╗  ██████╗  ███╗   ██╗ ██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝ ██╔═══██╗ ████╗  ██║ ╚██╗██╔╝
    ██████╔╝█████╗  ██║      ██║   ██║ ██╔██╗ ██║  ╚███╔╝
    ██╔══██╗██╔══╝  ██║      ██║   ██║ ██║╚██╗██║  ██╔██╗
    ██║  ██║███████╗╚██████╗ ╚██████╔╝ ██║ ╚████║ ██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝  ╚═╝  ╚═══╝ ╚═╝  ╚═╝
  ╔{'═' * (_bw + 2)}╗
{_box}
  ╚{'═' * (_bw + 2)}╝{C.RESET}""")

    p = argparse.ArgumentParser(description=f"ReconX Bug Bounty Scanner v{VERSION}")
    p.add_argument("-d", "--domain",    required=False, default=None)
    p.add_argument("-u", "--url",       nargs="+", dest="urls", metavar="URL")
    p.add_argument("-U", "--url-file",  dest="url_file", metavar="FILE")
    p.add_argument("--single",          dest="single", metavar="TARGET")
    p.add_argument("-s", "--stages",    nargs="+", type=int)
    for i in range(1, 16):
        p.add_argument(f"--stage{i}", action="store_true", help=f"Run only stage {i}")
    # On-demand scan sub-selector: restrict stage 12 (passive checks) to one
    # check so the report can expose CORS / Takeover / Bucket as separate buttons.
    p.add_argument("--check", nargs="+", dest="checks", metavar="NAME",
                   choices=["cors", "takeover", "bucket"],
                   help="With --stage12: run only these passive checks "
                        "(cors, takeover, bucket). Default: all three.")
    # --resume and --fresh are opposite answers to the same question, so let
    # argparse reject the contradiction instead of silently picking one.
    res_grp = p.add_mutually_exclusive_group()
    res_grp.add_argument("--resume",    action="store_true",
                   help="Continue the most recent unfinished scan of this target: stages already "
                        "marked done in its checkpoint file are skipped and their saved results "
                        "are reloaded. Without this flag an interactive run still offers to resume.")
    res_grp.add_argument("--fresh",     action="store_true",
                   help="Never resume — always start a new session even if an unfinished one exists.")
    p.add_argument("--doctor",          action="store_true",
                   help="Check the environment (external tools, Python packages, paths, DNS) and "
                        "exit. Exit code 1 when something critical is missing.")
    p.add_argument("--max-time",        dest="max_time", type=int, default=0, metavar="MIN",
                   help="Global wall-clock budget in minutes. When it runs out the running tool is "
                        "stopped, the scan is checkpointed and a report is written — continue later "
                        "with --resume. 0 (default) = unlimited.")
    p.add_argument("--no-diff",         dest="no_diff", action="store_true",
                   help="Skip the delta comparison against the previous completed scan of this target.")
    p.add_argument("--auto", "-y",      dest="auto", action="store_true",
                   help="Fully unattended mode: skip the stage 6 (XSS/Dalfox) and stage 7 "
                        "(Nuclei) 'run this?' confirmations and the resume prompt — the complete "
                        "pipeline runs with zero interactive input. Use this for scheduled tasks, "
                        "CI, or any run where nobody is at the keyboard.")
    # Deprecated no-op: the startup legal prompt was removed. Still accepted
    # (and ignored) so existing cron jobs / wrapper scripts keep working.
    p.add_argument("--no-legal",        action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--config",          default=str(CFG_FILE))
    p.add_argument("--session-dir",     dest="session_dir", default=None, metavar="DIR",
                   help="Run against this exact existing session directory (implies "
                        "--resume). Used by the report's on-demand Scan buttons to "
                        "attach a scan stage to the recon session it belongs to.")
    p.add_argument("--no-ai",           dest="no_ai", action="store_true",
                   help="Do not start the local AI bridge when the scan ends — open the "
                        "report as a plain file instead. The report is identical minus a "
                        "working 'AI Analysis' button; run it later with "
                        "'python3 reconx_ai.py serve <session-dir>'.")
    p.add_argument("--nuclei-templates", dest="nuclei_templates", default=None,
                   help="Override nuclei template path (e.g. /root/nuclei-templates)")
    p.add_argument("--severity",        dest="severity", default=None,
                   help="Nuclei severity filter (e.g. critical,high,medium,low)")
    p.add_argument("--blind",           dest="blind_cb", default=None,
                   help="Blind XSS callback URL for Dalfox")
    p.add_argument("--xss-payloads",    dest="xss_payloads", nargs="?", const="xss-payloads.txt",
                   default=None, metavar="FILE",
                   help="Feed dalfox an extra payload list (default: the bundled "
                        "xss-payloads.txt of WAF-bypass / context-breakout vectors) on top of its "
                        "own built-ins. OFF by default because it measured ~5x slower for no extra "
                        "findings on ordinary targets — worth it when a target reflects but dalfox's "
                        "built-ins get filtered.")

    auth_grp = p.add_argument_group("Authenticated scanning")
    auth_grp.add_argument("--login-url", dest="login_url", default=None,
                           help="Login form URL (e.g. https://target.com/login)")
    auth_grp.add_argument("--login-user", dest="login_user", default=None,
                           help="Username/email for login")
    auth_grp.add_argument("--login-pass", dest="login_pass", default=None,
                           help="Password for login")
    auth_grp.add_argument("--login-user-field", dest="login_user_field", default="username",
                           help="Form field name for username (default: username)")
    auth_grp.add_argument("--login-pass-field", dest="login_pass_field", default="password",
                           help="Form field name for password (default: password)")
    auth_grp.add_argument("--login-method", dest="login_method", default="POST",
                           choices=["POST", "GET", "post", "get"],
                           help="HTTP method used to submit the login form")
    auth_grp.add_argument("--login-extra-field", dest="login_extra_fields", action="append",
                           default=[], metavar="KEY=VALUE",
                           help="Additional static form field, repeatable (e.g. --login-extra-field remember=1)")
    auth_grp.add_argument("--login-success-indicator", dest="login_success_indicator", default=None,
                           help="String expected in response body/URL on successful login (e.g. 'Logout' or '/dashboard')")
    auth_grp.add_argument("--login-failure-indicator", dest="login_failure_indicator", default=None,
                           help="String indicating failed login (e.g. 'Invalid credentials')")
    auth_grp.add_argument("--login-csrf-field", dest="login_csrf_field", default=None,
                           help="Override CSRF token field name if auto-detection guesses wrong")
    auth_grp.add_argument("--cookie", dest="raw_cookie", default=None,
                           help="Use a raw 'k=v; k2=v2' cookie header directly instead of/in addition to login")
    auth_grp.add_argument("-r", "--request", dest="request_file", default=None, metavar="FILE",
                           help="Replay a captured raw HTTP login request (Burp/ZAP/sqlmap-style -r file)")

    args = p.parse_args()

    try:
        ensure_resilient_dns()
    except Exception as _dns_e:  # never let the DNS helper block a scan
        warn(f"DNS resilience check failed: {_dns_e}")

    cfg = load_config(Path(args.config))

    # Per-tool ceilings from config.yaml, applied before anything can run.
    _t_changed = apply_timeout_overrides(cfg)
    if _t_changed:
        info("Tool timeouts overridden from config: "
             + ", ".join(f"{k}={T[k]}s" for k in sorted(_t_changed)))

    # --doctor is a standalone environment report: no target needed, exits here.
    if args.doctor:
        sys.exit(run_doctor(cfg, config_path=args.config))

    default_scheme = (_cfg_get(cfg, "settings", "default_scheme", default="https") or "https").strip()

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

    stage_flags = [i for i in range(1, 6) if getattr(args, f"stage{i}")]
    for sf in (6, 7, 8, 9, 10, 11, 12, 13, 14, 15):
        if getattr(args, f"stage{sf}", False):
            stage_flags.append(sf)
    if stage_flags and args.stages:
        stages = sorted(set(stage_flags + list(args.stages)))
    elif stage_flags:
        stages = sorted(set(stage_flags))
    else:
        stages = args.stages

    domain = args.domain
    service_port = None
    if domain:
        # accept "*.example.com", "https://sub.example.com/path", "host:8080".
        # The bare host is the scope key. A port in -d is NOT optional noise:
        # dropping it makes every probe hit :443 while the service listens
        # somewhere else (harbor.lab:8088).
        _host, service_port = _split_host_port(domain)
        _norm = _host or _extract_domain_from_any(domain)
        if _norm and _norm != domain:
            shown = f"{_norm}:{service_port}" if service_port else _norm
            info(f"Domain normalised: {domain} → {shown}")
            domain = _norm
        elif _norm:
            domain = _norm
    if not domain:
        if url_targets:
            domain = _extract_domain_from_any(url_targets[0])
            if domain:
                info(f"Domain auto-detected: {domain}")
                if not service_port:
                    _, service_port = _split_host_port(url_targets[0])
                    if service_port:
                        info(f"Service port from URL: {service_port}")
            else:
                err("Domain could not be detected — use -d"); sys.exit(1)
        elif args.login_url:
            domain = _extract_domain_from_any(args.login_url)
            if domain:
                info(f"Domain auto-detected from login URL: {domain}")
            else:
                err("Domain could not be detected — use -d"); sys.exit(1)
        elif args.request_file:
            try:
                _req_meta = parse_request_file(args.request_file, default_scheme=default_scheme)
                domain = _extract_domain_from_any(_req_meta.get("url", ""))
                if domain:
                    info(f"Domain auto-detected from request file: {domain}")
                else:
                    err("Domain could not be detected from request file — use -d"); sys.exit(1)
            except Exception as e:
                err(f"--request parse failed: {e}"); sys.exit(1)
        elif args.session_dir:
            # An on-demand scan can omit -d: the target lives in the session.
            _st = read_state_file(args.session_dir)
            domain = _extract_domain_from_any(_st.get("target") or "") or (_st.get("target") or "")
            if domain:
                info(f"Domain from session: {domain}")
            else:
                err("--session-dir: could not read target from the session — pass -d"); sys.exit(1)
        else:
            err("-d / --domain required (or -u/--single with a URL)"); sys.exit(1)

    # Non-blocking environment check — names any missing tool that would make a
    # stage silently produce nothing. Full report: --doctor.
    preflight_warn(cfg)

    # ── checkpoint/resume decision ───────────────────────────────────────────
    # Looks for the most recent unfinished session of this target, shows what it
    # already completed and decides (flag or prompt) whether to continue it.
    _out_root = Path((os.environ.get("RECONX_OUTPUT_DIR") or "").strip() or (BASE_DIR / "output"))
    if args.session_dir:
        # v9.4: an on-demand scan launched from the report's Scan panel points
        # straight at the recon session it belongs to. This is unambiguous and,
        # unlike resolve_resume(), also adopts a session already marked
        # "completed" — which a recon-only run always is.
        sd = Path(args.session_dir).expanduser().resolve()
        if not (sd / "checkpoints").is_dir():
            err(f"--session-dir: not a ReconX session directory: {sd}")
            sys.exit(2)
        do_resume, resume_dir = True, sd
    else:
        do_resume, resume_dir = resolve_resume(_out_root, domain,
                                               force_resume=args.resume,
                                               fresh=args.fresh,
                                               auto=args.auto)

    extra_fields = {}
    for kv in (args.login_extra_fields or []):
        if "=" in kv:
            k, v = kv.split("=", 1)
            extra_fields[k.strip()] = v.strip()

    ReconPipeline(
        domain, cfg,
        resume=do_resume,
        session_dir=resume_dir,
        max_time_min=args.max_time,
        scan_diff=not args.no_diff,
        auto_mode=args.auto,
        url_targets=url_targets if url_targets else None,
        login_url=args.login_url,
        login_user=args.login_user,
        login_pass=args.login_pass,
        login_user_field=args.login_user_field,
        login_pass_field=args.login_pass_field,
        login_extra_fields=extra_fields,
        login_method=args.login_method,
        login_success_indicator=args.login_success_indicator or "",
        login_failure_indicator=args.login_failure_indicator or "",
        login_csrf_field=args.login_csrf_field or "",
        raw_cookie=args.raw_cookie,
        request_file=args.request_file,
        nuclei_templates_override=args.nuclei_templates,
        nuclei_severity_override=args.severity,
        blind_cb=args.blind_cb,
        xss_payloads=args.xss_payloads,
        config_path=str(Path(args.config)),
        ai_bridge_disabled=args.no_ai,
        only_checks=args.checks,
        service_port=service_port,
    ).run(stages=stages)

if __name__ == "__main__":
    main()
