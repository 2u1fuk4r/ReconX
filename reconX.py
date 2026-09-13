#!/usr/bin/env python3

import atexit, os, sys, re, json, yaml, time, logging, argparse, html, sqlite3, random, ipaddress
import subprocess, shutil, threading, signal, shlex, csv, tempfile
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

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

def info(m):  print(f"{C.BLUE}[*]{C.RESET} {m}", flush=True)
def ok(m):    print(f"{C.GREEN}[✓]{C.RESET} {m}", flush=True)
def warn(m):  print(f"{C.YELLOW}[!]{C.RESET} {m}", flush=True)
def err(m):   print(f"{C.RED}[✗]{C.RESET} {m}", flush=True)
def sub(m):   print(f"  {C.DIM}→{C.RESET} {m}", flush=True)

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

def _spinner(stop_evt: threading.Event, label: str):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    i = 0
    if not sys.stdout.isatty():
        return
    while not stop_evt.is_set():
        if _SPINNER_PAUSE.is_set():
            time.sleep(0.05)
            continue
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
VERSION = "8.9"
ANSI_RE  = re.compile(r"\x1b\[[0-9;]*m")

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s or "")

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


def _dns_is_healthy(hosts=("one.one.one.one", "dns.google", "example.com"), min_ok=2):
    import socket as _s
    good = 0
    for h in hosts:
        for _ in range(2):
            try:
                _s.getaddrinfo(h, 443, proto=_s.IPPROTO_TCP)
                good += 1
                break
            except OSError:
                continue
    return good >= min_ok


def _udp_dns_answers(server, port, name="cloudflare.com"):
    """Fire one raw A query at server:port and return True if we get an answer."""
    import socket as _s, struct
    q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         + b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
         + b"\x00\x00\x01\x00\x01")
    try:
        sk = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
        sk.settimeout(4)
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
    if _dns_is_healthy():
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
        },
        "api_keys": {},
        "tools": {
            "nuclei_severity": "critical,high,medium",
            "nuclei_templates": "",
            "nuclei_excluded_tags": "intrusive,dos",
            "nuclei_stats_interval": 5,
            "nuclei_tech_fastpass": True,
            "nuclei_rate_limit": 150,
            "nuclei_concurrency": 25,
            "nuclei_retries": 2,
            "blind_xss_callback": "",
            "dalfox_custom_payload": "",
            "dalfox_blind": False,
            "dalfox_test_path_only": False,
            "dalfox_path_only_max": 100,
            "dalfox_dedup_query_params": True,
            "dalfox_max_targets": 40,
            "dalfox_time_budget_sec": 2400,
            "dalfox_workers": 40,
            "dalfox_delay_ms": 0,
            "dalfox_stall_timeout_sec": 0,
            "dalfox_mass_workers": 10,
            "blind_xss_auto": True,
            "blind_xss_listen_after_sec": 90,
            "blind_xss_poll_interval": 5,
            "arjun_max_hosts": 10,
            "arjun_timeout_per_host": 180,
            "paramspider_enabled": True,
            "cors_test_origin": "https://reconx-cors-probe.invalid",
            "cloud_bucket_timeout": 10,
            "js_secrets_max_files": 200,
            "js_secrets_concurrency": 15,
            "js_secrets_request_timeout": 12,
            "js_secrets_budget_sec": 240,
            "js_secrets_patterns": "aws,gcp,azure,slack,stripe,github,jwt,private_key",
            "crtsh_timeout": 20,
            "chaos_enabled": False,
            "dnsx_enabled": True,
            "asn_lookup": True,
            "report_title": "ReconX Professional Report",
            "report_author": "",
        },
    }
    if not p.exists():
        try:
            _write_default_config_yaml(p, defaults)
            info(f"config.yaml olusturuldu (ornek sablon): {p}")
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
    """cfg (settings/api_keys/tools semasinda) icin okunabilir, yorumlu bir
    config.yaml yazar. Migrasyon sonrasi ve ilk-calistirma sablonunda kullanilir."""
    s = cfg.get("settings", {})
    t = cfg.get("tools", {})
    def _yq(v):  # YAML icin guvenli, alintili string
        s_ = str(v)
        return '"' + s_.replace('\\', '\\\\').replace('"', '\\"') + '"'
    _tpl = f"""# ReconX config.yaml — dogru sema (settings / api_keys / tools)
# Bu dosya ReconX tarafindan otomatik olusturuldu/gocuruldu.

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
  # Tor tabanli otomatik IP rotasyonu — hedef/WAF engellemesi ALGILANDIGINDA
  # devreye girer (normal istekler dogrudan gider, Tor sadece fallback'tir).
  # Gereksinim: ./install.sh (tor + stem kurar). Kendi izole SOCKS/Control
  # portlarini kullanir, sistem genelindeki bir Tor kurulumuyla CAKISMAZ.
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
  xss_verify_budget_sec: {s.get('xss_verify_budget_sec', 900)}

# Su an aktif kullanilan bir API anahtari yok — ileride eklenecek
# saglayicilar icin ayrilmis bos sema.
api_keys: {{}}

tools:
  nuclei_severity: {_yq(t.get('nuclei_severity', 'critical,high,medium'))}
  nuclei_templates: {_yq(t.get('nuclei_templates', ''))}
  nuclei_excluded_tags: {_yq(t.get('nuclei_excluded_tags', 'intrusive,dos'))}
  nuclei_stats_interval: {t.get('nuclei_stats_interval', 5)}
  nuclei_tech_fastpass: {str(t.get('nuclei_tech_fastpass', True)).lower()}
  nuclei_rate_limit: {t.get('nuclei_rate_limit', 150)}
  nuclei_concurrency: {t.get('nuclei_concurrency', 25)}
  nuclei_dast: {str(t.get('nuclei_dast', True)).lower()}
  nuclei_dast_max_urls: {t.get('nuclei_dast_max_urls', 400)}
  blind_xss_callback: {_yq(t.get('blind_xss_callback', ''))}
  dalfox_custom_payload: {_yq(t.get('dalfox_custom_payload', ''))}
  dalfox_blind: {str(t.get('dalfox_blind', False)).lower()}
  dalfox_test_path_only: {str(t.get('dalfox_test_path_only', False)).lower()}
  dalfox_path_only_max: {t.get('dalfox_path_only_max', 100)}
  dalfox_dedup_query_params: {str(t.get('dalfox_dedup_query_params', True)).lower()}
  dalfox_max_targets: {t.get('dalfox_max_targets', 40)}
  dalfox_time_budget_sec: {t.get('dalfox_time_budget_sec', 2400)}
  dalfox_parallel_jobs: {t.get('dalfox_parallel_jobs', 1)}
  dalfox_parallel_min: {t.get('dalfox_parallel_min', 8)}
  dalfox_workers: {t.get('dalfox_workers', 40)}
  dalfox_delay_ms: {t.get('dalfox_delay_ms', 0)}
  dalfox_stall_timeout_sec: {t.get('dalfox_stall_timeout_sec', 0)}
  dalfox_mass_workers: {t.get('dalfox_mass_workers', 10)}
  blind_xss_auto: {str(t.get('blind_xss_auto', True)).lower()}
  blind_xss_listen_after_sec: {t.get('blind_xss_listen_after_sec', 90)}
  blind_xss_poll_interval: {t.get('blind_xss_poll_interval', 5)}
  arjun_max_hosts: {t.get('arjun_max_hosts', 10)}
  arjun_timeout_per_host: {t.get('arjun_timeout_per_host', 180)}
  cors_test_origin: {_yq(t.get('cors_test_origin', 'https://reconx-cors-probe.invalid'))}
  cloud_bucket_timeout: {t.get('cloud_bucket_timeout', 10)}
  js_secrets_max_files: {t.get('js_secrets_max_files', 200)}
  js_secrets_concurrency: {t.get('js_secrets_concurrency', 15)}
  js_secrets_request_timeout: {t.get('js_secrets_request_timeout', 12)}
  js_secrets_budget_sec: {t.get('js_secrets_budget_sec', 240)}
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
    caps = {"is_v3": False, "headers_flag": "--header", "state_file": False}
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
    _DALFOX_CAPS_CACHE["caps"] = caps
    return caps

def _is_private_or_local_host(host: str) -> bool:
    """v8.3: true for a loopback/private/link-local IP (RFC1918, 127.0.0.0/8,
    169.254.0.0/16, etc.) or a bare "localhost". Used to skip archive-based
    discovery tools (gau: wayback/commoncrawl/otx/urlscan) that CANNOT ever
    have data for a non-routable address — retrying them against one is
    guaranteed-wasted time, confirmed against a real scan: gau burned ~160s
    across 3 attempts + retry waits, all 0 lines, against a 192.168.x.x
    target that a local dev/lab site (like ReconX's own vuln-lab) commonly
    runs on. A public IP or real domain is unaffected — this only ever
    returns True for addresses no public archive could possibly have."""
    h = (host or "").strip().lower()
    if not h or h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_private
    except ValueError:
        return False

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
                ok(f"Nuclei templates (nuclei -tl): {line}")
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
    _menu_lock  = threading.Lock()
    _raw_sigint = threading.Event()
    _watcher_started = False

    @classmethod
    def reset_op(cls):
        cls._op_skip = False

    @classmethod
    def reset_stage(cls):
        cls._stage_skip = False

    @classmethod
    def reset(cls):
        # Geriye donuk: interrupt'la ilgisiz yerlerde (orn. bir y/n
        # prompt'unun reddi sonrasi savunmacı temizlik) ikisini de temizler.
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
        cls._raw_sigint.set()

    @classmethod
    def _watch_loop(cls):
        while True:
            cls._raw_sigint.wait()
            cls._raw_sigint.clear()
            if cls._hard:
                continue
            cls._show_menu()

    @classmethod
    def _show_menu(cls):
        with cls._menu_lock:
            if cls._hard:
                return
            _SPINNER_PAUSE.set()
            try:
                with _PRINT_LOCK:
                    sys.stdout.write("\r" + " " * 100 + "\r")
                    print(f"\n{C.YELLOW}{C.BOLD}[!] Ctrl+C caught. What do you want to do?{C.RESET}")
                    print(f"  {C.WHITE}1){C.RESET} Skip this stage — everything collected so far is "
                          f"saved and the pipeline continues with the next stage")
                    print(f"  {C.WHITE}2){C.RESET} Skip only the running operation — the rest of this "
                          f"stage carries on normally")
                    print(f"  {C.WHITE}3){C.RESET} Stop the tool — the scan is checkpointed and a report "
                          f"is generated from what was collected (resume later with --resume)")
                    sys.stdout.flush()
                choice = None
                while choice not in ("1", "2", "3"):
                    if not sys.stdin.isatty():
                        choice = "3"
                        break
                    try:
                        choice = input(f"  {C.BOLD}Seciminiz [1/2/3]: {C.RESET}").strip()
                    except (EOFError, KeyboardInterrupt):
                        choice = "3"
                    if choice not in ("1", "2", "3"):
                        warn("Please enter 1, 2 or 3.")
                if choice == "1":
                    cls._stage_skip = True
                    cls._op_skip = True
                elif choice == "2":
                    cls._op_skip = True
                else:
                    cls._hard = True
                    print(f"{C.RED}[✗] Stopping — checkpointing and building a report from the "
                          f"collected data...{C.RESET}", flush=True)
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
signal.signal(signal.SIGINT,  _INT.handle)
signal.signal(signal.SIGTERM, lambda s, f: (
    setattr(_INT, "_hard", True),
    _INT._raw_sigint.set(),
    print(f"\n{C.RED}[✗] SIGTERM{C.RESET}", flush=True)
))

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

def _tor_cli_flag(tool: str, cfg: dict) -> list:
    """Tor aktif degilse veya proxy cozulemiyorsa bos liste (davranis degismez)."""
    if not _TOR_ACTIVE.is_set():
        return []
    proxy = _resolve_proxy(cfg)
    flag = _TOR_CLI_PROXY_FLAG.get(tool)
    if not (proxy and flag):
        return []
    return [flag, proxy]


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
T = {
    "whois": 120, "whatweb": 600, "wafw00f": 120, "nmap": 1800,
    "subfinder": 1800, "assetfinder": 900, "findomain": 900,
    "httpx": 1800,
    "gau": 3600, "katana": 3600,
    "nuclei": 14400,
    "nuclei_dast": 7200,
    "dalfox": 7200,
    "login": 60,
    "paramspider": 1800,
    "arjun": 3600,
    "extra_checks": 1800,
    "interactsh_startup": 20,
}

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
    "redirect", "redirect_uri", "redirect_url", "return", "returnurl", "return_url",
    "next", "goto", "url", "u", "target", "dest", "destination", "continue",
    "callback", "jsonp", "ref", "referrer", "referer", "host", "page", "view",
    "template", "lang", "locale", "filter", "sort", "tag", "category", "cat",
    "input", "value", "error", "err", "feedback", "note", "reason",
}

def _has_reflection_param(qs: str) -> bool:
    try:
        pairs = parse_qsl(qs, keep_blank_values=True)
    except Exception:
        return False
    return any((k or "").strip().lower() in _REFLECTION_PARAM_NAMES for k, _ in pairs)

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
            try:
                proc.kill()
            except Exception:
                pass
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
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


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
    'play','loadstart','wheel','scroll','select','drag','dragstart'];
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


def capture_xss_alert_screenshots(findings: list, out_dir: Path, max_shots: int = 15,
                                   nav_timeout_sec: int = 15, budget_sec: int = 900,
                                   payloads_per_point: int = 4, max_checks: int = 60) -> list:
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

    with_url = [f for f in (findings or []) if str(f.get("url", "")).startswith("http")]
    if not with_url:
        return []

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
        return []

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
        if _INT.stage_skip():
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

            fname = f"xss_{'confirmed' if confirmed else 'checked'}_{i+1}.png"
            fpath = shots_dir / fname
            if confirmed:
                try:
                    drv.execute_script(
                        "var b=document.createElement('div');"
                        "b.textContent='\U0001F534 XSS CONFIRMED — dialog fired: '+arguments[0];"
                        "b.style.cssText='position:fixed;top:0;left:0;right:0;z-index:2147483647;"
                        "background:#dc2626;color:#fff;font:bold 15px sans-serif;padding:10px 14px;"
                        "text-align:center';document.documentElement.appendChild(b);",
                        dtext or "(empty)")
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
                "screenshot": (f"07_xss/screenshots/{fname}" if (confirmed and fpath.exists()) else ""),
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

    # v8.6-fix: persist verification results to a file too, not only into
    # SUMMARY.json's stage6 entry — a later partial run (--resume -s 7) that
    # rewrites SUMMARY would otherwise erase which findings were confirmed.
    try:
        (out_dir / "xss_verified.json").write_text(
            json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

    confirmed_n = sum(1 for r in results if r["dialog_confirmed"])
    if confirmed_n:
        ok(f"XSS VERIFIED: {confirmed_n:,} finding(s) fired a real dialog in headless Chromium "
           f"(screenshots saved) — treat these as proven.")
    elif results:
        ok(f"XSS verification: replayed {len(results):,} candidate(s), none auto-fired a dialog "
           f"(may still be exploitable in the right context — check manually).")
    return results


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
    Path(path).write_text("\n".join(clean) + ("\n" if clean else ""), encoding="utf-8")
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
    3:  "Host Validation — httpx",
    4:  "URL Discovery",
    5:  "URL Categorisation",
    6:  "XSS Testing — Dalfox",
    7:  "Nuclei Vulnerability Scan",
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
        self.save()

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
        pending = sorted(
            (k for k, v in (self.data.get("stages") or {}).items()
             if isinstance(v, dict) and v.get("status") in ("failed", "partial", "running")),
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
    names = sorted({k for k, _ in pairs if k})
    return ",".join(names) if names else qs

# ── URL Categorisation (SQLite streaming) ─────────────────────────────────────
def categorise_streaming(url_file, out_dir, test_path_only: bool = True, path_only_max: int = 100,
                          dedup_query_params: bool = True):
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
    counts["xss_targets_path_only"] = 0
    counts["xss_targets_query_dedup_skipped"] = 0
    _mem_seen = set()
    _path_shapes_seen = set()
    _query_shapes_seen = set()

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
                    if _has_reflection_param(qs):
                        _w("reflection", url)
                    # v8.2: dedupe what actually reaches dalfox by (host,
                    # path-shape, sorted param-names) — ?id=1, ?id=2, ?id=3
                    # on the same path all probe the exact same injection
                    # point, so only the FIRST example of each unique shape
                    # is sent. params.txt above stays complete/undeduped
                    # (other stages may want every literal URL), this only
                    # trims dalfox's own target list.
                    if dedup_query_params:
                        q_shape = f"{parsed.netloc}{_path_shape(path)}?{_query_param_shape(qs)}"
                        if q_shape in _query_shapes_seen:
                            counts["xss_targets_query_dedup_skipped"] += 1
                        else:
                            _query_shapes_seen.add(q_shape)
                            _w("xss_targets", url)
                    else:
                        _w("xss_targets", url)
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
                    if _PAT_FORM.search(path):
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
            silent=False, stream=False, retries=2, retry_delay=5, stdin_file=None):
    # v8.8: stage_skip() zaten hard()'i de kapsar — "stage'i atla" secildiginde
    # bu stage'in KALAN cagrilari hic baslatilmadan atlanir (once baslatilip
    # hemen ardindan oldurulmesini beklemek yerine).
    if _INT.stage_skip():
        return False, ""
    _attempt = 0
    while True:
        _ok, _txt = _run_once(cmd, out_file=out_file, timeout=timeout,
                              log=log, label=label, silent=silent, stream=stream,
                              attempt=_attempt, stdin_file=stdin_file)
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
              silent=False, stream=False, attempt=0, stdin_file=None):
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
            argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
            stdin_handle = None
            try:
                if stdin_file:
                    stdin_handle = open(stdin_file, "rb")
                p = subprocess.Popen(argv, shell=False, stdin=stdin_handle,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                proc_ref[0] = p
                out, err_out = p.communicate()
            finally:
                if stdin_handle:
                    stdin_handle.close()
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
            _snippet = strip_ansi(etxt).strip().splitlines()
            if _snippet:
                for _sl in _snippet[:6]:
                    if _sl.strip():
                        print(f"  {C.DIM}  └ {_sl.strip()[:160]}{C.RESET}", flush=True)
    _INT.reset_op()
    return (not timed_out[0] and not ctrl_killed[0] and rc == 0), txt


# ── Streaming tool runner ─────────────────────────────────────────────────────
def _stream_tool(cmd, timeout: int, log=None, label: str = "",
                 line_cb=None, stall_timeout: int = 0, ok_exit_codes=(0, None)) -> tuple:
    """stall_timeout: eger > 0 ve o kadar saniye boyunca TEK BIR YENI SATIR bile
    gelmezse (arac askida kalmis / network'e sessizce takilmis olabilir), sureci
    zorla durdurur. v6.17: nuclei gibi araclarin bazen kendi ic guncelleme/
    telemetri kontrolleri yuzunden (once hicbir stdout uretmeden) tamamen
    askida kalabildigi gozlemlendi — bu onceden saatlerce (T['nuclei']=14400s)
    sessizce beklemeye yol aciyordu. Artik boyle bir durum acikca tespit edilip
    kullaniciya raporlanir.
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
    spin_label = label or (cmd[0] if isinstance(cmd, list) else cmd.split()[0])

    def _spin_ticker():
        frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        i = 0
        if not sys.stdout.isatty():
            return
        while not stop_spin.is_set():
            if _SPINNER_PAUSE.is_set():
                time.sleep(0.05)
                continue
            elapsed = round(time.time() - start, 0)
            # v8.3: shared _PRINT_LOCK with xss_live_hit() — a live finding
            # print (from a dalfox line_cb, also running on the reader
            # thread) and this spinner redraw both touch stdout with \r; the
            # lock keeps one from garbling mid-write into the other.
            with _PRINT_LOCK:
                sys.stdout.write(
                    f"\r  {C.CYAN}{frames[i % len(frames)]}{C.RESET} "
                    f"{C.DIM}{spin_label}{C.RESET} "
                    f"{C.DIM}processing {total_lines[0]:,} lines{C.RESET} "
                    f"{C.DIM}{int(elapsed)}s{C.RESET}   "
                )
                sys.stdout.flush()
            i += 1
            time.sleep(0.12)
        with _PRINT_LOCK:
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
    last_count = 0
    last_progress_ts = start
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
            if proc_ref[0]:
                try:
                    proc_ref[0].kill()
                    proc_ref[0].wait(3)
                except Exception:
                    pass
            break
        if now > deadline:
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
def check_cors_misconfig(url: str, cfg: dict, log=None) -> dict:
    """Origin header'i yansitilan/wildcard+credentials birlesimini test eder.
    Sadece header inceler; hicbir exploit/veri sizdirma denemesi yapmaz."""
    res = {"url": url, "vulnerable": False, "detail": "", "acao": "", "acac": ""}
    client, is_cffi = _get_http_client(cfg)
    if client is None:
        return res
    test_origin = (_cfg_get(cfg, "tools", "cors_test_origin",
                             default="https://reconx-cors-probe.invalid") or "").strip()
    host = _extract_domain_from_any(url) or ""
    headers = pick_header_strategy(host, cfg)
    headers["Origin"] = test_origin
    try:
        kw = dict(timeout=12, allow_redirects=True, headers=headers)
        kw["verify"] = False
        proxy = _resolve_proxy(cfg)
        if proxy:
            kw["proxies"] = {"http": proxy, "https": proxy}
        if is_cffi:
            kw["impersonate"] = _cfg_get(cfg, "settings", "curl_cffi_impersonate", default="chrome110")
        r = client.get(url, **kw)
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
    client, is_cffi = _get_http_client(cfg)
    if client is None:
        res["detail"] = f"CNAME -> {service} detected but HTTP verification could not run"
        return res
    try:
        kw = dict(timeout=10, allow_redirects=True,
                  headers=pick_header_strategy(domain, cfg))
        kw["verify"] = False
        proxy = _resolve_proxy(cfg)
        if proxy:
            kw["proxies"] = {"http": proxy, "https": proxy}
        if is_cffi:
            kw["impersonate"] = _cfg_get(cfg, "settings", "curl_cffi_impersonate", default="chrome110")
        r = client.get(f"https://{domain}", **kw)
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


def check_cloud_bucket(bucket_url: str, provider: str, cfg: dict, log=None) -> dict:
    """Bucket'in var olup olmadigini ve genel listelemeye acik olup olmadigini kontrol eder.
    Yalnizca GET/HEAD ile okur — yazma/silme denemesi asla yapilmaz."""
    res = {"url": bucket_url, "provider": provider, "status": "unknown", "public_listing": False, "detail": ""}
    client, is_cffi = _get_http_client(cfg)
    if client is None:
        return res
    timeout = int(_cfg_get(cfg, "tools", "cloud_bucket_timeout", default=10))
    try:
        kw = dict(timeout=timeout, allow_redirects=True,
                  headers={"User-Agent": _pick_ua()})
        kw["verify"] = False
        proxy = _resolve_proxy(cfg)
        if proxy:
            kw["proxies"] = {"http": proxy, "https": proxy}
        if is_cffi:
            kw["impersonate"] = _cfg_get(cfg, "settings", "curl_cffi_impersonate", default="chrome110")
        r = client.get(bucket_url, **kw)
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

class ReconPipeline:
    def __init__(self, target, cfg, resume=False, auto_mode=False,
                 url_targets=None, login_url=None, login_user=None, login_pass=None,
                 login_user_field="username", login_pass_field="password",
                 login_extra_fields=None, login_method="POST",
                 login_success_indicator="", login_failure_indicator="",
                 login_csrf_field="", raw_cookie=None, request_file=None,
                 nuclei_templates_override=None, nuclei_severity_override=None,
                 blind_cb=None, config_path=None, session_dir=None,
                 max_time_min=0, scan_diff=True):
        self.target      = target.strip()
        self.cfg         = cfg
        self._config_path = Path(config_path) if config_path else CFG_FILE
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
                f"{httpx_bin} -l {seed_file} -no-color -threads {threads} -timeout 20 -retries 2 "
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
        _probe_netloc = (_seed_parsed.netloc if (_seed_parsed and _seed_parsed.netloc) else tgt)
        _probe_scheme = (_seed_parsed.scheme if (_seed_parsed and _seed_parsed.scheme) else "https")
        _probe_base = f"{_probe_scheme}://{_probe_netloc}"
        target_ip = self._resolve_ip(tgt)
        if target_ip:
            ok(f"IP resolved: {tgt} → {target_ip}")
        else:
            warn("IP resolution failed — continuing with domain")
        try:
            probe = http_probe(_probe_base, self.cfg, timeout=12)
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
        # v6.17: eskiden "whois {tgt} || whois -H {tgt} || true" tek bir string
        # olarak run_cmd'ye veriliyordu. run_cmd, guvenlik sertlestirmesinden beri
        # (v6.11) komutlari ASLA shell uzerinden calistirmiyor — shlex.split()
        # sadece bosluklara gore boluyor, yani "||" ve "true" kelimeleri whois'e
        # DOGRUDAN GECERSIZ ARGUMAN olarak gidiyordu ve whois her seferinde
        # cakiliyordu (exit 1). Duzeltme: fallback mantigi Python tarafinda.
        ok_w, whois_out = run_cmd(["whois", tgt], timeout=T["whois"], log=self.log,
                                   label="whois", retries=1, retry_delay=3)
        if not ok_w or not whois_out.strip():
            ok_w, whois_out = run_cmd(["whois", "-H", tgt], timeout=T["whois"],
                                       log=self.log, label="whois-H", retries=1, retry_delay=3)
        if whois_out.strip():
            (d / "whois.txt").write_text(whois_out, encoding="utf-8", errors="replace")
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
                f"nmap -sV -sC --open -T4 --top-ports 1000 --min-rate 250 --version-intensity 2 {nmap_target} -oN {d}/nmap.txt",
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

        lines = [l.strip() for l in raw_f.read_text(errors="ignore").splitlines() if l.strip()]
        if tgt not in lines:
            lines.insert(0, tgt)
            write_lines(raw_f, lines)
        final = [l.strip() for l in raw_f.read_text(errors="ignore").splitlines() if l.strip()]
        n = checkpoint(self._cp("stage2_subdomains"), final, "subdomains")
        info(f"Total unique subdomains: {n:,}")
        self.summary["stage2"] = {"status": "done", "count": n}

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
        ports_flag = "-ports 80,443,8080,8443,8000,8888,9090,3000,5000 " if probe_ports else ""
        tor_flag = f"-http-proxy {_resolve_proxy(self.cfg)} " if _TOR_ACTIVE.is_set() else ""
        httpx_cmd = (
            f"{httpx_bin} -l {target_file} {noc_flag} "
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
                    except Exception:
                        continue
                    url = rec.get("url") or rec.get("input") or ""
                    if not url.startswith("http"):
                        continue
                    alive_urls.append(url)
                    status = int(rec.get("status-code") or rec.get("status_code") or 0)
                    status_cnt[status] = status_cnt.get(status, 0) + 1
        return alive_urls, status_cnt

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
        httpx_bin = _pd_httpx()
        if not httpx_bin:
            warn("httpx (ProjectDiscovery) not found — treating every subdomain "
                 "as alive")
            subs = [l.strip() for l in sub_file.read_text(errors="ignore").splitlines() if l.strip()]
            urls = sorted({f"https://{s}" if not s.startswith("http") else s for s in subs})
            n = checkpoint(self._cp("stage3_alive"), urls, "alive-nohttpx")
            self.summary["stage3"] = {"status": "done", "count": n, "note": "no-httpx"}
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
                alive_urls.append(f"https://{s}" if not s.startswith("http") else s)
        # v8.0: dnsx doğrulaması (opsiyonel) — brute-force değil, sadece passive DNS check
        if bool(_cfg_get(self.cfg, "tools", "dnsx_enabled", default=True)) and tool_exists("dnsx"):
            try:
                dnsx_tmp = d / "dnsx_validated.txt"
                run_cmd(f"dnsx -l {self._cp('stage3_alive')} -o {dnsx_tmp} -silent",
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
        base_threads = int(_cfg_get(self.cfg, "settings", "threads", default=50))
        threads = self._tuned_threads(min(base_threads, 120), 120)
        headers = pick_header_strategy(self.target, self.cfg)
        if self.has_auth():
            headers = self._auth_headers(headers)
        pruned_file = out_dir / "all_urls_live.txt"
        hh = _help_text(httpx_bin)
        noc_flag = "-no-color" if "-no-color" in hh else ""
        fc_flag = f"-fc {codes}" if codes else ""
        cmd = (
            f"{httpx_bin} -l {raw_all} {noc_flag} -silent "
            f"-threads {threads} -timeout 15 -retries 1 {fc_flag} "
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
        run_cmd(cmd, timeout=T["httpx"], log=self.log, label="httpx-url-prune",
                retries=1, retry_delay=5)
        if not pruned_file.exists() or pruned_file.stat().st_size == 0:
            warn("URL pruning produced no output (httpx error or every URL was unreachable) — "
                 "keeping the raw (unfiltered) URL list instead of risking an empty result")
            return raw_all, stats
        stats["ran"] = True
        stats["after"] = _count_lines(pruned_file)
        stats["removed"] = max(0, stats["before"] - stats["after"])
        ok(f"Dead-URL pruning: {stats['before']:,} → {stats['after']:,} live URLs "
           f"({stats['removed']:,} removed as {codes or 'dead'})")
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
        self.summary["stage4"] = {
            "status": "done", "count": n_final, "count_before_pruning": n,
            "canonicalized": bool(normalize), "prune": prune_stats,
        }

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

        for name in ["reflection", "xss_targets", "params", "forms"]:
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
    def _run_dalfox_once(self, xss_file: Path, d: Path, run_tag: str) -> dict:
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
        cmd += ["--worker", str(max(1, min(_dfx_workers, 60)))]
        if _dfx_delay > 0:
            cmd += ["--delay", str(_dfx_delay)]
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
            cpl = (_cfg_get(self.cfg, "tools", "dalfox_custom_payload", default="") or "")
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
            # v8.7-fix: this config key was documented in config.example.yaml
            # but never actually read anywhere — setting it silently had no
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
        info(f"Dalfox is running against {_count_lines(xss_file):,} targets "
             f"— progress streams below, runtime scales with the target count"
             + ("" if _dalfox_stall_sec else " (no stall limit — only the global 2h ceiling applies)"))

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
        def _dalfox_line_cb(line: str):
            s = line.strip()
            if not s or s[0] != "{":
                return
            try:
                rec = json.loads(s)
            except Exception:
                return
            if isinstance(rec, dict) and ("payload" in rec or "data" in rec) and "type" in rec:
                xss_live_hit(rec)

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
        _dfx_budget = int(_cfg_get(self.cfg, "tools", "dalfox_time_budget_sec", default=2400) or 2400)
        _dfx_budget = min(_dfx_budget, T["dalfox"]) if _dfx_budget > 0 else T["dalfox"]
        _t0 = time.time()
        rc, lines, killed, stalled = _stream_tool(
            cmd, timeout=_dfx_budget, log=self.log, label=f"dalfox-{run_tag}",
            line_cb=_dalfox_line_cb, stall_timeout=_dalfox_stall_sec,
            ok_exit_codes=_dalfox_ok_codes
        )
        res["duration_sec"] = round(time.time() - _t0, 1)
        # distinguish "we stopped dalfox at its time budget" (expected, findings
        # so far are kept) from a real user Ctrl+C — the report wording differs.
        _budget_hit = bool(killed) and not _INT.interrupted() and \
            res["duration_sec"] >= max(1, _dfx_budget - 10)
        res["budget_hit"] = _budget_hit
        res["interrupted"] = bool(killed) and not _budget_hit
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
        elif killed:
            res["tool_error"] = ("Tarama kullanici tarafindan erken durduruldu (Ctrl+C) — "
                                  "bulgular EKSIK olabilir, tum hedefler taranmamis olabilir")
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
        jobs = int(_cfg_get(self.cfg, "tools", "dalfox_parallel_jobs", default=1) or 1)
        min_targets = int(_cfg_get(self.cfg, "tools", "dalfox_parallel_min", default=8) or 8)
        if jobs <= 1 or n < min_targets or _dalfox_caps().get("is_v3") or not tool_exists("dalfox"):
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
        stage(6, "XSS Testing — Dalfox")
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
        _dfx_max = int(_cfg_get(self.cfg, "tools", "dalfox_max_targets", default=40) or 40)
        _dfx_path_only = bool(_cfg_get(self.cfg, "tools", "dalfox_test_path_only", default=False))
        try:
            raw = [l.strip() for l in xss_file.read_text(errors="ignore").splitlines() if l.strip()]
        except Exception:
            raw = []
        clean, seen_shape = [], set()
        for u in raw:
            if not u.startswith(("http://", "https://")):
                continue
            if any(c in u for c in ("\\n", "\\t", "\n", "\t", " ", "<", ">", "{", "}", "|", "^")):
                continue
            try:
                pr = urlparse(u)
                if not pr.hostname or not self._is_in_scope_url(u):
                    continue
                params = tuple(sorted(k for k, _ in parse_qsl(pr.query)))
            except Exception:
                continue
            shape = (pr.hostname, pr.path.rstrip("/"), params)
            if shape in seen_shape:
                continue
            seen_shape.add(shape)
            clean.append((u, len(params)))
        # params first, then by shorter URL (less likely to be junk)
        clean.sort(key=lambda t: (0 if t[1] else 1, len(t[0])))
        _param_urls = [u for u, n in clean if n]
        if _dfx_path_only or len(_param_urls) < 5:
            # keep path-only URLs too (config opted in, or too few real
            # injection points to fill a useful run)
            final = [u for u, _ in clean[:_dfx_max]]
        else:
            # every URL dalfox tests without a query param costs ~30s of DOM
            # mining for near-zero XSS yield — drop them
            final = _param_urls[:_dfx_max]
        if not final:
            # v8.7-fix: this fallback used to skip the scope check applied in
            # the `clean` loop above — re-apply it here too, otherwise an
            # empty `clean`/`final` (e.g. every URL failing urlparse or the
            # scope check) fed a raw, unfiltered slice straight to dalfox.
            final = [u for u in raw
                     if u.startswith(("http://", "https://")) and self._is_in_scope_url(u)][:_dfx_max]
        tested_f = d / "xss_targets_tested.txt"
        write_lines(tested_f, final)
        xss_file = tested_f
        if len(raw) > len(final):
            sub(f"Dalfox targets {len(raw)} → {len(final)} (cleanup + unique injection "
                f"points + tools.dalfox_max_targets={_dfx_max} cap)")

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
                budget_sec=int(_cfg_get(self.cfg, "settings", "xss_verify_budget_sec", default=900) or 900),
                payloads_per_point=int(_cfg_get(self.cfg, "settings", "xss_verify_payloads_per_point", default=4) or 4),
                max_checks=int(_cfg_get(self.cfg, "settings", "xss_verify_max_checks", default=60) or 60))
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
        self.xss_results = run
        self.summary["stage6"] = {
            "status": "done" if not run.get("tool_failed") else "tool_error",
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
    # Stage 7 — Nuclei Vulnerability Scan (alive hosts)
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
        cmd = ["nuclei", "-l", str(targets), "-nc", "-duc",
               "-jsonl", "-o", str(json_f),
               "-stats", "-stats-interval", stats_interval]
        cmd += ["-c", str(threads), "-rl", str(rate),
                "-timeout", str(int(_cfg_get(self.cfg, "settings", "timeout", default=20)))]
        if tpl:
            cmd += ["-t", tpl]
        if severity:
            cmd += ["-severity", severity]
        if ex_tags:
            cmd += ["-exclude-tags", ex_tags]
        if extra_tags:
            cmd += ["-tags", extra_tags]
        cmd += hdr_args
        cmd += _tor_cli_flag("nuclei", self.cfg)

        info(f"Nuclei is running against {_count_lines(targets):,} targets "
             f"(templates={res['template_path']}"
             f"{', tags=' + extra_tags if extra_tags else ''}) — progress is printed "
             f"every {stats_interval}s below")
        _t0 = time.time()
        rc, lines, killed, stalled = _stream_tool(
            cmd, timeout=T["nuclei"], log=self.log, label="nuclei", line_cb=None,
            stall_timeout=300
        )
        res["duration_sec"] = round(time.time() - _t0, 1)
        res["interrupted"] = bool(killed)
        res["stalled"] = bool(stalled)
        res["total_lines"] = lines
        res["exit_code"] = rc
        if not killed and rc not in (0, None):
            res["tool_failed"] = True
            res["tool_error"] = f"nuclei exited with code {rc} — sonuclar eksik/gecersiz olabilir (log: {dbg})"
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
                rerun_cmd = ["nuclei", "-l", str(targets), "-nc", "-duc",
                             "-jsonl", "-o", str(rerun_f),
                             "-stats", "-stats-interval", stats_interval,
                             "-c", str(max(1, threads // 2)), "-rl", str(rerun_rate),
                             "-timeout", str(int(_cfg_get(self.cfg, "settings", "timeout", default=20)))]
                if tpl:
                    rerun_cmd += ["-t", tpl]
                if severity:
                    rerun_cmd += ["-severity", severity]
                if ex_tags:
                    rerun_cmd += ["-exclude-tags", ex_tags]
                if extra_tags:
                    rerun_cmd += ["-tags", extra_tags]
                rerun_cmd += hdr_args
                rerun_cmd += _tor_cli_flag("nuclei", self.cfg)
                _rc2, _lines2, killed2, _stalled2 = _stream_tool(
                    rerun_cmd, timeout=T["nuclei"], log=self.log, label=f"nuclei-rerun-{idx}",
                    line_cb=None, stall_timeout=300
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
        if dbg.exists():
            try:
                with dbg.open("w") as fo:
                    fo.write("")
            except Exception:
                pass
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
                if len(out) >= limit:
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
        dast_max = int(_cfg_get(self.cfg, "tools", "nuclei_dast_max_urls", default=400) or 400)
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
        info(f"Nuclei DAST (fuzzing) on {len(param_urls):,} parameterised URLs — "
             f"XSS/SQLi/SSTI/LFI/cmdi/redirect fuzzing")
        _t0 = time.time()
        rc = lines = killed = stalled = None
        # v8.6-fix: the DAST pass runs right after dalfox has hammered the same
        # host for minutes — the target's edge (CDN/WAF/ALB) sometimes throttles
        # it just long enough that nuclei loads templates, gets blocked on the
        # first requests and exits in <10s with 0 findings, even though the same
        # command works fine a minute later. Detect that (fast exit + empty
        # output file) and retry once after a short cooldown.
        for _try in (1, 2):
            rc, lines, killed, stalled = _stream_tool(
                cmd, timeout=T.get("nuclei_dast", 7200), log=self.log, label=f"nuclei-dast{'' if _try == 1 else '-retry'}",
                line_cb=None, stall_timeout=600)
            _elapsed = time.time() - _t0
            _empty = not (json_f.exists() and json_f.stat().st_size > 0)
            if killed or not _empty or _elapsed > 25 or _try == 2:
                break
            warn(f"Nuclei DAST finished suspiciously fast ({_elapsed:.0f}s) and empty — the target "
                 f"probably rate-limited briefly (right after dalfox). Waiting 15s and retrying once.")
            time.sleep(15)
        res["duration_sec"] = round(time.time() - _t0, 1)
        if not killed and rc not in (0, None):
            res["tool_failed"] = True
            res["tool_error"] = f"nuclei -dast exited {rc}"
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
        else:
            ok("Nuclei DAST complete — no findings")
        return res

    def stage7_nuclei(self):
        stage(7, "Nuclei Vulnerability Scan (alive hosts)")
        d = self.out / "07_nuclei"
        d.mkdir(parents=True, exist_ok=True)
        tgt_file = d / "nuclei_targets.txt"
        # v6.12: hedef kumesi SADECE "alive" hostlar + authenticated URL'ler.
        sources = [self._cp("stage3_alive"), self._cp("stage8_authenticated_urls")]
        targets = []
        seen = set()
        for src in sources:
            if not src.exists():
                continue
            for line in src.read_text(errors="replace").splitlines():
                u = strip_ansi(line.strip())
                if not u or not u.startswith(("http://", "https://")) or not self._is_in_scope_url(u):
                    continue
                if u not in seen:
                    seen.add(u); targets.append(u)
        write_lines(tgt_file, targets)
        if not tgt_file.exists() or tgt_file.stat().st_size == 0:
            warn("No alive hosts — skipping nuclei")
            self.summary["stage7"] = {"status": "skipped", "reason": "no_alive"}
            return
        if not tool_exists("nuclei"):
            warn("nuclei not installed — skipping scan")
            self.summary["stage7"] = {"status": "skipped", "reason": "not_installed"}
            return

        # v6.13: teknoloji-bazli hizli on-tarama. Tespit edilen teknolojilere
        # (wordpress, php, jenkins, vb.) ozel nuclei taglariyla kucuk ama
        # isabetli bir on-gecis yapar; boylece ilk anlamli bulgular cok daha
        # erken gorunur. Ardindan mevcut tam-kapsamli (severity filtreli)
        # genel tarama calisir.
        # v6.15: stage7 artik sirali akista stage11'den ONCE calisiyor; tech_summary
        # henuz doldurulmamissa burada sessizce (banner basmadan) hesaplanir.
        fastpass_enabled = bool(_cfg_get(self.cfg, "tools", "nuclei_tech_fastpass", default=True))
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

        # v8.6: DAST/fuzzing pass — the part that actually finds injection bugs
        # (XSS/SQLi/SSTI/LFI/cmdi) on custom, vulnerable-by-design targets that
        # match no CVE template.
        dast = {"findings": 0, "severity_counts": {}}
        try:
            dast = self._run_nuclei_dast(d)
        except Exception as e:  # noqa: BLE001
            err(f"Nuclei DAST pass crashed: {e}")
            self.log.exception("nuclei dast fatal")
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
        self.summary["stage7"] = {
            "status": "done" if not tool_failed else "tool_error",
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
    # Stage 9 — Param/Endpoint Discovery (paramspider + arjun)
    # ══════════════════════════════════════════════════════════════════════════
    def stage9_params(self):
        stage(9, "Param Discovery (paramspider + arjun)")
        d = self.out / "09_params"
        all_params = []
        seen = set()

        subs_file = self._cp("stage2_subdomains")
        if tool_exists("paramspider"):
            pid = d / "paramspider_tmp"
            pid.mkdir(parents=True, exist_ok=True)
            paramspider_all = d / "paramspider.txt"
            domains = []
            if subs_file.exists() and subs_file.stat().st_size > 0:
                domains = [l.strip() for l in subs_file.read_text(errors="ignore").splitlines()
                           if l.strip()]
            if not domains:
                domains = [self.target]
            info(f"paramspider: {len(domains)} domain isleniyor")
            ph = _help_text("paramspider")
            ps_has_output = ("--output" in ph) or bool(re.search(r"\s-o\s", ph))
            ps_has_level  = bool(re.search(r"-l\s+LEVEL|-l\s+\d", ph))
            for dom in domains:
                if _INT.stage_skip():
                    break
                dom_dir = pid / dom
                dom_dir.mkdir(parents=True, exist_ok=True)
                txt_lines = []
                if ps_has_level:
                    ps_cmd = f"paramspider -d {dom} -l 3"
                else:
                    ps_cmd = f"paramspider -d {dom}"
                if ps_has_output:
                    ps_cmd += f" --output {dom_dir}"
                _, out_txt = run_cmd(ps_cmd, timeout=T["paramspider"], log=self.log,
                                     label=f"paramspider-{dom}", retries=1, retry_delay=5)
                if out_txt.strip():
                    for ln in out_txt.splitlines():
                        ln = strip_ansi(ln.strip())
                        if ln and ln.startswith("http") and self._is_in_scope_url(ln) and ln not in seen:
                            seen.add(ln)
                            txt_lines.append(ln)
                found = sorted([p for p in dom_dir.rglob("*.txt")
                                if p.stat().st_size > 0])
                if not found:
                    res_dom = BASE_DIR / "results" / f"{dom}.txt"
                    if res_dom.exists() and res_dom.stat().st_size > 0:
                        found = [res_dom]
                for p in found:
                    for ln in p.read_text(errors="replace").splitlines():
                        ln = strip_ansi(ln.strip())
                        if ln and ln.startswith("http") and self._is_in_scope_url(ln) and ln not in seen:
                            seen.add(ln)
                            txt_lines.append(ln)
                all_params.extend(txt_lines)
            if all_params:
                write_lines(paramspider_all, all_params)
                ok(f"paramspider: {len(all_params):,} parameterised URLs")
            else:
                warn("paramspider produced no results")
        else:
            sub("paramspider not found — skipping")

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
            info(f"arjun: probing the first {min(len(hosts), max_hosts)} alive hosts "
                 f"({per_host_t}s/host)")
            for h in hosts[:max_hosts]:
                if _INT.stage_skip():
                    break
                run_cmd(f"arjun -u {h} -oJ {arjun_out} -q",
                        timeout=per_host_t, log=self.log,
                        label=f"arjun-{urlparse(h).hostname or 'unknown'}", retries=0)
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
                ok(f"arjun: {len(arjun_res):,} parametreli URL buldu")
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

        # v6.15: yuzlerce JS dosyasi tek tek/sirali indirilince stage suresiz
        # "takili" gibi gorunuyordu (kullanici defalarca Ctrl+C basmak zorunda
        # kaliyordu). Artik: (1) analiz edilecek dosya sayisi sinirlandirilir,
        # (2) indirmeler paralel yapilir, (3) genel bir zaman butcesi asilirsa
        # tarama guvenli sekilde erken kesilir (kalan dosyalar atlanir, ne
        # kadar bulunduysa raporlanir), (4) ilerleme canli gosterilir.
        max_files    = int(_cfg_get(self.cfg, "tools", "js_secrets_max_files", default=150))
        concurrency  = max(1, int(_cfg_get(self.cfg, "tools", "js_secrets_concurrency", default=12)))
        budget_sec   = int(_cfg_get(self.cfg, "tools", "js_secrets_budget_sec", default=180))
        truncated = len(js_urls) > max_files
        js_urls_scan = js_urls[:max_files]
        if truncated:
            sub(f"JS file count ({len(js_urls):,}) hit the cap ({max_files}) — "
                f"analysing the first {max_files} files (config: js_secrets_max_files)")

        # ── TruffleHog (varsa) — paralel indirme, ilk 40 dosya ──────────────────
        th_cap = min(40, len(js_urls_scan))
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

            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                list(ex.map(_dl_for_trufflehog, js_urls_scan[:th_cap]))

            if saved[0]:
                th_out = d / "trufflehog.txt"
                run_cmd(f"trufflehog filesystem {js_dir} --json",
                        out_file=th_out, timeout=300, log=self.log,
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
                sub(f"trufflehog: {saved[0]} JS dosyasi tarandi")
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

        info(f"JS analysis starting: {len(js_urls_scan):,} files, {concurrency} in parallel, "
             f"{budget_sec}s budget")
        ex = ThreadPoolExecutor(max_workers=concurrency)
        try:
            futures = {ex.submit(_worker, u): u for u in js_urls_scan}
            last_print = start_t
            for fut in as_completed(futures):
                now = time.time()
                if _INT.stage_skip():
                    budget_hit[0] = True
                    break
                if now - start_t > budget_sec:
                    if not budget_hit[0]:
                        warn(f"JS analiz zaman butcesi ({budget_sec}s) asildi — kalan "
                             f"{len(js_urls_scan) - completed[0]:,} dosya atlaniyor "
                             f"(config: js_secrets_budget_sec ile arttirilabilir)")
                    budget_hit[0] = True
                    break
                if now - last_print >= 2:
                    sub(f"JS taraniyor: {completed[0]:,}/{len(js_urls_scan):,} "
                        f"({int(now - start_t)}s)")
                    last_print = now
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

        endpoints = list(dict.fromkeys(
            [x["value"] for x in details if x["type"] == "endpoint"]))
        secrets = list(dict.fromkeys(
            [x["value"] for x in details if x["type"] == "secret"]))

        write_lines(d / "endpoints.txt", endpoints)
        write_lines(d / "secrets.txt", secrets)
        (d / "secrets.json").write_text(
            json.dumps(details, indent=2, ensure_ascii=False), encoding="utf-8")

        self.js_results = {
            "details": details,
            "endpoints": len(endpoints),
            "secrets": len(secrets),
            "files": js_urls,
            "files_scanned": completed[0],
            "truncated": truncated or budget_hit[0],
        }
        self.summary["stage10"] = {
            "status": "done",
            "endpoints": len(endpoints),
            "secrets": len(secrets),
            "js_files": len(js_urls),
            "js_files_scanned": completed[0],
            "truncated": truncated or budget_hit[0],
        }
        elapsed = round(time.time() - start_t, 1)
        ok(f"JS analysis complete ({elapsed}s, {completed[0]:,}/{len(js_urls_scan):,} files) — "
           f"{len(endpoints):,} endpoints, {len(secrets):,} secrets")

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

        ww = self.out / "01_recon" / "whatweb.txt"
        if ww.exists() and ww.stat().st_size > 0:
            for ln in ww.read_text(errors="replace").splitlines():
                ln = strip_ansi(ln.strip())
                if not ln:
                    continue
                m = re.search(r"(https?://[^\s]+)", ln)
                if not m:
                    continue
                url = m.group(1).rstrip(",")
                found = re.findall(r"\[([^\[\]]+)\]", ln)
                host_techs.setdefault(url, {"status": 0, "techs": set()})
                for f in found:
                    name = self._normalize_tech(f.split("[")[0])
                    if name:
                        host_techs[url]["techs"].add(name)

        ranked = []
        for url, info_ in host_techs.items():
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
        ok(f"Tech prioritisation: {len(ranked):,} host — {high} high, {medium} medium")
        for r in ranked[:5]:
            sub(f"{r['risk_label'].upper():6} score={r['score']:3}  {r['url']}")

    # ══════════════════════════════════════════════════════════════════════════
    # Stage 12 — v6.13: Ekstra Guvenlik Kontrolleri (CORS / Takeover / Bucket)
    # ══════════════════════════════════════════════════════════════════════════
    def stage12_extra_checks(self):
        stage(12, "Extra Security Checks (CORS / Takeover / Cloud Bucket)")
        d = self.out / "12_extra"
        results = {"cors": [], "takeover": [], "buckets": []}

        # ── CORS misconfig — alive hostlarin ana sayfalarinda test ─────────────
        alive_file = self._cp("stage3_alive")
        alive_urls = []
        if alive_file.exists() and alive_file.stat().st_size > 0:
            alive_urls = [l.strip() for l in alive_file.read_text(errors="ignore").splitlines() if l.strip()]
        if alive_urls:
            info(f"CORS testi: {len(alive_urls):,} alive host")
            jitter = float(_cfg_get(self.cfg, "settings", "jitter_max", default=0.6) or 0)
            for i, u in enumerate(alive_urls):
                if _INT.stage_skip():
                    break
                if i:
                    time.sleep(random.random() * jitter)  # v6.17-fix: hedef/yuk koruma
                r = check_cors_misconfig(u, self.cfg, log=self.log)
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
        if subs_file.exists() and subs_file.stat().st_size > 0:
            subs = [l.strip() for l in subs_file.read_text(errors="ignore").splitlines() if l.strip()]
        if subs and tool_exists("dig"):
            info(f"Subdomain takeover check: {len(subs):,} subdomains (CNAME based)")
            jitter2 = float(_cfg_get(self.cfg, "settings", "jitter_max", default=0.6) or 0)
            for i, s in enumerate(subs):
                if _INT.stage_skip():
                    break
                if i:
                    time.sleep(random.random() * jitter2)  # v6.17-fix: hedef/yuk koruma
                r = check_subdomain_takeover(s, self.cfg, log=self.log)
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
        candidates = find_cloud_bucket_candidates(candidate_files)
        if candidates:
            info(f"Cloud bucket check: {len(candidates):,} candidates")
            jitter3 = float(_cfg_get(self.cfg, "settings", "jitter_max", default=0.6) or 0)
            for i, (bucket_url, provider) in enumerate(candidates):
                if _INT.stage_skip():
                    break
                if i:
                    time.sleep(random.random() * jitter3)  # v6.17-fix: hedef/yuk koruma
                r = check_cloud_bucket(bucket_url, provider, self.cfg, log=self.log)
                results["buckets"].append(r)
            public_buckets = [r for r in results["buckets"] if r.get("public_listing")]
            if public_buckets:
                ok(f"Cloud bucket: {len(public_buckets)} publicly listable bucket(s)!")
            else:
                ok("Cloud bucket: no publicly listable bucket found")
        else:
            sub("No cloud bucket candidates — skipped")

        (d / "extra_results.json").write_text(
            json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

        self.extra_results = results
        n_cors_vuln = sum(1 for r in results["cors"] if r.get("vulnerable"))
        n_tko_vuln = sum(1 for r in results["takeover"] if r.get("vulnerable"))
        n_bucket_vuln = sum(1 for r in results["buckets"] if r.get("public_listing"))
        self.summary["stage12"] = {
            "status": "done",
            "cors_checked": len(results["cors"]),
            "cors_vulnerable": n_cors_vuln,
            "takeover_checked": len(results["takeover"]),
            "takeover_vulnerable": n_tko_vuln,
            "bucket_checked": len(results["buckets"]),
            "bucket_public": n_bucket_vuln,
        }
        total_vuln = n_cors_vuln + n_tko_vuln + n_bucket_vuln
        if total_vuln:
            warn(f"Extra checks: {total_vuln} possible finding(s) in total (CORS={n_cors_vuln}, "
                 f"Takeover={n_tko_vuln}, Bucket={n_bucket_vuln})")
        else:
            ok("Extra checks complete — no findings")

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

        try:
            import webbrowser
            target_rp = report_path or full_report
            if target_rp:
                # Windows'ta dogru file URI: file:///C:/... (file://C:\... okunmaz)
                webbrowser.open(Path(target_rp).as_uri())
        except:
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
        for base in base_hosts:
            if _INT.stage_skip():
                break
            for cand in swagger_candidates:
                if _INT.stage_skip():
                    break
                cu = base + cand
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
            # URL-seed mode runs stage 1 and the seeder OUTSIDE the main loop, so
            # they need their own state bookkeeping — otherwise stage 1 is never
            # recorded as done and every --resume would pay for it again.
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
            self.stage0_seed_urls()
            run_stages = stages or [4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        else:
            run_stages = stages or [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]

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
        if self.auto_mode:
            info("Auto mode (--auto): all stages will run without interactive prompts.")

        # Record the plan so a later resume knows what the run was aiming at.
        self.state.planned(run_stages)
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
                if self.resume and self.state.is_done(n):
                    self._restore_stage(n)
                    continue

                if n == 6:
                    if interactive:
                        self.xss_asked = True
                        if not ask_yes_no("Run an XSS (Dalfox) scan against the high-value URLs?", default="n"):
                            self.state.finish_stage(n, "skipped", {"status": "skipped",
                                                                   "reason": "declined"})
                            _INT.reset()
                            continue
                    self.xss_chosen = True
                if n == 7:
                    if interactive:
                        self.nuclei_asked = True
                        if not ask_yes_no("Run a Nuclei vulnerability scan against the alive hosts?", default="n"):
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
    ("dalfox",            "critical",    "Stage 6 — XSS scanning"),
    ("nuclei",            "critical",    "Stage 7 — vulnerability scan + DAST fuzzing"),
    ("paramspider",       "recommended", "Stage 9 — parameter discovery"),
    ("arjun",             "recommended", "Stage 9 — hidden parameter brute force"),
    ("whatweb",           "recommended", "Stage 1/11 — technology fingerprinting"),
    ("wafw00f",           "optional",    "Stage 1 — WAF fingerprinting"),
    ("nmap",              "optional",    "Stage 1 — port/service scan"),
    ("trufflehog",        "optional",    "Stage 10 — deeper JS secret detection"),
    ("interactsh-client", "optional",    "Stage 6 — blind-XSS OOB callback"),
    ("tor",               "optional",    "Automatic IP rotation when blocked"),
]

_PY_CHECKS = [
    ("yaml",      "critical",    "config.yaml parsing"),
    ("requests",  "critical",    "HTTP fallback client"),
    ("curl_cffi", "recommended", "Primary HTTP client (Cloudflare-friendly TLS)"),
    ("stem",      "optional",    "Tor control port — automatic IP rotation"),
    ("flask",     "optional",    "Web control panel (reconx_web.py)"),
    ("playwright","optional",    "Stage 6 — headless XSS proof screenshots"),
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

    try:
        import socket
        socket.setdefaulttimeout(5)
        socket.gethostbyname("example.com")
        dns_ok = True
    except Exception:
        dns_ok = False
    _doctor_row(dns_ok, "DNS resolution", "critical",
                "cannot resolve names — see reconx_dns.py (DoH proxy) if UDP/53 is blocked")
    if not dns_ok:
        missing_critical.append("DNS")

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
    show_banner = not any(a in sys.argv for a in ("-h", "--help"))
    if show_banner:
        _bw = 55
        _lines = [
            f"ReconX  ·  Sequential Bug-Bounty Scanner  ·  v{VERSION}",
            "",
            "Recon → Subs → Alive → URLs → Params → XSS/Dalfox",
            "Nuclei + DAST fuzzing → JS-Secrets",
            "Tech-Priority → API Discovery   ·   13 stages",
            "Checkpoint/resume · scan diff · --doctor · --max-time",
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
    for i in range(1, 14):
        p.add_argument(f"--stage{i}", action="store_true", help=f"Run only stage {i}")
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
    # Deprecated: the startup legal prompt was removed, this flag is accepted
    # and ignored so existing wrappers (reconx_web.py, cron jobs) keep working.
    p.add_argument("--no-legal",        action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--config",          default=str(CFG_FILE))
    p.add_argument("--nuclei-templates", dest="nuclei_templates", default=None,
                   help="Override nuclei template path (e.g. /root/nuclei-templates)")
    p.add_argument("--severity",        dest="severity", default=None,
                   help="Nuclei severity filter (e.g. critical,high,medium)")
    p.add_argument("--blind",           dest="blind_cb", default=None,
                   help="Blind XSS callback URL for Dalfox")

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
    for sf in (6, 7, 8, 9, 10, 11, 12, 13):
        if getattr(args, f"stage{sf}", False):
            stage_flags.append(sf)
    if stage_flags and args.stages:
        stages = sorted(set(stage_flags + list(args.stages)))
    elif stage_flags:
        stages = sorted(set(stage_flags))
    else:
        stages = args.stages

    domain = args.domain
    if domain:
        # accept "*.example.com", "https://sub.example.com/path", "host:8080" —
        # normalise to the bare registrable host used for scope + output dir.
        _norm = _extract_domain_from_any(domain)
        if _norm and _norm != domain:
            info(f"Domain normalised: {domain} → {_norm}")
            domain = _norm
    if not domain:
        if url_targets:
            domain = _extract_domain_from_any(url_targets[0])
            if domain:
                info(f"Domain auto-detected: {domain}")
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
        else:
            err("-d / --domain required (or -u/--single with a URL)"); sys.exit(1)

    # Non-blocking environment check — names any missing tool that would make a
    # stage silently produce nothing. Full report: --doctor.
    preflight_warn(cfg)

    # ── checkpoint/resume decision ───────────────────────────────────────────
    # Looks for the most recent unfinished session of this target, shows what it
    # already completed and decides (flag or prompt) whether to continue it.
    _out_root = Path((os.environ.get("RECONX_OUTPUT_DIR") or "").strip() or (BASE_DIR / "output"))
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
        config_path=str(Path(args.config)),
    ).run(stages=stages)

if __name__ == "__main__":
    main()
