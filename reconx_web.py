#!/usr/bin/env python3
"""
reconx_web.py — local web control panel for ReconX.

  python3 reconx_web.py            # http://127.0.0.1:8711
  python3 reconx_web.py --port 9000 --host 0.0.0.0

Start / Stop / Pause / Resume scans, watch the log live, browse past scans and
their reports, edit config.yaml, check which external tools are installed.
One scan runs at a time. Flask only — no build step.
"""
import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

try:
    import yaml
except Exception:
    yaml = None
from flask import Flask, Response, request, jsonify, send_from_directory, abort

BASE_DIR = Path(__file__).resolve().parent
RECONX = BASE_DIR / "reconX.py"
OUTPUT_DIR = BASE_DIR / "output"
CONFIG_FILE = BASE_DIR / "config.yaml"
PYTHON = sys.executable or "python3"

EXTERNAL_TOOLS = [
    "httpx", "subfinder", "nuclei", "katana", "gau", "waybackurls", "dalfox",
    "sqlmap", "arjun", "paramspider", "interactsh-client", "trufflehog",
    "wafw00f", "whatweb", "nmap", "dnsx", "chromium", "chromedriver",
]

app = Flask(__name__)

# ── running-scan state ────────────────────────────────────────────────────────
SCAN = {
    "proc": None,          # subprocess.Popen
    "pgid": None,
    "cmd": "",
    "target": "",
    "outdir": None,        # Path — resolved once the scan creates it
    "outdir_hint": "",     # target token we expect the dir name to start with
    "started": 0.0,
    "ended": 0.0,
    "returncode": None,
    "stage": "-",
    "paused": False,
    "log": deque(maxlen=6000),
    "log_seq": 0,
    "lock": threading.Lock(),
}

_STAGE_RE = re.compile(r"STAGE\s+([0-9A-Za-z✦]+)\s*:\s*(.+?)\s*$")
_COMPLETE_RE = re.compile(r"SCAN COMPLETE")


def _push_log(line):
    with SCAN["lock"]:
        SCAN["log_seq"] += 1
        SCAN["log"].append((SCAN["log_seq"], line))
        m = _STAGE_RE.search(line)
        if m:
            SCAN["stage"] = f"{m.group(1)} — {m.group(2)[:48]}"
        elif _COMPLETE_RE.search(line):
            SCAN["stage"] = "complete"


def _reader(proc):
    for raw in iter(proc.stdout.readline, b""):
        try:
            line = raw.decode("utf-8", "replace").rstrip("\n")
        except Exception:
            line = repr(raw)
        # strip ANSI
        line = re.sub(r"\x1b\[[0-9;]*m", "", line)
        _push_log(line)
    proc.stdout.close()
    proc.wait()
    SCAN["returncode"] = proc.returncode
    SCAN["ended"] = time.time()
    _push_log(f"[reconx-web] process exited (code {proc.returncode})")
    # resolve the output dir now (dir name = <target>_<timestamp>)
    _resolve_outdir()


def _resolve_outdir():
    hint = SCAN.get("outdir_hint") or ""
    if not OUTPUT_DIR.exists():
        return
    cands = sorted(
        (p for p in OUTPUT_DIR.iterdir() if p.is_dir() and (not hint or p.name.startswith(hint))),
        key=lambda p: p.stat().st_mtime, reverse=True)
    if cands:
        SCAN["outdir"] = cands[0]


def _is_running():
    p = SCAN["proc"]
    return bool(p and p.poll() is None)


# ── scan discovery (past + current) ──────────────────────────────────────────
def _parse_summary(d: Path):
    sj = d / "SUMMARY.json"
    out = {"target": "", "timestamp": "", "stages": {}, "xss": 0, "xss_confirmed": 0,
           "sqli": 0, "sqli_candidates": 0, "nuclei": 0, "nuclei_dast": 0,
           "js_secrets": 0, "subs": 0, "alive": 0, "urls": 0}
    if not sj.exists():
        return out
    try:
        s = json.loads(sj.read_text(errors="ignore"))
    except Exception:
        return out
    out["target"] = s.get("target", "")
    out["timestamp"] = s.get("timestamp", "")
    st = s.get("stages", {}) or {}
    out["stages"] = {k: (v.get("status") if isinstance(v, dict) else v) for k, v in st.items()}
    s6 = st.get("stage6", {}) or {}
    out["xss"] = int(s6.get("findings", 0) or 0)
    out["xss_confirmed"] = sum(1 for x in (s6.get("screenshots") or []) if x.get("dialog_confirmed"))
    s7 = st.get("stage7", {}) or {}
    out["nuclei"] = int(s7.get("findings", 0) or 0)
    out["nuclei_dast"] = int(s7.get("findings_dast", 0) or 0)
    s14 = st.get("stage14", {}) or {}
    out["sqli"] = int(s14.get("findings_confirmed", 0) or 0)
    out["sqli_candidates"] = int(s14.get("candidates", 0) or 0)
    for key, sk in (("subs", "stage2"), ("alive", "stage3"), ("urls", "stage4")):
        out[key] = int((st.get(sk, {}) or {}).get("count", 0) or 0)
    out["js_secrets"] = len(((d / "10_js_secrets" / "secrets.json").exists()
                             and json.loads((d / "10_js_secrets" / "secrets.json").read_text(errors="ignore") or "[]")) or [])
    return out


def _scan_list():
    rows = []
    if OUTPUT_DIR.exists():
        for d in sorted(OUTPUT_DIR.iterdir(), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True):
            if not d.is_dir():
                continue
            summ = _parse_summary(d)
            running = _is_running() and SCAN["outdir"] and SCAN["outdir"].name == d.name
            rows.append({
                "name": d.name,
                "target": summ["target"] or d.name.rsplit("_", 2)[0],
                "mtime": datetime.fromtimestamp(d.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
                "has_report": (d / "report.html").exists(),
                "running": running,
                "summary": summ,
            })
    return rows


# ── routes ───────────────────────────────────────────────────────────────────
@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


@app.get("/api/state")
def api_state():
    running = _is_running()
    elapsed = (time.time() if running else (SCAN["ended"] or time.time())) - SCAN["started"] if SCAN["started"] else 0
    return jsonify({
        "running": running,
        "paused": SCAN["paused"],
        "target": SCAN["target"],
        "cmd": SCAN["cmd"],
        "stage": SCAN["stage"],
        "elapsed": int(elapsed),
        "returncode": SCAN["returncode"],
        "outdir": SCAN["outdir"].name if SCAN["outdir"] else "",
        "log_seq": SCAN["log_seq"],
    })


@app.get("/api/log")
def api_log():
    since = int(request.args.get("since", 0))
    with SCAN["lock"]:
        lines = [{"n": n, "t": t} for (n, t) in SCAN["log"] if n > since]
    return jsonify({"lines": lines, "seq": SCAN["log_seq"]})


@app.get("/api/scans")
def api_scans():
    return jsonify(_scan_list())


@app.get("/api/tools")
def api_tools():
    from shutil import which
    return jsonify([{"name": t, "path": which(t) or ""} for t in EXTERNAL_TOOLS])


@app.get("/api/config")
def api_config_get():
    txt = CONFIG_FILE.read_text(errors="ignore") if CONFIG_FILE.exists() else ""
    return jsonify({"raw": txt, "exists": CONFIG_FILE.exists()})


@app.post("/api/config")
def api_config_set():
    raw = (request.json or {}).get("raw", "")
    if yaml is not None:
        try:
            yaml.safe_load(raw)
        except Exception as e:
            return jsonify({"ok": False, "error": f"YAML invalid: {e}"}), 400
    CONFIG_FILE.write_text(raw, encoding="utf-8")
    return jsonify({"ok": True})


def _build_cmd(f):
    cmd = [PYTHON, str(RECONX)]
    mode = f.get("input_mode", "domain")
    if mode == "domain" and f.get("domain"):
        cmd += ["-d", f["domain"].strip()]
    elif mode == "urls" and f.get("urls"):
        cmd += ["-u", *[u for u in re.split(r"[\s,]+", f["urls"].strip()) if u]]
    elif mode == "single" and f.get("single"):
        cmd += ["--single", f["single"].strip()]
    elif mode == "urlfile" and f.get("urlfile"):
        cmd += ["-U", f["urlfile"].strip()]
    else:
        return None, "no target given"

    stages = f.get("stages") or []
    if stages and stages != "all":
        cmd += ["-s", *[str(int(x)) for x in stages]]
    if f.get("auto", True):
        cmd.append("--auto")
    if f.get("resume"):
        cmd.append("--resume")
    if f.get("no_legal"):
        cmd.append("--no-legal")
    if f.get("sqli_active"):
        cmd.append("--sqli-active")
    if f.get("severity"):
        cmd += ["--severity", f["severity"].strip()]
    if f.get("nuclei_templates"):
        cmd += ["--nuclei-templates", f["nuclei_templates"].strip()]
    if f.get("blind"):
        cmd += ["--blind", f["blind"].strip()]
    # auth
    if f.get("login_url"):
        cmd += ["--login-url", f["login_url"].strip()]
        for k, flag in (("login_user", "--login-user"), ("login_pass", "--login-pass"),
                        ("login_user_field", "--login-user-field"),
                        ("login_pass_field", "--login-pass-field"),
                        ("login_success", "--login-success-indicator"),
                        ("login_failure", "--login-failure-indicator")):
            if f.get(k):
                cmd += [flag, f[k]]
    if f.get("cookie"):
        cmd += ["--cookie", f["cookie"].strip()]
    if f.get("request_file"):
        cmd += ["-r", f["request_file"].strip()]
    return cmd, None


@app.post("/api/scan/start")
def api_scan_start():
    if _is_running():
        return jsonify({"ok": False, "error": "a scan is already running"}), 409
    f = request.json or {}
    cmd, err = _build_cmd(f)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    target = (f.get("domain") or f.get("single") or f.get("urls") or f.get("urlfile") or "target").strip()
    hint = re.sub(r"^https?://", "", target).split("/")[0].split()[0] if target else ""

    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    proc = subprocess.Popen(
        cmd, cwd=str(BASE_DIR), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, start_new_session=True, env=env, bufsize=1)
    with SCAN["lock"]:
        SCAN.update({"proc": proc, "pgid": os.getpgid(proc.pid), "cmd": " ".join(shlex.quote(c) for c in cmd),
                     "target": target, "outdir": None, "outdir_hint": hint,
                     "started": time.time(), "ended": 0.0, "returncode": None,
                     "stage": "starting", "paused": False})
        SCAN["log"].clear()
        SCAN["log_seq"] = 0
    _push_log(f"[reconx-web] $ {SCAN['cmd']}")
    threading.Thread(target=_reader, args=(proc,), daemon=True).start()
    return jsonify({"ok": True, "cmd": SCAN["cmd"]})


def _signal_group(sig):
    try:
        os.killpg(SCAN["pgid"], sig)
        return True
    except Exception:
        try:
            SCAN["proc"].send_signal(sig)
            return True
        except Exception:
            return False


@app.post("/api/scan/stop")
def api_scan_stop():
    if not _is_running():
        return jsonify({"ok": False, "error": "no scan running"}), 409
    if SCAN["paused"]:
        _signal_group(signal.SIGCONT)
        SCAN["paused"] = False
    _push_log("[reconx-web] stop requested — sending interrupts (a partial report will still be written)")

    def _kill():
        _signal_group(signal.SIGINT)
        time.sleep(1.2)
        _signal_group(signal.SIGINT)   # 2nd = reconX hard-exit -> writes report
        for _ in range(30):
            if not _is_running():
                return
            time.sleep(1)
        _push_log("[reconx-web] still alive after 30s — SIGTERM")
        _signal_group(signal.SIGTERM)
        time.sleep(5)
        if _is_running():
            _push_log("[reconx-web] SIGKILL")
            _signal_group(signal.SIGKILL)

    threading.Thread(target=_kill, daemon=True).start()
    return jsonify({"ok": True})


@app.post("/api/scan/pause")
def api_scan_pause():
    if not _is_running():
        return jsonify({"ok": False, "error": "no scan running"}), 409
    if SCAN["paused"]:
        return jsonify({"ok": True, "paused": True})
    if _signal_group(signal.SIGSTOP):
        SCAN["paused"] = True
        _push_log("[reconx-web] PAUSED (process group frozen). Long-lived network "
                  "connections may drop on resume.")
    return jsonify({"ok": True, "paused": SCAN["paused"]})


@app.post("/api/scan/resume-paused")
def api_scan_resume_paused():
    if not _is_running():
        return jsonify({"ok": False, "error": "no scan running"}), 409
    if _signal_group(signal.SIGCONT):
        SCAN["paused"] = False
        _push_log("[reconx-web] RESUMED")
    return jsonify({"ok": True, "paused": SCAN["paused"]})


@app.post("/api/scan/resume")
def api_scan_resume():
    """Re-launch --resume against an existing output dir's target."""
    if _is_running():
        return jsonify({"ok": False, "error": "a scan is already running"}), 409
    name = (request.json or {}).get("name", "")
    d = OUTPUT_DIR / name
    if not d.is_dir():
        return jsonify({"ok": False, "error": "unknown scan"}), 404
    summ = _parse_summary(d)
    target = summ["target"] or name.rsplit("_", 2)[0]
    f = {"input_mode": "domain", "domain": target, "auto": True, "resume": True}
    cmd, err = _build_cmd(f)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    proc = subprocess.Popen(cmd, cwd=str(BASE_DIR), stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            start_new_session=True, bufsize=1,
                            env={**os.environ, "PYTHONUNBUFFERED": "1"})
    with SCAN["lock"]:
        SCAN.update({"proc": proc, "pgid": os.getpgid(proc.pid),
                     "cmd": " ".join(shlex.quote(c) for c in cmd), "target": target,
                     "outdir": d, "outdir_hint": d.name.rsplit("_", 2)[0],
                     "started": time.time(), "ended": 0.0, "returncode": None,
                     "stage": "resuming", "paused": False})
        SCAN["log"].clear(); SCAN["log_seq"] = 0
    _push_log(f"[reconx-web] $ {SCAN['cmd']}")
    threading.Thread(target=_reader, args=(proc,), daemon=True).start()
    return jsonify({"ok": True})


@app.post("/api/scan/delete")
def api_scan_delete():
    name = (request.json or {}).get("name", "")
    d = OUTPUT_DIR / name
    if not d.is_dir() or OUTPUT_DIR not in d.parents:
        return jsonify({"ok": False, "error": "bad path"}), 400
    if _is_running() and SCAN["outdir"] and SCAN["outdir"].name == name:
        return jsonify({"ok": False, "error": "that scan is running"}), 409
    import shutil
    shutil.rmtree(d, ignore_errors=True)
    return jsonify({"ok": True})


@app.get("/report/<name>/")
@app.get("/report/<name>")
def report(name):
    d = OUTPUT_DIR / name
    if not (d / "report.html").exists():
        abort(404)
    return send_from_directory(str(d), "report.html")


@app.get("/report/<name>/<path:sub>")
def report_asset(name, sub):
    d = (OUTPUT_DIR / name).resolve()
    if OUTPUT_DIR.resolve() not in d.parents and d != OUTPUT_DIR.resolve():
        abort(403)
    return send_from_directory(str(d), sub)


# ── HTML (single page) ───────────────────────────────────────────────────────
PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconX Control Panel</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#060a14;--s1:#0f172a;--s2:#162032;--s3:#1e2e4a;--bd:#1e3a5f;--bd2:#2a4a6e;
 --tx:#e6edf5;--dim:#b8c7dc;--mut:#7a92b0;--acc:#38bdf8;--acc2:#7dd3fc;--grn:#22c55e;
 --red:#ef4444;--org:#f97316;--ylw:#eab308;--mono:'JetBrains Mono',ui-monospace,monospace;
 --sans:'Inter',system-ui,sans-serif}
body{background:var(--bg);color:var(--tx);font-family:var(--sans);font-size:14px;display:flex;min-height:100vh}
a{color:var(--acc2)}
.sb{width:210px;min-width:210px;background:rgba(15,23,42,.95);border-right:1px solid var(--bd);
 position:fixed;top:0;left:0;height:100vh;padding:18px 0;display:flex;flex-direction:column;z-index:20}
.sb h1{font-size:16px;padding:0 18px 14px;display:flex;align-items:center;gap:9px}
.sb h1 .m{width:30px;height:30px;border-radius:8px;background:linear-gradient(135deg,#38bdf8,#0284c7);
 display:flex;align-items:center;justify-content:center;font-size:15px}
.nav a{display:flex;align-items:center;gap:9px;padding:9px 18px;color:#8aaac8;cursor:pointer;
 border-left:2.5px solid transparent;font-size:13px;text-decoration:none}
.nav a:hover{background:rgba(56,189,248,.06);color:var(--tx)}
.nav a.on{background:linear-gradient(90deg,rgba(56,189,248,.14),transparent);border-left-color:var(--acc);color:#fff;font-weight:600}
.sb .foot{margin-top:auto;padding:0 18px;font-size:10.5px;color:var(--mut)}
main{margin-left:210px;flex:1;padding:26px 30px;max-width:1200px}
.pg{display:none}.pg.on{display:block}
h2{font-size:19px;margin-bottom:4px}.sub{color:var(--mut);font-size:12.5px;margin-bottom:20px}
.card{background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:18px;margin-bottom:16px}
.row{display:flex;gap:14px;flex-wrap:wrap}
label{display:block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
 color:var(--mut);margin:12px 0 5px}
input[type=text],input[type=password],select,textarea{width:100%;background:var(--s2);border:1px solid var(--bd2);
 color:var(--tx);border-radius:8px;padding:9px 11px;font-family:var(--mono);font-size:12.5px}
textarea{min-height:120px;resize:vertical;line-height:1.5}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--acc)}
.chk{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--dim);font-weight:500;
 text-transform:none;letter-spacing:0;margin:6px 14px 6px 0;cursor:pointer}
.chk input{width:auto}
button{background:var(--acc);color:#04121e;border:0;border-radius:8px;padding:10px 18px;font-weight:700;
 font-size:13px;cursor:pointer;transition:filter .15s}
button:hover{filter:brightness(1.1)}button:disabled{opacity:.4;cursor:not-allowed}
button.gray{background:var(--s3);color:var(--tx)}button.red{background:var(--red);color:#fff}
button.org{background:var(--org);color:#fff}button.grn{background:var(--grn);color:#04121e}
button.sm{padding:6px 12px;font-size:11.5px}
.stages{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px}
.log{background:#04070d;border:1px solid var(--bd);border-radius:10px;padding:12px 14px;
 font-family:var(--mono);font-size:11.5px;line-height:1.55;height:440px;overflow-y:auto;white-space:pre-wrap;color:#c9d6e6}
.log .stg{color:var(--acc2);font-weight:700}.log .ok{color:#86efac}.log .warn{color:#fde68a}.log .err{color:#fca5a5}
.badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:10.5px;font-weight:700;font-family:var(--mono)}
.b-red{background:rgba(239,68,68,.16);color:#f87171}.b-org{background:rgba(249,115,22,.16);color:#fb923c}
.b-grn{background:rgba(34,197,94,.16);color:#4ade80}.b-blue{background:rgba(56,189,248,.16);color:#7dd3fc}
.b-gray{background:rgba(120,140,170,.16);color:#9fb3cc}
.scan{display:flex;align-items:center;gap:14px;padding:13px 15px;background:var(--s1);border:1px solid var(--bd);
 border-radius:10px;margin-bottom:9px}
.scan .t{font-weight:600;font-family:var(--mono);font-size:13px}
.scan .d{color:var(--mut);font-size:11px}
.scan .badges{display:flex;gap:5px;flex-wrap:wrap;margin-left:auto}
.dot{width:8px;height:8px;border-radius:50%;background:var(--grn);box-shadow:0 0 8px var(--grn)}
.pulse{animation:p 1.4s infinite}@keyframes p{50%{opacity:.35}}
.statgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin-bottom:14px}
.stat{background:var(--s2);border:1px solid var(--bd);border-radius:10px;padding:12px 14px}
.stat .v{font-size:22px;font-weight:800}.stat .k{font-size:10.5px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
.toolrow{display:flex;justify-content:space-between;padding:7px 12px;border-bottom:1px solid var(--bd);font-family:var(--mono);font-size:12px}
.hint{font-size:11.5px;color:var(--mut);margin-top:5px}
.err-box{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);color:#fca5a5;padding:9px 12px;border-radius:8px;font-size:12px;margin-top:10px}
details{margin-top:10px}summary{cursor:pointer;color:var(--acc2);font-size:12.5px;font-weight:600}
</style></head><body>
<nav class="sb">
  <h1><span class="m">⚡</span> ReconX</h1>
  <div class="nav">
    <a data-p="run" class="on">▶  Run / Live</a>
    <a data-p="scans">🗂  Scans</a>
    <a data-p="config">⚙  Config</a>
    <a data-p="tools">🧰  Tools</a>
  </div>
  <div class="foot">Control Panel · local only<br><span id="verline"></span></div>
</nav>
<main>
  <!-- RUN -->
  <section class="pg on" id="pg-run">
    <h2>Run a scan</h2>
    <div class="sub">Launch ReconX and watch it live. One scan at a time.</div>
    <div class="card" id="form-card">
      <div class="row">
        <div style="flex:1;min-width:260px">
          <label>Target type</label>
          <select id="input_mode">
            <option value="domain">Domain  (-d, full pipeline)</option>
            <option value="single">Single URL  (--single)</option>
            <option value="urls">URL list  (-u, space/newline separated)</option>
            <option value="urlfile">URL file path  (-U)</option>
          </select>
        </div>
        <div style="flex:2;min-width:260px">
          <label id="tgt-label">Domain</label>
          <input type="text" id="target_val" placeholder="example.com">
          <textarea id="target_urls" style="display:none" placeholder="https://a.example.com/&#10;https://b.example.com/?x=1"></textarea>
        </div>
      </div>

      <label>Stages</label>
      <div style="margin-bottom:6px">
        <label class="chk"><input type="radio" name="stagemode" value="all" checked> All (1–14)</label>
        <label class="chk"><input type="radio" name="stagemode" value="pick"> Pick…</label>
      </div>
      <div class="stages" id="stagebox" style="display:none"></div>

      <label>Options</label>
      <div>
        <label class="chk"><input type="checkbox" id="auto" checked> --auto (no prompts)</label>
        <label class="chk"><input type="checkbox" id="resume"> --resume</label>
        <label class="chk"><input type="checkbox" id="no_legal"> --no-legal</label>
        <label class="chk"><input type="checkbox" id="sqli_active"> --sqli-active (run sqlmap, slow)</label>
      </div>
      <div class="row">
        <div style="flex:1;min-width:200px"><label>Nuclei severity</label><input type="text" id="severity" placeholder="critical,high,medium"></div>
        <div style="flex:1;min-width:200px"><label>Nuclei templates path</label><input type="text" id="nuclei_templates" placeholder="(default)"></div>
        <div style="flex:1;min-width:200px"><label>Blind XSS callback</label><input type="text" id="blind" placeholder="(auto via interactsh)"></div>
      </div>

      <details>
        <summary>Authenticated scanning</summary>
        <div class="row">
          <div style="flex:1;min-width:220px"><label>Login URL</label><input type="text" id="login_url"></div>
          <div style="flex:1;min-width:160px"><label>Username</label><input type="text" id="login_user"></div>
          <div style="flex:1;min-width:160px"><label>Password</label><input type="password" id="login_pass"></div>
        </div>
        <div class="row">
          <div style="flex:1"><label>User field</label><input type="text" id="login_user_field" placeholder="username"></div>
          <div style="flex:1"><label>Pass field</label><input type="text" id="login_pass_field" placeholder="password"></div>
          <div style="flex:1"><label>Success indicator</label><input type="text" id="login_success" placeholder="Logout"></div>
          <div style="flex:1"><label>Failure indicator</label><input type="text" id="login_failure"></div>
        </div>
        <div class="row">
          <div style="flex:2"><label>Raw Cookie header</label><input type="text" id="cookie" placeholder="session=...; csrf=..."></div>
          <div style="flex:1"><label>Request file (-r)</label><input type="text" id="request_file"></div>
        </div>
      </details>

      <div style="margin-top:16px">
        <button id="btn-start">▶  Start scan</button>
      </div>
      <div id="form-err"></div>
    </div>

    <div class="card" id="live-card">
      <div class="row" style="align-items:center;margin-bottom:12px">
        <span class="dot" id="livedot" style="background:var(--mut);box-shadow:none"></span>
        <b id="live-target">idle</b>
        <span class="badge b-blue" id="live-stage">–</span>
        <span class="hint" id="live-elapsed"></span>
        <div style="margin-left:auto;display:flex;gap:8px">
          <button class="org sm" id="btn-pause" disabled>⏸ Pause</button>
          <button class="grn sm" id="btn-rp" style="display:none">▶ Resume</button>
          <button class="red sm" id="btn-stop" disabled>⏹ Stop</button>
          <button class="gray sm" id="btn-open" disabled>📄 Report</button>
        </div>
      </div>
      <div class="log" id="log"></div>
      <div class="hint" id="cmdline" style="margin-top:8px;word-break:break-all"></div>
    </div>
  </section>

  <!-- SCANS -->
  <section class="pg" id="pg-scans">
    <h2>Scans</h2><div class="sub">Every run in <code>output/</code>.</div>
    <div id="scanlist"></div>
  </section>

  <!-- CONFIG -->
  <section class="pg" id="pg-config">
    <h2>config.yaml</h2><div class="sub">Edited live. Validated as YAML before save.</div>
    <div class="card">
      <textarea id="cfg" style="min-height:520px"></textarea>
      <div style="margin-top:12px"><button id="btn-cfg-save">💾 Save</button>
        <button class="gray" id="btn-cfg-reload">↻ Reload</button></div>
      <div id="cfg-msg"></div>
    </div>
  </section>

  <!-- TOOLS -->
  <section class="pg" id="pg-tools">
    <h2>External tools</h2><div class="sub">ReconX shells out to these. Missing ones just skip their stage.</div>
    <div class="card" id="toolbox"></div>
  </section>
</main>
<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const api=(u,o)=>fetch(u,o).then(r=>r.json());
let logSeq=0, poll=null;

// nav
$$('.nav a').forEach(a=>a.onclick=()=>{
  $$('.nav a').forEach(x=>x.classList.remove('on')); a.classList.add('on');
  $$('.pg').forEach(p=>p.classList.remove('on')); $('#pg-'+a.dataset.p).classList.add('on');
  if(a.dataset.p==='scans') loadScans();
  if(a.dataset.p==='config') loadCfg();
  if(a.dataset.p==='tools') loadTools();
});

// stage checkboxes
const STG=[[1,'Recon'],[2,'Subdomains'],[3,'Alive'],[4,'URLs'],[5,'Categorise'],[6,'XSS'],
 [7,'Nuclei+DAST'],[8,'Auth crawl'],[9,'Params'],[10,'JS secrets'],[11,'Tech'],[12,'Extra'],
 [13,'API'],[14,'SQLi']];
$('#stagebox').innerHTML=STG.map(([n,t])=>`<label class="chk"><input type="checkbox" class="stg" value="${n}"> ${n} ${t}</label>`).join('');
$$('input[name=stagemode]').forEach(r=>r.onchange=()=>{
  $('#stagebox').style.display=$('input[name=stagemode]:checked').value==='pick'?'grid':'none';
});
$('#input_mode').onchange=()=>{
  const m=$('#input_mode').value, lab={domain:'Domain',single:'Single URL',urls:'URLs',urlfile:'URL file path'}[m];
  $('#tgt-label').textContent=lab;
  const multi=(m==='urls');
  $('#target_val').style.display=multi?'none':'block';
  $('#target_urls').style.display=multi?'block':'none';
};

function collectForm(){
  const m=$('#input_mode').value;
  const f={input_mode:m,
    auto:$('#auto').checked, resume:$('#resume').checked, no_legal:$('#no_legal').checked,
    sqli_active:$('#sqli_active').checked,
    severity:$('#severity').value, nuclei_templates:$('#nuclei_templates').value, blind:$('#blind').value,
    login_url:$('#login_url').value, login_user:$('#login_user').value, login_pass:$('#login_pass').value,
    login_user_field:$('#login_user_field').value, login_pass_field:$('#login_pass_field').value,
    login_success:$('#login_success').value, login_failure:$('#login_failure').value,
    cookie:$('#cookie').value, request_file:$('#request_file').value};
  if(m==='urls') f.urls=$('#target_urls').value;
  else if(m==='domain') f.domain=$('#target_val').value;
  else if(m==='single') f.single=$('#target_val').value;
  else if(m==='urlfile') f.urlfile=$('#target_val').value;
  if($('input[name=stagemode]:checked').value==='pick')
    f.stages=$$('.stg:checked').map(c=>+c.value);
  return f;
}

$('#btn-start').onclick=async()=>{
  $('#form-err').innerHTML='';
  const r=await api('/api/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(collectForm())});
  if(!r.ok){ $('#form-err').innerHTML=`<div class="err-box">${r.error||'failed'}</div>`; return; }
  logSeq=0; $('#log').innerHTML=''; startPoll();
};
$('#btn-stop').onclick=()=>api('/api/scan/stop',{method:'POST'});
$('#btn-pause').onclick=()=>api('/api/scan/pause',{method:'POST'});
$('#btn-rp').onclick=()=>api('/api/scan/resume-paused',{method:'POST'});
$('#btn-open').onclick=()=>{ const n=$('#btn-open').dataset.name; if(n) window.open('/report/'+n,'_blank'); };

function fmtLine(t){
  let cls='';
  if(/^\s*STAGE /.test(t)||/={6,}/.test(t)) cls='stg';
  else if(/\[✓\]|\bok\b|CONFIRMED|VERIFIED/.test(t)) cls='ok';
  else if(/\[!\]|WARN|warn/i.test(t)) cls='warn';
  else if(/\[✗\]|ERROR|crash|Traceback/i.test(t)) cls='err';
  const e=t.replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
  return cls?`<span class="${cls}">${e}</span>`:e;
}
async function tick(){
  const st=await api('/api/state');
  const dot=$('#livedot');
  $('#live-target').textContent=st.target||'idle';
  $('#live-stage').textContent=st.stage||'–';
  $('#live-elapsed').textContent=st.elapsed?`${Math.floor(st.elapsed/60)}m ${st.elapsed%60}s`:'';
  $('#cmdline').textContent=st.cmd||'';
  const run=st.running;
  dot.style.background=run?(st.paused?'var(--org)':'var(--grn)'):'var(--mut)';
  dot.style.boxShadow=run?'0 0 8px currentColor':'none';
  dot.className='dot'+(run&&!st.paused?' pulse':'');
  $('#btn-start').disabled=run;
  $('#btn-stop').disabled=!run;
  $('#btn-pause').disabled=!run||st.paused;
  $('#btn-pause').style.display=st.paused?'none':'inline-block';
  $('#btn-rp').style.display=st.paused?'inline-block':'none';
  if(st.outdir){ $('#btn-open').disabled=false; $('#btn-open').dataset.name=st.outdir; }
  const lg=await api('/api/log?since='+logSeq);
  if(lg.lines.length){
    const box=$('#log'); const near=box.scrollTop+box.clientHeight>=box.scrollHeight-40;
    box.innerHTML+=lg.lines.map(l=>fmtLine(l.t)).join('\n')+'\n';
    logSeq=lg.seq;
    if(near) box.scrollTop=box.scrollHeight;
  }
  if(!run && st.returncode!==null && poll){ /* keep polling a bit for late log */ }
}
function startPoll(){ if(poll) clearInterval(poll); tick(); poll=setInterval(tick,1200); }

async function loadScans(){
  const rows=await api('/api/scans');
  $('#scanlist').innerHTML = rows.length? rows.map(r=>{
    const s=r.summary; const B=[];
    if(s.xss_confirmed) B.push(`<span class="badge b-red">XSS ${s.xss_confirmed}✓</span>`);
    else if(s.xss) B.push(`<span class="badge b-org">XSS ${s.xss}</span>`);
    if(s.sqli) B.push(`<span class="badge b-red">SQLi ${s.sqli}✓</span>`);
    else if(s.sqli_candidates) B.push(`<span class="badge b-org">SQLi ${s.sqli_candidates} cand</span>`);
    if(s.nuclei) B.push(`<span class="badge b-blue">Nuclei ${s.nuclei}</span>`);
    if(s.js_secrets) B.push(`<span class="badge b-org">JS ${s.js_secrets}</span>`);
    if(s.subs) B.push(`<span class="badge b-gray">${s.subs} subs</span>`);
    return `<div class="scan">
      ${r.running?'<span class="dot pulse"></span>':'<span class="dot" style="background:var(--mut);box-shadow:none"></span>'}
      <div><div class="t">${r.target}</div><div class="d">${r.mtime} · ${r.name}</div></div>
      <div class="badges">${B.join('')}</div>
      <div style="display:flex;gap:6px">
        ${r.has_report?`<button class="sm gray" onclick="window.open('/report/${r.name}','_blank')">📄 Report</button>`:''}
        <button class="sm" onclick="resumeScan('${r.name}')" ${r.running?'disabled':''}>↻ Resume</button>
        <button class="sm red" onclick="delScan('${r.name}')" ${r.running?'disabled':''}>🗑</button>
      </div></div>`;
  }).join('') : '<div class="hint">No scans yet.</div>';
}
async function resumeScan(n){
  const r=await api('/api/scan/resume',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})});
  if(r.ok){ $$('.nav a')[0].click(); logSeq=0; $('#log').innerHTML=''; startPoll(); }
  else alert(r.error||'failed');
}
async function delScan(n){ if(!confirm('Delete '+n+' ?'))return;
  await api('/api/scan/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:n})}); loadScans(); }

async function loadCfg(){ const r=await api('/api/config'); $('#cfg').value=r.raw; $('#cfg-msg').innerHTML=''; }
$('#btn-cfg-save').onclick=async()=>{
  const r=await api('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({raw:$('#cfg').value})});
  $('#cfg-msg').innerHTML = r.ok? '<div class="hint" style="color:#4ade80">Saved.</div>' : `<div class="err-box">${r.error}</div>`;
};
$('#btn-cfg-reload').onclick=loadCfg;

async function loadTools(){
  const t=await api('/api/tools');
  $('#toolbox').innerHTML=t.map(x=>`<div class="toolrow"><span>${x.name}</span>
    <span>${x.path?`<span class="badge b-grn">✓</span> <span style="color:var(--mut)">${x.path}</span>`:'<span class="badge b-red">missing</span>'}</span></div>`).join('');
}

startPoll();
</script></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description="ReconX web control panel")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8711)
    ap.add_argument("--debug", action="store_true")
    a = ap.parse_args()
    if not RECONX.exists():
        print(f"[reconx-web] reconX.py not found at {RECONX}", file=sys.stderr)
        sys.exit(1)
    print(f"[reconx-web] http://{a.host}:{a.port}  (reconX: {RECONX})", flush=True)
    app.run(host=a.host, port=a.port, debug=a.debug, threaded=True)


if __name__ == "__main__":
    main()
