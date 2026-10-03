"""Operator-facing names for recon work.

The binary stays in the log and on disk. The console, the Scan Center and the
report say what the step is doing.
"""
import re
from pathlib import Path

# Longer keys first so "httpx-toolkit" wins over "httpx".
ACTIVITY = (
    ("httpx-toolkit", "HTTP probing"),
    ("interactsh-client", "Out-of-band callback"),
    ("openredirex", "Open redirect testing"),
    ("assetfinder", "Passive subdomain discovery"),
    ("subfinder", "Passive subdomain discovery"),
    ("findomain", "Passive subdomain discovery"),
    ("github-subdomains", "Passive subdomain discovery"),
    ("waybackurls", "Archive URL discovery"),
    ("trufflehog", "Secret scan"),
    ("wafw00f", "WAF detection"),
    ("whatweb", "Technology fingerprint"),
    ("hakrawler", "Deep URL discovery"),
    ("gospider", "Deep URL discovery"),
    ("feroxbuster", "Content discovery"),
    ("gobuster", "Content discovery"),
    ("dalfox", "XSS testing"),
    ("nuclei", "Template vulnerability scan"),
    ("naabu", "Port discovery"),
    ("katana", "Deep URL discovery"),
    ("dnsx", "DNS resolution"),
    ("httpx", "HTTP probing"),
    ("nmap", "Service detection"),
    ("arjun", "Parameter discovery"),
    ("amass", "Passive subdomain discovery"),
    ("ffuf", "Content discovery"),
    ("gau", "Historical URL discovery"),
    ("whois", "Registration lookup"),
    ("dig", "DNS lookup"),
    ("theharvester", "Passive OSINT"),
    ("subjack", "Subdomain takeover check"),
    ("subzy", "Subdomain takeover check"),
    ("puredns", "DNS resolution"),
    ("massdns", "DNS resolution"),
    ("shuffledns", "DNS resolution"),
    ("tlsx", "TLS analysis"),
    ("cdncheck", "CDN detection"),
)

PHRASES = (
    ("js download", "JavaScript collection"),
    ("open-redirect", "Open redirect testing"),
    ("open redirect", "Open redirect testing"),
    ("takeover", "Subdomain takeover check"),
    ("bucket", "Cloud bucket check"),
    ("cors", "CORS check"),
    ("api", "API discovery"),
    ("js", "JavaScript analysis"),
)

_TITLE = {k.lower(): title for k, title in ACTIVITY}
_ACTIVITY_RE = re.compile(
    r"\b(" + "|".join(re.escape(k) for k, _ in sorted(ACTIVITY, key=lambda kv: -len(kv[0]))) + r")\b",
    re.I,
)


def public_activity(label: str) -> str:
    """Turn a binary or run label into the work it performs."""
    raw = (label or "").strip()
    if not raw:
        return raw
    low = Path(raw).name.lower()
    for key, title in PHRASES:
        if low == key or low.startswith(key + " ") or low.startswith(key + "-"):
            return title
    token = low.split()[0]
    for key, title in ACTIVITY:
        if token == key or token.startswith(key + "-"):
            return title
    return raw


def public_text(msg) -> str:
    text = str(msg if msg is not None else "")

    def repl(m):
        return _TITLE.get(m.group(1).lower(), m.group(1))

    return _ACTIVITY_RE.sub(repl, text)


def public_payload(obj: dict) -> dict:
    """Strip binary names from a progress dict before it reaches the report."""
    if not isinstance(obj, dict):
        return obj
    out = dict(obj)
    for key in ("label", "note", "item", "rate"):
        if out.get(key):
            out[key] = public_text(out[key])
    return out
