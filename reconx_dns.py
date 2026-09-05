#!/usr/bin/env python3
"""
reconx_dns.py — DNS-over-HTTPS forwarding resolver for restricted networks.

Some environments (labs, VPNs, cloud sandboxes) block outbound UDP/53 to
public resolvers while leaving HTTPS/443 fully open. Every tool in the ReconX
pipeline that resolves a hostname then fails intermittently with
"could not resolve host", which silently guts the results (no XSS, no nuclei
hits, empty subdomain lists) even against deliberately-vulnerable targets.

This is a tiny standalone UDP DNS server that answers queries by asking
Cloudflare / Google over DoH (HTTPS JSON API) and re-encoding the answer as a
normal DNS response. Point /etc/resolv.conf at it and every downstream tool
(dalfox, nuclei, httpx, katana, curl_cffi, gau, ...) resolves reliably.

Usage:
    sudo python3 reconx_dns.py            # bind 127.0.0.1:53  (needs root)
    python3 reconx_dns.py --port 5300     # unprivileged port for testing

Then:
    sudo chattr -i /etc/resolv.conf 2>/dev/null || true
    echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf

Stdlib only — no third-party packages required.
"""
import argparse
import json
import socket
import struct
import sys
import threading
import time
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

DOH_ENDPOINTS = [
    "https://1.1.1.1/dns-query",
    "https://1.0.0.1/dns-query",
    "https://8.8.8.8/resolve",
    "https://dns.google/resolve",
]

_TYPE_NAMES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS",
               6: "SOA", 12: "PTR", 33: "SRV", 257: "CAA", 65: "HTTPS", 64: "SVCB"}
_TYPE_NUMS = {v: k for k, v in _TYPE_NAMES.items()}

_cache = {}          # (name, qtype) -> (expires_at, [json answers])
_cache_lock = threading.Lock()
_VERBOSE = False


def log(*a):
    if _VERBOSE:
        print("[reconx-dns]", *a, file=sys.stderr, flush=True)


def _doh_query(name, qtype_num):
    qtype = _TYPE_NAMES.get(qtype_num, str(qtype_num))
    key = (name.lower().rstrip("."), qtype)
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] > now:
            return hit[1]

    params = urllib.parse.urlencode({"name": name, "type": qtype})
    last_err = None
    for base in DOH_ENDPOINTS:
        url = f"{base}?{params}"
        try:
            req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=6) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            answers = data.get("Answer", []) or []
            ttl = min([a.get("TTL", 60) for a in answers] or [60])
            ttl = max(15, min(ttl, 900))
            with _cache_lock:
                _cache[key] = (now + ttl, answers)
            log(f"{name} {qtype} -> {len(answers)} answer(s) via {base}")
            return answers
        except Exception as e:  # noqa: BLE001
            last_err = e
            continue
    log(f"{name} {qtype} FAILED: {last_err}")
    return []


# ── minimal DNS wire format ───────────────────────────────────────────────────
def _parse_question(data):
    # header is 12 bytes; qdcount at offset 4
    qd = struct.unpack(">H", data[4:6])[0]
    if qd < 1:
        return None
    off = 12
    labels = []
    while True:
        ln = data[off]
        if ln == 0:
            off += 1
            break
        labels.append(data[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    qtype, qclass = struct.unpack(">HH", data[off:off + 4])
    off += 4
    return ".".join(labels), qtype, qclass, off


def _encode_name(name):
    out = b""
    for part in name.rstrip(".").split("."):
        try:
            pb = part.encode("ascii")
        except UnicodeEncodeError:
            pb = part.encode("idna")
        out += bytes([len(pb)]) + pb
    return out + b"\x00"


def _build_response(query, qname, qtype, qclass, qend, answers):
    txid = query[:2]
    flags = b"\x81\x80"  # standard response, recursion available, no error
    rr = b""
    count = 0
    for a in answers:
        atype = a.get("type")
        adata = a.get("data", "")
        ttl = max(15, min(int(a.get("TTL", 60)), 900))
        name_field = b"\xc0\x0c"  # pointer to question name
        try:
            if atype == 1:  # A
                rd = socket.inet_aton(adata)
            elif atype == 28:  # AAAA
                rd = socket.inet_pton(socket.AF_INET6, adata)
            elif atype in (5, 2, 12):  # CNAME / NS / PTR
                rd = _encode_name(adata)
            elif atype == 16:  # TXT
                txt = adata.strip('"').encode("utf-8", "replace")
                rd = bytes([len(txt)]) + txt
            else:
                continue
        except Exception:  # noqa: BLE001
            continue
        rr += name_field + struct.pack(">HHIH", atype, 1, ttl, len(rd)) + rd
        count += 1

    header = txid + flags + struct.pack(">HHHH", 1, count, 0, 0)
    question = query[12:qend]
    return header + question + rr


def _handle(sock, data, addr):
    try:
        parsed = _parse_question(data)
        if not parsed:
            return
        qname, qtype, qclass, qend = parsed
        answers = _doh_query(qname, qtype)
        resp = _build_response(data, qname, qtype, qclass, qend, answers)
        sock.sendto(resp, addr)
    except Exception as e:  # noqa: BLE001
        log("handler error:", e)


def serve(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    print(f"[reconx-dns] DoH forwarder listening on {host}:{port} "
          f"(upstreams: {', '.join(DOH_ENDPOINTS)})", flush=True)
    # warm the cache / self-test
    test = _doh_query("cloudflare.com", 1)
    print(f"[reconx-dns] self-test cloudflare.com -> "
          f"{[a.get('data') for a in test if a.get('type') == 1] or 'NO ANSWER'}", flush=True)
    # Bounded pool — recon tools (subfinder/dnsx) can fire thousands of
    # concurrent lookups; cap in-flight DoH requests instead of one thread each.
    pool = ThreadPoolExecutor(max_workers=64, thread_name_prefix="doh")
    while True:
        try:
            data, addr = sock.recvfrom(2048)
            pool.submit(_handle, sock, data, addr)
        except KeyboardInterrupt:
            print("\n[reconx-dns] stopped", flush=True)
            pool.shutdown(wait=False)
            return
        except Exception as e:  # noqa: BLE001
            log("recv error:", e)


def main():
    global _VERBOSE
    ap = argparse.ArgumentParser(description="DoH-forwarding UDP DNS resolver for restricted networks")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    _VERBOSE = args.verbose
    try:
        serve(args.host, args.port)
    except PermissionError:
        print(f"[reconx-dns] permission denied binding {args.host}:{args.port} — "
              f"run with sudo, or use --port 5300 for an unprivileged port.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[reconx-dns] cannot bind {args.host}:{args.port}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
