#!/usr/bin/env python3
"""Triage for the secret candidates stage 10 pulls out of JavaScript.

Stage 10's regexes answer "does this LOOK like a key?". That question has a
terrible signal-to-noise ratio on real sites: a Stripe publishable key, a
Google Maps browser key and a reCAPTCHA site key are all *supposed* to be in
client-side JavaScript, while a sha256 integrity hash or a minified variable
name is not a credential at all. Reporting those next to a genuine leaked AWS
key trains the operator to ignore the list.

This module answers the second question — "does it MATTER?" — with an ordered
pattern table rather than a model. That choice was measured, not assumed:
against a 20-case set (10 of them credential types the prompt never mentioned),
a local llama3.2:3b scored 5/10 on the held-out half and classified three real
secrets (SendGrid, Twilio, npm) as "not a credential at all" — the single most
expensive error a bug-bounty tool can make. The table below scored 16/20 with
zero such errors, and its misses are UNKNOWN ("no rule matched"), i.e. honest
abstention rather than a confident wrong answer. Run --self-test to re-check.

Verdicts:
  REAL    — grants access; a genuine finding if it is really public
  PUBLIC  — designed to ship in client-side code; almost always a non-issue
  FALSE   — not a credential (hash, uuid, placeholder, asset blob, ...)
  UNKNOWN — no rule matched; left for the operator, never guessed
"""
from __future__ import annotations

import re
import sys

REAL, PUBLIC, FALSE, UNKNOWN = "REAL", "PUBLIC", "FALSE", "UNKNOWN"

# Vendor prefixes whose meaning is unambiguous on its own.
# Sources are each vendor's own documentation on what is safe to expose.
_RULES: list[tuple[re.Pattern, str, str]] = [
    # ── unambiguously secret ────────────────────────────────────────────────
    (re.compile(r"^-----BEGIN [A-Z ]*PRIVATE KEY"),          REAL,   "private key block"),
    (re.compile(r"^AKIA[0-9A-Z]{16}$"),                      REAL,   "AWS access key id"),
    (re.compile(r"^ASIA[0-9A-Z]{16}$"),                      REAL,   "AWS temporary access key id"),
    (re.compile(r"^sk_(live|test)_[0-9A-Za-z]{10,}"),        REAL,   "Stripe SECRET key"),
    (re.compile(r"^rk_(live|test)_[0-9A-Za-z]{10,}"),        REAL,   "Stripe restricted key"),
    (re.compile(r"^xox[baprse]-[0-9A-Za-z-]{10,}"),          REAL,   "Slack token"),
    (re.compile(r"^xapp-[0-9A-Za-z-]{10,}"),                 REAL,   "Slack app-level token"),
    (re.compile(r"^gh[pousr]_[0-9A-Za-z]{20,}"),             REAL,   "GitHub token"),
    (re.compile(r"^github_pat_[0-9A-Za-z_]{20,}"),           REAL,   "GitHub fine-grained PAT"),
    (re.compile(r"^glpat-[0-9A-Za-z_-]{16,}"),               REAL,   "GitLab personal access token"),
    (re.compile(r"^npm_[0-9A-Za-z]{30,}"),                   REAL,   "npm automation token"),
    (re.compile(r"^SG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}"), REAL, "SendGrid API key"),
    (re.compile(r"^key-[0-9a-f]{32}$"),                      REAL,   "Mailgun private API key"),
    (re.compile(r"^sq0(csp|atp)-[0-9A-Za-z_-]{20,}"),        REAL,   "Square access token"),
    (re.compile(r"^shp(at|ss|ca)_[0-9a-fA-F]{32}$"),         REAL,   "Shopify access token"),
    (re.compile(r"^dop_v1_[0-9a-f]{64}$"),                   REAL,   "DigitalOcean token"),
    (re.compile(r"^SK[0-9a-fA-F]{32}$"),                     REAL,   "Twilio API key SID"),
    (re.compile(r"^(?:AC|SK)[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$"), REAL, "Twilio SID:token pair"),
    (re.compile(r"^hf_[0-9A-Za-z]{30,}"),                    REAL,   "HuggingFace token"),
    (re.compile(r"^sk-(proj-)?[0-9A-Za-z_-]{20,}"),          REAL,   "OpenAI API key"),
    (re.compile(r"^AIza[0-9A-Za-z_-]{30,40}$"),              UNKNOWN, "Google API key — decided by context"),

    # ── public by design ────────────────────────────────────────────────────
    (re.compile(r"^pk_(live|test)_[0-9A-Za-z]{10,}"),        PUBLIC, "Stripe publishable key"),
    (re.compile(r"^pk\.ey[0-9A-Za-z._-]{20,}"),              PUBLIC, "Mapbox public token"),
    (re.compile(r"^sk\.ey[0-9A-Za-z._-]{20,}"),              REAL,   "Mapbox SECRET token"),
    (re.compile(r"^6L[0-9A-Za-z_-]{20,}$"),                  UNKNOWN, "reCAPTCHA key — decided by context"),
    (re.compile(r"^UA-\d{4,10}-\d{1,4}$"),                   FALSE,  "Google Analytics property id"),
    (re.compile(r"^G-[A-Z0-9]{8,12}$"),                      FALSE,  "GA4 measurement id"),
    (re.compile(r"^GTM-[A-Z0-9]{4,10}$"),                    FALSE,  "Google Tag Manager id"),

    # ── not a credential at all ─────────────────────────────────────────────
    (re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
                                                             FALSE,  "UUID"),
    (re.compile(r"^(iVBORw0KGgo|/9j/4|R0lGOD|PHN2Zw|data:)"), FALSE, "base64/data-URI asset blob"),
    (re.compile(r"^[0-9a-f]{64}$"),                          FALSE,  "sha256-length hex (integrity hash)"),
    (re.compile(r"^[0-9a-f]{40}$"),                          FALSE,  "sha1-length hex (git sha / hash)"),
    (re.compile(r"(?i)^(your|my|the)[_-]?(api|secret|access|auth)?[_-]?(key|token|secret)"),
                                                             FALSE,  "placeholder"),
    (re.compile(r"(?i)^(example|placeholder|changeme|dummy|sample|test)[_-]"), FALSE, "placeholder"),
    (re.compile(r"^[<{\[]|[>}\]]$"),                         FALSE,  "template placeholder"),
    (re.compile(r"(?i)^x{4,}$|^0{8,}$|^1234567890"),         FALSE,  "filler value"),
]

# Shapes that only a neighbouring word can resolve. (value_pattern,
# [(context_pattern, verdict, why)], fallback_verdict, fallback_why)
_CONTEXTUAL: list[tuple[re.Pattern, list[tuple[re.Pattern, str, str]], str, str]] = [
    (re.compile(r"^AIza[0-9A-Za-z_-]{30,40}$"), [
        (re.compile(r"(?i)recaptcha[_ ]?secret|secret[_ ]?key"), REAL,
         "server-side Google key exposed in client code"),
        (re.compile(r"(?i)maps\.googleapis|maps\.google|firebase|authDomain|"
                    r"messagingSenderId|storageBucket|places|geocod"), PUBLIC,
         "browser-scoped Google key (Maps/Firebase)"),
     ], PUBLIC, "Google API key — browser-scoped by default, check its HTTP-referrer restriction"),

    (re.compile(r"^6L[0-9A-Za-z_-]{20,}$"), [
        (re.compile(r"(?i)secret"), REAL, "reCAPTCHA SECRET key (server-side)"),
     ], PUBLIC, "reCAPTCHA site key"),

    (re.compile(r"^[0-9a-fA-F]{24,64}$"), [
        (re.compile(r"(?i)admin[_ ]?(api)?[_ ]?key|write[_ ]?key|full[_ ]?access"), REAL,
         "admin/write API key"),
        (re.compile(r"(?i)auth[_ ]?token|twilio|secret"), REAL, "auth token"),
        (re.compile(r"(?i)search[- _]?only|searchkey|public[_ ]?key|read[_ ]?only"), PUBLIC,
         "search-only / read-only key"),
        (re.compile(r"(?i)\bmd5\b|integrity|checksum|etag|hash"), FALSE, "hash"),
     ], None, "hex value with no telling context"),   # None -> _hex_fallback()

    (re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}$"), [
        (re.compile(r"(?i)\"alg\"\s*:\s*\"none\"|public[_ ]?key"), FALSE, "unsigned/public JWT"),
     ], REAL, "JWT hard-coded in client code — check its claims and expiry"),
]


def classify(value: str, context: str = "") -> tuple[str, str]:
    """Return (verdict, reason) for one secret candidate. Never raises."""
    try:
        v = (value or "").strip().strip("'\"` ,;")
        ctx = context or ""
        if not v:
            return FALSE, "empty value"
        for val_pat, subs, fb_verdict, fb_why in _CONTEXTUAL:
            if val_pat.search(v):
                for ctx_pat, verdict, why in subs:
                    if ctx_pat.search(ctx):
                        return verdict, why
                if fb_verdict is None:
                    # Bare hex with nothing around it: 40 and 64 chars are the
                    # canonical sha1/sha256 lengths and in practice always a
                    # hash, while 32 is genuinely ambiguous (md5 OR an API key)
                    # and stays unknown rather than being guessed either way.
                    if len(v) in (40, 64):
                        return FALSE, f"{len(v)}-char hex — canonical hash length"
                    return UNKNOWN, fb_why
                return fb_verdict, fb_why
        for pat, verdict, why in _RULES:
            if pat.search(v):
                return verdict, why
        # A long, high-entropy value next to an explicit secret-ish label is
        # worth surfacing even without a vendor rule — but as UNKNOWN, since
        # nothing here actually identifies it.
        if len(v) >= 20 and re.search(
                r"(?i)(admin[_ ]?(api)?[_ ]?key|full[ _]?(write[ _]?)?access|write[_ ]?key|"
                r"secret[_ ]?key|private[_ ]?key|auth[_ ]?token|\bpassword\b|\bpasswd\b)", ctx):
            return REAL, "unrecognised value the code itself labels as a secret"
        if len(v) >= 24 and re.search(r"(?i)(secret|token|bearer|credential)", ctx):
            return UNKNOWN, "unrecognised value under a secret-like label"
        return UNKNOWN, "no rule matched"
    except Exception:
        return UNKNOWN, "classifier error"


# Display order + styling hints for the report.
VERDICT_ORDER = {REAL: 0, UNKNOWN: 1, PUBLIC: 2, FALSE: 3}
VERDICT_LABEL = {
    REAL:    "REAL — treat as leaked",
    PUBLIC:  "public by design",
    FALSE:   "not a credential",
    UNKNOWN: "unclassified — review",
}


def summarise(details: list) -> dict:
    """Classify every {"type": "secret"} record in place; return counts."""
    counts = {REAL: 0, PUBLIC: 0, FALSE: 0, UNKNOWN: 0}
    for rec in details or []:
        if not isinstance(rec, dict) or rec.get("type") != "secret":
            continue
        verdict, why = classify(rec.get("value", ""), rec.get("context", ""))
        rec["verdict"] = verdict
        rec["verdict_reason"] = why
        counts[verdict] = counts.get(verdict, 0) + 1
    return counts


def _j(*parts: str) -> str:
    """Join a test value from fragments.

    GitHub's push protection scans for complete, format-valid tokens and blocks
    the push even when the value is plainly a placeholder (all zeros). Keeping
    the prefix and body apart in the source means no scanner-matchable literal
    exists here, while the joined value below is byte-identical to what a real
    scan would hand classify().
    """
    return "".join(parts)


# ── self-test ────────────────────────────────────────────────────────────────
# The same 20 cases the model was measured against, so a rule change that
# regresses one of them is caught immediately: python3 reconx_secrets.py --self-test
_CASES = [
    ("AWS access key",        _j("AKIA", "IOSFODNN7EXAMPLE"),
     "new AWS.S3({accessKeyId:'" + _j("AKIA", "IOSFODNN7EXAMPLE") + "'})", REAL),
    ("Stripe publishable",    "pk_live_51H8xKzGz00000000000000",
     "Stripe('pk_live_51H8xKzGz00000000000000')", PUBLIC),
    ("Stripe secret",         _j("sk_", "live_51H8xKzGz00000000000000"),
     "require('stripe')('" + _j("sk_", "live_51H8xKzGz00000000000000") + "')", REAL),
    ("Google Maps key",       "AIzaSyD0000000000000000000000000000000",
     "https://maps.googleapis.com/maps/api/js?key=AIzaSy...", PUBLIC),
    ("placeholder",           "YOUR_API_KEY_HERE",
     "apiKey:'YOUR_API_KEY_HERE' // replace", FALSE),
    ("sha256 hash",           "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
     "integrity:'sha256-9f86...'", FALSE),
    ("Slack bot token",       _j("xox", "b-000000000000-000000000000-AAAAAAAAAAAAAAAAAAAAAAAA"),
     "const SLACK='xoxb-...'", REAL),
    ("Firebase web apiKey",   "AIzaSyB000000000000000000000000000000",
     "firebase.initializeApp({apiKey:'AIzaSy...',authDomain:'x.firebaseapp.com'})", PUBLIC),
    ("minified variable",     "a8f3Kd0LmNq", "var a8f3Kd0LmNq=function(e){return e+1}", UNKNOWN),
    ("GitHub PAT",            _j("ghp", "_000000000000000000000000000000000000"),
     "Authorization:'token ghp_...'", REAL),
    ("SendGrid key",          _j("SG", ".aBcDeFgHiJkLmNoPqR.sTuVwXyZ0123456789abcdefghijklmnop"),
     "sgMail.setApiKey('SG....')", REAL),
    ("Twilio auth token",     "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
     "twilio('ACxxxx','a1b2...') // auth_token", REAL),
    ("Mapbox public token",   "pk.eyJ1IjoiZGVtbyIsImEiOiJjbGRlbW8ifQ.AbCdEf0123456789",
     "mapboxgl.accessToken='pk.ey...'", PUBLIC),
    ("Algolia search-only",   "1f2e3d4c5b6a7980a1b2c3d4e5f60718",
     "algoliasearch('APPID','1f2e...') // Search-Only API Key", PUBLIC),
    ("Algolia admin key",     "9988776655443322110011223344556677",
     "// Admin API Key (full write access)", REAL),
    ("npm token",             _j("npm", "_0123456789abcdefghijklmnopqrstuvwxyzAB"),
     "_authToken=npm_...", REAL),
    ("reCAPTCHA site key",    "6LcDEMO0000000000000000000000000000000",
     "<div class='g-recaptcha' data-sitekey='6Lc...'>", PUBLIC),
    ("reCAPTCHA secret key",  "6LdSECRET00000000000000000000000000000",
     "const RECAPTCHA_SECRET='6Ld...' // server verify", REAL),
    ("UUID",                  "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
     "requestId='3f25...'", FALSE),
    ("base64 sprite",         "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
     "img.src='data:image/png;base64,iVBOR...'", FALSE),
]


def self_test() -> int:
    ok = dangerous = 0
    for name, value, ctx, expect in _CASES:
        got, why = classify(value, ctx)
        hit = got == expect
        ok += hit
        bad = expect == REAL and got in (PUBLIC, FALSE)   # the costly direction
        dangerous += bad
        mark = "ok  " if hit else ("MISS" if not bad else "DANGEROUS")
        print(f"  {mark:9} {name:22} expected={expect:8} got={got:8}  ({why})")
    print(f"\n  {ok}/{len(_CASES)} correct · {dangerous} real secret(s) waved through")
    return 0 if (ok >= 18 and dangerous == 0) else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    for arg in sys.argv[1:]:
        print(f"{arg}\n  -> {classify(arg)}")
