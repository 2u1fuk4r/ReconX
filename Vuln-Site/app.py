#!/usr/bin/env python3
"""Harbor Supply — local ReconX lab.

Listens on 127.0.0.1 only. Does not run shell commands, does not fetch
user-supplied URLs, and does not read files outside this directory.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

APP = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 8088

# Names only. They answer on this same loopback port when Host matches.
# Nothing here starts ssh, ftp, or a shell.
LAB_VHOSTS = ("harbor.lab", "api.harbor.lab", "legacy.harbor.lab",
              "dev.harbor.lab", "files.harbor.lab")

REDIRECT_PARAMS = {
    "url", "next", "redirect", "redirect_uri", "redirect_url", "redir",
    "redirecturl", "return", "returnurl", "return_url", "returl", "goto",
    "dest", "destination", "continue", "target", "rurl",
}

ORDERS = {
    "1001": {"id": "1001", "customer": "ada", "sku": "HX-14", "total": "128.00"},
    "1002": {"id": "1002", "customer": "lin", "sku": "VL-2", "total": "64.50",
             "note": "other customer's order — no auth check"},
}

COMMENTS: list[tuple[str, str]] = [("lin", "The HX-14 seal kit arrived intact.")]
COMMENT_LOCK = threading.Lock()
ACCOUNT = {"email": "admin@harbor.lab"}

PRODUCTS = {
    "1": ("HX-14 seal kit", "Warehouse aisle C, bin 14."),
    "2": ("VL-2 valve", "Backorder until Friday."),
}


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _layout(title: str, body: str) -> bytes:
    html = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>{_esc(title)} · Harbor Supply</title>
<link rel="stylesheet" href="/static/app.css">
</head><body>
<header>
  <a class="brand" href="/">HARBOR <span>SUPPLY</span></a>
  <nav>
    <a href="/catalog">Catalog</a>
    <a href="/search?q=seal">Search</a>
    <a href="/forum">Forum</a>
    <a href="/login">Login</a>
    <a href="/account">Account</a>
    <a href="/admin">Admin</a>
    <a href="/swagger-ui.html">API</a>
  </nav>
</header>
<main>
{body}
<footer>
  <a href="/robots.txt">robots</a> ·
  <a href="/sitemap.xml">sitemap</a> ·
  <a href="/.env">env</a> ·
  <a href="/.git/HEAD">git</a> ·
  <a href="/phpinfo">phpinfo</a> ·
  <a href="/backup/db.sql.bak">backup</a> ·
  <a href="/static/app.js">app.js</a> ·
  <a href="/download?file=guide.txt">guide</a> ·
  <a href="/preview?tpl=hello">preview</a> ·
  <a href="/go?url=/catalog">go</a> ·
  <a href="/reset?redirect=/login">reset</a> ·
  <a href="/graphql">graphql</a> ·
  <a href="/openapi.json">openapi</a>
</footer>
</main>
<script src="/static/app.js"></script>
</body></html>"""
    return html.encode("utf-8")


def _redirect_target(params: dict) -> str:
    for key, values in params.items():
        if key.lower() not in REDIRECT_PARAMS or not values:
            continue
        dest = values[0]
        if dest.startswith(("http://", "https://", "//")):
            return dest
    return ""


SWAGGER = {
    "openapi": "3.0.0",
    "info": {"title": "Harbor Supply", "version": "1.0.0"},
    "paths": {
        "/api/orders": {"get": {"summary": "Order by id, no auth"}},
        "/api/profile": {"get": {"summary": "Profile, reflects Origin"}},
        "/graphql": {"post": {"summary": "Introspection enabled"}},
    },
}


class Handler(BaseHTTPRequestHandler):
    server_version = "HarborSupply/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"[lab] {self.address_string()} {fmt % args}")

    def version_string(self):
        if self._vhost() == "legacy.harbor.lab":
            return "Apache/2.2.22 (Ubuntu)"
        return "HarborSupply/1.0"

    def _qs(self) -> dict:
        return parse_qs(urlparse(self.path).query, keep_blank_values=True)

    def _path(self) -> str:
        return urlparse(self.path).path

    def _vhost(self) -> str:
        raw = (self.headers.get("Host") or "").split(",")[0].strip().lower()
        return raw.split(":")[0]

    def _port(self) -> str:
        raw = (self.headers.get("Host") or "")
        if ":" in raw:
            return raw.rsplit(":", 1)[-1].strip() or str(PORT)
        return str(PORT)

    def _cookie(self) -> str:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "lab_session":
                return value
        return ""

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _send(self, code: int, data: bytes, content_type: str, extra: dict | None = None,
              cors: bool = False):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        powered = "PHP/5.3.10" if self._vhost() == "legacy.harbor.lab" else "PHP/5.6.40"
        self.send_header("X-Powered-By", powered)
        if cors:
            origin = self.headers.get("Origin") or ""
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_HEAD(self):
        self.do_GET()

    def _html(self, code: int, title: str, body: str, extra: dict | None = None):
        self._send(code, _layout(title, body), "text/html; charset=utf-8", extra)

    def _redirect(self, dest: str):
        self.send_response(302)
        self.send_header("Location", dest)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self._path()
        host = self._vhost()
        if host == "legacy.harbor.lab":
            self.page_legacy(path)
            return
        if host == "api.harbor.lab" and path == "/":
            self.page_api_home()
            return
        if host == "dev.harbor.lab" and path == "/":
            self.page_dev_home()
            return
        if host == "files.harbor.lab" and path == "/":
            self.page_files_home()
            return
        qs = self._qs()
        dest = _redirect_target(qs)
        if path in ("/go", "/reset", "/login", "/out") and dest:
            self._redirect(dest)
            return
        routes = {
            "/": self.page_home,
            "/search": self.page_search,
            "/catalog": self.page_catalog,
            "/catalog/item": self.page_item,
            "/forum": self.page_forum,
            "/forum/thread": self.page_thread,
            "/login": self.page_login,
            "/account": self.page_account,
            "/reset": self.page_reset,
            "/preview": self.page_preview,
            "/download": self.page_download,
            "/admin": self.page_admin,
            "/phpinfo": self.page_phpinfo,
            "/swagger-ui.html": self.page_swagger_ui,
            "/graphql": self.page_graphql_get,
            "/api/graphql": self.page_graphql_get,
        }
        if path in routes:
            routes[path]()
            return
        if path in ("/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
                    "/api-docs", "/.well-known/openapi.json"):
            raw = json.dumps(SWAGGER).encode()
            self._send(200, raw, "application/json")
            return
        if path == "/api/orders":
            self.api_orders()
            return
        if path == "/api/profile":
            self.api_profile()
            return
        if path == "/robots.txt":
            text = "User-agent: *\nDisallow: /admin\nDisallow: /.env\nDisallow: /backup/\n"
            self._send(200, text.encode(), "text/plain")
            return
        if path == "/sitemap.xml":
            locs = ["/search?q=seal", "/catalog/item?id=1", "/forum/thread?id=1",
                    "/login?next=/", "/go?url=/", "/api/orders?id=1001", "/graphql",
                    "/swagger.json", "/static/app.js", "/download?file=guide.txt"]
            body = "<urlset>" + "".join(f"<url><loc>http://{HOST}:{PORT}{u}</loc></url>" for u in locs) + "</urlset>"
            self._send(200, body.encode(), "application/xml")
            return
        if path == "/.env":
            text = "APP_ENV=lab\nDB_PASSWORD=lab-db-placeholder\nSECRET_KEY=lab-placeholder\n"
            self._send(200, text.encode(), "text/plain")
            return
        if path == "/.git/HEAD":
            self._send(200, b"ref: refs/heads/lab\n", "text/plain")
            return
        if path == "/backup/db.sql.bak":
            text = "-- lab fixture, not a real dump\nINSERT INTO users VALUES (1,'admin','lab-not-a-password');\n"
            self._send(200, text.encode(), "text/plain")
            return
        if path.startswith("/static/"):
            self.static(path[len("/static/"):])
            return
        self._html(404, "Not found", "<div class='card'><h1>Not found</h1></div>")

    def do_POST(self):
        path = self._path()
        if path in ("/graphql", "/api/graphql"):
            self.api_graphql()
            return
        if path == "/login":
            self.post_login()
            return
        if path == "/forum/thread":
            self.post_comment()
            return
        if path == "/account/email":
            self.post_email()
            return
        self._html(404, "Not found", "<div class='card'><h1>Not found</h1></div>")

    def do_OPTIONS(self):
        origin = self.headers.get("Origin") or "*"
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def static(self, name: str):
        target = (APP / "static" / name).resolve()
        if APP / "static" not in target.parents or not target.is_file():
            self._html(404, "Not found", "<div class='card'><h1>Not found</h1></div>")
            return
        ctype = "text/css" if target.suffix == ".css" else "application/javascript"
        self._send(200, target.read_bytes(), ctype)

    def _vhost_links(self) -> str:
        port = self._port()
        bits = []
        for name in LAB_VHOSTS:
            bits.append(f'<li><a href="http://{name}:{port}/">{name}</a></li>')
        return "<ul>" + "".join(bits) + "</ul>"

    def page_home(self):
        self._html(200, "Home", f"""
<div class="card">
  <p class="flag">Local lab · 127.0.0.1 only</p>
  <h1>Harbor Supply</h1>
  <p class="muted">Internal ordering desk for the seal-kit warehouse. This process is the ReconX practice target: the bugs are real responses, scoped to this folder.</p>
</div>
<div class="grid">
  <div class="card"><h2>Catalog</h2><p>Two valves, an order book, a forum.</p><a class="btn" href="/catalog">Open catalog</a></div>
  <div class="card"><h2>Desk login</h2><p>Lab account <code>admin</code> / <code>admin</code>.</p><a class="btn" href="/login">Sign in</a></div>
  <div class="card"><h2>Other desks</h2><p>Same process, different Host names.</p>{self._vhost_links()}</div>
</div>""")

    def page_legacy(self, path: str):
        if path not in ("/", "/index.php", "/status"):
            self._html(404, "Legacy", "<div class='card'><h1>Not found</h1><p>Harbor Desk 2.4.1</p></div>")
            return
        if path == "/status":
            self._html(200, "Status", """
<div class="card"><h1>Harbor Desk 2.4.1</h1>
<p>Apache/2.2.22 · PHP/5.3.10 · uptime fixture</p></div>""")
            return
        self._html(200, "Harbor Desk 2.4.1", """
<div class="card">
  <p class="flag">Retired desk · still on the wire</p>
  <h1>Harbor Desk 2.4.1</h1>
  <p>Build 2014-03-18. PHP 5.3.10. Apache 2.2.22.</p>
  <p class="muted">Version banner only. This host does not run the old binary and does not execute commands.</p>
  <p><a href="/status">status</a></p>
</div>""")

    def page_api_home(self):
        self._html(200, "API", """
<div class="card"><h1>Harbor API</h1>
<ul>
  <li><a href="/api/orders?id=1001">/api/orders</a></li>
  <li><a href="/api/profile">/api/profile</a></li>
  <li><a href="/graphql">/graphql</a></li>
  <li><a href="/openapi.json">/openapi.json</a></li>
  <li><a href="/swagger.json">/swagger.json</a></li>
</ul></div>""")

    def page_dev_home(self):
        self._html(200, "Dev", """
<div class="card"><h1>Harbor dev desk</h1>
<p class="muted">Staging copy of the same lab. No extra services.</p>
<p><a href="/admin">admin</a> · <a href="/.env">env</a></p></div>""")

    def page_files_home(self):
        self._html(200, "Files", """
<div class="card"><h1>Harbor files</h1>
<ul>
  <li><a href="/download?file=guide.txt">guide</a></li>
  <li><a href="/backup/db.sql.bak">backup</a></li>
  <li><a href="/static/app.js">app.js</a></li>
</ul></div>""")

    def page_search(self):
        q = (self._qs().get("q") or self._qs().get("search") or [""])[0]
        # Reflected on purpose.
        self._html(200, "Search", f"""
<div class="card">
  <h1>Search</h1>
  <form method="get" action="/search"><label>Query</label><input name="q" value="{q}"><button>Search</button></form>
  <p>You searched for '{q}'</p>
</div>""")

    def page_catalog(self):
        rows = "".join(
            f"<tr><td><a href=\"/catalog/item?id={i}\">{_esc(name)}</a></td><td>{_esc(blurb)}</td></tr>"
            for i, (name, blurb) in PRODUCTS.items())
        self._html(200, "Catalog", f"<div class='card'><h1>Catalog</h1><table>{rows}</table></div>")

    def page_item(self):
        raw = (self._qs().get("id") or ["1"])[0]
        compact = raw.replace(" ", "")
        if "'" in raw or '"' in raw:
            detail = ("<p class='err'>You have an error in your SQL syntax; check the manual that "
                      f"corresponds to your MySQL server version for the right syntax near '{_esc(raw)}'</p>")
        elif "1=2" in compact:
            detail = "<p class='muted'>No such item.</p>"
        else:
            name, blurb = PRODUCTS.get(raw, ("Unknown item", "No row for that id."))
            detail = f"<h2>{_esc(name)}</h2><p>{_esc(blurb)}</p>"
        self._html(200, "Item", f"""
<div class="card"><p class="flag">Item { _esc(raw) }</p>{detail}
<div id="hash-slot"></div>
<p><a href="/catalog">Back</a></p></div>""")

    def page_forum(self):
        self._html(200, "Forum", """
<div class="card"><h1>Forum</h1>
<ul><li><a href="/forum/thread?id=1">Seal kit delivery notes</a></li></ul></div>""")

    def page_thread(self):
        with COMMENT_LOCK:
            comments = list(COMMENTS)
        blocks = "".join(f"<p><strong>{name}</strong><br>{text}</p>" for name, text in comments)
        self._html(200, "Thread", f"""
<div class="card"><h1>Seal kit delivery notes</h1>{blocks}
<form method="post" action="/forum/thread?id=1">
<label>Name</label><input name="name" value="ada">
<label>Comment</label><textarea name="comment"></textarea>
<button>Post</button></form></div>""")

    def page_login(self):
        nxt = (self._qs().get("next") or self._qs().get("RetURL") or ["/account"])[0]
        self._html(200, "Login", f"""
<div class="card"><h1>Desk login</h1>
<form method="post" action="/login">
<input type="hidden" name="next" value="{nxt}">
<label>User</label><input name="user">
<label>Password</label><input name="password" type="password">
<button>Sign in</button></form>
<p class="muted">Lab account admin / admin.</p></div>""")

    def page_account(self):
        who = self._cookie() or "anonymous"
        self._html(200, "Account", f"""
<div class="card"><h1>Account</h1>
<p>Session: {_esc(who)}</p>
<p>Email on file: {_esc(ACCOUNT['email'])}</p>
<form method="post" action="/account/email">
<label>New email</label><input name="email">
<button>Save</button></form>
<p class="muted">This form has no CSRF token.</p></div>""")

    def page_reset(self):
        host = self.headers.get("Host") or f"{HOST}:{PORT}"
        self._html(200, "Reset", f"""
<div class="card"><h1>Password reset</h1>
<p>If this were mailed, the link would be
<a href="http://{host}/reset?redirect=/login">http://{host}/reset?redirect=/login</a>.</p></div>""")

    def page_preview(self):
        tpl = (self._qs().get("tpl") or ["hello"])[0]
        rendered = tpl.replace("{{7*7}}", "49").replace("${7*7}", "49")
        self._html(200, "Preview", f"<div class='card'><h1>Preview</h1><p>{rendered}</p></div>")

    def page_download(self):
        rel = unquote((self._qs().get("file") or ["guide.txt"])[0])
        if rel.startswith("/") or "\x00" in rel:
            self._html(400, "Download", "<div class='card'><h1>Bad path</h1></div>")
            return
        target = (APP / "files" / rel).resolve()
        if APP not in target.parents or not target.is_file():
            self._html(404, "Download", "<div class='card'><h1>Missing file</h1></div>")
            return
        data = target.read_bytes()
        self._send(200, data, "text/plain; charset=utf-8",
                   {"Content-Disposition": f"inline; filename=\"{quote(target.name)}\""})

    def page_admin(self):
        self._html(200, "Admin", """
<div class="card"><h1>Admin desk</h1>
<p>No authentication on this page.</p>
<ul><li><a href="/backup/db.sql.bak">Nightly backup</a></li>
<li><a href="/.env">Environment file</a></li></ul></div>""")

    def page_phpinfo(self):
        self._send(200, b"<html><body><h1>PHP Version 5.6.40</h1><p>lab fixture</p></body></html>",
                   "text/html; charset=utf-8")

    def page_swagger_ui(self):
        self._html(200, "API", """
<div class="card"><h1>API docs</h1>
<p>Schema: <a href="/swagger.json">/swagger.json</a> and <a href="/openapi.json">/openapi.json</a>.</p>
<p>GraphQL: <a href="/graphql">/graphql</a></p></div>""")

    def page_graphql_get(self):
        self._send(200, b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
                   "application/json", cors=True)

    def api_orders(self):
        oid = (self._qs().get("id") or ["1001"])[0]
        row = ORDERS.get(oid)
        if not row:
            self._send(404, b'{"error":"no such order"}', "application/json", cors=True)
            return
        self._send(200, json.dumps(row).encode(), "application/json", cors=True)

    def api_profile(self):
        payload = {"user": self._cookie() or "ada", "email": ACCOUNT["email"]}
        self._send(200, json.dumps(payload).encode(), "application/json", cors=True)

    def api_graphql(self):
        raw = self._body().decode("utf-8", "replace")
        try:
            query = json.loads(raw).get("query", "") if raw.strip().startswith("{") or raw.strip().startswith("[") else raw
        except Exception:
            query = raw
        if "__schema" in query or "introspection" in query.lower():
            body = {"data": {"__schema": {"queryType": {"name": "Query"},
                                          "types": [{"name": "Order"}, {"name": "User"}]}}}
        else:
            body = {"data": {"orders": list(ORDERS.values())}}
        self._send(200, json.dumps(body).encode(), "application/json", cors=True)

    def post_login(self):
        form = parse_qs(self._body().decode("utf-8", "replace"))
        user = (form.get("user") or [""])[0]
        password = (form.get("password") or [""])[0]
        nxt = (form.get("next") or ["/account"])[0]
        if user == "admin" and password == "admin":
            dest = nxt if nxt.startswith("/") and not nxt.startswith("//") else "/account"
            self.send_response(302)
            self.send_header("Set-Cookie", "lab_session=admin; Path=/")
            self.send_header("Location", dest)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._html(401, "Login", "<div class='card'><h1>Rejected</h1><p>Use admin / admin.</p></div>")

    def post_comment(self):
        form = parse_qs(self._body().decode("utf-8", "replace"))
        name = ((form.get("name") or ["anon"])[0] or "anon")[:40]
        text = ((form.get("comment") or [""])[0])[:500]
        if text:
            with COMMENT_LOCK:
                COMMENTS.append((name, text))
        self._redirect("/forum/thread?id=1")

    def post_email(self):
        if self._cookie() != "admin":
            self._html(401, "Account", "<div class='card'><h1>Sign in first</h1></div>")
            return
        form = parse_qs(self._body().decode("utf-8", "replace"))
        email = (form.get("email") or [""])[0][:80]
        if email:
            ACCOUNT["email"] = email
        self._redirect("/account")


def main():
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Harbor Supply lab at http://{HOST}:{PORT}/")
    print("Bound to loopback only. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
