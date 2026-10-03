# Harbor Supply — ReconX lab

Local-only vulnerable application used to exercise ReconX. It listens on `127.0.0.1:8088` and does not execute shell commands or read files outside this folder.

```bash
python3 Vuln-Site/app.py
```

Then point the scanner at `http://127.0.0.1:8088/`.

Lab login: `admin` / `admin`.

What is actually broken, on purpose:

| Area | Where |
|---|---|
| Reflected XSS | `/search?q=` |
| DOM XSS | `/catalog/item?id=1#` then the hash is written into the page |
| Stored XSS | comment form on `/forum/thread?id=1` |
| SQL error + boolean difference | `/catalog/item?id=` |
| Open redirect | `/login?next=`, `/go?url=`, `/reset?redirect=`, `RetURL` |
| CORS origin reflection + credentials | `/api/profile` |
| IDOR | `/api/orders?id=1001` and `1002` |
| GraphQL introspection | `POST /graphql` and `/api/graphql` |
| OpenAPI | `/swagger.json`, `/openapi.json` |
| JS placeholder names + bucket URL | `/static/app.js` (no real or dummy credentials) |
| Path climb inside this folder | `/download?file=../private/canary.txt` |
| Template marker | `/preview?tpl={{7*7}}` |
| Sensitive paths | `/.env`, `/.git/HEAD`, `/phpinfo`, `/admin`, `/backup/db.sql.bak` |
| Missing frame / nosniff headers | every HTML page |
| CSRF | `POST /account/email` after logging in |

Same process also answers these Host names on port 8088. Add them to `/etc/hosts` as `127.0.0.1` (see `hosts.lab`):

| Host | What it is |
|---|---|
| `harbor.lab` | The main desk |
| `api.harbor.lab` | API index |
| `legacy.harbor.lab` | Old-version banner only (Apache 2.2 / PHP 5.3 / Harbor Desk 2.4.1). No old binary, no command execution |
| `dev.harbor.lab` | Staging copy of the same app |
| `files.harbor.lab` | Links to the file fixtures |

This lab does not run SSH, FTP, or anything that yields a shell.
