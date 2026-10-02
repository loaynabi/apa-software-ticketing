# -*- coding: utf-8 -*-
"""Deploy APA Software Ticketing to Cloudflare Workers (FREE plan, Workers KV only, no R2). Python stdlib only.

    python deploy.py --token-file cf.token --account-file account.txt [--seed users.json [--merge]] [--dry-run]

  --token-file    text file holding a Cloudflare API token (Workers Scripts: Edit, Workers KV Storage: Edit)
  --account-file  text file holding the Cloudflare account id
  --seed          upload a users.json made by seed_users.py into the `users` KV key
                  (refuses to overwrite a non-empty `users` key unless --merge, which adds new emails only)
  --dry-run       build the upload and show what would be sent; makes no network calls

What it does: creates (or reuses, remembered in deploy_config.json) the KV namespace `apa-software-tickets`;
generates a random SESSION_SECRET once and keeps it in .session_secret; uploads the Worker `apa-software-tickets`
(worker/**/*.js as ES modules + src/index.html as a text module); turns on its workers.dev URL; optionally seeds users.
The token and the session secret are never printed.
"""
import argparse
import glob
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
SCRIPT = "apa-software-tickets"
KV_TITLE = "apa-software-tickets"
API = "https://api.cloudflare.com/client/v4"
COMPAT_DATE = "2026-09-01"
UA = "apa-software-tickets-deploy/1.0"


class CfError(Exception):
    pass


def read_secret_file(path, what):
    try:
        with open(path, "rb") as f:
            val = f.read().decode("utf-8-sig").strip().splitlines()
    except OSError as e:
        sys.exit(f"Cannot read the {what} file: {e}")
    val = [l.strip() for l in val if l.strip()]
    if not val:
        sys.exit(f"The {what} file is empty.")
    return val[0]


class Cf:
    def __init__(self, token, account):
        self.token, self.account = token, account

    def call(self, method, path, body=None, content_type=None, raw=False):
        """Returns the parsed JSON `result` (or raw bytes if raw=True). Raises CfError with a safe message."""
        data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode("utf-8")
        if isinstance(body, (dict, list)):
            content_type = "application/json"
        req = urllib.request.Request(API + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.token)
        req.add_header("User-Agent", UA)
        if content_type:
            req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                payload = r.read()
        except urllib.error.HTTPError as e:
            payload = e.read()
            err = CfError(self._msg(e.code, payload))
            err.status = e.code
            raise err
        except urllib.error.URLError as e:
            raise CfError(f"Network error: {e.reason}")
        if raw:
            return payload
        try:
            j = json.loads(payload.decode("utf-8"))
        except ValueError:
            raise CfError("Unexpected non-JSON response from Cloudflare.")
        if not j.get("success", False):
            raise CfError(self._msg(200, payload))
        return j.get("result")

    @staticmethod
    def _msg(status, payload):
        try:
            errs = json.loads(payload.decode("utf-8")).get("errors") or []
            text = "; ".join(f"{e.get('message', '?')} (code {e.get('code', '?')})" for e in errs)
        except Exception:
            text = ""
        return f"Cloudflare API error HTTP {status}: {text or 'no details'}"


def multipart(fields):
    """fields: list of (name, filename|None, content_type, bytes). Returns (body, content_type_header). Binary safe."""
    boundary = "----apa" + secrets.token_hex(16)
    out = []
    for name, filename, ctype, data in fields:
        disp = f'form-data; name="{name}"' + (f'; filename="{filename}"' if filename else "")
        out.append(f"--{boundary}\r\nContent-Disposition: {disp}\r\nContent-Type: {ctype}\r\n\r\n".encode("utf-8"))
        out.append(data)
        out.append(b"\r\n")
    out.append(f"--{boundary}--\r\n".encode("utf-8"))
    return b"".join(out), f"multipart/form-data; boundary={boundary}"


def worker_parts():
    parts = []
    files = sorted(glob.glob(os.path.join(ROOT, "worker", "**", "*.js"), recursive=True))
    if not files:
        sys.exit("No worker/**/*.js files found.")
    for p in files:
        rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
        with open(p, "rb") as f:
            parts.append((rel, rel, "application/javascript+module", f.read()))
    html = os.path.join(ROOT, "src", "index.html")
    if not os.path.exists(html):
        sys.exit("src/index.html is missing.")
    with open(html, "rb") as f:
        parts.append(("src/index.html", "src/index.html", "text/plain", f.read()))
    return parts


def load_config():
    p = os.path.join(ROOT, "deploy_config.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_config(cfg):
    with open(os.path.join(ROOT, "deploy_config.json"), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def session_secret():
    p = os.path.join(ROOT, ".session_secret")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            s = f.read().strip()
        if s:
            return s
    s = secrets.token_hex(32)
    with open(p, "w", encoding="utf-8") as f:
        f.write(s)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return s


def ensure_namespace(cf, cfg):
    base = f"/accounts/{cf.account}/storage/kv/namespaces"
    nid = cfg.get("kv_namespace_id")
    found = cf.call("GET", base + "?per_page=100")
    if nid and any(n.get("id") == nid for n in found):
        print(f"KV namespace '{KV_TITLE}': reusing the one saved in deploy_config.json.")
        return nid
    for n in found:
        if n.get("title") == KV_TITLE:
            print(f"KV namespace '{KV_TITLE}': found an existing one, reusing it.")
            return n["id"]
    res = cf.call("POST", base, {"title": KV_TITLE})
    print(f"KV namespace '{KV_TITLE}': created.")
    return res["id"]


def upload_worker(cf, nid, secret, cfg):
    meta = {
        "main_module": "worker/index.js",
        "compatibility_date": COMPAT_DATE,
        "bindings": [
            {"type": "kv_namespace", "name": "KV", "namespace_id": nid},
            {"type": "secret_text", "name": "SESSION_SECRET", "text": secret},
            {"type": "durable_object_namespace", "name": "CHAT", "class_name": "TicketChat"},
        ],
    }
    if not cfg.get("chat_migrated"):   # first deploy with live chat creates the (free, SQLite-backed) Durable Object class
        meta["migrations"] = {"new_tag": "v1", "new_sqlite_classes": ["TicketChat"]}
    fields = [("metadata", None, "application/json", json.dumps(meta).encode("utf-8"))] + worker_parts()
    body, ctype = multipart(fields)
    cf.call("PUT", f"/accounts/{cf.account}/workers/scripts/{SCRIPT}", body, content_type=ctype)
    print(f"Worker '{SCRIPT}': uploaded ({len(fields) - 1} modules, {len(body) // 1024} KB).")


def seed_users(cf, nid, path, merge):
    with open(path, encoding="utf-8") as f:
        new = json.load(f)
    if not isinstance(new, list) or not new:
        sys.exit("The seed file has no users.")
    base = f"/accounts/{cf.account}/storage/kv/namespaces/{nid}"
    try:
        current = json.loads(cf.call("GET", f"{base}/values/users", raw=True).decode("utf-8") or "[]")
    except CfError as e:
        if getattr(e, "status", None) == 404:
            current = []
        else:
            raise
    if current and not merge:
        sys.exit(f"The `users` key already holds {len(current)} users. Nothing was changed. "
                 "Re-run with --merge to add only the new emails, or leave it as it is.")
    have = {u.get("email", "").lower() for u in current}
    add = [u for u in new if u.get("email", "").lower() not in have]
    merged = current + add
    cf.call("PUT", f"{base}/bulk", [{"key": "users", "value": json.dumps(merged, separators=(",", ":"), ensure_ascii=False)}])
    print(f"Users: {len(add)} added, {len(new) - len(add)} already present, {len(merged)} in total.")


def main():
    ap = argparse.ArgumentParser(description="Deploy APA Software Ticketing to Cloudflare Workers.")
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--account-file", required=True)
    ap.add_argument("--seed", help="users.json from seed_users.py")
    ap.add_argument("--merge", action="store_true", help="with --seed: add new emails to an existing users key")
    ap.add_argument("--dry-run", action="store_true", help="build everything, call nothing")
    a = ap.parse_args()
    if a.merge and not a.seed:
        ap.error("--merge only makes sense with --seed")

    if a.dry_run:
        parts = worker_parts()
        body, _ = multipart([("metadata", None, "application/json", b"{}")] + parts)
        print("DRY RUN: nothing is sent. The upload would contain these parts:")
        for name, _, ctype, data in parts:
            print(f"  {name:<34}{ctype:<34}{len(data):>8} bytes")
        print(f"Total multipart size: {len(body)} bytes. Worker: {SCRIPT}, KV namespace: {KV_TITLE}.")
        if a.seed:
            with open(a.seed, encoding="utf-8") as f:
                print(f"Would seed {len(json.load(f))} users from {a.seed}.")
        return

    token = read_secret_file(a.token_file, "token")
    account = read_secret_file(a.account_file, "account id")
    cf = Cf(token, account)
    cfg = load_config()
    try:
        nid = ensure_namespace(cf, cfg)
        cfg.update({"kv_namespace_id": nid, "kv_title": KV_TITLE, "script": SCRIPT})
        save_config(cfg)
        upload_worker(cf, nid, session_secret(), cfg)
        cfg["chat_migrated"] = True
        save_config(cfg)
        cf.call("POST", f"/accounts/{account}/workers/scripts/{SCRIPT}/subdomain", {"enabled": True})
        print("workers.dev URL: enabled.")
        if a.seed:
            seed_users(cf, nid, a.seed, a.merge)
        sub = (cf.call("GET", f"/accounts/{account}/workers/subdomain") or {}).get("subdomain")
    except CfError as e:
        sys.exit(f"\nDeploy stopped: {e}")
    if sub:
        print(f"\nDone. Open: https://{SCRIPT}.{sub}.workers.dev")
    else:
        print("\nDone, but the account has no workers.dev subdomain yet. Create one in the Cloudflare dashboard "
              "(Workers & Pages > your subdomain), then the URL is https://" + SCRIPT + ".<subdomain>.workers.dev")


if __name__ == "__main__":
    main()
