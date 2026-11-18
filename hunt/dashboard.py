#!/usr/bin/env python3
"""Bearcorp threat-hunt dashboard: run detections, change their settings, triage findings, export findings.json.

    python3 hunt/dashboard.py            # then open http://127.0.0.1:8800
Only the Python standard library is used. Results are cached in hunt/cache/ so restarts are instant.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import registry  # noqa: E402
import hunts_dns, hunts_web, hunts_endpoint, hunts_identity  # noqa: E402,F401
from common import db_path, iso, ms, q, users_table  # noqa: E402
from run_all import FIELDS, dedupe  # noqa: E402

CACHE_DIR = os.path.join(HERE, 'cache')
CACHE = os.path.join(CACHE_DIR, 'results.json')
LOCK = threading.Lock()
STATE = {'results': {}, 'busy': None, 'progress': []}

TRIAGE = {
    'Known-bad indicators': 'Block the indicator, check what else the host contacted around this time, and look for a download or credential prompt.',
    'Deceptive domains': 'Check whether the user entered credentials on the look-alike page; reset the password if so and block the domain.',
    'Data theft': 'Confirm what data left (size, destination). Contain the host, preserve the archive or session, and scope other hosts using the same destination.',
    'Command and control': 'Isolate the host, identify the process and how it started, and block the destination for every host.',
    'Reconnaissance': 'Find who launched the scan or lookups. Expect follow-on access: check this host for later lateral movement or credential use.',
    'Malware delivery': 'Pull the file hash, check whether it ran, and isolate the host if it did. Block the source site.',
    'Host intrusion signs': 'Treat the host as compromised: capture a timeline, check for persistence and new accounts, and rotate any exposed secrets.',
    'Lateral movement': 'Check the target server for the same account, disable the admin credential used, and trace where it was stolen.',
    'Credential abuse': 'Reset the account, revoke its sessions and tokens, and check its activity after the successful login.',
}


def load_cache():
    if os.path.exists(CACHE):
        try:
            with open(CACHE) as f:
                STATE['results'] = json.load(f)
        except (OSError, ValueError):
            STATE['results'] = {}


def save_cache():
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = CACHE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(STATE['results'], f)
    os.replace(tmp, CACHE)


def run_hunt(hid, params):
    with LOCK:
        STATE['busy'] = hid
        t = time.time()
        try:
            fs = registry.run(hid, params)
        finally:
            STATE['busy'] = None
        eff = registry.defaults(registry.HUNTS[hid])
        eff.update({k: v for k, v in (params or {}).items() if k in eff})
        STATE['results'][hid] = {'params': eff, 'findings': fs, 'ran_at': time.strftime('%H:%M:%S'), 'secs': round(time.time() - t, 1)}
        save_cache()
        return STATE['results'][hid]


def warm():
    for hid in registry.HUNTS:
        if hid not in STATE['results']:
            STATE['progress'].append(hid)
            run_hunt(hid, None)


def hunt_list():
    out = []
    for hid, h in registry.HUNTS.items():
        r = STATE['results'].get(hid)
        out.append({k: h[k] for k in ('id', 'role', 'title', 'categories', 'params', 'describe', 'sql')} |
                   {'count': len(r['findings']) if r else None, 'current': r['params'] if r else registry.defaults(h),
                    'ran_at': r['ran_at'] if r else None, 'secs': r['secs'] if r else None})
    return out


def all_findings(excluded=()):
    fs = []
    for hid, r in STATE['results'].items():
        fs += [f for f in r['findings']]
    fs = dedupe(fs)
    ex = set(excluded)
    return [f for f in fs if key_of(f) not in ex]


def key_of(f):
    return f"{f['hunt']}|{f['category']}|{f['host']}|{f['timestamp']}"


def context(host, ts, minutes=30):
    t = ms(ts)
    ev = q('SELECT ts, event, user, process, target FROM host WHERE host = ? AND ts BETWEEN ? AND ? ORDER BY ts LIMIT 400',
           host, iso(t - minutes * 60000), iso(t + minutes * 60000))
    # drop the very chatty background agents unless nothing else is there
    noisy = {'updater', 'telemetry', 'lic-agent', 'asset-agent', 'sysupdate', 'shield-agent', 'mailagent'}
    keep = [e for e in ev if e[3] not in noisy or e[1] in ('PROC_START',)]
    asset = q('SELECT hostname, ip, type, team FROM assets WHERE hostname = ?', host)
    owner = [{'user': u, **d} for u, d in users_table().items() if d['workstation'] == host]
    others = [f for f in all_findings() if f['host'] == host]
    usb = q('SELECT ts, user, action, device, mb FROM usb WHERE host = ? ORDER BY ts', host)
    return {'events': [dict(zip(('ts', 'event', 'user', 'process', 'target'), e)) for e in keep][:250],
            'hidden_background': len(ev) - len(keep),
            'asset': dict(zip(('hostname', 'ip', 'type', 'team'), asset[0])) if asset else None,
            'owners': owner, 'findings': sorted(others, key=lambda f: f['timestamp']),
            'usb': [dict(zip(('ts', 'user', 'action', 'device', 'mb'), u)) for u in usb][:40]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype='application/json', extra=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        return json.loads(self.rfile.read(n) or b'{}')

    def do_GET(self):
        u = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path in ('/', '/index.html'):
            with open(os.path.join(HERE, 'dashboard.html'), 'rb') as f:
                return self.send(200, f.read(), 'text/html; charset=utf-8')
        if u.path == '/api/hunts':
            return self.send(200, {'hunts': hunt_list(), 'busy': STATE['busy'], 'db': os.path.basename(os.path.dirname(db_path())) + '/' + os.path.basename(db_path()),
                                   'triage': TRIAGE})
        if u.path == '/api/findings':
            hid = qs.get('hunt')
            if hid:
                r = STATE['results'].get(hid)
                return self.send(200, {'findings': r['findings'] if r else [], 'meta': {k: r[k] for k in ('ran_at', 'secs')} if r else None})
            return self.send(200, {'findings': all_findings()})
        if u.path == '/api/context':
            return self.send(200, context(qs['host'], qs['ts'], int(qs.get('minutes', 30))))
        return self.send(404, {'error': 'not found'})

    def do_POST(self):
        u = urlparse(self.path)
        b = self.body()
        if u.path == '/api/run':
            hid = b.get('hunt')
            if hid not in registry.HUNTS:
                return self.send(400, {'error': 'unknown hunt'})
            try:
                r = run_hunt(hid, b.get('params') or {})
            except Exception as e:  # show the error in the page instead of crashing the server
                return self.send(500, {'error': f'{type(e).__name__}: {e}'})
            return self.send(200, {'findings': r['findings'], 'meta': {'ran_at': r['ran_at'], 'secs': r['secs']}})
        if u.path == '/api/reset':
            hid = b.get('hunt')
            r = run_hunt(hid, None)
            return self.send(200, {'findings': r['findings'], 'meta': {'ran_at': r['ran_at'], 'secs': r['secs']}})
        if u.path == '/api/export':
            team = str(b.get('team_id') or '12').strip()
            fs = all_findings(b.get('excluded') or [])
            doc = {'team_id': team, 'findings': [{**{k: f[k] for k in FIELDS}, 'confidence': f.get('confidence', 'high'),
                                                  'evidence': f.get('evidence', []) + [f"hunt {f['hunt']}"]} for f in fs]}
            return self.send(200, json.dumps(doc, indent=1).encode(), 'application/json',
                             {'Content-Disposition': 'attachment; filename="findings.json"'})
        return self.send(404, {'error': 'not found'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8800'))
    load_cache()
    threading.Thread(target=warm, daemon=True).start()
    print(f'Dashboard on http://127.0.0.1:{port}  (database: {db_path()})')
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
