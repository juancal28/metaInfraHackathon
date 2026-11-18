#!/usr/bin/env python3
"""Run every detection with its default settings and write findings.json (team 12).

Usage: python3 hunt/run_all.py [--team 12] [--out findings.json] [--only dns1,web2]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import registry  # noqa: E402
import hunts_dns, hunts_web, hunts_endpoint, hunts_identity  # noqa: E402,F401
from common import ms  # noqa: E402

FIELDS = ('category', 'timestamp', 'host', 'user', 'process')


def dedupe(findings: list[dict]) -> list[dict]:
    """Drop repeats: same category/host/user/process within 5 minutes (the scorer would ignore them anyway)."""
    out, seen = [], {}
    for f in sorted(findings, key=lambda f: f['timestamp']):
        k = (f['category'], f['host'], f['user'].lower(), f['process'].lower())
        t = ms(f['timestamp'])
        if k in seen and any(abs(t - x) <= 5 * 60 * 1000 for x in seen[k]):
            continue
        seen.setdefault(k, []).append(t)
        out.append(f)
    return out


def run_all(only=None, overrides=None, log=print):
    allf = []
    for hid in registry.HUNTS:
        if only and hid not in only:
            continue
        t = time.time()
        fs = registry.run(hid, (overrides or {}).get(hid))
        log(f'{hid:6} {len(fs):4} findings  {time.time() - t:5.1f}s  {registry.HUNTS[hid]["title"]}')
        allf += fs
    return dedupe(allf)


def document(team_id, findings):
    return {'team_id': team_id, 'findings': [{**{k: f[k] for k in FIELDS}, 'confidence': f.get('confidence', 'high'),
                                              'evidence': f.get('evidence', []) + [f"hunt {f['hunt']}"]} for f in findings]}


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--team', default='12')
    ap.add_argument('--out', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'findings.json'))
    ap.add_argument('--only', default='')
    a = ap.parse_args()
    fs = run_all(set(a.only.split(',')) if a.only else None)
    with open(a.out, 'w') as fh:
        json.dump(document(a.team, fs), fh, indent=1)
    by = {}
    for f in fs:
        by[f['category']] = by.get(f['category'], 0) + 1
    print(f'\n{len(fs)} findings -> {os.path.abspath(a.out)}')
    for k, v in sorted(by.items(), key=lambda x: -x[1]):
        print(f'  {v:4}  {k}')
