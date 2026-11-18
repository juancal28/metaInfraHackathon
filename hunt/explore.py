"""Ad-hoc helpers for looking at the data while writing detections."""
import sys
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from common import *


def sessions(rows, gap_ms=2 * 3600 * 1000):
    """rows: (ms, key, ...) sorted by key then time -> list of (key, start, end, n, rows)."""
    out = []
    by = {}
    for r in rows:
        by.setdefault(r[1], []).append(r)
    for k, rs in by.items():
        rs.sort()
        cur = [rs[0]]
        for r in rs[1:]:
            if r[0] - cur[-1][0] > gap_ms:
                out.append((k, cur[0][0], cur[-1][0], len(cur), cur)); cur = [r]
            else:
                cur.append(r)
        out.append((k, cur[0][0], cur[-1][0], len(cur), cur))
    return sorted(out, key=lambda s: s[1])


def dns_sessions(like, gap_h=2, extra=''):
    rows = [(ms(ts), s, qq, qt, rc) for ts, s, qq, qt, rc in q(f"SELECT ts, src_ip, query, qtype, rcode FROM dns WHERE query LIKE ? {extra}", like)]
    for k, a, b, n, rs in sessions(rows, gap_h * 3600 * 1000):
        hs = hosts_for_ip(k, a)
        print(f'  {k:14} {iso(a)} -> {iso(b)} n={n:5} hosts={hs} {rs[0][2][:50]} {rs[0][3]} {rs[0][4]}')
