"""Shared lookups for the Bearcorp detections: database access, IP -> host, logged-in user, and finding rows."""
from __future__ import annotations

import bisect
import os
import sqlite3
import threading
from datetime import datetime, timezone
from functools import lru_cache

HERE = os.path.dirname(os.path.abspath(__file__))
ORIGINAL_DB = os.path.join(HERE, '..', 'dataset', 'bearcorp.db')
# An indexed working copy (built by hunt/make_indexes.py) is much faster; fall back to the original.
WORK_DB = os.environ.get('BEARCORP_DB', os.path.expanduser('~/bearcorp-work/bearcorp.db'))


def db_path() -> str:
    return WORK_DB if os.path.exists(WORK_DB) else ORIGINAL_DB


_local = threading.local()


def con() -> sqlite3.Connection:
    """One read-only connection per thread (the dashboard serves requests while detections run)."""
    c = getattr(_local, 'con', None)
    if c is None:
        c = sqlite3.connect(f'file:{db_path()}?mode=ro', uri=True)
        c.execute('PRAGMA cache_size=-500000')
        c.execute('PRAGMA temp_store=MEMORY')
        c.execute('PRAGMA mmap_size=8000000000')
        _local.con = c
    return c


def q(sql: str, *args):
    return con().execute(sql, args).fetchall()


def ms(ts: str) -> int:
    return int(datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc).timestamp() * 1000)


def iso(t: int) -> str:
    return datetime.fromtimestamp(t / 1000, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') + f'{t % 1000:03d}Z'


def hour_of(ts: str) -> int:
    return int(ts[11:13])


# ---------- IP -> host ----------
@lru_cache(maxsize=1)
def ip_index():
    """ip -> sorted [(ms, host)] from IP_ASSIGNED rows (plus the assets table as the starting point)."""
    idx: dict[str, list] = {}
    for host, ip in q('SELECT hostname, ip FROM assets'):
        idx.setdefault(ip, []).append((0, host))
    for ts, host, ip in q("SELECT ts, host, target FROM host WHERE event = 'IP_ASSIGNED'"):
        idx.setdefault(ip, []).append((ms(ts), host))
    for v in idx.values():
        v.sort()
    return idx


@lru_cache(maxsize=1)
def host_ip_index():
    """host -> sorted [(ms, ip)]."""
    idx: dict[str, list] = {}
    for ip, rows in ip_index().items():
        for t, h in rows:
            idx.setdefault(h, []).append((t, ip))
    for v in idx.values():
        v.sort()
    return idx


@lru_cache(maxsize=1)
def nat_rows():
    rows: dict[str, list] = {}
    for nat_ip, internal, start, end in q('SELECT nat_ip, internal_ip, start, "end" FROM nat'):
        rows.setdefault(nat_ip, []).append((ms(start), ms(end), internal))
    return rows


def is_nat(ip: str) -> bool:
    return ip in nat_rows()


def host_for_ip(ip: str, t: int) -> str | None:
    """The host that held this (internal, non-NAT) IP at time t."""
    rows = ip_index().get(ip)
    if not rows:
        return None
    i = bisect.bisect_right(rows, (t, '￿')) - 1
    if i < 0:
        return None
    host = rows[i][1]
    # make sure the host still had this ip at t
    hr = host_ip_index().get(host, [])
    j = bisect.bisect_right(hr, (t, '￿')) - 1
    if j >= 0 and hr[j][1] != ip:
        return None
    return host


def hosts_for_ip(ip: str, t: int) -> list[str]:
    """Candidate hosts for an address seen in dns/proxy/fw (NAT addresses expand to several)."""
    if is_nat(ip):
        out = []
        for start, end, internal in nat_rows()[ip]:
            if start <= t < end:
                h = host_for_ip(internal, t)
                if h:
                    out.append(h)
        return out
    h = host_for_ip(ip, t)
    return [h] if h else []


def ip_of_host(host: str, t: int) -> str | None:
    hr = host_ip_index().get(host, [])
    j = bisect.bisect_right(hr, (t, '￿')) - 1
    return hr[j][1] if j >= 0 else None


# ---------- who is logged in ----------
@lru_cache(maxsize=1)
def session_index():
    idx: dict[str, list] = {}
    for ts, host, ev, user in q("SELECT ts, host, event, user FROM host WHERE event IN ('LOGIN', 'LOGOUT')"):
        idx.setdefault(host, []).append((ms(ts), 0 if ev == 'LOGOUT' else 1, user))
    for v in idx.values():
        v.sort()
    return idx


def user_at(host: str, t: int) -> str:
    """User logged in on host at time t, or 'none'."""
    rows = session_index().get(host, [])
    i = bisect.bisect_right(rows, (t, 2, '￿')) - 1
    if i < 0:
        return 'none'
    _, kind, user = rows[i]
    return user if kind == 1 else 'none'


@lru_cache(maxsize=1)
def users_table():
    return {u: dict(department=d, role=r, status=s, workstation=w) for u, d, r, s, w in q('SELECT * FROM users')}


def workstation_of(user: str) -> str | None:
    u = users_table().get(user)
    return u['workstation'] if u else None


# ---------- domain -> host/process ----------
def host_dns_rows(domain: str):
    """(ms, host, process) for host-table DNS_QUERY rows of this domain."""
    return [(ms(ts), h, p) for ts, h, p in q("SELECT ts, host, process FROM host WHERE target = ? AND event = 'DNS_QUERY'", domain)]


def host_conn_rows(dest_prefix: str):
    """(ms, host, process, target) for NET_CONNECT rows whose target starts with ip (ip or ip:port)."""
    return [(ms(ts), h, p, tg) for ts, h, p, tg in
            q("SELECT ts, host, process, target FROM host WHERE target >= ? AND target < ? AND event = 'NET_CONNECT'",
              dest_prefix, dest_prefix + '￿')]


def process_for(host: str, domain: str, t: int | None = None, rows=None) -> str | None:
    """Process on host that looked up domain (closest to t if given)."""
    rows = rows if rows is not None else host_dns_rows(domain)
    mine = [r for r in rows if r[1] == host]
    if not mine:
        return None
    if t is None:
        return min(mine)[2]
    return min(mine, key=lambda r: abs(r[0] - t))[2]


def resolve(src_ip: str, t: int, domain: str | None = None, dns_rows=None) -> tuple[str | None, str | None]:
    """(host, process) for traffic from src_ip at t to domain. NAT addresses are resolved via the host DNS rows."""
    cands = hosts_for_ip(src_ip, t)
    if domain is None:
        return (cands[0] if len(cands) == 1 else None), None
    rows = dns_rows if dns_rows is not None else host_dns_rows(domain)
    if len(cands) > 1 or not cands:
        # pick the candidate host that looked the domain up nearest in time
        pool = [r for r in rows if not cands or r[1] in cands]
        if not pool:
            return (cands[0] if len(cands) == 1 else None), None
        best = min(pool, key=lambda r: abs(r[0] - t))
        return best[1], best[2]
    return cands[0], process_for(cands[0], domain, t, rows)


def finding(category: str, t: int | str, host: str, user: str, process: str, hunt: str, evidence: list[str] | None = None,
            confidence: str = 'high') -> dict:
    ts = t if isinstance(t, str) else iso(t)
    return {'category': category, 'timestamp': ts, 'host': host, 'user': user or 'none', 'process': process or 'unknown',
            'hunt': hunt, 'confidence': confidence, 'evidence': evidence or []}
