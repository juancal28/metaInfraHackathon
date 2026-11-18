"""Role 2: Web analyst hunts (table proxy; host/process from host DNS_QUERY rows, or NET_CONNECT for raw IPs)."""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from common import finding, hosts_for_ip, iso, ms, q, user_at
from registry import hunt, sessions_by

H = 3600 * 1000
IP_RE = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
COLS = 'ts, src_ip, method, domain, url, status, bytes_out, bytes_in, user_agent'


def load(sql: str, *args) -> list[dict]:
    out = []
    for ts, src, m, d, u, st, bo, bi, ua in q(sql, *args):
        out.append(dict(t=ms(ts), src=src, method=m, domain=d, url=u, status=st, bytes_out=bo or 0, bytes_in=bi or 0, ua=ua))
    return out


def host_process(src: str, t: int, domain: str) -> tuple[str | None, str | None]:
    """Resolve host and process for a proxy request (NAT addresses are matched through the host's own logs)."""
    cands = hosts_for_ip(src, t)
    if IP_RE.match(domain):
        rows = q("SELECT ts, host, process FROM host WHERE event = 'NET_CONNECT' AND target >= ? AND target < ? AND ts BETWEEN ? AND ?",
                 domain + ':', domain + ';', iso(t - 2 * H), iso(t + 2 * H))
    elif len(cands) == 1:
        rows = q("SELECT ts, host, process FROM host WHERE event = 'DNS_QUERY' AND host = ? AND target = ? AND ts BETWEEN ? AND ?",
                 cands[0], domain, iso(t - 3 * H), iso(t + 3 * H))
        if not rows:
            rows = q("SELECT ts, host, process FROM host WHERE event = 'DNS_QUERY' AND host = ? AND target = ?", cands[0], domain)
    else:
        rows = q("SELECT ts, host, process FROM host WHERE event = 'DNS_QUERY' AND target = ? AND ts BETWEEN ? AND ?",
                 domain, iso(t - 3 * H), iso(t + 3 * H))
    pool = [(abs(ms(ts) - t), h, p) for ts, h, p in rows if not cands or h in cands]
    if pool:
        _, h, p = min(pool)
        return h, p
    return (cands[0] if len(cands) == 1 else None), None


def resolve_all(rows: list[dict]) -> list[dict]:
    """Attach host to each row (cheap: by IP; NAT rows resolved per request)."""
    for r in rows:
        c = hosts_for_ip(r['src'], r['t'])
        r['host'] = c[0] if len(c) == 1 else None
        if r['host'] is None and c:
            r['host'], _ = host_process(r['src'], r['t'], r['domain'])
    return [r for r in rows if r['host']]


def emit(groups, category, hunt_id, evidence, confidence='high'):
    out = []
    for _, rs in groups:
        r0 = min(rs, key=lambda r: r['t'])
        host, proc = host_process(r0['src'], r0['t'], r0['domain'])
        host = host or r0['host']
        out.append(finding(category, r0['t'], host, user_at(host, r0['t']), proc or 'unknown', hunt_id, evidence(rs), confidence))
    return out


# ---------------- 1. Big uploads to rare sites ----------------
@hunt('web1', 'Web analyst', 'Big uploads to rare sites', ['Data theft'],
      {'min_bytes': {'default': 1_000_000, 'type': 'int', 'label': 'Upload counted as big (bytes)'},
       'max_computers': {'default': 30, 'type': 'int', 'label': 'Site used by at most N computers'},
       'gap_hours': {'default': 12, 'type': 'int', 'label': 'New finding after a quiet gap of (hours)'},
       'ignore': {'default': ['vaultdrive.com'], 'type': 'list', 'label': 'Ignore sites'},
       'skip_scheduled': {'default': 1, 'type': 'int', 'label': 'Skip scheduled backups (same time of day on 3+ days): 1 = yes'}},
      'POST or PUT requests with large bytes_out to sites that only a few computers use. Backup sites with hundreds of users are normal.',
      """SELECT domain, COUNT(DISTINCT src_ip) AS computers, MAX(bytes_out) AS biggest_upload FROM proxy
WHERE method IN ('POST','PUT') AND bytes_out >= :min_bytes GROUP BY domain HAVING computers <= :max_computers""")
def web1(p):
    doms = [d for d, n in q("SELECT domain, COUNT(DISTINCT src_ip) n FROM proxy WHERE method IN ('POST','PUT') AND bytes_out >= ? GROUP BY domain HAVING n <= ?",
                            p['min_bytes'], p['max_computers']) if d not in p['ignore']]
    out = []
    for d in doms:
        rows = resolve_all(load(f"SELECT {COLS} FROM proxy WHERE domain = ? AND method IN ('POST','PUT') AND bytes_out >= ?", d, p['min_bytes']))
        groups = sessions_by(rows, lambda r: r['host'], lambda r: r['t'], p['gap_hours'] * H)
        if p['skip_scheduled']:
            starts = defaultdict(list)
            for h, rs in groups:
                starts[h].append(rs[0]['t'])
            def scheduled(h):
                ts = starts[h]
                if len(ts) < 3:
                    return False
                mins = [(t // 60000) % 1440 for t in ts]
                return max(mins) - min(mins) <= 15 and len({t // (24 * H) for t in ts}) >= 3
            groups = [(h, rs) for h, rs in groups if not scheduled(h)]
        out += emit(groups, 'Data theft', 'web1', lambda rs: [f"{len(rs)} uploads, {round(sum(r['bytes_out'] for r in rs) / 1e6)} MB to {rs[0]['domain']}"])
    return out


# ---------------- 2. Known-bad URLs ----------------
@hunt('web2', 'Web analyst', 'Known-bad URLs', ['Known-bad indicators'],
      {'gap_hours': {'default': 24, 'type': 'int', 'label': 'New finding after a quiet gap of (hours)'}},
      "'http://' || domain || url matches a url in the iocs table. The site is normal; only that page is bad.",
      "SELECT ts, src_ip, domain, url FROM proxy WHERE 'http://' || domain || url IN (SELECT value FROM iocs WHERE type = 'url')")
def web2(p):
    urls = [u for (u,) in q("SELECT value FROM iocs WHERE type = 'url'")]
    out = []
    for u in urls:
        m = re.match(r'https?://([^/]+)(/.*)$', u)
        if not m:
            continue
        rows = resolve_all(load(f"SELECT {COLS} FROM proxy WHERE domain = ? AND url = ?", m.group(1), m.group(2)))
        groups = sessions_by(rows, lambda r: r['host'], lambda r: r['t'], p['gap_hours'] * H)
        out += emit(groups, 'Known-bad indicators', 'web2', lambda rs: [f"requested {u}"])
    return out


# ---------------- 3. Data hidden in web addresses ----------------
@hunt('web3', 'Web analyst', 'Data hidden in web addresses', ['Data theft'],
      {'min_query_len': {'default': 100, 'type': 'int', 'label': 'Min characters after ?'},
       'min_requests': {'default': 5, 'type': 'int', 'label': 'Min requests by one computer'},
       'gap_hours': {'default': 6, 'type': 'int', 'label': 'Session gap (hours)'}},
      'Very long scrambled text after the ? in url, sent again and again by one computer.',
      "SELECT ts, src_ip, domain, url FROM proxy WHERE length(url) - instr(url, '?') >= :min_query_len AND instr(url, '?') > 0")
def web3(p):
    rows = resolve_all(load(f"SELECT {COLS} FROM proxy WHERE instr(url, '?') > 0 AND length(url) - instr(url, '?') >= ?", p['min_query_len']))
    groups = [g for g in sessions_by(rows, lambda r: (r['host'], r['domain']), lambda r: r['t'], p['gap_hours'] * H)
              if len(g[1]) >= p['min_requests']]
    return emit(groups, 'Data theft', 'web3', lambda rs: [f"{len(rs)} requests to {rs[0]['domain']} with {len(rs[0]['url'])}-char urls", rs[0]['url'][:90]])


# ---------------- 4. Odd web traffic ----------------
@hunt('web4', 'Web analyst', 'Odd web traffic', ['Command and control'],
      {'scripted': {'default': ['curl', 'wget', 'python', 'go-http', 'libwww', 'java/', 'powershell', 'okhttp', 'httpclient'],
                    'type': 'list', 'label': 'Scripted user-agent words'},
       'ignore_ua': {'default': ['dirb', 'BearcorpCrawler'], 'type': 'list', 'label': 'Ignore user agents containing'},
       'max_ua_sources': {'default': 20, 'type': 'int', 'label': 'Ignore user agents used by more computers than'},
       'pool_words': {'default': ['pool', 'mining', 'xmr', 'stratum', 'hashhaven', 'nicehash'], 'type': 'list', 'label': 'Mining pool words'},
       'pool_min_posts': {'default': 10, 'type': 'int', 'label': 'Min small POSTs to a mining pool'},
       'gap_hours': {'default': 12, 'type': 'int', 'label': 'Session gap (hours)'}},
      'user_agent empty, scripted or misspelled; a domain that is a raw IP address; or many small POSTs to a cryptocurrency mining pool.',
      "SELECT user_agent, COUNT(DISTINCT src_ip) FROM proxy GROUP BY user_agent  -- then: domain GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*', domain LIKE '%pool%'")
def web4(p):
    out = []
    uas = q('SELECT user_agent, COUNT(DISTINCT src_ip) FROM proxy GROUP BY user_agent')
    odd = []
    for ua, n in uas:
        u = (ua or '').lower()
        if any(w.lower() in u for w in p['ignore_ua']) or n > p['max_ua_sources']:
            continue
        if not u.strip() or any(w in u for w in p['scripted']) or (u.startswith('mozi') and not u.startswith('mozilla/')):
            odd.append(ua)
    for ua in odd:
        rows = resolve_all(load(f'SELECT {COLS} FROM proxy WHERE user_agent = ?', ua))
        groups = sessions_by(rows, lambda r: r['host'], lambda r: r['t'], p['gap_hours'] * H)
        out += emit(groups, 'Command and control', 'web4', lambda rs: [f"user agent {rs[0]['ua']!r} to {rs[0]['domain']}{rs[0]['url']}"])
    # raw IP domains
    ipdoms = [d for (d,) in q("SELECT DISTINCT domain FROM proxy WHERE domain GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*'") if IP_RE.match(d)]
    for d in ipdoms:
        rows = resolve_all(load(f'SELECT {COLS} FROM proxy WHERE domain = ?', d))
        groups = sessions_by(rows, lambda r: r['host'], lambda r: r['t'], p['gap_hours'] * H)
        out += emit(groups, 'Command and control', 'web4', lambda rs: [f"{len(rs)} requests straight to IP {rs[0]['domain']}"])
    # mining pools
    for w in p['pool_words']:
        for d, n in q("SELECT domain, COUNT(*) FROM proxy WHERE domain LIKE ? AND method = 'POST' GROUP BY domain", f'%{w}%'):
            if n < p['pool_min_posts']:
                continue
            rows = resolve_all(load(f"SELECT {COLS} FROM proxy WHERE domain = ? AND method = 'POST' AND bytes_out < 10000", d))
            groups = [g for g in sessions_by(rows, lambda r: r['host'], lambda r: r['t'], p['gap_hours'] * H) if len(g[1]) >= 3]
            out += emit(groups, 'Command and control', 'web4', lambda rs: [f"{len(rs)} small POSTs to mining pool {rs[0]['domain']}"])
    # one finding per (host, time)
    seen, uniq = set(), []
    for f in out:
        k = (f['host'], f['timestamp'])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


# ---------------- shared: regular check-ins ----------------
_DOMAIN_STATS = None
_SERIES = {}


def domain_stats():
    """domain -> (computers, requests); one pass over proxy, cached."""
    global _DOMAIN_STATS
    if _DOMAIN_STATS is None:
        _DOMAIN_STATS = {d: (n, c) for d, n, c in q('SELECT domain, COUNT(DISTINCT src_ip), COUNT(*) FROM proxy GROUP BY domain')}
    return _DOMAIN_STATS


def checkin_series(max_computers, min_requests, ignore):
    """(domain, host) -> sorted rows for small repeated requests to rarely used sites."""
    key = (max_computers, min_requests, tuple(ignore))
    if key in _SERIES:
        return _SERIES[key]
    stats = domain_stats()
    base_srcs = defaultdict(int)
    for d, (n, c) in stats.items():
        base_srcs['.'.join(d.split('.')[-2:])] += n
    doms = [d for d, (n, c) in stats.items() if n <= max_computers and c >= min_requests and d not in ignore
            and base_srcs['.'.join(d.split('.')[-2:])] <= max_computers * 5   # not a subdomain of a popular site
            and not any(w in d for w in ('update', 'patch'))]                 # look-alike update sites: Endpoint hunt 7
    series = defaultdict(list)
    for d in doms:
        rows = resolve_all(load(f"SELECT {COLS} FROM proxy WHERE domain = ? AND bytes_out < 5000 AND length(url) < 100", d))
        for r in rows:
            series[(d, r['host'])].append(r)
    for v in series.values():
        v.sort(key=lambda r: r['t'])
    _SERIES[key] = series
    return series


def gap_stats(rs):
    gaps = [b['t'] - a['t'] for a, b in zip(rs, rs[1:])]
    if not gaps:
        return 0, 9.0
    gaps.sort()
    med = gaps[len(gaps) // 2]
    # robust spread: share of gaps within 25% of the median
    near = sum(1 for g in gaps if abs(g - med) <= 0.25 * med) / len(gaps)
    return med, near


# ---------------- 5. Regular check-ins ----------------
@hunt('web5', 'Web analyst', 'Regular check-ins', ['Command and control'],
      {'max_computers': {'default': 20, 'type': 'int', 'label': 'Site used by at most N computers'},
       'min_requests': {'default': 20, 'type': 'int', 'label': 'Min requests from one computer'},
       'min_regular': {'default': 0.6, 'type': 'float', 'label': 'Share of gaps near the usual gap'},
       'max_period_min': {'default': 50, 'type': 'int', 'label': 'Usual gap at most (minutes)'},
       'ignore': {'default': ['vaultdrive.com', 'test.bearcorp.com'], 'type': 'list', 'label': 'Ignore sites'}},
      'One computer sends the same small request to the same site at steady intervals: every few minutes, only at night, or only during work hours.',
      "SELECT src_ip, domain, url, COUNT(*) FROM proxy GROUP BY src_ip, domain, url HAVING COUNT(*) >= :min_requests  -- then check the time gaps")
def web5(p):
    out = []
    for (d, host), rs in checkin_series(p['max_computers'], p['min_requests'], p['ignore']).items():
        if len(rs) < p['min_requests'] or len({r['url'].split('?')[0] for r in rs}) > 3:
            continue
        med, near = gap_stats(rs)
        if near >= p['min_regular'] and 0 < med <= p['max_period_min'] * 60000:
            hours = sorted({int(iso(r['t'])[11:13]) for r in rs})
            out += emit([(None, rs)], 'Command and control', 'web5',
                        lambda x: [f"{len(rs)} requests to {d} every ~{round(med / 60000, 1)} min", f"hours {hours[0]:02d}-{hours[-1]:02d}"])
    return out


# ---------------- 6. Rotating check-ins ----------------
@hunt('web6', 'Web analyst', 'Rotating check-ins', ['Command and control'],
      {'max_computers': {'default': 20, 'type': 'int', 'label': 'Site used by at most N computers'},
       'min_computers': {'default': 3, 'type': 'int', 'label': 'Min computers taking turns'},
       'min_requests': {'default': 20, 'type': 'int', 'label': 'Min requests per computer'},
       'period_min': {'default': 45, 'type': 'int', 'label': 'Each computer: usual gap at least (minutes)'},
       'min_regular': {'default': 0.6, 'type': 'float', 'label': 'Share of gaps near the usual gap'},
       'ignore': {'default': ['vaultdrive.com'], 'type': 'list', 'label': 'Ignore sites'}},
      'Several computers check in to the same site in turn, each about an hour apart, so each one looks quiet.',
      "SELECT domain, COUNT(DISTINCT src_ip) FROM proxy GROUP BY domain HAVING COUNT(DISTINCT src_ip) BETWEEN :min_computers AND :max_computers")
def web6(p):
    by_dom = defaultdict(list)
    for (d, host), rs in checkin_series(p['max_computers'], p['min_requests'], p['ignore']).items():
        if len(rs) < p['min_requests']:
            continue
        med, near = gap_stats(rs)
        if near >= p['min_regular'] and med >= p['period_min'] * 60000:
            by_dom[d].append((host, rs, med))
    out = []
    for d, members in by_dom.items():
        if len(members) < p['min_computers']:
            continue
        for host, rs, med in members:
            out += emit([(None, rs)], 'Command and control', 'web6',
                        lambda x: [f"{len(members)} computers take turns checking in to {d}", f"this one every ~{round(med / 60000)} min, {len(rs)} requests"])
    return out


# ---------------- 7. Hiding in a popular cloud storage site ----------------
@hunt('web7', 'Web analyst', 'Hiding in a popular cloud storage site', ['Command and control', 'Data theft'],
      {'site': {'default': 'vaultdrive.com', 'type': 'str', 'label': 'Cloud storage site'},
       'status_paths': {'default': ['/drive/status'], 'type': 'list', 'label': 'Status-check paths'},
       'trade_paths': {'default': ['/drive/shared/'], 'type': 'list', 'label': 'File-trade paths (GET + PUT)'},
       'upload_paths': {'default': ['/upload/'], 'type': 'list', 'label': 'Bulk upload paths'},
       'min_upload_mb': {'default': 500, 'type': 'int', 'label': 'Bulk upload: min MB in one session'},
       'min_events': {'default': 3, 'type': 'int', 'label': 'Min status checks / trades per computer'}},
      'Inside traffic to a storage site everyone uses: status checks hours apart or small hourly file trades (Command and control), or one user uploading far more than usual (Data theft).',
      "SELECT ts, src_ip, method, url, bytes_out FROM proxy WHERE domain = :site AND (url LIKE '/drive/%' OR method IN ('PUT','POST'))")
def web7(p):
    rows = resolve_all(load(f"SELECT {COLS} FROM proxy WHERE domain = ? AND (url LIKE '/drive/%' OR method IN ('PUT','POST'))", p['site']))
    out = []
    status = [r for r in rows if any(r['url'].startswith(x) for x in p['status_paths'])]
    trades = [r for r in rows if any(r['url'].startswith(x) for x in p['trade_paths'])]
    uploads = [r for r in rows if r['method'] in ('PUT', 'POST') and any(r['url'].startswith(x) for x in p['upload_paths'])]
    for label, rs_all in (('status checks', status), ('file trades', trades)):
        for host, rs in sessions_by(rs_all, lambda r: r['host'], lambda r: r['t'], 10 ** 12):
            if len(rs) >= p['min_events']:
                out += emit([(None, rs)], 'Command and control', 'web7', lambda x: [f"{len(rs)} {label} on {p['site']}", rs[0]['url'][:60]])
    for host, rs in sessions_by(uploads, lambda r: r['host'], lambda r: r['t'], 6 * H):
        mb = sum(r['bytes_out'] for r in rs) / 1e6
        if mb >= p['min_upload_mb']:
            out += emit([(None, rs)], 'Data theft', 'web7', lambda x: [f"{len(rs)} upload chunks, {round(mb)} MB to {p['site']}"])
    return out
