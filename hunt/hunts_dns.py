"""Role 1: DNS analyst hunts (tables dns, iocs; host/process from host DNS_QUERY rows)."""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict

from common import (con, finding, hosts_for_ip, iso, ms, q, user_at)
from registry import hunt, sessions_by

H = 3600 * 1000


def base_of(name: str) -> str:
    return '.'.join(name.split('.')[-2:])


def label_of(base: str) -> str:
    return base.split('.')[0]


def dns_process(host: str, t: int, suffix: str, window_ms: int = 2 * H) -> str | None:
    rows = q("SELECT ts, process FROM host WHERE event = 'DNS_QUERY' AND host = ? AND ts BETWEEN ? AND ? AND target LIKE ?",
             host, iso(t - window_ms), iso(t + window_ms), '%' + suffix)
    if not rows:
        return None
    return min(rows, key=lambda r: abs(ms(r[0]) - t))[1]


def resolve_host(src: str, t: int, query: str) -> str | None:
    cands = hosts_for_ip(src, t)
    if len(cands) == 1:
        return cands[0]
    rows = q("SELECT ts, host FROM host WHERE target = ? AND event = 'DNS_QUERY'", query)
    pool = [(abs(ms(ts) - t), h) for ts, h in rows if not cands or h in cands]
    return min(pool)[1] if pool else None


def to_findings(sess, category, hunt_id, suffix_of, evidence_of, confidence='high'):
    out = []
    for host, rows in sess:
        t0 = rows[0]['t']
        proc = dns_process(host, t0, suffix_of(rows)) or 'unknown'
        out.append(finding(category, t0, host, user_at(host, t0), proc, hunt_id, evidence_of(rows), confidence))
    return out


def load(sql: str, *args, keep=None) -> list[dict]:
    rows = []
    for ts, src, qq, qt, rc, ans in q(sql, *args):
        if keep is not None and not keep(qq):
            continue
        t = ms(ts)
        rows.append(dict(t=t, ts=ts, src=src, query=qq, qtype=qt, rcode=rc, answer=ans or ''))
    for r in rows:
        r['host'] = resolve_host(r['src'], r['t'], r['query'])
    return [r for r in rows if r['host']]


def entropy(s: str) -> float:
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values()) if s else 0.0


# ---------------- 1. Known-bad domains ----------------
@hunt('dns1', 'DNS analyst', 'Known-bad domains', ['Known-bad indicators'],
      {'gap_hours': {'default': 6, 'type': 'int', 'label': 'New finding after a quiet gap of (hours)'}},
      'A DNS query that exactly matches a domain in the iocs table. One finding per computer at its first lookup.',
      "SELECT d.ts, d.src_ip, d.query FROM dns d WHERE d.query IN (SELECT value FROM iocs WHERE type = 'domain')")
def dns1(p):
    rows = load("SELECT ts, src_ip, query, qtype, rcode, answer FROM dns WHERE query IN (SELECT value FROM iocs WHERE type = 'domain')")
    sess = sessions_by(rows, lambda r: (r['host'], r['query']), lambda r: r['t'], p['gap_hours'] * H)
    return to_findings([(k[0], v) for k, v in sess], 'Known-bad indicators', 'dns1', lambda rs: rs[0]['query'],
                       lambda rs: [f"looked up {rs[0]['query']} ({len(rs)}x)"])


# ---------------- 2. Lookalike company domains ----------------
def lev(a: str, b: str) -> int:
    p = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        c = [i]
        for j, cb in enumerate(b, 1):
            c.append(min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (ca != cb)))
        p = c
    return p[-1]


def is_transposition(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    d = [i for i in range(len(a)) if a[i] != b[i]]
    return len(d) == 2 and d[1] == d[0] + 1 and a[d[0]] == b[d[1]] and a[d[1]] == b[d[0]]


@hunt('dns2', 'DNS analyst', 'Lookalike company domains', ['Deceptive domains'],
      {'brand': {'default': 'bearcorp', 'type': 'str', 'label': 'Company name'},
       'real_domain': {'default': 'bearcorp.com', 'type': 'str', 'label': 'Real company domain'},
       'max_edits': {'default': 1, 'type': 'int', 'label': 'Max letter edits from the name'},
       'words': {'default': ['login', 'support', 'helpdesk', 'vpn', 'secure', 'portal', 'sso', 'my', 'mail', 'hr', 'it'],
                 'type': 'list', 'label': 'Words added to the name'}},
      'Domains that imitate the company: one letter swapped/missing/doubled/added, name plus a word, or punycode (xn--).',
      "SELECT ts, src_ip, query FROM dns WHERE query LIKE '%bear%' OR query LIKE '%corp%' OR query LIKE 'xn--%' OR query LIKE '%.xn--%'")
def dns2(p):
    brand, real = p['brand'].lower(), p['real_domain'].lower()
    names = [r[0] for r in q('SELECT DISTINCT query FROM dns')]
    bad = set()
    for n in names:
        b = base_of(n.lower())
        if b == real or n.lower().endswith('.' + real):
            continue
        lab = label_of(b)
        hit = False
        if lab.startswith('xn--'):
            hit = True
        elif lab != brand and (lev(lab, brand) <= p['max_edits'] or is_transposition(lab, brand)):
            hit = True
        elif brand in lab and lab != brand:
            rest = lab.replace(brand, '').strip('-')
            hit = rest in p['words'] or len(rest) <= 3 or any(w in rest for w in p['words'])
        elif lab == brand and b != real:
            hit = True  # same name, other top-level domain
        if hit:
            bad.add(n)
    if not bad:
        return []
    marks = ','.join('?' * len(bad))
    rows = load(f'SELECT ts, src_ip, query, qtype, rcode, answer FROM dns WHERE query IN ({marks})', *bad)
    sess = sessions_by(rows, lambda r: (r['host'], base_of(r['query'])), lambda r: r['t'], 24 * H)
    return to_findings([(k[0], v) for k, v in sess], 'Deceptive domains', 'dns2', lambda rs: base_of(rs[0]['query']),
                       lambda rs: [f"lookalike domain {rs[0]['query']}"])


# ---------------- shared: per-host sessions on a domain with many unique names ----------------
def unique_name_sessions(qtypes, min_unique, max_base_sources, gap_h, min_label_len=0):
    marks = ','.join('?' * len(qtypes))
    rows_by_base = defaultdict(list)
    srcs = defaultdict(set)
    for ts, src, qq, qt, rc, ans in q(f'SELECT ts, src_ip, query, qtype, rcode, answer FROM dns WHERE qtype IN ({marks})', *qtypes):
        b = base_of(qq)
        srcs[b].add(src)
        rows_by_base[b].append((ts, src, qq, qt, rc, ans))
    out = []
    for b, rows in rows_by_base.items():
        if len(srcs[b]) > max_base_sources or len({r[2] for r in rows}) < min_unique:
            continue
        recs = []
        for ts, src, qq, qt, rc, ans in rows:
            t = ms(ts)
            recs.append(dict(t=t, ts=ts, src=src, query=qq, qtype=qt, rcode=rc, answer=ans or '', base=b))
        for r in recs:
            r['host'] = resolve_host(r['src'], r['t'], r['query'])
        recs = [r for r in recs if r['host']]
        for (host, base), ss in sessions_by(recs, lambda r: (r['host'], r['base']), lambda r: r['t'], gap_h * H):
            uniq = {r['query'] for r in ss}
            if len(uniq) >= min_unique and max(len(r['query']) - len(r['base']) for r in ss) >= min_label_len:
                out.append((host, ss))
    return out


# ---------------- 3. Data smuggled out through DNS ----------------
@hunt('dns3', 'DNS analyst', 'Data smuggled out through DNS', ['Data theft'],
      {'min_unique': {'default': 20, 'type': 'int', 'label': 'Min unique names in one session'},
       'max_sources': {'default': 50, 'type': 'int', 'label': 'Ignore domains used by more sources than'},
       'gap_hours': {'default': 2, 'type': 'int', 'label': 'Session gap (hours)'}},
      'One computer sends many TXT or AAAA lookups, each a new scrambled name under the same domain.',
      "SELECT src_ip, query, COUNT(DISTINCT query) FROM dns WHERE qtype IN ('TXT','AAAA') GROUP BY src_ip, <base domain> HAVING COUNT(DISTINCT query) >= :min_unique")
def dns3(p):
    sess = unique_name_sessions(['TXT', 'AAAA'], p['min_unique'], p['max_sources'], p['gap_hours'])
    return to_findings(sess, 'Data theft', 'dns3', lambda rs: rs[0]['base'],
                       lambda rs: [f"{len({r['query'] for r in rs})} unique {rs[0]['qtype']} names under {rs[0]['base']}",
                                   f"e.g. {rs[0]['query']}"])


# ---------------- 4. Commands hidden in DNS ----------------
@hunt('dns4', 'DNS analyst', 'Commands hidden in DNS', ['Command and control'],
      {'min_label_len': {'default': 30, 'type': 'int', 'label': 'Long name: min first-label length'},
       'min_unique': {'default': 20, 'type': 'int', 'label': 'Min unique long names in a session'},
       'max_sources': {'default': 50, 'type': 'int', 'label': 'Ignore domains used by more sources than'},
       'min_repeat': {'default': 10, 'type': 'int', 'label': 'Repeated TXT lookups of one name'},
       'long_answer': {'default': 200, 'type': 'int', 'label': 'Answer length counted as huge'},
       'gap_hours': {'default': 2, 'type': 'int', 'label': 'Session gap (hours)'}},
      'Very long scrambled names under one domain in A lookups; repeated TXT lookups of one name with coded answers; or answers hundreds of characters long.',
      "SELECT ... FROM dns WHERE (qtype='A' AND length(query) > :min_label_len) OR (qtype='TXT' AND answer LIKE 'v=cmd%') OR length(answer) >= :long_answer")
def dns4(p):
    out = []
    # (a) long names in A lookups
    sess = unique_name_sessions(['A'], p['min_unique'], p['max_sources'], p['gap_hours'], p['min_label_len'])
    sess = [(h, [r for r in ss if len(r['query']) - len(r['base']) > p['min_label_len']]) for h, ss in sess]
    sess = [(h, ss) for h, ss in sess if len({r['query'] for r in ss}) >= p['min_unique']]
    out += to_findings(sess, 'Command and control', 'dns4', lambda rs: rs[0]['base'],
                       lambda rs: [f"{len(rs)} long A names under {rs[0]['base']}", f"e.g. {rs[0]['query'][:80]}"])
    # (b) one TXT name repeated, coded answers  (c) huge answers
    rows = load("SELECT ts, src_ip, query, qtype, rcode, answer FROM dns WHERE qtype = 'TXT' OR length(answer) >= ?", p['long_answer'])
    srcs = defaultdict(set)
    for r in rows:
        srcs[base_of(r['query'])].add(r['src'])
    rows = [r for r in rows if len(srcs[base_of(r['query'])]) <= p['max_sources']]
    for (host, qname), ss in sessions_by(rows, lambda r: (r['host'], base_of(r['query'])), lambda r: r['t'], p['gap_hours'] * H):
        big = [r for r in ss if len(r['answer']) >= p['long_answer']]
        names = Counter(r['query'] for r in ss if r['qtype'] == 'TXT')
        top, n = (names.most_common(1)[0] if names else ('', 0))
        coded = [r for r in ss if r['qtype'] == 'TXT' and r['query'] == top and (len(r['answer']) >= 24 and entropy(r['answer']) > 4)]
        if big:
            out += to_findings([(host, big)], 'Command and control', 'dns4', lambda rs: base_of(rs[0]['query']),
                               lambda rs: [f"{len(rs)} answers of {max(len(r['answer']) for r in rs)}+ characters from {base_of(rs[0]['query'])}"])
        elif n >= p['min_repeat'] and len(coded) >= p['min_repeat'] // 2:
            out += to_findings([(host, [r for r in ss if r['query'] == top])], 'Command and control', 'dns4', lambda rs: rs[0]['query'],
                               lambda rs: [f"{len(rs)} TXT lookups of {rs[0]['query']}", f"answer: {rs[0]['answer'][:60]}"])
    return out


# ---------------- 5. Made-up domains ----------------
@hunt('dns5', 'DNS analyst', 'Made-up domains', ['Reconnaissance'],
      {'min_nx': {'default': 15, 'type': 'int', 'label': 'Min NXDOMAIN answers per computer'},
       'min_subdomains': {'default': 20, 'type': 'int', 'label': 'Subdomain guessing: min names under one domain'},
       'gap_hours': {'default': 3, 'type': 'int', 'label': 'Session gap (hours)'},
       'ignore_repeat_ratio': {'default': 0.5, 'type': 'float', 'label': 'Ignore if names repeat more than (share)'}},
      'One computer gets many NXDOMAIN answers for random or two-word names (a burst or spread over hours), or guesses many subdomains of one domain.',
      "SELECT src_ip, COUNT(*), COUNT(DISTINCT query) FROM dns WHERE rcode = 'NXDOMAIN' GROUP BY src_ip HAVING COUNT(*) >= :min_nx")
def dns5(p):
    rows = load("SELECT ts, src_ip, query, qtype, rcode, answer FROM dns WHERE rcode = 'NXDOMAIN'")
    out = []
    for host, ss in sessions_by(rows, lambda r: r['host'], lambda r: r['t'], p['gap_hours'] * H):
        names = [r['query'] for r in ss]
        uniq = set(names)
        bases = Counter(base_of(n) for n in uniq)
        if len(names) < p['min_nx'] or (len(bases) > 1 and len(uniq) < len(names) * (1 - p['ignore_repeat_ratio'])):
            continue
        top_base, top_n = bases.most_common(1)[0]
        if len(bases) == 1:
            # subdomain guessing of one domain: include the found (NOERROR) guesses too
            if top_n < p['min_subdomains']:
                continue
            all_rows = load("SELECT ts, src_ip, query, qtype, rcode, answer FROM dns WHERE src_ip IN (SELECT DISTINCT src_ip FROM dns WHERE query LIKE ?) AND query LIKE ? AND ts BETWEEN ? AND ?",
                            '%.' + top_base, '%.' + top_base, iso(ss[0]['t'] - 10 * 60 * 1000), iso(ss[-1]['t']))
            mine = sorted([r for r in all_rows if r['host'] == host], key=lambda r: r['t']) or ss
            first = mine[0]
            out += to_findings([(host, [first] + ss)], 'Reconnaissance', 'dns5', lambda rs: top_base,
                               lambda rs: [f"guessed {top_n} subdomains of {top_base}", f"e.g. {', '.join(sorted(uniq)[:4])}"])
        else:
            out += to_findings([(host, ss)], 'Reconnaissance', 'dns5', lambda rs: base_of(rs[0]['query']),
                               lambda rs: [f"{len(rs)} NXDOMAIN answers for {len(bases)} made-up domains", f"e.g. {', '.join(list(uniq)[:3])}"])
    return out


# ---------------- 7. Spread-out subdomain sweep ----------------
@hunt('dns7', 'DNS analyst', 'Spread-out subdomain sweep', ['Reconnaissance'],
      {'min_hosts': {'default': 3, 'type': 'int', 'label': 'Min computers sweeping the same domain'},
       'max_per_host': {'default': 30, 'type': 'int', 'label': 'Max names per computer (quiet sweep)'},
       'min_per_host': {'default': 3, 'type': 'int', 'label': 'Min names per computer'},
       'window_hours': {'default': 3, 'type': 'int', 'label': 'All within (hours)'}},
      'Several computers each look up a few made-up subdomains of the same outside domain, so no single computer looks busy.',
      "SELECT <base>, COUNT(DISTINCT src_ip) FROM dns WHERE rcode = 'NXDOMAIN' GROUP BY <base> HAVING COUNT(DISTINCT src_ip) >= :min_hosts")
def dns7(p):
    rows = load("SELECT ts, src_ip, query, qtype, rcode, answer FROM dns WHERE rcode = 'NXDOMAIN'")
    by_base = defaultdict(list)
    for r in rows:
        by_base[base_of(r['query'])].append(r)
    out = []
    for b, rs in by_base.items():
        if b.endswith('bearcorp.com'):
            continue
        per = defaultdict(list)
        for r in rs:
            per[r['host']].append(r)
        names_per = {h: {r['query'] for r in v} for h, v in per.items()}
        sweepers = [h for h, n in names_per.items() if p['min_per_host'] <= len(n) <= p['max_per_host']]
        repeated = sum(len(v) for v in per.values()) > 20 * max(1, len(set(r['query'] for r in rs)))
        if len(sweepers) < p['min_hosts'] or repeated:
            continue
        span = max(r['t'] for r in rs) - min(r['t'] for r in rs)
        if span > p['window_hours'] * H:
            continue
        for h in sweepers:
            # include the host's NOERROR lookups of the same domain: the sweep starts at its first guess
            ss = sorted(per[h], key=lambda r: r['t'])
            alln = q("SELECT ts FROM host WHERE event = 'DNS_QUERY' AND host = ? AND ts BETWEEN ? AND ? AND target LIKE ? ORDER BY ts LIMIT 1",
                     h, iso(ss[0]['t'] - H), iso(ss[0]['t']), '%.' + b)
            if alln:
                ss = [dict(ss[0], t=ms(alln[0][0]))] + ss
            out += to_findings([(h, ss)], 'Reconnaissance', 'dns7', lambda x: b,
                               lambda x: [f"{len(names_per[h])} subdomains of {b}; {len(sweepers)} computers swept it"])
    return out


# ---------------- 6. New and shifting domains ----------------
@hunt('dns6', 'DNS analyst', 'New and shifting domains', ['Command and control'],
      {'burst_min': {'default': 20, 'type': 'int', 'label': 'Burst: min brand-new domains'},
       'burst_minutes': {'default': 10, 'type': 'int', 'label': 'Burst: within (minutes)'},
       'flux_min_ips': {'default': 8, 'type': 'int', 'label': 'Flux: min different IPs for one name'},
       'beacon_min': {'default': 20, 'type': 'int', 'label': 'Steady: min lookups'},
       'beacon_max_cv': {'default': 0.35, 'type': 'float', 'label': 'Steady: max spread of gaps (std/mean)'},
       'beacon_min_hours': {'default': 3, 'type': 'int', 'label': 'Steady: lasting at least (hours)'},
       'max_sources': {'default': 20, 'type': 'int', 'label': 'Ignore domains used by more sources than'}},
      'Dozens of never-seen domains resolving within minutes; one name returning many IPs; a name sharing an IP with an iocs domain; or one computer looking up one name at steady intervals for hours.',
      "SELECT query, COUNT(DISTINCT answer) FROM dns GROUP BY query HAVING COUNT(DISTINCT answer) >= :flux_min_ips")
def dns6(p):
    out = []
    # base -> number of sources overall
    src_n = defaultdict(set)
    for b, s in q("SELECT query, src_ip FROM dns GROUP BY query, src_ip"):
        src_n[base_of(b)].add(s)
    rare = {b for b, s in src_n.items() if len(s) == 1}
    # (a) burst of brand-new domains
    rows = load("SELECT ts, src_ip, query, qtype, rcode, answer FROM dns WHERE rcode = 'NOERROR' AND qtype = 'A'",
                keep=lambda n: base_of(n) in rare) if rare else []
    for host, ss in sessions_by(rows, lambda r: r['host'], lambda r: r['t'], p['burst_minutes'] * 60 * 1000):
        doms = {base_of(r['query']) for r in ss}
        if len(doms) >= p['burst_min'] and ss[-1]['t'] - ss[0]['t'] <= p['burst_minutes'] * 60 * 1000:
            out += to_findings([(host, ss)], 'Command and control', 'dns6', lambda rs: rs[0]['query'],
                               lambda rs: [f"{len(doms)} never-seen domains resolved in {round((rs[-1]['t'] - rs[0]['t']) / 60000)} min", f"e.g. {', '.join(sorted(doms)[:3])}"])
    # (b) fast flux
    flux = [n for n, k in q("SELECT query, COUNT(DISTINCT answer) k FROM dns WHERE rcode = 'NOERROR' AND qtype = 'A' GROUP BY query HAVING k >= ?", p['flux_min_ips'])
            if len(src_n[base_of(n)]) <= p['max_sources']]
    for n in flux:
        rows = load("SELECT ts, src_ip, query, qtype, rcode, answer FROM dns WHERE query = ?", n)
        for host, ss in sessions_by(rows, lambda r: r['host'], lambda r: r['t'], 6 * H):
            out += to_findings([(host, ss)], 'Command and control', 'dns6', lambda rs: n,
                               lambda rs: [f"{n} returned {len({r['answer'] for r in rs})} different IPs"])
    # (c) shares an IP with a known-bad domain
    ips = [a for (a,) in q("SELECT DISTINCT answer FROM dns WHERE query IN (SELECT value FROM iocs WHERE type = 'domain')")]
    if ips:
        marks = ','.join('?' * len(ips))
        rows = load(f"SELECT ts, src_ip, query, qtype, rcode, answer FROM dns WHERE answer IN ({marks}) AND query NOT IN (SELECT value FROM iocs)", *ips)
        for (host, n), ss in sessions_by(rows, lambda r: (r['host'], r['query']), lambda r: r['t'], 24 * H):
            out += to_findings([(host, ss)], 'Command and control', 'dns6', lambda rs: n,
                               lambda rs: [f"{n} resolves to {rs[0]['answer']}, the same IP as a domain in iocs"])
    # (d) steady lookups of one name for hours
    small = [b for b, s in src_n.items() if len(s) <= p['max_sources']]
    counts = q("SELECT query, COUNT(*) c FROM dns WHERE qtype = 'A' GROUP BY query HAVING c >= ?", p['beacon_min'])
    small = set(small)
    names = [n for n, c in counts if base_of(n) in small]
    for n in names:
        rows = load("SELECT ts, src_ip, query, qtype, rcode, answer FROM dns WHERE query = ?", n)
        done = set()
        for host, ss in sorted(sessions_by(rows, lambda r: r['host'], lambda r: r['t'], 6 * H), key=lambda x: x[1][0]['t']):
            if host in done or len(ss) < p['beacon_min'] or ss[-1]['t'] - ss[0]['t'] < p['beacon_min_hours'] * H:
                continue
            gaps = [b['t'] - a['t'] for a, b in zip(ss, ss[1:])]
            mean = sum(gaps) / len(gaps)
            cv = (sum((g - mean) ** 2 for g in gaps) / len(gaps)) ** 0.5 / mean if mean else 9
            if cv <= p['beacon_max_cv']:
                done.add(host)
                first = min((r for r in rows if r['host'] == host), key=lambda r: r['t'])
                out += to_findings([(host, [first] + ss)], 'Command and control', 'dns6', lambda rs: n,
                                   lambda rs: [f"{len(rs)} lookups of {n} every ~{round(mean / 60000, 1)} min for {round((rs[-1]['t'] - rs[0]['t']) / H)} h"])
    return out
