"""Role 4: Identity analyst hunts (tables auth, vpn, ldap, fw, flow).
Outside login attacks: host = the account owner's workstation, user = that account, process = the service (sso, vpn, kerberos).
Activity from an inside computer: that computer's rows in the host table."""
from __future__ import annotations

import re
from collections import defaultdict

from common import finding, hosts_for_ip, ip_of_host, iso, ms, q, user_at, users_table, workstation_of
from registry import hunt, sessions_by

H = 3600 * 1000
MIN = 60 * 1000


def is_inside(ip: str) -> bool:
    return ip.startswith('10.')


def outside_finding(cat, t, user, service, hunt_id, ev, confidence='high'):
    ws = workstation_of(user)
    if not ws:
        return None
    return finding(cat, t, ws, user, service, hunt_id, ev, confidence)


def sso_rows():
    return [(ms(ts), u, src, r, m) for ts, u, src, r, m in q("SELECT ts, user, src, result, mfa FROM auth WHERE service = 'sso' ORDER BY ts")]


# ---------------- 1. MFA fatigue ----------------
@hunt('id1', 'Identity analyst', 'MFA fatigue', ['Credential abuse'],
      {'min_fails': {'default': 10, 'type': 'int', 'label': 'Min failed SSO logins'},
       'window_min': {'default': 30, 'type': 'int', 'label': 'Within (minutes)'},
       'success_within_min': {'default': 60, 'type': 'int', 'label': 'Then a success within (minutes)'}},
      'One user gets many failed SSO logins within 30 minutes, then a success from the same source. Reported at the first failed login.',
      """SELECT a.user, MIN(a.ts) AS first_failure, COUNT(*) AS failures FROM auth a WHERE a.service = 'sso' AND a.result = 'fail'
GROUP BY a.user, a.src HAVING failures >= :min_fails AND EXISTS (SELECT 1 FROM auth s WHERE s.user = a.user AND s.src = a.src AND s.result = 'success')""")
def id1(p):
    by = defaultdict(list)
    for t, u, src, r, m in sso_rows():
        by[(u, src)].append((t, r))
    out = []
    for (u, src), ev in by.items():
        i = 0
        while i < len(ev):
            t0, r0 = ev[i]
            if r0 != 'fail':
                i += 1
                continue
            win = [e for e in ev[i:] if e[0] - t0 <= p['window_min'] * MIN]
            fails = [e for e in win if e[1] == 'fail']
            if len(fails) >= p['min_fails']:
                last = max(e[0] for e in fails)
                ok = [e for e in ev if e[1] == 'success' and t0 < e[0] <= last + p['success_within_min'] * MIN]
                if ok:
                    f = outside_finding('Credential abuse', t0, u, 'sso', 'id1', [f'{len(fails)} failed SSO logins from {src} in {p["window_min"]} min, then success at {iso(ok[0][0])[11:19]}'])
                    if f:
                        out.append(f)
                    i = next((k for k, e in enumerate(ev) if e[0] > ok[0][0]), len(ev))
                    continue
            i += 1
    return out


# ---------------- 2. Directory dumps and blocked connections ----------------
@hunt('id2', 'Identity analyst', 'Directory dumps and blocked connections', ['Reconnaissance', 'Command and control'],
      {'min_wildcards': {'default': 10, 'type': 'int', 'label': 'LDAP: min wildcard searches from one host'},
       'gap_hours': {'default': 6, 'type': 'int', 'label': 'LDAP: session gap (hours)'},
       'fw_rule': {'default': 'threat-intel-block', 'type': 'str', 'label': 'Firewall rule'},
       'min_denies': {'default': 3, 'type': 'int', 'label': 'Firewall: min denials from one address'}},
      'ldap: one host runs many searches with wildcard filters such as (uid=*) (Reconnaissance). fw: one address denied again and again by the threat-intel-block rule (Command and control), one finding per host at its first denial.',
      "SELECT host, COUNT(*) FROM ldap WHERE filter LIKE '%=*)%' GROUP BY host  -- and: SELECT src_ip, MIN(ts) FROM fw WHERE rule = 'threat-intel-block' GROUP BY src_ip")
def id2(p):
    out = []
    rows = [(ms(ts), h, u, f) for ts, h, u, f in q("SELECT ts, host, user, filter FROM ldap") if re.search(r'=\*\)', f)]
    for h, ss in sessions_by(rows, lambda r: r[1], lambda r: r[0], p['gap_hours'] * H):
        if len(ss) < p['min_wildcards']:
            continue
        t0 = ss[0][0]
        pr = q("SELECT process FROM host WHERE event = 'NET_CONNECT' AND host = ? AND ts BETWEEN ? AND ? AND target LIKE '%:389'", h, iso(t0 - 5 * MIN), iso(t0 + 5 * MIN))
        out.append(finding('Reconnaissance', t0, h, user_at(h, t0), pr[0][0] if pr else 'ldapsearch', 'id2',
                           [f'{len(ss)} wildcard LDAP searches, e.g. {", ".join(sorted({r[3] for r in ss})[:3])}']))
    denies = defaultdict(list)
    for ts, src, dst, port in q("SELECT ts, src_ip, dst_ip, dst_port FROM fw WHERE rule = ? AND action = 'deny' ORDER BY ts", p['fw_rule']):
        t = ms(ts)
        for h in hosts_for_ip(src, t):
            denies[h].append((t, dst, port))
    for h, ds in denies.items():
        if len(ds) < p['min_denies']:
            continue
        t0, dst, port = ds[0]
        pr = q("SELECT ts, process FROM host WHERE event = 'NET_CONNECT' AND host = ? AND target LIKE ? AND ts BETWEEN ? AND ?", h, dst + ':%', iso(t0 - 5 * MIN), iso(t0 + 5 * MIN))
        proc = min(pr, key=lambda r: abs(ms(r[0]) - t0))[1] if pr else 'unknown'
        out.append(finding('Command and control', t0, h, user_at(h, t0), proc, 'id2', [f'{len(ds)} connections to {dst}:{port} denied by {p["fw_rule"]}']))
    return out


# ---------------- 3. VPN uploads and password spraying ----------------
def spray_bursts(gap_min, min_users):
    by = defaultdict(list)
    for t, u, src, r, m in sso_rows():
        if not is_inside(src) and re.match(r'^\d+\.', src):
            by[src].append((t, u, r))
    bursts = []
    for src, ev in by.items():
        for _, b in sessions_by(ev, lambda e: src, lambda e: e[0], gap_min * MIN):
            if len({e[1] for e in b}) >= min_users:
                bursts.append((src, b))
    return bursts


@hunt('id3', 'Identity analyst', 'VPN uploads and password spraying', ['Data theft', 'Credential abuse'],
      {'up_ratio': {'default': 3.0, 'type': 'float', 'label': 'VPN: upload / download at least'},
       'min_up_mb': {'default': 300, 'type': 'int', 'label': 'VPN: upload at least (MB)'},
       'spray_gap_min': {'default': 15, 'type': 'int', 'label': 'Spray: burst ends after a gap of (minutes)'},
       'spray_min_users': {'default': 5, 'type': 'int', 'label': 'Spray: min different users in a burst'}},
      'vpn sessions that upload far more than they download (Data theft). One outside address fails SSO for many users in short bursts, each ending with one account getting in (Credential abuse), reported at the first failed login of its burst.',
      "SELECT ts, user, bytes_up, bytes_down FROM vpn WHERE bytes_up > :up_ratio * bytes_down  -- spraying: SELECT src, COUNT(DISTINCT user) FROM auth WHERE service='sso' AND result='fail' GROUP BY src")
def id3(p):
    out = []
    for ts, u, src, dur, up, down in q('SELECT ts, user, src_ip, duration_ms, bytes_up, bytes_down FROM vpn'):
        if up >= p['min_up_mb'] * 1e6 and up >= p['up_ratio'] * max(down, 1):
            f = outside_finding('Data theft', ms(ts), u, 'vpn', 'id3', [f'VPN from {src}: up {round(up / 1e6)} MB, down {round(down / 1e6)} MB'])
            if f:
                out.append(f)
    for src, b in spray_bursts(p['spray_gap_min'], p['spray_min_users']):
        wins = [e for e in b if e[2] == 'success']
        for w in wins:
            f = outside_finding('Credential abuse', b[0][0], w[1], 'sso', 'id3',
                                [f'{src} tried {len({e[1] for e in b})} accounts in {round((b[-1][0] - b[0][0]) / MIN)} min; {w[1]} got in'])
            if f:
                out.append(f)
    return out


# ---------------- 4. Service accounts and admins over SSH ----------------
@hunt('id4', 'Identity analyst', 'Service accounts and admins over SSH', ['Credential abuse'],
      {'service_prefix': {'default': 'svc-', 'type': 'str', 'label': 'Service account prefix'},
       'admin_prefix': {'default': 'admin-', 'type': 'str', 'label': 'Admin account prefix'},
       'night_start': {'default': 20, 'type': 'int', 'label': 'Night starts (hour, UTC)'},
       'night_end': {'default': 6, 'type': 'int', 'label': 'Night ends (hour, UTC)'}},
      'CMD rows where a workstation runs ssh as a service account (svc-...) or, at night, as an admin account (admin-...). Report the workstation, its logged-in user and process bash.',
      "SELECT ts, host, process, target FROM host WHERE event = 'CMD' AND host LIKE 'WS-%' AND (target LIKE 'ssh svc-%' OR target LIKE 'ssh %admin-%')")
def id4(p):
    out = []
    for ts, h, proc, cmd in q("SELECT ts, host, process, target FROM host WHERE event = 'CMD' AND target LIKE 'ssh %'"):
        if not h.startswith('WS-'):
            continue
        m = re.search(r'\b([\w.-]+)@', cmd)
        acct = m.group(1) if m else ''
        hr = int(ts[11:13])
        night = hr >= p['night_start'] or hr < p['night_end']
        if acct.startswith(p['service_prefix']) or (acct.startswith(p['admin_prefix']) and night):
            t = ms(ts)
            out.append(finding('Credential abuse', t, h, user_at(h, t), proc, 'id4', [f'{cmd} at {ts[11:16]} UTC']))
    return out


# ---------------- 5. Kerberos ticket bursts and fake accounts ----------------
@hunt('id5', 'Identity analyst', 'Kerberos ticket bursts and fake accounts', ['Credential abuse', 'Reconnaissance'],
      {'cmd_pattern': {'default': r'python\d?\s+\S*(tgs|spn|roast|GetUserSPNs)', 'type': 'str', 'label': 'Odd python3 command (regex)'},
       'within_min': {'default': 10, 'type': 'int', 'label': 'Tickets within (minutes) of the command'},
       'min_services': {'default': 5, 'type': 'int', 'label': 'Min different services requested'},
       'min_fake': {'default': 5, 'type': 'int', 'label': 'Fake accounts: min unknown accounts failing'}},
      'One user requests tickets for many services within seconds, right after an odd python3 command (Credential abuse). Kerberos failures for many accounts missing from the users table (Reconnaissance). Process kerberos for both.',
      "SELECT user, src, COUNT(DISTINCT target) FROM auth WHERE service = 'kerberos' GROUP BY user, src  -- joined to the python3 CMD just before")
def id5(p):
    out = []
    rx = re.compile(p['cmd_pattern'], re.I)
    for ts, h, proc, cmd in q("SELECT ts, host, process, target FROM host WHERE event = 'CMD' AND target LIKE 'python%'"):
        if not rx.search(cmd):
            continue
        t = ms(ts)
        ip = ip_of_host(h, t)
        if not ip:
            continue
        tk = q("SELECT ts, user, target FROM auth WHERE service = 'kerberos' AND src = ? AND ts BETWEEN ? AND ? ORDER BY ts",
               ip, iso(t - MIN), iso(t + p['within_min'] * MIN))
        by_user = defaultdict(list)
        for kts, u, tg in tk:
            by_user[u].append((ms(kts), tg))
        for u, v in by_user.items():
            if len({x[1] for x in v}) >= p['min_services']:
                out.append(finding('Credential abuse', v[0][0], h, u, 'kerberos', 'id5', [f'{len(v)} ticket requests for {len({x[1] for x in v})} services after: {cmd[:80]}']))
    known = set(users_table())
    bad = defaultdict(list)
    for ts, u, src in q("SELECT ts, user, src FROM auth WHERE service = 'kerberos' AND result = 'fail' ORDER BY ts"):
        if u not in known:
            bad[src].append((ms(ts), u))
    for src, v in bad.items():
        if len({x[1] for x in v}) < p['min_fake']:
            continue
        t0 = v[0][0]
        hs = hosts_for_ip(src, t0)
        if hs:
            out.append(finding('Reconnaissance', t0, hs[0], user_at(hs[0], t0), 'kerberos', 'id5', [f'Kerberos failures for {len({x[1] for x in v})} accounts not in the users table, e.g. {", ".join(sorted({x[1] for x in v})[:3])}']))
    return out


# ---------------- 6. Remote access to new servers ----------------
@hunt('id6', 'Identity analyst', 'Remote access to new servers', ['Lateral movement', 'Reconnaissance'],
      {'patterns': {'default': [r'smbclient.*(recurse|mget)', r'wmic.*process call create', r'(winrs|winexe).*admin-',
                                r'(winrs|winexe).*(pw-nt-hash|aad3b435|%[0-9a-f]{32})'], 'type': 'list', 'label': 'Attack commands (regex)'},
       'rdp_match_min': {'default': 5, 'type': 'int', 'label': 'xfreerdp: admin RDP sign-in without MFA within (minutes)'},
       'probe_min_ports': {'default': 8, 'type': 'int', 'label': 'Probing: min different server ports'},
       'probe_ignore': {'default': ['bash', 'curl', 'backup-agent', 'masscan'], 'type': 'list', 'label': 'Probing: ignore programs'}},
      'smbclient copying a whole share, wmic starting a hidden process, winrs/winexe as an admin- account or with a password hash, and xfreerdp matched to an admin RDP sign-in without MFA (Lateral movement). A workstation slowly probing many ports on a server (Reconnaissance).',
      "SELECT ts, host, process, target FROM host WHERE event = 'CMD' AND (target LIKE 'smbclient%mget%' OR target LIKE 'wmic%process call create%' OR target LIKE 'winrs%admin-%' OR target LIKE 'winexe%' OR target LIKE 'xfreerdp /u:admin-%')")
def id6(p):
    out = []
    rx = [re.compile(x, re.I) for x in p['patterns']]
    cmds = q("SELECT ts, host, process, target FROM host WHERE event = 'CMD' AND (target LIKE 'smbclient%' OR target LIKE 'wmic%' OR target LIKE 'winrs%' OR target LIKE 'winexe%' OR target LIKE 'xfreerdp%')")
    rdp = [(ms(ts), u, src) for ts, u, src in q("SELECT ts, user, src FROM auth WHERE service = 'rdp' AND result = 'success' AND mfa = 'no' AND user LIKE 'admin-%'")]
    for ts, h, proc, cmd in cmds:
        t = ms(ts)
        hit = any(r.search(cmd) for r in rx)
        if not hit and cmd.startswith('xfreerdp'):
            m = re.search(r'/u:(admin-[\w-]+)', cmd)
            ip = ip_of_host(h, t)
            hit = bool(m and any(u == m.group(1) and src == ip and abs(rt - t) <= p['rdp_match_min'] * MIN for rt, u, src in rdp))
        if hit:
            out.append(finding('Lateral movement', t, h, user_at(h, t), proc, 'id6', [cmd[:140]]))
    # slow port probing of a server
    progs = [x for x in p['probe_ignore']]
    marks = ','.join('?' * len(progs))
    ports = defaultdict(list)
    for ts, h, proc, tg in q(f"SELECT ts, host, process, target FROM host WHERE event = 'NET_CONNECT' AND target LIKE '10.%' AND process NOT IN ({marks})", *progs):
        if ':' in tg:
            ports[(h, proc)].append((ms(ts), tg))
    for (h, proc), v in ports.items():
        if len({x[1] for x in v}) >= p['probe_min_ports'] and h.startswith('WS-'):
            v.sort()
            servers = sorted({x[1].rsplit(':', 1)[0] for x in v})
            out.append(finding('Reconnaissance', v[0][0], h, user_at(h, v[0][0]), proc, 'id6',
                               [f'{proc} probed {len({x[1] for x in v})} ports on {len(servers)} server(s) over {round((v[-1][0] - v[0][0]) / MIN)} min']))
    return out


# ---------------- 7. Impossible travel and slow spraying ----------------
@hunt('id7', 'Identity analyst', 'Impossible travel and slow spraying', ['Credential abuse'],
      {'travel_min': {'default': 60, 'type': 'int', 'label': 'Travel: two networks within (minutes)'},
       'net_octets': {'default': 2, 'type': 'int', 'label': 'Travel: networks differ in the first N octets'},
       'slow_max_per_hour': {'default': 3, 'type': 'float', 'label': 'Slow spray: max attempts per hour'},
       'slow_min_days': {'default': 0.5, 'type': 'float', 'label': 'Slow spray: spread over at least (days)'},
       'slow_min_users': {'default': 5, 'type': 'int', 'label': 'Slow spray: min different users tried'}},
      'One user logs in to the VPN from two addresses in different networks within an hour (first login). One outside address tries a few SSO logins an hour or fewer, spread over one to four days, before one works (first attempt).',
      "SELECT a.user, a.ts, a.src_ip, b.src_ip FROM vpn a JOIN vpn b ON a.user = b.user AND b.ts > a.ts AND julianday(b.ts) - julianday(a.ts) < 1.0/24 AND substr(a.src_ip,1,7) != substr(b.src_ip,1,7)")
def id7(p):
    out = []
    by = defaultdict(list)
    for ts, u, src in q('SELECT ts, user, src_ip FROM vpn ORDER BY ts'):
        by[u].append((ms(ts), src))
    net = lambda ip: '.'.join(ip.split('.')[:p['net_octets']])
    for u, v in by.items():
        for a, b in zip(v, v[1:]):
            if b[0] - a[0] <= p['travel_min'] * MIN and net(a[1]) != net(b[1]):
                f = outside_finding('Credential abuse', a[0], u, 'vpn', 'id7', [f'VPN from {a[1]} then {b[1]} {round((b[0] - a[0]) / MIN)} min later'])
                if f:
                    out.append(f)
                break
    ev = defaultdict(list)
    for t, u, src, r, m in sso_rows():
        if not is_inside(src) and re.match(r'^\d+\.', src):
            ev[src].append((t, u, r))
    for src, v in ev.items():
        users = {e[1] for e in v}
        span = v[-1][0] - v[0][0]
        if len(users) < p['slow_min_users'] or span < p['slow_min_days'] * 24 * H or span > 5 * 24 * H:
            continue
        if len(v) / max(span / H, 1) > p['slow_max_per_hour']:
            continue
        wins = [e for e in v if e[2] == 'success']
        if len(wins) == 1:
            f = outside_finding('Credential abuse', v[0][0], wins[0][1], 'sso', 'id7',
                                [f'{src}: {len(v)} attempts on {len(users)} accounts over {round(span / (24 * H), 1)} days before {wins[0][1]} got in'])
            if f:
                out.append(f)
    return out
