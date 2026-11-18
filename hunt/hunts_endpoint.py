"""Role 3: Endpoint analyst hunts (tables host, usb). Each CMD row gives time, host and process; add the logged-in user."""
from __future__ import annotations

import re
from collections import defaultdict
from functools import lru_cache

from common import finding, iso, ms, q, user_at
from registry import hunt, sessions_by

H = 3600 * 1000


@lru_cache(maxsize=1)
def cmd_rows():
    return [(ms(ts), ts, h, p, t) for ts, h, p, t in q("SELECT ts, host, process, target FROM host WHERE event = 'CMD'")]


def match_cmds(patterns, exclude=()):
    rx = [re.compile(p, re.I) for p in patterns]
    ex = [re.compile(p, re.I) for p in exclude if p]
    out = []
    for t, ts, h, p, cmd in cmd_rows():
        if any(r.search(cmd) for r in rx) and not any(e.search(cmd) for e in ex):
            out.append((t, h, p, cmd))
    return out


IGNORE_USERS = ('pentest',)   # authorized testers


def cmd_findings(rows, category, hunt_id, label):
    out = []
    for t, h, p, cmd in rows:
        u = user_at(h, t)
        if any(x in u for x in IGNORE_USERS):
            continue
        out.append(finding(category, t, h, u, p, hunt_id, [f'{label}: {cmd[:140]}']))
    return out


# ---------------- 1. Persistence and cleanup commands ----------------
@hunt('end1', 'Endpoint analyst', 'Persistence and cleanup commands', ['Host intrusion signs'],
      {'patterns': {'default': [r'authorized_keys', r'crontab', r'useradd', r'\.bashrc', r'history -c', r'rm -f[r]? /var/log', r'rm -rf /var/log',
                                r'unset HISTFILE', r'/etc/crontab', r'systemctl enable', r'\.bash_history'],
                    'type': 'list', 'label': 'Command patterns (regex)'},
       'exclude': {'default': [r'^cat ', r'^less ', r'^vim '], 'type': 'list', 'label': 'Ignore commands matching'}},
      'CMD rows that add an SSH key, a scheduled job, a new user or a startup line, or that clear shell history or delete files in /var/log.',
      "SELECT ts, host, process, target FROM host WHERE event = 'CMD' AND (target LIKE '%authorized_keys%' OR target LIKE '%crontab%' OR target LIKE 'useradd%' OR target LIKE '%.bashrc%' OR target LIKE '%history -c%' OR target LIKE 'rm -f /var/log%')")
def end1(p):
    return cmd_findings(match_cmds(p['patterns'], p['exclude']), 'Host intrusion signs', 'end1', 'persistence/cleanup')


# ---------------- 2. Hands-on-keyboard commands ----------------
@hunt('end2', 'Endpoint analyst', 'Hands-on-keyboard commands', ['Host intrusion signs'],
      {'patterns': {'default': [r'/dev/tcp/', r'\bnc\b.*-e\b', r'\bncat\b.*-e\b', r'socket\.socket\(\).*connect', r'base64 -d', r'base64 --decode',
                                r'find / -perm -4000', r'find / -perm -u=s', r'169\.254\.169\.254'],
                    'type': 'list', 'label': 'Command patterns (regex)'}},
      'Reverse shells (/dev/tcp, nc -e, python3 socket connect), encoded text decoded and run (base64 -d), searches for SUID files, requests to the cloud metadata address.',
      "SELECT ts, host, process, target FROM host WHERE event = 'CMD' AND (target LIKE '%/dev/tcp/%' OR target LIKE '%nc -e%' OR target LIKE '%base64 -d%' OR target LIKE '%-perm -4000%' OR target LIKE '%169.254.169.254%')")
def end2(p):
    return cmd_findings(match_cmds(p['patterns']), 'Host intrusion signs', 'end2', 'hands-on-keyboard')


# ---------------- 3. Temp-folder programs and scanners ----------------
@hunt('end3', 'Endpoint analyst', 'Temp-folder programs and scanners', ['Malware delivery', 'Reconnaissance', 'Command and control'],
      {'tmp_patterns': {'default': [r'(^|&&\s*|;\s*)(/tmp|/dev/shm|/var/tmp)/\S+'], 'type': 'list', 'label': 'Program started from a temp folder (regex)'},
       'tmp_exclude': {'default': [r'^python\d? ', r'crontab', r'^cp ', r'^cat ', r'^(tar|zip|7z) '], 'type': 'list', 'label': 'Not a program start'},
       'scan_patterns': {'default': [r'^nmap\b', r'^masscan\b', r'\bnmap -s', r'\bmasscan '], 'type': 'list', 'label': 'Scanner commands'},
       'ping_size': {'default': 1000, 'type': 'int', 'label': 'Ping tunnel: min packet size (-s)'}},
      'Programs started from /tmp or /dev/shm (Malware delivery); nmap or masscan scans (Reconnaissance); ping with large packets to an outside address (Command and control).',
      "SELECT ts, host, process, target FROM host WHERE event = 'CMD' AND (target LIKE '/tmp/%' OR target LIKE '%&& /tmp/%' OR target LIKE 'nmap %' OR target LIKE 'masscan %' OR target LIKE 'ping -s %')")
def end3(p):
    out = cmd_findings(match_cmds(p['tmp_patterns'], p['tmp_exclude']), 'Malware delivery', 'end3', 'temp-folder program')
    out += cmd_findings(match_cmds(p['scan_patterns']), 'Reconnaissance', 'end3', 'network scan')
    pings = []
    for t, h, proc, cmd in match_cmds([r'\bping\b.*-s\s*\d+']):
        m = re.search(r'-s\s*(\d+)', cmd)
        dst = re.findall(r'(\d+\.\d+\.\d+\.\d+)', cmd)
        if m and int(m.group(1)) >= p['ping_size'] and dst and not dst[-1].startswith(('10.', '192.168.', '172.16.')):
            pings.append((t, h, proc, cmd))
    out += cmd_findings(pings, 'Command and control', 'end3', 'ping tunnel')
    return out


# ---------------- 4. Stolen credentials and USB theft ----------------
@hunt('end4', 'Endpoint analyst', 'Stolen credentials and USB theft', ['Host intrusion signs', 'Data theft'],
      {'cred_patterns': {'default': [r'\.ssh/id_(rsa|ed25519|ecdsa|dsa)\b(?!\.pub)', r'\.aws/credentials', r'gcloud/credentials', r'/etc/shadow',
                                     r'Cookies', r'Login Data', r'logins\.json', r'key4\.db', r'\.kube/config', r'\.git-credentials', r'\.netrc',
                                     r'\.docker/config\.json'],
                         'type': 'list', 'label': 'Secret files (regex)'},
       'cred_exclude': {'default': [r'id_rsa\.pub', r'^ls -l /etc/shadow'], 'type': 'list', 'label': 'Ignore commands matching'},
       'usb_minutes': {'default': 30, 'type': 'int', 'label': 'Archive followed by USB copy within (minutes)'},
       'sensitive_dirs': {'default': ['~/Documents/ ~/Projects/', '/home/ /etc/', '/home ', '/etc '], 'type': 'list',
                          'label': 'Archive of these folders is theft even without USB'}},
      'Commands that read private SSH keys, cloud credentials, password files or browser cookie/password stores (Host intrusion signs); files archived with tar, zip or 7z for theft, often minutes before a large USB copy (Data theft).',
      "SELECT ts, host, process, target FROM host WHERE event = 'CMD' AND (target LIKE '%.ssh/id_rsa' OR target LIKE '%.aws/credentials%' OR target LIKE '%/etc/shadow%' OR target LIKE '%Cookies%')  -- archives: target LIKE 'tar %' OR 'zip %' OR '7z %' joined to usb copies")
def end4(p):
    out = cmd_findings(match_cmds(p['cred_patterns'], p['cred_exclude']), 'Host intrusion signs', 'end4', 'reads secrets')
    usb = defaultdict(list)
    for ts, h, u, mb in q("SELECT ts, host, user, mb FROM usb WHERE action = 'copy'"):
        usb[h].append((ms(ts), mb))
    for t, h, proc, cmd in match_cmds([r'^(tar|zip|7z)\b', r'^\S*7z a\b']):
        after = [(ut, mb) for ut, mb in usb.get(h, []) if 0 <= ut - t <= p['usb_minutes'] * 60000] if '/tmp/' in cmd else []
        sensitive = any(d in cmd for d in p['sensitive_dirs'])
        if after or sensitive:
            ev = [f'archive: {cmd[:120]}'] + ([f'USB copy of {after[0][1]} MB {round((after[0][0] - t) / 60000)} min later'] if after else [])
            out.append(finding('Data theft', t, h, user_at(h, t), proc, 'end4', ev))
    return out


# ---------------- 5. Downloads piped into a shell ----------------
@hunt('end5', 'Endpoint analyst', 'Downloads piped into a shell', ['Malware delivery', 'Host intrusion signs'],
      {'trusted': {'default': ['ctf-tools.hackedu.io', 'get.docker.com', 'sh.rustup.rs', 'raw.githubusercontent.com'], 'type': 'list',
                   'label': 'Trusted setup-script sites'},
       'plugin_processes': {'default': ['plugin-host'], 'type': 'list', 'label': 'Browser plugin processes'}},
      'A command that downloads a URL and pipes it into sh or bash. Run by bash: Malware delivery. Run by a browser plugin process: Host intrusion signs. Known setup scripts are normal.',
      "SELECT ts, host, process, target FROM host WHERE event = 'CMD' AND (target LIKE 'curl%|%sh' OR target LIKE 'wget%|%sh')")
def end5(p):
    out = []
    for t, h, proc, cmd in match_cmds([r'\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b']):
        if any(s in cmd for s in p['trusted']):
            continue
        cat = 'Host intrusion signs' if proc in p['plugin_processes'] else 'Malware delivery'
        out.append(finding(cat, t, h, user_at(h, t), proc, 'end5', [f'download piped to shell: {cmd[:120]}']))
    return out


# ---------------- 6. Unsigned programs and empty desks ----------------
@hunt('end6', 'Endpoint analyst', 'Unsigned programs and empty desks', ['Malware delivery', 'Host intrusion signs'],
      {'max_hash_hosts': {'default': 3, 'type': 'int', 'label': 'Unusual hash: seen on at most N computers'},
       'min_program_hosts': {'default': 100, 'type': 'int', 'label': 'Common program: runs on at least N computers'},
       'empty_desk': {'default': 1, 'type': 'int', 'label': 'Include network activity with nobody logged in (1 = yes)'},
       'empty_desk_max_hosts': {'default': 150, 'type': 'int', 'label': 'Empty desk: program used on at most N computers'},
       'empty_desk_ignore': {'default': ['curl', 'backup-agent', 'ml-train', 'chrome', 'chromium', 'firefox', 'sync_helper', 'vaultdrive_sync',
                                         'invoice_viewer', 'usb-helper', 'crawler', 'nessus', 'dirb'], 'type': 'list', 'label': 'Empty desk: ignore programs'}},
      'PROC_START of a common program that is unsigned or has an unusual hash (Malware delivery, at its first outside NET_CONNECT); network activity while nobody is logged in; SSH that skips host key checks (Host intrusion signs).',
      "SELECT host, process, target FROM host WHERE event = 'PROC_START' AND target LIKE '%signed=no%'")
def end6(p):
    out = []
    starts = q("SELECT ts, host, process, target FROM host WHERE event = 'PROC_START'")
    hosts_per_prog = defaultdict(set)
    hosts_per_hash = defaultdict(set)
    for ts, h, proc, tg in starts:
        m = re.search(r'hash=(\S+) signed=(\S+)', tg)
        hosts_per_prog[proc].add(h)
        if m:
            hosts_per_hash[(proc, m.group(1))].add(h)
    for ts, h, proc, tg in starts:
        m = re.search(r'hash=(\S+) signed=(\S+)', tg)
        if not m or len(hosts_per_prog[proc]) < p['min_program_hosts']:
            continue
        if m.group(2) == 'no' or len(hosts_per_hash[(proc, m.group(1))]) <= p['max_hash_hosts']:
            t0 = ms(ts)
            conns = q("SELECT ts, target FROM host WHERE event = 'NET_CONNECT' AND host = ? AND process = ? AND ts >= ? ORDER BY ts", h, proc, ts)
            outside = [c for c in conns if not c[1].startswith('10.')]
            t1 = ms(outside[0][0]) if outside else t0
            out.append(finding('Malware delivery', t1, h, user_at(h, t1), proc, 'end6',
                               [f'{proc} started unsigned / rare hash ({tg})'] + ([f'first outside connection {outside[0][1]}'] if outside else [])))
    # SSH that skips host key checks
    for t, h, proc, cmd in match_cmds([r'StrictHostKeyChecking=no', r'UserKnownHostsFile=/dev/null']):
        out.append(finding('Host intrusion signs', t, h, user_at(h, t), proc, 'end6', [f'ssh skipping host key check: {cmd[:120]}']))
    # network activity at an empty desk
    if p['empty_desk']:
        progs = [k for k, v in hosts_per_prog.items() if len(v) <= p['empty_desk_max_hosts'] and k not in p['empty_desk_ignore']]
        if progs:
            marks = ','.join('?' * len(progs))
            seen = set()
            for ts, h, proc, tg in q(f"SELECT ts, host, process, target FROM host WHERE event = 'NET_CONNECT' AND process IN ({marks}) ORDER BY ts", *progs):
                if tg.startswith('10.') or (h, proc) in seen:
                    continue
                t = ms(ts)
                if user_at(h, t) == 'none':
                    seen.add((h, proc))
                    out.append(finding('Host intrusion signs', t, h, 'none', proc, 'end6', [f'{proc} connected to {tg} while nobody was logged in'], 'medium'))
    return out


# ---------------- 7. Risky downloads ----------------
@hunt('end7', 'Endpoint analyst', 'Risky downloads', ['Malware delivery'],
      {'extensions': {'default': ['.exe', '.dll', '.scr', '.hta', '.msi', '.ps1', '.jar'], 'type': 'list', 'label': 'Risky file types'},
       'max_computers': {'default': 20, 'type': 'int', 'label': 'Untrusted site: used by at most N computers'},
       'loader_minutes': {'default': 30, 'type': 'int', 'label': 'Loader then second file within (minutes)'},
       'real_update_sites': {'default': ['updates.nexusos.com'], 'type': 'list', 'label': 'Real update sites (look-alikes are flagged)'}},
      '.exe/.dll/.scr/.hta files from untrusted download sites; a loader followed minutes later by a second file; or updates fetched from a look-alike of the real update site. Host and process come from the host table.',
      "SELECT ts, src_ip, domain, url FROM proxy WHERE url LIKE '%.exe%' OR url LIKE '%.dll%' OR url LIKE '%.scr%' OR url LIKE '%.hta%'")
def end7(p):
    from hunts_web import COLS, domain_stats, emit, load, resolve_all
    ext = '|'.join(re.escape(e) for e in p['extensions'])
    like = ' OR '.join(['url LIKE ?'] * len(p['extensions']))
    rows = load(f'SELECT {COLS} FROM proxy WHERE {like}', *[f'%{e}%' for e in p['extensions']])
    stats = domain_stats()
    rows = [r for r in rows if re.search(rf'({ext})(\?|$)', r['url'], re.I) and stats.get(r['domain'], (0, 0))[0] <= p['max_computers']]
    rows = resolve_all(rows)
    out = []
    # one finding per computer per download session (a loader + second stage counts once, at the loader)
    for (host, dom), rs in sessions_by(rows, lambda r: (r['host'], r['domain']), lambda r: r['t'], p['loader_minutes'] * 60000):
        files = sorted({r['url'] for r in rs})
        out += emit([(None, rs)], 'Malware delivery', 'end7', lambda x: [f"downloaded {', '.join(files)[:120]} from {dom}"])
    # look-alike update sites
    real = [s.lower() for s in p['real_update_sites']]
    for d in list(stats):
        dl = d.lower()
        if dl in real or not any(w in dl for w in ('update', 'patch')):
            continue
        if any(r.split('.')[-2] in dl and dl != r for r in real):
            lr = resolve_all(load(f'SELECT {COLS} FROM proxy WHERE domain = ?', d))
            for host, rs in sessions_by(lr, lambda r: r['host'], lambda r: r['t'], 10 ** 12):
                out += emit([(None, rs)], 'Malware delivery', 'end7', lambda x: [f'{len(rs)} fetches from look-alike update site {d}'])
    return out
