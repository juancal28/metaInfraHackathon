#!/usr/bin/env python3
"""Make an indexed working copy of bearcorp.db (the original is left untouched).

    python3 hunt/make_indexes.py [--out ~/bearcorp-work/bearcorp.db]
"""
import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, '..', 'dataset', 'bearcorp.db')
INDEXES = [
    'CREATE INDEX IF NOT EXISTS ix_host_ev ON host(event, host, ts)',
    'CREATE INDEX IF NOT EXISTS ix_host_hostts ON host(host, ts)',
    'CREATE INDEX IF NOT EXISTS ix_proxy_domain ON proxy(domain)',
    'CREATE INDEX IF NOT EXISTS ix_proxy_src ON proxy(src_ip, ts)',
    'CREATE INDEX IF NOT EXISTS ix_dns_src ON dns(src_ip, ts)',
    'CREATE INDEX IF NOT EXISTS ix_auth_user ON auth(user, ts)',
    'ANALYZE',
]

ap = argparse.ArgumentParser()
ap.add_argument('--out', default=os.path.expanduser('~/bearcorp-work/bearcorp.db'))
out = ap.parse_args().out
os.makedirs(os.path.dirname(out), exist_ok=True)
if not os.path.exists(out):
    print('copying database ...')
    if sys.platform == 'darwin':
        subprocess.run(['cp', '-c', SRC, out], check=False)   # instant clone on APFS
    if not os.path.exists(out):
        shutil.copyfile(SRC, out)
con = sqlite3.connect(out)
con.execute('PRAGMA journal_mode=OFF')
con.execute('PRAGMA synchronous=OFF')
for sql in INDEXES:
    t = time.time()
    con.execute(sql)
    con.commit()
    print(f'{time.time() - t:6.1f}s  {sql}')
print('done:', out)
