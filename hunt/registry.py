"""Hunt registry: every detection registers its id, role, title, categories, tunable settings and SQL summary."""
from __future__ import annotations

HUNTS: dict[str, dict] = {}


def hunt(id: str, role: str, title: str, categories: list[str], params: dict, describe: str, sql: str = ''):
    """params: name -> {default, label, type ('int'|'float'|'list'|'str'), help}."""
    def wrap(fn):
        HUNTS[id] = dict(id=id, role=role, title=title, categories=categories, params=params, describe=describe,
                         sql=sql.strip(), fn=fn)
        return fn
    return wrap


def defaults(h: dict) -> dict:
    return {k: v['default'] for k, v in h['params'].items()}


def run(hunt_id: str, overrides: dict | None = None) -> list[dict]:
    h = HUNTS[hunt_id]
    p = defaults(h)
    for k, v in (overrides or {}).items():
        if k in p and v is not None:
            t = h['params'][k].get('type', 'str')
            if t == 'int':
                v = int(v)
            elif t == 'float':
                v = float(v)
            elif t == 'list' and isinstance(v, str):
                v = [x.strip() for x in v.split(',') if x.strip()]
            p[k] = v
    out = h['fn'](p)
    for f in out:
        f['hunt'] = hunt_id
    return out


def sessions_by(items, key, t, gap_ms):
    """Group items (sorted or not) by key(item), split where time t(item) jumps by more than gap_ms."""
    groups: dict = {}
    for it in items:
        groups.setdefault(key(it), []).append(it)
    out = []
    for k, rs in groups.items():
        rs.sort(key=t)
        cur = [rs[0]]
        for r in rs[1:]:
            if t(r) - t(cur[-1]) > gap_ms:
                out.append((k, cur))
                cur = [r]
            else:
                cur.append(r)
        out.append((k, cur))
    return out
