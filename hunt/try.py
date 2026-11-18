import sys, time, json
sys.path.insert(0, __file__.rsplit('/', 1)[0])
import registry, hunts_dns  # noqa
for mod in sys.argv[2:]:
    __import__(mod)
for hid in sys.argv[1].split(','):
    t = time.time()
    fs = registry.run(hid)
    print(f'== {hid}: {len(fs)} findings in {time.time()-t:.1f}s')
    for f in sorted(fs, key=lambda f: f['timestamp']):
        print(f"  {f['timestamp']} {f['category'][:18]:18} {f['host']:8} {f['user']:12} {f['process']:12} | {'; '.join(f['evidence'])[:110]}")
