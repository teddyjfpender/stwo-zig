#!/usr/bin/env python3
"""census2 deep-dive queries on an nsys sqlite (opened read-only), warm request window from receipt.json."""
import bisect, json, sqlite3, sys
from collections import defaultdict
run, sq, req = sys.argv[1], sys.argv[2], int(sys.argv[3])
rc = json.load(open(run + '/receipt.json'))
r = rc['requests'][req]
db = sqlite3.connect(f'file:{sq}?mode=ro', uri=True)
ep = db.execute('SELECT utcEpochNs FROM TARGET_INFO_SESSION_START_TIME').fetchone()[0]
lo, hi = (t - ep for t in r['utc_window_ns'])
names = dict(db.execute('SELECT id, value FROM StringIds'))
tables = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
out = {}
# NVTX innermost range per launch (runtime api thread)
ranges = defaultdict(list)
for tid, s0, e0, text in db.execute('SELECT e.globalTid, e.start, e.end, COALESCE(e.text, st.value) FROM NVTX_EVENTS e LEFT JOIN StringIds st ON e.textId = st.id '
                                    'WHERE e.end IS NOT NULL AND e.end > ? AND e.start < ? AND e.eventType = 59', (lo - 60_000_000_000, hi)):
    ranges[tid].append((s0, e0, text))
for v in ranges.values():
    v.sort()
starts = {t: [x[0] for x in v] for t, v in ranges.items()}
def label(tid, t):
    if tid not in ranges:
        return '(none)'
    i = bisect.bisect_right(starts[tid], t) - 1
    while i >= 0:
        s0, e0, text = ranges[tid][i]
        if e0 >= t:
            return text
        i -= 1
        if t - s0 > 120_000_000_000:
            break
    return '(none)'
# H2D by range, src kind, size bucket
cols = [c[1] for c in db.execute('PRAGMA table_info(CUPTI_ACTIVITY_KIND_MEMCPY)')]
h2d = defaultdict(lambda: [0, 0, 0])
kinds = defaultdict(lambda: [0, 0, 0])
sizes = defaultdict(lambda: [0, 0, 0])
for tid, rs, s, e, nb, ck, sk in db.execute('SELECT r.globalTid, r.start, m.start, m.end, m.bytes, m.copyKind, m.srcKind FROM CUPTI_ACTIVITY_KIND_MEMCPY m '
                                            'JOIN CUPTI_ACTIVITY_KIND_RUNTIME r ON m.correlationId = r.correlationId WHERE m.end > ? AND m.start < ? AND m.copyKind = 1', (lo, hi)):
    l = label(tid, rs)
    for d, k in ((h2d, l), (kinds, sk), (sizes, min(30, max(0, nb.bit_length())))):
        d[k][0] += nb; d[k][1] += e - s; d[k][2] += 1
out['h2d_by_range'] = {k: {'GB': round(v[0] / 1e9, 3), 'copy_s': round(v[1] / 1e9, 4), 'n': v[2], 'GBps': round(v[0] / max(v[1], 1), 1)}
                       for k, v in sorted(h2d.items(), key=lambda x: -x[1][0])[:20]}
out['h2d_by_srckind(0=unk,1=pageable,2=pinned,3=device,5=managed)'] = {str(k): {'GB': round(v[0] / 1e9, 3), 'copy_s': round(v[1] / 1e9, 4), 'n': v[2], 'GBps': round(v[0] / max(v[1], 1), 1)} for k, v in kinds.items()}
out['h2d_by_log2size'] = {str(k): {'GB': round(v[0] / 1e9, 3), 'copy_s': round(v[1] / 1e9, 4), 'n': v[2], 'GBps': round(v[0] / max(v[1], 1), 1)} for k, v in sorted(sizes.items())}
# per-kernel duration distribution and per-range breakdown for selected kernels
sel = sys.argv[4].split(',')
kd = defaultdict(list)
kr = defaultdict(lambda: defaultdict(lambda: [0, 0]))
for tid, rs, dev, s, e, sn, g, b, ssm, dsm in db.execute('SELECT r.globalTid, r.start, k.deviceId, k.start, k.end, k.shortName, k.gridX*k.gridY*k.gridZ, '
                                                         'k.blockX*k.blockY*k.blockZ, k.staticSharedMemory, k.dynamicSharedMemory FROM CUPTI_ACTIVITY_KIND_KERNEL k '
                                                         'JOIN CUPTI_ACTIVITY_KIND_RUNTIME r ON k.correlationId = r.correlationId WHERE k.end > ? AND k.start < ?', (lo, hi)):
    n = names.get(sn, '?')
    if any(x == n for x in sel):
        kd[n].append((e - s, g))
        l = label(tid, rs)
        kr[n][l][0] += e - s; kr[n][l][1] += 1
dist = {}
for n, v in kd.items():
    v.sort()
    ds = [x[0] for x in v]
    tot = sum(ds)
    buckets = defaultdict(lambda: [0, 0])
    for d, g in v:
        bk = 'lt10us' if d < 1e4 else 'lt100us' if d < 1e5 else 'lt1ms' if d < 1e6 else 'lt10ms' if d < 1e7 else 'ge10ms'
        buckets[bk][0] += d; buckets[bk][1] += 1
    grids = defaultdict(int)
    for d, g in v:
        grids[g] += d
    dist[n] = {'n': len(v), 'gpu_s': round(tot / 1e9, 4), 'p50_us': round(ds[len(ds) // 2] / 1e3, 1), 'p90_us': round(ds[int(len(ds) * .9)] / 1e3, 1),
               'max_us': round(ds[-1] / 1e3, 1), 'buckets': {k: {'gpu_s': round(a / 1e9, 4), 'n': c} for k, (a, c) in buckets.items()},
               'grid_gpu_s': {str(k): round(x / 1e9, 4) for k, x in sorted(grids.items(), key=lambda y: -y[1])[:6]},
               'by_range': {k: {'gpu_s': round(a / 1e9, 4), 'n': c} for k, (a, c) in sorted(kr[n].items(), key=lambda y: -y[1][0])[:8]}}
out['kernels'] = dist
print(json.dumps(out, indent=1))
