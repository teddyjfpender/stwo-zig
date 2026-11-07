import json, sqlite3, sys, bisect
from collections import defaultdict
run = sys.argv[1]; sq = run + '/nsys/timeline.sqlite'
rc = json.load(open(run + '/receipt.json'))
reqs = rc['requests']
db = sqlite3.connect(f'file:{sq}?mode=ro', uri=True)
ep = db.execute('SELECT utcEpochNs FROM TARGET_INFO_SESSION_START_TIME').fetchone()[0]
names = dict(db.execute('SELECT id, value FROM StringIds'))
def union(iv):
    iv.sort(); out = []
    for s, e in iv:
        if out and s <= out[-1][1]: out[-1][1] = max(out[-1][1], e)
        else: out.append([s, e])
    return out
def inter(a, b):
    i = j = 0; t = 0
    while i < len(a) and j < len(b):
        s = max(a[i][0], b[j][0]); e = min(a[i][1], b[j][1])
        if e > s: t += e - s
        if a[i][1] < b[j][1]: i += 1
        else: j += 1
    return t
def tot(u): return sum(e - s for s, e in u)
for ri, r in enumerate(reqs):
    lo, hi = (t - ep for t in r['utc_window_ns'])
    print('request', ri, 'window_s', round((hi - lo) / 1e9, 3))
    k = defaultdict(list); h = defaultdict(list); kst = defaultdict(list)
    for dev, s, e, sid, sn in db.execute('SELECT deviceId, start, end, streamId, shortName FROM CUPTI_ACTIVITY_KIND_KERNEL WHERE end > ? AND start < ?', (lo, hi)):
        k[dev].append((s, e)); kst[(dev, sid)].append((s, names.get(sn, '?')))
    nxt = defaultdict(lambda: [0, 0])
    for v in kst.values(): v.sort()
    starts = {key: [x[0] for x in v] for key, v in kst.items()}
    sizes = {}
    for dev, s, e, nb, sid in db.execute('SELECT deviceId, start, end, bytes, streamId FROM CUPTI_ACTIVITY_KIND_MEMCPY WHERE copyKind = 1 AND end > ? AND start < ?', (lo, hi)):
        h[dev].append((s, e))
        key = (dev, sid); name = '(no kernel after on stream)'
        if key in starts:
            i = bisect.bisect_left(starts[key], e)
            if i < len(starts[key]): name = kst[key][i][1]
        nxt[name][0] += nb; nxt[name][1] += e - s
    for dev in sorted(h):
        hu = union(h[dev]); ku = union(k[dev])
        print(f' dev{dev}: h2d_union_s={tot(hu)/1e9:.3f} kernel_union_s={tot(ku)/1e9:.3f} h2d_overlapping_kernels_s={inter(hu, ku)/1e9:.3f} h2d_exposed_s={(tot(hu)-inter(hu, ku))/1e9:.3f}')
    print(' h2d bytes by next kernel on same stream (top 25):')
    for n, (b, t) in sorted(nxt.items(), key=lambda x: -x[1][0])[:25]:
        print(f'  {b/1e9:7.3f} GB {t/1e9:6.3f} s  {n[:90]}')
