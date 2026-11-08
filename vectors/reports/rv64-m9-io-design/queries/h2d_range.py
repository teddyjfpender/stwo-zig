import json, sqlite3, sys, bisect
from collections import defaultdict
run = sys.argv[1]; sq = run + '/nsys/timeline.sqlite'
r = json.load(open(run + '/receipt.json'))['requests'][1]
db = sqlite3.connect(f'file:{sq}?mode=ro', uri=True)
ep = db.execute('SELECT utcEpochNs FROM TARGET_INFO_SESSION_START_TIME').fetchone()[0]
lo, hi = (t - ep for t in r['utc_window_ns'])
names = dict(db.execute('SELECT id, value FROM StringIds'))
ranges = defaultdict(list)
for tid, s0, e0, text in db.execute('SELECT e.globalTid, e.start, e.end, COALESCE(e.text, st.value) FROM NVTX_EVENTS e LEFT JOIN StringIds st ON e.textId = st.id WHERE e.end IS NOT NULL AND e.end > ? AND e.start < ? AND e.eventType = 59', (lo - 60_000_000_000, hi)):
    ranges[tid].append((s0, e0, text))
for v in ranges.values(): v.sort()
starts = {t: [x[0] for x in v] for t, v in ranges.items()}
def label(tid, t):
    if tid not in ranges: return '(none)'
    i = bisect.bisect_right(starts[tid], t) - 1
    while i >= 0:
        s0, e0, text = ranges[tid][i]
        if e0 >= t: return text
        i -= 1
        if t - s0 > 120_000_000_000: break
    return '(none)'
kst = defaultdict(list)
for dev, s, sid, sn in db.execute('SELECT deviceId, start, streamId, shortName FROM CUPTI_ACTIVITY_KIND_KERNEL WHERE end > ? AND start < ?', (lo, hi)):
    kst[(dev, sid)].append((s, names.get(sn, '?')))
for v in kst.values(): v.sort()
ks = {k: [x[0] for x in v] for k, v in kst.items()}
agg = defaultdict(lambda: [0, 0])
for tid, rs, dev, e, nb, sid in db.execute('SELECT r.globalTid, r.start, m.deviceId, m.end, m.bytes, m.streamId FROM CUPTI_ACTIVITY_KIND_MEMCPY m JOIN CUPTI_ACTIVITY_KIND_RUNTIME r ON m.correlationId = r.correlationId WHERE m.copyKind = 1 AND m.end > ? AND m.start < ?', (lo, hi)):
    key = (dev, sid); n = '-'
    if key in ks:
        i = bisect.bisect_left(ks[key], e)
        if i < len(ks[key]): n = kst[key][i][1]
    a = agg[(label(tid, rs), n)]; a[0] += nb; a[1] += 1
for (l, n), (b, c) in sorted(agg.items(), key=lambda x: -x[1][0])[:30]:
    print(f'{b/1e9:7.3f} GB n={c:5d}  {l[:40]:40s} -> {n[:50]}')
