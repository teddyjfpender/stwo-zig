"""NVTX enqueue ranges and CUPTI kernel attribution for resident proof requests."""
import re
from collections import Counter, defaultdict


LABEL = re.compile(r'rv64/gpu/[a-z][a-z0-9_]*/[0-9]+\Z')


def _range_rows(db, lower, upper):
    return db.execute('''SELECT n.start,n.end,n.globalTid,COALESCE(n.text,s.value)
        FROM NVTX_EVENTS n LEFT JOIN StringIds s ON s.id=n.textId
        WHERE n.start<? AND (n.end IS NULL OR n.end>?)
        AND COALESCE(n.text,s.value) LIKE 'rv64/gpu/%'
        ORDER BY n.start''', (upper, lower)).fetchall()


def native_ranges(db, lower, upper):
    columns = {row[1] for row in db.execute('PRAGMA table_info(NVTX_EVENTS)')}
    required = {'start', 'end', 'globalTid', 'text', 'textId'}
    if not required.issubset(columns):
        return {'status': 'UNAVAILABLE', 'reason': 'missing NVTX range columns',
                'missing_columns': sorted(required - columns), 'ranges': None}
    rows = _range_rows(db, lower, upper)
    if not rows:
        return {'status': 'NOT_INSTRUMENTED', 'reason': 'no native ranges in this request',
                'ranges': None}
    runtime_columns = {row[1] for row in db.execute('PRAGMA table_info(CUPTI_ACTIVITY_KIND_RUNTIME)')}
    can_count = {'start', 'end', 'globalTid', 'nameId'}.issubset(runtime_columns)
    result, excluded = [], []
    for start, end, thread, label in rows:
        if not LABEL.fullmatch(label) or end is None or end < start or start < lower or end > upper:
            excluded.append({'label': label, 'start_ns': start, 'end_ns': end})
            continue
        counts = None
        if can_count:
            counts = dict(sorted(Counter(row[0] for row in db.execute('''
                SELECT s.value FROM CUPTI_ACTIVITY_KIND_RUNTIME r
                JOIN StringIds s ON s.id=r.nameId
                WHERE r.globalTid=? AND r.start>=? AND r.end<=?''',
                (thread, start, end))).items()))
        result.append({'label': label, 'thread': thread, 'host_enqueue_ns': end - start,
                       'runtime_api_contained': counts})
    return {'status': 'PARTIAL' if excluded else 'MEASURED',
            'scope': 'Complete host enqueue ranges within the request. CUDA API calls are counted on the same thread and fully contained in each range. Range durations are not device durations; GPU projection is not calculated here.',
            'ranges': result, 'excluded_incomplete_or_malformed_ranges': excluded,
            'runtime_api_coverage': 'MEASURED' if can_count else 'UNAVAILABLE'}


def device_kernel_work(db, lower, upper, host):
    """Project through the submitting CUDA call. GPU execution may happen much later."""
    if host['status'] in ('UNAVAILABLE', 'NOT_INSTRUMENTED'):
        return {'status': host['status'], 'devices': None, 'reason': host['reason']}
    required = {
        'CUPTI_ACTIVITY_KIND_KERNEL': {'start', 'end', 'globalPid', 'deviceId', 'correlationId'},
        'CUPTI_ACTIVITY_KIND_RUNTIME': {'start', 'end', 'globalTid', 'correlationId'},
    }
    for table, columns in required.items():
        present = {row[1] for row in db.execute(f'PRAGMA table_info({table})')}
        if not columns <= present:
            return {'status': 'UNAVAILABLE', 'devices': None, 'reason': f'missing {table} origin columns'}

    ranges = defaultdict(list)
    for start, end, thread, label in _range_rows(db, lower, upper):
        ranges[thread].append((start, end, label))
    # Nsight serializes hardware, VM and process in the upper 40 bits of
    # globalTid. Clearing only the low 24 thread bits preserves that identity.
    # Count kernels before joining. A graph submit can produce many kernels,
    # and a duplicate runtime correlation must never multiply their duration.
    activity = db.execute("""
        WITH active AS (
            SELECT deviceId,globalPid,correlationId,COUNT(*) AS n,
                   SUM(MIN(end,:hi)-MAX(start,:lo)) AS elapsed
            FROM CUPTI_ACTIVITY_KIND_KERNEL
            WHERE end>:lo AND start<:hi
            GROUP BY deviceId,globalPid,correlationId
        ), ids AS (SELECT DISTINCT globalPid,correlationId FROM active), origins AS (
            SELECT i.globalPid,i.correlationId,COUNT(*) AS n,
                   MIN(r.globalTid) AS thread,MIN(r.start) AS start,MAX(r.end) AS end
            FROM CUPTI_ACTIVITY_KIND_RUNTIME r JOIN ids i ON
                (r.globalTid & ~16777215)=i.globalPid AND r.correlationId=i.correlationId
            WHERE i.correlationId>0
            GROUP BY i.globalPid,i.correlationId
        )
        SELECT a.deviceId,a.n,a.elapsed,o.n,o.thread,o.start,o.end
        FROM active a LEFT JOIN origins o USING(globalPid,correlationId)
    """, {'lo': lower, 'hi': upper})
    result = {}
    partial = host['status'] == 'PARTIAL'
    for device, count, elapsed, origins, thread, start, end in activity:
        stage = 'unattributed'
        if origins == 1 and start is not None and end is not None and lower <= start <= end <= upper:
            owners = [(lo, hi, name) for lo, hi, name in ranges[thread]
                      if lo < max(end, start + 1) and (hi is None or hi > start)]
            if len(owners) == 1:
                lo, hi, name = owners[0]
                if hi is not None and lower <= lo <= start <= end <= hi <= upper and LABEL.fullmatch(name):
                    stage = name.split('/')[2]
        partial |= stage == 'unattributed'
        stages = result.setdefault(str(device), {})
        row = stages.setdefault(stage, {'kernels': 0, 'duration_sum_ns': 0})
        row['kernels'] += count
        row['duration_sum_ns'] += elapsed
    return {'status': 'PARTIAL' if partial else 'MEASURED', 'devices': result,
            'scope': 'Per-device kernel executions and summed device durations clipped to the request. '
                     'Only a unique runtime submission inside one complete owning NVTX range is attributed. '
                     'Concurrent kernel durations overlap.'}
