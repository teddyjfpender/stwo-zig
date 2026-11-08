"""Native host enqueue ranges. These durations are never GPU timings."""
import re
from collections import Counter


LABEL = re.compile(r'rv64/gpu/[a-z][a-z0-9_]*/[0-9]+\Z')


def native_ranges(db, lower, upper):
    columns = {row[1] for row in db.execute('PRAGMA table_info(NVTX_EVENTS)')}
    required = {'start', 'end', 'globalTid', 'text', 'textId'}
    if not required.issubset(columns):
        return {'status': 'UNAVAILABLE', 'reason': 'missing NVTX range columns',
                'missing_columns': sorted(required - columns), 'ranges': None}
    rows = db.execute('''SELECT n.start,n.end,n.globalTid,COALESCE(n.text,s.value)
        FROM NVTX_EVENTS n LEFT JOIN StringIds s ON s.id=n.textId
        WHERE n.start<? AND (n.end IS NULL OR n.end>?)
        AND COALESCE(n.text,s.value) LIKE 'rv64/gpu/%'
        ORDER BY n.start''', (upper, lower)).fetchall()
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
