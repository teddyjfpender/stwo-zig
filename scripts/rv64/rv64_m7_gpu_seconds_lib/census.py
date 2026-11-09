"""CUDA API calls and transfer origins, independent of driver counters.

Runtime calls are counted by entry timestamp. Device activities overlap the
request window. Correlation IDs attribute CUDA's host-staged peer transport;
unmatched or ambiguous IDs remain explicitly unattributed.
"""
from collections import Counter, defaultdict
from .ranges import native_ranges


def request_census(db, lower, upper):
    if type(lower) is not int or type(upper) is not int or lower >= upper:
        raise ValueError('invalid request activity window')
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required = {'CUPTI_ACTIVITY_KIND_RUNTIME', 'CUPTI_ACTIVITY_KIND_MEMCPY', 'StringIds'}
    if not required.issubset(tables):
        return {'status': 'UNAVAILABLE', 'missing_tables': sorted(required - tables),
                'runtime_api_entered': None, 'd2h_activities': None,
                'native_enqueue_ranges': {'status': 'UNAVAILABLE', 'ranges': None}}
    apis = db.execute('''SELECT r.correlationId, s.value, r.start, r.end
        FROM CUPTI_ACTIVITY_KIND_RUNTIME r JOIN StringIds s ON s.id=r.nameId
        WHERE r.start>=? AND r.start<?''', (lower, upper)).fetchall()
    counts = Counter()
    durations = Counter()
    correlations = defaultdict(list)
    for correlation, name, start, end in apis:
        counts[name] += 1
        durations[name] += max(0, min(end, upper) - start)
        correlations[correlation].append(name)
    d2h = {kind: {'activities': 0, 'bytes': 0} for kind in ('ordinary_cuda_copy', 'peer_transport', 'unattributed')}
    copies = db.execute('''SELECT correlationId, bytes FROM CUPTI_ACTIVITY_KIND_MEMCPY
        WHERE copyKind=2 AND end>? AND start<?''', (lower, upper))
    for correlation, size in copies:
        names = correlations.get(correlation, [])
        origin = 'unattributed'
        if len(names) == 1:
            if names[0].startswith('cudaMemcpyPeerAsync'):
                origin = 'peer_transport'
            elif names[0].startswith(('cudaMemcpyAsync', 'cudaMemcpy_v', 'cuMemcpyDtoH')):
                origin = 'ordinary_cuda_copy'
        d2h[origin]['activities'] += 1
        d2h[origin]['bytes'] += size
    return {
        'status': 'MEASURED',
        'scope': 'Runtime calls entered in the window; overlapping CUPTI D2H activities. API durations sum across threads, not elapsed request time. Ordinary copies are not classified as private or final readbacks without further evidence.',
        'runtime_api_entered': dict(sorted(counts.items())),
        'runtime_api_duration_sum_ns': dict(sorted(durations.items())),
        'd2h_activities': d2h,
        'host_synchronization_calls': sum(n for name, n in counts.items() if name.startswith(('cudaEventSynchronize', 'cudaStreamSynchronize', 'cudaDeviceSynchronize', 'cuEventSynchronize', 'cuStreamSynchronize', 'cuCtxSynchronize'))),
        'host_callback_calls': sum(n for name, n in counts.items() if name.startswith('cudaLaunchHostFunc')),
        'event_creation_calls': sum(n for name, n in counts.items() if name.startswith(('cudaEventCreate', 'cuEventCreate'))),
        'native_enqueue_ranges': native_ranges(db, lower, upper),
    }
