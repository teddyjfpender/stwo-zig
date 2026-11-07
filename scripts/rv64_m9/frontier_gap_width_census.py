#!/usr/bin/env python3
"""Opened-width census from a producer log: per committed tree, columns opened per query vs average column height.

Input: a producer.stderr with GPU_DEVICE_PEAK stage=trace_commit lines (columns=, coefficient_bytes=) [M].
Output JSON: per (proof kind, tree) rows with columns, coefficient words, average column log2 height [D], and the
equal-height width at the tallest column of that proof class (2^22 rows for CPU segments) [D].
Usage: python3 -I scripts/rv64_m9/frontier_gap_width_census.py producer.stderr [--json out.json]
"""
import json, math, re, sys
from collections import Counter

PAT = re.compile(r'GPU_DEVICE_PEAK stage=trace_commit tree=(\d+) mode=(\w+) columns=(\d+) calls=\d+ coefficient_bytes=(\d+)')


def census(lines):
    c = Counter()
    for ln in lines:
        m = PAT.search(ln)
        if m:
            c[(m.group(2), int(m.group(1)), int(m.group(3)), int(m.group(4)))] += 1
    rows = []
    for (mode, tree, cols, cb), n in sorted(c.items()):
        words = cb // 4
        rows.append(dict(mode=mode, kind='native/truth (legacy)' if mode == 'legacy' else 'recursion (stream)', tree=tree,
                         columns=cols, coefficient_words=words, log_count=n, avg_col_log2=round(math.log2(words / cols), 2),
                         equal_height_width_at_2_22=round(words / 2 ** 22, 1)))
    leg = [r for r in rows if r['mode'] == 'legacy' and r['tree'] in (1, 2)]
    rec = [r for r in rows if r['mode'] == 'stream']
    summ = dict(
        legacy_tree12_columns_max=max(r['columns'] for r in leg), legacy_tree12_avg_col_log2_median=sorted(r['avg_col_log2'] for r in leg)[len(leg) // 2],
        recursion_columns_max=max(r['columns'] for r in rec), recursion_avg_col_log2_median=sorted(r['avg_col_log2'] for r in rec)[len(rec) // 2])
    return dict(schema='rv64-m9-frontier-gap-width-census/v1', labels='columns/coefficient_bytes [M] from the log; heights [D]',
                rows=rows, summary=summ)


if __name__ == '__main__':
    out = census(open(sys.argv[1]).read().splitlines())
    if '--json' in sys.argv:
        json.dump(out, open(sys.argv[sys.argv.index('--json') + 1], 'w'), indent=1)
    print(json.dumps(out['summary']))
    for r in out['rows']:
        if r['tree'] in (1, 2):
            print('%-22s tree %d cols %5d words %11d avg col 2^%.1f eq-width@2^22 %6.1f' % (r['kind'], r['tree'], r['columns'], r['coefficient_words'], r['avg_col_log2'], r['equal_height_width_at_2_22']))
