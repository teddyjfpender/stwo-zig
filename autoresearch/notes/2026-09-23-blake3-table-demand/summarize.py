"""Summarize actual demand, not a runtime speedup projection."""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
records=json.loads((HERE/'suite/results.json').read_text())
assert len(records)==16 and all(r['independent_verified'] for r in records)
rows=[]
for record in records:
 demand=[json.loads(line.split(' ',1)[1]) for line in (HERE/'suite'/f"{record['case']}.log").read_text().splitlines() if line.startswith('BLAKE3_LOOKUP_DEMAND ')]
 assert len(demand)==6
 rows.append(dict(case=record['case'],tables=demand))
(HERE/'demand.json').write_text(json.dumps(rows,indent=2)+'\n')
lines=['| Workload | range20 distinct | range8/11 distinct | range8/8/4 distinct |','| --- | ---: | ---: | ---: |']
for row in rows:
 d={t['kind']:t['distinct_nonzero'] for t in row['tables']}
 lines.append(f"| {row['case']} | {d['range_check_20']:,} | {d['range_check_8_11']:,} | {d['range_check_8_8_4']:,} |")
(HERE/'DEMAND.md').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines))
