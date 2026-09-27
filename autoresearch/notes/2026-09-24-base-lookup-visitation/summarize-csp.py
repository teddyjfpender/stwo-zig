import json, statistics
from pathlib import Path
here=Path(__file__).resolve().parent
records=json.loads((here/'metal-results.json').read_text())
assert len(records)==16
summary=[]
for case in dict.fromkeys(r['case'] for r in records):
 row={'case':case}
 for arm in ['control','candidate']:
  reports=[json.loads((here/f"{case}-{r['arm']}.json").read_text()) for r in records if r['case']==case and r['arm'].startswith(arm)]
  timings=[t for r in reports for t in r['timings']]
  assert len(timings)==6
  row[arm]=dict(complete_median_seconds=statistics.median(t['total_ns']/1e9 for t in timings),
   execution_witness_proving_mean_seconds=statistics.mean((t['execution_ns']+t['witness_ns']+t['proving_ns'])/1e9 for t in timings),
   peak_physical_footprint_bytes=max(r['resources']['after_verified_samples']['lifetime_max_phys_footprint_bytes'] for r in reports))
 row['complete_reduction_percent']=100*(1-row['candidate']['complete_median_seconds']/row['control']['complete_median_seconds'])
 summary.append(row)
(here/'csp-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
for r in summary:
 print(r['case'],f"{r['control']['complete_median_seconds']:.6f} -> {r['candidate']['complete_median_seconds']:.6f}",f"{r['complete_reduction_percent']:.1f}%",f"prove metric {r['candidate']['execution_witness_proving_mean_seconds']:.6f}")
