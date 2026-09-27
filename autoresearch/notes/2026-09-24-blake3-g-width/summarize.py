"""Aggregate the retained matched blocks; historical proving scope stays distinct."""
import json,statistics
from pathlib import Path
HERE=Path(__file__).resolve().parent
records=json.loads((HERE/'metal-results.json').read_text())
assert len(records)==16
rows=[]
for case in dict.fromkeys(r['case'] for r in records):
 row={'case':case}
 for arm in ('control','candidate'):
  blocks=[r for r in records if r['case']==case and r['arm'].startswith(arm)]
  assert len(blocks)==2
  reports=[json.loads((HERE/f"{case}-{r['arm']}.json").read_text()) for r in blocks]
  samples=[s for report in reports for s in report['timings']]
  assert len(samples)==6
  composition=[next(c['seconds'] for s in p['stages'] if s['id']=='execution.core' for c in s['children'] if c['id']=='composition_evaluation') for r in blocks for p in r['profiles']]
  row[arm]={'samples':6,'total_median_seconds':statistics.median(s['total_ns']/1e9 for s in samples),'composition_median_seconds':statistics.median(composition),'main_commit_median_seconds':statistics.median(next(s['seconds'] for s in p['stages'] if s['id']=='execution.main') for r in blocks for p in r['profiles']),'interaction_commit_median_seconds':statistics.median(next(s['seconds'] for s in p['stages'] if s['id']=='execution.interaction_commit') for r in blocks for p in r['profiles']),'historical_prove_mean_seconds':statistics.mean((s['execution_ns']+s['witness_ns']+s['proving_ns'])/1e9 for s in samples),'peak_process_bytes':max(r['resources']['after_verified_samples']['lifetime_max_phys_footprint_bytes'] for r in blocks),'proof_sha256':blocks[0]['proof_sha256']}
 row['total_speedup']=row['control']['total_median_seconds']/row['candidate']['total_median_seconds']
 rows.append(row)
(HERE/'summary.json').write_text(json.dumps({'timed_proofs':48,'fresh_verifications':16,'rows':rows},indent=2)+'\n')
for r in rows:
 c,n=r['control'],r['candidate']
 print(f"| {r['case'].removeprefix('metal-')} | {c['total_median_seconds']:.6f} → {n['total_median_seconds']:.6f} | {c['composition_median_seconds']:.6f} → {n['composition_median_seconds']:.6f} | {c['peak_process_bytes']/2**30:.2f} → {n['peak_process_bytes']/2**30:.2f} |")
