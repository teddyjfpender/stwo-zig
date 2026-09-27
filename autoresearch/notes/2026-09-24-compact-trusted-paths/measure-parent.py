"""Four serial canonical parent fixture runs; compilation excluded."""
import hashlib,json,os,re,statistics,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
control=HERE/'control-parent-test'
expected='87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b'
results=[]
for arm in ['control-first','candidate-first','candidate-last','control-last']:
 binary=HERE/'candidate-parent-test' if arm.startswith('candidate') else control
 cmd=['/usr/bin/time','-l',str(binary)]
 env=os.environ.copy();env['STWO_RISCV_RECURSIVE_PARENT_PROFILE']='1'
 env.pop('STWO_RISCV_PARENT_MONOLITHIC_MAIN',None)
 env['STWO_BLAKE3_CSP_RUNTIME']='authenticated_aot'
 env['STWO_RISCV_METAL_AOT_BUNDLE']=str(HERE/'core')
 env.pop('STWO_RISCV_CPU_PARENT_INTERACTIONS',None)
 env['STWO_RISCV_EXECUTION_PROFILE']='1'
 env.pop('STWO_ZIG_CPU_HOST_BARYCENTRIC',None)


 begin=time.perf_counter()
 with (HERE/f'{arm}.log').open('w') as f:subprocess.run(cmd,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 wall=time.perf_counter()-begin
 log=(HERE/f'{arm}.log').read_text()
 assert f'BLAKE3_PARENT_ARTIFACT_SHA256 {expected}' in log
 assert 'COMPACT_RECURSIVE_PARENT child_queries=70 child_pow_bits=26 parent_queries=70 parent_pow_bits=26 independently_verified=true' in log
 assert 'successful_worker_rekey=true fixed_plan_reused=true outputs_outlive_worker=true transcript_replayed=true' in log
 profiles=[json.loads(x.split('BLAKE3_PARENT_STAGE_PROFILE ',1)[1]) for x in log.splitlines() if 'BLAKE3_PARENT_STAGE_PROFILE ' in x]
 assert len(profiles)==1
 reuse=re.search(r'BLAKE3_PATH_PLAN_REUSE openings=(\d+) graph_builds=(\d+) retained_plans=(\d+)',log)
 assert reuse and int(reuse[2])==6 and int(reuse[3])==2
 dispatch=re.search(r'NATIVE_PARENT_DEVICE_WORK metal_framework_interaction_dispatches=(\d+)',log)
 assert dispatch and int(dispatch[1])>0
 staged=re.findall(r'METAL_HOST_BARYCENTRIC staging_bytes=(\d+) commands=(\d+)',log)
 assert staged and all(int(n)<=67108864 for n,_ in staged)
 metadata=re.search(r'BLAKE3_HASH_METADATA g_rows=(\d+) xor_rows=(\d+) full_row_bytes=(\d+) compact_bytes=(\d+) removed_bytes=(\d+)',log)
 assert metadata and int(metadata[3])-int(metadata[4])==int(metadata[5])
 trusted=re.search(r'BLAKE3_TRUSTED_PATH_METADATA full_row_bytes=(\d+) compact_bytes=(\d+) removed_bytes=(\d+)',log)
 if arm.startswith('candidate'):assert trusted and int(trusted[1])-int(trusted[2])==int(trusted[3])
 else:assert not trusted
 row=dict(arm=arm,command=cmd,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),wall_seconds=wall,recorded_parent_stage_seconds=sum(s['seconds'] for s in profiles[0]['stages']),profile=profiles[0],tracked_peak_bytes=int(re.search(r'CANONICAL_PARENT_MEMORY peak_bytes=(\d+)',log)[1]),peak_rss_bytes=int(re.search(r'(\d+)\s+maximum resident set size',log)[1]),artifact_sha256=expected,verified=True,plan_reuse=tuple(map(int,reuse.groups())) if reuse else None)
 row['trusted_path_metadata_bytes']=tuple(map(int, trusted.groups())) if trusted else None
 row['hash_metadata_counts_bytes']=tuple(map(int, metadata.groups())) if metadata else None
 row['peak_physical_footprint_bytes']=int(re.search(r'(\d+)\s+peak memory footprint',log)[1])
 results.append(row);(HERE/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(arm,'wall',round(wall,3),'parent stages',round(row['recorded_parent_stage_seconds'],3),flush=True)
summary={arm:{'samples':2,'wall_median_seconds':statistics.median(x['wall_seconds'] for x in results if x['arm'].startswith(arm)),'parent_stage_median_seconds':statistics.median(x['recorded_parent_stage_seconds'] for x in results if x['arm'].startswith(arm)),'peak_rss_bytes':max(x['peak_rss_bytes'] for x in results if x['arm'].startswith(arm))} for arm in ('control','candidate')}
for arm in summary:
 rows=[x for x in results if x['arm'].startswith(arm)]
 summary[arm]['peak_physical_footprint_bytes']=max(x['peak_physical_footprint_bytes'] for x in rows)
 summary[arm]['stage_medians_seconds']={st['id']:statistics.median(next(z['seconds'] for z in x['profile']['stages'] if z['id']==st['id']) for x in rows) for st in rows[0]['profile']['stages']}
 summary[arm]['sampled_value_median_seconds']=statistics.median(next(c['seconds'] for t in r['profile']['stages'] if t['id']=='parent.core' for c in t['children'] if c['id']=='sampled_value_evaluation') for r in rows)
(HERE/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary),flush=True)
