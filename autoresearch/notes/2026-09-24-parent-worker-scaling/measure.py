"""One frozen binary, canonical parent, serial mirrored worker-count sweep."""
import hashlib,json,os,re,statistics,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BINARY=HERE/'parent-test'
EXPECTED='87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b'
results=[]
for index,workers in enumerate([2,4,8,16,16,8,4,2]):
    env=os.environ.copy()
    env.update(STWO_RISCV_PARENT_BENCH_WORKERS=str(workers),STWO_RISCV_RECURSIVE_PARENT_PROFILE='1',STWO_RISCV_EXECUTION_PROFILE='1',STWO_BLAKE3_CSP_RUNTIME='authenticated_aot',STWO_RISCV_METAL_AOT_BUNDLE=str(HERE/'core'))
    for key in ('STWO_RISCV_PARENT_MONOLITHIC_MAIN','STWO_RISCV_CPU_PARENT_INTERACTIONS','STWO_ZIG_CPU_HOST_BARYCENTRIC'):env.pop(key,None)
    command=['/usr/bin/time','-l',str(BINARY)]
    path=HERE/f'run-{index:02d}-workers-{workers}.log'
    begin=time.perf_counter()
    with path.open('w') as output:
        process=subprocess.run(command,cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT)
    wall=time.perf_counter()-begin
    log=path.read_text()
    row=dict(workers=workers,index=index,command=command,log=path.name,wall_seconds=wall,exit_code=process.returncode,binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest())
    if process.returncode:
        row['verified']=False
        results.append(row);(HERE/'results.json').write_text(json.dumps(results,indent=2)+'\n')
        raise RuntimeError(f'Worker qualification failed: {path}')
    assert f'CANONICAL_PARENT_WORKERS count={workers} ' in log
    assert f'BLAKE3_PARENT_ARTIFACT_SHA256 {EXPECTED}' in log
    assert 'COMPACT_RECURSIVE_PARENT child_queries=70 child_pow_bits=26 parent_queries=70 parent_pow_bits=26 independently_verified=true' in log
    assert 'successful_worker_rekey=true fixed_plan_reused=true outputs_outlive_worker=true transcript_replayed=true' in log
    profiles=[json.loads(x.split('BLAKE3_PARENT_STAGE_PROFILE ',1)[1]) for x in log.splitlines() if 'BLAKE3_PARENT_STAGE_PROFILE ' in x]
    assert len(profiles)==1
    row.update(verified=True,artifact_sha256=EXPECTED,profile=profiles[0],parent_stage_seconds=sum(x['seconds'] for x in profiles[0]['stages']),peak_rss_bytes=int(re.search(r'(\d+)\s+maximum resident set size',log)[1]),peak_physical_footprint_bytes=int(re.search(r'(\d+)\s+peak memory footprint',log)[1]),tracked_peak_bytes=int(re.search(r'CANONICAL_PARENT_MEMORY peak_bytes=(\d+)',log)[1]))
    results.append(row);(HERE/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(index,'workers',workers,'wall',round(wall,3),'parent stages',round(row['parent_stage_seconds'],3),flush=True)
summary={}
for workers in (2,4,8,16):
    rows=[r for r in results if r['workers']==workers]
    summary[str(workers)]=dict(samples=len(rows),wall_median_seconds=statistics.median(r['wall_seconds'] for r in rows),parent_stage_median_seconds=statistics.median(r['parent_stage_seconds'] for r in rows),peak_rss_bytes=max(r['peak_rss_bytes'] for r in rows),peak_physical_footprint_bytes=max(r['peak_physical_footprint_bytes'] for r in rows),tracked_peak_bytes=max(r['tracked_peak_bytes'] for r in rows),stage_medians_seconds={s['id']:statistics.median(next(t['seconds'] for t in r['profile']['stages'] if t['id']==s['id']) for r in rows) for s in rows[0]['profile']['stages']})
(HERE/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary),flush=True)
