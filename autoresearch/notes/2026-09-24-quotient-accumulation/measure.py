import hashlib,json,os,re,statistics,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
results=[]
for index,variant in enumerate(('control','candidate','candidate','control')):
    binary=HERE/f'{variant}-parent-test'
    env=os.environ.copy()
    env.update(STWO_RISCV_PARENT_BENCH_ALLOCATOR='smp',STWO_RISCV_PARENT_BENCH_WORKERS='8',STWO_RISCV_RECURSIVE_PARENT_PROFILE='1',STWO_BLAKE3_CSP_RUNTIME='authenticated_aot',STWO_RISCV_METAL_AOT_BUNDLE=str(HERE.parent/'2026-09-24-canonical-parent-pipeline/core'))
    for key in ('STWO_RISCV_PARENT_FUSION_CENSUS','STWO_RISCV_PARENT_PREPARATION_PROFILE','STWO_RISCV_PARENT_PIPELINE','STWO_RISCV_PARENT_PIPELINE_SERIAL'):env.pop(key,None)
    log_path=HERE/f'run-{index:02d}-{variant}.log'
    command=['/usr/bin/time','-l',str(binary)]
    begin=time.perf_counter()
    with log_path.open('w') as output:subprocess.run(command,cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT,check=True)
    elapsed=time.perf_counter()-begin
    log=log_path.read_text()
    receipt=dict(re.findall(r'(\w+)=(\S+)',next(line for line in log.splitlines() if line.startswith('BLAKE3_PARENT_PROFILE '))))
    assert all(receipt[key]=='true' for key in ('verified','successful_worker_rekey','fixed_plan_reused','outputs_outlive_worker','transcript_replayed'))
    assert receipt['queries']==receipt['child_queries']=='70' and receipt['pow_bits']==receipt['child_pow_bits']=='26'
    assert receipt['artifact_bytes']==('866453' if variant=='candidate' else '857591')
    if variant=='candidate':assert 'BLAKE3_NATIVE_QUOTIENT_FUSION rows=210 inverse_rows=1944' in log
    row=dict(index=index,variant=variant,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),wall_seconds=elapsed,receipt=receipt,peak_physical_bytes=int(re.search(r'(\d+)\s+peak memory footprint',log)[1]),peak_rss_bytes=int(re.search(r'(\d+)\s+maximum resident set size',log)[1]))
    results.append(row);(HERE/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(index,variant,round(elapsed,3),flush=True)
summary={variant:{'samples':2,'wall_median_seconds':statistics.median(r['wall_seconds'] for r in results if r['variant']==variant),'peak_physical_bytes':max(r['peak_physical_bytes'] for r in results if r['variant']==variant)} for variant in ('control','candidate')}
(HERE/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary),flush=True)
