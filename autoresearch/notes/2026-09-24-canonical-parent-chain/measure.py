"""Frozen two-level recursion comparison; every proof independently verifies."""
from pathlib import Path
import hashlib,json,os,re,statistics,subprocess,time
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def fields(line):return dict(re.findall(r'(\w+)=(\S+)',line))
results=[]
for index,variant in enumerate(('control','candidate','candidate','control')):
    binary=HERE/f'{variant}-parent-test'
    env=os.environ.copy()
    env.update(STWO_RISCV_PARENT_NEXT_PROOF='1',STWO_RISCV_PARENT_PREPARATION_PROFILE='1',STWO_RISCV_RECURSIVE_PARENT_PROFILE='1',STWO_RISCV_PARENT_BENCH_ALLOCATOR='smp',STWO_RISCV_PARENT_BENCH_WORKERS='8',STWO_BLAKE3_CSP_RUNTIME='authenticated_aot',STWO_RISCV_METAL_AOT_BUNDLE=str(HERE.parent/'2026-09-24-canonical-parent-pipeline/core'))
    for key in ('STWO_RISCV_PARENT_PIPELINE','STWO_RISCV_PARENT_FUSION_CENSUS'):env.pop(key,None)
    log_path=HERE/f'run-{index:02d}-{variant}.log'
    begin=time.perf_counter()
    with log_path.open('w') as output:subprocess.run(['/usr/bin/time','-l',str(binary)],cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT,check=True)
    elapsed=time.perf_counter()-begin
    log=log_path.read_text()
    profiles=[fields(line) for line in log.splitlines() if line.startswith('BLAKE3_PARENT_PROFILE ')]
    assert len(profiles)==2
    for receipt in profiles:
        assert all(receipt[key]=='true' for key in ('verified','successful_worker_rekey','fixed_plan_reused','outputs_outlive_worker','transcript_replayed'))
        assert receipt['queries']==receipt['child_queries']=='70' and receipt['pow_bits']==receipt['child_pow_bits']=='26'
    prep=fields(next(line for line in log.splitlines() if line.startswith('CANONICAL_NEXT_PREPARATION ')))
    proof=fields(next(line for line in log.splitlines() if line.startswith('CANONICAL_NEXT_PROOF ')))
    assert proof['independently_verified']=='true' and proof['queries']=='70' and proof['pow_bits']=='26'
    assert int(prep['peak_bytes'])<=int(prep['limit_bytes'])
    hashes=re.findall(r'BLAKE3_PARENT_ARTIFACT_SHA256 ([0-9a-f]{64})',log)
    expected=re.findall(r'BLAKE3_PARENT_ARTIFACT_SHA256 ([0-9a-f]{64})',(HERE/f'{variant}-qualified.log').read_text())
    assert len(hashes)==2 and hashes==expected
    row=dict(index=index,variant=variant,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),wall_seconds=elapsed,preparation_seconds=int(prep['preparation_ns'])/1e9,proof_and_checks_seconds=int(proof['proof_and_checks_ns'])/1e9,profiles=profiles,preparation=prep,proof=proof,hashes=hashes,peak_physical_bytes=int(re.search(r'(\d+)\s+peak memory footprint',log)[1]),peak_rss_bytes=int(re.search(r'(\d+)\s+maximum resident set size',log)[1]))
    results.append(row);(HERE/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(index,variant,'fixture',round(elapsed,3),'next-preparation',round(row['preparation_seconds'],3),'next-proof/checks',round(row['proof_and_checks_seconds'],3),flush=True)
summary={variant:{'samples':2,**{key:statistics.median(r[key] for r in results if r['variant']==variant) for key in ('wall_seconds','preparation_seconds','proof_and_checks_seconds')},'peak_physical_bytes':max(r['peak_physical_bytes'] for r in results if r['variant']==variant)} for variant in ('control','candidate')}
(HERE/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary),flush=True)
