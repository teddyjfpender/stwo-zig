"""Serial versus overlapped canonical jobs on one frozen persistent-worker fixture."""
import hashlib,json,os,re,statistics,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]

EXPECTED='87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b'
results=[]
for index,variant in enumerate(('control','candidate','candidate','control')):
    mode='overlapped'
    BINARY=HERE/f'{variant}-parent-test'
    env=os.environ.copy()
    env.update(STWO_RISCV_PARENT_PREPARATION_PROFILE='1',STWO_RISCV_PARENT_BENCH_ALLOCATOR='smp',STWO_RISCV_PARENT_PIPELINE='1',STWO_RISCV_PARENT_BENCH_WORKERS='8',STWO_RISCV_RECURSIVE_PARENT_PROFILE='1',STWO_RISCV_EXECUTION_PROFILE='1',STWO_BLAKE3_CSP_RUNTIME='authenticated_aot',STWO_RISCV_METAL_AOT_BUNDLE=str(HERE.parent/'2026-09-24-canonical-parent-pipeline/core'))
    for key in ('STWO_RISCV_PARENT_MONOLITHIC_MAIN','STWO_RISCV_CPU_PARENT_INTERACTIONS','STWO_ZIG_CPU_HOST_BARYCENTRIC','STWO_RISCV_PARENT_PIPELINE_SERIAL'):env.pop(key,None)
    if mode=='serial':env['STWO_RISCV_PARENT_PIPELINE_SERIAL']='1'
    path=HERE/f'run-{index:02d}-{variant}.log'
    command=['/usr/bin/time','-l',str(BINARY)]
    begin=time.perf_counter()
    with path.open('w') as output:subprocess.run(command,cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT,check=True)
    wall=time.perf_counter()-begin
    log=path.read_text()
    assert 'CANONICAL_PARENT_ALLOCATOR mode=smp' in log
    artifacts=re.findall(r'CANONICAL_PIPELINE_ARTIFACT index=(\d+) sha256=([0-9a-f]+) bytes=(\d+) independently_verified=true',log)
    assert artifacts==[('0',EXPECTED,'857591'),('1',EXPECTED,'857591')],artifacts
    marker=next(x for x in log.splitlines() if x.startswith('CANONICAL_EXECUTION_PIPELINE '))
    receipt=dict(re.findall(r'(\w+)=(\S+)',marker))
    assert receipt['mode']==mode and receipt['workers']=='8' and receipt['cpu_tokens']=='9' and receipt['jobs']=='2'
    assert all(receipt[k]=='true' for k in ('plan_reused','outputs_outlive_worker','independently_verified'))
    assert all(receipt[k]=='70' for k in ('child_queries','parent_queries'))
    assert all(receipt[k]=='26' for k in ('child_pow_bits','parent_pow_bits'))
    assert int(receipt['worker_peak_bytes'])<=int(receipt['worker_limit_bytes'])
    assert (int(receipt['overlap_ns'])>0)==(mode=='overlapped')
    row=dict(index=index,variant=variant,mode=mode,command=command,binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest(),wall_seconds=wall,pipeline_seconds=int(receipt['wall_ns'])/1e9,overlap_seconds=int(receipt['overlap_ns'])/1e9,receipt=receipt,verified=True,artifacts=artifacts,peak_rss_bytes=int(re.search(r'(\d+)\s+maximum resident set size',log)[1]),peak_physical_footprint_bytes=int(re.search(r'(\d+)\s+peak memory footprint',log)[1]))
    row['path_profiles']=[dict((k,int(v)) for k,v in re.findall(r'(\w+)=(\d+)',line)) for line in log.splitlines() if line.startswith('PARENT_PATH_PREPARATION ')]
    assert len(row['path_profiles'])==3
    results.append(row);(HERE/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(index,variant,'fixture',round(wall,3),'pipeline',round(row['pipeline_seconds'],3),'overlap',round(row['overlap_seconds'],3),flush=True)
summary={variant:{'samples':2,'wall_median_seconds':statistics.median(r['wall_seconds'] for r in results if r['variant']==variant),'pipeline_median_seconds':statistics.median(r['pipeline_seconds'] for r in results if r['variant']==variant),'seed_live_path_median_seconds':statistics.median(r['path_profiles'][0]['live_ns']/1e9 for r in results if r['variant']==variant),'peak_physical_footprint_bytes':max(r['peak_physical_footprint_bytes'] for r in results if r['variant']==variant)} for variant in ('control','candidate')}
(HERE/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary),flush=True)
