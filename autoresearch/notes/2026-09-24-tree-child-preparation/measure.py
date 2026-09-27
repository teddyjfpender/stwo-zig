from pathlib import Path
import hashlib,json,os,re,statistics,subprocess,time
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
results=json.loads((HERE/'results.json').read_text()) if (HERE/'results.json').exists() else []
for index,variant in enumerate(('control','candidate','candidate','control')):
    binary=HERE/'candidate-tree-test' if variant=='candidate' else HERE.parent/'2026-09-24-native-two-level-frontier/candidate-tree-test'
    if index < len(results):
        assert results[index]['index']==index and results[index]['variant']==variant
        assert results[index]['binary_sha256']==hashlib.sha256(binary.read_bytes()).hexdigest()
        continue
    env=os.environ.copy()
    env.update(STWO_RISCV_PARENT_BENCH_ALLOCATOR='smp',STWO_RISCV_PARENT_BENCH_WORKERS='8',STWO_BLAKE3_CSP_RUNTIME='authenticated_aot',STWO_RISCV_METAL_AOT_BUNDLE=str(HERE.parent/'2026-09-24-canonical-parent-pipeline/core'))
    log_path=HERE/f'run-{index:02d}-{variant}.log'
    start=time.perf_counter()
    with log_path.open('w') as output:subprocess.run(['/usr/bin/time','-l',str(binary)],cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT,check=True)
    elapsed=time.perf_counter()-start
    log=log_path.read_text()
    nodes=[dict(re.findall(r'(\w+)=(\S+)',line)) for line in log.splitlines() if line.startswith('BLAKE3_TREE_NODE ')]
    assert [n['artifact_bytes'] for n in nodes]==['853044', '850623', '903838']
    assert all(n['verified']=='true' and n['queries']=='70' and n['pow_bits']=='26' for n in nodes)
    assert 'BLAKE3_TREE verified=true leaves=4 aggregate_levels=2 cycles=6' in log
    assert 'BLAKE3_TREE_PARAMETERS leaf_queries=70 leaf_pow_bits=26 parent_queries=70 parent_pow_bits=26 canonical=true' in log
    budget=dict(re.findall(r'(\w+)=(\d+)',next(line for line in log.splitlines() if line.startswith('CANONICAL_TREE_BUDGET '))))
    assert int(budget['peak_bytes'])<=int(budget['limit_bytes'])
    phases=[dict(re.findall(r'(\w+)=(\S+)',line)) for line in log.splitlines() if line.startswith('CANONICAL_TREE_PHASE ')]
    assert log.count('CANONICAL_TREE_LEAF_POOL workers=8')==2 and len(phases)==6
    if variant=='candidate': assert 'CANONICAL_TREE_CHILD_PREPARATION workers=2 reused_after_failure=true' in log
    row=dict(index=index,variant=variant,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),wall_seconds=elapsed,nodes=nodes,phases=phases,budget=budget,peak_physical_bytes=int(re.search(r'(\d+)\s+peak memory footprint',log)[1]),peak_rss_bytes=int(re.search(r'(\d+)\s+maximum resident set size',log)[1]))
    results.append(row);(HERE/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(index,variant,round(elapsed,3),flush=True)
summary={variant:{'samples':2,'wall_median_seconds':statistics.median(r['wall_seconds'] for r in results if r['variant']==variant),'peak_physical_bytes':max(r['peak_physical_bytes'] for r in results if r['variant']==variant)} for variant in ('control','candidate')}
(HERE/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary),flush=True)
