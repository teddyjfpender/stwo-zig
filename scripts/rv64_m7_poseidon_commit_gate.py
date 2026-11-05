#!/usr/bin/env python3
"""Actual native CUDA resident commitment hash go/no-go; no FFT/prover claim."""
import argparse, fcntl, hashlib, json, os, statistics, struct, subprocess, time
from pathlib import Path
import rv64_m7_poseidon2_ref as R
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def reference(cols,rows,kind):
    leaves=[]
    for r in range(rows):
        values=[((c*rows+r)*17+13)%R.P for c in range(cols)]
        leaves.append(R.sponge(1,values) if kind=='p2' else list(struct.unpack('<8I',hashlib.blake2s(b'leaf'+bytes(60)+struct.pack('<'+'I'*cols,*values)).digest())))
    all_nodes=list(leaves)
    while len(leaves)>1:
        layer=[]
        for i in range(0,len(leaves),2):
            pair=leaves[i]+leaves[i+1]
            layer.append(R.sponge(2,pair) if kind=='p2' else list(struct.unpack('<8I',hashlib.blake2s(b'node'+bytes(60)+struct.pack('<16I',*pair)).digest())))
        all_nodes+=layer;leaves=layer
    return [x for node in all_nodes for x in node]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);p.add_argument('--binary',type=Path,required=True);p.add_argument('--gpu',default='0');p.add_argument('--lock',default='/workspace/m3/locks/gpu.lock');p.add_argument('--quick',action='store_true');p.add_argument('--variant',default='prototype');p.add_argument('--generated-header',type=Path);p.add_argument('--baseline-receipt',type=Path);args=p.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    sources=['src/backends/cuda/native/common/m31.cuh','scripts/rv64_m7_poseidon_fast_reduction.py','tests/cuda/rv64/poseidon_commit_bench.cu','src/backends/cuda/native/rv64/poseidon2_m31.cuh','src/backends/cuda/native/commitment/blake2s_core.cuh','src/backends/cuda/native/commitment/blake2s_protocol.cuh','scripts/rv64_m7_poseidon2_ref.py','scripts/rv64_m7_poseidon_commit_gate.py']
    receipt=dict(schema='rv64-m7-native-merkle-commitment-hash-throughput/v1',status='RUNNING',variant=args.variant,ethereum=False,fft_included=False,transfer_included=False,production_p2_backend_selected=False,binary_sha256=sha(args.binary),source_sha256={s:sha(ROOT/s) for s in sources},independent_reference=R.check(),parity=[],benchmarks=[])
    lib=Path('/workspace/m3/build/m7-outer-gkr/cuda/native/libstwo-rv64-native.so');receipt['blake_library_sha256']=sha(lib)
    if args.generated_header:receipt['generated_header_sha256']=sha(args.generated_header)
    if args.baseline_receipt:receipt['baseline_receipt_sha256']=sha(args.baseline_receipt)
    env=os.environ.copy();env['CUDA_VISIBLE_DEVICES']=args.gpu
    def run(cols,log,reps,dump=False):
        argv=[str(args.binary),str(cols),str(log),str(reps)]+(['dump'] if dump else [])
        began=time.monotonic();r=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,text=True,timeout=75)
        logpath=args.out/f'c{cols}-l{log}-r{reps}.log';logpath.write_text(r.stdout+r.stderr)
        if r.returncode:raise RuntimeError(f'CUDA benchmark failed{r.returncode}: {r.stderr}')
        data=json.loads(next(l[6:] for l in r.stdout.splitlines() if l.startswith('BENCH ')));data['host_process_wall_s']=time.monotonic()-began
        return data,r.stdout
    try:
        with open(args.lock,'a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            for cols in (1,12,13,47,128,479):
                data,output=run(cols,3,1,True)
                for kind in ('blake','p2'):
                    got=list(map(int,next(l for l in output.splitlines() if l.startswith('TREE '+kind+' ')).split()[4:]));want=reference(cols,8,kind)
                    if got!=want:raise RuntimeError(f'{kind} all-layer CPU parity failed width{cols}')
                receipt['parity'].append(dict(columns=cols,rows=8,every_retained_node_matches_independent_CPU=True))
                print(json.dumps(receipt['parity'][-1]),flush=True)
            cases=[(47,14),(128,14),(479,14),(47,17),(128,17),(304,17),(479,17)]
            if not args.quick:cases += [(128,20),(479,20)]
            for cols,log in cases:
                data,_=run(cols,log,5)
                b=statistics.median(data['blake_ms'])/1000;p2=statistics.median(data['p2_ms'])/1000
                data.update(blake_median_gpu_s=b,p2_median_gpu_s=p2,p2_over_blake=p2/b,blake_input_GiB_s=data['input_bytes']/2**30/b,p2_input_GiB_s=data['input_bytes']/2**30/p2,blake_row_commitments_s=data['rows']/b,p2_row_commitments_s=data['rows']/p2)
                if args.baseline_receipt:
                    baseline=json.loads(args.baseline_receipt.read_text());old=next(b for b in baseline['benchmarks'] if b['columns']==cols and b['log_rows']==log)
                    if data['p2_root']!=old['p2_root'] or data['blake_root']!=old['blake_root']:raise RuntimeError('large-tree GPU baseline root parity')
                    data['large_tree_gpu_baseline_root_parity']=True
                receipt['benchmarks'].append(data);print(json.dumps(data),flush=True)
                (args.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        receipt['sources_unchanged']=receipt['source_sha256']=={s:sha(ROOT/s) for s in sources};receipt['status']='PASS' if receipt['sources_unchanged'] else 'SOURCE_CHANGED'
    except Exception as e:receipt['status']='FAIL';receipt['error']=str(e);raise
    finally:(args.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
if __name__=='__main__':main()
