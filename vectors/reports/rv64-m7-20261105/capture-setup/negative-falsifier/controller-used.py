#!/usr/bin/env python3
"""CPU-only capture/setup overlap falsifier on the two development blocks."""
import argparse,hashlib,json,os,subprocess,time,fcntl
from pathlib import Path
import rv64_m7_hybrid_fixture_run as F

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--build-only',action='store_true')
    args=p.parse_args();root=Path(__file__).resolve().parents[1];args.out.mkdir(parents=True,exist_ok=True)
    receipt=dict(schema='rv64-m7-capture-setup-diagnostic/v1',ethereum_proof=False,default_promoted=False,gpus=0,commands=[])
    env=os.environ.copy();env.update(CUDA_VISIBLE_DEVICES='',ZIG_GLOBAL_CACHE_DIR='/workspace/m3/cache/zig-global',STWO_ZIG_BUILD_JOBS='8')
    def run(name,argv,changes=None):
        e=env.copy();e.update(changes or {});start=time.monotonic()
        with open(args.out/(name+'.json' if name.startswith(('capture-','setup-')) else name+'.log'),'w') as out,open(args.out/(name+'.stderr'),'w') as err:
            result=subprocess.run(argv,cwd=root,env=e,stdout=out,stderr=err)
        receipt['commands'].append(dict(name=name,argv=list(map(str,argv)),env_changes=changes or {},exit=result.returncode,wall_s=time.monotonic()-start))
        (args.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        print(json.dumps(receipt['commands'][-1]),flush=True)
        if result.returncode:raise RuntimeError(name+' failed')
    with open('/workspace/m3/locks/build.1.lock','a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        before=F.source_hashes(root)
        before.update({str(p.relative_to(root)):F.sha(p) for p in (root/'build_support').rglob('*.zig')})
        receipt['source_files_sha256']=before
        digest=hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest()
        identity=['-Dimplementation-commit='+(root/'.m3-commit-full').read_text().strip(),'-Dimplementation-tree='+(root/'.m3-tree').read_text().strip(),'-Dimplementation-dirty=true','-Dimplementation-dirty-content-sha256='+digest]
        # Completed executable copies may be pruned independently of Zig's
        # runner manifests; clear only this owned, inactive runner hash cache.
        import shutil
        for d in [root/'.zig-cache/h',root/'.zig-cache/products/riscv_cpu/h']:
            if d.exists():shutil.rmtree(d)
        run('fixed-tests',['/workspace/zig/zig','build','test-riscv64-wide-fixed-setup','-Doptimize=ReleaseSafe','--summary','all',*identity])
        prefix='/workspace/m3/build/m7-outer-gkr/capture-setup2'
        run('build',['/workspace/zig/zig','build','rv64-capture-bench','-Doptimize=ReleaseFast','-p',prefix,'--summary','all',*identity])
        after=F.source_hashes(root);after.update({str(p.relative_to(root)):F.sha(p) for p in (root/'build_support').rglob('*.zig')})
        receipt['sources_unchanged']=before==after
        if before!=after:raise RuntimeError('source changed during build')
    binary=Path(prefix)/'bin/rv64-capture-bench';receipt['binary_sha256']=F.sha(binary)
    if not args.build_only:
        for block in (26235156,24628607):
            choices=sorted(Path('/workspace/m3/runs/m7-fold-v3').glob('*/request-'+str(block)+'.json'))
            if not choices:raise RuntimeError('missing dev request '+str(block))
            request=choices[0];receipt.setdefault('requests',{})[str(block)]=dict(path=str(request),sha256=F.sha(request))
            resources=dict(recycler_cache_bytes=1<<30,fixed_setup_bytes=12<<30,keccak_uniform_throughput=True,capture_options=dict(max_inflight_packets=4,packet_heap_bytes=1<<30,max_inflight_packet_heap_bytes=4<<30,max_inflight_wire_bytes=4<<30,execution_workers=8))
            res=args.out/('resources-'+str(block)+'.json');res.write_text(json.dumps(resources))
            for mode in ('off','on'):
                run('capture-'+str(block)+'-'+mode,[str(binary),str(request),'-','0',str(res)],{'STWO_RV64_CAPTURE_WORD_BITMAP':'1' if mode=='on' else '0'})
            left=json.load(open(args.out/('capture-'+str(block)+'-off.json')));right=json.load(open(args.out/('capture-'+str(block)+'-on.json')))
            if left['captured_values_v2_sha256']!=right['captured_values_v2_sha256']:raise RuntimeError('captured diagnostic mismatch')
            for mode in ('serial','classes','eager'):
                run('setup-'+str(block)+'-'+mode,[str(binary),str(request),'-','0',str(res),'setup-'+mode])
            x=json.load(open(args.out/('setup-'+str(block)+'-serial.json')));y=json.load(open(args.out/('setup-'+str(block)+'-eager.json')))
            if x['authorities']!=y['authorities'] or x['cpu']!=y['cpu'] or x['truths']!=y['truths']:raise RuntimeError('authority mismatch')
    receipt['status']='PASS_SCOPED';(args.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
if __name__=='__main__':main()
