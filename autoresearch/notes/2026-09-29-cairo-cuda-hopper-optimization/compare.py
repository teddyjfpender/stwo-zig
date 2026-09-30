"""Verified all-four-PIE ABBA, persistent requests and targeted CUDA profiles.

Run on the funded host after remote.py qualifies the assembled candidate.
Profiles are diagnostic; only uninstrumented runs contribute timing verdicts.
"""
from argparse import Namespace
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path('/workspace/stwo-zig')
sys.path.insert(0, str(ROOT/'scripts'))
import benchmark_cairo_cuda as bench

OUT = Path(os.environ.get('STWO_HOPPER_OUT','/workspace/hopper-experiments'))
OUT.mkdir(exist_ok=False)
VERIFIER = ROOT/'tools/stwo-cairo-official-verifier-rs/target/release/stwo-cairo-official-verifier'
PRODUCTS = {'baseline': Path(os.environ.get('STWO_HOPPER_BASELINE','/workspace/baseline-v45/stwo-cairo-cuda')),
            'candidate': ROOT/'zig-out/bin/stwo-cairo-cuda'}
ENV = dict(os.environ, STWO_CAIRO_CUDA_ARTIFACT_DIR=str(ROOT/'vectors/cairo'),
           STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS='/workspace/canonical.stwzppc',
           STWO_CAIRO_CUDA_PREPROCESSED_VARIANT='canonical',
           LD_LIBRARY_PATH='/usr/local/cuda/lib64:'+os.environ.get('LD_LIBRARY_PATH',''))

def run(label, args, timeout=180):
    with (OUT/(label+'.log')).open('w') as log:
        started = time.monotonic_ns()
        result = subprocess.run(args, cwd=ROOT, env=ENV, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
    print(label, result.returncode, (time.monotonic_ns()-started)/1e9, flush=True)
    if result.returncode:
        print((OUT/(label+'.log')).read_text()[-3000:], flush=True)
        raise RuntimeError(label+' failed')

nvml = ctypes.CDLL('libnvidia-ml.so.1')
assert nvml.nvmlInit_v2() == 0
device = ctypes.c_void_p()
assert nvml.nvmlDeviceGetHandleByIndex_v2(0, ctypes.byref(device)) == 0
doc = {'schema':'stwo-cairo-hopper-abba-v1', 'security':bench.SECURITY,
       'gpu':subprocess.check_output(['nvidia-smi','--query-gpu=name,uuid,memory.total,driver_version','--format=csv,noheader,nounits'],text=True).strip(),
       'products':{k:bench.sha(v) for k,v in PRODUCTS.items()},
       'compiled_snapshot':json.loads(Path('/workspace/compiled-snapshot.json').read_text()),
       'scope':'cold process; adapted input to publication; process wall includes teardown; excludes raw PIE execution and queueing',
       'order':['baseline','candidate','candidate','baseline'], 'results':[], 'warm':[]}
try:
    for block,label in enumerate(doc['order'],1):
        blockdir=OUT/('block-'+str(block)+'-'+label);blockdir.mkdir()
        args=Namespace(prover=PRODUCTS[label],verifier=VERIFIER,input_dir=Path('/workspace/inputs'),
                       artifact_dir=ROOT/'vectors/cairo',preprocessed=Path('/workspace/canonical.stwzppc'),out=blockdir,timeout=180)
        for number in range(1,5):
            result=bench.run_trial(args,number,1,nvml,device)
            result.update(product=label,block=block)
            if result['status']!='verified':
                raise RuntimeError('unqualified ABBA proof: '+json.dumps(result))
            report=json.loads((blockdir/f'sn-pie-{number}-trial-1/backend.json').read_text())
            result['runtime_teardown_ns']=report.get('runtime_teardown_ns',0)
            doc['results'].append(result)
            (OUT/'comparison.json').write_text(json.dumps(doc,indent=2)+'\n')
            print(label,number,result['status'],result.get('backend_trial',{}).get('proof_execute_and_decode_ns'),flush=True)
            if result['status']!='verified':raise RuntimeError('unqualified ABBA proof')
            verdict=result['backend_trial']['verdict']
            assert verdict['aot']['aot_misses']==0
            assert verdict['counters']['d2h_proof_operations']==1
    for number in range(1,5):
        prefix='warm-pie-'+str(number);proof=OUT/(prefix+'.proof.json');report=OUT/(prefix+'.backend.json');oracle=OUT/(prefix+'.oracle.json')
        source=Path('/workspace/inputs')/f'sn-pie-{number}.cpi'
        run(prefix,[str(PRODUCTS['candidate']),'prove','--backend','cuda','--input',str(source),'--output',str(proof),'--report-out',str(report),'--repeat','3'])
        run(prefix+'-verify',[str(VERIFIER),'verify','--proof',str(proof),'--channel','blake2s','--proof-format','json','--result',str(oracle)])
        backend=json.loads(report.read_text());official=json.loads(oracle.read_text());trials=backend['completed_trials']
        assert len(trials)==3
        for index,trial in enumerate(trials):
            bench.check_receipts(dict(backend,completed_trials=[trial]),official,proof,input_sha256=bench.sha(source),executable_sha256=bench.sha(PRODUCTS['candidate']))
            assert trial['prepared_arena_reused']==(index>0) and trial['preprocessed_reused']==(index>0)
            assert trial['verdict']['aot']['aot_misses']==0
            assert trial['verdict']['counters']['d2h_proof_operations']==1
        doc['warm'].append({'benchmark':f'SN PIE {number}','trials':trials,'official_verification':official,
                            'runtime_teardown_ns':backend['runtime_teardown_ns'],
                            'verification_scope':'every receipt digest matches the identical bytes accepted by pinned Rust; CLI enforces identical proof digests across repetitions'})
        (OUT/'comparison.json').write_text(json.dumps(doc,indent=2)+'\n')
    for label,number in [('baseline',1),('candidate',1),('candidate',3)]:
        prefix=f'profile-{label}-pie-{number}';proof=OUT/(prefix+'.proof.json');report=OUT/(prefix+'.backend.json')
        run(prefix,['python3',str(ROOT/'autoresearch/cli/stwo-prof'),'cuda','systems','--output',str(OUT/(prefix+'.nsys-rep')),'--timeout','180','--',str(PRODUCTS[label]),'prove','--backend','cuda','--input',f'/workspace/inputs/sn-pie-{number}.cpi','--output',str(proof),'--report-out',str(report),'--repeat','1'])
        run(prefix+'-stats',['nsys','stats','--report','cuda_gpu_kern_sum,cuda_api_sum,cuda_gpu_mem_time_sum','--format','csv',str(OUT/(prefix+'.nsys-rep'))])
    doc['complete']=True
    (OUT/'comparison.json').write_text(json.dumps(doc,indent=2)+'\n')
finally:
    nvml.nvmlShutdown()
