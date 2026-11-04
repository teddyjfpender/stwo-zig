#!/usr/bin/env python3
"""Future physical-GPU gate through the existing production outer DAG fixture.
No rentals or implicit hardware discovery. Never run as part of host tests.
"""
import argparse, hashlib, json, os, pathlib, re, sys
ROOT=pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
import rv64_ethereum_basket as B

def require(condition, message):
    if not condition: raise RuntimeError(message)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--tool',type=pathlib.Path,required=True)
    p.add_argument('--tool-sha256',required=True)
    p.add_argument('--library',type=pathlib.Path,required=True)
    p.add_argument('--library-sha256',required=True)
    p.add_argument('--output',type=pathlib.Path,required=True)
    args=p.parse_args()
    args.tool=args.tool.resolve();args.library=args.library.resolve();args.output=args.output.resolve()
    require(B.sha(args.tool)==args.tool_sha256 and B.sha(args.library)==args.library_sha256,"tool/library identity mismatch")
    args.output.mkdir(parents=True,exist_ok=False)
    cpu={k:v for k,v in os.environ.items() if not k.startswith(('STWO_RV64_','CUDA_'))}
    cpu['CUDA_VISIBLE_DEVICES']='';cpu['STWO_RV64_GPU_PCS_HELPER']='/bin/false'
    gpu=dict(os.environ);gpu['STWO_RV64_OUTER_PADDING_RANGES']='1'
    result={'schema':'rv64-assignment-range-future-GPU-gate/v1','accepted':False,'tool_sha256':args.tool_sha256,'library_sha256':args.library_sha256,'runs':[]}
    try:
        result['runs'].append(B.measure([str(args.tool),'--outer-dag-control',str(args.output)],args.output,'control',cpu,cwd=str(ROOT)))
        result['runs'].append(B.measure([str(args.tool),'--outer-dag-proof',str(args.library),str(args.output)],args.output,'candidate',gpu,cwd=str(ROOT)))
        log=(args.output/'candidate.stderr').read_text()
        calls=re.findall(r'GPU_OUTER_ASSIGNMENT_RANGE_CALLS calls=(\d+) kernel_launches=(\d+)',log)
        require(len(calls)>=2 and all(int(a)>0 and int(b)>0 for a,b in calls),"candidate did not execute range kernels")
        # Existing gpu_dag fixture enables check_reference: every generated
        # assignment coordinate is read back and compared before proof assembly.
        require(len(re.findall(r'reference_readback_ns=[1-9]\d*',log))>=2,"missing full assignment reference comparison")
        hashes={name:B.sha(args.output/name) for name in ['control.om31','gpu-0.om31','gpu-1.om31']}
        require(len(set(hashes.values()))==1,"CPU/cold/warm proof mismatch")
        for index in range(2):
            result['runs'].append(B.measure([str(args.tool),'--outer-dag-check',str(args.output/f'gpu-{index}.om31'),str(args.output)],args.output,f'fresh-{index}',cpu,cwd=str(ROOT)))
            require('OM31_OUTER_DEVICE_FRESH_RECEIVER accepted=true' in (args.output/f'fresh-{index}.stderr').read_text(),"fresh receiver did not accept")
        require(hashes=={name:B.sha(args.output/name) for name in hashes},"fresh receiver mutated proof artifacts")
        result.update(accepted=True,proof_sha256=hashes,actual_range_calls=calls,full_assignment_reference_exact=True,fresh_CPU_receivers=2,production_default_changed=False)
    except Exception as error:
        result['error']=repr(error)
        if hasattr(error,'measurement'):result['failed_process']=error.measurement
        raise
    finally:
        B.atomic_json(args.output/'range-qualification.json',result)
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
