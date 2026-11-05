#!/usr/bin/env python3
"""Existing setup-cache route, matched full M6 requests; no experimental flags."""
import argparse,hashlib,json,os,subprocess,sys,time
from pathlib import Path

EXPECTED={
 'driver':'eba08050ea233a4ead8d6d719127b2c5f84702b0339fe2566fed184c84b91f44',
 'library':'69f18a25c23c042b7fc00d2477097de64c69ea59fd46d2eee6fc9e154dc665e0',
 'receiver':'0434da7892cd5c0365eef9a999de0c2f78fb5323da604c0f30e96a7224f65d6d'}
PATHS={
 'driver':'/workspace/m3/build/m7-assignment-graphs/immutable/zig-out/bin/rv64-word16-ethereum-gpu-combined',
 'library':'/workspace/m3/build/m7-controller-graphs/cuda/native/libstwo-rv64-native.so',
 'receiver':'/workspace/m3/build/m6-integrate/zig-out/bin/rv64-word16-ethereum-recursion-receiver'}
def sha(p):
 with open(p,'rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--repeat',type=int,default=2);ap.add_argument('--blocks',nargs='+',type=int,default=[24628607,26235156]);args=ap.parse_args()
 if set(args.blocks)-{24628607,26235156}:raise ValueError('devblocks only')
 root=Path('/workspace/m3/src/m7-fold-v3');args.out.mkdir(parents=True,exist_ok=False)
 for k,p in PATHS.items():assert sha(p)==EXPECTED[k],(k,p)
 source={str(p.relative_to(root)):sha(p) for p in sorted((root/'src').rglob('*')) if p.is_file() and p.suffix in ('.zig','.cu','.cuh','.h','.cpp') and '.zig-cache' not in p.parts}
 scripts={str(p.relative_to(root)):sha(p) for p in (root/'scripts').glob('*.py')}
 receipt=dict(schema='rv64-m7-existing-setup-cache-full-request/v1',scope='Matched cold request comparison of EXISTING identity-only resident setup route; new bitmap/class-first/eager switches NOT in selected binary',controller_sha256=sha(__file__),source_checkpoint='df39f1a87 plus graph lease-alias fix; runtime69f11e-basis; parent-pinned assets',assets={k:dict(path=p,sha256=EXPECTED[k]) for k,p in PATHS.items()},source_sha256=source,scripts_sha256=scripts,runs=[])
 def save(): (args.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
 save()
 env={k:v for k,v in os.environ.items() if not k.startswith(('STWO_RV64_','STWO_ZIG_RV64_SETUP'))}
 for block in args.blocks:
  receipts={}
  for mode in ('off','on'):
   for k,p in PATHS.items():assert sha(p)==EXPECTED[k]
   assert all(sha(root/f)==h for f,h in source.items())
   tag='existing-setup-'+args.out.name+'-'+mode
   run=Path('/workspace/m3/runs/m7-fold-v3')/f'daemon-{block}-r{args.repeat}-{tag}'
   command=[sys.executable,str(root/'scripts/rv64_m4_resident.py'),'daemon',str(block),'--stream','m7-fold-v3','--build-stream','m7-fold-v3','--repeat',str(args.repeat),'--store','none','--receive','first','--driver',PATHS['driver'],'--library',PATHS['library'],'--receiver',PATHS['receiver'],'--tag',tag]
   for value in ['STWO_RV64_LEAF_SEED_TAPE=1','STWO_RV64_PACK_FOLD_CACHE=1','STWO_RV64_CPU_COMPACT_INGRESS=1','STWO_RV64_COMPOSITION_ENQUEUE=0','STWO_RV64_BLAKE_SAMPLE_PREFILL=1','STWO_RV64_NVTX=1','STWO_RV64_OUTER_ASSIGNMENT_GRAPH=0','STWO_RV64_OUTER_OWNER_CONTROLLER=0','STWO_RV64_RC_ROLE_WORKSPACE=0']:
    command+=['--env',value]
   if mode=='on':command+=['--env','STWO_ZIG_RV64_SETUP_CACHE=']
   name=f'{block}-{mode}';(args.out/(name+'-command.json')).write_text(json.dumps(command,indent=2)+'\n');start=time.monotonic()
   with open(args.out/(name+'.log'),'w') as log:result=subprocess.run(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
   row=dict(block=block,mode=mode,argv=command,run=str(run),exit=result.returncode,wall_s=time.monotonic()-start);receipt['runs'].append(row);save();print(json.dumps(row),flush=True)
   if result.returncode:
    receipt['status']='FAILED_CLOSED_NO_RETRY';save();return 1
   run_receipt=run/'receipt.json';receipts[mode]=run_receipt
   subprocess.run([sys.executable,'/workspace/m3/src/m7-admission/vectors/reports/rv64-m7-20261105/admission/raw/compare.py',str(run_receipt),str(args.out/(name+'-m6-parity.json'))],check=True)
   data=json.load(open(run_receipt));assert data['receivers'] and all(v['accepted'] for v in data['receivers'])
  subprocess.run([sys.executable,str(root/'scripts/rv64_m7_pair.py'),str(receipts['off']),str(receipts['on']),'--out',str(args.out/(str(block)+'-pair.json'))],check=True)
 receipt['status']='PASS_FULL_M6_PARITY_FRESH';save();return 0
if __name__=='__main__':raise SystemExit(main())
