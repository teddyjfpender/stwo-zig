import os,json,subprocess,hashlib,time
from pathlib import Path
root=Path('/private/tmp/stwo-rv64-streamed-sail-qualification');binary=root/'zig-out/bin/rv64-om-sail-qualification';config='/private/tmp/stwo-rv64-delivery/word16-independent-qualification-v1/sail/config.json'
report={'source':'48832ce0d866385dc16df666c0854572dd3d6099','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'config_sha256':hashlib.sha256(Path(config).read_bytes()).hexdigest(),'producer_environment':{'STWO_ZIG_GKR_TREE_CHECKPOINTS':'2','STWO_ZIG_GKR_STREAM_BOTTOM':'1','STWO_ZIG_GKR_TREE_METRICS':'1'},'fresh_receiver_environment':'all STWO_ZIG_GKR_* operational selection flags removed','security_qualified':False,'whole_protocol_128':False,'runs':{}}
env=os.environ.copy();env.update(report['producer_environment']);freshenv={k:v for k,v in os.environ.items() if not k.startswith('STWO_ZIG_GKR_')}
for mode in ['control','candidate']:
 out=Path(f'/tmp/stwo-rv64-om-sail-stream68-{mode}-v1')
 if out.exists():raise RuntimeError('refuse overwrite '+str(out))
 start=time.time()
 with open(f'/tmp/rv64-sail-stream68-{mode}-produce.stdout','w') as stdout,open(f'/tmp/rv64-sail-stream68-{mode}-produce.stderr','w') as stderr:
  subprocess.run(['/usr/bin/time','-l',str(binary),'prove-'+mode,config,str(out)],cwd=root,env=env,stdout=stdout,stderr=stderr,check=True)
 with open(f'/tmp/rv64-sail-stream68-{mode}-fresh.json','w') as stdout,open(f'/tmp/rv64-sail-stream68-{mode}-fresh.stderr','w') as stderr:
  subprocess.run([str(binary),'verify-'+mode,config,str(out)],cwd=root,env=freshenv,stdout=stdout,stderr=stderr,check=True)
 fresh=json.load(open(f'/tmp/rv64-sail-stream68-{mode}-fresh.json'));assert fresh['verification']['accepted'] and fresh['verification']['wrong_endpoint_rejected']
 names=['bundle.json','cells.bin','cpu-0.bin','stage-one.bin'];hashes={n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in names};original=Path(f'/tmp/stwo-rv64-om-sail-{mode}-v1');oldhashes={n:hashlib.sha256((original/n).read_bytes()).hexdigest() for n in names};assert hashes==oldhashes,('proof mismatch',mode,hashes,oldhashes)
 qual=json.load(open(out/'qualification.json'));assert qual['steps']==1032240 and qual['target_cases']==12903 and qual['every_retirement_compared'] and all(qual['opcode_histogram'][:63])
 assert 'streamed_bottom=true planned_input_reserve_bytes=0' in Path(f'/tmp/rv64-sail-stream68-{mode}-produce.stderr').read_text()
 opposite='candidate' if mode=='control' else 'control'
 cross=subprocess.run([str(binary),'verify-'+opposite,config,str(out)],cwd=root,env=freshenv,capture_output=True,text=True);assert cross.returncode!=0,'acceptedwrongprofile';Path(f'/tmp/rv64-sail-stream68-{mode}-cross.stderr').write_text(cross.stderr)
 report['runs'][mode]={'directory':str(out),'four_authoritative_files_byte_exact':True,'file_sha256':hashes,'qualification':qual,'fresh':fresh,'wrong_profile_rejected':cross.stderr.strip(),'elapsed_produce_fresh_and_cross_seconds':time.time()-start}
 Path('/tmp/rv64-sail-stream68-qualification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'passed':True,'profiles':len(report['runs']),'report':'/tmp/rv64-sail-stream68-qualification.json'}))
