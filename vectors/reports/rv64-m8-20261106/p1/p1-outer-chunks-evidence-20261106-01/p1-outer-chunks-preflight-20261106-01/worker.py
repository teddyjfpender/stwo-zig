import fcntl,json,os,pathlib,subprocess,sys,time
root=pathlib.Path('/workspace/m3/src/m7-integrate')
out=pathlib.Path('/workspace/m3/runs/m7-integrate/p1-outer-chunks-preflight-20261106-01')
sys.path.insert(0,str(root/'scripts'))
import rv64_m7_integration_stack as stack
env=stack.clean_environment(os.environ)
env['ZIG_GLOBAL_CACHE_DIR']='/workspace/m3/cache/zig-global'
env['TMPDIR']='/workspace/m3/tmp'
record={'status':'RUNNING','source_commit':(root/'.m3-commit').read_text().strip(),'source_sha256':stack.source_hashes(root),'steps':[]}
stack.write(out/'preflight.json',record)
lock=open('/workspace/m3/locks/build.1.lock','a')
fcntl.flock(lock,fcntl.LOCK_EX)
commands=[
 ('unit',['/workspace/zig/zig','build','test','test-rv64-recursion-ready','test-rv64-batch-plan','test-rv64-gkr-plan','test-rv64-pcs-geometry','-j2','-Doptimize=ReleaseSafe','-Dtarget=x86_64-linux-gnu','-Dcpu=x86_64_v4+sha','--cache-dir',str(root/'.zig-cache')],root/'src/integrations/riscv_cuda'),
 ('build',['python3','scripts/rv64_m3_pod.py','build','--stream','m7-integrate','--only','zig'],root)]
for name,argv,cwd in commands:
 step={'name':name,'argv':argv,'started_ns':time.time_ns()}
 record['steps'].append(step);stack.write(out/'preflight.json',record)
 with (out/(name+'.log')).open('w') as log:rc=subprocess.run(argv,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
 step.update(exit_code=rc,finished_ns=time.time_ns());stack.write(out/'preflight.json',record)
 if rc:
  record['status']='FAILED';stack.write(out/'preflight.json',record);(out/'exit').write_text(str(rc)+'\n');sys.exit(rc)
assert stack.source_hashes(root)==record['source_sha256'],'source changed while testing'
record['status']='UNIT_AND_BUILD_PASS';stack.write(out/'preflight.json',record);(out/'exit').write_text('0\n')
