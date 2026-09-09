import ctypes,fcntl,hashlib,json,os,pathlib,re,signal,subprocess,sys,time
repo=pathlib.Path.cwd();out=repo/'.git/local-ethereum/tree0-cpu-metal-v2'
exe=pathlib.Path(sys.argv[1]).resolve(strict=True)
aot=repo/'.git/local-ethereum/real-leaf-metal-aot-v1-20260907'
inputs=repo/'.git/local-ethereum/field-bound-v4'
def sha(path):
 with path.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()
assert sha(aot/'stwo_zig_core.manifest.json')=='d51ffc6f4de6307c47604c67a352f724f3763d798f188ab86ab71c226013acba'
assert sha(aot/'stwo_zig_core.metallib')=='9b1327752224ccd8837063f29c9e5112efac8f6746050f8ff5dc9c2fb23ce8a7'
class Usage(ctypes.Structure):
 _fields_=[('uuid',ctypes.c_uint8*16)]+[(n,ctypes.c_uint64) for n in ['user_time','system_time','idle_wakes','interrupt_wakes','pageins','wired_size','resident_size','physical_footprint','start','exit']]
class Timebase(ctypes.Structure):
 _fields_=[('numer',ctypes.c_uint32),('denom',ctypes.c_uint32)]
timebase=Timebase();ctypes.CDLL('/usr/lib/libSystem.B.dylib').mach_timebase_info(ctypes.byref(timebase))
lib=ctypes.CDLL('/usr/lib/libproc.dylib');lib.proc_pid_rusage.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p];lib.proc_pid_rusage.restype=ctypes.c_int
key=repo/'.git/local-ethereum/root-candidates/b1da0bdb2742637661c5d1626c9fa28ef409fedc77c0772164223e73636ee6b4/key.json'
assert sha(key)=='6be9c7e9cb82ccaf8ddf85038da033bbd0797e51a6731da1a69ebc8d2bf33edc'
expected_root=json.loads(key.read_text())['preprocessed_root']
assert len(expected_root)==8 and all(type(v) is int and 0<=v<2**31-1 for v in expected_root)
pinned=[exe,key,aot/'stwo_zig_core.manifest.json',aot/'stwo_zig_core.metallib',inputs/'native-inputs-v1.json',inputs/'global-metadata-v1.json',inputs/'program.elf']
identities={str(p):sha(p) for p in pinned}
env=os.environ.copy();env.update({'STWO_ETHEREUM_NATIVE_REPLAY_DIR':str(inputs),'STWO_RISCV_METAL_AOT_BUNDLE':str(aot),'STWO_ETHEREUM_TREE0_AOT_MANIFEST_SHA256':identities[str(aot/'stwo_zig_core.manifest.json')],'STWO_ROLE0_GENUINE_WORKER_COUNT':'1','STWO_ROLE0_GENUINE_HOST_BYTE_BUDGET':str(8*2**30),'STWO_ETHEREUM_PROOF_PROGRESS':str(out/'progress.log')})
policy={'workers':1,'graph_host_byte_budget':8*2**30,'sampled_process_footprint_stop_bytes':32*2**30,'timeout_seconds':3600,'sample_interval_seconds':2,'limits_scope':'sampled process monitor is not an allocation guarantee','cpu_reuse_bounded_tail':True,'metal_reuse_bounded_tail':False,'metal_grouped_source_layout':True,'cohort_destroyed_before_metal':True}
with open('/tmp/stwo-zig-build.lock','a+') as lock:
 print('waiting for shared lock',flush=True);fcntl.flock(lock,fcntl.LOCK_EX);print('acquired shared lock',flush=True)
 plan={'command':[str(exe)],'input_sha256':identities,'policy':policy,'endpoint':'tree0_admission_comparison_no_wrapper_proof','started_unix_ns':time.time_ns(),'independently_verified_reference_root':expected_root,'reference_authority':'prior pinned field9 key, never supplied to Tree0 derivation'}
 with (out/'plan.json').open('x') as f:json.dump(plan,f,indent=2)
 peak=0;cpu_ns=0;stopped=None;kill_at=None;started=time.monotonic_ns()
 with (out/'stdout.log').open('xb') as stdout,(out/'stderr.log').open('xb') as stderr,(out/'process-samples.ndjson').open('x') as samples:
  process=subprocess.Popen([str(exe)],stdout=stdout,stderr=stderr,env=env,start_new_session=True)
  print(json.dumps({'pid':process.pid,'directory':str(out)}),flush=True)
  while process.poll() is None:
   elapsed=time.monotonic_ns()-started;usage=Usage()
   if lib.proc_pid_rusage(process.pid,0,ctypes.byref(usage))==0:
    peak=max(peak,usage.physical_footprint);cpu_ns=(usage.user_time+usage.system_time)*timebase.numer//timebase.denom
    samples.write(json.dumps({'elapsed_ns':elapsed,'rss_bytes':usage.resident_size,'physical_footprint_bytes':usage.physical_footprint,'process_cpu_ns':cpu_ns})+'\n');samples.flush()
    if usage.physical_footprint>policy['sampled_process_footprint_stop_bytes'] and stopped is None:stopped='footprint'
   if elapsed>policy['timeout_seconds']*10**9 and stopped is None:stopped='timeout'
   if stopped and kill_at is None:
    os.killpg(process.pid,signal.SIGTERM);kill_at=time.monotonic()+5
   elif kill_at and time.monotonic()>kill_at:
    try:os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError:pass
   time.sleep(2)
 unchanged=all(sha(pathlib.Path(p))==h for p,h in identities.items())
 stderr=(out/'stderr.log').read_text(errors='replace')
 roots=[[int(v.strip()) for v in match.split(',') if v.strip()] for match in re.findall(r'cpu_root=\{([^}]*)\}',stderr)]
 prior_root_parity=bool(roots) and all(root==expected_root for root in roots)
 passed=process.returncode==0 and 'ETHEREUM_TREE0_PARITY exact=true' in stderr and 'All 1 tests passed.' in stderr and unchanged and prior_root_parity
 result={'exit_code':process.returncode,'passed':passed,'stop_reason':stopped,'source_and_binary_unchanged':unchanged,'elapsed_ns':time.monotonic_ns()-started,'sampled_peak_footprint_bytes':peak,'last_sample_process_cpu_ns':cpu_ns,'policy':policy,'wrapper_proof':False,'prior_verified_key_root_equal':prior_root_parity,'prior_key_sha256':identities[str(key)],'expected_preprocessed_root':expected_root,'observed_cpu_roots':roots}
 (out/'receipt.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
 sys.exit(0 if passed else 1)
