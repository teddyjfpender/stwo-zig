import ctypes, hashlib, json, os, pathlib, re, signal, subprocess, time
repo=pathlib.Path.cwd(); campaign=repo/'.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907'
cpu_root=campaign/'cpu-field4-segment9-selected-v5'
cpu_receipt=json.loads((cpu_root/'receipt.json').read_text())
if not cpu_receipt.get('verified_and_published'):raise SystemExit('CPU reference has not passed native verification')
reference=pathlib.Path(cpu_receipt['artifact']['path'])
reference_bytes=reference.read_bytes()
if len(reference_bytes)!=cpu_receipt['artifact']['bytes'] or hashlib.sha256(reference_bytes).hexdigest()!=cpu_receipt['artifact']['sha256']:raise SystemExit('CPU reference identity changed')
aot=repo/'.git/local-ethereum/real-leaf-metal-aot-v1-20260907'
aot_receipt=json.loads((aot/'build-receipt.json').read_text())
for name in ['stwo_zig_core.manifest.json','stwo_zig_core.metallib']:
 data=(aot/name).read_bytes();expected=aot_receipt['files'][name]
 if len(data)!=expected['bytes'] or hashlib.sha256(data).hexdigest()!=expected['sha256']:raise SystemExit('AOT identity changed')
root=campaign/'metal-field4-segment9-selected-v1'; root.mkdir()
admission={'schema':'stwo.stage101-benchmark-admission.v2','artifact_bytes':len(reference_bytes),'artifact_sha256':hashlib.sha256(reference_bytes).hexdigest(),'claim_schema':4,'manifest_sha256':aot_receipt['files']['stwo_zig_core.manifest.json']['sha256'],'metallib_sha256':aot_receipt['files']['stwo_zig_core.metallib']['sha256']}
admission_path=root/'benchmark-admission-v2.json';admission_path.write_text(json.dumps(admission,indent=2)+'\n')
del reference_bytes
exe=repo/'.git/local-ethereum/real-leaf-metal-product-v3/bin/stage101-metal-autoresearch-v1'
proof=root/'segment-000009.stwief04'; metadata=root/'segment-000009.metadata.json'
args=[str(exe),'--retained-materialization-result',str(campaign/'authority/materialization-v2.json'),'--publication-root',str(campaign/'capture/publication-parent/ethereum-incremental-capture-v4'),'--selected-leaf-admission-root',str(campaign/'selected-leaf-000009-v1'),'--segment-index','9','--output',str(proof),'--campaign-geometry','authenticated-v1','--claim-admission','field_authority_v4','--global-metadata-output',str(metadata),'--pcs-retained-byte-budget',str(24*2**30)]
def ident(path):
 data=path.read_bytes();return {'path':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
class Usage(ctypes.Structure):
 _fields_=[('uuid',ctypes.c_uint8*16)]+[(n,ctypes.c_uint64) for n in ['user_time','system_time','idle_wakes','interrupt_wakes','pageins','wired_size','resident_size','physical_footprint','start','exit']]
class Timebase(ctypes.Structure):
 _fields_=[('numer',ctypes.c_uint32),('denom',ctypes.c_uint32)]
timebase=Timebase();ctypes.CDLL('/usr/lib/libSystem.B.dylib').mach_timebase_info(ctypes.byref(timebase))
lib=ctypes.CDLL('/usr/lib/libproc.dylib');lib.proc_pid_rusage.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p];lib.proc_pid_rusage.restype=ctypes.c_int
policy={'worker_count':1,'composition_host_budget_bytes':16*2**30,'pcs_retained_byte_budget_bytes':24*2**30,'monitor_footprint_stop_bytes':32*2**30,'sample_interval_seconds':2,'limits_scope':'PCS LDE lower bound preflight and composition budget; task process monitor is a sampled fallback, not allocation guarantee'}
plan={'schema':'stwo.ethereum.real-native-leaf-measurement.v1','command':args,'policy':policy,'executable':ident(exe),'started_unix_ns':time.time_ns(),'segment_index':9,'execution_cycles':2097152,'core_rows':2096404,'keccak_calls':682,'signer_calls':66,'claim_admission':'field_authority_v4','backend':'authenticated_AOT_Metal','claim':'one native full leaf core plus providers, serialized producer destruction and fresh native verification; not a block or succinct root'}
(root/'plan.json').write_text(json.dumps(plan,indent=2)+'\n');(root/'run.py').write_bytes(pathlib.Path(__file__).read_bytes())
env=os.environ.copy();configured_env={'STWO_ZIG_STAGE101_STAGE_PROFILE':'1','STWO_ZIG_STAGE101_BENCHMARK_ADMISSION_V2':str(admission_path),'STWO_RISCV_METAL_AOT_BUNDLE':str(aot),'STWO_ZIG_STAGE101_REFERENCE_ARTIFACT':str(reference),'STWO_ZIG_STAGE101_WORKER_COUNT':'1','STWO_ZIG_STAGE101_HOST_BYTE_BUDGET':str(16*2**30),'STWO_ZIG_STAGE101_HOST_BYTE_LIMIT':str(32*2**30),'STWO_ZIG_STAGE101_BUDGET_MS':'600000,600000,3600000,600000'};env.update(configured_env)
(root/'environment.json').write_text(json.dumps(configured_env,indent=2)+'\n')
start=time.monotonic_ns();peak=0;child=None;stopped=False;kill_at=None
with (root/'stdout.log').open('wb') as out,(root/'stderr-and-time.log').open('wb') as err,(root/'process-samples.ndjson').open('w') as samples:
 process=subprocess.Popen(['/usr/bin/time','-l',*args],stdout=out,stderr=err,env=env)
 print(json.dumps({'started':True,'time_pid':process.pid,'directory':str(root)}),flush=True)
 while process.poll() is None:
  if child is None:
   for line in subprocess.check_output(['ps','-axo','pid=,ppid=,comm='],text=True).splitlines():
    p=line.split(None,2)
    if len(p)==3 and int(p[1])==process.pid and p[2].endswith(exe.name):child=int(p[0])
  usage=Usage()
  if child is not None and lib.proc_pid_rusage(child,0,ctypes.byref(usage))==0:
   peak=max(peak,usage.physical_footprint);samples.write(json.dumps({'elapsed_ns':time.monotonic_ns()-start,'pid':child,'rss_bytes':usage.resident_size,'physical_footprint_bytes':usage.physical_footprint,'process_cpu_ns':(usage.user_time+usage.system_time)*timebase.numer//timebase.denom})+'\n');samples.flush()
   if usage.physical_footprint>policy['monitor_footprint_stop_bytes'] and not stopped:
    os.kill(child,signal.SIGTERM);stopped=True;kill_at=time.monotonic()+5
   if stopped and time.monotonic()>kill_at:
    try:os.kill(child,signal.SIGKILL)
    except ProcessLookupError:pass
  time.sleep(2)
receipt={'schema':plan['schema'],'exit_code':process.returncode,'monitor_elapsed_ns':time.monotonic_ns()-start,'sampled_peak_footprint_bytes':peak,'stopped_for_footprint_limit':stopped,'policy':policy,'verified_and_published':process.returncode==0,'ended_unix_ns':time.time_ns()}
for line in (root/'stderr-and-time.log').read_text().splitlines():
 m=re.match(r'\s*([0-9.]+) real\s+([0-9.]+) user\s+([0-9.]+) sys',line)
 if m:receipt.update(dict(zip(('real_seconds','user_seconds','sys_seconds'),map(float,m.groups()))))
 for label,key in [('maximum resident set size','maximum_resident_set_size_bytes'),('peak memory footprint','peak_memory_footprint_bytes')]:
  if label in line:receipt[key]=int(line.strip().split()[0])
for key,path in [('artifact',proof),('global_metadata',metadata)]:
 if path.exists():receipt[key]=ident(path)
(root/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt),flush=True)
raise SystemExit(process.returncode)
