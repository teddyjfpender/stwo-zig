import ctypes, fcntl, hashlib, json, os, pathlib, re, subprocess, time
lock = open("/tmp/stwo-zig-build.lock", "w")
print("waiting for shared proof/build lock", flush=True)
fcntl.flock(lock, fcntl.LOCK_EX)
repo=pathlib.Path.cwd(); campaign=repo/'.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907'
aot_root=repo/'.git/local-ethereum/ethereum-fixed-program-narrow-aot-v1'
aot=aot_root/'bundle'
aot_receipt=json.loads((aot_root/'build-receipt.json').read_text())
for name,expected_hash in [('stwo_zig_core.manifest.json',aot_receipt['manifest_sha256']),('stwo_zig_core.metallib',aot_receipt['metallib']['sha256'])]:
 if hashlib.sha256((aot/name).read_bytes()).hexdigest()!=expected_hash:raise SystemExit('AOT identity changed')
root=campaign/'metal-field5-segment11-log18-v2'; root.mkdir()
product=repo/'.git/local-ethereum/prepared-leaf-metal-product-v7'
build_receipt=json.loads((product/'build-receipt.json').read_text())
if build_receipt['exit_code']!=0:raise SystemExit('Frozen Metal5 build has not passed')
exe=pathlib.Path(build_receipt['executable']['path'])
if hashlib.sha256(exe.read_bytes()).hexdigest()!=build_receipt['executable']['sha256']:raise SystemExit('Frozen Metal5 executable changed')
proof=root/'segment-000011.stwief04'; metadata=root/'segment-000011.metadata.json'
args=[str(exe),'--retained-materialization-result',str(campaign/'authority/materialization-v2.json'),'--publication-root',str(campaign/'capture/publication-parent/ethereum-incremental-capture-v4'),'--selected-leaf-admission-root',str(campaign/'metal-field5-block-selected-admissions-v1/leaf-000011'),'--segment-index','11','--output',str(proof),'--campaign-geometry','authenticated-v1','--claim-admission','fixed_program_narrow_v5','--global-metadata-output',str(metadata),'--pcs-retained-byte-budget',str(24*2**30),'--workers','1','--host-byte-budget',str(16*2**30),'--host-byte-limit',str(32*2**30),'--aot-bundle',str(aot),'--aot-manifest-sha256',aot_receipt['manifest_sha256']]
def ident(path):
 data=path.read_bytes();return {'path':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
class Usage(ctypes.Structure):
 _fields_=[('uuid',ctypes.c_uint8*16)]+[(n,ctypes.c_uint64) for n in ['user_time','system_time','idle_wakes','interrupt_wakes','pageins','wired_size','resident_size','physical_footprint','start','exit']]
class Timebase(ctypes.Structure):
 _fields_=[('numer',ctypes.c_uint32),('denom',ctypes.c_uint32)]
timebase=Timebase();ctypes.CDLL('/usr/lib/libSystem.B.dylib').mach_timebase_info(ctypes.byref(timebase))
lib=ctypes.CDLL('/usr/lib/libproc.dylib');lib.proc_pid_rusage.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p];lib.proc_pid_rusage.restype=ctypes.c_int
policy={'worker_count':1,'composition_host_budget_bytes':16*2**30,'pcs_retained_byte_budget_bytes':24*2**30,'host_admission_limit_bytes':32*2**30,'process_cap_enforced':False,'sample_interval_seconds':2,'limits_scope':'Composition and PCS admission budgets are distinct from host admission; process footprint sampling is observational and does not enforce a cap'}
plan={'schema':'stwo.ethereum.real-native-leaf-measurement.v1','command':args,'policy':policy,'executable':ident(exe),'source_manifest':build_receipt['source_manifest'],'cpu_reference_supplied':False,'aot_manifest_sha256':aot_receipt['manifest_sha256'],'started_unix_ns':time.time_ns(),'segment_index':11,'execution_cycles':2097152,'claim_admission':'fixed_program_narrow_v5','backend':'authenticated_AOT_Metal','claim':'one native full leaf core plus providers, serialized producer destruction and fresh native verification; not a block or succinct root'}
(root/'plan.json').write_text(json.dumps(plan,indent=2)+'\n');(root/'run.py').write_bytes(pathlib.Path(__file__).read_bytes())
env=os.environ.copy()
for name in ['STWO_ZIG_STAGE101_REFERENCE_ARTIFACT','STWO_ZIG_STAGE101_BENCHMARK_ADMISSION_V2']:env.pop(name,None)
configured_env={'STWO_ZIG_STAGE101_STAGE_PROFILE':'1'};env.update(configured_env)
(root/'environment.json').write_text(json.dumps(configured_env,indent=2)+'\n')
start=time.monotonic_ns();peak=0;child=None
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
  time.sleep(2)
receipt={'schema':plan['schema'],'exit_code':process.returncode,'monitor_elapsed_ns':time.monotonic_ns()-start,'sampled_peak_footprint_bytes':peak,'process_cap_enforced':False,'policy':policy,'verified_and_published':process.returncode==0 and proof.is_file() and metadata.is_file(),'ended_unix_ns':time.time_ns()}
for line in (root/'stderr-and-time.log').read_text().splitlines():
 m=re.match(r'\s*([0-9.]+) real\s+([0-9.]+) user\s+([0-9.]+) sys',line)
 if m:receipt.update(dict(zip(('real_seconds','user_seconds','sys_seconds'),map(float,m.groups()))))
 for label,key in [('maximum resident set size','maximum_resident_set_size_bytes'),('peak memory footprint','peak_memory_footprint_bytes')]:
  if label in line:receipt[key]=int(line.strip().split()[0])
for key,path in [('artifact',proof),('global_metadata',metadata)]:
 if path.exists():receipt[key]=ident(path)
receipt['measurement_lines']=[line for line in (root/'stderr-and-time.log').read_text().splitlines() if line.startswith(('INCREMENTAL_FIXED_PROGRAM_GEOMETRY_V1','INCREMENTAL_FULL_LEAF_INPUT_PHASES_V1','INCREMENTAL_FULL_LEAF_PHASES_V1','INCREMENTAL_FULL_LEAF_PREFLIGHT_V1','ETHEREUM_PREPARED_METAL_V1'))]
(root/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt),flush=True)
raise SystemExit(process.returncode)
