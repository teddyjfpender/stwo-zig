"""One bounded diagnostic CUDA proof; records failures and sampled GPU usage."""
import ctypes,datetime,hashlib,json,os,subprocess,threading,time
from pathlib import Path
out=Path(os.environ.get('STWO_RUNPOD_QUALIFICATION_DIR','/workspace/qualification-v4'))
out.mkdir(exist_ok=False)
product=Path('/workspace/stwo-zig/zig-out/bin/stwo-cairo-cuda')
command=[str(product),'prove','--backend','cuda','--input','/workspace/sn2-official.stwzcpi','--output',str(out/'proof.envelope'),'--report-out',str(out/'backend-report.json'),'--repeat','1']
env=dict(os.environ)
env['STWO_CAIRO_CUDA_ARTIFACT_DIR']='/workspace/stwo-zig/vectors/cairo'
env['STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS']='/workspace/canonical.stwzppc'
env['LD_LIBRARY_PATH']='/usr/local/cuda/lib64:'+env.get('LD_LIBRARY_PATH','')
class Memory(ctypes.Structure):
    _fields_=[('total',ctypes.c_ulonglong),('free',ctypes.c_ulonglong),('used',ctypes.c_ulonglong)]
nvml=ctypes.CDLL('libnvidia-ml.so.1')
assert nvml.nvmlInit_v2()==0
handle=ctypes.c_void_p()
assert nvml.nvmlDeviceGetHandleByIndex_v2(0,ctypes.byref(handle))==0
samples=[]
done=threading.Event()
def sample():
    while not done.is_set():
        mem=Memory()
        if nvml.nvmlDeviceGetMemoryInfo(handle,ctypes.byref(mem))==0: samples.append({'monotonic_ns':time.monotonic_ns(),'used_bytes':mem.used})
        done.wait(0.1)
thread=threading.Thread(target=sample);thread.start()
started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()
started=time.monotonic_ns()
with (out/'process.log').open('xb') as log:
    child=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,env=env)
    kill=threading.Timer(180,child.kill);kill.start()
    _,status,usage=os.wait4(child.pid,0)
    kill.cancel()
wall=time.monotonic_ns()-started
done.set();thread.join();nvml.nvmlShutdown()
receipt={'schema':'stwo-zig-cairo-cuda-runpod-hardware-diagnostic-v1','started_utc':started_utc,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':command,'status':'emitted-awaiting-independent-verification' if os.waitstatus_to_exitcode(status)==0 else 'failed','exit_code':os.waitstatus_to_exitcode(status),'process_wall_ns':wall,'host_max_rss_bytes':usage.ru_maxrss*1024,'highest_sampled_device_used_bytes':max(x['used_bytes'] for x in samples) if samples else None,'gpu_memory_scope':'whole device NVML samples at 100ms; observed lower bound on peak, includes driver allocations','samples':samples,'product_sha256':hashlib.sha256(product.read_bytes()).hexdigest()}
if (out/'backend-report.json').exists():receipt['backend_report']=json.loads((out/'backend-report.json').read_text())
(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({k:v for k,v in receipt.items() if k not in ('samples','backend_report')},indent=2))
raise SystemExit(receipt['exit_code'])
