import ctypes,json,pathlib,time
out=pathlib.Path.cwd()/".git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907/metal-field5-block-v1"
class Usage(ctypes.Structure):
 _fields_=[("uuid",ctypes.c_uint8*16)]+[(n,ctypes.c_uint64) for n in ["user_time","system_time","idle_wakes","interrupt_wakes","pageins","wired_size","resident_size","physical_footprint","start","exit"]]
lib=ctypes.CDLL("/usr/lib/libproc.dylib");lib.proc_pid_rusage.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p];lib.proc_pid_rusage.restype=ctypes.c_int
pid=24606;peak=0;start=time.time_ns()
(out/"leaf0-observer-v1.py").write_bytes(pathlib.Path(__file__).read_bytes())
with (out/"leaf0-process-samples-v1.ndjson").open("x") as f:
 while True:
  u=Usage()
  if lib.proc_pid_rusage(pid,0,ctypes.byref(u))!=0:break
  peak=max(peak,u.physical_footprint);f.write(json.dumps({"unix_ns":time.time_ns(),"pid":pid,"rss_bytes":u.resident_size,"physical_footprint_bytes":u.physical_footprint})+"\n");f.flush();time.sleep(2)
(out/"leaf0-observer-receipt-v1.json").write_text(json.dumps({"pid":pid,"sampling_start_unix_ns":start,"sampling_end_unix_ns":time.time_ns(),"sampled_peak_footprint_bytes":peak,"process_cap_enforced":False,"scope":"Observational samples begin after producer started; producer phase lifetime peak remains authoritative"},indent=2)+"\n")
