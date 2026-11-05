#!/usr/bin/env python3
"""GPU numerical graph lifecycle, dynamic seed and custody/counter smoke gate."""
import ctypes as C, json, sys, hashlib, threading
from pathlib import Path
u=C.c_uint32; p=C.c_void_p; q=C.c_uint64
libpath=Path(sys.argv[1]);lib=C.CDLL(str(libpath))
def fn(name,args):
 f=getattr(lib,name);f.argtypes=args;f.restype=C.c_int;return f
def ok(rc):
 assert rc==0,rc
class Options(C.Structure):_fields_=[('version',u),('device',u),('lanes',u),('dependencies',u)]
class Job(C.Structure):_fields_=[('values',p),('records',p),('indices',p),('status',p),('value_count',u),('record_count',u),('index_count',u),('first',u),('count',u),('reserved',u)]
create=fn('stwo_exec_context_create_options',[C.POINTER(Options),C.POINTER(p)])
destroy=fn('stwo_exec_context_destroy',[p]);alloc=fn('stwo_exec_context_alloc_u32',[p,C.c_size_t,C.POINTER(p)])
free=fn('stwo_exec_context_free_u32',[p,p]);upload=fn('stwo_exec_context_memcpy_h2d_async',[p,p,p,C.c_size_t]);download=fn('stwo_exec_context_memcpy_d2h_async',[p,p,p,C.c_size_t]);sync=fn('stwo_exec_context_sync',[p]);counter=fn('stwo_exec_context_h2d_enqueued_bytes',[p,C.POINTER(q)])
lookup=fn('stwo_rv64_graph_cache_lookup_on',[p,u,p,C.POINTER(p)]);begin=fn('stwo_rv64_graph_capture_begin_on',[p,u]);store=fn('stwo_rv64_graph_capture_store_on',[p,u,p,q,C.POINTER(p)]);launch=fn('stwo_rv64_graph_launch_on',[p,u,p]);level=fn('stwo_circuit_assignment_level_on',[p,u,C.POINTER(Job)])
ctx=p();foreign=p();ok(create(C.byref(Options(1,0,2,0)),C.byref(ctx)));ok(create(C.byref(Options(1,0,2,0)),C.byref(foreign)))
leases=[]
def allocate(n):
 out=p();ok(alloc(ctx,n,C.byref(out)));leases.append(out);return out
values=allocate(16);tasks=allocate(8);status=allocate(1)
v=(u*16)(1,0,0,0,2,0,0,0,*([0]*8));t=(u*8)(0,2,0,1,0,0,0,0);s=(u*1)(0)
ok(upload(ctx,values,v,C.sizeof(v)));ok(upload(ctx,tasks,t,C.sizeof(t)));ok(upload(ctx,status,s,4));ok(sync(ctx))
count=q();ok(counter(ctx,C.byref(count)));assert count.value==100,count.value
job=Job(values,tasks,None,status,4,1,0,0,1,0);key=(C.c_uint8*32)(*([0]*32));graph=p()
ok(lookup(ctx,1,key,C.byref(graph)));assert graph.value is None
ok(begin(ctx,1));assert begin(ctx,1)!=0
ok(level(ctx,1,C.byref(job)));ok(store(ctx,1,key,1,C.byref(graph)));assert graph.value
ok(launch(ctx,1,graph));ok(sync(ctx));observed=(u*16)();ok(download(ctx,observed,values,64));ok(sync(ctx));assert observed[8]==3,list(observed)
hit=p();ok(lookup(ctx,1,key,C.byref(hit)));assert hit.value==graph.value
assert launch(foreign,1,graph)!=0;assert launch(ctx,0,graph)!=0
v[0]=8;v[4]=9;ok(upload(ctx,values,v,64));ok(upload(ctx,status,s,4));ok(sync(ctx));ok(launch(ctx,1,hit));ok(sync(ctx));ok(download(ctx,observed,values,64));ok(sync(ctx));assert observed[8]==17,list(observed)
ok(counter(ctx,C.byref(count)));assert count.value==168,count.value
thread_result=[]
thread=threading.Thread(target=lambda:thread_result.append(lookup(ctx,1,key,C.byref(p()))));thread.start();thread.join();assert thread_result[0]!=0
# A wrong node census retires capture and never publishes a cache entry.
bad=(C.c_uint8*32)(*([250]*32));out=p();ok(begin(ctx,1));ok(level(ctx,1,C.byref(job)));assert store(ctx,1,bad,2,C.byref(out))!=0;assert out.value is None
ok(lookup(ctx,1,bad,C.byref(out)));assert out.value is None
# LRU is metadata only; eviction does not require/retain any request lease.
for n in range(1,34):
 k=(C.c_uint8*32)(*([n]*32));out=p();ok(begin(ctx,1));ok(level(ctx,1,C.byref(job)));ok(store(ctx,1,k,1,C.byref(out)));ok(launch(ctx,1,out));ok(sync(ctx))
ok(lookup(ctx,1,key,C.byref(out)));assert out.value is None
for lease in reversed(leases):ok(free(ctx,lease))
ok(destroy(ctx));ok(destroy(foreign))
print(json.dumps(dict(schema='rv64-m7-graph-context-smoke/v1',label='M',library_sha256=hashlib.sha256(libpath.read_bytes()).hexdigest(),gpu=0,dynamic_seed_outputs=[3,17],h2d_enqueued_bytes=168,cases=['cache_miss_hit','nested_capture_rejected','foreign_session_rejected','wrong_lane_rejected','foreign_thread_rejected','kernel_census_mismatch_rejected','lru_eviction','request_leases_release_before_context_destroy'],status='passed')))
