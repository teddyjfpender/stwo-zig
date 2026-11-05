#!/usr/bin/env python3
"""Actual18->20 scoped indexed/contiguousN2B parity; not a proof benchmark."""
import argparse,array,ctypes as C,fcntl,hashlib,json,os,traceback
from pathlib import Path
U=C.c_uint32;Q=C.c_uint64;V=C.c_void_p;CB=C.CFUNCTYPE(C.c_int,V,Q,V)
class Lease(C.Structure):_fields_=[('token',Q),('generation',Q),('words',V),('count',Q),('kind',U),('reserved',U)]
class Column(C.Structure):_fields_=[('words',V),('count',Q),('token',Q),('generation',Q)]
class Job(C.Structure):_fields_=[('version',U),('source_log',U),('eval_log',U),('count',U),('cache_slots',U),('reserved',U),('session',V),('scope',U*8),('sources',C.POINTER(Column)),('slots',C.POINTER(U)),('cache',Lease),('tables',Lease),('twiddles',Lease)]
def fn(lib,name,args):f=getattr(lib,name);f.argtypes=args;f.restype=C.c_int;return f
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--base',required=True);ap.add_argument('--addon',required=True);ap.add_argument('--twiddles',required=True);ap.add_argument('--out',required=True);ap.add_argument('--gpu-lock',default='/workspace/m3/locks/gpu.lock');a=ap.parse_args()
 os.environ['STWO_RV64_DEVICE_ARENA']='22G';os.environ['STWO_RV64_PCS_IDLE_CACHE_BYTES']='0'
 sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();receipt={'schema':'rv64-rc-sparse-indexed-lde-fixture/v1','scope':'N2Baddressadapteronly;actualdegree18/eval20;notproductionSparseRC','base_sha256':sha(a.base),'addon_sha256':sha(a.addon),'twiddles_sha256':sha(a.twiddles),'tests':[]}
 lock=open(a.gpu_lock,'a');fcntl.flock(lock,fcntl.LOCK_EX)
 base=C.CDLL(a.base,mode=C.RTLD_GLOBAL);ext=C.CDLL(a.addon)
 create=fn(base,'stwo_rv64_pcs_native_create',[U,Q,C.POINTER(V)]);destroy=fn(base,'stwo_rv64_pcs_native_destroy',[V]);submit=fn(base,'stwo_rv64_gpu_session_submit',[V,CB,V]);alloc=fn(base,'stwo_rv64_gpu_lease_allocate',[V,Q,U,C.POINTER(U),C.POINTER(Lease)]);free=fn(base,'stwo_rv64_gpu_lease_release',[V,C.POINTER(Lease)])
 upload=fn(base,'stwo_exec_context_memcpy_h2d_async',[V,V,V,C.c_size_t]);download=fn(base,'stwo_exec_context_memcpy_d2h_async',[V,V,V,C.c_size_t]);sync=fn(base,'stwo_exec_context_sync',[V]);lane=fn(base,'stwo_exec_context_lane_stream',[V,U,C.POINTER(V)]);clear=fn(base,'stwo_exec_context_memset_async',[V,V,C.c_int,C.c_size_t])
 old=fn(base,'stwo_lde_n2b_columns_compact_on',[V,C.c_size_t,V,V,C.c_size_t,U,U,V,U,U,C.c_size_t,V,C.POINTER(U)]);op=fn(ext,'stwo_rv64_rc_sparse_lde_on',[V,U,C.POINTER(Job),C.POINTER(U)])
 def ok(code):assert code==0,code
 def check(name,condition):assert condition,name;receipt['tests'].append(name)
 N=1<<20;S=1<<18;count=4;scope=(U*8)(*range(201,209));tw=array.array('I');tw.frombytes(Path(a.twiddles).read_bytes());assert len(tw)==N//2
 data=array.array('I',((i*1789+731)%2147483647 for i in range(count*S)));assert C.sizeof(Job)==200
 for device in [0,1]:
  session=V();ok(create(device,8<<30,C.byref(session)));failures=[]
  def run(raw,token,user):
   leases=[]
   try:
    def new(n):x=Lease();ok(alloc(session,n,0,scope,C.byref(x)));leases.append(x);return x
    def put(x,host,n=None):
     if isinstance(host,array.array):address,size=host.buffer_info();ok(upload(raw,x.words,V(address),(size if n is None else n)*4))
     else:ok(upload(raw,x.words,C.cast(host,V),C.sizeof(host)))
    def get(address,n):out=(U*n)();ok(download(raw,C.cast(out,V),V(address),n*4));ok(sync(raw));return bytes(out)
    source=new(count*S);dense=new(count*N);cache=new(1024*N);tables=new(4*count);logs=new(count);twiddle=new(N//2)
    put(source,data);put(twiddle,tw);put(logs,(U*count)(*([18]*count)));ok(clear(raw,cache.words,0x5a,cache.count*4));ok(sync(raw))
    stream=V();ok(lane(raw,0,C.byref(stream)));launches=U();ok(old(source.words,S,logs.words,dense.words,N,20,count,twiddle.words,N//2,N//2,S,stream,C.byref(launches)));ok(sync(raw));check(f'{device}/baseline-three-pass',launches.value==3)
    permutation=[2,0,3,1];slots=(U*count)(1023,1,512,7);columns=(Column*count)(*(Column(source.words+k*S*4,S,source.token,source.generation) for k in permutation))
    job=Job(1,18,20,count,1024,0,session,scope,columns,slots,cache,tables,twiddle)
    ok(op(raw,0,C.byref(job),C.byref(launches)));ok(sync(raw));check(f'{device}/indexed-three-pass',launches.value==3)
    for i,k in enumerate(permutation):check(f'{device}/column-{i}-exact',get(cache.words+slots[i]*N*4,N)==get(dense.words+k*N*4,N))
    check(f'{device}/untouched-cache-slot',get(cache.words,1024)==bytes([0x5a])*(1024*4))
    def reject(name,changed,which_lane=0):
     launches.value=99;check(f'{device}/{name}',op(raw,which_lane,C.byref(changed),C.byref(launches))!=0 and launches.value==0)
    for field,value in [('version',0),('source_log',17),('eval_log',19),('count',0),('count',513),('cache_slots',1023),('reserved',1)]:
     bad=Job.from_buffer_copy(job);setattr(bad,field,value);reject(f'bad-{field}-{value}',bad)
    reject('lane1-refused',job,1)
    for field in ['cache','tables','twiddles']:
     bad=Job.from_buffer_copy(job);lease=Lease.from_buffer_copy(getattr(bad,field));lease.generation+=1;setattr(bad,field,lease);reject(f'stale-{field}',bad)
    bad=Job.from_buffer_copy(job);bad.scope=(U*8)(*([99]*8));reject('wrong-scope',bad)
    for name,change in [('stale-source',lambda c:setattr(c,'generation',c.generation+1)),('wrong-token-source',lambda c:setattr(c,'token',c.token+1)),('short-source',lambda c:setattr(c,'count',S-1)),('output-source-alias',lambda c:(setattr(c,'words',cache.words),setattr(c,'generation',cache.generation)))]:
     changed=(Column*count).from_buffer_copy(columns);change(changed[0]);bad=Job.from_buffer_copy(job);bad.sources=changed;reject(name,bad)
    for field in ['tables','twiddles']:
     bad=Job.from_buffer_copy(job);setattr(bad,field,Lease.from_buffer_copy(cache));reject(f'cache-{field}-alias',bad)
    retired=new(S);stale=Lease.from_buffer_copy(retired);ok(free(session,C.byref(retired)));leases.pop();changed=(Column*count).from_buffer_copy(columns);changed[0]=Column(stale.words,S,stale.token,stale.generation);bad=Job.from_buffer_copy(job);bad.sources=changed;reject('retired-source',bad)
    changed=(U*count)(0,0,512,7);bad=Job.from_buffer_copy(job);bad.slots=changed;reject('duplicate-slots',bad)
    changed=(U*count)(1024,1,512,7);bad=Job.from_buffer_copy(job);bad.slots=changed;reject('out-of-range-slot',bad)
    ok(sync(raw))
   except BaseException:failures.append(traceback.format_exc())
   finally:
    for x in reversed(leases):
     try:ok(free(session,C.byref(x)))
     except BaseException:failures.append(traceback.format_exc())
   return 1 if failures else 0
  callback=CB(run)
  try:rc=submit(session,callback,None);assert not failures,failures;ok(rc)
  finally:ok(destroy(session))
 receipt.update(passed=True,checks=len(receipt['tests']));Path(a.out).write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({k:v for k,v in receipt.items() if k!='tests'}),flush=True)
if __name__=='__main__':main()
