#!/usr/bin/env python3
"""Full source-bound Keccak TRUTH0 role parity on actual log18/20 geometry.
All5650 roots,54 signed groups,4 denominator quarters,offset-sensitive input.
Uses existing owner callback/scoped leases; no full proof claim.
"""
import argparse,array,ctypes as C,fcntl,hashlib,json,os,traceback
from pathlib import Path
U=C.c_uint32;Q=C.c_uint64;V=C.c_void_p;CB=C.CFUNCTYPE(C.c_int,V,Q,V)
class Lease(C.Structure):_fields_=[('token',Q),('generation',Q),('words',V),('count',Q),('kind',U),('reserved',U)]
class Role(C.Structure):_fields_=[('role',U),('tl',U),('el',U),('first',U),('rows',U),('reserved',U),('trees',V*3),('tree_words',Q*3),('offsets',V),('mask_count',Q),('params',V),('param_count',Q),('powers',V),('root_count',Q),('denom',V),('output',V)]
def fn(lib,name,args):f=getattr(lib,name);f.argtypes=args;f.restype=C.c_int;return f
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--base',required=True);ap.add_argument('--addon',required=True);ap.add_argument('--fill',required=True);ap.add_argument('--mapping',required=True);ap.add_argument('--out',required=True);ap.add_argument('--observer');a=ap.parse_args()
 os.environ['STWO_RV64_DEVICE_ARENA']='22G';os.environ['STWO_RV64_PCS_IDLE_CACHE_BYTES']='0'
 sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest();m=json.load(open(a.mapping));plan=m['plan'];cache=m['cache'];inputs=m['inputs'];N=1<<20;S=1<<18
 assert len(plan['groups'])==54 and len(inputs)==6733 and cache['slots']==1024
 receipt={'schema':'rv64-rc-sparse-full-role-fixture/v1','scope':'fullactualTRUTH0DAG/syntheticrow-sensitiveevaluations/4quarters;notfullproof','base_sha256':sha(a.base),'addon_sha256':sha(a.addon),'fill_sha256':sha(a.fill),'mapping_sha256':sha(a.mapping),'tests':[]}
 lock=open('/workspace/m3/locks/gpu.lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
 base=C.CDLL(a.base,mode=C.RTLD_GLOBAL);ext=C.CDLL(a.addon);filllib=C.CDLL(a.fill)
 observerlib=C.CDLL(a.observer) if a.observer else None;observe=fn(observerlib,'stwo_rv64_process_memory_snapshot_on',[V,C.c_char_p]) if observerlib else None
 if a.observer:receipt['observer_sha256']=sha(a.observer)
 create=fn(base,'stwo_rv64_pcs_native_create',[U,Q,C.POINTER(V)]);destroy=fn(base,'stwo_rv64_pcs_native_destroy',[V]);submit=fn(base,'stwo_rv64_gpu_session_submit',[V,CB,V]);alloc=fn(base,'stwo_rv64_gpu_lease_allocate',[V,Q,U,C.POINTER(U),C.POINTER(Lease)]);free=fn(base,'stwo_rv64_gpu_lease_release',[V,C.POINTER(Lease)])
 upload=fn(base,'stwo_exec_context_memcpy_h2d_async',[V,V,V,C.c_size_t]);download=fn(base,'stwo_exec_context_memcpy_d2h_async',[V,V,V,C.c_size_t]);sync=fn(base,'stwo_exec_context_sync',[V]);clear=fn(base,'stwo_exec_context_memset_async',[V,V,C.c_int,C.c_size_t]);copy=fn(base,'stwo_exec_context_memcpy_d2d_async',[V,V,V,C.c_size_t])
 old=fn(base,'stwo_rv64_truth_composition_role_on',[V,U,C.POINTER(Role),C.POINTER(U)]);new=fn(ext,'stwo_rv64_rc_sparse_group_on',[V,U,U,C.POINTER(Role),C.POINTER(U)]);fill=fn(filllib,'sparse_fixture_fill',[V,V,Q])
 identity=fn(ext,'stwo_rv64_rc_sparse_identity',[V]);ident=(C.c_ubyte*64)();assert identity(ident)==0;assert bytes(ident)==bytes(plan['source']+plan['identity'])
 def ok(code):assert code==0,code
 def check(name,condition):assert condition,name;receipt['tests'].append(name)
 scope=(U*8)(*range(333,341));selected=[q*S for q in range(4)];count=64
 for device in [0,1]:
  session=V();ok(create(device,20<<30,C.byref(session)));failures=[];owner_raw=[]
  def run(raw,token,user):
   leases=[]
   owner_raw.append(raw)
   try:
    def newlease(n):x=Lease();ok(alloc(session,n,0,scope,C.byref(x)));leases.append(x);return x
    def put(x,values):
     data=(U*len(values))(*values);ok(upload(raw,x.words,C.cast(data,V),len(values)*4))
    def get(address,n):out=(U*n)();ok(download(raw,C.cast(out,V),V(address),n*4));ok(sync(raw));return bytes(out)
    dense=newlease(3516*N);bounded=newlease(1024*N);offsets=newlease(6733*2);params=newlease(31*8);powers=newlease(5650*8);denom=newlease(4);expected=newlease(8*N);actual=newlease(8*N)
    put(params,[(i*7919+91)%2147483647 for i in range(params.count)]);put(powers,[(i*4591+131)%2147483647 for i in range(powers.count)]);put(denom,[7,19,31,47]);ok(fill(raw,dense.words,dense.count));ok(clear(raw,expected.words,0,expected.count*4));ok(clear(raw,actual.words,0,actual.count*4))
    dense_offsets=[x['column']*N for x in inputs];data=(Q*len(dense_offsets))(*dense_offsets);ok(upload(raw,offsets.words,C.cast(data,V),len(data)*8))
    launches=U();role=Role(0,18,20,0,count,0,(V*3)(dense.words,dense.words+32*N*4,dense.words+1955*N*4),(Q*3)(32*N,1923*N,1561*N),offsets.words,6733,params.words,31,powers.words,5650,denom.words,expected.words)
    for first in selected:role.first=first;ok(old(raw,0,C.byref(role),C.byref(launches)))
    ok(sync(raw));check(f'{device}/original5650roots',True)
    role.trees=(V*3)(*([bounded.words]*3));role.tree_words=(Q*3)(*([1024*N]*3));role.output=actual.words
    for index,(group,step) in enumerate(zip(plan['groups'],cache['steps'])):
     for load in step['loads']:
      col=plan['columns'][load['column']];physical=[0,32,1955][col['tree']]+col['column'];ok(copy(raw,bounded.words+load['slot']*N*4,dense.words+physical*N*4,N*4))
     wanted=set(group['columns']);mapping=[step['column_slots'][column]*N if column in wanted else 0 for column in plan['input_columns']];data=(Q*len(mapping))(*mapping);ok(upload(raw,offsets.words,C.cast(data,V),len(data)*8))
     for first in selected:role.first=first;ok(new(raw,0,index,C.byref(role),C.byref(launches)))
    ok(sync(raw))
    for quarter,first in enumerate(selected):
     for coordinate in range(8):check(f'{device}/quarter{quarter}/coordinate{coordinate}',get(expected.words+(coordinate*N+first)*4,count)==get(actual.words+(coordinate*N+first)*4,count))
    if observe:
     check(f'{device}/observer-owner',observe(raw,b'fixture_joined')==0)
     check(f'{device}/observer-null-refused',observe(None,b'null')!=0)
    role.first=0;role.mask_count-=1;launches.value=9;check(f'{device}/wrongmask-refused',new(raw,0,0,C.byref(role),C.byref(launches))!=0 and launches.value==0);role.mask_count+=1
    launches.value=9;check(f'{device}/foreigngroup-refused',new(raw,0,54,C.byref(role),C.byref(launches))!=0 and launches.value==0)
   except BaseException:failures.append(traceback.format_exc())
   finally:
    for x in reversed(leases):
     try:ok(free(session,C.byref(x)))
     except BaseException:failures.append(traceback.format_exc())
   return int(bool(failures))
  callback=CB(run)
  try:
   code=submit(session,callback,None);assert not failures,failures;ok(code)
   if observe:check(f'{device}/observer-nonowner-refused',observe(owner_raw[0],b'nonowner')!=0)
  finally:ok(destroy(session))
 receipt.update(passed=True,checks=len(receipt['tests']),samples_per_device=4*64*8,roots=5650,groups=54);Path(a.out).write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({k:v for k,v in receipt.items() if k!='tests'}),flush=True)
if __name__=='__main__':main()
