#!/usr/bin/env python3
import ctypes as C, hashlib, json, sys
from pathlib import Path
u=C.c_uint32;p=C.c_void_p
path=Path(sys.argv[1]);lib=C.CDLL(str(path))
def fn(n,args):f=getattr(lib,n);f.argtypes=args;f.restype=C.c_int;return f
def ok(rc):assert rc==0,rc
class Options(C.Structure):_fields_=[('version',u),('device',u),('lanes',u),('dependencies',u)]
create=fn('stwo_exec_context_create_options',[C.POINTER(Options),C.POINTER(p)]);destroy=fn('stwo_exec_context_destroy',[p]);alloc=fn('stwo_exec_context_alloc_u32',[p,C.c_size_t,C.POINTER(p)]);free=fn('stwo_exec_context_free_u32',[p,p]);upload=fn('stwo_exec_context_memcpy_h2d_async',[p,p,p,C.c_size_t]);download=fn('stwo_exec_context_memcpy_d2h_async',[p,p,p,C.c_size_t]);sync=fn('stwo_exec_context_sync',[p]);check=fn('stwo_circuit_blake_sample_inputs_check_on',[p,u,p,u,C.POINTER(p),u,u,p,u,p])
prefill=fn('stwo_circuit_blake_sample_prefill_on',[p,u,p,u,p,p,u,p])
ctx=p();foreign=p();ok(create(C.byref(Options(1,0,2,0)),C.byref(ctx)));ok(create(C.byref(Options(1,0,2,0)),C.byref(foreign)));leases=[]
def allocate(n):
 o=p();ok(alloc(ctx,n,C.byref(o)));leases.append(o);return o
values=allocate(1100*4);records=allocate(3*26);output_map=allocate(3);status=allocate(1)
iv=[0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19]
sigma=[[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],[11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],[9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],[12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],[6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]]
groups=[[0,4,8,12],[1,5,9,13],[2,6,10,14],[3,7,11,15],[0,5,10,15],[1,6,11,12],[2,7,8,13],[3,4,9,14]]
def reference(w):
 v=w[:8]+iv.copy();m=w[8:24];v[12]^=w[24];v[14]^=0xffffffff if w[25] else 0;out=[]
 def r(x,n):return ((x>>n)|(x<<(32-n)))&0xffffffff
 for order in sigma:
  for gi,(ai,bi,ci,di) in enumerate(groups):
   a,b,c,d=[v[x] for x in [ai,bi,ci,di]]
   a=(a+b+m[order[2*gi]])&0xffffffff;d=r(d^a,16);c=(c+d)&0xffffffff;b=r(b^c,12)
   a=(a+b+m[order[2*gi+1]])&0xffffffff;d=r(d^a,8);c=(c+d)&0xffffffff;b=r(b^c,7)
   for index,z in zip([ai,bi,ci,di],[a,b,c,d]):v[index]=z;out.extend([z&65535,z>>16,0,0])
 return out
w=[]
for seed in [1,17,93]:w.append([((seed*0x12345678+j*0xabcdef)^j)&0xffffffff for j in range(24)]+[64*seed,seed&1])
base=[16,352,700];original=[0xa5a5a5a5]*(1100*4);host=(u*(1100*4))(*original);packed=(u*78)(*[z for x in w for z in x]);mp=(u*3)(*base);zero=u();flag=u()
ok(upload(ctx,values,host,C.sizeof(host)));ok(upload(ctx,records,packed,C.sizeof(packed)));ok(upload(ctx,output_map,mp,C.sizeof(mp)));ok(upload(ctx,status,C.byref(zero),4));ok(sync(ctx))
ok(prefill(ctx,0,values,1100,records,output_map,3,status));ok(download(ctx,host,values,C.sizeof(host)));ok(download(ctx,C.byref(flag),status,4));ok(sync(ctx));assert flag.value==0
expected=original.copy()
for b,x in zip(base,w):expected[b*4:(b+320)*4]=reference(x)
assert list(host)==expected,'full output or untouched-region mismatch'
cases=['three_independent_compressions_all_960_words_equal_cpu','untouched_values_preserved']
assert prefill(foreign,0,values,1100,records,output_map,3,status)!=0;cases.append('foreign_context_refused')
assert prefill(ctx,0,values,1100,records,values,3,status)!=0;cases.append('read_write_alias_refused')
mp[2]=1000;ok(upload(ctx,output_map,mp,C.sizeof(mp)));ok(upload(ctx,status,C.byref(zero),4));ok(sync(ctx));ok(prefill(ctx,0,values,1100,records,output_map,3,status));ok(download(ctx,C.byref(flag),status,4));ok(sync(ctx));assert flag.value==1;cases.append('output_range_bad_flagged')
mp[2]=700;packed[25]=2;ok(upload(ctx,records,packed,C.sizeof(packed)));ok(upload(ctx,output_map,mp,C.sizeof(mp)));ok(upload(ctx,status,C.byref(zero),4));ok(sync(ctx));ok(prefill(ctx,0,values,1100,records,output_map,3,status));ok(download(ctx,C.byref(flag),status,4));ok(sync(ctx));assert flag.value==1;cases.append('invalid_finalization_flagged')
for lease in reversed(leases):ok(free(ctx,lease))
ok(destroy(ctx));ok(destroy(foreign))
print(json.dumps(dict(schema='rv64-m7-blake-prefill-smoke/v1',label='M',library_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),status='passed',cases=cases)))
