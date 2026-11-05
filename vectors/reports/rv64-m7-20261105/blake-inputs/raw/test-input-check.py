#!/usr/bin/env python3
import ctypes as C, hashlib, json, sys
from pathlib import Path
u=C.c_uint32;p=C.c_void_p
path=Path(sys.argv[1]);lib=C.CDLL(str(path))
def fn(n,args):f=getattr(lib,n);f.argtypes=args;f.restype=C.c_int;return f
def ok(rc):assert rc==0,rc
class Options(C.Structure):_fields_=[('version',u),('device',u),('lanes',u),('dependencies',u)]
create=fn('stwo_exec_context_create_options',[C.POINTER(Options),C.POINTER(p)]);destroy=fn('stwo_exec_context_destroy',[p]);alloc=fn('stwo_exec_context_alloc_u32',[p,C.c_size_t,C.POINTER(p)]);free=fn('stwo_exec_context_free_u32',[p,p]);upload=fn('stwo_exec_context_memcpy_h2d_async',[p,p,p,C.c_size_t]);download=fn('stwo_exec_context_memcpy_d2h_async',[p,p,p,C.c_size_t]);sync=fn('stwo_exec_context_sync',[p]);check=fn('stwo_circuit_blake_sample_inputs_check_on',[p,u,p,u,C.POINTER(p),u,u,p,u,p])
ctx=p();foreign=p();ok(create(C.byref(Options(1,0,2,0)),C.byref(ctx)));ok(create(C.byref(Options(1,0,2,0)),C.byref(foreign)));leases=[]
def allocate(n):o=p();ok(alloc(ctx,n,C.byref(o)));leases.append(o);return o
values=allocate(128);pp=allocate(800);records=allocate(26);status=allocate(1)
iv=[0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19]
h=[0x12345678+i for i in range(8)];m=[0x87654321-i for i in range(16)];words=h+m+iv[:4]+[iv[4]^64,iv[5],iv[6]^0xffffffff,iv[7]]
v=(u*128)(*[c for w in words for c in (w&65535,w>>16,0,0)])
columns=(u*800)()
for j in range(4):columns[j]=j;columns[80+j]=4+j;columns[160+j]=24+j;columns[240+j]=28+j
for j in range(8):columns[320+j]=8+2*j;columns[400+j]=8+2*j+1
ppp=(p*10)(*[pp.value+4*80*j for j in range(10)]);honest=h+m+[64,1]
ok(upload(ctx,values,v,512));ok(upload(ctx,pp,columns,3200));ok(sync(ctx));cases=[]
def run(name,data,expected):
 r=(u*26)(*data);zero=u();flag=u();ok(upload(ctx,records,r,104));ok(upload(ctx,status,C.byref(zero),4));ok(check(ctx,0,values,32,ppp,80,0,records,1,status));ok(download(ctx,C.byref(flag),status,4));ok(sync(ctx));assert flag.value==expected,(name,flag.value);cases.append(name)
run('honest_full_input',honest,0)
for name,index in [('wrong_cv',3),('wrong_message',17),('wrong_counter',24),('wrong_finalization',25)]:
 bad=honest.copy();bad[index]^=1;run(name,bad,1)
bad=honest.copy();bad[25]=2;run('invalid_finalization_flag',bad,1)
v[2]=1;ok(upload(ctx,values,v,512));run('non_u32_assignment_word',honest,1);v[2]=0;ok(upload(ctx,values,v,512));ok(sync(ctx))
assert check(ctx,0,values,32,ppp,80,1,records,1,status)!=0;cases.append('span_out_of_range')
assert check(foreign,0,values,32,ppp,80,0,records,1,status)!=0;cases.append('foreign_context')
for lease in reversed(leases):ok(free(ctx,lease))
ok(destroy(ctx));ok(destroy(foreign))
print(json.dumps(dict(schema='rv64-m7-blake-input-kernel-smoke/v1',label='M',library_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),status='passed',cases=cases)))
