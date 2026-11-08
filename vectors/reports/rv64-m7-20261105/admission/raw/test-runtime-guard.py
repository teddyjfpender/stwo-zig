#!/usr/bin/env python3
import ctypes as C,json,sys,hashlib
from pathlib import Path
u=C.c_uint32;q=C.c_uint64;p=C.c_void_p
libpath=Path(sys.argv[1]);lib=C.CDLL(str(libpath))
def fn(name,args):f=getattr(lib,name);f.argtypes=args;f.restype=C.c_int;return f
def ok(rc):assert rc==0,rc
class Options(C.Structure):_fields_=[('version',u),('device',u),('lanes',u),('dependencies',u)]
class Snapshot(C.Structure):_fields_=[('version',u),('device',u)]+[(n,q) for n in ['capacity','chunk','small_slab','live_large','live_small','largest_virtual_free','free_device','total_device']]
assert C.sizeof(Snapshot)==72
create=fn('stwo_exec_context_create_options',[C.POINTER(Options),C.POINTER(p)]);destroy=fn('stwo_exec_context_destroy',[p]);alloc=fn('stwo_exec_context_alloc_u32',[p,C.c_size_t,C.POINTER(p)]);free=fn('stwo_exec_context_free_u32',[p,p]);sync=fn('stwo_exec_context_sync',[p]);snapshot=fn('stwo_exec_context_arena_snapshot_v1',[p,C.POINTER(Snapshot)]);configure=fn('stwo_exec_context_admission_configure_v1',[p,q]);begin=fn('stwo_exec_context_admission_begin_v1',[p,q,q,q,q,q,C.c_char_p]);end=fn('stwo_exec_context_admission_end_v1',[p,q,C.POINTER(Snapshot)])
a=p();b=p();ok(create(C.byref(Options(1,0,2,0)),C.byref(a)));ok(create(C.byref(Options(1,0,2,0)),C.byref(b)));cases=[];s=Snapshot();ok(snapshot(a,C.byref(s)));assert s.capacity==22<<30 and s.chunk==32<<20 and s.small_slab==512<<20 and s.live_large==s.live_small==0
cases.append('physical_snapshot_static_layout')
assert configure(a,20<<30)!=0;cases.append('wrong_static_preset_refused')
ok(configure(a,22<<30));ok(configure(b,22<<30));x=p();assert alloc(a,1,C.byref(x))!=0 and not x.value;cases.append('unreserved_allocation_refused')
ok(begin(a,71,0,0,32<<20,512,b'm7/fixture/guard/r1/o0/t71'));assert begin(b,72,0,0,0,512,b'm7/fixture/foreign')!=0;cases.append('physical_stage_exclusion')
assert alloc(b,1,C.byref(x))!=0 and not x.value;cases.append('foreign_context_cannot_borrow_permit')
ok(alloc(a,1,C.byref(x)));ok(snapshot(b,C.byref(s)));assert s.live_small==512;cases.append('global_retention_visible_from_peer_context')
y=p();assert alloc(a,129,C.byref(y))!=0 and not y.value;cases.append('small_allocation_peak_bound_before_mutation')
ok(sync(a));ok(free(a,x));ok(sync(a));x=p();ok(alloc(a,1<<20,C.byref(x)));ok(snapshot(b,C.byref(s)));assert s.live_large==32<<20;cases.append('large_allocation_rounded_to_physical_chunk')
assert alloc(a,1<<20,C.byref(y))!=0 and not y.value;cases.append('large_peak_bound_before_mutation')
assert end(b,71,C.byref(s))!=0;cases.append('foreign_end_refused')
ok(sync(a));ok(free(a,x));ok(sync(a));ok(end(a,71,C.byref(s)));assert s.live_large==s.live_small==0;cases.append('joined_cleanup_reconciles_zero_retention')
assert end(a,71,C.byref(s))!=0;assert alloc(a,1,C.byref(y))!=0;cases.append('stale_permit_and_post_end_allocation_refused')
# A retained allocation remains visible after its first stage ends, and the
# next stage must include that owner's live bytes in its expected baseline.
ok(begin(a,73,0,0,32<<20,0,b'm7/fixture/retain/r1/o0/t73'));ok(alloc(a,1<<20,C.byref(x)));ok(sync(a));ok(end(a,73,C.byref(s)));assert s.live_large==32<<20
assert begin(b,74,0,0,0,512,b'm7/fixture/stale-baseline')!=0;cases.append('existing_retention_cannot_be_omitted')
ok(begin(b,75,32<<20,0,0,512,b'm7/fixture/consumer/r1/o1/t75'));ok(end(b,75,C.byref(s)));ok(free(a,x));ok(sync(a));ok(snapshot(b,C.byref(s)));assert s.live_large==s.live_small==0;cases.append('retained_owner_retires_only_on_physical_free')
ok(destroy(b));ok(destroy(a))
print(json.dumps({'schema':'rv64-m7-global-admission-gpu-guard/v1','label':'M','status':'passed','library_sha256':hashlib.sha256(libpath.read_bytes()).hexdigest(),'cases':cases,'scope':'Small actual allocations only; no full native/recursion request or GKR promotion qualified'}))
