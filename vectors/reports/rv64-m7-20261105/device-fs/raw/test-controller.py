#!/usr/bin/env python3
import ctypes as C,hashlib,json,sys,threading
from pathlib import Path
p=C.c_void_p;u=C.c_uint32;q=C.c_uint64;i=C.c_int
libpath=Path(sys.argv[1]);lib=C.CDLL(str(libpath))
CB=C.CFUNCTYPE(i,p,q,p)
def fn(name,args):f=getattr(lib,name);f.argtypes=args;f.restype=i;return f
create=fn('stwo_rv64_pcs_native_create',[u,q,C.POINTER(p)]);destroy=fn('stwo_rv64_pcs_native_destroy',[p]);submit=fn('stwo_rv64_gpu_session_submit',[p,CB,p]);controller=fn('stwo_rv64_gpu_session_controller',[p,CB,p]);upload=fn('stwo_exec_context_memcpy_h2d_async',[p,p,p,C.c_size_t]);download=fn('stwo_exec_context_memcpy_d2h_async',[p,p,p,C.c_size_t])
class Lease(C.Structure):_fields_=[('token',q),('generation',q),('words',p),('count',q),('kind',u),('reserved',u)]
class Result(C.Structure):_fields_=[('words',p),('count',q),('device_ns',q),('requested_bytes',q),('retained_bytes',q),('owner',p)]
class Request(C.Structure):_fields_=[('version',u),('sections',u)]
alloc=fn('stwo_rv64_gpu_lease_allocate',[p,q,u,C.POINTER(u),C.POINTER(Lease)]);release=fn('stwo_rv64_gpu_lease_release',[p,C.POINTER(Lease)]);validate=fn('stwo_rv64_gpu_lease_validate',[p,C.POINTER(Lease),C.POINTER(u)]);live=fn('stwo_rv64_gpu_session_live_leases',[p,C.POINTER(q),C.POINTER(q)]);prove=fn('stwo_rv64_pcs_native_prove',[p,C.POINTER(Request),C.POINTER(Result)])
def ok(rc):assert rc==0,rc
cases=[];errors=[];callbacks=[]
def cb(f):
 def wrapped(*args):
  try:return f(*args)
  except BaseException as e:errors.append(repr(e));return 99
 c=CB(wrapped);callbacks.append(c);return c
session=p();ok(create(0,2<<30,C.byref(session)));lease=Lease();scope=(u*8)(*range(1,9));expected=(u*4)(11,22,33,44);caller=threading.get_native_id();owner_id=[]
@cb
def nop(raw,token,user):return 0
@cb
def reject_reentry(raw,token,user):
 assert submit(session,nop,None)!=0
 assert controller(session,nop,None)!=0
 return 0
ok(submit(session,reject_reentry,None));cases.append('ordinary_callback_still_rejects_owner_reentry')
@cb
def allocate(raw,token,user):
 ok(alloc(session,4,0,scope,C.byref(lease)));assert lease.token==token
 ok(upload(raw,lease.words,C.cast(expected,p),16));return 0
@cb
def read_and_release(raw,token,user):
 ok(validate(session,C.byref(lease),scope));observed=(u*4)();ok(download(raw,C.cast(observed,p),lease.words,16));assert list(observed)==list(expected)
 stale=Lease.from_buffer_copy(lease);ok(release(session,C.byref(lease)));assert not lease.words
 assert validate(session,C.byref(stale),scope)!=0;return 0
@cb
def whole(raw,token,user):
 owner_id.append(threading.get_native_id());assert owner_id[-1]!=caller
 assert controller(session,nop,None)!=0
 ok(submit(session,allocate,None));assert lease.words
 ok(submit(session,read_and_release,None));return 0
ok(controller(session,whole,None));assert not errors,errors
cases+=['controller_runs_on_native_owner','nested_controller_refused_without_deadlock','same_owner_inline_allocation_upload','later_inline_callback_reads_fresh_device_words','joined_terminal_return_after_scoped_release','stale_lease_refused']
@cb
def audit(raw,token,user):
 counts=(q*5)();n=q();ok(live(session,counts,C.byref(n)));assert not any(counts) and n.value==0;return 0
ok(submit(session,audit,None));cases.append('ordinary_submit_works_after_controller');ok(destroy(session))
# A failed nested job poisons its session; its still-owned device allocation
# stays with the native owner until successful terminal context destruction.
failed=p();ok(create(0,2<<30,C.byref(failed)));pending=Lease()
@cb
def allocate_then_fail(raw,token,user):ok(alloc(failed,4,0,scope,C.byref(pending)));return 7
@cb
def failing_controller(raw,token,user):assert submit(failed,allocate_then_fail,None)==7;assert submit(failed,nop,None)!=0;return 7
assert controller(failed,failing_controller,None)!=0;cases.append('nested_failure_propagates_and_refuses_later_inline_work')
assert submit(failed,nop,None)!=0;cases.append('poisoned_session_refuses_following_jobs');ok(destroy(failed));cases.append('failed_controller_allocations_remain_owned_until_context_destroy')
invalid=p();ok(create(0,2<<30,C.byref(invalid)))
@cb
def invalid_prove(raw,token,user):
 result=Result();request=Request(0,0);assert prove(invalid,C.byref(request),C.byref(result))!=0;assert not result.owner;return 9
assert controller(invalid,invalid_prove,None)!=0;ok(destroy(invalid));cases.append('inline_native_prove_validates_abi_and_propagates_failure')
assert not errors,errors
print(json.dumps({'schema':'rv64-m7-owner-controller-fixture/v1','label':'M','status':'passed','library_sha256':hashlib.sha256(libpath.read_bytes()).hexdigest(),'cases':cases,'scope':'Small actual GPU custody/control fixture. Full proof bytes, TLS transfer and production correctness remain separate gates.'}))
