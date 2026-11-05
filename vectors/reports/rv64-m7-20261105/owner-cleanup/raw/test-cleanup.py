#!/usr/bin/env python3
from pathlib import Path
import ctypes as C,json,traceback
U=C.c_uint32;Q=C.c_uint64;P=C.POINTER(U);CB=C.CFUNCTYPE(C.c_int,C.c_void_p,Q,C.c_void_p)
class Lease(C.Structure):_fields_=[('token',Q),('generation',Q),('words',P),('count',Q),('kind',U),('reserved',U)]
class Job(C.Structure):_fields_=[('values',P),('records',C.c_void_p),('indices',P),('status',P),('value_count',U),('record_count',U),('index_count',U),('first',U),('count',U),('reserved',U)]
class Step(C.Structure):_fields_=[('first',U),('count',U),('first_level',U),('levels',U),('kind',U)]
class Request(C.Structure):_fields_=[('version',U),('sections',U),('payload',Q*40)]
class Result(C.Structure):_fields_=[('words',P),('count',Q),('ns',Q),('requested',Q),('retained',Q),('owner',C.c_void_p)]
lib=C.CDLL('/workspace/m3/build/m7-owner-cleanup/cleanup-overlay.so',mode=C.RTLD_GLOBAL)
base=C.CDLL('/workspace/m3/build/m7-controller-graphs/cuda/native/libstwo-rv64-native.so',mode=C.RTLD_GLOBAL)
def fn(handle,name,args,rest=C.c_int):
 f=getattr(handle,name);f.argtypes=args;f.restype=rest;return f
create=fn(lib,'stwo_rv64_pcs_native_create',[U,Q,C.POINTER(C.c_void_p)]);destroy=fn(lib,'stwo_rv64_pcs_native_destroy',[C.c_void_p]);submit=fn(lib,'stwo_rv64_gpu_session_submit',[C.c_void_p,CB,C.c_void_p]);controller=fn(lib,'stwo_rv64_gpu_session_controller',[C.c_void_p,CB,C.c_void_p]);cleanup=fn(lib,'stwo_rv64_gpu_session_cleanup',[C.c_void_p,CB,C.c_void_p]);allocate=fn(lib,'stwo_rv64_gpu_lease_allocate',[C.c_void_p,Q,U,P,C.POINTER(Lease)]);release=fn(lib,'stwo_rv64_gpu_lease_release',[C.c_void_p,C.POINTER(Lease)]);live=fn(lib,'stwo_rv64_gpu_session_live_leases',[C.c_void_p,C.POINTER(Q),C.POINTER(Q)]);error=fn(lib,'stwo_rv64_pcs_native_error',[C.c_void_p],C.c_char_p);prove=fn(lib,'stwo_rv64_pcs_native_prove',[C.c_void_p,C.POINTER(Request),C.POINTER(Result)])
trim=fn(lib,'stwo_rv64_gpu_session_trim_unused',[C.c_void_p,C.POINTER(Q)])
gc=fn(base,'stwo_assignment_graph_create_v1',[C.c_void_p,U,C.POINTER(Job),C.POINTER(Step),U,P,U,C.POINTER(C.c_void_p)]);gd=fn(base,'stwo_assignment_graph_destroy_v1',[C.c_void_p,C.c_void_p])
scope=(U*8)();session=C.c_void_p();state={};checks=[];ordinary_called=[0]
def ok(code):
 if code:raise AssertionError(f'status {code}')
def check(name,value):
 if not value:raise AssertionError(name)
 checks.append(name)
def ordinary(raw,token,user):ordinary_called[0]+=1;return 0
ordinary_cb=CB(ordinary)
def poison(raw,token,user):
 try:
  leases=[]
  for words in [12,8,1,1]:
   x=Lease();ok(allocate(session,words,0,scope,C.byref(x)));leases.append(x)
  released=Q(99);ok(trim(session,C.byref(released)));check('unused_trim_preserves_live_leases',released.value==0)
  counts=(Q*5)();size=Q();ok(live(session,counts,C.byref(size)));check('live_lease_count_unchanged_by_trim',sum(counts)==4)
  job=Job(leases[0].words,C.cast(leases[1].words,C.c_void_p),None,leases[2].words,3,1,0,0,1,0);step=Step(0,1,0,1,0);graph=C.c_void_p();ok(gc(raw,1,C.byref(job),C.byref(step),1,leases[3].words,1,C.byref(graph)));check('actual_cuda_graph_created',bool(graph.value));state.update(raw=raw,token=token,graph=graph,leases=leases);return 7
 except BaseException:traceback.print_exc();return 99
poison_cb=CB(poison)
def retire(raw,token,user):
 try:
  check('original_owner_identity',raw==state['raw'] and token==state['token'])
  check('cleanup_reentry_refused',cleanup(session,ordinary_cb,None)!=0)
  check('cleanup_submit_refused',submit(session,ordinary_cb,None)!=0)
  check('cleanup_controller_refused',controller(session,ordinary_cb,None)!=0)
  released=Q(99);check('cleanup_pressure_trim_refused',trim(session,C.byref(released))!=0 and released.value==0)
  forbidden=Lease();check('cleanup_managed_allocation_refused',allocate(session,1,0,scope,C.byref(forbidden))!=0 and not forbidden.words)
  ok(gd(raw,state['graph']));state['graph']=None;check('graph_destroyed_on_poisoned_owner',True)
  for lease in state['leases']:ok(release(session,C.byref(lease)))
  counts=(Q*5)();size=Q();ok(live(session,counts,C.byref(size)));check('all_leases_physically_retired',sum(counts)==0 and size.value==0)
  return 0
 except BaseException:traceback.print_exc();return 1
retire_cb=CB(retire)
try:
 ok(create(0,1<<30,C.byref(session)));released=Q(99);check('nonowner_pressure_trim_refused',trim(session,C.byref(released))!=0 and released.value==0)
 check('null_session_refused',cleanup(None,ordinary_cb,None)!=0)
 check('fatal_callback_refused',submit(session,poison_cb,None)!=0);original=error(session);check('failure_diagnostic_present',b'7' in original)
 check('ordinary_submission_remains_refused',submit(session,ordinary_cb,None)!=0 and ordinary_called[0]==0)
 check('failure_preserved_after_refusal',error(session)==original)
 ok(cleanup(session,retire_cb,None));check('failure_preserved_after_cleanup',error(session)==original)
 request=Request(1,17);result=Result();check('future_prove_refused',prove(session,C.byref(request),C.byref(result))!=0 and not result.owner)
 check('future_controller_refused',controller(session,ordinary_cb,None)!=0 and ordinary_called[0]==0)
 check('terminal_failure_still_original',error(session)==original)
finally:
 if session.value:ok(destroy(session))
receipt={'schema':'rv64-m7-cleanup-custody/v1','label':'M','scope':'Actual owner/graph CUDA metadata destruction after logicalpoison; not numerical or production proof gate','checks':checks,'passed':len(checks)}
Path('/workspace/m3/runs/m7-owner-cleanup/gate.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
