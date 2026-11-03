import ctypes as c,json,sys
class Lease(c.Structure): _fields_=[('token',c.c_uint64),('generation',c.c_uint64),('words',c.POINTER(c.c_uint32)),('count',c.c_uint64),('kind',c.c_uint32),('reserved',c.c_uint32)]
lib=c.CDLL(sys.argv[1]);session=c.c_void_p();lib.stwo_rv64_pcs_native_create.argtypes=[c.c_uint32,c.c_uint64,c.POINTER(c.c_void_p)];assert lib.stwo_rv64_pcs_native_create(0,64<<20,c.byref(session))==0
callback=c.CFUNCTYPE(c.c_int,c.c_void_p,c.c_uint64,c.c_void_p);alloc=lib.stwo_rv64_gpu_lease_allocate;alloc.argtypes=[c.c_void_p,c.c_uint64,c.c_uint32,c.POINTER(c.c_uint32),c.POINTER(Lease)];validate=lib.stwo_rv64_gpu_lease_validate_range;validate.argtypes=[c.c_void_p,c.POINTER(c.c_uint32),c.c_uint64,c.c_uint64,c.c_uint64,c.POINTER(c.c_uint32)];release=lib.stwo_rv64_gpu_lease_release;release.argtypes=[c.c_void_p,c.POINTER(Lease)];submit=lib.stwo_rv64_gpu_session_submit;submit.argtypes=[c.c_void_p,callback,c.c_void_p];destroy=lib.stwo_rv64_pcs_native_destroy;destroy.argtypes=[c.c_void_p]
whole=lib.stwo_rv64_gpu_lease_validate;whole.argtypes=[c.c_void_p,c.POINTER(Lease),c.POINTER(c.c_uint32)]
rebind=lib.stwo_rv64_gpu_lease_rebind;rebind.argtypes=[c.c_void_p,c.POINTER(Lease),c.POINTER(c.c_uint32),c.POINTER(c.c_uint32)]
seal=lib.stwo_rv64_gpu_immutable_seal;seal.argtypes=[c.c_void_p,c.POINTER(Lease),c.POINTER(c.c_uint32)]
immutable=lib.stwo_rv64_gpu_immutable_bind;immutable.argtypes=[c.c_void_p,c.POINTER(Lease),c.POINTER(c.c_uint32),c.POINTER(c.c_uint32)]
unbind=lib.stwo_rv64_gpu_immutable_unbind_scope;unbind.argtypes=[c.c_void_p,c.POINTER(c.c_uint32)]
live=lib.stwo_rv64_gpu_session_live_leases;live.argtypes=[c.c_void_p,c.POINTER(c.c_uint64),c.POINTER(c.c_uint64)]
checks=[]
@callback
def run(ctx,token,user):
 try:
  scope=(c.c_uint32*8)(*range(8));other=(c.c_uint32*8)(*range(1,9));a=Lease();assert alloc(session,1024,2,scope,c.byref(a))==0;old=Lease.from_buffer_copy(a);ptr=c.cast(c.byref(a.words.contents,4*64),c.POINTER(c.c_uint32));assert validate(session,ptr,64,token,a.generation,scope)==0;checks.append('valid_subrange');altered=Lease.from_buffer_copy(a);altered.kind=0;assert whole(session,c.byref(altered),scope)!=0;checks.append('altered_lease_kind');altered=Lease.from_buffer_copy(a);altered.count-=1;assert whole(session,c.byref(altered),scope)!=0;checks.append('altered_whole_lease_count')
  for label,ptr_,n,t,g,s in [('wrong_token',ptr,64,token+1,a.generation,scope),('wrong_generation',ptr,64,token,a.generation+1,scope),('wrong_scope',ptr,64,token,a.generation,other),('overflow_range',ptr,1024,token,a.generation,scope)]:
   assert validate(session,ptr_,n,t,g,s)!=0;checks.append(label)
  assert rebind(session,c.byref(altered),scope,other)!=0;checks.append('altered_rebind_descriptor');assert whole(session,c.byref(a),scope)==0;checks.append('failed_rebind_preserves_scope');assert rebind(session,c.byref(a),other,scope)!=0;checks.append('wrong_rebind_source');assert rebind(session,c.byref(a),scope,(c.c_uint32*8)())!=0;checks.append('empty_rebind_target');assert rebind(session,c.byref(a),scope,other)==0;checks.append('valid_scope_promotion');assert whole(session,c.byref(a),scope)!=0;assert whole(session,c.byref(a),other)==0;checks.append('old_scope_rejected_after_promotion')
  assert release(session,c.byref(a))==0;assert validate(session,old.words,old.count,old.token,old.generation,scope)!=0;checks.append('retired_lease');assert release(session,c.byref(old))!=0;checks.append('double_release')
  fixed=Lease();assert alloc(session,1024,4,scope,c.byref(fixed))==0
  assert validate(session,fixed.words,1024,token,fixed.generation,other)!=0;checks.append('immutable_unbound_scope_rejected')
  assert immutable(session,c.byref(fixed),other,scope)!=0;checks.append('immutable_wrong_setup_rejected')
  bad=Lease.from_buffer_copy(fixed);bad.count-=1;assert immutable(session,c.byref(bad),scope,other)!=0;checks.append('immutable_altered_extent_rejected')
  assert immutable(session,c.byref(fixed),scope,(c.c_uint32*8)())!=0;checks.append('immutable_empty_request_rejected')
  assert immutable(session,c.byref(fixed),scope,other)!=0;checks.append('immutable_unsealed_borrow_rejected')
  assert seal(session,c.byref(fixed),scope)==0;checks.append('immutable_exact_allocation_sealed')
  h2d=lib.stwo_exec_context_memcpy_h2d_async;h2d.argtypes=[c.c_void_p,c.c_void_p,c.c_void_p,c.c_size_t]
  d2d=lib.stwo_exec_context_memcpy_d2d_async;d2d.argtypes=h2d.argtypes
  memset=lib.stwo_exec_context_memset_async;memset.argtypes=[c.c_void_p,c.c_void_p,c.c_int,c.c_size_t]
  fill=lib.stwo_exec_context_fill_u32_async;fill.argtypes=[c.c_void_p,c.c_void_p,c.c_uint32,c.c_size_t]
  host=(c.c_uint32*1)(7)
  assert h2d(ctx,fixed.words,host,4)!=0;checks.append('immutable_h2d_destination_rejected')
  assert d2d(ctx,fixed.words,fixed.words,4)!=0;checks.append('immutable_d2d_destination_rejected')
  assert memset(ctx,fixed.words,0,4)!=0;checks.append('immutable_memset_rejected')
  assert fill(ctx,fixed.words,7,1)!=0;checks.append('immutable_fill_rejected')
  assert immutable(session,c.byref(fixed),scope,other)==0
  assert validate(session,fixed.words,1024,token,fixed.generation,other)==0;checks.append('immutable_bound_scope_admitted')
  assert rebind(session,c.byref(fixed),scope,other)!=0;checks.append('immutable_namespace_promotion_rejected')
  oldfixed=Lease.from_buffer_copy(fixed);assert release(session,c.byref(fixed))!=0;assert whole(session,c.byref(fixed),scope)==0;checks.append('immutable_borrow_prevents_release')
  counts=(c.c_uint64*5)();bytecount=c.c_uint64();assert live(session,counts,c.byref(bytecount))==0;assert counts[4]==1 and bytecount.value==4096;checks.append('immutable_live_bytes_accounted')
  assert unbind(session,other)==0
  assert validate(session,fixed.words,1024,token,fixed.generation,other)!=0;assert whole(session,c.byref(fixed),scope)==0;checks.append('immutable_request_end_revokes_alias_only')
  assert release(session,c.byref(fixed))==0;assert validate(session,oldfixed.words,1024,token,oldfixed.generation,scope)!=0;checks.append('immutable_stale_generation_rejected')
  assert live(session,counts,c.byref(bytecount))==0;assert list(counts)==[0]*5 and bytecount.value==0;checks.append('all_request_and_setup_leases_released')
  return 0
 except BaseException as e:
  print(repr(e),flush=True);return 1
try:
 assert alloc(session,1,0,(c.c_uint32*8)(),c.byref(Lease()))!=0;checks.append('wrong_owner_thread');assert submit(session,run,None)==0;print(json.dumps({'passed':checks}))
finally: assert destroy(session)==0
