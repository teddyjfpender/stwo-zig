import ctypes as c,json,sys
class Lease(c.Structure): _fields_=[('token',c.c_uint64),('generation',c.c_uint64),('words',c.POINTER(c.c_uint32)),('count',c.c_uint64),('kind',c.c_uint32),('reserved',c.c_uint32)]
lib=c.CDLL(sys.argv[1]);session=c.c_void_p();lib.stwo_rv64_pcs_native_create.argtypes=[c.c_uint32,c.c_uint64,c.POINTER(c.c_void_p)];assert lib.stwo_rv64_pcs_native_create(0,64<<20,c.byref(session))==0
callback=c.CFUNCTYPE(c.c_int,c.c_void_p,c.c_uint64,c.c_void_p);alloc=lib.stwo_rv64_gpu_lease_allocate;alloc.argtypes=[c.c_void_p,c.c_uint64,c.c_uint32,c.POINTER(c.c_uint32),c.POINTER(Lease)];validate=lib.stwo_rv64_gpu_lease_validate_range;validate.argtypes=[c.c_void_p,c.POINTER(c.c_uint32),c.c_uint64,c.c_uint64,c.c_uint64,c.POINTER(c.c_uint32)];release=lib.stwo_rv64_gpu_lease_release;release.argtypes=[c.c_void_p,c.POINTER(Lease)];submit=lib.stwo_rv64_gpu_session_submit;submit.argtypes=[c.c_void_p,callback,c.c_void_p];destroy=lib.stwo_rv64_pcs_native_destroy;destroy.argtypes=[c.c_void_p]
whole=lib.stwo_rv64_gpu_lease_validate;whole.argtypes=[c.c_void_p,c.POINTER(Lease),c.POINTER(c.c_uint32)]
rebind=lib.stwo_rv64_gpu_lease_rebind;rebind.argtypes=[c.c_void_p,c.POINTER(Lease),c.POINTER(c.c_uint32),c.POINTER(c.c_uint32)]
checks=[]
@callback
def run(ctx,token,user):
 try:
  scope=(c.c_uint32*8)(*range(8));other=(c.c_uint32*8)(*range(1,9));a=Lease();assert alloc(session,1024,2,scope,c.byref(a))==0;old=Lease.from_buffer_copy(a);ptr=c.cast(c.byref(a.words.contents,4*64),c.POINTER(c.c_uint32));assert validate(session,ptr,64,token,a.generation,scope)==0;checks.append('valid_subrange');altered=Lease.from_buffer_copy(a);altered.kind=0;assert whole(session,c.byref(altered),scope)!=0;checks.append('altered_lease_kind');altered=Lease.from_buffer_copy(a);altered.count-=1;assert whole(session,c.byref(altered),scope)!=0;checks.append('altered_whole_lease_count')
  for label,ptr_,n,t,g,s in [('wrong_token',ptr,64,token+1,a.generation,scope),('wrong_generation',ptr,64,token,a.generation+1,scope),('wrong_scope',ptr,64,token,a.generation,other),('overflow_range',ptr,1024,token,a.generation,scope)]:
   assert validate(session,ptr_,n,t,g,s)!=0;checks.append(label)
  assert rebind(session,c.byref(altered),scope,other)!=0;checks.append('altered_rebind_descriptor');assert whole(session,c.byref(a),scope)==0;checks.append('failed_rebind_preserves_scope');assert rebind(session,c.byref(a),other,scope)!=0;checks.append('wrong_rebind_source');assert rebind(session,c.byref(a),scope,(c.c_uint32*8)())!=0;checks.append('empty_rebind_target');assert rebind(session,c.byref(a),scope,other)==0;checks.append('valid_scope_promotion');assert whole(session,c.byref(a),scope)!=0;assert whole(session,c.byref(a),other)==0;checks.append('old_scope_rejected_after_promotion')
  assert release(session,c.byref(a))==0;assert validate(session,old.words,old.count,old.token,old.generation,scope)!=0;checks.append('retired_lease');assert release(session,c.byref(old))!=0;checks.append('double_release');return 0
 except BaseException as e:
  print(repr(e),flush=True);return 1
try:
 assert alloc(session,1,0,(c.c_uint32*8)(),c.byref(Lease()))!=0;checks.append('wrong_owner_thread');assert submit(session,run,None)==0;print(json.dumps({'passed':checks}))
finally: assert destroy(session)==0
