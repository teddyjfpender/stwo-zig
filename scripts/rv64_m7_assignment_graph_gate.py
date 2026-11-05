#!/usr/bin/env python3
"""Actual CUDA assignment graph custody/rebinding gate, not a prover benchmark."""
import argparse,ctypes as C,json,traceback
from pathlib import Path
P=(1<<31)-1
U=C.c_uint32
class Lease(C.Structure):
    _fields_=[('token',C.c_uint64),('generation',C.c_uint64),('words',C.POINTER(U)),('count',C.c_uint64),('kind',U),('reserved',U)]
class Job(C.Structure):
    _fields_=[('values',C.POINTER(U)),('records',C.c_void_p),('indices',C.POINTER(U)),('status',C.POINTER(U)),('value_count',U),('record_count',U),('index_count',U),('first',U),('count',U),('reserved',U)]
class Task(C.Structure):
    _fields_=[('kind',U),('out',U),('args',U*6)]
class Step(C.Structure):
    _fields_=[('first',U),('count',U),('first_level',U),('levels',U),('kind',U)]
CB=C.CFUNCTYPE(C.c_int,C.c_void_p,C.c_uint64,C.c_void_p)
def fn(lib,name,args):
    f=getattr(lib,name);f.argtypes=args;f.restype=C.c_int;return f
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',required=True);ap.add_argument('--graphs',required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    base=C.CDLL(args.library,mode=C.RTLD_GLOBAL);ext=C.CDLL(args.graphs,mode=C.RTLD_GLOBAL)
    create=fn(base,'stwo_rv64_pcs_native_create',[U,C.c_uint64,C.POINTER(C.c_void_p)])
    destroy=fn(base,'stwo_rv64_pcs_native_destroy',[C.c_void_p])
    submit=fn(base,'stwo_rv64_gpu_session_submit',[C.c_void_p,CB,C.c_void_p])
    alloc=fn(base,'stwo_rv64_gpu_lease_allocate',[C.c_void_p,C.c_uint64,U,C.POINTER(U),C.POINTER(Lease)])
    free=fn(base,'stwo_rv64_gpu_lease_release',[C.c_void_p,C.POINTER(Lease)])
    validate=fn(base,'stwo_rv64_gpu_lease_validate',[C.c_void_p,C.POINTER(Lease),C.POINTER(U)])
    seal=fn(base,'stwo_rv64_gpu_immutable_seal',[C.c_void_p,C.POINTER(Lease),C.POINTER(U)])
    bind=fn(base,'stwo_rv64_gpu_immutable_bind',[C.c_void_p,C.POINTER(Lease),C.POINTER(U),C.POINTER(U)])
    unbind=fn(base,'stwo_rv64_gpu_immutable_unbind_scope',[C.c_void_p,C.POINTER(U)])
    upload=fn(base,'stwo_exec_context_memcpy_h2d_async',[C.c_void_p,C.c_void_p,C.c_void_p,C.c_size_t])
    download=fn(base,'stwo_exec_context_memcpy_d2h_async',[C.c_void_p,C.c_void_p,C.c_void_p,C.c_size_t])
    sync=fn(base,'stwo_exec_context_sync',[C.c_void_p])
    seed=fn(base,'stwo_circuit_assignment_seed_on',[C.c_void_p,U,C.POINTER(Job)])
    gc=fn(ext,'stwo_assignment_graph_create_v1',[C.c_void_p,U,C.POINTER(Job),C.POINTER(Step),U,C.POINTER(U),U,C.POINTER(C.c_void_p)])
    gl=fn(ext,'stwo_assignment_graph_launch_v1',[C.c_void_p,U,C.c_void_p,C.POINTER(Job),C.POINTER(U),U])
    gd=fn(ext,'stwo_assignment_graph_destroy_v1',[C.c_void_p,C.c_void_p])
    scope=(U*8)(*([7]*8));sessions=[C.c_void_p(),C.c_void_p()];state={};checks=[];keep=[]
    def ok(rc):
        if rc:raise AssertionError(f'CUDA status {rc}')
    def check(name,value):
        if not value:raise AssertionError(name)
        checks.append(name)
    def new(session,n):
        lease=Lease();ok(alloc(session,n,0,scope,C.byref(lease)));return lease
    def put(raw,lease,host):
        keep.append(host);ok(upload(raw,lease.words,C.cast(host,C.c_void_p),C.sizeof(host)))
    def tasks(subtract):
        out=(Task*4099)()
        out[0]=Task(1 if subtract else 0,2,(U*6)(0,1));out[1]=Task(2,3,(U*6)(2,1))
        for k in range(4096):out[k+2]=Task(0,k+4,(U*6)(3,1))
        out[4098]=Task(0,4100,(U*6)(4099,0));return out
    def setup(raw,session,left,right,subtract=False):
        ls=[new(session,4101*4),new(session,4099*8),new(session,4),new(session,1),new(session,10)]
        put(raw,ls[0],(U*(4101*4))());put(raw,ls[1],tasks(subtract));put(raw,ls[2],(U*4)(1,2,4098,4099));put(raw,ls[3],(U*1)(0));put(raw,ls[4],(U*10)(0,left,0,0,0,1,right,0,0,0));ok(sync(raw))
        sj=Job(ls[0].words,C.cast(ls[4].words,C.c_void_p),None,ls[3].words,4101,2,0,0,2,0);ok(seed(raw,1,C.byref(sj)));ok(sync(raw))
        job=Job(ls[0].words,C.cast(ls[1].words,C.c_void_p),None,ls[3].words,4101,4099,0,0,4099,0)
        return ls,job
    def read(raw,lease):
        host=(U*lease.count)();ok(download(raw,host,lease.words,C.sizeof(host)));ok(sync(raw));return list(host)
    def expected(left,right,subtract=False):
        out=[0]*(4101*4);out[0]=left;out[4]=right;x=(left-right if subtract else left+right)%P;y=x*right%P
        out[8]=x;out[12]=y
        for k in range(4096):out[4*(k+4)]=(y+right)%P
        out[4*4100]=(y+right+left)%P;return out
    def first(raw,token,user):
        try:
            session=sessions[0];a,ja=setup(raw,session,2,3);steps=(Step*3)(Step(0,2,0,2,1),Step(2,4096,2,1,0),Step(4098,1,3,1,1));graph=C.c_void_p()
            ok(gc(raw,1,C.byref(ja),steps,3,a[2].words,4,C.byref(graph)));check('created_nonempty_graph',bool(graph.value));ok(gl(raw,1,graph,C.byref(ja),a[2].words,4));ok(sync(raw))
            check('first_assignment_exact',read(raw,a[0])==expected(2,3));check('first_status_zero',read(raw,a[3])==[0])
            b,jb=setup(raw,session,7,11,True);check('fresh_allocation_addresses',C.cast(a[0].words,C.c_void_p).value!=C.cast(b[0].words,C.c_void_p).value)
            # Poison every old input. A replay that retained any old records or
            # chain-end pointer must now disagree or set the wrong status.
            put(raw,a[1],(U*(4099*8))());put(raw,a[2],(U*4)(100000,100000,100000,100000));put(raw,a[3],(U*1)(1));ok(sync(raw))
            wrong=Job.from_buffer_copy(jb);wrong.value_count-=1
            check('changed_shape_refused',gl(raw,1,graph,C.byref(wrong),b[2].words,4)!=0)
            wrong=Job.from_buffer_copy(jb);wrong.status=b[0].words
            check('overlapping_output_status_refused',gl(raw,1,graph,C.byref(wrong),b[2].words,4)!=0)
            ok(gl(raw,1,graph,C.byref(jb),b[2].words,4));ok(sync(raw))
            check('fresh_pointer_assignment_exact',read(raw,b[0])==expected(7,11,True));check('fresh_status_zero',read(raw,b[3])==[0])
            # Production fold plans use sealed cache schedules with explicit
            # read-only aliases into the proof scope. Full descriptor validation
            # must accept those aliases and reject stale/altered/unbound ones.
            key=(U*8)(*([9]*8));immutable=[]
            for host in (tasks(True),(U*4)(1,2,4098,4099)):
                lease=Lease();ok(alloc(session,C.sizeof(host)//4,4,key,C.byref(lease)));put(raw,lease,host);ok(sync(raw));ok(seal(session,C.byref(lease),key));ok(bind(session,C.byref(lease),key,scope));immutable.append(lease)
            check('immutable_readonly_aliases_validate',all(validate(session,C.byref(lease),scope)==0 for lease in immutable))
            bad=Lease.from_buffer_copy(immutable[0]);bad.generation+=1
            check('immutable_stale_generation_refused',validate(session,C.byref(bad),scope)!=0)
            bad=Lease.from_buffer_copy(immutable[0]);bad.kind=0
            check('immutable_altered_descriptor_refused',validate(session,C.byref(bad),scope)!=0)
            ji=Job.from_buffer_copy(jb);ji.records=C.cast(immutable[0].words,C.c_void_p)
            ok(gl(raw,1,graph,C.byref(ji),immutable[1].words,4));ok(sync(raw))
            check('immutable_schedule_graph_assignment_exact',read(raw,b[0])==expected(7,11,True))
            ok(unbind(session,scope));check('immutable_unbound_scope_refused',all(validate(session,C.byref(lease),scope)!=0 for lease in immutable))
            for lease in immutable:ok(free(session,C.byref(lease)))
            invalid=tasks(True);invalid[0].out=5000;put(raw,b[1],invalid);ok(sync(raw));ok(gl(raw,1,graph,C.byref(jb),b[2].words,4));ok(sync(raw));check('invalid_task_sets_fresh_status',read(raw,b[3])[0]!=0)
            old_ends=C.cast(C.c_void_p(C.cast(a[2].words,C.c_void_p).value),C.POINTER(U))
            for lease in a:ok(free(session,C.byref(lease)))
            check('retired_pointers_refused',gl(raw,1,graph,C.byref(ja),old_ends,4)!=0)
            state.update(graph=graph,leases=b,job=jb)
            return 0
        except BaseException:traceback.print_exc();return 1
    def foreign(raw,token,user):
        try:
            check('foreign_context_refused',gl(raw,1,state['graph'],C.byref(state['job']),state['leases'][2].words,4)!=0);return 0
        except BaseException:traceback.print_exc();return 1
    def cleanup(raw,token,user):
        try:
            ok(gd(raw,state['graph']));state['graph']=None
            for lease in state['leases']:ok(free(sessions[0],C.byref(lease)))
            check('graph_and_leases_destroyed',True);return 0
        except BaseException:traceback.print_exc();return 1
    try:
        for session in sessions:ok(create(0,1<<30,C.byref(session)))
        callbacks=[CB(first),CB(foreign),CB(cleanup)]
        ok(submit(sessions[0],callbacks[0],None));ok(submit(sessions[1],callbacks[1],None));ok(submit(sessions[0],callbacks[2],None))
    finally:
        for session in reversed(sessions):
            if session.value:ok(destroy(session))
    args.output.write_text(json.dumps({'scope':'actual GPU assignment graph generation/custody only; not a proof or performance result','checks':checks,'passed':len(checks),'device':0,'graph_kernel_nodes':3,'tasks':4099},indent=2)+'\n');print(json.dumps({'passed':len(checks),'checks':checks}))
if __name__=='__main__':main()
