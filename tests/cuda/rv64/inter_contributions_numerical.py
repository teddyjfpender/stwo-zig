"""Scoped GPU numerical parity for direct circuit contributions; no speed claim."""
from pathlib import Path
import argparse, ctypes as C, fcntl, hashlib, json, os, random
U,Q,V=C.c_uint32,C.c_uint64,C.c_void_p
class Options(C.Structure):
    _fields_=[('version',U),('device',U),('lanes',U),('staging',U)]
class Fractions(C.Structure):
    _fields_=[('fixed',V),('main',V),('parameters',V),('numerators',V),('denominators',V),('status',V),('fixed_words',Q),('main_words',Q),('numerator_words',Q),('denominator_words',Q),('component',U),('row_log',U),('reserved',U*2)]
class Contributions(C.Structure):
    _fields_=[('fixed',V),('main',V),('parameters',V),('output',V),('status',V),('fixed_words',Q),('main_words',Q),('output_words',Q),('component',U),('row_log',U),('reserved',U*2)]
class Global(C.Structure):
    _fields_=[('output',V),('contributions',V),('scratch',V),('claim',V),('status',V),('stride',Q),('scan_words',Q),('row_log',U),('pairs',U),('reserved',U*2)]
class Cumulative(C.Structure):
    _fields_=[('output',V),('contributions',V),('claim',V),('stride',Q),('row_log',U),('pairs',U)]
def fn(lib,name,args):
    f=getattr(lib,name);f.argtypes=args;f.restype=C.c_int;return f
def clone(x):return type(x).from_buffer_copy(bytes(x))
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    lock=open('/workspace/m3/locks/gpu.lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
    os.environ['STWO_RV64_DEVICE_ARENA']='0'
    lib=C.CDLL(a.library)
    create=fn(lib,'stwo_exec_context_create_options',[C.POINTER(Options),C.POINTER(V)])
    destroy=fn(lib,'stwo_exec_context_destroy',[V]);allocate=fn(lib,'stwo_exec_context_alloc_u32',[V,Q,C.POINTER(V)])
    free=fn(lib,'stwo_exec_context_free_u32',[V,V]);sync=fn(lib,'stwo_exec_context_sync',[V])
    upload=fn(lib,'stwo_exec_context_memcpy_h2d_async',[V,V,V,Q]);download=fn(lib,'stwo_exec_context_memcpy_d2h_async',[V,V,V,Q])
    fractions=fn(lib,'stwo_circuit_om31_fractions_on',[V,U,C.POINTER(Fractions)])
    generate=fn(lib,'stwo_circuit_om31_contributions_v1_on',[V,U,C.POINTER(Contributions)])
    oldscan=fn(lib,'stwo_rv64_global_pairs_on',[V,U,C.POINTER(Global)])
    scan=fn(lib,'stwo_rv64_global_contributions_scan_v1_on',[V,U,C.POINTER(Global)])
    oldcum=fn(lib,'stwo_circuit_om31_cumulative_on',[V,U,C.POINTER(Cumulative)])
    cumulative=fn(lib,'stwo_circuit_om31_cumulative_inplace_v1_on',[V,U,C.POINTER(Cumulative)])
    assert [C.sizeof(t) for t in [Fractions,Contributions,Global,Cumulative]]==[96,80,72,40]
    pp=[2,8,5,3,11,3,0,3,3,3,1];base=[4,12,20,4,52,2,16,1,1,1,1];pairs=[1,2,6,3,13,1,8,1,1,1,1]
    def ok(code):assert code==0,code
    result={'schema':'rv64-inter-contributions-numerical/v1','library_sha256':hashlib.sha256(Path(a.library).read_bytes()).hexdigest(),'fixture_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope':'New fused numerical ABI versus complete legacy N/D+inverse+scan+cumulative pipeline in the same source image. Whole-proof frozen parity remains required.','cases':[],'invalid_calls_rejected':0}
    for device in [0,1]:
        context,other=V(),V();ok(create(C.byref(Options(1,device,2,32)),C.byref(context)));ok(create(C.byref(Options(1,device,2,32)),C.byref(other)))
        foreign=V();ok(allocate(other,52*256,C.byref(foreign)))
        try:
            for log in [4,5,8]:
                rows=1<<log
                for component in range(11):
                    for zero in [False,True]:
                        allocations=[];hosts=[]
                        def alloc(words):
                            p=V();ok(allocate(context,max(words,1),C.byref(p)));allocations.append(p);return p
                        def put(pointer,words):
                            h=(U*len(words))(*words);hosts.append(h);ok(upload(context,pointer,C.cast(h,V),len(words)*4))
                        def get(pointer,words):
                            h=(U*words)();ok(download(context,C.cast(h,V),pointer,words*4));ok(sync(context));return bytes(h)
                        def rejected(function,job):
                            code=function(context,0,C.byref(job));assert code!=0,'invalid descriptor accepted';result['invalid_calls_rejected']+=1
                        try:
                            n=pairs[component];words=8*n*rows;total=8*(n+1)*rows
                            need=0;count=rows
                            while count>1:count=(count+127)//128;need+=count*8
                            fixed,main,parameters=alloc(pp[component]*rows),alloc(base[component]*rows),alloc(56)
                            numerator,oldout,newout=alloc(words),alloc(total),alloc(total)
                            oldscratch,newscratch,oldclaim,newclaim,oldstatus,newstatus=alloc(need),alloc(need),alloc(8),alloc(8),alloc(1),alloc(1)
                            rng=random.Random(0x1A73+component*131+log*17+device)
                            put(fixed,[rng.randrange(4) for _ in range(max(pp[component]*rows,1))]);put(main,[rng.randrange(4) for _ in range(base[component]*rows)])
                            put(parameters,[0]*56 if zero else [rng.randrange(1,2147483647) for _ in range(56)])
                            put(oldstatus,[0]);put(newstatus,[0]);ok(sync(context))
                            old=Fractions(fixed,main,parameters,numerator,oldout,oldstatus,pp[component]*rows,base[component]*rows,words,words,component,log,(U*2)(0,0))
                            new=Contributions(fixed,main,parameters,newout,newstatus,pp[component]*rows,base[component]*rows,words,component,log,(U*2)(0,0))
                            oldglobal=Global(oldout,numerator,oldscratch,oldclaim,oldstatus,rows,need,log,n,(U*2)(0,0))
                            newglobal=Global(newout,newout,newscratch,newclaim,newstatus,rows,need,log,n,(U*2)(0,0))
                            ok(fractions(context,0,C.byref(old)));ok(oldscan(context,0,C.byref(oldglobal)))
                            ok(generate(context,0,C.byref(new)));ok(sync(context))
                            assert get(numerator,words)==get(newout,words),'fused contributions differ'
                            ok(scan(context,0,C.byref(newglobal)));ok(sync(context))
                            assert get(V(oldout.value+words*4),8*rows)==get(V(newout.value+words*4),8*rows),'prefix differs'
                            assert get(oldclaim,8)==get(newclaim,8),'claim differs'
                            c0=Cumulative(oldout,numerator,oldclaim,rows,log,n);c1=Cumulative(newout,newout,newclaim,rows,log,n)
                            ok(oldcum(context,0,C.byref(c0)));ok(cumulative(context,0,C.byref(c1)));ok(sync(context))
                            final=get(newout,total);assert final==get(oldout,total),'cumulative output differs'
                            status=get(newstatus,1);assert status==get(oldstatus,1)
                            verdict=int.from_bytes(status,'little');assert (verdict&4)!=0 if zero else verdict==0
                            for field,value in [('main_words',new.main_words-1),('output_words',words-1),('component',11),('row_log',3),('status',newout.value),('output',parameters.value),('main',foreign.value)]:
                                bad=clone(new);setattr(bad,field,value);rejected(generate,bad)
                            bad=clone(new);bad.reserved[0]=1;rejected(generate,bad)
                            for field,value in [('contributions',newout.value+4),('scan_words',need-1),('claim',newout.value),('scratch',newout.value)]:
                                bad=clone(newglobal);setattr(bad,field,value);rejected(scan,bad)
                            for field,value in [('contributions',newout.value+4),('claim',newout.value),('stride',rows-1)]:
                                bad=clone(c1);setattr(bad,field,value);rejected(cumulative,bad)
                            rejected(oldcum,c1) # the legacy overlap contract remains strict
                            ok(sync(context))
                            result['cases'].append({'device':device,'component':component,'row_log':log,'pairs':n,'zero_denominator':zero,'status':verdict,'final_sha256':hashlib.sha256(final+get(newclaim,8)+status).hexdigest(),'contribution_prefix_claim_and_final_exact':True})
                        finally:
                            ok(sync(context))
                            for p in reversed(allocations):ok(free(context,p))
        finally:
            ok(sync(other));ok(free(other,foreign));ok(destroy(other));ok(destroy(context))
    result['status']='GPU_NUMERICAL_PASS_NOT_WHOLE_PROVER_OR_SPEED_QUALIFICATION'
    Path(a.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'cases':len(result['cases']),'invalid_calls_rejected':result['invalid_calls_rejected']}))
if __name__=='__main__':main()
