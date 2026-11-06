"""Small numerical ABI test; no whole-prover, memory-peak or speed claim."""
from pathlib import Path
import argparse, ctypes as C, fcntl, hashlib, json
U,Q,V=C.c_uint32,C.c_uint64,C.c_void_p
class Segment(C.Structure):
    _fields_=[('columns',V),('stride',Q),('capacity',Q),('size',U),('reserved',U)]
def function(lib,name,args):
    f=getattr(lib,name);f.argtypes=args;f.restype=C.c_int;return f

def main():
    p=argparse.ArgumentParser();p.add_argument('--base',required=True);p.add_argument('--compact',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    lock=open('/workspace/m3/locks/gpu.lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
    cuda=C.CDLL('/usr/local/cuda/lib64/libcudart.so.12')
    base=C.CDLL(a.base);compact=C.CDLL(a.compact)
    select=function(cuda,'cudaSetDevice',[C.c_int]);malloc=function(cuda,'cudaMalloc',[C.POINTER(V),Q]);free=function(cuda,'cudaFree',[V]);copy=function(cuda,'cudaMemcpy',[V,V,Q,C.c_int]);create=function(cuda,'cudaStreamCreate',[C.POINTER(V)]);destroy=function(cuda,'cudaStreamDestroy',[V]);sync=function(cuda,'cudaStreamSynchronize',[V])
    old=function(base,'stwo_blake2s_mixed_seeded_eager_on',[U,U,C.POINTER(Segment),U,U,V,V,V,V])
    leaf=function(base,'stwo_blake2s_mixed_leaf_on',[U,U,C.POINTER(Segment),V,V])
    new=function(compact,'stwo_blake2s_mixed_seeded_eager_compact_on',[U,U,C.POINTER(Segment),U,U,V,Q,V,Q,V,Q,V])
    def ok(code):assert code==0,code
    result={'schema':'rv64-compact-state-numerical/v1','scope':'frozen eager and unchunked mixed-leaf numerical parity on two GPUs; no full proof or timing claim','base_sha256':hashlib.sha256(Path(a.base).read_bytes()).hexdigest(),'compact_sha256':hashlib.sha256(Path(a.compact).read_bytes()).hexdigest(),'cases':[],'rejections':0}
    for device in [0,1]:
        ok(select(device));stream=V();ok(create(C.byref(stream)))
        for first in range(1,33):
            allocations=[]
            def alloc(words):
                x=V();ok(malloc(C.byref(x),words*4));allocations.append(x);return x
            def fetch(ptr,words):
                host=(U*words)();ok(copy(C.cast(host,V),ptr,words*4,2));return bytes(host)
            try:
                sources=[]
                for phase,(size,columns) in enumerate([(16,first),(64,3),(128,5)]):
                    data=(U*(size*columns))(*[((i//size)*7919+(i%size)*104729+phase*131+17)%2147483647 for i in range(size*columns)])
                    ptr=alloc(len(data));ok(copy(ptr,C.cast(data,V),len(data)*4,1));sources.append(Segment(ptr,size,size*columns,size,0))
                stages=(Segment*3)(*sources)
                old0,old1=alloc(24*16),alloc(24*64)
                need0=(8+first%16)*16;need1=(8+(first+3)%16)*64
                new0,new1=alloc(need0),alloc(need1)
                expected,oldhash,newhash=alloc(8*128),alloc(8*128),alloc(8*128)
                ok(old(16,1,C.byref(stages[0]),0,0,None,old0,None,stream))
                ok(new(16,1,C.byref(stages[0]),0,0,None,0,new0,need0,None,0,stream))
                ok(old(64,1,C.byref(stages[1]),first,16,old0,old1,None,stream))
                ok(new(64,1,C.byref(stages[1]),first,16,new0,need0,new1,need1,None,0,stream))
                ok(old(128,1,C.byref(stages[2]),first+3,64,old1,None,oldhash,stream))
                ok(new(128,1,C.byref(stages[2]),first+3,64,new1,need1,None,0,newhash,8*128,stream))
                ok(leaf(128,3,stages,expected,stream));ok(sync(stream))
                assert fetch(new0,need0)==fetch(old0,need0)
                assert fetch(new1,need1)==fetch(old1,need1)
                assert fetch(newhash,8*128)==fetch(oldhash,8*128)==fetch(expected,8*128)
                bad=[new(16,1,C.byref(stages[0]),0,0,None,0,new0,need0-1,None,0,stream),new(64,1,C.byref(stages[1]),first,16,new0,need0-1,new1,need1,None,0,stream),new(128,1,C.byref(stages[2]),first+3,64,new1,need1,None,0,newhash,8*128-1,stream),new(64,1,C.byref(stages[1]),first,16,new0,need0,new0,need1,None,0,stream),new(16,1,C.byref(stages[0]),0,0,None,0,new0,need0,expected,8*128,stream),new(16,1,C.byref(stages[0]),0,0,None,0,new0,need0,None,0,None)]
                assert all(code!=0 for code in bad);result['rejections']+=len(bad)
                result['cases'].append({'device':device,'first_columns':first,'pending_before_expansion':first%16,'pending_after_expansion':(first+3)%16,'sizes':[16,64,128],'prefix_words':[need0,need1],'exact_prefix_and_final_parity':True})
            finally:
                ok(sync(stream))
                for pointer in reversed(allocations):ok(free(pointer))
        ok(destroy(stream))
    result.update(status='GPU_NUMERICAL_PARITY_PASS_NOT_WHOLE_PROVER_QUALIFIED',pending_alignments=list(range(16)))
    Path(a.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
if __name__=='__main__':main()
