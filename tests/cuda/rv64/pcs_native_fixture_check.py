import ctypes as c, mmap,sys,time,hashlib,json
class Words(c.Structure): _fields_=[('words',c.POINTER(c.c_uint32)),('count',c.c_uint64)]
class Column(c.Structure): _fields_=[('kind',c.c_uint32),('log',c.c_uint32),('words',c.POINTER(c.c_uint32)),('count',c.c_uint64),('token',c.c_uint64),('generation',c.c_uint64)]
class Req(c.Structure): _fields_=[('version',c.c_uint32),('nsections',c.c_uint32),('sections',Words*17),('columns',c.POINTER(Column)),('ncolumns',c.c_uint64),('scope',c.c_uint32*8)]
class Res(c.Structure): _fields_=[('words',c.POINTER(c.c_uint32)),('count',c.c_uint64),('device_ns',c.c_uint64),('requested_bytes',c.c_uint64),('retained_bytes',c.c_uint64),('owner',c.c_void_p)]
f=open(sys.argv[2],'rb');m=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_COPY);data=(c.c_uint32*(len(m)//4)).from_buffer(m);pos=0
def take(n):
 global pos
 r=Words(c.cast(c.byref(data,pos*4),c.POINTER(c.c_uint32)),n);pos+=n;return r
h=take(24); H=list(h.words[:24]);sections=[h];sizes=[9,16 if H[21] else 0,H[8]*4,H[9]*4,H[10]*8,H[11]*8,H[12]*6,H[10]*4,H[10]*2,H[13],H[8]]
sections.extend(take(n) for n in sizes);warehouse=take(H[15]);cols=(Column*H[8])()
for i in range(H[8]):
 src=sections[3].words[i*4:i*4+4];off=src[0]+(src[1]<<32);log=src[3];cols[i]=Column(0,log,c.cast(c.byref(warehouse.words.contents,off*4),c.POINTER(c.c_uint32)),1<<log,0,0)
sections.extend([take(H[19]),take(H[14]*8),take(H[20])]);domain=take(2<<H[4]);roots=take(H[12]*8);take(17)
assert pos*4==len(m)
p=2147483647;x,y=domain.words[:2]; nx,ny=domain.words[(1<<(H[4]-1))*2: (1<<(H[4]-1))*2+2];params=(c.c_uint32*4)(x,y,(nx*x+ny*y)%p,(ny*x-nx*y)%p);sections.extend([roots,Words(params,4)])
req=Req(1,17,(Words*17)(*sections),cols,len(cols),(c.c_uint32*8)(*range(1,9)))
lib=c.CDLL(sys.argv[1]);create=lib.stwo_rv64_pcs_native_create;create.argtypes=[c.c_uint32,c.c_uint64,c.POINTER(c.c_void_p)];prove=lib.stwo_rv64_pcs_native_prove;prove.argtypes=[c.c_void_p,c.POINTER(Req),c.POINTER(Res)];release=lib.stwo_rv64_pcs_native_release;release.argtypes=[c.POINTER(Res)];destroy=lib.stwo_rv64_pcs_native_destroy;destroy.argtypes=[c.c_void_p];error=lib.stwo_rv64_pcs_native_error;error.argtypes=[c.c_void_p];error.restype=c.c_char_p
session=c.c_void_p();assert create(0,24*1024**3,c.byref(session))==0
try:
 for i in range(2):
  out=Res();t=time.monotonic();rc=prove(session,c.byref(req),c.byref(out));assert rc==0,error(session)
  payload=c.string_at(out.words,out.count*4);expected=open(sys.argv[3],'rb').read();assert payload==expected,(hashlib.sha256(payload).hexdigest(),hashlib.sha256(expected).hexdigest());print(json.dumps(dict(run=i,wall=time.monotonic()-t,device_ns=out.device_ns,requested=out.requested_bytes,retained=out.retained_bytes,sha256=hashlib.sha256(payload).hexdigest(),equal=True)),flush=True);release(c.byref(out))
finally: assert destroy(session)==0
