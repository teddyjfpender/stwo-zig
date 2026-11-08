#include <stdint.h>
#include <stddef.h>
#include <string.h>
#if defined(__aarch64__)
#include <arm_neon.h>
#endif
typedef uint32_t V __attribute__((ext_vector_type(4)));
typedef uint64_t W __attribute__((ext_vector_type(4)));
typedef struct { V x[4]; } Q;
typedef struct { const uint32_t *values; uint32_t shift, reserved; } Column;
typedef struct {
    const Column *sites;
    const uint32_t *parameters, *coefficients, *denominators;
    uint32_t *output[4];
    size_t first, end;
    uint32_t evaluation_log, trace_log, constraint_base, additive;
} Range;
#define P 0x7fffffffU
static inline V vs(uint32_t x) { return (V){x,x,x,x}; }
static inline V canon(V x) { return x - ((V)(x == vs(P)) & vs(P)); }
static inline V va(V a,V b) {
    V x=a+b;
#if defined(__aarch64__)
    return (V)vminq_u32((uint32x4_t)x,(uint32x4_t)(x-vs(P)));
#else
    return canon((x&vs(P))+(x>>31));
#endif
}
static inline V vn(V a) { return canon(vs(P)-a); }
static inline V vb(V a,V b) {
#if defined(__aarch64__)
    V d=a-b;return (V)vminq_u32((uint32x4_t)d,(uint32x4_t)(d+vs(P)));
#else
    return va(a,vn(b));
#endif
}
static inline V vm(V a,V b) {
#if defined(__aarch64__)
    V lo=(V)vmulq_u32((uint32x4_t)a,(uint32x4_t)b);
    V hi=(V)vqdmulhq_s32((int32x4_t)a,(int32x4_t)b);
    V x=(lo&vs(P))+hi;
    return (V)vminq_u32((uint32x4_t)x,(uint32x4_t)(x-vs(P)));
#else
    W x=__builtin_convertvector(a,W)*__builtin_convertvector(b,W);
    W p=(W){P,P,P,P}; x=(x&p)+(x>>31);
    V folded=__builtin_convertvector(x,V);
    return (folded>=vs(P))?folded-vs(P):folded;
#endif
}
static inline V vi(V a) { V out=vs(1); uint32_t e=P-2; for(;e;e>>=1){if(e&1)out=vm(out,a);a=vm(a,a);}return out; }
static inline Q qs(const uint32_t *a) { return (Q){{vs(a[0]),vs(a[1]),vs(a[2]),vs(a[3])}}; }
static inline Q qa(Q a,Q b) { Q o;for(int j=0;j<4;j++)o.x[j]=va(a.x[j],b.x[j]);return o; }
static inline Q qb(Q a,Q b) { Q o;for(int j=0;j<4;j++)o.x[j]=vb(a.x[j],b.x[j]);return o; }
static inline Q qn(Q a) { Q o;for(int j=0;j<4;j++)o.x[j]=vn(a.x[j]);return o; }
static inline void cm(V a,V b,V c,V d,V *re,V *im) {
    V ac=vm(a,c),bd=vm(b,d);*re=vb(ac,bd);*im=vb(vb(vm(va(a,b),va(c,d)),ac),bd);
}
static inline Q qm(Q a,Q b) {
    V p0,p1,q0,q1,s0,s1;
    cm(a.x[0],a.x[1],b.x[0],b.x[1],&p0,&p1);
    cm(a.x[2],a.x[3],b.x[2],b.x[3],&q0,&q1);
    cm(va(a.x[0],a.x[2]),va(a.x[1],a.x[3]),va(b.x[0],b.x[2]),va(b.x[1],b.x[3]),&s0,&s1);
    return (Q){{va(p0,vb(va(q0,q0),q1)),va(p1,va(q0,va(q1,q1))),vb(vb(s0,p0),q0),vb(vb(s1,p1),q1)}};
}
static inline Q qmb(Q value,V scalar) {
    return (Q){{vm(value.x[0],scalar),vm(value.x[1],scalar),vm(value.x[2],scalar),vm(value.x[3],scalar)}};
}
static inline size_t reverse_index(size_t x,uint32_t log) {
    uint64_t v=__builtin_bitreverse64((uint64_t)x);return (size_t)(v>>(64-log));
}
static inline size_t mapped_index(size_t row,const Range *r,int32_t offset) {
    if(!offset)return row;
    size_t p=reverse_index(row,r->evaluation_log);
    if(r->evaluation_log==r->trace_log){
        size_t n=(size_t)1<<r->evaluation_log, half=n>>1;
        size_t coset=p<half?2*p:2*(n-1-p)+1;
        size_t shifted=(coset+(size_t)(int64_t)offset)&(n-1);
        p=(shifted&1)?n-1-(shifted>>1):(shifted>>1);
    }else{
        size_t half=(size_t)1<<(r->evaluation_log-1);
        int64_t step=(int64_t)offset*((int64_t)1<<(r->evaluation_log-r->trace_log-1));
        p=p<half?(p+(uint64_t)step)&(half-1):((p-(uint64_t)step)&(half-1))+half;
    }
    return reverse_index(p,r->evaluation_log);
}
static inline V gather(Column c,const size_t p[4]) {
    return (V){c.values[((p[0]>>c.shift)<<1)+(p[0]&1)],c.values[((p[1]>>c.shift)<<1)+(p[1]&1)],
        c.values[((p[2]>>c.shift)<<1)+(p[2]&1)],c.values[((p[3]>>c.shift)<<1)+(p[3]&1)]};
}
static inline void store(const Range *r,size_t row,Q value) {
    V d=(V){r->denominators[row>>r->trace_log],r->denominators[(row+1)>>r->trace_log],
        r->denominators[(row+2)>>r->trace_log],r->denominators[(row+3)>>r->trace_log]};
    for(int j=0;j<4;j++) { V v=vm(value.x[j],d);if(r->additive){V old;memcpy(&old,r->output[j]+row,16);v=va(old,v);}memcpy(r->output[j]+row,&v,16); }
}
_Static_assert(offsetof(Range,first)==8*sizeof(void*),"Range ABI");
_Static_assert(offsetof(Range,evaluation_log)==10*sizeof(void*),"Range ABI");
