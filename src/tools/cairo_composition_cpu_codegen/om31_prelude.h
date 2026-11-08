/* Additive eight-coordinate evaluator ABI; prelude.h supplies M31/QM31. */
typedef struct { V x[8]; } O;
typedef struct {
    const Column *sites;
    const uint32_t *parameters, *coefficients, *denominators;
    uint32_t *output[8];
    size_t first, end;
    uint32_t evaluation_log, trace_log, constraint_base, additive;
} ORange;
static inline O oz(void) { O o;for(int j=0;j<8;j++)o.x[j]=vs(0);return o; }
static inline O os(const uint32_t *a) { O o;for(int j=0;j<8;j++)o.x[j]=vs(a[j]);return o; }
static inline O oa(O a,O b) { O o;for(int j=0;j<8;j++)o.x[j]=va(a.x[j],b.x[j]);return o; }
static inline O ob(O a,O b) { O o;for(int j=0;j<8;j++)o.x[j]=vb(a.x[j],b.x[j]);return o; }
static inline O on(O a) { O o;for(int j=0;j<8;j++)o.x[j]=vn(a.x[j]);return o; }
static inline O omb(O a,V b) { O o;for(int j=0;j<8;j++)o.x[j]=vm(a.x[j],b);return o; }
/* OM31 is QM31[v]/(v^2-u), with u the existing QM31 tower generator. */
static inline Q qu(Q a) {
    return (Q){{vb(va(a.x[2],a.x[2]),a.x[3]),
        va(a.x[2],va(a.x[3],a.x[3])),a.x[0],a.x[1]}};
}
static inline __attribute__((always_inline)) O om(O a,O b) {
    Q a0={{a.x[0],a.x[1],a.x[2],a.x[3]}},a1={{a.x[4],a.x[5],a.x[6],a.x[7]}};
    Q b0={{b.x[0],b.x[1],b.x[2],b.x[3]}},b1={{b.x[4],b.x[5],b.x[6],b.x[7]}};
    Q ac=qm(a0,b0),bd=qm(a1,b1);
    Q lo=qa(ac,qu(bd)),hi=qb(qb(qm(qa(a0,a1),qa(b0,b1)),ac),bd);
    return (O){{lo.x[0],lo.x[1],lo.x[2],lo.x[3],hi.x[0],hi.x[1],hi.x[2],hi.x[3]}};
}
static inline size_t omapped_index(size_t row,const ORange *r,int32_t offset) {
    if(!offset)return row;
    size_t p=reverse_index(row,r->evaluation_log);
    if(r->evaluation_log==r->trace_log){
        size_t n=(size_t)1<<r->evaluation_log,half=n>>1;
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
static inline void ostore(const ORange *r,size_t row,O value) {
    V d=(V){r->denominators[row>>r->trace_log],r->denominators[(row+1)>>r->trace_log],
        r->denominators[(row+2)>>r->trace_log],r->denominators[(row+3)>>r->trace_log]};
    for(int j=0;j<8;j++) {
        V v=vm(value.x[j],d);
        if(r->additive){V old;memcpy(&old,r->output[j]+row,16);v=va(old,v);}
        memcpy(r->output[j]+row,&v,16);
    }
}
_Static_assert(offsetof(ORange,first)==12*sizeof(void*),"OM31 range ABI");
_Static_assert(offsetof(ORange,evaluation_log)==14*sizeof(void*),"OM31 range ABI");
