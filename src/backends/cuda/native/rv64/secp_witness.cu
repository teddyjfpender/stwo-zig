#include "custody.cuh"
#include "oods/field.cuh"
#include "secp_witness.h"
namespace stwo::cuda::rv64 { namespace secp {
struct Term{uint32_t a;int32_t b,c;uint32_t shift;};
struct Geometry{uint32_t q,carry,qbytes,groups,carries,group,bits,kp[96];};
struct Query{uint32_t column,addend;};
#include "secp_witness_layout.cuh"
__device__ __constant__ uint32_t P[32]={47,252,255,255,254,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255};
struct Big{uint32_t b[96];};
struct Word{uint32_t b[32];};
__device__ int cmp(const Big&a,const Big&b){for(int i=95;i>=0;--i)if(a.b[i]!=b.b[i])return a.b[i]>b.b[i]?1:-1;return 0;}
__device__ void sub(Big&a,const Big&b){uint32_t borrow=0;for(uint32_t i=0;i<96;++i){uint32_t t=b.b[i]+borrow;borrow=a.b[i]<t;a.b[i]=(a.b[i]-t)&255u;}}
__device__ void addTerm(Big&out,const uint32_t*row,Term t){uint64_t carry=0;uint32_t absolute=uint32_t(t.c<0?-t.c:t.c);
 for(uint32_t k=0;k<96;++k){uint64_t sum=out.b[k]+carry;
 if(t.b>=0){for(uint32_t i=0;i<32;++i)if(k>=i&&k-i<32)sum+=uint64_t(absolute)*row[t.a+i]*row[uint32_t(t.b)+k-i];}
 else if(k>=t.shift&&k-t.shift<32)sum+=uint64_t(absolute)*row[t.a+k-t.shift];
 out.b[k]=uint32_t(sum)&255u;carry=sum>>8;}}
__device__ void divide(const Big&v,Big&q,Word&r){Big rem{},mod{};for(uint32_t i=0;i<32;++i)mod.b[i]=P[i];
 for(int bit=767;bit>=0;--bit){uint32_t carry=(v.b[uint32_t(bit)/8]>>(uint32_t(bit)&7))&1u;
 for(uint32_t i=0;i<33;++i){uint32_t x=(rem.b[i]<<1)|carry;rem.b[i]=x&255u;carry=x>>8;}
 if(cmp(rem,mod)>=0){sub(rem,mod);q.b[uint32_t(bit)/8]|=1u<<(uint32_t(bit)&7);}}
 for(uint32_t i=0;i<32;++i)r.b[i]=rem.b[i];}
__device__ Word reduce(Word a){Big v{},q{};Word r{};for(uint32_t i=0;i<32;++i)v.b[i]=a.b[i];divide(v,q,r);return r;}
__device__ Word mul(Word a,Word b){Big v{},q{};Word r{};uint64_t carry=0;for(uint32_t k=0;k<64;++k){uint64_t x=carry;for(uint32_t i=0;i<32;++i)if(k>=i&&k-i<32)x+=uint64_t(a.b[i])*b.b[k-i];v.b[k]=x&255u;carry=x>>8;}divide(v,q,r);return r;}
__device__ Word small(uint32_t v){Word a{};for(uint32_t i=0;i<4;++i)a.b[i]=(v>>(8*i))&255u;return a;}
__device__ Word add(Word a,Word b){Big v{},q{};Word r{};uint32_t carry=0;for(uint32_t i=0;i<32;++i){uint32_t x=a.b[i]+b.b[i]+carry;v.b[i]=x&255u;carry=x>>8;}v.b[32]=carry;divide(v,q,r);return r;}
__device__ Word minus(Word a,Word b){Big av{},bv{};for(uint32_t i=0;i<32;++i){av.b[i]=a.b[i];bv.b[i]=b.b[i];}if(cmp(av,bv)<0){uint32_t carry=0;for(uint32_t i=0;i<32;++i){uint32_t x=av.b[i]+P[i]+carry;av.b[i]=x&255u;carry=x>>8;}av.b[32]=carry;}sub(av,bv);Word r{};for(uint32_t i=0;i<32;++i)r.b[i]=av.b[i];return r;}
template<class L> __device__ void compute(uint32_t*row){Word in[6]{},w[6]{},out[3]{};for(uint32_t j=0;j<L::INPUTS;++j){for(uint32_t b=0;b<32;++b)in[j].b[b]=row[L::PACKET+32*j+b];in[j]=reduce(in[j]);}
 if(L::INPUTS==6){w[0]=mul(in[0],in[3]);w[1]=mul(in[1],in[4]);w[2]=mul(in[2],in[5]);w[3]=add(mul(in[0],in[4]),mul(in[1],in[3]));w[4]=add(mul(in[1],in[5]),mul(in[2],in[4]));w[5]=add(mul(in[0],in[5]),mul(in[2],in[3]));Word bzz=mul(w[2],small(21)),ym=minus(w[1],bzz),yp=add(w[1],bzz);out[0]=minus(mul(w[3],ym),mul(mul(w[4],small(21)),w[5]));out[1]=add(mul(yp,ym),mul(mul(w[0],small(63)),w[5]));out[2]=add(mul(w[4],yp),mul(mul(w[0],small(3)),w[3]));}
 else{w[0]=mul(in[1],in[1]);w[1]=mul(in[2],in[2]);w[2]=mul(in[0],in[1]);w[3]=mul(in[1],in[2]);w[4]=minus(w[0],mul(w[1],small(63)));Word yp=add(w[0],mul(w[1],small(21)));out[0]=mul(mul(w[2],small(2)),w[4]);out[1]=add(mul(w[4],yp),mul(mul(w[0],w[1]),small(168)));out[2]=mul(mul(w[0],w[3]),small(8));}
 for(uint32_t j=0;j<3;++j)for(uint32_t b=0;b<32;++b)row[L::OUT+32*j+b]=out[j].b[b];for(uint32_t j=0;j<L::WITNESSES;++j)for(uint32_t b=0;b<32;++b)row[L::WIT+32*j+b]=w[j].b[b];}
template<class L> __global__ void witness(StwoRv64SecpWitness j){uint32_t physical=blockIdx.x*blockDim.x+threadIdx.x,n=1u<<j.log;if(physical>=n)return;uint32_t circle=__brev(physical)>>(32-j.log),logical=circle<n/2?2*circle:2*(n-1-circle)+1;uint32_t row[L::MAIN]{};
 if(logical<j.calls){row[0]=1;const uint32_t*input=j.inputs+uint64_t(logical)*L::INPUTS*8;for(uint32_t b=0;b<L::INPUTS*32;++b)row[L::PACKET+b]=(input[b/4]>>(8*(b&3)))&255u;compute<L>(row);
 for(uint32_t r=0;r<L::RELATIONS;++r){Geometry g=L::geometry(r);Term terms[8];uint32_t count=L::terms(r,terms);Big pos{},neg{};for(uint32_t i=0;i<96;++i)pos.b[i]=g.kp[i];for(uint32_t i=0;i<count;++i)addTerm(terms[i].c>0?pos:neg,row,terms[i]);if(cmp(pos,neg)<0){atomicOr(j.status,1u);return;}sub(pos,neg);Big quotient{};Word remainder{};divide(pos,quotient,remainder);for(uint32_t i=0;i<32;++i)if(remainder.b[i]){atomicOr(j.status,2u);return;}for(uint32_t i=0;i<g.qbytes;++i)row[g.q+i]=quotient.b[i];for(uint32_t i=g.qbytes;i<96;++i)if(quotient.b[i]){atomicOr(j.status,4u);return;}
 int64_t carry=0;for(uint32_t group=0;group<g.groups;++group){int64_t sum=carry;for(uint32_t k=0;k<g.group;++k){uint32_t at=group*g.group+k;int64_t c=g.kp[at];for(uint32_t t=0;t<count;++t){Term term=terms[t];if(term.b>=0){for(uint32_t i=0;i<32;++i)if(at>=i&&at-i<32)c+=int64_t(term.c)*row[term.a+i]*row[uint32_t(term.b)+at-i];}else if(at>=term.shift&&at-term.shift<32)c+=int64_t(term.c)*row[term.a+at-term.shift];}for(uint32_t i=0;i<g.qbytes;++i)if(at>=i&&at-i<32)c-=int64_t(row[g.q+i])*P[at-i];sum+=c*(int64_t(1)<<(8*k));}int64_t radix=int64_t(1)<<(8*g.group);if(sum%radix){atomicOr(j.status,8u);return;}carry=sum/radix;if(group==g.carries){if(carry)atomicOr(j.status,16u);break;}int64_t half=int64_t(1)<<(g.bits-1);if(carry< -half||carry>=half){atomicOr(j.status,32u);return;}uint64_t encoded=uint64_t(carry+half);uint32_t bytes=(g.bits+7)/8;for(uint32_t b=0;b<bytes;++b)row[g.carry+bytes*group+b]=uint32_t(encoded>>(8*b))&255u;}}
 for(uint32_t j=0;j<3;++j){uint32_t borrow=1;for(uint32_t i=0;i<32;++i){uint32_t xi=row[L::OUT+32*j+i],subtrahend=xi+borrow;row[L::dbase(j)+i]=(P[i]-subtrahend)&255u;borrow=P[i]<subtrahend;}
 uint32_t carry=0;for(uint32_t i=0;i<15;++i){uint32_t x=row[L::OUT+32*j+2*i]+256*row[L::OUT+32*j+2*i+1],d=row[L::dbase(j)+2*i]+256*row[L::dbase(j)+2*i+1],m=P[2*i]+256*P[2*i+1];uint32_t total=x+d+carry+(i==0);carry=total!=m;row[L::borrow(j)+i]=carry;}}
 }
 for(uint32_t q=0;q<L::QUERIES;++q){auto query=L::query(q);uint32_t value=row[query.column]+query.addend;if(value>=256){atomicOr(j.status,64u);return;}atomicAdd(j.byte_counts+value,1u);}
 for(uint32_t c=0;c<L::MAIN;++c)j.main[uint64_t(c)*n+physical]=row[c];}
template<class L> __global__ void counts(StwoRv64SecpWitness j){uint32_t value=threadIdx.x,n=1u<<j.log;if(value>=256)return;uint32_t circle=value&1?n-1-value/2:value/2,physical=__brev(circle)>>(32-j.log);if(j.byte_counts[value]>=0x7fffffffu){atomicOr(j.status,128u);return;}j.main[uint64_t(L::MULT)*n+physical]=j.byte_counts[value];}
} }
extern "C" __attribute__((visibility("default"))) int stwo_rv64_secp_witness_on(void*ctx,uint32_t lane,const StwoRv64SecpWitness*ptr){using namespace stwo::cuda::rv64;if(!ptr||ptr->kind>1||ptr->log<8||ptr->log>22||!ptr->first_id)return int(cudaErrorInvalidValue);auto j=*ptr;uint64_t n=1ull<<j.log,width=j.kind?secp::Double::MAIN:secp::Add::MAIN,inputs=j.kind?3:6,queries=j.kind?secp::Double::QUERIES:secp::Add::QUERIES;if(j.calls>=n||uint64_t(j.first_id)+j.calls>0x7fffffffull||queries*n>=0x7fffffffull||j.input_words!=uint64_t(j.calls)*inputs*8||j.main_words<width*n)return int(cudaErrorInvalidValue);Custody c(ctx,lane);if((j.calls&&!c.range(j.inputs,j.input_words,false))||!c.range(j.main,width*n,true)||!c.range(j.byte_counts,256,true)||!c.range(j.status,1,true))return c.status;auto error=cudaMemsetAsync(j.byte_counts,0,1024,c.stream);if(error!=cudaSuccess)return int(error);if(j.kind){secp::witness<secp::Double><<<(n+31)/32,32,0,c.stream>>>(j);secp::counts<secp::Double><<<1,256,0,c.stream>>>(j);}else{secp::witness<secp::Add><<<(n+31)/32,32,0,c.stream>>>(j);secp::counts<secp::Add><<<1,256,0,c.stream>>>(j);}return int(cudaPeekAtLastError());}
