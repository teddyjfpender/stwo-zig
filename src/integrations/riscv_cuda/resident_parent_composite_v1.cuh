// Append after mechanically lowered original parent row constructors.
// Numeric row arithmetic is exclusively in those original functions.
#include <stdint.h>
#include <cuda_runtime.h>
struct RPSource { uint32_t kind,index,aux,ready_phase; };
struct RPWrite { RPSource source; uint32_t destination,byte_offset,bytes,phase; };
struct RPCall { uint32_t cohort,row,log,fixed_first,source_first,source_count,phase,reserved;uint64_t destination_first; };
struct RPCohort {uint64_t first;uint32_t rows,columns;};
struct RPHashRow {uint32_t kind,source,cohort,row;};
static_assert(sizeof(RPCall)==40);static_assert(sizeof(RPWrite)==32);
// Error-only first-failure diagnostic. Bit0 remains the legacy sticky flag;
// legacy atomicOr(status,1) cannot alter the diagnostic payload. Bit31 marks
// a diagnostic, [30:27]=category, [26:22]=cohort/source kind, [21:1]=row/index
// modulo 2^21. Successful calls do not read or write status through this helper.
__device__ void rp_fail(uint32_t*status,uint32_t category,uint32_t subject,uint32_t index){
 uint32_t code=0x80000001u|((category&15u)<<27)|((subject&31u)<<22)|((index&0x1fffffu)<<1);
 uint32_t seen=atomicCAS(status,0u,code);
 while(!(seen&0x80000000u)&&seen!=0u){uint32_t old=atomicCAS(status,seen,code);if(old==seen)return;seen=old;}
}

__device__ bool rp_word(const uint32_t*p,uint32_t n,uint32_t i,uint32_t&v){if(i>=n)return false;v=p[i];return true;}
__device__ bool rp_raw(const unsigned char*p,uint32_t n,uint32_t i,uint32_t&v){if(i>n||n-i<4)return false;v=uint32_t(p[i])|(uint32_t(p[i+1])<<8)|(uint32_t(p[i+2])<<16)|(uint32_t(p[i+3])<<24);return true;}
__device__ bool rp_source(RPSource s,const unsigned char*raw,uint32_t rn,const uint32_t*resident,uint32_t wn,const uint32_t*hash,uint32_t hn,const uint32_t*arithmetic,uint32_t an,uint32_t*main,uint32_t mn,const uint32_t*readonly,uint32_t ron,uint32_t&v){
 switch(s.kind){case 0:v=s.index;return true;case 1:return rp_raw(raw,rn,s.index,v);case 2:return rp_word(resident,wn,s.index,v);case 3:{if(s.index>wn||wn-s.index<4)return false;v=0;for(uint32_t j=0;j<4;++j){uint32_t b=resident[s.index+j];if(b>255)return false;v|=b<<(8*j);}return true;}case 4:if(s.aux>=32||!rp_word(resident,wn,s.index,v))return false;v=(v>>s.aux)&1;return true;case 5:return rp_word(arithmetic,an,s.index,v);case 6:return rp_word(main,mn,s.index,v);case 7:return rp_word(hash,hn,s.index,v);case 8:{v=0;for(uint32_t j=0;j<4;++j){uint64_t index=uint64_t(s.index)+uint64_t(j)*s.aux;if(index>=mn||main[index]>255)return false;v|=main[index]<<(8*j);}return true;}case 9:if(s.aux>=4||!rp_word(hash,hn,s.index,v))return false;v=(v>>(8*s.aux))&255;return true;case 10:if(s.index>=rn)return false;v=raw[s.index];return true;case 11:return rp_word(readonly,ron,s.index,v);case 12:if(s.aux>=4||!rp_word(resident,wn,s.index,v))return false;v=(v>>(8*s.aux))&255;return true;default:return false;}
}
__global__ void rp_write(const RPWrite*w,uint32_t count,const unsigned char*raw,uint32_t rn,uint32_t*resident,uint32_t wn,const uint32_t*hash,uint32_t hn,const uint32_t*arithmetic,uint32_t an,uint32_t*main,uint32_t mn,const uint32_t*readonly,uint32_t ron,unsigned char*input,uint32_t in,uint32_t*arguments,uint32_t argn,uint32_t*status){
 uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;RPWrite r=w[i];uint32_t v=0;if(r.bytes<1||r.bytes>4||!rp_source(r.source,raw,rn,resident,wn,hash,hn,arithmetic,an,main,mn,readonly,ron,v)){rp_fail(status,1,r.source.kind,r.source.index);return;}
 unsigned char*dst=nullptr;uint64_t size=0;switch(r.destination){case 0:dst=input;size=in;break;case 1:dst=(unsigned char*)arguments;size=uint64_t(argn)*4;break;case 2:dst=(unsigned char*)resident;size=uint64_t(wn)*4;break;case 3:dst=(unsigned char*)main;size=uint64_t(mn)*4;break;default:rp_fail(status,2,r.destination,i);return;}
 if(r.byte_offset>size||r.bytes>size-r.byte_offset){rp_fail(status,3,r.destination,i);return;}for(uint32_t j=0;j<r.bytes;++j)dst[r.byte_offset+j]=(unsigned char)(v>>(8*j));
}
extern "C" int stwo_resident_parent_write_on(const RPWrite*w,uint32_t count,const unsigned char*raw,uint32_t rn,uint32_t*resident,uint32_t wn,const uint32_t*hash,uint32_t hn,const uint32_t*arithmetic,uint32_t an,uint32_t*main,uint32_t mn,const uint32_t*readonly,uint32_t ron,unsigned char*input,uint32_t in,uint32_t*arguments,uint32_t argn,uint32_t*status,void*stream){if(!count)return 1;rp_write<<<(count+127)/128,128,0,(cudaStream_t)stream>>>(w,count,raw,rn,resident,wn,hash,hn,arithmetic,an,main,mn,readonly,ron,input,in,arguments,argn,status);return int(cudaGetLastError());}
__global__ void rp_direct(const RPCall*calls,uint32_t count,const RPSource*sources,uint32_t sn,const uint32_t*fixed,uint32_t fn,const unsigned char*raw,uint32_t rn,const uint32_t*resident,uint32_t wn,const uint32_t*hash,uint32_t hn,const uint32_t*arithmetic,uint32_t an,const uint32_t*readonly,uint32_t ron,uint32_t*main,uint32_t mn,uint32_t*status){
 uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;RPCall c=calls[i];if(c.reserved||c.log<1||c.log>27||c.row>=(1u<<c.log)||c.source_count>40||c.source_first>sn||c.source_count>sn-c.source_first||c.fixed_first>fn||c.destination_first>mn){rp_fail(status,4,c.cohort,c.row);return;}
 uint32_t d[40];for(uint32_t j=0;j<c.source_count;++j){if(!rp_source(sources[c.source_first+j],raw,rn,resident,wn,hash,hn,arithmetic,an,main,mn,readonly,ron,d[j])){rp_fail(status,5,c.cohort,c.row);return;}}
 uint32_t e=1;const uint32_t*p=fixed+c.fixed_first;uint32_t*out=main+c.destination_first;uint32_t rows=1u<<c.log;
 #define RP_CASE(N) case N: if(c.source_count==stwo_parent_direct_input_##N##_v1()&&stwo_parent_direct_fixed_##N##_v1()<=fn-c.fixed_first&&uint64_t(stwo_parent_direct_width_##N##_v1())*rows<=mn-c.destination_first){e=stwo_parent_direct_row_##N##_v1(p,d,out,rows,c.row);if(e)rp_fail(status,7,c.cohort,c.row);}else rp_fail(status,6,c.cohort,c.row);break;
 switch(c.cohort){RP_CASE(2) RP_CASE(3) RP_CASE(4) RP_CASE(5) RP_CASE(6) RP_CASE(7) RP_CASE(8) RP_CASE(9) RP_CASE(10) RP_CASE(11) RP_CASE(12) RP_CASE(13) RP_CASE(14) RP_CASE(15) RP_CASE(16) RP_CASE(17) RP_CASE(18) RP_CASE(19) default:rp_fail(status,8,c.cohort,c.row);break;}
 #undef RP_CASE
 // Constructor errors are tagged at their call site above.
}
extern "C" int stwo_resident_parent_direct_routes_on(const RPCall*c,uint32_t n,const RPSource*s,uint32_t sn,const uint32_t*f,uint32_t fn,const unsigned char*r,uint32_t rn,const uint32_t*w,uint32_t wn,const uint32_t*h,uint32_t hn,const uint32_t*a,uint32_t an,const uint32_t*ro,uint32_t ron,uint32_t*m,uint32_t mn,uint32_t*status,void*stream){if(!n)return 1;rp_direct<<<(n+127)/128,128,0,(cudaStream_t)stream>>>(c,n,s,sn,f,fn,r,rn,w,wn,h,hn,a,an,ro,ron,m,mn,status);return int(cudaGetLastError());}
__device__ uint32_t rp_row(uint32_t row,uint32_t log){uint32_t n=1u<<log;uint32_t circle=(row&1)?(2*n-row)/2:row/2;return __brev(circle)>>(32-log);}
__global__ void rp_scatter(const RPHashRow*map,uint32_t count,const RPCohort*cohorts,const uint32_t*g,uint32_t gl,const uint32_t*x,uint32_t xl,uint32_t*main,uint32_t mn,uint32_t*status){
 uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;auto r=map[i];if(r.kind>1||r.cohort>=23){rp_fail(status,9,r.cohort,r.row);return;}auto c=cohorts[r.cohort];uint32_t log=r.kind?xl:gl,width=r.kind?12:82;if(log<1||log>27||r.source>=(1u<<log)||r.row>=c.rows||c.columns!=width||c.first>mn||uint64_t(width)*c.rows>mn-c.first){rp_fail(status,10,r.cohort,r.row);return;}const uint32_t*src=r.kind?x:g;uint32_t si=rp_row(r.source,log),di=rp_row(r.row,31u-__clz(c.rows));for(uint32_t j=0;j<width;++j)main[c.first+uint64_t(j)*c.rows+di]=src[uint64_t(j)*(1u<<log)+si];
}
extern "C" int stwo_resident_parent_hash_scatter_on(const RPHashRow*m,uint32_t n,const RPCohort*c,const uint32_t*g,uint32_t gl,const uint32_t*x,uint32_t xl,uint32_t*main,uint32_t mn,uint32_t*status,void*stream){if(!n)return 1;rp_scatter<<<(n+127)/128,128,0,(cudaStream_t)stream>>>(m,n,c,g,gl,x,xl,main,mn,status);return int(cudaGetLastError());}
