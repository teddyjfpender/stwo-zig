// Raw child input validation and graph gather. No host-derived challenges or
// query answers. Sticky errors must be included in final parent verdict.
#include <cuda_runtime.h>
#include <stdint.h>
struct StwoChildCheck { uint32_t kind,first,count,low,high; };
struct StwoChildInput { uint32_t kind,destination,index,aux,arg; };
static constexpr uint32_t child_p=2147483647u;
__global__ void child_validate(const uint32_t* packet,uint32_t words,const StwoChildCheck* checks,uint32_t count,uint32_t* error) {
  uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;
  StwoChildCheck c=checks[i];if((uint64_t)c.first+c.count>words){atomicOr(error,1u);return;}
  if(c.kind==0){for(uint32_t j=0;j<c.count;j++)if(packet[c.first+j]>=child_p)atomicOr(error,2u);}
  else if((c.kind==1||c.kind==2)&&c.count==2){uint64_t v=packet[c.first]|((uint64_t)packet[c.first+1]<<32),bound=c.low|((uint64_t)c.high<<32);if(c.kind==1?v!=bound:v>bound)atomicOr(error,4u);}
  else atomicOr(error,8u);
}
__global__ void child_gather(const uint32_t* packet,uint32_t words,const uint32_t* resident,uint32_t resident_words,
 const uint32_t* queries,uint32_t nq,uint32_t domain_log,const StwoChildInput* inputs,uint32_t count,uint32_t* output,uint32_t output_words,uint32_t* error){
 uint32_t i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=count)return;StwoChildInput s=inputs[i];uint32_t v=0;
 if(s.destination>=output_words||domain_log==0||domain_log>30||nq==0||nq>128){atomicOr(error,16u);return;}
 switch(s.kind){
 case 0:v=s.index;break;
 case 1:if(s.index>=words){atomicOr(error,32u);return;}v=packet[s.index];break;
 case 2:if(s.index>=resident_words){atomicOr(error,64u);return;}v=resident[s.index];break;
 case 3:{
  if(s.arg>=nq||(uint64_t)s.index+s.aux>words){atomicOr(error,128u);return;}
  // Raw PCS queried columns use ascending globally unique raw query order.
  uint32_t unique=0,rank=0,target=queries[s.arg];
  for(uint32_t j=0;j<nq;j++){
   uint32_t q=queries[j];if(q>=(1u<<domain_log)){atomicOr(error,256u);return;}
   bool first=true;for(uint32_t k=0;k<j;k++)if(queries[k]==q){first=false;break;}
   if(first){unique++;if(q<target)rank++;}
  }
  if(unique!=s.aux||rank>=s.aux){atomicOr(error,512u);return;}v=packet[s.index+rank];break;
 }
 case 4:if(s.index>=nq||s.aux>=32||queries[s.index]>=(1u<<domain_log)){atomicOr(error,1024u);return;}v=(queries[s.index]>>s.aux)&s.arg;break;
 case 5:if((uint64_t)s.index+2>words){atomicOr(error,2048u);return;}v=(uint32_t)((packet[s.index]|((uint64_t)packet[s.index+1]<<32))%child_p);break;
 default:atomicOr(error,4096u);return;
 }
 if(v>=child_p){atomicOr(error,8192u);return;}output[s.destination]=v;
}
extern "C" int stwo_parent_child_validate_v1(const uint32_t* packet,uint32_t words,const StwoChildCheck* checks,uint32_t count,uint32_t* error,cudaStream_t stream){
 if(!packet||!checks||!error||!words||!count)return (int)cudaErrorInvalidValue;
 child_validate<<<(count+127)/128,128,0,stream>>>(packet,words,checks,count,error);return (int)cudaGetLastError();
}
extern "C" int stwo_parent_child_gather_v1(const uint32_t* packet,uint32_t words,const uint32_t* resident,uint32_t resident_words,const uint32_t* queries,uint32_t nq,uint32_t domain_log,const StwoChildInput* inputs,uint32_t count,uint32_t* output,uint32_t output_words,uint32_t* error,cudaStream_t stream){
 if(!packet||!resident||!queries||!inputs||!output||!error||!count)return (int)cudaErrorInvalidValue;
 child_gather<<<(count+127)/128,128,0,stream>>>(packet,words,resident,resident_words,queries,nq,domain_log,inputs,count,output,output_words,error);return (int)cudaGetLastError();
}
