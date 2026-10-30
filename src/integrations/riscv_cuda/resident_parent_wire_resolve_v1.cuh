#include <cuda_runtime.h>
struct ParentWireInstruction{unsigned op,value,lhs,rhs;};
struct ParentWireCandidate{unsigned weight,coordinates[4];};
struct ParentWireRequest{unsigned first,count,candidate_first,candidate_count,weight,output_first,phase;};
__device__ unsigned parent_wire_add(unsigned a,unsigned b){unsigned long long x=(unsigned long long)a+b;x=(x&0x7fffffffull)+(x>>31);return unsigned(x>=0x7fffffffull?x-0x7fffffffull:x);}
__device__ unsigned parent_wire_mul(unsigned a,unsigned b){unsigned long long x=(unsigned long long)a*b;x=(x&0x7fffffffull)+(x>>31);x=(x&0x7fffffffull)+(x>>31);return unsigned(x>=0x7fffffffull?x-0x7fffffffull:x);}
__global__ void parent_wire_resolve(const ParentWireInstruction*instructions,const ParentWireCandidate*candidates,const ParentWireRequest*requests,unsigned count,const unsigned*main,unsigned*scratch,unsigned*output,unsigned*status){
 unsigned id=blockIdx.x*blockDim.x+threadIdx.x;if(id>=count)return;ParentWireRequest request=requests[id];
 for(unsigned j=request.first;j<request.first+request.count;++j){ParentWireInstruction n=instructions[j];unsigned value=0;switch(n.op){case 0:value=n.value;break;case 1:value=main[n.value];if(value>=0x7fffffffu){atomicOr(status,1u);value=0;}break;case 2:value=parent_wire_add(scratch[n.lhs],scratch[n.rhs]);break;case 3:value=parent_wire_add(scratch[n.lhs],scratch[n.rhs]?0x7fffffffu-scratch[n.rhs]:0u);break;case 4:value=parent_wire_mul(scratch[n.lhs],scratch[n.rhs]);break;case 5:value=scratch[n.lhs]?0x7fffffffu-scratch[n.lhs]:0u;break;default:atomicOr(status,8u);break;}scratch[j]=value;}
 unsigned selected[4]={0,0,0,0};bool found=false;
 if(scratch[request.weight]!=0u){for(unsigned j=0;j<request.candidate_count;++j){ParentWireCandidate c=candidates[request.candidate_first+j];if(scratch[c.weight]==0u)continue;if(!found){for(unsigned k=0;k<4;++k)selected[k]=scratch[c.coordinates[k]];found=true;}else for(unsigned k=0;k<4;++k)if(selected[k]!=scratch[c.coordinates[k]])atomicOr(status,4u);}if(!found)atomicOr(status,2u);}
 for(unsigned k=0;k<4;++k)output[request.output_first+k]=selected[k];
}
extern "C" int stwo_resident_parent_wire_resolve_on(const ParentWireInstruction*i,const ParentWireCandidate*c,const ParentWireRequest*r,unsigned count,const unsigned*main,unsigned*scratch,unsigned*out,unsigned*status,void*stream){if(!i||!c||!r||!count||!main||!scratch||!out||!status)return int(cudaErrorInvalidValue);parent_wire_resolve<<<(count+127u)/128u,128,0,static_cast<cudaStream_t>(stream)>>>(i,c,r,count,main,scratch,out,status);return int(cudaGetLastError());}
