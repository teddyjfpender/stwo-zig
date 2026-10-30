#include <cuda_runtime.h>
struct ParentArithmeticNode{uint op,lhs,rhs,input,constant[4];};
struct ParentArithmeticGraph{uint node_first,node_count,input_first,input_count,value_word_base,level_first,level_count,output_first,output_count;};
__device__ void parent_arithmetic_store(uint*out,uint index,RiscvQm31 q){out[4u*index]=q.a;out[4u*index+1]=q.b;out[4u*index+2]=q.c;out[4u*index+3]=q.d;}
// One persistent CTA per independently scheduled graph. Every dependency level
// has a device barrier; there are no host value fetches or relaunches per node.
__global__ void parent_arithmetic_evaluate(const ParentArithmeticGraph*graphs,const uint*selected,uint count,const ParentArithmeticNode*nodes,const uint*level_nodes,const uint*level_offsets,const uint*outputs,const uint*inputs,uint*values,uint*status){
 uint gidx=blockIdx.x;if(gidx>=count)return;ParentArithmeticGraph g=graphs[selected[gidx]];
 for(uint level=0;level<g.level_count;++level){uint first=level_offsets[g.level_first+level],end=level_offsets[g.level_first+level+1u];
  for(uint j=first+threadIdx.x;j<end;j+=blockDim.x){uint id=level_nodes[j];ParentArithmeticNode n=nodes[id];RiscvQm31 q={0u,0u,0u,0u};
   if(n.op==0u){q=riscv_load_qm31(inputs,4u*n.input);if(q.a>=0x7fffffffu||q.b>=0x7fffffffu||q.c>=0x7fffffffu||q.d>=0x7fffffffu)atomicOr(status,64u);}
   else if(n.op==1u)q={n.constant[0],n.constant[1],n.constant[2],n.constant[3]};
   else {RiscvQm31 a=riscv_load_qm31(values,4u*n.lhs);switch(n.op){case 2:q=riscv_qm_add(a,riscv_load_qm31(values,4u*n.rhs));break;case 3:q=riscv_qm_sub(a,riscv_load_qm31(values,4u*n.rhs));break;case 4:q=riscv_qm_mul(a,riscv_load_qm31(values,4u*n.rhs));break;case 5:q=riscv_qm_sub(RiscvQm31{0u,0u,0u,0u},a);break;case 6:if((a.a|a.b|a.c|a.d)==0u)atomicOr(status,128u);else q=riscv_from_q(stwo::cuda::oods::inverse(riscv_to_q(a)));break;default:atomicOr(status,256u);break;}}
   parent_arithmetic_store(values,id,q);
  }__syncthreads();
 }
 for(uint j=threadIdx.x;j<g.output_count;j+=blockDim.x){RiscvQm31 q=riscv_load_qm31(values,4u*outputs[g.output_first+j]);if((q.a|q.b|q.c|q.d)!=0u)atomicOr(status,512u);}
}
extern "C" int stwo_resident_parent_arithmetic_on(const ParentArithmeticGraph*g,const uint*selected,uint count,const ParentArithmeticNode*n,const uint*levels,const uint*offsets,const uint*outputs,const uint*input,uint*values,uint*status,void*stream){if(!g||!selected||!count||!n||!levels||!offsets||!outputs||!input||!values||!status)return int(cudaErrorInvalidValue);parent_arithmetic_evaluate<<<count,128,0,static_cast<cudaStream_t>(stream)>>>(g,selected,count,n,levels,offsets,outputs,input,values,status);return int(cudaGetLastError());}
