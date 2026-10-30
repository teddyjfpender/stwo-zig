// Exact physical assembly from native access denominator roots. Prefix/mean
// kernels are the unchanged shared framework emitters. All buffers are leased
// from the proof arena; this implementation does not allocate or read back.
__device__ bool native_access_canonical(RiscvQm31 v) {
 return v.a<0x7fffffffu&&v.b<0x7fffffffu&&v.c<0x7fffffffu&&v.d<0x7fffffffu;
}
__global__ void native_access_fraction_rows(const uint* denominators,uint* streams,uint* terms,uint*status,uint rows) {
 uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=rows)return;
 RiscvQm31 active=framework_load(denominators,rows,17u,row);
 if(active.a>1u||(active.b|active.c|active.d)){atomicOr(status,1u);return;}
 // Montgomery's trick across this row's seventeen independent denominators.
 // Keep the same seventeen-element local array as the scalar path: it holds
 // inclusive products first and exact inverses after the backward pass.
 // No new arena plane, launch, transcript value, or host work is introduced.
 RiscvQm31 inverse[17];
 for(uint i=0;i<17u;i++){
  RiscvQm31 d=framework_load(denominators,rows,i,row);
  if(!native_access_canonical(d)){atomicOr(status,2u);return;}
  if(active.a&&!(d.a|d.b|d.c|d.d)){atomicOr(status,4u);return;}
  inverse[i]=active.a?(i?riscv_qm_mul(inverse[i-1u],d):d):RiscvQm31{0u,0u,0u,0u};
 }
 if(active.a){
  RiscvQm31 suffix=framework_inverse(inverse[16]);
  for(uint i=16u;i>0u;i--){
   const RiscvQm31 d=framework_load(denominators,rows,i,row);
   inverse[i]=riscv_qm_mul(suffix,inverse[i-1u]);
   suffix=riscv_qm_mul(suffix,d);
  }
  inverse[0]=suffix;
 }
 framework_store(terms,rows,0,row,inverse[0]);
 framework_store(terms,rows,1,row,inverse[1]);
 framework_store(terms,rows,2,row,inverse[2]);
 const ulong stride=4ul*rows+4u;
 framework_store(streams,rows,0,row,inverse[0]);
 framework_store(streams+stride,rows,0,row,active);
 for(uint i=0;i<7u;i++)framework_store(streams+(2u+i)*stride,rows,0,row,riscv_qm_add(inverse[3+2*i],inverse[4+2*i]));
 framework_store(streams+9u*stride,rows,0,row,riscv_qm_sub(inverse[1],inverse[2]));
}
__global__ void native_access_scatter_rows(const uint*streams,const uint*terms,uint*output,uint*claims,uint*status,uint rows){
 uint row=blockIdx.x*blockDim.x+threadIdx.x;if(row>=rows)return;
 const ulong stride=4ul*rows+4u;
 for(uint limb=0;limb<4u;limb++){
  output[ulong(limb)*rows+row]=terms[ulong(limb)*rows+row];
  output[ulong(4u+limb)*rows+row]=streams[ulong(limb)*rows+row];
  output[ulong(37u+limb)*rows+row]=terms[ulong(4u+limb)*rows+row];
  output[ulong(41u+limb)*rows+row]=terms[ulong(8u+limb)*rows+row];
  output[ulong(45u+limb)*rows+row]=streams[9u*stride+ulong(limb)*rows+row];
  for(uint i=0;i<7u;i++)output[ulong(9u+4u*i+limb)*rows+row]=streams[(2u+i)*stride+ulong(limb)*rows+row];
 }
 RiscvQm31 count=framework_load(streams+stride,rows,0,row);
 if(count.b|count.c|count.d)atomicOr(status,8u);
 output[8ul*rows+row]=count.a;
 if(row==0u)for(uint i=0;i<10u;i++)for(uint limb=0;limb<4u;limb++)claims[4u*i+limb]=streams[i*stride+4ul*rows+limb];
}
