// Appended after exact Zig->C device fold. Runtime values never leave GPU.
#include <cuda_runtime.h>
#include <stdint.h>
static constexpr uint32_t stwo_fri_max_queries=128;
__global__ void stwo_fri_expand_kernel_v1(
 const uint32_t* raw_queries,uint32_t nq,const uint32_t* deep,
 const uint32_t* input_positions,const uint32_t* input_values,const uint32_t* input_count,
 const uint32_t* witness,uint32_t witness_count,const uint32_t* alpha,
 uint32_t domain_log,uint32_t fold_log,uint32_t shift,uint32_t first,
 uint32_t* positions,uint32_t* values,uint32_t* count,
 uint32_t* subset_scratch,uint32_t* expanded,uint32_t* status) {
 __shared__ uint32_t pos[128],eval[128][4],beg[128],end[128],groups,nknown,failed;
 uint32_t t=threadIdx.x,width=1u<<fold_log;
 if(t==0){
  failed=0;groups=0;nknown=first?nq:*input_count;
  if(!nknown||nknown>nq||nknown>128)failed=1;
  if(!failed)for(uint32_t i=0;i<nknown;i++){
   pos[i]=first?raw_queries[i]:input_positions[i];
   for(uint32_t c=0;c<4;c++)eval[i][c]=first?deep[i*4+c]:input_values[i*4+c];
   if(pos[i]>=(1u<<domain_log))failed=1;
   for(uint32_t c=0;c<4;c++)if(eval[i][c]>=2147483647u)failed=1;
  }
  if(!failed&&first){
   for(uint32_t i=1;i<nknown;i++){
    uint32_t p=pos[i],q[4];for(uint32_t c=0;c<4;c++)q[c]=eval[i][c];
    uint32_t j=i;while(j&&pos[j-1]>p){pos[j]=pos[j-1];for(uint32_t c=0;c<4;c++)eval[j][c]=eval[j-1][c];j--;}
    pos[j]=p;for(uint32_t c=0;c<4;c++)eval[j][c]=q[c];
   }
   uint32_t used=0;
   for(uint32_t i=0;i<nknown;i++){
    if(used&&pos[used-1]==pos[i]){for(uint32_t c=0;c<4;c++)if(eval[used-1][c]!=eval[i][c])failed=1;}
    else {pos[used]=pos[i];for(uint32_t c=0;c<4;c++)eval[used][c]=eval[i][c];used++;}
   }
   nknown=used;
  }
  if(!failed){
   for(uint32_t i=0;i<nknown;i++){
    if(i&&pos[i-1]>=pos[i]){failed=1;break;}
    if(!i||(pos[i]>>fold_log)!=(pos[i-1]>>fold_log)){
     if(groups)end[groups-1]=i;beg[groups++]=i;
    }
   }
   if(groups)end[groups-1]=nknown;
   if(groups*width-nknown!=witness_count)failed=1;
  }
  if(failed){atomicOr(status,1u<<14);*count=0;}
 }
 __syncthreads();if(failed)return;
 if(t<groups){
  uint32_t start=(pos[beg[t]]>>fold_log)<<fold_log;
  uint32_t next=beg[t],wi=t*width-beg[t];
  uint32_t* subset=subset_scratch+(size_t)t*width*4;
  for(uint32_t k=0;k<width;k++){
   const uint32_t* value=(next<end[t]&&pos[next]==start+k)?eval[next++]:witness+(size_t)wi++*4;
   for(uint32_t c=0;c<4;c++)subset[k*4+c]=value[c];
  }
  uint32_t result=stwo_parent_fri_subset_fold_v1(first,domain_log,fold_log,start,subset,
   reinterpret_cast<const uint32_t (*)[4]>(alpha),reinterpret_cast<uint32_t (*)[4]>(values+t*4));
  if(result)atomicOr(status,1u<<15);
  positions[t]=start>>fold_log;
 }
 __syncthreads();
 if(t==0)*count=groups;
 if(t<nq){
  uint32_t q=raw_queries[t]>>shift;
  if(q>=(1u<<domain_log)){atomicOr(status,1u<<16);return;}
  uint32_t group=q>>fold_log,g=0;while(g<groups&&positions[g]!=group)g++;
  if(g==groups){atomicOr(status,1u<<17);return;}
  for(uint32_t k=0;k<width*4;k++)expanded[(size_t)t*width*4+k]=subset_scratch[(size_t)g*width*4+k];
 }
}
extern "C" int stwo_parent_fri_expand_v1(
 const uint32_t* raw_queries,uint32_t nq,const uint32_t* deep,
 const uint32_t* input_positions,const uint32_t* input_values,const uint32_t* input_count,
 const uint32_t* witness,uint32_t witness_count,const uint32_t* alpha,
 uint32_t domain_log,uint32_t fold_log,uint32_t shift,uint32_t first,
 uint32_t* positions,uint32_t* values,uint32_t* count,uint32_t* scratch,uint32_t* expanded,uint32_t* status,cudaStream_t stream){
 if(!stream||!raw_queries||!nq||nq>128||!deep||!alpha||!domain_log||domain_log>30||!fold_log||fold_log>5||fold_log>domain_log||shift>30-domain_log||first>1||!positions||!values||!count||!scratch||!expanded||!status||
  (witness_count&&!witness)||witness_count>nq*(1u<<fold_log)||(!first&&(!input_positions||!input_values||!input_count)))return (int)cudaErrorInvalidValue;
 stwo_fri_expand_kernel_v1<<<1,128,0,stream>>>(raw_queries,nq,deep,input_positions,input_values,input_count,witness,witness_count,alpha,domain_log,fold_log,shift,first,positions,values,count,scratch,expanded,status);
 return (int)cudaGetLastError();
}
