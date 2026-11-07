// T5 parity + CUDA-event microbenchmark: admitted AOT constraint shard vs its
// register-scheduled lowering. Same launch geometry as composition_dispatch
// (grid (rows/128, groups), block 128). Both kernels read identical inputs and
// start from identical output; the outputs must be bit-identical.
#include <cuda_runtime.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "bench_case.h"  // BENCH_BEFORE, BENCH_AFTER, mask_tree[], mask_count, parameter_count, power_count, groups
typedef void (*Kernel)(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t);
extern "C" __global__ void BENCH_BEFORE(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t);
extern "C" __global__ void BENCH_AFTER(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t);
#define CK(x) do{cudaError_t e=(x);if(e!=cudaSuccess){fprintf(stderr,"%s:%d %s\n",__FILE__,__LINE__,cudaGetErrorString(e));exit(1);}}while(0)
__global__ void fill(uint32_t *p,uint64_t n,uint64_t seed){
  for(uint64_t i=blockIdx.x*uint64_t(blockDim.x)+threadIdx.x;i<n;i+=uint64_t(gridDim.x)*blockDim.x){
    uint64_t x=(i+1)*0x9E3779B97F4A7C15ull^seed; x^=x>>31; x*=0xBF58476D1CE4E5B9ull; x^=x>>29;
    p[i]=uint32_t(x%2147483647ull);
  }
}
static uint32_t *dev_random(uint64_t n,uint64_t seed){uint32_t *p;CK(cudaMalloc(&p,std::max<uint64_t>(n,1)*4));fill<<<1024,256>>>(p,std::max<uint64_t>(n,1),seed);CK(cudaGetLastError());return p;}
int main(int argc,char**argv){
  const uint32_t el=argc>1?atoi(argv[1]):18, tl=argc>2?atoi(argv[2]):17, reps=argc>3?atoi(argv[3]):7;
  // argv[4] (optional): alias masks onto at most this many distinct columns per tree. Parity holds for
  // any data; timings are then cache-friendlier than production for BOTH arms (reported as alias_cols).
  const uint64_t alias=argc>4?atoll(argv[4]):0;
  const uint64_t rows=uint64_t(1)<<el;
  size_t free0=0,free1=0,total=0;
  CK(cudaFree(0)); CK(cudaMemGetInfo(&free0,&total));
  // Force-load both kernels so the context sizes its local-memory reservation for their frames.
  cudaFuncAttributes fa[2]; CK(cudaFuncGetAttributes(&fa[0],(const void*)BENCH_BEFORE)); CK(cudaFuncGetAttributes(&fa[1],(const void*)BENCH_AFTER));
  CK(cudaMemGetInfo(&free1,&total));
  fprintf(stderr,"{\"free_after_context_mib\":%zu,\"free_after_module_load_mib\":%zu,\"before_local_bytes\":%zu,\"after_local_bytes\":%zu,\"before_regs\":%d,\"after_regs\":%d}\n",free0>>20,free1>>20,fa[0].localSizeBytes,fa[1].localSizeBytes,fa[0].numRegs,fa[1].numRegs);
  uint64_t cols[3]={0,0,0};
  std::vector<uint64_t> offsets(mask_count,0);
  for(uint32_t k=0;k<mask_count;++k) if(mask_tree[k]<3) {
    const uint64_t c=cols[mask_tree[k]]++;
    offsets[k]=(alias?c%alias:c)*rows;
  }
  if(alias) for(int t=0;t<3;++t) cols[t]=std::min(cols[t],alias);
  uint32_t *tree[3];
  for(int t=0;t<3;++t) tree[t]=dev_random(cols[t]*rows,0x1000+t);
  uint64_t *doff;CK(cudaMalloc(&doff,mask_count*8));CK(cudaMemcpy(doff,offsets.data(),mask_count*8,cudaMemcpyHostToDevice));
  uint32_t *params=dev_random(8*parameter_count,0x2000),*powers=dev_random(8*power_count,0x3000),*inv=dev_random(1u<<(el-tl),0x4000);
  uint32_t *init=dev_random(8*rows,0x5000),*out[2];
  for(int i=0;i<2;++i)CK(cudaMalloc(&out[i],8*rows*4));
  Kernel ks[2]={BENCH_BEFORE,BENCH_AFTER};
  const char *names[2]={"before","after"};
  dim3 grid((rows+127)/128,groups),block(128);
  CK(cudaDeviceSynchronize());
  // parity
  for(int i=0;i<2;++i){CK(cudaMemcpy(out[i],init,8*rows*4,cudaMemcpyDeviceToDevice));
    ks[i]<<<grid,block>>>(tree[0],tree[1],tree[2],doff,params,powers,inv,out[i],tl,el,0,uint32_t(rows));CK(cudaGetLastError());}
  CK(cudaDeviceSynchronize());
  std::vector<uint32_t> h0(8*rows),h1(8*rows);
  CK(cudaMemcpy(h0.data(),out[0],8*rows*4,cudaMemcpyDeviceToHost));CK(cudaMemcpy(h1.data(),out[1],8*rows*4,cudaMemcpyDeviceToHost));
  uint64_t diff=0,changed=0; for(uint64_t i=0;i<8*rows;++i){diff+=h0[i]!=h1[i];}
  std::vector<uint32_t> hi(8*rows);CK(cudaMemcpy(hi.data(),init,8*rows*4,cudaMemcpyDeviceToHost));
  for(uint64_t i=0;i<8*rows;++i) changed+=h0[i]!=hi[i];
  printf("{\"case\":\"%s\",\"eval_log\":%u,\"trace_log\":%u,\"rows\":%llu,\"masks\":%u,\"cols\":[%llu,%llu,%llu],\"alias_cols\":%llu,\"parity_words_differing\":%llu,\"output_words_changed\":%llu",
    BENCH_CASE_NAME,el,tl,(unsigned long long)rows,mask_count,(unsigned long long)cols[0],(unsigned long long)cols[1],(unsigned long long)cols[2],(unsigned long long)alias,(unsigned long long)diff,(unsigned long long)changed);
  cudaEvent_t a,b;CK(cudaEventCreate(&a));CK(cudaEventCreate(&b));
  std::vector<float> ms[2];
  for(uint32_t r=0;r<reps+1;++r) for(int i=0;i<2;++i){   // interleaved A/B; rep 0 is warmup
    CK(cudaEventRecord(a));
    ks[i]<<<grid,block>>>(tree[0],tree[1],tree[2],doff,params,powers,inv,out[i],tl,el,0,uint32_t(rows));
    CK(cudaEventRecord(b));CK(cudaEventSynchronize(b));CK(cudaGetLastError());
    float t;CK(cudaEventElapsedTime(&t,a,b)); if(r) ms[i].push_back(t);
  }
  for(int i=0;i<2;++i){auto v=ms[i];std::sort(v.begin(),v.end());
    printf(",\"%s_ms\":{\"median\":%.4f,\"min\":%.4f,\"max\":%.4f,\"reps\":%zu}",names[i],v[v.size()/2],v.front(),v.back(),v.size());}
  printf("}\n");
  return diff?2:0;
}
