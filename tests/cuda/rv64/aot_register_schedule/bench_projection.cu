// T5 parity + CUDA-event microbenchmark for source-projection kernels (launch_N geometry:
// grid (rows+127)/128, block 128). Before = admitted object, after = launch-bounded copy.
#include <cuda_runtime.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include "bench_proj_case.h"  // BENCH_BEFORE, BENCH_AFTER, BENCH_CASE_NAME, mask_tree[], mask_count, parameter_count, public_count, lanes
extern "C" __global__ void BENCH_BEFORE(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t*);
extern "C" __global__ void BENCH_AFTER(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t*);
typedef void (*Kernel)(const uint32_t*,const uint32_t*,const uint32_t*,const uint64_t*,const uint32_t*,uint32_t*,uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t*);
#define CK(x) do{cudaError_t e=(x);if(e!=cudaSuccess){fprintf(stderr,"%s:%d %s\n",__FILE__,__LINE__,cudaGetErrorString(e));exit(1);}}while(0)
__global__ void fill(uint32_t *p,uint64_t n,uint64_t seed){
  for(uint64_t i=blockIdx.x*uint64_t(blockDim.x)+threadIdx.x;i<n;i+=uint64_t(gridDim.x)*blockDim.x){
    uint64_t x=(i+1)*0x9E3779B97F4A7C15ull^seed; x^=x>>31; x*=0xBF58476D1CE4E5B9ull; x^=x>>29; p[i]=uint32_t(x%2147483647ull);}
}
static uint32_t *dev_random(uint64_t n,uint64_t seed){uint32_t *p;CK(cudaMalloc(&p,std::max<uint64_t>(n,1)*4));fill<<<1024,256>>>(p,std::max<uint64_t>(n,1),seed);CK(cudaGetLastError());return p;}
int main(int argc,char**argv){
  const uint32_t log=argc>1?atoi(argv[1]):20, reps=argc>2?atoi(argv[2]):7;
  const uint64_t rows=uint64_t(1)<<log;
  uint64_t cols[2]={0,0}; std::vector<uint64_t> offsets(mask_count,0);
  for(uint32_t k=0;k<mask_count;++k) if(mask_tree[k]<2) offsets[k]=(cols[mask_tree[k]]++)*rows;
  uint32_t *tree[2]; for(int t=0;t<2;++t) tree[t]=dev_random(cols[t]*rows,0x1000+t);
  uint64_t *doff;CK(cudaMalloc(&doff,std::max<uint32_t>(mask_count,1)*8));CK(cudaMemcpy(doff,offsets.data(),mask_count*8,cudaMemcpyHostToDevice));
  uint32_t *params=dev_random(8*parameter_count,0x2000),*pub=dev_random(public_count,0x3000);
  uint32_t *n[2],*d[2],*st[2];
  for(int i=0;i<2;++i){CK(cudaMalloc(&n[i],rows*lanes*4));CK(cudaMalloc(&d[i],8*rows*lanes*4));CK(cudaMalloc(&st[i],4));}
  Kernel ks[2]={BENCH_BEFORE,BENCH_AFTER};
  auto launch=[&](int i){CK(cudaMemset(n[i],0xab,rows*lanes*4));CK(cudaMemset(d[i],0xcd,8*rows*lanes*4));CK(cudaMemset(st[i],0,4));
    ks[i]<<<(rows+127)/128,128>>>(tree[0],tree[1],pub,doff,params,n[i],d[i],log,0,uint32_t(rows),st[i]);CK(cudaGetLastError());};
  launch(0);launch(1);CK(cudaDeviceSynchronize());
  std::vector<uint32_t> a(9*rows*lanes+1),b(9*rows*lanes+1);
  CK(cudaMemcpy(a.data(),n[0],rows*lanes*4,cudaMemcpyDeviceToHost));CK(cudaMemcpy(a.data()+rows*lanes,d[0],8*rows*lanes*4,cudaMemcpyDeviceToHost));CK(cudaMemcpy(a.data()+9*rows*lanes,st[0],4,cudaMemcpyDeviceToHost));
  CK(cudaMemcpy(b.data(),n[1],rows*lanes*4,cudaMemcpyDeviceToHost));CK(cudaMemcpy(b.data()+rows*lanes,d[1],8*rows*lanes*4,cudaMemcpyDeviceToHost));CK(cudaMemcpy(b.data()+9*rows*lanes,st[1],4,cudaMemcpyDeviceToHost));
  uint64_t diff=0; for(size_t i=0;i<a.size();++i) diff+=a[i]!=b[i];
  printf("{\"case\":\"%s\",\"log\":%u,\"rows\":%llu,\"lanes\":%u,\"status\":%u,\"parity_words_differing\":%llu",BENCH_CASE_NAME,log,(unsigned long long)rows,lanes,a.back(),(unsigned long long)diff);
  cudaEvent_t e0,e1;CK(cudaEventCreate(&e0));CK(cudaEventCreate(&e1)); std::vector<float> ms[2];
  for(uint32_t r=0;r<reps+1;++r) for(int i=0;i<2;++i){
    CK(cudaEventRecord(e0)); ks[i]<<<(rows+127)/128,128>>>(tree[0],tree[1],pub,doff,params,n[i],d[i],log,0,uint32_t(rows),st[i]);
    CK(cudaEventRecord(e1));CK(cudaEventSynchronize(e1));CK(cudaGetLastError()); float t;CK(cudaEventElapsedTime(&t,e0,e1)); if(r) ms[i].push_back(t);}
  const char *names[2]={"before","after"};
  for(int i=0;i<2;++i){auto v=ms[i];std::sort(v.begin(),v.end());printf(",\"%s_ms\":{\"median\":%.4f,\"min\":%.4f,\"max\":%.4f,\"reps\":%zu}",names[i],v[v.size()/2],v.front(),v.back(),v.size());}
  printf("}\n"); return diff?2:0;
}
