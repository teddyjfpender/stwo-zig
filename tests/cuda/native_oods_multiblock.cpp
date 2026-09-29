// Production-size coefficient sampling against independent scalar arithmetic.
#include "oods_reference.h"
#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <vector>
using namespace oods_reference;
extern "C" int stwo_oods_eval_first_on(const M31*,size_t,uint32_t,uint32_t,const QM31*,QM31*,void*);
extern "C" int stwo_oods_eval_reduce_on(const QM31*,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,const QM31*,QM31*,uint32_t,void*);
bool ok(int status) { if(status) std::fprintf(stderr,"CUDA: %s\n",cudaGetErrorString((cudaError_t)status)); return status==0; }
int main() {
 cudaStream_t stream; if(!ok(cudaStreamCreate(&stream))) return 1;
 for(uint32_t log : {13u,14u,18u,20u,22u}) {
  uint32_t n=1u<<log, blocks=n/4096u, state=0x89101234u;
  std::vector<M31> coefficients(n);
  for(auto& value:coefficients) { state^=state<<13;state^=state>>17;state^=state<<5;value=state%prime; }
  auto point=derive_point(QM31{{7,2},{3,4}}, CirclePoint{1,0});
  auto factors=folding_factors(point,log);auto expected=evaluate(coefficients,factors);
  M31* c;QM31 *f,*a,*b;
  if(!ok(cudaMalloc(&c,n*sizeof(M31)))||!ok(cudaMalloc(&f,log*sizeof(QM31)))||!ok(cudaMalloc(&a,blocks*sizeof(QM31)))||!ok(cudaMalloc(&b,blocks*sizeof(QM31)))) return 1;
  if(!ok(cudaMemcpyAsync(c,coefficients.data(),n*sizeof(M31),cudaMemcpyHostToDevice,stream))||!ok(cudaMemcpyAsync(f,factors.data(),log*sizeof(QM31),cudaMemcpyHostToDevice,stream)))return 1;
  if(!ok(stwo_oods_eval_first_on(c,n,n,1,f,a,stream)))return 1;
  auto input=a;auto output=b;uint32_t count=blocks;
  while(count>1) { uint32_t index=0;for(auto x=count;x>2;x>>=1)++index;uint32_t next=(count+511)/512;
   if(!ok(stwo_oods_eval_reduce_on(input,count,count,index,log,1,f,output,next,stream)))return 1;
   auto tmp=input;input=output;output=tmp;count=next;
  }
  QM31 actual;if(!ok(cudaMemcpyAsync(&actual,input,sizeof(actual),cudaMemcpyDeviceToHost,stream))||!ok(cudaStreamSynchronize(stream)))return 1;
  if(!equal(actual,expected)) { std::fprintf(stderr,"log %u mismatch actual=%u,%u,%u,%u expected=%u,%u,%u,%u\n",log,actual.a.a,actual.a.b,actual.b.a,actual.b.b,expected.a.a,expected.a.b,expected.b.a,expected.b.b);return 1; }
  std::printf("log %u coefficient sampling passed\n",log);
  cudaFree(c);cudaFree(f);cudaFree(a);cudaFree(b);
 }
 cudaStreamDestroy(stream);return 0;
}
