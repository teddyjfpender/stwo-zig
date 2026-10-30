// Independent CPU-generated original-row oracle; never part of the proving path.
#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>
extern "C" cudaError_t stwo_parent_direct_launch_v1(uint32_t,const uint32_t*,const uint32_t*,uint32_t,uint32_t,uint32_t*,uint32_t*,cudaStream_t);
#define CUDA(x) do{cudaError_t e=(x);if(e!=cudaSuccess){fprintf(stderr,"CUDA %s:%d %s\n",__FILE__,__LINE__,cudaGetErrorString(e));return 2;}}while(0)
int main(int argc,char**argv){
 if(argc!=2)return 2;FILE*f=fopen(argv[1],"rb");if(!f)return 2;fseek(f,0,SEEK_END);size_t bytes=ftell(f);rewind(f);if(bytes%4)return 2;std::vector<uint32_t> data(bytes/4);if(fread(data.data(),1,bytes,f)!=bytes)return 2;fclose(f);
 size_t at=0;auto get=[&](){if(at>=data.size())std::abort();return data[at++];};if(get()!=0x50335257)return 2;uint32_t cases=get();cudaStream_t stream;CUDA(cudaStreamCreate(&stream));uint64_t compared=0;
 for(uint32_t c=0;c<cases;++c){uint32_t family=get(),rows=get(),active=get(),nf=get(),nd=get(),width=get();size_t fp=at;at+=size_t(active)*nf;size_t dp=at;at+=size_t(active)*nd;size_t ep=at;at+=size_t(rows)*width;if(at>data.size())return 2;
  uint32_t *fixed,*dynamic,*output,*status;CUDA(cudaMalloc(&fixed,size_t(active)*nf*4));CUDA(cudaMalloc(&dynamic,size_t(active)*nd*4));CUDA(cudaMalloc(&output,size_t(rows)*width*4));CUDA(cudaMalloc(&status,4));
  CUDA(cudaMemcpyAsync(fixed,data.data()+fp,size_t(active)*nf*4,cudaMemcpyHostToDevice,stream));CUDA(cudaMemcpyAsync(dynamic,data.data()+dp,size_t(active)*nd*4,cudaMemcpyHostToDevice,stream));CUDA(cudaMemsetAsync(output,0xa5,size_t(rows)*width*4,stream));CUDA(cudaMemsetAsync(status,0,4,stream));CUDA(stwo_parent_direct_launch_v1(family,fixed,dynamic,active,rows,output,status,stream));
  std::vector<uint32_t> actual(size_t(rows)*width);uint32_t error=99;CUDA(cudaMemcpyAsync(actual.data(),output,actual.size()*4,cudaMemcpyDeviceToHost,stream));CUDA(cudaMemcpyAsync(&error,status,4,cudaMemcpyDeviceToHost,stream));CUDA(cudaStreamSynchronize(stream));if(error){fprintf(stderr,"family%u status%u\n",family,error);return 1;}
  for(size_t j=0;j<actual.size();++j)if(actual[j]!=data[ep+j]){fprintf(stderr,"family%u word%zu got%u expected%u\n",family,j,actual[j],data[ep+j]);return 1;}compared+=actual.size();
  uint32_t invalid=0x7fffffff;CUDA(cudaMemcpyAsync(fixed,&invalid,4,cudaMemcpyHostToDevice,stream));CUDA(cudaMemsetAsync(status,0,4,stream));CUDA(stwo_parent_direct_launch_v1(family,fixed,dynamic,active,rows,output,status,stream));CUDA(cudaMemcpyAsync(&error,status,4,cudaMemcpyDeviceToHost,stream));CUDA(cudaStreamSynchronize(stream));if(!error){fprintf(stderr,"family%u accepted noncanonical fixed\n",family);return 1;}
  CUDA(cudaFree(fixed));CUDA(cudaFree(dynamic));CUDA(cudaFree(output));CUDA(cudaFree(status));
 }
 CUDA(cudaStreamDestroy(stream));if(at!=data.size())return 2;printf("PASS original parent direct writers families=%u physical_words=%llu hostile_fixed=%u fully_resident_primitive=true\n",cases,(unsigned long long)compared,cases);return 0;
}
