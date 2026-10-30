// Independent original Zig epoch outputs are test oracles, never GPU inputs.
#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <vector>
struct Channel { uint32_t digest[8], counter[2], error_code; };
static_assert(sizeof(Channel)==44);
extern "C" int stwo_blake3_channel_on(Channel*,uint32_t*,size_t,uint32_t,uint32_t,uint32_t,void*);
static void check(cudaError_t e){if(e!=cudaSuccess)throw std::runtime_error(cudaGetErrorString(e));}
struct Buffer {void*p=nullptr; explicit Buffer(size_t n){check(cudaMalloc(&p,n));}~Buffer(){cudaFree(p);}uint32_t*words(){return static_cast<uint32_t*>(p);}};
static uint32_t read(std::ifstream&f){unsigned char b[4];if(!f.read(reinterpret_cast<char*>(b),4))throw std::runtime_error("truncated oracle");return uint32_t(b[0])|(uint32_t(b[1])<<8)|(uint32_t(b[2])<<16)|(uint32_t(b[3])<<24);}
int main(int argc,char**argv)try{
 if(argc!=2)throw std::runtime_error("original Zig oracle required");std::ifstream f(argv[1],std::ios::binary);auto cases=read(f);if(cases!=32)throw std::runtime_error("oracle coverage");
 cudaStream_t stream;check(cudaStreamCreateWithFlags(&stream,cudaStreamNonBlocking));uint64_t compared=0;float total_ms=0;
 for(uint32_t c=0;c<cases;c++){
  auto n=read(f);if(n<3||n>1024)throw std::runtime_error("word geometry");std::vector<uint32_t> words(n);for(auto&v:words)v=read(f);
  uint32_t epoch[8];for(auto&v:epoch)v=read(f);auto ns=read(f);if(ns>1024)throw std::runtime_error("step geometry");
  struct Step{uint32_t op,first,count;};std::vector<Step> steps(ns);for(auto&s:steps){s.op=read(f);s.first=read(f);s.count=read(f);if((s.op!=1&&s.op!=5)||s.first> (s.op==1?n:106)||s.count>(s.op==1?n:106)-s.first)throw std::runtime_error("step bounds");}
  std::vector<uint32_t> expected(424);for(auto&v:expected)v=read(f);Channel wanted{};for(auto&v:wanted.digest)v=read(f);for(auto&v:wanted.counter)v=read(f);
  Buffer state(sizeof(Channel)),metadata(n*4),root(32),output(424*4);check(cudaMemcpyAsync(metadata.p,words.data(),n*4,cudaMemcpyHostToDevice,stream));check(cudaMemcpyAsync(root.p,epoch,32,cudaMemcpyHostToDevice,stream));
  auto channel=[&](uint32_t*data,size_t capacity,uint32_t count,uint32_t op){check(static_cast<cudaError_t>(stwo_blake3_channel_on(static_cast<Channel*>(state.p),data,capacity,count,op,1024,stream)));};
  cudaEvent_t begin,end;check(cudaEventCreate(&begin));check(cudaEventCreate(&end));check(cudaEventRecord(begin,stream));channel(nullptr,0,0,0);channel(metadata.words(),3,3,1);channel(root.words(),8,8,4);
  for(auto&s:steps)if(s.op==1)channel(metadata.words()+s.first,s.count,s.count,1);else channel(output.words()+4*s.first,4*s.count,s.count,5);
  check(cudaEventRecord(end,stream));check(cudaEventSynchronize(end));float ms=0;check(cudaEventElapsedTime(&ms,begin,end));total_ms+=ms;
  Channel got{};std::vector<uint32_t> actual(424);check(cudaMemcpyAsync(&got,state.p,sizeof(got),cudaMemcpyDeviceToHost,stream));check(cudaMemcpyAsync(actual.data(),output.p,424*4,cudaMemcpyDeviceToHost,stream));check(cudaStreamSynchronize(stream));
  if(got.error_code)throw std::runtime_error("honest epoch poisoned");for(size_t i=0;i<424;i++)if(actual[i]!=expected[i])throw std::runtime_error("original challenge mismatch");for(int i=0;i<8;i++)if(got.digest[i]!=wanted.digest[i])throw std::runtime_error("final digest mismatch");for(int i=0;i<2;i++)if(got.counter[i]!=wanted.counter[i])throw std::runtime_error("single/pair consumption mismatch");
  compared+=434;check(cudaEventDestroy(begin));check(cudaEventDestroy(end));
 }
 if(f.peek()!=std::char_traits<char>::eof())throw std::runtime_error("oracle tail");check(cudaStreamDestroy(stream));std::printf("{\"status\":\"pass\",\"scope\":\"native_epoch_transcript_primitive\",\"cases\":%u,\"secure_outputs_per_case\":106,\"compared_words\":%llu,\"device_total_ns\":%.0f,\"full_native_proof_qualified\":false}\n",cases,(unsigned long long)compared,total_ms*1e6);return 0;
}catch(const std::exception&e){std::fprintf(stderr,"NATIVE_EPOCH_FAILED %s\n",e.what());return 1;}
