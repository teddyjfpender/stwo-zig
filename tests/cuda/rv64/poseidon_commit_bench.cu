// Actual resident column slab -> retained complete Merkle tree. No FFT, transfer,
// host setup, proof or Ethereum timing. P2 is the new numerical prototype.
#include <cuda_runtime.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <vector>
#include <cstring>
#if defined(STWO_P2_FAST_REDUCTION) && defined(STWO_P2_FUSED)
#error "Select one numerical Poseidon variant"
#endif
#ifdef STWO_P2_FUSED
#include "poseidon2_m31_fused.cuh"
#elif defined(STWO_P2_FAST_REDUCTION)
#include "poseidon2_m31_fast.cuh"
#else
#include "poseidon2_m31.cuh"
#endif
#include "blake2s_core.cuh"
#ifdef STWO_P2_FUSED
namespace P=stwo::cuda::p2m31_fused;
static constexpr const char* p2_variant="fused-pipe-balanced-v1";
#elif defined(STWO_P2_FAST_REDUCTION)
namespace P=stwo::cuda::p2m31;
static constexpr const char* p2_variant="generated-fast-reduction";
#else
namespace P=stwo::cuda::p2m31;
static constexpr const char* p2_variant="original-prototype";
#endif
using Hash=stwo::cuda::blake2s::Hash;
extern "C" int stwo_blake2s_contiguous_leaf_on(uint32_t,const uint32_t*,size_t,size_t,Hash*,void*);
extern "C" int stwo_blake2s_layer_on(const Hash*,uint32_t,Hash*,void*);
extern "C" int stwo_blake2s_contiguous_tail_on(const Hash*,uint32_t,Hash*,size_t,uint32_t,void*);
#define CU(x) do{auto e=(x);if(e!=cudaSuccess)throw std::runtime_error(cudaGetErrorString(e));}while(0)
struct Buffer{uint32_t*p=nullptr;size_t words;explicit Buffer(size_t n):words(n){CU(cudaMalloc(&p,n*4));}~Buffer(){if(p)cudaFree(p);}};
__global__ void fill(uint32_t*p,uint64_t n){uint64_t i=uint64_t(blockIdx.x)*blockDim.x+threadIdx.x;if(i<n)p[i]=uint32_t((i*17ull+13ull)%2147483647ull);}
__global__ void p2_tail(const uint32_t*previous,uint32_t n,uint32_t*out,uint32_t levels){
 for(uint32_t level=0;level<levels;++level){uint32_t next=n/2;for(uint32_t i=threadIdx.x;i<next;i+=blockDim.x){
#ifdef STWO_P2_FUSED
 P::hash_parent(previous+uint64_t(i)*18,out+uint64_t(i)*9);
#else
 P::Sponge s(2);for(uint32_t j=0;j<18;++j)s.absorb(previous[uint64_t(i)*18+j]);s.finish(out+uint64_t(i)*9);
#endif
 }__syncthreads();previous=out;out+=uint64_t(next)*9;n=next;}
}
struct Events{cudaEvent_t a,b;Events(){CU(cudaEventCreate(&a));CU(cudaEventCreate(&b));}~Events(){cudaEventDestroy(a);cudaEventDestroy(b);}template<class Fn>float time(cudaStream_t s,Fn f){CU(cudaEventRecord(a,s));f();CU(cudaEventRecord(b,s));CU(cudaEventSynchronize(b));float ms;CU(cudaEventElapsedTime(&ms,a,b));return ms;}};
uint32_t levels(uint32_t n){uint32_t out=0;while(n>1){n/=2;++out;}return out;}
void blake(cudaStream_t stream,Buffer&in,Buffer&tree,uint32_t cols,uint32_t rows){
 CU(cudaError_t(stwo_blake2s_contiguous_leaf_on(rows,in.p,rows,size_t(cols)*rows,reinterpret_cast<Hash*>(tree.p),stream)));
 Hash*previous=reinterpret_cast<Hash*>(tree.p);Hash*out=previous+rows;uint32_t n=rows;
 while(n>1){if(n<=1024){CU(cudaError_t(stwo_blake2s_contiguous_tail_on(previous,n,out,n-1,levels(n),stream)));break;}CU(cudaError_t(stwo_blake2s_layer_on(previous,n/2,out,stream)));previous=out;out+=n/2;n/=2;}
}
void poseidon(cudaStream_t stream,Buffer&in,Buffer&tree,Buffer&status,uint32_t cols,uint32_t rows){
 P::leaves<<<(rows+127)/128,128,0,stream>>>(in.p,cols,rows,tree.p,status.p);CU(cudaPeekAtLastError());
 uint32_t*previous=tree.p,*out=tree.p+uint64_t(rows)*9;uint32_t n=rows;
 while(n>1){if(n<=1024){p2_tail<<<1,256,0,stream>>>(previous,n,out,levels(n));CU(cudaPeekAtLastError());break;}P::parents<<<(n/2+127)/128,128,0,stream>>>(previous,n/2,out,status.p);CU(cudaPeekAtLastError());previous=out;out+=uint64_t(n/2)*9;n/=2;}
}
void dump(const char*kind,uint32_t cols,uint32_t rows,Buffer&tree,uint32_t width){std::vector<uint32_t> v(tree.words);CU(cudaMemcpy(v.data(),tree.p,v.size()*4,cudaMemcpyDeviceToHost));std::printf("TREE %s %u %u",kind,cols,rows);for(auto x:v)std::printf(" %u",x);std::puts("");}
int main(int argc,char**argv){try{
 if(argc<4)throw std::runtime_error("usage: width logrows repeats [dump]");uint32_t cols=std::stoul(argv[1]),log=std::stoul(argv[2]),reps=std::stoul(argv[3]);if(!cols||log<1||log>22||!reps)throw std::runtime_error("geometry");uint32_t rows=1u<<log;
 CU(cudaSetDevice(0));cudaDeviceProp prop;CU(cudaGetDeviceProperties(&prop,0));cudaStream_t stream;CU(cudaStreamCreateWithFlags(&stream,cudaStreamNonBlocking));
 Buffer in(size_t(cols)*rows),bt(size_t(2ull*rows-1)*8),pt(size_t(2ull*rows-1)*9),status(1);CU(cudaMemset(status.p,0,4));fill<<<(in.words+255)/256,256,0,stream>>>(in.p,in.words);CU(cudaStreamSynchronize(stream));
 Events events;std::vector<float>b,p;for(uint32_t r=0;r<reps+2;++r){if(r%2){auto t=events.time(stream,[&]{poseidon(stream,in,pt,status,cols,rows);});if(r>=2)p.push_back(t);t=events.time(stream,[&]{blake(stream,in,bt,cols,rows);});if(r>=2)b.push_back(t);}else{auto t=events.time(stream,[&]{blake(stream,in,bt,cols,rows);});if(r>=2)b.push_back(t);t=events.time(stream,[&]{poseidon(stream,in,pt,status,cols,rows);});if(r>=2)p.push_back(t);}}
 uint32_t flag;CU(cudaMemcpy(&flag,status.p,4,cudaMemcpyDeviceToHost));if(flag)throw std::runtime_error("P2 canonical status");std::vector<uint32_t>br(8),pr(9);CU(cudaMemcpy(br.data(),bt.p+(2ull*rows-2)*8,32,cudaMemcpyDeviceToHost));CU(cudaMemcpy(pr.data(),pt.p+(2ull*rows-2)*9,36,cudaMemcpyDeviceToHost));
 std::printf("BENCH {\"p2_variant\":\"%s\",\"device\":\"%s\",\"columns\":%u,\"log_rows\":%u,\"rows\":%u,\"input_bytes\":%zu,\"retained_blake_bytes\":%zu,\"retained_p2_bytes\":%zu,\"repeats\":%u,\"all_layers_retained\":true,\"fft_included\":false,\"transfer_included\":false,\"blake_ms\":[",p2_variant,prop.name,cols,log,rows,in.words*4,bt.words*4,pt.words*4,reps);for(size_t i=0;i<b.size();++i)std::printf("%s%.9g",i?",":"",b[i]);std::printf("],\"p2_ms\":[");for(size_t i=0;i<p.size();++i)std::printf("%s%.9g",i?",":"",p[i]);std::printf("],\"blake_root\":[");for(int i=0;i<8;++i)std::printf("%s%u",i?",":"",br[i]);std::printf("],\"p2_root\":[");for(int i=0;i<9;++i)std::printf("%s%u",i?",":"",pr[i]);std::puts("]}");
 if(argc>4){dump("blake",cols,rows,bt,8);dump("p2",cols,rows,pt,9);}CU(cudaStreamDestroy(stream));return 0;
 }catch(const std::exception&e){std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
