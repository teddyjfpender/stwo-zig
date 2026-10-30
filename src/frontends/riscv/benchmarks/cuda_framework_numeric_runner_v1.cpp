#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <vector>
#include <stdexcept>
#include "kernels.cu"
const void *kernel(unsigned);
static void ck(cudaError_t e){if(e!=cudaSuccess)throw std::runtime_error(cudaGetErrorString(e));}
static std::uint32_t word(std::ifstream&f){std::uint32_t x;f.read((char*)&x,4);if(!f)throw std::runtime_error("truncated vector");return x;}
static std::vector<std::uint32_t> read(std::ifstream&f){auto n=word(f);if(n>(1u<<26))throw std::runtime_error("vector bound");std::vector<std::uint32_t> v(n);f.read((char*)v.data(),n*4);if(!f)throw std::runtime_error("truncated vector");return v;}
int main(int argc,char**argv){try{
 if(argc!=2)throw std::runtime_error("numeric.bin required");std::ifstream f(argv[1],std::ios::binary);auto cases=word(f);std::size_t checked=0;
 for(unsigned c=0;c<cases;++c){auto id=word(f),rows=word(f),den=word(f);std::vector<std::uint32_t> v[10];void*d[9]={};for(auto&i:v)i=read(f);
 for(unsigned i=0;i<9;++i){ck(cudaMalloc(&d[i],std::max(std::size_t(4),v[i].size()*4)));if(!v[i].empty())ck(cudaMemcpy(d[i],v[i].data(),v[i].size()*4,cudaMemcpyHostToDevice));}
 // vector order: trees3, offsets, profile, relations, powers, denominators, output, expected.
 void*args[]={&d[0],&d[1],&d[2],&d[3],&d[4],&d[5],&d[6],&d[8],&rows,&d[7],&den};
 for(unsigned repeat=0;repeat<2;++repeat)ck(cudaLaunchKernel(kernel(id),dim3((rows+127)/128),dim3(128),args,0,nullptr));
 ck(cudaDeviceSynchronize());ck(cudaMemcpy(v[8].data(),d[8],v[8].size()*4,cudaMemcpyDeviceToHost));
 for(unsigned i=0;i<v[9].size();++i)if(v[8][i]!=v[9][i]){std::fprintf(stderr,"MISMATCH case=%u kernel=%u rowcoord=%u got=%u expected=%u\n",c,id,i,v[8][i],v[9][i]);return 2;}
 for(auto ptr:d)ck(cudaFree(ptr));checked+=v[9].size();
 }
 if(f.peek()!=EOF)throw std::runtime_error("trailing vector data");std::printf("CUDA_FRAMEWORK_NUMERIC PASS cases=%u checked_words=%zu\n",cases,checked);return 0;
}catch(const std::exception&e){std::fprintf(stderr,"ERROR %s\n",e.what());return 1;}}
