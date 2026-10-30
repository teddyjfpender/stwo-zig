#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <vector>
#include <stdexcept>
#include "kernels.cu"
const void *fraction(unsigned);const void *scan(unsigned);
static void ck(cudaError_t e){if(e!=cudaSuccess)throw std::runtime_error(cudaGetErrorString(e));}
static std::uint32_t word(std::ifstream&f){std::uint32_t x;f.read((char*)&x,4);if(!f)throw std::runtime_error("truncated vector");return x;}
static std::vector<std::uint32_t> read(std::ifstream&f){auto n=word(f);if(n>(1u<<27))throw std::runtime_error("vector bound");std::vector<std::uint32_t> v(n);f.read((char*)v.data(),n*4);if(!f)throw std::runtime_error("truncated vector");return v;}
int main(int argc,char**argv){try{
 if(argc!=2)throw std::runtime_error("interaction_numeric.bin required");std::ifstream f(argv[1],std::ios::binary);auto cases=word(f);std::size_t checked=0,negative=0,launches=0;
 for(unsigned c=0;c<cases;++c){auto id=word(f),rows=word(f),batches=word(f),layout=word(f),want_status=word(f),blocks=(rows+255)/256,scans=layout==1?1:batches;
 std::vector<std::uint32_t> v[6];for(auto&i:v)i=read(f);void*d[8]={};
 for(unsigned i=0;i<5;++i){ck(cudaMalloc(&d[i],std::max(std::size_t(4),v[i].size()*4)));if(!v[i].empty())ck(cudaMemcpy(d[i],v[i].data(),v[i].size()*4,cudaMemcpyHostToDevice));}
 ck(cudaMalloc(&d[5],v[5].size()*4));ck(cudaMemset(d[5],0xa5,v[5].size()*4));ck(cudaMalloc(&d[6],4));ck(cudaMemset(d[6],0,4));ck(cudaMalloc(&d[7],scans*blocks*16));
 void*args[]={&d[0],&d[1],&d[2],&d[3],&d[4],&d[5],&d[6],&rows};
 ck(cudaLaunchKernel(fraction(id),dim3((rows+127)/128),dim3(128),args,0,nullptr));++launches;ck(cudaDeviceSynchronize());unsigned status=0;ck(cudaMemcpy(&status,d[6],4,cudaMemcpyDeviceToHost));
 if(status!=want_status){std::fprintf(stderr,"STATUS case=%u kernel=%u got=%u expected=%u\n",c,id,status,want_status);return 3;}
 if(status){++negative;for(auto ptr:d)ck(cudaFree(ptr));continue;}
 void*sargs[]={&d[5],&d[7],&rows,&blocks,&batches,&layout};
 ck(cudaLaunchKernel(scan(0),dim3(scans*blocks),dim3(256),sargs,0,nullptr));
 ck(cudaLaunchKernel(scan(1),dim3((scans+127)/128),dim3(128),sargs,0,nullptr));
 ck(cudaLaunchKernel(scan(2),dim3((rows+127)/128,scans),dim3(128),sargs,0,nullptr));launches+=3;
 ck(cudaDeviceSynchronize());std::vector<std::uint32_t> actual(v[5].size());ck(cudaMemcpy(actual.data(),d[5],actual.size()*4,cudaMemcpyDeviceToHost));
 for(unsigned i=0;i<actual.size();++i)if(actual[i]!=v[5][i]){std::fprintf(stderr,"MISMATCH case=%u kernel=%u rows=%u layout=%u word=%u got=%u expected=%u\n",c,id,rows,layout,i,actual[i],v[5][i]);return 2;}
 for(auto ptr:d)ck(cudaFree(ptr));checked+=actual.size();
 }
 if(f.peek()!=EOF)throw std::runtime_error("trailing vector data");std::printf("CUDA_FRAMEWORK_INTERACTION_NUMERIC PASS cases=%u negatives=%zu checked_words=%zu kernel_launches=%zu\n",cases,negative,checked,launches);return 0;
}catch(const std::exception&e){std::fprintf(stderr,"ERROR %s\n",e.what());return 1;}}
