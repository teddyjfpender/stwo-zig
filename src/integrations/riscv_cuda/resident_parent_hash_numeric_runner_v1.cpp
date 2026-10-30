#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <vector>
#include <stdexcept>
#include "resident_hash.cu"
static void ck(cudaError_t e){if(e!=cudaSuccess)throw std::runtime_error(cudaGetErrorString(e));}
static uint word(std::ifstream&f){uint x;f.read((char*)&x,4);if(!f)throw std::runtime_error("truncated");return x;}
static std::vector<uint> read(std::ifstream&f){auto n=word(f);if(n>(1u<<28))throw std::runtime_error("bound");std::vector<uint>v(n);f.read((char*)v.data(),n*4);if(!f)throw std::runtime_error("truncated vector");return v;}
int main(int argc,char**argv){try{if(argc!=2)throw std::runtime_error("numeric.bin required");std::ifstream f(argv[1],std::ios::binary);auto cases=word(f);std::size_t checked=0,compressions=0,launches=0;
for(uint c=0;c<cases;++c){uint wires=word(f),gl=word(f),xl=word(f),bytes=word(f);std::vector<uint>v[9];for(auto&x:v)x=read(f);auto phase=read(f);uint frames=word(f);std::vector<uint>fs(frames),fc(frames);std::vector<std::vector<uint>>fo(frames);for(uint i=0;i<frames;++i){fs[i]=word(f);fc[i]=word(f);fo[i]=read(f);}uint*d[9]={};
// device source/call/order/digest routing, raw input, wires, G and XOR columns, status.
uint sizes[9]={uint(v[0].size()),uint(v[1].size()),uint(v[2].size()),uint(v[4].size()),uint(v[5].size()),wires,uint(v[6].size()),uint(v[7].size()),1};
for(uint i=0;i<9;++i)ck(cudaMalloc(&d[i],std::max(std::size_t(4),std::size_t(sizes[i])*4)));
for(uint i=0;i<3;++i)ck(cudaMemcpy(d[i],v[i].data(),v[i].size()*4,cudaMemcpyHostToDevice));ck(cudaMemcpy(d[3],v[4].data(),v[4].size()*4,cudaMemcpyHostToDevice));if(!v[5].empty())ck(cudaMemcpy(d[4],v[5].data(),v[5].size()*4,cudaMemcpyHostToDevice));
ck((cudaError_t)stwo_resident_parent_hash_sources_on((unsigned char*)d[4],bytes,(ParentHashSource*)d[0],v[0].size()/4,d[5],wires,d[6],gl,d[7],xl,d[8],nullptr));++launches;
for(uint level=0;level+1<v[3].size();++level){uint first=v[3][level],count=v[3][level+1]-first;if(!count)continue;ck((cudaError_t)stwo_resident_parent_hash_calls_on(d[5],wires,(ParentHashCall*)d[1],d[2]+first,count,d[6],d[7],gl,xl,d[8],nullptr));++launches;}
ck(cudaDeviceSynchronize());uint status;ck(cudaMemcpy(&status,d[8],4,cudaMemcpyDeviceToHost));if(status)throw std::runtime_error("device topology status");
for(uint which=0;which<2;++which){std::vector<uint>got(v[6+which].size());ck(cudaMemcpy(got.data(),d[6+which],got.size()*4,cudaMemcpyDeviceToHost));for(uint i=0;i<got.size();++i)if(got[i]!=v[6+which][i]){std::fprintf(stderr,"MISMATCH case=%u G_or_X=%u word=%u got=%u expected=%u\n",c,which,i,got[i],v[6+which][i]);return 2;}checked+=got.size();}
std::vector<uint>ws(wires);ck(cudaMemcpy(ws.data(),d[5],wires*4,cudaMemcpyDeviceToHost));for(uint i=0;i<v[4].size();++i)if(ws[v[4][i]]!=v[8][i])throw std::runtime_error("BLAKE3 output mismatch");checked+=v[4].size();compressions+=v[1].size()/50;
uint*dp;ck(cudaMalloc(&dp,phase.size()*4));ck(cudaMemcpy(dp,phase.data(),phase.size()*4,cudaMemcpyHostToDevice));
// Reverse order is deliberately different from cold frame order. Raw input may
// be produced by earlier device phases; only this frame's source words change.
ck((cudaError_t)stwo_resident_parent_hash_initialize_on(d[5],wires,d[6],gl,d[7],xl,nullptr));
for(uint left=frames;left;--left){uint i=left-1;ck((cudaError_t)stwo_resident_parent_hash_source_range_on((unsigned char*)d[4],bytes,((ParentHashSource*)d[0])+fs[i],fc[i],d[5],wires,d[8],nullptr));for(uint j=0;j+1<fo[i].size();++j){uint n=fo[i][j+1]-fo[i][j];if(n)ck((cudaError_t)stwo_resident_parent_hash_calls_on(d[5],wires,(ParentHashCall*)d[1],dp+fo[i][j],n,d[6],d[7],gl,xl,d[8],nullptr));}}
for(uint which=0;which<2;++which){std::vector<uint>got(v[6+which].size());ck(cudaMemcpy(got.data(),d[6+which],got.size()*4,cudaMemcpyDeviceToHost));if(got!=v[6+which])throw std::runtime_error("phased witness mismatch");checked+=got.size();}
ck(cudaMemcpy(ws.data(),d[5],wires*4,cudaMemcpyDeviceToHost));for(uint i=0;i<v[4].size();++i)if(ws[v[4][i]]!=v[8][i])throw std::runtime_error("phased digest mismatch");checked+=v[4].size();ck(cudaFree(dp));for(auto x:d)ck(cudaFree(x));}
if(f.peek()!=EOF)throw std::runtime_error("trailing vector");std::printf("RESIDENT_PARENT_HASH_NUMERIC PASS cases=%u compressions=%zu checked_words=%zu launches=%zu CPU_numeric_inputs=0 reverse_frame_parity=true\n",cases,compressions,checked,launches);return 0;
}catch(const std::exception&e){std::fprintf(stderr,"ERROR %s\n",e.what());return 1;}}
