#include "arithmetic.cu"
#include <vector>
#include <fstream>
#include <iostream>
#include <stdexcept>
static void check(cudaError_t r){if(r!=cudaSuccess)throw std::runtime_error(cudaGetErrorString(r));}
static uint word(std::ifstream&f){uint x;f.read((char*)&x,4);if(!f)throw std::runtime_error("truncated");return x;}
static std::vector<uint> words(std::ifstream&f){std::vector<uint>v(word(f));f.read((char*)v.data(),v.size()*4);if(!f)throw std::runtime_error("truncated");return v;}
struct D{uint*p;size_t n;D(size_t n):n(n){check(cudaMalloc(&p,n*4));check(cudaMemset(p,0,n*4));}D(const std::vector<uint>&v):D(v.size()){check(cudaMemcpy(p,v.data(),n*4,cudaMemcpyHostToDevice));}~D(){cudaFree(p);}std::vector<uint>get(){std::vector<uint>a(n);check(cudaMemcpy(a.data(),p,n*4,cudaMemcpyDeviceToHost));return a;}void same(const std::vector<uint>&v){if(get()!=v)throw std::runtime_error("numeric mismatch");}};
int main(int argc,char**argv){try{if(argc!=2)return 2;std::ifstream f(argv[1],std::ios::binary);auto graphs=words(f),nodes=words(f),levels=words(f),offsets=words(f),outputs=words(f),inputs=words(f),expected=words(f);uint count=graphs.size()/9;std::vector<uint>select(count);for(uint i=0;i<count;++i)select[i]=i;D dg(graphs),dn(nodes),dl(levels),df(offsets),doo(outputs),di(inputs),dsel(select),values(expected.size()),status(1);
auto run=[&](){check((cudaError_t)stwo_resident_parent_arithmetic_on((ParentArithmeticGraph*)dg.p,dsel.p,count,(ParentArithmeticNode*)dn.p,dl.p,df.p,doo.p,di.p,values.p,status.p,nullptr));};run();values.same(expected);status.same({0});
for(uint test=0;test<3;++test){auto bad=inputs;if(test==0)for(uint i=0;i<4;++i)bad[i]=0;else if(test==1)bad[0]^=1;else bad[0]=0x80000000u;check(cudaMemcpy(di.p,bad.data(),bad.size()*4,cudaMemcpyHostToDevice));check(cudaMemset(status.p,0,4));run();uint required=test==0?128u:test==1?512u:64u;if(!(status.get()[0]&required))throw std::runtime_error("hostile not rejected");}
std::cout<<"RESIDENT_ARITHMETIC PASS graphs="<<count<<" nodes="<<nodes.size()/8<<" exact_words="<<expected.size()<<" hostile=3 CPU_node_values_as_input=0\n";return 0;}catch(std::exception&e){std::cerr<<e.what()<<"\n";return 1;}}
