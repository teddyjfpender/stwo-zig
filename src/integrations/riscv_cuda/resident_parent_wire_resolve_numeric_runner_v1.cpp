#include "resolve.cu"
#include <vector>
#include <fstream>
#include <iostream>
#include <stdexcept>
static void check(cudaError_t r){if(r!=cudaSuccess)throw std::runtime_error(cudaGetErrorString(r));}
static unsigned word(std::ifstream&f){unsigned x;f.read((char*)&x,4);if(!f)throw std::runtime_error("truncated");return x;}
static std::vector<unsigned>words(std::ifstream&f){std::vector<unsigned>v(word(f));f.read((char*)v.data(),v.size()*4);if(!f)throw std::runtime_error("truncated");return v;}
struct D{unsigned*p;size_t n;D(size_t n):n(n){check(cudaMalloc(&p,n*4));check(cudaMemset(p,0,n*4));}D(const std::vector<unsigned>&v):D(v.size()){check(cudaMemcpy(p,v.data(),n*4,cudaMemcpyHostToDevice));}~D(){cudaFree(p);}std::vector<unsigned>get(){std::vector<unsigned>v(n);check(cudaMemcpy(v.data(),p,n*4,cudaMemcpyDeviceToHost));return v;}};
int main(int argc,char**argv){try{if(argc!=2)return 2;std::ifstream f(argv[1],std::ios::binary);auto ins=words(f),cs=words(f),rs=words(f);D di(ins),dc(cs),dr(rs),scratch(ins.size()/4),out(4),status(1);unsigned count=word(f),hostiles=0;
for(unsigned t=0;t<count;++t){auto main=words(f),expected=words(f);unsigned flag=word(f);D dm(main);unsigned initial=1024;check(cudaMemcpy(status.p,&initial,4,cudaMemcpyHostToDevice));check((cudaError_t)stwo_resident_parent_wire_resolve_on((ParentWireInstruction*)di.p,(ParentWireCandidate*)dc.p,(ParentWireRequest*)dr.p,1,dm.p,scratch.p,out.p,status.p,nullptr));if(out.get()!=expected||status.get()[0]!=(flag|initial))throw std::runtime_error("resolver parity/status mismatch");hostiles+=flag!=0;}
std::cout<<"RESIDENT_WIRE_RESOLVE PASS cases="<<count<<" exact_words="<<4*count<<" hostile="<<hostiles<<" CPU_private_selection=0\n";return 0;}catch(std::exception&e){std::cerr<<e.what()<<"\n";return 1;}}
