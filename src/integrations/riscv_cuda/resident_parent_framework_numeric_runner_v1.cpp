#include "framework_util.cu"
#include <vector>
#include <fstream>
#include <iostream>
#include <stdexcept>
static void check(cudaError_t r){if(r!=cudaSuccess)throw std::runtime_error(cudaGetErrorString(r));}
static uint word(std::ifstream&f){uint x;f.read((char*)&x,4);if(!f)throw std::runtime_error("truncated");return x;}
static std::vector<uint> words(std::ifstream&f){std::vector<uint>v(word(f));f.read((char*)v.data(),v.size()*4);if(!f)throw std::runtime_error("truncated");return v;}
struct D{uint*p;size_t n;D(size_t n):n(n){check(cudaMalloc(&p,n*4));check(cudaMemset(p,0,n*4));}D(const std::vector<uint>&v):D(v.size()){check(cudaMemcpy(p,v.data(),n*4,cudaMemcpyHostToDevice));}~D(){cudaFree(p);}void same(const std::vector<uint>&v){std::vector<uint>a(n);check(cudaMemcpy(a.data(),p,n*4,cudaMemcpyDeviceToHost));if(a!=v)throw std::runtime_error("numeric mismatch");}};
__global__ void wide_stress(uint*narrow,unsigned long long*wide,uint*status,uint n){
 uint i=blockIdx.x*blockDim.x+threadIdx.x;if(i>=n)return;uint index=(i*13u)%17u;
 uint value=(i%5u==0u)?2147483646u:(i%5u==1u)?0u:(i%5u==2u)?1u:(i*107u)%2147483647u;
 parent_framework_atomic_add(narrow+index,value);parent_framework_wide_add(wide+index,value,status);
}
__global__ void wide_invalid(unsigned long long*wide,uint*status){parent_framework_wide_add(wide,2147483647u,status);}
static void stress(){
 const uint n=10003;D narrow(17),wide(34),status(1),reduced(17);
 wide_stress<<<(n+127u)/128u,128>>>(narrow.p,(unsigned long long*)wide.p,status.p,n);check(cudaGetLastError());
 check((cudaError_t)stwo_resident_framework_wide_reduce_on((unsigned long long*)wide.p,reduced.p,17,nullptr));
 std::vector<uint>expected(17,0);for(uint i=0;i<n;i++){uint v=(i%5u==0u)?2147483646u:(i%5u==1u)?0u:(i%5u==2u)?1u:(i*107u)%2147483647u;uint k=(i*13u)%17u;expected[k]=uint((uint64_t(expected[k])+v)%2147483647ull);}
 narrow.same(expected);reduced.same(expected);status.same({0});
 wide_invalid<<<1,1>>>((unsigned long long*)wide.p,status.p);check(cudaGetLastError());status.same({32});
 const uint64_t edge[]={0,2147483646ull,2147483647ull,~uint64_t(0),8589934600ull*2147483646ull};
 D de(10),eo(5);check(cudaMemcpy(de.p,edge,sizeof(edge),cudaMemcpyHostToDevice));check((cudaError_t)stwo_resident_framework_wide_reduce_on((unsigned long long*)de.p,eo.p,5,nullptr));std::vector<uint>ee;for(auto v:edge)ee.push_back(uint(v%2147483647ull));eo.same(ee);
 std::cout<<"RESIDENT_FRAMEWORK_WIDE_STRESS PASS requests="<<n<<" signed_weights=true invalid_canonical_rejected=true\n";
}
int main(int argc,char**argv){try{if(argc!=2)return 2;std::ifstream f(argv[1],std::ios::binary);uint count=word(f);uint64_t compared=0;
for(uint i=0;i<count;++i){auto draws=words(f),routes=words(f),expected=words(f);D d(draws),r(routes),out(expected.size()),status(1);check((cudaError_t)stwo_resident_framework_relations_on(d.p,(ParentRelationRoute*)r.p,routes.size()/3,out.p,status.p,nullptr));out.same(expected);status.same({0});compared+=expected.size();
uint n=word(f);auto alpha=words(f),powers=words(f);D da(alpha),po(powers.size());check((cudaError_t)stwo_resident_framework_powers_on(da.p,n,po.p,nullptr));po.same(powers);compared+=powers.size();
uint factor=word(f);auto claim=words(f),normalized=words(f);D dc(claim),nc(4);check((cudaError_t)stwo_resident_framework_claim_on(dc.p,nc.p,factor,nullptr));nc.same(normalized);compared+=4;
routes[0]=47;check(cudaMemcpy(r.p,routes.data(),routes.size()*4,cudaMemcpyHostToDevice));check((cudaError_t)stwo_resident_framework_relations_on(d.p,(ParentRelationRoute*)r.p,routes.size()/3,out.p,status.p,nullptr));status.same({16});}
uint counters=word(f);for(uint c=0;c<counters;++c){uint kind=word(f),rows=word(f);auto source=words(f),offsets=words(f),profile=words(f);uint dummy=word(f);auto bitwise=words(f),range=words(f);if(profile.empty())profile.push_back(0);D ds(source),dof(offsets),dp(profile),dd(dummy),db(1u<<18),dr(1u<<16),status(1);check((cudaError_t)stwo_resident_framework_counts_on(kind,ds.p,(ulong*)dof.p,dp.p,dd.p,db.p,dr.p,status.p,rows,nullptr));status.same({0});std::vector<uint>eb(1u<<18),er(1u<<16);for(size_t i=0;i<bitwise.size();i+=2)eb[bitwise[i]]=bitwise[i+1];for(size_t i=0;i<range.size();i+=2)er[range[i]]=range[i+1];db.same(eb);dr.same(er);
 D wb(2u*(1u<<18)),wr(2u*(1u<<16));
 check((cudaError_t)stwo_resident_framework_counts_wide_on(kind,ds.p,(ulong*)dof.p,dp.p,dd.p,(unsigned long long*)wb.p,(unsigned long long*)wr.p,status.p,rows,nullptr));
 check((cudaError_t)stwo_resident_framework_wide_reduce_on((unsigned long long*)wb.p,db.p,1u<<18,nullptr));
 check((cudaError_t)stwo_resident_framework_wide_reduce_on((unsigned long long*)wr.p,dr.p,1u<<16,nullptr));
 status.same({0});db.same(eb);dr.same(er);compared+=2*(eb.size()+er.size());}
stress();std::cout<<"RESIDENT_FRAMEWORK_COUNTERS PASS cohorts="<<counters<<"\n";
std::cout<<"RESIDENT_FRAMEWORK_PARAMETERS PASS cases="<<count<<" compared_words="<<compared<<" bad_domain_rejected="<<count<<"\n";return 0;}catch(std::exception&e){std::cerr<<e.what()<<"\n";return 1;}}
