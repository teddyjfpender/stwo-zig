#include <cuda_runtime.h>
#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <algorithm>
extern "C" int stwo_parent_fri_expand_v1(const uint32_t*,uint32_t,const uint32_t*,const uint32_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t,const uint32_t*,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t*,uint32_t*,uint32_t*,uint32_t*,uint32_t*,uint32_t*,cudaStream_t);
static void ck(cudaError_t r){if(r!=cudaSuccess)throw std::runtime_error(cudaGetErrorString(r));}
static uint32_t* put(const std::vector<uint32_t>& a){uint32_t* p;ck(cudaMalloc(&p,std::max(size_t(4),a.size()*4)));if(!a.empty())ck(cudaMemcpy(p,a.data(),a.size()*4,cudaMemcpyHostToDevice));return p;}
static uint32_t* space(size_t n){return put(std::vector<uint32_t>(n));}
struct Reader{std::vector<uint32_t>x;size_t i=0;Reader(const char*p){std::ifstream f(p,std::ios::binary|std::ios::ate);if(!f)throw std::runtime_error("vector file");auto n=f.tellg();if(n<0||n%4)throw std::runtime_error("vector framing");x.resize(n/4);f.seekg(0);f.read((char*)x.data(),n);}uint32_t one(){if(i>=x.size())throw std::runtime_error("truncated");return x[i++];}std::vector<uint32_t>take(size_t n){if(n>x.size()-i)throw std::runtime_error("truncated span");std::vector<uint32_t>a(x.begin()+i,x.begin()+i+n);i+=n;return a;}};
static uint64_t checked=0;static uint32_t cases=0,layers_seen=0,hostiles=0;
static void run(Reader&r,cudaStream_t stream){
 if(r.one()!=0x42374652)throw std::runtime_error("magic");uint32_t nq=r.one(),nl=r.one(),log=r.one();if(!nq||nq>128||!nl||nl>30)throw std::runtime_error("shape");
 auto query=r.take(nq),deep=r.take(nq*4);auto*dq=put(query);auto*dd=put(deep);
 uint32_t *p[2]={space(128),space(128)},*v[2]={space(512),space(512)},*n[2]={space(1),space(1)};
 auto*scratch=space(128*32*4);auto*expanded=space(nq*32*4+1);auto*error=space(1);uint32_t shift=0;
 for(uint32_t layer=0;layer<nl;layer++){
  uint32_t width=r.one(),nw=r.one(),ne=r.one(),step=0;while((1u<<step)<width)step++;if((1u<<step)!=width||step>5||ne!=nq*width)throw std::runtime_error("layer shape");
  auto alpha=r.take(4),witness=r.take(nw*4),expected=r.take(ne*4);auto*da=put(alpha);auto*dw=put(witness);
  uint32_t canary=0x981724f1;ck(cudaMemcpy(expanded+ne*4,&canary,4,cudaMemcpyHostToDevice));
  unsigned out=layer&1,in=out^1;
  ck((cudaError_t)stwo_parent_fri_expand_v1(dq,nq,dd,p[in],v[in],n[in],dw,nw,da,log,step,shift,layer==0,p[out],v[out],n[out],scratch,expanded,error,stream));
  ck(cudaStreamSynchronize(stream));uint32_t flag=0;ck(cudaMemcpy(&flag,error,4,cudaMemcpyDeviceToHost));if(flag){std::fprintf(stderr,"case%u layer%u flag%u\n",cases,layer,flag);throw std::runtime_error("unexpected device rejection");}
  std::vector<uint32_t>got(ne*4+1);ck(cudaMemcpy(got.data(),expanded,got.size()*4,cudaMemcpyDeviceToHost));
  if(got.back()!=canary)throw std::runtime_error("canary");
  for(size_t i=0;i<expected.size();i++)if(got[i]!=expected[i]){std::fprintf(stderr,"case%u layer%u word%zu expected%u got%u\n",cases,layer,i,expected[i],got[i]);throw std::runtime_error("numerical mismatch");}
  checked+=expected.size();layers_seen++;
  if(layer==0){
   // Raw query overflow, conflicting repeated query, noncanonical alpha,
   // missing/extra witness, and sticky status are all device responsibilities.
   auto bad=query;bad[0]=1u<<log;ck(cudaMemcpy(dq,bad.data(),nq*4,cudaMemcpyHostToDevice));
   ck((cudaError_t)stwo_parent_fri_expand_v1(dq,nq,dd,nullptr,nullptr,nullptr,dw,nw,da,log,step,0,1,p[out],v[out],n[out],scratch,expanded,error,stream));ck(cudaStreamSynchronize(stream));ck(cudaMemcpy(&flag,error,4,cudaMemcpyDeviceToHost));if(!flag)throw std::runtime_error("raw query accepted");hostiles++;
   ck(cudaMemcpy(dq,query.data(),nq*4,cudaMemcpyHostToDevice));ck(cudaMemset(error,0,4));
   uint32_t invalid=2147483647;ck(cudaMemcpy(da,&invalid,4,cudaMemcpyHostToDevice));
   ck((cudaError_t)stwo_parent_fri_expand_v1(dq,nq,dd,nullptr,nullptr,nullptr,dw,nw,da,log,step,0,1,p[out],v[out],n[out],scratch,expanded,error,stream));ck(cudaStreamSynchronize(stream));ck(cudaMemcpy(&flag,error,4,cudaMemcpyDeviceToHost));if(!flag)throw std::runtime_error("bad alpha accepted");hostiles++;
   ck(cudaMemcpy(da,alpha.data(),16,cudaMemcpyHostToDevice));ck(cudaMemset(error,0,4));
   if(nw){ck((cudaError_t)stwo_parent_fri_expand_v1(dq,nq,dd,nullptr,nullptr,nullptr,dw,nw-1,da,log,step,0,1,p[out],v[out],n[out],scratch,expanded,error,stream));ck(cudaStreamSynchronize(stream));ck(cudaMemcpy(&flag,error,4,cudaMemcpyDeviceToHost));if(!flag)throw std::runtime_error("short witness accepted");hostiles++;ck(cudaMemset(error,0,4));}
   uint32_t sticky=1u<<30;ck(cudaMemcpy(error,&sticky,4,cudaMemcpyHostToDevice));
   ck((cudaError_t)stwo_parent_fri_expand_v1(dq,nq,dd,nullptr,nullptr,nullptr,dw,nw,da,log,step,0,1,p[out],v[out],n[out],scratch,expanded,error,stream));ck(cudaStreamSynchronize(stream));ck(cudaMemcpy(&flag,error,4,cudaMemcpyDeviceToHost));if(flag!=sticky)throw std::runtime_error("sticky state overwritten");hostiles++;ck(cudaMemset(error,0,4));
  }
  shift+=step;log-=step;ck(cudaFree(da));ck(cudaFree(dw));
 }
 for(auto q:p)ck(cudaFree(q));for(auto q:v)ck(cudaFree(q));for(auto q:n)ck(cudaFree(q));for(auto q:{dq,dd,scratch,expanded,error})ck(cudaFree(q));cases++;
}
int main(int argc,char**argv){try{if(argc!=3)throw std::runtime_error("synthetic and genuine vector paths");cudaStream_t stream;ck(cudaStreamCreate(&stream));Reader batch(argv[1]);if(batch.one()!=0x46524932)throw std::runtime_error("batch magic");uint32_t count=batch.one();for(uint32_t i=0;i<count;i++)run(batch,stream);if(batch.i!=batch.x.size())throw std::runtime_error("batch tail");Reader genuine(argv[2]);run(genuine,stream);if(genuine.i!=genuine.x.size())throw std::runtime_error("genuine tail");ck(cudaStreamDestroy(stream));std::printf("{\"status\":\"pass\",\"cases\":%u,\"layers\":%u,\"field_words\":%llu,\"hostiles\":%u,\"genuine_child_cases\":1,\"fully_resident_prover\":false}\n",cases,layers_seen,(unsigned long long)checked,hostiles);return 0;}catch(const std::exception&e){std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
