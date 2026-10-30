// Device routing differential only. This does not qualify a child receipt.
#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
struct Source {uint32_t kind,index,aux,phase;};
struct Write {Source source;uint32_t destination,offset,bytes,phase;};
extern "C" int stwo_resident_parent_write_on(const Write*,uint32_t,const unsigned char*,uint32_t,uint32_t*,uint32_t,const uint32_t*,uint32_t,const uint32_t*,uint32_t,uint32_t*,uint32_t,const uint32_t*,uint32_t,unsigned char*,uint32_t,uint32_t*,uint32_t,uint32_t*,void*);
#define CUDA(x) do{auto e=(x);if(e!=cudaSuccess){fprintf(stderr,"CUDA %s:%d %s\n",__FILE__,__LINE__,cudaGetErrorString(e));exit(2);}}while(0)
#define REQUIRE(x) do{if(!(x)){fprintf(stderr,"mismatch line %d\n",__LINE__);exit(3);}}while(0)
int main(){
 uint32_t *memory=nullptr;Write *writes=nullptr;CUDA(cudaMalloc(&memory,8*8*sizeof(uint32_t)));CUDA(cudaMalloc(&writes,sizeof(Write)));CUDA(cudaMemset(memory,0,8*8*sizeof(uint32_t)));
 uint32_t *raw=memory,*pool=memory+8,*hash=memory+16,*arithmetic=memory+24,*main=memory+32,*readonly=memory+40,*input=memory+48,*status=memory+56;
 uint32_t value=0x78563412u;CUDA(cudaMemcpy(raw,&value,4,cudaMemcpyHostToDevice));value=37;CUDA(cudaMemcpy(readonly+3,&value,4,cudaMemcpyHostToDevice));
 auto run=[&](Write w){CUDA(cudaMemcpy(writes,&w,sizeof(w),cudaMemcpyHostToDevice));REQUIRE(stwo_resident_parent_write_on(writes,1,(unsigned char*)raw,32,pool,8,hash,8,arithmetic,8,main,8,readonly,8,(unsigned char*)input,32,arithmetic,8,status,nullptr)==0);CUDA(cudaDeviceSynchronize());};
 auto read=[&](const uint32_t*p){uint32_t v;CUDA(cudaMemcpy(&v,p,4,cudaMemcpyDeviceToHost));return v;};
 run({{1,0,0,0},2,0,4,1});REQUIRE(read(pool)==0x78563412u);REQUIRE(read(status)==0);
 run({{2,0,0,1},3,0,4,2});REQUIRE(read(main)==0x78563412u);REQUIRE(read(status)==0);
 run({{12,0,2,1},0,0,1,2});REQUIRE(read(input)==0x56u);REQUIRE(read(status)==0);
 run({{11,3,0,1},1,0,4,2});REQUIRE(read(arithmetic)==37u);REQUIRE(read(status)==0);
 run({{6,0,0,2},2,4,4,3});REQUIRE(read(pool+1)==0x78563412u);REQUIRE(read(status)==0);
 const Write invalid[]={{{12,0,4,1},0,0,1,2},{{1,31,0,0},2,0,4,1},{{0,5,0,0},3,31,4,1},{{11,8,0,1},1,0,4,2}};
 for(auto w:invalid){CUDA(cudaMemset(status,0,4));run(w);REQUIRE(read(status)!=0);}
 value=128;CUDA(cudaMemcpy(status,&value,4,cudaMemcpyHostToDevice));run({{0,7,0,0},2,8,4,1});REQUIRE(read(status)==128);REQUIRE(read(pool+2)==7);
 CUDA(cudaFree(writes));CUDA(cudaFree(memory));puts("PASS resident_composite_routing positive=6 hostile=4 sticky_preserved=true child_receipt=false");
}
