// Auxiliary answer construction is not admission: the full zero anchor must
// pass afterward. Four scalar inputs encode one extension-field answer.
#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
struct Node{uint32_t op,lhs,rhs,input,constant[4];};
struct Graph{uint32_t node_first,node_count,input_first,input_count,value_word_base,level_first,level_count,output_first,output_count;};
extern "C" int stwo_resident_parent_arithmetic_on(const Graph*,const uint32_t*,uint32_t,const Node*,const uint32_t*,const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint32_t*,void*);
#define CUDA(x) do{auto e=(x);if(e!=cudaSuccess){fprintf(stderr,"CUDA %s:%d %s\n",__FILE__,__LINE__,cudaGetErrorString(e));exit(2);}}while(0)
#define REQUIRE(x) do{if(!(x)){fprintf(stderr,"mismatch line %d\n",__LINE__);exit(3);}}while(0)
template<class T>T*upload(const T*p,size_t n){T*d;CUDA(cudaMalloc(&d,n*sizeof(T)));CUDA(cudaMemcpy(d,p,n*sizeof(T),cudaMemcpyHostToDevice));return d;}
int main(){
 Node n[15]={};n[0]={1,0,0,0,{2,3,5,7}};for(uint32_t j=0;j<4;++j)n[j+1]={0,0,0,j,{}};
 n[5]={1,0,0,0,{0,1,0,0}};n[6]={1,0,0,0,{0,0,1,0}};n[7]={1,0,0,0,{0,0,0,1}};
 n[8]={4,2,5,0,{}};n[9]={4,3,6,0,{}};n[10]={4,4,7,0,{}};n[11]={2,1,8,0,{}};n[12]={2,11,9,0,{}};n[13]={2,12,10,0,{}};n[14]={3,0,13,0,{}};
 const Graph graphs[]={ {0,15,0,4,0,0,6,0,0},{0,15,0,4,0,0,6,0,1} };
 const uint32_t levels[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14},offsets[]={0,8,11,12,13,14,15},outputs[]={14},selected[]={0,1};
 Graph*g=upload(graphs,2);Node*nodes=upload(n,15);auto*l=upload(levels,15);auto*o=upload(offsets,7);auto*out=upload(outputs,1);auto*s=upload(selected,2);
 uint32_t*workspace;CUDA(cudaMalloc(&workspace,81*4));CUDA(cudaMemset(workspace,0,81*4));auto*inputs=workspace;auto*values=workspace+16;auto*pool=workspace+76;auto*status=workspace+80;
 auto run=[&](unsigned ordinal){REQUIRE(stwo_resident_parent_arithmetic_on(g,s+ordinal,1,nodes,l,o,out,inputs,values,status,nullptr)==0);CUDA(cudaDeviceSynchronize());};
 auto check=[&](uint32_t expected){uint32_t actual;CUDA(cudaMemcpy(&actual,status,4,cudaMemcpyDeviceToHost));REQUIRE(actual==expected);};
 run(0);check(0);
 for(unsigned j=0;j<4;++j){CUDA(cudaMemcpy(inputs+4*j,values+j,4,cudaMemcpyDeviceToDevice));CUDA(cudaMemcpy(pool+j,values+j,4,cudaMemcpyDeviceToDevice));}
 run(1);check(0);uint32_t captured[20];CUDA(cudaMemcpy(captured,inputs,16*4,cudaMemcpyDeviceToHost));CUDA(cudaMemcpy(captured+16,pool,4*4,cudaMemcpyDeviceToHost));
 const uint32_t expected[]={2,3,5,7};for(unsigned j=0;j<4;++j){REQUIRE(captured[4*j]==expected[j]);REQUIRE(captured[16+j]==expected[j]);for(unsigned k=1;k<4;++k)REQUIRE(captured[4*j+k]==0);}
 uint32_t wrong=3;CUDA(cudaMemcpy(inputs,&wrong,4,cudaMemcpyHostToDevice));run(1);check(512);
 CUDA(cudaFree(workspace));CUDA(cudaFree(s));CUDA(cudaFree(out));CUDA(cudaFree(o));CUDA(cudaFree(l));CUDA(cudaFree(nodes));CUDA(cudaFree(g));
 puts("PASS resident_deep_answer_two_pass scalar_inputs=4 exact_words=20 full_anchor=true changed_answer_rejected=true admission_from_aux=false");
}
