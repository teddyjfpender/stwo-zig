// Diagnostic replay using the exact authenticated Cairo CUDA archive.
// No proof is constructed or qualified by this program.
#include "/workspace/stwo-zig/src/backends/cuda/native/aot_loader.h"
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <vector>
#include <stdexcept>
extern "C" int stwo_exec_context_create(void**);
extern "C" int stwo_exec_context_destroy(void*);
extern "C" int stwo_exec_context_alloc_u32(void*,size_t,uint32_t**);
extern "C" int stwo_exec_context_free_u32(void*,uint32_t*);
extern "C" int stwo_exec_context_memcpy_h2d_async(void*,void*,const void*,size_t);
extern "C" int stwo_exec_context_memcpy_d2h_async(void*,void*,const void*,size_t);
extern "C" int stwo_exec_context_sync(void*);
void ck(int s){if(s)throw std::runtime_error("CUDA status "+std::to_string(s));}
int main(int argc,char**argv){try{
 if(argc!=2)throw std::runtime_error("usage: probe input.bin");
 std::ifstream f(argv[1],std::ios::binary);if(!f)throw std::runtime_error("input absent");
 auto word=[&](){uint32_t v;f.read((char*)&v,4);if(!f)throw std::runtime_error("truncated");return v;};
 auto read=[&](size_t n){std::vector<uint32_t>v(n);f.read((char*)v.data(),n*4);if(!f)throw std::runtime_error("truncated");return v;};
 auto rows=word(),na=word(),nb=word(),ns=word();
 if(rows!=16)throw std::runtime_error("bounded prefix requires 16 rows");
 auto inputs=read(rows*4),addresses=read(na),big=read(nb*8),small=read(ns*4);
 void*context=nullptr;ck(stwo_exec_context_create(&context));std::vector<uint32_t*>owned;
 auto alloc=[&](size_t n){uint32_t*p;ck(stwo_exec_context_alloc_u32(context,n,&p));owned.push_back(p);return p;};
 auto upload=[&](const void*v,size_t n){auto*p=alloc(n);ck(stwo_exec_context_memcpy_h2d_async(context,p,v,n*4));return p;};
 auto pointers=[&](std::vector<uint32_t*>v){return upload(v.data(),v.size()*2);};
 std::vector<std::vector<uint32_t>> host(37);host[0]=addresses;
 for(int limb=0;limb<36;limb++){bool b=limb<28;auto l=b?limb:limb-28;auto&h=host[limb+1];h.resize(b?nb:ns);auto&w=b?big:small;auto stride=b?8:4;
  for(size_t r=0;r<h.size();r++){unsigned bit=l*9,ix=bit/32,sh=bit%32;uint64_t v=w[r*stride+ix];if(sh>23&&ix+1<(unsigned)stride)v|=(uint64_t)w[r*stride+ix+1]<<32;h[r]=(v>>sh)&511;}}
 std::vector<uint32_t*>tables;for(auto&h:host)tables.push_back(upload(h.data(),h.size()));auto*tableptr=pointers(tables);
 uint32_t stride_values[3]={na,nb,ns};auto*strides=upload(stride_values,3);
 std::vector<uint32_t*>in;for(int c=0;c<4;c++)in.push_back(upload(inputs.data()+c*rows,rows));auto*inptr=pointers(in);
 auto*out=alloc(17*rows);std::vector<uint32_t*>outs;for(int c=0;c<17;c++)outs.push_back(out+c*rows);auto*outptr=pointers(outs);
 auto*mult=alloc(1);auto*multptr=pointers({mult});auto*lookup=alloc(55*rows);auto*sub=alloc(11*rows);
 ck(stwo_exec_context_sync(context));void*loader=nullptr;void*fn=nullptr;ck(stwo_native_aot_loader_create(context,&loader));
 const uint32_t grid[3]={1,1,1},block[3]={256,1,1};StwoNativeAotFunctionReceipt receipt{};
 ck(stwo_native_aot_function_bind_with_globals(loader,0x735903777afd70d2ull,2,0,"stwo_jit_witness_d94540f2fd219001",grid,block,0,8,&fn,&receipt));
 void*args[8]={&inptr,&tableptr,&strides,&outptr,&multptr,&lookup,&sub,&rows};ck(stwo_native_aot_function_launch(fn,args,8));
 std::vector<uint32_t>result(17*rows);ck(stwo_exec_context_memcpy_d2h_async(context,result.data(),out,result.size()*4));ck(stwo_exec_context_sync(context));
 std::printf("{\"full_proof_verified\":false,\"component\":\"add_ap_opcode\",\"columns\":[");for(int c=0;c<17;c++){if(c)printf(",");printf("[");for(unsigned r=0;r<rows;r++)printf("%s%u",r?",":"",result[c*rows+r]);printf("]");}printf("]}\n");
 ck(stwo_native_aot_function_destroy(fn));ck(stwo_native_aot_loader_destroy(loader));for(auto it=owned.rbegin();it!=owned.rend();++it)ck(stwo_exec_context_free_u32(context,*it));ck(stwo_exec_context_destroy(context));return 0;
 }catch(const std::exception&e){fprintf(stderr,"%s\n",e.what());return 1;}}
