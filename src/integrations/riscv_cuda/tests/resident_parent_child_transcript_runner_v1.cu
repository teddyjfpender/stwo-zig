#include "blake3_protocol.cuh"
#include <cuda_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>
using namespace stwo::cuda::blake3;
struct ChildRef{uint32_t kind,index;};struct ChildTask{uint32_t kind,first,count,output,aux,trace_first,attempt_first,attempt_count;};
extern "C" int stwo_parent_child_transcript_v1(const ChildTask*,uint32_t,const ChildRef*,uint32_t,const uint32_t*,uint32_t,uint32_t*,uint32_t,uint32_t*,uint32_t,Channel*,uint32_t*,cudaStream_t);
#define OK(x) do{int cuda_status_=(int)(x);if(cuda_status_){fprintf(stderr,"CUDA error%d line%d\n",cuda_status_,__LINE__);return 1;}}while(0)
template<class T>std::vector<T>read(FILE*f,size_t n){std::vector<T>v(n);if(fread(v.data(),sizeof(T),n,f)!=n)abort();return v;}
template<class T>T*put(const std::vector<T>&v){T*p;if(cudaMalloc((void**)&p,v.size()*sizeof(T))||cudaMemcpy(p,v.data(),v.size()*sizeof(T),cudaMemcpyHostToDevice))abort();return p;}
int main(int argc,char**argv){if(argc!=2)return 2;FILE*f=fopen(argv[1],"rb");if(!f)return 2;auto header=read<uint32_t>(f,6);if(header[0]!=0x42374346)return 2;
 auto tasks=read<ChildTask>(f,header[1]);auto refs=read<ChildRef>(f,header[2]);auto packet=read<uint32_t>(f,header[3]);auto expected=read<uint32_t>(f,header[4]);auto trace=read<uint32_t>(f,header[5]);auto end=read<uint32_t>(f,10);if(fgetc(f)!=EOF)return 2;fclose(f);
 auto t=put(tasks);auto r=put(refs);auto p=put(packet);auto o=put(std::vector<uint32_t>(expected.size()));auto s=put(std::vector<uint32_t>(trace.size()));auto e=put(std::vector<uint32_t>{0});auto c=put(std::vector<Channel>(1));
 auto run=[&](){cudaMemset(e,0,4);return stwo_parent_child_transcript_v1(t,tasks.size(),r,refs.size(),p,packet.size(),o,expected.size(),s,trace.size(),c,e,0);};OK(run());
 auto actual=expected;auto actual_trace=trace;Channel final;uint32_t error;
 OK(cudaMemcpy(actual.data(),o,actual.size()*4,cudaMemcpyDeviceToHost));OK(cudaMemcpy(actual_trace.data(),s,actual_trace.size()*4,cudaMemcpyDeviceToHost));OK(cudaMemcpy(&final,c,sizeof(final),cudaMemcpyDeviceToHost));OK(cudaMemcpy(&error,e,4,cudaMemcpyDeviceToHost));
 if(error||actual!=expected||actual_trace!=trace||memcmp(&final,end.data(),40)){fprintf(stderr,"child mismatch error%u\n",error);for(size_t i=0;i<actual.size();i++)if(actual[i]!=expected[i]){fprintf(stderr,"output%zu got%u expected%u\n",i,actual[i],expected[i]);break;}for(size_t i=0;i<trace.size();i++)if(actual_trace[i]!=trace[i]){fprintf(stderr,"trace%zu got%u expected%u\n",i,actual_trace[i],trace[i]);break;}return 3;}
 unsigned attacks=0;for(size_t i=0;i<tasks.size();i++)if(tasks[i].kind==5){auto bad=tasks[i];bad.attempt_count=0;OK(cudaMemcpy(t+i,&bad,sizeof(bad),cudaMemcpyHostToDevice));OK(run());OK(cudaMemcpy(&error,e,4,cudaMemcpyDeviceToHost));if(!error)return 4;attacks++;OK(cudaMemcpy(t+i,&tasks[i],sizeof(bad),cudaMemcpyHostToDevice));break;}
 auto badref=refs[0];badref.kind=1;badref.index=packet.size();OK(cudaMemcpy(r,&badref,sizeof(badref),cudaMemcpyHostToDevice));OK(run());OK(cudaMemcpy(&error,e,4,cudaMemcpyDeviceToHost));if(!error)return 4;attacks++;OK(cudaMemcpy(r,refs.data(),refs.size()*sizeof(ChildRef),cudaMemcpyHostToDevice));
 for(size_t i=0;i<tasks.size();i++)if(tasks[i].kind==6){auto bad=tasks[i];bad.aux=32;OK(cudaMemcpy(t+i,&bad,sizeof(bad),cudaMemcpyHostToDevice));OK(run());OK(cudaMemcpy(&error,e,4,cudaMemcpyDeviceToHost));if(!error)return 4;attacks++;break;}
 cudaFree(t);cudaFree(r);cudaFree(p);cudaFree(o);cudaFree(s);cudaFree(e);cudaFree(c);
 printf("PASS original child FS %zu tasks, %zu exported words, %zu full state/retry words, %u malformed attacks\n",tasks.size(),expected.size(),trace.size(),attacks);return 0;
}
