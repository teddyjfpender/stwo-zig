#include "blake3_protocol.cuh"
#include <cuda_runtime.h>
#include <stdint.h>
using namespace stwo::cuda::blake3;
struct ChildRef{uint32_t kind,index;};
struct ChildTask{uint32_t kind,first,count,output,aux,trace_first,attempt_first,attempt_count;};
__device__ bool child_ref(ChildRef r,const uint32_t*packet,uint32_t n,uint32_t&v){if(r.kind==0){v=r.index;return true;}if(r.kind==1&&r.index<n){v=packet[r.index];return true;}return false;}
__device__ void child_state(uint32_t*trace,uint32_t first,const Channel&c){for(int j=0;j<8;j++)trace[first+j]=c.digest[j];trace[first+8]=c.counter[0];trace[first+9]=c.counter[1];}
__global__ void child_replay(const ChildTask*tasks,uint32_t nt,const ChildRef*refs,uint32_t nr,const uint32_t*packet,uint32_t np,uint32_t*out,uint32_t no,uint32_t*trace,uint32_t ns,Channel*final,uint32_t*error){
 if(threadIdx.x||blockIdx.x)return;Channel c={};
 for(uint32_t ordinal=0;ordinal<nt;ordinal++){
  ChildTask t=tasks[ordinal];if((uint64_t)t.trace_first+20>ns||(uint64_t)t.first+t.count>nr&&(t.kind>=1&&t.kind<=4||t.kind==6)){atomicOr(error,1u);return;}
  child_state(trace,t.trace_first,c);State s;
  if(t.kind==0){stwo_blake3_frame_init(s,0);stwo_blake3_words_finish(s,c.digest);c.counter[0]=c.counter[1]=0;}
  else if(t.kind>=1&&t.kind<=4){
   if((t.kind==2&&t.count%4)||(t.kind==3&&t.count!=2)||(t.kind==4&&t.count!=8)){atomicOr(error,2u);return;}
   stwo_blake3_frame_init(s,t.kind);for(int j=0;j<8;j++)stwo_blake3_word(s,c.digest[j]);
   if(t.kind==1||t.kind==2){stwo_blake3_word(s,t.kind==2?t.count/4:t.count);stwo_blake3_word(s,0);}
   for(uint32_t j=0;j<t.count;j++){uint32_t v;if(!child_ref(refs[t.first+j],packet,np,v)||(t.kind==2&&v>=0x7fffffffu)){atomicOr(error,4u);return;}stwo_blake3_word(s,v);}
   stwo_blake3_words_finish(s,c.digest);c.counter[0]=c.counter[1]=0;
  }else if(t.kind==5||t.kind==7){
   if((uint64_t)t.output+t.count>no||(uint64_t)t.attempt_first+32ull*t.attempt_count>ns||!t.attempt_count||(t.kind==5&&t.count!=4&&t.count!=8)||(t.kind==7&&(t.aux>30||t.attempt_count!=(t.count+7)/8))){atomicOr(error,8u);return;}
   uint32_t pending=1,produced=0,consumed=0;uint64_t counter=c.counter[0]|((uint64_t)c.counter[1]<<32);
   for(uint32_t attempt=0;attempt<t.attempt_count;attempt++){
    if(counter==UINT64_MAX&&(t.kind==7||pending)){atomicOr(error,16u);return;}
    const uint32_t at=t.attempt_first+32*attempt;for(int j=0;j<32;j++)trace[at+j]=0;
    stwo_blake3_frame_init(s,5);for(int j=0;j<8;j++){stwo_blake3_word(s,c.digest[j]);trace[at+22+j]=c.digest[j];}
    stwo_blake3_word(s,(uint32_t)counter);stwo_blake3_word(s,(uint32_t)(counter>>32));uint32_t raw[8];stwo_blake3_words_finish(s,raw);
    bool valid=true;for(int j=0;j<8;j++){trace[at+j]=raw[j];trace[at+8+j]=raw[j]>=0xfffffffeu?0:raw[j]%0x7fffffffu;valid=valid&&raw[j]<0xfffffffeu;}
    trace[at+16]=pending;trace[at+17]=valid;trace[at+18]=(uint32_t)counter;trace[at+19]=(uint32_t)(counter>>32);
    if(t.kind==5){counter+=pending;if(pending&&valid){for(uint32_t j=0;j<t.count;j++)out[t.output+j]=trace[at+8+j];pending=0;consumed=attempt+1;}}
    else{counter++;for(int j=0;j<8&&produced<t.count;j++)out[t.output+produced++]=raw[j]&((1u<<t.aux)-1);}
    trace[at+20]=(uint32_t)counter;trace[at+21]=(uint32_t)(counter>>32);trace[at+30]=pending;trace[at+31]=consumed;
   }
   if(t.kind==5&&pending){atomicOr(error,32u);return;}c.counter[0]=(uint32_t)counter;c.counter[1]=(uint32_t)(counter>>32);
  }else if(t.kind==6){
   if(t.count!=2||t.aux>32){atomicOr(error,64u);return;}stwo_blake3_frame_init(s,6);for(int j=0;j<8;j++)stwo_blake3_word(s,c.digest[j]);stwo_blake3_word(s,t.aux);
   for(int j=0;j<2;j++){uint32_t v;if(!child_ref(refs[t.first+j],packet,np,v)){atomicOr(error,128u);return;}stwo_blake3_word(s,v);}
   uint32_t h[8];stwo_blake3_words_finish(s,h);if((h[0]?uint32_t(__ffs(h[0])-1):32)<t.aux){atomicOr(error,256u);return;}
  }else{atomicOr(error,512u);return;}
  child_state(trace,t.trace_first+10,c);
 }
 *final=c;
}
extern "C" int stwo_parent_child_transcript_v1(const ChildTask*tasks,uint32_t nt,const ChildRef*refs,uint32_t nr,const uint32_t*packet,uint32_t np,uint32_t*out,uint32_t no,uint32_t*trace,uint32_t ns,Channel*final,uint32_t*error,cudaStream_t stream){
 if(!tasks||!nt||!refs||!packet||!out||!trace||!final||!error)return (int)cudaErrorInvalidValue;
 child_replay<<<1,1,0,stream>>>(tasks,nt,refs,nr,packet,np,out,no,trace,ns,final,error);return(int)cudaGetLastError();
}
