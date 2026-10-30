#include "transform/quotient_tiny.cuh"
#include <cstdio>
#include <cstdint>
#include <cstring>
int main(int argc,char**argv){
 if(argc!=2)return 2;FILE*f=std::fopen(argv[1],"rb");if(!f)return 3;
 uint32_t words[10];size_t cases=0;
 while(std::fread(words,4,10,f)==10){
  uint32_t values[4];std::memcpy(values,words+2,16);
  if(!stwo::cuda::quotient_tiny::invert(values,words[0],words[1]))return 4;
  for(uint32_t i=0;i<(1u<<words[0]);++i)if(values[i]!=words[6+i]){std::fprintf(stderr,"mismatch case=%zu log=%u index=%u word=%u got=%u expected=%u\n",cases,words[0],words[1],i,values[i],words[6+i]);return 5;}
  ++cases;
 }
 if(!std::feof(f)||!cases)return 6;
 uint32_t v[4]={1,2,3,4};
 if(stwo::cuda::quotient_tiny::invert(v,0,0)||stwo::cuda::quotient_tiny::invert(v,3,1u<<26)||stwo::cuda::quotient_tiny::invert(v,1,0))return 7;
 std::printf("PASS %zu exact original-interpolation cases; invalid log/domain rejected; host-only CUDA arithmetic\n",cases);
}
