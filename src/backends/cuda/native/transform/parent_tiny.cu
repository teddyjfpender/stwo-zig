#include <cuda_runtime.h>
#include "../common/m31.cuh"
namespace {using namespace stwo::cuda;
__global__ void inverse(const uint32_t*in,size_t is,uint32_t*out,size_t os,uint32_t columns,uint32_t log,const uint32_t*tw,uint32_t words){
 uint32_t c=blockIdx.x*blockDim.x+threadIdx.x;if(c>=columns)return;uint32_t n=1u<<log;M31 v[4];for(uint32_t i=0;i<n;++i)v[i]=in[size_t(c)*is+i];
 if(log==1){M31 a=v[0],b=v[1];v[0]=m31_add(a,b);v[1]=m31_sub(b,a);}else{M31 t=tw[words-2];for(uint32_t k=0;k<2;++k){M31 a=v[2*k],b=v[2*k+1];v[2*k]=m31_add(a,b);v[2*k+1]=m31_mul(m31_sub(a,b),k?t:m31_neg(t));}for(uint32_t k=0;k<2;++k){M31 a=v[k],b=v[k+2];v[k]=m31_add(a,b);v[k+2]=m31_mul(m31_sub(a,b),t);}}
 for(uint32_t i=0;i<n;++i)out[size_t(c)*os+i]=m31_mul(v[i],(1u<<(31-log)));
}
__global__ void extend(const uint32_t*in,size_t is,const uint32_t*logs,uint32_t*out,size_t os,uint32_t columns,uint32_t log,const uint32_t*tw,uint32_t words){
 uint32_t c=blockIdx.x*blockDim.x+threadIdx.x;if(c>=columns)return;uint32_t n=1u<<log,count=1u<<logs[c];M31 v[4]={0,0,0,0};for(uint32_t i=0;i<n/2&&i<count;++i)v[i]=in[size_t(c)*is+i];
 if(log==1){M31 a=v[0],b=v[1];v[0]=m31_add(a,b);v[1]=m31_sub(a,b);}else{M31 t=tw[words-2];for(uint32_t k=0;k<2;++k){M31 a=v[k],b=m31_mul(v[k+2],t);v[k]=m31_add(a,b);v[k+2]=m31_sub(a,b);}for(uint32_t k=0;k<2;++k){M31 a=v[2*k],b=m31_mul(v[2*k+1],k?t:m31_neg(t));v[2*k]=m31_add(a,b);v[2*k+1]=m31_sub(a,b);}}
 for(uint32_t i=0;i<n;++i)out[size_t(c)*os+i]=v[i];
}}
extern "C" int stwo_parent_tiny_inverse_on(const uint32_t*in,size_t is,uint32_t*out,size_t os,uint32_t columns,uint32_t log,const uint32_t*tw,uint32_t words,void*stream){if(log<1||log>2||!columns||is<(1u<<log)||os<(1u<<log)||words<(1u<<(log-1)))return 1;inverse<<<(columns+127)/128,128,0,(cudaStream_t)stream>>>(in,is,out,os,columns,log,tw,words);return int(cudaGetLastError());}
extern "C" int stwo_parent_tiny_extend_on(const uint32_t*in,size_t is,const uint32_t*logs,uint32_t*out,size_t os,uint32_t columns,uint32_t log,const uint32_t*tw,uint32_t words,void*stream){if(log<1||log>2||!columns||is<(1u<<(log-1))||os<(1u<<log)||words<(1u<<(log-1)))return 1;extend<<<(columns+127)/128,128,0,(cudaStream_t)stream>>>(in,is,logs,out,os,columns,log,tw,words);return int(cudaGetLastError());}
