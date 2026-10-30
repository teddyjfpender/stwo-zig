// Original lifted Merkle decommitment algorithm, device-only raw-proof replay.
#include "blake3_protocol.cuh"
#include <cuda_runtime.h>
#include <stdint.h>
using namespace stwo::cuda::blake3;
struct ChildPathColumn { uint32_t first,count,log_size; };
struct ChildPathTree { uint32_t kind,domain_log,depth,query_shift,columns_first,columns_count,values_first,leaf_width,leaf_count,hash_first,hash_count,root_first,output_first,ancestor_first,frontier_first; };
static __device__ bool cp_span(uint32_t first,uint64_t count,uint32_t size){return first<=size&&count<=uint64_t(size-first);}
static __device__ uint32_t cp_position(const ChildPathTree&t,uint32_t q){return t.kind==0?(t.depth?((q>>(t.query_shift+1))<<1)|(q&1u):0u):(q>>t.query_shift);}
static __device__ bool cp_eq(const Hash&a,const Hash&b){for(int j=0;j<8;j++)if(a.words[j]!=b.words[j])return false;return true;}
static __device__ Hash cp_parent(const Hash&a,const Hash&b){uint32_t p[16];for(int j=0;j<8;j++){p[j]=a.words[j];p[8+j]=b.words[j];}Hash out;stwo_zig_blake3_parent(p,out.words);return out;}
static __device__ bool cp_leaf(const ChildPathTree&t,uint32_t q,const uint32_t*queries,uint32_t nq,const ChildPathColumn*cols,uint32_t nc,const uint32_t*packet,uint32_t np,const uint32_t*values,uint32_t nv,uint32_t rank,uint32_t unique,Hash&out){
 if(t.kind==0){
  if(!t.columns_count||!cp_span(t.columns_first,t.columns_count,nc))return false;
  State s;stwo_blake3_leaf_init(s);for(uint32_t c=0;c<t.columns_count;c++){ChildPathColumn col=cols[t.columns_first+c];if(col.count!=unique||!cp_span(col.first,col.count,np))return false;uint32_t v=packet[col.first+rank];if(v>=0x7fffffffu)return false;stwo_blake3_word(s,v);}stwo_blake3_words_finish(s,out.words);return true;
 }
 if(t.kind!=1||!t.leaf_count||t.leaf_count>256||(t.leaf_count&(t.leaf_count-1))||!t.leaf_width||t.leaf_width>16||!cp_span(t.values_first,uint64_t(nq)*t.leaf_count*t.leaf_width,nv))return false;
 Hash hashes[256];for(uint32_t l=0;l<t.leaf_count;l++){State s;stwo_blake3_leaf_init(s);for(uint32_t w=0;w<t.leaf_width;w++){uint32_t v=values[t.values_first+(uint64_t(q)*t.leaf_count+l)*t.leaf_width+w];if(v>=0x7fffffffu)return false;stwo_blake3_word(s,v);}stwo_blake3_words_finish(s,hashes[l].words);}
 for(uint32_t n=t.leaf_count;n>1;n>>=1)for(uint32_t i=0;i<n/2;i++)hashes[i]=cp_parent(hashes[2*i],hashes[2*i+1]);out=hashes[0];return true;
}
static __device__ bool cp_tree(const ChildPathTree&t,const ChildPathColumn*cols,uint32_t nc,const uint32_t*packet,uint32_t np,const uint32_t*queries,uint32_t nq,const uint32_t*values,uint32_t nv,uint32_t*out,uint32_t no){
 if(!nq||nq>128||t.domain_log>30||t.depth>t.domain_log||t.query_shift!=t.domain_log-t.depth||t.hash_count%8||!cp_span(t.hash_first,t.hash_count,np)||!cp_span(t.root_first,8,np)||!cp_span(t.output_first,uint64_t(nq)*t.depth*8,no)||!cp_span(t.ancestor_first,uint64_t(nq)*(t.depth+1)*8,no)||!cp_span(t.frontier_first,50,no))return false;
 uint32_t order[128],positions[128],n=0;Hash previous[128],next[128];uint32_t next_pos[128];
 for(uint32_t q=0;q<nq;q++){if(queries[q]>=(1u<<t.domain_log))return false;order[q]=q;}
 for(uint32_t i=1;i<nq;i++){uint32_t k=order[i],j=i;while(j&&(cp_position(t,queries[order[j-1]])>cp_position(t,queries[k]))){order[j]=order[j-1];j--;}order[j]=k;}
 // Original ranks depend only on raw queries, not columns or alias pairs.
 // Compute them once; the previous nested rank scan was quartic per column.
 uint32_t raw_order[128],ranks[128],unique=0;
 for(uint32_t q=0;q<nq;q++)raw_order[q]=q;
 for(uint32_t i=1;i<nq;i++){uint32_t k=raw_order[i],j=i;while(j&&queries[raw_order[j-1]]>queries[k]){raw_order[j]=raw_order[j-1];j--;}raw_order[j]=k;}
 for(uint32_t i=0;i<nq;i++){if(i==0||queries[raw_order[i]]!=queries[raw_order[i-1]])unique++;ranks[raw_order[i]]=unique-1;}

 for(uint32_t i=0;i<nq;i++){uint32_t q=order[i],pos=cp_position(t,queries[q]);Hash leaf;if(!cp_leaf(t,q,queries,nq,cols,nc,packet,np,values,nv,ranks[q],unique,leaf))return false;if(n&&positions[n-1]==pos){if(!cp_eq(previous[n-1],leaf))return false;}else{positions[n]=pos;previous[n++]=leaf;}}
 // The original lifted-leaf admission also requires aliasing shorter columns
 // to have equal values, including distinct positions in the taller tree.
 if(t.kind==0){for(uint32_t ci=0;ci<t.columns_count;ci++){ChildPathColumn col=cols[t.columns_first+ci];if(!col.log_size||col.log_size>t.depth)return false;for(uint32_t a=0;a<nq;a++)for(uint32_t b=0;b<a;b++){
  uint32_t pa=cp_position(t,queries[a]),pb=cp_position(t,queries[b]);uint32_t shift=t.depth-col.log_size+1;
  if((((pa>>shift)<<1)|(pa&1u))!=(((pb>>shift)<<1)|(pb&1u)))continue;
  const uint32_t ra=ranks[a],rb=ranks[b];
  if(ra>=col.count||rb>=col.count||packet[col.first+ra]!=packet[col.first+rb])return false;
 }}}
 uint32_t witness=0;
 for(uint32_t level=0;level<t.depth;level++){
  for(uint32_t q=0;q<nq;q++){uint32_t pos=cp_position(t,queries[q])>>level,i=0;while(i<n&&positions[i]!=pos)i++;if(i==n)return false;for(uint32_t w=0;w<8;w++)out[t.ancestor_first+(uint64_t(q)*(t.depth+1)+level)*8+w]=previous[i].words[w];}
  uint32_t count=0;
  for(uint32_t i=0;i<n;){Hash sibling;uint32_t chunk=1;if(i+1<n&&(positions[i]^1u)==positions[i+1]){sibling=previous[i+1];chunk=2;}else{if(witness>=t.hash_count/8)return false;for(uint32_t w=0;w<8;w++)sibling.words[w]=packet[t.hash_first+8*witness+w];witness++;}
   for(uint32_t q=0;q<nq;q++){uint32_t pos=cp_position(t,queries[q])>>level;if(pos==positions[i]||(chunk==2&&pos==positions[i+1])){Hash h=pos==positions[i]?sibling:previous[i];for(uint32_t w=0;w<8;w++)out[t.output_first+(uint64_t(q)*t.depth+level)*8+w]=h.words[w];}}
   next[count]=(positions[i]&1u)?cp_parent(sibling,previous[i]):cp_parent(previous[i],sibling);next_pos[count++]=positions[i]>>1;i+=chunk;
  }
  n=count;for(uint32_t i=0;i<n;i++){previous[i]=next[i];positions[i]=next_pos[i];}
 }
 if(n!=1||positions[0]!=0||witness!=t.hash_count/8)return false;for(uint32_t w=0;w<8;w++){if(previous[0].words[w]!=packet[t.root_first+w])return false;for(uint32_t q=0;q<nq;q++)out[t.ancestor_first+(uint64_t(q)*(t.depth+1)+t.depth)*8+w]=previous[0].words[w];}
 // Canonical two-level frontier: active[2], inputs[2][2][8], opaque[2][8].
 for(uint32_t i=0;i<50;i++)out[t.frontier_first+i]=0;
 if(t.depth>=2){for(uint32_t q=0;q<nq;q++){
  uint32_t branch=(cp_position(t,queries[q])>>(t.depth-1))&1u,side=(cp_position(t,queries[q])>>(t.depth-2))&1u;
  for(uint32_t w=0;w<8;w++){
   uint32_t current=out[t.ancestor_first+(uint64_t(q)*(t.depth+1)+t.depth-2)*8+w],sibling=out[t.output_first+(uint64_t(q)*t.depth+t.depth-2)*8+w];
   uint32_t a=t.frontier_first+2+(branch*2+side)*8+w,b=t.frontier_first+2+(branch*2+(side^1))*8+w;
   if(out[t.frontier_first+branch]&&(out[a]!=current||out[b]!=sibling))return false;out[a]=current;out[b]=sibling;
   uint32_t upper=out[t.ancestor_first+(uint64_t(q)*(t.depth+1)+t.depth-1)*8+w],other=out[t.output_first+(uint64_t(q)*t.depth+t.depth-1)*8+w];
   a=t.frontier_first+34+branch*8+w;b=t.frontier_first+34+(branch^1)*8+w;if(q&&(out[a]!=upper||out[b]!=other))return false;out[a]=upper;out[b]=other;
  }out[t.frontier_first+branch]=1;
 }}return true;
}
__global__ void child_paths_kernel(const ChildPathTree*trees,uint32_t nt,const ChildPathColumn*cols,uint32_t nc,const uint32_t*packet,uint32_t np,const uint32_t*queries,uint32_t nq,const uint32_t*values,uint32_t nv,uint32_t*out,uint32_t no,uint32_t*error){if(blockIdx.x||threadIdx.x||*error)return;for(uint32_t t=0;t<nt;t++)if(!cp_tree(trees[t],cols,nc,packet,np,queries,nq,values,nv,out,no)){atomicOr(error,1u);return;}}
extern "C" int stwo_parent_child_paths_v1(const ChildPathTree*t,uint32_t nt,const ChildPathColumn*c,uint32_t nc,const uint32_t*p,uint32_t np,const uint32_t*q,uint32_t nq,const uint32_t*v,uint32_t nv,uint32_t*out,uint32_t no,uint32_t*error,cudaStream_t stream){if(!t||!nt||(!c&&nc)||!p||!q||(!v&&nv)||!out||!error)return int(cudaErrorInvalidValue);child_paths_kernel<<<1,1,0,stream>>>(t,nt,c,nc,p,np,q,nq,v,nv,out,no,error);return int(cudaGetLastError());}
