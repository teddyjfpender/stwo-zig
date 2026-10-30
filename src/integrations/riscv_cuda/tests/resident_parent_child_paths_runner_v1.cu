#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
struct Column{uint32_t first,count,log_size;};struct Tree{uint32_t kind,domain_log,depth,query_shift,columns_first,columns_count,values_first,leaf_width,leaf_count,hash_first,hash_count,root_first,output_first,ancestor_first,frontier_first;};
extern "C" int stwo_parent_child_paths_v1(const Tree*,uint32_t,const Column*,uint32_t,const uint32_t*,uint32_t,const uint32_t*,uint32_t,const uint32_t*,uint32_t,uint32_t*,uint32_t,uint32_t*,cudaStream_t);
#define OK(x) do{int result_=(int)(x);if(result_){fprintf(stderr,"cuda%d line%d\n",result_,__LINE__);return 1;}}while(0)
template<class T>std::vector<T>read(FILE*f,size_t n){std::vector<T>v(n);if(fread(v.data(),sizeof(T),n,f)!=n)abort();return v;}
template<class T>T*put(const std::vector<T>&v){T*p;if(cudaMalloc((void**)&p,v.size()*sizeof(T))||cudaMemcpy(p,v.data(),v.size()*sizeof(T),cudaMemcpyHostToDevice))abort();return p;}
int main(int argc,char**argv){if(argc!=2)return 2;FILE*f=fopen(argv[1],"rb");if(!f)return 2;auto h=read<uint32_t>(f,7);if(h[0]!=0x42375041)return 2;auto trees=read<Tree>(f,h[1]);auto columns=read<Column>(f,h[2]);auto packet=read<uint32_t>(f,h[3]);auto queries=read<uint32_t>(f,h[4]);auto values=read<uint32_t>(f,h[5]);auto expected=read<uint32_t>(f,h[6]);if(fgetc(f)!=EOF)return 2;fclose(f);
 auto t=put(trees);auto c=put(columns);auto p=put(packet);auto q=put(queries);auto v=put(values);auto out=put(std::vector<uint32_t>(expected.size()));auto error=put(std::vector<uint32_t>{0});auto run=[&](){cudaMemset(error,0,4);return stwo_parent_child_paths_v1(t,trees.size(),c,columns.size(),p,packet.size(),q,queries.size(),v,values.size(),out,expected.size(),error,0);};OK(run());uint32_t e=0;OK(cudaMemcpy(&e,error,4,cudaMemcpyDeviceToHost));if(e){fprintf(stderr,"honest path error%u\n",e);return 3;}auto actual=expected;OK(cudaMemcpy(actual.data(),out,actual.size()*4,cudaMemcpyDeviceToHost));size_t checked=0;
 for(auto&tree:trees)for(size_t i=0;i<queries.size()*tree.depth*8;i++){size_t at=tree.output_first+i;if(actual[at]!=expected[at]){fprintf(stderr,"path%zu got%u expected%u\n",at,actual[at],expected[at]);return 3;}checked++;}
 for(size_t i=0;i<expected.size();i++)if(actual[i]!=expected[i]){fprintf(stderr,"full path%zu got%u expected%u\n",i,actual[i],expected[i]);return 3;}
 unsigned attacks=0;for(int kind=0;kind<5;kind++){Tree bad=trees[0];if(kind==0)bad.hash_count-=8;if(kind==1)bad.hash_count+=8;if(kind==2)bad.root_first=packet.size();if(kind==3)bad.output_first=expected.size();if(kind==4)bad.query_shift+=1;OK(cudaMemcpy(t,&bad,sizeof(bad),cudaMemcpyHostToDevice));OK(run());OK(cudaMemcpy(&e,error,4,cudaMemcpyDeviceToHost));if(!e)return 4;attacks++;}OK(cudaMemcpy(t,trees.data(),trees.size()*sizeof(Tree),cudaMemcpyHostToDevice));
 uint32_t saved=packet[trees[0].root_first],bad=saved^1;OK(cudaMemcpy(p+trees[0].root_first,&bad,4,cudaMemcpyHostToDevice));OK(run());OK(cudaMemcpy(&e,error,4,cudaMemcpyDeviceToHost));if(!e)return 4;attacks++;
 printf("PASS child Merkle raw witness expansion %zu trees %zu path words %u attacks\n",trees.size(),checked,attacks);cudaFree(t);cudaFree(c);cudaFree(p);cudaFree(q);cudaFree(v);cudaFree(out);cudaFree(error);return 0;}
