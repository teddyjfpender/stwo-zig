#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
struct StwoChildCheck{uint32_t kind,first,count,low,high;};
struct StwoChildInput{uint32_t kind,destination,index,aux,arg;};
extern "C" int stwo_parent_child_validate_v1(const uint32_t*,uint32_t,const StwoChildCheck*,uint32_t,uint32_t*,cudaStream_t);
extern "C" int stwo_parent_child_gather_v1(const uint32_t*,uint32_t,const uint32_t*,uint32_t,const uint32_t*,uint32_t,uint32_t,const StwoChildInput*,uint32_t,uint32_t*,uint32_t,uint32_t*,cudaStream_t);
#define OK(x) do{int e=(int)(x);if(e){fprintf(stderr,"CUDA failure %d line %d\n",e,__LINE__);return 1;}}while(0)
template<class T>T* put(const std::vector<T>&v){T*p=nullptr;if(cudaMalloc((void**)&p,v.size()*sizeof(T))||cudaMemcpy(p,v.data(),v.size()*sizeof(T),cudaMemcpyHostToDevice))abort();return p;}
int main(){
 std::vector<uint32_t> packet={11,22,33,44,0xffffffffu,1,19,0,7,8,9};
 std::vector<uint32_t> resident={123,456,789,42};
 std::vector<uint32_t> queries={9,2,9,7,2,15}; // unique ascending2,7,9,15
 std::vector<StwoChildCheck> checks={{0,0,4,0,0},{1,6,2,19,0},{2,4,2,0xffffffffu,1}};
 std::vector<StwoChildInput> routes;
 std::vector<uint32_t> expected;
 auto add=[&](uint32_t kind,uint32_t index,uint32_t aux,uint32_t arg,uint32_t value){routes.push_back({kind,(uint32_t)routes.size(),index,aux,arg});expected.push_back(value);};
 add(0,1,0,0,1);add(1,0,0,0,11);add(2,1,0,0,456);
 for(uint32_t i=0;i<queries.size();i++)add(3,0,4,i,queries[i]==2?11:queries[i]==7?22:queries[i]==9?33:44);
 add(4,0,1,7,4);add(4,3,0,1,1);add(5,4,0,0,3);
 auto p=put(packet);auto r=put(resident);auto q=put(queries);auto c=put(checks);auto d=put(routes);
 auto error=put(std::vector<uint32_t>{0});auto out=put(std::vector<uint32_t>(routes.size(),0xdeadbeefu));
 OK(stwo_parent_child_validate_v1(p,packet.size(),c,checks.size(),error,0));
 OK(stwo_parent_child_gather_v1(p,packet.size(),r,resident.size(),q,queries.size(),4,d,routes.size(),out,routes.size(),error,0));
 std::vector<uint32_t> got(routes.size());uint32_t verdict;OK(cudaMemcpy(got.data(),out,got.size()*4,cudaMemcpyDeviceToHost));OK(cudaMemcpy(&verdict,error,4,cudaMemcpyDeviceToHost));
 if(verdict||got!=expected){fprintf(stderr,"positive mismatch verdict%u\n",verdict);for(auto x:got)fprintf(stderr,"%u ",x);return 2;}
 unsigned attacks=0;
 auto validateAttack=[&](StwoChildCheck check){cudaMemset(error,0,4);cudaMemcpy(c,&check,sizeof(check),cudaMemcpyHostToDevice);int e=stwo_parent_child_validate_v1(p,packet.size(),c,1,error,0);cudaMemcpy(&verdict,error,4,cudaMemcpyDeviceToHost);if(e||!verdict)abort();attacks++;};
 validateAttack({0,4,1,0,0});validateAttack({1,6,2,18,0});validateAttack({2,4,2,0xfffffffeu,1});validateAttack({0,11,1,0,0});validateAttack({17,0,1,0,0});
 auto gatherAttack=[&](StwoChildInput desc){cudaMemset(error,0,4);cudaMemcpy(d,&desc,sizeof(desc),cudaMemcpyHostToDevice);int e=stwo_parent_child_gather_v1(p,packet.size(),r,resident.size(),q,queries.size(),4,d,1,out,routes.size(),error,0);cudaMemcpy(&verdict,error,4,cudaMemcpyDeviceToHost);if(e||!verdict)abort();attacks++;};
 gatherAttack({3,0,0,3,0});gatherAttack({3,0,0,4,6});gatherAttack({1,0,4,0,0});gatherAttack({2,0,4,0,0});gatherAttack({4,0,0,32,1});gatherAttack({5,0,10,0,0});gatherAttack({0,99,1,0,0});
 uint32_t invalid=16;OK(cudaMemcpy(q,&invalid,4,cudaMemcpyHostToDevice));gatherAttack({3,0,0,4,1});
 cudaFree(p);cudaFree(r);cudaFree(q);cudaFree(c);cudaFree(d);cudaFree(error);cudaFree(out);
 printf("PASS resident child packet %zu words, %u malformed packet/route attacks\n",got.size(),attacks);return 0;
}
