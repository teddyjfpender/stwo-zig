#include "rv64/trace_stream_plan.h"
#include <algorithm>
#include <cassert>
#include <iostream>
int main(){
 using namespace stwo::cuda::rv64::stream;
 const unsigned logs[]={16,23,20,21,23,16,20,8,14,18,16};
 const unsigned pairs[]={1,2,6,3,13,1,8,1,1,1,1};
 std::vector<uint32_t> rows;
 for(unsigned i=0;i<11;++i)rows.insert(rows.end(),8*pairs[i],1u<<(logs[i]+1));
 std::sort(rows.begin(),rows.end());
 unsigned trials=0;
 for(uint64_t budget:{1ull<<24,1ull<<25,1ull<<27,1ull<<29})
  for(uint32_t lift:{rows.back(),rows.back()*2}){
   Plan old,compact;assert(plan(rows,budget,&old,lift,false));assert(plan(rows,budget,&compact,lift,true));
   assert(old.calls.size()==compact.calls.size());
   for(size_t i=0;i<old.calls.size();++i){
    const auto&a=old.calls[i];const auto&b=compact.calls[i];
    assert(a.first==b.first&&a.end==b.end&&a.size==b.size&&a.absorbed==b.absorbed&&a.seed_size==b.seed_size&&a.seed_bank==b.seed_bank&&a.out_bank==b.out_bank&&a.final==b.final&&a.chunk_words==b.chunk_words);
    const uint64_t needed=b.final?compact.tree_words:uint64_t(b.size)*(8u+((b.absorbed+b.end-b.first)&15u));
    assert(compact.bank_words[b.out_bank]>=needed);
   }
   assert(compact.scratchWords()<=old.scratchWords());
   if(budget==(1ull<<27)&&lift==rows.back()){
    assert(compact.calls.size()==18&&compact.bank_words[0]==318767104&&compact.bank_words[1]==268435448);
    assert((old.scratchWords()-compact.scratchWords())*4==872415232);
   }++trials;
  }
 std::cout << "CPP_COMPACT_PLAN_PASS " << trials << " " << rows.size() << std::endl;
}
