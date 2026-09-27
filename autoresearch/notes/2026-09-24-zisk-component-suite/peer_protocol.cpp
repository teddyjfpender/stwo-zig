#include "transcriptGL.hpp"
#include "blake3_goldilocks.hpp"
// Benchmark-only fatal logging hooks: no logging call is expected on measured paths.
zkLog::zkLog():jsonLogs(false){pthread_mutex_init(&mutex,nullptr);}
void zkLog::log(zkLogType,const std::string&,const std::vector<LogTag>*){std::abort();}
zkLog zklog;
void exitProcess(){std::abort();}
extern "C" void peer_transcript_case(const uint64_t*data,uint32_t words,uint32_t draws,uint64_t*out){
 define_hash_family(HashFamily::Blake3);TranscriptGL t(2,false);std::vector<Goldilocks::Element>in(words);for(unsigned i=0;i<words;i++)in[i]=Goldilocks::fromU64(data[i]);t.put(in.data(),words);for(unsigned i=0;i<draws;i++)t.getField(out+i*3);
}
extern "C" uint64_t peer_protocol_batch(uint32_t op,uint32_t words,uint32_t rounds){
 define_hash_family(HashFamily::Blake3);std::vector<Goldilocks::Element>in(words);for(unsigned i=0;i<words;i++)in[i]=Goldilocks::fromU64(i+1);uint64_t sum=0;
 for(unsigned r=0;r<rounds;r++){
  if(op==0){in[0]=Goldilocks::fromU64(r+1);TranscriptGL t(2,false);t.put(in.data(),words);uint64_t out[3];for(unsigned d=0;d<8;d++){t.getField(out);for(auto v:out)sum+=v;}}
  else {uint64_t state[8]={17,29,41,r,0,0,0,0},out[8];blake3core::permute8(state,out);sum+=out[0];}
 }return sum;
}
extern "C" uint64_t peer_grind_case(uint64_t seed,uint32_t bits){uint64_t in[3]={seed,29,41},nonce;Blake3Goldilocks::grinding(nonce,in,bits);return nonce;}
