#ifndef STWO_CUDA_RV64_BRIDGE_WITNESS_H
#define STWO_CUDA_RV64_BRIDGE_WITNESS_H
#include <cstdint>
// Four header words; eight words per original authenticated RAM predecessor.
struct StwoRv64BridgeWitness {
 const uint32_t *inputs;
 uint32_t *main,*range16,*range8,*status;
 uint64_t input_words,main_words;
 uint32_t calls,first_id,log,kind,coordinates,write_mask;
};
static_assert(sizeof(StwoRv64BridgeWitness)==80,"bridge witness ABI");
extern "C" int stwo_rv64_bridge_witness_on(void*,uint32_t,const StwoRv64BridgeWitness*);
#endif
