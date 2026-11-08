#pragma once
#include <stdint.h>
struct StwoRv64SecpWitness {
 const uint32_t* inputs; uint32_t* main; uint32_t* byte_counts; uint32_t* status;
 uint64_t input_words,main_words;
 uint32_t calls,first_id,log,kind;
};
extern "C" int stwo_rv64_secp_witness_on(void*,uint32_t,const StwoRv64SecpWitness*);
