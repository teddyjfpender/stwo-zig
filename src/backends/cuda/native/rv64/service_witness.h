#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct StwoRv64ServiceState {uint64_t value;uint32_t tick;uint16_t epoch;uint8_t rights,reserved;} StwoRv64ServiceState;
typedef struct StwoRv64BulkCall {uint64_t pointer,dst,word1,len;uint32_t epoch,tick,op,examined;int32_t result;uint32_t first_word,first_scan,reserved;StwoRv64ServiceState packet[4];} StwoRv64BulkCall;
typedef struct StwoRv64BulkWord {StwoRv64ServiceState dst,src;} StwoRv64BulkWord;
typedef struct StwoRv64ServiceRow {uint32_t call,word,index,reserved;} StwoRv64ServiceRow;
typedef struct StwoRv64BulkWitness {
 const StwoRv64BulkCall *calls;const StwoRv64BulkWord *words;const StwoRv64ServiceRow *rows;
 const uint32_t *pending;uint32_t *main,*range16,*jump_counts,*status;
 uint32_t count,log,kind,call_count,word_count,pending_count;
} StwoRv64BulkWitness;
typedef struct StwoRv64SpongeCall {uint64_t pointer;uint32_t epoch,tick,first_word,first_perm;StwoRv64ServiceState packet[4],state[25];} StwoRv64SpongeCall;
typedef struct StwoRv64SpongeWitness {
 const StwoRv64SpongeCall *calls;const StwoRv64ServiceState *words;const uint64_t *outputs;const StwoRv64ServiceRow *rows;
 uint32_t *main,*range16,*range8,*and_counts,*status;uint32_t count,log,kind,first_id,call_count,word_count,permutation_count,reserved;
} StwoRv64SpongeWitness;
int stwo_rv64_bulk_analyze_on(void *,uint32_t,const StwoRv64BulkCall *,uint32_t,const StwoRv64BulkWord *,uint32_t,uint32_t *,uint32_t,uint32_t *,uint32_t *);
int stwo_rv64_bulk_witness_on(void *,uint32_t,const StwoRv64BulkWitness *);
int stwo_rv64_sponge_outputs_on(void *,uint32_t,const uint64_t *,uint64_t *,uint32_t,uint32_t *);
int stwo_rv64_sponge_witness_on(void *,uint32_t,const StwoRv64SpongeWitness *);
#ifdef __cplusplus
}
static_assert(sizeof(StwoRv64ServiceState)==16 && sizeof(StwoRv64ServiceRow)==16,"service state packing");
static_assert(sizeof(StwoRv64BulkCall)==128 && sizeof(StwoRv64SpongeCall)==488,"service call packing");
#endif
