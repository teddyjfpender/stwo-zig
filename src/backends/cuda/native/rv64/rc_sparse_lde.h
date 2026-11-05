#pragma once
#include <stdint.h>
struct StwoRv64SparseLease { uint64_t context_token,generation;uint32_t*words;uint64_t count;uint32_t kind,reserved; };
struct StwoRv64SparseColumn { const uint32_t*words;uint64_t count,context_token,generation; };
struct StwoRv64SparseLde {
  uint32_t version,source_log,eval_log,column_count,cache_slots,reserved;
  void*session;uint32_t scope[8];
  const StwoRv64SparseColumn*sources;const uint32_t*slots;
  StwoRv64SparseLease cache,tables,twiddles;
};
// Sole selected geometry/stream: source18/eval20, lane0. Tables are caller-owned 4*count
// scratch words. Every host descriptor/scope/range/alias is checked before
// any upload or launch. Must run inside ONE serialized Service owner callback;
// concurrent interleaving of table updates and launches is not supported. Sources may be separate retained/immutable leases;
// cache destinations must be distinct, live, scoped slots. No host joins.
extern "C" int stwo_rv64_rc_sparse_lde_on(void*,uint32_t,const StwoRv64SparseLde*,uint32_t*);
