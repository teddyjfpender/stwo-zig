#pragma once
// Private host dispatch for the statically linked parity benchmark. These
// hidden C++ functions are not a runtime-library C ABI or process selector.
#include "../deep.h"
#include "../samples.h"
namespace stwo::cuda::rv64::detail {
__attribute__((visibility("hidden")))
int deep_prepare(void *, uint32_t, const StwoRv64DeepPrepare *, bool legacy);
__attribute__((visibility("hidden")))
int deep_combine(void *, uint32_t, const StwoRv64DeepCombine *, bool legacy);
__attribute__((visibility("hidden")))
int sample_evaluate(void *, uint32_t, const StwoRv64SampleEvaluation *, bool legacy);
}
