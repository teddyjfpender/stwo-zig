#pragma once
// Lazy outer-GKR input authority. Uses the ORIGINAL row-to-lookup tuple
// emitter; only the storage layout changes to lane-major for the GKR.
#include "om31.cuh"
#if defined(STWO_CIRCUIT_OM31_HOST_EMULATION)
#define STWO_CIRCUIT_INTERACTION_HOST_EMULATION
#endif
#include "../circuit/lookup_tuples.cuh"
#if !defined(STWO_CIRCUIT_OM31_HOST_EMULATION)
#include "custody.cuh"
#endif

struct StwoCircuitOuterGkrSource {
  const uint32_t *fixed;
  const uint32_t *main;
  const uint32_t *parameters; //56 words: z, alpha^0..alpha^5 (OM31 AoS)
  uint32_t *status;
  uint64_t fixed_words;
  uint64_t main_words;
  uint32_t component;
  uint32_t row_log;
  uint32_t lane_first;
  uint32_t lane_log;
};

namespace stwo::cuda::rv64::outer_gkr {
namespace tuples = stwo::cuda::circuit_interaction;

inline bool valid_source(const StwoCircuitOuterGkrSource &s) {
  if (!s.main || !s.parameters || !s.status || s.row_log < 4 ||
      s.row_log > 27 || s.lane_log > 4 || s.row_log + s.lane_log > 28 ||
      !(s.component == 2 || s.component == 3 || s.component == 4 || s.component == 6))
    return false;
  const uint64_t rows = uint64_t(1) << s.row_log;
  if (s.fixed_words != rows * tuples::kPpWidths[s.component] ||
      s.main_words != rows * tuples::kBaseWidths[s.component] ||
      (s.fixed_words && !s.fixed)) return false;
  const uint32_t count = s.component == 2 ? 12 : s.component == 3 ? 5 :
                         s.component == 4 ? 26 : 16;
  return s.lane_first <= count && (1u << s.lane_log) <= count - s.lane_first;
}

template<unsigned Kind> struct Source {
  StwoCircuitOuterGkrSource source;
#if !defined(STWO_CIRCUIT_OM31_HOST_EMULATION)
  bool validate(Custody &c, uint32_t count) const {
    return valid_source(source) && source.component == Kind &&
      count == (1u << (source.row_log + source.lane_log)) &&
      (!source.fixed_words || c.range(source.fixed, source.fixed_words, false)) &&
      c.range(source.main, source.main_words, false) && c.range(source.parameters, 56, false) &&
      c.range(source.status, 1, true);
  }
#endif
  __host__ __device__ __forceinline__ void fail(uint32_t bits) const {
#if defined(__CUDA_ARCH__)
    atomicOr(source.status, bits);
#else
    *source.status |= bits;
#endif
  }
  template<unsigned Lookup>
  __host__ __device__ __forceinline__ Fraction at_row(uint32_t row) const {
    if constexpr (Lookup < tuples::lookup_count<Kind>()) {
      const uint32_t rows = 1u << source.row_log;
      tuples::Columns cols{};
      for (unsigned c = 0; c < tuples::pp_width<Kind>(); ++c)
        cols.pp[c] = source.fixed + uint64_t(c) * rows;
      for (unsigned c = 0; c < tuples::base_width<Kind>(); ++c)
        cols.base[c] = source.main + uint64_t(c) * rows;
      // Lookup is constant at each switch arm. This lets NVCC retain only
      // the MAIN/FIXED columns the term reads, avoiding52-column spills.
      const auto lookup = tuples::lookup_at<Kind>(Lookup, row, cols);
      OM31 denominator = sub(zero(), from_words(source.parameters));
      for (unsigned c = 0; c < lookup.len; ++c)
        denominator = add(denominator, scale(from_words(source.parameters + 8 * (c + 1)), lookup.tuple[c]));
      const OM31 numerator = base(lookup.numerator);
      if (!canonical(numerator) || !canonical(denominator) || is_zero(denominator)) {
        fail(1u);
      }
      // A real pole remains a real pole. Sticky status additionally refuses
      // the request; it must never be laundered into neutral padding (0,1).
      return {numerator, denominator};
    }
    return {zero(), one()};
  }
  __host__ __device__ __forceinline__ Fraction get(uint32_t index) const {
    const uint32_t row = index & ((1u << source.row_log) - 1);
    const uint32_t term = source.lane_first + (index >> source.row_log);
#define OGKR_TERM(C) case C: return at_row<C>(row)
    switch (term) {
      OGKR_TERM(0); OGKR_TERM(1); OGKR_TERM(2); OGKR_TERM(3);
      OGKR_TERM(4); OGKR_TERM(5); OGKR_TERM(6); OGKR_TERM(7);
      OGKR_TERM(8); OGKR_TERM(9); OGKR_TERM(10); OGKR_TERM(11);
      OGKR_TERM(12); OGKR_TERM(13); OGKR_TERM(14); OGKR_TERM(15);
      OGKR_TERM(16); OGKR_TERM(17); OGKR_TERM(18); OGKR_TERM(19);
      OGKR_TERM(20); OGKR_TERM(21); OGKR_TERM(22); OGKR_TERM(23);
      OGKR_TERM(24); OGKR_TERM(25);
      default: fail(2u); return {zero(), one()};
    }
#undef OGKR_TERM
  }
  __host__ __device__ __forceinline__ Fraction operator()(uint32_t index) const { return get(index); }
};
} // namespace stwo::cuda::rv64::outer_gkr
