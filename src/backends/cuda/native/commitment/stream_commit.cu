// M9 streaming commit prototype entry points (STWO_RV64_M9_STREAM_COMMIT).
// Default off: nothing in the prover calls these yet; see
// design/riscv-proving-stack/rv64-m9-stream-commit.md for the integration.

#include "stream_commit.cuh"
#include "../transform/n2b_smem.cuh"

#include <cstdlib>

namespace m9 = stwo::cuda::m9;
using stwo::cuda::M31;
using stwo::cuda::transform::ColumnSlab;

extern "C" int stwo_m9_stream_commit_enabled(void) {
  static const int enabled = [] {
    const char *v = std::getenv("STWO_RV64_M9_STREAM_COMMIT");
    return v && v[0] == '1' ? 1 : 0;
  }();
  return enabled;
}

// Fused tile height: the smallest Low >= 10 whose W1 height log_n - Low fits
// the existing strided kernels (<= 11).
extern "C" uint32_t stwo_m9_stream_commit_low_bits(uint32_t log_n) {
  if (log_n < 15 || log_n > 24) return 0;
  return log_n > 21 ? log_n - 11u : 10u;
}
static bool valid_split(uint32_t log_n, uint32_t low) {
  return log_n >= 15 && log_n <= 24 && low >= 10 && low <= 13 && log_n - low >= 5 && log_n - low <= 14;
}

// Taller W1 than production allows (heights 12..14 with 4/2/1-word lanes), so
// the fused pass can run with fewer cross-CTA stages. Same body as
// n2b_wide_strided_rows<High, LaneLog, true> (whose shape asserts High <= 11).
template <uint32_t High, uint32_t LaneLog>
__global__ __launch_bounds__(1u << (High + LaneLog - 5u)) void m9_strided_rows(
    ColumnSlab<const M31> inputs, const uint32_t *input_log_sizes, ColumnSlab<M31> columns,
    uint32_t log_n, const M31 *twiddles) {
  using namespace stwo::cuda::transform;
  extern __shared__ M31 tile_values[];
  const uint32_t column_index = blockIdx.y, tile = blockIdx.x;
  const M31 *input = inputs.column(column_index);
  M31 *column = columns.column(column_index);
  const uint32_t t = threadIdx.x;
  const uint32_t lane = t & ((1u << LaneLog) - 1u);
  const uint32_t j = t >> LaneLog;
  const uint32_t shift = log_n - High;
  const uint32_t fixed = (tile << LaneLog) | lane;
  const uint32_t input_log_size = input_log_sizes[column_index];
  const uint32_t requested = input_log_size < 31u ? 1u << input_log_size : 0u;
  const uint32_t domain = 1u << (log_n - 1u);
  const uint32_t input_count = requested < domain ? requested : domain;
  M31 v[kWideValues];
  n2b_wide_rows_phase<High, LaneLog, 0, true>(v, tile_values, input, column, input_count, j, lane,
                                              shift, fixed, log_n, twiddles);
  n2b_wide_rows_phase<High, LaneLog, 1, true>(v, tile_values, input, column, input_count, j, lane,
                                              shift, fixed, log_n, twiddles);
  n2b_wide_rows_phase<High, LaneLog, 2, true>(v, tile_values, input, column, input_count, j, lane,
                                              shift, fixed, log_n, twiddles);
}

// W1 only (stages 1..H, coefficient load + zero extension), with the same
// kernels launch_n2b_wide uses at that height.
extern "C" int stwo_m9_lde_first_pass_split_on(const uint32_t *coefficients, size_t coefficient_stride,
                                               const uint32_t *coefficient_logs, uint32_t *intermediate,
                                               size_t intermediate_stride, uint32_t log_n, uint32_t count,
                                               const uint32_t *twiddles, uint32_t twiddle_words,
                                               uint32_t low, void *stream_raw) {
  using namespace stwo::cuda::transform;
  if (!low) low = stwo_m9_stream_commit_low_bits(log_n);
  if (!valid_split(log_n, low) || !coefficients || !coefficient_logs || !intermediate || !twiddles || !count ||
      !stream_raw || twiddle_words < (1u << (log_n - 1)) ||
      intermediate_stride < (size_t(1) << log_n))
    return int(cudaErrorInvalidValue);
  const uint32_t high = log_n - low;
  const auto *tw = reinterpret_cast<const M31 *>(twiddles + twiddle_words - (1u << (log_n - 1)));
  auto stream = reinterpret_cast<cudaStream_t>(stream_raw);
  for (uint32_t base = 0; base < count; base += 65535u) {
    const uint32_t chunk = count - base < 65535u ? count - base : 65535u;
    ColumnSlab<const M31> in{reinterpret_cast<const M31 *>(coefficients) + size_t(base) * coefficient_stride,
                             coefficient_stride};
    ColumnSlab<M31> out{reinterpret_cast<M31 *>(intermediate) + size_t(base) * intermediate_stride,
                        intermediate_stride};
    const uint32_t *logs = coefficient_logs + base;
    cudaError_t status = cudaSuccess;
    if (high >= 12) {
      const auto tall = [&](auto kernel, uint32_t lane_log) {
        const uint32_t words = 1u << (high + lane_log);
        const size_t bytes = sizeof(M31) * (words + words / 32u);
        cudaError_t e = wide_allow_shared_bytes(kernel, bytes);
        if (e != cudaSuccess) return e;
        kernel<<<dim3{1u << (log_n - high - lane_log), chunk}, 1u << (high + lane_log - 5u), bytes, stream>>>(
            in, logs, out, log_n, tw);
        return cudaPeekAtLastError();
      };
      if (high == 12) status = tall(m9_strided_rows<12, 2>, 2);
      else if (high == 13) status = tall(m9_strided_rows<13, 1>, 1);
      else status = tall(m9_strided_rows<14, 0>, 0);
      if (status != cudaSuccess) return int(status);
    } else if (high == 11) {
      const size_t bytes = sizeof(M31) * ((size_t(8) << 11) + (size_t(8) << 11) / 32u);
      status = wide_allow_shared_bytes(n2b_wide_strided<true>, bytes);
      if (status != cudaSuccess) return int(status);
      n2b_wide_strided<true><<<dim3{1u << (log_n - 14), chunk}, kWideStridedThreads, bytes, stream>>>(
          in, logs, out, log_n, tw, 0u);
    } else {
#define STWO_M9_ROWS(H)                                                                   \
  case H: {                                                                               \
    constexpr uint32_t lane_log = n2b_wide_rows_lane_log(H);                              \
    using Shape = WideStridedShape<H, lane_log>;                                          \
    status = wide_allow_shared_bytes(n2b_wide_strided_rows<H, lane_log, true>, Shape::bytes); \
    if (status != cudaSuccess) return int(status);                                        \
    n2b_wide_strided_rows<H, lane_log, true>                                              \
        <<<dim3{1u << (log_n - H - lane_log), chunk}, Shape::threads, Shape::bytes, stream>>>( \
            in, logs, out, log_n, tw, 0u);                                                \
  } break;
      switch (high) {
        STWO_M9_ROWS(5) STWO_M9_ROWS(6) STWO_M9_ROWS(7) STWO_M9_ROWS(8) STWO_M9_ROWS(9)
        STWO_M9_ROWS(10)
        default: return int(cudaErrorInvalidValue);
      }
#undef STWO_M9_ROWS
    }
    status = cudaPeekAtLastError();
    if (status != cudaSuccess) return int(status);
  }
  return 0;
}

extern "C" int stwo_m9_lde_first_pass_on(const uint32_t *coefficients, size_t coefficient_stride,
                                         const uint32_t *coefficient_logs, uint32_t *intermediate,
                                         size_t intermediate_stride, uint32_t log_n, uint32_t count,
                                         const uint32_t *twiddles, uint32_t twiddle_words,
                                         void *stream_raw) {
  return stwo_m9_lde_first_pass_split_on(coefficients, coefficient_stride, coefficient_logs, intermediate,
                                         intermediate_stride, log_n, count, twiddles, twiddle_words, 0,
                                         stream_raw);
}

extern "C" size_t stwo_m9_stream_commit_smem_bytes(uint32_t) {
  return sizeof(uint32_t) * m9::kSmemWords;
}

template <uint32_t Low, bool LdeInput = false>
static int launch(const m9::StreamCommitParams &p, cudaStream_t stream) {
  constexpr uint32_t cluster = 1u << (Low - 10);
  auto kernel = m9::stream_commit_kernel<Low, LdeInput>;
  const size_t bytes = stwo_m9_stream_commit_smem_bytes(Low);
  cudaError_t status = cudaFuncSetAttribute(kernel, cudaFuncAttributeMaxDynamicSharedMemorySize, int(bytes));
  if (status != cudaSuccess) return int(status);
  cudaLaunchConfig_t config{};
  config.gridDim = dim3{(1u << p.log_n) / m9::kRows, 1, 1};
  config.blockDim = dim3{m9::kRows, 1, 1};
  config.dynamicSmemBytes = bytes;
  config.stream = stream;
  cudaLaunchAttribute attribute{};
  attribute.id = cudaLaunchAttributeClusterDimension;
  attribute.val.clusterDim.x = cluster;
  attribute.val.clusterDim.y = 1;
  attribute.val.clusterDim.z = 1;
  config.attrs = &attribute;
  config.numAttrs = 1;
  return int(cudaLaunchKernelEx(&config, kernel, p));
}

// Fused W2 + leaf absorption for one chunk of full-height columns. Exactly one
// of prefix / nodes is set (non-final / final call), as in
// stwo_blake2s_mixed_seeded_eager_compact_on.
extern "C" int stwo_m9_stream_commit_on(const m9::StreamCommitParams *params, void *stream_raw) {
  if (!params || !stream_raw) return int(cudaErrorInvalidValue);
  m9::StreamCommitParams p = *params;
  if (p.lde_input > 1 || (p.lde_input && p.low_bits && p.low_bits != 10)) return int(cudaErrorInvalidValue);
  const uint32_t low = p.lde_input ? 10u : p.low_bits ? p.low_bits : stwo_m9_stream_commit_low_bits(p.log_n);
  const uint32_t size = 1u << p.log_n;
  if (!valid_split(p.log_n, low) || !p.intermediate || !p.columns || (!p.twiddles && !p.lde_input) || !p.status ||
      (p.paths && p.path_log < p.log_n) ||
      p.column_stride_words < size || ((p.prefix == nullptr) == (p.nodes == nullptr)) ||
      p.subtree_levels > m9::kMaxSubtreeLevels || (p.prefix && p.subtree_levels) ||
      (p.query_count && (!p.query_rows || !p.values)) || (p.paths && !p.query_count) ||
      uint64_t(p.absorbed_before) + p.columns > UINT32_MAX)
    return int(cudaErrorInvalidValue);
  if (p.seed) {
    if (!p.absorbed_before || p.seed_size < 2 || p.seed_size > size || (p.seed_size & (p.seed_size - 1)))
      return int(cudaErrorInvalidValue);
  } else if (p.absorbed_before || p.seed_size) {
    return int(cudaErrorInvalidValue);
  }
  auto stream = reinterpret_cast<cudaStream_t>(stream_raw);
  if (p.lde_input) return launch<10, true>(p, stream);
  switch (low) {
    case 10: return launch<10>(p, stream);
    case 11: return launch<11>(p, stream);
    case 12: return launch<12>(p, stream);
    case 13: return launch<13>(p, stream);
    default: return int(cudaErrorInvalidValue);
  }
}

extern "C" int stwo_m9_stream_commit_upper_paths_on(const uint32_t *tree, uint32_t tree_log,
                                                    uint32_t k, const uint32_t *query_rows,
                                                    uint32_t query_count, uint32_t *paths,
                                                    void *stream_raw) {
  if (!tree || !query_rows || !paths || !stream_raw || k >= tree_log || !query_count)
    return int(cudaErrorInvalidValue);
  const uint32_t work = (tree_log - k) * 8u;
  m9::stream_commit_upper_paths<0><<<dim3{(work + 127u) / 128u, query_count}, 128, 0,
                                  reinterpret_cast<cudaStream_t>(stream_raw)>>>(
      tree, tree_log, k, query_rows, query_count, paths);
  return int(cudaPeekAtLastError());
}

// Diagnostics: active clusters / CTAs the device can co-schedule for a height.
extern "C" int stwo_m9_stream_commit_occupancy(uint32_t log_n, int *clusters, int *cluster_size) {
  uint32_t low = stwo_m9_stream_commit_low_bits(log_n);
  if (!low || !clusters || !cluster_size) return int(cudaErrorInvalidValue);
  if (const char *o = std::getenv("SC_LOW")) low = uint32_t(std::atoi(o));
  cudaLaunchConfig_t config{};
  config.gridDim = dim3{(1u << log_n) / m9::kRows, 1, 1};
  config.blockDim = dim3{m9::kRows, 1, 1};
  config.dynamicSmemBytes = stwo_m9_stream_commit_smem_bytes(low);
  cudaLaunchAttribute attribute{};
  attribute.id = cudaLaunchAttributeClusterDimension;
  attribute.val.clusterDim.x = 1u << (low - 10);
  attribute.val.clusterDim.y = attribute.val.clusterDim.z = 1;
  config.attrs = &attribute;
  config.numAttrs = 1;
  *cluster_size = int(1u << (low - 10));
  cudaError_t status = cudaSuccess;
#define STWO_M9_OCC(L)                                                                          \
  case L:                                                                                       \
    status = cudaFuncSetAttribute(m9::stream_commit_kernel<L>,                                  \
                                  cudaFuncAttributeMaxDynamicSharedMemorySize,                  \
                                  int(config.dynamicSmemBytes));                                \
    if (status == cudaSuccess)                                                                  \
      status = cudaOccupancyMaxActiveClusters(clusters, m9::stream_commit_kernel<L>, &config);  \
    break;
  switch (low) { STWO_M9_OCC(10) STWO_M9_OCC(11) STWO_M9_OCC(12) STWO_M9_OCC(13) default: break; }
#undef STWO_M9_OCC
  return int(status);
}
