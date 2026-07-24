#include "fri_final.cuh"

#include <cuda_runtime.h>

#include "fields.cuh"
#include "utils.cuh"

namespace {

constexpr uint32_t SECURE_COORDINATES = 4U;
constexpr uint32_t M31_P = 0x7fffffffU;
constexpr uint32_t BLOCK_SIZE = 256U;

// LineEvaluation stores evaluations in bit-reversed order. The reference first
// bit-reverses them before line_ifft, so materialize that exact natural order in
// the caller-owned coefficient workspace.
__global__ void naturalize_line_evaluation(
    const uint32_t *evaluation,
    uint32_t evaluation_stride,
    uint32_t log_size,
    uint32_t *coefficients) {
  const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t coordinate = blockIdx.y;
  const uint32_t size = 1U << log_size;
  if (row < size && coordinate < SECURE_COORDINATES) {
    coefficients[coordinate * size + row] =
        evaluation[coordinate * evaluation_stride + bit_reverse(row, log_size)];
  }
}

// One exact iteration of prover::line::line_ifft. The twiddle tree stores each
// coset layer in bit-reversed order, while line_ifft walks the domain naturally.
__global__ void line_ifft_stage(
    uint32_t *coefficients,
    uint32_t size,
    uint32_t domain_log_size,
    const uint32_t *inverse_twiddles,
    uint32_t inverse_twiddle_words) {
  const uint32_t butterfly = blockIdx.x * blockDim.x + threadIdx.x;
  const uint32_t coordinate = blockIdx.y;
  if (butterfly >= (size >> 1U) || coordinate >= SECURE_COORDINATES) {
    return;
  }

  const uint32_t domain_size = 1U << domain_log_size;
  const uint32_t half = domain_size >> 1U;
  const uint32_t chunk = butterfly / half;
  const uint32_t index = butterfly - chunk * half;
  const uint32_t left = chunk * domain_size + index;
  const uint32_t right = left + half;
  const uint32_t twiddle_index =
      domain_log_size == 1U ? 0U : bit_reverse(index, domain_log_size - 1U);
  const uint32_t twiddle =
      inverse_twiddles[inverse_twiddle_words - domain_size + twiddle_index];

  uint32_t *column = coefficients + coordinate * size;
  const uint32_t a = column[left];
  const uint32_t b = column[right];
  column[left] = add(a, b);
  column[right] = mul(sub(a, b), twiddle);
}

__global__ void normalize_line_coefficients(
    uint32_t *coefficients,
    uint32_t words,
    uint32_t factor) {
  const uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
  if (index < words) {
    coefficients[index] = mul(coefficients[index], factor);
  }
}

__global__ void validate_high_coefficients(
    const uint32_t *coefficients,
    uint32_t size,
    uint32_t log_size,
    uint32_t degree_bound,
    uint32_t *degree_error) {
  const uint32_t ordered_index =
      degree_bound + blockIdx.x * blockDim.x + threadIdx.x;
  if (ordered_index >= size) {
    return;
  }
  const uint32_t source_index = bit_reverse(ordered_index, log_size);
  uint32_t nonzero = 0U;
#pragma unroll
  for (uint32_t coordinate = 0; coordinate < SECURE_COORDINATES; ++coordinate) {
    nonzero |= coefficients[coordinate * size + source_index];
  }
  if (nonzero != 0U) {
    atomicExch(degree_error, 1U);
  }
}

__global__ void emit_ordered_low_coefficients(
    const uint32_t *coefficients,
    uint32_t size,
    uint32_t log_size,
    uint32_t degree_bound,
    const uint32_t *degree_error,
    uint32_t *transcript_coefficients) {
  const uint32_t output_index = blockIdx.x * blockDim.x + threadIdx.x;
  if (output_index >= degree_bound) {
    return;
  }
  const uint32_t log_degree_bound =
      degree_bound == 1U ? 0U : 31U - static_cast<uint32_t>(__clz(degree_bound));
  // commit_last_layer first truncates natural-order coefficients, then calls
  // LinePoly::from_ordered_coefficients, which bit-reverses the retained vector
  // before it is mixed into the channel and serialized into the proof.
  const uint32_t ordered_index = log_degree_bound == 0U
                                     ? 0U
                                     : bit_reverse(output_index, log_degree_bound);
  const uint32_t source_index = bit_reverse(ordered_index, log_size);
#pragma unroll
  for (uint32_t coordinate = 0; coordinate < SECURE_COORDINATES; ++coordinate) {
    transcript_coefficients[SECURE_COORDINATES * output_index + coordinate] =
        coefficients[coordinate * size + source_index];
  }

  // MixFelts validates every word as canonical M31. Poisoning its first word
  // makes a bad degree bound fail closed without a replay-time host read.
  if (output_index == 0U && *degree_error != 0U) {
    transcript_coefficients[0] = M31_P;
  }
}

}  // namespace

extern "C" int stwo_fri_last_layer_on(
    const uint32_t *evaluation,
    uint32_t evaluation_stride,
    uint32_t log_size,
    const uint32_t *inverse_twiddles,
    uint32_t inverse_twiddle_words,
    uint32_t log_degree_bound,
    uint32_t *coefficients,
    uint32_t *degree_error,
    uint32_t *transcript_coefficients,
    void *stream_raw) {
  if (evaluation == nullptr || inverse_twiddles == nullptr ||
      coefficients == nullptr || degree_error == nullptr ||
      transcript_coefficients == nullptr || stream_raw == nullptr ||
      log_size == 0U || log_size > 30U ||
      log_degree_bound > log_size) {
    return static_cast<int>(cudaErrorInvalidValue);
  }
  const uint32_t size = 1U << log_size;
  if (evaluation_stride < size || inverse_twiddle_words < size) {
    return static_cast<int>(cudaErrorInvalidValue);
  }

  cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
  const uint32_t row_blocks = (size + BLOCK_SIZE - 1U) / BLOCK_SIZE;
  naturalize_line_evaluation<<<dim3(row_blocks, SECURE_COORDINATES), BLOCK_SIZE,
                               0, stream>>>(
      evaluation, evaluation_stride, log_size, coefficients);
  cudaError_t error = cudaGetLastError();
  if (error != cudaSuccess) {
    return static_cast<int>(error);
  }

  const uint32_t butterfly_blocks =
      ((size >> 1U) + BLOCK_SIZE - 1U) / BLOCK_SIZE;
  for (uint32_t domain_log_size = log_size; domain_log_size > 0U;
       --domain_log_size) {
    line_ifft_stage<<<dim3(butterfly_blocks, SECURE_COORDINATES), BLOCK_SIZE,
                      0, stream>>>(
        coefficients, size, domain_log_size, inverse_twiddles,
        inverse_twiddle_words);
    error = cudaGetLastError();
    if (error != cudaSuccess) {
      return static_cast<int>(error);
    }
  }

  const uint32_t words = SECURE_COORDINATES * size;
  // In M31, (2^log_size)^-1 = 2^(31-log_size).
  const uint32_t normalization = 1U << (31U - log_size);
  normalize_line_coefficients<<<(words + BLOCK_SIZE - 1U) / BLOCK_SIZE,
                                BLOCK_SIZE, 0, stream>>>(
      coefficients, words, normalization);
  error = cudaGetLastError();
  if (error != cudaSuccess) {
    return static_cast<int>(error);
  }

  const uint32_t degree_bound = 1U << log_degree_bound;
  const uint32_t high_count = size - degree_bound;
  if (high_count != 0U) {
    validate_high_coefficients<<<(high_count + BLOCK_SIZE - 1U) / BLOCK_SIZE,
                                 BLOCK_SIZE, 0, stream>>>(
        coefficients, size, log_size, degree_bound, degree_error);
    error = cudaGetLastError();
    if (error != cudaSuccess) {
      return static_cast<int>(error);
    }
  }
  emit_ordered_low_coefficients<<<
      (degree_bound + BLOCK_SIZE - 1U) / BLOCK_SIZE, BLOCK_SIZE, 0, stream>>>(
      coefficients, size, log_size, degree_bound, degree_error,
      transcript_coefficients);
  return static_cast<int>(cudaGetLastError());
}
