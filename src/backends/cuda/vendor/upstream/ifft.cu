#include "ifft.cuh"
#include "composition_split.cuh"
#include "point.cuh"
#include "poly_utils.cuh"
#include "utils.cuh"

// CUDA caps grid.y and grid.z at 65535 (maxGridSize[1]/[2]). Every batched NTT
// launcher maps the column (batch) axis onto grid.y or grid.z, so a same-log_size
// column group larger than this overflows the launch configuration. The column
// (batch) set is tiled into chunks of at most this many columns.
static constexpr unsigned MAX_NTT_BATCH_COLUMNS = 65535;

__global__ void ifft_circle_part(m31 *values, m31 *inverse_twiddles_tree, int values_size) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < (values_size >> 1)) {
        m31 val0 = values[2 * idx];
        m31 val1 = values[2 * idx + 1];
        m31 twiddle = get_circle_twiddle(inverse_twiddles_tree, idx);

        values[2 * idx] = add(val0, val1);
        values[2 * idx + 1] = mul(sub(val0, val1), twiddle);
    }
}

__global__ void ifft_line_part(m31 *values, m31 *twiddles, int values_size, int layer) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < (values_size >> 1)) {
        // `index` is in [0, values_size / 2).
        // It is interpreted as the n - 1 bit-string `twiddle_index || polynomial_index`,
        // where n = log_2(`values_size`), `polynomial_index` is the rightmost `layer` bits,
        // and `twiddle_index` is the rest `n - layer - 1` bits.
        // This thread performs a butterfly between the values at indexes `twiddle_index || 0 || polynomial_index`
        // and `twiddle_index || 1 || polynomial_index`.
        int number_polynomials = 1 << layer;
        int twiddle_index = idx >> layer;
        int l = idx & (number_polynomials - 1);
        int idx0 = (twiddle_index << (layer + 1)) + l;
        int idx1 = idx0 + number_polynomials;

        m31 val0 = values[idx0];
        m31 val1 = values[idx1];
        m31 twiddle = twiddles[twiddle_index];


        values[idx0] = add(val0, val1);
        values[idx1] = mul(sub(val0, val1), twiddle);

    }
}

void interpolate(int eval_domain_size, m31 *values, m31 *inverse_twiddles_tree, int inverse_twiddles_size, int values_size) {
    inverse_twiddles_tree = &inverse_twiddles_tree[inverse_twiddles_size - eval_domain_size];
    int block_dim = 256;
    int num_blocks = ((values_size >> 1) + block_dim - 1) / block_dim;
    ifft_circle_part<<<num_blocks, block_dim>>>(values, inverse_twiddles_tree, values_size);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    int log_values_size = log_2(values_size);
    int layer_domain_size = values_size >> 1;
    int layer_domain_offset = 0;
    int i = 1;
    while (i < log_values_size) {
        ifft_line_part<<<num_blocks, block_dim>>>(values, &inverse_twiddles_tree[layer_domain_offset], values_size, i);

        layer_domain_size >>= 1;
        layer_domain_offset += layer_domain_size;
        i += 1;
        ASSERT_CUDA_SUCCESS(cudaGetLastError());
        stwo_maybe_debug_sync();
        ASSERT_CUDA_SUCCESS(cudaGetLastError());

    }

    block_dim = 1024;
    num_blocks = (values_size + block_dim - 1) / block_dim;
    m31 factor = inv(pow(m31{2}, log_values_size));
    rescale<<<num_blocks, block_dim>>>(values, values_size, factor);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}



template <unsigned LOG_VALS_PER_THREAD>
DEVICE_FORCEINLINE void shfl_xor_bf(m31* vals, const unsigned log_stride,
                                    const unsigned lane_id) {
    const unsigned mask = 1 << log_stride;
    const unsigned num_pair_per_thread = 1 << (LOG_VALS_PER_THREAD - 1);
    // All callers launch complete warps. In the B2N init kernels this full-mask
    // fence follows every global tile load and precedes every global tile
    // store, which makes an exact input/output tile alias race-free.
    __syncwarp(0xffffffffu);
    #pragma unroll
    for (unsigned i = 0; i < num_pair_per_thread; i++) {
        m31* ptr = lane_id & mask ? vals + 2 * i : vals + 2 * i + 1;
        *ptr = __shfl_xor_sync(0xffffffff, *ptr, mask);
    }
}

// row_block_offset: index of this launch's first row-block along the (tiled)
// grid.y axis; index is identical to a single launch with blockIdx.y + offset.
__global__ void batch_ifft_circle_part(m31 **values, m31 *inverse_twiddles_tree, int values_size, int number_of_rows, int row_block_offset) {
    int index = (blockIdx.y + row_block_offset) * blockDim.x + threadIdx.x;
    unsigned int column_index = blockIdx.x;

    if (index < (number_of_rows >> 1) && column_index < values_size) {
        m31 *column = values[column_index];

        m31 val0 = column[2 * index];
        m31 val1 = column[2 * index + 1];
        m31 twiddle = get_circle_twiddle(inverse_twiddles_tree, index);

        column[2 * index] = add(val0, val1);
        column[2 * index + 1] = mul(sub(val0, val1), twiddle);
    }
}

__global__
void batch_ifft_line_part(m31 **values, m31 *twiddles, int values_size, int number_of_rows, int layer, int row_block_offset) {
    int index = (blockIdx.y + row_block_offset) * blockDim.x + threadIdx.x;
    unsigned int column_index = blockIdx.x;

    if (index < (number_of_rows >> 1) && column_index < values_size) {
        // `index` is in [0, number_of_rows / 2).
        // It is interpreted as the n - 1 bit-string `twiddle_index || polynomial_index`,
        // where n = log_2(`number_of_rows`), `polynomial_index` is the rightmost `layer` bits,
        // and `twiddle_index` is the rest `n - layer - 1` bits.
        // This thread performs a butterfly between the values at indexes `twiddle_index || 0 || polynomial_index`
        // and `twiddle_index || 1 || polynomial_index`.
        m31 *column = values[column_index];

        int number_polynomials = 1 << layer;
        int twiddle_index = index >> layer;
        int polynomial_index = index & (number_polynomials - 1);

        int idx0 = (twiddle_index << (layer + 1)) | polynomial_index;
        int idx1 = idx0 | number_polynomials;

        m31 val0 = column[idx0];
        m31 val1 = column[idx1];

        m31 twiddle = twiddles[twiddle_index];

        column[idx0] = add(val0, val1);
        column[idx1] = mul(sub(val0, val1), twiddle);
    }
}

__global__ void batch_rescale(m31 **values, int values_size, int number_of_rows, m31 factor, int row_block_offset) {
    int index = (blockIdx.y + row_block_offset) * blockDim.x + threadIdx.x;
    unsigned int column_index = blockIdx.x;

    if (index < number_of_rows && column_index < values_size) {
        values[column_index][index] = mul(values[column_index][index], factor);
    }
}


void interpolate_columns(int eval_domain_size, m31 **values, m31 *inverse_twiddles_tree, int inverse_twiddles_size,
                         int values_size, int number_of_rows) {
    // TODO: Handle case where columns are of different sizes.
    int blockDimensions = 1024;

    m31 **device_values = cuda_proving_clone_to_device<m31*>(values, values_size);

    m31 *inverseTwiddlesTree = inverse_twiddles_tree;
    inverseTwiddlesTree = &inverseTwiddlesTree[inverse_twiddles_size - eval_domain_size];
    int numBlocks = ((number_of_rows >> 1) + blockDimensions - 1) / blockDimensions;

    // The row-block axis is grid.y (CUDA cap 65535); columns ride grid.x
    // (cap 2^31-1, never workload-limited here). Tile the row-block axis:
    // each chunk covers disjoint index values via row_block_offset, so the
    // union of the tiled launches touches exactly the same (column, index)
    // pairs as one big launch would.
    constexpr int MAX_Y_BLOCKS = 65535;

    for (int y_base = 0; y_base < numBlocks; y_base += MAX_Y_BLOCKS) {
        dim3 gridDimensions(values_size, min(numBlocks - y_base, MAX_Y_BLOCKS));
        batch_ifft_circle_part<<<gridDimensions, blockDimensions>>>(device_values, inverseTwiddlesTree, values_size, number_of_rows, y_base);
        ASSERT_CUDA_SUCCESS(cudaGetLastError());
    }
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    int log_number_of_rows = log_2(number_of_rows);
    int layer_domain_size = number_of_rows >> 1;
    int layer_domain_offset = 0;
    int i = 1;
    while (i < log_number_of_rows) {
        for (int y_base = 0; y_base < numBlocks; y_base += MAX_Y_BLOCKS) {
            dim3 gridDimensions(values_size, min(numBlocks - y_base, MAX_Y_BLOCKS));
            batch_ifft_line_part<<<gridDimensions, blockDimensions>>>(
                device_values,
                &inverseTwiddlesTree[layer_domain_offset],
                values_size,
                number_of_rows,
                i,
                y_base
            );
            ASSERT_CUDA_SUCCESS(cudaGetLastError());
        }
        layer_domain_size >>= 1;
        layer_domain_offset += layer_domain_size;
        i += 1;
    }
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    m31 factor = inv(pow(m31{2}, log_number_of_rows));
    numBlocks = (number_of_rows + blockDimensions - 1) / blockDimensions;
    for (int y_base = 0; y_base < numBlocks; y_base += MAX_Y_BLOCKS) {
        dim3 rescaleGridDimensions(values_size, min(numBlocks - y_base, MAX_Y_BLOCKS));
        batch_rescale<<<rescaleGridDimensions, blockDimensions>>>(device_values, values_size, number_of_rows, factor, y_base);
        ASSERT_CUDA_SUCCESS(cudaGetLastError());
    }
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    cuda_proving_free(device_values);
}


template <unsigned LOG_VALS_PER_THREAD>
__global__ void b2n_init_warp_batch(m31** input, m31** output,
                                  const unsigned log_n, const unsigned num_poly,
                                  unsigned min_stage, unsigned max_stage,
                                   m31 *g_twiddles) {
  const unsigned ntt_idx = blockIdx.y;
  const unsigned thread_idx_in_warp = threadIdx.x;
  const unsigned warps_idx_in_ntt = blockDim.y * blockIdx.x + threadIdx.y;
  const unsigned log_vals_per_warp = LOG_VALS_PER_THREAD + LOG_THREADS_PER_WARP;
  m31* input_ntt_start = input[ntt_idx];
  unsigned warp_start = warps_idx_in_ntt << log_vals_per_warp;

  m31 vals[1 << LOG_VALS_PER_THREAD];
#pragma unroll
  for (unsigned i = 0; i < 1 << LOG_VALS_PER_THREAD; i++) {
    vals[i] = input_ntt_start[warp_start + thread_idx_in_warp * (1 << LOG_VALS_PER_THREAD) + i];
  }

 unsigned layer_domain_size = (1 << log_n) >> 1;
 unsigned layer_domain_offset = 0;
 unsigned stage = min_stage;
#pragma unroll
  for (; stage < min_stage + LOG_VALS_PER_THREAD; stage++) {
    const unsigned log_inner_stride_size = stage - 1;
#pragma unroll
    for (unsigned gid = 0; gid < 1 << (LOG_VALS_PER_THREAD - 1); gid++) {
      const unsigned inner_group_idx = gid & ((1 << log_inner_stride_size) - 1);
      const unsigned inner_pair_idx = gid >> log_inner_stride_size;
      const unsigned inner_left_idx =
          inner_group_idx + (inner_pair_idx << (log_inner_stride_size + 1));
      const unsigned inner_right_idx =
          inner_left_idx + (1 << log_inner_stride_size);
      const unsigned outer_pair_idx = (warp_start + (thread_idx_in_warp << LOG_VALS_PER_THREAD)) >> log_inner_stride_size >> 1;


      m31 twiddle = m31(1);

      if (stage == 1) {
        twiddle =  get_circle_twiddle(g_twiddles, inner_pair_idx + outer_pair_idx);
      } else {
        twiddle = g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx];
      }


      const m31 temp = vals[inner_left_idx];
      vals[inner_left_idx] = add(temp, vals[inner_right_idx]);
      vals[inner_right_idx] = sub(temp, vals[inner_right_idx]);
      vals[inner_right_idx] = mul(vals[inner_right_idx], twiddle);

     }
    if (stage >= 2) {
        layer_domain_size >>= 1;
        layer_domain_offset += layer_domain_size;
    }
  }

#pragma unroll
  for (; stage <= max_stage; stage++) {
    const unsigned log_stride = stage - LOG_VALS_PER_THREAD - 1;
    shfl_xor_bf<LOG_VALS_PER_THREAD>(vals, log_stride, thread_idx_in_warp);
#pragma unroll
    for (unsigned i = 0; i < 1 << (LOG_VALS_PER_THREAD - 1); i++) {
      const unsigned log_inner_stride_size = stage - 1;
      const unsigned inner_pair_idx = i >> log_inner_stride_size;
      const unsigned outer_pair_idx = (warp_start + (thread_idx_in_warp << LOG_VALS_PER_THREAD)) >> stage;

      m31 twiddle = g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx];

      const m31 temp = vals[2 * i];
      vals[2 * i] = add(temp, vals[2 * i + 1]);
      vals[2 * i + 1] = sub(temp, vals[2 * i + 1]) ;
      vals[2 * i + 1] = mul(vals[2 * i + 1], twiddle);

    }
    layer_domain_size >>= 1;
    layer_domain_offset += layer_domain_size;
  }

  shfl_xor_bf<LOG_VALS_PER_THREAD>(vals, 0, thread_idx_in_warp);

  m31* output_ntt_start = output[ntt_idx];

  if ((thread_idx_in_warp & 1) == 1) {
    #pragma unroll
    for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); i++) {
      output_ntt_start[warp_start + i + (thread_idx_in_warp >> 1) * (1 << LOG_VALS_PER_THREAD) + (1 << (log_vals_per_warp - 1))] = vals[i];
    }
  } else {
    #pragma unroll
    for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); i++) {
      output_ntt_start[warp_start + i + (thread_idx_in_warp >> 1) * (1 << LOG_VALS_PER_THREAD)] = vals[i];
    }
  }
}


EXTERN void ntt_b2n_init_7_stage_batch(m31** input, m31** output,
                              unsigned log_n, unsigned num_poly,
                              unsigned start_stage, m31* g_twiddles, unsigned twiddles_size, unsigned eval_domain_size
) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_val_per_thread = 2;
    dim3 block_dim = dim3{32, 1, 1};
    dim3 grid_dim = dim3{1, 1, 1};
    const unsigned num_warp = 1 << (log_n - LOG_THREADS_PER_WARP - log_val_per_thread);
    const unsigned num_stage = log_val_per_thread + LOG_THREADS_PER_WARP; // 2 + 5=7
    const unsigned end_stage = start_stage + num_stage - 1;
    block_dim.y = min(num_warp, 4);
    grid_dim.y = num_poly;
    grid_dim.x = num_warp / block_dim.y;
    b2n_init_warp_batch<log_val_per_thread><<<grid_dim, block_dim, 0>>>(
        input, output,
        log_n, num_poly, start_stage, end_stage, g_twiddles);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}



EXTERN void ntt_b2n_init_8_stage_batch(m31** input, m31** output,
                              unsigned log_n, unsigned num_poly,
                              unsigned start_stage, m31* g_twiddles, unsigned twiddles_size, unsigned eval_domain_size
) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_val_per_thread = 3;
    dim3 block_dim = dim3{32, 1, 1};
    dim3 grid_dim = dim3{1, 1, 1};
    const unsigned num_warp = 1 << (log_n - LOG_THREADS_PER_WARP - log_val_per_thread);
    const unsigned num_stage = log_val_per_thread + LOG_THREADS_PER_WARP; // 3 + 5 = 8
    const unsigned end_stage = start_stage + num_stage - 1;
    block_dim.y = min(num_warp, 4);
    grid_dim.y = num_poly;
    grid_dim.x = num_warp / block_dim.y;
    b2n_init_warp_batch<log_val_per_thread><<<grid_dim, block_dim, 0>>>(
        input, output,
        log_n, num_poly, start_stage, end_stage, g_twiddles);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}


template <unsigned LOG_WARP_PER_BLOCK>
__global__ void b2n_init_block_warp_batch(m31** input, m31** output,
                                  const unsigned log_n, const unsigned num_poly,
                                  unsigned min_stage, unsigned max_stage,
                                  m31 *g_twiddles) {
  constexpr unsigned log_vals_per_threads_default = 3;
  const unsigned log_threads_per_warp = 5; // LOG_THREADS_PER_WARP

  const unsigned ntt_idx = blockIdx.z;
  const unsigned warp_idx_in_block = threadIdx.y;
  const unsigned thread_idx_in_warp = threadIdx.x;

  const unsigned log_vals_per_warp = log_vals_per_threads_default + log_threads_per_warp;
  m31* input_ntt_start = input[ntt_idx];

  const unsigned block_index_y = blockIdx.x;
  const unsigned block_start = (block_index_y << (log_threads_per_warp + log_vals_per_threads_default + LOG_WARP_PER_BLOCK));

  m31 vals[1 << log_vals_per_threads_default];

  const unsigned warps_idx_in_ntt = blockDim.y * block_index_y + threadIdx.y;
  unsigned warp_start = warps_idx_in_ntt << log_vals_per_warp;

#pragma unroll
  for (unsigned i = 0; i < 1 << log_vals_per_threads_default; i++) {
    vals[i] = input_ntt_start[warp_start + thread_idx_in_warp * (1 << log_vals_per_threads_default) + i];
  }

 unsigned layer_domain_size = (1 << log_n) >> 1;
 unsigned layer_domain_offset = 0;
 unsigned stage = min_stage;
#pragma unroll
  for (; stage < min_stage + log_vals_per_threads_default; stage++) {
    const unsigned log_inner_stride_size = stage - 1;
#pragma unroll
    for (unsigned gid = 0; gid < 1 << (log_vals_per_threads_default - 1); gid++) {
      const unsigned inner_group_idx = gid & ((1 << log_inner_stride_size) - 1);
      const unsigned inner_pair_idx = gid >> log_inner_stride_size;
      const unsigned inner_left_idx =
          inner_group_idx + (inner_pair_idx << (log_inner_stride_size + 1));
      const unsigned inner_right_idx =
          inner_left_idx + (1 << log_inner_stride_size);
      const unsigned outer_pair_idx = (warp_start + (thread_idx_in_warp << log_vals_per_threads_default)) >> log_inner_stride_size >> 1;


      m31 twiddle = m31(1);

      if (stage == 1) {
        twiddle =  get_circle_twiddle(g_twiddles, inner_pair_idx + outer_pair_idx);
      } else {
        twiddle = g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx];
      }

      const m31 temp = vals[inner_left_idx];
      vals[inner_left_idx] = add(temp, vals[inner_right_idx]);
      vals[inner_right_idx] = sub(temp, vals[inner_right_idx]);
      vals[inner_right_idx] = mul(vals[inner_right_idx], twiddle);

    }

    if (stage >= 2) {
        layer_domain_size >>= 1;
        layer_domain_offset += layer_domain_size;
    }
  }

  unsigned new_min_stage = min_stage + log_vals_per_threads_default;
  stage = new_min_stage;

#pragma unroll
  for (; stage < new_min_stage + log_threads_per_warp; stage++) {
    const unsigned log_stride = stage - log_vals_per_threads_default - 1;

    shfl_xor_bf<log_vals_per_threads_default>(vals, log_stride, thread_idx_in_warp);
#pragma unroll
    for (unsigned i = 0; i < 1 << (log_vals_per_threads_default - 1); i++) {
      const unsigned log_inner_stride_size = stage - 1;
      const unsigned inner_pair_idx = i >> log_inner_stride_size;
      const unsigned outer_pair_idx = (warp_start + (thread_idx_in_warp << log_vals_per_threads_default)) >> stage;

      m31 twiddle  = g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx];

      const m31 temp = vals[2 * i];
      vals[2 * i] = add(temp, vals[2 * i + 1]);
      vals[2 * i + 1] = sub(temp, vals[2 * i + 1]) ;
      vals[2 * i + 1] = mul(vals[2 * i + 1], twiddle);

    }
    layer_domain_size >>= 1;
    layer_domain_offset += layer_domain_size;
  }
  shfl_xor_bf<log_vals_per_threads_default>(vals, 0, thread_idx_in_warp);

  const unsigned log_vals_per_blocks = log_vals_per_threads_default + log_threads_per_warp + LOG_WARP_PER_BLOCK;

  __shared__ m31 smem[1 << log_vals_per_blocks];

  if ((thread_idx_in_warp & 1) == 1) {
    #pragma unroll
    for (unsigned i = 0; i < (1 << log_vals_per_threads_default); i++) {
      smem[warp_start + i + (thread_idx_in_warp >> 1) * (1 << log_vals_per_threads_default) + (1 << (log_vals_per_warp - 1)) - block_start] = vals[i];
    }
  } else {
    #pragma unroll
    for (unsigned i = 0; i < (1 << log_vals_per_threads_default); i++) {
      smem[warp_start + i + (thread_idx_in_warp >> 1) * (1 << log_vals_per_threads_default) - block_start] = vals[i];
    }
  }
  __syncthreads();

#pragma unroll
  for (unsigned i = 0; i < 1 << log_vals_per_threads_default; i++) {
    vals[i] = smem[thread_idx_in_warp + (i << (log_threads_per_warp + LOG_WARP_PER_BLOCK)) + (warp_idx_in_block << log_threads_per_warp)];
  }

  new_min_stage = min_stage + log_vals_per_threads_default + log_threads_per_warp;
  stage = new_min_stage;
#pragma unroll
  for (; stage < max_stage; stage++) {
    const unsigned log_inner_stride_size = stage - new_min_stage + (log_vals_per_threads_default - LOG_WARP_PER_BLOCK);
#pragma unroll
    for (unsigned gid = 0; gid < 1 << (log_vals_per_threads_default - 1); gid++) {
      const unsigned inner_group_idx = gid & ((1 << log_inner_stride_size) - 1);
      const unsigned inner_left_idx = inner_group_idx + ((gid >> log_inner_stride_size) << (log_inner_stride_size + 1));
      const unsigned inner_right_idx = inner_left_idx + (1 << log_inner_stride_size);

      const unsigned pair_offset_in_block = block_index_y * blockDim.y * (1 << (log_vals_per_threads_default - 1)) * (1 << log_threads_per_warp);
      const unsigned pair_idx = (gid << (log_threads_per_warp + LOG_WARP_PER_BLOCK)) + thread_idx_in_warp + (threadIdx.y << log_threads_per_warp) + pair_offset_in_block;
      const unsigned tw_idx = pair_idx >> (stage - 1);
      m31 twiddle = g_twiddles[layer_domain_offset + tw_idx];

      const m31 temp = vals[inner_left_idx];
      vals[inner_left_idx] = add(temp, vals[inner_right_idx]);
      vals[inner_right_idx] = sub(temp, vals[inner_right_idx]);
      vals[inner_right_idx] = mul(vals[inner_right_idx], twiddle);

    }
    layer_domain_size >>= 1;
    layer_domain_offset += layer_domain_size;
  }

  m31* output_ntt_start = output[ntt_idx];
  const unsigned offset_per_vals = 1 << (log_threads_per_warp + LOG_WARP_PER_BLOCK);
  #pragma unroll
  for (unsigned i = 0; i < (1 << log_vals_per_threads_default); i++) {
    output_ntt_start[thread_idx_in_warp + (threadIdx.y << log_threads_per_warp) + i * offset_per_vals + block_start] = vals[i];
  }
}


EXTERN void ntt_b2n_init_9_stage_batch(m31** input, m31** output,
                               unsigned log_n, unsigned num_poly,
                               unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_warp_per_block = 1;
    constexpr unsigned log_vals_per_threads_default = 3;
    constexpr unsigned log_threads_per_warp = 5;  // LOG_THREADS_PER_WARP
    dim3 block_dim = {1 << log_threads_per_warp, 1 << log_warp_per_block, 1}; // {32, 1 << log_warp_per_block, 1};
    dim3 grid_dim = {};
    grid_dim.z = num_poly;
    grid_dim.x = 1 << (log_n - log_threads_per_warp - log_vals_per_threads_default - log_warp_per_block);
    unsigned end_stage = start_stage + log_threads_per_warp + log_vals_per_threads_default + log_warp_per_block;

    b2n_init_block_warp_batch<log_warp_per_block><<<grid_dim, block_dim>>>(
        input, output,
        log_n, num_poly, start_stage, end_stage, g_twiddles);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

EXTERN void ntt_b2n_init_10_stage_batch(m31** input, m31** output,
                               unsigned log_n, unsigned num_poly,
                               unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_warp_per_block = 2;
    constexpr unsigned log_vals_per_threads_default = 3;
    constexpr unsigned log_threads_per_warp = 5;  // LOG_THREADS_PER_WARP
    dim3 block_dim = {1 << log_threads_per_warp, 1 << log_warp_per_block, 1}; // {32, 1 << log_warp_per_block, 1};
    dim3 grid_dim = {};
    grid_dim.z = num_poly;
    grid_dim.x = 1 << (log_n - log_threads_per_warp - log_vals_per_threads_default - log_warp_per_block);
    unsigned end_stage = start_stage + log_threads_per_warp + log_vals_per_threads_default + log_warp_per_block;

    b2n_init_block_warp_batch<log_warp_per_block><<<grid_dim, block_dim>>>(
        input, output,
        log_n, num_poly, start_stage, end_stage, g_twiddles);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

EXTERN void ntt_b2n_init_11_stage_batch(m31** input, m31** output,
                               unsigned log_n, unsigned num_poly,
                               unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_warp_per_block = 3;
    constexpr unsigned log_vals_per_threads_default = 3;
    constexpr unsigned log_threads_per_warp = 5;  // LOG_THREADS_PER_WARP
    dim3 block_dim = {1 << log_threads_per_warp, 1 << log_warp_per_block, 1}; // {32, 1 << log_warp_per_block, 1};
    dim3 grid_dim = {};
    grid_dim.z = num_poly;
    grid_dim.x = 1 << (log_n - log_threads_per_warp - log_vals_per_threads_default - log_warp_per_block);
    unsigned end_stage = start_stage + log_threads_per_warp + log_vals_per_threads_default + log_warp_per_block;
    b2n_init_block_warp_batch<log_warp_per_block><<<grid_dim, block_dim>>>(
        input, output,
        log_n, num_poly, start_stage, end_stage, g_twiddles);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

EXTERN void ntt_b2n_init_12_stage_batch(m31** input, m31** output,
                               unsigned log_n, unsigned num_poly,
                               unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_warp_per_block = 4;
    constexpr unsigned log_vals_per_threads_default = 3;
    constexpr unsigned log_threads_per_warp = 5;  // LOG_THREADS_PER_WARP
    dim3 block_dim = {1 << log_threads_per_warp, 1 << log_warp_per_block, 1}; // {32, 1 << log_warp_per_block, 1};
    dim3 grid_dim = {};
    grid_dim.z = num_poly;
    grid_dim.x = 1 << (log_n - log_threads_per_warp - log_vals_per_threads_default - log_warp_per_block);
    unsigned end_stage = start_stage + log_threads_per_warp + log_vals_per_threads_default + log_warp_per_block;
    b2n_init_block_warp_batch<log_warp_per_block><<<grid_dim, block_dim>>>(
        input, output,
        log_n, num_poly, start_stage, end_stage, g_twiddles);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}
EXTERN void ntt_b2n_init_6_3_stage_batch(m31** input, m31** output,
                               unsigned log_n, unsigned num_poly,
                               unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_warp_per_block = 2;
    constexpr unsigned log_vals_per_threads_default = 3;
    constexpr unsigned log_threads_per_warp = 1;
    dim3 block_dim = {1 << log_threads_per_warp, 1 << log_warp_per_block, 1};
    dim3 grid_dim = {};
    grid_dim.z = num_poly;
    grid_dim.x = 1 << (log_n - log_threads_per_warp - log_vals_per_threads_default - log_warp_per_block);
    unsigned end_stage = start_stage + log_threads_per_warp + log_vals_per_threads_default + log_warp_per_block;

    b2n_init_block_warp_batch<log_warp_per_block><<<grid_dim, block_dim>>>(
        input, output,
        log_n, num_poly, start_stage, end_stage, g_twiddles);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

template <unsigned LOG_VALS_PER_THREAD, bool DUPLICATE_TO_RETAINED>
__global__ void  b2n_noinit_block_batch(m31** input, m31** output,
                                  const unsigned log_n, const unsigned num_poly,
                                  unsigned min_stage, unsigned max_stage,
                                  m31 *g_twiddles, m31 rescale_factor) {
  const unsigned min_stride = 1 << (min_stage - 1);
  const unsigned log_threads_per_warp = 5;
  const unsigned num_threads_per_warp = 1 << log_threads_per_warp;
 const unsigned num_stage = 2 * LOG_VALS_PER_THREAD;

  const unsigned ntt_idx = blockIdx.z;
  const unsigned block_index_x = blockIdx.x;
  const unsigned block_index_y = blockIdx.y;
  const unsigned warp_idx_in_block = threadIdx.y;
  const unsigned thread_idx_in_warp = threadIdx.x;

  const m31* input_ntt_start = input[ntt_idx];
  const unsigned block_start = (block_index_x << log_threads_per_warp) +
      (block_index_y << (min_stage + num_stage - 1));

  m31 vals[1 << LOG_VALS_PER_THREAD];

  unsigned offset = warp_idx_in_block * (min_stride << LOG_VALS_PER_THREAD) + thread_idx_in_warp;
#pragma unroll
  for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); i++) {
    vals[i] = input_ntt_start[ block_start + i * min_stride + offset];
  }

  unsigned layer_domain_size = (1 << log_n) >> 1;
  unsigned layer_domain_offset = 0;

 for (unsigned i = 2; i <= min_stage - 1; i++) {
    layer_domain_size >>= 1;
    layer_domain_offset += layer_domain_size;
  }

 unsigned stage = min_stage;
#pragma unroll
  for (; stage < min_stage + LOG_VALS_PER_THREAD; stage++) {
    const unsigned log_inner_stride_size = stage - min_stage;
#pragma unroll
    for (unsigned gid = 0; gid < 1 << (LOG_VALS_PER_THREAD - 1); gid++) {
      const unsigned inner_group_idx = gid & ((1 << log_inner_stride_size) - 1);
      const unsigned inner_pair_idx = gid >> log_inner_stride_size;
      const unsigned inner_left_idx = inner_group_idx + (inner_pair_idx << (log_inner_stride_size + 1));
      const unsigned inner_right_idx = inner_left_idx + (1 << log_inner_stride_size);
      const unsigned outer_pair_idx = (block_start + offset) >> stage;


      m31 twiddle = g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx];

      const m31 temp = vals[inner_left_idx];
      vals[inner_left_idx] = add(temp, vals[inner_right_idx]);
      vals[inner_right_idx] = sub(temp, vals[inner_right_idx]);
      vals[inner_right_idx] = mul(vals[inner_right_idx], twiddle);

     }
    layer_domain_size >>= 1;
    layer_domain_offset += layer_domain_size;
  }

  __shared__ m31 smem[(num_threads_per_warp << (2 * LOG_VALS_PER_THREAD)) + num_threads_per_warp]; // 32 * (2^(2 or 3))

  unsigned offset_store_between_warps = warp_idx_in_block * (min_stride << LOG_VALS_PER_THREAD);
#pragma unroll
  for (unsigned i = 0; i < 1 << LOG_VALS_PER_THREAD; i++) {
    smem[(i * min_stride + offset_store_between_warps) / gridDim.x + thread_idx_in_warp] = vals[i];
  }
  __syncthreads();

  unsigned new_min_stage = min_stage + LOG_VALS_PER_THREAD;
  stage = new_min_stage;
  const unsigned new_min_stride = 1 << (new_min_stage - 1);
  unsigned new_offset = ((warp_idx_in_block * (min_stride << LOG_VALS_PER_THREAD)) >> LOG_VALS_PER_THREAD) + thread_idx_in_warp;
  unsigned offset_load_between_warps = ((warp_idx_in_block * (min_stride << LOG_VALS_PER_THREAD)) >> LOG_VALS_PER_THREAD);

#pragma unroll
  for (unsigned i = 0; i < 1 << LOG_VALS_PER_THREAD; i++) {
    vals[i] = smem[(i * new_min_stride + offset_load_between_warps) / gridDim.x + thread_idx_in_warp];
  }

#pragma unroll
  for (; stage < new_min_stage + LOG_VALS_PER_THREAD; stage++) {
    const unsigned log_inner_stride_size = stage - new_min_stage;
#pragma unroll
    for (unsigned gid = 0; gid < 1 << (LOG_VALS_PER_THREAD - 1); gid++) {
      const unsigned inner_group_idx = gid & ((1 << log_inner_stride_size) - 1);
      const unsigned inner_pair_idx = gid >> log_inner_stride_size;
      const unsigned inner_left_idx = inner_group_idx + (inner_pair_idx << (log_inner_stride_size + 1));
      const unsigned inner_right_idx = inner_left_idx + (1 << log_inner_stride_size);
      const unsigned outer_pair_idx = (block_start + new_offset) >> stage;

      m31 twiddle = g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx];

      // m31 a_debug = vals[inner_left_idx];
      // m31 b_debug = vals[inner_right_idx];

      const m31 temp = vals[inner_left_idx];
      vals[inner_left_idx] = add(temp, vals[inner_right_idx]);
      vals[inner_right_idx] = sub(temp, vals[inner_right_idx]);
      vals[inner_right_idx] = mul(vals[inner_right_idx], twiddle);

      if (stage == log_n) {
        vals[inner_left_idx] = mul(vals[inner_left_idx], rescale_factor);
        vals[inner_right_idx] = mul(vals[inner_right_idx], rescale_factor);
      }
    }
    layer_domain_size >>= 1;
    layer_domain_offset += layer_domain_size;
  }

  m31* output_ntt_start = output[ntt_idx];
#pragma unroll
  for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); i++) {
    const unsigned output_index = block_start + i * new_min_stride + new_offset;
    output_ntt_start[output_index] = vals[i];
    if constexpr (DUPLICATE_TO_RETAINED) {
      // The omitted first N2B butterfly sees (coefficient, 0), hence (c, c).
      output_ntt_start[output_index + (1u << log_n)] = vals[i];
    }
  }

}

EXTERN void ntt_b2n_noinit_4_stage_batch(m31** input, m31** output,
                                unsigned log_n, unsigned num_poly,
                                unsigned start_stage,
                                m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_val_per_thread = 2;
    constexpr unsigned num_threads_per_warp = 32;
    dim3 block_dim{num_threads_per_warp, 1 << log_val_per_thread, 1};
    dim3 grid_dim{};
    constexpr unsigned num_stage = 2 * log_val_per_thread;
    unsigned end_stage = start_stage + num_stage - 1;
    unsigned min_stride = 1 << (start_stage - 1);
    grid_dim.z = num_poly;
    grid_dim.x = min_stride / num_threads_per_warp;
    grid_dim.y = (1 << log_n) / (min_stride << num_stage);
    m31 rescale_factor = inv(pow(m31{2}, log_n));

    b2n_noinit_block_batch<log_val_per_thread, false><<<grid_dim, block_dim, 0>>>(
        input, output,
        log_n, num_poly, start_stage, end_stage, g_twiddles, rescale_factor);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}


EXTERN void ntt_b2n_noinit_6_stage_batch(m31** input, m31** output,
                                unsigned log_n, unsigned num_poly,
                                unsigned start_stage,
                                m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_val_per_thread = 3;
    constexpr unsigned num_threads_per_warp = 32;
     dim3 block_dim{num_threads_per_warp, 1 << log_val_per_thread, 1};
    dim3 grid_dim{};
    constexpr unsigned num_stage = 2 * log_val_per_thread;
    unsigned end_stage = start_stage + num_stage - 1;
    unsigned min_stride = 1 << (start_stage - 1);
    grid_dim.z = num_poly;
    grid_dim.x = min_stride / num_threads_per_warp;
    grid_dim.y = (1 << log_n) / (1 << end_stage);
    m31 rescale_factor = inv(pow(m31{2}, log_n));
    b2n_noinit_block_batch<log_val_per_thread, false><<<grid_dim, block_dim, 0>>>(
        input, output,
        log_n, num_poly, start_stage, end_stage, g_twiddles, rescale_factor);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}


EXTERN void ntt_b2n_noinit_8_stage_batch(m31** input, m31** output,
                                unsigned log_n, unsigned num_poly,
                                unsigned start_stage,
                                m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_val_per_thread = 4;
    constexpr unsigned num_threads_per_warp = 32;
    dim3 block_dim{num_threads_per_warp, 1 << log_val_per_thread, 1};
    dim3 grid_dim{};
    constexpr unsigned num_stage = 2 * log_val_per_thread;
    unsigned end_stage = start_stage + num_stage - 1;
    unsigned min_stride = 1 << (start_stage - 1);
    grid_dim.z = num_poly;
    grid_dim.x = min_stride / num_threads_per_warp;
    grid_dim.y = (1 << log_n) / (1 << end_stage);
    m31 rescale_factor = inv(pow(m31{2}, log_n));
    b2n_noinit_block_batch<log_val_per_thread, false><<<grid_dim, block_dim, 0>>>(
        input, output,
        log_n, num_poly, start_stage, end_stage, g_twiddles, rescale_factor);
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

template <bool DUPLICATE_TO_RETAINED>
__global__ void ntt_b2n_stage_batch(m31** input, m31** output,
                              unsigned log_n, unsigned stage,
                              m31 *layer_twiddles, m31 rescale_factor) {
    const unsigned ntt_index = blockIdx.y;
    const unsigned gid = blockIdx.x * blockDim.x + threadIdx.x;
    const unsigned stride = 1 << (stage - 1);
    const unsigned group_idx = gid & (stride - 1);
    const unsigned pair_idx = gid >> (stage - 1);

    const m31* input_start = input[ntt_index];
    const unsigned left_index = group_idx + pair_idx * 2 * stride;
    const unsigned right_index = left_index + stride;

    m31 left = input_start[left_index];
    m31 right = input_start[right_index];

    m31 twiddle = m31(1);

    if (stage == 1) {
        twiddle = get_circle_twiddle(layer_twiddles, pair_idx);
    } else {
        twiddle = layer_twiddles[pair_idx];
    }

    const m31 temp = left;
    m31 left_r = add(temp, right);
    m31 right_r = mul(sub(temp, right), twiddle);

    if (stage == log_n) {
        left_r = mul(left_r, rescale_factor);
        right_r = mul(right_r, rescale_factor);
    }
    m31* output_start = output[ntt_index];

    output_start[left_index] = left_r;
    output_start[right_index] = right_r;
    if constexpr (DUPLICATE_TO_RETAINED) {
        // The omitted first N2B butterfly sees (coefficient, 0), hence (c, c).
        output_start[left_index + (1u << log_n)] = left_r;
        output_start[right_index + (1u << log_n)] = right_r;
    }

}


static cudaError_t ntt_b2n_native_device_batch_on(
        m31 **device_values,
        unsigned log_n,
        unsigned num_poly,
        m31 *g_twiddles,
        unsigned twiddles_size,
        unsigned eval_domain_size,
        cudaStream_t stream) {
    if (device_values == nullptr || g_twiddles == nullptr || stream == nullptr ||
        log_n < 3 || log_n > 30 || num_poly == 0 ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddles_size) {
        return cudaErrorInvalidValue;
    }

    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    dim3 block_dim{};
    block_dim.x = log_n <= 8 ? 1u << (log_n - 1) : 128;
    dim3 grid_dim{};
    grid_dim.y = num_poly;
    grid_dim.x = log_n <= 8 ? 1 : 1u << (log_n - 8);

    const m31 rescale_factor = inv(pow(m31{2}, log_n));
    unsigned layer_domain_size = (1u << log_n) >> 1;
    unsigned layer_domain_offset = 0;
    ntt_b2n_stage_batch<false><<<grid_dim, block_dim, 0, stream>>>(
        device_values, device_values, log_n, 1, g_twiddles, rescale_factor);
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) {
        return error;
    }

    for (unsigned stage = 2; stage <= log_n; stage++) {
        ntt_b2n_stage_batch<false><<<grid_dim, block_dim, 0, stream>>>(
            device_values, device_values, log_n, stage,
            &g_twiddles[layer_domain_offset], rescale_factor);
        error = cudaGetLastError();
        if (error != cudaSuccess) {
            return error;
        }
        layer_domain_size >>= 1;
        layer_domain_offset += layer_domain_size;
    }
    return cudaSuccess;
}


extern "C" int stwo_ntt_b2n_columns_on(
        uint32_t **device_values,
        uint32_t log_n,
        uint32_t num_poly,
        uint32_t *g_twiddles,
        uint32_t twiddles_size,
        uint32_t eval_domain_size,
        void *stream) {
    if (device_values == nullptr || g_twiddles == nullptr || stream == nullptr ||
        log_n < 3 || log_n > 30 || num_poly == 0 ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddles_size) {
        return cudaErrorInvalidValue;
    }

    const cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    for (unsigned base = 0; base < num_poly; base += MAX_NTT_BATCH_COLUMNS) {
        const unsigned chunk = min(num_poly - base, MAX_NTT_BATCH_COLUMNS);
        const cudaError_t error = ntt_b2n_native_device_batch_on(
            reinterpret_cast<m31 **>(device_values + base), log_n, chunk,
            g_twiddles, twiddles_size, eval_domain_size, cuda_stream);
        if (error != cudaSuccess) {
            return error;
        }
    }
    return cudaSuccess;
}

namespace {

constexpr bool b2n_partition_is_exact(const size_t *parts, size_t count,
                                      unsigned log_n) {
    unsigned covered = 0;
    for (size_t i = 0; i < count; ++i) {
        if (parts[i] == 0 || covered + parts[i] > log_n) return false;
        covered += static_cast<unsigned>(parts[i]);
    }
    return covered == log_n;
}

constexpr bool b2n_init_interval_is_supported(size_t stages) {
    return stages == 7 || stages == 8 || stages == 9 || stages == 10;
}

constexpr bool b2n_tables_partition_exactly() {
    for (unsigned i = 0; i < 6; ++i) {
        if (!b2n_init_interval_is_supported(LAUNCH_B2N_CONFIG_13_18[i][0]) ||
            !b2n_partition_is_exact(LAUNCH_B2N_CONFIG_13_18[i], 2, 13 + i) ||
            !b2n_init_interval_is_supported(LAUNCH_B2N_CONFIG_19_24[i][0]) ||
            !b2n_partition_is_exact(LAUNCH_B2N_CONFIG_19_24[i], 3, 19 + i))
            return false;
    }
    for (unsigned i = 0; i < 5; ++i)
        if (!b2n_init_interval_is_supported(LAUNCH_B2N_CONFIG_25_29[i][0]) ||
            !b2n_partition_is_exact(LAUNCH_B2N_CONFIG_25_29[i], 4, 25 + i))
            return false;
    return true;
}

static_assert(b2n_tables_partition_exactly(),
              "fused B2N stage tables must cover exactly 1..=log_n");

template <unsigned LOG_VALUES_PER_THREAD>
cudaError_t b2n_init_interval_on(m31 **input, m31 **output, unsigned log_n,
                                unsigned num_poly, unsigned stages,
                                m31 *twiddles, cudaStream_t stream) {
    constexpr unsigned expected = LOG_VALUES_PER_THREAD + LOG_THREADS_PER_WARP;
    if (stages != expected) return cudaErrorInvalidConfiguration;
    dim3 block{32, 1, 1};
    const unsigned warps =
        1u << (log_n - LOG_THREADS_PER_WARP - LOG_VALUES_PER_THREAD);
    block.y = min(warps, 4u);
    dim3 grid{warps / block.y, num_poly, 1};
    b2n_init_warp_batch<LOG_VALUES_PER_THREAD><<<grid, block, 0, stream>>>(
        input, output, log_n, num_poly, 1, stages, twiddles);
    return cudaGetLastError();
}

template <unsigned LOG_WARPS_PER_BLOCK>
cudaError_t b2n_init_block_interval_on(m31 **input, m31 **output,
                                      unsigned log_n, unsigned num_poly,
                                      unsigned stages, m31 *twiddles,
                                      cudaStream_t stream) {
    constexpr unsigned expected =
        3 + LOG_THREADS_PER_WARP + LOG_WARPS_PER_BLOCK;
    if (stages != expected || log_n < expected)
        return cudaErrorInvalidConfiguration;
    dim3 block{1u << LOG_THREADS_PER_WARP, 1u << LOG_WARPS_PER_BLOCK, 1};
    dim3 grid{
        1u << (log_n - LOG_THREADS_PER_WARP - 3 - LOG_WARPS_PER_BLOCK),
        1,
        num_poly,
    };
    // b2n_init_block_warp_batch uses an exclusive upper stage bound.
    b2n_init_block_warp_batch<LOG_WARPS_PER_BLOCK>
        <<<grid, block, 0, stream>>>(input, output, log_n, num_poly, 1,
                                    1 + stages, twiddles);
    return cudaGetLastError();
}

cudaError_t b2n_dispatch_init_interval_on(
    m31 **input, m31 **output, unsigned log_n, unsigned num_poly,
    unsigned stages, m31 *twiddles, cudaStream_t stream) {
    switch (stages) {
    case 7:
        return b2n_init_interval_on<2>(input, output, log_n, num_poly, stages,
                                       twiddles, stream);
    case 8:
        return b2n_init_interval_on<3>(input, output, log_n, num_poly, stages,
                                       twiddles, stream);
    case 9:
        return b2n_init_block_interval_on<1>(
            input, output, log_n, num_poly, stages, twiddles, stream);
    case 10:
        return b2n_init_block_interval_on<2>(
            input, output, log_n, num_poly, stages, twiddles, stream);
    default:
        return cudaErrorInvalidConfiguration;
    }
}

template <unsigned LOG_VALUES_PER_THREAD, bool DUPLICATE_TO_RETAINED>
cudaError_t b2n_noinit_interval_on(m31 **values, unsigned log_n,
                                  unsigned num_poly, unsigned start_stage,
                                  unsigned stages, m31 *twiddles,
                                  cudaStream_t stream) {
    constexpr unsigned expected = 2 * LOG_VALUES_PER_THREAD;
    if (stages != expected || start_stage == 0 ||
        start_stage + stages - 1 > log_n ||
        (DUPLICATE_TO_RETAINED && start_stage + stages - 1 != log_n))
        return cudaErrorInvalidConfiguration;
    constexpr unsigned warp = 32;
    dim3 block{warp, 1u << LOG_VALUES_PER_THREAD, 1};
    const unsigned end_stage = start_stage + stages - 1;
    const unsigned min_stride = 1u << (start_stage - 1);
    dim3 grid{min_stride / warp, (1u << log_n) / (1u << end_stage), num_poly};
    const m31 rescale_factor = inv(pow(m31{2}, log_n));
    b2n_noinit_block_batch<LOG_VALUES_PER_THREAD, DUPLICATE_TO_RETAINED>
        <<<grid, block, 0, stream>>>(
        values, values, log_n, num_poly, start_stage, end_stage, twiddles,
        rescale_factor);
    return cudaGetLastError();
}

template <bool DUPLICATE_TO_RETAINED>
cudaError_t b2n_dispatch_noinit_interval_on(
    m31 **values, unsigned log_n, unsigned num_poly, unsigned start_stage,
    unsigned stages, m31 *twiddles, cudaStream_t stream) {
    switch (stages) {
    case 4:
        return b2n_noinit_interval_on<2, DUPLICATE_TO_RETAINED>(
            values, log_n, num_poly, start_stage, stages, twiddles, stream);
    case 6:
        return b2n_noinit_interval_on<3, DUPLICATE_TO_RETAINED>(
            values, log_n, num_poly, start_stage, stages, twiddles, stream);
    case 8:
        return b2n_noinit_interval_on<4, DUPLICATE_TO_RETAINED>(
            values, log_n, num_poly, start_stage, stages, twiddles, stream);
    default:
        return cudaErrorInvalidConfiguration;
    }
}

template <bool DUPLICATE_TO_RETAINED>
cudaError_t b2n_stagewise_out_of_place_on(m31 **input, m31 **output,
                                          unsigned log_n, unsigned num_poly,
                                          m31 *twiddles,
                                          cudaStream_t stream) {
    dim3 block{};
    block.x = log_n <= 8 ? 1u << (log_n - 1) : 128;
    dim3 grid{};
    grid.y = num_poly;
    grid.x = log_n <= 8 ? 1 : 1u << (log_n - 8);
    const m31 rescale_factor = inv(pow(m31{2}, log_n));
    unsigned layer_size = (1u << log_n) >> 1;
    unsigned layer_offset = 0;
    ntt_b2n_stage_batch<false><<<grid, block, 0, stream>>>(
        input, output, log_n, 1, twiddles, rescale_factor);
    cudaError_t error = cudaGetLastError();
    for (unsigned stage = 2; error == cudaSuccess && stage < log_n; ++stage) {
        ntt_b2n_stage_batch<false><<<grid, block, 0, stream>>>(
            output, output, log_n, stage, &twiddles[layer_offset],
            rescale_factor);
        error = cudaGetLastError();
        layer_size >>= 1;
        layer_offset += layer_size;
    }
    if (error == cudaSuccess) {
        ntt_b2n_stage_batch<DUPLICATE_TO_RETAINED>
            <<<grid, block, 0, stream>>>(output, output, log_n, log_n,
                                         &twiddles[layer_offset],
                                         rescale_factor);
        error = cudaGetLastError();
    }
    return error;
}

template <bool DUPLICATE_TO_RETAINED>
cudaError_t b2n_fused_out_of_place_on(m31 **input, m31 **output,
                                      unsigned log_n, unsigned num_poly,
                                      m31 *twiddles, cudaStream_t stream) {
    const size_t *parts = nullptr;
    size_t count = 0;
    if (log_n >= 13 && log_n <= 18) {
        parts = LAUNCH_B2N_CONFIG_13_18[log_n - 13]; count = 2;
    } else if (log_n >= 19 && log_n <= 24) {
        parts = LAUNCH_B2N_CONFIG_19_24[log_n - 19]; count = 3;
    } else if (log_n >= 25 && log_n <= 29) {
        parts = LAUNCH_B2N_CONFIG_25_29[log_n - 25]; count = 4;
    } else {
        return b2n_stagewise_out_of_place_on<DUPLICATE_TO_RETAINED>(
            input, output, log_n, num_poly, twiddles, stream);
    }
    if (!b2n_partition_is_exact(parts, count, log_n))
        return cudaErrorInvalidConfiguration;
    cudaError_t error = b2n_dispatch_init_interval_on(
        input, output, log_n, num_poly, static_cast<unsigned>(parts[0]),
        twiddles, stream);
    unsigned start = 1u + static_cast<unsigned>(parts[0]);
    for (size_t i = 1; error == cudaSuccess && i < count; ++i) {
        const unsigned stages = static_cast<unsigned>(parts[i]);
        const bool duplicate = DUPLICATE_TO_RETAINED && i + 1 == count;
        error = duplicate
            ? b2n_dispatch_noinit_interval_on<true>(
                  output, log_n, num_poly, start, stages, twiddles, stream)
            : b2n_dispatch_noinit_interval_on<false>(
                  output, log_n, num_poly, start, stages, twiddles, stream);
        start += stages;
    }
    return error;
}

template <unsigned LOG_VALUES_PER_THREAD, bool FUSE_FIRST_FORWARD>
cudaError_t launch_composition_split_boundary_on(
    m31 **sources, m31 **retained_outputs, unsigned log_n,
    unsigned start_stage, m31 *inverse_twiddles, m31 *forward_twiddles,
    cudaStream_t stream) {
    constexpr unsigned stages = 2 * LOG_VALUES_PER_THREAD;
    if (start_stage + stages - 1 != log_n)
        return cudaErrorInvalidConfiguration;
    constexpr unsigned warp = 32;
    dim3 block{warp, 1u << LOG_VALUES_PER_THREAD, 1};
    const unsigned min_stride = 1u << (start_stage - 1);
    dim3 grid{min_stride / warp, 1, 4};
    const m31 rescale_factor = inv(pow(m31{2}, log_n));
    composition_split_boundary_batch<
        LOG_VALUES_PER_THREAD, FUSE_FIRST_FORWARD>
        <<<grid, block, 0, stream>>>(
            sources, retained_outputs, log_n, start_stage, inverse_twiddles,
            forward_twiddles, rescale_factor);
    return cudaGetLastError();
}

template <bool FUSE_FIRST_FORWARD>
cudaError_t b2n_composition_split_on(
    m31 **sources, m31 **retained_outputs, unsigned log_n,
    m31 *inverse_twiddles, m31 *forward_twiddles, cudaStream_t stream) {
    static constexpr size_t LOG24_COMPOSITION_PARTS[3] = {10, 8, 6};
    const size_t *parts = nullptr;
    size_t count = 0;
    if (log_n == 24) {
        // The ordinary 8+8+8 split makes the fused boundary a 512-thread
        // LOG4 kernel.  A composition-only 10+8+6 split reaches the same
        // normalized coefficients with the already-qualified 256-thread LOG3
        // boundary and leaves an exact 8+10 forward continuation.
        parts = LOG24_COMPOSITION_PARTS;
        count = 3;
    } else if (log_n == 25) {
        parts = LAUNCH_B2N_CONFIG_25_29[0];
        count = 4;
    } else {
        return cudaErrorInvalidValue;
    }
    if (!b2n_partition_is_exact(parts, count, log_n))
        return cudaErrorInvalidConfiguration;

    cudaError_t error = b2n_dispatch_init_interval_on(
        sources, sources, log_n, 4, static_cast<unsigned>(parts[0]),
        inverse_twiddles, stream);
    unsigned start_stage = 1u + static_cast<unsigned>(parts[0]);
    for (size_t index = 1;
         error == cudaSuccess && index + 1 < count; ++index) {
        const unsigned stages = static_cast<unsigned>(parts[index]);
        error = b2n_dispatch_noinit_interval_on<false>(
            sources, log_n, 4, start_stage, stages, inverse_twiddles, stream);
        start_stage += stages;
    }
    if (error != cudaSuccess) return error;

    const unsigned final_stages = static_cast<unsigned>(parts[count - 1]);
    if (start_stage + final_stages - 1 != log_n)
        return cudaErrorInvalidConfiguration;
    if ((log_n == 24 || log_n == 25) && final_stages == 6)
        return launch_composition_split_boundary_on<3, FUSE_FIRST_FORWARD>(
            sources, retained_outputs, log_n, start_stage, inverse_twiddles,
            forward_twiddles, stream);
    return cudaErrorInvalidConfiguration;
}

template <bool FUSE_FIRST_FORWARD>
int b2n_composition_split_entry(
    uint32_t **source_values, uint32_t **retained_outputs, uint32_t log_n,
    const uint32_t *inverse_twiddles, uint32_t inverse_twiddle_words,
    const uint32_t *forward_twiddles, uint32_t forward_twiddle_words,
    uint32_t eval_domain_size, void *stream_raw) {
    if (source_values == nullptr || retained_outputs == nullptr ||
        inverse_twiddles == nullptr || stream_raw == nullptr ||
        (log_n != 24 && log_n != 25) ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > inverse_twiddle_words ||
        (FUSE_FIRST_FORWARD &&
         (forward_twiddles == nullptr ||
          eval_domain_size > forward_twiddle_words)))
        return (int)cudaErrorInvalidValue;

    auto inverse = reinterpret_cast<m31 *>(const_cast<uint32_t *>(
        inverse_twiddles + inverse_twiddle_words - eval_domain_size));
    m31 *forward = nullptr;
    if constexpr (FUSE_FIRST_FORWARD) {
        forward = reinterpret_cast<m31 *>(const_cast<uint32_t *>(
            forward_twiddles + forward_twiddle_words - eval_domain_size));
    }
    return (int)b2n_composition_split_on<FUSE_FIRST_FORWARD>(
        reinterpret_cast<m31 **>(source_values),
        reinterpret_cast<m31 **>(retained_outputs), log_n, inverse, forward,
        reinterpret_cast<cudaStream_t>(stream_raw));
}

template <bool DUPLICATE_TO_RETAINED>
int b2n_columns_out_of_place_entry(
    const uint32_t *const *inputs, uint32_t *const *outputs, uint32_t log_n,
    uint32_t num_poly, const uint32_t *g_twiddles, uint32_t twiddles_size,
    uint32_t eval_domain_size, void *stream_raw) {
    if (inputs == nullptr || outputs == nullptr || g_twiddles == nullptr ||
        stream_raw == nullptr || log_n < 3 || log_n > 30 || num_poly == 0 ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddles_size)
        return (int)cudaErrorInvalidValue;
    cudaStream_t stream = reinterpret_cast<cudaStream_t>(stream_raw);
    m31 *twiddles = reinterpret_cast<m31 *>(
        const_cast<uint32_t *>(g_twiddles + twiddles_size - eval_domain_size));
    for (uint32_t base = 0; base < num_poly; base += MAX_NTT_BATCH_COLUMNS) {
        const uint32_t chunk = min(num_poly - base, MAX_NTT_BATCH_COLUMNS);
        auto input = reinterpret_cast<m31 **>(const_cast<uint32_t **>(inputs + base));
        auto output = reinterpret_cast<m31 **>(
            const_cast<uint32_t **>(outputs + base));
        cudaError_t error = b2n_fused_out_of_place_on<DUPLICATE_TO_RETAINED>(
            input, output, log_n, chunk, twiddles, stream);
        if (error != cudaSuccess) return (int)error;
    }
    return (int)cudaSuccess;
}

} // namespace

extern "C" int stwo_ntt_b2n_columns_out_of_place_on(
    const uint32_t *const *inputs, uint32_t *const *outputs, uint32_t log_n,
    uint32_t num_poly, const uint32_t *g_twiddles, uint32_t twiddles_size,
    uint32_t eval_domain_size, void *stream_raw) {
    return b2n_columns_out_of_place_entry<false>(
        inputs, outputs, log_n, num_poly, g_twiddles, twiddles_size,
        eval_domain_size, stream_raw);
}

extern "C" int stwo_ntt_b2n_columns_after_first_seven_on(
    uint32_t **device_values, uint32_t log_n, uint32_t num_poly,
    const uint32_t *g_twiddles, uint32_t twiddles_size,
    uint32_t eval_domain_size, void *stream_raw) {
    if (device_values == nullptr || g_twiddles == nullptr || stream_raw == nullptr ||
        log_n != 23 || num_poly != 4 || eval_domain_size != (1u << 22) ||
        eval_domain_size > twiddles_size)
        return (int)cudaErrorInvalidValue;

    auto twiddles = reinterpret_cast<m31 *>(const_cast<uint32_t *>(
        g_twiddles + twiddles_size - eval_domain_size));
    auto values = reinterpret_cast<m31 **>(device_values);
    auto stream = reinterpret_cast<cudaStream_t>(stream_raw);
    cudaError_t error = b2n_dispatch_noinit_interval_on<false>(
        values, log_n, num_poly, 8, 8, twiddles, stream);
    if (error != cudaSuccess) return (int)error;
    return (int)b2n_dispatch_noinit_interval_on<false>(
        values, log_n, num_poly, 16, 8, twiddles, stream);
}

extern "C" int stwo_ntt_b2n_after_first_seven_function_attributes(
    uint32_t start_stage, uint32_t stages, StwoCudaFunctionAttributes *out) {
    if ((start_stage != 8 && start_stage != 16) || stages != 8)
        return (int)cudaErrorInvalidValue;
    return (int)stwo_cuda_function_attributes(
        b2n_noinit_block_batch<4, false>, out);
}

extern "C" int stwo_ntt_b2n_columns_to_retained_on(
    const uint32_t *const *inputs, uint32_t *const *retained_outputs,
    uint32_t log_n, uint32_t num_poly, const uint32_t *g_twiddles,
    uint32_t twiddles_size, uint32_t eval_domain_size, void *stream_raw) {
    return b2n_columns_out_of_place_entry<true>(
        inputs, retained_outputs, log_n, num_poly, g_twiddles, twiddles_size,
        eval_domain_size, stream_raw);
}

extern "C" int stwo_ntt_b2n_composition_to_retained_on(
    uint32_t **source_values, uint32_t **retained_outputs, uint32_t log_n,
    const uint32_t *inverse_twiddles, uint32_t inverse_twiddle_words,
    uint32_t eval_domain_size, void *stream_raw) {
    return b2n_composition_split_entry<false>(
        source_values, retained_outputs, log_n, inverse_twiddles,
        inverse_twiddle_words, nullptr, 0, eval_domain_size, stream_raw);
}

extern "C" int stwo_ntt_b2n_composition_fused_first_forward_on(
    uint32_t **source_values, uint32_t **retained_outputs, uint32_t log_n,
    const uint32_t *inverse_twiddles, uint32_t inverse_twiddle_words,
    const uint32_t *forward_twiddles, uint32_t forward_twiddle_words,
    uint32_t eval_domain_size, void *stream_raw) {
    return b2n_composition_split_entry<true>(
        source_values, retained_outputs, log_n, inverse_twiddles,
        inverse_twiddle_words, forward_twiddles, forward_twiddle_words,
        eval_domain_size, stream_raw);
}


EXTERN void ntt_b2n_native_batch(m31** input, m31** output,
                           unsigned log_n, unsigned num_poly,
                           unsigned start_stage,
                           unsigned end_stage,
                           m31 *g_twiddles,
                           unsigned twiddles_size, unsigned eval_domain_size) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    dim3 block_dim{};
    block_dim.x = log_n <= 8 ? 1 << (log_n - 1) : 128;
    dim3 grid_dim{};
    grid_dim.y = num_poly;
    grid_dim.x = log_n <= 8 ? 1 : 1 << (log_n - 8);

    m31 rescale_factor = inv(pow(m31{2}, log_n));
    unsigned layer_domain_size = (1 << log_n) >> 1;
    unsigned layer_domain_offset = 0;
    if (start_stage == 1) {
        ntt_b2n_stage_batch<false><<<grid_dim, block_dim, 0>>>(
            input, output, log_n, 1, g_twiddles, rescale_factor);
        ASSERT_CUDA_SUCCESS(cudaGetLastError());
    }

    ASSERT_TRUE(start_stage >= 1, "start_stage < 1 in ntt_n2b_native");
    ASSERT_TRUE(end_stage <= log_n, "end_stage <= log_n in ntt_n2b_native");
    for (unsigned stage = 2; stage <= end_stage; stage++) {
        if (stage >= start_stage) {
            ntt_b2n_stage_batch<false><<<grid_dim, block_dim, 0>>>(
                output, output, log_n, stage, &g_twiddles[layer_domain_offset], rescale_factor);
            ASSERT_CUDA_SUCCESS(cudaGetLastError());
        }
        layer_domain_size >>= 1;
        layer_domain_offset += layer_domain_size;
    }
    stwo_maybe_debug_sync();
}

static void ntt_b2n_column_dispatch(
    m31** device_values,
    uint32_t log_n,
    uint32_t num_poly,
    uint32_t* g_twiddles,
    uint32_t twiddles_size,
    uint32_t eval_domain_size
) {
    if (log_n < 13) {
        ntt_b2n_native_batch(device_values, device_values, log_n, num_poly, 1, log_n, g_twiddles, twiddles_size, eval_domain_size);
    } else if (log_n >= 13 && log_n <= 18) {
        const auto& config = LAUNCH_B2N_CONFIG_13_18[log_n - 13];
        auto kernel0 = [config]() -> void(*)(uint32_t**, uint32_t**, uint32_t, uint32_t, uint32_t, uint32_t*, uint32_t, uint32_t) {
            switch (config[0]) {
                case 7: return ntt_b2n_init_7_stage_batch;
                case 8: return ntt_b2n_init_8_stage_batch;
                case 9: return ntt_b2n_init_9_stage_batch;
                case 10: return ntt_b2n_init_10_stage_batch;
                case 11: return ntt_b2n_init_11_stage_batch;
                default: throw std::runtime_error("invalid config");
            }
        }();

        auto kernel1 = [config]() -> void(*)(uint32_t**, uint32_t**, uint32_t, uint32_t, uint32_t, uint32_t*, uint32_t, uint32_t) {
            switch (config[1]) {
                case 4: return ntt_b2n_noinit_4_stage_batch;
                case 6: return ntt_b2n_noinit_6_stage_batch;;
                case 8: return ntt_b2n_noinit_8_stage_batch;
                default: throw std::runtime_error("invalid config");
            }
        }();

        const uint32_t start_stage1 = 1 + config[0];

        kernel0(device_values, device_values, log_n, num_poly, 1, g_twiddles, twiddles_size, eval_domain_size);
        kernel1(device_values, device_values, log_n, num_poly, start_stage1, g_twiddles, twiddles_size, eval_domain_size);

    } else if (log_n >= 19 && log_n <= 24) {
        const auto& config = LAUNCH_B2N_CONFIG_19_24[log_n - 19];

        auto kernel0 = [config]() -> void(*)(uint32_t**, uint32_t**, uint32_t, uint32_t, uint32_t, uint32_t*, uint32_t, uint32_t) {
            switch (config[0]) {
                case 7: return ntt_b2n_init_7_stage_batch;
                case 8: return ntt_b2n_init_8_stage_batch;
                case 9: return ntt_b2n_init_9_stage_batch;
                case 10: return ntt_b2n_init_10_stage_batch;
                case 11: return ntt_b2n_init_11_stage_batch;
                case 14: return ntt_b2n_init_12_stage_batch;
                default: throw std::runtime_error("invalid config");
            }
        }();

        auto kernel1 = [config]() -> void(*)(uint32_t**, uint32_t**, uint32_t, uint32_t, uint32_t, uint32_t*, uint32_t, uint32_t) {
            switch (config[1]) {
                case 4: return ntt_b2n_noinit_4_stage_batch;;
                case 6: return ntt_b2n_noinit_6_stage_batch;
                case 8: return ntt_b2n_noinit_8_stage_batch;
                default: throw std::runtime_error("invalid config");
            }
        }();

        auto kernel2 = [config]() -> void(*)(uint32_t**, uint32_t**, uint32_t, uint32_t, uint32_t, uint32_t*, uint32_t, uint32_t) {
            switch (config[2]) {
                case 4: return ntt_b2n_noinit_4_stage_batch;
                case 6: return ntt_b2n_noinit_6_stage_batch;
                case 8: return ntt_b2n_noinit_8_stage_batch;
                default: throw std::runtime_error("invalid config");
            }
        }();

        const uint32_t start_stage1 = 1 + config[0];
        const uint32_t start_stage2 = start_stage1 + config[1];

        kernel0(device_values, device_values, log_n, num_poly, 1, g_twiddles, twiddles_size, eval_domain_size);
        kernel1(device_values, device_values, log_n, num_poly, start_stage1, g_twiddles, twiddles_size, eval_domain_size);
        kernel2(device_values, device_values, log_n, num_poly, start_stage2, g_twiddles, twiddles_size, eval_domain_size);

    } else if (log_n >= 25 && log_n <= 29) {
        const auto& config = LAUNCH_B2N_CONFIG_25_29[log_n - 25];

        auto kernel0 = [config]() -> void(*)(uint32_t**, uint32_t**, uint32_t, uint32_t, uint32_t, uint32_t*, uint32_t, uint32_t) {
            switch (config[0]) {
                case 7: return ntt_b2n_init_7_stage_batch;
                case 8: return ntt_b2n_init_8_stage_batch;
                case 9: return ntt_b2n_init_9_stage_batch;
                case 10: return ntt_b2n_init_10_stage_batch;
                case 11: return ntt_b2n_init_11_stage_batch;
                default: throw std::runtime_error("invalid config");
            }
        }();

        auto kernel1 = [config]() -> void(*)(uint32_t**, uint32_t**, uint32_t, uint32_t, uint32_t, uint32_t*, uint32_t, uint32_t) {
            switch (config[1]) {
                case 4: return ntt_b2n_noinit_4_stage_batch;
                case 6: return ntt_b2n_noinit_6_stage_batch;
                case 8: return ntt_b2n_noinit_8_stage_batch;
                default: throw std::runtime_error("invalid config");
            }
        }();

        auto kernel2 = [config]() -> void(*)(uint32_t**, uint32_t**, uint32_t, uint32_t, uint32_t, uint32_t*, uint32_t, uint32_t) {
            switch (config[2]) {
                case 4: return ntt_b2n_noinit_4_stage_batch;;
                case 6: return ntt_b2n_noinit_6_stage_batch;
                case 8: return ntt_b2n_noinit_8_stage_batch;
                default: throw std::runtime_error("invalid config");
            }
        }();

        auto kernel3 = [config]() -> void(*)(uint32_t**, uint32_t**, uint32_t, uint32_t, uint32_t, uint32_t*, uint32_t, uint32_t) {
            switch (config[3]) {
                case 4: return ntt_b2n_noinit_4_stage_batch;;
                case 6: return ntt_b2n_noinit_6_stage_batch;;
                case 8: return ntt_b2n_noinit_8_stage_batch;
                default: throw std::runtime_error("invalid config");
            }
        }();

        const uint32_t start_stage1 = 1 + config[0];
        const uint32_t start_stage2 = start_stage1 + config[1];
        const uint32_t start_stage3 = start_stage2 + config[2];

        kernel0(device_values, device_values, log_n, num_poly, 1, g_twiddles, twiddles_size, eval_domain_size);
        kernel1(device_values, device_values, log_n, num_poly, start_stage1, g_twiddles, twiddles_size, eval_domain_size);
        kernel2(device_values, device_values, log_n, num_poly, start_stage2, g_twiddles, twiddles_size, eval_domain_size);
        kernel3(device_values, device_values, log_n, num_poly, start_stage3, g_twiddles, twiddles_size, eval_domain_size);

    } else {
        throw std::runtime_error("b2n log_n too big");
    }

    stwo_maybe_debug_sync();
}

// Tile the column (batch) axis into chunks of at most MAX_NTT_BATCH_COLUMNS so the
// per-launcher grid.y/grid.z (= num_poly) never exceeds CUDA's 65535 limit. Columns
// are transformed independently -- num_poly is never used for indexing inside any
// kernel; only blockIdx.{y,z} selects input[ntt_idx]/output[ntt_idx] -- so processing
// a contiguous sub-range of columns is bit-for-bit identical to one big launch. Each
// chunk is cloned from the host pointer array (values_columns + base) exactly as the
// original single call did, so memory layout and math are unchanged. Any group with
// num_poly <= 65535 (every workload before the 14M-step PIEs) runs a single iteration
// with base == 0 and behaves exactly as before.
EXTERN void ntt_b2n_column(
    uint32_t** values_columns,
    uint32_t log_n,
    uint32_t num_poly,
    uint32_t* g_twiddles,
    uint32_t twiddles_size,
    uint32_t eval_domain_size
) {
    stwo_maybe_debug_sync();

    for (uint32_t base = 0; base < num_poly; base += MAX_NTT_BATCH_COLUMNS) {
        const uint32_t chunk = min(num_poly - base, MAX_NTT_BATCH_COLUMNS);
        m31 **device_values =
            cuda_proving_clone_to_device<m31*>(values_columns + base, chunk);
        // Surface any sticky error from an earlier async launch at this call site
        // instead of letting it masquerade as a failure of the launches below.
        ASSERT_CUDA_SUCCESS(cudaGetLastError());
        ntt_b2n_column_dispatch(device_values, log_n, chunk, g_twiddles,
                                twiddles_size, eval_domain_size);
        cuda_proving_free(device_values);
    }
}
