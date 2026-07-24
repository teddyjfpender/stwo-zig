#include "rfft.cuh"
#include "blake2s.cuh"
#include "poly_utils.cuh"
#include "utils.cuh"

// CUDA caps grid.y and grid.z at 65535 (maxGridSize[1]/[2]). Every batched NTT
// launcher maps the column (batch) axis onto grid.y or grid.z, so a same-log_size
// column group larger than this overflows the launch configuration. The column
// (batch) set is tiled into chunks of at most this many columns.
static constexpr unsigned MAX_NTT_BATCH_COLUMNS = 65535;

// log_stride = 4,3,2,1,0
template <unsigned LOG_VALS_PER_THREAD>
DEVICE_FORCEINLINE void shfl_xor_bf(m31* vals, const unsigned log_stride,
                                    const unsigned lane_id) {
  const unsigned mask = 1 << log_stride;
  const unsigned num_pair_per_thread = 1 << (LOG_VALS_PER_THREAD - 1);
  __syncwarp();
#pragma unroll
  for (unsigned i = 0; i < num_pair_per_thread; i++) {
    m31* ptr = lane_id & mask ? vals + 2 * i : vals + 2 * i + 1;
    *ptr = __shfl_xor_sync(0xffffffff, *ptr, mask);
  }
}

__global__ void rfft_circle_part(m31 *values, m31 *inverse_twiddles_tree, int values_size) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;


    if (idx < (values_size >> 1)) {
        m31 val0 = values[2 * idx];
        m31 val1 = values[2 * idx + 1];
        m31 twiddle = get_circle_twiddle(inverse_twiddles_tree, idx);

        m31 temp = mul(val1, twiddle);

        values[2 * idx] = add(val0, temp);
        values[2 * idx + 1] = sub(val0, temp);
    }
}

__global__ void rfft_line_part(m31 *values, m31 *inverse_twiddles_tree, int values_size, int inverse_twiddles_size,
                               int layer_domain_offset, int layer) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < (values_size >> 1)) {
        int number_polynomials = 1 << layer;
        int h = idx / number_polynomials;
        int l = idx % number_polynomials;
        int idx0 = (h << (layer + 1)) + l;
        int idx1 = idx0 + number_polynomials;

        m31 val0 = values[idx0];
        m31 val1 = values[idx1];
        m31 twiddle = inverse_twiddles_tree[layer_domain_offset + h];

        m31 temp = mul(val1, twiddle);

        values[idx0] = add(val0, temp);
        values[idx1] = sub(val0, temp);
    }
}

void evaluate(int eval_domain_size, m31 *values, m31 *twiddles_tree, int twiddles_size, int values_size) {
    twiddles_tree = &twiddles_tree[twiddles_size - eval_domain_size];
    int block_dim = 256;
    int num_blocks = ((values_size >> 1) + block_dim - 1) / block_dim;

    int log_values_size = log_2(values_size);
    int layer_domain_size = 1;
    int layer_domain_offset = (values_size >> 1) - 2;
    int i = log_values_size - 1;
    while (i > 0) {
        rfft_line_part<<<num_blocks, block_dim>>>(values, twiddles_tree, values_size, layer_domain_size,
                                                  layer_domain_offset, i);
        ASSERT_CUDA_SUCCESS(cudaGetLastError());
        layer_domain_size <<= 1;
        layer_domain_offset -= layer_domain_size;
        i -= 1;
    }

    rfft_circle_part<<<num_blocks, block_dim>>>(values, twiddles_tree, values_size);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}


// row_block_offset: index of this launch's first row-block along the (tiled)
// grid.y axis; idx is identical to a single launch with blockIdx.y + offset.
__global__ void batch_rfft_circle_part(m31 **values, m31 *inverse_twiddles_tree, int number_of_columns, int number_of_rows, int row_block_offset) {
    int idx = (blockIdx.y + row_block_offset) * blockDim.x + threadIdx.x;
    unsigned int column_index = blockIdx.x;

    if (idx < (number_of_rows >> 1) && column_index < number_of_columns) {
        m31 *column = values[column_index];

        m31 val0 = column[2 * idx];
        m31 val1 = column[2 * idx + 1];
        m31 twiddle = get_circle_twiddle(inverse_twiddles_tree, idx);

        m31 temp = mul(val1, twiddle);

        column[2 * idx] = add(val0, temp);
        column[2 * idx + 1] = sub(val0, temp);
    }
}

__global__ void batch_rfft_line_part(
        m31 **values, m31 *inverse_twiddles_tree, int number_of_columns, int number_of_rows, int layer_domain_offset, int layer,
        int row_block_offset
) {
    int idx = (blockIdx.y + row_block_offset) * blockDim.x + threadIdx.x;
    unsigned int column_index = blockIdx.x;

    if (idx < (number_of_rows >> 1) && column_index < number_of_columns) {
        m31 *column = values[column_index];

        int number_polynomials = 1 << layer;
        int h = idx / number_polynomials;
        int l = idx % number_polynomials;
        int idx0 = (h << (layer + 1)) + l;
        int idx1 = idx0 + number_polynomials;

        m31 val0 = column[idx0];
        m31 val1 = column[idx1];
        m31 twiddle = inverse_twiddles_tree[layer_domain_offset + h];

        m31 temp = mul(val1, twiddle);

        column[idx0] = add(val0, temp);
        column[idx1] = sub(val0, temp);
    }
}

void evaluate_columns(const int *eval_domain_sizes, m31 **values, m31 *twiddles_tree, int twiddles_size, int number_of_columns, const int *column_sizes) {
    // TODO: Handle case where columns are of different sizes.
    int number_of_rows = column_sizes[0];
    int eval_domain_size = eval_domain_sizes[0];

    m31 **device_values = cuda_proving_clone_to_device<m31*>(values, number_of_columns);

    twiddles_tree = &twiddles_tree[twiddles_size - eval_domain_size];

    int block_size = 1024;
    int number_of_blocks = ((number_of_rows >> 1) + block_size - 1) / block_size;

    // The row-block axis is grid.y (CUDA cap 65535); columns ride grid.x
    // (cap 2^31-1, never workload-limited here). Tile the row-block axis:
    // each chunk covers disjoint idx values via row_block_offset, so the
    // union of the tiled launches touches exactly the same (column, idx)
    // pairs as one big launch would.
    constexpr int MAX_Y_BLOCKS = 65535;

    int log_number_of_rows = log_2(number_of_rows);
    int layer_domain_size = 1;
    int layer_domain_offset = (number_of_rows >> 1) - 2;
    int i = log_number_of_rows - 1;

    while (i > 0) {
        for (int y_base = 0; y_base < number_of_blocks; y_base += MAX_Y_BLOCKS) {
            dim3 grid_dimensions(number_of_columns, min(number_of_blocks - y_base, MAX_Y_BLOCKS));
            batch_rfft_line_part<<<grid_dimensions, block_size>>>(
                    device_values, twiddles_tree, number_of_columns, number_of_rows, layer_domain_offset, i, y_base
            );
            ASSERT_CUDA_SUCCESS(cudaGetLastError());
        }
        layer_domain_size <<= 1;
        layer_domain_offset -= layer_domain_size;
        i -= 1;
    }

    for (int y_base = 0; y_base < number_of_blocks; y_base += MAX_Y_BLOCKS) {
        dim3 grid_dimensions(number_of_columns, min(number_of_blocks - y_base, MAX_Y_BLOCKS));
        batch_rfft_circle_part<<<grid_dimensions, block_size>>>(device_values, twiddles_tree, number_of_columns, number_of_rows, y_base);
        ASSERT_CUDA_SUCCESS(cudaGetLastError());
    }
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    cuda_proving_free(device_values);
}

// Keep the register-width families on their measured spill-free occupancy boundary.
// On SM90, log3 compiles at 40 registers and admits six 256-thread blocks;
// log4 compiles at 64 registers and admits two 512-thread blocks. A generic
// two-block hint regresses log3 to 50 registers, while asking log4 for more
// than two blocks spills. The 5/7-stage twins reduce only the warp dimension;
// they keep the same per-thread register width and bound.
template <unsigned LOG_VALS_PER_THREAD,
          unsigned LOG_WARPS_PER_BLOCK = LOG_VALS_PER_THREAD>
__global__ __launch_bounds__(
    1u << (LOG_WARP + LOG_WARPS_PER_BLOCK),
    LOG_VALS_PER_THREAD == 3 ? 6 : 2)
void n2b_nofinal_block_batch(m31** input, m31** output,
                                  const unsigned log_n, const unsigned num_poly,
                                  unsigned min_stage, unsigned max_stage, m31 *g_twiddles) {

    const unsigned min_stride = 1 << (log_n - max_stage);
    const unsigned middle_stage = min_stage + LOG_VALS_PER_THREAD;
    const unsigned num_stage = LOG_VALS_PER_THREAD + LOG_WARPS_PER_BLOCK;

    const unsigned ntt_idx = blockIdx.z;
    const unsigned block_index_x = blockIdx.x;
    const unsigned block_index_y = blockIdx.y;
    const unsigned warp_idx_in_block = threadIdx.y;
    const unsigned thread_idx_in_warp = threadIdx.x;

    const m31* input_ntt_start = input[ntt_idx];
    const unsigned block_start =
        (block_index_x << LOG_WARP) +
        (block_index_y << (log_n - max_stage + num_stage));

    __shared__ m31 smem[32 << (LOG_VALS_PER_THREAD + LOG_WARPS_PER_BLOCK)];
    m31 vals[1 << LOG_VALS_PER_THREAD];

    unsigned offset = warp_idx_in_block * min_stride + thread_idx_in_warp;
    #pragma unroll
    for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); i++) {
            const unsigned address =
                block_start + i * (min_stride << LOG_WARPS_PER_BLOCK) + offset;
            vals[i] = input_ntt_start[address];
    }

    unsigned layer_domain_size = 1;
    unsigned layer_domain_offset = ((1 << log_n) >> 1) - 2;

    for (unsigned i = 1; i < min_stage; i++) {
        layer_domain_size <<= 1;
        layer_domain_offset -= layer_domain_size;
    }
#pragma unroll
  for (unsigned stage = min_stage; stage < middle_stage; stage++) {
    const unsigned log_inner_stride_size = LOG_VALS_PER_THREAD - 1 - (stage - min_stage);
#pragma unroll
    for (unsigned gid = 0; gid < 1 << (LOG_VALS_PER_THREAD - 1); gid++) {
        const unsigned inner_group_idx = gid & ((1 << log_inner_stride_size) - 1);
        const unsigned inner_pair_idx = gid >> log_inner_stride_size;
        const unsigned inner_left_idx = inner_group_idx + (inner_pair_idx << (log_inner_stride_size + 1));
        const unsigned inner_right_idx = inner_left_idx + (1 << log_inner_stride_size);
        const unsigned outer_pair_idx = (block_start + offset) >> (1 + log_n - stage);

        const m31 twiddle = mul(g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx], vals[inner_right_idx]);
        const m31 temp = vals[inner_left_idx];
        vals[inner_left_idx] = add(temp, twiddle);
        vals[inner_right_idx] = sub(temp, twiddle);

    }
    layer_domain_size <<= 1;
    layer_domain_offset -= layer_domain_size;
  }

#pragma unroll
  for (unsigned i = 0; i < 1 << LOG_VALS_PER_THREAD; i++)
    smem[thread_idx_in_warp + (i << (LOG_WARP + LOG_WARPS_PER_BLOCK)) +
         (warp_idx_in_block << LOG_WARP)] = vals[i];
  __syncthreads();
  offset = warp_idx_in_block * (min_stride << LOG_VALS_PER_THREAD) +
           thread_idx_in_warp;
#pragma unroll
  for (unsigned i = 0; i < 1 << LOG_VALS_PER_THREAD; i++) {
    vals[i] = smem[thread_idx_in_warp + (i << LOG_WARP) +
                    (warp_idx_in_block << (LOG_WARP + LOG_VALS_PER_THREAD))];
  }

#pragma unroll
  for (unsigned stage = middle_stage; stage <= max_stage; stage++) {
    const unsigned log_inner_stride_size = LOG_WARPS_PER_BLOCK - 1 - (stage - middle_stage);
#pragma unroll
    for (unsigned gid = 0; gid < 1 << (LOG_VALS_PER_THREAD - 1); gid++) {
        const unsigned inner_group_idx = gid & ((1 << log_inner_stride_size) - 1);
        const unsigned inner_pair_idx = gid >> log_inner_stride_size;
        const unsigned inner_left_idx = inner_group_idx + (inner_pair_idx << (log_inner_stride_size + 1));
        const unsigned inner_right_idx = inner_left_idx + (1 << log_inner_stride_size);
        const unsigned outer_pair_idx = (block_start + offset) >> (1 + log_n - stage);
        const m31 twiddle = mul(g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx], vals[inner_right_idx]);
        const m31 temp = vals[inner_left_idx];
        vals[inner_left_idx] = add(temp, twiddle);
        vals[inner_right_idx] = sub(temp, twiddle);
    }
    layer_domain_size <<= 1;
    layer_domain_offset -= layer_domain_size;
  }

  m31* output_ntt_start = output[ntt_idx];
#pragma unroll
  for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); i++) {
    const unsigned address = block_start + i * min_stride + offset;
    output_ntt_start[address] = vals[i];
  }
}

template <unsigned LOG_VALS_PER_THREAD, unsigned LOG_WARPS_PER_BLOCK>
static cudaError_t ntt_n2b_nofinal_stage_batch_on(
    m31** input, m31** output, unsigned log_n, unsigned num_poly,
    unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size,
    unsigned eval_domain_size, cudaStream_t stream
) {
    static_assert(LOG_VALS_PER_THREAD >= LOG_WARPS_PER_BLOCK);
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned num_stage =
        LOG_VALS_PER_THREAD + LOG_WARPS_PER_BLOCK;
    if (start_stage < 1 || start_stage > log_n ||
        num_stage > log_n - start_stage + 1) {
        return cudaErrorInvalidValue;
    }
    const unsigned end_stage = start_stage + num_stage - 1;
    if (log_n - end_stage < LOG_WARP) {
        return cudaErrorInvalidConfiguration;
    }
    dim3 block_dim{32, 1 << LOG_WARPS_PER_BLOCK, 1};
    dim3 grid_dim{};
    const unsigned min_stride = 1 << (log_n - end_stage);
    grid_dim.z = num_poly;
    grid_dim.x = min_stride / 32;
    grid_dim.y = (1 << log_n) / (min_stride << num_stage);

    if ((grid_dim.y * grid_dim.x * block_dim.x * block_dim.y
         << LOG_VALS_PER_THREAD) != (1u << log_n)) {
        return cudaErrorInvalidConfiguration;
    }
    n2b_nofinal_block_batch<LOG_VALS_PER_THREAD, LOG_WARPS_PER_BLOCK>
        <<<grid_dim, block_dim, 0, stream>>>(
            input, output, log_n, num_poly, start_stage, end_stage, g_twiddles);
    return cudaGetLastError();
}

static cudaError_t ntt_n2b_nofinal_5_stage_batch_on(
    m31** input, m31** output, unsigned log_n, unsigned num_poly,
    unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size,
    unsigned eval_domain_size, cudaStream_t stream
) {
    return ntt_n2b_nofinal_stage_batch_on<3, 2>(
        input, output, log_n, num_poly, start_stage, g_twiddles,
        twiddles_size, eval_domain_size, stream);
}

static cudaError_t ntt_n2b_nofinal_6_stage_batch_on(
    m31** input, m31** output, unsigned log_n, unsigned num_poly,
    unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size,
    unsigned eval_domain_size, cudaStream_t stream
) {
    return ntt_n2b_nofinal_stage_batch_on<3, 3>(
        input, output, log_n, num_poly, start_stage, g_twiddles,
        twiddles_size, eval_domain_size, stream);
}

EXTERN void ntt_n2b_nofinal_6_stage_batch(m31** input, m31** output,
                                unsigned log_n, unsigned num_poly, unsigned start_stage,
                                m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    ASSERT_CUDA_SUCCESS(ntt_n2b_nofinal_6_stage_batch_on(
        input, output, log_n, num_poly, start_stage, g_twiddles, twiddles_size,
        eval_domain_size, 0));
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

static cudaError_t ntt_n2b_nofinal_8_stage_batch_on(
    m31** input, m31** output, unsigned log_n, unsigned num_poly,
    unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size,
    unsigned eval_domain_size, cudaStream_t stream
) {
    return ntt_n2b_nofinal_stage_batch_on<4, 4>(
        input, output, log_n, num_poly, start_stage, g_twiddles,
        twiddles_size, eval_domain_size, stream);
}

static cudaError_t ntt_n2b_nofinal_7_stage_batch_on(
    m31** input, m31** output, unsigned log_n, unsigned num_poly,
    unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size,
    unsigned eval_domain_size, cudaStream_t stream
) {
    return ntt_n2b_nofinal_stage_batch_on<4, 3>(
        input, output, log_n, num_poly, start_stage, g_twiddles,
        twiddles_size, eval_domain_size, stream);
}

EXTERN void ntt_n2b_nofinal_8_stage_batch(m31** input, m31** output,
                                unsigned log_n, unsigned num_poly, unsigned start_stage,
                                m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    ASSERT_CUDA_SUCCESS(ntt_n2b_nofinal_8_stage_batch_on(
        input, output, log_n, num_poly, start_stage, g_twiddles, twiddles_size,
        eval_domain_size, 0));
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

template <unsigned LOG_VALS_PER_THREAD, bool APPLY_CIRCLE = true>
__global__ void n2b_final_warp_batch(m31** input, m31** output,
                               const unsigned log_n, const unsigned num_poly,
                               unsigned min_stage, m31 *g_twiddles) {
    const unsigned ntt_idx = blockIdx.y;
    const unsigned thread_idx_in_warp = threadIdx.x;
    const unsigned warps_idx_in_ntt = blockDim.y * blockIdx.x + threadIdx.y;
    const unsigned log_vals_per_warp = LOG_VALS_PER_THREAD + LOG_WARP;
    const m31* input_ntt_start = input[ntt_idx];
    unsigned warp_start =
        (warps_idx_in_ntt << log_vals_per_warp) + thread_idx_in_warp;

    m31 vals[1 << LOG_VALS_PER_THREAD];
    #pragma unroll
    for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); i++) {
        vals[i] = input_ntt_start[warp_start + (i << LOG_WARP)];
    }

    // int log_values_size = log_n;
    unsigned layer_domain_size = 1;
    unsigned layer_domain_offset = ((1 << log_n) >> 1) - 2;

    for (unsigned i = 1; i < min_stage; i++) {
        layer_domain_size <<= 1;
        layer_domain_offset -= layer_domain_size;
    }
    unsigned stage = min_stage;
    #pragma unroll
    for (; stage < min_stage + LOG_VALS_PER_THREAD; stage++) {
        const unsigned log_inner_stride_size =
            LOG_VALS_PER_THREAD - 1 - (stage - min_stage);
    #pragma unroll
        for (unsigned gid = 0; gid < 1 << (LOG_VALS_PER_THREAD - 1); gid++) {
            const unsigned inner_group_idx = gid & ((1 << log_inner_stride_size) - 1);
            const unsigned inner_pair_idx = gid >> log_inner_stride_size;
            const unsigned inner_left_idx =
                inner_group_idx + (inner_pair_idx << (log_inner_stride_size + 1));
            const unsigned inner_right_idx =
                inner_left_idx + (1 << log_inner_stride_size);
            const unsigned outer_pair_idx = warp_start >> (1 + log_n - stage);
            const m31 twiddle = mul(g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx], vals[inner_right_idx]);
            const m31 temp = vals[inner_left_idx];
            vals[inner_left_idx] = add(temp, twiddle);
            vals[inner_right_idx] = sub(temp, twiddle);
        }
        layer_domain_size <<= 1;
        layer_domain_offset -= layer_domain_size;
    }

    #pragma unroll
    for (; stage <= log_n; stage++) {
        const unsigned log_stride = log_n - stage;
        shfl_xor_bf<LOG_VALS_PER_THREAD>(vals, log_stride, thread_idx_in_warp);
        // The hash-from-tile lane needs the canonical adjacent inputs to the
        // final circle butterfly. The last shuffle gathers exactly those pairs;
        // skip only their arithmetic and store them with the ordinary mapping.
        if constexpr (!APPLY_CIRCLE) {
            if (stage == log_n) continue;
        }
    #pragma unroll
        for (unsigned i = 0; i < 1 << (LOG_VALS_PER_THREAD - 1); i++) {
            const unsigned inner_pair_idx =
                (thread_idx_in_warp >> log_stride) + (i << (LOG_WARP - log_stride));
            const unsigned outer_pair_idx = warps_idx_in_ntt
                                            << (log_vals_per_warp - 1 - log_stride);
            m31 twiddle = m31(1);
            if (stage == log_n) {
                twiddle = mul(get_circle_twiddle(g_twiddles, inner_pair_idx + outer_pair_idx), vals[2 * i + 1]);
            } else {
                twiddle = mul(g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx], vals[2 * i + 1]);
            }

            const m31 temp = vals[2 * i];
            vals[2 * i] = add(temp, twiddle);
            vals[2 * i + 1] = sub(temp, twiddle);
        }
        layer_domain_size <<= 1;
        layer_domain_offset -= layer_domain_size;
    }

    m31* output_ntt_start = output[ntt_idx];
    warp_start = (warps_idx_in_ntt << log_vals_per_warp) + thread_idx_in_warp * 2;
    uint64_t* src = reinterpret_cast<uint64_t*>(vals);
    uint64_t* dst = reinterpret_cast<uint64_t*>(output_ntt_start + warp_start);


    #pragma unroll
    for (unsigned i = 0; i < 1 << (LOG_VALS_PER_THREAD - 1); i++) {
        dst[(i << LOG_WARP)] = src[i];
    }
}

template <unsigned LOG_VALS_PER_THREAD>
__global__ void n2b_final_warp_hash16_batch(
    m31 **input,
    const unsigned log_n,
    unsigned min_stage,
    m31 *g_twiddles,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states
) {
    extern __shared__ uint32_t messages[];
    const unsigned lane = threadIdx.x;
    const unsigned local_warp = threadIdx.y;
    const unsigned global_warp = blockDim.y * blockIdx.x + local_warp;
    const unsigned log_values_per_warp = LOG_VALS_PER_THREAD + LOG_WARP;
    const unsigned global_warp_start = global_warp << log_values_per_warp;
    const unsigned local_warp_start = local_warp << log_values_per_warp;

    for (unsigned column = 0; column < 16; ++column) {
        const m31 *input_start = input[column];
        unsigned warp_start = global_warp_start + lane;
        m31 vals[1 << LOG_VALS_PER_THREAD];
        #pragma unroll
        for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); ++i) {
            vals[i] = input_start[warp_start + (i << LOG_WARP)];
        }

        unsigned layer_domain_size = 1;
        unsigned layer_domain_offset = ((1 << log_n) >> 1) - 2;
        for (unsigned i = 1; i < min_stage; ++i) {
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }
        unsigned stage = min_stage;
        #pragma unroll
        for (; stage < min_stage + LOG_VALS_PER_THREAD; ++stage) {
            const unsigned log_inner_stride =
                LOG_VALS_PER_THREAD - 1 - (stage - min_stage);
            #pragma unroll
            for (unsigned gid = 0; gid < (1 << (LOG_VALS_PER_THREAD - 1)); ++gid) {
                const unsigned inner_group = gid & ((1 << log_inner_stride) - 1);
                const unsigned inner_pair = gid >> log_inner_stride;
                const unsigned left_index =
                    inner_group + (inner_pair << (log_inner_stride + 1));
                const unsigned right_index = left_index + (1 << log_inner_stride);
                const unsigned outer_pair = warp_start >> (1 + log_n - stage);
                const m31 product = mul(
                    g_twiddles[layer_domain_offset + inner_pair + outer_pair],
                    vals[right_index]);
                const m31 left = vals[left_index];
                vals[left_index] = add(left, product);
                vals[right_index] = sub(left, product);
            }
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }
        #pragma unroll
        for (; stage <= log_n; ++stage) {
            const unsigned log_stride = log_n - stage;
            shfl_xor_bf<LOG_VALS_PER_THREAD>(vals, log_stride, lane);
            #pragma unroll
            for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
                const unsigned inner_pair =
                    (lane >> log_stride) + (i << (LOG_WARP - log_stride));
                const unsigned outer_pair = global_warp
                    << (log_values_per_warp - 1 - log_stride);
                const m31 product = stage == log_n
                    ? mul(get_circle_twiddle(g_twiddles, inner_pair + outer_pair),
                          vals[2 * i + 1])
                    : mul(g_twiddles[layer_domain_offset + inner_pair + outer_pair],
                          vals[2 * i + 1]);
                const m31 left = vals[2 * i];
                vals[2 * i] = add(left, product);
                vals[2 * i + 1] = sub(left, product);
            }
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }

        #pragma unroll
        for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
            const unsigned row = local_warp_start + 2 * lane + (i << 6);
            messages[(row + 0) * 16 + column] = vals[2 * i];
            messages[(row + 1) * 16 + column] = vals[2 * i + 1];
        }
    }
    __syncthreads();

    const uint32_t total_bytes = 4u * (cols_done + 16u);
    const uint32_t lastblock = is_final != 0 ? 0xffffffffu : 0u;
    #pragma unroll
    for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
        #pragma unroll
        for (unsigned side = 0; side < 2; ++side) {
            const unsigned local_row = local_warp_start + 2 * lane + (i << 6) + side;
            const unsigned global_row = global_warp_start + 2 * lane + (i << 6) + side;
            uint32_t message[16];
            #pragma unroll
            for (unsigned k = 0; k < 16; ++k) {
                message[k] = messages[local_row * 16 + k];
            }
            stwo_blake2s_compress_leaf_block_device(
                &states[global_row], message, total_bytes, lastblock);
        }
    }
}

template <bool APPLY_CIRCLE = true>
static cudaError_t ntt_n2b_final_7_stage_batch_on(
    m31** input, m31** output, unsigned log_n, unsigned num_poly,
    unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size,
    unsigned eval_domain_size, cudaStream_t stream
) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_val_per_thread = 2;
    if (log_n + 1 - (log_val_per_thread + LOG_WARP) != start_stage) {
        return cudaErrorInvalidValue;
    }
    dim3 block_dim = dim3{32, 1, 1};
    dim3 grid_dim = dim3{1, 1, 1};
    const unsigned num_warp = 1 << (log_n - LOG_WARP - log_val_per_thread);
    block_dim.y = min(num_warp, 4);
    grid_dim.y = num_poly;
    grid_dim.x = num_warp / block_dim.y;

    n2b_final_warp_batch<log_val_per_thread, APPLY_CIRCLE><<<grid_dim, block_dim, 0, stream>>>(
        input, output, log_n, num_poly, start_stage, g_twiddles);
    return cudaGetLastError();
}

EXTERN void ntt_n2b_final_7_stage_batch(m31** input, m31** output,
                              unsigned log_n, unsigned num_poly,
                              unsigned start_stage,
                              m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    ASSERT_CUDA_SUCCESS(ntt_n2b_final_7_stage_batch_on<true>(
        input, output, log_n, num_poly, start_stage, g_twiddles, twiddles_size,
        eval_domain_size, 0));
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

template <bool APPLY_CIRCLE = true>
static cudaError_t ntt_n2b_final_8_stage_batch_on(
    m31** input, m31** output, unsigned log_n, unsigned num_poly,
    unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size,
    unsigned eval_domain_size, cudaStream_t stream
) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_val_per_thread = 3;
    if (log_n + 1 - (log_val_per_thread + LOG_WARP) != start_stage) {
        return cudaErrorInvalidValue;
    }
    dim3 block_dim = dim3{32, 1, 1};
    dim3 grid_dim = dim3{1, 1, 1};
    const unsigned num_warp = 1 << (log_n - LOG_WARP - log_val_per_thread);
    block_dim.y = min(num_warp, 4);
    grid_dim.y = num_poly;
    grid_dim.x = num_warp / block_dim.y;

    n2b_final_warp_batch<log_val_per_thread, APPLY_CIRCLE><<<grid_dim, block_dim, 0, stream>>>(
        input, output, log_n, num_poly, start_stage, g_twiddles);
    return cudaGetLastError();
}

EXTERN void ntt_n2b_final_8_stage_batch(m31** input, m31** output,
                              unsigned log_n, unsigned num_poly,
                              unsigned start_stage,
                              m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    ASSERT_CUDA_SUCCESS(ntt_n2b_final_8_stage_batch_on<true>(
        input, output, log_n, num_poly, start_stage, g_twiddles, twiddles_size,
        eval_domain_size, 0));
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}


template <unsigned LOG_WARP_PER_BLOCK, bool APPLY_CIRCLE = true>
__global__ void n2b_final_block_warp_batch(
    m31** input, m31** output, const unsigned log_n,
    const unsigned num_poly, unsigned min_stage, m31 *g_twiddles) {

    constexpr unsigned LOG_VALS_PER_THREAD = 3;
    const unsigned ntt_idx = blockIdx.z;
    const unsigned warp_idx_in_block = threadIdx.y;
    const unsigned thread_idx_in_warp = threadIdx.x;

    const m31* input_ntt_start = input[ntt_idx];
    const unsigned block_index_y = blockIdx.x;
    const unsigned block_start = (block_index_y << (LOG_WARP + LOG_VALS_PER_THREAD + LOG_WARP_PER_BLOCK));

    __shared__ m31 smem[32 << (LOG_WARP_PER_BLOCK + LOG_VALS_PER_THREAD)];
    m31 vals[1 << LOG_VALS_PER_THREAD];

    unsigned offset = (warp_idx_in_block << LOG_WARP) + thread_idx_in_warp;
    #pragma unroll
    for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); i++) {
        const unsigned address = block_start + (i << (LOG_WARP + LOG_WARP_PER_BLOCK)) + offset;
        vals[i] = input_ntt_start[address];
    }

    unsigned layer_domain_size = 1;
    unsigned layer_domain_offset = ((1 << log_n) >> 1) - 2;

    for (unsigned stage = 1; stage < min_stage; stage++) {
        layer_domain_size <<= 1;
        layer_domain_offset -= layer_domain_size;
    }
    unsigned stage = min_stage;
    #pragma unroll
    for (; stage < min_stage + LOG_WARP_PER_BLOCK; stage++) {
        const unsigned log_inner_stride_size = LOG_VALS_PER_THREAD - 1 - (stage - min_stage);
    #pragma unroll
        for (unsigned gid = 0; gid < 1 << (LOG_VALS_PER_THREAD - 1); gid++) {
            const unsigned inner_group_idx = gid & ((1 << log_inner_stride_size) - 1);
            const unsigned inner_pair_idx = gid >> log_inner_stride_size;
            const unsigned inner_left_idx =
                inner_group_idx + (inner_pair_idx << (log_inner_stride_size + 1));
            const unsigned inner_right_idx =
                inner_left_idx + (1 << log_inner_stride_size);
            const unsigned outer_pair_idx =
                (block_start + offset) >> (1 + log_n - stage);
            const m31 twiddle = mul(g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx], vals[inner_right_idx]);
            const m31 temp = vals[inner_left_idx];
            vals[inner_left_idx] = add(temp, twiddle);
            vals[inner_right_idx] = sub(temp, twiddle);
        }
        layer_domain_size <<= 1;
        layer_domain_offset -= layer_domain_size;
    }

    #pragma unroll
    for (unsigned i = 0; i < 1 << LOG_VALS_PER_THREAD; i++) {
        smem[thread_idx_in_warp + (i << (LOG_WARP + LOG_WARP_PER_BLOCK)) +
            (warp_idx_in_block << LOG_WARP)] = vals[i];
    }
    __syncthreads();
    #pragma unroll
    for (unsigned i = 0; i < 1 << LOG_VALS_PER_THREAD; i++) {
        vals[i] = smem[thread_idx_in_warp + (i << LOG_WARP) +
                    (warp_idx_in_block << (LOG_WARP + LOG_VALS_PER_THREAD))];
    }
    offset = (warp_idx_in_block << (LOG_WARP + LOG_VALS_PER_THREAD)) +
            thread_idx_in_warp;

    const unsigned warps_idx_in_ntt = blockDim.y * block_index_y + threadIdx.y;
    const unsigned log_vals_per_warp = LOG_VALS_PER_THREAD + LOG_WARP;
    unsigned warp_start =
        (warps_idx_in_ntt << log_vals_per_warp) + thread_idx_in_warp;
    const unsigned new_min_stage = min_stage + LOG_WARP_PER_BLOCK;
    stage = new_min_stage;
    #pragma unroll
    for (; stage < new_min_stage + LOG_VALS_PER_THREAD; stage++) {
        const unsigned log_inner_stride_size =
            LOG_VALS_PER_THREAD - 1 - (stage - new_min_stage);
    #pragma unroll
        for (unsigned gid = 0; gid < 1 << (LOG_VALS_PER_THREAD - 1); gid++) {
            const unsigned inner_group_idx = gid & ((1 << log_inner_stride_size) - 1);
            const unsigned inner_pair_idx = gid >> log_inner_stride_size;
            const unsigned inner_left_idx =
                inner_group_idx + (inner_pair_idx << (log_inner_stride_size + 1));
            const unsigned inner_right_idx =
                inner_left_idx + (1 << log_inner_stride_size);
            const unsigned outer_pair_idx = warp_start >> (1 + log_n - stage);
            const m31 twiddle = mul(g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx], vals[inner_right_idx]);
            const m31 temp = vals[inner_left_idx];
            vals[inner_left_idx] = add(temp, twiddle);
            vals[inner_right_idx] = sub(temp, twiddle);
        }
        layer_domain_size <<= 1;
        layer_domain_offset -= layer_domain_size;
    }
    #pragma unroll
    for (; stage <= log_n; stage++) {
        const unsigned log_stride = log_n - stage;
        shfl_xor_bf<LOG_VALS_PER_THREAD>(vals, log_stride, thread_idx_in_warp);
        if constexpr (!APPLY_CIRCLE) {
            if (stage == log_n) continue;
        }
    #pragma unroll
        for (unsigned i = 0; i < 1 << (LOG_VALS_PER_THREAD - 1); i++) {
            const unsigned inner_pair_idx =
                (thread_idx_in_warp >> log_stride) + (i << (LOG_WARP - log_stride));
            const unsigned outer_pair_idx = warps_idx_in_ntt
                                            << (log_vals_per_warp - 1 - log_stride);
            m31 twiddle = m31(1);
            if (stage == log_n) {
                twiddle = mul(get_circle_twiddle(g_twiddles, inner_pair_idx + outer_pair_idx), vals[2 * i + 1]);
            } else {
                twiddle = mul(g_twiddles[layer_domain_offset + inner_pair_idx + outer_pair_idx], vals[2 * i + 1]);
            }

            const m31 temp = vals[2 * i];
            vals[2 * i] = add(temp, twiddle);
            vals[2 * i + 1] = sub(temp, twiddle);
        }
        layer_domain_size <<= 1;
        layer_domain_offset -= layer_domain_size;
    }

    m31* output_ntt_start = output[ntt_idx];
    warp_start = (warps_idx_in_ntt << log_vals_per_warp) + thread_idx_in_warp * 2;
    uint64_t* src = reinterpret_cast<uint64_t*>(vals);
    uint64_t* dst = reinterpret_cast<uint64_t*>(output_ntt_start + warp_start);

    #pragma unroll
    for (unsigned i = 0; i < 1 << (LOG_VALS_PER_THREAD - 1); i++)
        dst[i << LOG_WARP] = src[i];
}

template <unsigned LOG_WARP_PER_BLOCK>
__global__ void n2b_final_block_warp_hash16_batch(
    m31 **input,
    const unsigned log_n,
    unsigned min_stage,
    m31 *g_twiddles,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states
) {
    constexpr unsigned LOG_VALS_PER_THREAD = 3;
    constexpr unsigned VALUES_PER_WARP = 1 << (LOG_WARP + LOG_VALS_PER_THREAD);
    constexpr unsigned VALUES_PER_BLOCK = 32 << (LOG_WARP_PER_BLOCK + LOG_VALS_PER_THREAD);
    extern __shared__ uint32_t shared_words[];
    m31 *smem = reinterpret_cast<m31 *>(shared_words);
    uint32_t *messages = shared_words + VALUES_PER_BLOCK;

    const unsigned local_warp = threadIdx.y;
    const unsigned lane = threadIdx.x;
    const unsigned block_start = blockIdx.x
        << (LOG_WARP + LOG_VALS_PER_THREAD + LOG_WARP_PER_BLOCK);
    const unsigned global_warp = blockDim.y * blockIdx.x + local_warp;
    const unsigned global_warp_start = global_warp << (LOG_WARP + LOG_VALS_PER_THREAD);
    const unsigned local_warp_start = local_warp * VALUES_PER_WARP;

    for (unsigned column = 0; column < 16; ++column) {
        const m31 *input_start = input[column];
        m31 vals[1 << LOG_VALS_PER_THREAD];
        unsigned offset = (local_warp << LOG_WARP) + lane;
        #pragma unroll
        for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); ++i) {
            vals[i] = input_start[
                block_start + (i << (LOG_WARP + LOG_WARP_PER_BLOCK)) + offset];
        }

        unsigned layer_domain_size = 1;
        unsigned layer_domain_offset = ((1 << log_n) >> 1) - 2;
        for (unsigned stage = 1; stage < min_stage; ++stage) {
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }
        unsigned stage = min_stage;
        #pragma unroll
        for (; stage < min_stage + LOG_WARP_PER_BLOCK; ++stage) {
            const unsigned log_inner_stride =
                LOG_VALS_PER_THREAD - 1 - (stage - min_stage);
            #pragma unroll
            for (unsigned gid = 0; gid < (1 << (LOG_VALS_PER_THREAD - 1)); ++gid) {
                const unsigned inner_group = gid & ((1 << log_inner_stride) - 1);
                const unsigned inner_pair = gid >> log_inner_stride;
                const unsigned left_index =
                    inner_group + (inner_pair << (log_inner_stride + 1));
                const unsigned right_index = left_index + (1 << log_inner_stride);
                const unsigned outer_pair = (block_start + offset) >> (1 + log_n - stage);
                const m31 product = mul(
                    g_twiddles[layer_domain_offset + inner_pair + outer_pair],
                    vals[right_index]);
                const m31 left = vals[left_index];
                vals[left_index] = add(left, product);
                vals[right_index] = sub(left, product);
            }
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }

        #pragma unroll
        for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); ++i) {
            smem[lane + (i << (LOG_WARP + LOG_WARP_PER_BLOCK))
                + (local_warp << LOG_WARP)] = vals[i];
        }
        __syncthreads();
        #pragma unroll
        for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); ++i) {
            vals[i] = smem[lane + (i << LOG_WARP)
                + (local_warp << (LOG_WARP + LOG_VALS_PER_THREAD))];
        }
        offset = (local_warp << (LOG_WARP + LOG_VALS_PER_THREAD)) + lane;

        const unsigned new_min_stage = min_stage + LOG_WARP_PER_BLOCK;
        stage = new_min_stage;
        #pragma unroll
        for (; stage < new_min_stage + LOG_VALS_PER_THREAD; ++stage) {
            const unsigned log_inner_stride =
                LOG_VALS_PER_THREAD - 1 - (stage - new_min_stage);
            #pragma unroll
            for (unsigned gid = 0; gid < (1 << (LOG_VALS_PER_THREAD - 1)); ++gid) {
                const unsigned inner_group = gid & ((1 << log_inner_stride) - 1);
                const unsigned inner_pair = gid >> log_inner_stride;
                const unsigned left_index =
                    inner_group + (inner_pair << (log_inner_stride + 1));
                const unsigned right_index = left_index + (1 << log_inner_stride);
                const unsigned outer_pair =
                    (global_warp_start + lane) >> (1 + log_n - stage);
                const m31 product = mul(
                    g_twiddles[layer_domain_offset + inner_pair + outer_pair],
                    vals[right_index]);
                const m31 left = vals[left_index];
                vals[left_index] = add(left, product);
                vals[right_index] = sub(left, product);
            }
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }
        #pragma unroll
        for (; stage <= log_n; ++stage) {
            const unsigned log_stride = log_n - stage;
            shfl_xor_bf<LOG_VALS_PER_THREAD>(vals, log_stride, lane);
            #pragma unroll
            for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
                const unsigned inner_pair =
                    (lane >> log_stride) + (i << (LOG_WARP - log_stride));
                const unsigned outer_pair = global_warp
                    << (LOG_WARP + LOG_VALS_PER_THREAD - 1 - log_stride);
                const m31 product = stage == log_n
                    ? mul(get_circle_twiddle(g_twiddles, inner_pair + outer_pair),
                          vals[2 * i + 1])
                    : mul(g_twiddles[layer_domain_offset + inner_pair + outer_pair],
                          vals[2 * i + 1]);
                const m31 left = vals[2 * i];
                vals[2 * i] = add(left, product);
                vals[2 * i + 1] = sub(left, product);
            }
            layer_domain_size <<= 1;
            layer_domain_offset -= layer_domain_size;
        }

        #pragma unroll
        for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
            const unsigned row = local_warp_start + 2 * lane + (i << 6);
            messages[(row + 0) * 16 + column] = vals[2 * i];
            messages[(row + 1) * 16 + column] = vals[2 * i + 1];
        }
        __syncthreads();
    }

    const uint32_t total_bytes = 4u * (cols_done + 16u);
    const uint32_t lastblock = is_final != 0 ? 0xffffffffu : 0u;
    #pragma unroll
    for (unsigned i = 0; i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
        #pragma unroll
        for (unsigned side = 0; side < 2; ++side) {
            const unsigned local_row = local_warp_start + 2 * lane + (i << 6) + side;
            const unsigned global_row = global_warp_start + 2 * lane + (i << 6) + side;
            uint32_t message[16];
            #pragma unroll
            for (unsigned k = 0; k < 16; ++k) {
                message[k] = messages[local_row * 16 + k];
            }
            stwo_blake2s_compress_leaf_block_device(
                &states[global_row], message, total_bytes, lastblock);
        }
    }
}

template <bool APPLY_CIRCLE = true>
static cudaError_t ntt_n2b_final_10_stage_batch_on(
    m31** input, m31** output, unsigned log_n, unsigned num_poly,
    unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size,
    unsigned eval_domain_size, cudaStream_t stream
) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_warp_per_block = 2;
    constexpr unsigned LOG_VALS_PER_THREAD = 3;
    if (log_n + 1 - start_stage !=
        LOG_VALS_PER_THREAD + LOG_WARP + log_warp_per_block) {
        return cudaErrorInvalidValue;
    }
    dim3 block_dim = {32, 1 << log_warp_per_block, 1};
    dim3 grid_dim = {};
    grid_dim.z = num_poly;
    grid_dim.x = 1 << (log_n - LOG_WARP - LOG_VALS_PER_THREAD - log_warp_per_block);

    n2b_final_block_warp_batch<log_warp_per_block, APPLY_CIRCLE><<<grid_dim, block_dim, 0, stream>>>(
        input, output, log_n, num_poly, start_stage, g_twiddles);
    return cudaGetLastError();
}

EXTERN void ntt_n2b_final_10_stage_batch(m31** input, m31** output,
                               unsigned log_n, unsigned num_poly, unsigned start_stage,
                               m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    ASSERT_CUDA_SUCCESS(ntt_n2b_final_10_stage_batch_on<true>(
        input, output, log_n, num_poly, start_stage, g_twiddles, twiddles_size,
        eval_domain_size, 0));
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

template <bool APPLY_CIRCLE = true>
static cudaError_t ntt_n2b_final_11_stage_batch_on(
    m31** input, m31** output, unsigned log_n, unsigned num_poly,
    unsigned start_stage, m31 *g_twiddles, unsigned twiddles_size,
    unsigned eval_domain_size, cudaStream_t stream
) {
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    constexpr unsigned log_warp_per_block = 3;
    constexpr unsigned LOG_VALS_PER_THREAD = 3;
    if (log_n + 1 - start_stage !=
        LOG_VALS_PER_THREAD + LOG_WARP + log_warp_per_block) {
        return cudaErrorInvalidValue;
    }
    dim3 block_dim = {32, 1 << log_warp_per_block, 1};
    dim3 grid_dim = {};
    grid_dim.z = num_poly;
    grid_dim.x = 1 << (log_n - LOG_WARP - LOG_VALS_PER_THREAD - log_warp_per_block);
    n2b_final_block_warp_batch<log_warp_per_block, APPLY_CIRCLE><<<grid_dim, block_dim, 0, stream>>>(
        input, output,  log_n, num_poly, start_stage, g_twiddles);
    return cudaGetLastError();
}

EXTERN void ntt_n2b_final_11_stage_batch(m31** input, m31** output,
                               unsigned log_n, unsigned num_poly, unsigned start_stage,
                               m31 *g_twiddles, unsigned twiddles_size, unsigned eval_domain_size) {
    ASSERT_CUDA_SUCCESS(ntt_n2b_final_11_stage_batch_on<true>(
        input, output, log_n, num_poly, start_stage, g_twiddles, twiddles_size,
        eval_domain_size, 0));
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

template <unsigned LOG_VALS_PER_THREAD>
static cudaError_t ntt_n2b_final_warp_hash16_on(
    m31 **values,
    unsigned log_n,
    unsigned start_stage,
    m31 *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states,
    cudaStream_t stream
) {
    if (log_n + 1 - (LOG_VALS_PER_THREAD + LOG_WARP) != start_stage) {
        return cudaErrorInvalidValue;
    }
    twiddles += twiddle_words - eval_domain_size;
    const unsigned num_warps = 1 << (log_n - LOG_WARP - LOG_VALS_PER_THREAD);
    dim3 block_dim{32, min(num_warps, 4u), 1};
    dim3 grid_dim{num_warps / block_dim.y, 1, 1};
    const size_t shared_bytes = size_t(block_dim.y)
        * (1u << (LOG_WARP + LOG_VALS_PER_THREAD)) * 16u * sizeof(uint32_t);
    n2b_final_warp_hash16_batch<LOG_VALS_PER_THREAD>
        <<<grid_dim, block_dim, shared_bytes, stream>>>(
            values, log_n, start_stage, twiddles, cols_done, is_final, states);
    return cudaGetLastError();
}

template <unsigned LOG_WARP_PER_BLOCK>
static cudaError_t ntt_n2b_final_block_hash16_on(
    m31 **values,
    unsigned log_n,
    unsigned start_stage,
    m31 *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states,
    cudaStream_t stream
) {
    constexpr unsigned LOG_VALS_PER_THREAD = 3;
    if (log_n + 1 - start_stage !=
        LOG_VALS_PER_THREAD + LOG_WARP + LOG_WARP_PER_BLOCK) {
        return cudaErrorInvalidValue;
    }
    twiddles += twiddle_words - eval_domain_size;
    dim3 block_dim{32, 1u << LOG_WARP_PER_BLOCK, 1};
    dim3 grid_dim{1u << (log_n - LOG_WARP - LOG_VALS_PER_THREAD
        - LOG_WARP_PER_BLOCK), 1, 1};
    constexpr size_t values_per_block =
        32u << (LOG_WARP_PER_BLOCK + LOG_VALS_PER_THREAD);
    constexpr size_t shared_bytes = values_per_block * 17u * sizeof(uint32_t);
    n2b_final_block_warp_hash16_batch<LOG_WARP_PER_BLOCK>
        <<<grid_dim, block_dim, shared_bytes, stream>>>(
            values, log_n, start_stage, twiddles, cols_done, is_final, states);
    return cudaGetLastError();
}

static cudaError_t configure_n2b_hash16_kernel(unsigned final_stages) {
    switch (final_stages) {
        case 7:
            return cudaFuncSetAttribute(
                n2b_final_warp_hash16_batch<2>,
                cudaFuncAttributeMaxDynamicSharedMemorySize, 32 * 1024);
        case 8:
            return cudaFuncSetAttribute(
                n2b_final_warp_hash16_batch<3>,
                cudaFuncAttributeMaxDynamicSharedMemorySize, 64 * 1024);
        case 10:
            return cudaFuncSetAttribute(
                n2b_final_block_warp_hash16_batch<2>,
                cudaFuncAttributeMaxDynamicSharedMemorySize, 68 * 1024);
        case 11:
            return cudaFuncSetAttribute(
                n2b_final_block_warp_hash16_batch<3>,
                cudaFuncAttributeMaxDynamicSharedMemorySize, 136 * 1024);
        default:
            return cudaErrorInvalidConfiguration;
    }
}

static cudaError_t ntt_n2b_final_hash16_on(
    unsigned final_stages,
    m31 **values,
    unsigned log_n,
    unsigned start_stage,
    m31 *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states,
    cudaStream_t stream
) {
    switch (final_stages) {
        case 7:
            return ntt_n2b_final_warp_hash16_on<2>(
                values, log_n, start_stage, twiddles, twiddle_words,
                eval_domain_size, cols_done, is_final, states, stream);
        case 8:
            return ntt_n2b_final_warp_hash16_on<3>(
                values, log_n, start_stage, twiddles, twiddle_words,
                eval_domain_size, cols_done, is_final, states, stream);
        case 10:
            return ntt_n2b_final_block_hash16_on<2>(
                values, log_n, start_stage, twiddles, twiddle_words,
                eval_domain_size, cols_done, is_final, states, stream);
        case 11:
            return ntt_n2b_final_block_hash16_on<3>(
                values, log_n, start_stage, twiddles, twiddle_words,
                eval_domain_size, cols_done, is_final, states, stream);
        default:
            return cudaErrorInvalidConfiguration;
    }
}


__global__ void ntt_n2b_stage_batch(m31** input, m31** output,
                              unsigned log_n, unsigned stage, m31 *layer_twiddles) {
    const unsigned ntt_index = blockIdx.y;
    const unsigned gid = blockIdx.x * blockDim.x + threadIdx.x;
    const unsigned stride = 1 << (log_n - stage);
    const unsigned group_idx = gid & (stride - 1);
    const unsigned pair_idx = gid >> (log_n - stage);

    const m31* input_start = input[ntt_index];
    const unsigned left_index = group_idx + pair_idx * 2 * stride;
    const unsigned right_index = left_index + stride;

    m31 left = input_start[left_index];
    m31 right = input_start[right_index];

    m31 twiddle = m31(1);
    if (stage == log_n) {
        twiddle = get_circle_twiddle(layer_twiddles, pair_idx);
    } else {
        twiddle = layer_twiddles[pair_idx];
    }


    m31 twiddle_x = mul(twiddle, right);
    const m31 temp = left;
    m31 left_r = add(temp, twiddle_x);
    m31 right_r = sub(temp, twiddle_x);

    m31* output_start = output[ntt_index];

    output_start[left_index] = left_r;
    output_start[right_index] = right_r;
}

static cudaError_t ntt_n2b_native_device_batch_on(
    m31** device_values, unsigned log_n, unsigned num_poly,
    unsigned start_stage, unsigned end_stage, m31 *g_twiddles,
    unsigned twiddles_size, unsigned eval_domain_size, cudaStream_t stream
) {
    if (start_stage < 1 || end_stage > log_n) {
        return cudaErrorInvalidValue;
    }
    g_twiddles = &g_twiddles[twiddles_size - eval_domain_size];
    dim3 block_dim{};
    block_dim.x = log_n <= 9 ? 1 << (log_n - 1) : 256;
    dim3 grid_dim{};
    grid_dim.y = num_poly;
    grid_dim.x = log_n <= 9 ? 1 : 1 << (log_n - 9);

    unsigned layer_domain_size = 1;
    unsigned layer_domain_offset = ((1 << log_n) >> 1) - 2;

    for (unsigned stage = 1; stage < log_n; stage++) {

        if (stage >= start_stage) {
            ntt_n2b_stage_batch<<<grid_dim, block_dim, 0, stream>>>(
                device_values, device_values, log_n, stage,
                &g_twiddles[layer_domain_offset]);
            cudaError_t err = cudaGetLastError();
            if (err != cudaSuccess) {
                return err;
            }
        }

        layer_domain_size <<= 1;
        layer_domain_offset -= layer_domain_size;
    }
    if (end_stage == log_n) {
        ntt_n2b_stage_batch<<<grid_dim, block_dim, 0, stream>>>(
            device_values, device_values, log_n, log_n, g_twiddles);
        return cudaGetLastError();
    }
    return cudaSuccess;
}

EXTERN void ntt_n2b_native_batch(m31** value,
                           unsigned log_n, unsigned num_poly,
                           unsigned start_stage, unsigned end_stage,
                           m31 *g_twiddles,
                           unsigned twiddles_size, unsigned eval_domain_size) {
    m31 **device_values = cuda_proving_clone_to_device<m31*>(value, num_poly);
    ASSERT_CUDA_SUCCESS(ntt_n2b_native_device_batch_on(
        device_values, log_n, num_poly, start_stage, end_stage, g_twiddles,
        twiddles_size, eval_domain_size, 0));
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
    cuda_proving_free(device_values);
}

static cudaError_t ntt_n2b_columns_dispatch_from_stage_on(
    m31** device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t* g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    unsigned first_stage,
    cudaStream_t stream,
    bool legacy_debug_sync,
    bool include_circle
) {
    if (first_stage < 1 || first_stage > 2 || first_stage > log_n) {
        return cudaErrorInvalidValue;
    }
    const unsigned skipped_stages = first_stage - 1;
    auto finish_stage = [legacy_debug_sync](cudaError_t err) -> cudaError_t {
        if (err != cudaSuccess) {
            return err;
        }
        if (legacy_debug_sync) {
            stwo_maybe_debug_sync();
            return cudaGetLastError();
        }
        return cudaSuccess;
    };
    auto nofinal = [&](unsigned n_stages, unsigned start_stage) -> cudaError_t {
        cudaError_t err;
        switch (n_stages) {
            case 5:
                err = ntt_n2b_nofinal_5_stage_batch_on(
                    device_values, device_values, log_n, num_poly, start_stage,
                    g_twiddles, twiddles_size, eval_domain_size, stream);
                break;
            case 6:
                err = ntt_n2b_nofinal_6_stage_batch_on(
                    device_values, device_values, log_n, num_poly, start_stage,
                    g_twiddles, twiddles_size, eval_domain_size, stream);
                break;
            case 7:
                err = ntt_n2b_nofinal_7_stage_batch_on(
                    device_values, device_values, log_n, num_poly, start_stage,
                    g_twiddles, twiddles_size, eval_domain_size, stream);
                break;
            case 8:
                err = ntt_n2b_nofinal_8_stage_batch_on(
                    device_values, device_values, log_n, num_poly, start_stage,
                    g_twiddles, twiddles_size, eval_domain_size, stream);
                break;
            default:
                return cudaErrorInvalidConfiguration;
        }
        return finish_stage(err);
    };
    auto final = [&](unsigned n_stages, unsigned start_stage) -> cudaError_t {
        cudaError_t err;
        switch (n_stages) {
            case 7:
                err = include_circle
                    ? ntt_n2b_final_7_stage_batch_on<true>(
                        device_values, device_values, log_n, num_poly, start_stage,
                        g_twiddles, twiddles_size, eval_domain_size, stream)
                    : ntt_n2b_final_7_stage_batch_on<false>(
                        device_values, device_values, log_n, num_poly, start_stage,
                        g_twiddles, twiddles_size, eval_domain_size, stream);
                break;
            case 8:
                err = include_circle
                    ? ntt_n2b_final_8_stage_batch_on<true>(
                        device_values, device_values, log_n, num_poly, start_stage,
                        g_twiddles, twiddles_size, eval_domain_size, stream)
                    : ntt_n2b_final_8_stage_batch_on<false>(
                        device_values, device_values, log_n, num_poly, start_stage,
                        g_twiddles, twiddles_size, eval_domain_size, stream);
                break;
            case 10:
                err = include_circle
                    ? ntt_n2b_final_10_stage_batch_on<true>(
                        device_values, device_values, log_n, num_poly, start_stage,
                        g_twiddles, twiddles_size, eval_domain_size, stream)
                    : ntt_n2b_final_10_stage_batch_on<false>(
                        device_values, device_values, log_n, num_poly, start_stage,
                        g_twiddles, twiddles_size, eval_domain_size, stream);
                break;
            case 11:
                err = include_circle
                    ? ntt_n2b_final_11_stage_batch_on<true>(
                        device_values, device_values, log_n, num_poly, start_stage,
                        g_twiddles, twiddles_size, eval_domain_size, stream)
                    : ntt_n2b_final_11_stage_batch_on<false>(
                        device_values, device_values, log_n, num_poly, start_stage,
                        g_twiddles, twiddles_size, eval_domain_size, stream);
                break;
            default:
                return cudaErrorInvalidConfiguration;
        }
        return finish_stage(err);
    };

    if (log_n < 13) {
        return finish_stage(ntt_n2b_native_device_batch_on(
            device_values, log_n, num_poly, first_stage,
            include_circle ? log_n : log_n - 1, g_twiddles,
            twiddles_size, eval_domain_size, stream));
    } else if (log_n >= 13 && log_n <= 19) {
        const auto& config = LAUNCH_N2B_CONFIG_13_19[log_n - 13];
        const uint32_t start_stage1 = 1 + config[0];
        cudaError_t err = nofinal(config[0] - skipped_stages, first_stage);
        if (err != cudaSuccess) return err;
        return final(config[1], start_stage1);
    } else if (log_n >= 20 && log_n <= 27) {
        const auto& config = LAUNCH_N2B_CONFIG_20_27[log_n - 20];
        const uint32_t start_stage1 = 1 + config[0];
        const uint32_t start_stage2 = start_stage1 + config[1];
        cudaError_t err = nofinal(config[0] - skipped_stages, first_stage);
        if (err == cudaSuccess) err = nofinal(config[1], start_stage1);
        if (err != cudaSuccess) return err;
        return final(config[2], start_stage2);
    } else if (log_n >= 28 && log_n <= 30) {
        const auto& config = LAUNCH_N2B_CONFIG_28_30[log_n - 28];
        const uint32_t start_stage1 = 1 + config[0];
        const uint32_t start_stage2 = start_stage1 + config[1];
        const uint32_t start_stage3 = start_stage2 + config[2];
        cudaError_t err = nofinal(config[0] - skipped_stages, first_stage);
        if (err == cudaSuccess) err = nofinal(config[1], start_stage1);
        if (err == cudaSuccess) err = nofinal(config[2], start_stage2);
        if (err != cudaSuccess) return err;
        return final(config[3], start_stage3);
    }
    return cudaErrorInvalidValue;
}

static cudaError_t ntt_n2b_columns_dispatch_on(
    m31** device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t* g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    cudaStream_t stream,
    bool legacy_debug_sync,
    bool include_circle
) {
    return ntt_n2b_columns_dispatch_from_stage_on(
        device_values, log_n, num_poly, g_twiddles, twiddles_size,
        eval_domain_size, 1, stream, legacy_debug_sync, include_circle);
}

static unsigned n2b_hash16_final_stages(unsigned log_n) {
    if (log_n >= 13 && log_n <= 19) {
        return LAUNCH_N2B_CONFIG_13_19[log_n - 13][1];
    }
    if (log_n >= 20 && log_n <= 27) {
        return LAUNCH_N2B_CONFIG_20_27[log_n - 20][2];
    }
    if (log_n >= 28 && log_n <= 30) {
        return LAUNCH_N2B_CONFIG_28_30[log_n - 28][3];
    }
    return 0;
}

static cudaError_t ntt_n2b_before_final_interval_from_stage_two_on(
    m31 **values,
    unsigned log_n,
    unsigned num_poly,
    m31 *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    cudaStream_t stream
) {
    auto nofinal = [&](unsigned stages, unsigned start_stage) -> cudaError_t {
        switch (stages) {
            case 5:
                return ntt_n2b_nofinal_5_stage_batch_on(
                    values, values, log_n, num_poly, start_stage, twiddles,
                    twiddle_words, eval_domain_size, stream);
            case 6:
                return ntt_n2b_nofinal_6_stage_batch_on(
                    values, values, log_n, num_poly, start_stage, twiddles,
                    twiddle_words, eval_domain_size, stream);
            case 7:
                return ntt_n2b_nofinal_7_stage_batch_on(
                    values, values, log_n, num_poly, start_stage, twiddles,
                    twiddle_words, eval_domain_size, stream);
            case 8:
                return ntt_n2b_nofinal_8_stage_batch_on(
                    values, values, log_n, num_poly, start_stage, twiddles,
                    twiddle_words, eval_domain_size, stream);
            default:
                return cudaErrorInvalidConfiguration;
        }
    };

    if (log_n <= 19) {
        const auto &config = LAUNCH_N2B_CONFIG_13_19[log_n - 13];
        return nofinal(config[0] - 1, 2);
    }
    if (log_n <= 27) {
        const auto &config = LAUNCH_N2B_CONFIG_20_27[log_n - 20];
        cudaError_t status = nofinal(config[0] - 1, 2);
        return status == cudaSuccess
            ? nofinal(config[1], 1 + config[0]) : status;
    }
    const auto &config = LAUNCH_N2B_CONFIG_28_30[log_n - 28];
    cudaError_t status = nofinal(config[0] - 1, 2);
    if (status == cudaSuccess) {
        status = nofinal(config[1], 1 + config[0]);
    }
    return status == cudaSuccess
        ? nofinal(config[2], 1 + config[0] + config[1]) : status;
}

static cudaError_t ntt_n2b_final_interval_before_circle_dispatch_on(
    m31 **values,
    unsigned log_n,
    unsigned num_poly,
    m31 *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    cudaStream_t stream
) {
    const unsigned stages = n2b_hash16_final_stages(log_n);
    const unsigned start_stage = log_n + 1 - stages;
    switch (stages) {
        case 7:
            return ntt_n2b_final_7_stage_batch_on<false>(
                values, values, log_n, num_poly, start_stage, twiddles,
                twiddle_words, eval_domain_size, stream);
        case 8:
            return ntt_n2b_final_8_stage_batch_on<false>(
                values, values, log_n, num_poly, start_stage, twiddles,
                twiddle_words, eval_domain_size, stream);
        case 10:
            return ntt_n2b_final_10_stage_batch_on<false>(
                values, values, log_n, num_poly, start_stage, twiddles,
                twiddle_words, eval_domain_size, stream);
        case 11:
            return ntt_n2b_final_11_stage_batch_on<false>(
                values, values, log_n, num_poly, start_stage, twiddles,
                twiddle_words, eval_domain_size, stream);
        default:
            return cudaErrorInvalidConfiguration;
    }
}

// Composition's fused inverse boundary already materialized the exact output
// after the first stage-two-successor interval. Only the two table-pinned
// production continuations are valid here.
static cudaError_t ntt_n2b_after_first_stage_two_interval_dispatch_on(
    m31 **values,
    unsigned log_n,
    unsigned num_poly,
    m31 *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    cudaStream_t stream
) {
    unsigned middle_start = 0;
    unsigned final_start = 0;
    unsigned final_stages = 0;
    if (log_n == 24) {
        const auto &config = LAUNCH_N2B_CONFIG_20_27[6];
        if (config[0] != 8 || config[1] != 8 || config[2] != 10)
            return cudaErrorInvalidConfiguration;
        // Composition's fused LOG3 boundary already owns stages 2..6.
        middle_start = 7;
        final_start = 15;
        final_stages = 10;
    } else if (log_n == 25) {
        const auto &config = LAUNCH_N2B_CONFIG_20_27[5];
        if (config[0] != 6 || config[1] != 8 || config[2] != 11)
            return cudaErrorInvalidConfiguration;
        middle_start = 7;
        final_start = 15;
        final_stages = 11;
    } else {
        return cudaErrorInvalidValue;
    }
    cudaError_t status = ntt_n2b_nofinal_8_stage_batch_on(
        values, values, log_n, num_poly, middle_start, twiddles,
        twiddle_words, eval_domain_size, stream);
    if (status != cudaSuccess) return status;
    return final_stages == 10
        ? ntt_n2b_final_10_stage_batch_on<true>(
              values, values, log_n, num_poly, final_start, twiddles,
              twiddle_words, eval_domain_size, stream)
        : ntt_n2b_final_11_stage_batch_on<true>(
              values, values, log_n, num_poly, final_start, twiddles,
              twiddle_words, eval_domain_size, stream);
}

static cudaError_t ntt_n2b_hash16_dispatch_on(
    m31 **values,
    unsigned log_n,
    m31 *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states,
    cudaStream_t stream
) {
    auto nofinal = [&](unsigned stages, unsigned start_stage) -> cudaError_t {
        switch (stages) {
            case 6:
                return ntt_n2b_nofinal_6_stage_batch_on(
                    values, values, log_n, 16, start_stage, twiddles,
                    twiddle_words, eval_domain_size, stream);
            case 8:
                return ntt_n2b_nofinal_8_stage_batch_on(
                    values, values, log_n, 16, start_stage, twiddles,
                    twiddle_words, eval_domain_size, stream);
            default:
                return cudaErrorInvalidConfiguration;
        }
    };

    if (log_n >= 13 && log_n <= 19) {
        const auto &config = LAUNCH_N2B_CONFIG_13_19[log_n - 13];
        const unsigned final_start = 1 + config[0];
        cudaError_t err = nofinal(config[0], 1);
        return err == cudaSuccess
            ? ntt_n2b_final_hash16_on(
                config[1], values, log_n, final_start, twiddles,
                twiddle_words, eval_domain_size, cols_done, is_final, states, stream)
            : err;
    }
    if (log_n >= 20 && log_n <= 27) {
        const auto &config = LAUNCH_N2B_CONFIG_20_27[log_n - 20];
        const unsigned second_start = 1 + config[0];
        const unsigned final_start = second_start + config[1];
        cudaError_t err = nofinal(config[0], 1);
        if (err == cudaSuccess) err = nofinal(config[1], second_start);
        return err == cudaSuccess
            ? ntt_n2b_final_hash16_on(
                config[2], values, log_n, final_start, twiddles,
                twiddle_words, eval_domain_size, cols_done, is_final, states, stream)
            : err;
    }
    if (log_n >= 28 && log_n <= 30) {
        const auto &config = LAUNCH_N2B_CONFIG_28_30[log_n - 28];
        const unsigned second_start = 1 + config[0];
        const unsigned third_start = second_start + config[1];
        const unsigned final_start = third_start + config[2];
        cudaError_t err = nofinal(config[0], 1);
        if (err == cudaSuccess) err = nofinal(config[1], second_start);
        if (err == cudaSuccess) err = nofinal(config[2], third_start);
        return err == cudaSuccess
            ? ntt_n2b_final_hash16_on(
                config[3], values, log_n, final_start, twiddles,
                twiddle_words, eval_domain_size, cols_done, is_final, states, stream)
            : err;
    }
    return cudaErrorInvalidValue;
}

static void ntt_n2b_columns_dispatch(
    m31** device_values, unsigned log_n, unsigned num_poly,
    uint32_t* g_twiddles, unsigned twiddles_size, unsigned eval_domain_size
) {
    ASSERT_CUDA_SUCCESS(ntt_n2b_columns_dispatch_on(
        device_values, log_n, num_poly, g_twiddles, twiddles_size,
        eval_domain_size, 0, true, true));
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
EXTERN void ntt_n2b_columns(
    uint32_t** values_columns,
    unsigned log_n,
    unsigned num_poly,
    uint32_t* g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size
) {
    for (unsigned base = 0; base < num_poly; base += MAX_NTT_BATCH_COLUMNS) {
        const unsigned chunk = min(num_poly - base, MAX_NTT_BATCH_COLUMNS);
        m31 **device_values =
            cuda_proving_clone_to_device<m31*>(values_columns + base, chunk);
        // Surface any sticky error from an earlier async launch at this call site
        // instead of letting it masquerade as a failure of the launches below.
        ASSERT_CUDA_SUCCESS(cudaGetLastError());
        ntt_n2b_columns_dispatch(device_values, log_n, chunk, g_twiddles,
                                 twiddles_size, eval_domain_size);
        cuda_proving_free(device_values);
    }
}

// Allocation-free, explicit-stream N2B transform for graph capture. `device_values`
// is already a DEVICE-resident array of device-column pointers owned by the caller.
// No upload, allocation, free, default-stream launch, or host synchronization occurs.
extern "C" int stwo_ntt_n2b_columns_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
) {
    if (device_values == nullptr || g_twiddles == nullptr || stream == nullptr ||
        log_n == 0 || log_n > 30 || num_poly == 0 || eval_domain_size == 0 ||
        eval_domain_size > twiddles_size) {
        return cudaErrorInvalidValue;
    }

    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    for (unsigned base = 0; base < num_poly; base += MAX_NTT_BATCH_COLUMNS) {
        const unsigned chunk = min(num_poly - base, MAX_NTT_BATCH_COLUMNS);
        cudaError_t err = ntt_n2b_columns_dispatch_on(
            reinterpret_cast<m31 **>(device_values + base), log_n, chunk,
            g_twiddles, twiddles_size, eval_domain_size, cuda_stream, false, true);
        if (err != cudaSuccess) {
            return err;
        }
    }
    return cudaSuccess;
}

// Exact successor for the direct retained-B2N path. Stage one has already
// transformed every zero-extended pair (c, 0) into (c, c), so this entry runs
// only stages 2..log_n. Large logs keep the qualified N2B schedule boundaries:
// only its first 6/8-stage interval becomes the rectangular 5/7-stage twin.
extern "C" int stwo_ntt_n2b_columns_from_stage_two_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
) {
    if (device_values == nullptr || g_twiddles == nullptr || stream == nullptr ||
        log_n < 3 || log_n > 30 || num_poly == 0 ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddles_size) {
        return cudaErrorInvalidValue;
    }

    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    for (unsigned base = 0; base < num_poly; base += MAX_NTT_BATCH_COLUMNS) {
        const unsigned chunk = min(num_poly - base, MAX_NTT_BATCH_COLUMNS);
        cudaError_t err = ntt_n2b_columns_dispatch_from_stage_on(
            reinterpret_cast<m31 **>(device_values + base), log_n, chunk,
            g_twiddles, twiddles_size, eval_domain_size, 2, cuda_stream,
            false, true);
        if (err != cudaSuccess) {
            return err;
        }
    }
    return cudaSuccess;
}

extern "C" int stwo_ntt_n2b_columns_from_stage_two_before_circle_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
) {
    if (device_values == nullptr || g_twiddles == nullptr || stream == nullptr ||
        log_n < 3 || log_n > 30 || num_poly == 0 ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddles_size) {
        return cudaErrorInvalidValue;
    }

    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    for (unsigned base = 0; base < num_poly; base += MAX_NTT_BATCH_COLUMNS) {
        const unsigned chunk = min(num_poly - base, MAX_NTT_BATCH_COLUMNS);
        cudaError_t err = ntt_n2b_columns_dispatch_from_stage_on(
            reinterpret_cast<m31 **>(device_values + base), log_n, chunk,
            g_twiddles, twiddles_size, eval_domain_size, 2, cuda_stream,
            false, false);
        if (err != cudaSuccess) {
            return err;
        }
    }
    return cudaSuccess;
}

extern "C" int stwo_ntt_n2b_columns_from_stage_two_before_final_interval_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
) {
    if (device_values == nullptr || g_twiddles == nullptr || stream == nullptr ||
        log_n < 13 || log_n > 30 || num_poly == 0 ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddles_size) {
        return cudaErrorInvalidValue;
    }
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    for (unsigned base = 0; base < num_poly; base += MAX_NTT_BATCH_COLUMNS) {
        const unsigned chunk = min(num_poly - base, MAX_NTT_BATCH_COLUMNS);
        cudaError_t err = ntt_n2b_before_final_interval_from_stage_two_on(
            reinterpret_cast<m31 **>(device_values + base), log_n, chunk,
            reinterpret_cast<m31 *>(g_twiddles), twiddles_size,
            eval_domain_size, cuda_stream);
        if (err != cudaSuccess) return err;
    }
    return cudaSuccess;
}

extern "C" int stwo_ntt_n2b_columns_final_interval_before_circle_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
) {
    if (device_values == nullptr || g_twiddles == nullptr || stream == nullptr ||
        log_n < 13 || log_n > 30 || num_poly == 0 ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddles_size) {
        return cudaErrorInvalidValue;
    }
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    for (unsigned base = 0; base < num_poly; base += MAX_NTT_BATCH_COLUMNS) {
        const unsigned chunk = min(num_poly - base, MAX_NTT_BATCH_COLUMNS);
        cudaError_t err = ntt_n2b_final_interval_before_circle_dispatch_on(
            reinterpret_cast<m31 **>(device_values + base), log_n, chunk,
            reinterpret_cast<m31 *>(g_twiddles), twiddles_size,
            eval_domain_size, cuda_stream);
        if (err != cudaSuccess) return err;
    }
    return cudaSuccess;
}

extern "C" int stwo_ntt_n2b_columns_after_first_stage_two_interval_on(
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
) {
    if (device_values == nullptr || g_twiddles == nullptr || stream == nullptr ||
        (log_n != 24 && log_n != 25) || num_poly != 8 ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddles_size) {
        return cudaErrorInvalidValue;
    }
    return ntt_n2b_after_first_stage_two_interval_dispatch_on(
        reinterpret_cast<m31 **>(device_values), log_n, num_poly,
        reinterpret_cast<m31 *>(g_twiddles), twiddles_size,
        eval_domain_size, reinterpret_cast<cudaStream_t>(stream));
}

__global__ void stage_lde_columns(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned eval_domain_size
) {
    const unsigned column = blockIdx.y;
    const unsigned index = blockIdx.x * blockDim.x + threadIdx.x;
    // The safe Rust preparation layer validates this bound before uploading the
    // descriptor. Clamp defensively here so a raw FFI caller still cannot make
    // the staging kernel read beyond the NTT half-domain.
    const unsigned coefficient_count = min(coefficient_sizes[column], eval_domain_size);
    if (index < coefficient_count) {
        device_values[column][index] = coefficient_values[column][index];
    } else if (index < 2 * eval_domain_size) {
        device_values[column][index] = 0;
    }
}

// Allocation-free, explicit-stream LDE for graph capture. Both pointer tables
// and every pointed-to buffer are caller-owned device memory. Staging and N2B
// run on the supplied stream, with no host upload, allocation, free, or sync.
static int lde_n2b_columns_on(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream,
    bool include_circle
) {
    if (coefficient_values == nullptr || coefficient_sizes == nullptr ||
        device_values == nullptr ||
        g_twiddles == nullptr || stream == nullptr || log_n == 0 ||
        log_n > 30 || num_poly == 0 ||
        eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddles_size) {
        return cudaErrorInvalidValue;
    }

    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    constexpr unsigned block_size = 256;
    const unsigned output_size = 2 * eval_domain_size;
    const unsigned grid_x = (output_size + block_size - 1) / block_size;
    for (unsigned base = 0; base < num_poly; base += MAX_NTT_BATCH_COLUMNS) {
        const unsigned chunk = min(num_poly - base, MAX_NTT_BATCH_COLUMNS);
        stage_lde_columns<<<dim3(grid_x, chunk), block_size, 0, cuda_stream>>>(
            coefficient_values + base, coefficient_sizes + base,
            device_values + base, eval_domain_size);
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            return err;
        }
        err = ntt_n2b_columns_dispatch_on(
            reinterpret_cast<m31 **>(device_values + base), log_n, chunk,
            g_twiddles, twiddles_size, eval_domain_size, cuda_stream, false,
            include_circle);
        if (err != cudaSuccess) {
            return err;
        }
    }
    return cudaSuccess;
}

extern "C" int stwo_lde_n2b_columns_on(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
) {
    return lde_n2b_columns_on(
        coefficient_values, coefficient_sizes, device_values, log_n, num_poly,
        g_twiddles, twiddles_size, eval_domain_size, stream, true);
}

extern "C" int stwo_lde_n2b_columns_before_circle_on(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    unsigned num_poly,
    uint32_t *g_twiddles,
    unsigned twiddles_size,
    unsigned eval_domain_size,
    void *stream
) {
    return lde_n2b_columns_on(
        coefficient_values, coefficient_sizes, device_values, log_n, num_poly,
        g_twiddles, twiddles_size, eval_domain_size, stream, false);
}

extern "C" int stwo_lde_n2b_hash16_configure(unsigned log_n) {
    const unsigned final_stages = n2b_hash16_final_stages(log_n);
    return final_stages == 0
        ? cudaErrorInvalidValue
        : configure_n2b_hash16_kernel(final_stages);
}

extern "C" int stwo_lde_n2b_hash16_on(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    uint32_t cols_done,
    uint32_t is_final,
    Blake2sHash *states,
    void *stream
) {
    if (coefficient_values == nullptr || coefficient_sizes == nullptr ||
        device_values == nullptr || log_n < 13 || log_n > 30 ||
        twiddles == nullptr || eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddle_words || (cols_done % 16) != 0 ||
        is_final > 1 || states == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }

    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    constexpr unsigned block_size = 256;
    const unsigned output_size = 2 * eval_domain_size;
    const unsigned grid_x = (output_size + block_size - 1) / block_size;
    stage_lde_columns<<<dim3(grid_x, 16), block_size, 0, cuda_stream>>>(
        coefficient_values, coefficient_sizes, device_values, eval_domain_size);
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) return err;
    return ntt_n2b_hash16_dispatch_on(
        reinterpret_cast<m31 **>(device_values), log_n, twiddles,
        twiddle_words, eval_domain_size, cols_done, is_final, states,
        cuda_stream);
}

// --- ntt_leaf_fused support (Step 3.1) --------------------------------------
// Additive export: staging + the NOFINAL prefix of the hash16 lane, so
// cuda/ntt_leaf_fused.cu can attach its write+hash final-stage kernel. This
// runs exactly the launches ntt_n2b_hash16_dispatch_on performs before its
// final kernel (same static launchers, same LAUNCH_N2B_CONFIG rows, same
// order), so the prefinal buffer state is byte-identical to both existing
// lanes' intermediate state. No existing entry point changes behavior.
extern "C" int stwo_lde_n2b_prefinal16_on(
    const uint32_t *const *coefficient_values,
    const uint32_t *coefficient_sizes,
    uint32_t **device_values,
    unsigned log_n,
    uint32_t *twiddles,
    unsigned twiddle_words,
    unsigned eval_domain_size,
    void *stream
) {
    if (coefficient_values == nullptr || coefficient_sizes == nullptr ||
        device_values == nullptr || log_n < 13 || log_n > 30 ||
        twiddles == nullptr || eval_domain_size != (1u << (log_n - 1)) ||
        eval_domain_size > twiddle_words || stream == nullptr) {
        return cudaErrorInvalidValue;
    }

    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    constexpr unsigned block_size = 256;
    const unsigned output_size = 2 * eval_domain_size;
    const unsigned grid_x = (output_size + block_size - 1) / block_size;
    stage_lde_columns<<<dim3(grid_x, 16), block_size, 0, cuda_stream>>>(
        coefficient_values, coefficient_sizes, device_values, eval_domain_size);
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) return err;

    m31 **values = reinterpret_cast<m31 **>(device_values);
    auto nofinal = [&](unsigned stages, unsigned start_stage) -> cudaError_t {
        switch (stages) {
            case 6:
                return ntt_n2b_nofinal_6_stage_batch_on(
                    values, values, log_n, 16, start_stage, twiddles,
                    twiddle_words, eval_domain_size, cuda_stream);
            case 8:
                return ntt_n2b_nofinal_8_stage_batch_on(
                    values, values, log_n, 16, start_stage, twiddles,
                    twiddle_words, eval_domain_size, cuda_stream);
            default:
                return cudaErrorInvalidConfiguration;
        }
    };

    if (log_n <= 19) {
        const auto &config = LAUNCH_N2B_CONFIG_13_19[log_n - 13];
        return nofinal(config[0], 1);
    }
    if (log_n <= 27) {
        const auto &config = LAUNCH_N2B_CONFIG_20_27[log_n - 20];
        cudaError_t status = nofinal(config[0], 1);
        return status == cudaSuccess ? nofinal(config[1], 1 + config[0]) : status;
    }
    const auto &config = LAUNCH_N2B_CONFIG_28_30[log_n - 28];
    cudaError_t status = nofinal(config[0], 1);
    if (status == cudaSuccess) {
        status = nofinal(config[1], 1 + config[0]);
    }
    return status == cudaSuccess
        ? nofinal(config[2], 1 + config[0] + config[1])
        : status;
}
