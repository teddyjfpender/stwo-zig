#ifndef STWO_NTT_LEAF_FUSED_COL8_CUH
#define STWO_NTT_LEAF_FUSED_COL8_CUH

// DirectCompact terminal successor for final seven/eight-stage N2B intervals.
// Eight producer warps own one common row tile and cover the canonical sixteen
// columns in two waves. This preserves the scalar NTT/twiddle/store mapping
// while exposing the independent column axis and keeping the complete Blake2s
// message resident in a small, bank-padded CTA slab.
template <unsigned LOG_VALS_PER_THREAD>
__global__ __launch_bounds__(256, 4)
void n2b_final_warp_col8_compact16_write_batch(
    m31 **values,
    const unsigned log_n,
    unsigned min_stage,
    m31 *g_twiddles,
    uint32_t cols_done,
    Blake2sHash *states,
    uint32_t tiles,
    CompactBlake2sTailDescriptor initial_tail
) {
    static_assert(
        LOG_VALS_PER_THREAD == 2 || LOG_VALS_PER_THREAD == 3,
        "col8 supports only final seven/eight-stage warp intervals");
    constexpr unsigned WARPS = 8;
    constexpr unsigned MESSAGE_STRIDE = 17;
    constexpr unsigned ROWS = 1u << (LOG_WARP + LOG_VALS_PER_THREAD);
    constexpr unsigned QUADS = 32u * WARPS / 4u;

    extern __shared__ uint32_t shared_words[];
    uint32_t *messages = shared_words;
    uint32_t *compact_scratch = messages + ROWS * MESSAGE_STRIDE;

    const unsigned lane = threadIdx.x;
    const unsigned producer_warp = threadIdx.y;
    const unsigned logical_warp = blockIdx.x;
    const unsigned global_start =
        logical_warp << (LOG_WARP + LOG_VALS_PER_THREAD);

    for (uint32_t tile = 0; tile < tiles; ++tile) {
        #pragma unroll
        for (unsigned wave = 0; wave < 2; ++wave) {
            const unsigned column = wave * WARPS + producer_warp;
            m31 *column_values = values[16 * tile + column];
            const unsigned warp_start = global_start + lane;
            m31 vals[1 << LOG_VALS_PER_THREAD];
            #pragma unroll
            for (unsigned i = 0; i < (1 << LOG_VALS_PER_THREAD); ++i) {
                vals[i] = column_values[warp_start + (i << LOG_WARP)];
            }

            unsigned layer_domain_size = 1;
            unsigned layer_domain_offset = ((1 << log_n) >> 1) - 2;
            for (unsigned stage = 1; stage < min_stage; ++stage) {
                layer_domain_size <<= 1;
                layer_domain_offset -= layer_domain_size;
            }
            unsigned stage = min_stage;
            #pragma unroll
            for (; stage < min_stage + LOG_VALS_PER_THREAD; ++stage) {
                const unsigned log_inner_stride =
                    LOG_VALS_PER_THREAD - 1 - (stage - min_stage);
                #pragma unroll
                for (unsigned gid = 0;
                     gid < (1 << (LOG_VALS_PER_THREAD - 1)); ++gid) {
                    const unsigned inner_group =
                        gid & ((1 << log_inner_stride) - 1);
                    const unsigned inner_pair = gid >> log_inner_stride;
                    const unsigned left_index =
                        inner_group + (inner_pair << (log_inner_stride + 1));
                    const unsigned right_index =
                        left_index + (1 << log_inner_stride);
                    const unsigned outer_pair =
                        warp_start >> (1 + log_n - stage);
                    const m31 product = fused_mul<FusedLeafSink::DirectCompact>(
                        g_twiddles[
                            layer_domain_offset + inner_pair + outer_pair],
                        vals[right_index]);
                    const m31 left = vals[left_index];
                    vals[left_index] =
                        fused_add<FusedLeafSink::DirectCompact>(left, product);
                    vals[right_index] =
                        fused_sub<FusedLeafSink::DirectCompact>(left, product);
                }
                layer_domain_size <<= 1;
                layer_domain_offset -= layer_domain_size;
            }
            #pragma unroll
            for (; stage <= log_n; ++stage) {
                const unsigned log_stride = log_n - stage;
                shfl_xor_bf_fused<LOG_VALS_PER_THREAD>(
                    vals, log_stride, lane);
                #pragma unroll
                for (unsigned i = 0;
                     i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
                    const unsigned inner_pair =
                        (lane >> log_stride) +
                        (i << (LOG_WARP - log_stride));
                    const unsigned outer_pair =
                        logical_warp
                        << (LOG_WARP + LOG_VALS_PER_THREAD - 1 -
                            log_stride);
                    const m31 product =
                        stage == log_n
                            ? fused_mul<FusedLeafSink::DirectCompact>(
                                  get_circle_twiddle(
                                      g_twiddles,
                                      inner_pair + outer_pair),
                                  vals[2 * i + 1])
                            : fused_mul<FusedLeafSink::DirectCompact>(
                                  g_twiddles[
                                      layer_domain_offset + inner_pair +
                                      outer_pair],
                                  vals[2 * i + 1]);
                    const m31 left = vals[2 * i];
                    vals[2 * i] =
                        fused_add<FusedLeafSink::DirectCompact>(left, product);
                    vals[2 * i + 1] =
                        fused_sub<FusedLeafSink::DirectCompact>(left, product);
                }
                layer_domain_size <<= 1;
                layer_domain_offset -= layer_domain_size;
            }

            uint64_t *src = reinterpret_cast<uint64_t *>(vals);
            uint64_t *dst = reinterpret_cast<uint64_t *>(
                column_values + global_start + 2 * lane);
            #pragma unroll
            for (unsigned i = 0;
                 i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
                dst[i << LOG_WARP] = src[i];
            }

            #pragma unroll
            for (unsigned i = 0;
                 i < (1 << (LOG_VALS_PER_THREAD - 1)); ++i) {
                const unsigned row = 2 * lane + (i << 6);
                messages[(row + 0) * MESSAGE_STRIDE + column] = vals[2 * i];
                messages[(row + 1) * MESSAGE_STRIDE + column] =
                    vals[2 * i + 1];
            }
        }
        __syncthreads();

        const unsigned linear_thread = producer_warp * 32 + lane;
        const unsigned quad = linear_thread / 4;
        for (unsigned local_row = quad; local_row < ROWS;
             local_row += QUADS) {
            stwo_compact_consume_final16_quad(
                states,
                global_start + local_row,
                messages + local_row * MESSAGE_STRIDE,
                values,
                tile,
                cols_done,
                initial_tail,
                compact_scratch + quad * MESSAGE_STRIDE);
        }
        __syncthreads();
    }
}

#endif
