// Device witness generation for the Cairo memory tables (witness-on-GPU P1).
//
// Ports of the generated SIMD writers' math, formula-for-formula (see
// stwo-cairo `witness/components/memory_id_to_big.rs` and the spec in
// gpu_benchmarks/WITNESS_ON_GPU.md):
//
// - 252-bit limb split: walk the 8 (big) / 4 (small) little-endian u32 words,
//   emitting 28 (resp. 8) limbs of 9 bits each — identical to
//   `split_f252` in stwo-cairo-common (LSB-first bit-buffer walk).
// - rc_9_9 multiplicity feed: per row, limb pairs (2j, 2j+1) count into the
//   relation-indexed (j % 8) multiplicity tables through the rc table's
//   input->row LUT (a table-layout mapping, uploaded once — NOT closed-form).
//   Padding rows count their (0, 0) pairs exactly like the host loop does.
// - Logup denominators: combine(values) = sum_i alpha_powers[i] * values[i] - z
//   (the constraint-framework LookupElements formula) over
//   [RELATION_ID, offset + row, limb_0..limb_27]; numerators are (-mult, 0, 0, 0).
//
// All counts are order-independent (field/integer adds), so atomics preserve
// byte-equality by construction. The decisive gates live in stwo-cairo: a
// device-vs-host writer differential and the Cairo e2e proof byte-equality.

#include "batch_inverse.cuh"
#include "fields.cuh"
#include "utils.cuh"

namespace {

constexpr uint32_t MW_BLOCK = 256;
constexpr uint32_t FELT252_BITS_PER_WORD = 9;
constexpr uint32_t LIMB_MASK = (1u << FELT252_BITS_PER_WORD) - 1;
constexpr int MW_MAX_LIMBS = 28;

struct MemoryResidentOutputs {
    uint32_t *limbs[MW_MAX_LIMBS];
};

struct MemoryBaseTraceColumns {
    uint32_t *columns[32];
};

struct MemoryBaseTraceSources {
    const uint32_t *columns[MW_MAX_LIMBS];
};

// LSB-first split of `n_words` 32-bit words into `n_limbs` 9-bit limbs —
// line-for-line the generic `split` in stwo-cairo-common/prover_types/felt.rs.
template <int N_WORDS, int N_LIMBS>
DEVICE_FORCEINLINE void split_le_9bit(const uint32_t *words, uint32_t *limbs) {
    uint32_t n_bits_in_word = 32;
    uint32_t word_i = 0;
    uint32_t word = words[0];
    for (int e = 0; e < N_LIMBS; ++e) {
        if (n_bits_in_word > FELT252_BITS_PER_WORD) {
            limbs[e] = word & LIMB_MASK;
            word >>= FELT252_BITS_PER_WORD;
            n_bits_in_word -= FELT252_BITS_PER_WORD;
            continue;
        }
        limbs[e] = word;
        word_i += 1;
        word = word_i < N_WORDS ? words[word_i] : 0;
        if (n_bits_in_word < FELT252_BITS_PER_WORD) {
            limbs[e] |= (word << n_bits_in_word) & LIMB_MASK;
            word >>= FELT252_BITS_PER_WORD - n_bits_in_word;
        }
        n_bits_in_word += 32 - FELT252_BITS_PER_WORD;
    }
}

// One thread per output row. Rows past `n_values` are padding: all-zero limbs
// (matching the host's zero-extension of the value table).
template <int N_WORDS, int N_LIMBS>
__global__ void memory_limb_split_kernel(
    const uint32_t *values,  // n_values * N_WORDS words, row-major
    uint32_t n_values,
    uint32_t column_length,
    uint32_t *const *limb_cols  // N_LIMBS device pointers, column_length each
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    uint32_t words[N_WORDS] = {0};
    if (row < n_values) {
        for (int w = 0; w < N_WORDS; ++w) {
            words[w] = values[(size_t)row * N_WORDS + w];
        }
    }
    uint32_t limbs[N_LIMBS];
    split_le_9bit<N_WORDS, N_LIMBS>(words, limbs);
    for (int j = 0; j < N_LIMBS; ++j) {
        limb_cols[j][row] = limbs[j];
    }
}

// Arena-native counterpart: output addresses travel as kernel arguments, so
// there is no per-proof device pointer-table allocation/upload.
template <int N_WORDS, int N_LIMBS>
__global__ void memory_limb_split_into_kernel(
    const uint32_t *values,
    uint32_t n_values,
    uint32_t column_length,
    MemoryResidentOutputs outputs
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    uint32_t words[N_WORDS] = {0};
    if (row < n_values) {
        for (int word = 0; word < N_WORDS; ++word) {
            words[word] = values[(size_t)row * N_WORDS + word];
        }
    }
    uint32_t limbs[N_LIMBS];
    split_le_9bit<N_WORDS, N_LIMBS>(words, limbs);
    for (int limb = 0; limb < N_LIMBS; ++limb) {
        outputs.limbs[limb][row] = limbs[limb];
    }
}

__global__ void memory_address_base_trace_kernel(
    const uint32_t *raw_addr_to_id,
    uint32_t n_addrs,
    const uint32_t *multiplicities,
    uint32_t count_words,
    uint32_t column_length,
    MemoryBaseTraceColumns outputs
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    for (uint32_t chunk = 0; chunk < 16; ++chunk) {
        uint32_t index = chunk * column_length + row;
        // Address zero is reserved; host AddressToId stores address 1 at row 0.
        outputs.columns[2 * chunk][row] = index + 1 < n_addrs
            ? raw_addr_to_id[index + 1]
            : 0u;
        outputs.columns[2 * chunk + 1][row] = index < count_words
            ? multiplicities[index]
            : 0u;
    }
}

// Sliced ABI: address zero has already been removed from `address_ids`, so the
// kernel's index is local to the declared read range. Keep the legacy kernel
// above unchanged for existing callers.
__global__ void memory_address_base_trace_sliced_kernel(
    const uint32_t *address_ids,
    uint32_t address_id_words,
    const uint32_t *multiplicities,
    uint32_t multiplicity_words,
    uint32_t column_length,
    MemoryBaseTraceColumns outputs
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    for (uint32_t chunk = 0; chunk < 16; ++chunk) {
        uint32_t index = chunk * column_length + row;
        outputs.columns[2 * chunk][row] = index < address_id_words
            ? address_ids[index]
            : 0u;
        outputs.columns[2 * chunk + 1][row] = index < multiplicity_words
            ? multiplicities[index]
            : 0u;
    }
}

__global__ void memory_value_base_trace_kernel(
    MemoryBaseTraceSources sources,
    uint32_t n_limbs,
    uint32_t source_words,
    uint32_t source_offset,
    const uint32_t *multiplicities,
    uint32_t count_words,
    uint32_t column_length,
    MemoryBaseTraceColumns outputs
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    uint32_t index = source_offset + row;
    for (uint32_t limb = 0; limb < n_limbs; ++limb) {
        outputs.columns[limb][row] = index < source_words
            ? sources.columns[limb][index]
            : 0u;
    }
    outputs.columns[n_limbs][row] = index < count_words
        ? multiplicities[index]
        : 0u;
}

__global__ void memory_value_base_trace_sliced_kernel(
    MemoryBaseTraceSources sources,
    uint32_t n_limbs,
    uint32_t source_slice_words,
    const uint32_t *multiplicities,
    uint32_t multiplicity_slice_words,
    uint32_t column_length,
    MemoryBaseTraceColumns outputs
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    for (uint32_t limb = 0; limb < n_limbs; ++limb) {
        outputs.columns[limb][row] = row < source_slice_words
            ? sources.columns[limb][row]
            : 0u;
    }
    outputs.columns[n_limbs][row] = row < multiplicity_slice_words
        ? multiplicities[row]
        : 0u;
}

// rc_9_9 feed: per row, limb pairs (2j, 2j+1) for j in [0, n_pairs) count into
// counts[(j % 8) * rc_table_size + lut[v0 * 512 + v1]]. Includes padding rows,
// exactly like the host's par_iter over the full columns.
__global__ void rc99_count_kernel(
    const uint32_t *const *limb_cols,
    uint32_t n_pairs,
    uint32_t column_length,
    const uint32_t *input_to_row_lut,  // 2^18 entries: (v0 << 9 | v1) -> rc row
    uint32_t rc_table_size,
    uint32_t *counts  // 8 * rc_table_size
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    for (uint32_t j = 0; j < n_pairs; ++j) {
        uint32_t v0 = limb_cols[2 * j][row];
        uint32_t v1 = limb_cols[2 * j + 1][row];
        uint32_t rc_row = input_to_row_lut[(v0 << FELT252_BITS_PER_WORD) | v1];
        atomicAdd(&counts[(j % 8) * (size_t)rc_table_size + rc_row], 1u);
    }
}

// Capture-safe counterpart: the fixed pointer set travels by value instead of
// through a device pointer table allocated by the legacy wrapper.
__global__ void rc99_count_on_kernel(
    MemoryBaseTraceSources limb_cols,
    uint32_t n_pairs,
    uint32_t column_length,
    const uint32_t *input_to_row_lut,
    uint32_t rc_table_size,
    uint32_t *counts
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    for (uint32_t j = 0; j < n_pairs; ++j) {
        uint32_t v0 = limb_cols.columns[2 * j][row];
        uint32_t v1 = limb_cols.columns[2 * j + 1][row];
        uint32_t rc_row = input_to_row_lut[(v0 << FELT252_BITS_PER_WORD) | v1];
        atomicAdd(&counts[(j % 8) * (size_t)rc_table_size + rc_row], 1u);
    }
}

DEVICE_FORCEINLINE qm31 qm31_mul_m31(qm31 x, m31 s) {
    return qm31{cm31{mul(x.a.a, s), mul(x.a.b, s)}, cm31{mul(x.b.a, s), mul(x.b.b, s)}};
}

// Final memory-relation column for one segment:
//   id[row]   = (id_offset + row) | id_tag     (plain u32; host guarantees < P)
//   denom     = alpha[0]*REL_ID + alpha[1]*id + sum_k alpha[2+k]*limb_k - z
//   numerator = (-mult[row], 0, 0, 0)
// alphas/z are channel-drawn QM31 params; limbs/mults are M31 device columns.
// Output denominators are element-major qm31 (the finalize lane's layout).
__global__ void memory_logup_inputs_kernel(
    const uint32_t *const *limb_cols,
    uint32_t n_limbs,
    const uint32_t *mults,
    uint32_t relation_id,
    uint32_t id_offset,
    uint32_t id_tag,
    uint32_t column_length,
    const qm31 *alpha_powers,  // n_limbs + 2 entries
    qm31 z,
    qm31 *denoms,
    uint32_t *num0, uint32_t *num1, uint32_t *num2, uint32_t *num3
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    uint32_t id = (id_offset + row) | id_tag;
    qm31 acc = qm31_mul_m31(alpha_powers[0], relation_id);
    acc = add(acc, qm31_mul_m31(alpha_powers[1], id));
    for (uint32_t k = 0; k < n_limbs; ++k) {
        acc = add(acc, qm31_mul_m31(alpha_powers[2 + k], limb_cols[k][row]));
    }
    denoms[row] = sub(acc, z);
    num0[row] = neg(mults[row]);
    num1[row] = 0;
    num2[row] = 0;
    num3[row] = 0;
}

// One pair-batched rc_9_9 logup column (the host writes 7 of these per big
// segment, 2 per small table):
//   d0 = alpha[0]*rel_id0 + alpha[1]*limb_a + alpha[2]*limb_b - z
//   d1 = alpha[0]*rel_id1 + alpha[1]*limb_c + alpha[2]*limb_d - z
//   numerator = d0 + d1   (both lookups have multiplicity 1)
//   denominator = d0 * d1
__global__ void memory_rc_pair_logup_kernel(
    const uint32_t *limb_a, const uint32_t *limb_b,
    const uint32_t *limb_c, const uint32_t *limb_d,
    uint32_t rel_id0,
    uint32_t rel_id1,
    uint32_t column_length,
    const qm31 *alpha_powers,  // 3 entries
    qm31 z,
    qm31 *denoms,
    uint32_t *num0, uint32_t *num1, uint32_t *num2, uint32_t *num3
) {
    uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= column_length) {
        return;
    }
    qm31 d0 = qm31_mul_m31(alpha_powers[0], rel_id0);
    d0 = add(d0, qm31_mul_m31(alpha_powers[1], limb_a[row]));
    d0 = add(d0, qm31_mul_m31(alpha_powers[2], limb_b[row]));
    d0 = sub(d0, z);
    qm31 d1 = qm31_mul_m31(alpha_powers[0], rel_id1);
    d1 = add(d1, qm31_mul_m31(alpha_powers[1], limb_c[row]));
    d1 = add(d1, qm31_mul_m31(alpha_powers[2], limb_d[row]));
    d1 = sub(d1, z);
    qm31 numerator = add(d0, d1);
    denoms[row] = mul(d0, d1);
    num0[row] = numerator.a.a;
    num1[row] = numerator.a.b;
    num2[row] = numerator.b.a;
    num3[row] = numerator.b.b;
}

}  // namespace

extern "C" void memory_limb_split_big(
    const uint32_t *values,
    uint32_t n_values,
    uint32_t column_length,
    const uint32_t *const *limb_cols  // 28 device pointers (device-resident table)
) {
    uint32_t blocks = (column_length + MW_BLOCK - 1) / MW_BLOCK;
    memory_limb_split_kernel<8, 28><<<blocks, MW_BLOCK>>>(
        values, n_values, column_length, const_cast<uint32_t *const *>(limb_cols));
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

extern "C" void memory_limb_split_small(
    const uint32_t *values,  // 4 words per value (u128 LE)
    uint32_t n_values,
    uint32_t column_length,
    const uint32_t *const *limb_cols  // 8 device pointers
) {
    uint32_t blocks = (column_length + MW_BLOCK - 1) / MW_BLOCK;
    memory_limb_split_kernel<4, 8><<<blocks, MW_BLOCK>>>(
        values, n_values, column_length, const_cast<uint32_t *const *>(limb_cols));
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

template <int N_WORDS, int N_LIMBS>
int memory_limb_split_into_on_impl(
    const uint32_t *values,
    uint32_t n_values,
    uint32_t column_length,
    uint32_t *const *limb_cols_host,
    const uint32_t *mults_host,
    uint32_t *mults,
    cudaStream_t stream
) {
    if (column_length == 0 || values == nullptr || limb_cols_host == nullptr ||
        mults_host == nullptr || mults == nullptr || n_values > column_length) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    MemoryResidentOutputs outputs = {};
    for (int limb = 0; limb < N_LIMBS; ++limb) {
        if (limb_cols_host[limb] == nullptr) {
            return static_cast<int>(cudaErrorInvalidDevicePointer);
        }
        outputs.limbs[limb] = limb_cols_host[limb];
    }
    cudaError_t status = cudaMemcpyAsync(
        mults, mults_host, (size_t)column_length * sizeof(uint32_t),
        cudaMemcpyHostToDevice, stream);
    if (status != cudaSuccess) {
        return static_cast<int>(status);
    }
    uint32_t blocks = (column_length + MW_BLOCK - 1) / MW_BLOCK;
    memory_limb_split_into_kernel<N_WORDS, N_LIMBS><<<blocks, MW_BLOCK, 0, stream>>>(
        values, n_values, column_length, outputs);
    return static_cast<int>(cudaGetLastError());
}

// Prepared execution-table counterpart: split compact values directly into
// stable arena columns on the caller's stream. Unlike the migration-era
// `*_into_on` entry points this performs no host transfer and owns no temporary
// allocation, so it is safe both during capture and graph replay.
template <int N_WORDS, int N_LIMBS>
int memory_limb_split_columns_on_impl(
    const uint32_t *values,
    uint32_t n_values,
    uint32_t column_length,
    uint32_t *const *limb_cols_host,
    cudaStream_t stream
) {
    if (column_length == 0 || (n_values != 0 && values == nullptr) ||
        limb_cols_host == nullptr || stream == nullptr || n_values > column_length) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    MemoryResidentOutputs outputs = {};
    for (int limb = 0; limb < N_LIMBS; ++limb) {
        if (limb_cols_host[limb] == nullptr) {
            return static_cast<int>(cudaErrorInvalidDevicePointer);
        }
        outputs.limbs[limb] = limb_cols_host[limb];
    }
    uint32_t blocks = (column_length + MW_BLOCK - 1) / MW_BLOCK;
    memory_limb_split_into_kernel<N_WORDS, N_LIMBS><<<blocks, MW_BLOCK, 0, stream>>>(
        values, n_values, column_length, outputs);
    return static_cast<int>(cudaGetLastError());
}

extern "C" int memory_limb_split_big_into_on(
    const uint32_t *values,
    uint32_t n_values,
    uint32_t column_length,
    uint32_t *const *limb_cols_host,
    const uint32_t *mults_host,
    uint32_t *mults,
    cudaStream_t stream
) {
    return memory_limb_split_into_on_impl<8, 28>(
        values, n_values, column_length, limb_cols_host, mults_host, mults, stream);
}

extern "C" int memory_limb_split_small_into_on(
    const uint32_t *values,
    uint32_t n_values,
    uint32_t column_length,
    uint32_t *const *limb_cols_host,
    const uint32_t *mults_host,
    uint32_t *mults,
    cudaStream_t stream
) {
    return memory_limb_split_into_on_impl<4, 8>(
        values, n_values, column_length, limb_cols_host, mults_host, mults, stream);
}

extern "C" int memory_limb_split_big_columns_on(
    const uint32_t *values,
    uint32_t n_values,
    uint32_t column_length,
    uint32_t *const *limb_cols_host,
    cudaStream_t stream
) {
    return memory_limb_split_columns_on_impl<8, 28>(
        values, n_values, column_length, limb_cols_host, stream);
}

extern "C" int memory_limb_split_small_columns_on(
    const uint32_t *values,
    uint32_t n_values,
    uint32_t column_length,
    uint32_t *const *limb_cols_host,
    cudaStream_t stream
) {
    return memory_limb_split_columns_on_impl<4, 8>(
        values, n_values, column_length, limb_cols_host, stream);
}

extern "C" int memory_address_base_trace_on(
    const uint32_t *raw_addr_to_id,
    uint32_t n_addrs,
    const uint32_t *multiplicities,
    uint32_t count_words,
    uint32_t column_length,
    uint32_t *const *outputs_host,
    cudaStream_t stream
) {
    if (raw_addr_to_id == nullptr || multiplicities == nullptr || outputs_host == nullptr ||
        stream == nullptr || column_length == 0 || count_words != 16u * column_length) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    MemoryBaseTraceColumns outputs = {};
    for (uint32_t column = 0; column < 32; ++column) {
        if (outputs_host[column] == nullptr) {
            return static_cast<int>(cudaErrorInvalidDevicePointer);
        }
        outputs.columns[column] = outputs_host[column];
    }
    uint32_t blocks = (column_length + MW_BLOCK - 1) / MW_BLOCK;
    memory_address_base_trace_kernel<<<blocks, MW_BLOCK, 0, stream>>>(
        raw_addr_to_id, n_addrs, multiplicities, count_words, column_length, outputs);
    return static_cast<int>(cudaGetLastError());
}

extern "C" int memory_value_base_trace_on(
    const uint32_t *const *sources_host,
    uint32_t n_limbs,
    uint32_t source_words,
    uint32_t source_offset,
    const uint32_t *multiplicities,
    uint32_t count_words,
    uint32_t column_length,
    uint32_t *const *outputs_host,
    cudaStream_t stream
) {
    if (sources_host == nullptr || multiplicities == nullptr || outputs_host == nullptr ||
        stream == nullptr || column_length == 0 || n_limbs == 0 || n_limbs > MW_MAX_LIMBS ||
        source_offset > count_words || column_length > count_words - source_offset) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    MemoryBaseTraceSources sources = {};
    MemoryBaseTraceColumns outputs = {};
    for (uint32_t limb = 0; limb < n_limbs; ++limb) {
        if (sources_host[limb] == nullptr || outputs_host[limb] == nullptr) {
            return static_cast<int>(cudaErrorInvalidDevicePointer);
        }
        sources.columns[limb] = sources_host[limb];
        outputs.columns[limb] = outputs_host[limb];
    }
    if (outputs_host[n_limbs] == nullptr) {
        return static_cast<int>(cudaErrorInvalidDevicePointer);
    }
    outputs.columns[n_limbs] = outputs_host[n_limbs];
    uint32_t blocks = (column_length + MW_BLOCK - 1) / MW_BLOCK;
    memory_value_base_trace_kernel<<<blocks, MW_BLOCK, 0, stream>>>(
        sources, n_limbs, source_words, source_offset, multiplicities, count_words,
        column_length, outputs);
    return static_cast<int>(cudaGetLastError());
}

extern "C" int memory_address_base_trace_sliced_on(
    const uint32_t *address_ids,
    uint32_t address_id_words,
    const uint32_t *multiplicities,
    uint32_t multiplicity_words,
    uint32_t column_length,
    uint32_t *const *outputs_host,
    cudaStream_t stream
) {
    if (address_ids == nullptr || multiplicities == nullptr || outputs_host == nullptr ||
        stream == nullptr || column_length == 0 || column_length > 0xffffffffu / 16u ||
        multiplicity_words != 16u * column_length || address_id_words > multiplicity_words) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    MemoryBaseTraceColumns outputs = {};
    for (uint32_t column = 0; column < 32; ++column) {
        if (outputs_host[column] == nullptr) {
            return static_cast<int>(cudaErrorInvalidDevicePointer);
        }
        outputs.columns[column] = outputs_host[column];
    }
    uint32_t blocks = 1u + (column_length - 1u) / MW_BLOCK;
    memory_address_base_trace_sliced_kernel<<<blocks, MW_BLOCK, 0, stream>>>(
        address_ids, address_id_words, multiplicities, multiplicity_words, column_length, outputs);
    return static_cast<int>(cudaGetLastError());
}

extern "C" int memory_value_base_trace_sliced_on(
    const uint32_t *const *sources_host,
    uint32_t n_limbs,
    uint32_t source_slice_words,
    const uint32_t *multiplicities,
    uint32_t multiplicity_slice_words,
    uint32_t column_length,
    uint32_t *const *outputs_host,
    cudaStream_t stream
) {
    if (sources_host == nullptr || multiplicities == nullptr || outputs_host == nullptr ||
        stream == nullptr || column_length == 0 || n_limbs == 0 || n_limbs > MW_MAX_LIMBS ||
        source_slice_words > column_length || multiplicity_slice_words != column_length) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    MemoryBaseTraceSources sources = {};
    MemoryBaseTraceColumns outputs = {};
    for (uint32_t limb = 0; limb < n_limbs; ++limb) {
        if ((source_slice_words != 0 && sources_host[limb] == nullptr) ||
            outputs_host[limb] == nullptr) {
            return static_cast<int>(cudaErrorInvalidDevicePointer);
        }
        sources.columns[limb] = sources_host[limb];
        outputs.columns[limb] = outputs_host[limb];
    }
    if (outputs_host[n_limbs] == nullptr) {
        return static_cast<int>(cudaErrorInvalidDevicePointer);
    }
    outputs.columns[n_limbs] = outputs_host[n_limbs];
    uint32_t blocks = 1u + (column_length - 1u) / MW_BLOCK;
    memory_value_base_trace_sliced_kernel<<<blocks, MW_BLOCK, 0, stream>>>(
        sources, n_limbs, source_slice_words, multiplicities, multiplicity_slice_words,
        column_length, outputs);
    return static_cast<int>(cudaGetLastError());
}

extern "C" void memory_rc99_count(
    const uint32_t *const *limb_cols,
    uint32_t n_pairs,
    uint32_t column_length,
    const uint32_t *input_to_row_lut,
    uint32_t rc_table_size,
    uint32_t *counts
) {
    uint32_t blocks = (column_length + MW_BLOCK - 1) / MW_BLOCK;
    rc99_count_kernel<<<blocks, MW_BLOCK>>>(
        limb_cols, n_pairs, column_length, input_to_row_lut, rc_table_size, counts);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

extern "C" int memory_rc99_count_on(
    const uint32_t *const *limb_cols_host,
    uint32_t n_pairs,
    uint32_t column_length,
    const uint32_t *input_to_row_lut,
    uint32_t rc_table_size,
    uint32_t *counts,
    cudaStream_t stream
) {
    if (limb_cols_host == nullptr || input_to_row_lut == nullptr || counts == nullptr ||
        stream == nullptr || n_pairs == 0 || n_pairs > MW_MAX_LIMBS / 2 ||
        column_length == 0 || rc_table_size == 0) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    MemoryBaseTraceSources limb_cols = {};
    for (uint32_t limb = 0; limb < 2 * n_pairs; ++limb) {
        if (limb_cols_host[limb] == nullptr) {
            return static_cast<int>(cudaErrorInvalidDevicePointer);
        }
        limb_cols.columns[limb] = limb_cols_host[limb];
    }
    uint32_t blocks = 1u + (column_length - 1u) / MW_BLOCK;
    rc99_count_on_kernel<<<blocks, MW_BLOCK, 0, stream>>>(
        limb_cols, n_pairs, column_length, input_to_row_lut, rc_table_size, counts);
    return static_cast<int>(cudaGetLastError());
}

extern "C" void memory_logup_inputs(
    const uint32_t *const *limb_cols,
    uint32_t n_limbs,
    const uint32_t *mults,
    uint32_t relation_id,
    uint32_t id_offset,
    uint32_t id_tag,
    uint32_t column_length,
    const uint32_t *alpha_powers,  // (n_limbs + 2) qm31s, element-major
    qm31 z,
    uint32_t *denoms,  // column_length qm31s, element-major
    uint32_t *num0, uint32_t *num1, uint32_t *num2, uint32_t *num3
) {
    uint32_t blocks = (column_length + MW_BLOCK - 1) / MW_BLOCK;
    memory_logup_inputs_kernel<<<blocks, MW_BLOCK>>>(
        limb_cols, n_limbs, mults, relation_id, id_offset, id_tag, column_length,
        reinterpret_cast<const qm31 *>(alpha_powers), z,
        reinterpret_cast<qm31 *>(denoms), num0, num1, num2, num3);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

extern "C" void memory_rc_pair_logup(
    const uint32_t *limb_a, const uint32_t *limb_b,
    const uint32_t *limb_c, const uint32_t *limb_d,
    uint32_t rel_id0,
    uint32_t rel_id1,
    uint32_t column_length,
    const uint32_t *alpha_powers,  // 3 qm31s, element-major
    qm31 z,
    uint32_t *denoms,
    uint32_t *num0, uint32_t *num1, uint32_t *num2, uint32_t *num3
) {
    uint32_t blocks = (column_length + MW_BLOCK - 1) / MW_BLOCK;
    memory_rc_pair_logup_kernel<<<blocks, MW_BLOCK>>>(
        limb_a, limb_b, limb_c, limb_d, rel_id0, rel_id1, column_length,
        reinterpret_cast<const qm31 *>(alpha_powers), z,
        reinterpret_cast<qm31 *>(denoms), num0, num1, num2, num3);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}

namespace {

// Composed device `deduce_output` — the ENDGAME_ARCHITECTURE.md §2 keystone primitive.
//
// addr -> raw encoded id (addr_to_id LUT) -> decode -> 28 9-bit value limbs,
// reproducing the host `memory_address_to_id.deduce_output` followed by
// `memory_id_to_big.deduce_output`. The big/small limb tables are the SAME
// device-resident column-major split tables the memory component commits
// (memory_limb_split_big/small), so the value a witness kernel deduces on device is
// bit-identical to the host HashMap deduction — this is the "device table read"
// that replaces the host `sub_state.deduce_output(key)`.
//
// Encoding (stwo-cairo-common::memory::EncodedMemoryValueId): the raw id's top two
// bits are the tag. tag == 1 => F252: value index = id & 0x3FFFFFFF into the 28-limb
// big table. tag == 0 => Small: index into the 8-limb small table, zero-extended to 28
// (the host builds [small_limbs, 0..] since a small value is < 2^72). DEFAULT_ID
// (0x3FFFFFFF, an empty cell) must never be queried; the host caller filters it, as
// `memory_id_to_big.deduce_output` itself panics on Empty. One thread per query.
__global__ void exec_deduce_output_kernel(
    const uint32_t *addr_to_id,          // [n_addrs] raw encoded id per address
    const uint32_t *const *big_limbs,    // 28 device columns
    const uint32_t *const *small_limbs,  // 8 device columns
    const uint32_t *addresses,           // [n_queries]
    uint32_t n_queries,
    uint32_t *out_ids,                   // [n_queries]
    uint32_t *const *out_limbs           // 28 device columns, [n_queries]
) {
    uint32_t q = blockIdx.x * blockDim.x + threadIdx.x;
    if (q >= n_queries) {
        return;
    }
    uint32_t addr = addresses[q];
    uint32_t id = addr_to_id[addr];
    out_ids[q] = id;
    uint32_t tag = id >> 30;
    uint32_t val = id & 0x3FFFFFFFu;
    for (int j = 0; j < 28; ++j) {
        uint32_t limb;
        if (tag == 1u) {
            limb = big_limbs[j][val];
        } else {
            limb = (j < 8) ? small_limbs[j][val] : 0u;
        }
        out_limbs[j][q] = limb;
    }
}

}  // namespace

// Batched composed deduce_output over `addresses` (see exec_deduce_output_kernel).
// `out_ids` receives the raw encoded id per query; `out_limbs` the 28 value limbs
// (column-major, one device column per limb). All addresses must be non-empty cells.
extern "C" void exec_deduce_output(
    const uint32_t *addr_to_id,
    const uint32_t *const *big_limbs,
    const uint32_t *const *small_limbs,
    const uint32_t *addresses,
    uint32_t n_queries,
    uint32_t *out_ids,
    uint32_t *const *out_limbs
) {
    if (n_queries == 0) {
        return;
    }
    uint32_t blocks = (n_queries + MW_BLOCK - 1) / MW_BLOCK;
    exec_deduce_output_kernel<<<blocks, MW_BLOCK>>>(
        addr_to_id, big_limbs, small_limbs, addresses, n_queries, out_ids, out_limbs);
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());
}
