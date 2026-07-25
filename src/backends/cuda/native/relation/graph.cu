// Allocation-free relation graph extracted from the pinned CUDA authority.

#include "batch_inverse.cuh"

#include <cuda_runtime_api.h>

namespace stwo::cuda::relation {
namespace {

__global__ void expand_challenges_kernel(
    const QM31 *drawn,
    QM31 *alpha_powers,
    std::uint32_t alpha_count,
    QM31 *z) {
    if (blockIdx.x != 0u || threadIdx.x != 0u) return;
    z[0] = drawn[0];
    const QM31 alpha = drawn[1];
    QM31 power = one();
    for (std::uint32_t index = 0; index < alpha_count; ++index) {
        alpha_powers[index] = power;
        power = mul(power, alpha);
    }
}

__device__ __forceinline__ void relation_pair_at(
    const std::uint32_t *const *sources,
    std::uint32_t rows,
    std::uint32_t row,
    std::uint32_t real_rows,
    std::uint32_t source_offset_rows,
    const std::uint32_t *descriptors,
    std::uint32_t column,
    const QM31 *alphas,
    QM31 z,
    M31 *const *outputs,
    QM31 *denominators) {
    QM31 numerator;
    QM31 denominator;
    relation_column_fraction(
        sources,
        rows,
        row,
        real_rows,
        source_offset_rows,
        descriptors + column * kDescriptorWords,
        alphas,
        z,
        &numerator,
        &denominator);
    const std::uint32_t output_base = column * 4u;
    outputs[output_base][row] = numerator.a.a;
    outputs[output_base + 1u][row] = numerator.a.b;
    outputs[output_base + 2u][row] = numerator.b.a;
    outputs[output_base + 3u][row] = numerator.b.b;
    denominators[column * rows + row] = denominator;
}

__global__ void relation_pairs_global_kernel(
    const std::uint32_t *const *const *source_tables,
    const std::uint32_t *const *descriptors,
    M31 *const *const *output_tables,
    QM31 *const *denominator_slabs,
    const std::uint32_t *geometry,
    std::uint32_t instance_count,
    const QM31 *alphas,
    const QM31 *z) {
    std::uint32_t local_block = 0u;
    const std::uint32_t instance = relation_instance_for_block(
        geometry,
        instance_count,
        blockIdx.x,
        kPairFirst,
        kPairBlocks,
        &local_block);
    if (instance == instance_count) return;

    const std::uint32_t *record =
        geometry + instance * kGeometryWords;
    const std::uint32_t row_blocks = record[kRowBlocks];
    const std::uint32_t column = local_block / row_blocks;
    const std::uint32_t row_block =
        local_block - column * row_blocks;
    const std::uint32_t row =
        row_block * kLaunchBlock + threadIdx.x;
    if (row >= record[kRows]) return;
    relation_pair_at(
        source_tables[instance],
        record[kRows],
        row,
        record[kRealRows],
        record[kSourceOffset],
        descriptors[instance],
        column,
        alphas,
        z[0],
        output_tables[instance],
        denominator_slabs[instance]);
}

__global__ void fraction_chain_global_kernel(
    M31 *const *const *output_tables,
    const QM31 *const *inverses,
    const std::uint32_t *geometry,
    std::uint32_t instance_count) {
    const std::uint32_t global_block = blockIdx.x;
    std::uint32_t low = 0u;
    std::uint32_t high = instance_count;
    while (low < high) {
        const std::uint32_t middle = low + (high - low) / 2u;
        if (geometry[middle * kGeometryWords + kRowFirst] <=
            global_block) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }
    if (low == 0u) return;

    const std::uint32_t instance = low - 1u;
    const std::uint32_t *record =
        geometry + instance * kGeometryWords;
    const std::uint32_t local_block =
        global_block - record[kRowFirst];
    if (local_block >= record[kRowBlocks]) return;

    const std::uint32_t rows = record[kRows];
    const std::uint32_t columns = record[kColumns];
    const std::uint32_t row =
        local_block * kLaunchBlock + threadIdx.x;
    if (row >= rows) return;

    M31 *const *outputs = output_tables[instance];
    const QM31 *inverse_values = inverses[instance];
    QM31 accumulated = zero();
    for (std::uint32_t column = 0; column < columns; ++column) {
        const std::uint32_t base = column * 4u;
        const QM31 numerator{
            {outputs[base][row], outputs[base + 1u][row]},
            {outputs[base + 2u][row], outputs[base + 3u][row]},
        };
        accumulated = add(
            accumulated,
            mul(
                numerator,
                inverse_values[column * rows + row]));
        outputs[base][row] = accumulated.a.a;
        outputs[base + 1u][row] = accumulated.a.b;
        outputs[base + 2u][row] = accumulated.b.a;
        outputs[base + 3u][row] = accumulated.b.b;
    }
}

__global__ void reduce_coordinates_ragged_kernel(
    M31 *const *const *output_tables,
    const std::uint32_t *geometry,
    std::uint32_t instance_count,
    QM31 *partials) {
    std::uint32_t local_block = 0u;
    const std::uint32_t instance = relation_instance_for_block(
        geometry,
        instance_count,
        blockIdx.x,
        kRowFirst,
        kRowBlocks,
        &local_block);
    if (instance == instance_count) return;

    const std::uint32_t *record =
        geometry + instance * kGeometryWords;
    M31 *const *outputs = output_tables[instance];
    const std::uint32_t last = (record[kColumns] - 1u) * 4u;
    const std::uint32_t row =
        local_block * kLaunchBlock + threadIdx.x;
    extern __shared__ __align__(16) unsigned char shared_storage[];
    auto *shared = reinterpret_cast<QM31 *>(shared_storage);
    shared[threadIdx.x] =
        row < record[kRows]
            ? QM31{
                  {outputs[last][row], outputs[last + 1u][row]},
                  {outputs[last + 2u][row], outputs[last + 3u][row]},
              }
            : zero();
    __syncthreads();
    for (std::uint32_t stride = kLaunchBlock / 2u;
         stride != 0u;
         stride >>= 1u) {
        if (threadIdx.x < stride) {
            shared[threadIdx.x] =
                add(shared[threadIdx.x], shared[threadIdx.x + stride]);
        }
        __syncthreads();
    }
    if (threadIdx.x == 0u) {
        partials[record[kRowFirst] + local_block] = shared[0];
    }
}

__global__ void finalize_claimed_sums_ragged_kernel(
    QM31 *const *claimed_sums,
    const std::uint32_t *geometry,
    std::uint32_t instance_count,
    const QM31 *partials) {
    const std::uint32_t instance = blockIdx.x;
    if (instance >= instance_count) return;

    const std::uint32_t *record =
        geometry + instance * kGeometryWords;
    const std::uint32_t first = record[kRowFirst];
    const std::uint32_t count = record[kRowBlocks];
    QM31 accumulated = zero();
    for (std::uint32_t index = threadIdx.x;
         index < count;
         index += kLaunchBlock) {
        accumulated = add(accumulated, partials[first + index]);
    }
    extern __shared__ __align__(16) unsigned char shared_storage[];
    auto *shared = reinterpret_cast<QM31 *>(shared_storage);
    shared[threadIdx.x] = accumulated;
    __syncthreads();
    for (std::uint32_t stride = kLaunchBlock / 2u;
         stride != 0u;
         stride >>= 1u) {
        if (threadIdx.x < stride) {
            shared[threadIdx.x] =
                add(shared[threadIdx.x], shared[threadIdx.x + stride]);
        }
        __syncthreads();
    }
    if (threadIdx.x == 0u) {
        claimed_sums[instance][0] = shared[0];
    }
}

__device__ __forceinline__ std::uint32_t
relation_scan_instance_for_block(
    const std::uint32_t *geometry,
    std::uint32_t instance_count,
    std::uint32_t global_block,
    std::uint32_t *local_block) {
    std::uint32_t low = 0u;
    std::uint32_t high = instance_count;
    while (low < high) {
        const std::uint32_t middle = low + (high - low) / 2u;
        const std::uint32_t *record =
            geometry + middle * kGeometryWords;
        if (record[kRowFirst] * 4u <= global_block) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }
    if (low == 0u) return instance_count;
    const std::uint32_t instance = low - 1u;
    const std::uint32_t *record =
        geometry + instance * kGeometryWords;
    *local_block = global_block - record[kRowFirst] * 4u;
    return *local_block < record[kRowBlocks] * 4u
        ? instance
        : instance_count;
}

__global__ void shift_scan_tiles_ragged_kernel(
    M31 *const *const *output_tables,
    QM31 *const *claimed_sums,
    const std::uint32_t *geometry,
    std::uint32_t instance_count,
    M31 *block_sums) {
    std::uint32_t local_block = 0u;
    const std::uint32_t instance = relation_scan_instance_for_block(
        geometry,
        instance_count,
        blockIdx.x,
        &local_block);
    if (instance == instance_count) return;

    const std::uint32_t *record =
        geometry + instance * kGeometryWords;
    const std::uint32_t row_blocks = record[kRowBlocks];
    const std::uint32_t coordinate = local_block / row_blocks;
    const std::uint32_t row_block =
        local_block - coordinate * row_blocks;
    const std::uint32_t scan_index =
        row_block * kLaunchBlock + threadIdx.x;
    M31 *output = output_tables[instance][
        (record[kColumns] - 1u) * 4u + coordinate];
    const QM31 sum = claimed_sums[instance][0];
    const M31 sum_coordinate =
        coordinate == 0u   ? sum.a.a
        : coordinate == 1u ? sum.a.b
        : coordinate == 2u ? sum.b.a
                           : sum.b.b;
    const M31 shift =
        mul(record[kInverseRows], sum_coordinate);
    extern __shared__ __align__(16) unsigned char shared_storage[];
    auto *shared = reinterpret_cast<M31 *>(shared_storage);
    shared[threadIdx.x] =
        scan_index < record[kRows]
            ? sub(
                  output[relation_coset_scan_row(
                      scan_index,
                      record[kRows])],
                  shift)
            : 0u;
    __syncthreads();
    for (std::uint32_t offset = 1u;
         offset < kLaunchBlock;
         offset <<= 1u) {
        M31 value = shared[threadIdx.x];
        if (threadIdx.x >= offset) {
            value = add(value, shared[threadIdx.x - offset]);
        }
        __syncthreads();
        shared[threadIdx.x] = value;
        __syncthreads();
    }
    if (scan_index < record[kRows]) {
        output[relation_coset_scan_row(scan_index, record[kRows])] =
            shared[threadIdx.x];
    }
    std::uint32_t valid =
        record[kRows] - row_block * kLaunchBlock;
    if (valid > kLaunchBlock) valid = kLaunchBlock;
    if (threadIdx.x + 1u == valid) {
        block_sums[blockIdx.x] = shared[threadIdx.x];
    }
}

__global__ void scan_block_totals_ragged_kernel(
    M31 *block_sums,
    const std::uint32_t *geometry,
    std::uint32_t instance_count) {
    const std::uint32_t segment = blockIdx.x;
    const std::uint32_t instance = segment / 4u;
    const std::uint32_t coordinate = segment % 4u;
    if (instance >= instance_count) return;

    const std::uint32_t *record =
        geometry + instance * kGeometryWords;
    const std::uint32_t count = record[kRowBlocks];
    const std::uint32_t first =
        record[kRowFirst] * 4u + coordinate * count;
    __shared__ M31 shared[kLaunchBlock];
    __shared__ M31 carry;
    if (threadIdx.x == 0u) carry = 0u;
    __syncthreads();
    for (std::uint32_t chunk = 0u; chunk < count;
         chunk += kLaunchBlock) {
        const std::uint32_t remaining = count - chunk;
        const std::uint32_t valid =
            remaining < kLaunchBlock ? remaining : kLaunchBlock;
        shared[threadIdx.x] =
            threadIdx.x < valid
                ? block_sums[first + chunk + threadIdx.x]
                : 0u;
        __syncthreads();
        for (std::uint32_t offset = 1u;
             offset < kLaunchBlock;
             offset <<= 1u) {
            M31 value = shared[threadIdx.x];
            if (threadIdx.x >= offset) {
                value = add(value, shared[threadIdx.x - offset]);
            }
            __syncthreads();
            shared[threadIdx.x] = value;
            __syncthreads();
        }
        const M31 base = carry;
        __syncthreads();
        if (threadIdx.x < valid) {
            const M31 total = add(shared[threadIdx.x], base);
            block_sums[first + chunk + threadIdx.x] = total;
            if (threadIdx.x + 1u == valid) carry = total;
        }
        __syncthreads();
    }
}

__global__ void add_scan_offsets_ragged_kernel(
    M31 *const *const *output_tables,
    const std::uint32_t *geometry,
    std::uint32_t instance_count,
    const M31 *block_sums) {
    std::uint32_t local_block = 0u;
    const std::uint32_t instance = relation_scan_instance_for_block(
        geometry,
        instance_count,
        blockIdx.x,
        &local_block);
    if (instance == instance_count) return;

    const std::uint32_t *record =
        geometry + instance * kGeometryWords;
    const std::uint32_t row_blocks = record[kRowBlocks];
    const std::uint32_t coordinate = local_block / row_blocks;
    const std::uint32_t row_block =
        local_block - coordinate * row_blocks;
    if (row_block == 0u) return;

    const std::uint32_t scan_index =
        row_block * kLaunchBlock + threadIdx.x;
    if (scan_index >= record[kRows]) return;
    const std::uint32_t row =
        relation_coset_scan_row(scan_index, record[kRows]);
    M31 *output = output_tables[instance][
        (record[kColumns] - 1u) * 4u + coordinate];
    output[row] = add(output[row], block_sums[blockIdx.x - 1u]);
}

}  // namespace
}  // namespace stwo::cuda::relation

extern "C" int stwo_relation_expand_challenges_on(
    const std::uint32_t *drawn_z_alpha,
    std::uint32_t *alpha_powers,
    std::uint32_t alpha_count,
    std::uint32_t *z,
    void *stream_raw) {
    using namespace stwo::cuda::relation;
    if (drawn_z_alpha == nullptr || alpha_powers == nullptr ||
        alpha_count == 0u || z == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    expand_challenges_kernel<<<
        1,
        1,
        0,
        reinterpret_cast<cudaStream_t>(stream_raw)>>>(
            reinterpret_cast<const QM31 *>(drawn_z_alpha),
            reinterpret_cast<QM31 *>(alpha_powers),
            alpha_count,
            reinterpret_cast<QM31 *>(z));
    return static_cast<int>(cudaGetLastError());
}

extern "C" int stwo_relation_pairs_global_on(
    const std::uint32_t *const *const *source_tables,
    const std::uint32_t *const *descriptors,
    std::uint32_t *const *const *output_tables,
    std::uint32_t *const *denominator_slabs,
    const std::uint32_t *geometry,
    std::uint32_t instance_count,
    std::uint32_t total_pair_blocks,
    const std::uint32_t *alpha_powers,
    std::uint32_t alpha_count,
    const std::uint32_t *z,
    void *stream_raw) {
    using namespace stwo::cuda::relation;
    if (source_tables == nullptr || descriptors == nullptr ||
        output_tables == nullptr || denominator_slabs == nullptr ||
        geometry == nullptr || instance_count == 0u ||
        total_pair_blocks == 0u || alpha_powers == nullptr ||
        alpha_count == 0u || z == nullptr || stream_raw == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    relation_pairs_global_kernel<<<
        total_pair_blocks,
        kLaunchBlock,
        0,
        reinterpret_cast<cudaStream_t>(stream_raw)>>>(
            source_tables,
            descriptors,
            reinterpret_cast<M31 *const *const *>(output_tables),
            reinterpret_cast<QM31 *const *>(denominator_slabs),
            geometry,
            instance_count,
            reinterpret_cast<const QM31 *>(alpha_powers),
            reinterpret_cast<const QM31 *>(z));
    return static_cast<int>(cudaGetLastError());
}

extern "C" int stwo_relation_fraction_chain_global_on(
    std::uint32_t *const *const *output_tables,
    std::uint32_t *const *denominator_slabs,
    const std::uint32_t *geometry,
    std::uint32_t instance_count,
    std::uint32_t total_inverse_blocks,
    std::uint32_t total_chain_blocks,
    void *stream_raw) {
    using namespace stwo::cuda::relation;
    if (output_tables == nullptr || denominator_slabs == nullptr ||
        geometry == nullptr || instance_count == 0u ||
        total_inverse_blocks == 0u || total_chain_blocks == 0u ||
        total_inverse_blocks > 0x7fffffffu ||
        total_chain_blocks > 0x7fffffffu) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const cudaStream_t stream =
        reinterpret_cast<cudaStream_t>(stream_raw);
    const cudaError_t inverse_error = batch_inverse_ragged_on(
        stream,
        reinterpret_cast<QM31 *const *>(denominator_slabs),
        geometry,
        static_cast<int>(instance_count),
        static_cast<int>(total_inverse_blocks));
    if (inverse_error != cudaSuccess) {
        return static_cast<int>(inverse_error);
    }
    fraction_chain_global_kernel<<<
        total_chain_blocks,
        kLaunchBlock,
        0,
        stream>>>(
            reinterpret_cast<M31 *const *const *>(output_tables),
            reinterpret_cast<const QM31 *const *>(denominator_slabs),
            geometry,
            instance_count);
    return static_cast<int>(cudaGetLastError());
}

extern "C" int stwo_relation_tail_global_on(
    std::uint32_t *const *const *output_tables,
    std::uint32_t *const *claimed_sums,
    const std::uint32_t *geometry,
    std::uint32_t instance_count,
    std::uint32_t total_row_blocks,
    std::uint32_t *reduction_partials,
    std::uint32_t reduction_capacity,
    std::uint32_t *scan_block_sums,
    std::uint32_t scan_capacity,
    void *stream_raw) {
    using namespace stwo::cuda::relation;
    if (output_tables == nullptr || claimed_sums == nullptr ||
        geometry == nullptr || instance_count == 0u ||
        total_row_blocks == 0u ||
        instance_count > 0xffffffffu / 4u ||
        reduction_partials == nullptr ||
        reduction_capacity < total_row_blocks ||
        scan_block_sums == nullptr ||
        total_row_blocks > 0xffffffffu / 4u ||
        scan_capacity < total_row_blocks * 4u ||
        stream_raw == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const cudaStream_t stream =
        reinterpret_cast<cudaStream_t>(stream_raw);
    auto outputs =
        reinterpret_cast<M31 *const *const *>(output_tables);
    auto sums = reinterpret_cast<QM31 *const *>(claimed_sums);
    auto partials = reinterpret_cast<QM31 *>(reduction_partials);
    const std::uint32_t total_scan_blocks = total_row_blocks * 4u;

    reduce_coordinates_ragged_kernel<<<
        total_row_blocks,
        kLaunchBlock,
        kLaunchBlock * sizeof(QM31),
        stream>>>(
            outputs,
            geometry,
            instance_count,
            partials);
    cudaError_t error = cudaGetLastError();
    if (error != cudaSuccess) return static_cast<int>(error);

    finalize_claimed_sums_ragged_kernel<<<
        instance_count,
        kLaunchBlock,
        kLaunchBlock * sizeof(QM31),
        stream>>>(
            sums,
            geometry,
            instance_count,
            partials);
    error = cudaGetLastError();
    if (error != cudaSuccess) return static_cast<int>(error);

    shift_scan_tiles_ragged_kernel<<<
        total_scan_blocks,
        kLaunchBlock,
        kLaunchBlock * sizeof(M31),
        stream>>>(
            outputs,
            sums,
            geometry,
            instance_count,
            scan_block_sums);
    error = cudaGetLastError();
    if (error != cudaSuccess) return static_cast<int>(error);

    scan_block_totals_ragged_kernel<<<
        instance_count * 4u,
        kLaunchBlock,
        0,
        stream>>>(
            scan_block_sums,
            geometry,
            instance_count);
    error = cudaGetLastError();
    if (error != cudaSuccess) return static_cast<int>(error);

    add_scan_offsets_ragged_kernel<<<
        total_scan_blocks,
        kLaunchBlock,
        0,
        stream>>>(
            outputs,
            geometry,
            instance_count,
            scan_block_sums);
    return static_cast<int>(cudaGetLastError());
}
