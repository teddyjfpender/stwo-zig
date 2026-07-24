#pragma once

// Resident relation semantics extracted from the pinned CUDA authority.

#include "../oods/field.cuh"

#include <cstdint>

namespace stwo::cuda::relation {

using M31 = oods::M31;
using CM31 = oods::CM31;
using QM31 = oods::QM31;
using oods::add;
using oods::inverse;
using oods::mul;
using oods::one;
using oods::sub;
using oods::zero;

constexpr std::uint32_t kLaunchBlock = 256;
constexpr std::uint32_t kDescriptorWords = 16;
constexpr std::uint32_t kUseWords = 7;
constexpr std::uint32_t kGeometryWords = 11;
constexpr std::uint32_t kPairFirst = 0;
constexpr std::uint32_t kPairBlocks = 1;
constexpr std::uint32_t kInverseFirst = 2;
constexpr std::uint32_t kInverseBlocks = 3;
constexpr std::uint32_t kRowFirst = 4;
constexpr std::uint32_t kRowBlocks = 5;
constexpr std::uint32_t kRows = 6;
constexpr std::uint32_t kColumns = 7;
constexpr std::uint32_t kRealRows = 8;
constexpr std::uint32_t kSourceOffset = 9;
constexpr std::uint32_t kInverseRows = 10;
constexpr std::uint32_t kLargeMemoryValueIdBase = 0x40000000u;
constexpr std::uint32_t kXor12LimbBits = 10;
constexpr std::uint32_t kXor12ExpandBits = 2;

__device__ __forceinline__ M31 relation_tuple_word(
    const std::uint32_t *const *sources,
    std::uint32_t rows,
    std::uint32_t row,
    std::uint32_t source_offset_rows,
    const std::uint32_t *use,
    std::uint32_t word) {
    const std::uint32_t kind = use[0];
    const std::uint32_t argument = use[1];
    if (word == 0) return use[3];
    if (kind == 0u) {
        return sources[0][(argument + word) * rows + row];
    }
    if (kind == 7u) {
        return sources[argument + word - 1u][row];
    }
    if (kind == 8u) {
        return sources[argument + word][row];
    }
    if (kind == 1u) {
        if (word == 1u) return row + 1u + argument * rows;
        return sources[argument * 2u][row];
    }
    if (kind == 2u || kind == 4u) {
        return sources[argument + word - 1u][row];
    }
    if (kind == 3u) {
        if (word == 1u) {
            return (row + source_offset_rows) |
                kLargeMemoryValueIdBase;
        }
        return sources[word - 2u][row];
    }
    if (kind == 5u) {
        if (word == 1u) return row + source_offset_rows;
        return sources[word - 2u][row];
    }
    const std::uint32_t a_high = argument >> kXor12ExpandBits;
    const std::uint32_t b_high =
        argument & ((1u << kXor12ExpandBits) - 1u);
    const std::uint32_t a =
        (a_high << kXor12LimbBits) | (row >> kXor12LimbBits);
    const std::uint32_t b =
        (b_high << kXor12LimbBits) |
        (row & ((1u << kXor12LimbBits) - 1u));
    return word == 1u ? a : (word == 2u ? b : (a ^ b));
}

__device__ __forceinline__ QM31 relation_combine_use(
    const std::uint32_t *const *sources,
    std::uint32_t rows,
    std::uint32_t row,
    std::uint32_t source_offset_rows,
    const std::uint32_t *use,
    const QM31 *alphas,
    QM31 z) {
    QM31 accumulated = sub(zero(), z);
    for (std::uint32_t word = 0; word < use[2]; ++word) {
        accumulated = add(
            accumulated,
            mul(
                relation_tuple_word(
                    sources,
                    rows,
                    row,
                    source_offset_rows,
                    use,
                    word),
                alphas[word]));
    }
    return accumulated;
}

__device__ __forceinline__ M31 relation_multiplicity(
    const std::uint32_t *const *sources,
    std::uint32_t rows,
    std::uint32_t row,
    std::uint32_t real_rows,
    const std::uint32_t *use) {
    const std::uint32_t kind = use[4];
    const std::uint32_t argument = use[5];
    M31 value;
    if (kind == 0u) {
        value = 1u;
    } else if (kind == 1u) {
        value = row < real_rows ? 1u : 0u;
    } else if (kind == 2u) {
        value = sources[0][argument * rows + row];
    } else if (kind == 3u) {
        value = sources[argument * 2u + 1u][row];
    } else {
        value = sources[argument][row];
    }
    return use[6] != 0u && value != 0u ? oods::kPrime - value : value;
}

__device__ __forceinline__ void relation_column_fraction(
    const std::uint32_t *const *sources,
    std::uint32_t rows,
    std::uint32_t row,
    std::uint32_t real_rows,
    std::uint32_t source_offset_rows,
    const std::uint32_t *descriptor,
    const QM31 *alphas,
    QM31 z,
    QM31 *numerator,
    QM31 *denominator) {
    const std::uint32_t *first = descriptor + 1;
    const QM31 denominator_first = relation_combine_use(
        sources,
        rows,
        row,
        source_offset_rows,
        first,
        alphas,
        z);
    const M31 multiplicity_first =
        relation_multiplicity(sources, rows, row, real_rows, first);
    if (descriptor[0] == 2u) {
        const std::uint32_t *second = first + kUseWords;
        const QM31 denominator_second = relation_combine_use(
            sources,
            rows,
            row,
            source_offset_rows,
            second,
            alphas,
            z);
        const M31 multiplicity_second =
            relation_multiplicity(sources, rows, row, real_rows, second);
        *numerator = add(
            mul(multiplicity_second, denominator_first),
            mul(multiplicity_first, denominator_second));
        *denominator = mul(denominator_first, denominator_second);
    } else {
        *numerator = {{multiplicity_first, 0u}, {0u, 0u}};
        *denominator = denominator_first;
    }
}

__device__ __forceinline__ std::uint32_t relation_instance_for_block(
    const std::uint32_t *geometry,
    std::uint32_t instance_count,
    std::uint32_t global_block,
    std::uint32_t first_word,
    std::uint32_t count_word,
    std::uint32_t *local_block) {
    std::uint32_t low = 0u;
    std::uint32_t high = instance_count;
    while (low < high) {
        const std::uint32_t middle = low + (high - low) / 2u;
        const std::uint32_t *record =
            geometry + middle * kGeometryWords;
        if (record[first_word] <= global_block) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }
    if (low == 0u) return instance_count;
    const std::uint32_t instance = low - 1u;
    const std::uint32_t *record =
        geometry + instance * kGeometryWords;
    *local_block = global_block - record[first_word];
    return *local_block < record[count_word] ? instance : instance_count;
}

__device__ __forceinline__ std::uint32_t relation_coset_scan_row(
    std::uint32_t scan_index,
    std::uint32_t rows) {
    const std::uint32_t circle_index =
        (scan_index & 1u) == 0u
            ? scan_index / 2u
            : rows - 1u - scan_index / 2u;
    const std::uint32_t bits = 31u - __clz(rows);
    return bits == 0u ? 0u : __brev(circle_index) >> (32u - bits);
}

}  // namespace stwo::cuda::relation
