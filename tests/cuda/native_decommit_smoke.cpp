#include "blake2s_reference.h"

#include <cuda_runtime_api.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

using Hash = blake2s_reference::Hash;

struct RetainedLayer {
    std::uint64_t offset_hashes;
    std::uint32_t hash_count;
    std::uint32_t reserved;
};

extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);
extern "C" int stwo_exec_context_sync(void *handle);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
extern "C" int stwo_exec_context_alloc_u32(
    void *handle, std::size_t count, std::uint32_t **out_pointer);
extern "C" int stwo_exec_context_free_u32(void *handle, std::uint32_t *pointer);
extern "C" int stwo_exec_context_memcpy_h2d_async(
    void *handle, void *destination, const void *source, std::size_t bytes);
extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *handle, void *destination, const void *source, std::size_t bytes);

extern "C" int stwo_decommit_normalize_queries_on(
    const std::uint32_t *, std::uint32_t, std::uint32_t, std::uint32_t,
    std::uint32_t *, std::uint32_t *, std::uint32_t *, std::uint32_t, void *);
extern "C" int stwo_decommit_prepare_trace_queries_on(
    const std::uint32_t *, const std::uint32_t *, std::uint32_t, std::uint32_t,
    std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t *,
    std::uint32_t *, std::uint32_t *, std::uint32_t *, std::uint32_t *,
    std::uint32_t, std::uint32_t *, void *);
extern "C" int stwo_decommit_pack_trace_group_on(
    std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t,
    const std::uint32_t *, std::size_t, std::size_t, const std::uint32_t *,
    std::uint32_t, const std::uint32_t *, const std::uint32_t *,
    std::uint32_t, std::uint32_t *, std::uint32_t, void *);
extern "C" int stwo_decommit_sparse_parent_on(
    const std::uint32_t *, const Hash *, const std::uint32_t *, std::uint32_t,
    std::uint32_t *, Hash *, std::uint32_t, std::uint32_t *, void *);
extern "C" int stwo_decommit_assemble_trace_on(
    std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t,
    const std::uint32_t *, std::uint32_t, std::uint32_t *, std::uint32_t *,
    const std::uint32_t *, std::uint32_t, const Hash *, std::uint64_t,
    const RetainedLayer *, std::uint32_t, const std::uint32_t *, const Hash *,
    std::uint32_t, const std::uint32_t *, const std::uint32_t *, std::uint32_t,
    std::uint32_t *, std::uint32_t, void *);
extern "C" int stwo_decommit_prepare_fri_queries_on(
    const std::uint32_t *, const std::uint32_t *, std::uint32_t, std::uint32_t,
    std::uint32_t, std::uint32_t, std::uint32_t *, std::uint32_t *,
    std::uint32_t *, std::uint32_t, std::uint32_t *, std::uint32_t *,
    std::uint32_t, std::uint32_t *, void *);
extern "C" int stwo_decommit_assemble_fri_on(
    std::uint32_t, std::uint32_t, const std::uint32_t *, const std::uint32_t *,
    std::uint32_t, const std::uint32_t *, const std::uint32_t *,
    std::uint32_t, const std::uint32_t *, std::size_t, std::size_t,
    std::uint32_t *, std::uint32_t *, const std::uint32_t *, std::uint32_t,
    const Hash *, std::uint64_t, const RetainedLayer *, std::uint32_t,
    std::uint32_t *, std::uint32_t, void *);

namespace {

constexpr std::uint32_t kP = 0x7fffffffu;
constexpr std::uint32_t kHeaderWords = 8;
constexpr std::uint32_t kMetaWords = 16;

bool check(int status, const char *operation) {
    if (status == 0) return true;
    std::fprintf(
        stderr, "%s: %s\n", operation,
        cudaGetErrorString(static_cast<cudaError_t>(status)));
    return false;
}

bool expect_invalid(int status, const char *operation) {
    if (status == static_cast<int>(cudaErrorInvalidValue)) return true;
    std::fprintf(stderr, "%s did not reject an invalid contract\n", operation);
    return false;
}

struct DeviceArena {
    void *context = nullptr;
    void *stream = nullptr;
    std::vector<std::uint32_t *> allocations;

    template <typename T>
    T *allocate(std::size_t count) {
        const std::size_t words =
            (count * sizeof(T) + sizeof(std::uint32_t) - 1) /
            sizeof(std::uint32_t);
        std::uint32_t *pointer = nullptr;
        if (!check(
                stwo_exec_context_alloc_u32(context, words, &pointer),
                "allocate")) {
            return nullptr;
        }
        allocations.push_back(pointer);
        return reinterpret_cast<T *>(pointer);
    }

    template <typename T>
    bool upload(T *destination, const std::vector<T> &source) {
        return check(
            stwo_exec_context_memcpy_h2d_async(
                context, destination, source.data(), source.size() * sizeof(T)),
            "upload");
    }

    template <typename T>
    bool read(std::vector<T> &destination, const T *source) {
        return check(
            stwo_exec_context_memcpy_d2h_async(
                context, destination.data(), source,
                destination.size() * sizeof(T)),
            "read");
    }

    bool close() {
        for (auto *pointer : allocations) {
            if (!check(stwo_exec_context_free_u32(context, pointer), "free")) {
                return false;
            }
        }
        if (!check(stwo_exec_context_sync(context), "wait for free")) return false;
        return check(stwo_exec_context_destroy(context), "destroy context");
    }
};

std::uint32_t canonical(std::uint32_t value) {
    return value < kP ? value : value % kP;
}

void append_hash(std::vector<std::uint32_t> &words, const Hash &hash) {
    words.insert(words.end(), hash.words, hash.words + 8);
}

struct WalkResult {
    std::uint32_t hash_offset;
    std::uint32_t hash_count;
    std::uint32_t aux_offset;
    std::uint32_t aux_count;
};

WalkResult append_walk(
    std::vector<std::uint32_t> &assembly,
    std::vector<std::uint32_t> current,
    std::uint32_t leaf_log,
    const std::vector<Hash> &slab,
    const std::vector<RetainedLayer> &layers) {
    std::vector<Hash> witnesses;
    std::vector<std::uint32_t> auxiliary;
    for (std::uint32_t level = leaf_log; level != 0; --level) {
        std::vector<std::uint32_t> parents;
        for (std::size_t index = 0; index < current.size();) {
            const std::uint32_t value = current[index];
            const bool pair = index + 1 < current.size() &&
                current[index + 1] == (value ^ 1u);
            const std::uint32_t parent = value >> 1u;
            parents.push_back(parent);
            const auto &descriptor = layers[level];
            if (!pair) {
                witnesses.push_back(
                    slab[descriptor.offset_hashes + (value ^ 1u)]);
            }
            for (std::uint32_t child = 2u * parent;
                 child <= 2u * parent + 1u;
                 ++child) {
                auxiliary.push_back(level);
                auxiliary.push_back(child);
                append_hash(
                    auxiliary,
                    slab[descriptor.offset_hashes + child]);
            }
            index += pair ? 2 : 1;
        }
        current = std::move(parents);
    }
    WalkResult result{};
    result.hash_offset = assembly.size();
    result.hash_count = witnesses.size();
    for (const auto &hash : witnesses) append_hash(assembly, hash);
    result.aux_offset = assembly.size();
    result.aux_count = auxiliary.size() / 10;
    assembly.insert(assembly.end(), auxiliary.begin(), auxiliary.end());
    return result;
}

void write_meta(
    std::vector<std::uint32_t> &assembly,
    std::uint32_t tree,
    const std::uint32_t values[16]) {
    std::copy(
        values, values + 16,
        assembly.begin() + kHeaderWords + tree * kMetaWords);
}

std::vector<std::uint32_t> expected_assembly(
    const std::vector<std::uint32_t> &raw,
    const std::vector<std::uint32_t> &mapped,
    const std::vector<std::uint32_t> &columns,
    const std::vector<std::uint32_t> &expanded,
    const std::vector<std::uint32_t> &coordinates,
    const std::vector<Hash> &retained,
    const std::vector<RetainedLayer> &layers) {
    const std::vector<std::uint32_t> unique = {1, 2, 7};
    std::vector<std::uint32_t> assembly(
        kHeaderWords + 2 * kMetaWords, 0);
    const std::uint32_t raw_offset = assembly.size();
    assembly.insert(assembly.end(), raw.begin(), raw.end());
    const std::uint32_t unique_offset = assembly.size();
    assembly.insert(assembly.end(), unique.begin(), unique.end());
    assembly[0] = 0x44575453u;
    assembly[1] = 1;
    assembly[2] = 2;
    assembly[3] = raw.size();
    assembly[4] = unique.size();
    assembly[5] = raw_offset;
    assembly[6] = unique_offset;

    const std::uint32_t trace_start = assembly.size();
    const std::uint32_t trace_query_offset = assembly.size();
    assembly.insert(assembly.end(), mapped.begin(), mapped.end());
    const std::uint32_t trace_value_offset = assembly.size();
    for (std::uint32_t column = 0; column < 2; ++column) {
        const std::uint32_t log = column == 0 ? 3 : 2;
        for (std::uint32_t query : mapped) {
            const std::uint32_t shift = 3 - log;
            const std::uint32_t row = shift == 0
                ? query
                : ((query >> (shift + 1)) << 1) + (query & 1u);
            assembly.push_back(canonical(columns[column * 8 + row]));
        }
    }
    const WalkResult trace_walk =
        append_walk(assembly, mapped, 3, retained, layers);
    const std::uint32_t trace_meta[16] = {
        0, 9, trace_query_offset, 3, trace_value_offset, 6, 0, 0,
        trace_walk.hash_offset, trace_walk.hash_count,
        trace_walk.aux_offset, trace_walk.aux_count, 0, 0, 3,
        static_cast<std::uint32_t>(assembly.size() - trace_start),
    };
    write_meta(assembly, 0, trace_meta);

    const std::uint32_t fri_start = assembly.size();
    const std::uint32_t fri_query_offset = assembly.size();
    assembly.insert(assembly.end(), unique.begin(), unique.end());
    const std::uint32_t witness_offset = assembly.size();
    std::uint32_t witness_count = 0;
    for (std::uint32_t position : expanded) {
        if (std::binary_search(unique.begin(), unique.end(), position)) continue;
        ++witness_count;
        for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
            assembly.push_back(
                canonical(coordinates[coordinate * 8 + position]));
        }
    }
    const WalkResult fri_walk =
        append_walk(assembly, {0, 1, 3}, 2, retained, layers);
    const std::uint32_t all_values_offset = assembly.size();
    for (std::uint32_t position : expanded) {
        assembly.push_back(position);
        for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
            assembly.push_back(
                canonical(coordinates[coordinate * 8 + position]));
        }
    }
    const std::uint32_t fri_meta[16] = {
        1, 1, fri_query_offset, 3, 0, 0, witness_offset, witness_count,
        fri_walk.hash_offset, fri_walk.hash_count,
        fri_walk.aux_offset, fri_walk.aux_count,
        all_values_offset, static_cast<std::uint32_t>(expanded.size()), 2,
        static_cast<std::uint32_t>(assembly.size() - fri_start),
    };
    write_meta(assembly, 1, fri_meta);
    assembly[7] = assembly.size();
    return assembly;
}

bool equal_words(
    const std::vector<std::uint32_t> &actual,
    const std::vector<std::uint32_t> &expected,
    const char *label) {
    if (actual.size() >= expected.size() &&
        std::equal(expected.begin(), expected.end(), actual.begin())) {
        return true;
    }
    std::fprintf(stderr, "%s mismatch\n", label);
    return false;
}

bool run(DeviceArena &arena) {
    const std::vector<std::uint32_t> raw = {7, 1, 7, 2};
    const std::vector<std::uint32_t> columns = {
        11, kP, 13, 14, 15, 16, 17, 18,
        101, 102, 103, 104, 0, 0, 0, 0,
    };
    const std::vector<std::uint32_t> column_logs = {3, 2};
    std::vector<Hash> retained(15);
    for (std::size_t node = 0; node < retained.size(); ++node) {
        for (std::uint32_t word = 0; word < 8; ++word) {
            retained[node].words[word] =
                10000u + static_cast<std::uint32_t>(node) * 101u + word;
        }
    }
    const std::vector<RetainedLayer> layers = {
        {0, 1, 0}, {1, 2, 0}, {3, 4, 0}, {7, 8, 0},
    };
    std::vector<Hash> child_hashes = {
        retained[7], retained[8], retained[13], retained[14],
    };
    const std::vector<std::uint32_t> child_indices = {0, 1, 6, 7};
    const std::vector<std::uint32_t> coordinates = {
        1, 2, 3, 4, 5, 6, 7, 8,
        11, 12, 13, 14, 15, 16, 17, 18,
        21, 22, kP, 24, 25, 26, 27, 28,
        31, 32, 33, 34, 35, 36, 37, 38,
    };
    auto *d_raw = arena.allocate<std::uint32_t>(raw.size());
    auto *d_unique = arena.allocate<std::uint32_t>(raw.size());
    auto *d_unique_count = arena.allocate<std::uint32_t>(1);
    auto *d_assembly = arena.allocate<std::uint32_t>(1024);
    auto *d_mapped = arena.allocate<std::uint32_t>(raw.size());
    auto *d_mapped_count = arena.allocate<std::uint32_t>(1);
    auto *d_trace_walk = arena.allocate<std::uint32_t>(8);
    auto *d_trace_walk_count = arena.allocate<std::uint32_t>(1);
    auto *d_leaves = arena.allocate<std::uint32_t>(8);
    auto *d_leaf_count = arena.allocate<std::uint32_t>(1);
    auto *d_columns = arena.allocate<std::uint32_t>(columns.size());
    auto *d_column_logs = arena.allocate<std::uint32_t>(column_logs.size());
    auto *d_child_indices = arena.allocate<std::uint32_t>(child_indices.size());
    auto *d_child_hashes = arena.allocate<Hash>(child_hashes.size());
    auto *d_child_count = arena.allocate<std::uint32_t>(1);
    auto *d_parent_indices = arena.allocate<std::uint32_t>(2);
    auto *d_parent_hashes = arena.allocate<Hash>(2);
    auto *d_parent_count = arena.allocate<std::uint32_t>(1);
    auto *d_trace_scratch = arena.allocate<std::uint32_t>(8);
    auto *d_retained = arena.allocate<Hash>(retained.size());
    auto *d_layers = arena.allocate<RetainedLayer>(layers.size());
    auto *d_fri_queries = arena.allocate<std::uint32_t>(raw.size());
    auto *d_fri_query_count = arena.allocate<std::uint32_t>(1);
    auto *d_expanded = arena.allocate<std::uint32_t>(8);
    auto *d_expanded_count = arena.allocate<std::uint32_t>(1);
    auto *d_fri_walk = arena.allocate<std::uint32_t>(8);
    auto *d_fri_walk_count = arena.allocate<std::uint32_t>(1);
    auto *d_fri_scratch = arena.allocate<std::uint32_t>(8);
    auto *d_coordinates = arena.allocate<std::uint32_t>(coordinates.size());
    if (d_coordinates == nullptr ||
        !arena.upload(d_raw, raw) ||
        !arena.upload(d_columns, columns) ||
        !arena.upload(d_column_logs, column_logs) ||
        !arena.upload(d_child_indices, child_indices) ||
        !arena.upload(d_child_hashes, child_hashes) ||
        !arena.upload(d_child_count, std::vector<std::uint32_t>{4}) ||
        !arena.upload(d_retained, retained) ||
        !arena.upload(d_layers, layers) ||
        !arena.upload(d_coordinates, coordinates)) {
        return false;
    }

    if (!check(stwo_decommit_normalize_queries_on(
            d_raw, 4, 3, 2, d_unique, d_unique_count,
            d_assembly, 1024, arena.stream), "normalize") ||
        !check(stwo_decommit_prepare_trace_queries_on(
            d_unique, d_unique_count, 4, 3, 3, 3, 1, d_mapped,
            d_mapped_count, d_trace_walk, d_trace_walk_count, d_leaves, 8,
            d_leaf_count, arena.stream), "prepare trace") ||
        !check(stwo_decommit_pack_trace_group_on(
            0, 2, 0, 2, d_columns, 8, 16, d_column_logs, 3,
            d_mapped, d_mapped_count, 4, d_assembly, 1024, arena.stream),
            "pack trace") ||
        !check(stwo_decommit_sparse_parent_on(
            d_child_indices, d_child_hashes, d_child_count, 4,
            d_parent_indices, d_parent_hashes, 2, d_parent_count, arena.stream),
            "sparse parent") ||
        !check(stwo_decommit_assemble_trace_on(
            0, 9, 3, 3, 2, d_mapped_count, 4, d_trace_walk,
            d_trace_scratch, d_trace_walk_count, 8, d_retained, 15,
            d_layers, 4, nullptr, nullptr, 0, nullptr, nullptr, 0,
            d_assembly, 1024, arena.stream), "assemble trace") ||
        !check(stwo_decommit_prepare_fri_queries_on(
            d_unique, d_unique_count, 4, 0, 1, 1, d_fri_queries,
            d_fri_query_count, d_expanded, 8, d_expanded_count,
            d_fri_walk, 8, d_fri_walk_count, arena.stream), "prepare FRI") ||
        !check(stwo_decommit_assemble_fri_on(
            1, 2, d_fri_queries, d_fri_query_count, 4, d_expanded,
            d_expanded_count, 8, d_coordinates, 8, 32, d_fri_walk,
            d_fri_scratch, d_fri_walk_count, 8, d_retained, 15,
            d_layers, 4, d_assembly, 1024, arena.stream), "assemble FRI")) {
        return false;
    }

    if (!expect_invalid(stwo_decommit_normalize_queries_on(
            d_raw, 257, 3, 2, d_unique, d_unique_count,
            d_assembly, 1024, arena.stream), "query admission") ||
        !expect_invalid(stwo_decommit_prepare_trace_queries_on(
            d_unique, d_unique_count, 4, 3, 3, 3, 1, d_mapped,
            d_mapped_count, d_trace_walk, d_trace_walk_count, d_leaves, 7,
            d_leaf_count, arena.stream), "leaf capacity") ||
        !expect_invalid(stwo_decommit_sparse_parent_on(
            d_child_indices, d_child_hashes, d_child_count, 4,
            d_parent_indices, d_parent_hashes, 1, d_parent_count, arena.stream),
            "parent capacity") ||
        !expect_invalid(stwo_decommit_pack_trace_group_on(
            0, 2, 0, 2, d_assembly, 8, 16, d_column_logs, 3,
            d_mapped, d_mapped_count, 4, d_assembly, 1024, arena.stream),
            "assembly alias") ||
        !expect_invalid(stwo_decommit_assemble_fri_on(
            1, 2, d_fri_queries, d_fri_query_count, 4, d_expanded,
            d_expanded_count, 8, d_coordinates, 8, 32, d_fri_walk,
            d_fri_scratch, d_fri_walk_count, 8, d_retained, 15,
            d_layers, 2, d_assembly, 1024, arena.stream),
            "retained shape")) {
        return false;
    }

    std::vector<std::uint32_t> actual_assembly(1024);
    std::vector<std::uint32_t> actual_unique(4);
    std::vector<std::uint32_t> actual_mapped(4);
    std::vector<std::uint32_t> actual_leaves(8);
    std::vector<std::uint32_t> counts(6);
    std::vector<std::uint32_t> actual_parents(2);
    std::vector<Hash> actual_parent_hashes(2);
    if (!arena.read(actual_assembly, d_assembly) ||
        !arena.read(actual_unique, d_unique) ||
        !arena.read(actual_mapped, d_mapped) ||
        !arena.read(actual_leaves, d_leaves) ||
        !arena.read(actual_parents, d_parent_indices) ||
        !arena.read(actual_parent_hashes, d_parent_hashes) ||
        !check(stwo_exec_context_memcpy_d2h_async(
            arena.context, &counts[0], d_unique_count, sizeof(std::uint32_t)),
            "read unique count") ||
        !check(stwo_exec_context_memcpy_d2h_async(
            arena.context, &counts[1], d_mapped_count, sizeof(std::uint32_t)),
            "read mapped count") ||
        !check(stwo_exec_context_memcpy_d2h_async(
            arena.context, &counts[2], d_leaf_count, sizeof(std::uint32_t)),
            "read leaf count") ||
        !check(stwo_exec_context_memcpy_d2h_async(
            arena.context, &counts[3], d_parent_count, sizeof(std::uint32_t)),
            "read parent count") ||
        !check(stwo_exec_context_memcpy_d2h_async(
            arena.context, &counts[4], d_fri_query_count, sizeof(std::uint32_t)),
            "read FRI query count") ||
        !check(stwo_exec_context_memcpy_d2h_async(
            arena.context, &counts[5], d_expanded_count, sizeof(std::uint32_t)),
            "read expanded count") ||
        !check(stwo_exec_context_sync(arena.context), "wait for result")) {
        return false;
    }

    const std::vector<std::uint32_t> expected_unique = {1, 2, 7};
    const std::vector<std::uint32_t> expected_leaves = {0, 1, 2, 3, 6, 7};
    const std::vector<std::uint32_t> expected_expanded = expected_leaves;
    const auto expected = expected_assembly(
        raw, expected_unique, columns, expected_expanded,
        coordinates, retained, layers);
    bool valid =
        counts == std::vector<std::uint32_t>({3, 3, 6, 2, 3, 6}) &&
        std::equal(expected_unique.begin(), expected_unique.end(),
                   actual_unique.begin()) &&
        std::equal(expected_unique.begin(), expected_unique.end(),
                   actual_mapped.begin()) &&
        std::equal(expected_leaves.begin(), expected_leaves.end(),
                   actual_leaves.begin()) &&
        actual_parents == std::vector<std::uint32_t>({0, 3}) &&
        equal_words(actual_assembly, expected, "decommit assembly");
    for (std::uint32_t parent = 0; parent < 2; ++parent) {
        const Hash reference = blake2s_reference::hash_children(
            child_hashes[2 * parent], child_hashes[2 * parent + 1]);
        valid = valid &&
            blake2s_reference::equal(actual_parent_hashes[parent], reference);
    }

    const std::vector<std::uint32_t> invalid_unique = {2, 1, 7, 0};
    const std::vector<std::uint32_t> invalid_children = {0, 2, 4, 5};
    if (!arena.upload(d_unique, invalid_unique) ||
        !arena.upload(d_unique_count, std::vector<std::uint32_t>{3}) ||
        !arena.upload(d_child_indices, invalid_children) ||
        !check(stwo_decommit_prepare_trace_queries_on(
            d_unique, d_unique_count, 4, 3, 3, 3, 1, d_mapped,
            d_mapped_count, d_trace_walk, d_trace_walk_count, d_leaves, 8,
            d_leaf_count, arena.stream), "invalid query topology") ||
        !check(stwo_decommit_sparse_parent_on(
            d_child_indices, d_child_hashes, d_child_count, 4,
            d_parent_indices, d_parent_hashes, 2, d_parent_count, arena.stream),
            "invalid sparse topology") ||
        !check(stwo_exec_context_memcpy_d2h_async(
            arena.context, &counts[1], d_mapped_count, sizeof(std::uint32_t)),
            "read invalid mapped count") ||
        !check(stwo_exec_context_memcpy_d2h_async(
            arena.context, &counts[3], d_parent_count, sizeof(std::uint32_t)),
            "read invalid parent count") ||
        !check(stwo_exec_context_sync(arena.context), "wait invalid topology")) {
        return false;
    }
    return valid && counts[1] == 0 && counts[3] == 0;
}

}  // namespace

int main() {
    DeviceArena arena;
    if (!check(stwo_exec_context_create(&arena.context), "create context") ||
        !check(
            stwo_exec_context_stream(arena.context, &arena.stream),
            "query stream")) {
        return 1;
    }
    if (!run(arena) || !arena.close()) return 1;
    std::puts("Native CUDA decommit differential passed");
    return 0;
}
