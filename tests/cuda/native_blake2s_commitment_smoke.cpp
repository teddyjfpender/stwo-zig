#include "blake2s_reference.h"
#include "../../src/backends/cuda/native/commitment/blake2s_domain_states.h"

#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

using Hash = blake2s_reference::Hash;

extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);
extern "C" int stwo_exec_context_sync(void *handle);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
extern "C" int stwo_exec_context_alloc_u32(
    void *handle, std::size_t count, std::uint32_t **out_pointer);
extern "C" int stwo_exec_context_free_u32(
    void *handle, std::uint32_t *pointer);
extern "C" int stwo_exec_context_memcpy_h2d_async(
    void *handle, void *destination, const void *source, std::size_t bytes);
extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *handle, void *destination, const void *source, std::size_t bytes);
extern "C" int stwo_blake2s_progressive_init_on(
    std::uint32_t size, void *states, void *stream);
extern "C" int stwo_blake2s_progressive_absorb_on(
    std::uint32_t size,
    std::uint32_t absorbed_before,
    const std::uint32_t *columns,
    std::size_t column_stride_words,
    std::size_t column_capacity_words,
    void *states,
    void *stream);
extern "C" int stwo_blake2s_progressive_finalize_on(
    std::uint32_t size,
    std::uint32_t absorbed_columns,
    const void *states,
    Hash *result,
    void *stream);
extern "C" int stwo_blake2s_contiguous_leaf_on(
    std::uint32_t size,
    const std::uint32_t *columns,
    std::size_t column_stride_words,
    std::size_t column_capacity_words,
    Hash *result,
    void *stream);
extern "C" int stwo_blake2s_contiguous_tail_on(
    const Hash *previous,
    std::uint32_t previous_size,
    Hash *outputs,
    std::size_t output_capacity,
    std::uint32_t level_count,
    void *stream);
extern "C" int stwo_blake2s_layer_on(
    const Hash *previous, std::uint32_t output_size, Hash *result, void *stream);
extern "C" int stwo_blake2s_interior4_on(
    const Hash *previous, std::uint32_t output_size, Hash *result, void *stream);
extern "C" int stwo_blake2s_fri_leaf_on(
    std::uint32_t evaluation_size,
    const std::uint32_t *coordinates,
    std::size_t coordinate_stride_words,
    std::size_t coordinate_capacity_words,
    std::uint32_t log_rows_per_leaf,
    Hash *result,
    void *stream);

namespace {

bool check(int status, const char *operation) {
    if (status == 0) return true;
    std::fprintf(
        stderr, "%s: %s\n", operation,
        cudaGetErrorString(static_cast<cudaError_t>(status)));
    return false;
}

struct DeviceArena {
    void *context = nullptr;
    void *stream = nullptr;
    std::vector<std::uint32_t *> allocations;

    std::uint32_t *allocate(std::size_t words) {
        std::uint32_t *pointer = nullptr;
        if (!check(
                stwo_exec_context_alloc_u32(context, words, &pointer),
                "allocate")) {
            return nullptr;
        }
        allocations.push_back(pointer);
        return pointer;
    }

    bool upload(void *destination, const void *source, std::size_t bytes) {
        return check(
            stwo_exec_context_memcpy_h2d_async(
                context, destination, source, bytes),
            "upload");
    }

    bool read(void *destination, const void *source, std::size_t bytes) {
        return check(
            stwo_exec_context_memcpy_d2h_async(
                context, destination, source, bytes),
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

bool expect_hash(
    const Hash &actual,
    const Hash &expected,
    const char *stage,
    std::uint32_t index) {
    if (blake2s_reference::equal(actual, expected)) return true;
    std::fprintf(stderr, "%s hash mismatch at %u\n", stage, index);
    for (std::uint32_t word : actual.words) {
        std::fprintf(stderr, "%08x", word);
    }
    std::fprintf(stderr, " actual words\n");
    for (std::uint32_t word : expected.words) {
        std::fprintf(stderr, "%08x", word);
    }
    std::fprintf(stderr, " expected words\n");
    return false;
}

bool test_pinned_zig_oracles() {
    const auto expect_domain_state = [](
        std::uint32_t tag,
        const stwo::cuda::blake2s::DomainState &precomputed,
        const char *name) {
        const Hash reference = blake2s_reference::domain_state(tag);
        for (std::uint32_t index = 0; index < 8; ++index) {
            if (reference.words[index] == precomputed.words[index]) continue;
            std::fprintf(
                stderr,
                "%s domain state mismatch at %u: %08x != %08x\n",
                name,
                index,
                precomputed.words[index],
                reference.words[index]);
            return false;
        }
        return true;
    };
    if (!expect_domain_state(
            0x6661656cu,
            stwo::cuda::blake2s::kLeafInitialState,
            "leaf") ||
        !expect_domain_state(
            0x65646f6eu,
            stwo::cuda::blake2s::kNodeInitialState,
            "node")) {
        return false;
    }

    const Hash empty_expected{{
        0x153e132au, 0x19723802u, 0x77ead121u, 0x9c978228u,
        0xf2850f81u, 0xb9999084u, 0x865a41d3u, 0xad5fd819u,
    }};
    if (!expect_hash(
            blake2s_reference::hash_leaf_words({}),
            empty_expected,
            "pinned Zig empty leaf",
            0)) {
        return false;
    }

    Hash left{};
    Hash right{};
    for (std::uint32_t &word : left.words) word = 0x01010101u;
    for (std::uint32_t &word : right.words) word = 0x02020202u;
    const Hash parent_expected{{
        0x4762c324u, 0xb1c76cc6u, 0x9ce7ae45u, 0xe3d5f9cfu,
        0xe1a896e5u, 0x39d1863eu, 0x6414f642u, 0x3ca54f36u,
    }};
    return expect_hash(
        blake2s_reference::hash_children(left, right),
        parent_expected,
        "pinned Zig parent",
        0);
}

bool test_progressive(DeviceArena &arena) {
    constexpr std::uint32_t kRows = 8;
    constexpr std::uint32_t kMaxColumns = 257;
    constexpr std::uint32_t kTreeHashes = 2 * kRows - 1;
    constexpr std::size_t kStride = kRows + 5;
    const std::uint32_t widths[] = {
        1, 15, 16, 17, 31, 32, 33, 37, 64, 73, 100, 128, 257,
    };

    std::vector<std::uint32_t> host_columns(
        kMaxColumns * kStride, 0xa5a5a5a5u);
    for (std::uint32_t column = 0; column < kMaxColumns; ++column) {
        for (std::uint32_t row = 0; row < kRows; ++row) {
            host_columns[column * kStride + row] =
                1009u * column + 17u * row + 3u;
        }
    }
    auto *device_columns = arena.allocate(host_columns.size());
    auto *states = arena.allocate(kRows * 24);
    auto *progressive_tree =
        reinterpret_cast<Hash *>(arena.allocate(kTreeHashes * 8));
    auto *direct_tree =
        reinterpret_cast<Hash *>(arena.allocate(kTreeHashes * 8));
    if (device_columns == nullptr || states == nullptr ||
        progressive_tree == nullptr || direct_tree == nullptr ||
        !arena.upload(
            device_columns,
            host_columns.data(),
            host_columns.size() * sizeof(std::uint32_t))) {
        return false;
    }

    if (stwo_blake2s_progressive_absorb_on(
            kRows,
            0,
            device_columns,
            kStride,
            2 * kStride - 1,
            states,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "progressive accepted undersized source slab\n");
        return false;
    }
    if (stwo_blake2s_progressive_absorb_on(
            kRows,
            0,
            device_columns,
            kRows - 1,
            4 * (kRows - 1),
            states,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "progressive accepted a short column stride\n");
        return false;
    }
    if (stwo_blake2s_progressive_absorb_on(
            kRows,
            0,
            states,
            kRows,
            kRows,
            states,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "progressive accepted aliased state and source\n");
        return false;
    }
    if (stwo_blake2s_progressive_absorb_on(
            kRows,
            UINT32_MAX,
            device_columns,
            kStride,
            2 * kStride,
            states,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "progressive accepted an absorbed-count overflow\n");
        return false;
    }
    if (stwo_blake2s_progressive_absorb_on(
            kRows,
            0,
            device_columns,
            kStride,
            kStride,
            states,
            nullptr) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "progressive accepted a null proof stream\n");
        return false;
    }
    if (stwo_blake2s_progressive_finalize_on(
            kRows,
            1,
            states,
            reinterpret_cast<Hash *>(states),
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "progressive finalize accepted aliased buffers\n");
        return false;
    }
    if (stwo_blake2s_contiguous_leaf_on(
            kRows,
            device_columns,
            kStride,
            2 * kStride - 1,
            direct_tree,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "direct leaf accepted undersized source slab\n");
        return false;
    }
    if (stwo_blake2s_contiguous_leaf_on(
            kRows,
            device_columns,
            kRows - 1,
            4 * (kRows - 1),
            direct_tree,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "direct leaf accepted a short column stride\n");
        return false;
    }
    if (stwo_blake2s_contiguous_leaf_on(
            kRows,
            reinterpret_cast<std::uint32_t *>(direct_tree),
            kRows,
            kRows,
            direct_tree,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "direct leaf accepted aliased source and output\n");
        return false;
    }
    if (stwo_blake2s_contiguous_leaf_on(
            kRows,
            device_columns,
            kStride,
            kStride,
            direct_tree,
            nullptr) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "direct leaf accepted a null proof stream\n");
        return false;
    }

    for (std::uint32_t width : widths) {
        if (!check(
                stwo_blake2s_progressive_init_on(
                    kRows, states, arena.stream),
                "progressive init")) {
            return false;
        }
        const std::uint32_t first = width > 7 ? 7 : width;
        if (!check(
                stwo_blake2s_progressive_absorb_on(
                    kRows,
                    0,
                    device_columns,
                    kStride,
                    first * kStride,
                    states,
                    arena.stream),
                "progressive first absorb")) {
            return false;
        }
        if (first != width &&
            !check(
                stwo_blake2s_progressive_absorb_on(
                    kRows,
                    first,
                    device_columns + first * kStride,
                    kStride,
                    (width - first) * kStride,
                    states,
                    arena.stream),
                "progressive second absorb")) {
            return false;
        }
        if (!check(
                stwo_blake2s_progressive_finalize_on(
                    kRows, width, states, progressive_tree, arena.stream),
                "progressive finalize")) {
            return false;
        }
        if (!check(
                stwo_blake2s_contiguous_leaf_on(
                    kRows,
                    device_columns,
                    kStride,
                    width * kStride,
                    direct_tree,
                    arena.stream),
                "direct leaf")) {
            return false;
        }

        std::uint32_t input_offset = 0;
        std::uint32_t input_size = kRows;
        std::uint32_t output_offset = kRows;
        while (input_size > 1) {
            const std::uint32_t output_size = input_size / 2;
            if (!check(
                    stwo_blake2s_layer_on(
                        progressive_tree + input_offset,
                        output_size,
                        progressive_tree + output_offset,
                        arena.stream),
                    "progressive tree layer") ||
                !check(
                    stwo_blake2s_layer_on(
                        direct_tree + input_offset,
                        output_size,
                        direct_tree + output_offset,
                        arena.stream),
                    "direct tree layer")) {
                return false;
            }
            input_offset = output_offset;
            input_size = output_size;
            output_offset += output_size;
        }

        std::vector<Hash> progressive(kTreeHashes);
        std::vector<Hash> direct(kTreeHashes);
        if (!arena.read(
                progressive.data(),
                progressive_tree,
                progressive.size() * sizeof(Hash)) ||
            !arena.read(
                direct.data(),
                direct_tree,
                direct.size() * sizeof(Hash)) ||
            !check(stwo_exec_context_sync(arena.context), "wait leaf trees")) {
            return false;
        }
        for (std::uint32_t index = 0; index < kTreeHashes; ++index) {
            if (!expect_hash(
                    direct[index],
                    progressive[index],
                    "direct-progressive tree",
                    index)) {
                return false;
            }
        }
        for (std::uint32_t row = 0; row < kRows; ++row) {
            std::vector<std::uint32_t> words;
            for (std::uint32_t column = 0; column < width; ++column) {
                words.push_back(host_columns[column * kStride + row]);
            }
            if (!expect_hash(
                    direct[row],
                    blake2s_reference::hash_leaf_words(words),
                    "direct leaf",
                    row)) {
                return false;
            }
        }
    }
    return true;
}

bool test_merkle_and_fri(DeviceArena &arena) {
    constexpr std::uint32_t kEvaluationSize = 16;
    constexpr std::size_t kCoordinateStride = kEvaluationSize + 7;
    std::vector<std::uint32_t> coordinates(
        4 * kCoordinateStride, 0x5a5a5a5au);
    for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
        for (std::uint32_t row = 0; row < kEvaluationSize; ++row) {
            coordinates[coordinate * kCoordinateStride + row] =
                257u * coordinate + 11u * row + 5u;
        }
    }
    auto *device_coordinates = arena.allocate(coordinates.size());
    auto *leaves = reinterpret_cast<Hash *>(arena.allocate(kEvaluationSize * 8));
    if (device_coordinates == nullptr || leaves == nullptr ||
        !arena.upload(
            device_coordinates,
            coordinates.data(),
            coordinates.size() * sizeof(std::uint32_t))) {
        return false;
    }
    if (stwo_blake2s_fri_leaf_on(
            kEvaluationSize,
            device_coordinates,
            kCoordinateStride,
            3 * kCoordinateStride,
            0,
            leaves,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "FRI leaf accepted undersized coordinate slab\n");
        return false;
    }
    if (stwo_blake2s_fri_leaf_on(
            kEvaluationSize,
            device_coordinates,
            kEvaluationSize - 1,
            4 * (kEvaluationSize - 1),
            0,
            leaves,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "FRI leaf accepted a short coordinate stride\n");
        return false;
    }
    if (stwo_blake2s_fri_leaf_on(
            kEvaluationSize,
            device_coordinates,
            kCoordinateStride,
            coordinates.size(),
            0,
            reinterpret_cast<Hash *>(device_coordinates),
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "FRI leaf accepted aliased coordinates/output\n");
        return false;
    }
    for (std::uint32_t log_rows : {0u, 2u}) {
        const std::uint32_t leaf_count = kEvaluationSize >> log_rows;
        if (!check(
                stwo_blake2s_fri_leaf_on(
                    kEvaluationSize,
                    device_coordinates,
                    kCoordinateStride,
                    coordinates.size(),
                    log_rows,
                    leaves,
                    arena.stream),
                "FRI leaf")) {
            return false;
        }
        std::vector<Hash> actual(leaf_count);
        if (!arena.read(actual.data(), leaves, leaf_count * sizeof(Hash)) ||
            !check(stwo_exec_context_sync(arena.context), "wait FRI leaves")) {
            return false;
        }
        for (std::uint32_t leaf = 0; leaf < leaf_count; ++leaf) {
            std::vector<std::uint32_t> words;
            const std::uint32_t rows = 1u << log_rows;
            for (std::uint32_t offset = 0; offset < rows; ++offset) {
                for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
                    words.push_back(
                        coordinates[
                            coordinate * kCoordinateStride +
                            rows * leaf +
                            offset]);
                }
            }
            if (!expect_hash(
                    actual[leaf],
                    blake2s_reference::hash_leaf_words(words),
                    "FRI",
                    leaf)) {
                return false;
            }
        }
    }

    std::vector<Hash> children(32);
    for (std::uint32_t index = 0; index < children.size(); ++index) {
        children[index] =
            blake2s_reference::hash_leaf_words({index, index * 3 + 1});
    }
    auto *device_children =
        reinterpret_cast<Hash *>(arena.allocate(children.size() * 8));
    auto *device_parents =
        reinterpret_cast<Hash *>(arena.allocate(children.size() / 2 * 8));
    if (device_children == nullptr || device_parents == nullptr ||
        !arena.upload(
            device_children, children.data(), children.size() * sizeof(Hash))) {
        return false;
    }
    if (stwo_blake2s_layer_on(
            device_children, 16, device_children, arena.stream) ==
        static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "Merkle layer accepted overlapping buffers\n");
        return false;
    }
    if (!check(
            stwo_blake2s_layer_on(
                device_children, 16, device_parents, arena.stream),
            "Merkle layer")) {
        return false;
    }
    std::vector<Hash> parents(16);
    if (!arena.read(
            parents.data(), device_parents, parents.size() * sizeof(Hash)) ||
        !check(stwo_exec_context_sync(arena.context), "wait Merkle layer")) {
        return false;
    }
    for (std::uint32_t index = 0; index < parents.size(); ++index) {
        if (!expect_hash(
                parents[index],
                blake2s_reference::hash_children(
                    children[2 * index], children[2 * index + 1]),
                "Merkle",
                index)) {
            return false;
        }
    }

    auto *device_roots = reinterpret_cast<Hash *>(arena.allocate(2 * 8));
    if (device_roots == nullptr ||
        !check(
            stwo_blake2s_interior4_on(
                device_children, 2, device_roots, arena.stream),
            "interior4")) {
        return false;
    }
    std::vector<Hash> roots(2);
    if (!arena.read(roots.data(), device_roots, roots.size() * sizeof(Hash)) ||
        !check(stwo_exec_context_sync(arena.context), "wait interior4")) {
        return false;
    }
    std::vector<Hash> reduced = children;
    for (int level = 0; level < 4; ++level) {
        std::vector<Hash> next(reduced.size() / 2);
        for (std::size_t index = 0; index < next.size(); ++index) {
            next[index] = blake2s_reference::hash_children(
                reduced[2 * index], reduced[2 * index + 1]);
        }
        reduced = std::move(next);
    }
    for (std::uint32_t index = 0; index < roots.size(); ++index) {
        if (!expect_hash(roots[index], reduced[index], "interior4", index)) {
            return false;
        }
    }

    constexpr std::uint32_t kTailLevels = 5;
    constexpr std::uint32_t kTailInputHashes = 32;
    constexpr std::size_t kTailHashes = kTailInputHashes - 1;
    auto *device_tail =
        reinterpret_cast<Hash *>(arena.allocate(kTailHashes * 8));
    if (device_tail == nullptr) return false;
    if (stwo_blake2s_contiguous_tail_on(
            device_children,
            kTailInputHashes,
            device_tail,
            kTailHashes - 1,
            kTailLevels,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "Merkle tail accepted an undersized output\n");
        return false;
    }
    if (stwo_blake2s_contiguous_tail_on(
            device_children,
            kTailInputHashes,
            device_children,
            kTailHashes,
            kTailLevels,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "Merkle tail accepted overlapping buffers\n");
        return false;
    }
    if (stwo_blake2s_contiguous_tail_on(
            device_children,
            kTailInputHashes,
            device_tail,
            0,
            0,
            arena.stream) == static_cast<int>(cudaSuccess) ||
        stwo_blake2s_contiguous_tail_on(
            device_children,
            kTailInputHashes,
            device_tail,
            kTailHashes,
            kTailLevels + 1,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "Merkle tail accepted an invalid depth\n");
        return false;
    }
    if (!check(
            stwo_blake2s_contiguous_tail_on(
                device_children,
                kTailInputHashes,
                device_tail,
                kTailHashes,
                kTailLevels,
                arena.stream),
            "Merkle tail")) {
        return false;
    }
    std::vector<Hash> tail(kTailHashes);
    if (!arena.read(tail.data(), device_tail, tail.size() * sizeof(Hash)) ||
        !check(stwo_exec_context_sync(arena.context), "wait Merkle tail")) {
        return false;
    }
    std::vector<Hash> previous = children;
    std::size_t tail_offset = 0;
    while (previous.size() > 1) {
        std::vector<Hash> next(previous.size() / 2);
        for (std::size_t index = 0; index < next.size(); ++index) {
            next[index] = blake2s_reference::hash_children(
                previous[2 * index], previous[2 * index + 1]);
            if (!expect_hash(
                    tail[tail_offset + index],
                    next[index],
                    "Merkle tail",
                    tail_offset + index)) {
                return false;
            }
        }
        tail_offset += next.size();
        previous = std::move(next);
    }
    if (tail_offset != kTailHashes) {
        std::fprintf(stderr, "Merkle tail reference has the wrong size\n");
        return false;
    }
    return true;
}

}  // namespace

int main() {
    DeviceArena arena;
    if (!check(stwo_exec_context_create(&arena.context), "create context") ||
        !check(
            stwo_exec_context_stream(arena.context, &arena.stream),
            "get proof stream")) {
        return 1;
    }
    if (!test_pinned_zig_oracles() || !test_progressive(arena) ||
        !test_merkle_and_fri(arena) ||
        !arena.close()) {
        return 1;
    }
    std::printf("native CUDA Blake2s commitment smoke passed\n");
    return 0;
}
