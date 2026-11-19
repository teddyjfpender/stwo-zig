#include "transcript_reference.h"

#include <cuda_runtime_api.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

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

extern "C" int stwo_blake2s_transcript_init_on(
    std::uint32_t *, const std::uint32_t *, std::uint32_t *,
    std::uint64_t, void *);
extern "C" int stwo_blake2s_transcript_mix_words_on(
    std::uint32_t *, std::uint32_t, std::uint64_t, std::uint64_t,
    const std::uint32_t *, std::uint32_t, std::uint32_t,
    std::uint32_t *, std::uint32_t *, void *);
extern "C" int stwo_blake2s_transcript_mix_words_pair_on(
    std::uint32_t *, std::uint32_t, std::uint64_t, std::uint64_t,
    const std::uint32_t *, std::uint32_t, const std::uint32_t *,
    std::uint32_t, std::uint32_t, std::uint32_t *, std::uint32_t *, void *);
extern "C" int stwo_blake2s_transcript_absorb_pow_on(
    std::uint32_t *, std::uint32_t, std::uint64_t, std::uint64_t,
    const std::uint32_t *, std::uint32_t, std::uint32_t *,
    std::uint32_t *, void *);
extern "C" int stwo_blake2s_transcript_draw_u32s_on(
    std::uint32_t *, std::uint32_t, std::uint64_t, std::uint64_t,
    std::uint32_t *, std::uint32_t *, std::uint32_t *, void *);
extern "C" int stwo_blake2s_transcript_draw_secure_on(
    std::uint32_t *, std::uint32_t, std::uint64_t, std::uint64_t,
    std::uint32_t, std::uint32_t, std::uint32_t *, std::uint32_t *,
    std::uint32_t *, void *);
extern "C" int stwo_blake2s_transcript_draw_queries_on(
    std::uint32_t *, std::uint32_t, std::uint64_t, std::uint64_t,
    std::uint32_t, std::uint32_t, std::uint32_t *, std::uint32_t *,
    std::uint32_t *, void *);

namespace {

constexpr std::uint32_t kOperationCount = 8;
constexpr std::uint32_t kPowBits = 8;
constexpr std::uint32_t kSecureCount = 3;
constexpr std::uint32_t kQueryCount = 13;
constexpr std::uint32_t kLogDomainSize = 23;
constexpr std::array<std::uint64_t, kOperationCount + 1> kChains = {
    0x1020304050607080ull, 0x1121314151617181ull,
    0x1222324252627282ull, 0x1323334353637383ull,
    0x1424344454647484ull, 0x1525354555657585ull,
    0x1626364656667686ull, 0x1727374757677787ull,
    0x1828384858687888ull,
};
constexpr std::array<std::uint32_t, 12> kPinnedSecure = {
    0x6c7eba13u, 0x2e404b19u, 0x422e7270u, 0x416c78b3u,
    0x1916d16eu, 0x5f47d20eu, 0x64e46ca3u, 0x4c959b40u,
    0x2f6cafd7u, 0x4ce721d8u, 0x3fd75f94u, 0x219c91d9u,
};
constexpr std::array<std::uint32_t, 8> kPinnedRaw = {
    0x47b79d72u, 0x3a0876f4u, 0x4fcf4ed2u, 0x4340906fu,
    0x4acc43d8u, 0x8b7f2843u, 0x767cc845u, 0xda7cc3bcu,
};
constexpr std::array<std::uint32_t, kQueryCount> kPinnedQueries = {
    886089u, 7117390u, 7454939u, 5585918u, 1857695u,
    3491743u, 7866864u, 2815499u, 6401809u, 7816758u,
    3186871u, 4887186u, 2433836u,
};
constexpr std::array<std::uint32_t, 16> kPinnedFinalState = {
    0x93458da8u, 0xf7b79301u, 0x9b64ee9fu, 0xc65f8fc1u,
    0xf448640cu, 0x8fd2a8b0u, 0xfaf31f8eu, 0x4c63437eu,
    2u, 8u, 0u, 0u, 0x58687888u, 0x18283848u, 0u, 0u,
};

bool check(int status, const char *operation) {
    if (status == 0) return true;
    std::fprintf(
        stderr, "%s: status=%d (%s)\n", operation, status,
        cudaGetErrorString(static_cast<cudaError_t>(status)));
    return false;
}

struct DeviceArena {
    void *context = nullptr;
    void *stream = nullptr;
    std::vector<std::uint32_t *> allocations;

    std::uint32_t *allocate(std::size_t words) {
        std::uint32_t *result = nullptr;
        if (!check(
                stwo_exec_context_alloc_u32(context, words, &result),
                "allocate transcript words")) {
            return nullptr;
        }
        allocations.push_back(result);
        return result;
    }

    bool upload(void *destination, const void *source, std::size_t bytes) {
        return check(
            stwo_exec_context_memcpy_h2d_async(
                context, destination, source, bytes),
            "upload transcript words");
    }

    bool read(void *destination, const void *source, std::size_t bytes) {
        return check(
            stwo_exec_context_memcpy_d2h_async(
                context, destination, source, bytes),
            "read transcript words");
    }

    bool close() {
        for (std::uint32_t *allocation : allocations) {
            if (!check(
                    stwo_exec_context_free_u32(context, allocation),
                    "free transcript words")) {
                return false;
            }
        }
        return check(stwo_exec_context_sync(context), "wait for frees") &&
            check(stwo_exec_context_destroy(context), "destroy context");
    }
};

template <std::size_t N>
bool expect_words(
    const std::array<std::uint32_t, N> &actual,
    const std::array<std::uint32_t, N> &expected,
    const char *label) {
    for (std::size_t index = 0; index < N; ++index) {
        if (actual[index] != expected[index]) {
            std::fprintf(
                stderr, "%s mismatch at %zu: expected=%08x actual=%08x\n",
                label, index, expected[index], actual[index]);
            return false;
        }
    }
    return true;
}

struct Reference {
    std::vector<std::array<std::uint32_t, 16>> boundaries;
    std::array<std::uint32_t, 12> secure{};
    std::array<std::uint32_t, 8> raw{};
    std::array<std::uint32_t, kQueryCount> queries{};
    std::uint64_t nonce = 0;
};

Reference build_reference(
    const std::vector<std::uint32_t> &felts,
    const std::vector<std::uint32_t> &u32s,
    const std::vector<std::uint32_t> &u64_words,
    const std::vector<std::uint32_t> &root) {
    transcript_reference::Channel channel;
    Reference result;
    auto boundary = [&](std::uint32_t cursor) {
        result.boundaries.push_back(channel.state_words(cursor, kChains[cursor]));
    };
    channel.mix(felts);
    boundary(1);
    channel.mix(u32s);
    boundary(2);
    channel.mix(u64_words);
    boundary(3);
    channel.mix(root);
    boundary(4);

    const auto secure = channel.draw_secure(kSecureCount);
    std::copy(secure.begin(), secure.end(), result.secure.begin());
    boundary(5);
    result.raw = channel.draw_words();
    boundary(6);
    while (!channel.valid_pow(kPowBits, result.nonce)) ++result.nonce;
    channel.mix({
        static_cast<std::uint32_t>(result.nonce),
        static_cast<std::uint32_t>(result.nonce >> 32),
    });
    boundary(7);
    std::size_t produced = 0;
    const std::uint32_t mask = (1u << kLogDomainSize) - 1u;
    while (produced < result.queries.size()) {
        for (std::uint32_t word : channel.draw_words()) {
            result.queries[produced++] = word & mask;
            if (produced == result.queries.size()) break;
        }
    }
    boundary(8);
    return result;
}

}  // namespace

int main() {
    const std::vector<std::uint32_t> felts = {1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<std::uint32_t> u32s = {9, 10, 11};
    const std::vector<std::uint32_t> u64_words = {
        0xcafebabeu, 0x12345678u};
    const std::vector<std::uint32_t> root = {
        0x10203040u, 0x10203041u, 0x10203042u, 0x10203043u,
        0x10203044u, 0x10203045u, 0x10203046u, 0x10203047u,
    };
    const Reference reference = build_reference(felts, u32s, u64_words, root);
    if (reference.nonce != 477 ||
        !expect_words(reference.secure, kPinnedSecure, "CPU secure vector") ||
        !expect_words(reference.raw, kPinnedRaw, "CPU raw vector") ||
        !expect_words(reference.queries, kPinnedQueries, "CPU query vector") ||
        !expect_words(
            reference.boundaries.back(), kPinnedFinalState,
            "CPU final state vector")) {
        return 1;
    }

    DeviceArena arena;
    if (!check(stwo_exec_context_create(&arena.context), "create context") ||
        !check(
            stwo_exec_context_stream(arena.context, &arena.stream),
            "get proof stream")) {
        return 1;
    }
    if (stwo_blake2s_transcript_init_on(
            nullptr, nullptr, nullptr, kChains[0], arena.stream) ==
        static_cast<int>(cudaSuccess)) {
        std::fprintf(stderr, "transcript accepted a null resident state\n");
        return 1;
    }

    auto *state = arena.allocate(16);
    auto *input = arena.allocate(23);
    auto *input_snapshot = arena.allocate(23);
    auto *boundaries = arena.allocate(kOperationCount * 16);
    auto *secure = arena.allocate(kPinnedSecure.size());
    auto *secure_snapshot = arena.allocate(kPinnedSecure.size());
    auto *raw = arena.allocate(kPinnedRaw.size());
    auto *raw_snapshot = arena.allocate(kPinnedRaw.size());
    auto *queries = arena.allocate(kPinnedQueries.size());
    auto *query_snapshot = arena.allocate(kPinnedQueries.size());
    auto *seed = arena.allocate(9);
    auto *seed_snapshot = arena.allocate(9);
    auto *pair_state = arena.allocate(16);
    auto *pair_input_snapshot = arena.allocate(5);
    auto *pair_boundary = arena.allocate(16);
    if (state == nullptr || input == nullptr || input_snapshot == nullptr ||
        boundaries == nullptr || secure == nullptr ||
        secure_snapshot == nullptr || raw == nullptr ||
        raw_snapshot == nullptr || queries == nullptr ||
        query_snapshot == nullptr || seed == nullptr ||
        seed_snapshot == nullptr || pair_state == nullptr ||
        pair_input_snapshot == nullptr || pair_boundary == nullptr) {
        return 1;
    }

    std::vector<std::uint32_t> host_input;
    host_input.insert(host_input.end(), felts.begin(), felts.end());
    host_input.insert(host_input.end(), u32s.begin(), u32s.end());
    host_input.insert(host_input.end(), u64_words.begin(), u64_words.end());
    host_input.insert(host_input.end(), root.begin(), root.end());
    host_input.push_back(static_cast<std::uint32_t>(reference.nonce));
    host_input.push_back(static_cast<std::uint32_t>(reference.nonce >> 32));
    if (!arena.upload(
            input, host_input.data(),
            host_input.size() * sizeof(std::uint32_t)) ||
        !check(
            stwo_blake2s_transcript_init_on(
                state, nullptr, nullptr, kChains[0], arena.stream),
            "initialize transcript") ||
        !check(
            stwo_blake2s_transcript_mix_words_on(
                state, 0, kChains[0], kChains[1], input, 8, 1,
                input_snapshot, boundaries, arena.stream),
            "mix secure fields") ||
        !check(
            stwo_blake2s_transcript_mix_words_on(
                state, 1, kChains[1], kChains[2], input + 8, 3, 0,
                input_snapshot + 8, boundaries + 16, arena.stream),
            "mix u32 words") ||
        !check(
            stwo_blake2s_transcript_mix_words_on(
                state, 2, kChains[2], kChains[3], input + 11, 2, 0,
                input_snapshot + 11, boundaries + 32, arena.stream),
            "mix u64") ||
        !check(
            stwo_blake2s_transcript_mix_words_on(
                state, 3, kChains[3], kChains[4], input + 13, 8, 0,
                input_snapshot + 13, boundaries + 48, arena.stream),
            "mix Merkle root") ||
        !check(
            stwo_blake2s_transcript_draw_secure_on(
                state, 4, kChains[4], kChains[5], kSecureCount, 64,
                secure, secure_snapshot, boundaries + 64, arena.stream),
            "draw secure fields") ||
        !check(
            stwo_blake2s_transcript_draw_u32s_on(
                state, 5, kChains[5], kChains[6], raw, raw_snapshot,
                boundaries + 80, arena.stream),
            "draw raw words") ||
        !check(
            stwo_blake2s_transcript_absorb_pow_on(
                state, 6, kChains[6], kChains[7], input + 21, kPowBits,
                input_snapshot + 21, boundaries + 96, arena.stream),
            "validate and mix PoW nonce") ||
        !check(
            stwo_blake2s_transcript_draw_queries_on(
                state, 7, kChains[7], kChains[8], kLogDomainSize,
                kQueryCount, queries, query_snapshot, boundaries + 112,
                arena.stream),
            "draw queries")) {
        return 1;
    }

    transcript_reference::Channel pair_reference;
    pair_reference.mix(u32s);
    pair_reference.mix(u64_words);
    const auto pair_expected = pair_reference.state_words(1, kChains[1]);
    if (!check(
            stwo_blake2s_transcript_init_on(
                pair_state, nullptr, nullptr, kChains[0], arena.stream),
            "initialize paired transcript")) {
        return 1;
    }
    if (stwo_blake2s_transcript_mix_words_pair_on(
            pair_state, 0, kChains[0], kChains[1], input + 8, 0,
            input + 11, 2, 0, pair_input_snapshot, pair_boundary,
            arena.stream) == static_cast<int>(cudaSuccess) ||
        stwo_blake2s_transcript_mix_words_pair_on(
            pair_state, 0, kChains[0], kChains[1], input + 8, 3,
            input + 10, 2, 0, pair_input_snapshot, pair_boundary,
            arena.stream) == static_cast<int>(cudaSuccess) ||
        stwo_blake2s_transcript_mix_words_pair_on(
            pair_state, 0, kChains[0], kChains[1], input + 8, UINT32_MAX,
            input + 11, 2, 0, pair_input_snapshot, pair_boundary,
            arena.stream) == static_cast<int>(cudaSuccess)) {
        std::fprintf(
            stderr,
            "paired transcript accepted an empty, overlapping, or invalid split\n");
        return 1;
    }
    if (!check(
            stwo_blake2s_transcript_mix_words_pair_on(
                pair_state, 0, kChains[0], kChains[1], input + 8, 3,
                input + 11, 2, 0, pair_input_snapshot, pair_boundary,
                arena.stream),
            "mix paired transcript words")) {
        return 1;
    }

    std::array<std::uint32_t, 16> actual_state{};
    std::array<std::uint32_t, kOperationCount * 16> actual_boundaries{};
    std::array<std::uint32_t, 23> actual_input_snapshot{};
    std::array<std::uint32_t, kPinnedSecure.size()> actual_secure{};
    std::array<std::uint32_t, kPinnedSecure.size()> actual_secure_snapshot{};
    std::array<std::uint32_t, kPinnedRaw.size()> actual_raw{};
    std::array<std::uint32_t, kPinnedRaw.size()> actual_raw_snapshot{};
    std::array<std::uint32_t, kPinnedQueries.size()> actual_queries{};
    std::array<std::uint32_t, kPinnedQueries.size()> actual_query_snapshot{};
    std::array<std::uint32_t, 16> actual_pair_state{};
    std::array<std::uint32_t, 16> actual_pair_boundary{};
    std::array<std::uint32_t, 5> actual_pair_input{};
    if (!arena.read(actual_state.data(), state, sizeof(actual_state)) ||
        !arena.read(
            actual_boundaries.data(), boundaries, sizeof(actual_boundaries)) ||
        !arena.read(
            actual_input_snapshot.data(), input_snapshot,
            sizeof(actual_input_snapshot)) ||
        !arena.read(actual_secure.data(), secure, sizeof(actual_secure)) ||
        !arena.read(
            actual_secure_snapshot.data(), secure_snapshot,
            sizeof(actual_secure_snapshot)) ||
        !arena.read(actual_raw.data(), raw, sizeof(actual_raw)) ||
        !arena.read(
            actual_raw_snapshot.data(), raw_snapshot,
            sizeof(actual_raw_snapshot)) ||
        !arena.read(actual_queries.data(), queries, sizeof(actual_queries)) ||
        !arena.read(
            actual_query_snapshot.data(), query_snapshot,
            sizeof(actual_query_snapshot)) ||
        !arena.read(
            actual_pair_state.data(), pair_state,
            sizeof(actual_pair_state)) ||
        !arena.read(
            actual_pair_boundary.data(), pair_boundary,
            sizeof(actual_pair_boundary)) ||
        !arena.read(
            actual_pair_input.data(), pair_input_snapshot,
            sizeof(actual_pair_input)) ||
        !check(stwo_exec_context_sync(arena.context), "wait for transcript")) {
        return 1;
    }

    std::array<std::uint32_t, kOperationCount * 16> expected_boundaries{};
    for (std::size_t operation = 0; operation < kOperationCount; ++operation) {
        std::copy(
            reference.boundaries[operation].begin(),
            reference.boundaries[operation].end(),
            expected_boundaries.begin() + operation * 16);
    }
    std::array<std::uint32_t, 23> expected_input{};
    std::copy(host_input.begin(), host_input.end(), expected_input.begin());
    std::array<std::uint32_t, 5> expected_pair_input{};
    std::copy(u32s.begin(), u32s.end(), expected_pair_input.begin());
    std::copy(
        u64_words.begin(),
        u64_words.end(),
        expected_pair_input.begin() + u32s.size());
    const bool matches =
        expect_words(actual_state, kPinnedFinalState, "GPU final state") &&
        expect_words(
            actual_boundaries, expected_boundaries, "GPU boundaries") &&
        expect_words(
            actual_input_snapshot, expected_input, "GPU input snapshots") &&
        expect_words(actual_secure, kPinnedSecure, "GPU secure") &&
        expect_words(
            actual_secure_snapshot, kPinnedSecure, "GPU secure snapshot") &&
        expect_words(actual_raw, kPinnedRaw, "GPU raw words") &&
        expect_words(
            actual_raw_snapshot, kPinnedRaw, "GPU raw snapshot") &&
        expect_words(actual_queries, kPinnedQueries, "GPU queries") &&
        expect_words(
            actual_query_snapshot, kPinnedQueries, "GPU query snapshot") &&
        expect_words(
            actual_pair_state, pair_expected,
            "GPU paired transcript state") &&
        expect_words(
            actual_pair_boundary, pair_expected,
            "GPU paired transcript boundary") &&
        expect_words(
            actual_pair_input, expected_pair_input,
            "GPU paired transcript input");
    if (!matches) return 1;

    std::array<std::uint32_t, 9> host_seed{};
    std::copy(
        kPinnedFinalState.begin(), kPinnedFinalState.begin() + 8,
        host_seed.begin());
    host_seed[8] = kPinnedFinalState[8];
    std::array<std::uint32_t, 16> expected_seeded_state{};
    std::copy(host_seed.begin(), host_seed.begin() + 8, expected_seeded_state.begin());
    expected_seeded_state[8] = host_seed[8];
    expected_seeded_state[12] = static_cast<std::uint32_t>(kChains[0]);
    expected_seeded_state[13] = static_cast<std::uint32_t>(kChains[0] >> 32);
    std::array<std::uint32_t, 16> actual_seeded_state{};
    std::array<std::uint32_t, 9> actual_seed_snapshot{};
    if (!arena.upload(seed, host_seed.data(), sizeof(host_seed)) ||
        !check(
            stwo_blake2s_transcript_init_on(
                state, seed, seed_snapshot, kChains[0], arena.stream),
            "initialize seeded transcript") ||
        !arena.read(
            actual_seeded_state.data(), state, sizeof(actual_seeded_state)) ||
        !arena.read(
            actual_seed_snapshot.data(), seed_snapshot,
            sizeof(actual_seed_snapshot)) ||
        !check(stwo_exec_context_sync(arena.context), "wait for seeded state") ||
        !expect_words(
            actual_seeded_state, expected_seeded_state,
            "GPU seeded state") ||
        !expect_words(actual_seed_snapshot, host_seed, "GPU seed snapshot") ||
        !arena.close()) {
        return 1;
    }

    std::printf(
        "native CUDA transcript smoke passed: %u operations, PoW nonce %llu\n",
        kOperationCount,
        static_cast<unsigned long long>(reference.nonce));
    return 0;
}
