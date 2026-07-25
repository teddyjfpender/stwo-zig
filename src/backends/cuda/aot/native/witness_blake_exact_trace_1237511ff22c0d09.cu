// Exact mixed-height Native Blake witness.
//
// One lane owns one stored scheduler, round, or XOR-table row. XOR
// multiplicities are the only shared writes: atomic unit increments are
// commutative in u32, and admission bounds their maximum at 10,485,760.
// Callers must zero the main multiplicity range before this launch.

#include <cstdint>

using u64 = unsigned long long;

namespace {
constexpr std::uint32_t kRounds = 10u;
constexpr std::uint32_t kColumnsPerScheduler = 384u;
constexpr std::uint32_t kColumnsPerRound = 384u;
constexpr std::uint32_t kTableCount = 5u;
constexpr std::uint32_t kTableLogs[kTableCount] = {
    16u, 14u, 12u, 10u, 8u,
};
constexpr std::uint32_t kTableWidths[kTableCount] = {
    12u, 9u, 8u, 7u, 4u,
};
constexpr std::uint32_t kTableExpands[kTableCount] = {
    4u, 2u, 2u, 2u, 0u,
};
constexpr std::uint32_t kMultiplicityColumns[kTableCount] = {
    256u, 16u, 16u, 16u, 1u,
};
constexpr std::uint8_t kSigma[kRounds][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

__device__ __forceinline__ std::uint32_t rotate_right(
    std::uint32_t value,
    std::uint32_t amount) {
    return (value >> amount) | (value << (32u - amount));
}

__device__ __forceinline__ void blake_g(
    std::uint32_t *state,
    std::uint32_t a,
    std::uint32_t b,
    std::uint32_t c,
    std::uint32_t d,
    std::uint32_t message0,
    std::uint32_t message1) {
    state[a] += state[b] + message0;
    state[d] = rotate_right(state[d] ^ state[a], 16u);
    state[c] += state[d];
    state[b] = rotate_right(state[b] ^ state[c], 12u);
    state[a] += state[b] + message1;
    state[d] = rotate_right(state[d] ^ state[a], 8u);
    state[c] += state[d];
    state[b] = rotate_right(state[b] ^ state[c], 7u);
}

__device__ __forceinline__ void blake_round(
    std::uint32_t *state,
    const std::uint32_t *message,
    std::uint32_t round) {
    const std::uint8_t *sigma = kSigma[round];
    blake_g(state, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]]);
    blake_g(state, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]]);
    blake_g(state, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]]);
    blake_g(state, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]]);
    blake_g(state, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]]);
    blake_g(state, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]]);
    blake_g(state, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]]);
    blake_g(state, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]]);
}

__device__ __forceinline__ u64 preprocessed_offset(
    std::uint32_t table) {
    u64 offset = 0;
    for (std::uint32_t index = 0; index < table; ++index) {
        offset += 3ull * (1ull << kTableLogs[index]);
    }
    return offset;
}

__device__ __forceinline__ u64 main_xor_offset(
    std::uint32_t table,
    std::uint32_t log_n_rows) {
    const u64 scheduler_rows = 1ull << log_n_rows;
    u64 offset =
        kColumnsPerScheduler * scheduler_rows +
        kColumnsPerRound * (scheduler_rows << 3u) +
        kColumnsPerRound * (scheduler_rows << 1u);
    for (std::uint32_t index = 0; index < table; ++index) {
        offset += static_cast<u64>(kMultiplicityColumns[index]) *
            (1ull << kTableLogs[index]);
    }
    return offset;
}

__device__ __forceinline__ u64 required_preprocessed_words() {
    return preprocessed_offset(kTableCount);
}

__device__ __forceinline__ u64 required_main_words(
    std::uint32_t log_n_rows) {
    return main_xor_offset(kTableCount, log_n_rows);
}

struct ColumnWriter {
    std::uint32_t *main;
    u64 main_base;
    u64 stride;
    std::uint32_t row;
    u64 column = 0;

    __device__ __forceinline__ void append_felt(std::uint32_t value) {
        const u64 index = main_base + column * stride + row;
        main[index] = value;
        ++column;
    }

    __device__ __forceinline__ void append_u32(std::uint32_t value) {
        append_felt(value & 0xffffu);
        append_felt(value >> 16u);
    }
};

struct RoundWriter : ColumnWriter {
    std::uint32_t log_n_rows;

    __device__ __forceinline__ void record_xor(
        std::uint32_t width,
        std::uint32_t a,
        std::uint32_t b) {
        std::uint32_t table = 0;
        while (table < kTableCount && kTableWidths[table] != width) ++table;
        if (table == kTableCount) return;

        const std::uint32_t limb_bits =
            kTableWidths[table] - kTableExpands[table];
        const std::uint32_t mask = (1u << limb_bits) - 1u;
        const std::uint32_t column =
            (a >> limb_bits) * (1u << kTableExpands[table]) +
            (b >> limb_bits);
        const std::uint32_t table_row =
            ((a & mask) << limb_bits) + (b & mask);
        const u64 index =
            main_xor_offset(table, log_n_rows) +
            static_cast<u64>(column) * (1ull << kTableLogs[table]) +
            table_row;
        atomicAdd(main + index, 1u);
    }

    __device__ __forceinline__ std::uint32_t xor_rotate(
        std::uint32_t a,
        std::uint32_t b,
        std::uint32_t width) {
        const std::uint32_t mask = (1u << width) - 1u;
        const std::uint32_t al = (a & 0xffffu) & mask;
        const std::uint32_t ah = (a >> 16u) & mask;
        const std::uint32_t bl = (b & 0xffffu) & mask;
        const std::uint32_t bh = (b >> 16u) & mask;
        const std::uint32_t al_high = (a & 0xffffu) >> width;
        const std::uint32_t ah_high = (a >> 16u) >> width;
        const std::uint32_t bl_high = (b & 0xffffu) >> width;
        const std::uint32_t bh_high = (b >> 16u) >> width;
        append_felt(al_high);
        append_felt(ah_high);
        append_felt(bl_high);
        append_felt(bh_high);
        append_felt(al ^ bl);
        record_xor(width, al, bl);
        append_felt(ah ^ bh);
        record_xor(width, ah, bh);
        append_felt(al_high ^ bl_high);
        record_xor(16u - width, al_high, bl_high);
        append_felt(ah_high ^ bh_high);
        record_xor(16u - width, ah_high, bh_high);
        return rotate_right(a ^ b, width);
    }

    __device__ __forceinline__ std::uint32_t xor_rotate_16(
        std::uint32_t a,
        std::uint32_t b) {
        const std::uint32_t al = a & 0xffu;
        const std::uint32_t ah = (a >> 16u) & 0xffu;
        const std::uint32_t bl = b & 0xffu;
        const std::uint32_t bh = (b >> 16u) & 0xffu;
        const std::uint32_t al_high = (a >> 8u) & 0xffu;
        const std::uint32_t ah_high = a >> 24u;
        const std::uint32_t bl_high = (b >> 8u) & 0xffu;
        const std::uint32_t bh_high = b >> 24u;
        append_felt(al_high);
        append_felt(ah_high);
        append_felt(bl_high);
        append_felt(bh_high);
        append_felt(al ^ bl);
        record_xor(8u, al, bl);
        append_felt(ah ^ bh);
        record_xor(8u, ah, bh);
        append_felt(al_high ^ bl_high);
        record_xor(8u, al_high, bl_high);
        append_felt(ah_high ^ bh_high);
        record_xor(8u, ah_high, bh_high);
        return rotate_right(a ^ b, 16u);
    }

    __device__ __forceinline__ std::uint32_t add2(
        std::uint32_t a,
        std::uint32_t b) {
        const std::uint32_t value = a + b;
        append_u32(value);
        return value;
    }

    __device__ __forceinline__ std::uint32_t add3(
        std::uint32_t a,
        std::uint32_t b,
        std::uint32_t c) {
        const std::uint32_t value = a + b + c;
        append_u32(value);
        return value;
    }

    __device__ __forceinline__ void g(
        std::uint32_t *state,
        std::uint32_t a,
        std::uint32_t b,
        std::uint32_t c,
        std::uint32_t d,
        std::uint32_t message0,
        std::uint32_t message1) {
        state[a] = add3(state[a], state[b], message0);
        state[d] = xor_rotate_16(state[a], state[d]);
        state[c] = add2(state[c], state[d]);
        state[b] = xor_rotate(state[b], state[c], 12u);
        state[a] = add3(state[a], state[b], message1);
        state[d] = xor_rotate(state[a], state[d], 8u);
        state[c] = add2(state[c], state[d]);
        state[b] = xor_rotate(state[b], state[c], 7u);
    }
};

__device__ __forceinline__ void fill_preprocessed(
    std::uint32_t *preprocessed,
    std::uint32_t row) {
    for (std::uint32_t table = 0; table < kTableCount; ++table) {
        const std::uint32_t rows = 1u << kTableLogs[table];
        if (row >= rows) continue;
        const std::uint32_t limb_bits =
            kTableWidths[table] - kTableExpands[table];
        const std::uint32_t mask = (1u << limb_bits) - 1u;
        const std::uint32_t a = row >> limb_bits;
        const std::uint32_t b = row & mask;
        const u64 base = preprocessed_offset(table);
        const std::uint32_t values[3] = {a, b, a ^ b};
        for (std::uint32_t column = 0; column < 3; ++column) {
            const u64 index =
                base + static_cast<u64>(column) * rows + row;
            preprocessed[index] = values[column];
        }
    }
}

__device__ __forceinline__ void fill_scheduler(
    std::uint32_t *main,
    std::uint32_t log_n_rows,
    std::uint32_t row) {
    const std::uint32_t rows = 1u << log_n_rows;
    if (row >= rows) return;
    const std::uint32_t base = row / 16u + 2u * (row % 16u);
    std::uint32_t state[16];
    std::uint32_t message[16];
    for (std::uint32_t lane = 0; lane < 16; ++lane) {
        state[lane] = base;
        message[lane] = base + 1u;
    }
    ColumnWriter writer{main, 0, rows, row};
    for (std::uint32_t lane = 0; lane < 16; ++lane)
        writer.append_u32(message[lane]);
    for (std::uint32_t lane = 0; lane < 16; ++lane)
        writer.append_u32(state[lane]);
    for (std::uint32_t round = 0; round < kRounds; ++round) {
        blake_round(state, message, round);
        for (std::uint32_t lane = 0; lane < 16; ++lane)
            writer.append_u32(state[lane]);
    }
}

__device__ __forceinline__ void fill_round_component(
    std::uint32_t *main,
    std::uint32_t log_n_rows,
    std::uint32_t component,
    std::uint32_t row) {
    const std::uint32_t scheduler_rows = 1u << log_n_rows;
    const std::uint32_t split = component == 0u ? 3u : 1u;
    const std::uint32_t rows = scheduler_rows << split;
    if (row >= rows) return;
    const std::uint32_t scheduler_pack_count = scheduler_rows >> 4u;
    const std::uint32_t packed_offset =
        component == 0u ? 0u : scheduler_pack_count << 3u;
    const std::uint32_t packed_index = packed_offset + row / 16u;
    const std::uint32_t scheduler_pack = packed_index / kRounds;
    const std::uint32_t round = packed_index % kRounds;
    const std::uint32_t base =
        scheduler_pack + 2u * (row % 16u);
    std::uint32_t state[16];
    std::uint32_t original_message[16];
    std::uint32_t message[16];
    for (std::uint32_t lane = 0; lane < 16; ++lane) {
        state[lane] = base;
        original_message[lane] = base + 1u;
    }
    for (std::uint32_t prior = 0; prior < round; ++prior)
        blake_round(state, original_message, prior);
    for (std::uint32_t lane = 0; lane < 16; ++lane)
        message[lane] = original_message[kSigma[round][lane]];

    const u64 main_base = component == 0u
        ? static_cast<u64>(kColumnsPerScheduler) * scheduler_rows
        : static_cast<u64>(kColumnsPerScheduler) * scheduler_rows +
            static_cast<u64>(kColumnsPerRound) * (scheduler_rows << 3u);
    RoundWriter writer{};
    writer.main = main;
    writer.main_base = main_base;
    writer.stride = rows;
    writer.row = row;
    writer.log_n_rows = log_n_rows;
    for (std::uint32_t lane = 0; lane < 16; ++lane)
        writer.append_u32(state[lane]);
    for (std::uint32_t lane = 0; lane < 16; ++lane)
        writer.append_u32(message[lane]);
    writer.g(state, 0, 4, 8, 12, message[0], message[1]);
    writer.g(state, 1, 5, 9, 13, message[2], message[3]);
    writer.g(state, 2, 6, 10, 14, message[4], message[5]);
    writer.g(state, 3, 7, 11, 15, message[6], message[7]);
    writer.g(state, 0, 5, 10, 15, message[8], message[9]);
    writer.g(state, 1, 6, 11, 12, message[10], message[11]);
    writer.g(state, 2, 7, 8, 13, message[12], message[13]);
    writer.g(state, 3, 4, 9, 14, message[14], message[15]);
}
}  // namespace

extern "C" __global__ void __launch_bounds__(128)
stwo_native_trace_blake_exact_mixed_v2_b8a99643ffc4a29b(
    std::uint32_t *preprocessed,
    u64 preprocessed_words,
    std::uint32_t *main,
    u64 main_words,
    std::uint32_t log_n_rows,
    std::uint32_t n_rounds) {
    const std::uint32_t row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (preprocessed == nullptr || main == nullptr ||
        log_n_rows < 4u || log_n_rows > 13u || n_rounds != kRounds) {
        return;
    }
    const u64 expected_preprocessed = required_preprocessed_words();
    const u64 expected_main = required_main_words(log_n_rows);
    if (preprocessed_words != expected_preprocessed ||
        main_words != expected_main) {
        return;
    }
    const std::uint32_t max_rows =
        1u << (log_n_rows + 3u > 16u ? log_n_rows + 3u : 16u);
    if (row >= max_rows) return;

    fill_preprocessed(preprocessed, row);
    fill_scheduler(
        main,
        log_n_rows,
        row);
    fill_round_component(
        main,
        log_n_rows,
        0u,
        row);
    fill_round_component(
        main,
        log_n_rows,
        1u,
        row);
}
