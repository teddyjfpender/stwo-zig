#include "../../src/backends/cuda/native/aot_loader.h"

#include <cuda_runtime_api.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);
extern "C" int stwo_exec_context_sync(void *handle);
extern "C" int stwo_exec_context_alloc_u32(
    void *handle,
    std::size_t count,
    std::uint32_t **out_pointer);
extern "C" int stwo_exec_context_free_u32(
    void *handle,
    std::uint32_t *pointer);
extern "C" int stwo_exec_context_fill_u32_async(
    void *handle,
    std::uint32_t *destination,
    std::uint32_t value,
    std::size_t count);
extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *handle,
    void *destination,
    const void *source,
    std::size_t bytes);
extern "C" int stwo_exec_context_pool_current(
    void *handle,
    std::size_t *used_current,
    std::size_t *reserved_current);

namespace {

constexpr std::uint64_t kCacheKey = 0x0ce5a65a150f8601ull;
constexpr std::uint32_t kTraceSchema = 18;
constexpr std::uint32_t kArgumentCount = 18;
constexpr const char *kKernelName =
    "stwo_native_trace_m31_permutation_slab_v3_5c1cfb67d2fc10b4";
constexpr std::uint32_t kInstancesPerRow = 8;
constexpr std::uint32_t kStateWidth = 16;
constexpr std::uint32_t kHalfFullRounds = 4;
constexpr std::uint32_t kPartialRounds = 14;
constexpr std::uint32_t kColumnsPerRep =
    kStateWidth * (1 + 2 * kHalfFullRounds) + kPartialRounds;
constexpr std::uint32_t kColumnCount =
    kInstancesPerRow * kColumnsPerRep;
constexpr std::uint64_t kInitialRowStride = 16;
constexpr std::uint64_t kInitialRepStride = 1;
constexpr std::uint64_t kExternalConstantBase = 1234;
constexpr std::uint64_t kExternalRoundStride = 37;
constexpr std::uint64_t kExternalLaneStride = 1;
constexpr std::uint64_t kInternalConstantBase = 9876;
constexpr std::uint64_t kInternalRoundStride = 17;
constexpr std::uint64_t kM31Prime = 2147483647ull;
constexpr std::uint32_t kTraceSentinel = 0xa5a5a5a5u;
constexpr std::uint32_t kRelationSentinel = 0x5a5a5a5au;

struct Case {
    const char *name;
    std::uint32_t log_n_instances;
};

bool check_status(int status, const char *operation) {
    if (status == 0) return true;
    std::fprintf(
        stderr,
        "%s: status=%d (%s)\n",
        operation,
        status,
        cudaGetErrorString(static_cast<cudaError_t>(status)));
    return false;
}

std::uint32_t m31_from_u64(std::uint64_t value) {
    std::uint64_t reduced = (value & kM31Prime) + (value >> 31u);
    reduced = (reduced & kM31Prime) + (reduced >> 31u);
    return reduced >= kM31Prime
        ? static_cast<std::uint32_t>(reduced - kM31Prime)
        : static_cast<std::uint32_t>(reduced);
}

std::uint32_t m31_add(std::uint32_t lhs, std::uint32_t rhs) {
    const std::uint64_t sum = static_cast<std::uint64_t>(lhs) + rhs;
    return static_cast<std::uint32_t>(
        sum >= kM31Prime ? sum - kM31Prime : sum);
}

std::uint32_t m31_mul(std::uint32_t lhs, std::uint32_t rhs) {
    return m31_from_u64(static_cast<std::uint64_t>(lhs) * rhs);
}

std::uint32_t m31_pow5(std::uint32_t value) {
    const std::uint32_t square = m31_mul(value, value);
    return m31_mul(m31_mul(square, square), value);
}

void apply_m4(std::uint32_t *values) {
    const std::uint32_t t0 = m31_add(values[0], values[1]);
    const std::uint32_t t02 = m31_add(t0, t0);
    const std::uint32_t t1 = m31_add(values[2], values[3]);
    const std::uint32_t t12 = m31_add(t1, t1);
    const std::uint32_t t2 =
        m31_add(m31_add(values[1], values[1]), t1);
    const std::uint32_t t3 =
        m31_add(m31_add(values[3], values[3]), t0);
    const std::uint32_t t4 =
        m31_add(m31_add(t12, t12), t3);
    const std::uint32_t t5 =
        m31_add(m31_add(t02, t02), t2);
    values[0] = m31_add(t3, t5);
    values[1] = t5;
    values[2] = m31_add(t2, t4);
    values[3] = t4;
}

void apply_external_matrix(std::uint32_t *state) {
    for (std::uint32_t group = 0; group < 4; ++group) {
        apply_m4(state + group * 4);
    }
    for (std::uint32_t lane = 0; lane < 4; ++lane) {
        std::uint32_t sum = state[lane];
        sum = m31_add(sum, state[lane + 4]);
        sum = m31_add(sum, state[lane + 8]);
        sum = m31_add(sum, state[lane + 12]);
        for (std::uint32_t group = 0; group < 4; ++group) {
            const std::uint32_t index = group * 4 + lane;
            state[index] = m31_add(state[index], sum);
        }
    }
}

void apply_internal_matrix(std::uint32_t *state) {
    std::uint32_t sum = state[0];
    for (std::uint32_t lane = 1; lane < kStateWidth; ++lane) {
        sum = m31_add(sum, state[lane]);
    }
    std::uint32_t coefficient = 2;
    for (std::uint32_t lane = 0; lane < kStateWidth; ++lane) {
        state[lane] = m31_add(m31_mul(state[lane], coefficient), sum);
        coefficient = m31_add(coefficient, coefficient);
    }
}

void fill_oracle_row(
    std::vector<std::uint32_t> *trace,
    std::uint64_t trace_stride,
    std::vector<std::uint32_t> *relation,
    std::uint64_t relation_stride,
    std::uint32_t row) {
    std::uint64_t column = 0;
    for (std::uint32_t rep = 0; rep < kInstancesPerRow; ++rep) {
        std::uint32_t state[kStateWidth];
        for (std::uint32_t lane = 0; lane < kStateWidth; ++lane) {
            state[lane] = m31_from_u64(
                static_cast<std::uint64_t>(row) * kInitialRowStride +
                static_cast<std::uint64_t>(rep) * kInitialRepStride +
                lane);
            (*trace)[column++ * trace_stride + row] = state[lane];
            (*relation)[
                (static_cast<std::uint64_t>(rep) * 2 * kStateWidth + lane) *
                    relation_stride +
                row] = state[lane];
        }

        for (std::uint32_t round = 0; round < kHalfFullRounds; ++round) {
            for (std::uint32_t lane = 0; lane < kStateWidth; ++lane) {
                state[lane] = m31_add(
                    state[lane],
                    m31_from_u64(
                        kExternalConstantBase +
                        static_cast<std::uint64_t>(round) *
                            kExternalRoundStride +
                        static_cast<std::uint64_t>(lane) *
                            kExternalLaneStride));
            }
            apply_external_matrix(state);
            for (std::uint32_t lane = 0; lane < kStateWidth; ++lane) {
                state[lane] = m31_pow5(state[lane]);
                (*trace)[column++ * trace_stride + row] = state[lane];
            }
        }

        for (std::uint32_t round = 0; round < kPartialRounds; ++round) {
            state[0] = m31_add(
                state[0],
                m31_from_u64(
                    kInternalConstantBase +
                    static_cast<std::uint64_t>(round) *
                        kInternalRoundStride));
            apply_internal_matrix(state);
            state[0] = m31_pow5(state[0]);
            (*trace)[column++ * trace_stride + row] = state[0];
        }

        for (std::uint32_t offset = 0; offset < kHalfFullRounds; ++offset) {
            const std::uint32_t round = offset + kHalfFullRounds;
            for (std::uint32_t lane = 0; lane < kStateWidth; ++lane) {
                state[lane] = m31_add(
                    state[lane],
                    m31_from_u64(
                        kExternalConstantBase +
                        static_cast<std::uint64_t>(round) *
                            kExternalRoundStride +
                        static_cast<std::uint64_t>(lane) *
                            kExternalLaneStride));
            }
            apply_external_matrix(state);
            for (std::uint32_t lane = 0; lane < kStateWidth; ++lane) {
                state[lane] = m31_pow5(state[lane]);
                (*trace)[column++ * trace_stride + row] = state[lane];
            }
        }
        for (std::uint32_t lane = 0; lane < kStateWidth; ++lane) {
            (*relation)[
                (static_cast<std::uint64_t>(rep) * 2 * kStateWidth +
                 kStateWidth + lane) *
                    relation_stride +
                row] = state[lane];
        }
    }
}

bool run_case(
    void *context,
    void *loader,
    Case test_case,
    std::size_t *peak_used_bytes,
    std::size_t *peak_reserved_bytes) {
    if (test_case.log_n_instances < 3) return false;
    std::uint32_t log_n_rows = test_case.log_n_instances - 3;
    const std::uint32_t row_count = 1u << log_n_rows;
    const std::uint64_t trace_stride = row_count + 3u;
    const std::uint64_t trace_words = trace_stride * kColumnCount;
    const std::uint64_t relation_column_count =
        static_cast<std::uint64_t>(kInstancesPerRow) * 2 * kStateWidth;
    const std::uint64_t relation_stride = row_count + 5u;
    const std::uint64_t relation_words =
        relation_stride * relation_column_count;
    std::uint32_t *device_trace = nullptr;
    std::uint32_t *device_relation = nullptr;
    if (!check_status(
            stwo_exec_context_alloc_u32(
                context,
                trace_words,
                &device_trace),
            "allocate M31 permutation trace") ||
        !check_status(
            stwo_exec_context_fill_u32_async(
                context,
                device_trace,
                kTraceSentinel,
                trace_words),
            "poison M31 permutation trace") ||
        !check_status(
            stwo_exec_context_alloc_u32(
                context,
                relation_words,
                &device_relation),
            "allocate M31 permutation relation snapshot") ||
        !check_status(
            stwo_exec_context_fill_u32_async(
                context,
                device_relation,
                kRelationSentinel,
                relation_words),
            "poison M31 permutation relation snapshot")) {
        return false;
    }

    std::size_t used_bytes = 0;
    std::size_t reserved_bytes = 0;
    if (!check_status(
            stwo_exec_context_pool_current(
                context,
                &used_bytes,
                &reserved_bytes),
            "read M31 permutation pool counters")) {
        return false;
    }
    *peak_used_bytes = std::max(*peak_used_bytes, used_bytes);
    *peak_reserved_bytes = std::max(*peak_reserved_bytes, reserved_bytes);

    const std::uint32_t grid[3] = {
        (row_count + 255u) / 256u,
        1,
        1,
    };
    const std::uint32_t block[3] = {256, 1, 1};
    void *function = nullptr;
    StwoNativeAotFunctionReceipt receipt{};
    if (!check_status(
            stwo_native_aot_function_bind(
                loader,
                kCacheKey,
                kTraceSchema,
                kKernelName,
                grid,
                block,
                0,
                kArgumentCount,
                &function,
                &receipt),
            "bind M31 permutation trace") ||
        receipt.abi_version != STWO_NATIVE_AOT_FUNCTION_RECEIPT_ABI_VERSION ||
        receipt.abi_schema != kTraceSchema ||
        receipt.cache_key != kCacheKey ||
        receipt.argument_count != kArgumentCount) {
        std::fprintf(stderr, "invalid M31 permutation AOT receipt\n");
        return false;
    }

    std::uint64_t capacity = trace_words;
    std::uint64_t column_stride = trace_stride;
    std::uint64_t relation_capacity = relation_words;
    std::uint64_t relation_column_stride = relation_stride;
    std::uint32_t rows = row_count;
    std::uint32_t reps = kInstancesPerRow;
    std::uint32_t half_rounds = kHalfFullRounds;
    std::uint32_t partial_rounds = kPartialRounds;
    std::uint64_t row_stride = kInitialRowStride;
    std::uint64_t rep_stride = kInitialRepStride;
    std::uint64_t external_base = kExternalConstantBase;
    std::uint64_t external_stride = kExternalRoundStride;
    std::uint64_t external_lane_stride = kExternalLaneStride;
    std::uint64_t internal_base = kInternalConstantBase;
    std::uint64_t internal_stride = kInternalRoundStride;
    void *arguments[kArgumentCount] = {
        &device_trace,
        &capacity,
        &column_stride,
        &device_relation,
        &relation_capacity,
        &relation_column_stride,
        &rows,
        &log_n_rows,
        &reps,
        &half_rounds,
        &partial_rounds,
        &row_stride,
        &rep_stride,
        &external_base,
        &external_stride,
        &external_lane_stride,
        &internal_base,
        &internal_stride,
    };
    if (!check_status(
            stwo_native_aot_function_launch(
                function,
                arguments,
                kArgumentCount),
            "launch M31 permutation trace") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for M31 permutation trace")) {
        return false;
    }

    std::vector<std::uint32_t> actual_trace(trace_words);
    std::vector<std::uint32_t> oracle_trace(
        trace_words,
        kTraceSentinel);
    std::vector<std::uint32_t> actual_relation(relation_words);
    std::vector<std::uint32_t> oracle_relation(
        relation_words,
        kRelationSentinel);
    if (!check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                actual_trace.data(),
                device_trace,
                trace_words * sizeof(std::uint32_t)),
            "read M31 permutation trace") ||
        !check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                actual_relation.data(),
                device_relation,
                relation_words * sizeof(std::uint32_t)),
            "read M31 permutation relation snapshot") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for M31 permutation reads")) {
        return false;
    }
    for (std::uint32_t row = 0; row < row_count; ++row) {
        fill_oracle_row(
            &oracle_trace,
            trace_stride,
            &oracle_relation,
            relation_stride,
            row);
    }
    for (std::uint64_t index = 0; index < trace_words; ++index) {
        if (actual_trace[index] != oracle_trace[index]) {
            const std::uint64_t column = index / trace_stride;
            const std::uint64_t row = index % trace_stride;
            std::fprintf(
                stderr,
                "%s trace mismatch row=%llu column=%llu "
                "expected=%u actual=%u\n",
                test_case.name,
                static_cast<unsigned long long>(row),
                static_cast<unsigned long long>(column),
                oracle_trace[index],
                actual_trace[index]);
            return false;
        }
    }
    for (std::uint64_t index = 0; index < relation_words; ++index) {
        if (actual_relation[index] != oracle_relation[index]) {
            const std::uint64_t column = index / relation_stride;
            const std::uint64_t row = index % relation_stride;
            std::fprintf(
                stderr,
                "%s relation mismatch row=%llu column=%llu "
                "expected=%u actual=%u\n",
                test_case.name,
                static_cast<unsigned long long>(row),
                static_cast<unsigned long long>(column),
                oracle_relation[index],
                actual_relation[index]);
            return false;
        }
    }

    if (!check_status(
            stwo_native_aot_function_destroy(function),
            "destroy M31 permutation function") ||
        !check_status(
            stwo_exec_context_free_u32(context, device_trace),
            "free M31 permutation trace") ||
        !check_status(
            stwo_exec_context_free_u32(context, device_relation),
            "free M31 permutation relation snapshot") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for M31 permutation frees")) {
        return false;
    }
    used_bytes = 1;
    if (!check_status(
            stwo_exec_context_pool_current(
                context,
                &used_bytes,
                &reserved_bytes),
            "read final M31 permutation pool counters") ||
        used_bytes != 0) {
        std::fprintf(
            stderr,
            "M31 permutation pool retains %zu bytes\n",
            used_bytes);
        return false;
    }
    return true;
}

}  // namespace

int main() {
    void *context = nullptr;
    void *loader = nullptr;
    if (!check_status(stwo_exec_context_create(&context), "create context") ||
        !check_status(
            stwo_native_aot_loader_create(context, &loader),
            "create AOT loader")) {
        return 1;
    }

    std::size_t peak_used_bytes = 0;
    std::size_t peak_reserved_bytes = 0;
    const Case cases[] = {
        {"target-log-instances-10", 10},
        {"non-target-log-instances-7", 7},
    };
    for (const Case &test_case : cases) {
        if (!run_case(
                context,
                loader,
                test_case,
                &peak_used_bytes,
                &peak_reserved_bytes)) {
            return 1;
        }
    }

    StwoNativeAotStats stats{};
    if (!check_status(
            stwo_native_aot_loader_stats(loader, &stats),
            "read M31 permutation stats") ||
        stats.aot_loads != 1 || stats.aot_cache_hits != 1 ||
        stats.aot_misses != 0 || stats.launches != 2 ||
        stats.launch_failures != 0) {
        std::fprintf(
            stderr,
            "invalid M31 permutation telemetry loads=%llu hits=%llu "
            "misses=%llu launches=%llu failures=%llu\n",
            static_cast<unsigned long long>(stats.aot_loads),
            static_cast<unsigned long long>(stats.aot_cache_hits),
            static_cast<unsigned long long>(stats.aot_misses),
            static_cast<unsigned long long>(stats.launches),
            static_cast<unsigned long long>(stats.launch_failures));
        return 1;
    }
    if (!check_status(
            stwo_native_aot_loader_destroy(loader),
            "destroy AOT loader") ||
        !check_status(stwo_exec_context_destroy(context), "destroy context")) {
        return 1;
    }
    std::printf(
        "native CUDA M31 permutation trace smoke passed: 2 launches, "
        "target_rows=128 target_columns=1264 peak_used=%zu "
        "peak_reserved=%zu bytes\n",
        peak_used_bytes,
        peak_reserved_bytes);
    return 0;
}
