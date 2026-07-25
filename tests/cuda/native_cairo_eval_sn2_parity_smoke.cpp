#include "../../src/backends/cuda/native/aot_loader.h"
#include "fixtures/cairo_eval_sn2_parity_fixture.h"

#include <cuda_runtime_api.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iterator>

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
extern "C" int stwo_exec_context_memcpy_h2d_async(
    void *handle,
    void *destination,
    const void *source,
    std::size_t bytes);
extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *handle,
    void *destination,
    const void *source,
    std::size_t bytes);

namespace {

namespace fixture = stwo_sn2_eval_parity;

constexpr std::uint64_t kExpectedAotLoads = 271;
constexpr std::uint64_t kExpectedAotCacheHits =
    fixture::kPlacementCount - kExpectedAotLoads;

struct StwoCairoEvalArgs {
    std::uint64_t trace_offsets;
    std::uint64_t interaction_offsets;
    std::uint64_t base_params;
    std::uint64_t ext_params;
    std::uint64_t random_coeffs;
    std::uint64_t denom_inv;
    std::uint64_t coord_0;
    std::uint64_t coord_1;
    std::uint64_t coord_2;
    std::uint64_t coord_3;
    std::uint32_t row_count;
    std::uint32_t trace_log_size;
    std::uint32_t domain_log_size;
    std::uint32_t rc_base;
};

static_assert(sizeof(StwoCairoEvalArgs) == 96);
static_assert(offsetof(StwoCairoEvalArgs, trace_offsets) == 0);
static_assert(offsetof(StwoCairoEvalArgs, random_coeffs) == 32);
static_assert(offsetof(StwoCairoEvalArgs, coord_0) == 48);
static_assert(offsetof(StwoCairoEvalArgs, row_count) == 80);
static_assert(offsetof(StwoCairoEvalArgs, rc_base) == 92);
static_assert(fixture::kComponentCount == 58);
static_assert(fixture::kPlacementCount == 279);
static_assert(fixture::kPaletteCount == 8);
static_assert(fixture::kKernelArgumentCount == 3);

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

bool valid_receipt(
    const fixture::Placement &placement,
    const StwoNativeAotFunctionReceipt &receipt) {
    const std::uint32_t expected_grid[3] = {1, 1, 1};
    const std::uint32_t expected_block[3] = {
        fixture::kFixtureRows,
        1,
        1,
    };
    return receipt.abi_version ==
            STWO_NATIVE_AOT_FUNCTION_RECEIPT_ABI_VERSION &&
        receipt.abi_schema == fixture::kConstraintSchema &&
        receipt.cache_key == placement.cache_key &&
        receipt.argument_count == fixture::kKernelArgumentCount &&
        receipt.context_token != 0 && receipt.module_token != 0 &&
        receipt.function_token != 0 && receipt.stream_token != 0 &&
        receipt.verification.verified != 0 &&
        receipt.verification.cubin_bytes != 0 &&
        std::memcmp(
            receipt.verification.expected_sha256,
            receipt.verification.observed_sha256,
            sizeof(receipt.verification.expected_sha256)) == 0 &&
        std::equal(
            std::begin(receipt.grid),
            std::end(receipt.grid),
            expected_grid) &&
        std::equal(
            std::begin(receipt.block),
            std::end(receipt.block),
            expected_block);
}

bool prepare_fixture(void *context, std::uint32_t *arena) {
    for (std::size_t index = 0; index < fixture::kPaletteCount; ++index) {
        if (!check_status(
                stwo_exec_context_fill_u32_async(
                    context,
                    arena + index * fixture::kMaxRows,
                    fixture::kPaletteValues[index],
                    fixture::kMaxRows),
                "initialize SN2 trace palette")) {
            return false;
        }
    }
    if (!check_status(
            stwo_exec_context_memcpy_h2d_async(
                context,
                arena + fixture::kMetadataOffset,
                fixture::kMetadataWords,
                sizeof(fixture::kMetadataWords)),
            "upload SN2 evaluation metadata") ||
        !check_status(
            stwo_exec_context_fill_u32_async(
                context,
                arena + fixture::kCoordinatesOffset,
                0,
                4 * fixture::kFixtureRows),
            "initialize SN2 composition accumulator") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for SN2 parity fixture")) {
        return false;
    }
    return true;
}

bool run_placement(
    void *context,
    void *loader,
    std::uint32_t *arena,
    std::uint32_t *device_args,
    std::size_t placement_index) {
    const fixture::Placement &placement =
        fixture::kPlacements[placement_index];
    const fixture::Component &component =
        fixture::kComponents[placement.component_index];
    StwoCairoEvalArgs args{
        component.trace_offsets,
        component.interaction_offsets,
        component.base_params,
        component.ext_params,
        fixture::kRandomCoefficientsOffset,
        component.denominator_inverses,
        fixture::kCoordinatesOffset,
        fixture::kCoordinatesOffset + fixture::kFixtureRows,
        fixture::kCoordinatesOffset + 2 * fixture::kFixtureRows,
        fixture::kCoordinatesOffset + 3 * fixture::kFixtureRows,
        1u << component.evaluation_log_size,
        component.trace_log_size,
        placement.domain_log_size,
        placement.global_rc_base,
    };
    if (!check_status(
            stwo_exec_context_memcpy_h2d_async(
                context,
                device_args,
                &args,
                sizeof(args)),
            "upload SN2 evaluation arguments")) {
        return false;
    }

    void *function = nullptr;
    const std::uint32_t grid[3] = {1, 1, 1};
    const std::uint32_t block[3] = {
        fixture::kFixtureRows,
        1,
        1,
    };
    StwoNativeAotFunctionReceipt receipt{};
    if (!check_status(
            stwo_native_aot_function_bind_with_globals(
                loader,
                placement.cache_key,
                fixture::kConstraintSchema,
                STWO_NATIVE_AOT_MODULE_GLOBALS_NONE,
                placement.kernel_name,
                grid,
                block,
                0,
                fixture::kKernelArgumentCount,
                &function,
                &receipt),
            "bind authenticated SN2 evaluation body") ||
        !valid_receipt(placement, receipt)) {
        std::fprintf(
            stderr,
            "invalid SN2 AOT receipt component=%s instance=%u part=%u\n",
            component.label,
            placement.instance,
            placement.part_index);
        return false;
    }

    std::uint32_t *arena_argument = arena;
    std::uint64_t arena_words = fixture::kArenaWords;
    auto *args_argument =
        reinterpret_cast<StwoCairoEvalArgs *>(device_args);
    void *kernel_arguments[fixture::kKernelArgumentCount] = {
        &arena_argument,
        &arena_words,
        &args_argument,
    };
    if (!check_status(
            stwo_native_aot_function_launch(
                function,
                kernel_arguments,
                fixture::kKernelArgumentCount),
            "launch authenticated SN2 evaluation body") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for SN2 evaluation body")) {
        return false;
    }

    std::uint32_t actual[4][fixture::kFixtureRows]{};
    if (!check_status(
            stwo_exec_context_memcpy_d2h_async(
                context,
                actual,
                arena + fixture::kCoordinatesOffset,
                sizeof(actual)),
            "read SN2 composition accumulator") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for SN2 accumulator read")) {
        return false;
    }
    for (std::uint32_t row = 0; row < fixture::kFixtureRows; ++row) {
        for (std::uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
            const std::uint32_t observed = actual[coordinate][row];
            const std::uint32_t expected =
                placement.expected[row][coordinate];
            if (observed == expected) continue;
            std::fprintf(
                stderr,
                "SN2 constraint mismatch component=%s instance=%u part=%u "
                "row=%u coordinate=%u expected=%u actual=%u\n",
                component.label,
                placement.instance,
                placement.part_index,
                row,
                coordinate,
                expected,
                observed);
            return false;
        }
    }
    return check_status(
        stwo_native_aot_function_destroy(function),
        "destroy SN2 evaluation function");
}

}  // namespace

int main() {
    void *context = nullptr;
    void *loader = nullptr;
    std::uint32_t *arena = nullptr;
    std::uint32_t *device_args = nullptr;
    if (!check_status(stwo_exec_context_create(&context), "create context") ||
        !check_status(
            stwo_native_aot_loader_create(context, &loader),
            "create SN2 AOT loader") ||
        !check_status(
            stwo_exec_context_alloc_u32(
                context,
                fixture::kArenaWords,
                &arena),
            "allocate SN2 parity arena") ||
        !check_status(
            stwo_exec_context_alloc_u32(
                context,
                sizeof(StwoCairoEvalArgs) / sizeof(std::uint32_t),
                &device_args),
            "allocate SN2 evaluation arguments") ||
        !prepare_fixture(context, arena)) {
        return 1;
    }

    for (std::size_t index = 0; index < fixture::kPlacementCount; ++index) {
        if (!run_placement(
                context,
                loader,
                arena,
                device_args,
                index)) {
            return 1;
        }
    }

    StwoNativeAotStats stats{};
    if (!check_status(
            stwo_native_aot_loader_stats(loader, &stats),
            "read SN2 strict-AOT telemetry") ||
        stats.aot_loads != kExpectedAotLoads ||
        stats.aot_cache_hits != kExpectedAotCacheHits ||
        stats.aot_misses != 0 ||
        stats.launches != fixture::kPlacementCount ||
        stats.launch_failures != 0) {
        std::fprintf(
            stderr,
            "invalid SN2 strict-AOT telemetry loads=%llu cache_hits=%llu "
            "misses=%llu launches=%llu launch_failures=%llu\n",
            static_cast<unsigned long long>(stats.aot_loads),
            static_cast<unsigned long long>(stats.aot_cache_hits),
            static_cast<unsigned long long>(stats.aot_misses),
            static_cast<unsigned long long>(stats.launches),
            static_cast<unsigned long long>(stats.launch_failures));
        return 1;
    }

    if (!check_status(
            stwo_native_aot_loader_destroy(loader),
            "destroy SN2 AOT loader") ||
        !check_status(
            stwo_exec_context_free_u32(context, device_args),
            "free SN2 evaluation arguments") ||
        !check_status(
            stwo_exec_context_free_u32(context, arena),
            "free SN2 parity arena") ||
        !check_status(
            stwo_exec_context_sync(context),
            "wait for SN2 device frees") ||
        !check_status(
            stwo_exec_context_destroy(context),
            "destroy context")) {
        return 1;
    }
    std::printf(
        "SN2 constraint parity passed: components=%zu placements=%zu "
        "aot_loads=%llu cache_hits=%llu missing=0 runtime_compiles=0 "
        "cpu_fallbacks=0\n",
        fixture::kComponentCount,
        fixture::kPlacementCount,
        static_cast<unsigned long long>(kExpectedAotLoads),
        static_cast<unsigned long long>(kExpectedAotCacheHits));
    return 0;
}
