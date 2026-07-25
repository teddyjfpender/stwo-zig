#include "../../src/backends/cuda/native/aot_loader.h"
#include "fixtures/add_ap_opcode_recorded_witness_fixture.h"

#include <cuda_runtime_api.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
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
extern "C" int stwo_exec_context_pool_current(
    void *handle,
    std::size_t *used_current,
    std::size_t *reserved_current);

namespace {

namespace fixture = stwo::cuda::test::add_ap;

constexpr std::uint32_t kPoison = 0xa5a5a5a5u;
constexpr std::uint32_t kMultiplicitySentinel = 0x5a5a5a5au;
constexpr std::uint32_t kExecutionTableCount =
    1 + fixture::kBigLimbCount + fixture::kSmallLimbCount;
constexpr std::size_t kPointerWords =
    sizeof(std::uint32_t *) / sizeof(std::uint32_t);

static_assert(kExecutionTableCount == 37);
static_assert(sizeof(std::uint32_t *) % sizeof(std::uint32_t) == 0);

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

class DeviceArena {
  public:
    bool create() {
        return check_status(
            stwo_exec_context_create(&context_),
            "create add-ap execution context");
    }

    std::uint32_t *allocate(std::size_t words) {
        std::uint32_t *pointer = nullptr;
        if (!check_status(
                stwo_exec_context_alloc_u32(
                    context_,
                    std::max<std::size_t>(words, 1),
                    &pointer),
                "allocate add-ap resident words")) {
            return nullptr;
        }
        allocations_.push_back(pointer);
        return pointer;
    }

    bool upload(
        void *destination,
        const void *source,
        std::size_t bytes) {
        return check_status(
            stwo_exec_context_memcpy_h2d_async(
                context_,
                destination,
                source,
                bytes),
            "upload add-ap resident words");
    }

    bool poison(std::uint32_t *destination, std::size_t words) {
        return check_status(
            stwo_exec_context_fill_u32_async(
                context_,
                destination,
                kPoison,
                words),
            "poison add-ap output");
    }

    bool download(
        void *destination,
        const void *source,
        std::size_t bytes) {
        return check_status(
            stwo_exec_context_memcpy_d2h_async(
                context_,
                destination,
                source,
                bytes),
            "download add-ap output");
    }

    bool sync(const char *operation) {
        return check_status(stwo_exec_context_sync(context_), operation);
    }

    void *context() const {
        return context_;
    }

    bool destroy() {
        for (auto iterator = allocations_.rbegin();
             iterator != allocations_.rend();
             ++iterator) {
            if (!check_status(
                    stwo_exec_context_free_u32(context_, *iterator),
                    "free add-ap resident words")) {
                return false;
            }
        }
        if (!sync("wait for add-ap frees")) return false;
        std::size_t used = 1;
        std::size_t reserved = 0;
        if (!check_status(
                stwo_exec_context_pool_current(
                    context_,
                    &used,
                    &reserved),
                "read add-ap pool counters") ||
            used != 0) {
            std::fprintf(
                stderr,
                "add-ap pool retained %zu live bytes\n",
                used);
            return false;
        }
        return check_status(
            stwo_exec_context_destroy(context_),
            "destroy add-ap execution context");
    }

  private:
    void *context_ = nullptr;
    std::vector<std::uint32_t *> allocations_;
};

std::uint32_t **upload_pointer_table(
    DeviceArena *arena,
    const std::vector<std::uint32_t *> &pointers) {
    std::uint32_t *storage =
        arena->allocate(std::max<std::size_t>(pointers.size(), 1) *
                        kPointerWords);
    if (storage == nullptr ||
        !arena->upload(
            storage,
            pointers.data(),
            pointers.size() * sizeof(std::uint32_t *))) {
        return nullptr;
    }
    return reinterpret_cast<std::uint32_t **>(storage);
}

bool compare_words(
    const char *name,
    const std::uint32_t *actual,
    const std::uint32_t *expected,
    std::size_t outer_count,
    std::size_t row_words) {
    for (std::size_t outer = 0; outer < outer_count; ++outer) {
        for (std::size_t row = 0; row < row_words; ++row) {
            const std::size_t index = outer * row_words + row;
            if (actual[index] == expected[index]) continue;
            std::fprintf(
                stderr,
                "%s mismatch outer=%zu row=%zu expected=%u actual=%u\n",
                name,
                outer,
                row,
                expected[index],
                actual[index]);
            return false;
        }
    }
    return true;
}

bool valid_receipt(const StwoNativeAotFunctionReceipt &receipt) {
    const std::uint32_t expected_grid[3] = {1, 1, 1};
    const std::uint32_t expected_block[3] = {256, 1, 1};
    return
        receipt.abi_version ==
            STWO_NATIVE_AOT_FUNCTION_RECEIPT_ABI_VERSION &&
        receipt.abi_schema == fixture::kAbiSchema &&
        receipt.cache_key == fixture::kCacheKey &&
        receipt.argument_count == fixture::kArgumentCount &&
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

bool run() {
    DeviceArena arena;
    if (!arena.create()) return false;

    std::vector<std::uint32_t *> inputs;
    for (std::uint32_t column = 0;
         column < fixture::kInputCount;
         ++column) {
        std::uint32_t *device = arena.allocate(fixture::kRowCount);
        if (device == nullptr ||
            !arena.upload(
                device,
                fixture::kInputs + column * fixture::kRowCount,
                fixture::kRowCount * sizeof(std::uint32_t))) {
            return false;
        }
        inputs.push_back(device);
    }
    std::uint32_t **device_inputs =
        upload_pointer_table(&arena, inputs);
    if (device_inputs == nullptr) return false;

    std::vector<std::uint32_t> address_table(
        fixture::kAddressTableSize,
        0);
    for (const auto &entry : fixture::kAddressEntries) {
        address_table[entry.address] = entry.encoded_id;
    }
    std::vector<std::uint32_t *> execution_tables;
    std::uint32_t *device_address =
        arena.allocate(fixture::kAddressTableSize);
    if (device_address == nullptr ||
        !arena.upload(
            device_address,
            address_table.data(),
            address_table.size() * sizeof(std::uint32_t))) {
        return false;
    }
    execution_tables.push_back(device_address);
    for (std::uint32_t limb = 0;
         limb < fixture::kBigLimbCount;
         ++limb) {
        std::uint32_t *device = arena.allocate(fixture::kBigValueCount);
        if (device == nullptr ||
            !arena.upload(
                device,
                fixture::kBigLimbs +
                    limb * fixture::kBigValueCount,
                fixture::kBigValueCount * sizeof(std::uint32_t))) {
            return false;
        }
        execution_tables.push_back(device);
    }
    for (std::uint32_t limb = 0;
         limb < fixture::kSmallLimbCount;
         ++limb) {
        std::uint32_t *device =
            arena.allocate(fixture::kSmallValueCount);
        if (device == nullptr ||
            !arena.upload(
                device,
                fixture::kSmallLimbs +
                    limb * fixture::kSmallValueCount,
                fixture::kSmallValueCount * sizeof(std::uint32_t))) {
            return false;
        }
        execution_tables.push_back(device);
    }
    if (execution_tables.size() != kExecutionTableCount) return false;
    std::uint32_t **device_execution_tables =
        upload_pointer_table(&arena, execution_tables);
    const std::array<std::uint32_t, 3> execution_strides = {
        fixture::kAddressTableSize,
        fixture::kBigValueCount,
        fixture::kSmallValueCount,
    };
    std::uint32_t *device_execution_strides =
        arena.allocate(execution_strides.size());
    if (device_execution_tables == nullptr ||
        device_execution_strides == nullptr ||
        !arena.upload(
            device_execution_strides,
            execution_strides.data(),
            sizeof(execution_strides))) {
        return false;
    }

    std::vector<std::uint32_t *> outputs;
    for (std::uint32_t column = 0;
         column < fixture::kOutputCount;
         ++column) {
        std::uint32_t *device = arena.allocate(fixture::kRowCount);
        if (device == nullptr ||
            !arena.poison(device, fixture::kRowCount)) {
            return false;
        }
        outputs.push_back(device);
    }
    std::uint32_t **device_outputs =
        upload_pointer_table(&arena, outputs);
    if (device_outputs == nullptr) return false;

    std::uint32_t *device_multiplicity = arena.allocate(1);
    if (device_multiplicity == nullptr ||
        !arena.upload(
            device_multiplicity,
            &kMultiplicitySentinel,
            sizeof(kMultiplicitySentinel))) {
        return false;
    }
    std::uint32_t **device_multiplicity_tables =
        upload_pointer_table(&arena, {device_multiplicity});
    if (device_multiplicity_tables == nullptr) return false;

    constexpr std::size_t lookup_words =
        fixture::kLookupCount * fixture::kRowCount;
    constexpr std::size_t sub_words =
        fixture::kSubCount * fixture::kRowCount;
    std::uint32_t *device_lookup = arena.allocate(lookup_words);
    std::uint32_t *device_sub = arena.allocate(sub_words);
    if (device_lookup == nullptr || device_sub == nullptr ||
        !arena.poison(device_lookup, lookup_words) ||
        !arena.poison(device_sub, sub_words) ||
        !arena.sync("wait for add-ap fixture upload")) {
        return false;
    }

    void *loader = nullptr;
    void *function = nullptr;
    if (!check_status(
            stwo_native_aot_loader_create(
                arena.context(),
                &loader),
            "create add-ap AOT loader")) {
        return false;
    }
    const std::uint32_t grid[3] = {1, 1, 1};
    const std::uint32_t block[3] = {256, 1, 1};
    StwoNativeAotFunctionReceipt receipt{};
    if (!check_status(
            stwo_native_aot_function_bind(
                loader,
                fixture::kCacheKey,
                fixture::kAbiSchema,
                fixture::kKernelName,
                grid,
                block,
                0,
                fixture::kArgumentCount,
                &function,
                &receipt),
            "bind authenticated add-ap recorded witness") ||
        !valid_receipt(receipt)) {
        std::fprintf(stderr, "invalid add-ap strict-AOT receipt\n");
        return false;
    }

    std::uint32_t rows = fixture::kRowCount;
    void *arguments[fixture::kArgumentCount] = {
        &device_inputs,
        &device_execution_tables,
        &device_execution_strides,
        &device_outputs,
        &device_multiplicity_tables,
        &device_lookup,
        &device_sub,
        &rows,
    };
    if (!check_status(
            stwo_native_aot_function_launch(
                function,
                arguments,
                fixture::kArgumentCount),
            "launch add-ap recorded witness") ||
        !arena.sync("wait for add-ap recorded witness")) {
        return false;
    }

    std::array<
        std::uint32_t,
        fixture::kOutputCount * fixture::kRowCount>
        actual_outputs{};
    for (std::uint32_t column = 0;
         column < fixture::kOutputCount;
         ++column) {
        if (!arena.download(
                actual_outputs.data() +
                    column * fixture::kRowCount,
                outputs[column],
                fixture::kRowCount * sizeof(std::uint32_t))) {
            return false;
        }
    }
    std::array<std::uint32_t, lookup_words> actual_lookup{};
    std::array<std::uint32_t, sub_words> actual_sub{};
    std::uint32_t actual_multiplicity = 0;
    if (!arena.download(
            actual_lookup.data(),
            device_lookup,
            sizeof(actual_lookup)) ||
        !arena.download(
            actual_sub.data(),
            device_sub,
            sizeof(actual_sub)) ||
        !arena.download(
            &actual_multiplicity,
            device_multiplicity,
            sizeof(actual_multiplicity)) ||
        !arena.sync("wait for add-ap result download")) {
        return false;
    }

    if (!compare_words(
            "add-ap output",
            actual_outputs.data(),
            fixture::kExpectedOutputs,
            fixture::kOutputCount,
            fixture::kRowCount) ||
        !compare_words(
            "add-ap lookup word-major",
            actual_lookup.data(),
            fixture::kExpectedLookupWordMajor,
            fixture::kLookupCount,
            fixture::kRowCount) ||
        !compare_words(
            "add-ap sub word-major",
            actual_sub.data(),
            fixture::kExpectedSubWordMajor,
            fixture::kSubCount,
            fixture::kRowCount) ||
        actual_multiplicity != kMultiplicitySentinel) {
        std::fprintf(
            stderr,
            "add-ap zero-table multiplicity sentinel changed\n");
        return false;
    }

    StwoNativeAotStats stats{};
    if (!check_status(
            stwo_native_aot_loader_stats(loader, &stats),
            "read add-ap AOT stats") ||
        stats.aot_loads != 1 || stats.aot_cache_hits != 0 ||
        stats.aot_misses != 0 || stats.launches != 1 ||
        stats.launch_failures != 0) {
        std::fprintf(stderr, "invalid add-ap AOT telemetry\n");
        return false;
    }
    if (!check_status(
            stwo_native_aot_function_destroy(function),
            "destroy add-ap AOT function") ||
        !check_status(
            stwo_native_aot_loader_destroy(loader),
            "destroy add-ap AOT loader") ||
        !arena.destroy()) {
        return false;
    }
    return true;
}

}  // namespace

int main() {
    if (!run()) return 1;
    std::printf(
        "native CUDA add-ap authenticated recorded-witness smoke passed\n");
    return 0;
}
