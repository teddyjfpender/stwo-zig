#include "../../src/backends/cuda/native/aot_loader.h"

#include <cuda.h>
#include <cuda_runtime_api.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <utility>
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

constexpr char kMagic[8] = {'S', 'T', 'W', 'Z', 'R', 'W', 'M', '\0'};
constexpr std::uint32_t kVersion = 2;
constexpr std::uint32_t kRowCount = 4;
constexpr std::uint32_t kExpectedCases = 32;
constexpr std::uint32_t kExpectedBlocked = 1;
constexpr std::uint32_t kRecordedWitnessAbiSchema = 2;
constexpr std::uint32_t kModuleGlobalsReceiptAbiVersion = 1;
constexpr std::uint32_t kArgumentCount = 8;
constexpr std::uint32_t kExecutionTableCount = 37;
constexpr std::uint32_t kAddressTableWords = 65536;
constexpr std::uint32_t kPoison = 0xa5a5a5a5u;
constexpr std::uint32_t kMultiplicitySentinel = 0x5a5a5a5au;
constexpr std::size_t kPointerWords =
    sizeof(std::uint32_t *) / sizeof(std::uint32_t);

static_assert(sizeof(std::uint32_t *) % sizeof(std::uint32_t) == 0);

struct MatrixCase {
    std::string label;
    std::string kernel_name;
    std::uint64_t cache_key = 0;
    std::uint64_t semantic_hash = 0;
    std::array<std::uint8_t, 32> program_identity{};
    std::uint32_t module_globals = STWO_NATIVE_AOT_MODULE_GLOBALS_NONE;
    std::uint32_t input_count = 0;
    std::uint32_t output_count = 0;
    std::uint32_t lookup_count = 0;
    std::uint32_t sub_count = 0;
    std::uint32_t multiplicity_count = 0;
    std::vector<std::uint32_t> inputs;
    std::vector<std::uint32_t> outputs;
    std::vector<std::uint32_t> lookup_word_major;
    std::vector<std::uint32_t> sub_word_major;
};

struct BlockedCase {
    std::string label;
    std::uint32_t reason = 0;
};

struct PedersenRow {
    std::uint32_t row = 0;
    std::array<
        std::uint32_t,
        STWO_NATIVE_PEDERSEN_W18_COLUMN_COUNT> words{};
};

struct Fixture {
    std::array<std::uint8_t, 32> pedersen_identity{};
    std::vector<PedersenRow> pedersen_rows;
    std::vector<MatrixCase> cases;
    std::vector<BlockedCase> blocked;
};

class Reader {
  public:
    explicit Reader(const std::string &path) {
        std::ifstream stream(path, std::ios::binary | std::ios::ate);
        if (!stream) throw std::runtime_error("matrix fixture is absent");
        const auto size = stream.tellg();
        if (size <= 0 || size > 8 * 1024 * 1024) {
            throw std::runtime_error("matrix fixture size is invalid");
        }
        bytes_.resize(static_cast<std::size_t>(size));
        stream.seekg(0);
        stream.read(
            reinterpret_cast<char *>(bytes_.data()),
            static_cast<std::streamsize>(bytes_.size()));
        if (!stream) throw std::runtime_error("matrix fixture read failed");
    }

    std::uint32_t u32() {
        const auto *bytes = take(4);
        return static_cast<std::uint32_t>(bytes[0]) |
            (static_cast<std::uint32_t>(bytes[1]) << 8) |
            (static_cast<std::uint32_t>(bytes[2]) << 16) |
            (static_cast<std::uint32_t>(bytes[3]) << 24);
    }

    std::uint64_t u64() {
        const std::uint64_t low = u32();
        return low | (static_cast<std::uint64_t>(u32()) << 32);
    }

    std::string string() {
        const auto *length_bytes = take(2);
        const std::uint16_t length =
            static_cast<std::uint16_t>(length_bytes[0]) |
            static_cast<std::uint16_t>(length_bytes[1] << 8);
        if (length == 0 || length > 256) {
            throw std::runtime_error("matrix fixture string is invalid");
        }
        const auto *value = take(length);
        return {
            reinterpret_cast<const char *>(value),
            reinterpret_cast<const char *>(value + length),
        };
    }

    std::vector<std::uint32_t> words(std::size_t count) {
        if (count > 4 * 1024 * 1024) {
            throw std::runtime_error("matrix fixture word extent is invalid");
        }
        std::vector<std::uint32_t> result(count);
        for (auto &word : result) word = u32();
        return result;
    }

    void copy(void *destination, std::size_t bytes) {
        std::memcpy(destination, take(bytes), bytes);
    }

    void expect(const void *expected, std::size_t bytes) {
        if (std::memcmp(take(bytes), expected, bytes) != 0) {
            throw std::runtime_error("matrix fixture identity mismatch");
        }
    }

    bool finished() const {
        return cursor_ == bytes_.size();
    }

  private:
    const std::uint8_t *take(std::size_t count) {
        if (count > bytes_.size() - cursor_) {
            throw std::runtime_error("matrix fixture is truncated");
        }
        const auto *result = bytes_.data() + cursor_;
        cursor_ += count;
        return result;
    }

    std::vector<std::uint8_t> bytes_;
    std::size_t cursor_ = 0;
};

std::size_t checked_words(std::uint32_t outer) {
    return static_cast<std::size_t>(outer) * kRowCount;
}

Fixture read_fixture(const std::string &path) {
    Reader reader(path);
    reader.expect(kMagic, sizeof(kMagic));
    if (reader.u32() != kVersion || reader.u32() != kRowCount) {
        throw std::runtime_error("matrix fixture schema is unsupported");
    }
    const std::uint32_t case_count = reader.u32();
    const std::uint32_t blocked_count = reader.u32();
    if (case_count != kExpectedCases || blocked_count != kExpectedBlocked) {
        throw std::runtime_error("matrix fixture admission count drift");
    }
    Fixture fixture;
    reader.copy(
        fixture.pedersen_identity.data(),
        fixture.pedersen_identity.size());
    if (std::all_of(
            fixture.pedersen_identity.begin(),
            fixture.pedersen_identity.end(),
            [](std::uint8_t byte) { return byte == 0; })) {
        throw std::runtime_error("matrix Pedersen identity is absent");
    }
    const std::uint32_t pedersen_row_count = reader.u32();
    if (pedersen_row_count != 28) {
        throw std::runtime_error("matrix Pedersen sparse-row count drift");
    }
    fixture.pedersen_rows.reserve(pedersen_row_count);
    for (std::uint32_t index = 0; index < pedersen_row_count; ++index) {
        PedersenRow row;
        row.row = reader.u32();
        if (row.row != index * (1u << 18)) {
            throw std::runtime_error("matrix Pedersen sparse-row index drift");
        }
        for (auto &word : row.words) {
            word = reader.u32();
            if (word > 511) {
                throw std::runtime_error("matrix Pedersen word is non-canonical");
            }
        }
        fixture.pedersen_rows.push_back(row);
    }
    fixture.cases.reserve(case_count);
    for (std::uint32_t index = 0; index < case_count; ++index) {
        MatrixCase entry;
        entry.label = reader.string();
        entry.kernel_name = reader.string();
        entry.cache_key = reader.u64();
        entry.semantic_hash = reader.u64();
        reader.copy(entry.program_identity.data(), entry.program_identity.size());
        entry.module_globals = reader.u32();
        entry.input_count = reader.u32();
        entry.output_count = reader.u32();
        entry.lookup_count = reader.u32();
        entry.sub_count = reader.u32();
        entry.multiplicity_count = reader.u32();
        if (entry.cache_key == 0 || entry.semantic_hash == 0 ||
            entry.input_count == 0 || entry.output_count == 0 ||
            entry.lookup_count == 0 || entry.sub_count == 0 ||
            entry.multiplicity_count != 0 ||
            entry.module_globals >
                STWO_NATIVE_AOT_MODULE_GLOBALS_PEDERSEN_W18_COLUMNS_ROWS_V1 ||
            std::all_of(
                entry.program_identity.begin(),
                entry.program_identity.end(),
                [](std::uint8_t byte) { return byte == 0; })) {
            throw std::runtime_error("matrix fixture case is invalid");
        }
        entry.inputs = reader.words(checked_words(entry.input_count));
        entry.outputs = reader.words(checked_words(entry.output_count));
        entry.lookup_word_major =
            reader.words(checked_words(entry.lookup_count));
        entry.sub_word_major =
            reader.words(checked_words(entry.sub_count));
        fixture.cases.push_back(std::move(entry));
    }
    fixture.blocked.reserve(blocked_count);
    for (std::uint32_t index = 0; index < blocked_count; ++index) {
        BlockedCase entry{reader.string(), reader.u32()};
        if (entry.reason != 1) {
            throw std::runtime_error("matrix fixture block reason is invalid");
        }
        fixture.blocked.push_back(std::move(entry));
    }
    if (!reader.finished()) {
        throw std::runtime_error("matrix fixture has trailing bytes");
    }
    return fixture;
}

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
            "create recorded-witness matrix context");
    }

    std::uint32_t *allocate(std::size_t words) {
        std::uint32_t *pointer = nullptr;
        if (!check_status(
                stwo_exec_context_alloc_u32(
                    context_,
                    std::max<std::size_t>(words, 1),
                    &pointer),
                "allocate recorded-witness matrix words")) {
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
            "upload recorded-witness matrix words");
    }

    bool fill(
        std::uint32_t *destination,
        std::uint32_t value,
        std::size_t words) {
        return check_status(
            stwo_exec_context_fill_u32_async(
                context_,
                destination,
                value,
                words),
            "fill recorded-witness matrix words");
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
            "download recorded-witness matrix words");
    }

    bool sync(const char *operation) {
        return check_status(stwo_exec_context_sync(context_), operation);
    }

    std::size_t mark() const {
        return allocations_.size();
    }

    bool release_to(std::size_t mark) {
        if (mark > allocations_.size()) return false;
        while (allocations_.size() != mark) {
            if (!check_status(
                    stwo_exec_context_free_u32(
                        context_,
                        allocations_.back()),
                    "free recorded-witness matrix words")) {
                return false;
            }
            allocations_.pop_back();
        }
        return sync("wait for recorded-witness matrix frees");
    }

    void *context() const {
        return context_;
    }

    bool destroy() {
        if (!release_to(0)) return false;
        std::size_t used = 1;
        std::size_t reserved = 0;
        if (!check_status(
                stwo_exec_context_pool_current(
                    context_,
                    &used,
                    &reserved),
                "read recorded-witness matrix pool counters") ||
            used != 0) {
            std::fprintf(
                stderr,
                "recorded-witness matrix retained %zu live bytes\n",
                used);
            return false;
        }
        return check_status(
            stwo_exec_context_destroy(context_),
            "destroy recorded-witness matrix context");
    }

  private:
    void *context_ = nullptr;
    std::vector<std::uint32_t *> allocations_;
};

std::uint32_t **upload_pointer_table(
    DeviceArena *arena,
    const std::vector<std::uint32_t *> &pointers) {
    std::uint32_t *storage = arena->allocate(
        std::max<std::size_t>(pointers.size(), 1) * kPointerWords);
    if (storage == nullptr ||
        !arena->upload(
            storage,
            pointers.data(),
            pointers.size() * sizeof(std::uint32_t *))) {
        return nullptr;
    }
    return reinterpret_cast<std::uint32_t **>(storage);
}

bool exercise_allocation_ledger(DeviceArena *arena) {
    const std::size_t mark = arena->mark();
    for (std::size_t index = 0; index < 300; ++index) {
        if (arena->allocate(1) == nullptr) return false;
    }
    return arena->sync("wait for allocation-ledger growth") &&
        arena->release_to(mark);
}

bool compare_words(
    const MatrixCase &entry,
    const char *kind,
    const std::vector<std::uint32_t> &actual,
    const std::vector<std::uint32_t> &expected) {
    if (actual.size() != expected.size()) return false;
    for (std::size_t index = 0; index < actual.size(); ++index) {
        if (actual[index] == expected[index]) continue;
        std::fprintf(
            stderr,
            "%s %s mismatch word=%zu expected=%u actual=%u\n",
            entry.label.c_str(),
            kind,
            index,
            expected[index],
            actual[index]);
        return false;
    }
    return true;
}

bool valid_receipt(
    const MatrixCase &entry,
    const StwoNativeAotFunctionReceipt &receipt) {
    const std::uint32_t expected_grid[3] = {1, 1, 1};
    const std::uint32_t expected_block[3] = {256, 1, 1};
    return receipt.abi_version ==
            STWO_NATIVE_AOT_FUNCTION_RECEIPT_ABI_VERSION &&
        receipt.abi_schema == kRecordedWitnessAbiSchema &&
        receipt.cache_key == entry.cache_key &&
        receipt.argument_count == kArgumentCount &&
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

struct ExecutionTables {
    std::uint32_t **pointers = nullptr;
    std::uint32_t *strides = nullptr;
};

struct PedersenTable {
    std::array<std::uint64_t, STWO_NATIVE_PEDERSEN_W18_COLUMN_COUNT>
        columns{};
    std::array<std::uint8_t, 32> identity{};
    bool present = false;
};

bool prepare_execution_tables(
    DeviceArena *arena,
    ExecutionTables *tables) {
    std::vector<std::uint32_t *> pointers;
    const std::size_t storage_words =
        kAddressTableWords + kExecutionTableCount - 1;
    std::uint32_t *storage = arena->allocate(storage_words);
    if (storage == nullptr || !arena->fill(storage, 0, storage_words)) {
        return false;
    }
    pointers.push_back(storage);
    for (std::uint32_t index = 1; index < kExecutionTableCount; ++index) {
        pointers.push_back(storage + kAddressTableWords + index - 1);
    }
    tables->pointers = upload_pointer_table(arena, pointers);
    const std::array<std::uint32_t, 3> strides = {
        kAddressTableWords,
        1,
        1,
    };
    tables->strides = arena->allocate(strides.size());
    return tables->pointers != nullptr && tables->strides != nullptr &&
        arena->upload(tables->strides, strides.data(), sizeof(strides)) &&
        arena->sync("wait for recorded-witness execution tables");
}

bool prepare_pedersen_table(
    DeviceArena *arena,
    const Fixture &fixture,
    PedersenTable *table) {
    const bool required = std::any_of(
        fixture.cases.begin(),
        fixture.cases.end(),
        [](const MatrixCase &entry) {
            return entry.module_globals ==
                STWO_NATIVE_AOT_MODULE_GLOBALS_PEDERSEN_W18_COLUMNS_ROWS_V1;
        });
    if (!required) return true;

    const std::size_t rows = STWO_NATIVE_PEDERSEN_W18_ROW_COUNT;
    std::uint32_t *resident = arena->allocate(
        rows * STWO_NATIVE_PEDERSEN_W18_COLUMN_COUNT);
    if (resident == nullptr ||
        !arena->fill(
            resident,
            kPoison,
            rows * STWO_NATIVE_PEDERSEN_W18_COLUMN_COUNT)) {
        return false;
    }
    for (std::size_t index = 0; index < table->columns.size(); ++index) {
        std::uint32_t *column = resident + index * rows;
        for (const auto &row : fixture.pedersen_rows) {
            if (!arena->upload(
                    column + row.row,
                    &row.words[index],
                    sizeof(row.words[index]))) {
                return false;
            }
        }
        table->columns[index] =
            static_cast<std::uint64_t>(
                reinterpret_cast<std::uintptr_t>(column));
    }
    table->identity = fixture.pedersen_identity;
    table->present = true;
    return arena->sync("wait for fixture Pedersen table residency");
}

bool valid_module_globals_receipt(
    const PedersenTable &table,
    const StwoNativeAotModuleGlobalsReceipt &receipt) {
    return receipt.abi_version == kModuleGlobalsReceiptAbiVersion &&
        receipt.verified != 0 &&
        receipt.module_globals ==
            STWO_NATIVE_AOT_MODULE_GLOBALS_PEDERSEN_W18_COLUMNS_ROWS_V1 &&
        receipt.column_count == STWO_NATIVE_PEDERSEN_W18_COLUMN_COUNT &&
        receipt.row_count == STWO_NATIVE_PEDERSEN_W18_ROW_COUNT &&
        receipt.columns_symbol_bytes ==
            STWO_NATIVE_PEDERSEN_W18_COLUMN_COUNT * sizeof(std::uint64_t) &&
        receipt.row_count_symbol_bytes == sizeof(std::uint32_t) &&
        receipt.module_token != 0 && receipt.stream_token != 0 &&
        std::memcmp(
            receipt.table_identity,
            table.identity.data(),
        table.identity.size()) == 0;
}

void report_pedersen_context(const PedersenTable &table) {
    CUcontext current = nullptr;
    CUcontext pointer_context = nullptr;
    const CUresult current_status = cuCtxGetCurrent(&current);
    const CUresult pointer_status = cuPointerGetAttribute(
        &pointer_context,
        CU_POINTER_ATTRIBUTE_CONTEXT,
        static_cast<CUdeviceptr>(table.columns[0]));
    std::fprintf(
        stderr,
        "Pedersen residency diagnostic: current_status=%d "
        "pointer_status=%d same_context=%u\n",
        static_cast<int>(current_status),
        static_cast<int>(pointer_status),
        current != nullptr && current == pointer_context);
}

bool run_case(
    DeviceArena *arena,
    void *loader,
    const ExecutionTables &tables,
    const PedersenTable &pedersen,
    const MatrixCase &entry,
    std::size_t case_index) {
    const std::size_t allocation_mark = arena->mark();
    std::vector<std::uint32_t *> inputs;
    std::uint32_t *input_storage =
        arena->allocate(checked_words(entry.input_count));
    if (input_storage == nullptr ||
        !arena->upload(
            input_storage,
            entry.inputs.data(),
            entry.inputs.size() * sizeof(std::uint32_t))) {
        return false;
    }
    for (std::uint32_t column = 0; column < entry.input_count; ++column) {
        inputs.push_back(input_storage + column * kRowCount);
    }
    std::uint32_t **device_inputs = upload_pointer_table(arena, inputs);

    std::vector<std::uint32_t *> outputs;
    std::uint32_t *output_storage =
        arena->allocate(checked_words(entry.output_count));
    if (output_storage == nullptr ||
        !arena->fill(
            output_storage,
            kPoison,
            checked_words(entry.output_count))) {
        return false;
    }
    for (std::uint32_t column = 0; column < entry.output_count; ++column) {
        outputs.push_back(output_storage + column * kRowCount);
    }
    std::uint32_t **device_outputs = upload_pointer_table(arena, outputs);
    std::uint32_t *multiplicity = arena->allocate(1);
    if (multiplicity == nullptr ||
        !arena->upload(
            multiplicity,
            &kMultiplicitySentinel,
            sizeof(kMultiplicitySentinel))) {
        return false;
    }
    std::uint32_t **multiplicity_tables =
        upload_pointer_table(arena, {multiplicity});
    std::uint32_t *lookup =
        arena->allocate(entry.lookup_word_major.size());
    std::uint32_t *sub = arena->allocate(entry.sub_word_major.size());
    if (device_inputs == nullptr || device_outputs == nullptr ||
        multiplicity_tables == nullptr || lookup == nullptr || sub == nullptr ||
        !arena->fill(lookup, kPoison, entry.lookup_word_major.size()) ||
        !arena->fill(sub, kPoison, entry.sub_word_major.size()) ||
        !arena->sync("wait for recorded-witness case upload")) {
        return false;
    }

    void *function = nullptr;
    const std::uint32_t grid[3] = {1, 1, 1};
    const std::uint32_t block[3] = {256, 1, 1};
    StwoNativeAotFunctionReceipt receipt{};
    if (!check_status(
            stwo_native_aot_function_bind_with_globals(
                loader,
                entry.cache_key,
                kRecordedWitnessAbiSchema,
                entry.module_globals,
                entry.kernel_name.c_str(),
                grid,
                block,
                0,
                kArgumentCount,
                &function,
                &receipt),
            "bind authenticated recorded-witness matrix case") ||
        !valid_receipt(entry, receipt)) {
        std::fprintf(
            stderr,
            "%s produced an invalid strict-AOT receipt\n",
            entry.label.c_str());
        return false;
    }
    if (entry.module_globals ==
        STWO_NATIVE_AOT_MODULE_GLOBALS_PEDERSEN_W18_COLUMNS_ROWS_V1) {
        StwoNativeAotModuleGlobalsReceipt globals_receipt{};
        const int globals_status = pedersen.present
            ? stwo_native_aot_function_publish_pedersen_w18(
                  function,
                  pedersen.columns.data(),
                  STWO_NATIVE_PEDERSEN_W18_ROW_COUNT,
                  pedersen.identity.data(),
                  &globals_receipt)
            : CUDA_ERROR_INVALID_VALUE;
        if (!check_status(
                globals_status,
                "publish authenticated Pedersen recorded-witness globals") ||
            !valid_module_globals_receipt(pedersen, globals_receipt)) {
            report_pedersen_context(pedersen);
            std::fprintf(
                stderr,
                "%s produced an invalid module-global receipt\n",
                entry.label.c_str());
            return false;
        }
    }
    std::uint32_t rows = kRowCount;
    std::uint32_t **table_pointers = tables.pointers;
    std::uint32_t *table_strides = tables.strides;
    void *arguments[kArgumentCount] = {
        &device_inputs,
        &table_pointers,
        &table_strides,
        &device_outputs,
        &multiplicity_tables,
        &lookup,
        &sub,
        &rows,
    };
    if (!check_status(
            stwo_native_aot_function_launch(
                function,
                arguments,
                kArgumentCount),
            "launch recorded-witness matrix case") ||
        !arena->sync("wait for recorded-witness matrix case")) {
        return false;
    }

    std::vector<std::uint32_t> actual_outputs(entry.outputs.size());
    if (!arena->download(
            actual_outputs.data(),
            output_storage,
            actual_outputs.size() * sizeof(std::uint32_t))) {
        return false;
    }
    std::vector<std::uint32_t> actual_lookup(
        entry.lookup_word_major.size());
    std::vector<std::uint32_t> actual_sub(entry.sub_word_major.size());
    std::uint32_t actual_multiplicity = 0;
    if (!arena->download(
            actual_lookup.data(),
            lookup,
            actual_lookup.size() * sizeof(std::uint32_t)) ||
        !arena->download(
            actual_sub.data(),
            sub,
            actual_sub.size() * sizeof(std::uint32_t)) ||
        !arena->download(
            &actual_multiplicity,
            multiplicity,
            sizeof(actual_multiplicity)) ||
        !arena->sync("wait for recorded-witness matrix download")) {
        return false;
    }
    const bool values_match =
        compare_words(entry, "output", actual_outputs, entry.outputs) &&
        compare_words(
            entry,
            "lookup word-major",
            actual_lookup,
            entry.lookup_word_major) &&
        compare_words(
            entry,
            "sub word-major",
            actual_sub,
            entry.sub_word_major);
    if (!values_match) return false;
    if (actual_multiplicity != kMultiplicitySentinel) {
        std::fprintf(
            stderr,
            "%s multiplicity mismatch expected=%u actual=%u\n",
            entry.label.c_str(),
            kMultiplicitySentinel,
            actual_multiplicity);
        return false;
    }
    StwoNativeAotStats stats{};
    if (!check_status(
            stwo_native_aot_loader_stats(loader, &stats),
            "read recorded-witness matrix AOT telemetry") ||
        stats.aot_loads != case_index + 1 ||
        stats.aot_cache_hits != 0 || stats.aot_misses != 0 ||
        stats.launches != case_index + 1 ||
        stats.launch_failures != 0) {
        std::fprintf(
            stderr,
            "%s produced invalid strict-AOT telemetry\n",
            entry.label.c_str());
        return false;
    }
    return check_status(
               stwo_native_aot_function_destroy(function),
               "destroy recorded-witness matrix function") &&
        arena->release_to(allocation_mark);
}

bool run(const std::string &fixture_path) {
    Fixture fixture;
    try {
        fixture = read_fixture(fixture_path);
    } catch (const std::exception &error) {
        std::fprintf(stderr, "%s\n", error.what());
        return false;
    }
    DeviceArena arena;
    if (!arena.create() || !exercise_allocation_ledger(&arena)) return false;
    ExecutionTables tables;
    if (!prepare_execution_tables(&arena, &tables)) return false;
    PedersenTable pedersen;
    if (!prepare_pedersen_table(&arena, fixture, &pedersen)) return false;
    void *loader = nullptr;
    if (!check_status(
            stwo_native_aot_loader_create(arena.context(), &loader),
            "create recorded-witness matrix AOT loader")) {
        return false;
    }
    for (std::size_t index = 0; index < fixture.cases.size(); ++index) {
        if (!run_case(
                &arena,
                loader,
                tables,
                pedersen,
                fixture.cases[index],
                index)) {
            return false;
        }
    }
    for (const auto &blocked : fixture.blocked) {
        std::printf(
            "recorded-witness matrix blocked: %s reason=%u\n",
            blocked.label.c_str(),
            blocked.reason);
    }
    if (!check_status(
            stwo_native_aot_loader_destroy(loader),
            "destroy recorded-witness matrix AOT loader") ||
        !arena.destroy()) {
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char **argv) {
    if (argc > 2) {
        std::fprintf(stderr, "usage: %s [fixture]\n", argv[0]);
        return 2;
    }
    const std::string fixture_path = argc == 2
        ? argv[1]
        : "tests/cuda/fixtures/recorded_witness_matrix_fixture.bin";
    if (!run(fixture_path)) return 1;
    std::printf(
        "native CUDA recorded-witness matrix passed: "
        "32 exact Zig SIMD differential cases, 1 native-composite exclusion\n");
    return 0;
}
