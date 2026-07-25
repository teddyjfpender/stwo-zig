#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

extern "C" int stwo_exec_context_create(void **out_handle);
extern "C" int stwo_exec_context_destroy(void *handle);
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream);
extern "C" int stwo_exec_context_sync(void *handle);
extern "C" int stwo_exec_context_alloc_u32(
    void *handle,
    std::size_t count,
    std::uint32_t **out_pointer);
extern "C" int stwo_exec_context_free_u32(
    void *handle,
    std::uint32_t *pointer);
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

extern "C" int stwo_witness_casm_input_scatter_on(
    const std::uint32_t *rows,
    std::uint32_t real_rows,
    std::uint32_t consumer_rows,
    std::uint32_t *pc,
    std::uint32_t *ap,
    std::uint32_t *fp,
    std::uint32_t *enabler,
    std::uint32_t *iota,
    void *stream);
extern "C" int stwo_witness_input_seed_contiguous_on(
    const std::uint32_t *scalars,
    std::uint32_t scalar_count,
    std::uint32_t real_rows,
    std::uint32_t consumer_rows,
    std::uint32_t *outputs,
    std::size_t output_stride_words,
    std::size_t output_capacity_words,
    std::uint32_t include_enabler,
    std::uint32_t include_iota,
    void *stream);
extern "C" int stwo_witness_edge_gather_contiguous_on(
    const std::uint32_t *producer,
    std::size_t producer_capacity_words,
    std::uint32_t producer_rows,
    std::uint32_t word_base,
    std::uint32_t words_per_instance,
    std::uint32_t instance_count,
    std::uint32_t consumer_rows,
    std::uint32_t *outputs,
    std::size_t output_stride_words,
    std::size_t output_capacity_words,
    std::uint32_t include_enabler,
    std::uint32_t include_iota,
    void *stream);

namespace {

constexpr std::uint32_t kRealRows = 17;
constexpr std::uint32_t kConsumerRows = 32;
constexpr std::size_t kStateWords = kRealRows * 3;
constexpr std::size_t kSeedStride = 37;
constexpr std::size_t kSeedColumns = 5;
constexpr std::size_t kSeedWords = kSeedStride * kSeedColumns;
constexpr std::uint32_t kProducerRows = 16;
constexpr std::uint32_t kEdgeWordBase = 2;
constexpr std::uint32_t kEdgeWordsPerInstance = 2;
constexpr std::uint32_t kEdgeInstances = 3;
constexpr std::uint32_t kEdgeRows = 64;
constexpr std::size_t kEdgeProducerWords =
    (kEdgeWordBase + kEdgeWordsPerInstance * kEdgeInstances) * kProducerRows;
constexpr std::size_t kEdgeStride = 67;
constexpr std::size_t kEdgeColumns = 4;
constexpr std::size_t kEdgeWords = kEdgeStride * kEdgeColumns;

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

bool expect_invalid(int status, const char *operation) {
    if (status == static_cast<int>(cudaErrorInvalidValue)) return true;
    std::fprintf(
        stderr,
        "%s: expected cudaErrorInvalidValue, observed %d (%s)\n",
        operation,
        status,
        cudaGetErrorString(static_cast<cudaError_t>(status)));
    return false;
}

bool check_casm_column(
    const char *name,
    const std::vector<std::uint32_t> &actual,
    const std::vector<std::uint32_t> &states,
    std::size_t coordinate) {
    for (std::uint32_t row = 0; row < kConsumerRows; ++row) {
        const std::uint32_t source_row = row < kRealRows ? row : 0;
        const std::uint32_t expected = states[source_row * 3 + coordinate];
        if (actual[row] == expected) continue;
        std::fprintf(
            stderr,
            "%s mismatch row=%u expected=%u actual=%u\n",
            name,
            row,
            expected,
            actual[row]);
        return false;
    }
    return true;
}

bool run() {
    void *context = nullptr;
    void *stream = nullptr;
    if (!check_status(stwo_exec_context_create(&context), "create context") ||
        !check_status(
            stwo_exec_context_stream(context, &stream),
            "read proof stream") ||
        stream == nullptr) {
        return false;
    }

    std::vector<std::uint32_t *> allocations;
    auto allocate = [&](std::size_t words, std::uint32_t **pointer) {
        if (!check_status(
                stwo_exec_context_alloc_u32(context, words, pointer),
                "allocate resident Cairo witness")) {
            return false;
        }
        allocations.push_back(*pointer);
        return true;
    };

    std::uint32_t *device_states = nullptr;
    std::uint32_t *device_pc = nullptr;
    std::uint32_t *device_ap = nullptr;
    std::uint32_t *device_fp = nullptr;
    std::uint32_t *device_enabler = nullptr;
    std::uint32_t *device_iota = nullptr;
    std::uint32_t *device_scalars = nullptr;
    std::uint32_t *device_seed = nullptr;
    std::uint32_t *device_edge_producer = nullptr;
    std::uint32_t *device_edge = nullptr;
    if (!allocate(kStateWords, &device_states) ||
        !allocate(kConsumerRows, &device_pc) ||
        !allocate(kConsumerRows, &device_ap) ||
        !allocate(kConsumerRows, &device_fp) ||
        !allocate(kConsumerRows, &device_enabler) ||
        !allocate(kConsumerRows, &device_iota) ||
        !allocate(3, &device_scalars) ||
        !allocate(kSeedWords, &device_seed) ||
        !allocate(kEdgeProducerWords, &device_edge_producer) ||
        !allocate(kEdgeWords, &device_edge)) {
        return false;
    }

    std::vector<std::uint32_t> states(kStateWords);
    for (std::uint32_t row = 0; row < kRealRows; ++row) {
        states[row * 3] = 1000 + row * 11;
        states[row * 3 + 1] = 2000 + row * 13;
        states[row * 3 + 2] = 3000 + row * 17;
    }
    const std::uint32_t scalars[3] = {7, 19, 2147483646u};
    std::vector<std::uint32_t> edge_producer(kEdgeProducerWords);
    for (std::size_t word = 0;
         word < kEdgeProducerWords / kProducerRows;
         ++word) {
        for (std::uint32_t row = 0; row < kProducerRows; ++row) {
            edge_producer[word * kProducerRows + row] =
                static_cast<std::uint32_t>(word * 1000 + row * 7 + 3);
        }
    }
    if (!check_status(
            stwo_exec_context_memcpy_h2d_async(
                context,
                device_states,
                states.data(),
                states.size() * sizeof(std::uint32_t)),
            "upload CASM states") ||
        !check_status(
            stwo_exec_context_memcpy_h2d_async(
                context,
                device_scalars,
                scalars,
                sizeof(scalars)),
            "upload scalar seeds") ||
        !check_status(
            stwo_exec_context_memcpy_h2d_async(
                context,
                device_edge_producer,
                edge_producer.data(),
                edge_producer.size() * sizeof(std::uint32_t)),
            "upload packed edge producer") ||
        !check_status(
            stwo_witness_casm_input_scatter_on(
                device_states,
                kRealRows,
                kConsumerRows,
                device_pc,
                device_ap,
                device_fp,
                device_enabler,
                device_iota,
                stream),
            "scatter CASM states") ||
        !check_status(
            stwo_witness_input_seed_contiguous_on(
                device_scalars,
                3,
                kRealRows,
                kConsumerRows,
                device_seed,
                kSeedStride,
                kSeedWords,
                1,
                1,
                stream),
            "expand scalar witness seeds") ||
        !check_status(
            stwo_witness_edge_gather_contiguous_on(
                device_edge_producer,
                kEdgeProducerWords,
                kProducerRows,
                kEdgeWordBase,
                kEdgeWordsPerInstance,
                kEdgeInstances,
                kEdgeRows,
                device_edge,
                kEdgeStride,
                kEdgeWords,
                1,
                1,
                stream),
            "gather packed witness edge")) {
        return false;
    }

    if (!expect_invalid(
            stwo_witness_casm_input_scatter_on(
                device_states,
                kRealRows,
                64,
                device_pc,
                device_ap,
                device_fp,
                device_enabler,
                device_iota,
                stream),
            "reject noncanonical CASM height") ||
        !expect_invalid(
            stwo_witness_casm_input_scatter_on(
                device_states,
                kRealRows,
                kConsumerRows,
                device_states,
                device_ap,
                device_fp,
                device_enabler,
                device_iota,
                stream),
            "reject overlapping CASM ranges") ||
        !expect_invalid(
            stwo_witness_input_seed_contiguous_on(
                device_scalars,
                3,
                kRealRows,
                kConsumerRows,
                device_seed,
                kSeedStride,
                kSeedWords - 1,
                1,
                1,
                stream),
            "reject truncated scalar-seed output") ||
        !expect_invalid(
            stwo_witness_input_seed_contiguous_on(
                device_seed,
                3,
                kRealRows,
                kConsumerRows,
                device_seed,
                kSeedStride,
                kSeedWords,
                1,
                1,
                stream),
            "reject overlapping scalar-seed ranges") ||
        !expect_invalid(
            stwo_witness_edge_gather_contiguous_on(
                device_edge_producer,
                kEdgeProducerWords - 1,
                kProducerRows,
                kEdgeWordBase,
                kEdgeWordsPerInstance,
                kEdgeInstances,
                kEdgeRows,
                device_edge,
                kEdgeStride,
                kEdgeWords,
                1,
                1,
                stream),
            "reject truncated edge producer") ||
        !expect_invalid(
            stwo_witness_edge_gather_contiguous_on(
                device_edge_producer,
                kEdgeProducerWords,
                kProducerRows,
                kEdgeWordBase,
                kEdgeWordsPerInstance,
                kEdgeInstances,
                kEdgeRows,
                device_edge_producer,
                kEdgeStride,
                kEdgeWords,
                1,
                1,
                stream),
            "reject overlapping edge ranges")) {
        return false;
    }

    std::vector<std::uint32_t> pc(kConsumerRows);
    std::vector<std::uint32_t> ap(kConsumerRows);
    std::vector<std::uint32_t> fp(kConsumerRows);
    std::vector<std::uint32_t> enabler(kConsumerRows);
    std::vector<std::uint32_t> iota(kConsumerRows);
    std::vector<std::uint32_t> seed(kSeedWords);
    std::vector<std::uint32_t> edge(kEdgeWords);
    const struct {
        void *host;
        const void *device;
        std::size_t bytes;
        const char *label;
    } copies[] = {
        {pc.data(), device_pc, pc.size() * sizeof(std::uint32_t), "read pc"},
        {ap.data(), device_ap, ap.size() * sizeof(std::uint32_t), "read ap"},
        {fp.data(), device_fp, fp.size() * sizeof(std::uint32_t), "read fp"},
        {
            enabler.data(),
            device_enabler,
            enabler.size() * sizeof(std::uint32_t),
            "read enabler",
        },
        {
            iota.data(),
            device_iota,
            iota.size() * sizeof(std::uint32_t),
            "read iota",
        },
        {
            seed.data(),
            device_seed,
            seed.size() * sizeof(std::uint32_t),
            "read scalar seed",
        },
        {
            edge.data(),
            device_edge,
            edge.size() * sizeof(std::uint32_t),
            "read packed edge",
        },
    };
    for (const auto &copy : copies) {
        if (!check_status(
                stwo_exec_context_memcpy_d2h_async(
                    context,
                    copy.host,
                    copy.device,
                    copy.bytes),
                copy.label)) {
            return false;
        }
    }
    const std::uint32_t edge_real_rows =
        kProducerRows * kEdgeInstances;
    for (std::uint32_t row = 0; row < kEdgeRows; ++row) {
        const std::uint32_t source_row =
            row < edge_real_rows ? row : (row & 15u);
        const std::uint32_t instance = source_row / kProducerRows;
        const std::uint32_t producer_row = source_row % kProducerRows;
        for (std::uint32_t column = 0;
             column < kEdgeWordsPerInstance;
             ++column) {
            const std::size_t source_word =
                kEdgeWordBase + instance * kEdgeWordsPerInstance + column;
            const std::uint32_t expected =
                edge_producer[source_word * kProducerRows + producer_row];
            const std::uint32_t observed =
                edge[column * kEdgeStride + row];
            if (observed != expected) {
                std::fprintf(
                    stderr,
                    "packed-edge mismatch column=%u row=%u "
                    "expected=%u actual=%u\n",
                    column,
                    row,
                    expected,
                    observed);
                return false;
            }
        }
        const std::uint32_t expected_enabler =
            row < edge_real_rows ? 1 : 0;
        if (edge[2 * kEdgeStride + row] != expected_enabler ||
            edge[3 * kEdgeStride + row] != row) {
            std::fprintf(
                stderr,
                "packed-edge derived-column mismatch row=%u\n",
                row);
            return false;
        }
    }
    if (!check_status(
            stwo_exec_context_sync(context),
            "wait for Cairo witness stages")) {
        return false;
    }

    if (!check_casm_column("pc", pc, states, 0) ||
        !check_casm_column("ap", ap, states, 1) ||
        !check_casm_column("fp", fp, states, 2)) {
        return false;
    }
    for (std::uint32_t row = 0; row < kConsumerRows; ++row) {
        const std::uint32_t expected_enabler = row < kRealRows ? 1 : 0;
        if (enabler[row] != expected_enabler || iota[row] != row) {
            std::fprintf(stderr, "CASM derived-column mismatch row=%u\n", row);
            return false;
        }
        for (std::size_t column = 0; column < 3; ++column) {
            if (seed[column * kSeedStride + row] != scalars[column]) {
                std::fprintf(
                    stderr,
                    "scalar-seed mismatch column=%zu row=%u\n",
                    column,
                    row);
                return false;
            }
        }
        if (seed[3 * kSeedStride + row] != expected_enabler ||
            seed[4 * kSeedStride + row] != row) {
            std::fprintf(
                stderr,
                "scalar-seed derived-column mismatch row=%u\n",
                row);
            return false;
        }
    }

    for (auto iterator = allocations.rbegin();
         iterator != allocations.rend();
         ++iterator) {
        if (!check_status(
                stwo_exec_context_free_u32(context, *iterator),
                "free resident Cairo witness")) {
            return false;
        }
    }
    if (!check_status(
            stwo_exec_context_sync(context),
            "wait for Cairo witness frees")) {
        return false;
    }
    std::size_t used = 1;
    std::size_t reserved = 0;
    if (!check_status(
            stwo_exec_context_pool_current(context, &used, &reserved),
            "read pool counters") ||
        used != 0) {
        std::fprintf(stderr, "pool retained %zu live bytes\n", used);
        return false;
    }
    return check_status(
        stwo_exec_context_destroy(context),
        "destroy context");
}

}  // namespace

int main() {
    if (!run()) return 1;
    std::printf("native CUDA Cairo witness smoke passed\n");
    return 0;
}
