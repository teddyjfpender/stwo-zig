#include "fixtures/add_ap_relation_fixture.h"

#include <cuda_runtime_api.h>

#include <algorithm>
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

extern "C" int stwo_relation_expand_challenges_on(
    const std::uint32_t *drawn,
    std::uint32_t *alpha_powers,
    std::uint32_t n_alpha_powers,
    std::uint32_t *z,
    void *stream);
extern "C" int stwo_relation_pairs_global_on(
    const std::uint32_t *source_tables,
    const std::uint32_t *descriptors,
    const std::uint32_t *output_tables,
    const std::uint32_t *denominator_slabs,
    const std::uint32_t *geometry,
    std::uint32_t n_instances,
    std::uint32_t total_pair_blocks,
    const std::uint32_t *alpha_powers,
    std::uint32_t n_alpha_powers,
    const std::uint32_t *z,
    void *stream);
extern "C" int stwo_relation_fraction_chain_global_on(
    const std::uint32_t *output_tables,
    const std::uint32_t *denominator_slabs,
    const std::uint32_t *geometry,
    std::uint32_t n_instances,
    std::uint32_t total_inverse_blocks,
    std::uint32_t total_chain_blocks,
    void *stream);
extern "C" int stwo_relation_tail_global_on(
    const std::uint32_t *output_tables,
    const std::uint32_t *claimed_sums,
    const std::uint32_t *geometry,
    std::uint32_t n_instances,
    std::uint32_t total_row_blocks,
    std::uint32_t *reduction_partials,
    std::uint32_t reduction_capacity,
    std::uint32_t *scan_block_sums,
    std::uint32_t scan_capacity,
    void *stream);

namespace {

namespace fixture = stwo::cuda::test::add_ap_relation;

constexpr std::size_t kPointerWords =
    sizeof(std::uint32_t *) / sizeof(std::uint32_t);
constexpr std::uint32_t kRowBlocks = 1;
constexpr std::uint32_t kPairBlocks = fixture::kOutputColumns;
constexpr std::uint32_t kInverseBlocks = 1;
constexpr std::uint32_t kInverseRows = 1u << 27u;

static_assert(sizeof(std::uint32_t *) == 2 * sizeof(std::uint32_t));
static_assert(fixture::kRows == 16);

bool check(int status, const char *operation) {
    if (status == 0) return true;
    std::fprintf(
        stderr,
        "%s: status=%d (%s)\n",
        operation,
        status,
        cudaGetErrorString(static_cast<cudaError_t>(status)));
    return false;
}

class Arena {
  public:
    bool create() {
        return check(stwo_exec_context_create(&context_), "create context") &&
               check(
                   stwo_exec_context_stream(context_, &stream_),
                   "get proof stream");
    }

    std::uint32_t *allocate(std::size_t words) {
        std::uint32_t *pointer = nullptr;
        if (!check(
                stwo_exec_context_alloc_u32(
                    context_,
                    std::max<std::size_t>(words, 1),
                    &pointer),
                "allocate relation words")) {
            return nullptr;
        }
        allocations_.push_back(pointer);
        return pointer;
    }

    std::uint32_t *upload(
        const void *source,
        std::size_t words) {
        auto *destination = allocate(words);
        if (destination == nullptr ||
            !check(
                stwo_exec_context_memcpy_h2d_async(
                    context_,
                    destination,
                    source,
                    words * sizeof(std::uint32_t)),
                "upload relation words")) {
            return nullptr;
        }
        return destination;
    }

    std::uint32_t *pointerTable(
        const std::vector<std::uint32_t *> &pointers) {
        return upload(
            pointers.data(),
            pointers.size() * kPointerWords);
    }

    bool download(
        void *destination,
        const void *source,
        std::size_t words) {
        return check(
            stwo_exec_context_memcpy_d2h_async(
                context_,
                destination,
                source,
                words * sizeof(std::uint32_t)),
            "download relation words");
    }

    bool sync(const char *operation) {
        return check(stwo_exec_context_sync(context_), operation);
    }

    bool destroy() {
        for (auto iterator = allocations_.rbegin();
             iterator != allocations_.rend();
             ++iterator) {
            if (!check(
                    stwo_exec_context_free_u32(context_, *iterator),
                    "free relation words")) {
                return false;
            }
        }
        if (!sync("wait for relation frees")) return false;
        std::size_t used = 1;
        std::size_t reserved = 0;
        if (!check(
                stwo_exec_context_pool_current(
                    context_,
                    &used,
                    &reserved),
                "read relation pool") ||
            used != 0) {
            std::fprintf(stderr, "relation pool retained %zu bytes\n", used);
            return false;
        }
        return check(
            stwo_exec_context_destroy(context_),
            "destroy relation context");
    }

    void *stream() const {
        return stream_;
    }

  private:
    void *context_ = nullptr;
    void *stream_ = nullptr;
    std::vector<std::uint32_t *> allocations_;
};

bool compare(
    const char *name,
    const std::uint32_t *actual,
    const std::uint32_t *expected,
    std::size_t outer,
    std::size_t inner) {
    for (std::size_t group = 0; group < outer; ++group) {
        for (std::size_t index = 0; index < inner; ++index) {
            const std::size_t offset = group * inner + index;
            if (actual[offset] == expected[offset]) continue;
            std::fprintf(
                stderr,
                "%s mismatch group=%zu index=%zu expected=%u actual=%u\n",
                name,
                group,
                index,
                expected[offset],
                actual[offset]);
            return false;
        }
    }
    return true;
}

bool run() {
    Arena arena;
    if (!arena.create()) return false;

    auto *drawn = arena.upload(fixture::kDrawnZAlpha, 8);
    auto *alpha_powers = arena.allocate(fixture::kAlphaPowers * 4);
    auto *z = arena.allocate(4);
    auto *source = arena.upload(
        fixture::kSourceWords,
        fixture::kSourceColumns * fixture::kRows);
    auto *source_table = arena.pointerTable({source});
    auto *descriptors = arena.upload(
        fixture::kDescriptors,
        fixture::kOutputColumns * 16);
    auto *coordinates = arena.allocate(
        fixture::kOutputColumns * 4 * fixture::kRows);
    std::vector<std::uint32_t *> coordinate_pointers;
    for (std::uint32_t coordinate = 0;
         coordinate < fixture::kOutputColumns * 4;
         ++coordinate) {
        coordinate_pointers.push_back(
            coordinates + coordinate * fixture::kRows);
    }
    auto *output_table = arena.pointerTable(coordinate_pointers);
    auto *denominators = arena.allocate(
        fixture::kOutputColumns * fixture::kRows * 4);
    auto *claimed_sum = arena.upload(fixture::kClaimedSum, 4);
    const std::uint32_t host_geometry[11] = {
        0,
        kPairBlocks,
        0,
        kInverseBlocks,
        0,
        kRowBlocks,
        fixture::kRows,
        fixture::kOutputColumns,
        fixture::kRealRows,
        0,
        kInverseRows,
    };
    auto *geometry = arena.upload(host_geometry, 11);
    auto *source_tables = arena.pointerTable({source_table});
    auto *descriptor_tables = arena.pointerTable({descriptors});
    auto *output_tables = arena.pointerTable({output_table});
    auto *denominator_tables = arena.pointerTable({denominators});
    auto *claimed_sums = arena.pointerTable({claimed_sum});
    auto *reduction = arena.allocate(kRowBlocks * 4);
    auto *scan = arena.allocate(kRowBlocks * 4);
    if (drawn == nullptr || alpha_powers == nullptr || z == nullptr ||
        source == nullptr || source_table == nullptr ||
        descriptors == nullptr || coordinates == nullptr ||
        output_table == nullptr || denominators == nullptr ||
        claimed_sum == nullptr || geometry == nullptr ||
        source_tables == nullptr || descriptor_tables == nullptr ||
        output_tables == nullptr || denominator_tables == nullptr ||
        claimed_sums == nullptr || reduction == nullptr || scan == nullptr) {
        return false;
    }

    if (!check(
            stwo_relation_expand_challenges_on(
                drawn,
                alpha_powers,
                fixture::kAlphaPowers,
                z,
                arena.stream()),
            "expand relation challenges") ||
        !check(
            stwo_relation_pairs_global_on(
                source_tables,
                descriptor_tables,
                output_tables,
                denominator_tables,
                geometry,
                1,
                kPairBlocks,
                alpha_powers,
                fixture::kAlphaPowers,
                z,
                arena.stream()),
            "evaluate relation pairs") ||
        !check(
            stwo_relation_fraction_chain_global_on(
                output_tables,
                denominator_tables,
                geometry,
                1,
                kInverseBlocks,
                kRowBlocks,
                arena.stream()),
            "accumulate relation columns") ||
        !check(
            stwo_relation_tail_global_on(
                output_tables,
                claimed_sums,
                geometry,
                1,
                kRowBlocks,
                reduction,
                kRowBlocks,
                scan,
                kRowBlocks * 4,
                arena.stream()),
            "shift and scan relation tail")) {
        return false;
    }

    std::vector<std::uint32_t> actual(
        fixture::kOutputColumns * 4 * fixture::kRows);
    std::vector<std::uint32_t> actual_alpha(
        fixture::kAlphaPowers * 4);
    std::uint32_t actual_z[4] = {};
    if (!arena.download(actual.data(), coordinates, actual.size()) ||
        !arena.download(
            actual_alpha.data(),
            alpha_powers,
            actual_alpha.size()) ||
        !arena.download(actual_z, z, 4) ||
        !arena.sync("wait for relation differential")) {
        return false;
    }
    const bool exact =
        compare(
            "cumulative coordinate",
            actual.data(),
            fixture::kExpectedCoordinates,
            fixture::kOutputColumns * 4,
            fixture::kRows) &&
        compare(
            "alpha power",
            actual_alpha.data(),
            fixture::kExpectedAlphaPowers,
            fixture::kAlphaPowers,
            4) &&
        compare("z", actual_z, fixture::kDrawnZAlpha, 1, 4);
    if (!exact || !arena.destroy()) return false;
    std::printf(
        "Cairo relation exact: component=add_ap_opcode rows=%u "
        "columns=%u coordinates=%u graph=%016llx\n",
        fixture::kRows,
        fixture::kOutputColumns,
        fixture::kOutputColumns * 4,
        static_cast<unsigned long long>(fixture::kGraphHash));
    return true;
}

}  // namespace

int main() {
    return run() ? 0 : 1;
}
