#include "fixtures/cairo_relation_sn2_parity_fixture.h"

#include <cuda_runtime_api.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
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

namespace fixture = stwo::cuda::test::sn2_relation;

constexpr std::uint32_t kM31Modulus = 0x7fffffffu;
constexpr std::size_t kPointerWords =
    sizeof(std::uint32_t *) / sizeof(std::uint32_t);

static_assert(sizeof(std::uint32_t *) == 2 * sizeof(std::uint32_t));
static_assert(sizeof(fixture::Geometry) == 11 * sizeof(std::uint32_t));
static_assert(fixture::kInstanceCount == 58);
static_assert(fixture::kMaxAlphaPowers == 126);

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

std::uint32_t add_m31(std::uint32_t lhs, std::uint32_t rhs) {
    const std::uint64_t sum =
        static_cast<std::uint64_t>(lhs) + rhs;
    const std::uint32_t folded =
        static_cast<std::uint32_t>((sum & kM31Modulus) + (sum >> 31u));
    return folded == kM31Modulus ? 0u : folded;
}

std::uint8_t source_byte(
    std::uint32_t ordinal,
    std::uint32_t source_column) {
    return static_cast<std::uint8_t>(
        1u + (ordinal * 17u + source_column * 13u) % 126u);
}

std::uint32_t terminal_scan_row(std::uint32_t rows) {
    std::uint32_t log_rows = 0;
    for (std::uint32_t value = rows; value > 1u; value >>= 1u)
        ++log_rows;
    const std::uint32_t scan_index = rows - 1u;
    const std::uint32_t circle =
        (scan_index & 1u) == 0u
            ? scan_index / 2u
            : rows - 1u - scan_index / 2u;
    std::uint32_t reversed = circle;
    reversed = ((reversed & 0x55555555u) << 1u) |
               ((reversed >> 1u) & 0x55555555u);
    reversed = ((reversed & 0x33333333u) << 2u) |
               ((reversed >> 2u) & 0x33333333u);
    reversed = ((reversed & 0x0f0f0f0fu) << 4u) |
               ((reversed >> 4u) & 0x0f0f0f0fu);
    reversed = ((reversed & 0x00ff00ffu) << 8u) |
               ((reversed >> 8u) & 0x00ff00ffu);
    reversed = (reversed << 16u) | (reversed >> 16u);
    return reversed >> (32u - log_rows);
}

class Arena {
  public:
    bool create() {
        return check(stwo_exec_context_create(&context_), "create context") &&
               check(
                   stwo_exec_context_stream(context_, &stream_),
                   "get proof stream");
    }

    std::size_t mark() const {
        return allocations_.size();
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

    std::uint32_t *upload(const void *source, std::size_t words) {
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

    std::uint32_t *pointer_table(
        const std::vector<std::uint32_t *> &pointers) {
        return upload(
            pointers.data(),
            pointers.size() * kPointerWords);
    }

    bool fill(
        std::uint32_t *destination,
        std::uint8_t byte,
        std::size_t words) {
        return check(
            cudaMemsetAsync(
                destination,
                byte,
                words * sizeof(std::uint32_t),
                reinterpret_cast<cudaStream_t>(stream_)),
            "fill relation source");
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

    bool release_since(std::size_t mark) {
        for (std::size_t index = allocations_.size(); index > mark; --index) {
            if (!check(
                    stwo_exec_context_free_u32(
                        context_,
                        allocations_[index - 1]),
                    "free relation words")) {
                return false;
            }
        }
        allocations_.resize(mark);
        return sync("wait for component release");
    }

    bool destroy() {
        if (!release_since(0)) return false;
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

bool compare_words(
    const fixture::Instance &instance,
    const char *kind,
    const std::uint32_t actual[4],
    const std::uint32_t expected[4]) {
    for (std::size_t coordinate = 0; coordinate < 4; ++coordinate) {
        if (actual[coordinate] == expected[coordinate]) continue;
        std::fprintf(
            stderr,
            "%s mismatch component=%s instance=%u coordinate=%zu "
            "expected=%u actual=%u\n",
            kind,
            instance.component,
            instance.component_instance,
            coordinate,
            expected[coordinate],
            actual[coordinate]);
        return false;
    }
    return true;
}

bool run_component(
    Arena &arena,
    std::uint32_t ordinal,
    const fixture::Instance &instance,
    const std::uint32_t *alpha_powers,
    const std::uint32_t *z,
    std::uint32_t cumulative[4],
    std::uint64_t *peak_bytes) {
    const std::size_t mark = arena.mark();
    const std::size_t rows = instance.geometry.rows;
    std::vector<std::uint32_t *> sources;
    if (instance.layout == 0u) {
        const std::size_t source_words =
            rows * instance.lookup_word_columns;
        auto *source = arena.allocate(source_words);
        if (source == nullptr) return false;
        for (std::uint32_t column = 0;
             column < instance.lookup_word_columns;
             ++column) {
            if (!arena.fill(
                    source + static_cast<std::size_t>(column) * rows,
                    source_byte(ordinal, column),
                    rows)) {
                return false;
            }
        }
        sources.push_back(source);
    } else {
        for (std::uint32_t column = 0;
             column < instance.source_pointer_count;
             ++column) {
            auto *source = arena.allocate(rows);
            if (source == nullptr ||
                !arena.fill(
                    source,
                    source_byte(ordinal, column),
                    rows)) {
                return false;
            }
            sources.push_back(source);
        }
    }
    auto *source_table = arena.pointer_table(sources);
    auto *descriptors = arena.upload(
        fixture::kDescriptors + instance.descriptor_offset,
        static_cast<std::size_t>(instance.geometry.columns) * 16u);
    const std::size_t coordinate_count =
        static_cast<std::size_t>(instance.geometry.columns) * 4u;
    auto *coordinates = arena.allocate(coordinate_count * rows);
    std::vector<std::uint32_t *> coordinate_pointers;
    for (std::size_t coordinate = 0;
         coordinate < coordinate_count;
         ++coordinate) {
        coordinate_pointers.push_back(coordinates + coordinate * rows);
    }
    auto *output_table = arena.pointer_table(coordinate_pointers);
    auto *denominators = arena.allocate(
        static_cast<std::size_t>(instance.geometry.columns) * rows * 4u);
    auto *claimed_sum = arena.allocate(4);
    auto *geometry = arena.upload(&instance.geometry, 11);
    auto *source_tables = arena.pointer_table({source_table});
    auto *descriptor_tables = arena.pointer_table({descriptors});
    auto *output_tables = arena.pointer_table({output_table});
    auto *denominator_tables = arena.pointer_table({denominators});
    auto *claimed_sums = arena.pointer_table({claimed_sum});
    auto *reduction =
        arena.allocate(static_cast<std::size_t>(
            instance.geometry.row_blocks) * 4u);
    auto *scan =
        arena.allocate(static_cast<std::size_t>(
            instance.geometry.row_blocks) * 4u);
    if (source_table == nullptr || descriptors == nullptr ||
        coordinates == nullptr || output_table == nullptr ||
        denominators == nullptr || claimed_sum == nullptr ||
        geometry == nullptr || source_tables == nullptr ||
        descriptor_tables == nullptr || output_tables == nullptr ||
        denominator_tables == nullptr || claimed_sums == nullptr ||
        reduction == nullptr || scan == nullptr) {
        return false;
    }

    if (!check(
            stwo_relation_pairs_global_on(
                source_tables,
                descriptor_tables,
                output_tables,
                denominator_tables,
                geometry,
                1,
                instance.geometry.pair_blocks,
                alpha_powers,
                fixture::kMaxAlphaPowers,
                z,
                arena.stream()),
            "evaluate SN2 relation pairs") ||
        !check(
            stwo_relation_fraction_chain_global_on(
                output_tables,
                denominator_tables,
                geometry,
                1,
                instance.geometry.inverse_blocks,
                instance.geometry.row_blocks,
                arena.stream()),
            "accumulate SN2 relation columns") ||
        !check(
            stwo_relation_tail_global_on(
                output_tables,
                claimed_sums,
                geometry,
                1,
                instance.geometry.row_blocks,
                reduction,
                instance.geometry.row_blocks,
                scan,
                instance.geometry.row_blocks * 4u,
                arena.stream()),
            "scan SN2 relation tail")) {
        return false;
    }

    std::uint32_t actual_sum[4] = {};
    std::uint32_t terminal[4] = {};
    const std::size_t last =
        (static_cast<std::size_t>(instance.geometry.columns) - 1u) * 4u;
    const std::uint32_t terminal_row =
        terminal_scan_row(instance.geometry.rows);
    if (!arena.download(actual_sum, claimed_sum, 4)) return false;
    for (std::size_t coordinate = 0; coordinate < 4; ++coordinate) {
        if (!arena.download(
                &terminal[coordinate],
                coordinate_pointers[last + coordinate] + terminal_row,
                1)) {
            return false;
        }
    }
    if (!arena.sync("wait for SN2 relation component")) return false;
    if (!compare_words(
            instance,
            "claimed sum",
            actual_sum,
            instance.claimed_sum)) {
        return false;
    }
    for (std::size_t coordinate = 0; coordinate < 4; ++coordinate) {
        cumulative[coordinate] =
            add_m31(cumulative[coordinate], actual_sum[coordinate]);
        if (terminal[coordinate] != 0u) {
            std::fprintf(
                stderr,
                "tail mismatch component=%s instance=%u row=%u "
                "coordinate=%zu actual=%u\n",
                instance.component,
                instance.component_instance,
                terminal_row,
                coordinate,
                terminal[coordinate]);
            return false;
        }
    }
    if (!compare_words(
            instance,
            "cumulative accumulator",
            cumulative,
            instance.cumulative_sum)) {
        return false;
    }
    const std::uint64_t source_words =
        instance.layout == 0u
            ? static_cast<std::uint64_t>(rows) *
                  instance.lookup_word_columns
            : static_cast<std::uint64_t>(rows) *
                  instance.source_pointer_count;
    const std::uint64_t relation_words =
        static_cast<std::uint64_t>(rows) *
        instance.geometry.columns * 8u;
    *peak_bytes = std::max(
        *peak_bytes,
        (source_words + relation_words) * sizeof(std::uint32_t));
    return arena.release_since(mark);
}

bool run() {
    Arena arena;
    if (!arena.create()) return false;
    auto *drawn = arena.upload(fixture::kDrawnZAlpha, 8);
    auto *alpha_powers =
        arena.allocate(fixture::kMaxAlphaPowers * 4u);
    auto *z = arena.allocate(4);
    if (drawn == nullptr || alpha_powers == nullptr || z == nullptr ||
        !check(
            stwo_relation_expand_challenges_on(
                drawn,
                alpha_powers,
                fixture::kMaxAlphaPowers,
                z,
                arena.stream()),
            "expand SN2 relation challenges")) {
        return false;
    }
    std::vector<std::uint32_t> actual_alpha(
        fixture::kMaxAlphaPowers * 4u);
    std::uint32_t actual_z[4] = {};
    if (!arena.download(
            actual_alpha.data(),
            alpha_powers,
            actual_alpha.size()) ||
        !arena.download(actual_z, z, 4) ||
        !arena.sync("wait for relation challenges") ||
        std::memcmp(
            actual_alpha.data(),
            fixture::kAlphaPowers,
            actual_alpha.size() * sizeof(std::uint32_t)) != 0 ||
        std::memcmp(
            actual_z,
            fixture::kDrawnZAlpha,
            sizeof(actual_z)) != 0) {
        std::fprintf(stderr, "SN2 relation challenge mismatch\n");
        return false;
    }

    std::uint32_t cumulative[4] = {};
    std::uint64_t peak_bytes = 0;
    std::uint64_t coordinate_cells = 0;
    for (std::uint32_t ordinal = 0;
         ordinal < fixture::kInstanceCount;
         ++ordinal) {
        const auto &instance = fixture::kInstances[ordinal];
        if (!run_component(
                arena,
                ordinal,
                instance,
                alpha_powers,
                z,
                cumulative,
                &peak_bytes)) {
            return false;
        }
        coordinate_cells +=
            static_cast<std::uint64_t>(instance.geometry.rows) *
            instance.geometry.columns * 4u;
    }
    if (!arena.destroy()) return false;
    std::printf(
        "SN2 relation cumulative parity passed: components=%zu "
        "coordinate_cells=%llu peak_bytes=%llu jit=0 fallbacks=0 "
        "graph=%016llx\n",
        fixture::kInstanceCount,
        static_cast<unsigned long long>(coordinate_cells),
        static_cast<unsigned long long>(peak_bytes),
        static_cast<unsigned long long>(fixture::kGraphHash));
    return true;
}

}  // namespace

int main() {
    return run() ? 0 : 1;
}
