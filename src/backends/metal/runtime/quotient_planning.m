// Every segmented source run launches a full row grid and read-modify-writes
// every quotient accumulator. Keep that repeated domain traffic bounded.
// Large fragmented inputs gather on the GPU once; smaller inputs retain the
// established CPU flat pack.
static const size_t stwo_zig_quotient_max_segmented_source_runs = 64u;
static const size_t stwo_zig_quotient_resident_segment_min_bytes =
    8u * 1024u * 1024u;
static const size_t stwo_zig_quotient_gpu_flat_pack_min_bytes =
    64u * 1024u * 1024u;
static const NSUInteger stwo_zig_quotient_max_resident_sources = 4u;
static const uint32_t stwo_zig_m31_modulus = UINT32_C(0x7fffffff);

// The public raw-view ABI describes offsets in the logical flattened column
// stream.  This private descriptor replaces that offset with the exact offset
// in one proof-owned resident buffer and records which of the four bounded
// source slots owns it.  Keeping the public ABI unchanged leaves the segmented
// and flat fallbacks byte-for-byte compatible.
typedef struct {
    uint32_t offset, length, batch, shift, direct;
    uint32_t coeff_a, coeff_b, coeff_c, coeff_d;
    uint32_t source_slot;
} StwoZigResidentRawQuotientView;

// One reduction group contains all coefficient-weighted columns which share
// a sample batch and native evaluation geometry.  Reducing them before the
// quotient-domain lift avoids rereading every short column once per lifted
// row.  The intermediate remains planar so the final pass keeps coalesced
// reads and writes.
typedef struct {
    uint32_t view_start;
    uint32_t view_count;
    uint32_t row_count;
    uint32_t partial_offset;
    uint32_t shift;
    uint32_t direct;
} StwoZigResidentRawQuotientGroup;

_Static_assert(sizeof(StwoZigResidentRawQuotientView) == 40u,
               "resident raw quotient view ABI");
_Static_assert(offsetof(StwoZigResidentRawQuotientView, source_slot) == 36u,
               "resident raw quotient source-slot ABI");
_Static_assert(sizeof(StwoZigResidentRawQuotientGroup) == 24u,
               "resident raw quotient group ABI");

typedef struct {
    size_t logical_offset;
    size_t word_count;
    uint32_t physical_offset;
    uint32_t source_slot;
} StwoZigResidentRawColumn;

static uint32_t stwo_zig_reverse_bits_u32(uint32_t value) {
    value = ((value >> 1u) & UINT32_C(0x55555555)) |
        ((value & UINT32_C(0x55555555)) << 1u);
    value = ((value >> 2u) & UINT32_C(0x33333333)) |
        ((value & UINT32_C(0x33333333)) << 2u);
    value = ((value >> 4u) & UINT32_C(0x0f0f0f0f)) |
        ((value & UINT32_C(0x0f0f0f0f)) << 4u);
    value = ((value >> 8u) & UINT32_C(0x00ff00ff)) |
        ((value & UINT32_C(0x00ff00ff)) << 8u);
    return (value >> 16u) | (value << 16u);
}

static bool stwo_zig_checked_mul_u64(uint64_t lhs, uint64_t rhs, uint64_t *out) {
    if (out == NULL || (lhs != 0u && rhs > UINT64_MAX / lhs)) return false;
    *out = lhs * rhs;
    return true;
}

static bool stwo_zig_checked_add_u64(uint64_t lhs, uint64_t rhs, uint64_t *out) {
    if (out == NULL || rhs > UINT64_MAX - lhs) return false;
    *out = lhs + rhs;
    return true;
}

static bool stwo_zig_quotient_domain_circle_additions(
    uint32_t row_count,
    uint32_t log_size,
    uint32_t initial_index,
    uint32_t step_size,
    uint64_t *out
) {
    if (out == NULL || row_count == 0u || log_size == 0u || log_size >= 31u ||
        row_count != (1u << log_size))
        return false;
    uint64_t total = 0u;
    const uint32_t half_count = row_count >> 1u;
    for (uint32_t row = 0u; row < row_count; ++row) {
        const uint32_t domain_index = stwo_zig_reverse_bits_u32(row) >> (32u - log_size);
        const uint32_t local = domain_index < half_count
            ? domain_index
            : domain_index - half_count;
        const uint64_t global = (uint64_t)initial_index + (uint64_t)step_size * local;
        uint32_t exponent = (uint32_t)(global & UINT64_C(0x7fffffff));
        if (domain_index >= half_count)
            exponent = (UINT32_C(0x80000000) - exponent) & UINT32_C(0x7fffffff);
        if (exponent == 0u) continue;
        const uint64_t additions = (uint64_t)(32u - (uint32_t)__builtin_clz(exponent)) +
            (uint64_t)__builtin_popcount(exponent);
        if (!stwo_zig_checked_add_u64(total, additions, &total)) return false;
    }
    *out = total;
    return true;
}

// Stable counting-bucket layout for the quotient's small, dense batch key.
// The shader consumes one contiguous descriptor range per batch instead of
// scanning every descriptor once for every batch.  Stability is intentional:
// it preserves the host's within-batch transcript-power order exactly.
static bool stwo_zig_bucket_resident_raw_quotient_views(
    NSData *mapped_view_data,
    uint32_t view_count,
    uint32_t batch_count,
    NSData **views_out,
    NSData **batch_offsets_out
) {
    if (views_out == NULL || batch_offsets_out == NULL) return false;
    *views_out = nil;
    *batch_offsets_out = nil;
    if (mapped_view_data == nil || view_count == 0u || batch_count == 0u ||
        mapped_view_data.length !=
            (NSUInteger)view_count * sizeof(StwoZigResidentRawQuotientView) ||
        (size_t)batch_count + 1u > SIZE_MAX / sizeof(uint32_t))
        return false;

    NSMutableData *offset_data = [NSMutableData dataWithLength:
        ((NSUInteger)batch_count + 1u) * sizeof(uint32_t)];
    NSMutableData *cursor_data = [NSMutableData dataWithLength:
        (NSUInteger)batch_count * sizeof(uint32_t)];
    NSMutableData *grouped_view_data = [NSMutableData dataWithLength:
        (NSUInteger)view_count * sizeof(StwoZigResidentRawQuotientView)];
    if (offset_data == nil || cursor_data == nil || grouped_view_data == nil)
        return false;

    const StwoZigResidentRawQuotientView *input = mapped_view_data.bytes;
    uint32_t *offsets = offset_data.mutableBytes;
    for (uint32_t view_index = 0u; view_index < view_count; ++view_index) {
        uint32_t batch = input[view_index].batch;
        if (batch >= batch_count || offsets[batch + 1u] == UINT32_MAX)
            return false;
        offsets[batch + 1u] += 1u;
    }
    for (uint32_t batch = 0u; batch < batch_count; ++batch) {
        if (offsets[batch + 1u] > UINT32_MAX - offsets[batch]) return false;
        offsets[batch + 1u] += offsets[batch];
    }
    if (offsets[batch_count] != view_count) return false;

    uint32_t *cursors = cursor_data.mutableBytes;
    memcpy(cursors, offsets, (NSUInteger)batch_count * sizeof(uint32_t));
    StwoZigResidentRawQuotientView *grouped = grouped_view_data.mutableBytes;
    for (uint32_t view_index = 0u; view_index < view_count; ++view_index) {
        uint32_t batch = input[view_index].batch;
        uint32_t destination = cursors[batch]++;
        if (destination >= offsets[batch + 1u]) return false;
        grouped[destination] = input[view_index];
    }
    for (uint32_t batch = 0u; batch < batch_count; ++batch) {
        if (cursors[batch] != offsets[batch + 1u]) return false;
        for (uint32_t view_index = offsets[batch];
             view_index < offsets[batch + 1u];
             ++view_index) {
            if (grouped[view_index].batch != batch) return false;
        }
    }

    *views_out = [grouped_view_data copy];
    *batch_offsets_out = [offset_data copy];
    return *views_out != nil && *batch_offsets_out != nil;
}

// Re-bucket the already batch-contiguous descriptors by their small geometry
// key.  The output order is batch-major then shift-major, with stable order
// inside each group.  Field addition makes the grouping algebraically exact;
// stability nevertheless keeps the transformation easy to audit.
static bool stwo_zig_prepare_resident_quotient_groups(
    NSData *batch_view_data,
    NSData *batch_offset_data,
    uint32_t view_count,
    uint32_t batch_count,
    uint32_t row_count,
    NSData **views_out,
    NSData **groups_out,
    NSData **row_starts_out,
    NSData **batch_groups_out,
    uint32_t *group_count_out,
    uint32_t *total_group_rows_out,
    uint32_t *partial_words_out
) {
    if (views_out == NULL || groups_out == NULL || row_starts_out == NULL ||
        batch_groups_out == NULL || group_count_out == NULL ||
        total_group_rows_out == NULL || partial_words_out == NULL)
        return false;
    *views_out = nil;
    *groups_out = nil;
    *row_starts_out = nil;
    *batch_groups_out = nil;
    *group_count_out = 0u;
    *total_group_rows_out = 0u;
    *partial_words_out = 0u;
    if (batch_view_data == nil || batch_offset_data == nil || view_count == 0u ||
        batch_count == 0u || row_count == 0u ||
        batch_view_data.length !=
            (NSUInteger)view_count * sizeof(StwoZigResidentRawQuotientView) ||
        batch_offset_data.length !=
            ((NSUInteger)batch_count + 1u) * sizeof(uint32_t) ||
        (size_t)batch_count > SIZE_MAX / 32u)
        return false;

    const size_t bucket_count = (size_t)batch_count * 32u;
    if (bucket_count > SIZE_MAX / sizeof(uint32_t)) return false;
    NSMutableData *count_data = [NSMutableData dataWithLength:
        (NSUInteger)bucket_count * sizeof(uint32_t)];
    NSMutableData *bucket_offset_data = [NSMutableData dataWithLength:
        ((NSUInteger)bucket_count + 1u) * sizeof(uint32_t)];
    NSMutableData *cursor_data = [NSMutableData dataWithLength:
        (NSUInteger)bucket_count * sizeof(uint32_t)];
    if (count_data == nil || bucket_offset_data == nil || cursor_data == nil)
        return false;

    const StwoZigResidentRawQuotientView *input = batch_view_data.bytes;
    const uint32_t *batch_offsets = batch_offset_data.bytes;
    uint32_t *counts = count_data.mutableBytes;
    for (uint32_t batch = 0u; batch < batch_count; ++batch) {
        if (batch_offsets[batch] > batch_offsets[batch + 1u] ||
            batch_offsets[batch + 1u] > view_count)
            return false;
        for (uint32_t index = batch_offsets[batch];
             index < batch_offsets[batch + 1u]; ++index) {
            const StwoZigResidentRawQuotientView view = input[index];
            if (view.batch != batch || view.shift >= 32u || view.length == 0u ||
                view.length > row_count)
                return false;
            const size_t bucket = (size_t)batch * 32u + view.shift;
            if (counts[bucket] == UINT32_MAX) return false;
            counts[bucket] += 1u;
        }
    }

    uint32_t *bucket_offsets = bucket_offset_data.mutableBytes;
    uint32_t group_count = 0u;
    for (size_t bucket = 0u; bucket < bucket_count; ++bucket) {
        if (counts[bucket] != 0u) {
            if (group_count == UINT32_MAX) return false;
            group_count += 1u;
        }
        if (counts[bucket] > UINT32_MAX - bucket_offsets[bucket]) return false;
        bucket_offsets[bucket + 1u] = bucket_offsets[bucket] + counts[bucket];
    }
    if (bucket_offsets[bucket_count] != view_count || group_count == 0u)
        return false;

    NSMutableData *grouped_view_data = [NSMutableData dataWithLength:
        (NSUInteger)view_count * sizeof(StwoZigResidentRawQuotientView)];
    NSMutableData *group_data = [NSMutableData dataWithLength:
        (NSUInteger)group_count * sizeof(StwoZigResidentRawQuotientGroup)];
    NSMutableData *row_start_data = [NSMutableData dataWithLength:
        ((NSUInteger)group_count + 1u) * sizeof(uint32_t)];
    NSMutableData *batch_group_data = [NSMutableData dataWithLength:
        ((NSUInteger)batch_count + 1u) * sizeof(uint32_t)];
    if (grouped_view_data == nil || group_data == nil || row_start_data == nil ||
        batch_group_data == nil)
        return false;

    uint32_t *cursors = cursor_data.mutableBytes;
    memcpy(cursors, bucket_offsets, bucket_count * sizeof(uint32_t));
    StwoZigResidentRawQuotientView *grouped = grouped_view_data.mutableBytes;
    for (uint32_t batch = 0u; batch < batch_count; ++batch) {
        for (uint32_t index = batch_offsets[batch];
             index < batch_offsets[batch + 1u]; ++index) {
            const StwoZigResidentRawQuotientView view = input[index];
            const size_t bucket = (size_t)batch * 32u + view.shift;
            const uint32_t destination = cursors[bucket]++;
            if (destination >= bucket_offsets[bucket + 1u]) return false;
            grouped[destination] = view;
        }
    }

    StwoZigResidentRawQuotientGroup *groups = group_data.mutableBytes;
    uint32_t *row_starts = row_start_data.mutableBytes;
    uint32_t *batch_groups = batch_group_data.mutableBytes;
    uint32_t group_index = 0u;
    uint32_t total_group_rows = 0u;
    uint32_t partial_words = 0u;
    for (uint32_t batch = 0u; batch < batch_count; ++batch) {
        batch_groups[batch] = group_index;
        for (uint32_t shift = 0u; shift < 32u; ++shift) {
            const size_t bucket = (size_t)batch * 32u + shift;
            const uint32_t count = counts[bucket];
            if (count == 0u) continue;
            const uint32_t start = bucket_offsets[bucket];
            const StwoZigResidentRawQuotientView first = grouped[start];
            if (first.batch != batch || first.shift != shift ||
                first.length > UINT32_MAX / 4u ||
                total_group_rows > UINT32_MAX - first.length ||
                partial_words > UINT32_MAX - first.length * 4u)
                return false;
            for (uint32_t local = 1u; local < count; ++local) {
                const StwoZigResidentRawQuotientView view = grouped[start + local];
                if (view.batch != batch || view.shift != shift ||
                    view.length != first.length || view.direct != first.direct)
                    return false;
            }
            row_starts[group_index] = total_group_rows;
            groups[group_index] = (StwoZigResidentRawQuotientGroup){
                .view_start = start,
                .view_count = count,
                .row_count = first.length,
                .partial_offset = partial_words,
                .shift = shift,
                .direct = first.direct,
            };
            total_group_rows += first.length;
            partial_words += first.length * 4u;
            group_index += 1u;
        }
    }
    batch_groups[batch_count] = group_index;
    row_starts[group_index] = total_group_rows;
    if (group_index != group_count) return false;

    *views_out = [grouped_view_data copy];
    *groups_out = [group_data copy];
    *row_starts_out = [row_start_data copy];
    *batch_groups_out = [batch_group_data copy];
    *group_count_out = group_count;
    *total_group_rows_out = total_group_rows;
    *partial_words_out = partial_words;
    return *views_out != nil && *groups_out != nil && *row_starts_out != nil &&
        *batch_groups_out != nil;
}

static bool stwo_zig_raw_quotient_view_geometry_is_valid(
    const StwoZigRawQuotientView *view,
    uint32_t row_count,
    uint32_t batch_count
) {
    if (view == NULL || row_count == 0u || batch_count == 0u ||
        (row_count & (row_count - 1u)) != 0u ||
        view->length == 0u || (view->length & (view->length - 1u)) != 0u ||
        view->length > row_count || view->batch >= batch_count ||
        view->direct > 1u ||
        view->coeff_a >= stwo_zig_m31_modulus ||
        view->coeff_b >= stwo_zig_m31_modulus ||
        view->coeff_c >= stwo_zig_m31_modulus ||
        view->coeff_d >= stwo_zig_m31_modulus)
        return false;

    if (view->direct != 0u)
        return view->shift == 1u && view->length == row_count;
    if (view->shift <= 1u || view->shift >= 32u) return false;
    return (row_count >> (view->shift - 1u)) == view->length;
}

// Resolves every active quotient column through only the residency handles
// supplied by this proof.  Admission is all-or-nothing: any host column,
// duplicate/reordered tree, fifth source buffer, malformed geometry, or offset
// ambiguity returns false and the caller keeps the established segmented path.
// Views are stably grouped by batch after source mapping.  The grouping changes
// no coefficient assignment and preserves original order inside every batch.
static bool stwo_zig_prepare_resident_multi_source_quotient(
    const uint32_t *const *raw_columns,
    const size_t *raw_column_lengths,
    uint32_t raw_column_count,
    NSArray<StwoZigMetalTree *> *resident_trees,
    const void *views,
    uint32_t view_count,
    uint32_t row_count,
    uint32_t batch_count,
    NSArray<id<MTLBuffer>> **sources_out,
    NSData **views_out,
    NSData **batch_offsets_out
) {
    if (sources_out == NULL || views_out == NULL || batch_offsets_out == NULL)
        return false;
    *sources_out = nil;
    *views_out = nil;
    *batch_offsets_out = nil;
    if (raw_columns == NULL || raw_column_lengths == NULL ||
        raw_column_count == 0u || resident_trees.count == 0u ||
        views == NULL || view_count == 0u)
        return false;

    // Duplicate tree handles make ownership/order checks ambiguous.  The
    // production scheme supplies each committed tree exactly once.
    for (NSUInteger tree_index = 0u; tree_index < resident_trees.count; ++tree_index) {
        if ([resident_trees indexOfObjectIdenticalTo:resident_trees[tree_index]] != tree_index)
            return false;
    }

    if ((size_t)raw_column_count > SIZE_MAX / sizeof(StwoZigResidentRawColumn) ||
        (size_t)view_count > SIZE_MAX / sizeof(StwoZigResidentRawQuotientView))
        return false;
    NSMutableData *column_data = [NSMutableData dataWithLength:
        (NSUInteger)raw_column_count * sizeof(StwoZigResidentRawColumn)];
    NSMutableData *mapped_view_data = [NSMutableData dataWithLength:
        (NSUInteger)view_count * sizeof(StwoZigResidentRawQuotientView)];
    NSMutableArray<id<MTLBuffer>> *sources =
        [NSMutableArray arrayWithCapacity:stwo_zig_quotient_max_resident_sources];
    if (column_data == nil || mapped_view_data == nil || sources == nil) return false;

    StwoZigResidentRawColumn *columns = column_data.mutableBytes;
    size_t logical_offset = 0u;
    NSUInteger prior_tree_index = 0u;
    bool have_tree = false;
    for (uint32_t column = 0u; column < raw_column_count; ++column) {
        size_t word_count = raw_column_lengths[column];
        if (raw_columns[column] == NULL || word_count == 0u ||
            (word_count & (word_count - 1u)) != 0u ||
            logical_offset > UINT32_MAX)
            return false;

        StwoZigResidentColumnBinding binding;
        if (!stwo_zig_tree_resident_column(
                resident_trees, raw_columns[column], word_count, &binding) ||
            binding.tree == nil || binding.buffer == nil ||
            binding.availableWords < word_count ||
            binding.wordOffset > UINT32_MAX ||
            word_count - 1u > (size_t)UINT32_MAX - binding.wordOffset)
            return false;

        NSUInteger tree_index = [resident_trees indexOfObjectIdenticalTo:binding.tree];
        if (tree_index == NSNotFound || (have_tree && tree_index < prior_tree_index))
            return false;
        prior_tree_index = tree_index;
        have_tree = true;

        NSUInteger source_slot = [sources indexOfObjectIdenticalTo:binding.buffer];
        if (source_slot == NSNotFound) {
            if (sources.count == stwo_zig_quotient_max_resident_sources) return false;
            [sources addObject:binding.buffer];
            source_slot = sources.count - 1u;
        }
        if (source_slot > UINT32_MAX) return false;

        columns[column] = (StwoZigResidentRawColumn){
            .logical_offset = logical_offset,
            .word_count = word_count,
            .physical_offset = (uint32_t)binding.wordOffset,
            .source_slot = (uint32_t)source_slot,
        };
        if (word_count > SIZE_MAX - logical_offset) return false;
        logical_offset += word_count;
    }
    if (sources.count == 0u || sources.count > stwo_zig_quotient_max_resident_sources)
        return false;

    const StwoZigRawQuotientView *input_views =
        (const StwoZigRawQuotientView *)views;
    StwoZigResidentRawQuotientView *mapped_views = mapped_view_data.mutableBytes;
    uint32_t column_index = 0u;
    bool column_seen = false;
    bool have_prior_view = false;
    uint32_t prior_logical_offset = 0u;
    uint32_t prior_batch = 0u;
    for (uint32_t view_index = 0u; view_index < view_count; ++view_index) {
        StwoZigRawQuotientView view = input_views[view_index];
        if (!stwo_zig_raw_quotient_view_geometry_is_valid(&view, row_count, batch_count) ||
            (have_prior_view && view.offset < prior_logical_offset))
            return false;

        while (column_index < raw_column_count &&
               columns[column_index].logical_offset < (size_t)view.offset) {
            if (!column_seen) return false;
            column_index += 1u;
            column_seen = false;
        }
        if (column_index >= raw_column_count ||
            columns[column_index].logical_offset != (size_t)view.offset ||
            columns[column_index].word_count != (size_t)view.length ||
            (column_seen && view.batch < prior_batch))
            return false;

        mapped_views[view_index] = (StwoZigResidentRawQuotientView){
            .offset = columns[column_index].physical_offset,
            .length = view.length,
            .batch = view.batch,
            .shift = view.shift,
            .direct = view.direct,
            .coeff_a = view.coeff_a,
            .coeff_b = view.coeff_b,
            .coeff_c = view.coeff_c,
            .coeff_d = view.coeff_d,
            .source_slot = columns[column_index].source_slot,
        };
        column_seen = true;
        have_prior_view = true;
        prior_logical_offset = view.offset;
        prior_batch = view.batch;
    }
    if (!column_seen || column_index + 1u != raw_column_count) return false;

    NSData *grouped_views = nil;
    NSData *batch_offsets = nil;
    if (!stwo_zig_bucket_resident_raw_quotient_views(
            mapped_view_data,
            view_count,
            batch_count,
            &grouped_views,
            &batch_offsets))
        return false;

    *sources_out = [sources copy];
    *views_out = grouped_views;
    *batch_offsets_out = batch_offsets;
    return *sources_out != nil && *views_out != nil && *batch_offsets_out != nil;
}

static bool stwo_zig_prepare_raw_quotient_views_for_single_source(
    const void *views,
    uint32_t view_count,
    uint32_t batch_count,
    NSData **views_out,
    NSData **batch_offsets_out
) {
    if (views_out == NULL || batch_offsets_out == NULL) return false;
    *views_out = nil;
    *batch_offsets_out = nil;
    if (views == NULL || view_count == 0u ||
        (size_t)view_count > SIZE_MAX / sizeof(StwoZigResidentRawQuotientView))
        return false;
    NSMutableData *mapped_view_data = [NSMutableData dataWithLength:
        (NSUInteger)view_count * sizeof(StwoZigResidentRawQuotientView)];
    if (mapped_view_data == nil) return false;
    const StwoZigRawQuotientView *input_views =
        (const StwoZigRawQuotientView *)views;
    StwoZigResidentRawQuotientView *mapped_views = mapped_view_data.mutableBytes;
    for (uint32_t view_index = 0u; view_index < view_count; ++view_index) {
        StwoZigRawQuotientView view = input_views[view_index];
        mapped_views[view_index] = (StwoZigResidentRawQuotientView){
            .offset = view.offset,
            .length = view.length,
            .batch = view.batch,
            .shift = view.shift,
            .direct = view.direct,
            .coeff_a = view.coeff_a,
            .coeff_b = view.coeff_b,
            .coeff_c = view.coeff_c,
            .coeff_d = view.coeff_d,
            .source_slot = 0u,
        };
    }
    return stwo_zig_bucket_resident_raw_quotient_views(
        mapped_view_data,
        view_count,
        batch_count,
        views_out,
        batch_offsets_out
    );
}

static size_t stwo_zig_quotient_raw_source_run_count(
    const uint32_t *const *raw_columns,
    const size_t *raw_column_lengths,
    uint32_t raw_column_count,
    NSArray<StwoZigMetalTree *> *resident_trees
) {
    size_t runs = 0u;
    size_t column = 0u;
    while (column < raw_column_count) {
        size_t run_start = column;
        size_t run_words = raw_column_lengths[column];
        StwoZigResidentColumnBinding resident_binding;
        bool resident = stwo_zig_tree_resident_column(
            resident_trees, raw_columns[column], raw_column_lengths[column],
            &resident_binding);
        column += 1u;
        if (resident) {
            while (column < raw_column_count) {
                StwoZigResidentColumnBinding next_binding;
                if (!stwo_zig_tree_resident_column(
                        resident_trees, raw_columns[column], raw_column_lengths[column],
                        &next_binding) ||
                    next_binding.buffer != resident_binding.buffer ||
                    run_words > SIZE_MAX - raw_column_lengths[column])
                    break;
                run_words += raw_column_lengths[column];
                column += 1u;
            }
        } else {
            while (column < raw_column_count &&
                   run_words <= SIZE_MAX - raw_column_lengths[column] &&
                   raw_columns[column] == raw_columns[run_start] + run_words) {
                run_words += raw_column_lengths[column];
                column += 1u;
            }
        }
        runs += 1u;
    }
    return runs;
}

static bool stwo_zig_encode_quotient_flat_pack(
    StwoZigMetalRuntime *runtime,
    id<MTLCommandBuffer> command,
    const uint32_t *const *raw_columns,
    const size_t *raw_column_lengths,
    uint32_t raw_column_count,
    NSArray<StwoZigMetalTree *> *resident_trees,
    id<MTLBuffer> destination,
    NSMutableArray<id<MTLBuffer>> *retained_sources
) {
    id<MTLBlitCommandEncoder> pack = [command blitCommandEncoder];
    if (pack == nil) return false;
    size_t destination_offset = 0u;
    size_t page_size = (size_t)getpagesize();
    for (uint32_t column = 0u; column < raw_column_count; ++column) {
        if (raw_column_lengths[column] > SIZE_MAX / sizeof(uint32_t)) {
            [pack endEncoding];
            return false;
        }
        size_t column_bytes = raw_column_lengths[column] * sizeof(uint32_t);
        StwoZigResidentColumnBinding resident_binding;
        bool resident = stwo_zig_tree_resident_column(
            resident_trees, raw_columns[column], raw_column_lengths[column],
            &resident_binding);
        id<MTLBuffer> source = nil;
        size_t source_offset = 0u;
        if (resident) {
            source = resident_binding.buffer;
            source_offset = resident_binding.wordOffset * sizeof(uint32_t);
        } else {
            uintptr_t address = (uintptr_t)raw_columns[column];
            uintptr_t alias_address = address - (address % page_size);
            source_offset = address - alias_address;
            bool alias_shared = runtime.device.hasUnifiedMemory &&
                column_bytes <= SIZE_MAX - source_offset;
            size_t alias_length = 0u;
            if (alias_shared) {
                size_t alias_span = source_offset + column_bytes;
                alias_shared = alias_span <= SIZE_MAX - (page_size - 1u);
                if (alias_shared)
                    alias_length = (alias_span + page_size - 1u) / page_size * page_size;
            }
            source = alias_shared
                ? [runtime.device newBufferWithBytesNoCopy:(void *)alias_address
                                                    length:alias_length
                                                   options:MTLResourceStorageModeShared
                                               deallocator:nil]
                : [runtime.device newBufferWithBytes:raw_columns[column]
                                              length:column_bytes
                                             options:MTLResourceStorageModeShared];
        }
        if (source == nil ||
            source_offset > source.length ||
            column_bytes > source.length - source_offset ||
            destination_offset > destination.length ||
            column_bytes > destination.length - destination_offset) {
            [pack endEncoding];
            return false;
        }
        [retained_sources addObject:source];
        [pack copyFromBuffer:source
               sourceOffset:source_offset
                   toBuffer:destination
          destinationOffset:destination_offset
                       size:column_bytes];
        destination_offset += column_bytes;
    }
    [pack endEncoding];
    return destination_offset == destination.length;
}
