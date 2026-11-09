// Private owned buffers for one quotient transaction; destroyed in the caller scope.
typedef struct {
    __strong NSMutableArray<StwoZigMetalTree *> * resident_trees;
    __strong NSArray<id<MTLBuffer>> * resident_quotient_sources;
    __strong NSData * resident_quotient_views;
    __strong NSData * resident_quotient_batch_offsets;
    bool resident_multi_source;
    __strong id<MTLBuffer> flat_buffer;
    size_t raw_len;
    size_t raw_bytes;
    size_t raw_source_runs;
    bool gpu_raw_upload;
    bool gpu_flat_pack;
    __strong id<MTLBuffer> view_buffer;
    __strong NSData * single_source_raw_views;
    __strong NSData * single_source_batch_offsets;
    __strong NSData * partial_view_data;
    __strong NSData * partial_group_data;
    __strong NSData * partial_row_start_data;
    __strong NSData * partial_batch_group_data;
    uint32_t partial_group_count;
    uint32_t partial_total_rows;
    uint32_t partial_words;
    bool gpu_grouped_partials;
    bool flat_grouping;
    __strong NSData * selected_raw_views;
    __strong id<MTLBuffer> raw_view_buffer;
    __strong NSData * raw_batch_offsets;
    __strong id<MTLBuffer> raw_batch_offset_buffer;
    __strong id<MTLBuffer> partial_group_buffer;
    __strong id<MTLBuffer> partial_row_start_buffer;
    __strong id<MTLBuffer> partial_batch_group_buffer;
    __strong id<MTLBuffer> partial_buffer;
    __strong id<MTLBuffer> sample_buffer;
    __strong id<MTLBuffer> linear_buffer;
    NSUInteger domain_bytes;
    NSUInteger x_offset;
    NSUInteger y_offset;
    __strong id<MTLBuffer> x_buffer;
    __strong id<MTLBuffer> y_buffer;
    __strong id<MTLBuffer> domain_cache_candidate;
    bool build_domain_cache;
    size_t output_bytes;
    size_t page_size;
    bool direct_output;
    __strong id<MTLBuffer> output_buffer;
    __strong NSMutableArray<id<MTLBuffer>> * layers;
    __strong id<MTLBuffer> hash_arena;
    __strong id<MTLBuffer> root_readback;
    __strong id<MTLBuffer> column_offsets;
    __strong id<MTLBuffer> column_logs;
    __strong id<MTLBuffer> leaf_seed_buffer;
    __strong StwoZigMerkleParentChain * parent_plan;
    __strong NSData * layer_word_offsets_data;
    __strong NSData * layer_word_lengths_data;
    uint32_t fri_state_word_offset;
    uint32_t fri_root_word_offset;
    uint32_t fri_alpha_word_offset;
    __strong id<MTLBuffer> fri_channel_buffer;
    uint32_t layer_word_offsets[31];
    uint32_t layer_word_lengths[31];
    uint32_t lifting_log_size;
} StwoZigQuotientPrepared;

static bool stwo_zig_prepare_quotient_buffers(
    StwoZigMetalRuntime *runtime, bool commit_tree, bool profile_quotient, bool fri_transaction,
    void *runtime_ptr,
    const uint32_t *flat_views,
    size_t flat_views_len,
    const uint32_t *const *raw_columns,
    const size_t *raw_column_lengths,
    uint32_t raw_column_count,
    void *const *resident_tree_handles,
    uint32_t resident_tree_count,
    const void *views,
    uint32_t view_count,
    bool raw_views,
    const uint32_t *sample_components,
    const uint32_t *linear_terms,
    uint32_t batch_count,
    bool cache_domain,
    uint32_t domain_log_size,
    uint32_t domain_initial_index,
    uint32_t domain_step_size,
    const uint32_t *domain_x,
    const uint32_t *domain_y,
    uint32_t row_count,
    uint32_t *output,
    void *resident_output_ptr,
    const uint32_t *leaf_seed,
    const uint32_t *node_seed,
    uint32_t domain_prefix_bytes,
    uint32_t hash_family,
    uint32_t *fri_channel_state,
    StwoZigQuotientParityObserverV1 quotient_parity_observer,
    void *budget_context,
    StwoZigExternalBudgetAdmitV1 budget_admit,
    bool retain_domain_cache,
    char *error_message,
    size_t error_message_len,
    StwoZigQuotientPrepared *p
) {
        NSMutableArray<StwoZigMetalTree *> *resident_trees =
            [NSMutableArray arrayWithCapacity:resident_tree_count];
        for (uint32_t i = 0u; i < resident_tree_count; ++i) {
            StwoZigMetalTree *tree = (__bridge StwoZigMetalTree *)resident_tree_handles[i];
            if (tree == nil || tree.runtimeOwner != runtime) {
                write_error(error_message, error_message_len,
                            @"Metal quotient residency handle belongs to another runtime");
                return false;
            }
            [resident_trees addObject:tree];
        }
        NSArray<id<MTLBuffer>> *resident_quotient_sources = nil;
        NSData *resident_quotient_views = nil;
        NSData *resident_quotient_batch_offsets = nil;
        bool resident_multi_source = false;
        id<MTLBuffer> flat_buffer;
        size_t raw_len = 0;
        size_t raw_bytes = 0u;
        size_t raw_source_runs = 0u;
        bool gpu_raw_upload = false;
        bool gpu_flat_pack = false;
        if (raw_views) {
            for (uint32_t i = 0; i < raw_column_count; ++i) {
                if (raw_column_lengths[i] > SIZE_MAX - raw_len) {
                    write_error(error_message, error_message_len,
                                @"Metal quotient raw input length overflow");
                    return false;
                }
                raw_len += raw_column_lengths[i];
            }
            if (raw_len > SIZE_MAX / sizeof(uint32_t)) {
                write_error(error_message, error_message_len,
                            @"Metal quotient raw input byte length overflow");
                return false;
            }
            if (!stwo_zig_metal_validate_raw_quotient_source_views_v2(
                    raw_column_lengths,
                    raw_column_count,
                    (const StwoZigRawQuotientSourceViewV2 *)views,
                    view_count,
                    row_count,
                    batch_count)) {
                write_error(error_message, error_message_len,
                            @"Metal quotient raw source-view authority is invalid");
                return false;
            }
            raw_bytes = raw_len * sizeof(uint32_t);
            bool resident_segment_candidate =
                resident_tree_count != 0u &&
                raw_bytes >= stwo_zig_quotient_resident_segment_min_bytes;
            bool large_segment_candidate =
                raw_bytes >= stwo_zig_quotient_gpu_flat_pack_min_bytes;
            bool segmented_candidate =
                resident_segment_candidate || large_segment_candidate;
            if (segmented_candidate &&
                !stwo_zig_quotient_raw_source_run_count_v2(
                    raw_columns,
                    raw_column_lengths,
                    raw_column_count,
                    resident_trees,
                    &raw_source_runs)) {
                write_error(error_message, error_message_len,
                            @"Metal quotient raw source-run planning failed");
                return false;
            }
            gpu_raw_upload =
                segmented_candidate &&
                stwo_zig_metal_prefer_segmented_quotient_v2(raw_len, raw_source_runs);
            resident_multi_source =
                segmented_candidate &&
                stwo_zig_prepare_resident_multi_source_quotient(
                    raw_columns,
                    raw_column_lengths,
                    raw_column_count,
                    resident_trees,
                    views,
                    view_count,
                    row_count,
                    batch_count,
                    &resident_quotient_sources,
                    &resident_quotient_views,
                    &resident_quotient_batch_offsets
                );
            gpu_flat_pack =
                large_segment_candidate && !resident_multi_source && !gpu_raw_upload;
            if (quotient_parity_observer != NULL &&
                (!gpu_raw_upload || resident_multi_source)) {
                write_error(error_message, error_message_len,
                            @"Metal quotient internal parity requires the segmented raw path");
                return false;
            }
            flat_buffer = (resident_multi_source || gpu_raw_upload)
                ? stwo_quotient_owned_buffer(runtime.device, NULL, sizeof(uint32_t), MTLResourceStorageModeShared, budget_context, budget_admit)
                : stwo_quotient_owned_buffer(runtime.device, NULL, raw_len * sizeof(uint32_t), gpu_flat_pack
                                                  ? MTLResourceStorageModePrivate
                                                  : MTLResourceStorageModeShared, budget_context, budget_admit);
            if (flat_buffer == nil) return false;
            if (!resident_multi_source && !gpu_raw_upload && !gpu_flat_pack) {
                uint32_t *destination = flat_buffer.contents;
                size_t cursor = 0;
                for (uint32_t i = 0; i < raw_column_count; ++i) {
                    memcpy(destination + cursor, raw_columns[i], raw_column_lengths[i] * sizeof(uint32_t));
                    cursor += raw_column_lengths[i];
                }
            }
        } else {
            flat_buffer = stwo_quotient_owned_buffer(runtime.device, flat_views, flat_views_len * sizeof(uint32_t), MTLResourceStorageModeShared, budget_context, budget_admit);
        }
        id<MTLBuffer> view_buffer = raw_views ? nil :
            stwo_quotient_owned_buffer(runtime.device, views, (NSUInteger)view_count * 5u * sizeof(uint32_t), MTLResourceStorageModeShared, budget_context, budget_admit);
        NSData *single_source_raw_views = nil;
        NSData *single_source_batch_offsets = nil;
        if (raw_views && !resident_multi_source && !gpu_raw_upload &&
            !stwo_zig_prepare_raw_quotient_views_for_single_source(
                views,
                view_count,
                row_count,
                batch_count,
                &single_source_raw_views,
                &single_source_batch_offsets)) {
            write_error(error_message, error_message_len,
                        @"Metal quotient batch-index planning failed");
            return false;
        }
        NSData *partial_view_data = nil;
        NSData *partial_group_data = nil;
        NSData *partial_row_start_data = nil;
        NSData *partial_batch_group_data = nil;
        uint32_t partial_group_count = 0u;
        uint32_t partial_total_rows = 0u;
        uint32_t partial_words = 0u;
        bool gpu_grouped_partials = false;
        // Flat and resident inputs use the same checked source-view ABI.
        // Group at native heights before lifting, regardless of source custody.
        const bool flat_grouping = single_source_raw_views != nil &&
            getenv("STWO_ZIG_METAL_DIRECT_FLAT_QUOTIENT") == NULL;
        if ((resident_multi_source || flat_grouping) &&
            raw_bytes >= stwo_zig_quotient_gpu_flat_pack_min_bytes &&
            stwo_zig_prepare_resident_quotient_groups(
                resident_multi_source ? resident_quotient_views : single_source_raw_views,
                resident_multi_source ? resident_quotient_batch_offsets : single_source_batch_offsets,
                view_count,
                batch_count,
                row_count,
                &partial_view_data,
                &partial_group_data,
                &partial_row_start_data,
                &partial_batch_group_data,
                &partial_group_count,
                &partial_total_rows,
                &partial_words
            )) {
            const uint64_t partial_bytes = (uint64_t)partial_words * sizeof(uint32_t);
            // Compare evaluated cells, not temporary bytes with input bytes.
            // Mixed-log guest traces can have tiny source columns lifted over
            // millions of quotient rows. Their grouped intermediate is larger
            // than the inputs but avoids rereading each column at every row.
            // Keep the established one-GiB cap and require at least a 2x work
            // reduction before admitting the extra intermediate.
            uint64_t direct_cells = 0u;
            uint64_t grouped_cells = 0u;
            bool bounded_work = stwo_zig_checked_mul_u64(row_count, view_count, &direct_cells) &&
                stwo_zig_checked_mul_u64(row_count, partial_group_count, &grouped_cells);
            const StwoZigResidentRawQuotientGroup *groups = partial_group_data.bytes;
            for (uint32_t group = 0u; bounded_work && group < partial_group_count; ++group) {
                uint64_t cells = 0u;
                bounded_work = stwo_zig_checked_mul_u64(groups[group].row_count, groups[group].view_count, &cells) &&
                    stwo_zig_checked_add_u64(grouped_cells, cells, &grouped_cells);
            }
            gpu_grouped_partials = bounded_work &&
                partial_bytes <= UINT64_C(1024) * 1024u * 1024u &&
                grouped_cells <= direct_cells / 2u;
        }
        if (profile_quotient) {
            fprintf(stderr,
                    "Metal quotient shape: raw_bytes=%zu columns=%u views=%u "
                    "source_runs=%zu resident_sources=%lu resident_trees=%u "
                    "batches=%u rows=%u path=%s groups=%u partial_bytes=%llu\n",
                    raw_bytes, raw_column_count, view_count, raw_source_runs,
                    (unsigned long)resident_quotient_sources.count,
                    resident_tree_count, batch_count, row_count,
                    gpu_grouped_partials ? (resident_multi_source ? "resident-partials" : "flat-partials") :
                        (resident_multi_source ? "resident-direct" :
                            (gpu_raw_upload ? "segmented" :
                                (gpu_flat_pack ? "gpu-flat" : "cpu-flat"))),
                    gpu_grouped_partials ? partial_group_count : 0u,
                    (unsigned long long)(gpu_grouped_partials
                        ? (uint64_t)partial_words * sizeof(uint32_t)
                        : 0u));
        }
        NSData *selected_raw_views = gpu_grouped_partials
            ? partial_view_data
            : (resident_multi_source ? resident_quotient_views : single_source_raw_views);
        id<MTLBuffer> raw_view_buffer = selected_raw_views != nil
            ? stwo_quotient_owned_buffer(runtime.device, selected_raw_views.bytes, selected_raw_views.length, MTLResourceStorageModeShared, budget_context, budget_admit)
            : nil;
        NSData *raw_batch_offsets = resident_multi_source
            ? resident_quotient_batch_offsets
            : single_source_batch_offsets;
        id<MTLBuffer> raw_batch_offset_buffer = raw_batch_offsets == nil
            ? nil
            : stwo_quotient_owned_buffer(runtime.device, raw_batch_offsets.bytes, raw_batch_offsets.length, MTLResourceStorageModeShared, budget_context, budget_admit);
        id<MTLBuffer> partial_group_buffer = gpu_grouped_partials
            ? stwo_quotient_owned_buffer(runtime.device, partial_group_data.bytes, partial_group_data.length, MTLResourceStorageModeShared, budget_context, budget_admit)
            : nil;
        id<MTLBuffer> partial_row_start_buffer = gpu_grouped_partials
            ? stwo_quotient_owned_buffer(runtime.device, partial_row_start_data.bytes, partial_row_start_data.length, MTLResourceStorageModeShared, budget_context, budget_admit)
            : nil;
        id<MTLBuffer> partial_batch_group_buffer = gpu_grouped_partials
            ? stwo_quotient_owned_buffer(runtime.device, partial_batch_group_data.bytes, partial_batch_group_data.length, MTLResourceStorageModeShared, budget_context, budget_admit)
            : nil;
        id<MTLBuffer> partial_buffer = gpu_grouped_partials
            ? stwo_quotient_owned_buffer(runtime.device, NULL, (NSUInteger)partial_words * sizeof(uint32_t), MTLResourceStorageModePrivate, budget_context, budget_admit)
            : nil;
        id<MTLBuffer> sample_buffer = stwo_quotient_owned_buffer(runtime.device, sample_components, (NSUInteger)batch_count * 8u * sizeof(uint32_t), MTLResourceStorageModeShared, budget_context, budget_admit);
        id<MTLBuffer> linear_buffer = stwo_quotient_owned_buffer(runtime.device, linear_terms, (NSUInteger)batch_count * 8u * sizeof(uint32_t), MTLResourceStorageModeShared, budget_context, budget_admit);
        NSUInteger domain_bytes = (NSUInteger)row_count * sizeof(uint32_t);
        NSUInteger x_offset = 0u;
        NSUInteger y_offset = 0u;
        id<MTLBuffer> x_buffer = nil;
        id<MTLBuffer> y_buffer = nil;
        id<MTLBuffer> domain_cache_candidate = nil;
        bool build_domain_cache = false;
        if (cache_domain) {
            // A local strong reference keeps a hit alive if another proof
            // replaces the one-entry cache after this synchronized lookup.
            if (retain_domain_cache) @synchronized(runtime) {
                if (runtime.quotientDomainCache != nil &&
                    runtime.quotientDomainCacheRowCount == row_count &&
                    runtime.quotientDomainCacheLogSize == domain_log_size &&
                    runtime.quotientDomainCacheInitialIndex == domain_initial_index &&
                    runtime.quotientDomainCacheStepSize == domain_step_size) {
                    domain_cache_candidate = runtime.quotientDomainCache;
                }
            }
            if (domain_cache_candidate == nil) {
                domain_cache_candidate = stwo_quotient_owned_buffer(runtime.device, NULL, 2u * domain_bytes, MTLResourceStorageModeShared, budget_context, budget_admit);
                build_domain_cache = true;
            }
            x_buffer = domain_cache_candidate;
            y_buffer = domain_cache_candidate;
            y_offset = domain_bytes;
        } else {
            x_buffer = stwo_quotient_owned_buffer(runtime.device, domain_x, domain_bytes, MTLResourceStorageModeShared, budget_context, budget_admit);
            y_buffer = stwo_quotient_owned_buffer(runtime.device, domain_y, domain_bytes, MTLResourceStorageModeShared, budget_context, budget_admit);
        }
        size_t output_bytes = (size_t)row_count * 4u * sizeof(uint32_t);
        size_t page_size = (size_t)getpagesize();
        bool direct_output = ((uintptr_t)output % page_size) == 0u && (output_bytes % page_size) == 0u;
        id<MTLBuffer> output_buffer = resident_output_ptr != NULL
            ? (__bridge id<MTLBuffer>)resident_output_ptr
            : (direct_output
                ? [runtime.device newBufferWithBytesNoCopy:output
                                                    length:output_bytes
                                                   options:MTLResourceStorageModeShared
                                               deallocator:nil]
                : stwo_quotient_owned_buffer(runtime.device, NULL, output_bytes, MTLResourceStorageModeShared, budget_context, budget_admit));
        if (resident_output_ptr != NULL &&
            (output_buffer.length != output_bytes || output_buffer.contents != output)) {
            write_error(error_message, error_message_len, @"Resident quotient output shape mismatch");
            return false;
        }
        if (flat_buffer == nil || (!raw_views && view_buffer == nil) ||
            (resident_multi_source && raw_view_buffer == nil) ||
            (raw_views && !resident_multi_source && !gpu_raw_upload && raw_view_buffer == nil) ||
            (raw_views && !gpu_raw_upload && raw_batch_offset_buffer == nil) ||
            (gpu_grouped_partials &&
                (partial_group_buffer == nil || partial_row_start_buffer == nil ||
                 partial_batch_group_buffer == nil || partial_buffer == nil)) ||
            sample_buffer == nil ||
            linear_buffer == nil || x_buffer == nil || y_buffer == nil || output_buffer == nil) {
            write_error(error_message, error_message_len, @"Metal quotient allocation failed");
            return false;
        }

        NSMutableArray<id<MTLBuffer>> *layers = nil;
        id<MTLBuffer> hash_arena = nil;
        id<MTLBuffer> root_readback = nil;
        id<MTLBuffer> column_offsets = nil;
        id<MTLBuffer> column_logs = nil;
        id<MTLBuffer> leaf_seed_buffer = nil;
        StwoZigMerkleParentChain *parent_plan = nil;
        NSData *layer_word_offsets_data = nil;
        NSData *layer_word_lengths_data = nil;
        const uint32_t fri_state_word_offset = 0u;
        const uint32_t fri_root_word_offset = 16u;
        const uint32_t fri_alpha_word_offset = 24u;
        id<MTLBuffer> fri_channel_buffer = nil;
        uint32_t layer_word_offsets[31] = { 0u };
        uint32_t layer_word_lengths[31] = { 0u };
        uint32_t lifting_log_size = 0u;
        if (commit_tree) {
            if (row_count > UINT32_MAX / 4u || (row_count & (row_count - 1u)) != 0u) {
                write_error(error_message, error_message_len, @"Resident quotient row count is invalid");
                return false;
            }
            lifting_log_size = 31u - (uint32_t)__builtin_clz(row_count);
            uint32_t offsets[4] = { 0u, row_count, 2u * row_count, 3u * row_count };
            uint32_t logs[4] = { lifting_log_size, lifting_log_size, lifting_log_size, lifting_log_size };
            column_offsets = stwo_quotient_owned_buffer(runtime.device, offsets, sizeof(offsets), MTLResourceStorageModeShared, budget_context, budget_admit);
            column_logs = stwo_quotient_owned_buffer(runtime.device, logs, sizeof(logs), MTLResourceStorageModeShared, budget_context, budget_admit);
            leaf_seed_buffer = stwo_quotient_owned_buffer(runtime.device, leaf_seed, 8u * sizeof(uint32_t), MTLResourceStorageModeShared, budget_context, budget_admit);
            layers = [NSMutableArray arrayWithCapacity:lifting_log_size + 1u];
            uint32_t layer_count = row_count;
            uint64_t arena_words = 0u;
            for (uint32_t level = 0u; level <= lifting_log_size; ++level) {
                arena_words = (arena_words + 63u) & ~UINT64_C(63);
                uint64_t length_words = (uint64_t)layer_count * 8u;
                if (arena_words > UINT32_MAX || length_words > UINT32_MAX ||
                    arena_words + length_words > UINT32_MAX) {
                    write_error(error_message, error_message_len, @"Resident quotient Merkle arena exceeds word offsets");
                    return false;
                }
                layer_word_offsets[level] = (uint32_t)arena_words;
                layer_word_lengths[level] = (uint32_t)length_words;
                arena_words += length_words;
                layer_count >>= 1u;
            }
            hash_arena = stwo_quotient_owned_buffer(runtime.device, NULL, (NSUInteger)arena_words * sizeof(uint32_t), runtime.device.hasUnifiedMemory
                                                         ? MTLResourceStorageModeShared
                                                         : MTLResourceStorageModePrivate, budget_context, budget_admit);
            root_readback = runtime.device.hasUnifiedMemory ? hash_arena
                : stwo_quotient_owned_buffer(runtime.device, NULL, 32u, MTLResourceStorageModeShared, budget_context, budget_admit);
            layer_word_offsets_data = [NSData dataWithBytes:layer_word_offsets
                                                    length:(NSUInteger)(lifting_log_size + 1u) * sizeof(uint32_t)];
            layer_word_lengths_data = [NSData dataWithBytes:layer_word_lengths
                                                    length:(NSUInteger)(lifting_log_size + 1u) * sizeof(uint32_t)];
            if (column_offsets == nil || column_logs == nil || leaf_seed_buffer == nil ||
                hash_arena == nil || root_readback == nil || layer_word_offsets_data == nil ||
                layer_word_lengths_data == nil) {
                write_error(error_message, error_message_len, @"Resident quotient Merkle metadata allocation failed");
                return false;
            }
            for (uint32_t level = 0u; level <= lifting_log_size; ++level) [layers addObject:hash_arena];

            uint32_t child_offsets[30] = { 0u };
            uint32_t destination_offsets[30] = { 0u };
            uint32_t parent_counts[30] = { 0u };
            for (uint32_t level = 0u; level < lifting_log_size; ++level) {
                child_offsets[level] = layer_word_offsets[level];
                destination_offsets[level] = layer_word_offsets[level + 1u];
                parent_counts[level] = row_count >> (level + 1u);
            }
            // The parent plan owns one private GPU node-seed buffer.
            if (!budget_admit(budget_context, 32u)) return false;
            void *parent_plan_ptr = stwo_zig_metal_merkle_parent_chain_prepare_v2(
                runtime_ptr, child_offsets, destination_offsets, parent_counts,
                lifting_log_size, node_seed, domain_prefix_bytes, hash_family,
                error_message, error_message_len);
            if (parent_plan_ptr != NULL)
                parent_plan = (__bridge_transfer StwoZigMerkleParentChain *)parent_plan_ptr;
            if (parent_plan == nil) {
                write_error(error_message, error_message_len, @"Resident quotient parent-chain allocation failed");
                return false;
            }
            if (fri_transaction) {
                fri_channel_buffer = stwo_quotient_owned_buffer(runtime.device, NULL, 
                    (NSUInteger)(fri_alpha_word_offset + 4u) * sizeof(uint32_t), MTLResourceStorageModeShared, budget_context, budget_admit);
                if (fri_channel_buffer == nil) {
                    write_error(error_message, error_message_len, @"Resident FRI transcript allocation failed");
                    return false;
                }
                memset(fri_channel_buffer.contents, 0, fri_channel_buffer.length);
                memcpy((uint32_t *)fri_channel_buffer.contents + fri_state_word_offset,
                       fri_channel_state, (hash_family == StwoZigCommitmentHashFamilyBlake3V1 ? 11u : 10u) * sizeof(uint32_t));
            }
        }

    p->resident_trees = resident_trees;
    p->resident_quotient_sources = resident_quotient_sources;
    p->resident_quotient_views = resident_quotient_views;
    p->resident_quotient_batch_offsets = resident_quotient_batch_offsets;
    p->resident_multi_source = resident_multi_source;
    p->flat_buffer = flat_buffer;
    p->raw_len = raw_len;
    p->raw_bytes = raw_bytes;
    p->raw_source_runs = raw_source_runs;
    p->gpu_raw_upload = gpu_raw_upload;
    p->gpu_flat_pack = gpu_flat_pack;
    p->view_buffer = view_buffer;
    p->single_source_raw_views = single_source_raw_views;
    p->single_source_batch_offsets = single_source_batch_offsets;
    p->partial_view_data = partial_view_data;
    p->partial_group_data = partial_group_data;
    p->partial_row_start_data = partial_row_start_data;
    p->partial_batch_group_data = partial_batch_group_data;
    p->partial_group_count = partial_group_count;
    p->partial_total_rows = partial_total_rows;
    p->partial_words = partial_words;
    p->gpu_grouped_partials = gpu_grouped_partials;
    p->flat_grouping = flat_grouping;
    p->selected_raw_views = selected_raw_views;
    p->raw_view_buffer = raw_view_buffer;
    p->raw_batch_offsets = raw_batch_offsets;
    p->raw_batch_offset_buffer = raw_batch_offset_buffer;
    p->partial_group_buffer = partial_group_buffer;
    p->partial_row_start_buffer = partial_row_start_buffer;
    p->partial_batch_group_buffer = partial_batch_group_buffer;
    p->partial_buffer = partial_buffer;
    p->sample_buffer = sample_buffer;
    p->linear_buffer = linear_buffer;
    p->domain_bytes = domain_bytes;
    p->x_offset = x_offset;
    p->y_offset = y_offset;
    p->x_buffer = x_buffer;
    p->y_buffer = y_buffer;
    p->domain_cache_candidate = domain_cache_candidate;
    p->build_domain_cache = build_domain_cache;
    p->output_bytes = output_bytes;
    p->page_size = page_size;
    p->direct_output = direct_output;
    p->output_buffer = output_buffer;
    p->layers = layers;
    p->hash_arena = hash_arena;
    p->root_readback = root_readback;
    p->column_offsets = column_offsets;
    p->column_logs = column_logs;
    p->leaf_seed_buffer = leaf_seed_buffer;
    p->parent_plan = parent_plan;
    p->layer_word_offsets_data = layer_word_offsets_data;
    p->layer_word_lengths_data = layer_word_lengths_data;
    p->fri_state_word_offset = fri_state_word_offset;
    p->fri_root_word_offset = fri_root_word_offset;
    p->fri_alpha_word_offset = fri_alpha_word_offset;
    p->fri_channel_buffer = fri_channel_buffer;
    memcpy(p->layer_word_offsets, layer_word_offsets, sizeof(p->layer_word_offsets));
    memcpy(p->layer_word_lengths, layer_word_lengths, sizeof(p->layer_word_lengths));
    p->lifting_log_size = lifting_log_size;
    return true;
}
