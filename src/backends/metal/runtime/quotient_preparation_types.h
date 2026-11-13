// Private quotient preparation boundary. Request pointers are borrowed for
// one call. Prepared buffers are ARC-owned until the caller returns, including
// every failure after submission; no proof/cache is published by preparation.
#pragma once
#import <Metal/Metal.h>
#include <stdbool.h>
#include "abi.h"
@class StwoZigMetalRuntime, StwoZigMetalTree, StwoZigMerkleParentChain;

typedef struct {
    void * runtime_ptr;
    const uint32_t * flat_views;
    size_t flat_views_len;
    const uint32_t *const * raw_columns;
    const size_t * raw_column_lengths;
    uint32_t raw_column_count;
    void *const * resident_tree_handles;
    uint32_t resident_tree_count;
    const void * views;
    uint32_t view_count;
    bool raw_views;
    const uint32_t * sample_components;
    const uint32_t * linear_terms;
    uint32_t batch_count;
    bool cache_domain;
    uint32_t domain_log_size;
    uint32_t domain_initial_index;
    uint32_t domain_step_size;
    const uint32_t * domain_x;
    const uint32_t * domain_y;
    uint32_t row_count;
    uint32_t * output;
    void * resident_output_ptr;
    const uint32_t * leaf_seed;
    const uint32_t * node_seed;
    uint32_t domain_prefix_bytes;
    uint32_t hash_family;
    uint32_t * fri_channel_state;
    StwoZigQuotientParityObserverV1 quotient_parity_observer;
    void * budget_context;
    StwoZigExternalBudgetAdmitV1 budget_admit;
    bool retain_domain_cache;
    char * error_message;
    size_t error_message_len;
    StwoZigMetalRuntime *__unsafe_unretained runtime;
    bool commit_tree;
    bool fri_transaction;
    bool profile_quotient;
} StwoZigQuotientPreparationRequest;

typedef struct {
    NSMutableArray<StwoZigMetalTree *> * resident_trees;
    NSArray<id<MTLBuffer>> * resident_quotient_sources;
    bool resident_multi_source;
    id<MTLBuffer> flat_buffer;
    size_t raw_len;
    size_t raw_source_runs;
    bool gpu_raw_upload;
    bool gpu_flat_pack;
    id<MTLBuffer> view_buffer;
    NSData * partial_group_data;
    uint32_t partial_group_count;
    uint32_t partial_total_rows;
    bool gpu_grouped_partials;
    id<MTLBuffer> raw_view_buffer;
    id<MTLBuffer> raw_batch_offset_buffer;
    id<MTLBuffer> partial_group_buffer;
    id<MTLBuffer> partial_row_start_buffer;
    id<MTLBuffer> partial_batch_group_buffer;
    id<MTLBuffer> partial_buffer;
    id<MTLBuffer> sample_buffer;
    id<MTLBuffer> linear_buffer;
    NSUInteger x_offset;
    NSUInteger y_offset;
    id<MTLBuffer> x_buffer;
    id<MTLBuffer> y_buffer;
    id<MTLBuffer> domain_cache_candidate;
    bool build_domain_cache;
    size_t output_bytes;
    bool direct_output;
    id<MTLBuffer> output_buffer;
    NSMutableArray<id<MTLBuffer>> * layers;
    id<MTLBuffer> hash_arena;
    id<MTLBuffer> root_readback;
    id<MTLBuffer> column_offsets;
    id<MTLBuffer> column_logs;
    id<MTLBuffer> leaf_seed_buffer;
    StwoZigMerkleParentChain * parent_plan;
    NSData * layer_word_offsets_data;
    NSData * layer_word_lengths_data;
    uint32_t fri_state_word_offset;
    uint32_t fri_root_word_offset;
    uint32_t fri_alpha_word_offset;
    id<MTLBuffer> fri_channel_buffer;
    uint32_t layer_word_offsets[31];
    uint32_t lifting_log_size;
    NSMutableArray<id<MTLBuffer>> * raw_sources;
    id<MTLCommandBuffer> command;
    double parity_completed_gpu_milliseconds;
} StwoZigQuotientPreparation;
