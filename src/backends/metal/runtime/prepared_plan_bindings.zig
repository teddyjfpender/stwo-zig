//! Objective-C ABI for preparing and executing immutable resident plans.
//! Objective-C/Metal entry points consumed by the Zig runtime stages.

const runtime = @import("../runtime.zig");

const WitnessLayout = runtime.WitnessLayout;
const BasePolynomialDispatch = runtime.BasePolynomialDispatch;
const FrameworkPolynomialDispatch = runtime.FrameworkPolynomialDispatch;
const BasePolynomialOutput = runtime.BasePolynomialOutput;
const LookupPolynomialDispatch = runtime.LookupPolynomialDispatch;

pub extern fn stwo_zig_metal_witness_feed_prepare(
    runtime: *anyopaque,
    descriptors: [*]const u32,
    descriptor_count: u32,
    luts: [*]const u32,
    lut_words: usize,
    destination_offsets: [*]const u32,
    destination_count: usize,
    source_offsets: [*]const u32,
    source_count: usize,
    clear_ranges: [*]const [2]u32,
    clear_range_count: u32,
    clear_max_length: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_witness_feed_batch_prepare(
    runtime: *anyopaque,
    plans: [*]const *anyopaque,
    column_lengths: [*]const u32,
    plan_count: u32,
    clear_ranges: [*]const [2]u32,
    clear_range_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_witness_feed_batch_counts_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    batch: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_witness_feed_batch_clear_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    batch: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_witness_feed_batch_index_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    batch: *anyopaque,
    index: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_circle_lde_prepare(
    runtime: *anyopaque,
    source_offsets: [*]const u64,
    destination_offsets: [*]const u64,
    column_count: u32,
    base_log_size: u32,
    extended_log_size: u32,
    twiddle_offset_words: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_circle_lde_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_circle_ifft_prepare(
    runtime: *anyopaque,
    source_offsets: [*]const u64,
    destination_offsets: [*]const u64,
    column_count: u32,
    log_size: u32,
    twiddle_offset_words: u32,
    scale_factor: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_circle_ifft_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_fixed_table_prepare(
    runtime: *anyopaque,
    descriptors: [*]const u32,
    descriptor_words: u32,
    source_offsets: [*]const u32,
    source_count: u32,
    multiplicity_offsets: [*]const u32,
    multiplicity_count: u32,
    destination_offset: u32,
    row_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_fixed_table_batch_prepare(
    runtime: *anyopaque,
    plans: [*]const *anyopaque,
    plan_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_fixed_table_batch_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    batch: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_merkle_parent_chain_prepare(
    runtime: *anyopaque,
    child_offsets: [*]const u32,
    destination_offsets: [*]const u32,
    parent_counts: [*]const u32,
    level_count: u32,
    node_seed: *const [8]u32,
    prefix_bytes: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_merkle_parent_chain_prepare_v2(
    runtime: *anyopaque,
    child_offsets: [*]const u32,
    destination_offsets: [*]const u32,
    parent_counts: [*]const u32,
    level_count: u32,
    node_seed: *const [8]u32,
    prefix_bytes: u32,
    hash_family: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_merkle_leaf_prepare(
    runtime: *anyopaque,
    column_offsets: [*]const u32,
    column_log_sizes: [*]const u32,
    column_count: u32,
    lifting_log_size: u32,
    destination_offset: u32,
    leaf_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_merkle_leaf_prepare_v2(
    runtime: *anyopaque,
    column_offsets: [*]const u32,
    column_log_sizes: [*]const u32,
    column_count: u32,
    lifting_log_size: u32,
    destination_offset: u32,
    leaf_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    hash_family: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_merkle_leaf_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_resident_merkle_prepare(
    runtime: *anyopaque,
    column_offsets: [*]const u32,
    column_log_sizes: [*]const u32,
    column_count: u32,
    lifting_log_size: u32,
    layer_offsets: [*]const u32,
    layer_count: u32,
    leaf_seed: *const [8]u32,
    node_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_resident_merkle_prepare_v2(
    runtime: *anyopaque,
    column_offsets: [*]const u32,
    column_log_sizes: [*]const u32,
    column_count: u32,
    lifting_log_size: u32,
    layer_offsets: [*]const u32,
    layer_count: u32,
    leaf_seed: *const [8]u32,
    node_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    hash_family: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_resident_merkle_prepare_staged_poseidon_v1(
    runtime: *anyopaque,
    column_offsets: [*]const u32,
    column_log_sizes: [*]const u32,
    column_count: u32,
    lifting_log_size: u32,
    layer_offsets: [*]const u32,
    layer_count: u32,
    leaf_seed: *const [8]u32,
    node_seed: *const [8]u32,
    domain_prefix_bytes: u32,
    state_offsets: *const [2]u32,
    state_offset_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_resident_merkle_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_merkle_parent_chain_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_ec_op_prepare(
    runtime: *anyopaque,
    execution_offsets: *const [37]u32,
    trace_offsets: *const [273]u32,
    partial_offsets: *const [127]u32,
    multiplicity_offsets: *const [4]u32,
    lookup_offset: u32,
    segment_offset: u32,
    scratch_offset: u32,
    row_count: u32,
    write_base: bool,
    write_lookup: bool,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_ec_op_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_compact_prepare(
    runtime: *anyopaque,
    source_offsets: [*]const u32,
    source_count: u32,
    descriptors: [*]const u32,
    descriptor_words: u32,
    output_offsets: [*]const u32,
    output_count: u32,
    params: *const [21]u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_compact_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_eval_prepare(
    runtime: *anyopaque,
    source: [*]const u8,
    source_len: usize,
    name: [*]const u8,
    name_len: usize,
    arguments: *const [14]u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_eval_library_load(
    runtime: *anyopaque,
    path: [*]const u8,
    path_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_eval_library_compile(
    runtime: *anyopaque,
    source: [*]const u8,
    source_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_witness_prepare_library(
    runtime: *anyopaque,
    library: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    arguments: *const WitnessLayout,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_witness_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    plan: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_eval_prepare_library(
    runtime: *anyopaque,
    library: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    arguments: *const [14]u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_framework_polynomial_prepare_aot(
    runtime: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    column_trees: [*]const u32,
    column_count: u32,
    profile_word_count: u32,
    relation_word_count: u32,
    power_word_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_framework_polynomial_batch(
    runtime: *anyopaque,
    trees: [*]const ?*anyopaque,
    tree_count: u32,
    composition_domain_buffer: ?*anyopaque,
    composition_domain_host_begin: ?[*]const u32,
    composition_domain_word_count: usize,
    columns: [*]const ?[*]const u32,
    column_count: u32,
    dispatches: [*]const FrameworkPolynomialDispatch,
    dispatch_count: u32,
    profile_words: [*]const u32,
    profile_word_count: u32,
    relation_words: [*]const u32,
    relation_word_count: u32,
    power_words: [*]const u32,
    power_word_count: u32,
    outputs: [*]const BasePolynomialOutput,
    output_count: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) u32;
pub extern fn stwo_zig_metal_base_polynomial_prepare_aot(
    runtime: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_base_polynomial_prepare_library(
    runtime: *anyopaque,
    library: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_base_polynomial_batch(
    runtime: *anyopaque,
    trees: [*]const ?*anyopaque,
    tree_count: u32,
    composition_domain_buffer: ?*anyopaque,
    composition_domain_host_begin: ?[*]const u32,
    composition_domain_word_count: usize,
    main_columns: [*]const [*]const u32,
    total_main_columns: u32,
    dispatches: [*]const BasePolynomialDispatch,
    dispatch_count: u32,
    power_words: [*]const u32,
    total_power_words: u32,
    outputs: [*]const BasePolynomialOutput,
    output_count: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_lookup_polynomial_prepare_aot(
    runtime: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_lookup_polynomial_prepare_library(
    runtime: *anyopaque,
    library: *anyopaque,
    name: [*]const u8,
    name_len: usize,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_lookup_polynomial_batch(
    runtime: *anyopaque,
    trees: [*]const ?*anyopaque,
    tree_count: u32,
    composition_domain_buffer: ?*anyopaque,
    composition_domain_host_begin: ?[*]const u32,
    composition_domain_word_count: usize,
    main_columns: [*]const [*]const u32,
    total_main_columns: u32,
    interaction_columns: [*]const [*]const u32,
    total_interaction_columns: u32,
    dispatches: [*]const LookupPolynomialDispatch,
    dispatch_count: u32,
    power_words: [*]const u32,
    total_power_words: u32,
    parameter_words: [*]const u32,
    total_parameter_words: u32,
    outputs: [*]const BasePolynomialOutput,
    output_count: u32,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
pub extern fn stwo_zig_metal_eval_batch_prepare(
    plans: [*]const *anyopaque,
    plan_count: u32,
    error_message: [*]u8,
    error_message_len: usize,
) ?*anyopaque;
pub extern fn stwo_zig_metal_eval_batch_prepared(
    runtime: *anyopaque,
    arena: *anyopaque,
    batch: *anyopaque,
    gpu_milliseconds: *f64,
    error_message: [*]u8,
    error_message_len: usize,
) bool;
