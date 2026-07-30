//! Allocation-free Cairo witness construction on the proof-owned stream.

pub const MultiEdgeDescriptor = extern struct {
    source_offset_words: u64,
    producer_rows: u32,
    word_base: u32,
    words_per_instance: u32,
    instance_count: u32,
    destination_row_offset: u32,
    reserved: u32 = 0,
};

pub extern "c" fn stwo_witness_casm_input_scatter_on(
    rows: [*]const u32,
    real_rows: u32,
    consumer_rows: u32,
    pc: [*]u32,
    ap: [*]u32,
    fp: [*]u32,
    enabler: [*]u32,
    iota: ?[*]u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_witness_input_seed_contiguous_on(
    scalars: [*]const u32,
    scalar_count: u32,
    real_rows: u32,
    consumer_rows: u32,
    outputs: [*]u32,
    output_stride_words: usize,
    output_capacity_words: usize,
    include_enabler: u32,
    include_iota: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_witness_edge_gather_contiguous_on(
    producer: [*]const u32,
    producer_capacity_words: usize,
    producer_rows: u32,
    word_base: u32,
    words_per_instance: u32,
    instance_count: u32,
    consumer_rows: u32,
    outputs: [*]u32,
    output_stride_words: usize,
    output_capacity_words: usize,
    include_enabler: u32,
    include_iota: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_witness_multi_edge_gather_contiguous_on(
    producer_arena: [*]const u32,
    producer_word_count: usize,
    descriptors: [*]const MultiEdgeDescriptor,
    edge_count: u32,
    input_width: u32,
    total_real_rows: u32,
    consumer_rows: u32,
    outputs: [*]u32,
    output_stride_words: usize,
    output_capacity_words: usize,
    include_enabler: u32,
    include_iota: u32,
    stream: *anyopaque,
) c_int;

pub extern "c" fn stwo_witness_input_compact_sort_temp_bytes(
    rows: u32,
    out_bytes: *usize,
) c_int;

pub extern "c" fn stwo_witness_input_compact_scan_temp_bytes(
    rows: u32,
    out_bytes: *usize,
) c_int;

/// Canonical compaction for padded word-major producer slabs. Each six-word
/// descriptor separates physical column stride from logical active rows:
/// `[stride_rows, real_rows, word_base, words_per_instance, instances, dst]`.
pub extern "c" fn stwo_witness_input_compact_v2_on(
    producer_pointer_table: [*]const u64,
    edge_descriptors: [*]const u32,
    edge_count: u32,
    tuple_words: u32,
    key_words: u32,
    total_rows: u32,
    sort_rows: u32,
    consumer_rows: u32,
    input_count: u32,
    consumer_pointer_table: [*]const u64,
    enabler_slot: u32,
    iota_slot: u32,
    multiplicity_slot: u32,
    tuples: [*]u32,
    keys_a: [*]u32,
    keys_b: [*]u32,
    indices_a: [*]u32,
    indices_b: [*]u32,
    heads: [*]u32,
    positions: [*]u32,
    unique_count: *u32,
    sort_temp: *anyopaque,
    sort_temp_bytes: usize,
    scan_temp: *anyopaque,
    scan_temp_bytes: usize,
    stream: *anyopaque,
) c_int;

test "multi-edge descriptor ABI is stable" {
    const std = @import("std");
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(MultiEdgeDescriptor));
    try std.testing.expectEqual(@as(usize, 8), @alignOf(MultiEdgeDescriptor));
    try std.testing.expectEqual(
        @as(usize, 0),
        @offsetOf(MultiEdgeDescriptor, "source_offset_words"),
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        @offsetOf(MultiEdgeDescriptor, "producer_rows"),
    );
    try std.testing.expectEqual(
        @as(usize, 24),
        @offsetOf(MultiEdgeDescriptor, "destination_row_offset"),
    );
}
