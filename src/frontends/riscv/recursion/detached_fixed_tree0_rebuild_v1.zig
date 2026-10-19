//! Complete proof-free SegmentV2 leaf Tree0 materialization from a detached key.
//! The caller owns the commitment backend and must compare its root with the
//! authenticated key. This writer never receives a native or outer proof.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;
const framework = @import("air/framework_interaction.zig");
const air = @import("air/mod.zig");
const key_rows = @import("detached_fixed_tree0_key_recipe_v1.zig");
const control = @import("detached_fixed_tree0_control_recipe_v1.zig");
const transcript = @import("detached_fixed_tree0_transcript_shape_recipe_v1.zig");
const public_relay = @import("detached_fixed_tree0_public_relay_recipe_v1.zig");
const vm = @import("detached_fixed_tree0_vm_input_recipe_v1.zig");
const query = @import("detached_fixed_tree0_query_recipe_v1.zig");
const trace_merkle = @import("detached_fixed_tree0_trace_merkle_recipe_v1.zig");
const pcs = @import("detached_fixed_tree0_pcs_recipe_v1.zig");
const fri = @import("detached_fixed_tree0_fri_recipe_v1.zig");
const fri_input = @import("detached_fixed_tree0_fri_input_recipe_v1.zig");
const arithmetic = @import("detached_fixed_tree0_arithmetic_recipe_v1.zig");
const statement = @import("segment_statement_outer_source_v2_contract.zig");

pub fn fillFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: [][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1 or
        columns.len != key.manifest.total_preprocessed_columns)
        return error.InvalidDetachedFixedTreeGeometry;
    for (key.manifest.roster_rows[0..key.manifest.roster_count]) |row_index| {
        const placement = key.manifest.placements[row_index] orelse return error.InvalidDetachedFixedTreeGeometry;
        const offset: usize = placement.preprocessed_offset;
        const count: usize = placement.geometry.preprocessed_columns;
        const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
        if (offset + count > columns.len) return error.InvalidDetachedFixedTreeGeometry;
        for (columns[offset..][0..count]) |column| {
            if (column.len != size) return error.InvalidDetachedFixedTreeGeometry;
            @memset(column, M31.zero());
        }
    }

    var row0 = try lane(air.control_witness.COLUMN_COUNT, key, columns, 0);
    try control.fillTranscriptControlFromKey(allocator, key, &row0);
    inline for ([_]usize{ 2, 3, 4, 5, 8, 9 }) |row_index|
        try transcript.fillFromKey(allocator, key, row_index, try rowSlice(key, columns, row_index));

    var row10 = try lane(air.statement_input.PREPROCESSED_COLUMN_COUNT, key, columns, 10);
    try key_rows.fillInactiveStatementInputRow(&key.manifest, &row10);
    var row11 = try lane(statement.Air.PREPROCESSED_COLUMN_COUNT, key, columns, 11);
    try key_rows.fillStatementRow(&key.manifest, key.retained_section_counts, &row11);
    inline for ([_]usize{ 12, 14, 15, 16 }) |row_index|
        try public_relay.fillFromKey(allocator, key, row_index, try rowSlice(key, columns, row_index));
    try public_relay.fillHashFromKey(allocator, key, try rowSlice(key, columns, 13));
    var row17 = try lane(air.vm_public_logup_control_v2.PREPROCESSED_COLUMN_COUNT, key, columns, 17);
    try control.fillPublicControlFromKey(allocator, key, &row17);

    var row18 = try lane(air.vm_air_composition_input_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 18);
    try vm.fillFromKey(allocator, key, &row18);
    try commitOrder(allocator, key, 18, row18[0..]);
    var row19 = try lane(air.control_slice_witness.COLUMN_COUNT, key, columns, 19);
    try control.fillFromKey(allocator, key, &row19);
    try commitOrder(allocator, key, 19, row19[0..]);

    var row20 = try lane(air.query_bits_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 20);
    try query.fillBitsFromKey(allocator, key, &row20);
    try commitOrder(allocator, key, 20, row20[0..]);
    var row21 = try lane(air.query_mapping_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 21);
    try query.fillMappingFromKey(allocator, key, &row21);
    try commitOrder(allocator, key, 21, row21[0..]);
    var row22 = try lane(air.merkle_root_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 22);
    try query.fillRootFromKey(allocator, key, &row22);
    try commitOrder(allocator, key, 22, row22[0..]);
    var row23 = try lane(air.trace_merkle_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 23);
    try trace_merkle.fillFromKey(allocator, key, &row23);
    try commitOrder(allocator, key, 23, row23[0..]);
    var row24 = try lane(air.pcs_deep_input_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 24);
    try pcs.fillFromKey(allocator, key, &row24);
    try commitOrder(allocator, key, 24, row24[0..]);
    var row25 = try lane(air.fri_merkle_leaf_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 25);
    try fri.fillLeafFromKey(allocator, key, &row25);
    try commitOrder(allocator, key, 25, row25[0..]);
    var row26 = try lane(air.fri_merkle_node_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 26);
    try fri.fillNodeFromKey(allocator, key, &row26);
    try commitOrder(allocator, key, 26, row26[0..]);
    var row27 = try lane(air.fri_merkle_anchor_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 27);
    try fri.fillAnchorFromKey(allocator, key, &row27);
    try commitOrder(allocator, key, 27, row27[0..]);
    var row28 = try lane(air.fri_verifier_control_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 28);
    try fri.fillControlFromKey(allocator, key, &row28);
    try commitOrder(allocator, key, 28, row28[0..]);
    var row29 = try lane(air.fri_verifier_input_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 29);
    try fri_input.fillFromKey(allocator, key, &row29);
    try commitOrder(allocator, key, 29, row29[0..]);

    var row30 = try lane(air.qm31_mul_full_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 30);
    var row31 = try lane(air.qm31_inv_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 31);
    var row32 = try lane(air.linear_ops_witness.PREPROCESSED_COLUMN_COUNT, key, columns, 32);
    try arithmetic.fillFromKey(allocator, key, &row30, &row31, &row32);
    try commitOrder(allocator, key, 30, row30[0..]);
    try commitOrder(allocator, key, 31, row31[0..]);
    try commitOrder(allocator, key, 32, row32[0..]);

    const row34 = try rowSlice(key, columns, 34);
    if (row34.len != 1) return error.InvalidDetachedFixedTreeGeometry;
    try key_rows.fillPoseidonFirst(&key.manifest, row34[0]);
    var row35 = try lane(3, key, columns, 35);
    try key_rows.fillRangeTable(&key.manifest, &row35);
    var row36 = try lane(3, key, columns, 36);
    try key_rows.fillBoundaryStatementRow(&key.manifest, key.source_manifest.wire_word_count, &row36);
    var row37 = try lane(2, key, columns, 37);
    try key_rows.fillBoundaryPublicLogupRow(&key.manifest, &row37);
    var row38 = try lane(4, key, columns, 38);
    try key_rows.fillPublicationInputProviderRow(&key.manifest, &row38);
    try commitOrder(allocator, key, 38, row38[0..]);
}

fn rowSlice(key: *const KeyV1, columns: [][]M31, row_index: usize) ![][]M31 {
    const placement = key.manifest.placements[row_index] orelse return error.InvalidDetachedFixedTreeGeometry;
    const offset: usize = placement.preprocessed_offset;
    const count: usize = placement.geometry.preprocessed_columns;
    if (offset + count > columns.len) return error.InvalidDetachedFixedTreeGeometry;
    return columns[offset..][0..count];
}

fn lane(comptime count: usize, key: *const KeyV1, columns: [][]M31, row_index: usize) ![count][]M31 {
    const slice = try rowSlice(key, columns, row_index);
    if (slice.len != count) return error.InvalidDetachedFixedTreeGeometry;
    var result: [count][]M31 = undefined;
    @memcpy(&result, slice);
    return result;
}

/// Component generators emit logical-row order. PCS commits bit-reversed rows.
fn commitOrder(allocator: std.mem.Allocator, key: *const KeyV1, row_index: usize, columns: [][]M31) !void {
    const placement = key.manifest.placements[row_index] orelse return error.InvalidDetachedFixedTreeGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    const scratch = try allocator.alloc(M31, size);
    defer allocator.free(scratch);
    for (columns) |column| {
        if (column.len != size) return error.InvalidDetachedFixedTreeGeometry;
        @memcpy(scratch, column);
        for (scratch, 0..) |value, logical|
            column[framework.committedRow(logical, placement.geometry.log_size)] = value;
    }
}
