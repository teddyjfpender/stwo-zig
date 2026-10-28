//! Proof-free fixed columns for the four ordinary SegmentV2 public relays.
//! The published values and native challenge limbs are main-column witnesses.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;
const layout_mod = @import("segment_statement_v2_transcript_layout.zig");
const native_sum = @import("segment_public_native_sum_authority_v2.zig");
const public = @import("segment_public_outer_source_v2.zig");
const register_bytes = @import("segment_register_byte_layout_v1.zig");
const relation_challenge = @import("air/relation_challenge_witness.zig");
const framework = @import("air/framework_interaction.zig");
const authority = @import("segment_leaf_authority_v2.zig");
const channel = @import("poseidon2_channel.zig");
const hash_air = @import("air/vm_public_claim_hash_authority_v2.zig");

pub const COLUMN_COUNT: usize = 14;

/// Row 13 interleaves 16 public-sum relays with the value-dependent
/// authority-hash Poseidon calls. Only call count and call-wire coordinates
/// belong to Tree0; every call input/output remains a witness.
pub fn fillHashFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: [][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1) return error.InvalidFixedPublicRelayGeometry;
    const placement = key.manifest.placements[13] orelse return error.InvalidFixedPublicRelayGeometry;
    if (placement.geometry.preprocessed_columns != hash_air.PREPROCESSED_COLUMN_COUNT or
        columns.len != hash_air.PREPROCESSED_COLUMN_COUNT or
        placement.geometry.log_size >= @bitSizeOf(usize))
        return error.InvalidFixedPublicRelayGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (columns) |column| {
        if (column.len != size) return error.InvalidFixedPublicRelayGeometry;
        @memset(column, M31.zero());
    }
    const descriptor_count = key.native_descriptors.components.len +
        key.native_descriptors.infrastructure.len;
    const preimage_count = authority.AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT +
        descriptor_count * authority.AUTHORITY_HASH_WORDS_PER_DESCRIPTOR;
    const call_count = channel.canonicalWordPermutationCount(preimage_count);
    const active = @max(public.NATIVE_PUBLIC_SUM_WORD_COUNT, call_count);
    if (active > size) return error.InvalidFixedPublicRelayGeometry;

    const retained = try layout_mod.Layout.init(key.retained_section_counts);
    const topology = key.native_sum_topology orelse return error.MissingPublicNativeSumTopology;
    var authored = try native_sum.buildNativeGraphFromTopology(allocator, &retained, topology);
    defer authored.circuit.deinit();
    const use_counts = authored.circuit.useCounts();
    if (use_counts.len < retained.total_words + public.NATIVE_PUBLIC_SUM_WORD_COUNT)
        return error.InvalidFixedPublicRelayGeometry;

    for (0..active) |index| {
        var values: [hash_air.PREPROCESSED_COLUMN_COUNT]u32 = .{0} ** hash_air.PREPROCESSED_COLUMN_COUNT;
        values[0] = 1;
        values[1] = @intFromBool(index < public.NATIVE_PUBLIC_SUM_WORD_COUNT);
        values[2] = @intFromBool(index < call_count);
        values[3] = @intFromBool(index == 0);
        if (index < public.NATIVE_PUBLIC_SUM_WORD_COUNT) {
            const node = retained.total_words + index;
            values[4] = public.PUBLICATION_BRIDGE_CIRCUIT_ID;
            values[5] = @intCast(public.PUBLICATION_SUM_START + index);
            values[9] = public.NATIVE_SUM_CIRCUIT_ID;
            values[10] = @intCast(node);
            values[11] = use_counts[node];
            values[12] = public.CONTROL_RELAY_CIRCUIT_ID;
        }
        if (index < call_count) for (0..hash_air.CALL_WIRE_GROUP_COUNT) |group| {
            values[15 + group] = @intCast(index * hash_air.CALL_WIRE_GROUP_COUNT + group);
        };
        const committed = framework.committedRow(index, placement.geometry.log_size);
        for (columns, values) |column, value|
            column[committed] = M31.fromCanonical(value);
    }
}

pub fn fillFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    row: usize,
    columns: [][]M31,
) !void {
    try key.validate();
    if (key.profile != .recursive_q193_v1 or
        (row != 12 and row != 14 and row != 15 and row != 16))
        return error.InvalidFixedPublicRelayGeometry;
    const placement = key.manifest.placements[row] orelse return error.InvalidFixedPublicRelayGeometry;
    if (placement.geometry.preprocessed_columns != COLUMN_COUNT or
        columns.len != COLUMN_COUNT or
        placement.geometry.log_size >= @bitSizeOf(usize))
        return error.InvalidFixedPublicRelayGeometry;
    const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (columns) |column| {
        if (column.len != size) return error.InvalidFixedPublicRelayGeometry;
        @memset(column, M31.zero());
    }

    const retained = try layout_mod.Layout.init(key.retained_section_counts);
    const memory_bytes = (@as(usize, key.retained_section_counts[0]) +
        key.retained_section_counts[1]) * 4;
    const bridge_words = register_bytes.BYTE_COUNT + 2 * memory_bytes;
    const active: usize = switch (row) {
        12 => public.PUBLICATION_HEADER_WORD_COUNT,
        14 => public.PUBLICATION_SEAL_WORD_COUNT,
        15 => retained.total_words + bridge_words,
        16 => public.CHALLENGE_WORD_COUNT,
        else => unreachable,
    };
    if (active > size) return error.InvalidFixedPublicRelayGeometry;

    const topology = key.native_sum_topology orelse return error.MissingPublicNativeSumTopology;
    var authored = try native_sum.buildNativeGraphFromTopology(allocator, &retained, topology);
    defer authored.circuit.deinit();
    const use_counts = authored.circuit.useCounts();
    const required_inputs = retained.total_words +
        public.ARITHMETIC_PUBLICATION_WORD_COUNT +
        public.CHALLENGE_WORD_COUNT + bridge_words;
    if (use_counts.len < required_inputs) return error.InvalidFixedPublicRelayGeometry;

    for (0..active) |index| {
        var values: [COLUMN_COUNT]u32 = .{0} ** COLUMN_COUNT;
        values[0] = 1; // row mask
        values[8] = public.NATIVE_SUM_CIRCUIT_ID;
        values[11] = public.CONTROL_RELAY_CIRCUIT_ID;
        switch (row) {
            12, 14 => {
                const publication_index = if (row == 12)
                    index
                else
                    public.PUBLICATION_SEAL_START + index;
                const arithmetic = row == 14 and index < public.NATIVE_TOTAL_WORD_COUNT;
                const control = publication_index == public.CONTROL_PUBLICATION_INDEX;
                values[1] = @intFromBool(arithmetic);
                values[2] = @intFromBool(control);
                values[3] = public.PUBLICATION_BRIDGE_CIRCUIT_ID;
                values[4] = @intCast(publication_index);
                if (arithmetic) {
                    const node = retained.total_words + publication_index - public.PUBLICATION_SUM_START;
                    values[9] = @intCast(node);
                    values[10] = use_counts[node];
                }
                values[13] = @intFromBool(control);
            },
            15 => {
                const node = if (index < retained.total_words)
                    index
                else
                    retained.total_words + public.ARITHMETIC_PUBLICATION_WORD_COUNT +
                        public.CHALLENGE_WORD_COUNT + index - retained.total_words;
                values[1] = 1;
                values[3] = public.BOUNDARY_BRIDGE_CIRCUIT_ID;
                values[4] = @intCast(index);
                values[9] = @intCast(node);
                values[10] = use_counts[node];
            },
            16 => {
                const node = retained.total_words + public.ARITHMETIC_PUBLICATION_WORD_COUNT + index;
                values[1] = 1;
                values[3] = public.TRANSCRIPT_VERIFIER_ID;
                values[4] = relation_challenge.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE;
                values[5] = @intCast(index / public.CHALLENGE_WORDS_PER_RELATION);
                values[6] = @intCast(index % public.CHALLENGE_WORDS_PER_RELATION);
                values[9] = @intCast(node);
                values[10] = use_counts[node];
            },
            else => unreachable,
        }
        const committed = framework.committedRow(index, placement.geometry.log_size);
        for (columns, values) |column, value|
            column[committed] = M31.fromCanonical(value);
    }
}
