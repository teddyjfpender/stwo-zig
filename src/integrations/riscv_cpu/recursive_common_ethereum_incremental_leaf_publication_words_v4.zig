//! Statement, digest and public-boundary routes for the five Ethereum hashes.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const air = @import("stwo_riscv_frontend").recursion.air.ethereum_publication_control_v1;
const public = @import("recursive_field_node_public_v2.zig");
const hashes = @import("recursive_common_ethereum_incremental_leaf_publication_hash_v4.zig");
pub const ROW_COUNT = public.AIR_WORD_COUNT + 8 + 7;
pub const STATEMENT_SOURCE_USES: u32 = 1;
pub const Row = air.Relation.Row;

/// Header values are anchored by the independently computed public boundary.
/// Statement values additionally consume the native statement route; each
/// digest is equated to its hash AIR's final state via kind11 lookup closure.
pub fn write(schedule: anytype, destination: []Row) !void {
    return writeWithGlobalStatement(schedule, false, destination);
}

pub fn writeWithGlobalStatement(schedule: anytype, global_statement: bool, destination: []Row) !void {
    return writeWithCompletionPolicy(schedule, global_statement, .nonfinal_program_v1, destination);
}

pub fn writeWithCompletionPolicy(schedule: anytype, global_statement: bool, policy: @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig").CompletionPolicyV1, destination: []Row) !void {
    if (policy == .terminal_halt_v1 and !global_statement) return error.EthereumTerminalAdmissionRequired;
    if (destination.len != ROW_COUNT) return error.InvalidEthereumPublicationRows;
    const words = try schedule.node_public.canonicalAirWords();
    for (words, destination[0..words.len], 0..) |value, *row, index| {
        var pp = [_]u32{0} ** air.PREPROCESSED_COLUMN_COUNT;
        pp[9] = 1;
        pp[22] = 1;
        pp[23] = @intCast(index);
        if (index < public.HEADER_WORD_COUNT) {
            route(&pp, 0, .subtree, index);
            route(&pp, 1, .output, index);
            if (index >= 3) route(&pp, 2, .source, index + 2);
        } else if (index < hashes.DIGEST_START) {
            const statement_index = index - public.HEADER_WORD_COUNT;
            row.* = try statementWordRow(global_statement, statement_index, M31.fromCanonical(value));
            continue;
        } else {
            const phase: hashes.Phase = @enumFromInt(1 + (index - hashes.DIGEST_START) / 8);
            const limb = (index - hashes.DIGEST_START) % 8;
            pp[24] = 1;
            pp[25] = hashes.hashScope(phase);
            pp[26] = @intCast(limb);
            switch (phase) {
                .statement => {
                    route(&pp, 0, .source, 8 + limb);
                    route(&pp, 1, .subtree, public.HEADER_WORD_COUNT + limb);
                    route(&pp, 2, .output, index);
                },
                .source => {
                    route(&pp, 0, .subtree, public.HEADER_WORD_COUNT + 8 + limb);
                    route(&pp, 1, .output, index);
                },
                .subtree => route(&pp, 0, .output, index),
                .output => {},
                .io_stream => unreachable,
            }
        }
        row.* = air.wordRow(M31.fromCanonical(value), pp);
    }
    for (schedule.phases[0].output_digest, destination[words.len..][0..8], 0..) |value, *row, limb| {
        var pp = [_]u32{0} ** air.PREPROCESSED_COLUMN_COUNT;
        pp[9] = 1;
        pp[24] = 1;
        pp[25] = hashes.hashScope(.io_stream);
        pp[26] = @intCast(limb);
        route(&pp, 0, .source, 96 + limb);
        row.* = air.wordRow(M31.fromCanonical(value), pp);
    }
    const source = try schedule.source.preimage();
    const schema2 = @import("recursive_common_ethereum_incremental_leaf_field_public_v4.zig");
    const execution_profile = @import("stwo_riscv_frontend").air.program.decode.ExecutionProfile;
    const indices = [_]usize{ 0, 1, 2, 3, 4, 40, 48 };
    const expected = [_]u32{ schema2.FORMAT_VERSION, schema2.SCHEMA_VERSION, schema2.SOURCE_KIND_ETHEREUM_INCREMENTAL_LEAF_V4, @intFromEnum(schema2.CIRCUIT_ROLE), schema2.COMMITMENT_COUNT, @intFromEnum(execution_profile.rv32im_zkvm_ethereum_v1), @intFromBool(policy == .nonfinal_program_v1) };
    for (indices, expected, destination[words.len + 8 ..]) |index, value, *row| {
        if (source[index] != value) return error.EthereumNonfinalPublicationProfileRequired;
        var pp = [_]u32{0} ** air.PREPROCESSED_COLUMN_COUNT;
        pp[9] = 1;
        pp[30] = 1;
        pp[31] = value;
        route(&pp, 0, .source, index);
        row.* = air.wordRow(M31.fromCanonical(value), pp);
    }
}

pub fn statementWordRow(global_statement: bool, index: usize, value: M31) !Row {
    if (index >= public.STATEMENT_WORD_COUNT) return error.InvalidEthereumPublicationRows;
    var pp = [_]u32{0} ** air.PREPROCESSED_COLUMN_COUNT;
    pp[9] = 1;
    pp[22] = 1;
    pp[23] = @intCast(public.HEADER_WORD_COUNT + index);
    pp[if (global_statement) 32 else 10] = 1;
    pp[11] = if (global_statement) hashes.hashScope(.statement) else 0;
    pp[12] = @intCast(index);
    route(&pp, 0, .statement, index);
    route(&pp, 1, .output, public.HEADER_WORD_COUNT + index);
    return air.wordRow(value, pp);
}
fn route(pp: *[air.PREPROCESSED_COLUMN_COUNT]u32, slot: usize, phase: hashes.Phase, index: usize) void {
    const at = 13 + slot * 3;
    pp[at] = 1;
    pp[at + 1] = hashes.hashScope(phase);
    pp[at + 2] = @intCast(index);
}
