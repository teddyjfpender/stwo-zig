//! Strict exact Blake terminal bundle and public-statement decoding.

const std = @import("std");
const stark = @import(
    "../../../../backends/cuda/runtime/proof_assembly/stark_bundle.zig",
);
const cpu_blake = @import("../../../../examples/blake.zig");
const geometry_mod = @import("geometry.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const Modulus = @import("stwo_core").fields.m31.Modulus;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const Descriptor = struct {
    pub fn validateProtocol(protocol: stark.Protocol) stark.Error!void {
        const variable_query_log = std.math.add(
            u32,
            protocol.log_n_rows,
            cpu_blake.constants.ROUND_LOG_SPLIT[0] + 1,
        ) catch return error.SizeOverflow;
        const fixed_query_log =
            cpu_blake.geometry.XOR_TABLES[0].logSize() + 1;
        const query_log = @max(variable_query_log, fixed_query_log);
        const fri_roots = query_log - 1;
        const decommit_trees = std.math.add(
            u32,
            fri_roots,
            geometry_mod.trace_tree_count,
        ) catch return error.SizeOverflow;
        if (protocol.log_n_rows < 4 or
            protocol.log_n_rows >= 28 or
            protocol.sequence_len != cpu_blake.constants.N_ROUNDS or
            protocol.pow_bits != 10 or
            protocol.log_blowup_factor != 1 or
            protocol.log_last_layer_degree_bound != 0 or
            protocol.n_queries != 3 or
            protocol.fold_step != 1 or
            protocol.lifting_log_size != null or
            protocol.commitment_root_count !=
                geometry_mod.trace_tree_count or
            protocol.fri_root_count != fri_roots or
            protocol.decommit_tree_count != decommit_trees)
        {
            return error.InvalidProtocolCounts;
        }
    }

    pub fn sampledValueCount(_: stark.Protocol) stark.Error!usize {
        return geometry_mod.sampled_value_count;
    }
};

pub fn decodeBundleOwned(
    allocator: std.mem.Allocator,
    words: []u32,
) !stark.Bundle {
    return stark.Bundle.decodeOwnedWith(Descriptor, allocator, words);
}

pub fn decodeStatement(
    log_n_rows: u32,
    words: []const u32,
) !cpu_blake.Statement {
    if (words.len != geometry_mod.statement1_words)
        return error.InvalidStatement;
    var cursor: usize = 0;
    const scheduler = try decodeSecure(words, &cursor);
    var xors: [cpu_blake.geometry.XOR_TABLES.len]QM31 = undefined;
    for (&xors) |*claim| claim.* = try decodeSecure(words, &cursor);
    var rounds: [cpu_blake.constants.ROUND_LOG_SPLIT.len]QM31 = undefined;
    for (&rounds) |*claim| claim.* = try decodeSecure(words, &cursor);
    if (cursor != words.len) return error.InvalidStatement;
    const statement = cpu_blake.Statement{
        .stmt0 = .{ .log_size = log_n_rows },
        .stmt1 = .{
            .scheduler_claimed_sum = scheduler,
            .round_claimed_sums = rounds,
            .xor_claimed_sums = xors,
        },
    };
    try cpu_blake.exact_statement.verify(statement);
    return statement;
}

fn decodeSecure(words: []const u32, cursor: *usize) !QM31 {
    if (cursor.* + 4 > words.len) return error.InvalidStatement;
    const value = words[cursor.*..][0..4];
    for (value) |word| {
        if (word >= Modulus) return error.InvalidFieldElement;
    }
    cursor.* += 4;
    return QM31.fromM31(
        M31.fromCanonical(value[0]),
        M31.fromCanonical(value[1]),
        M31.fromCanonical(value[2]),
        M31.fromCanonical(value[3]),
    );
}

test "exact terminal policy binds four trees and fixed-height FRI" {
    const protocol = stark.Protocol{
        .log_n_rows = 4,
        .sequence_len = 10,
        .pow_bits = 10,
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
        .lifting_log_size = null,
        .commitment_root_count = 4,
        .fri_root_count = 16,
        .decommit_tree_count = 20,
    };
    try Descriptor.validateProtocol(protocol);
    try std.testing.expectEqual(
        @as(usize, 2_668),
        try Descriptor.sampledValueCount(protocol),
    );
}

test "exact terminal statement decodes Rust claim order and closure" {
    const words = [_]u32{0} ** geometry_mod.statement1_words;
    const statement = try decodeStatement(4, &words);
    try std.testing.expectEqual(@as(u32, 4), statement.stmt0.log_size);
    try std.testing.expect(statement.stmt1.totalClaimedSum().isZero());

    var nonzero = words;
    nonzero[0] = 1;
    try std.testing.expectError(
        error.ClaimedSumMismatch,
        decodeStatement(4, &nonzero),
    );
    var invalid = words;
    invalid[7] = Modulus;
    try std.testing.expectError(
        error.InvalidFieldElement,
        decodeStatement(4, &invalid),
    );
}
