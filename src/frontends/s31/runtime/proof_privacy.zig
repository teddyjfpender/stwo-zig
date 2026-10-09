//! Experimental, source-bound random-row blinding for the full circuit AIR.
//! See design/s31/language/PROOF_PRIVACY.md. This does not establish a general
//! zero-knowledge guarantee for the complete proof transcript.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const relation = @import("../language/relation.zig");

const QM31 = core.fields.qm31.QM31;
const NoValue = circuit.builder.NoValue;
pub const queries: u32 = 70;
pub const extra_openings: u32 = @intCast(circuit.statements.cairo_verifier.NON_QUERY_INFO_LEAK);
pub const Policy = struct {
    scheme: enum { upstream_random_rows_v1 } = .upstream_random_rows_v1,
    rounds: u32 = queries + extra_openings,
    queries: u32 = queries,
    extra_openings: u32 = extra_openings,
};

/// The fixed allowance is not established for other components or FRI
/// schedules. Reject them before constructing or proving a blinded circuit.
pub fn forMode(mode: relation.ProofMode, full_gate: bool, fold_step: u32) !?Policy {
    if (mode == .transparent) return null;
    if (!full_gate or fold_step != 1) return error.UnsupportedBlindingProfile;
    return .{};
}

/// Topology reconstruction needs only the public policy, never private entropy.
pub fn blindTopology(ctx: *circuit.builder.Context(NoValue), policy: ?Policy) !void {
    if (policy) |p| try addWithSeed(NoValue, ctx, p, @splat(0));
}

/// There is deliberately no seed override in the proving API. OS entropy
/// failure cannot downgrade this call to a deterministic or unblinded proof.
pub fn blindWitness(ctx: *circuit.builder.Context(QM31), policy: ?Policy) !void {
    const p = policy orelse return;
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    defer std.crypto.secureZero(u8, &seed);
    try addWithSeed(QM31, ctx, p, seed);
}

fn addWithSeed(comptime V: type, ctx: *circuit.builder.Context(V), policy: Policy, seed: [32]u8) !void {
    if (!std.meta.eql(policy, Policy{})) return error.InvalidBlindingPolicy;
    try circuit.common.zk_blinding.addZkBlinding(V, ctx, seed, policy.rounds);
}

test "blinding policy fails closed on unsupported profiles and schedules" {
    try std.testing.expectEqual(@as(u32, 80), (try forMode(.blinded, true, 1)).?.rounds);
    try std.testing.expectEqual(null, try forMode(.transparent, false, 4));
    try std.testing.expectError(error.UnsupportedBlindingProfile, forMode(.blinded, false, 1));
    try std.testing.expectError(error.UnsupportedBlindingProfile, forMode(.blinded, true, 4));
}

test "random rows change values without changing topology, public wires or validity" {
    const gpa = std.testing.allocator;
    var topology = try circuit.builder.Context(NoValue).init(gpa, 0);
    defer topology.deinit();
    var first = try circuit.builder.Context(QM31).init(gpa, 0);
    defer first.deinit();
    var second = try circuit.builder.Context(QM31).init(gpa, 0);
    defer second.deinit();
    try topology.finalize(false);
    try first.finalize(false);
    try second.finalize(false);
    const public_before = first.circuit.output.items.len;
    const variables_before = first.circuit.n_vars;
    const rows_before = first.circuit.add.items.len;
    try std.testing.expectError(error.InvalidBlindingPolicy, addWithSeed(QM31, &first, .{ .rounds = 0 }, @splat(1)));
    try blindTopology(&topology, .{});
    try addWithSeed(QM31, &first, .{}, @splat(1));
    try addWithSeed(QM31, &second, .{}, @splat(2));
    try std.testing.expectEqual(variables_before + 80 * 20, first.circuit.n_vars);
    try std.testing.expectEqual(rows_before + 80 * 14, first.circuit.add.items.len);
    try std.testing.expectEqual(public_before, first.circuit.output.items.len);
    try std.testing.expect(!first.values()[variables_before].eql(second.values()[variables_before]));
    inline for (.{ &first, &second }) |ctx| {
        try std.testing.expectEqual(null, try ctx.circuit.firstYieldViolation(gpa));
        try std.testing.expect(try ctx.isCircuitValid());
        try circuit.common.finalize.padContext(QM31, ctx);
    }
    try circuit.common.finalize.padContext(NoValue, &topology);
    const topology_text = try circuit.builder.debug_format.circuitText(gpa, &topology.circuit);
    defer gpa.free(topology_text);
    inline for (.{ &first, &second }) |ctx| {
        const value_text = try circuit.builder.debug_format.circuitText(gpa, &ctx.circuit);
        defer gpa.free(value_text);
        try std.testing.expectEqualStrings(topology_text, value_text);
        try std.testing.expect(try ctx.isCircuitValid());
    }
}
