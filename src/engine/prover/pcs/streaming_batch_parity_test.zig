//! Resource batching changes must preserve the complete PCS transcript and proof.
const std = @import("std");
const core = @import("stwo_core");
const trees = @import("commitment_tree.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const H = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
const MC = core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Backend = @import("owned_source_admission_test.zig").Backend;
const Scheme = @import("scheme.zig").CommitmentSchemeProver(Backend, H, MC);
const config: core.pcs.PcsConfig = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 8, .fold_step = 1 } };
const COUNT = 129;
fn logs() [COUNT]u32 {
    var out: [COUNT]u32 = undefined;
    for (&out, 0..) |*log, i| log.* = @intCast(5 + i % 3);
    return out;
}
const LOGS = logs();
const Points = core.pcs.TreeVec([][]core.circle.CirclePointQM31);
fn points(a: std.mem.Allocator) !Points {
    const outer = try a.alloc([][]core.circle.CirclePointQM31, 1);
    errdefer a.free(outer);
    outer[0] = try a.alloc([]core.circle.CirclePointQM31, COUNT);
    var filled: usize = 0;
    errdefer {
        for (outer[0][0..filled]) |entry| a.free(entry);
        a.free(outer[0]);
    }
    for (outer[0]) |*entry| {
        entry.* = try a.dupe(core.circle.CirclePointQM31, &.{core.circle.SECURE_FIELD_CIRCLE_GEN.mul(17)});
        filled += 1;
    }
    return .{ .items = outer };
}
fn prove(a: std.mem.Allocator, cap: u32, owned: bool) !core.pcs.ExtendedCommitmentSchemeProof(H) {
    var scheme = try Scheme.init(a, config);
    var live = true;
    defer if (live) scheme.deinit(a);
    scheme.setCompactPolynomialStorage(4);
    const columns = try a.alloc(trees.ColumnEvaluation, COUNT);
    var filled: usize = 0;
    var input_live = true;
    defer if (input_live) {
        for (columns[0..filled]) |column| a.free(column.values);
        a.free(columns);
    };
    for (columns, LOGS, 0..) |*column, log, i| {
        const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
        column.* = .{ .log_size = log, .values = values };
        filled += 1;
        for (values, 0..) |*value, row| value.* = M.fromU64(7 + i * 71 + row * row);
    }
    var channel = Channel{};
    if (owned) {
        input_live = false; // consuming entrypoint owns every failure path
        try scheme.commitOwnedStreaming(a, columns, cap, &channel);
    } else try scheme.commitBorrowedStreaming(a, columns, cap, &channel);
    const sample_points = try points(a);
    live = false;
    return scheme.proveValues(a, sample_points, &channel);
}
fn verify(a: std.mem.Allocator, extended: core.pcs.ExtendedCommitmentSchemeProof(H)) !void {
    var value = extended;
    defer value.aux.deinit(a);
    var live = true;
    defer if (live) value.proof.deinit(a);
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(H, MC).init(a, config);
    defer verifier.deinit(a);
    var channel = Channel{};
    try verifier.commit(a, value.proof.commitments.items[0], &LOGS, &channel);
    const sample_points = try points(a);
    live = false;
    try verifier.verifyValues(a, sample_points, value.proof, &channel);
}
test "coefficient storage cap8 and cap64 preserve complete mixed-height proofs and fresh verification" {
    const a = std.testing.allocator;
    var baseline = try prove(a, 8, false);
    var baseline_live = true;
    defer if (baseline_live) baseline.deinit(a);
    for ([_]bool{ false, true }) |owned| {
        var candidate = try prove(a, 64, owned);
        var candidate_live = true;
        defer if (candidate_live) candidate.deinit(a);
        try std.testing.expectEqualDeep(baseline.proof, candidate.proof);
        candidate_live = false;
        try verify(a, candidate);
    }
    baseline_live = false;
    try verify(a, baseline);
}
