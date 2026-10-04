//! Actual PCS verification captures, with a typed proof of a captured FRI path.
const std = @import("std");
const f = @import("../blake3_proof_fixture.zig");
const path = @import("../blake3_merkle_path_witness.zig");
const geometry = @import("../blake3_lifted_leaf_plan.zig");
const F = @import("../blake3_fixture_roster.zig").WithExtras(.{ path.route, path.word });
const fri_opening = @import("../blake3_fri_path_opening.zig");
pub const sample_seed = f.QM31.fromU32Unchecked(7, 11, 13, 17);
const Capture = f.core.pcs.verifier.VerifiedProofCapture(f.Hasher);

test "BLAKE3 actual PCS captures feed typed trace and FRI paths" {
    try roundtrip(1);
    try roundtrip(2);
    try roundtrip(4);
}
fn roundtrip(fold_step: u32) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var capture = try verifiedCapture(a, fold_step);
    defer capture.deinit(a);
    try std.testing.expectEqual(@as(usize, 17), capture.queries.raw.len);
    if (fold_step != 4) try std.testing.expect(capture.queries.unique.len < capture.queries.raw.len);
    try std.testing.expect(capture.fri.layers.len > 1);
    var offset: usize = 0;
    for (capture.trace_paths, capture.column_log_sizes, capture.commitments) |captured, logs, root| {
        var plan = try geometry.build(a, logs);
        defer plan.deinit();
        const columns = try a.alloc([]const f.M31, logs.len);
        for (columns) |*column| {
            column.* = capture.queried_values[offset..][0..captured.positions.len];
            offset += captured.positions.len;
        }
        try plan.admitQueries(a, captured.positions, columns);
        const sample = try a.alloc(f.M31, columns.len);
        for (captured.positions, 0..) |position, q| {
            for (columns, sample) |column, *value| value.* = column[q];
            const leaf = try plan.leaf(a, sample);
            const s = path.Statement{ .namespace = 1701, .leaf = leaf, .index = @intCast(position), .depth = @intCast(captured.path_depth), .root = root };
            var live = try path.prepare(a, s, captured.path(q));
            defer live.deinit();
            try std.testing.expectEqualSlices(u8, &root, &live.computed_root.?);
        }
    }
    try std.testing.expectEqual(capture.queried_values.len, offset);
    for (capture.fri.layers, 0..) |layer, l| {
        try std.testing.expectEqual(capture.queries.raw.len, layer.query_count);
        try std.testing.expectError(error.InvalidBlake3FriCapture, fri_opening.firstLeaf(a, layer, layer.query_count));
        var bad = layer;
        bad.values = layer.values[1..];
        try std.testing.expectError(error.InvalidBlake3FriCapture, fri_opening.firstLeaf(a, bad, 0));
        bad = layer;
        bad.fold_width += 1;
        try std.testing.expectError(error.InvalidBlake3FriCapture, fri_opening.firstLeaf(a, bad, 0));
        bad = layer;
        bad.positions = try a.dupe(usize, layer.positions);
        bad.positions[0] = @as(usize, 1) << @intCast(layer.path_depth + layer.fold_step);
        try std.testing.expectError(error.InvalidBlake3FriCapture, fri_opening.firstLeaf(a, bad, 0));
        if (l == 0) try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{layer});
        for (0..layer.positions.len) |q| {
            var opening = try fri_opening.firstLeaf(a, layer, q);
            defer opening.deinit();
            const leaf = opening.leaf;
            const s = path.Statement{ .namespace = 1901, .leaf = leaf, .index = opening.index, .depth = opening.depth, .root = layer.commitment };
            var live = try path.prepare(a, s, opening.siblings);
            defer live.deinit();
            try std.testing.expectEqualSlices(u8, &s.root, &live.computed_root.?);
            if (fold_step == 2 and l == 0 and q == 0) {
                const sizes = live.logs();
                const rows = .{ try f.padded(path.g, a, live.g_rows, sizes[0]), try f.padded(path.xor, a, live.xor_rows, sizes[1]), try f.padded(path.boundary, a, live.boundary_rows, sizes[2]), try f.padded(path.route, a, live.route_rows, sizes[3]), try f.padded(path.word, a, live.word_rows, sizes[4]) };
                const trusted = try preprocessing(a, s);
                var wrong = s;
                wrong.leaf = try a.dupe(f.M31, leaf);
                @constCast(wrong.leaf)[0] = wrong.leaf[0].add(f.M31.one());
                const false_pp = try preprocessing(a, wrong);
                try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, rows, sizes, trusted, false_pp);
            }
        }
    }
}

pub fn verifiedCapture(a: std.mem.Allocator, fold_step: u32) !Capture {
    const MC = f.core.vcs_lifted.blake3_merkle.MerkleChannel;
    const Scheme = f.prover.pcs.CommitmentSchemeProver(@import("stwo_cpu_backend").CpuBackend, f.Hasher, MC);
    const Verifier = f.core.pcs.verifier.CommitmentSchemeVerifier(f.Hasher, MC);
    var config = f.core.pcs.PcsConfig{ .pow_bits = 4, .fri_config = try f.core.fri.FriConfig.init(0, 1, 17) };
    config.fri_config.fold_step = fold_step;
    var scheme = try Scheme.init(a, config);
    var prover_channel = f.Channel{};
    const logs: [2]u32 = if (fold_step == 4) .{ 5, 3 } else .{ 3, 2 };
    var storage: [32]f.M31 = undefined;
    for (&storage, 0..) |*value, i| value.* = f.M31.fromCanonical(@intCast(19 + i * i));
    try scheme.commit(a, &.{ .{ .log_size = logs[0], .values = storage[0 .. @as(usize, 1) << @intCast(logs[0])] }, .{ .log_size = logs[1], .values = storage[0 .. @as(usize, 1) << @intCast(logs[1])] } }, &prover_channel);
    var extended = try scheme.proveValues(a, try samplePoints(a), &prover_channel);
    defer extended.aux.deinit(a);
    var channel = f.Channel{};
    var verifier = try Verifier.init(a, config);
    defer verifier.deinit(a);
    try verifier.commit(a, extended.proof.commitments.items[0], &logs, &channel);
    var capture: Capture = undefined;
    // The seed defines the fixture sample point; it is not a transcript draw.
    // Composition metadata remains absent from this standalone PCS fixture.
    try verifier.verifyValuesWithProofCapture(a, try samplePoints(a), extended.proof, &channel, .{ .composition_randomness = f.QM31.zero(), .oods_seed = sample_seed }, &capture);
    errdefer capture.deinit(a);
    try std.testing.expectEqualSlices(u8, &prover_channel.digestBytes(), &channel.digestBytes());
    try std.testing.expectEqual(prover_channel.n_draws, channel.n_draws);
    return capture;
}
fn samplePoints(a: std.mem.Allocator) !f.core.pcs.TreeVec([][]f.core.circle.CirclePointQM31) {
    const Point = f.core.circle.CirclePointQM31;
    const columns = try a.alloc([]Point, 2);
    for (columns) |*column| column.* = try a.dupe(Point, &.{try f.core.circle.secureFieldPointFromRandomSeedChecked(sample_seed)});
    return f.core.pcs.TreeVec([][]Point).initOwned(try a.dupe([][]Point, &.{columns}));
}
fn preprocessing(a: std.mem.Allocator, s: path.Statement) ![]f.Column {
    var fixed = try path.trusted(a, s);
    defer fixed.deinit();
    const sizes = fixed.logs();
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, .{ fixed.g_rows, fixed.xor_rows, fixed.boundary_rows, fixed.route_rows, fixed.word_rows }, 0..) |Air, rows, i| try f.project(Air, a, rows, sizes[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}

fn allocationCase(a: std.mem.Allocator, layer: f.core.fri.FriLayerQueryCapture(f.Hasher)) !void {
    var opening = try fri_opening.firstLeaf(a, layer, 0);
    defer opening.deinit();
}
