const std = @import("std");
const f = @import("../blake3_proof_fixture.zig");
const geometry = @import("../blake3_lifted_leaf_plan.zig");
const path = @import("../blake3_merkle_path_witness.zig");
const F = @import("../blake3_fixture_roster.zig").WithExtras(.{ path.route, path.word });
const logs = [_]u32{ 3, 1, 2, 3 };
const raw = [_][8]u32{ .{ 1, 2, 3, 4, 5, 6, 7, 8 }, .{ 19, 23, 0, 0, 0, 0, 0, 0 }, .{ 29, 31, 37, 41, 0, 0, 0, 0 }, .{ 43, 47, 53, 59, 61, 67, 71, 73 } };
test "BLAKE3 lifted geometry matches native decommitments and a complete typed path proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var storage: [4][8]f.M31 = undefined;
    var columns: [4][]const f.M31 = undefined;
    for (&storage, raw, &columns, logs) |*values, words, *column, log| {
        for (values, words) |*value, word| value.* = f.M31.fromCanonical(word);
        column.* = values[0 .. @as(usize, 1) << @as(u6, @intCast(log))];
    }
    const Prover = f.prover.vcs_lifted.prover.MerkleProverLifted(f.Hasher);
    const Verifier = f.core.vcs_lifted.verifier.MerkleVerifierLifted(f.Hasher);
    var tree = try Prover.commit(a, &columns);
    defer tree.deinit(a);
    const positions = [_]usize{ 0, 1, 2, 3, 4, 5, 6, 7 };
    var opening = try tree.decommit(a, &positions, &columns);
    defer opening.deinit(a);
    var queried: [4][]const f.M31 = undefined;
    for (&queried, opening.queried_values) |*column, values| column.* = values;
    var verifier = try Verifier.init(a, tree.root(), &logs);
    defer verifier.deinit(a);
    var capture = f.core.vcs_lifted.verifier.MerklePathCapture(f.Hasher){ .positions = &.{}, .path_depth = 0, .siblings = &.{} };
    try verifier.verifyWithPathCapture(a, &positions, &queried, opening.decommitment.decommitment, &capture);
    defer capture.deinit(a);
    var plan = try geometry.build(a, &logs);
    defer plan.deinit();
    try plan.admitQueries(a, &positions, &queried);
    var changed_queries = queried;
    const changed_short = try a.dupe(f.M31, queried[1]);
    changed_short[2] = changed_short[2].add(f.M31.one());
    changed_queries[1] = changed_short;
    try std.testing.expectError(error.InconsistentBlake3LiftedQuery, plan.admitQueries(a, &positions, &changed_queries));
    changed_queries[1] = queried[1][0..7];
    try std.testing.expectError(error.InvalidBlake3LiftedLeaf, plan.admitQueries(a, &positions, &changed_queries));
    var bad_positions = positions;
    bad_positions[7] = 8;
    try std.testing.expectError(error.InvalidBlake3LiftedLeaf, plan.admitQueries(a, &bad_positions, &queried));

    try std.testing.expectEqualSlices(usize, &.{ 1, 2, 0, 3 }, plan.order);
    for (positions) |position| for (columns, queried, 0..) |column, values, c| {
        const index = try plan.columnIndex(c, @intCast(position));
        try std.testing.expect(column[index].eql(values[position]));
    };
    var sample: [4]f.M31 = undefined;
    for (&sample, queried) |*value, column| value.* = column[6];
    const leaf = try plan.leaf(a, &sample);
    const s = path.Statement{ .namespace = 1301, .leaf = leaf, .index = 6, .depth = @intCast(plan.max_log), .root = tree.root() };
    var live = try path.prepare(a, s, capture.path(6));
    defer live.deinit();
    try std.testing.expectEqualSlices(u8, &s.root, &live.computed_root.?);
    const sizes = live.logs();
    const rows = .{ try f.padded(path.g, a, live.g_rows, sizes[0]), try f.padded(path.xor, a, live.xor_rows, sizes[1]), try f.padded(path.boundary, a, live.boundary_rows, sizes[2]), try f.padded(path.route, a, live.route_rows, sizes[3]), try f.padded(path.word, a, live.word_rows, sizes[4]) };
    const trusted = try preprocessing(a, s);
    var wrong_values = sample;
    std.mem.swap(f.M31, &wrong_values[0], &wrong_values[3]);
    var wrong = s;
    wrong.leaf = try plan.leaf(a, &wrong_values);
    const false_pp = try preprocessing(a, wrong);
    try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, rows, sizes, trusted, false_pp);
    try std.testing.expectError(error.InvalidBlake3LiftedLeaf, plan.columnIndex(1, 8));
    try std.testing.expectError(error.InvalidBlake3LiftedLeaf, plan.leaf(a, &.{}));
    try std.testing.expectError(error.InvalidBlake3LiftedLeaf, geometry.build(a, &.{0}));
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}
fn allocationCase(a: std.mem.Allocator) !void {
    var plan = try geometry.build(a, &logs);
    defer plan.deinit();
    const leaf = try plan.leaf(a, &.{ f.M31.one(), f.M31.zero(), f.M31.one(), f.M31.zero() });
    defer a.free(leaf);
    const repeated = [_]f.M31{ f.M31.one(), f.M31.one(), f.M31.one() };
    const columns = [_][]const f.M31{ &repeated, &repeated, &repeated, &repeated };
    try plan.admitQueries(a, &.{ 0, 2, 0 }, &columns);
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
