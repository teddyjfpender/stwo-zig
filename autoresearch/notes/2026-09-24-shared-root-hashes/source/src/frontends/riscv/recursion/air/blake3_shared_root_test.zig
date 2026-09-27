//! Exact recursive-wire closure across three private paths and one root hash.
const std = @import("std");
const core = @import("stwo_core");
const group = @import("blake3_merkle_group_witness.zig");
const binding = @import("universal_relation_binding.zig");
const interaction = @import("relation_interaction.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Airs = .{ group.g, group.xor, group.boundary, group.route, group.word, group.select };
fn add(comptime Air: type, a: std.mem.Allocator, ledger: *interaction.TupleLedger, inputs: []const Air.Row) !void {
    var definition = if (@hasDecl(Air, "Location")) try Air.build(a, .generated) else try Air.build(a);
    defer definition.deinit();
    const plan = try binding.Binding(Air).authenticate(&definition);
    for (inputs) |row| for (plan.preparedEntries(row)) |entry| {
        if (entry.domain == .recursion_wire) try ledger.append(entry.domain, 0, 0, .emit, entry.numerator, entry.values[0..entry.arity]);
    };
}
fn rows(p: group.Prepared) struct { []const group.g.Row, []const group.xor.Row, []const group.boundary.Row, []const group.route.Row, []const group.word.Row, []const group.select.Row } {
    return .{ p.g_rows, p.xor_rows, p.boundary_rows, p.route_rows, p.word_rows, p.select_rows };
}
test "shared BLAKE3 root preserves every query input and exact multiplicity" {
    const a = std.testing.allocator;
    const values = [2][1]M{ .{M.fromCanonical(17)}, .{M.fromCanonical(29)} };
    const digests = [2][32]u8{ (core.channel.blake3.Frame{ .leaf = &values[0] }).hash(), (core.channel.blake3.Frame{ .leaf = &values[1] }).hash() };
    const root = (core.channel.blake3.Frame{ .node = .{ .left = digests[0], .right = digests[1] } }).hash();
    var prepared: [3]group.Prepared = undefined;
    var completed: usize = 0;
    defer for (prepared[0..completed]) |*p| p.deinit();
    var producers: std.ArrayList(group.word.Row) = .empty;
    defer producers.deinit(a);
    for ([_]u32{ 0, 1, 0 }, 0..) |index, q| {
        const directions = [_]group.select.Endpoint{.{ .circuit = 900, .wire = @intCast(q) }};
        const s = group.Statement{ .namespace = @intCast(1000 + 4 * q), .payload = .{ .circuit = 800, .first_wire = @intCast(q) }, .leaf_count = 1, .words_per_leaf = 1, .index = index, .depth = 1, .root = root, .root_source = .{ .circuit = 700, .first_wire = 0 }, .directions = &directions, .shared_root = .{ .first_namespace = 1000, .query_index = @intCast(q), .queries = 3 } };
        prepared[q] = try group.prepare(a, s, &values[index], &.{digests[index ^ 1]});
        completed += 1;
        try std.testing.expectEqual(root, prepared[q].computed_root.?);
        var fixed = try group.trusted(a, s);
        defer fixed.deinit();
        inline for (Airs, rows(prepared[q]), rows(fixed)) |Air, live_rows, fixed_rows| {
            try std.testing.expectEqual(live_rows.len, fixed_rows.len);
            for (live_rows, fixed_rows) |live, trusted| try std.testing.expectEqualSlices(M, trusted[Air.PHYSICAL_MAIN_COLUMN_COUNT..], live[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
        }
        try producers.append(a, try group.word.logicalRow(800, @intCast(q), prepared[q].payload_uses[0], values[index][0].toU32()));
        var invalid = s;
        invalid.shared_root.?.query_index = 3;
        try std.testing.expectError(error.InvalidSharedBlake3Root, group.trusted(a, invalid));
        invalid = s;
        invalid.directions = null;
        try std.testing.expectError(error.InvalidSharedBlake3Root, group.trusted(a, invalid));
    }
    try std.testing.expectEqual(prepared[1].g_rows.len + 112, prepared[0].g_rows.len);
    for (0..8) |i| try producers.append(a, try group.word.logicalRow(700, @intCast(i), 3, std.mem.readInt(u32, root[4 * i ..][0..4], .little)));
    // The path-select bit has scalar, rather than byte-word, coordinates.
    var ledger = interaction.TupleLedger.init(a);
    defer ledger.deinit();
    for ([_]u32{ 0, 1, 0 }, 0..) |bit, q| try ledger.append(.recursion_wire, 0, 0, .emit, Q.fromU32Unchecked(8, 0, 0, 0), &.{ Q.fromU32Unchecked(900, 0, 0, 0), Q.fromU32Unchecked(@intCast(q), 0, 0, 0), Q.fromU32Unchecked(bit, 0, 0, 0), Q.zero(), Q.zero(), Q.zero() });
    try add(group.word, a, &ledger, producers.items);
    for (prepared) |p| inline for (Airs, rows(p)) |Air, r| try add(Air, a, &ledger, r);
    const closure = ledger.classify();
    if (!closure.isClosed()) ledger.printUnmatched(12);
    try std.testing.expect(closure.isClosed());
    var selection = try group.select.build(a);
    defer selection.deinit();
    var changed_bit = prepared[1].select_rows[0];
    changed_bit[0] = M.one().sub(changed_bit[0]);
    const evaluated = try @import("test_support.zig").evaluateArena(a, &selection.arena, &changed_bit);
    defer a.free(evaluated);
    var rejected = false;
    for (selection.arena.constraintsView()) |constraint| {
        rejected = rejected or !evaluated[@intFromEnum(constraint.root)].isZero();
    }
    try std.testing.expect(rejected);
    // Replacing one borrowed input equality with a different word must unbalance
    // the relation even though the already-computed shared root stays unchanged.
    var definition = try group.route.build(a);
    defer definition.deinit();
    const plan = try binding.Binding(group.route).authenticate(&definition);
    for (prepared[1].route_rows[prepared[1].route_rows.len - 24 ..]) |original| {
        var mutated = original;
        mutated[0] = mutated[0].add(M.one());
        for (plan.preparedEntries(original)) |entry| try ledger.append(entry.domain, 0, 0, .emit, entry.numerator.neg(), entry.values[0..entry.arity]);
        for (plan.preparedEntries(mutated)) |entry| try ledger.append(entry.domain, 0, 0, .emit, entry.numerator, entry.values[0..entry.arity]);
        try std.testing.expect(!ledger.classify().isClosed());
        for (plan.preparedEntries(mutated)) |entry| try ledger.append(entry.domain, 0, 0, .emit, entry.numerator.neg(), entry.values[0..entry.arity]);
        for (plan.preparedEntries(original)) |entry| try ledger.append(entry.domain, 0, 0, .emit, entry.numerator, entry.values[0..entry.arity]);
        try std.testing.expect(ledger.classify().isClosed());
    }
}
