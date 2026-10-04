const std = @import("std");
const core = @import("stwo_core");
const frontier = @import("../blake3_two_level_frontier.zig");
const group = @import("../blake3_merkle_group_witness.zig");
const support = @import("../blake3_shared_hash_test_support.zig");
const interaction = @import("../relation_interaction.zig");
const M = core.fields.m31.M31;
const Digest = [32]u8;
const Data = struct {
    owner: frontier.Prepared,
    g_rows: []const group.g.Row,
    xor_rows: []const group.xor.Row,
    boundary_rows: []const group.boundary.Row,
    route_rows: []const group.route.Row,
    word_rows: []const group.word.Row,
    select_rows: []const group.select.Row,
};
fn fixture(a: std.mem.Allocator, active: [2]u1, queries: [3]u1, scramble_unused: bool) !Data {
    const inputs = [2][2]Digest{ .{ @splat(13), @splat(29) }, .{ @splat(37), @splat(53) } };
    var w = frontier.Witness{ .inputs = inputs, .opaque_digests = undefined, .active = active };
    for (inputs, &w.opaque_digests) |pair, *d| d.* = (core.channel.blake3.Frame{ .node = .{ .left = pair[0], .right = pair[1] } }).hash();
    // Valid cases must work without preimages for opaque branches and without
    // trusting opaque alternatives for active branches. Invalid cases retain
    // matching hashes so membership, alone, has to reject their activity flags.
    if (scramble_unused) for (0..2) |branch| {
        if (active[branch] == 1) w.opaque_digests[branch] = @splat(0xaa) else w.inputs[branch] = @splat(@splat(0xbb));
    };
    const plan = frontier.Plan{ .namespace = 1000, .queries = 3, .root_source = .{ .circuit = 800, .first_wire = 0 } };
    var base = try frontier.prepare(a, plan, w);
    errdefer base.deinit();
    var ss: std.ArrayList(group.select.Row) = .empty;
    var rs: std.ArrayList(group.route.Row) = .empty;
    var ws: std.ArrayList(group.word.Row) = .empty;
    var bs: std.ArrayList(group.boundary.Row) = .empty;
    try ss.appendSlice(a, base.select_rows);
    try rs.appendSlice(a, base.route_rows);
    try ws.appendSlice(a, base.word_rows);
    try bs.appendSlice(a, base.boundary_rows);
    for (0..8) |i| try bs.append(a, try group.boundary.logicalRow(800, @intCast(i), M.fromCanonical(3), std.mem.readInt(u32, base.root[4 * i ..][0..4], .little)));
    for (queries, 0..) |bit, q| {
        const sources = frontier.Query{ .high_bit = .{ .circuit = 700, .wire = @intCast(q) }, .inputs = .{ .{ .circuit = @intCast(600 + q), .first_wire = 0 }, .{ .circuit = @intCast(600 + q), .first_wire = 8 } } };
        const query = try frontier.queryRows(plan, @intCast(q), sources, inputs[bit], bit, w);
        try ss.appendSlice(a, &query.select_rows);
        try rs.appendSlice(a, &query.route_rows);
        try ws.append(a, try group.word.logicalRow(700, @intCast(q), 17, bit));
        for (inputs[bit], 0..) |d, side| for (0..8) |i| try ws.append(a, try group.word.logicalRow(@intCast(600 + q), @intCast(side * 8 + i), 1, std.mem.readInt(u32, d[4 * i ..][0..4], .little)));
    }
    return .{ .owner = base, .g_rows = base.g_rows, .xor_rows = base.xor_rows, .boundary_rows = try bs.toOwnedSlice(a), .route_rows = try rs.toOwnedSlice(a), .word_rows = try ws.toOwnedSlice(a), .select_rows = try ss.toOwnedSlice(a) };
}
fn fingerprint(data: Data) Digest {
    var hash = std.crypto.hash.Blake3.init(.{});
    inline for (frontier.Airs, support.rows(data)) |Air, rows| for (rows) |row| hash.update(std.mem.sliceAsBytes(row[Air.PHYSICAL_MAIN_COLUMN_COUNT..]));
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}
test "two level BLAKE3 frontier constrains queried activity with fixed topology" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cases = [_]struct { active: [2]u1, bits: [3]u1, valid: bool }{
        .{ .active = .{ 1, 1 }, .bits = .{ 0, 1, 0 }, .valid = true },
        .{ .active = .{ 1, 0 }, .bits = .{ 0, 0, 0 }, .valid = true },
        .{ .active = .{ 0, 1 }, .bits = .{ 1, 1, 1 }, .valid = true },
        .{ .active = .{ 0, 0 }, .bits = .{ 0, 0, 0 }, .valid = false },
        .{ .active = .{ 1, 0 }, .bits = .{ 0, 1, 0 }, .valid = false },
    };
    var first: ?Digest = null;
    for (cases) |case| {
        var data = try fixture(a, case.active, case.bits, case.valid);
        defer data.owner.deinit();
        const fixed = fingerprint(data);
        if (first) |expected| try std.testing.expectEqual(expected, fixed) else first = fixed;
        try std.testing.expectEqual(@as(usize, 336), data.g_rows.len);
        var ledger = interaction.TupleLedger.init(a);
        defer ledger.deinit();
        inline for (frontier.Airs, support.rows(data)) |Air, rows| try support.add(Air, a, &ledger, rows);
        try std.testing.expectEqual(case.valid, ledger.classify().isClosed());
    }
    try std.testing.expectError(error.InvalidTwoLevelFrontier, (frontier.Plan{ .namespace = 1000, .queries = 3, .root_source = .{ .circuit = 1001, .first_wire = 0 } }).validate());
    const dead = group.select.Schedule{ .bit = .{ .circuit = 1, .wire = 0 }, .current = .{ .circuit = 2, .wire = 0 }, .sibling = .{ .circuit = 3, .wire = 0 }, .destination_circuit = 4, .left_wire = 0, .right_wire = 1, .left_uses = 0, .right_uses = 0 };
    try std.testing.expectError(error.InvalidBlake3PathSelect, group.select.fixedRow(dead));
    // A real standalone STARK qualifies the existing AIRs and all lookup domains.
    var live = try fixture(a, .{ 1, 1 }, .{ 0, 1, 0 }, true);
    defer live.owner.deinit();
    var trusted = try fixture(a, .{ 1, 0 }, .{ 0, 0, 0 }, true);
    defer trusted.owner.deinit();
    try prove(a, live, trusted);
    try @import("../blake3_frontier_emission_test_support.zig").columns(a);
    try @import("../blake3_frontier_emission_test_support.zig").capture(a);
}

fn prove(a: std.mem.Allocator, live: Data, trusted: Data) !void {
    const f = @import("../blake3_proof_fixture.zig");
    const F = @import("../blake3_fixture_roster.zig").WithExtras(.{ group.route, group.word, group.select });
    const Rows = @TypeOf(support.rows(live));
    var padded: Rows = undefined;
    var logs: [6]u32 = undefined;
    var pp: std.ArrayList(f.Column) = .empty;
    inline for (frontier.Airs, support.rows(live), support.rows(trusted), 0..) |Air, rows, fixed, i| {
        logs[i] = if (rows.len < 2) 1 else std.math.log2_int_ceil(usize, rows.len);
        padded[i] = try f.padded(Air, a, rows, logs[i]);
        try f.project(Air, a, fixed, logs[i], 0, &pp);
    }
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &pp);
    const false_pp = try a.dupe(f.Column, pp.items);
    const changed = try a.dupe(M, false_pp[0].values);
    changed[0] = changed[0].add(M.one());
    false_pp[0].values = changed;
    try @import("../blake3_proof_gate_test_support.zig").runFor(F, a, padded, logs, pp.items, false_pp);
}
