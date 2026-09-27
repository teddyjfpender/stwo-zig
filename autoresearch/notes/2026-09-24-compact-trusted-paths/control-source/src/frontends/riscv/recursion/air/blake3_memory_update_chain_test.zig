//! Full-word conversion qualification; execution custody is a separate contract.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const chain = @import("blake3_memory_update_chain.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const route = @import("blake3_byte_route.zig");
const word = @import("blake3_private_word.zig");
const bridge = @import("blake3_input_bridge.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ route, word, bridge });
const Rows = std.meta.Tuple(&.{ []f.g.Row, []f.xor.Row, []f.boundary.Row, []route.Row, []word.Row, []bridge.Row });
const initial = [_]tree.Leaf{ .{ .index = 12, .value = 0xfedcba98 }, .{ .index = 900, .value = 8 } };
const inserted = [_]tree.Leaf{ .{ .index = 0, .value = 0xffffffff }, .{ .index = 12, .value = 0xfedcba98 }, .{ .index = 900, .value = 8 } };
const final = [_]tree.Leaf{ .{ .index = 0, .value = 0xffffffff }, .{ .index = 900, .value = 8 } };
const edits = [_]chain.Edit{ .{ .address = 0, .before = 0, .after = 0xffffffff }, .{ .address = 12, .before = 0xfedcba98, .after = 0 } };
fn roots() ![3]tree.Digest {
    const h = tree.TreeHasher.init(.memory);
    return .{ try h.root(&initial), try h.root(&inserted), try h.root(&final) };
}
test "BLAKE3 memory update proves chained insertion deletion and preserved words" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try roots();
    var plan = try chain.Plan.init(a, 100, 99, &edits, &r);
    defer plan.deinit();
    const pin = try plan.identity();
    var live = try chain.prepare(a, &plan, pin, r[0], r[2], &initial);
    defer live.deinit();
    const assembled = try assemble(a, &live);
    var logs: [6]u32 = undefined;
    var rows: Rows = undefined;
    inline for (F.Airs, assembled, 0..) |Air, values, i| {
        logs[i] = @max(1, std.math.log2_int_ceil(usize, values.len));
        rows[i] = try f.padded(Air, a, values, logs[i]);
    }
    const pp = try preprocessing(a, &plan, logs);
    // Same endpoints, altered intermediate root: independently reconstructed
    // fixed columns must reject this different transition schedule.
    plan.roots[1].bytes[31] ^= 0x80;
    const false_pp = try preprocessing(a, &plan, logs);
    try @import("blake3_proof_gate_test_support.zig").runFor(F, a, rows, logs, pp, false_pp);
}
test "BLAKE3 memory update proves admission rejects disconnected transitions" {
    const a = std.testing.allocator;
    const r = try roots();
    var plan = try chain.Plan.init(a, 100, 99, &edits, &r);
    defer plan.deinit();
    const pin = try plan.identity();
    var bad_pin = pin;
    bad_pin[31] ^= 1;
    try std.testing.expectError(error.UntrustedMemoryUpdateChain, chain.prepare(a, &plan, bad_pin, r[0], r[2], &initial));
    try std.testing.expectError(error.UntrustedMemoryUpdateChain, plan.admit(pin, r[0], r[1]));
    plan.roots[2].bytes[31] ^= 1;
    // Re-pinning cannot make a wrong final transition a valid witness. This
    // fails after the first update is built, exercising partial cleanup.
    try std.testing.expectError(error.InvalidMemoryChainWitness, chain.prepare(a, &plan, try plan.identity(), r[0], plan.roots[2], &initial));
    plan.roots[2] = r[2];
    plan.edits[1].before = 41;
    try std.testing.expectError(error.InvalidMemoryChainWitness, chain.prepare(a, &plan, try plan.identity(), r[0], r[2], &initial));
    plan.edits[1] = edits[1];
    plan.roots[1].bytes[31] ^= 1;
    try std.testing.expectError(error.InvalidMemoryChainWitness, chain.prepare(a, &plan, try plan.identity(), r[0], r[2], &initial));
    plan.roots[1] = r[1];
    plan.edits[1].address = 0;
    try std.testing.expectError(error.InvalidMemoryUpdateChain, plan.validate());
    plan.edits[1] = edits[1];
    plan.source_circuit = 252;
    try std.testing.expectError(error.InvalidMemoryUpdateChain, plan.validate());
    plan.source_circuit = 99;
    const changed = [_]tree.Leaf{ .{ .index = 12, .value = 0xfedcba98 }, .{ .index = 900, .value = 9 } };
    try std.testing.expectError(error.InvalidMemoryChainWitness, chain.prepare(a, &plan, pin, r[0], r[2], &changed));
    var empty = try chain.Plan.init(a, 100, 99, &.{}, r[0..1]);
    defer empty.deinit();
    var unchanged = try chain.prepare(a, &empty, try empty.identity(), r[0], r[0], &initial);
    defer unchanged.deinit();
    try std.testing.expectEqual(@as(usize, 0), unchanged.updates.len);
}
fn assemble(a: std.mem.Allocator, p: *const chain.Prepared) !Rows {
    var rows: Rows = .{ &.{}, &.{}, &.{}, &.{}, &.{}, &.{} };
    for (p.updates) |*item| {
        const part: Rows = .{
            try std.mem.concat(a, f.g.Row, &.{ item.before.g_rows, item.after.g_rows }),
            try std.mem.concat(a, f.xor.Row, &.{ item.before.xor_rows, item.after.xor_rows }),
            try std.mem.concat(a, f.boundary.Row, &.{ item.before.boundary_rows, item.after.boundary_rows }),
            try std.mem.concat(a, route.Row, &.{ item.before.route_rows, item.after.route_rows }),
            try std.mem.concat(a, word.Row, &.{ item.before.word_rows, item.after.word_rows }),
            try a.dupe(bridge.Row, &.{ item.before.input, item.after.input }),
        };
        inline for (F.Airs, 0..) |Air, i| rows[i] = try std.mem.concat(a, Air.Row, &.{ rows[i], part[i] });
    }
    rows[2] = try std.mem.concat(a, f.boundary.Row, &.{ rows[2], p.sources });
    return rows;
}
fn preprocessing(a: std.mem.Allocator, plan: *const chain.Plan, logs: [6]u32) ![]f.Column {
    var fixed = try chain.trusted(a, plan, try plan.identity(), plan.roots[0], plan.roots[plan.roots.len - 1]);
    defer fixed.deinit();
    const rows = try assemble(a, &fixed);
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, rows, 0..) |Air, values, i| try f.project(Air, a, values, logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
