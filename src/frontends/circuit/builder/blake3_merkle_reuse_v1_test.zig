const std = @import("std");
const core = @import("stwo_core");
const b = @import("mod.zig");
const merkle = @import("blake3_merkle_reuse_v1.zig");
const channel = @import("blake3_channel_reuse_v1.zig");
const Q = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const M = b.wrappers.M31Wrapper(b.Var);
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const D = H.Hash;
const a = std.testing.allocator;
fn rootWire(comptime V: type, ctx: *b.Context(V), digest: D) !merkle.Digest {
    var out: merkle.Digest = undefined;
    for (&out, 0..) |*word, i| word.* = try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, std.mem.readInt(u32, digest[4 * i ..][0..4], .little)));
    return out;
}
fn indexWire(comptime V: type, ctx: *b.Context(V), index: u32) !M {
    return b.wrappers.guessM31(V, ctx, b.wrappers.m31Value(V, M31.fromCanonical(index)));
}
fn rowsWire(comptime V: type, ctx: *b.Context(V), values: []const M31) ![]M {
    const out = try ctx.scratch().alloc(M, values.len);
    for (out, values) |*word, value| word.* = try b.wrappers.guessM31(V, ctx, b.wrappers.m31Value(V, value));
    return out;
}
const Tree = struct {
    logs: []u32,
    rows: [8][]M31,
    layers: [4][8]D = undefined,
    fn init(width: usize) !Tree {
        var t: Tree = undefined;
        t.logs = try a.alloc(u32, width);
        errdefer a.free(t.logs);
        var ready: usize = 0;
        errdefer for (t.rows[0..ready]) |row| a.free(row);
        const order = try a.alloc(usize, width);
        defer a.free(order);
        for (t.logs, order, 0..) |*log, *index, i| {
            log.* = @intCast(i % 4);
            index.* = i;
        }
        std.sort.heap(usize, order, t.logs, struct {
            fn less(logs: []const u32, x: usize, y: usize) bool {
                return logs[x] < logs[y] or (logs[x] == logs[y] and x < y);
            }
        }.less);
        const sorted = try a.alloc(M31, width);
        defer a.free(sorted);
        for (&t.rows, 0..) |*row, leaf| {
            row.* = try a.alloc(M31, width);
            ready += 1;
            for (row.*, 0..) |*value, i| value.* = M31.fromCanonical(@intCast((leaf + 1) * 10000 + i * 7));
            for (sorted, order) |*value, index| value.* = row.*[index];
            var h = H.defaultWithInitialState();
            h.updateLeaf(sorted);
            t.layers[0][leaf] = h.finalize();
        }
        for (1..4) |level| for (0..(@as(usize, 8) >> @intCast(level))) |i| {
            t.layers[level][i] = H.hashChildren(.{ .left = t.layers[level - 1][2 * i], .right = t.layers[level - 1][2 * i + 1] });
        };
        return t;
    }
    fn deinit(t: *Tree) void {
        a.free(t.logs);
        for (t.rows) |row| a.free(row);
    }
    fn path(t: *const Tree, leaf: usize) [3]D {
        var out: [3]D = undefined;
        for (&out, 0..) |*sibling, level| sibling.* = t.layers[level][(leaf >> @intCast(level)) ^ 1];
        return out;
    }
    fn pathWires(t: *const Tree, comptime V: type, ctx: *b.Context(V), leaf: usize) ![3]merkle.Digest {
        var out: [3]merkle.Digest = undefined;
        for (&out, t.path(leaf)) |*wire, digest| wire.* = try rootWire(V, ctx, digest);
        return out;
    }
};
const Fault = enum { none, leaf, root, index, sibling };
fn opening(comptime V: type, ctx: *b.Context(V), t: *const Tree, global_query: u32, global_log: u32, leaf: usize, fault: Fault) !void {
    var values = try rowsWire(V, ctx, t.rows[leaf]);
    if (fault == .leaf) values[0] = try indexWire(V, ctx, t.rows[leaf][0].v + 1);
    var root = t.layers[3][0];
    if (fault == .root) root[0] ^= 1;
    const root_wires = try rootWire(V, ctx, root);
    var siblings = try t.pathWires(V, ctx, leaf);
    if (fault == .sibling) {
        var corrupted = t.path(leaf)[1];
        corrupted[13] ^= 1;
        siblings[1] = try rootWire(V, ctx, corrupted);
    }
    const query = try indexWire(V, ctx, if (fault == .index) global_query ^ 1 else global_query);
    // This is the SAME root wire the transcript absorbs, not a nominated copy.
    var transcript = try channel.Channel(V).init(ctx);
    try transcript.mixRoot(ctx, root_wires);
    try merkle.verifyOpening(V, ctx, .{ .column_logs = t.logs, .height = 3 }, query, global_log, values, &siblings, root_wires);
}
test "circuit Blake3 Merkle native leaf ordering multi-chunk widths and path parity" {
    for ([_]usize{ 1, 249, 250, 300, 1100 }) |width| {
        var t = try Tree.init(width);
        defer t.deinit();
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        try opening(Q, &ctx, &t, 5, 3, 5, .none);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    }
}
test "circuit Blake3 Merkle rejects wrong leaf root index and sibling" {
    var t = try Tree.init(6);
    defer t.deinit();
    for ([_]Fault{ .leaf, .root, .index, .sibling }) |fault| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        try opening(Q, &ctx, &t, 5, 3, 5, fault);
        try ctx.finalize(false);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}
test "circuit Blake3 Merkle query projection preserves circle pair bit and exact range" {
    for ([_]u32{ 0, 1, 2, 3, 7, 15 }) |index| for ([_]u32{ 0, 1, 2, 4, 6 }) |height| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        const query = try indexWire(Q, &ctx, index);
        const bits = try merkle.queryDirections(Q, &ctx, query, 4, height);
        const expected = try core.pcs.utils.prepareTreeQueryPositions(a, &.{index}, 4, height);
        defer a.free(expected);
        var actual = ctx.zero();
        for (bits, 0..) |bit, i| {
            const power = try ctx.constant(Q.fromU32Unchecked(@as(u32, 1) << @intCast(i), 0, 0, 0));
            actual = try ctx.add(actual, try ctx.mul(bit, power));
        }
        const expected_wire = try indexWire(Q, &ctx, @intCast(expected[0]));
        try ctx.eq(actual, expected_wire.get());
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    };
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    _ = try merkle.queryDirections(Q, &ctx, try indexWire(Q, &ctx, 16), 4, 3);
    try ctx.finalize(false);
    try std.testing.expect(!try ctx.isCircuitValid());
}
test "circuit Blake3 Merkle projected physical trees match native expanded and folded query" {
    var t = try Tree.init(17);
    defer t.deinit();
    for ([_][3]u32{ .{ 4, 13, 7 }, .{ 1, 1, 1 }, .{ 3, 5, 5 } }) |item| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        try opening(Q, &ctx, &t, item[1], item[0], item[2], .none);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    }
}
test "circuit Blake3 Merkle rejects path and row shape mismatches before hashing" {
    var t = try Tree.init(6);
    defer t.deinit();
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    const rows = try rowsWire(Q, &ctx, t.rows[0]);
    const root = try rootWire(Q, &ctx, t.layers[3][0]);
    const query = try indexWire(Q, &ctx, 0);
    const siblings = try t.pathWires(Q, &ctx, 0);
    const layout = merkle.Layout{ .column_logs = t.logs, .height = 3 };
    try std.testing.expectError(error.InvalidBlake3MerklePathLength, merkle.verifyOpening(Q, &ctx, layout, query, 3, rows, siblings[0..2], root));
    const long = siblings ++ [1]merkle.Digest{root};
    try std.testing.expectError(error.InvalidBlake3MerklePathLength, merkle.verifyOpening(Q, &ctx, layout, query, 3, rows, &long, root));
    try std.testing.expectError(error.InvalidBlake3MerkleLeafWidth, merkle.hashLeaf(Q, &ctx, layout, rows[0..5]));
    try std.testing.expectError(error.InvalidBlake3MerkleLayout, merkle.hashLeaf(Q, &ctx, .{ .column_logs = &.{}, .height = 0 }, &.{}));
    try std.testing.expectError(error.InvalidBlake3MerkleLayout, merkle.hashLeaf(Q, &ctx, .{ .column_logs = &.{31}, .height = 31 }, rows[0..1]));
}
test "circuit Blake3 Merkle finite forest has no four-tree or short-leaf restriction" {
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    const row: [2]M31 = .{ M31.fromCanonical(1), M31.fromCanonical(19) };
    var host = H.defaultWithInitialState();
    host.updateLeaf(&row);
    const root = try rootWire(Q, &ctx, host.finalize());
    const values = try rowsWire(Q, &ctx, &row);
    const query = try indexWire(Q, &ctx, 15);
    var forest: [135]merkle.Opening = undefined;
    for (&forest) |*tree| tree.* = .{ .layout = .{ .column_logs = &.{ 0, 0 }, .height = 0 }, .values = values, .root = root, .siblings = &.{} };
    try merkle.verifyForest(Q, &ctx, query, 4, &forest);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "circuit Blake3 Merkle compressed native multiproof expands without granting circuit authority" {
    var t = try Tree.init(6);
    defer t.deinit();
    const positions = [_]usize{ 5, 2, 5, 3 };
    var pending: [8]bool = @splat(false);
    for (positions) |index| pending[index] = true;
    var witness: std.ArrayList(D) = .empty;
    defer witness.deinit(a);
    for (0..3) |level| {
        var next: [8]bool = @splat(false);
        for (0..(@as(usize, 8) >> @intCast(level))) |index| if (pending[index]) {
            if (!pending[index ^ 1]) try witness.append(a, t.layers[level][index ^ 1]);
            next[index / 2] = true;
        };
        pending = next;
    }
    try std.testing.expectEqual(@as(usize, 3), witness.items.len);
    var columns: [6][]const M31 = undefined;
    var values: [6][4]M31 = undefined;
    for (&values, &columns, 0..) |*column, *view, i| {
        for (column, positions) |*value, position| value.* = t.rows[position][i];
        view.* = column;
    }
    var verifier = try core.vcs_lifted.verifier.MerkleVerifierLifted(H).initWithHeight(a, t.layers[3][0], t.logs, 3);
    defer verifier.deinit(a);
    var expanded: core.vcs_lifted.verifier.MerklePathCapture(H) = undefined;
    try verifier.verifyWithPathCapture(a, &positions, &columns, .{ .hash_witness = witness.items }, &expanded);
    defer expanded.deinit(a);
    try std.testing.expectEqual(@as(usize, 12), expanded.siblings.len);
    // Capture provides values ONLY: each path is checked again in the circuit.
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    const root = try rootWire(Q, &ctx, t.layers[3][0]);
    for (positions, 0..) |position, i| {
        var siblings: [3]merkle.Digest = undefined;
        for (&siblings, expanded.path(i)) |*wire, digest| wire.* = try rootWire(Q, &ctx, digest);
        try merkle.verifyOpening(Q, &ctx, .{ .column_logs = t.logs, .height = 3 }, try indexWire(Q, &ctx, @intCast(position)), 3, try rowsWire(Q, &ctx, t.rows[position]), &siblings, root);
    }
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
test "circuit Blake3 Merkle NoValue topology and gate-free replay preserve request wires" {
    var t = try Tree.init(6);
    defer t.deinit();
    var values = try b.Context(Q).init(a, 0);
    defer values.deinit();
    var topology = try b.Context(b.NoValue).init(a, 0);
    defer topology.deinit();
    var replay = try b.Context(Q).initWithGateRecording(a, 0, false);
    defer replay.deinit();
    try opening(Q, &values, &t, 5, 3, 5, .none);
    try opening(b.NoValue, &topology, &t, 5, 3, 5, .none);
    try opening(Q, &replay, &t, 5, 3, 5, .none);
    try values.finalize(false);
    try topology.finalize(false);
    try replay.finalize(false);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    inline for (.{ "add", "sub", "mul", "pointwise_mul", "eq", "blake_g_gate", "triple_xor", "m31_to_u32", "output" }) |field| {
        try std.testing.expectEqualDeep(@field(values.circuit, field).items, @field(topology.circuit, field).items);
    }
    try std.testing.expectEqualDeep(values.value_table.items, replay.value_table.items);
    try std.testing.expectEqualDeep(values.gate_counts, replay.gate_counts);
    try std.testing.expect(try values.isCircuitValid());
}

test "circuit Blake3 Merkle query wires are exact native raw masks including partial draws" {
    for ([_]u32{ 0, 3, 17, 30 }) |log| for ([_]usize{ 0, 1, 8, 9 }) |count| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        var transcript = try channel.Channel(Q).init(&ctx);
        var native = core.channel.blake3.Channel{};
        const expected = try core.queries.drawQueries(&native, a, log, count);
        defer a.free(expected);
        const indices = try merkle.drawQueries(Q, &ctx, &transcript, log, count);
        for (indices, expected) |index, value| {
            const check = try indexWire(Q, &ctx, @intCast(value));
            try ctx.eq(index.get(), check.get());
        }
        try std.testing.expectEqual(native.n_draws, transcript.n_draws);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    };
}
test "circuit Blake3 Merkle root absorption to authenticated query to complete path has no host direction authority" {
    var t = try Tree.init(6);
    defer t.deinit();
    for ([_]bool{ false, true }) |wrong_path| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        var transcript = try channel.Channel(Q).init(&ctx);
        const root = try rootWire(Q, &ctx, t.layers[3][0]);
        try transcript.mixRoot(&ctx, root);
        const indices = try merkle.drawQueries(Q, &ctx, &transcript, 3, 9);
        var native = core.channel.blake3.Channel{};
        native.mixRoot(t.layers[3][0]);
        const expected = try core.queries.drawQueries(&native, a, 3, 9);
        defer a.free(expected);
        for (indices, expected, 0..) |index, value, i| {
            const witness_position = if (wrong_path and i == 0) value ^ 1 else value;
            const siblings = try t.pathWires(Q, &ctx, witness_position);
            try merkle.verifyOpening(Q, &ctx, .{ .column_logs = t.logs, .height = 3 }, index, 3, try rowsWire(Q, &ctx, t.rows[witness_position]), &siblings, root);
        }
        try ctx.finalize(false);
        try std.testing.expectEqual(!wrong_path, try ctx.isCircuitValid());
    }
}
