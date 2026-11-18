//! Value-mode parity of `merkle.zig` with `MerkleVerifierLifted` on trees
//! committed by the prover's `MerkleProverLifted`, including mixed column
//! heights and trees shorter than the lifting domain.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const builder = @import("../builder/mod.zig");
const merkle = @import("merkle.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Context = builder.Context(QM31);
const Var = builder.Var;
const HashValue = builder.blake.HashValue;
const M31Wrapper = builder.wrappers.M31Wrapper;
const Hasher = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
const Prover = prover.vcs_lifted.prover.MerkleProverLifted(Hasher);
const Verifier = core.vcs_lifted.verifier.MerkleVerifierLifted(Hasher);
const PathCapture = core.vcs_lifted.verifier.MerklePathCapture(Hasher);

fn guessDigest(ctx: *Context, hash: Hasher.Hash) !HashValue(Var) {
    return builder.blake.guessHash(QM31, ctx, builder.blake.hashValueFromDigest(QM31, hash));
}

fn circuitWords(ctx: *const Context, hash: HashValue(Var)) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, hash.words) |*word, wire| word.* = builder.ivalue.unpackU32(QM31, ctx.get(wire.get()));
    return out;
}

fn bitWire(ctx: *Context, value: u32) !Var {
    return ctx.guess(builder.ivalue.qm31FromU32s(value, 0, 0, 0));
}

test "native merkle: leaf and node hashes equal the prefixed native hasher" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const values = [_]M31{ M31.fromCanonical(10), M31.fromCanonical(20), M31.fromCanonical(30) };
    var wires: [values.len]M31Wrapper(Var) = undefined;
    for (&wires, values) |*wire, value| wire.* = try builder.wrappers.guessM31(QM31, &ctx, builder.wrappers.m31Value(QM31, value));
    var hasher = Hasher.defaultWithInitialState();
    hasher.updateLeaf(&values);
    const leaf = try merkle.hashLeafM31s(QM31, &ctx, &wires);
    try std.testing.expectEqual(core.vcs.blake2_hash.digestToU32s(hasher.finalize()), circuitWords(&ctx, leaf));

    const qm31_values = [_]QM31{ QM31.fromU32Unchecked(1, 2, 3, 4), QM31.fromU32Unchecked(5, 6, 7, 8) };
    var qm31_wires: [2]Var = undefined;
    for (&qm31_wires, qm31_values) |*wire, value| wire.* = try ctx.guess(value);
    var qm31_hasher = Hasher.defaultWithInitialState();
    for (qm31_values) |value| qm31_hasher.updateLeaf(&value.toM31Array());
    const qm31_leaf = try merkle.hashLeafQm31s(QM31, &ctx, &qm31_wires);
    try std.testing.expectEqual(core.vcs.blake2_hash.digestToU32s(qm31_hasher.finalize()), circuitWords(&ctx, qm31_leaf));

    const left = [_]u8{7} ** 32;
    const right = [_]u8{11} ** 32;
    const node = try merkle.hashNode(QM31, &ctx, try guessDigest(&ctx, left), try guessDigest(&ctx, right));
    try std.testing.expectEqual(core.vcs.blake2_hash.digestToU32s(Hasher.hashChildren(.{ .left = left, .right = right })), circuitWords(&ctx, node));
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "native merkle: column permutation is the stable sort by log size" {
    const order = try merkle.columnPermutation(std.testing.allocator, &.{ 5, 3, 5, 2, 3 });
    defer std.testing.allocator.free(order);
    try std.testing.expectEqualSlices(usize, &.{ 3, 1, 4, 0, 2 }, order);
    try std.testing.expectEqual(@as(u32, 5), merkle.treeHeight(&.{ 5, 3, 5, 2, 3 }));
}

test "native merkle: tree positions select the prepareTreeQueryPositions bits" {
    const lifting_log: u32 = 7;
    const positions = [_]usize{ 0, 1, 37, 100, 127 };
    for ([_]u32{ 7, 5, 1 }) |tree_log| {
        const expected = try core.pcs.utils.prepareTreeQueryPositions(std.testing.allocator, &positions, lifting_log, tree_log);
        defer std.testing.allocator.free(expected);
        for (positions, expected) |position, want| {
            try std.testing.expectEqual(want, merkle.treePosition(position, tree_log, lifting_log));
            var ctx = try Context.init(std.testing.allocator, 0);
            defer ctx.deinit();
            var bits: [lifting_log]Var = undefined;
            for (&bits, 0..) |*bit, i| bit.* = try bitWire(&ctx, @intCast((position >> @intCast(i)) & 1));
            const selected = try merkle.treePositionBits(ctx.scratch(), &bits, tree_log, lifting_log);
            var rebuilt: usize = 0;
            for (selected, 0..) |bit, i| rebuilt |= @as(usize, ctx.get(bit).c0.a.v) << @intCast(i);
            try std.testing.expectEqual(want, rebuilt);
        }
    }
}

/// Commits `columns` natively, decommits `positions` and verifies them in
/// the circuit through `decommitTrees` with `lifting_log` query bits.
fn checkTree(columns: []const []const M31, log_sizes: []const u32, positions: []const usize, lifting_log: u32, corrupt: bool) !bool {
    const alloc = std.testing.allocator;
    var tree = try Prover.commit(alloc, columns);
    defer tree.deinit(alloc);
    const height = merkle.treeHeight(log_sizes);
    const tree_positions = try alloc.alloc(usize, positions.len);
    defer alloc.free(tree_positions);
    for (tree_positions, positions) |*out, position| out.* = merkle.treePosition(position, height, lifting_log);
    var unique = try core.queries.Queries.init(alloc, tree_positions, height);
    defer unique.deinit(alloc);

    var decommitment = try tree.decommit(alloc, unique.positions, columns);
    defer decommitment.deinit(alloc);
    const queried = try alloc.alloc([]const M31, decommitment.queried_values.len);
    defer alloc.free(queried);
    for (queried, decommitment.queried_values) |*out, column| out.* = column;
    var verifier = try Verifier.init(alloc, tree.root(), log_sizes);
    defer verifier.deinit(alloc);
    var capture: PathCapture = undefined;
    try verifier.verifyWithPathCapture(alloc, unique.positions, queried, decommitment.decommitment.decommitment, &capture);
    defer capture.deinit(alloc);

    var ctx = try Context.init(alloc, 0);
    defer ctx.deinit();
    const scratch = ctx.scratch();
    // Expand the unique openings to the raw query order.
    const values = try scratch.alloc([]const M31Wrapper(Var), columns.len);
    for (values, 0..) |*column_wires, c| {
        const wires = try scratch.alloc(M31Wrapper(Var), positions.len);
        for (wires, tree_positions) |*wire, position| {
            const unique_index = std.mem.indexOfScalar(usize, unique.positions, position).?;
            var value = queried[c][unique_index];
            if (corrupt and c == 0) value = value.add(M31.one());
            wire.* = try builder.wrappers.guessM31(QM31, &ctx, builder.wrappers.m31Value(QM31, value));
        }
        column_wires.* = wires;
    }
    const paths = try scratch.alloc([]const HashValue(Var), positions.len);
    for (paths, tree_positions) |*path, position| {
        const unique_index = std.mem.indexOfScalar(usize, unique.positions, position).?;
        const nodes = try scratch.alloc(HashValue(Var), height);
        for (nodes, capture.path(unique_index)) |*node, sibling| node.* = try guessDigest(&ctx, sibling);
        path.* = nodes;
    }
    const bits = try scratch.alloc([]const Var, lifting_log);
    for (bits, 0..) |*column_bits, i| {
        const wires = try scratch.alloc(Var, positions.len);
        for (wires, positions) |*wire, position| wire.* = try bitWire(&ctx, @intCast((position >> @intCast(i)) & 1));
        column_bits.* = wires;
    }
    const root = try guessDigest(&ctx, tree.root());
    try merkle.decommitTrees(QM31, &ctx, &.{log_sizes}, lifting_log, &.{values}, &.{paths}, bits, &.{root});
    try ctx.finalize(false);
    return ctx.isCircuitValid();
}

test "native merkle: decommitment of a mixed-height lifted tree verifies in the circuit" {
    var column_a: [8]M31 = undefined;
    var column_b: [4]M31 = undefined;
    var column_c: [8]M31 = undefined;
    for (&column_a, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(1 + i));
    for (&column_b, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(9 + i));
    for (&column_c, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(13 + i));
    const columns = [_][]const M31{ &column_a, &column_b, &column_c };
    const log_sizes = [_]u32{ 3, 2, 3 };
    // Raw queries with a duplicate, in the tree's own domain.
    try std.testing.expect(try checkTree(&columns, &log_sizes, &.{ 1, 6, 6, 3 }, 3, false));
    try std.testing.expect(!try checkTree(&columns, &log_sizes, &.{ 1, 6, 6, 3 }, 3, true));
    // The same tree queried from a lifting domain two bits larger.
    try std.testing.expect(try checkTree(&columns, &log_sizes, &.{ 5, 24, 31, 0 }, 5, false));
}

test "sparse cap binds queried paths and unopened subtrees with a fixed circuit shape" {
    const height = 6;
    const depth = 4;
    var levels: [height + 1][1 << height]Hasher.Hash = undefined;
    for (&levels[0], 0..) |*leaf, i| for (leaf, 0..) |*b, j| {
        b.* = @truncate(i * 19 + j * 7);
    };
    for (1..height + 1) |l| for (0..@as(usize, 1) << @intCast(height - l)) |i| {
        levels[l][i] = Hasher.hashChildren(.{ .left = levels[l - 1][2 * i], .right = levels[l - 1][2 * i + 1] });
    };
    const Case = enum { honest, frontier_digest, terminal, bit, root };
    var counts: ?@TypeOf(@as(Context, undefined).gate_counts) = null;
    for ([_][16]usize{ @splat(0), @splat(63), .{ 0, 0, 1, 5, 9, 12, 15, 19, 23, 23, 24, 34, 37, 43, 48, 51 }, .{ 0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60 } }) |pos| {
        var leaves: [pos.len]Hasher.Hash = undefined;
        var store: [pos.len][height]Hasher.Hash = undefined;
        var paths: [pos.len][]const Hasher.Hash = undefined;
        for (pos, &leaves, &store, &paths) |v, *leaf, *nodes, *path| {
            leaf.* = levels[0][v];
            for (nodes, 0..) |*n, l| n.* = levels[l][(v >> @intCast(l)) ^ 1];
            path.* = nodes;
        }
        var cap: [1 << depth]Hasher.Hash = undefined;
        try merkle.hostSparseCap(Hasher, &cap, &pos, &leaves, &paths, height, levels[height][0]);
        for ([_]Case{ .honest, .frontier_digest, .terminal, .bit, .root }) |case| {
            var ctx = try Context.init(std.testing.allocator, 0);
            defer ctx.deinit();
            var raw: [depth][pos.len]Var = undefined;
            var high: [depth][]const Var = undefined;
            for (&raw, &high, 0..) |*column, *view, j| {
                for (column, pos, 0..) |*wire, v, qi| {
                    const b: u32 = @intCast((v >> @intCast(height - depth + j)) & 1);
                    wire.* = try bitWire(&ctx, b ^ @intFromBool(case == .bit and qi == 0 and j == depth - 1));
                }
                view.* = column;
            }
            var ws: [cap.len]HashValue(Var) = undefined;
            for (cap, &ws, 0..) |digest, *w, i| {
                var d = digest;
                if (case == .frontier_digest and i == (if (pos[0] < 32) @as(usize, 8) else 0)) d[0] ^= 1;
                w.* = try guessDigest(&ctx, d);
            }
            var root = levels[height][0];
            if (case == .root) root[0] ^= 1;
            const frontier = try merkle.SparseCap.init(QM31, &ctx, &high);
            try frontier.verify(QM31, &ctx, &ws, try guessDigest(&ctx, root));
            for (pos, 0..) |v, i| {
                const selected = try frontier.terminal(QM31, &ctx, &ws, i);
                var term = levels[height - depth][v >> (height - depth)];
                if (case == .terminal and i == 0) term[0] ^= 1;
                const expected = try guessDigest(&ctx, term);
                for (expected.words, selected.words) |a, b| try ctx.eq(a.get(), b.get());
            }
            try ctx.finalize(false);
            try std.testing.expectEqual(case == .honest, try ctx.isCircuitValid());
            if (counts) |c| try std.testing.expectEqualDeep(c, ctx.gate_counts) else counts = ctx.gate_counts;
        }
        store[0][height - 1][0] ^= 1;
        try std.testing.expectError(error.MerkleCapMismatch, merkle.hostSparseCap(Hasher, &cap, &pos, &leaves, &paths, height, levels[height][0]));
    }
}
