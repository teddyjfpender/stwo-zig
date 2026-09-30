//! Row-tiled compact commitment (design §9.3, tile-wise LDE + Merkle).
//!
//! The streaming compact committer extends bounded column batches and keeps
//! one open leaf hasher per final-domain row between batches: about 2 GB of
//! BLAKE2s state at 2^24 leaves, loaded and stored once per batch. This path
//! turns the loop around. Columns are interpolated once into the
//! coefficients the compact tree retains anyway. Then, one aligned row tile of
//! the extended domain at a time, every column's block of the tile is
//! evaluated from its coefficients (`coset_blocks.Tiles`), the tile's leaves
//! are hashed whole (`LeafOps.buildBatched` over the blocks), and the tile's
//! subtree is hashed up to its root. Only the Merkle layers the compact tree
//! keeps (`MerkleProverLifted.compactForQueries`) are ever resident.
//!
//! Byte identity. Within a tile of `2^m` rows of an extended domain of log
//! `L`, the lifted read `2 * (r >> (L - g + 1)) + (r & 1)` of a column of
//! extended log `g` touches exactly block `t` of log `j = g - (L - m)` of its
//! evaluation, at `2 * (p >> (m - j + 1)) + (p & 1)` for the row's offset `p`
//! in the tile: the same lifted read in a tree of max log `m` over blocks of
//! log `j` (clamped to the two values at `2 * (t >> (1 - j))` when `j <= 0`).
//! So every leaf absorbs the same values in the same (height-sorted,
//! index-stable) order as in the whole tree, and every parent is the same
//! node hash. The blocks are exact evaluations (`coset_blocks`).
//!
//! Columns below the compact threshold keep their extended evaluation, as
//! `CommitmentTreeProver.compactPolynomialStorage` keeps it.

const std = @import("std");
const core = @import("stwo_core");
const circle = @import("../poly/circle/mod.zig");
const commitment_tree = @import("commitment_tree.zig");
const vcs_lifted_prover = @import("../vcs_lifted/prover.zig");
const leaves_mod = @import("../vcs_lifted/leaves.zig");
const columns_mod = @import("../vcs_lifted/columns.zig");
const parents = @import("../vcs_lifted/parents.zig");
const work_pool = @import("../work_pool.zig");
const twiddles = @import("../poly/twiddles.zig");

const M31 = core.fields.m31.M31;
const ColumnEvaluation = commitment_tree.ColumnEvaluation;
const CircleCoefficients = circle.CircleCoefficients;
const coset_blocks = circle.coset_blocks;

pub const Ownership = enum {
    /// The caller keeps the columns; they are copied to interpolate.
    borrowed,
    /// The columns' value buffers become the retained coefficients.
    owned,
    /// The columns' value buffers already hold the coefficients (a column of
    /// `log_size` is a polynomial of that log size) and are retained as they
    /// are: no interpolation.
    owned_coefficients,
};

pub const Budget = struct {
    /// Bytes of column blocks per tile.
    tile_bytes: usize = 256 << 20,
    /// Bytes of per-group prefolds (`coset_blocks.Tiles`).
    group_bytes: usize = 256 << 20,
};

/// Whether `columns` are shaped for this path: every column at least 2 rows,
/// power-of-two lengths, and at least one column at or above the compact
/// threshold once extended.
pub fn applies(columns: []const ColumnEvaluation, log_blowup: u32, compact_min_log: u32) bool {
    var any_large = false;
    for (columns) |column| {
        if (column.values.len < 2 or !std.math.isPowerOfTwo(column.values.len)) return false;
        if (std.math.log2_int(usize, column.values.len) != column.log_size) return false;
        if (column.log_size + log_blowup >= compact_min_log) any_large = true;
    }
    return any_large;
}

/// Commits `columns` as the scheme's next tree (compact storage) and mixes
/// its root into `channel`. With `.owned` or `.owned_coefficients`, `columns`
/// (the slice and its value buffers) is consumed on success and on error.
pub fn commit(
    comptime B: type,
    comptime H: type,
    scheme: anytype,
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    ownership: Ownership,
    budget: Budget,
    channel: anytype,
) !void {
    const Tree = vcs_lifted_prover.MerkleProverLifted(H);
    const LeafOps = leaves_mod.Operations(H);
    const n = columns.len;
    var owned_input = ownership != .borrowed;
    defer if (owned_input) {
        for (columns) |column| if (column.values.len != 0) allocator.free(column.values);
        allocator.free(columns);
    };
    const log_blowup = scheme.config.fri_config.log_blowup_factor;
    const compact_min_log = scheme.compact_polynomial_min_log_size;
    if (n == 0 or !applies(columns, log_blowup, compact_min_log)) return error.InvalidColumnSize;

    // 1. Coefficients, interpolated in place (one job per column).
    const coefficient_buffers = try allocator.alloc([]M31, n);
    var buffers_ready: usize = 0;
    defer allocator.free(coefficient_buffers);
    var coefficients_owned = true;
    defer if (coefficients_owned) for (coefficient_buffers[0..buffers_ready], columns[0..buffers_ready]) |buffer, column| {
        if (ownership == .borrowed or buffer.ptr != column.values.ptr) allocator.free(buffer);
    };
    for (columns, coefficient_buffers) |column, *buffer| {
        buffer.* = if (ownership != .borrowed) @constCast(column.values) else try allocator.dupe(M31, column.values);
        buffers_ready += 1;
    }
    if (ownership != .borrowed) {
        // The buffers now belong to `coefficient_buffers`.
        for (columns) |*column| column.values = &.{};
    }
    if (ownership != .owned_coefficients) {
        const Interpolate = struct {
            values: []M31,
            domain: circle.CircleDomain,
            transform: twiddles.TwiddleTree([]const M31),
            failure: ?anyerror = null,
            pub fn run(self: *@This()) void {
                _ = circle.poly.interpolateOwnedValuesWithTwiddles(self.domain, self.values, self.transform) catch |err| {
                    self.failure = err;
                };
            }
        };
        const jobs = try allocator.alloc(Interpolate, n);
        defer allocator.free(jobs);
        for (columns, coefficient_buffers, jobs) |column, buffer, *job| {
            const tree = try scheme.twiddle_source.get(allocator, column.log_size);
            job.* = .{
                .values = buffer,
                .domain = circle.CanonicCoset.new(column.log_size).circleDomain(),
                .transform = tree,
            };
        }
        coset_blocks.runJobs(Interpolate, jobs);
        for (jobs) |job| if (job.failure) |err| return err;
    }

    // 2. Height order (ascending extended log, then input index), the
    //    small columns' extended evaluations, and the tiled sources.
    var extended_log: u32 = 0;
    for (columns) |column| extended_log = @max(extended_log, column.log_size + log_blowup);
    const order = try allocator.alloc(usize, n);
    defer allocator.free(order);
    for (order, 0..) |*slot, index| slot.* = index;
    const HeightOrder = struct {
        columns: []const ColumnEvaluation,
        fn less(self: @This(), lhs: usize, rhs: usize) bool {
            const l = self.columns[lhs].log_size;
            const r = self.columns[rhs].log_size;
            return l < r or (l == r and lhs < rhs);
        }
    };
    std.sort.heap(usize, order, HeightOrder{ .columns = columns }, HeightOrder.less);

    const small_values = try allocator.alloc([]M31, n);
    defer allocator.free(small_values);
    @memset(small_values, &.{});
    var small_owned = true;
    defer if (small_owned) for (small_values) |values| if (values.len != 0) allocator.free(values);
    var sources = std.ArrayList(coset_blocks.Source).empty;
    defer sources.deinit(allocator);
    const source_of = try allocator.alloc(usize, n);
    defer allocator.free(source_of);
    for (columns, coefficient_buffers, small_values, source_of) |column, buffer, *values, *source_index| {
        const log = column.log_size + log_blowup;
        if (log < compact_min_log) {
            const polynomial = try CircleCoefficients.initBorrowed(buffer);
            const evaluation = try polynomial.evaluate(allocator, circle.CanonicCoset.new(log).circleDomain());
            values.* = @constCast(evaluation.values);
            source_index.* = std.math.maxInt(usize);
        } else {
            source_index.* = sources.items.len;
            try sources.append(allocator, .{ .coefficients = buffer, .coset_log = log });
        }
    }

    // 3. Tiles: every tiled block keeps at least 16 rows.
    const min_block_log: u32 = 4;
    var max_lift: u32 = 0;
    const logs = try allocator.alloc(u32, sources.items.len);
    defer allocator.free(logs);
    for (sources.items, logs) |source, *log| {
        log.* = source.coset_log;
        max_lift = @max(max_lift, extended_log - source.coset_log);
    }
    const min_tile_log = @min(extended_log - 1, max_lift + min_block_log);
    const NoExtra = struct {
        pub fn bytes(_: @This(), _: u32) usize {
            return 0;
        }
    };
    const tile_log = coset_blocks.chooseTileLog(logs, extended_log, min_tile_log, budget.tile_bytes, NoExtra{});
    var tiles = try coset_blocks.Tiles.init(allocator, sources.items, extended_log, tile_log, budget.group_bytes);
    defer tiles.deinit();

    // 4. The retained layers: all of them below log 20, else all but the
    //    bottom four (`compactForQueries`).
    const pruned: u32 = if (extended_log < 20) 0 else 4;
    if (tile_log < pruned) return error.InvalidColumnSize;
    const layers = try Tree.allocateLayersPruned(allocator, extended_log, pruned);
    var merkle = Tree.fromLayers(allocator, layers);
    var merkle_owned = true;
    defer if (merkle_owned) merkle.deinit(allocator);

    const refs = try allocator.alloc(columns_mod.ColumnRef, n);
    defer allocator.free(refs);
    const tile_rows = tiles.tileRows();
    // Unretained subtree levels ping-pong between two halves: a parallel
    // parent pass must never write where another range still reads.
    const scratch = try allocator.alloc(H.Hash, tile_rows);
    defer allocator.free(scratch);
    const halves = [2][]H.Hash{ scratch[0 .. tile_rows / 2], scratch[tile_rows / 2 ..] };
    for (0..tiles.tileCount()) |tile| {
        try tiles.load(tile);
        for (order, refs) |index, *ref| {
            const log = columns[index].log_size + log_blowup;
            const source_index = source_of[index];
            ref.* = .{ .original_index = index, .log_size = undefined, .values = undefined };
            if (source_index != std.math.maxInt(usize)) {
                ref.values = tiles.block(source_index);
                ref.log_size = tiles.block_logs[source_index];
                continue;
            }
            // A small column's block of the tile, from its evaluation.
            const values = small_values[index];
            if (log + tile_log > extended_log) {
                const block_log = log + tile_log - extended_log;
                ref.values = values[tile << @intCast(block_log) ..][0 .. @as(usize, 1) << @intCast(block_log)];
                ref.log_size = block_log;
            } else {
                const pair = 2 * (tile >> @intCast(extended_log - tile_log - log + 1));
                ref.values = values[pair..][0..2];
                ref.log_size = 1;
            }
        }
        const leaves = try LeafOps.buildBatched(allocator, allocator, refs, 1024);
        defer allocator.free(leaves);
        std.debug.assert(leaves.len == tile_rows);

        // The tile's subtree, writing the retained layers in place.
        var level = extended_log;
        var current: []const H.Hash = leaves;
        var width = tile_rows;
        var half: usize = 0;
        while (true) {
            if (level + pruned <= extended_log) {
                const retained = merkle.layers[level][(tile * width)..][0..width];
                if (retained.ptr != current.ptr) @memcpy(retained, current);
                current = retained;
            }
            if (width == 1) break;
            width /= 2;
            level -= 1;
            const out = if (level + pruned <= extended_log)
                merkle.layers[level][(tile * width)..][0..width]
            else blk: {
                half ^= 1;
                break :blk halves[half][0..width];
            };
            parents.hashParents(H, current, out);
            current = out;
        }
    }
    // 5. The layers above the tiles.
    var level = extended_log - tile_log;
    while (level > 0) : (level -= 1) parents.hashParents(H, merkle.layers[level], merkle.layers[level - 1]);

    // 6. The compact tree: coefficients for every column, and the extended
    //    evaluation of every small one.
    const tree_columns = try allocator.alloc(ColumnEvaluation, n);
    var tree_columns_owned = true;
    defer if (tree_columns_owned) allocator.free(tree_columns);
    const coefficients = try allocator.alloc(CircleCoefficients, n);
    var coefficient_array_owned = true;
    defer if (coefficient_array_owned) allocator.free(coefficients);
    for (columns, coefficient_buffers, small_values, tree_columns, coefficients) |column, buffer, values, *tree_column, *coefficient| {
        const log = column.log_size + log_blowup;
        coefficient.* = try CircleCoefficients.initOwned(buffer);
        tree_column.* = if (values.len != 0)
            .{ .log_size = log, .values = values }
        else
            .{ .log_size = log, .values = &.{}, .coefficient_values = buffer };
    }
    const BackendCommitmentTree = commitment_tree.CommitmentTreeProverForBackend(B, H);
    var tree = BackendCommitmentTree{
        .columns = tree_columns,
        .coefficients = coefficients,
        .compact_polynomials = true,
        .commitment = try adopt(B, H, merkle),
    };
    // The tree owns the layers, coefficients and small evaluations now.
    merkle_owned = false;
    coefficients_owned = false;
    small_owned = false;
    tree_columns_owned = false;
    coefficient_array_owned = false;
    if (ownership != .borrowed) {
        allocator.free(columns);
        owned_input = false;
    }
    // A failed append leaves the tree with the caller.
    errdefer tree.deinit(allocator);
    try scheme.appendCommittedTree(allocator, tree, channel);
}

/// Whether `B`'s Merkle tree is this path's host tree itself.
pub fn hostTree(comptime B: type, comptime H: type) bool {
    return B.MerkleTree(H) == vcs_lifted_prover.MerkleProverLifted(H);
}

fn adopt(comptime B: type, comptime H: type, tree: vcs_lifted_prover.MerkleProverLifted(H)) !B.MerkleTree(H) {
    if (comptime B.MerkleTree(H) == vcs_lifted_prover.MerkleProverLifted(H)) return tree;
    if (comptime @hasDecl(B, "adoptHostMerkle")) return B.adoptHostMerkle(H, tree);
    @compileError("Backend-specific Merkle trees require `adoptHostMerkle` for tiled PCS commits.");
}

fn checkAgainstStreaming(comptime TestHasher: type, a: std.mem.Allocator, logs: []const u32, compact_min_log: u32, budget: Budget) !void {
    const blake2_merkle = core.vcs_lifted.blake2_merkle;
    const MC = blake2_merkle.Blake2sMerkleChannel;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const Cpu = struct {
        pub fn MerkleTree(comptime Hasher: type) type {
            return vcs_lifted_prover.MerkleProverLifted(Hasher);
        }
        pub fn commitMerkle(comptime Hasher: type, allocator: std.mem.Allocator, columns: []const []const M31) !MerkleTree(Hasher) {
            return MerkleTree(Hasher).commit(allocator, columns);
        }
    };
    const Scheme = @import("scheme.zig").CommitmentSchemeProver(Cpu, TestHasher, MC);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };

    const columns = try a.alloc(ColumnEvaluation, logs.len);
    defer a.free(columns);
    var filled: usize = 0;
    defer for (columns[0..filled]) |column| a.free(column.values);
    for (logs, columns, 0..) |log, *column, index| {
        const values = try a.alloc(M31, @as(usize, 1) << @intCast(log));
        for (values, 0..) |*value, i| value.* = M31.fromU64(index * 1_000_003 + i * i * 7919 + i * 31 + 5);
        column.* = .{ .log_size = log, .values = values };
        filled += 1;
    }

    var streaming = try Scheme.init(a, config);
    defer streaming.deinit(a);
    streaming.setCompactPolynomialStorage(compact_min_log);
    var streaming_channel = Channel{};
    try streaming.commitBorrowedStreamingWithRecorder(a, columns, 0, null, &streaming_channel);

    var tiled = try Scheme.init(a, config);
    defer tiled.deinit(a);
    tiled.setCompactPolynomialStorage(compact_min_log);
    var tiled_channel = Channel{};
    try commit(Cpu, TestHasher, &tiled, a, columns, .borrowed, budget, &tiled_channel);

    try std.testing.expectEqualSlices(u8, &streaming_channel.digestBytes(), &tiled_channel.digestBytes());

    // The same columns handed over as coefficients: the same tree.
    var direct = try Scheme.init(a, config);
    defer direct.deinit(a);
    direct.setCompactPolynomialStorage(compact_min_log);
    const coefficient_columns = try a.alloc(ColumnEvaluation, logs.len);
    for (columns, coefficient_columns) |column, *out| {
        const values = try a.dupe(M31, column.values);
        const transform = try direct.twiddle_source.get(a, column.log_size);
        _ = try circle.poly.interpolateOwnedValuesWithTwiddles(circle.CanonicCoset.new(column.log_size).circleDomain(), values, transform);
        out.* = .{ .log_size = column.log_size, .values = values };
    }
    var direct_channel = Channel{};
    try commit(Cpu, TestHasher, &direct, a, coefficient_columns, .owned_coefficients, budget, &direct_channel);
    try std.testing.expectEqualSlices(u8, &streaming_channel.digestBytes(), &direct_channel.digestBytes());
    for (tiled.trees.items[0].commitment.layers, direct.trees.items[0].commitment.layers) |want, got|
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(want), std.mem.sliceAsBytes(got));

    const expected = streaming.trees.items[0];
    const actual = tiled.trees.items[0];
    try std.testing.expectEqual(expected.commitment.layers.len, actual.commitment.layers.len);
    for (expected.commitment.layers, actual.commitment.layers) |want, got| {
        try std.testing.expectEqual(want.len, got.len);
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(want), std.mem.sliceAsBytes(got));
    }
    for (expected.columns, actual.columns) |want, got| {
        try std.testing.expectEqual(want.log_size, got.log_size);
        try std.testing.expectEqualSlices(M31, want.values, got.values);
        try std.testing.expectEqual(want.coefficient_values != null, got.coefficient_values != null);
        if (want.coefficient_values) |coefficients| try std.testing.expectEqualSlices(M31, coefficients, got.coefficient_values.?);
    }
    for (expected.coefficients.?, actual.coefficients.?) |want, got| try std.testing.expectEqualSlices(M31, want.coefficients(), got.coefficients());
    var extended_log: u32 = 0;
    for (logs) |log| extended_log = @max(extended_log, log + 1);
    const n_leaves = @as(usize, 1) << @intCast(extended_log);
    const queries = [_]usize{ 0, 1, n_leaves - 1, n_leaves / 2 + 3, 7, 7 };
    var want = try expected.decommit(a, &queries);
    defer want.deinit(a);
    var got = try actual.decommit(a, &queries);
    defer got.deinit(a);
    try std.testing.expectEqualDeep(want, got);
}

test "tiled compact commitment equals the streaming compact commitment" {
    const a = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3 });
    defer pool.deinit();
    var binding = try work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const blake2_merkle = core.vcs_lifted.blake2_merkle;
    inline for (.{ blake2_merkle.Blake2sPlainMerkleHasher, blake2_merkle.Blake2sMerkleHasher }) |TestHasher| {
        // Mixed heights, small columns kept evaluated, tiny budgets: many
        // tiles and groups, no pruned layers.
        try checkAgainstStreaming(TestHasher, a, &.{ 7, 3, 9, 5, 9, 8 }, 6, .{ .tile_bytes = 1 << 10, .group_bytes = 1 << 12 });
        try checkAgainstStreaming(TestHasher, a, &.{ 9, 9 }, 6, .{});
        // A tiny column below one row per tile: its two values per tile.
        try checkAgainstStreaming(TestHasher, a, &.{ 11, 2, 9 }, 6, .{ .tile_bytes = 1, .group_bytes = 1 << 12 });
        // A log-20 tree: the bottom four layers pruned, as `compactForQueries`.
        try checkAgainstStreaming(TestHasher, a, &.{ 19, 12, 3, 16 }, 12, .{ .tile_bytes = 1 << 20, .group_bytes = 1 << 20 });
    }
}

test "tiled compact commitment of polynomials equals the uncompacted tree" {
    const a = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3 });
    defer pool.deinit();
    var binding = try work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const blake2_merkle = core.vcs_lifted.blake2_merkle;
    const TestHasher = blake2_merkle.Blake2sMerkleHasher;
    const MC = blake2_merkle.Blake2sMerkleChannel;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const Cpu = struct {
        pub fn MerkleTree(comptime Hasher: type) type {
            return vcs_lifted_prover.MerkleProverLifted(Hasher);
        }
        pub fn commitMerkle(comptime Hasher: type, allocator: std.mem.Allocator, columns: []const []const M31) !MerkleTree(Hasher) {
            return MerkleTree(Hasher).commit(allocator, columns);
        }
    };
    const Scheme = @import("scheme.zig").CommitmentSchemeProver(Cpu, TestHasher, MC);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };

    // Mixed heights, one below the compact threshold; log 20 once extended,
    // so the tiled tree also prunes its bottom layers.
    const logs = [_]u32{ 19, 12, 3, 16 };
    var polys: [logs.len]CircleCoefficients = undefined;
    var filled: usize = 0;
    defer for (polys[0..filled]) |*poly| poly.deinit(a);
    for (logs, &polys, 0..) |log, *poly, index| {
        const coefficients = try a.alloc(M31, @as(usize, 1) << @intCast(log));
        for (coefficients, 0..) |*value, i| value.* = M31.fromU64(index * 7_000_003 + i * i * 131 + i + 9);
        poly.* = try CircleCoefficients.initOwned(coefficients);
        filled += 1;
    }

    var plain = try Scheme.init(a, config);
    defer plain.deinit(a);
    var plain_channel = Channel{};
    try plain.commitPolysWithRecorder(a, &polys, null, &plain_channel);

    var compact = try Scheme.init(a, config);
    defer compact.deinit(a);
    compact.setCompactPolynomialStorage(12);
    var compact_channel = Channel{};
    try compact.commitPolysWithRecorder(a, &polys, null, &compact_channel);

    try std.testing.expectEqualSlices(u8, &plain_channel.digestBytes(), &compact_channel.digestBytes());
    const expected = plain.trees.items[0];
    const actual = compact.trees.items[0];
    try std.testing.expect(actual.compact_polynomials);
    // Tiled: the bottom four layers were never built.
    try std.testing.expectEqual(@as(usize, 0), actual.commitment.layers[actual.commitment.layers.len - 1].len);
    for (expected.commitment.layers[0 .. expected.commitment.layers.len - 4], actual.commitment.layers[0 .. actual.commitment.layers.len - 4]) |want, got|
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(want), std.mem.sliceAsBytes(got));
    const n_leaves = @as(usize, 1) << 20;
    const queries = [_]usize{ 0, 1, n_leaves - 1, n_leaves / 2 + 3, 7, 7 };
    var want = try expected.decommit(a, &queries);
    defer want.deinit(a);
    var got = try actual.decommit(a, &queries);
    defer got.deinit(a);
    try std.testing.expectEqualDeep(want, got);
}
