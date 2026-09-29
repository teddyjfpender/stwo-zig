const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const poly = @import("../poly/circle/mod.zig");
const trees = @import("commitment_tree.zig");
const planning = @import("quotients/planning.zig");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const Tree = trees.CommitmentTreeProver(H);
const Column = trees.ColumnEvaluation;

fn checkOpenings(a: std.mem.Allocator, backed: bool) !void {
    const logs = [_]u32{ 5, 3, 5, 4 };
    const columns = try a.alloc(Column, logs.len);
    const coefficients = a.alloc(poly.CircleCoefficients, logs.len) catch |err| {
        a.free(columns);
        return err;
    };
    var initialized: usize = 0;
    var owned = true;
    defer if (owned) {
        for (columns[0..initialized], coefficients[0..initialized]) |column, *coefficient| {
            a.free(column.values);
            coefficient.deinit(a);
        }
        a.free(columns);
        a.free(coefficients);
    };
    for (logs, 0..) |log, i| {
        const c = try a.alloc(M, @as(usize, 1) << @intCast(log - 1));
        errdefer a.free(c);
        for (c, 0..) |*x, j| x.* = M.fromU64(11 + i * 19 + j * j);
        const polynomial = try poly.CircleCoefficients.initOwned(c);
        const evaluation = try polynomial.evaluate(a, poly.CanonicCoset.new(log).circleDomain());
        columns[i] = .{ .log_size = log, .values = evaluation.values };
        coefficients[i] = polynomial;
        initialized += 1;
    }
    var tree = try Tree.initOwnedWithCoefficients(a, columns, coefficients);
    owned = false;
    defer tree.deinit(a);
    if (backed) {
        const backings = try a.alloc(trees.ColumnBacking, columns.len);
        for (columns, backings) |column, *backing| backing.* = .{ .values = @constCast(column.values), .alignment = .of(M) };
        tree.streaming_column_backings = backings;
    }
    // Exercise missing bottom hash layers and mixed log-size column lifting.
    tree.commitment.pruneBottomLayers(3);
    const queries = [_]usize{ 31, 0, 7, 7, 14, 23 };
    var expected = try tree.decommit(a, &queries);
    defer expected.deinit(a);
    const root = tree.root();
    try tree.compactPolynomialStorage(a, 4);
    tree.releaseCoefficients(a);
    try std.testing.expect(tree.coefficients != null);
    try std.testing.expectEqual(@as(usize, 0), tree.columns[0].values.len);
    try std.testing.expectEqual(@as(usize, 8), tree.columns[1].values.len);
    var actual = try tree.decommit(a, &queries);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected, actual);
    try std.testing.expectEqualDeep(root, tree.root());
    try tree.share(a);
    var lease = tree.retainShared();
    defer lease.deinit(a);
    var shared_opening = try lease.decommit(a, &queries);
    defer shared_opening.deinit(a);
    try std.testing.expectEqualDeep(expected, shared_opening);
}

test "coefficient storage openings preserve mixed columns, duplicates, pruned hashes and shared leases" {
    try checkOpenings(std.testing.allocator, false);
    try checkOpenings(std.testing.allocator, true);
}

test "coefficient storage cleans up every opening and compaction allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkOpenings, .{false});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkOpenings, .{true});
}

fn checkCombination(a: std.mem.Allocator) !void {
    const c1 = [_]M{ M.fromCanonical(3), M.fromCanonical(7), M.one(), M.zero() };
    const c2 = [_]M{ M.fromCanonical(11), M.one() };
    const p1 = try poly.CircleCoefficients.initBorrowed(&c1);
    const p2 = try poly.CircleCoefficients.initBorrowed(&c2);
    const e1 = try p1.evaluate(a, poly.CanonicCoset.new(4).circleDomain());
    defer a.free(e1.values);
    const e2 = try p2.evaluate(a, poly.CanonicCoset.new(4).circleDomain());
    defer a.free(e2.values);
    const e3 = try p2.evaluate(a, poly.CanonicCoset.new(3).circleDomain());
    defer a.free(e3.values);
    const columns = [_]Column{
        .{ .log_size = 4, .values = e1.values },
        .{ .log_size = 4, .values = e2.values },
        .{ .log_size = 3, .values = e3.values },
    };
    var compact = columns;
    compact[0].values = &.{};
    compact[0].coefficient_values = &c1;
    compact[1].values = &.{};
    compact[1].coefficient_values = &c2;
    const indices = [_]usize{ 0, 1, 2 };
    const ranges = [_]@import("quotient_row_executor.zig").ColumnContributionRange{
        .{ .start = 0, .len = 2 }, .{ .start = 2, .len = 1 }, .{ .start = 3, .len = 1 },
    };
    const contributions = [_]@import("quotient_row_executor.zig").ColumnContribution{
        .{ .batch_index = 0, .value_coeff = Q.fromM31(M.fromCanonical(13), M.zero(), M.zero(), M.zero()) },
        .{ .batch_index = 1, .value_coeff = Q.fromM31Array(.{ M.one(), M.fromCanonical(7), M.fromCanonical(19), M.one() }) },
        .{ .batch_index = 0, .value_coeff = Q.one() },
        .{ .batch_index = 0, .value_coeff = Q.fromM31(M.fromCanonical(29), M.zero(), M.zero(), M.zero()) },
    };
    var expected = try planning.buildCombinedContributionPlan(a, &columns, &indices, &ranges, &contributions, &.{ true, true, true }, 5);
    defer expected.deinit(a);
    var actual = try planning.buildCombinedContributionPlan(a, &compact, &indices, &ranges, &contributions, &.{ true, true, true }, 5);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected.views, actual.views);
}

test "coefficient storage quotient folding matches full LDEs across domains and sample batches" {
    try checkCombination(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkCombination, .{});
}

fn checkLazy(a: std.mem.Allocator) !void {
    const c = [_]M{ M.one(), M.fromCanonical(3), M.fromCanonical(5), M.fromCanonical(7) };
    const polynomial = try poly.CircleCoefficients.initBorrowed(&c);
    const evaluation = try polynomial.evaluate(a, poly.CanonicCoset.new(5).circleDomain());
    defer a.free(evaluation.values);
    const zero = [_]M{ M.zero(), M.zero() };
    const materialized = [_]Column{ .{ .log_size = 5, .values = evaluation.values }, .{ .log_size = 1, .values = &zero } };
    var compact = materialized;
    compact[0].values = &.{};
    compact[0].coefficient_values = &c;
    compact[1].values = &.{};
    compact[1].coefficient_values = &zero;
    var columns = [_][]const Column{&materialized};
    var compact_columns = [_][]const Column{&compact};
    const Point = core.circle.CirclePointQM31;
    var points = [_]Point{ core.circle.SECURE_FIELD_CIRCLE_GEN.mul(7), core.circle.SECURE_FIELD_CIRCLE_GEN.mul(19) };
    var tree_points = [_][]Point{ &points, &.{} };
    var point_trees = [_][][]Point{&tree_points};
    var samples = [_]Q{ Q.fromU32Unchecked(11, 13, 17, 19), Q.fromU32Unchecked(23, 29, 31, 37) };
    var tree_samples = [_][]Q{ &samples, &.{} };
    var sample_trees = [_][][]Q{&tree_samples};
    const Provider = @import("quotient_ops.zig").LazyQuotientProvider;
    const TreeVec = core.pcs.TreeVec;
    const random = Q.fromU32Unchecked(3, 0, 1, 0);
    var expected = try Provider.initWithMode(a, TreeVec([]const Column).initOwned(&columns), TreeVec([][]Point).initOwned(&point_trees), TreeVec([][]Q).initOwned(&sample_trees), random, 5, .bounded_cpu);
    defer expected.deinit(a);
    var actual = try Provider.initWithMode(a, TreeVec([]const Column).initOwned(&compact_columns), TreeVec([][]Point).initOwned(&point_trees), TreeVec([][]Q).initOwned(&sample_trees), random, 5, .bounded_cpu);
    defer actual.deinit(a);
    try std.testing.expectEqual(.combined_compatibility, actual.input_mode);
    var want: [4][32]M = undefined;
    var got: [4][32]M = undefined;
    var want_views: [4][]M = undefined;
    var got_views: [4][]M = undefined;
    for (&want, &got, &want_views, &got_views) |*w, *g, *wv, *gv| {
        wv.* = w;
        gv.* = g;
    }
    try expected.computeChunk(0, 32, &want_views);
    try actual.computeChunk(0, 32, &got_views);
    try std.testing.expectEqualDeep(want, got);
}

test "coefficient storage lazy quotient pipeline matches bounded CPU including unsampled zero columns" {
    try checkLazy(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkLazy, .{});
}

fn checkStreamingFor(comptime TestHasher: type, comptime MC: type, comptime Channel: type, a: std.mem.Allocator) !void {
    const Cpu = struct {
        pub fn MerkleTree(comptime Hasher: type) type {
            return @import("../vcs_lifted/prover.zig").MerkleProverLifted(Hasher);
        }
        pub fn commitMerkle(comptime Hasher: type, allocator: std.mem.Allocator, columns: []const []const M) !MerkleTree(Hasher) {
            return MerkleTree(Hasher).commit(allocator, columns);
        }
    };
    const Scheme = @import("scheme.zig").CommitmentSchemeProver(Cpu, TestHasher, MC);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var baseline = try Scheme.init(a, config);
    defer baseline.deinit(a);
    var compact = try Scheme.init(a, config);
    defer compact.deinit(a);
    compact.setCompactPolynomialStorage(4);
    var original_channel = Channel{};
    var compact_channel = original_channel;
    var small: [8]M = undefined;
    var large: [32]M = undefined;
    for (&small, 0..) |*x, i| x.* = M.fromU64(i * 7 + 13);
    for (&large, 0..) |*x, i| x.* = M.fromU64(i * i + 31);
    const columns = [_]Column{
        .{ .log_size = 5, .values = &large },
        .{ .log_size = 3, .values = &small },
        .{ .log_size = 5, .values = &large },
    };
    try baseline.commitBorrowedStreamingWithRecorder(a, &columns, 1, null, &original_channel);
    try compact.commitBorrowedStreamingWithRecorder(a, &columns, 1, null, &compact_channel);
    try std.testing.expectEqualSlices(u8, &original_channel.digestBytes(), &compact_channel.digestBytes());
    const queries = [_]usize{ 0, 61, 7, 16, 7 };
    var expected = try baseline.trees.items[0].decommit(a, &queries);
    defer expected.deinit(a);
    var actual = try compact.trees.items[0].decommit(a, &queries);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected, actual);
}

test "coefficient storage incremental commitments match materialized roots and openings" {
    try checkStreaming(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkStreaming, .{});
}

fn checkStreaming(a: std.mem.Allocator) !void {
    try checkStreamingFor(H, core.vcs_lifted.blake3_merkle.MerkleChannel, core.channel.blake3.Channel, a);
}
fn checkPlainBlake2(a: std.mem.Allocator) !void {
    try checkStreamingFor(core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher, core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel, core.channel.blake2s.Blake2sChannel, a);
}
fn checkPrefixedBlake2(a: std.mem.Allocator) !void {
    try checkStreamingFor(core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher, core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel, core.channel.blake2s.Blake2sChannel, a);
}
test "coefficient storage BLAKE2s incremental commitments preserve plain and prefixed roots and openings" {
    try checkPlainBlake2(std.testing.allocator);
    try checkPrefixedBlake2(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkPlainBlake2, .{});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkPrefixedBlake2, .{});
}

fn checkArenaStream(a: std.mem.Allocator) !void {
    const Blake = core.vcs_lifted.blake2_merkle;
    const Backend = struct {
        pub const combined_base_in_place = true;
        // The last batch must still use the arena-aware combined preparation.
        pub const combined_commit_min_columns: usize = 65;
        pub const MerkleTree = @import("owned_source_admission_test.zig").Backend.MerkleTree;
        pub const commitMerkle = @import("owned_source_admission_test.zig").Backend.commitMerkle;
        pub const interpolateAndEvaluateCircleBuffers = @import("owned_source_admission_test.zig").Backend.interpolateAndEvaluateCircleBuffers;
    };
    const Scheme = @import("scheme.zig").CommitmentSchemeProver(Backend, Blake.Blake2sPlainMerkleHasher, Blake.Blake2sMerkleChannel);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var baseline = try Scheme.init(a, config);
    defer baseline.deinit(a);
    var compact = try Scheme.init(a, config);
    defer compact.deinit(a);
    compact.setCompactPolynomialStorage(4);
    const count = 129;
    var words: usize = 17; // Retain padding and the original allocation, not interior slices.
    for (0..count) |i| words += @as(usize, 1) << @intCast(3 + i % 3);
    const arena = try a.alloc(M, words);
    var input_live = true;
    defer if (input_live) a.free(arena);
    const columns = try a.alloc(Column, count);
    var columns_live = true;
    defer if (columns_live) a.free(columns);
    var starts: [count]usize = undefined;
    var cursor: usize = 17;
    for (columns, 0..) |*column, i| {
        const log: u32 = @intCast(3 + i % 3);
        const len = @as(usize, 1) << @intCast(log);
        starts[i] = cursor;
        const values = arena[cursor..][0..len];
        for (values, 0..) |*value, row| value.* = M.fromU64(1 + i * 31 + row * row);
        column.* = .{ .log_size = log, .values = values };
        cursor += len;
    }
    var original_channel = core.channel.blake2s.Blake2sChannel{};
    var compact_channel = original_channel;
    try baseline.commitBorrowedStreamingWithRecorder(a, columns, 64, null, &original_channel);
    const buffers = try a.alloc([]M, 1);
    buffers[0] = arena;
    input_live = false;
    columns_live = false;
    // Both descriptors and arena ownership transfer on success and error.
    try compact.commitOwnedWithRecorderAndBacking(a, columns, buffers, null, &compact_channel);
    try std.testing.expectEqualSlices(u8, &original_channel.digestBytes(), &compact_channel.digestBytes());
    const tree = &compact.trees.items[0];
    try std.testing.expectEqual(@as(usize, 1), tree.coefficient_backing_buffers.?.len);
    try std.testing.expectEqual(arena.ptr, tree.coefficient_backing_buffers.?[0].ptr);
    for (tree.coefficients.?, 0..) |coefficient, i|
        try std.testing.expectEqual(arena[starts[i]..].ptr, coefficient.coefficients().ptr);
    const queries = [_]usize{ 0, 61, 7, 16, 7 };
    var expected = try baseline.trees.items[0].decommit(a, &queries);
    defer expected.deinit(a);
    var actual = try tree.decommit(a, &queries);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected, actual);
}

test "coefficient storage arena streaming retains original custody across batches and allocation failures" {
    try checkArenaStream(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkArenaStream, .{});
}

test "coefficient storage selected FFT matches full evaluation across heights, degrees and query tails" {
    const a = std.testing.allocator;
    const tw = @import("../poly/twiddles.zig");
    var transform = try tw.precomputeM31(a, poly.CanonicCoset.new(14).circleDomain().half_coset);
    defer tw.deinitM31(a, &transform);
    const borrowed = tw.TwiddleTree([]const M){ .root_coset = transform.root_coset, .twiddles = transform.twiddles, .itwiddles = transform.itwiddles };
    for (6..15) |log_raw| {
        const log: u32 = @intCast(log_raw);
        const size = @as(usize, 1) << @intCast(log);
        const expected = try a.alloc(M, size);
        defer a.free(expected);
        const actual = try a.alloc(M, size);
        defer a.free(actual);
        for ([_]usize{ size, size / 2, size / 4 }) |count| {
            for (expected[0..count], 0..) |*value, i| value.* = M.fromU64(i * i * 37 + i * 29 + 17);
            @memcpy(actual[0..count], expected[0..count]);
            @memset(expected[count..], M.zero());
            @memset(actual[count..], M.fromCanonical(71)); // Stale scratch must be ignored.
            const domain = poly.CanonicCoset.new(log).circleDomain();
            try poly.poly.evaluateBuffersWithTwiddles(&.{expected}, domain, borrowed);
            const positions = [_]usize{ 0, 1, 1, size / 3, size / 2, size / 2 + 1, size - 2, size - 1 };
            try @import("../poly/circle/transforms.zig").evaluateSelectedBufferWithTwiddles(actual, count, domain, borrowed, &positions);
            for (positions) |position| try std.testing.expectEqualDeep(expected[position], actual[position]);
        }
    }
    var buffer = [_]M{M.one()} ** 64;
    const selected = @import("../poly/circle/transforms.zig").evaluateSelectedBufferWithTwiddles;
    const domain = poly.CanonicCoset.new(6).circleDomain();
    try std.testing.expectError(error.InvalidLength, selected(&buffer, 0, domain, borrowed, &.{0}));
    try std.testing.expectError(error.InvalidLength, selected(&buffer, 32, domain, borrowed, &.{64}));
    try std.testing.expectError(error.InvalidLength, selected(&buffer, 32, domain, borrowed, &.{ 3, 2 }));
}

fn checkFixedCache(a: std.mem.Allocator, corrupt: bool) !void {
    const Blake = core.vcs_lifted.blake2_merkle;
    const Hasher = Blake.Blake2sPlainMerkleHasher;
    const Cpu = struct {
        pub fn MerkleTree(comptime F: type) type {
            return @import("../vcs_lifted/prover.zig").MerkleProverLifted(F);
        }
        pub fn commitMerkle(comptime F: type, allocator: std.mem.Allocator, columns: []const []const M) !MerkleTree(F) {
            return MerkleTree(F).commit(allocator, columns);
        }
    };
    const Scheme = @import("scheme.zig").CommitmentSchemeProver(Cpu, Hasher, Blake.Blake2sMerkleChannel);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var baseline = try Scheme.init(a, config);
    defer baseline.deinit(a);
    var compact = try Scheme.init(a, config);
    defer compact.deinit(a);
    compact.setCompactPolynomialStorage(4);
    var small = [_]M{M.one()} ** 8;
    var large: [32]M = undefined;
    for (&large, 0..) |*value, i| value.* = M.fromU64(i * i + 17);
    const columns = [_]Column{
        .{ .log_size = 5, .values = &large }, .{ .log_size = 3, .values = &small },
        .{ .log_size = 5, .values = &large },
    };
    var baseline_channel = core.channel.blake2s.Blake2sChannel{};
    var compact_channel = baseline_channel;
    try baseline.commitBorrowedStreamingWithRecorder(a, &columns, 1, null, &baseline_channel);
    const seam = @import("merkle_layer_cache.zig");
    const Context = struct {
        tree: *const @import("../vcs_lifted/prover.zig").MerkleProverLifted(Hasher),
        corrupt: bool,
        fn load(raw: *anyopaque, request: seam.Request, layers: []const []u8) bool {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (request.log_size != 6 or request.pruned_bottom_layers != 0 or
                !std.mem.eql(u32, request.column_log_sizes, &.{ 4, 6, 6 })) return false;
            for (self.tree.layers, layers) |source, destination| {
                if (destination.len != std.mem.sliceAsBytes(source).len) return false;
                @memcpy(destination, std.mem.sliceAsBytes(source));
            }
            if (self.corrupt) layers[0][0] ^= 1;
            return true;
        }
        fn store(_: *anyopaque, _: seam.Request, _: []const []const u8) void {}
    };
    var context = Context{ .tree = &baseline.trees.items[0].commitment, .corrupt = corrupt };
    seam.arm(.{ .ctx = &context, .load = Context.load, .store = Context.store });
    defer seam.disarm();
    try compact.commitBorrowedStreamingWithRecorder(a, &columns, 1, null, &compact_channel);
    try std.testing.expectEqualSlices(u8, &baseline_channel.digestBytes(), &compact_channel.digestBytes());
    const queries = [_]usize{ 0, 7, 16, 61 };
    var expected = try baseline.trees.items[0].decommit(a, &queries);
    defer expected.deinit(a);
    var actual = try compact.trees.items[0].decommit(a, &queries);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected, actual);
    // A fixed-data compact tree must survive the policy transition back to
    // ordinary witness storage, including release before subsequent openings.
    compact.compact_polynomial_storage = false;
    compact.setCoefficientRetentionPolicy(.never);
    seam.disarm();
    try compact.commitBorrowedStreamingWithRecorder(a, &columns, 1, null, &compact_channel);
    try std.testing.expect(compact.trees.items[1].coefficients == null);
    compact.trees.items[0].releaseCoefficients(a);
    var retained = try compact.trees.items[0].decommit(a, &queries);
    defer retained.deinit(a);
    try std.testing.expectEqualDeep(expected, retained);
}

test "coefficient storage fixed cache preserves openings, rejects corrupt layers and owns failure cleanup" {
    try checkFixedCache(std.testing.allocator, false);
    try checkFixedCache(std.testing.allocator, true);
    // Cache allocation failures deliberately recover through a fresh commit.
    // Admit either correct success or OOM, while checking every owner is freed.
    for ([_]bool{ false, true }) |corrupt| {
        var index: usize = 0;
        while (true) : (index += 1) {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
            checkFixedCache(failing.allocator(), corrupt) catch |err| {
                if (err != error.OutOfMemory) return err;
            };
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            if (!failing.has_induced_failure) break;
        }
    }
}

fn checkHybrid(a: std.mem.Allocator) !void {
    const log = 13;
    const size = 1 << log;
    const coeff = [_]M{ M.one(), M.fromCanonical(3), M.fromCanonical(5), M.fromCanonical(7) };
    const polynomial = try poly.CircleCoefficients.initBorrowed(&coeff);
    const evaluation = try polynomial.evaluate(a, poly.CanonicCoset.new(log).circleDomain());
    defer a.free(evaluation.values);
    const materialized = [_]Column{
        .{ .log_size = log, .values = evaluation.values },
        .{ .log_size = log, .values = evaluation.values },
    };
    var compact = materialized;
    compact[0].values = &.{};
    compact[0].coefficient_values = &coeff;
    var trees_materialized = [_][]const Column{&materialized};
    var trees_compact = [_][]const Column{&compact};
    const Point = core.circle.CirclePointQM31;
    var first = [_]Point{ core.circle.SECURE_FIELD_CIRCLE_GEN.mul(7), core.circle.SECURE_FIELD_CIRCLE_GEN.mul(19) };
    var second = [_]Point{first[1]};
    var tree_points = [_][]Point{ &first, &second };
    var point_trees = [_][][]Point{&tree_points};
    var first_values = [_]Q{ Q.fromU32Unchecked(11, 13, 17, 19), Q.fromU32Unchecked(23, 29, 31, 37) };
    var second_values = [_]Q{Q.fromU32Unchecked(41, 43, 47, 53)};
    var tree_values = [_][]Q{ &first_values, &second_values };
    var sample_trees = [_][][]Q{&tree_values};
    const Provider = @import("quotient_ops.zig").LazyQuotientProvider;
    const TreeVec = core.pcs.TreeVec;
    const random = Q.fromU32Unchecked(3, 0, 1, 0);
    var expected = try Provider.initWithMode(a, TreeVec([]const Column).initOwned(&trees_materialized), TreeVec([][]Point).initOwned(&point_trees), TreeVec([][]Q).initOwned(&sample_trees), random, log, .bounded_cpu);
    defer expected.deinit(a);
    var actual = try Provider.initWithMode(a, TreeVec([]const Column).initOwned(&trees_compact), TreeVec([][]Point).initOwned(&point_trees), TreeVec([][]Q).initOwned(&sample_trees), random, log, .bounded_cpu);
    defer actual.deinit(a);
    try std.testing.expectEqual(.bounded_cpu, actual.input_mode);
    try std.testing.expectEqual(@as(usize, 1), actual.direct_plan.views.len);
    try std.testing.expectEqual(@as(usize, 2), actual.combined_views.len);
    const values = try a.alloc(M, 8 * size);
    defer a.free(values);
    var want: [4][]M = undefined;
    var got: [4][]M = undefined;
    for (&want, &got, 0..) |*w, *g, i| {
        w.* = values[i * size ..][0..size];
        g.* = values[(4 + i) * size ..][0..size];
    }
    try expected.computeChunk(0, size, &want);
    try actual.computeChunk(0, size, &got);
    for (want, got) |w, g| try std.testing.expectEqualSlices(M, w, g);
    // Also qualify the parallel full-domain path with the same mixed inputs.
    var out = @import("../secure_column.zig").SecureColumnByCoords{ .columns = got, .owns_columns = false };
    try actual.computeAll(a, &out);
    for (want, got) |w, g| try std.testing.expectEqualSlices(M, w, g);
}

test "coefficient storage hybrid bounded quotients preserve raw columns and parallel output parity" {
    var pool: @import("../work_pool.zig").WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var binding = try @import("../work_pool.zig").ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try checkHybrid(std.testing.allocator);
    var index: usize = 0;
    while (true) : (index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        checkHybrid(failing.allocator()) catch |err| {
            if (err != error.OutOfMemory) return err;
        };
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        if (!failing.has_induced_failure) break;
    }
}

fn checkSpilledTail(a: std.mem.Allocator) !void {
    const Blake = core.vcs_lifted.blake2_merkle;
    const Cpu = struct {
        pub fn MerkleTree(comptime F: type) type {
            return @import("../vcs_lifted/prover.zig").MerkleProverLifted(F);
        }
        pub fn commitMerkle(comptime F: type, allocator: std.mem.Allocator, columns: []const []const M) !MerkleTree(F) {
            return MerkleTree(F).commit(allocator, columns);
        }
    };
    const Scheme = @import("scheme.zig").CommitmentSchemeProver(Cpu, Blake.Blake2sPlainMerkleHasher, Blake.Blake2sMerkleChannel);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var baseline = try Scheme.init(a, config);
    defer baseline.deinit(a);
    var compact = try Scheme.init(a, config);
    defer compact.deinit(a);
    compact.setCompactPolynomialStorage(4);
    var data: [128]M = undefined;
    for (&data, 0..) |*value, i| value.* = M.fromU64(i * i * 71 + 13);
    var columns: [18]Column = undefined;
    for (columns[0..16]) |*column| column.* = .{ .log_size = 3, .values = data[0..8] };
    columns[16] = .{ .log_size = 6, .values = data[0..64] };
    columns[17] = .{ .log_size = 7, .values = &data };
    // Sixteen lower-height words fill a BLAKE2s block. The two terminal
    // heights must continue through a new block, preserving exactly the root.
    var original_channel = core.channel.blake2s.Blake2sChannel{};
    var compact_channel = original_channel;
    try baseline.commitBorrowedStreamingWithRecorder(a, &columns, 4, null, &original_channel);
    try compact.commitBorrowedStreamingWithRecorder(a, &columns, 4, null, &compact_channel);
    try std.testing.expectEqualSlices(u8, &original_channel.digestBytes(), &compact_channel.digestBytes());
    const queries = [_]usize{ 0, 1, 37, 127, 255 };
    var expected = try baseline.trees.items[0].decommit(a, &queries);
    defer expected.deinit(a);
    var actual = try compact.trees.items[0].decommit(a, &queries);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected, actual);
}

test "coefficient storage sparse terminal columns spill a full hash block without final-height state" {
    try checkSpilledTail(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkSpilledTail, .{});
}
