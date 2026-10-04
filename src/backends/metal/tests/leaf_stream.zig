const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const native = @import("../runtime.zig");
const M31 = core.fields.m31.M31;
const b2 = core.vcs_lifted.blake2_merkle;
const a = std.testing.allocator;

fn makeColumns(allocator: std.mem.Allocator, count: usize, base_log: u32) ![][]M31 {
    const columns = try allocator.alloc([]M31, count);
    var made: usize = 0;
    errdefer {
        for (columns[0..made]) |column| allocator.free(column);
        allocator.free(columns);
    }
    for (columns, 0..) |*column, index| {
        column.* = try allocator.alloc(M31, @as(usize, 1) << @intCast(base_log + index / 16));
        made += 1;
        for (column.*, 0..) |*value, row| value.* = M31.fromCanonical(@intCast((index * 7919 + row * 513 + 0x7fffff00) % 0x7fffffff));
    }
    return columns;
}

fn freeColumns(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

test "metal: streaming BLAKE2s planned terminal flags preserve all carry boundaries" {
    const shared = @import("../shared_runtime.zig");
    try shared.initialize(a, .source_jit);
    defer shared.shutdown() catch @panic("planned compact commit leaked runtime custody");
    const H = b2.Blake2sPlainMerkleHasher;
    const Tree = prover.vcs_lifted.prover.MerkleProverLifted(H);
    const Committer = @import("../runtime/compact_streaming_committer.zig").Committer(H);
    for ([_]usize{ 0, 1, 15, 16, 17, 31, 32, 33, 49 }) |count| {
        const columns = try makeColumns(a, count, 4);
        defer freeColumns(a, columns);
        const values = try a.alloc([]const M31, count);
        defer a.free(values);
        const refs = try a.alloc(Tree.ColumnRef, count);
        defer a.free(refs);
        for (columns, values, refs, 0..) |column, *value, *ref, i| {
            value.* = column;
            ref.* = .{ .log_size = @intCast(std.math.log2_int(usize, column.len)), .values = column, .original_index = i };
        }
        var expected = try Tree.commit(a, values);
        defer expected.deinit(a);
        for ([_]usize{ 1, 3, 16, 64 }) |batch| {
            var committer = Committer.init(a);
            var owns_committer = true;
            defer if (owns_committer) committer.deinit();
            try committer.planColumnCount(count);
            var next: usize = 0;
            while (next < count) {
                const end = @min(count, next + batch);
                try committer.addColumns(refs[next..end]);
                next = end;
            }
            if (count == 17 and batch == 1)
                try std.testing.expectEqual(@as(u64, 16), committer.stream.?.aliases);
            if (count != 0 and batch >= 16 and count % 16 == 0)
                try std.testing.expectEqual(@as(usize, 0), committer.pending_count);
            var actual = try committer.finalize();
            owns_committer = false;
            defer actual.deinit(a);
            try std.testing.expectEqualDeep(expected.root(), actual.root());
        }
        if (count != 0) {
            var incomplete = Committer.init(a);
            defer incomplete.deinit();
            try incomplete.planColumnCount(count);
            try std.testing.expectError(error.IncompleteIncrementalCommitmentPlan, incomplete.finalize());
            var excess = Committer.init(a);
            defer excess.deinit();
            try excess.planColumnCount(count - 1);
            try std.testing.expectError(error.InvalidIncrementalCommitmentPlan, excess.addColumns(refs));
        }
    }
}

test "metal: streaming BLAKE2s planned batches retire borrowed page owners without carry copies" {
    const shared = @import("../shared_runtime.zig");
    try shared.initialize(a, .source_jit);
    defer shared.shutdown() catch @panic("planned compact commit leaked runtime custody");
    const H = b2.Blake2sPlainMerkleHasher;
    const Tree = prover.vcs_lifted.prover.MerkleProverLifted(H);
    const count = 33;
    const alignment = comptime std.mem.Alignment.fromByteUnits(std.heap.page_size_max);
    var owners: [count][]align(std.heap.page_size_max) M31 = undefined;
    var refs: [count]Tree.ColumnRef = undefined;
    var values: [count][]const M31 = undefined;
    var made: usize = 0;
    defer for (owners[0..made]) |owner| a.free(owner);
    for (&owners, &refs, &values, 0..) |*owner, *ref, *value, i| {
        owner.* = try a.alignedAlloc(M31, alignment, 4096);
        made += 1;
        for (owner.*, 0..) |*word, row| word.* = M31.fromCanonical(@intCast(row * 61 + i * 17));
        value.* = owner.*;
        ref.* = .{ .log_size = 12, .values = owner.*, .original_index = i };
    }
    var expected = try Tree.commit(a, &values);
    defer expected.deinit(a);
    var committer = @import("../runtime/compact_streaming_committer.zig").Committer(H).init(a);
    var owned = true;
    defer if (owned) committer.deinit();
    try committer.planColumnCount(count);
    var next: usize = 0;
    while (next < count) {
        const end = @min(count, next + 16);
        var backing: [16][]M31 = undefined;
        for (owners[next..end], backing[0 .. end - next]) |owner, *view| view.* = owner;
        try committer.addColumnsWithBacking(refs[next..end], backing[0 .. end - next]);
        try std.testing.expectEqual(@as(usize, 0), committer.pending_count);
        for (owners[next..end]) |*owner| {
            a.free(owner.*);
            owner.* = &.{};
        }
        next = end;
    }
    try std.testing.expectEqual(@as(u64, count), committer.stream.?.aliases);
    try std.testing.expectEqual(@as(u64, 0), committer.stream.?.uploads);
    var actual = try committer.finalize();
    owned = false;
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected.root(), actual.root());
}

fn feed(comptime H: type, stream: *native.Blake2LeafStream(H), columns: []const []const M31) !void {
    var start: usize = 0;
    while (start < columns.len) {
        const end = @min(columns.len, start + 16);
        try stream.pushBlock(columns[start..end], end == columns.len, &.{});
        start = end;
    }
}

test "metal: streaming BLAKE2s covers terminal blocks and native-height lifting in both domains" {
    var runtime = try native.Runtime.init();
    defer runtime.deinit();
    inline for (.{ b2.Blake2sPlainMerkleHasher, b2.Blake2sMerkleHasher }) |H| {
        for ([_]usize{ 1, 15, 16, 17, 31, 32, 33, 49 }) |count| {
            const columns = try makeColumns(a, count, 4);
            defer freeColumns(a, columns);
            const refs = try a.alloc([]const M31, count);
            defer a.free(refs);
            for (columns, refs) |column, *ref| ref.* = column;
            var expected = try prover.vcs_lifted.prover.MerkleProverLifted(H).commit(a, refs);
            defer expected.deinit(a);
            var stream = try native.Blake2LeafStream(H).init(a, &runtime);
            defer stream.deinit();
            try feed(H, &stream, refs);
            try std.testing.expectEqual(@as(usize, 32) << @intCast(stream.log_size), stream.reservation.bytes);
            var actual = try stream.finish(0);
            defer actual.deinit(a);
            try std.testing.expectEqualDeep(expected.root(), actual.root());
            for (expected.layers, actual.layers) |want, got| try std.testing.expectEqualSlices(H.Hash, want, got);
            try std.testing.expectEqual(@as(usize, 0), stream.reservation.bytes);
        }
    }
}

test "metal: streaming BLAKE2s retires page-backed sources after each real GPU block" {
    const H = b2.Blake2sPlainMerkleHasher;
    const count = 49;
    var runtime = try native.Runtime.init();
    defer runtime.deinit();
    var columns: [count][]const M31 = undefined;
    const alignment = comptime std.mem.Alignment.fromByteUnits(std.heap.page_size_max);
    var owners: [count][]align(std.heap.page_size_max) M31 = undefined;
    var initialized: usize = 0;
    defer for (owners[0..initialized]) |owner| a.free(owner);
    for (&owners, &columns, 0..) |*owner, *column, index| {
        const rows = @as(usize, 1) << @intCast(14 + index / 16);
        // Header/footer guards exercise subcolumn offsets inside live owners.
        const padded = std.mem.alignForward(usize, (rows + 2) * @sizeOf(M31), std.heap.page_size_max) / @sizeOf(M31);
        owner.* = try a.alignedAlloc(M31, alignment, padded);
        initialized += 1;
        @memset(owner.*, M31.fromCanonical(101));
        const values = owner.*[1..][0..rows];
        for (values, 0..) |*value, row| value.* = M31.fromCanonical(@intCast((row * 3511 + index * 101) % 0x7fffffff));
        column.* = values;
    }
    var expected = try prover.vcs_lifted.prover.MerkleProverLifted(H).commit(a, &columns);
    defer expected.deinit(a);
    var stream = try native.Blake2LeafStream(H).init(a, &runtime);
    defer stream.deinit();
    var start: usize = 0;
    while (start < count) {
        const end = @min(count, start + 16);
        var backings: [16][]const M31 = undefined;
        for (owners[start..end], backings[0 .. end - start]) |owner, *backing| backing.* = owner;
        try stream.pushBlock(columns[start..end], end == count, backings[0 .. end - start]);
        for (owners[start..end]) |*owner| {
            try std.testing.expectEqual(@as(u32, 101), owner.*[0].v);
            a.free(owner.*);
            owner.* = &.{};
        }
        start = end;
    }
    try std.testing.expectEqual(@as(u64, count), stream.aliases);
    try std.testing.expectEqual(@as(u64, 0), stream.uploads);
    var actual = try stream.finish(4);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected.root(), actual.root());
    for (actual.layers, 0..) |layer, log| {
        if (log <= stream.log_size - 4) try std.testing.expectEqualSlices(H.Hash, expected.layers[log], layer) else try std.testing.expectEqual(@as(usize, 0), layer.len);
    }
}

test "metal: streaming BLAKE2s reads multiple columns from one page backing" {
    const H = b2.Blake2sPlainMerkleHasher;
    const rows: usize = 1 << 12;
    const alignment = comptime std.mem.Alignment.fromByteUnits(std.heap.page_size_max);
    const owner = try a.alignedAlloc(M31, alignment, rows * 2);
    defer a.free(owner);
    for (owner, 0..) |*value, index|
        value.* = M31.fromCanonical(@intCast((index * 17 + 3) % 0x7fffffff));
    const columns = [_][]const M31{ owner[0..rows], owner[rows .. rows * 2] };
    var expected = try prover.vcs_lifted.prover.MerkleProverLifted(H).commit(a, &columns);
    defer expected.deinit(a);
    var runtime = try native.Runtime.init();
    defer runtime.deinit();
    var stream = try native.Blake2LeafStream(H).init(a, &runtime);
    defer stream.deinit();
    try stream.pushBlock(&columns, true, &.{owner});
    try std.testing.expectEqual(@as(u64, 2), stream.aliases);
    try std.testing.expectEqual(@as(u64, 0), stream.uploads);
    var actual = try stream.finish(0);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected.root(), actual.root());
    for (expected.layers, actual.layers) |want, got|
        try std.testing.expectEqualSlices(H.Hash, want, got);
}

fn allocationCase(allocator: std.mem.Allocator, runtime: *native.Runtime, columns: []const []const M31) !void {
    const H = b2.Blake2sPlainMerkleHasher;
    var stream = try native.Blake2LeafStream(H).init(allocator, runtime);
    defer stream.deinit();
    try feed(H, &stream, columns);
    var tree = try stream.finish(0);
    defer tree.deinit(allocator);
}

test "metal: streaming BLAKE2s closes every host allocation failure during adoption and publication" {
    var runtime = try native.Runtime.init();
    defer runtime.deinit();
    const columns = try makeColumns(a, 17, 4);
    defer freeColumns(a, columns);
    const refs = try a.alloc([]const M31, columns.len);
    defer a.free(refs);
    for (columns, refs) |column, *ref| ref.* = column;
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{ &runtime, refs });
}

test "metal: streaming BLAKE2s admits native allocations before use and returns the exact live budget" {
    const H = b2.Blake2sPlainMerkleHasher;
    var runtime = try native.Runtime.init();
    defer runtime.deinit();
    const columns = try makeColumns(a, 16, 4);
    defer freeColumns(a, columns);
    const refs = try a.alloc([]const M31, columns.len);
    defer a.free(refs);
    for (columns, refs) |column, *ref| ref.* = column;
    for ([_]usize{ 600, 4096 }) |limit| {
        const budget = try prover.host_budget_allocator.SharedHostBudget.create(a, limit);
        defer budget.destroy();
        {
            var stream = try native.Blake2LeafStream(H).init(budget.allocator(), &runtime);
            defer stream.deinit();
            if (limit == 600) {
                try std.testing.expectError(error.OutOfMemory, stream.pushBlock(refs, true, &.{}));
                try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
            } else {
                try stream.pushBlock(refs, true, &.{});
                try std.testing.expectEqual(@as(usize, 512), budget.snapshot().external_live_bytes);
                var tree = try stream.finish(0);
                defer tree.deinit(budget.allocator());
                try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
            }
        }
        try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
        try std.testing.expect(budget.snapshot().peak_live_bytes <= limit);
    }
}

test "metal: streaming BLAKE2s refuses malformed geometry without consuming good prefix state" {
    const H = b2.Blake2sPlainMerkleHasher;
    var runtime = try native.Runtime.init();
    defer runtime.deinit();
    const columns = try makeColumns(a, 17, 4);
    defer freeColumns(a, columns);
    var refs: [17][]const M31 = undefined;
    for (columns, &refs) |column, *ref| ref.* = column;
    var stream = try native.Blake2LeafStream(H).init(a, &runtime);
    defer stream.deinit();
    try std.testing.expectError(error.InvalidColumns, stream.pushBlock(refs[0..15], false, &.{}));
    try std.testing.expectError(error.InvalidColumns, stream.pushBlock(refs[0..17], true, &.{}));
    try std.testing.expectError(error.InvalidColumns, stream.pushBlock(refs[0..16], false, refs[16..]));
    try stream.pushBlock(refs[0..16], false, &.{});
    var invalid = refs[16..][0..1].*;
    invalid[0] = refs[0][0..8];
    try std.testing.expectError(error.InvalidColumns, stream.pushBlock(&invalid, true, &.{}));
    try std.testing.expectEqual(@as(u32, 16), stream.columns);
    try stream.pushBlock(refs[16..], true, &.{});
    try std.testing.expectError(error.NativeLeafStreamClosed, stream.pushBlock(refs[0..1], true, &.{}));
    try std.testing.expectError(error.NativeLeafStreamClosed, stream.finish(stream.log_size + 1));
    var tree = try stream.finish(0);
    defer tree.deinit(a);
    try std.testing.expectError(error.NativeLeafStreamClosed, stream.finish(0));
}

test "metal: streaming BLAKE2s PCS adapter handles arbitrary retired batches and runtime custody" {
    const shared = @import("../shared_runtime.zig");
    const H = b2.Blake2sPlainMerkleHasher;
    const Tree = prover.vcs_lifted.prover.MerkleProverLifted(H);
    const Committer = @import("../runtime/compact_streaming_committer.zig").Committer(H);
    try shared.initialize(a, .source_jit);
    defer shared.shutdown() catch @panic("streaming adapter leaked runtime custody");
    for ([_]usize{ 1, 7, 16, 17, 64 }) |batch_size| {
        const columns = try makeColumns(a, 49, 4);
        defer freeColumns(a, columns);
        var refs: [49][]const M31 = undefined;
        for (columns, &refs) |column, *ref| ref.* = column;
        var expected = try Tree.commit(a, &refs);
        defer expected.deinit(a);
        var committer = Committer.init(a);
        var owns_committer = true;
        defer if (owns_committer) committer.deinit();
        var next: usize = 0;
        while (next < columns.len) {
            const end = @min(columns.len, next + batch_size);
            const batch = try a.alloc(Tree.ColumnRef, end - next);
            defer a.free(batch);
            var made: usize = 0;
            defer for (batch[0..made]) |reference| a.free(reference.values);
            for (columns[next..end], batch, next..) |column, *reference, index| {
                reference.* = .{ .log_size = @intCast(std.math.log2_int(usize, column.len)), .values = try a.dupe(M31, column), .original_index = index };
                made += 1;
            }
            try committer.addColumns(batch);
            try std.testing.expect(committer.pending_count <= 16);
            try std.testing.expectEqual(@as(u64, 1), shared.lifecycleSnapshot().live_resident_resources);
            try std.testing.expectError(error.ResidentResourcesLive, shared.shutdown());
            next = end;
        }
        var actual = try committer.finalize();
        owns_committer = false;
        defer actual.deinit(a);
        try std.testing.expectEqualDeep(expected.root(), actual.root());
        for (expected.layers, actual.layers) |want, got| try std.testing.expectEqualSlices(H.Hash, want, got);
        try std.testing.expectEqual(@as(u64, 0), shared.lifecycleSnapshot().live_resident_resources);
    }
}

test "metal: streaming BLAKE2s compact PCS matches transcript and coefficient query openings" {
    const shared = @import("../shared_runtime.zig");
    const Metal = @import("../commit_backend.zig").MetalCommitBackend;
    const H = b2.Blake2sPlainMerkleHasher;
    const Cpu = struct {
        pub fn MerkleTree(comptime F: type) type {
            return prover.vcs_lifted.prover.MerkleProverLifted(F);
        }
        pub fn commitMerkle(comptime F: type, allocator: std.mem.Allocator, columns: []const []const M31) !MerkleTree(F) {
            return MerkleTree(F).commit(allocator, columns);
        }
    };
    try shared.initialize(a, .source_jit);
    defer shared.shutdown() catch @panic("compact PCS leaked runtime custody");
    const HostScheme = prover.pcs.CommitmentSchemeProver(Cpu, H, b2.Blake2sMerkleChannel);
    const NativeScheme = prover.pcs.CommitmentSchemeProver(Metal, H, b2.Blake2sMerkleChannel);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var baseline = try HostScheme.init(a, config);
    defer baseline.deinit(a);
    var compact = try NativeScheme.init(a, config);
    defer compact.deinit(a);
    compact.setCompactPolynomialStorage(4);
    const values = try makeColumns(a, 49, 4);
    defer freeColumns(a, values);
    var columns: [49]prover.pcs.ColumnEvaluation = undefined;
    // Unsorted PCS positions ensure hashing order and query order both survive.
    for (&columns, 0..) |*column, index| {
        const value = values[48 - index];
        column.* = .{ .log_size = @intCast(std.math.log2_int(usize, value.len)), .values = value };
    }
    var host_channel = core.channel.blake2s.Blake2sChannel{};
    var metal_channel = host_channel;
    try baseline.commitBorrowedStreamingWithRecorder(a, &columns, 7, null, &host_channel);
    try compact.commitBorrowedStreamingWithRecorder(a, &columns, 7, null, &metal_channel);
    try std.testing.expectEqualSlices(u8, &host_channel.digestBytes(), &metal_channel.digestBytes());
    try std.testing.expect(compact.trees.items[0].compact_polynomials);
    for (compact.trees.items[0].columns) |column| {
        try std.testing.expectEqual(@as(usize, 0), column.values.len);
        try std.testing.expect(column.coefficient_values != null);
    }
    const queries = [_]usize{ 0, 7, 17, 61, 128, 255 };
    var expected = try baseline.trees.items[0].decommit(a, &queries);
    defer expected.deinit(a);
    var actual = try compact.trees.items[0].decommit(a, &queries);
    defer actual.deinit(a);
    try std.testing.expectEqualDeep(expected, actual);

    // Exercise normal auto-dispatch and one arena borrowed across all batches,
    // then transferred once. Ordinary Metal's monolithic preference must not
    // override the explicit compact policy.
    var words: usize = 0;
    for (columns) |column| words += column.values.len;
    const arena_inputs = blk: {
        const owned_columns = try a.alloc(prover.pcs.ColumnEvaluation, columns.len);
        errdefer a.free(owned_columns);
        const arena = try a.alloc(M31, words);
        errdefer a.free(arena);
        const backings = try a.alloc([]M31, 1);
        backings[0] = arena;
        break :blk .{ .columns = owned_columns, .arena = arena, .backings = backings };
    };
    const owned_columns = arena_inputs.columns;
    const arena = arena_inputs.arena;
    const backings = arena_inputs.backings;
    var offset: usize = 0;
    for (columns, owned_columns) |source, *destination| {
        const values_out = arena[offset..][0..source.values.len];
        @memcpy(values_out, source.values);
        destination.* = .{ .log_size = source.log_size, .values = values_out };
        offset += source.values.len;
    }
    // Input ownership passes to the commit API, including all failure paths.
    try compact.commitOwnedWithRecorderAndBacking(a, owned_columns, backings, null, &metal_channel);
    try baseline.commitBorrowedStreamingWithRecorder(a, &columns, 7, null, &host_channel);
    try std.testing.expectEqualSlices(u8, &host_channel.digestBytes(), &metal_channel.digestBytes());
    compact.trees.items[1].releaseCoefficients(a);
    var arena_opening = try compact.trees.items[1].decommit(a, &queries);
    defer arena_opening.deinit(a);
    try std.testing.expectEqualDeep(expected, arena_opening);
    const poly = prover.poly.circle;
    var coefficients: [3]poly.CircleCoefficients = undefined;
    var made: usize = 0;
    defer for (coefficients[0..made]) |*coefficient| coefficient.deinit(a);
    for (&coefficients, 0..) |*coefficient, index| {
        const words_poly = try a.alloc(M31, @as(usize, 1) << @intCast(4 + index));
        for (words_poly, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(row * row + index * 137));
        coefficient.* = try poly.CircleCoefficients.initOwned(words_poly);
        made += 1;
    }
    try compact.commitPolys(a, &coefficients, &metal_channel);
    try baseline.commitPolys(a, &coefficients, &host_channel);
    try std.testing.expectEqualSlices(u8, &host_channel.digestBytes(), &metal_channel.digestBytes());
    const coeff_queries = [_]usize{ 0, 3, 19, 65, 127 };
    var expected_polys = try baseline.trees.items[2].decommit(a, &coeff_queries);
    defer expected_polys.deinit(a);
    var actual_polys = try compact.trees.items[2].decommit(a, &coeff_queries);
    defer actual_polys.deinit(a);
    try std.testing.expectEqualDeep(expected_polys, actual_polys);
}

test "metal: streaming BLAKE2s compact FRI inputs preserve mixed native domains and OODS batches" {
    const shared = @import("../shared_runtime.zig");
    const Metal = @import("../commit_backend.zig").MetalCommitBackend;
    const quotient = prover.pcs.quotient_ops;
    const QM31 = core.fields.qm31.QM31;
    const Point = core.circle.CirclePointQM31;
    const TreeVec = core.pcs.utils.TreeVec;
    const poly = prover.poly.circle;
    try shared.initialize(a, .source_jit);
    defer shared.shutdown() catch @panic("compact FRI leaked runtime custody");
    var polynomials: [6]poly.CircleCoefficients = undefined;
    var evaluations: [6]poly.CircleEvaluation = undefined;
    var made: usize = 0;
    defer for (polynomials[0..made], evaluations[0..made]) |*polynomial, *evaluation| {
        polynomial.deinit(a);
        a.free(evaluation.values);
    };
    var ordinary: [6]quotient.ColumnEvaluation = undefined;
    var compact: [6]quotient.ColumnEvaluation = undefined;
    for (&ordinary, &compact, &polynomials, &evaluations, 0..) |*original, *column, *polynomial, *evaluation, index| {
        const log: u32 = @intCast(4 + index % 3);
        const coefficients = try a.alloc(M31, @as(usize, 1) << @intCast(log - 1));
        for (coefficients, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(row * row * 31 + index * 73 + 5));
        polynomial.* = try poly.CircleCoefficients.initOwned(coefficients);
        evaluation.* = polynomial.evaluate(a, poly.CanonicCoset.new(log).circleDomain()) catch |err| {
            polynomial.deinit(a);
            return err;
        };
        made += 1;
        original.* = .{ .log_size = log, .values = evaluation.values };
        column.* = if (index % 2 == 0) .{ .log_size = log, .values = &.{}, .coefficient_values = coefficients } else original.*;
    }
    var points = [_]Point{ core.circle.SECURE_FIELD_CIRCLE_GEN.mul(7), core.circle.SECURE_FIELD_CIRCLE_GEN.mul(19) };
    var samples = [_]QM31{ QM31.fromU32Unchecked(3, 5, 7, 11), QM31.fromU32Unchecked(13, 17, 19, 23) };
    var point_columns: [6][]Point = undefined;
    var sample_columns: [6][]QM31 = undefined;
    for (&point_columns, &sample_columns, 0..) |*p, *s, index| {
        const n = index % 3;
        p.* = points[0..n];
        s.* = samples[0..n];
    }
    var ordinary_trees = [_][]const quotient.ColumnEvaluation{ ordinary[0..2], ordinary[2..] };
    var compact_trees = [_][]const quotient.ColumnEvaluation{ compact[0..2], compact[2..] };
    var point_trees = [_][][]Point{ point_columns[0..2], point_columns[2..] };
    var sample_trees = [_][][]QM31{ sample_columns[0..2], sample_columns[2..] };
    const ot = TreeVec([]const quotient.ColumnEvaluation).initOwned(&ordinary_trees);
    const ct = TreeVec([]const quotient.ColumnEvaluation).initOwned(&compact_trees);
    const pt = TreeVec([][]Point).initOwned(&point_trees);
    const st = TreeVec([][]QM31).initOwned(&sample_trees);
    const alpha = QM31.fromU32Unchecked(29, 31, 37, 41);
    // Log 13 exercises native-height segmentation in the production dispatcher.
    var expected = try quotient.computeFriQuotients(a, ot, pt, st, alpha, 13, 1);
    defer expected.deinit(a);
    var provider = try quotient.LazyQuotientProvider.initForBackend(Metal, a, ct, pt, st, alpha, 13);
    defer provider.deinit(a);
    try std.testing.expectEqual(quotient.InputMode.raw_backend, provider.input_mode);
    for (provider.prepared.contribution_plan.active_column_indices) |index| try std.testing.expect(provider.raw_columns[index].coefficient_values == null);
    var actual = try prover.secure_column.SecureColumnByCoords.zeros(a, 1 << 13);
    defer actual.deinit(a);
    var lease = try shared.acquire();
    defer lease.deinit();
    _ = try lease.runtime.computeQuotients(a, &provider, &actual);
    for (expected.columns, actual.columns) |want, got| try std.testing.expectEqualSlices(M31, want, got);
    // All sampled columns may fold to zero. Retain the sample denominators
    // while publishing no source planes; this must remain a native dispatch.
    for (&compact, polynomials) |*column, polynomial| {
        @memset(@constCast(polynomial.coefficients()), M31.zero());
        column.* = .{ .log_size = column.log_size, .values = &.{}, .coefficient_values = polynomial.coefficients() };
    }
    @memset(&samples, QM31.zero());
    var zero_provider = try quotient.LazyQuotientProvider.initForBackend(Metal, a, ct, pt, st, alpha, 13);
    defer zero_provider.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), zero_provider.prepared.contribution_plan.active_column_indices.len);
    _ = try lease.runtime.computeQuotients(a, &zero_provider, &actual);
    for (actual.columns) |coordinate| for (coordinate) |value| try std.testing.expect(value.isZero());
}

fn compactArenaFailureCase(allocator: std.mem.Allocator) !void {
    const Metal = @import("../commit_backend.zig").MetalCommitBackend;
    const Scheme = prover.pcs.CommitmentSchemeProver(Metal, b2.Blake2sPlainMerkleHasher, b2.Blake2sMerkleChannel);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var scheme = try Scheme.init(allocator, config);
    defer scheme.deinit(allocator);
    scheme.setCompactPolynomialStorage(4);
    const columns = try allocator.alloc(prover.pcs.ColumnEvaluation, 3);
    var input_live = true;
    defer if (input_live) allocator.free(columns);
    const arena = try allocator.alloc(M31, 48);
    defer if (input_live) allocator.free(arena);
    const backings = try allocator.alloc([]M31, 1);
    defer if (input_live) allocator.free(backings);
    backings[0] = arena;
    for (columns, 0..) |*column, index| {
        const values = arena[index * 16 ..][0..16];
        for (values, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(row * row + index * 71));
        column.* = .{ .log_size = 4, .values = values };
    }
    var channel = core.channel.blake2s.Blake2sChannel{};
    input_live = false;
    try scheme.commitOwnedWithRecorderAndBacking(allocator, columns, backings, null, &channel);
    scheme.trees.items[0].releaseCoefficients(allocator);
    var opening = try scheme.trees.items[0].decommit(allocator, &.{ 0, 3, 31 });
    defer opening.deinit(allocator);
    var coefficient_values: [16]M31 = undefined;
    for (&coefficient_values, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(row * row + 3));
    const polynomial = try prover.poly.circle.CircleCoefficients.initBorrowed(&coefficient_values);
    try scheme.commitPolys(allocator, &.{polynomial}, &channel);
    var coefficient_opening = try scheme.trees.items[1].decommit(allocator, &.{ 0, 3, 31 });
    defer coefficient_opening.deinit(allocator);
}

test "metal: streaming BLAKE2s compact arena allocation failures retain one cleanup owner" {
    const shared = @import("../shared_runtime.zig");
    try shared.initialize(a, .source_jit);
    defer shared.shutdown() catch @panic("compact arena allocation failure leaked runtime custody");
    try std.testing.checkAllAllocationFailures(a, compactArenaFailureCase, .{});
    try std.testing.expectEqual(@as(u64, 0), shared.lifecycleSnapshot().live_resident_resources);
}
