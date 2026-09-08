//! Retained LDE storage must preserve complete PCS proofs and allocator custody.
const std = @import("std");
const core = @import("stwo_core");
const tree_mod = @import("commitment_tree.zig");
const M31 = core.fields.m31.M31;
const Column = tree_mod.ColumnEvaluation;
const blake = core.vcs_lifted.blake2_merkle;
const H = blake.Blake2sMerkleHasher;
const MC = blake.Blake2sMerkleChannel;
const Channel = core.channel.blake2s.Blake2sChannel;
const Backend = struct {
    pub const combined_commit_min_columns: usize = 65;
    pub const combined_commit_max_columns: usize = 256;
    pub const interpolateAndEvaluateCircleBuffers = @import("owned_source_admission_test.zig").Backend.interpolateAndEvaluateCircleBuffers;
    pub fn MerkleTree(comptime Hasher: type) type {
        return @import("../vcs_lifted/prover.zig").MerkleProverLifted(Hasher);
    }
    pub fn commitMerkle(comptime Hasher: type, allocator: std.mem.Allocator, columns: []const []const M31) !MerkleTree(Hasher) {
        return MerkleTree(Hasher).commit(allocator, columns);
    }
};
const Scheme = @import("scheme.zig").CommitmentSchemeProver(Backend, H, MC);
const config: core.pcs.PcsConfig = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 } };
const logs = [_]u32{ 3, 4, 3, 5, 4, 3 };
const Points = core.pcs.TreeVec([][]core.circle.CirclePointQM31);

fn makeColumns(allocator: std.mem.Allocator) ![]Column {
    const result = try allocator.alloc(Column, logs.len);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column.values);
        allocator.free(result);
    }
    for (logs, result, 0..) |log, *column, index| {
        column.* = .{ .log_size = log, .values = try allocator.alloc(M31, @as(usize, 1) << @intCast(log)) };
        initialized += 1;
        for (@constCast(column.values), 0..) |*word, row| word.* = M31.fromCanonical(@intCast(1 + row * row + 73 * index));
    }
    return result;
}

fn points(allocator: std.mem.Allocator) !Points {
    const result = try allocator.alloc([][]core.circle.CirclePointQM31, 2);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |row| {
            for (row) |entry| allocator.free(entry);
            allocator.free(row);
        }
        allocator.free(result);
    }
    for ([_]usize{ logs.len, 1 }, result) |count, *row| {
        row.* = try allocator.alloc([]core.circle.CirclePointQM31, count);
        var filled: usize = 0;
        errdefer {
            for (row.*[0..filled]) |entry| allocator.free(entry);
            allocator.free(row.*);
        }
        for (row.*) |*entry| {
            entry.* = try allocator.dupe(core.circle.CirclePointQM31, &.{core.circle.SECURE_FIELD_CIRCLE_GEN.mul(17)});
            filled += 1;
        }
        initialized += 1;
    }
    return .{ .items = result };
}

fn prove(allocator: std.mem.Allocator, retained: ?std.mem.Allocator) !core.pcs.ExtendedCommitmentSchemeProof(H) {
    return proveSource(allocator, retained, .owned);
}

fn proveSource(allocator: std.mem.Allocator, retained: ?std.mem.Allocator, source: enum { owned, backed, borrowed }) !core.pcs.ExtendedCommitmentSchemeProof(H) {
    var scheme = try Scheme.init(allocator, config);
    var owned = true;
    defer if (owned) scheme.deinit(allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    scheme.setRetainedColumnAllocator(retained);
    var channel = Channel{};
    const input = try makeColumns(allocator);
    if (source == .backed) {
        const backing = @import("backed_columns.zig").packOwnedByLog(allocator, input, .fromByteUnits(64)) catch |err| {
            tree_mod.freeRetainedColumns(allocator, allocator, input);
            return err;
        };
        try scheme.commitOwnedWithRecorderAndBacking(allocator, input, backing, null, &channel);
    } else if (source == .borrowed) {
        defer tree_mod.freeRetainedColumns(allocator, allocator, input);
        try scheme.commit(allocator, input, &channel);
        // The caller can still read and independently destroy every source.
        for (input, 0..) |column, index| {
            try std.testing.expectEqual(logs[index], column.log_size);
            for (column.values, 0..) |word, row|
                try std.testing.expectEqual(M31.fromCanonical(@intCast(1 + row * row + 73 * index)), word);
        }
    } else {
        // Exercise the streaming producer in both modes; small batches keep the
        // fixture sensitive to partial moves and mixed column ordering.
        try scheme.commitOwnedStreaming(allocator, input, 2, &channel);
    }
    const Poly = @import("../poly/circle/mod.zig").CircleCoefficients;
    var polynomial = try Poly.initOwned(try allocator.alloc(M31, 32));
    defer polynomial.deinit(allocator);
    for (@constCast(polynomial.coefficients()), 0..) |*word, i| word.* = M31.fromCanonical(@intCast(i + 1));
    try scheme.commitPolys(allocator, &.{polynomial}, &channel);
    for (scheme.trees.items) |tree| {
        try std.testing.expect((tree.retained_column_allocator != null) == (retained != null));
        try std.testing.expect(tree.coefficients == null);
    }
    const sample_points = try points(allocator);
    owned = false;
    return scheme.proveValues(allocator, sample_points, &channel);
}

fn verify(allocator: std.mem.Allocator, extended: core.pcs.ExtendedCommitmentSchemeProof(H)) !void {
    var result = extended;
    defer result.aux.deinit(allocator);
    var owns_proof = true;
    defer if (owns_proof) result.proof.deinit(allocator);
    const proof = result.proof;
    const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, MC);
    var verifier = try Verifier.init(allocator, config);
    defer verifier.deinit(allocator);
    var channel = Channel{};
    try verifier.commit(allocator, proof.commitments.items[0], &logs, &channel);
    try verifier.commit(allocator, proof.commitments.items[1], &.{5}, &channel);
    const sample_points = try points(allocator);
    // The verifier consumes both the proof and its independently built points.
    owns_proof = false;
    try verifier.verifyValues(allocator, sample_points, proof, &channel);
}

test "PCS retained column storage preserves complete proof and fresh verification" {
    const allocator = std.testing.allocator;
    var retained = std.testing.FailingAllocator.init(allocator, .{});
    var ordinary = try prove(allocator, null);
    var ordinary_owned = true;
    defer if (ordinary_owned) ordinary.deinit(allocator);
    var relocated = try prove(allocator, retained.allocator());
    var relocated_owned = true;
    defer if (relocated_owned) relocated.deinit(allocator);
    // All producer trees are destroyed by proveValues before fresh admission.
    try std.testing.expectEqual(@as(usize, 960), retained.allocated_bytes);
    try std.testing.expectEqual(retained.allocated_bytes, retained.freed_bytes);
    try std.testing.expectEqualDeep(ordinary.proof, relocated.proof);
    ordinary_owned = false;
    try verify(allocator, ordinary);
    relocated_owned = false;
    try verify(allocator, relocated);
}

fn relocationAllocationCase(allocator: std.mem.Allocator) !void {
    var retained = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    defer std.debug.assert(retained.allocated_bytes == retained.freed_bytes);
    const moved = try tree_mod.relocateOwnedColumns(allocator, retained.allocator(), try makeColumns(allocator));
    tree_mod.freeRetainedColumns(allocator, retained.allocator(), moved);
}

test "PCS retained column storage cleans partial moves on allocation failure" {
    const allocator = std.testing.allocator;
    try std.testing.checkAllAllocationFailures(allocator, relocationAllocationCase, .{});
    // The public builder also consumes an input if its first metadata
    // allocation fails, before preparation or retained storage can begin.
    var primary = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 + logs.len });
    {
        var scheme = try Scheme.init(primary.allocator(), config);
        defer scheme.deinit(primary.allocator());
        scheme.setCoefficientRetentionPolicy(.never);
        scheme.setRetainedColumnAllocator(allocator);
        var builder = scheme.streamingTreeBuilder(primary.allocator(), 2);
        defer builder.deinit();
        try std.testing.expectError(error.OutOfMemory, builder.addColumnsOwned(try makeColumns(primary.allocator()), null));
    }
    try std.testing.expectEqual(primary.allocated_bytes, primary.freed_bytes);
    for (0..logs.len) |index| {
        var retained = std.testing.FailingAllocator.init(allocator, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, tree_mod.relocateOwnedColumns(allocator, retained.allocator(), try makeColumns(allocator)));
        try std.testing.expectEqual(retained.allocated_bytes, retained.freed_bytes);
    }
    // Failure after complete batches exercises the builder's own cleanup.
    for (0..logs.len + 1) |index| {
        var retained = std.testing.FailingAllocator.init(allocator, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, prove(allocator, retained.allocator()));
        try std.testing.expectEqual(retained.allocated_bytes, retained.freed_bytes);
    }
}

test "PCS retained column storage routes source entrypoints and rejects unsupported policies" {
    const allocator = std.testing.allocator;
    var retained = std.testing.FailingAllocator.init(allocator, .{});
    {
        var scheme = try Scheme.init(allocator, config);
        defer scheme.deinit(allocator);
        scheme.setRetainedColumnAllocator(retained.allocator());
        var channel = Channel{};
        try std.testing.expectError(error.UnsupportedRetainedColumnStorage, scheme.commitOwned(allocator, try makeColumns(allocator), &channel));
        try std.testing.expectEqual(@as(usize, 0), retained.allocated_bytes);
        scheme.setCoefficientRetentionPolicy(.never);
        try std.testing.expectError(error.UnsupportedRetainedColumnStorage, scheme.commitOwnedStreaming(allocator, try makeColumns(allocator), 65, &channel));
        try scheme.commitOwned(allocator, try makeColumns(allocator), &channel);
        const borrowed = try makeColumns(allocator);
        defer tree_mod.freeRetainedColumns(allocator, allocator, borrowed);
        try scheme.commit(allocator, borrowed, &channel);
        var builder = scheme.treeBuilder(allocator);
        defer builder.deinit();
        _ = try builder.extendColumns(borrowed);
        try builder.commit(&channel);
        try std.testing.expectEqual(@as(usize, 3), scheme.trees.items.len);
        for (scheme.trees.items) |tree| {
            try std.testing.expect(tree.retained_column_allocator != null);
            try std.testing.expectEqualDeep(scheme.trees.items[0].root(), tree.root());
        }
        // Existing trees retain their exact allocator when future policy changes.
        scheme.setRetainedColumnAllocator(null);
    }
    try std.testing.expectEqual(@as(usize, 3 * 704), retained.allocated_bytes);
    try std.testing.expectEqual(retained.allocated_bytes, retained.freed_bytes);
}

test "PCS retained column storage mapped proof survives producer destruction and fresh verification" {
    if (comptime @import("builtin").os.tag != .macos and @import("builtin").os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    var mapped = try @import("../file_backed_allocator.zig").FileBackedAllocator.init(path);
    defer mapped.deinit();
    var ordinary = try prove(allocator, null);
    var ordinary_owned = true;
    defer if (ordinary_owned) ordinary.deinit(allocator);
    var relocated = try prove(allocator, mapped.allocator());
    var relocated_owned = true;
    defer if (relocated_owned) relocated.deinit(allocator);
    try std.testing.expect(mapped.total_bytes.load(.monotonic) > 0);
    try std.testing.expectEqual(@as(usize, 0), mapped.live_bytes.load(.monotonic));
    try std.testing.expectEqualDeep(ordinary.proof, relocated.proof);
    ordinary_owned = false;
    try verify(allocator, ordinary);
    relocated_owned = false;
    try verify(allocator, relocated);
}

test "PCS retained column storage packed source preserves complete proof and fresh verification" {
    const allocator = std.testing.allocator;
    var retained = std.testing.FailingAllocator.init(allocator, .{});
    var ordinary = try prove(allocator, null);
    var ordinary_owned = true;
    defer if (ordinary_owned) ordinary.deinit(allocator);
    var packed_proof = try proveSource(allocator, retained.allocator(), .backed);
    var packed_owned = true;
    defer if (packed_owned) packed_proof.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 960), retained.allocated_bytes);
    try std.testing.expectEqual(retained.allocated_bytes, retained.freed_bytes);
    try std.testing.expectEqualDeep(ordinary.proof, packed_proof.proof);
    ordinary_owned = false;
    try verify(allocator, ordinary);
    packed_owned = false;
    try verify(allocator, packed_proof);
}

fn packedCommitAllocationCase(allocator: std.mem.Allocator) !void {
    var retained = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    defer std.debug.assert(retained.allocated_bytes == retained.freed_bytes);
    var scheme = try Scheme.init(allocator, config);
    defer scheme.deinit(allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    scheme.setRetainedColumnAllocator(retained.allocator());
    const input = try makeColumns(allocator);
    const backing = @import("backed_columns.zig").packOwnedByLog(allocator, input, .fromByteUnits(64)) catch |err| {
        tree_mod.freeRetainedColumns(allocator, allocator, input);
        return err;
    };
    var channel = Channel{};
    try scheme.commitOwnedWithRecorderAndBacking(allocator, input, backing, null, &channel);
}

test "PCS retained column storage packed source cleans every failed ownership transfer" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, packedCommitAllocationCase, .{});
    for (0..logs.len + 1) |index| {
        var retained = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = index });
        try std.testing.expectError(error.OutOfMemory, proveSource(std.testing.allocator, retained.allocator(), .backed));
        try std.testing.expectEqual(retained.allocated_bytes, retained.freed_bytes);
    }
}

test "PCS retained column storage borrowed source preserves proof and caller values" {
    const allocator = std.testing.allocator;
    var retained = std.testing.FailingAllocator.init(allocator, .{});
    var ordinary = try prove(allocator, null);
    var ordinary_owned = true;
    defer if (ordinary_owned) ordinary.deinit(allocator);
    var borrowed = try proveSource(allocator, retained.allocator(), .borrowed);
    var borrowed_owned = true;
    defer if (borrowed_owned) borrowed.deinit(allocator);
    try std.testing.expectEqualDeep(ordinary.proof, borrowed.proof);
    try std.testing.expectEqual(retained.allocated_bytes, retained.freed_bytes);
    ordinary_owned = false;
    try verify(allocator, ordinary);
    borrowed_owned = false;
    try verify(allocator, borrowed);
}

// Count source-sized allocations before the first retained LDE allocation.
// This distinguishes bounded detachment from cloning all129 source columns,
// without allocating a production-sized trace or depending on RSS sampling.
const SourceCopyProbe = struct {
    source_allocations: usize = 0,
    observed_source: ?*SourceCopyProbe = null,
    first_retained_source_count: ?usize = null,

    fn allocator(self: *SourceCopyProbe) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *SourceCopyProbe = @ptrCast(@alignCast(context));
        const result = std.testing.allocator.rawAlloc(len, alignment, ret_addr) orelse return null;
        if (len == 1024) self.source_allocations += 1;
        if (self.observed_source) |source| if (self.first_retained_source_count == null) {
            self.first_retained_source_count = source.source_allocations;
        };
        return result;
    }
    fn resize(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ret_addr: usize) bool {
        return std.testing.allocator.rawResize(memory, alignment, len, ret_addr);
    }
    fn remap(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ret_addr: usize) ?[*]u8 {
        return std.testing.allocator.rawRemap(memory, alignment, len, ret_addr);
    }
    fn free(_: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        std.testing.allocator.rawFree(memory, alignment, ret_addr);
    }
};

test "PCS retained column storage bounds shared and borrowed source detachment" {
    for ([_]bool{ false, true }) |borrowed| {
        var primary = SourceCopyProbe{};
        var retained = SourceCopyProbe{ .observed_source = &primary };
        const allocator = primary.allocator();
        var scheme = try Scheme.init(allocator, config);
        defer scheme.deinit(allocator);
        scheme.setCoefficientRetentionPolicy(.never);
        scheme.setRetainedColumnAllocator(retained.allocator());
        const columns = try allocator.alloc(Column, 129);
        var initialized: usize = 0;
        var input_live = true;
        defer if (input_live) {
            for (columns[0..initialized]) |column| allocator.free(column.values);
            allocator.free(columns);
        };
        for (columns, 0..) |*column, index| {
            column.* = .{ .log_size = 8, .values = try allocator.alloc(M31, 256) };
            initialized += 1;
            for (@constCast(column.values), 0..) |*word, row| word.* = M31.fromCanonical(@intCast(1 + row * row + 73 * index));
        }
        var channel = Channel{};
        if (borrowed) {
            primary.source_allocations = 0;
            try scheme.commit(allocator, columns, &channel);
            for (columns, 0..) |column, index| {
                for (column.values, 0..) |word, row|
                    try std.testing.expectEqual(M31.fromCanonical(@intCast(1 + row * row + 73 * index)), word);
            }
        } else {
            const backing = try @import("backed_columns.zig").packOwnedByLog(allocator, columns, .fromByteUnits(64));
            input_live = false;
            primary.source_allocations = 0;
            try scheme.commitOwnedWithRecorderAndBacking(allocator, columns, backing, null, &channel);
        }
        const source_count = retained.first_retained_source_count orelse return error.MissingRetainedColumnAllocation;
        try std.testing.expect(source_count > 0);
        try std.testing.expect(source_count < 129);
    }
}

test "PCS retained column storage keeps quotient allocator selection explicit in borrowed traces" {
    const allocator = std.testing.allocator;
    var values = std.testing.FailingAllocator.init(allocator, .{});
    var scheme = try Scheme.init(allocator, config);
    defer scheme.deinit(allocator);
    var channel = Channel{};
    try scheme.commitOwned(allocator, try makeColumns(allocator), &channel);
    try @import("mod.zig").flushPendingCommit(MC, &scheme, allocator, &channel);
    {
        var trace = try scheme.trace(allocator);
        defer trace.polys.deinitDeep(allocator);
        try std.testing.expect(trace.quotient_values_allocator == null);
    }
    // Retained LDE policy alone does not silently change quotient allocation.
    scheme.setRetainedColumnAllocator(values.allocator());
    {
        var trace = try scheme.trace(allocator);
        defer trace.polys.deinitDeep(allocator);
        try std.testing.expect(trace.quotient_values_allocator == null);
    }
    scheme.setQuotientValuesAllocator(values.allocator());
    {
        var trace = try scheme.trace(allocator);
        defer trace.polys.deinitDeep(allocator);
        const selected = trace.quotient_values_allocator.?;
        try std.testing.expect(selected.ptr == values.allocator().ptr);
        try std.testing.expect(selected.vtable == values.allocator().vtable);
        try std.testing.expect(trace.polys.items[0][0].values.ptr == scheme.trees.items[0].columns[0].values.ptr);
    }
    scheme.setQuotientValuesAllocator(null);
    {
        var trace = try scheme.trace(allocator);
        defer trace.polys.deinitDeep(allocator);
        try std.testing.expect(trace.quotient_values_allocator == null);
    }
    try std.testing.expectEqual(@as(usize, 0), values.alloc_index);
}
