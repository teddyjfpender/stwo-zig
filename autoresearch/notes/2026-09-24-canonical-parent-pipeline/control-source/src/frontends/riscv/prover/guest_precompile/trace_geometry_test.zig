const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const prover_pcs = @import("stwo_prover_engine").pcs;
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const preprocessed = @import("../preprocessed.zig");
const types = @import("../types.zig");
const subject = @import("trace_geometry.zig");

const Blake2s256 = blk: {
    if (@hasDecl(std.crypto.hash, "Blake2s256"))
        break :blk std.crypto.hash.Blake2s256;
    if (@hasDecl(std.crypto.hash, "blake2") and
        @hasDecl(std.crypto.hash.blake2, "Blake2s256"))
    {
        break :blk std.crypto.hash.blake2.Blake2s256;
    }
    @compileError("Blake2s256 not found in std.crypto.hash");
};

const FakeEngine = struct {
    pub const Channel = struct {};
    pub const Scheme = struct {
        root: types.Hasher.Hash = .{0} ** 32,

        pub fn roots(
            self: *Scheme,
            allocator: std.mem.Allocator,
        ) !pcs_core.TreeVec(types.Hasher.Hash) {
            const result = try allocator.alloc(types.Hasher.Hash, root_count);
            @memset(result, self.root);
            return pcs_core.TreeVec(types.Hasher.Hash).initOwned(result);
        }
    };

    var init_calls: usize = 0;
    var commit_calls: usize = 0;
    var consumed_commit_calls: usize = 0;
    var root_count: usize = 1;
    var fail_commit: bool = false;

    fn reset() void {
        init_calls = 0;
        commit_calls = 0;
        consumed_commit_calls = 0;
        root_count = 1;
        fail_commit = false;
    }

    pub fn init(
        _: std.mem.Allocator,
        _: pcs_core.PcsConfig,
    ) !Scheme {
        init_calls += 1;
        return .{};
    }

    pub fn deinit(_: *Scheme, _: std.mem.Allocator) void {}

    pub fn commit(
        scheme: *Scheme,
        allocator: std.mem.Allocator,
        columns: []prover_pcs.ColumnEvaluation,
        _: anytype,
        _: *Channel,
    ) !void {
        commit_calls += 1;
        const root = hashColumns(columns);
        freeColumns(allocator, columns);
        consumed_commit_calls += 1;
        if (fail_commit) return error.InjectedCommitFailure;
        scheme.root = root;
    }
};

test "profile log sizes pin zero and nonzero append-only tree geometry" {
    const allocator = std.testing.allocator;
    var zero_core = support.coreFixture(0);
    const zero_extension = try guest_statement.ExtensionStatement.canonical(&zero_core, 0);
    var live_core = support.coreFixture(17);
    const live_extension = try guest_statement.ExtensionStatement.canonical(&live_core, 17);

    var zero_tree0 = try subject.tree0LogSizes(allocator, &zero_core, &zero_extension);
    defer zero_tree0.deinit(allocator);
    var zero_tree1 = try subject.tree1LogSizes(allocator, &zero_core, &zero_extension);
    defer zero_tree1.deinit(allocator);
    var zero_tree2 = try subject.tree2LogSizes(allocator, &zero_core, &zero_extension);
    defer zero_tree2.deinit(allocator);

    var live_tree0 = try subject.tree0LogSizes(allocator, &live_core, &live_extension);
    defer live_tree0.deinit(allocator);
    var live_tree1 = try subject.tree1LogSizes(allocator, &live_core, &live_extension);
    defer live_tree1.deinit(allocator);
    var live_tree2 = try subject.tree2LogSizes(allocator, &live_core, &live_extension);
    defer live_tree2.deinit(allocator);

    try expectBoundaries(zero_tree0, .{ 8, 8, 10, 10, 12 });
    try expectBoundaries(zero_tree1, .{ 34, 34, 320, 320, 765 });
    try expectBoundaries(zero_tree2, .{ 48, 48, 356, 356, 364 });
    try expectBoundaries(live_tree0, .{ 8, 8, 10, 10, 12 });
    try expectBoundaries(live_tree1, .{ 34, 34, 320, 320, 765 });
    try expectBoundaries(live_tree2, .{ 48, 48, 356, 356, 364 });

    // Base order: fence component, then program, memory, and clock-update.
    try expectRuns(zero_tree0.values[0..8], &.{ .{ 2, 4 }, .{ 2, 3 }, .{ 2, 4 }, .{ 2, 4 } });
    try expectRuns(zero_tree1.values[0..34], &.{ .{ 6, 4 }, .{ 10, 3 }, .{ 8, 4 }, .{ 10, 4 } });
    try expectRuns(zero_tree2.values[0..48], &.{ .{ 8, 4 }, .{ 16, 3 }, .{ 16, 4 }, .{ 8, 4 } });
    try std.testing.expectEqualSlices(u32, zero_tree0.values[0..8], live_tree0.values[0..8]);
    try std.testing.expectEqualSlices(u32, zero_tree1.values[0..34], live_tree1.values[0..34]);
    try std.testing.expectEqualSlices(u32, zero_tree2.values[0..48], live_tree2.values[0..48]);

    // A zero-row profile retains its fixed components at the minimum log size.
    try expectAll(zero_tree0.values[8..12], 4);
    try expectAll(zero_tree1.values[34..765], 4);
    try expectAll(zero_tree2.values[48..364], 4);
    try expectAll(live_tree0.values[8..12], 5);
    try expectAll(live_tree1.values[34..765], 5);
    try expectAll(live_tree2.values[48..364], 5);
}

test "geometry arithmetic and malformed profiles fail closed before allocation" {
    try std.testing.expectError(
        error.TraceGeometryOverflow,
        subject.Boundaries.checked(std.math.maxInt(usize), 1, 0),
    );
    try std.testing.expectError(
        error.TraceGeometryOverflow,
        subject.Boundaries.checked(std.math.maxInt(usize) - 1, 1, 1),
    );

    var core = support.coreFixture(17);
    var extension = try guest_statement.ExtensionStatement.canonical(&core, 17);
    extension.manifest_digest[0] ^= 1;
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    const allocator = failing.allocator();

    try std.testing.expectError(
        error.ManifestDigestMismatch,
        subject.tree0LogSizes(allocator, &core, &extension),
    );
    try std.testing.expectError(
        error.ManifestDigestMismatch,
        subject.tree1LogSizes(allocator, &core, &extension),
    );
    try std.testing.expectError(
        error.ManifestDigestMismatch,
        subject.tree2LogSizes(allocator, &core, &extension),
    );

    FakeEngine.reset();
    try std.testing.expectError(
        error.ManifestDigestMismatch,
        subject.verifyPreprocessedRoot(
            FakeEngine,
            allocator,
            pcs_core.PcsConfig.default(),
            &core,
            &extension,
            .{0} ** 32,
        ),
    );
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), FakeEngine.init_calls);
    try std.testing.expectEqual(@as(usize, 0), FakeEngine.commit_calls);
}

test "each geometry vector uses one allocation and rolls back every failure" {
    var core = support.coreFixture(17);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 17);

    try expectOneAllocation(subject.tree0LogSizes, &core, &extension);
    try expectOneAllocation(subject.tree1LogSizes, &core, &extension);
    try expectOneAllocation(subject.tree2LogSizes, &core, &extension);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        geometryAllocationCase,
        .{ &core, &extension },
    );

    FakeEngine.reset();
    const root = try expectedRoot(std.testing.allocator, &core, &extension);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        verificationAllocationCase,
        .{ &core, &extension, root },
    );
}

test "preprocessed root verification requires one exact regenerated root" {
    const allocator = std.testing.allocator;
    var core = support.coreFixture(17);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 17);
    const root = try expectedRoot(allocator, &core, &extension);

    FakeEngine.reset();
    try subject.verifyPreprocessedRoot(
        FakeEngine,
        allocator,
        pcs_core.PcsConfig.default(),
        &core,
        &extension,
        root,
    );

    var mismatch = root;
    mismatch[0] ^= 1;
    try std.testing.expectError(
        types.ProverError.InvalidPreprocessedCommitment,
        subject.verifyPreprocessedRoot(
            FakeEngine,
            allocator,
            pcs_core.PcsConfig.default(),
            &core,
            &extension,
            mismatch,
        ),
    );

    FakeEngine.root_count = 2;
    try std.testing.expectError(
        types.ProverError.InvalidPreprocessedCommitment,
        subject.verifyPreprocessedRoot(
            FakeEngine,
            allocator,
            pcs_core.PcsConfig.default(),
            &core,
            &extension,
            root,
        ),
    );
    try std.testing.expectEqual(@as(usize, 3), FakeEngine.init_calls);
    try std.testing.expectEqual(@as(usize, 3), FakeEngine.commit_calls);

    // A failed commit consumes the regenerated columns exactly once. The
    // verifier must relinquish them before calling the engine, so its rollback
    // cannot double-free the failed transfer.
    FakeEngine.reset();
    FakeEngine.fail_commit = true;
    var counter = std.testing.FailingAllocator.init(allocator, .{});
    try std.testing.expectError(
        error.InjectedCommitFailure,
        subject.verifyPreprocessedRoot(
            FakeEngine,
            counter.allocator(),
            pcs_core.PcsConfig.default(),
            &core,
            &extension,
            root,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), FakeEngine.commit_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeEngine.consumed_commit_calls);
    try std.testing.expectEqual(counter.allocated_bytes, counter.freed_bytes);
}

const ExpectedBoundaries = struct { usize, usize, usize, usize, usize };
const ExpectedRun = struct { usize, u32 };

fn expectBoundaries(
    geometry: subject.OwnedLogSizes,
    expected: ExpectedBoundaries,
) !void {
    try std.testing.expectEqual(expected[0], geometry.boundaries.base_end);
    try std.testing.expectEqual(expected[1], geometry.boundaries.caller_start);
    try std.testing.expectEqual(expected[2], geometry.boundaries.caller_end);
    try std.testing.expectEqual(expected[3], geometry.boundaries.provider_start);
    try std.testing.expectEqual(expected[4], geometry.boundaries.provider_end);
    try std.testing.expectEqual(expected[4], geometry.values.len);
}

fn expectRuns(values: []const u32, runs: []const ExpectedRun) !void {
    var cursor: usize = 0;
    for (runs) |run| {
        try expectAll(values[cursor .. cursor + run[0]], run[1]);
        cursor += run[0];
    }
    try std.testing.expectEqual(values.len, cursor);
}

fn expectAll(values: []const u32, expected: u32) !void {
    for (values) |actual| try std.testing.expectEqual(expected, actual);
}

fn expectOneAllocation(
    comptime builder: anytype,
    core: *const support.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
) !void {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );
    var result = try builder(failing.allocator(), core, extension);
    defer result.deinit(failing.allocator());
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), failing.alloc_index);
}

fn geometryAllocationCase(
    allocator: std.mem.Allocator,
    core: *const support.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
) !void {
    var tree0 = try subject.tree0LogSizes(allocator, core, extension);
    defer tree0.deinit(allocator);
    var tree1 = try subject.tree1LogSizes(allocator, core, extension);
    defer tree1.deinit(allocator);
    var tree2 = try subject.tree2LogSizes(allocator, core, extension);
    defer tree2.deinit(allocator);
}

fn verificationAllocationCase(
    allocator: std.mem.Allocator,
    core: *const support.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    root: types.Hasher.Hash,
) !void {
    try subject.verifyPreprocessedRoot(
        FakeEngine,
        allocator,
        pcs_core.PcsConfig.default(),
        core,
        extension,
        root,
    );
}

fn expectedRoot(
    allocator: std.mem.Allocator,
    core: *const support.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
) !types.Hasher.Hash {
    const columns = try preprocessed.generatePoseidon2(allocator, core, extension);
    defer freeColumns(allocator, columns);
    return hashColumns(columns);
}

fn hashColumns(columns: []const prover_pcs.ColumnEvaluation) types.Hasher.Hash {
    var hasher = Blake2s256.init(.{});
    hasher.update("trace-geometry-test-root-v1\x00");
    hashInt(&hasher, u64, @intCast(columns.len));
    for (columns) |column| {
        hashInt(&hasher, u32, column.log_size);
        hashInt(&hasher, u64, @intCast(column.values.len));
        for (column.values) |value| hasher.update(&value.toBytesLe());
    }
    var result: types.Hasher.Hash = undefined;
    hasher.final(&result);
    return result;
}

fn hashInt(hasher: *Blake2s256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}
