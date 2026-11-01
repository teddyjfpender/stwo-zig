const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const Cache = @import("fixed_native_cache.zig").Cache;
const Key = @import("../word16_global_execution/keccak/shared/key.zig").Key;
const Setup = @import("setup.zig");
const E = @import("execution.zig");
const T = @import("protocol.zig").T;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const a = std.testing.allocator;
fn fill(values: *[16][32]M) void {
    for (values, 0..) |*row, i| for (row, 0..) |*value, j| {
        value.* = M.fromCanonical(@intCast(19 * i * i + 31 * j + 7 * i * j));
    };
}
fn columnsFor(values: *[16][32]M) [16]Column {
    var columns: [16]Column = undefined;
    for (&columns, values) |*column, *row| column.* = .{ .log_size = 5, .values = row };
    return columns;
}
fn unshared(allocator: std.mem.Allocator, columns: []const Column) !T.Scheme.CommittedTree {
    var scheme = try T.Scheme.init(allocator, T.P.config());
    defer scheme.deinit(allocator);
    scheme.setCompactPolynomialStorage(5);
    var channel = T.P.Channel{};
    try scheme.commitBorrowedStreaming(allocator, columns, 8, &channel);
    return scheme.trees.pop().?;
}

test "Fixed native cache shares exact independently generated coefficients and roots" {
    var values: [16][32]M = undefined;
    fill(&values);
    const columns = columnsFor(&values);
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var plain = try Key.seal(a, &columns);
    defer plain.deinit();
    var first = try Key.sealWithCache(a, &columns, &cache);
    defer first.deinit();
    const suite4 = Key.Suite.experimentalFold4();
    var second = try Key.sealWithSuiteAndCache(a, &columns, suite4, &cache);
    defer second.deinit();
    try std.testing.expect(second.suite.eql(suite4));
    try std.testing.expect(first.suite.eql(Key.Suite.production()));
    var wrong_scheme = try T.Scheme.init(a, T.P.config());
    defer wrong_scheme.deinit(a);
    var wrong_channel = T.P.Channel{};
    try std.testing.expectError(error.InvalidSharedTruthFixedPhase, second.append(a, &wrong_scheme, &wrong_channel));
    var correct_scheme = try T.Scheme.init(a, suite4.config());
    defer correct_scheme.deinit(a);
    var correct_channel = T.P.Channel{};
    try second.append(a, &correct_scheme, &correct_channel);
    try std.testing.expectEqual(plain.root, first.root);
    try std.testing.expectEqual(plain.root, second.root);
    for (plain.tree.coefficients.?, first.tree.coefficients.?, second.tree.coefficients.?) |normal, left, right| {
        try std.testing.expectEqualSlices(M, normal.coeffs, left.coeffs);
        try std.testing.expectEqualSlices(M, normal.coeffs, right.coeffs);
        try std.testing.expectEqual(left.coeffs.ptr, right.coeffs.ptr);
    }
    const stats = cache.snapshot();
    try std.testing.expect(stats.groups > 0 and stats.hits > 0);
    try std.testing.expect(stats.duplicate_native_bytes_released > 0);
    try std.testing.expect(stats.retained_bytes <= stats.limit_bytes);
    try std.testing.expectEqual(@as(usize, 3), stats.owner_leases);
    const allocations = try cache.ownedAllocations(a);
    defer a.free(allocations);
    var accounted: usize = 0;
    for (allocations) |allocation| accounted += allocation.bytes;
    try std.testing.expectEqual(stats.retained_bytes, accounted);
    try std.testing.expect(stats.observed_individual_owners > 0);
}

test "Fixed native cache capacity misses and disabled mode retain private custody" {
    var values: [16][32]M = undefined;
    fill(&values);
    const columns = columnsFor(&values);
    const minimum = @import("fixed_native_cache.zig").MINIMUM_BUDGET_BYTES;
    var tiny = try Cache.init(a, minimum);
    defer tiny.deinit();
    var tree = try unshared(a, &columns);
    defer tree.deinit(a);
    const result = try tiny.internTree(a, &tree);
    try std.testing.expectEqual(@as(usize, 0), result.shared_groups);
    try std.testing.expect(tree.backing_teardown == null);
    try std.testing.expect(tiny.snapshot().retained_bytes <= minimum);
    var disabled = try Cache.init(a, 0);
    defer disabled.deinit();
    try std.testing.expectEqualDeep(@import("fixed_native_cache.zig").Result{}, try disabled.internTree(a, &tree));
    try std.testing.expectEqual(@as(usize, 0), disabled.snapshot().retained_bytes);
}

test "Fixed native coefficient leases outlive cache handles and source Setup owners" {
    var values: [16][32]M = undefined;
    fill(&values);
    const columns = columnsFor(&values);
    var cache = try Cache.init(a, 1024 * 1024);
    var key = try Key.sealWithCache(a, &columns, &cache);
    const root = key.root;
    const first = try a.dupe(M, key.tree.coefficients.?[0].coeffs);
    defer a.free(first);
    var scheme = try T.Scheme.init(a, T.P.config());
    defer scheme.deinit(a);
    var channel = T.P.Channel{};
    try key.append(a, &scheme, &channel);
    key.deinit();
    cache.deinit();
    try std.testing.expectEqual(root, scheme.trees.items[0].root());
    try std.testing.expectEqualSlices(M, first, scheme.trees.items[0].coefficients.?[0].coeffs);
}

test "Fixed native preflight rejects malformed shapes aliases and repeat custody changes" {
    var values: [16][32]M = undefined;
    fill(&values);
    const columns = columnsFor(&values);
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var tree = try unshared(a, &columns);
    defer tree.deinit(a);
    const original = tree.coefficients.?[0];
    tree.coefficients.?[0].log_size += 1;
    try std.testing.expectError(error.InvalidFixedNativeCacheShape, cache.internTree(a, &tree));
    tree.coefficients.?[0] = original;
    const second = tree.coefficients.?[1];
    const second_view = tree.columns[1].coefficient_values;
    tree.coefficients.?[1] = original;
    tree.columns[1].coefficient_values = original.coeffs;
    try std.testing.expectError(error.InvalidFixedNativeCacheAlias, cache.internTree(a, &tree));
    tree.coefficients.?[1] = second;
    tree.columns[1].coefficient_values = second_view;
    try std.testing.expectEqual(@as(usize, 0), cache.snapshot().groups);
    _ = try cache.internTree(a, &tree);
    try std.testing.expectError(error.InvalidFixedNativeCachePhase, cache.internTree(a, &tree));
}

test "Hash collisions never replace exact ordered coefficient equality" {
    var left: [16][32]M = undefined;
    fill(&left);
    var right = left;
    right[0][0] = right[0][0].add(M.one());
    const lc = columnsFor(&left);
    const rc = columnsFor(&right);
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var other = try Cache.init(a, 1024 * 1024);
    defer other.deinit();
    var key = try Key.sealWithCache(a, &lc, &cache);
    defer key.deinit();
    var independently_different = try Key.sealWithCache(a, &rc, &other);
    defer independently_different.deinit();
    // Deliberately corrupt only the lookup fingerprint, not the payload. This
    // models a collision without adding an unsafe production injection API.
    cache.state.?.entries.items[0].digest = other.state.?.entries.items[0].digest;
    var result = try Key.sealWithCache(a, &rc, &cache);
    defer result.deinit();
    try std.testing.expectEqual(independently_different.root, result.root);
    try std.testing.expect(!std.mem.eql(u8, &key.root, &result.root));
    try std.testing.expectEqualSlices(M, independently_different.tree.coefficients.?[0].coeffs, result.tree.coefficients.?[0].coeffs);
}

fn oomExercise(allocator: std.mem.Allocator) !void {
    var values: [16][32]M = undefined;
    fill(&values);
    const columns = columnsFor(&values);
    var cache = try Cache.init(allocator, 1024 * 1024);
    defer cache.deinit();
    var first = try Key.sealWithCache(allocator, &columns, &cache);
    defer first.deinit();
    var second = try Key.sealWithCache(allocator, &columns, &cache);
    defer second.deinit();
    try std.testing.expectEqual(first.root, second.root);
}
test "Every key cache and lease allocation failure tears down exactly once" {
    try std.testing.checkAllAllocationFailures(a, oomExercise, .{});
}

test "Failed interning is atomic and retry preserves the original root" {
    var failing = std.testing.FailingAllocator.init(a, .{});
    const allocator = failing.allocator();
    var values: [16][32]M = undefined;
    fill(&values);
    const columns = columnsFor(&values);
    var cache = try Cache.init(allocator, 1024 * 1024);
    defer cache.deinit();
    var tree = try unshared(allocator, &columns);
    defer tree.deinit(allocator);
    const root = tree.root();
    const original = tree.coefficients.?[0].coeffs.ptr;
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, cache.internTree(allocator, &tree));
    try std.testing.expect(tree.backing_teardown == null);
    try std.testing.expectEqual(original, tree.coefficients.?[0].coeffs.ptr);
    try std.testing.expectEqual(@as(usize, 0), cache.snapshot().groups);
    failing.fail_index = std.math.maxInt(usize);
    _ = try cache.internTree(allocator, &tree);
    try std.testing.expectEqual(root, tree.root());
}

const ParallelJob = struct {
    cache: *const Cache,
    tree: *T.Scheme.CommittedTree,
    failure: ?anyerror = null,
    fn run(self: *ParallelJob) void {
        _ = self.cache.internTree(a, self.tree) catch |err| {
            self.failure = err;
            return;
        };
    }
};
test "Concurrent independent key owners publish one bounded immutable group set" {
    var values: [16][32]M = undefined;
    fill(&values);
    const columns = columnsFor(&values);
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var left = try unshared(a, &columns);
    defer left.deinit(a);
    var right = try unshared(a, &columns);
    defer right.deinit(a);
    var jobs = [_]ParallelJob{ .{ .cache = &cache, .tree = &left }, .{ .cache = &cache, .tree = &right } };
    const thread = try std.Thread.spawn(.{}, ParallelJob.run, .{&jobs[0]});
    const second = std.Thread.spawn(.{}, ParallelJob.run, .{&jobs[1]}) catch |err| {
        thread.join();
        return err;
    };
    thread.join();
    second.join();
    for (jobs) |job| if (job.failure) |err| return err;
    try std.testing.expectEqual(left.root(), right.root());
    try std.testing.expectEqual(left.coefficients.?[0].coeffs.ptr, right.coefficients.?[0].coeffs.ptr);
    try std.testing.expect(cache.snapshot().retained_bytes <= cache.snapshot().limit_bytes);
}

var context: u8 = 0;
const Zero = struct {
    fn word(_: *const anyopaque, _: u64) !u64 {
        return 0;
    }
    fn rights(_: *const anyopaque, _: u64) !u2 {
        return 0;
    }
};
fn admission() E.Admission {
    return .{ .image = .{ .context = &context, .initial_word = Zero.word, .rights_at = Zero.rights }, .image_identity = @splat(9), .initial_pc = 4096, .initial_registers = @splat(0) };
}
test "Cached full fixed setup preserves complete q70 proof claims bytes and fresh authority" {
    for ([_]Setup.Suite{ Setup.Suite.production(), Setup.Suite.experimentalFold4() }) |suite| {
        const words = [_]u32{ 0x00700093, 0x0010c133 };
        const geometry = Setup.Geometry{ .cpu_log = 5, .omit_empty_division = true };
        var cache = try Cache.init(a, 64 * 1024 * 1024);
        defer cache.deinit();
        var normal = try Setup.Setup.initWithSuite(a, .{ .base = 4096, .words = &words }, geometry, suite);
        defer normal.deinit();
        var cached = try Setup.Setup.initWithSuiteAndNativeCache(a, .{ .base = 4096, .words = &words }, geometry, suite, &cache);
        defer cached.deinit();
        try std.testing.expectEqual(normal.fixed_root, cached.fixed_root);
        try std.testing.expect(cached.materials.suite.eql(suite));
        var tape = try front.rv64.compact_tape.Tape.init(a, 2, 4096, 0, .ethereum_services_v2);
        defer tape.deinit();
        tape.len = 2;
        tape.storage[0] = .{ .next_pc = 4100, .lhs = 0, .rhs = 0, .previous_rd = 0, .result = 7, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        tape.storage[1] = .{ .next_pc = 4104, .lhs = 7, .rhs = 7, .previous_rd = 0, .result = 0, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        var public: front.rv64_air.word16_execution.types.Boundary = .{ .steps = 2, .initial_pc = 4096, .final_pc = 4104, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
        public.final_registers[1] = 7;
        public.register_clocks[1] = 6;
        public.register_clocks[2] = 7;
        var old = try E.prove(a, &normal, admission(), public, &tape, null);
        defer old.deinit(a);
        var proof = try E.prove(a, &cached, admission(), public, &tape, null);
        defer proof.deinit(a);
        try std.testing.expectEqualDeep(old.claims, proof.claims);
        try std.testing.expectEqualSlices(u8, old.bytes, proof.bytes);
        try cached.releaseFixedWitness();
        var fresh = try Setup.Setup.initWithSuiteAndNativeCache(a, .{ .base = 4096, .words = &words }, geometry, suite, &cache);
        defer fresh.deinit();
        try fresh.releaseFixedWitness();
        try E.verify(a, &fresh, admission(), proof);
        try std.testing.expect(cache.snapshot().hits > 0);
    }
}

test "Sparse high64 programs and geometry-specific fixed roots never alias authority" {
    const words = [_]u32{ 0x00700093, 0x0010c133 };
    const addresses = [_]u64{ 0xffff_ffff_ffff_fff8, 0x1_0000_1000 };
    // Program addresses must be sorted; the upper limb is never truncated.
    const sorted = [_]u64{ addresses[1], addresses[0] };
    var cache = try Cache.init(a, 64 * 1024 * 1024);
    defer cache.deinit();
    const program = front.rv64_air.program.setup.Program{ .base = sorted[0], .words = &words, .addresses = &sorted };
    var normal = try Setup.Setup.init(a, program, .{ .cpu_log = 5, .omit_empty_division = true });
    defer normal.deinit();
    var cached = try Setup.Setup.initWithNativeCache(a, program, .{ .cpu_log = 5, .omit_empty_division = true }, &cache);
    defer cached.deinit();
    try std.testing.expectEqual(normal.fixed_root, cached.fixed_root);
    try std.testing.expectEqual(@as(usize, 1), try cached.materials.program.lookup(sorted[1]));
    var other = try Setup.Setup.initWithNativeCache(a, program, .{ .cpu_log = 6, .omit_empty_division = true }, &cache);
    defer other.deinit();
    try std.testing.expect(!std.meta.eql(cached.fixed_root, other.fixed_root));
    try std.testing.expectEqual(cached.materials.program.identity, other.materials.program.identity);
}

test "Stateless SMP and mixed source allocators retain actual payload custody" {
    var values: [16][32]M = undefined;
    fill(&values);
    const columns = columnsFor(&values);
    for (0..3) |mode| {
        const metadata = if (mode == 1) a else std.heap.smp_allocator;
        const payload = if (mode == 2) a else std.heap.smp_allocator;
        var cache = try Cache.init(metadata, 1024 * 1024);
        defer cache.deinit();
        var first = try Key.sealWithCache(payload, &columns, &cache);
        defer first.deinit();
        var second = try Key.sealWithCache(payload, &columns, &cache);
        defer second.deinit();
        try std.testing.expectEqual(first.root, second.root);
        try std.testing.expect(cache.snapshot().observed_spans > 0);
        try std.testing.expect(cache.snapshot().native_backing_bytes > 0);
        try std.testing.expect(cache.snapshot().hits > 0);
        try std.testing.expectEqual(first.tree.coefficients.?[0].coeffs.ptr, second.tree.coefficients.?[0].coeffs.ptr);
    }
    const Budget = engine.host_budget_allocator.SharedHostBudget;
    const source_budget = try Budget.create(a, 16 * 1024 * 1024);
    var source_budget_owned = true;
    defer if (source_budget_owned) source_budget.destroy();
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var first = try Key.sealWithCache(source_budget.allocator(), &columns, &cache);
    var first_owned = true;
    defer if (first_owned) first.deinit();
    var second = try Key.sealWithCache(a, &columns, &cache);
    defer second.deinit();
    first.deinit();
    first_owned = false;
    source_budget.destroy();
    source_budget_owned = false;
    // Native buffers retain their original budget after its caller and original
    // key are gone. A different allocator owns this later tree's descriptors.
    try std.testing.expect(cache.snapshot().hits > 0);
    try std.testing.expectEqual(@as(usize, 32), second.tree.coefficients.?[0].coeffs.len);
}

fn ownedInput(allocator: std.mem.Allocator, values: *[16][32]M) !struct { columns: []Column, backings: [][]M } {
    const buffers = try allocator.alloc([]M, 2);
    errdefer allocator.free(buffers);
    var done: usize = 0;
    errdefer for (buffers[0..done]) |buffer| allocator.free(buffer);
    for (buffers) |*buffer| {
        buffer.* = try allocator.alloc(M, 8 * 32);
        done += 1;
    }
    const columns = try allocator.alloc(Column, 16);
    for (columns, values, 0..) |*column, row, i| {
        const target = buffers[i / 8][32 * (i % 8) ..][0..32];
        @memcpy(target, &row);
        column.* = .{ .log_size = 5, .values = target };
    }
    return .{ .columns = columns, .backings = buffers };
}
fn unsharedOwned(allocator: std.mem.Allocator, values: *[16][32]M) !T.Scheme.CommittedTree {
    var scheme = try T.Scheme.init(allocator, T.P.config());
    defer scheme.deinit(allocator);
    scheme.setCompactPolynomialStorage(5);
    const input = try ownedInput(allocator, values);
    var channel = T.P.Channel{};
    // The canonical PCS operation consumes both input owners on success/error.
    try scheme.commitOwnedStreamingWithRecorderAndBacking(allocator, input.columns, input.backings, 8, null, &channel);
    return scheme.trees.pop().?;
}
test "Complete backing groups preserve uncached aliases and retire only transferred buffers" {
    var values: [16][32]M = undefined;
    fill(&values);
    var cache = try Cache.init(a, 1024 * 1024);
    defer cache.deinit();
    var left = try unsharedOwned(a, &values);
    defer left.deinit(a);
    var right = try unsharedOwned(a, &values);
    defer right.deinit(a);
    try std.testing.expectEqual(@as(usize, 2), left.coefficient_backing_buffers.?.len);
    _ = try cache.internTree(a, &left);
    _ = try cache.internTree(a, &right);
    try std.testing.expectEqual(left.root(), right.root());
    try std.testing.expectEqual(left.coefficients.?[0].coeffs.ptr, right.coefficients.?[0].coeffs.ptr);
    for (right.coefficient_backing_buffers.?) |buffer| try std.testing.expectEqual(@as(usize, 0), buffer.len);

    var partial = try unsharedOwned(a, &values);
    defer partial.deinit(a);
    const original = partial.coefficient_backing_buffers.?[0];
    const saved = partial.columns[0].values;
    partial.columns[0].values = partial.coefficients.?[0].coeffs;
    defer partial.columns[0].values = saved;
    const result = try cache.internTree(a, &partial);
    try std.testing.expectEqual(@as(usize, 1), result.shared_groups);
    try std.testing.expectEqual(original.ptr, partial.coefficient_backing_buffers.?[0].ptr);
    try std.testing.expectEqual(original.len, partial.coefficient_backing_buffers.?[0].len);
    try std.testing.expectEqual(@as(usize, 0), partial.coefficient_backing_buffers.?[1].len);
}
