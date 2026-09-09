//! Root parity and opt-in performance gate for bounded Poseidon leaf building.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_engine = @import("stwo_prover_engine");
const recursion = @import("stwo_riscv_frontend").recursion;

const Hasher = recursion.engine.Hasher;
const Prover = prover_engine.vcs_lifted.prover.MerkleProverLifted(Hasher);
const ColumnRef = Prover.ColumnRef;
const benchmark_env = "STWO_ZIG_RUN_POSEIDON_PREFIX_BENCH";

const HeightGroup = struct {
    log_size: u32,
    column_count: usize,
};

const Fixture = struct {
    allocator: std.mem.Allocator,
    owned: [][]M31,
    references: [][]const M31,

    fn init(allocator: std.mem.Allocator, groups: []const HeightGroup) !Fixture {
        var total_columns: usize = 0;
        for (groups) |group| {
            total_columns = try std.math.add(usize, total_columns, group.column_count);
        }

        const owned = try allocator.alloc([]M31, total_columns);
        var owned_count: usize = 0;
        errdefer {
            for (owned[0..owned_count]) |column| allocator.free(column);
            allocator.free(owned);
        }
        const references = try allocator.alloc([]const M31, total_columns);
        errdefer allocator.free(references);

        var column_index: usize = 0;
        for (groups) |group| {
            const row_count = @as(usize, 1) << @intCast(group.log_size);
            for (0..group.column_count) |_| {
                const values = try allocator.alloc(M31, row_count);
                for (values, 0..) |*value, row| {
                    // Non-constant, canonical data prevents the generic
                    // constant-column shortcut from invalidating the timing
                    // comparison.
                    value.* = M31.fromU64(@intCast(
                        (column_index + 19) * 1_000_003 +
                            (row + 7) * (column_index % 29 + 31),
                    ));
                }
                owned[column_index] = values;
                references[column_index] = values;
                owned_count += 1;
                column_index += 1;
            }
        }
        return .{
            .allocator = allocator,
            .owned = owned,
            .references = references,
        };
    }

    fn deinit(self: *Fixture) void {
        for (self.owned) |column| self.allocator.free(column);
        self.allocator.free(self.owned);
        self.allocator.free(self.references);
        self.* = undefined;
    }
};

fn oldStreamingCommit(
    allocator: std.mem.Allocator,
    sorted: []const ColumnRef,
) !Prover {
    var streaming = Prover.StreamingCommitter.init(allocator);
    errdefer streaming.deinit();
    // Poseidon has no BLAKE2s domain-prefix seam, so this is the mature
    // full-state streaming implementation used before the bounded path.
    return streaming.commitColumnsWithSparseTail(sorted);
}

fn boundedCommit(
    allocator: std.mem.Allocator,
    sorted: []const ColumnRef,
    state_budget_bytes: usize,
    stats: *Prover.BoundedPrefixStats,
) !Prover {
    var streaming = Prover.StreamingCommitter.init(allocator);
    errdefer streaming.deinit();
    return streaming.commitColumnsWithBoundedPrefix(
        sorted,
        state_budget_bytes,
        stats,
    );
}

test "Poseidon bounded prefix preserves generic and full-streaming roots under a forced cap" {
    const allocator = std.testing.allocator;
    const groups = [_]HeightGroup{
        .{ .log_size = 5, .column_count = 17 },
        .{ .log_size = 8, .column_count = 7 },
        .{ .log_size = 10, .column_count = 3 },
        .{ .log_size = 11, .column_count = 2 },
    };
    var fixture = try Fixture.init(allocator, &groups);
    defer fixture.deinit();

    const sorted = try Prover.sortColumnsByLogSizeAsc(allocator, fixture.references);
    defer allocator.free(sorted);

    var generic = try Prover.commit(allocator, fixture.references);
    defer generic.deinit(allocator);
    var old_streaming = try oldStreamingCommit(allocator, sorted);
    defer old_streaming.deinit(allocator);

    const prefix_state_count = @as(usize, 1) << 8;
    const state_budget_bytes = prefix_state_count * @sizeOf(Hasher);
    var stats: Prover.BoundedPrefixStats = .{};
    var bounded = try boundedCommit(
        allocator,
        sorted,
        state_budget_bytes,
        &stats,
    );
    defer bounded.deinit(allocator);

    try std.testing.expectEqual(generic.root(), old_streaming.root());
    try std.testing.expectEqual(generic.root(), bounded.root());
    try std.testing.expectEqual(@as(u32, 11), stats.final_log_size);
    try std.testing.expectEqual(@as(u32, 8), stats.prefix_log_size);
    try std.testing.expectEqual(@as(usize, 24), stats.prefix_column_count);
    try std.testing.expectEqual(@as(usize, 5), stats.tail_column_count);
    try std.testing.expectEqual(state_budget_bytes, stats.prefix_state_bytes);
    try std.testing.expect(stats.prefix_state_bytes <= state_budget_bytes);
    try std.testing.expectEqual(
        state_budget_bytes + (@as(usize, 1) << 11) * @sizeOf(Hasher.Hash),
        stats.leaf_phase_peak_bytes,
    );
    try std.testing.expectEqual(
        @as(usize, 3) * (@as(usize, 1) << 10),
        stats.repeated_tail_absorptions,
    );
}

const Mode = enum { old_streaming, generic_batched, bounded_prefix };

const TimedRoot = struct {
    elapsed_ns: u64,
    root: Hasher.Hash,
};

fn timedCommit(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
    sorted: []const ColumnRef,
    mode: Mode,
    state_budget_bytes: usize,
) !TimedRoot {
    var timer = try std.time.Timer.start();
    var tree = switch (mode) {
        .old_streaming => try oldStreamingCommit(allocator, sorted),
        .generic_batched => try Prover.commit(allocator, fixture.references),
        .bounded_prefix => blk: {
            var stats: Prover.BoundedPrefixStats = .{};
            break :blk try boundedCommit(
                allocator,
                sorted,
                state_budget_bytes,
                &stats,
            );
        },
    };
    const elapsed_ns = timer.read();
    const root = tree.root();
    tree.deinit(allocator);
    return .{ .elapsed_ns = elapsed_ns, .root = root };
}

fn median3(values: [3]u64) u64 {
    var ordered = values;
    std.sort.insertion(u64, &ordered, {}, std.sort.asc(u64));
    return ordered[1];
}

test "Poseidon bounded prefix ReleaseFast representative no-regression gate" {
    if (!std.process.hasEnvVarConstant(benchmark_env)) return error.SkipZigTest;
    if (@import("builtin").mode != .ReleaseFast) return error.ReleaseFastRequired;

    const allocator = std.testing.allocator;
    // The absent production histogram is modeled without inventing one: the
    // observed 625-column tree count is exact, while four mixed heights expose
    // the prefix-replay failure mode. Logs and the byte cap are shifted down by
    // five together (21 -> 16, 96 MiB -> 3 MiB), preserving state ratios while
    // keeping this opt-in gate practical on developer machines.
    const groups = [_]HeightGroup{
        .{ .log_size = 10, .column_count = 600 },
        .{ .log_size = 13, .column_count = 20 },
        .{ .log_size = 15, .column_count = 3 },
        .{ .log_size = 16, .column_count = 2 },
    };
    const state_budget_bytes: usize = 3 * 1024 * 1024;
    var fixture = try Fixture.init(allocator, &groups);
    defer fixture.deinit();
    const sorted = try Prover.sortColumnsByLogSizeAsc(allocator, fixture.references);
    defer allocator.free(sorted);

    // One excluded warmup per arm establishes code/data pages before timing.
    const warm_old = try timedCommit(
        allocator,
        &fixture,
        sorted,
        .old_streaming,
        state_budget_bytes,
    );
    const warm_generic = try timedCommit(
        allocator,
        &fixture,
        sorted,
        .generic_batched,
        state_budget_bytes,
    );
    const warm_bounded = try timedCommit(
        allocator,
        &fixture,
        sorted,
        .bounded_prefix,
        state_budget_bytes,
    );
    try std.testing.expectEqual(warm_old.root, warm_generic.root);
    try std.testing.expectEqual(warm_old.root, warm_bounded.root);

    var old_samples: [3]u64 = undefined;
    var generic_samples: [3]u64 = undefined;
    var bounded_samples: [3]u64 = undefined;
    for (0..3) |sample| {
        // Alternate the two competitive arms to avoid assigning a monotonic
        // thermal drift to one implementation. The already-regressed generic
        // control remains between them.
        if ((sample & 1) == 0) {
            old_samples[sample] = (try timedCommit(
                allocator,
                &fixture,
                sorted,
                .old_streaming,
                state_budget_bytes,
            )).elapsed_ns;
        } else {
            bounded_samples[sample] = (try timedCommit(
                allocator,
                &fixture,
                sorted,
                .bounded_prefix,
                state_budget_bytes,
            )).elapsed_ns;
        }
        generic_samples[sample] = (try timedCommit(
            allocator,
            &fixture,
            sorted,
            .generic_batched,
            state_budget_bytes,
        )).elapsed_ns;
        if ((sample & 1) == 0) {
            bounded_samples[sample] = (try timedCommit(
                allocator,
                &fixture,
                sorted,
                .bounded_prefix,
                state_budget_bytes,
            )).elapsed_ns;
        } else {
            old_samples[sample] = (try timedCommit(
                allocator,
                &fixture,
                sorted,
                .old_streaming,
                state_budget_bytes,
            )).elapsed_ns;
        }
    }

    const old_median = median3(old_samples);
    const generic_median = median3(generic_samples);
    const bounded_median = median3(bounded_samples);
    std.debug.print(
        "poseidon_bounded_prefix_bench columns=625 max_log=16 " ++
            "old_streaming_ns={d} generic_batched_ns={d} bounded_prefix_ns={d} " ++
            "bounded_over_old_ppm={d} generic_over_bounded_ppm={d}\n",
        .{
            old_median,
            generic_median,
            bounded_median,
            bounded_median * 1_000_000 / old_median,
            generic_median * 1_000_000 / bounded_median,
        },
    );

    // This is intentionally generous enough for ordinary host jitter but
    // strict enough to prevent another order-of-magnitude memory/speed trade.
    try std.testing.expect(bounded_median <= old_median + old_median / 10);
    try std.testing.expect(bounded_median < generic_median);
}

fn reusedCommit(
    allocator: std.mem.Allocator,
    sorted: []const ColumnRef,
    state_budget_bytes: usize,
    stats: *Prover.BoundedPrefixStats,
) !Prover {
    var streaming = Prover.StreamingCommitter.init(allocator);
    errdefer streaming.deinit();
    return streaming.commitColumnsWithReusedBoundedPrefix(sorted, state_budget_bytes, stats);
}

test "Poseidon bounded tail reuse preserves every Merkle layer across caps and uneven worker ranges" {
    const allocator = std.testing.allocator;
    const groups = [_]HeightGroup{
        .{ .log_size = 1, .column_count = 3 },
        .{ .log_size = 5, .column_count = 11 },
        .{ .log_size = 8, .column_count = 7 },
        .{ .log_size = 10, .column_count = 3 },
        .{ .log_size = 12, .column_count = 2 },
    };
    var fixture = try Fixture.init(allocator, &groups);
    defer fixture.deinit();
    const sorted = try Prover.sortColumnsByLogSizeAsc(allocator, fixture.references);
    defer allocator.free(sorted);
    var reference = try oldStreamingCommit(allocator, sorted);
    defer reference.deinit(allocator);

    for ([_]usize{ 1, 2, 3 }) |workers| {
        if (@import("builtin").single_threaded and workers > 1) continue;
        var pool: prover_engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers });
        defer pool.deinit();
        var binding = try prover_engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        for ([_]usize{ 2 * @sizeOf(Hasher), 32 * @sizeOf(Hasher), 256 * @sizeOf(Hasher), 4096 * @sizeOf(Hasher) }) |budget| {
            var stats: Prover.BoundedPrefixStats = .{};
            var reused = try reusedCommit(allocator, sorted, budget, &stats);
            defer reused.deinit(allocator);
            try std.testing.expectEqual(reference.layers.len, reused.layers.len);
            for (reference.layers, reused.layers) |expected, actual| {
                try std.testing.expectEqualSlices(Hasher.Hash, expected, actual);
            }
            var native_absorptions: usize = 0;
            for (sorted[stats.prefix_column_count..]) |column| native_absorptions += column.values.len;
            try std.testing.expectEqual(native_absorptions + stats.repeated_tail_absorptions, stats.tail_absorptions);
            if (workers == 1 or budget >= 4096 * @sizeOf(Hasher)) {
                try std.testing.expectEqual(@as(usize, 0), stats.repeated_tail_absorptions);
            }
            try std.testing.expect(stats.tail_absorptions <= stats.tail_column_count * 4096);
            try std.testing.expect(stats.prefix_state_bytes <= @max(budget, 2 * @sizeOf(Hasher)));
            try std.testing.expect(stats.tail_cache_bytes < workers * 16 * 1024);
        }
    }
}

test "Poseidon bounded tail reuse handles empty and uniform height trees" {
    const allocator = std.testing.allocator;
    const cases = [_][]const HeightGroup{
        &.{},
        &.{.{ .log_size = 1, .column_count = 9 }},
        &.{.{ .log_size = 5, .column_count = 9 }},
    };
    for (cases) |groups| {
        var fixture = try Fixture.init(allocator, groups);
        defer fixture.deinit();
        const sorted = try Prover.sortColumnsByLogSizeAsc(allocator, fixture.references);
        defer allocator.free(sorted);
        var old_stats: Prover.BoundedPrefixStats = .{};
        var new_stats: Prover.BoundedPrefixStats = .{};
        var reference = try boundedCommit(allocator, sorted, 2 * @sizeOf(Hasher), &old_stats);
        defer reference.deinit(allocator);
        var reused = try reusedCommit(allocator, sorted, 2 * @sizeOf(Hasher), &new_stats);
        defer reused.deinit(allocator);
        try std.testing.expectEqual(reference.root(), reused.root());
        try std.testing.expectEqual(old_stats.tail_absorptions, new_stats.tail_absorptions);
        try std.testing.expectEqual(@as(usize, 0), new_stats.repeated_tail_absorptions);
    }
}

test "Poseidon bounded tail reuse measured heterogeneous commitment comparison" {
    if (!std.process.hasEnvVarConstant("STWO_ZIG_RUN_POSEIDON_TAIL_REUSE_BENCH")) return error.SkipZigTest;
    if (@import("builtin").mode != .ReleaseFast) return error.ReleaseFastRequired;
    const allocator = std.testing.allocator;
    var pool: prover_engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1 });
    defer pool.deinit();
    var binding = try prover_engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    // Native Tree0's measured tail has 41 columns at log 21 and 63 at log 25.
    // Shift those heights down 11 and force the prefix below both. This prices
    // the identical absorption ratio on a small input, not full-block latency.
    const groups = [_]HeightGroup{
        .{ .log_size = 8, .column_count = 39 },
        .{ .log_size = 10, .column_count = 41 },
        .{ .log_size = 14, .column_count = 63 },
    };
    const budget = 256 * @sizeOf(Hasher);
    var fixture = try Fixture.init(allocator, &groups);
    defer fixture.deinit();
    const sorted = try Prover.sortColumnsByLogSizeAsc(allocator, fixture.references);
    defer allocator.free(sorted);
    var baseline: [3]u64 = undefined;
    var optimized: [3]u64 = undefined;
    var baseline_stats: Prover.BoundedPrefixStats = .{};
    var optimized_stats: Prover.BoundedPrefixStats = .{};
    var expected_root: ?Hasher.Hash = null;
    // Exclude a warmup pair; alternate measured arm ordering.
    for (0..4) |round| {
        for (0..2) |arm| {
            const reuse = (arm ^ (round & 1)) == 1;
            var timer = try std.time.Timer.start();
            var tree = if (reuse)
                try reusedCommit(allocator, sorted, budget, &optimized_stats)
            else
                try boundedCommit(allocator, sorted, budget, &baseline_stats);
            const elapsed = timer.read();
            defer tree.deinit(allocator);
            if (expected_root) |expected| try std.testing.expectEqual(expected, tree.root()) else expected_root = tree.root();
            if (round > 0) {
                if (reuse) optimized[round - 1] = elapsed else baseline[round - 1] = elapsed;
            }
        }
    }
    std.debug.print("poseidon_tail_reuse_bench synthetic=true workers=1 baseline_ns={any} reused_ns={any} baseline_median_ns={d} reused_median_ns={d} baseline_absorptions={d} reused_absorptions={d} prefix_heap_bytes={d} leaf_heap_bytes={d} tail_cache_stack_bytes={d}\n", .{
        baseline,                         optimized,                          median3(baseline),                median3(optimized),               baseline_stats.tail_absorptions,
        optimized_stats.tail_absorptions, optimized_stats.prefix_state_bytes, optimized_stats.leaf_layer_bytes, optimized_stats.tail_cache_bytes,
    });
    try std.testing.expectEqual(@as(usize, 0), optimized_stats.repeated_tail_absorptions);
    try std.testing.expect(optimized_stats.tail_absorptions < baseline_stats.tail_absorptions);
}

test "Poseidon bounded tail reuse rejects mismatched column geometry before allocation" {
    const allocator = std.testing.allocator;
    const values = [_]M31{ M31.one(), M31.zero(), M31.one(), M31.zero() };
    const columns = [_]ColumnRef{.{ .values = &values, .log_size = 3, .original_index = 0 }};
    var streaming = Prover.StreamingCommitter.init(allocator);
    defer streaming.deinit();
    try std.testing.expectError(error.InvalidColumnSize, streaming.commitColumnsWithReusedBoundedPrefix(&columns, 2 * @sizeOf(Hasher), null));
    try std.testing.expectEqual(@as(usize, 0), streaming.leaf_hashers.len);
}
