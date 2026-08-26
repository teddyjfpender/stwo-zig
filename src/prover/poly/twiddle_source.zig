const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const canonic = @import("stwo_core").poly.circle.canonic;
const domain = @import("stwo_core").poly.circle.domain;
const work_profile = @import("stwo_prover_api").work_profile;
const twiddles = @import("twiddles.zig");
const twiddle_tower = @import("twiddle_tower.zig");

const M31 = m31.M31;
const M31TwiddleTree = twiddles.TwiddleTree([]M31);
const ConstM31TwiddleTree = twiddles.TwiddleTree([]const M31);
const M31TwiddleTower = twiddle_tower.M31TwiddleTower;
const WorkRecorder = work_profile.Recorder(true);

/// A per-scheme twiddle provider.
///
/// The owned mode preserves the compatibility cache used by standalone
/// commitment schemes. The borrowed mode lets a long-lived prover session
/// supply one immutable canonical tower to many schemes. Returned trees are
/// values containing stable allocation slices; no pointer into the movable
/// owned hash map escapes this type.
pub const TwiddleSource = struct {
    storage: Storage,
    request_count: u64 = 0,
    rejected_request_count: u64 = 0,
    cache_hit_count: u64 = 0,
    tree_build_count: u64 = 0,

    const Self = @This();

    const Owned = struct {
        cache: std.AutoHashMap(u32, M31TwiddleTree),
        // Serializes cache access so a deferred-commit worker and the main
        // thread may request trees concurrently; returned slices are stable
        // allocations, so the lock covers only lookup/insert.
        mutex: std.Thread.Mutex = .{},
    };

    const Storage = union(enum) {
        owned: Owned,
        borrowed: *const M31TwiddleTower,
    };

    pub const Mode = enum {
        owned_cache,
        borrowed_tower,
    };

    pub const Telemetry = struct {
        mode: Mode,
        request_count: u64,
        rejected_request_count: u64,
        cache_hit_count: u64,
        tree_build_count: u64,
        retained_tree_count: usize,
        /// Forward and inverse twiddle storage reachable through this source.
        /// Provider bookkeeping is deliberately excluded.
        retained_bytes: usize,
    };

    pub fn initOwned(allocator: std.mem.Allocator) Self {
        return .{
            .storage = .{
                .owned = .{
                    .cache = std.AutoHashMap(u32, M31TwiddleTree).init(allocator),
                },
            },
        };
    }

    pub fn initBorrowed(tower: *const M31TwiddleTower) Self {
        return .{ .storage = .{ .borrowed = tower } };
    }

    pub fn isBorrowed(self: *const Self) bool {
        return self.storage == .borrowed;
    }

    pub fn get(
        self: *Self,
        allocator: std.mem.Allocator,
        circle_log: u32,
    ) !ConstM31TwiddleTree {
        return self.getWithWorkRecorder(allocator, circle_log, null);
    }

    /// Returns an exact-log tree and charges construction only to the request
    /// that wins an owned-cache miss. Borrowed views and owned cache hits do
    /// not plan or complete a cold-twiddle producer.
    pub fn getWithWorkRecorder(
        self: *Self,
        allocator: std.mem.Allocator,
        circle_log: u32,
        work_recorder: ?*WorkRecorder,
    ) !ConstM31TwiddleTree {
        _ = @atomicRmw(u64, &self.request_count, .Add, 1, .monotonic);
        if (circle_log < domain.MIN_CIRCLE_DOMAIN_LOG_SIZE or
            circle_log > domain.MAX_CIRCLE_DOMAIN_LOG_SIZE)
        {
            _ = @atomicRmw(u64, &self.rejected_request_count, .Add, 1, .monotonic);
            return error.InvalidCircleLog;
        }

        return switch (self.storage) {
            .borrowed => |tower| blk: {
                const tree = tower.view(circle_log) catch |err| {
                    _ = @atomicRmw(u64, &self.rejected_request_count, .Add, 1, .monotonic);
                    return err;
                };
                _ = @atomicRmw(u64, &self.cache_hit_count, .Add, 1, .monotonic);
                break :blk tree;
            },
            .owned => |*owned| blk: {
                owned.mutex.lock();
                defer owned.mutex.unlock();
                if (owned.cache.get(circle_log)) |tree| {
                    self.cache_hit_count +|= 1;
                    break :blk treeConst(tree);
                }

                // Reserve map storage before publishing a plan or completing
                // expensive construction. The final insertion is infallible
                // while this mutex excludes another builder for the same log.
                try owned.cache.ensureUnusedCapacity(1);
                const cold_work = if (work_recorder != null)
                    try work_profile.logicalM31ColdTwiddleWork(circle_log)
                else
                    null;
                if (work_recorder) |active|
                    try active.expectProducer(.cold_twiddle_construction);

                var tree = try twiddles.precomputeM31(
                    allocator,
                    canonic.CanonicCoset.new(circle_log).circleDomain().half_coset,
                );
                errdefer twiddles.deinitM31(allocator, &tree);

                if (work_recorder) |active| {
                    try active.recordCompletedDelta(.{
                        .site = .cold_twiddle_construction,
                        .producer = work_profile.boundaryForSite(.cold_twiddle_construction),
                        .source_mask = .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
                            work_profile.SourceMask.one(.field_multiplications).bits |
                            work_profile.SourceMask.one(.field_inversions).bits },
                        .counters = cold_work.?,
                    });
                }

                const gop = owned.cache.getOrPutAssumeCapacity(circle_log);
                std.debug.assert(!gop.found_existing);
                gop.value_ptr.* = tree;
                self.tree_build_count +|= 1;
                break :blk treeConst(tree);
            },
        };
    }

    pub fn telemetry(self: *const Self) Telemetry {
        return switch (self.storage) {
            .owned => |*owned| .{
                .mode = .owned_cache,
                .request_count = self.request_count,
                .rejected_request_count = self.rejected_request_count,
                .cache_hit_count = self.cache_hit_count,
                .tree_build_count = self.tree_build_count,
                .retained_tree_count = owned.cache.count(),
                .retained_bytes = ownedRetainedBytes(&owned.cache),
            },
            .borrowed => |tower| .{
                .mode = .borrowed_tower,
                .request_count = self.request_count,
                .rejected_request_count = self.rejected_request_count,
                .cache_hit_count = self.cache_hit_count,
                .tree_build_count = self.tree_build_count,
                .retained_tree_count = 1,
                .retained_bytes = tower.retainedBytes(),
            },
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        switch (self.storage) {
            .owned => |*owned| {
                var values = owned.cache.valueIterator();
                while (values.next()) |tree| twiddles.deinitM31(allocator, tree);
                owned.cache.deinit();
            },
            .borrowed => {},
        }
        self.* = undefined;
    }
};

fn treeConst(tree: M31TwiddleTree) ConstM31TwiddleTree {
    return .{
        .root_coset = tree.root_coset,
        .twiddles = tree.twiddles,
        .itwiddles = tree.itwiddles,
    };
}

fn ownedRetainedBytes(cache: *const std.AutoHashMap(u32, M31TwiddleTree)) usize {
    var total: usize = 0;
    var values = cache.valueIterator();
    while (values.next()) |tree| {
        const element_count = std.math.add(
            usize,
            tree.twiddles.len,
            tree.itwiddles.len,
        ) catch unreachable;
        total = std.math.add(
            usize,
            total,
            std.math.mul(
                usize,
                element_count,
                @sizeOf(M31),
            ) catch unreachable,
        ) catch unreachable;
    }
    return total;
}

fn expectTreesEqual(expected: ConstM31TwiddleTree, actual: ConstM31TwiddleTree) !void {
    try std.testing.expect(expected.root_coset.eql(actual.root_coset));
    try std.testing.expectEqualSlices(M31, expected.twiddles, actual.twiddles);
    try std.testing.expectEqualSlices(M31, expected.itwiddles, actual.itwiddles);
}

test "twiddle source: owned and borrowed trees are exactly equivalent" {
    const allocator = std.testing.allocator;
    var tower = try M31TwiddleTower.init(allocator, 8, 1 << 20);
    defer tower.deinit(allocator);

    var owned = TwiddleSource.initOwned(allocator);
    defer owned.deinit(allocator);
    var borrowed = TwiddleSource.initBorrowed(&tower);
    defer borrowed.deinit(allocator);

    for (2..9) |log| {
        const owned_tree = try owned.get(allocator, @intCast(log));
        const borrowed_tree = try borrowed.get(allocator, @intCast(log));
        try expectTreesEqual(owned_tree, borrowed_tree);
    }

    const owned_stats = owned.telemetry();
    try std.testing.expectEqual(TwiddleSource.Mode.owned_cache, owned_stats.mode);
    try std.testing.expectEqual(@as(u64, 7), owned_stats.tree_build_count);
    try std.testing.expectEqual(@as(usize, 7), owned_stats.retained_tree_count);
    try std.testing.expect(owned_stats.retained_bytes > 0);

    const borrowed_stats = borrowed.telemetry();
    try std.testing.expectEqual(TwiddleSource.Mode.borrowed_tower, borrowed_stats.mode);
    try std.testing.expectEqual(@as(u64, 0), borrowed_stats.tree_build_count);
    try std.testing.expectEqual(tower.retainedBytes(), borrowed_stats.retained_bytes);
}

test "twiddle source: owned cache reuse does not rebuild" {
    const allocator = std.testing.allocator;
    var source = TwiddleSource.initOwned(allocator);
    defer source.deinit(allocator);

    const first = try source.get(allocator, 8);
    const cold = source.telemetry();
    const second = try source.get(allocator, 8);
    const warm = source.telemetry();

    try expectTreesEqual(first, second);
    try std.testing.expectEqual(@as(u64, 1), cold.tree_build_count);
    try std.testing.expectEqual(cold.tree_build_count, warm.tree_build_count);
    try std.testing.expectEqual(@as(u64, 1), warm.cache_hit_count);
    try std.testing.expectEqual(cold.retained_bytes, warm.retained_bytes);
}

test "twiddle source: exact work belongs only to the cold owned-cache miss" {
    const allocator = std.testing.allocator;
    var source = TwiddleSource.initOwned(allocator);
    defer source.deinit(allocator);
    var recorder = WorkRecorder{};

    _ = try source.getWithWorkRecorder(allocator, 8, &recorder);
    const expected = try work_profile.logicalM31ColdTwiddleWork(8);
    try std.testing.expectEqual(expected.field_additions, recorder.counters.field_additions);
    try std.testing.expectEqual(expected.field_multiplications, recorder.counters.field_multiplications);
    try std.testing.expectEqual(expected.field_inversions, recorder.counters.field_inversions);
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.planned_sites[@intFromEnum(work_profile.Site.cold_twiddle_construction)],
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(work_profile.Site.cold_twiddle_construction)],
    );

    _ = try source.getWithWorkRecorder(allocator, 8, &recorder);
    try std.testing.expectEqual(expected.field_additions, recorder.counters.field_additions);
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(work_profile.Site.cold_twiddle_construction)],
    );
}

test "twiddle source: borrowed views never charge a later request" {
    const allocator = std.testing.allocator;
    var tower = try M31TwiddleTower.init(allocator, 8, 1 << 20);
    defer tower.deinit(allocator);
    var source = TwiddleSource.initBorrowed(&tower);
    defer source.deinit(allocator);
    var recorder = WorkRecorder{};

    _ = try source.getWithWorkRecorder(allocator, 8, &recorder);
    try std.testing.expectEqual(@as(u64, 0), recorder.record_count);
    try std.testing.expectEqual(
        @as(u64, 0),
        recorder.planned_sites[@intFromEnum(work_profile.Site.cold_twiddle_construction)],
    );
}

test "twiddle source: returned owned slices survive source movement and map growth" {
    const allocator = std.testing.allocator;
    var source = TwiddleSource.initOwned(allocator);
    source = moveSource(source);
    defer source.deinit(allocator);

    const first = try source.get(allocator, 4);
    const first_twiddles = first.twiddles;
    const first_itwiddles = first.itwiddles;

    for (5..14) |log| _ = try source.get(allocator, @intCast(log));

    try std.testing.expectEqualSlices(M31, first_twiddles, (try source.get(allocator, 4)).twiddles);
    try std.testing.expectEqualSlices(M31, first_itwiddles, (try source.get(allocator, 4)).itwiddles);
}

fn moveSource(source: TwiddleSource) TwiddleSource {
    return source;
}

test "twiddle source: borrowed deinit leaves tower usable" {
    const allocator = std.testing.allocator;
    var tower = try M31TwiddleTower.init(allocator, 8, 1 << 20);
    defer tower.deinit(allocator);

    var source = TwiddleSource.initBorrowed(&tower);
    _ = try source.get(allocator, 6);
    source.deinit(allocator);

    const tree = try tower.view(6);
    try std.testing.expectEqual(@as(usize, 1 << 5), tree.twiddles.len);
}

test "twiddle source: reports invalid and out-of-session requests" {
    const allocator = std.testing.allocator;
    var tower = try M31TwiddleTower.init(allocator, 8, 1 << 20);
    defer tower.deinit(allocator);
    var source = TwiddleSource.initBorrowed(&tower);
    defer source.deinit(allocator);

    try std.testing.expectError(error.InvalidCircleLog, source.get(allocator, 0));
    try std.testing.expectError(error.InvalidCircleLog, source.get(allocator, 9));
    const stats = source.telemetry();
    try std.testing.expectEqual(@as(u64, 2), stats.request_count);
    try std.testing.expectEqual(@as(u64, 2), stats.rejected_request_count);
    try std.testing.expectEqual(@as(u64, 0), stats.cache_hit_count);
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var source = TwiddleSource.initOwned(allocator);
    defer source.deinit(allocator);

    _ = try source.get(allocator, 5);
    _ = try source.get(allocator, 8);
    _ = try source.get(allocator, 5);
}

test "twiddle source: owned cache cleans up on every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}
