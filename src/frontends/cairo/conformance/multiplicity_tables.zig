//! Fixture-independent accumulation for Cairo fixed-table multiplicities.

const std = @import("std");
const producer_output = @import("../witness/producer_output.zig");
const feed_topology = @import("../witness/feed_topology.zig");
const fixed_table_bundle = @import("../witness/fixed_table_bundle.zig");
const fixed_feed_plan = @import("fixed_feed_plan.zig");
const pool_split = @import("../witness/pool_split.zig");

const max_fixed_rows: u32 = 1 << 24;
const max_dense_words: usize = 1 << 27;

pub const Table = struct {
    entry: *const fixed_table_bundle.Entry,
    dense: ?[]u32 = null,
};

pub const Tables = struct {
    allocator: std.mem.Allocator,
    items: []Table,
    dense_words: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        fixed: *const fixed_table_bundle.Bundle,
    ) !Tables {
        const items = try allocator.alloc(Table, fixed.entries.len);
        errdefer allocator.free(items);
        for (fixed.entries, items, 0..) |*entry, *item, index| {
            if (entry.row_count == 0 or entry.row_count > max_fixed_rows or
                entry.multiplicity_columns == 0)
                return error.GeometryTooLarge;
            for (fixed.entries[0..index]) |previous| {
                if (std.mem.eql(u8, previous.component, entry.component))
                    return error.DuplicateFixedTable;
            }
            item.* = .{ .entry = entry };
        }
        return .{ .allocator = allocator, .items = items };
    }

    pub fn deinit(self: *Tables) void {
        for (self.items) |item| {
            if (item.dense) |dense| self.allocator.free(dense);
        }
        self.allocator.free(self.items);
        self.* = undefined;
    }

    pub fn find(self: *Tables, label: []const u8) ?*Table {
        for (self.items) |*item| {
            if (std.mem.eql(u8, item.entry.component, label)) return item;
        }
        return null;
    }

    /// Materializes a table's dense storage, charging the shared budget exactly
    /// as the first `increment` would. Parallel accumulators call this once, in
    /// serial order, at the point their first increment would have allocated —
    /// the dense-word budget is the one order-sensitive part of this structure.
    pub fn reserve(self: *Tables, label: []const u8) ![]u32 {
        const table = self.find(label) orelse return error.MissingFixedTable;
        if (table.dense == null) {
            const words = std.math.mul(
                usize,
                table.entry.multiplicity_columns,
                table.entry.row_count,
            ) catch return error.AllocationSizeOverflow;
            if (words > max_dense_words or self.dense_words > max_dense_words - words)
                return error.GeometryTooLarge;
            table.dense = try self.allocator.alloc(u32, words);
            @memset(table.dense.?, 0);
            self.dense_words += words;
        }
        return table.dense.?;
    }

    pub fn increment(self: *Tables, label: []const u8, relation: u32, row: u32) !void {
        const table = self.find(label) orelse return error.MissingFixedTable;
        if (relation >= table.entry.multiplicity_columns or row >= table.entry.row_count)
            return error.InvalidMultiplicityKey;
        const row_count = table.entry.row_count;
        const dense = try self.reserve(label);
        const index = @as(usize, relation) * row_count + row;
        dense[index] = std.math.add(u32, dense[index], 1) catch
            return error.MultiplicityOverflow;
    }

    pub fn column(
        self: *Tables,
        label: []const u8,
        relation: u32,
        zeros: []const u32,
    ) ![]const u32 {
        const table = self.find(label) orelse return error.MissingFixedTable;
        if (relation >= table.entry.multiplicity_columns or zeros.len < table.entry.row_count)
            return error.FixedGeometryMismatch;
        if (table.dense) |dense| {
            const start = @as(usize, relation) * table.entry.row_count;
            return dense[start .. start + table.entry.row_count];
        }
        return zeros[0..table.entry.row_count];
    }

    pub fn value(
        self: *Tables,
        label: []const u8,
        relation: u32,
        row: usize,
    ) !u32 {
        const table = self.find(label) orelse return error.MissingFixedTable;
        if (relation >= table.entry.multiplicity_columns or row >= table.entry.row_count)
            return error.FixedGeometryMismatch;
        if (table.dense) |dense|
            return dense[@as(usize, relation) * table.entry.row_count + row];
        return 0;
    }

    /// Routes every exact generated producer through the compiler-derived
    /// topology. Non-fixed destinations are owned by the memory/dynamic lanes.
    pub fn route(
        self: *Tables,
        topology: feed_topology.Loaded,
        producers: []const producer_output.ProducerOutput,
    ) !void {
        var feeds: std.ArrayList(PreparedFeed) = .empty;
        defer feeds.deinit(self.allocator);
        var active_rows: usize = 0;
        for (producers) |producer| {
            const component = topology.find(producer.label) orelse
                return error.MissingProducerTopology;
            if (component.sub_words_per_row != producer.words_per_row or
                producer.active_rows > producer.row_count or
                producer.words.len != @as(usize, producer.row_count) * producer.words_per_row)
                return error.FeedGeometryMismatch;
            for (component.feeds) |feed| {
                const table = self.find(feed.target) orelse continue;
                if (producer.active_rows == 0) continue;
                if (feed.word_base > producer.words_per_row or
                    feed.words_per_instance > producer.words_per_row - feed.word_base)
                    return error.FeedGeometryMismatch;
                const plan = try fixed_feed_plan.Plan.init(table.entry.*, feed);
                // Reserve in source order so admission still uses one shared
                // dense-word budget. Workers never allocate private histograms.
                _ = try self.reserve(feed.target);
                try feeds.append(self.allocator, .{
                    .table_index = (@intFromPtr(table) - @intFromPtr(self.items.ptr)) / @sizeOf(Table),
                    .plan = plan,
                    .words = producer.words,
                    .rows = producer.active_rows,
                    .stride = producer.words_per_row,
                    .word_base = feed.word_base,
                });
                active_rows = std.math.add(usize, active_rows, producer.active_rows) catch
                    return error.AllocationSizeOverflow;
            }
        }
        try accumulate(self.allocator, self.items, feeds.items, active_rows);
    }
};

const PreparedFeed = struct {
    table_index: usize,
    plan: fixed_feed_plan.Plan,
    words: []const u32,
    rows: usize,
    stride: usize,
    word_base: usize,
};

const TableWork = struct {
    tables: []const Table,
    feeds: []const PreparedFeed,
    worker_index: usize,
    worker_count: usize,
    parallel_tables: []const bool,
    profile_tables: bool,
    failure: ?anyerror = null,

    pub fn run(self: *TableWork) void {
        var index = self.worker_index;
        while (index < self.tables.len) : (index += self.worker_count) {
            if (self.parallel_tables[index]) continue;
            const dense = self.tables[index].dense orelse continue;
            var timer = if (self.profile_tables) std.time.Timer.start() catch null else null;
            var feed_rows: usize = 0;
            for (self.feeds) |feed| {
                if (feed.table_index != index) continue;
                feed_rows += feed.rows;
                for (0..feed.rows) |row| {
                    const base = row * feed.stride + feed.word_base;
                    feed.plan.increment(dense, feed.words[base..][0..feed.plan.word_count]) catch |err| {
                        self.failure = err;
                        return;
                    };
                }
            }
            if (timer) |*running| std.log.info(
                "Cairo fixed table {s}: {d} feed rows, {d} destination words, {d:.3} ms",
                .{ self.tables[index].entry.component, feed_rows, dense.len, @as(f64, @floatFromInt(running.read())) / std.time.ns_per_ms },
            );
        }
    }
};

const AtomicTask = struct { feed_index: usize, begin: usize, end: usize };
const AtomicWork = struct {
    tables: []const Table,
    feeds: []const PreparedFeed,
    tasks: []const AtomicTask,
    next: *std.atomic.Value(usize),
    failure: ?anyerror = null,

    pub fn run(self: *AtomicWork) void {
        while (true) {
            const task_index = self.next.fetchAdd(1, .monotonic);
            if (task_index >= self.tasks.len) return;
            const task = self.tasks[task_index];
            const feed = self.feeds[task.feed_index];
            const dense = self.tables[feed.table_index].dense orelse {
                self.failure = error.FixedGeometryMismatch;
                return;
            };
            // Small keys repeat in every multiplicity relation. Coalesce a
            // bounded prefix of each relation, keeping hot bins from bouncing
            // between cores without replicating a large table.
            const cached_rows = 256;
            const cached_relations = 16;
            var small_counts: [cached_rows * cached_relations]u32 = @splat(0);
            for (task.begin..task.end) |row| {
                const base = row * feed.stride + feed.word_base;
                const key = feed.plan.key(feed.words[base..][0..feed.plan.word_count]) catch |err| {
                    self.failure = err;
                    return;
                };
                const index = @as(usize, key.relation) * feed.plan.row_count + key.row;
                if (index >= dense.len) {
                    self.failure = error.FixedGeometryMismatch;
                    return;
                }
                if (key.row < cached_rows and key.relation < cached_relations)
                    small_counts[@as(usize, key.relation) * cached_rows + key.row] += 1
                else
                    atomicAddChecked(&dense[index], 1) catch |err| {
                        self.failure = err;
                        return;
                    };
            }
            for (0..@min(feed.plan.columns, cached_relations)) |relation|
                for (0..@min(feed.plan.row_count, cached_rows)) |row| {
                    const count = small_counts[relation * cached_rows + row];
                    if (count == 0) continue;
                    atomicAddChecked(&dense[relation * feed.plan.row_count + row], count) catch |err| {
                        self.failure = err;
                        return;
                    };
                };
        }
    }
};

fn atomicAddChecked(counter: *u32, count: u32) !void {
    const previous = @atomicRmw(u32, counter, .Add, count, .monotonic);
    if (previous > std.math.maxInt(u32) - count) return error.MultiplicityOverflow;
}

fn accumulateAtomic(tables: []const Table, feeds: []const PreparedFeed, tasks: []const AtomicTask, worker_count: usize) !void {
    if (tasks.len == 0) return;
    var next = std.atomic.Value(usize).init(0);
    var workers: [pool_split.work_pool.MAX_WORKERS]AtomicWork = undefined;
    for (workers[0..worker_count]) |*worker| worker.* = .{
        .tables = tables,
        .feeds = feeds,
        .tasks = tasks,
        .next = &next,
    };
    try pool_split.dispatch(AtomicWork, workers[0..worker_count]);
}

/// Small tables retain one writer. Large feeds use shared atomic counters over
/// bounded row tasks, preventing one huge table from serializing the whole
/// stage. Both routes own exactly one dense histogram per table.
fn accumulate(allocator: std.mem.Allocator, tables: []const Table, feeds: []const PreparedFeed, rows: usize) !void {
    if (feeds.len == 0) return;
    const pool_workers = pool_split.workerCount(.{
        .rows = rows,
        .min_rows_per_worker = 1 << 14,
    });
    const parallel_tables = try allocator.alloc(bool, tables.len);
    defer allocator.free(parallel_tables);
    @memset(parallel_tables, false);
    for (tables, 0..) |table, index| {
        const dense = table.dense orelse continue;
        if (pool_workers <= 1 or dense.len < 1 << 16) continue;
        var table_rows: usize = 0;
        for (feeds) |feed| if (feed.table_index == index) {
            table_rows = std.math.add(usize, table_rows, feed.rows) catch return error.AllocationSizeOverflow;
        };
        parallel_tables[index] = table_rows >= 1 << 22;
    }
    var tasks: std.ArrayList(AtomicTask) = .empty;
    defer tasks.deinit(allocator);
    for (feeds, 0..) |feed, index| {
        if (!parallel_tables[feed.table_index]) continue;
        var begin: usize = 0;
        while (begin < feed.rows) {
            const end = begin + @min(@as(usize, 1 << 18), feed.rows - begin);
            try tasks.append(allocator, .{ .feed_index = index, .begin = begin, .end = end });
            begin = end;
        }
    }
    const worker_count = @min(tables.len, pool_workers);
    const profile_tables = std.posix.getenv("STWO_CAIRO_PROFILE_FIXED_TABLES") != null;
    var work: [pool_split.work_pool.MAX_WORKERS]TableWork = undefined;
    for (work[0..worker_count], 0..) |*item, index| item.* = .{
        .tables = tables,
        .feeds = feeds,
        .worker_index = index,
        .worker_count = worker_count,
        .parallel_tables = parallel_tables,
        .profile_tables = profile_tables,
    };
    try pool_split.dispatch(TableWork, work[0..worker_count]);
    var timer = if (profile_tables) std.time.Timer.start() catch null else null;
    try accumulateAtomic(tables, feeds, tasks.items, @min(pool_workers, tasks.items.len));
    if (timer) |*running| std.log.info(
        "Cairo fixed atomic scatter: {d} bounded tasks over {d} workers, {d:.3} ms",
        .{ tasks.items.len, @min(pool_workers, tasks.items.len), @as(f64, @floatFromInt(running.read())) / std.time.ns_per_ms },
    );
}

test "Cairo fixed feed parallel table ownership preserves collisions without replicas" {
    const allocator = std.testing.allocator;
    const row_count = (1 << 16) + 1;
    const words = try allocator.alloc(u32, row_count);
    defer allocator.free(words);
    for (words, 0..) |*word, row| word.* = @intCast((row * 5 + 3) % 8);
    const plan = fixed_feed_plan.Plan{
        .kind = .indexed,
        .relation = 0,
        .row_count = 8,
        .columns = 1,
        .word_count = 1,
    };
    const feeds = [_]PreparedFeed{
        .{ .table_index = 0, .plan = plan, .words = words, .rows = row_count, .stride = 1, .word_base = 0 },
        .{ .table_index = 1, .plan = plan, .words = words, .rows = row_count, .stride = 1, .word_base = 0 },
        .{ .table_index = 0, .plan = plan, .words = words, .rows = row_count, .stride = 1, .word_base = 0 },
        .{ .table_index = 2, .plan = plan, .words = words, .rows = row_count, .stride = 1, .word_base = 0 },
    };
    var histograms = [_][8]u32{[_]u32{0} ** 8} ** 3;
    const entry: fixed_table_bundle.Entry = .{
        .component = @constCast("blake_round_sigma"),
        .log_size = 3,
        .row_count = 8,
        .multiplicity_columns = 1,
        .trace_multiplicity_columns = &.{},
        .preprocessed_sources = &.{},
        .lookup_descriptors = &.{},
    };
    var tables: [3]Table = undefined;
    for (&tables, &histograms) |*table, *histogram| table.* = .{ .entry = &entry, .dense = histogram };
    var pool: pool_split.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .backing_allocator = allocator });
    defer pool.deinit();
    var binding = try pool_split.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try accumulate(allocator, &tables, &feeds, row_count * feeds.len);
    var expected = [_]u32{0} ** 8;
    for (words) |word| expected[word] += 1;
    for (expected, 0..) |count, key| {
        try std.testing.expectEqual(2 * count, histograms[0][key]);
        try std.testing.expectEqual(count, histograms[1][key]);
        try std.testing.expectEqual(count, histograms[2][key]);
    }
    // Checked arithmetic still propagates from a helper thread after joining.
    histograms[2][words[0]] = std.math.maxInt(u32);
    try std.testing.expectError(error.MultiplicityOverflow, accumulate(allocator, &tables, &feeds, row_count * feeds.len));
    words[0] = 8;
    try std.testing.expectError(error.InvalidMultiplicityKey, accumulate(allocator, &tables, &feeds, row_count * feeds.len));
}

test "Cairo fixed atomic scatter preserves shared collisions and rejects overflow" {
    const allocator = std.testing.allocator;
    const row_count = (1 << 16) + 1;
    const words = try allocator.alloc(u32, row_count);
    defer allocator.free(words);
    for (words, 0..) |*word, row| {
        const bin = row % 16;
        word.* = @intCast(if (bin < 8) bin else bin - 8 + 256);
    }
    const plan = fixed_feed_plan.Plan{
        .kind = .indexed,
        .relation = 0,
        .row_count = 512,
        .columns = 2,
        .word_count = 1,
    };
    var second_relation = plan;
    second_relation.relation = 1;
    const feeds = [_]PreparedFeed{
        .{ .table_index = 0, .plan = plan, .words = words, .rows = row_count, .stride = 1, .word_base = 0 },
        .{ .table_index = 0, .plan = plan, .words = words, .rows = row_count, .stride = 1, .word_base = 0 },
        .{ .table_index = 1, .plan = second_relation, .words = words, .rows = row_count, .stride = 1, .word_base = 0 },
    };
    const tasks = [_]AtomicTask{
        .{ .feed_index = 0, .begin = 0, .end = row_count },
        .{ .feed_index = 1, .begin = 0, .end = row_count },
        .{ .feed_index = 2, .begin = 0, .end = row_count },
    };
    var histograms = [_][1024]u32{[_]u32{0} ** 1024} ** 2;
    const entry: fixed_table_bundle.Entry = .{
        .component = @constCast("blake_round_sigma"),
        .log_size = 9,
        .row_count = 512,
        .multiplicity_columns = 2,
        .trace_multiplicity_columns = &.{},
        .preprocessed_sources = &.{},
        .lookup_descriptors = &.{},
    };
    var tables: [2]Table = undefined;
    for (&tables, &histograms) |*table, *histogram| table.* = .{ .entry = &entry, .dense = histogram };
    var pool: pool_split.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .backing_allocator = allocator });
    defer pool.deinit();
    var binding = try pool_split.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try accumulateAtomic(&tables, &feeds, &tasks, 3);
    var expected = [_]u32{0} ** 512;
    for (words) |word| expected[word] += 1;
    for (expected, 0..) |count, key| {
        try std.testing.expectEqual(2 * count, histograms[0][key]);
        try std.testing.expectEqual(count, histograms[1][512 + key]);
        try std.testing.expectEqual(@as(u32, 0), histograms[0][512 + key]);
        try std.testing.expectEqual(@as(u32, 0), histograms[1][key]);
    }
    histograms[0][0] = std.math.maxInt(u32);
    try std.testing.expectError(error.MultiplicityOverflow, accumulateAtomic(&tables, &feeds, &tasks, 3));
    @memset(&histograms[0], 0);
    @memset(&histograms[1], 0);
    words[0] = 512;
    try std.testing.expectError(error.InvalidMultiplicityKey, accumulateAtomic(&tables, &feeds, &tasks, 3));
}
