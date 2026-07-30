//! Canonical key-sorted multiset inputs for Cairo compact consumers.

const std = @import("std");
const proof_plan = @import("../proof_plan.zig");
const gathered_inputs = @import("gathered_inputs.zig");
const pool_split = @import("pool_split.zig");
const work_pool = pool_split.work_pool;

const max_tuple_words: usize = 7;

/// Smallest producer-row span worth handing to its own worker. Below this the
/// private-table and merge overhead dominates the counting itself.
const min_rows_per_worker: usize = 1 << 16;

pub const Error = error{
    AllocationSizeOverflow,
    ConflictingKey,
    EmptyInput,
    InvalidGeometry,
    InvalidRowCount,
    MultiplicityOverflow,
};

const Key = [max_tuple_words]u32;

const Row = struct {
    tuple: Key,
    multiplicity: u32,
};

pub const CompactInput = struct {
    allocator: std.mem.Allocator,
    rows: []Row,
    padded_rows: usize,
    geometry: proof_plan.CompactGeometry,

    pub fn deinit(self: *CompactInput) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn columnCount(self: CompactInput) usize {
        return self.geometry.multiplicity_slot + 1;
    }

    pub fn realRowCount(self: CompactInput, padded_rows: usize) !usize {
        try self.validateRowCount(padded_rows);
        return padded_rows;
    }

    pub fn paddedRowCount(self: CompactInput) Error!usize {
        return self.padded_rows;
    }

    pub fn validateRowCount(self: CompactInput, row_count: usize) Error!void {
        if (row_count != self.padded_rows) return Error.InvalidRowCount;
    }

    pub fn writeColumn(
        self: CompactInput,
        column: usize,
        destination: []u32,
    ) Error!void {
        try self.validateRowCount(destination.len);
        if (column >= self.columnCount()) return Error.InvalidGeometry;
        for (destination, 0..) |*value, row_index| {
            const active = row_index < self.rows.len;
            const row = self.rows[if (active) row_index else 0];
            value.* = if (column < self.geometry.tuple_words)
                row.tuple[column]
            else if (column == self.geometry.enabler_slot)
                @intFromBool(active)
            else if (column == self.geometry.iota_slot)
                @intCast(row_index)
            else if (column == self.geometry.multiplicity_slot)
                if (active) row.multiplicity else 0
            else
                return Error.InvalidGeometry;
        }
    }
};

pub fn materialize(
    allocator: std.mem.Allocator,
    geometry: proof_plan.CompactGeometry,
    edges: []const proof_plan.ProducerEdge,
    producers: []const gathered_inputs.Producer,
    consumer_rows: u32,
) !CompactInput {
    return materializeInternal(
        allocator,
        geometry,
        edges,
        producers,
        consumer_rows,
    );
}

/// Materializes and sizes a compact consumer from its live unique key set.
pub fn materializeDerived(
    allocator: std.mem.Allocator,
    geometry: proof_plan.CompactGeometry,
    edges: []const proof_plan.ProducerEdge,
    producers: []const gathered_inputs.Producer,
) !CompactInput {
    return materializeInternal(allocator, geometry, edges, producers, null);
}

fn materializeInternal(
    allocator: std.mem.Allocator,
    geometry: proof_plan.CompactGeometry,
    edges: []const proof_plan.ProducerEdge,
    producers: []const gathered_inputs.Producer,
    expected_rows: ?u32,
) !CompactInput {
    if (edges.len == 0 or edges.len != producers.len or geometry.tuple_words == 0 or
        geometry.tuple_words > max_tuple_words or geometry.key_words == 0 or
        geometry.key_words > geometry.tuple_words or
        geometry.multiplicity_slot + 1 != geometry.tuple_words + 3 or
        geometry.enabler_slot != geometry.tuple_words or
        geometry.iota_slot != geometry.tuple_words + 1)
        return Error.InvalidGeometry;

    var widest_rows: usize = 0;
    for (edges, producers) |edge, producer| {
        if (!std.mem.eql(u8, edge.producer, producer.label) or
            edge.words_per_instance < geometry.tuple_words or edge.instances == 0 or
            producer.active_rows == 0 or producer.active_rows > producer.row_count or
            producer.words.len != @as(usize, producer.row_count) * producer.words_per_row)
            return Error.InvalidGeometry;
        const final_word = @as(u64, edge.word_base) +
            @as(u64, edge.instances - 1) * edge.words_per_instance +
            geometry.tuple_words;
        if (final_word > producer.words_per_row) return Error.InvalidGeometry;
        widest_rows = @max(widest_rows, producer.active_rows);
    }

    var counting = try Counting.init(geometry, edges, producers, widest_rows);
    defer counting.deinit();
    try counting.run();
    const multiplicities = counting.merged();

    if (multiplicities.count() == 0) return Error.EmptyInput;
    const rows = try allocator.alloc(Row, multiplicities.count());
    errdefer allocator.free(rows);
    var iterator = multiplicities.iterator();
    var row_index: usize = 0;
    while (iterator.next()) |entry| : (row_index += 1) rows[row_index] = .{
        .tuple = entry.key_ptr.*,
        .multiplicity = entry.value_ptr.*,
    };
    std.mem.sortUnstable(Row, rows, geometry.key_words, lessThanKey);
    for (rows[1..], rows[0 .. rows.len - 1]) |current, previous| {
        if (keyEqual(current.tuple, previous.tuple, geometry.key_words) and
            !std.mem.eql(u32, &current.tuple, &previous.tuple))
            return Error.ConflictingKey;
    }
    const padded_rows = @max(
        std.math.ceilPowerOfTwo(usize, rows.len) catch
            return Error.AllocationSizeOverflow,
        16,
    );
    if (expected_rows) |expected| {
        if (expected < 16 or !std.math.isPowerOfTwo(expected))
            return Error.InvalidGeometry;
        if (padded_rows != expected) return Error.InvalidRowCount;
    }
    return .{
        .allocator = allocator,
        .rows = rows,
        .padded_rows = padded_rows,
        .geometry = geometry,
    };
}

const Histogram = std.AutoHashMapUnmanaged(Key, u32);

/// One worker's private tuple histogram over a disjoint producer-row span.
///
/// Every worker sees every edge and every instance, but only the rows in its
/// own span, so each `(edge, instance, producer_row)` triple is counted exactly
/// once across the pool. Counts are `u32` additions, so the per-worker partial
/// histograms merge exactly and the merged result is independent of the span
/// decomposition and of completion order.
const CountWorker = struct {
    geometry: proof_plan.CompactGeometry,
    edges: []const proof_plan.ProducerEdge,
    producers: []const gathered_inputs.Producer,
    index: usize,
    worker_count: usize,
    arena: std.heap.ArenaAllocator,
    map: Histogram,
    failure: ?anyerror,

    pub fn run(self: *CountWorker) void {
        self.accumulate() catch |err| {
            self.failure = err;
        };
    }

    fn accumulate(self: *CountWorker) !void {
        const scratch = self.arena.allocator();
        const tuple_words: usize = self.geometry.tuple_words;
        for (self.edges, self.producers) |edge, producer| {
            const rows = pool_split.span(producer.active_rows, self.index, self.worker_count);
            if (rows.isEmpty()) continue;
            const words_per_row: usize = producer.words_per_row;
            for (0..edge.instances) |instance| {
                const base = @as(usize, edge.word_base) +
                    instance * @as(usize, edge.words_per_instance);
                for (rows.start..rows.end) |producer_row| {
                    var key = [_]u32{0} ** max_tuple_words;
                    @memcpy(
                        key[0..tuple_words],
                        producer.words[producer_row * words_per_row + base ..][0..tuple_words],
                    );
                    const result = try self.map.getOrPut(scratch, key);
                    if (!result.found_existing) result.value_ptr.* = 0;
                    result.value_ptr.* = std.math.add(u32, result.value_ptr.*, 1) catch
                        return Error.MultiplicityOverflow;
                }
            }
        }
    }
};

/// Pool-split tuple counting with a serial fallback when no pool exists.
const Counting = struct {
    slots: [work_pool.MAX_WORKERS]CountWorker,
    worker_count: usize,

    fn init(
        geometry: proof_plan.CompactGeometry,
        edges: []const proof_plan.ProducerEdge,
        producers: []const gathered_inputs.Producer,
        widest_rows: usize,
    ) !Counting {
        const worker_count = pool_split.workerCount(.{
            .rows = widest_rows,
            .min_rows_per_worker = min_rows_per_worker,
        });
        var counting = Counting{ .slots = undefined, .worker_count = worker_count };
        for (counting.slots[0..worker_count], 0..) |*slot, index| slot.* = .{
            .geometry = geometry,
            .edges = edges,
            .producers = producers,
            .index = index,
            .worker_count = worker_count,
            .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator),
            .map = .empty,
            .failure = null,
        };
        return counting;
    }

    fn deinit(self: *Counting) void {
        for (self.slots[0..self.worker_count]) |*slot| slot.arena.deinit();
        self.* = undefined;
    }

    fn run(self: *Counting) !void {
        try pool_split.dispatch(CountWorker, self.slots[0..self.worker_count]);
        const scratch = self.slots[0].arena.allocator();
        for (self.slots[1..self.worker_count]) |*slot| {
            var iterator = slot.map.iterator();
            while (iterator.next()) |entry| {
                const result = try self.slots[0].map.getOrPut(scratch, entry.key_ptr.*);
                if (!result.found_existing) result.value_ptr.* = 0;
                result.value_ptr.* = std.math.add(u32, result.value_ptr.*, entry.value_ptr.*) catch
                    return Error.MultiplicityOverflow;
            }
        }
    }

    fn merged(self: *Counting) *const Histogram {
        return &self.slots[0].map;
    }
};

fn lessThanKey(key_words: u32, lhs: Row, rhs: Row) bool {
    for (0..key_words) |word| {
        if (lhs.tuple[word] != rhs.tuple[word])
            return lhs.tuple[word] < rhs.tuple[word];
    }
    return false;
}

fn keyEqual(lhs: Key, rhs: Key, key_words: u32) bool {
    return std.mem.eql(u32, lhs[0..key_words], rhs[0..key_words]);
}

test "Cairo compact inputs merge tuples, sort by key, and pad with the first row" {
    const words = [_]u32{
        2, 20, 200,
        1, 10, 100,
        2, 20, 200,
        1, 10, 100,
    };
    const edges = [_]proof_plan.ProducerEdge{.{
        .producer = "source",
        .word_base = 0,
        .words_per_instance = 3,
        .instances = 1,
    }};
    const producers = [_]gathered_inputs.Producer{.{
        .label = "source",
        .row_count = 4,
        .active_rows = 4,
        .words_per_row = 3,
        .words = &words,
    }};
    const geometry = proof_plan.CompactGeometry{
        .edges = &edges,
        .tuple_words = 3,
        .key_words = 2,
        .enabler_slot = 3,
        .iota_slot = 4,
        .multiplicity_slot = 5,
    };
    var compact = try materialize(
        std.testing.allocator,
        geometry,
        &edges,
        &producers,
        16,
    );
    defer compact.deinit();
    try std.testing.expectEqual(@as(usize, 2), compact.rows.len);
    try std.testing.expectEqual(@as(usize, 16), try compact.realRowCount(16));

    var column: [16]u32 = undefined;
    try compact.writeColumn(0, &column);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 1 }, column[0..3]);
    try compact.writeColumn(5, &column);
    try std.testing.expectEqualSlices(u32, &.{ 2, 2, 0 }, column[0..3]);

    var derived = try materializeDerived(
        std.testing.allocator,
        geometry,
        &edges,
        &producers,
    );
    defer derived.deinit();
    try std.testing.expectEqual(@as(usize, 16), derived.padded_rows);
    try std.testing.expectEqual(@as(usize, 2), derived.rows.len);
}
