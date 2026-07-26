//! Canonical CPU materialization of gathered Cairo witness inputs.

const std = @import("std");
const proof_plan = @import("../proof_plan.zig");

pub const Error = error{
    AllocationSizeOverflow,
    InvalidEdge,
    InvalidRowCount,
    MissingProducer,
};

pub const Producer = struct {
    label: []const u8,
    row_count: u32,
    active_rows: u32,
    words_per_row: u32,
    words: []const u32,
};

pub const Geometry = struct {
    input_width: u32,
    active_rows: u32,
    padded_rows: u32,
};

pub const GatheredInput = struct {
    allocator: std.mem.Allocator,
    storage: []u32,
    columns: usize,
    rows: usize,
    active_rows: usize,

    pub fn deinit(self: *GatheredInput) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn columnCount(self: GatheredInput) usize {
        return self.columns;
    }

    pub fn validateRowCount(self: GatheredInput, row_count: usize) Error!void {
        if (row_count != self.rows) return Error.InvalidRowCount;
    }

    pub fn realRowCount(self: GatheredInput, _: usize) !usize {
        return self.active_rows;
    }

    pub fn paddedRowCount(self: GatheredInput) Error!usize {
        return self.rows;
    }

    pub fn writeColumn(
        self: GatheredInput,
        column: usize,
        destination: []u32,
    ) Error!void {
        try self.validateRowCount(destination.len);
        if (column >= self.columns) return Error.InvalidEdge;
        @memcpy(destination, self.storage[column * self.rows ..][0..self.rows]);
    }
};

/// Mirrors `stwo_zig_witness_input_gather_resident`: producer subwords are
/// concatenated in edge order, padding repeats the first SIMD pack, and the
/// final input column enables only real gathered rows.
pub fn materialize(
    allocator: std.mem.Allocator,
    edges: []const proof_plan.ProducerEdge,
    producers: []const Producer,
    consumer_rows: u32,
) !GatheredInput {
    const geometry = try deriveGeometry(edges, producers);
    if (consumer_rows != geometry.padded_rows) return Error.InvalidRowCount;
    return materializeGeometry(allocator, edges, producers, geometry);
}

pub fn materializeDerived(
    allocator: std.mem.Allocator,
    edges: []const proof_plan.ProducerEdge,
    producers: []const Producer,
) !GatheredInput {
    return materializeGeometry(
        allocator,
        edges,
        producers,
        try deriveGeometry(edges, producers),
    );
}

/// Derives the exact gathered domain from live producer cardinalities.
pub fn deriveGeometry(
    edges: []const proof_plan.ProducerEdge,
    producers: []const Producer,
) Error!Geometry {
    if (edges.len == 0) return Error.InvalidEdge;
    const input_width = edges[0].words_per_instance;
    if (input_width == 0) return Error.InvalidEdge;
    var total_real_rows: u32 = 0;
    for (edges) |edge| {
        if (edge.words_per_instance != input_width or edge.instances == 0)
            return Error.InvalidEdge;
        const producer_index = findProducerIndex(producers, edge.producer) orelse
            return Error.MissingProducer;
        const producer = producers[producer_index];
        try validateProducer(edge, producer, input_width);
        const edge_rows = std.math.mul(u32, producer.active_rows, edge.instances) catch
            return Error.InvalidRowCount;
        total_real_rows = std.math.add(u32, total_real_rows, edge_rows) catch
            return Error.InvalidRowCount;
    }
    if (total_real_rows == 0) return Error.InvalidRowCount;
    const padded_rows = @max(
        std.math.ceilPowerOfTwo(u32, total_real_rows) catch
            return Error.AllocationSizeOverflow,
        16,
    );
    return .{
        .input_width = input_width,
        .active_rows = total_real_rows,
        .padded_rows = padded_rows,
    };
}

fn materializeGeometry(
    allocator: std.mem.Allocator,
    edges: []const proof_plan.ProducerEdge,
    producers: []const Producer,
    geometry: Geometry,
) !GatheredInput {
    const input_width = geometry.input_width;
    const consumer_rows = geometry.padded_rows;
    const columns = std.math.add(usize, input_width, 1) catch
        return Error.AllocationSizeOverflow;
    const storage_words = std.math.mul(usize, columns, consumer_rows) catch
        return Error.AllocationSizeOverflow;
    const storage = try allocator.alloc(u32, storage_words);
    errdefer allocator.free(storage);
    @memset(storage, 0);

    const Location = struct {
        edge: u32,
        producer: u32,
        instance: u32,
        row: u32,
    };
    var full = std.ArrayList(Location).empty;
    defer full.deinit(allocator);
    var remainder = std.ArrayList(Location).empty;
    defer remainder.deinit(allocator);
    for (edges, 0..) |edge, edge_index| {
        const producer_index = findProducerIndex(producers, edge.producer) orelse
            return Error.MissingProducer;
        const producer = producers[producer_index];
        const full_rows = producer.active_rows & ~@as(u32, 15);
        for (0..edge.instances) |instance| {
            for (0..full_rows) |row| try full.append(allocator, .{
                .edge = @intCast(edge_index),
                .producer = @intCast(producer_index),
                .instance = @intCast(instance),
                .row = @intCast(row),
            });
        }
        for (0..edge.instances) |instance| {
            for (full_rows..producer.active_rows) |row| try remainder.append(allocator, .{
                .edge = @intCast(edge_index),
                .producer = @intCast(producer_index),
                .instance = @intCast(instance),
                .row = @intCast(row),
            });
        }
    }
    var locations = std.ArrayList(Location).empty;
    defer locations.deinit(allocator);
    try locations.ensureTotalCapacity(allocator, consumer_rows);
    try locations.appendSlice(allocator, full.items);
    try locations.appendSlice(allocator, remainder.items);
    if (remainder.items.len != 0) {
        const packed_remainder = std.mem.alignForward(usize, remainder.items.len, 16);
        if (full.items.len + packed_remainder > consumer_rows)
            return Error.InvalidRowCount;
        while (locations.items.len < full.items.len + packed_remainder)
            locations.appendAssumeCapacity(remainder.items[0]);
    }
    if (locations.items.len == 0 or locations.items.len > consumer_rows)
        return Error.InvalidRowCount;
    while (locations.items.len < consumer_rows)
        locations.appendAssumeCapacity(locations.items[locations.items.len & 15]);

    for (locations.items, 0..) |location, row| {
        const edge = edges[location.edge];
        const producer = producers[location.producer];
        for (0..input_width) |word| {
            const source_word = edge.word_base +
                location.instance * edge.words_per_instance +
                @as(u32, @intCast(word));
            storage[word * consumer_rows + row] =
                producer.words[@as(usize, location.row) * producer.words_per_row + source_word];
        }
        storage[@as(usize, input_width) * consumer_rows + row] =
            @intFromBool(row < geometry.active_rows);
    }
    return .{
        .allocator = allocator,
        .storage = storage,
        .columns = columns,
        .rows = consumer_rows,
        .active_rows = geometry.active_rows,
    };
}

fn validateProducer(
    edge: proof_plan.ProducerEdge,
    producer: Producer,
    input_width: u32,
) Error!void {
    if (producer.row_count == 0 or producer.active_rows == 0 or
        producer.active_rows > producer.row_count or producer.words_per_row == 0 or
        producer.words.len != @as(usize, producer.row_count) * producer.words_per_row)
        return Error.InvalidEdge;
    const final_word = @as(u64, edge.word_base) +
        @as(u64, edge.instances - 1) * edge.words_per_instance +
        input_width;
    if (final_word > producer.words_per_row) return Error.InvalidEdge;
}

fn findProducerIndex(producers: []const Producer, label: []const u8) ?usize {
    for (producers, 0..) |producer, index| {
        if (std.mem.eql(u8, producer.label, label)) return index;
    }
    return null;
}

test "Cairo gathered inputs mirror resident gather padding and instance order" {
    const words = [_]u32{
        10, 11, 12, 13, 14, 15,
        20, 21, 22, 23, 24, 25,
    };
    const edges = [_]proof_plan.ProducerEdge{.{
        .producer = "source",
        .word_base = 1,
        .words_per_instance = 2,
        .instances = 2,
    }};
    const producers = [_]Producer{.{
        .label = "source",
        .row_count = 2,
        .active_rows = 2,
        .words_per_row = 6,
        .words = &words,
    }};
    var gathered = try materialize(std.testing.allocator, &edges, &producers, 16);
    defer gathered.deinit();

    var column: [16]u32 = undefined;
    try gathered.writeColumn(0, &column);
    try std.testing.expectEqualSlices(u32, &.{ 11, 21, 13, 23, 11 }, column[0..5]);
    try gathered.writeColumn(1, &column);
    try std.testing.expectEqualSlices(u32, &.{ 12, 22, 14, 24, 12 }, column[0..5]);
    try gathered.writeColumn(2, &column);
    try std.testing.expectEqualSlices(u32, &.{ 1, 1, 1, 1, 0 }, column[0..5]);
}

test "Cairo gathered inputs derive exact live geometry" {
    const words = [_]u32{ 1, 2, 3, 4, 5, 6 };
    const edges = [_]proof_plan.ProducerEdge{.{
        .producer = "source",
        .word_base = 0,
        .words_per_instance = 1,
        .instances = 3,
    }};
    const producers = [_]Producer{.{
        .label = "source",
        .row_count = 6,
        .active_rows = 6,
        .words_per_row = 1,
        .words = &words,
    }};
    const geometry = try deriveGeometry(&edges, &producers);
    try std.testing.expectEqual(@as(u32, 18), geometry.active_rows);
    try std.testing.expectEqual(@as(u32, 32), geometry.padded_rows);
    var gathered = try materializeDerived(std.testing.allocator, &edges, &producers);
    defer gathered.deinit();
    try std.testing.expectEqual(@as(usize, 32), gathered.rows);
    try std.testing.expectEqual(@as(usize, 18), gathered.active_rows);
}

test "Cairo gathered inputs place full SIMD packs before cross-instance remainders" {
    var words: [36]u32 = undefined;
    for (0..18) |row| {
        words[row * 2] = 100 + @as(u32, @intCast(row));
        words[row * 2 + 1] = 200 + @as(u32, @intCast(row));
    }
    const edges = [_]proof_plan.ProducerEdge{.{
        .producer = "source",
        .word_base = 0,
        .words_per_instance = 1,
        .instances = 2,
    }};
    const producers = [_]Producer{.{
        .label = "source",
        .row_count = 18,
        .active_rows = 18,
        .words_per_row = 2,
        .words = &words,
    }};
    var gathered = try materialize(std.testing.allocator, &edges, &producers, 64);
    defer gathered.deinit();

    var column: [64]u32 = undefined;
    try gathered.writeColumn(0, &column);
    try std.testing.expectEqualSlices(u32, &.{ 100, 101, 102, 103 }, column[0..4]);
    try std.testing.expectEqualSlices(u32, &.{ 112, 113, 114, 115 }, column[12..16]);
    try std.testing.expectEqualSlices(u32, &.{ 200, 201, 202, 203 }, column[16..20]);
    try std.testing.expectEqualSlices(u32, &.{ 212, 213, 214, 215 }, column[28..32]);
    try std.testing.expectEqualSlices(u32, &.{ 116, 117, 216, 217 }, column[32..36]);
    try std.testing.expectEqual(@as(u32, 116), column[36]);
    try std.testing.expectEqualSlices(u32, column[0..16], column[48..64]);

    try gathered.writeColumn(1, &column);
    for (column[0..36]) |value| try std.testing.expectEqual(@as(u32, 1), value);
    for (column[36..]) |value| try std.testing.expectEqual(@as(u32, 0), value);
}
