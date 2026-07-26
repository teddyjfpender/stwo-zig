//! Fixture-independent accumulation for Cairo fixed-table multiplicities.

const std = @import("std");
const recorded_trace = @import("recorded_trace.zig");
const feed_topology = @import("../witness/feed_topology.zig");
const fixed_table_bundle = @import("../witness/fixed_table_bundle.zig");

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

    pub fn increment(self: *Tables, label: []const u8, relation: u32, row: u32) !void {
        const table = self.find(label) orelse return error.MissingFixedTable;
        if (relation >= table.entry.multiplicity_columns or row >= table.entry.row_count)
            return error.InvalidMultiplicityKey;
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
        const index = @as(usize, relation) * table.entry.row_count + row;
        table.dense.?[index] = std.math.add(u32, table.dense.?[index], 1) catch
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

    /// Routes every exact generated producer through the compiler-derived
    /// topology. Non-fixed destinations are owned by the memory/dynamic lanes.
    pub fn route(
        self: *Tables,
        topology: feed_topology.Loaded,
        producers: []const recorded_trace.ProducerOutput,
    ) !void {
        for (producers) |producer| {
            const component = topology.find(producer.label) orelse
                return error.MissingProducerTopology;
            if (component.sub_words_per_row != producer.words_per_row or
                producer.active_rows > producer.row_count or
                producer.words.len != @as(usize, producer.row_count) * producer.words_per_row)
                return error.FeedGeometryMismatch;
            for (component.feeds) |feed| {
                const table = self.find(feed.target) orelse continue;
                for (0..producer.active_rows) |row| {
                    const base = @as(usize, row) * producer.words_per_row + feed.word_base;
                    const words = producer.words[base .. base + feed.words_per_instance];
                    try self.routeOne(table.entry.*, feed, words);
                }
            }
        }
    }

    fn routeOne(
        self: *Tables,
        entry: fixed_table_bundle.Entry,
        feed: feed_topology.Feed,
        words: []const u32,
    ) !void {
        if (std.mem.startsWith(u8, feed.target, "range_check_")) {
            const key = try rangeKey(feed.target["range_check_".len..], words);
            try self.increment(feed.target, feed.relation, key);
            return;
        }
        if (std.mem.startsWith(u8, feed.target, "verify_bitwise_xor_")) {
            const bits = std.fmt.parseUnsigned(
                u5,
                feed.target["verify_bitwise_xor_".len..],
                10,
            ) catch return error.UnsupportedFixedRelation;
            if (words.len != 3 or bits == 0 or bits >= 16)
                return error.FeedGeometryMismatch;
            const limit = @as(u32, 1) << bits;
            if ((words[0] | words[1] | words[2]) >= limit or
                words[2] != (words[0] ^ words[1]))
                return error.InvalidMultiplicityKey;
            if (bits == 12) {
                if (entry.multiplicity_columns != 16 or entry.row_count != 1 << 20)
                    return error.FixedGeometryMismatch;
                const relation = ((words[0] >> 10) << 2) | (words[1] >> 10);
                const row = ((words[0] & 0x3ff) << 10) | (words[1] & 0x3ff);
                try self.increment(feed.target, relation, row);
            } else {
                const row = (words[0] << bits) | words[1];
                try self.increment(feed.target, feed.relation, row);
            }
            return;
        }
        if (std.mem.eql(u8, feed.target, "blake_round_sigma") or
            std.mem.eql(u8, feed.target, "poseidon_round_keys") or
            std.mem.eql(u8, feed.target, "pedersen_points_table_window_bits_18") or
            std.mem.eql(u8, feed.target, "pedersen_points_table_window_bits_9"))
        {
            if (words.len != 1) return error.FeedGeometryMismatch;
            try self.increment(feed.target, feed.relation, words[0]);
            return;
        }
        return error.UnsupportedFixedRelation;
    }
};

fn rangeKey(shape: []const u8, words: []const u32) !u32 {
    var parts = std.mem.splitScalar(u8, shape, '_');
    var key: u32 = 0;
    var word_index: usize = 0;
    while (parts.next()) |part| {
        const bits = std.fmt.parseUnsigned(u5, part, 10) catch
            return error.UnsupportedFixedRelation;
        if (bits == 0 or bits >= 31 or word_index == words.len)
            return error.FeedGeometryMismatch;
        const limit = @as(u32, 1) << bits;
        if (words[word_index] >= limit) return error.InvalidMultiplicityKey;
        key = std.math.shl(u32, key, bits);
        key = std.math.add(u32, key, words[word_index]) catch
            return error.InvalidMultiplicityKey;
        word_index += 1;
    }
    if (word_index != words.len) return error.FeedGeometryMismatch;
    return key;
}

test "Cairo multiplicity routing derives composite and XOR keys" {
    try std.testing.expectEqual(@as(u32, 0b101_010101_111000), try rangeKey(
        "3_6_6",
        &.{ 0b101, 0b010101, 0b111000 },
    ));
    try std.testing.expectError(error.InvalidMultiplicityKey, rangeKey("4_3", &.{ 16, 0 }));
    try std.testing.expectError(error.FeedGeometryMismatch, rangeKey("4_3", &.{1}));
}
