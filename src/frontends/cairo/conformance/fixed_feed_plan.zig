//! Compile fixed-table routing once per authenticated feed, outside row loops.

const std = @import("std");
const topology = @import("../witness/feed_topology.zig");
const fixed = @import("../witness/fixed_table_bundle.zig");

pub const Key = struct { relation: u32, row: u32 };

pub const Plan = struct {
    kind: enum { range, xor, indexed },
    relation: u32,
    row_count: u32,
    columns: u32,
    widths: [31]u5 = @splat(0),
    width_count: u6 = 0,
    xor_bits: u5 = 0,
    word_count: u32,

    pub fn init(entry: fixed.Entry, feed: topology.Feed) !Plan {
        var plan: Plan = .{
            .kind = .indexed,
            .relation = feed.relation,
            .row_count = entry.row_count,
            .columns = entry.multiplicity_columns,
            .word_count = feed.words_per_instance,
        };
        if (std.mem.startsWith(u8, feed.target, "range_check_")) {
            plan.kind = .range;
            var parts = std.mem.splitScalar(u8, feed.target["range_check_".len..], '_');
            var total_bits: u32 = 0;
            while (parts.next()) |part| {
                const bits = std.fmt.parseUnsigned(u5, part, 10) catch return error.UnsupportedFixedRelation;
                if (bits == 0 or bits >= 31 or plan.width_count == plan.widths.len)
                    return error.FeedGeometryMismatch;
                total_bits += bits;
                if (total_bits > 31) return error.FeedGeometryMismatch;
                plan.widths[plan.width_count] = bits;
                plan.width_count += 1;
            }
            if (plan.width_count != feed.words_per_instance) return error.FeedGeometryMismatch;
        } else if (std.mem.startsWith(u8, feed.target, "verify_bitwise_xor_")) {
            plan.kind = .xor;
            plan.xor_bits = std.fmt.parseUnsigned(u5, feed.target["verify_bitwise_xor_".len..], 10) catch return error.UnsupportedFixedRelation;
            if (feed.words_per_instance != 3 or plan.xor_bits == 0 or plan.xor_bits >= 16)
                return error.FeedGeometryMismatch;
            if (plan.xor_bits == 12 and (entry.multiplicity_columns != 16 or entry.row_count != 1 << 20))
                return error.FixedGeometryMismatch;
        } else if (std.mem.eql(u8, feed.target, "blake_round_sigma") or
            std.mem.eql(u8, feed.target, "poseidon_round_keys") or
            std.mem.eql(u8, feed.target, "pedersen_points_table_window_bits_18") or
            std.mem.eql(u8, feed.target, "pedersen_points_table_window_bits_9"))
        {
            if (feed.words_per_instance != 1) return error.FeedGeometryMismatch;
        } else return error.UnsupportedFixedRelation;
        if (!(plan.kind == .xor and plan.xor_bits == 12) and plan.relation >= plan.columns)
            return error.InvalidMultiplicityKey;
        return plan;
    }

    pub fn key(self: Plan, words: []const u32) !Key {
        if (words.len != self.word_count) return error.FeedGeometryMismatch;
        var result: Key = .{ .relation = self.relation, .row = 0 };
        switch (self.kind) {
            .range => for (self.widths[0..self.width_count], words) |bits, word| {
                if (word >= @as(u32, 1) << bits) return error.InvalidMultiplicityKey;
                result.row = (result.row << bits) | word;
            },
            .xor => {
                if ((words[0] | words[1] | words[2]) >= @as(u32, 1) << self.xor_bits or words[2] != (words[0] ^ words[1]))
                    return error.InvalidMultiplicityKey;
                if (self.xor_bits == 12) {
                    result.relation = ((words[0] >> 10) << 2) | (words[1] >> 10);
                    result.row = ((words[0] & 0x3ff) << 10) | (words[1] & 0x3ff);
                } else result.row = (words[0] << self.xor_bits) | words[1];
            },
            .indexed => result.row = words[0],
        }
        if (result.relation >= self.columns or result.row >= self.row_count)
            return error.InvalidMultiplicityKey;
        return result;
    }

    pub fn increment(self: Plan, dense: []u32, words: []const u32) !void {
        const location = try self.key(words);
        const index = @as(usize, location.relation) * self.row_count + location.row;
        if (index >= dense.len) return error.FixedGeometryMismatch;
        dense[index] = std.math.add(u32, dense[index], 1) catch return error.MultiplicityOverflow;
    }
};
