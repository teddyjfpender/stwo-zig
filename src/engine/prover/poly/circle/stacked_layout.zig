//! Deterministic layout for one lifted commitment tree. Both ends derive the
//! layout from the original, admitted column geometry. No proof supplies indices.
const std = @import("std");
const core = @import("stwo_core");
const max_log = core.poly.circle.domain.MAX_CIRCLE_DOMAIN_LOG_SIZE;
const Allocator = std.mem.Allocator;

pub const Group = struct {
    first: usize,
    source_log: u32,
    log_width: u5,

    pub fn targetLog(self: Group) u32 {
        return self.source_log + self.log_width;
    }

    /// Mask shifts use the original AIR domain. A packed commitment may
    /// require a taller FRI domain; it only changes the query projection.
    pub fn lift(self: Group, air_log: u32, fri_log: u32) !Lift {
        if (self.source_log == 0 or self.source_log > air_log or air_log > fri_log or
            fri_log > max_log or self.log_width > fri_log - self.source_log) return error.InvalidStackShape;
        return .{ .source_doublings = air_log - self.source_log, .packed_doublings = fri_log - self.targetLog() };
    }
};

pub const Lift = struct {
    source_doublings: u32,
    packed_doublings: u32,

    /// The input already includes the AIR mask shift on the global domain.
    pub fn samplePoint(self: Lift, shifted: core.circle.CirclePoint(core.fields.om31.OM31)) @TypeOf(shifted) {
        return shifted.repeatedDouble(self.source_doublings);
    }

    pub fn queryPoint(self: Lift, query: core.circle.CirclePointM31) core.circle.CirclePointM31 {
        return query.repeatedDouble(self.packed_doublings);
    }
};

pub const Layout = struct {
    order: []const usize,
    groups: []const Group,

    pub fn members(self: Layout, g: Group) []const usize {
        return self.order[g.first..][0 .. @as(usize, 1) << g.log_width];
    }

    /// The native prefixed BLAKE2s leaf starts from its precomputed chaining
    /// value. The opened words cost one compression per block of 16 words.
    pub fn rowBlocks(words: usize) usize {
        return words / 16 + @intFromBool(words % 16 != 0);
    }

    /// null selects the original tree and its original single-row openings.
    /// Width is an experiment input until a production policy is admitted.
    pub fn init(a: Allocator, logs: []const u32, masks: []const []const i32, height: u32, max_width: usize) !?Layout {
        if (height == 0 or height > max_log or logs.len != masks.len or max_width < 2 or !std.math.isPowerOfTwo(max_width) or
            std.math.log2_int(usize, max_width) >= max_log) return error.InvalidStackShape;
        var lowest: u32 = max_log;
        for (logs) |log| {
            if (log == 0 or log > height) return error.InvalidStackShape;
            lowest = @min(lowest, log);
        }
        if (height <= lowest or rowBlocks(logs.len) <= 2) return null;
        const order = try a.alloc(usize, logs.len);
        var owned = false;
        defer if (!owned) a.free(order);
        for (order, 0..) |*v, i| v.* = i;
        const keys = Keys{ .logs = logs, .masks = masks };
        std.mem.sort(usize, order, keys, Keys.less);
        var groups: std.ArrayList(Group) = .empty;
        defer groups.deinit(a);
        var at: usize = 0;
        while (at < order.len) {
            const first = order[at];
            const h = logs[first];
            const limit = @min(max_width, @as(usize, 1) << @intCast(height - h));
            var end = at + 1;
            while (end < order.len and keys.same(first, order[end])) : (end += 1) {}
            while (at < end) {
                const log_width: u5 = @intCast(std.math.log2_int(usize, @min(end - at, limit)));
                try groups.append(a, .{ .first = at, .source_log = h, .log_width = log_width });
                at += @as(usize, 1) << log_width;
            }
        }
        if (2 * rowBlocks(groups.items.len) >= rowBlocks(logs.len)) return null;
        const result = try groups.toOwnedSlice(a);
        owned = true;
        return .{ .order = order, .groups = result };
    }

    pub fn deinit(self: *Layout, a: Allocator) void {
        a.free(self.groups);
        a.free(self.order);
        self.* = undefined;
    }
};

const Keys = struct {
    logs: []const u32,
    masks: []const []const i32,

    fn same(self: Keys, a: usize, b: usize) bool {
        return self.logs[a] == self.logs[b] and std.mem.eql(i32, self.masks[a], self.masks[b]);
    }
    fn less(self: Keys, a: usize, b: usize) bool {
        if (self.logs[a] != self.logs[b]) return self.logs[a] < self.logs[b];
        return switch (std.mem.order(i32, self.masks[a], self.masks[b])) {
            .lt => true,
            .gt => false,
            .eq => a < b,
        };
    }
};
