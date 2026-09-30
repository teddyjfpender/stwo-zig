//! Thread-private AIR storage, shared by logical registers with disjoint lifetimes.
//! Repeated writes retain one conservative interval; constraints stay live until
//! their final write and their actual consumption in canonical root order.
const std = @import("std");
const eval = @import("stwo_cairo_frontend").witness.eval_program;

pub const Layout = struct {
    base: []u32,
    extended: []u32,
    base_count: usize,
    extended_count: usize,

    pub fn init(a: std.mem.Allocator, program: eval.Program) !Layout {
        const base = try a.alloc(Interval, program.header.max_base_regs);
        defer a.free(base);
        const extended = try a.alloc(Interval, program.header.max_ext_regs);
        defer a.free(extended);
        @memset(base, .{});
        @memset(extended, .{});
        for (program.base_insts, 0..) |inst, index| {
            const time = index * 2;
            base[inst.dst].write(time);
            switch (inst.op) {
                .add, .sub, .mul => {
                    base[inst.a].read(time);
                    base[inst.b].read(time);
                },
                .neg, .inv => base[inst.a].read(time),
                else => {},
            }
        }
        const final_writes = try a.alloc(usize, extended.len);
        defer a.free(final_writes);
        @memset(final_writes, 0);
        for (program.ext_insts, 0..) |inst, index| {
            const time = (program.base_insts.len + index) * 2;
            extended[inst.dst].write(time);
            final_writes[inst.dst] = time;
            switch (inst.op) {
                .secure_col => {
                    base[inst.a].read(time);
                    base[inst.b].read(time);
                    base[inst.c].read(time);
                    base[inst.d].read(time);
                },
                .add, .sub, .mul => {
                    extended[inst.a].read(time);
                    extended[inst.b].read(time);
                },
                .neg => extended[inst.a].read(time),
                else => {},
            }
        }
        var root_time: usize = 0;
        for (program.constraint_roots) |root| {
            root_time = @max(root_time, final_writes[root] + 1);
            extended[root].read(root_time);
        }
        const base_layout = try color(a, base);
        errdefer a.free(base_layout.map);
        const ext_layout = try color(a, extended);
        return .{ .base = base_layout.map, .extended = ext_layout.map, .base_count = base_layout.count, .extended_count = ext_layout.count };
    }

    pub fn deinit(self: Layout, a: std.mem.Allocator) void {
        a.free(self.base);
        a.free(self.extended);
    }
};

const Interval = struct {
    first: usize = std.math.maxInt(usize),
    last: usize = 0,

    fn write(self: *Interval, time: usize) void {
        self.first = @min(self.first, time);
        self.last = @max(self.last, time);
    }
    fn read(self: *Interval, time: usize) void {
        self.last = @max(self.last, time);
    }
};

fn color(a: std.mem.Allocator, intervals: []const Interval) !struct { map: []u32, count: usize } {
    const order = try a.alloc(u32, intervals.len);
    defer a.free(order);
    for (order, 0..) |*id, index| id.* = @intCast(index);
    std.mem.sort(u32, order, intervals, struct {
        fn less(spans: []const Interval, left: u32, right: u32) bool {
            if (spans[left].first != spans[right].first)
                return spans[left].first < spans[right].first;
            return left < right;
        }
    }.less);
    const map = try a.alloc(u32, intervals.len);
    errdefer a.free(map);
    @memset(map, 0);
    const ends = try a.alloc(usize, intervals.len);
    defer a.free(ends);
    var count: usize = 0;
    for (order) |id| {
        const span = intervals[id];
        if (span.first == std.math.maxInt(usize)) continue;
        var slot: usize = 0;
        while (slot < count and ends[slot] >= span.first) : (slot += 1) {}
        if (slot == count) count += 1;
        ends[slot] = span.last;
        map[id] = @intCast(slot);
    }
    return .{ .map = map, .count = count };
}
