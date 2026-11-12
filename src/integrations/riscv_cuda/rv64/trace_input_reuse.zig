//! Validate owned INTER prefixes before destructive in-place interpolation.
//! Padding stays in the transferred leases and remains physically charged.
const std = @import("std");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Native = @import("pcs_native_abi.zig");

pub fn enabled() bool {
    return false;
}

pub const Layout = struct {
    order: [11]usize,
    offsets: [11]usize,
    logical_words: usize = 0,
    tail_words: usize = 0,
    pub fn init(components: anytype) !Layout {
        if (components.len != 11) return error.InvalidOwnedInterInputs;
        var out: Layout = .{ .order = undefined, .offsets = undefined };
        var logs: [11]u32 = undefined;
        for (components, &logs, &out.order, 0..) |component, *log, *order, i| {
            if (component.log < 4 or component.log > 27 or component.pairs == 0) return error.InvalidOwnedInterInputs;
            log.* = component.log;
            order.* = i;
        }
        std.mem.sort(usize, &out.order, &logs, struct {
            fn less(values: *const [11]u32, x: usize, y: usize) bool {
                return values[x] < values[y] or (values[x] == values[y] and x < y);
            }
        }.less);
        for (out.order) |i| {
            const rows = @as(usize, 1) << @intCast(components[i].log);
            out.offsets[i] = out.logical_words;
            const count = try std.math.mul(usize, 8, @intCast(components[i].pairs));
            out.logical_words = try std.math.add(usize, out.logical_words, try std.math.mul(usize, count, rows));
            out.tail_words = @max(out.tail_words, 8 * rows);
        }
        _ = try out.words();
        return out;
    }
    pub fn words(self: Layout) !usize {
        return std.math.add(usize, self.logical_words, self.tail_words);
    }
};

pub fn validate(a: std.mem.Allocator, leases: []const Native.Lease, columns: []const D.TraceColumn) !void {
    // PCS's borrowed-tree promise requires one sorted contiguous coefficient
    // prefix. The unused tail belongs to the same lease and remains charged.
    if (leases.len != 1 or columns.len == 0) return error.InvalidOwnedInterInputs;
    const lease = leases[0];
    if (lease.kind != 2 or lease.words == null or lease.count == 0 or lease.context_token == 0 or lease.generation == 0) return error.InvalidOwnedInterInputs;
    const order = try a.alloc(usize, columns.len);
    defer a.free(order);
    for (order, 0..) |*index, i| index.* = i;
    std.mem.sort(usize, order, columns, struct {
        fn less(items: []const D.TraceColumn, x: usize, y: usize) bool {
            return items[x].log_size < items[y].log_size or (items[x].log_size == items[y].log_size and x < y);
        }
    }.less);
    var used: u64 = 0;
    for (order) |index| {
        const column = columns[index];
        try column.validate();
        if (column.encoding != .evaluations) return error.InvalidOwnedInterInputs;
        const source = column.device orelse return error.InvalidOwnedInterInputs;
        if (lease.context_token != source.context_token or lease.generation != source.generation or
            source.count > lease.count - used or source.words != lease.words.? + @as(usize, @intCast(used))) return error.InvalidOwnedInterInputs;
        used += source.count;
    }
}

pub fn adjacent(left: D.TraceColumn, right: D.TraceColumn) bool {
    const x = left.device orelse return false;
    const y = right.device orelse return false;
    return x.context_token == y.context_token and x.generation == y.generation and
        x.words + @as(usize, @intCast(x.count)) == y.words;
}

test "INTER ownership enforces the PCS sorted contiguous borrow promise" {
    const lease = Native.Lease{ .words = @ptrFromInt(4096), .count = 80, .context_token = 7, .generation = 11, .kind = 2 };
    const columns = [_]D.TraceColumn{
        .{ .log_size = 5, .encoding = .evaluations, .device = .{ .words = @ptrFromInt(4224), .count = 32, .context_token = 7, .generation = 11 } },
        .{ .log_size = 4, .encoding = .evaluations, .device = .{ .words = @ptrFromInt(4096), .count = 16, .context_token = 7, .generation = 11 } },
        .{ .log_size = 4, .encoding = .evaluations, .device = .{ .words = @ptrFromInt(4160), .count = 16, .context_token = 7, .generation = 11 } },
    };
    try validate(std.testing.allocator, &.{lease}, &columns);
    try std.testing.expect(adjacent(columns[1], columns[2]));
    try std.testing.expect(adjacent(columns[2], columns[0]));
    for (0..4) |mutation| {
        var bad = columns;
        switch (mutation) {
            0 => bad[2].device.?.words = bad[1].device.?.words,
            1 => bad[2].device.?.context_token = 8,
            2 => bad[2].device.?.generation = 99,
            3 => bad[2].encoding = .coefficients,
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidOwnedInterInputs, validate(std.testing.allocator, &.{lease}, &bad));
    }
    try std.testing.expectError(error.InvalidOwnedInterInputs, validate(std.testing.allocator, &.{ lease, lease }, &columns));
}

test "packed INTER cumulative scratch never overwrites an earlier component" {
    const Component = struct { log: u32, pairs: u64 };
    var components = [_]Component{.{ .log = 4, .pairs = 1 }} ** 11;
    components[0] = .{ .log = 6, .pairs = 2 };
    components[7] = .{ .log = 5, .pairs = 1 };
    const layout = try Layout.init(&components);
    const memory = try std.testing.allocator.alloc(u32, try layout.words());
    defer std.testing.allocator.free(memory);
    @memset(memory, 0);
    for (layout.order) |i| {
        const n = @as(usize, 1) << @intCast(components[i].log);
        const count = 8 * @as(usize, @intCast(components[i].pairs)) * n;
        const offset = layout.offsets[i];
        @memset(memory[offset..][0..count], @intCast(i + 1));
        @memset(memory[offset + count ..][0 .. 8 * n], 99);
    }
    for (components, 0..) |component, i| {
        const count = 8 * @as(usize, @intCast(component.pairs)) * (@as(usize, 1) << @intCast(component.log));
        for (memory[layout.offsets[i]..][0..count]) |value| try std.testing.expectEqual(@as(u32, @intCast(i + 1)), value);
    }
    try std.testing.expectEqual(@as(usize, 8 * 64), layout.tail_words);
}
