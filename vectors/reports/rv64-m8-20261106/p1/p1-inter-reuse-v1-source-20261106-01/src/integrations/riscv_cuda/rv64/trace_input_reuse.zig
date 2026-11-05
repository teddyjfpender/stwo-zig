//! Validate owned INTER prefixes before destructive in-place interpolation.
//! Padding stays in the transferred leases and remains physically charged.
const std = @import("std");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Native = @import("pcs_native_abi.zig");

pub fn enabled() bool {
    return if (std.posix.getenv("STWO_RV64_RC_INTER_REUSE")) |v| std.mem.eql(u8, v, "1") else false;
}

pub fn validate(a: std.mem.Allocator, leases: []const Native.Lease, columns: []const D.TraceColumn) !void {
    if (leases.len == 0 or columns.len == 0) return error.InvalidOwnedInterInputs;
    const used = try a.alloc(u64, leases.len);
    defer a.free(used);
    @memset(used, 0);
    for (leases, 0..) |lease, i| {
        if (lease.kind != 2 or lease.words == null or lease.count == 0 or lease.context_token == 0 or lease.generation == 0) return error.InvalidOwnedInterInputs;
        for (leases[0..i]) |previous| if (previous.context_token == lease.context_token and previous.generation == lease.generation) return error.InvalidOwnedInterInputs;
    }
    for (columns) |column| {
        try column.validate();
        if (column.encoding != .evaluations) return error.InvalidOwnedInterInputs;
        const source = column.device orelse return error.InvalidOwnedInterInputs;
        var found = false;
        for (leases, used) |lease, *at| {
            if (lease.context_token != source.context_token or lease.generation != source.generation) continue;
            if (source.count > lease.count - at.* or source.words != lease.words.? + @as(usize, @intCast(at.*))) return error.InvalidOwnedInterInputs;
            at.* += source.count;
            found = true;
            break;
        }
        if (!found) return error.InvalidOwnedInterInputs;
    }
    for (used) |count| if (count == 0) return error.InvalidOwnedInterInputs;
}

pub fn adjacent(left: D.TraceColumn, right: D.TraceColumn) bool {
    const x = left.device orelse return false;
    const y = right.device orelse return false;
    return x.context_token == y.context_token and x.generation == y.generation and
        x.words + @as(usize, @intCast(x.count)) == y.words;
}

test "INTER ownership accepts permuted leases and retains padding without aliasing" {
    const first = Native.Lease{ .words = @ptrFromInt(4096), .count = 64, .context_token = 7, .generation = 11, .kind = 2 };
    const second = Native.Lease{ .words = @ptrFromInt(8192), .count = 48, .context_token = 7, .generation = 12, .kind = 2 };
    const columns = [_]D.TraceColumn{
        .{ .log_size = 4, .encoding = .evaluations, .device = .{ .words = @ptrFromInt(4096), .count = 16, .context_token = 7, .generation = 11 } },
        .{ .log_size = 4, .encoding = .evaluations, .device = .{ .words = @ptrFromInt(4160), .count = 16, .context_token = 7, .generation = 11 } },
        .{ .log_size = 5, .encoding = .evaluations, .device = .{ .words = @ptrFromInt(8192), .count = 32, .context_token = 7, .generation = 12 } },
    };
    try validate(std.testing.allocator, &.{ second, first }, &columns);
    try std.testing.expect(adjacent(columns[0], columns[1]));
    try std.testing.expect(!adjacent(columns[1], columns[2]));
    for (0..4) |mutation| {
        var bad = columns;
        switch (mutation) {
            0 => bad[1].device.?.words = bad[0].device.?.words,
            1 => bad[1].device.?.context_token = 8,
            2 => bad[1].device.?.generation = 99,
            3 => bad[1].encoding = .coefficients,
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidOwnedInterInputs, validate(std.testing.allocator, &.{ first, second }, &bad));
    }
    try std.testing.expectError(error.InvalidOwnedInterInputs, validate(std.testing.allocator, &.{ first, first, second }, &columns));
}
