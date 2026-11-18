//! Private ingress batching. A run never gains authority from adjacency alone.
const std = @import("std");
pub const Copy = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
pub const Validate = *const fn (*anyopaque, *const anyopaque, usize) callconv(.c) c_int;
pub const Runs = struct {
    ctx: *anyopaque,
    copy: Copy,
    validate: ?Validate = null,
    pending: ?struct { dst: usize, src: usize, bytes: usize } = null,
    failed: bool = false,
    pub fn push(self: *Runs, dst: [*]u32, src: [*]const u32, words: usize) !void {
        if (self.failed) return error.CudaEnqueueFailed;
        errdefer self.failed = true;
        const bytes = try std.math.mul(usize, words, 4);
        if (bytes == 0) return error.InvalidDeviceAddress;
        const d = @intFromPtr(dst);
        const s = @intFromPtr(src);
        const dend = try std.math.add(usize, d, bytes);
        const send = try std.math.add(usize, s, bytes);
        if (self.pending) |run| {
            if (self.validate) |validate| {
                if (try std.math.add(usize, run.dst, run.bytes) == d and
                    try std.math.add(usize, run.src, run.bytes) == s and
                    (dend <= run.src or send <= run.dst))
                {
                    const total = try std.math.add(usize, run.bytes, bytes);
                    const source_status = validate(self.ctx, @ptrFromInt(run.src), total);
                    if (source_status != 0 and source_status != 17) return error.CudaEnqueueFailed;
                    if (source_status == 0) {
                        const destination_status = validate(self.ctx, @ptrFromInt(run.dst), total);
                        if (destination_status != 0 and destination_status != 17) return error.CudaEnqueueFailed;
                        if (destination_status == 0) {
                            self.pending.?.bytes = total;
                            return;
                        }
                    }
                }
            }
            try self.finish();
        }
        self.pending = .{ .dst = d, .src = s, .bytes = bytes };
    }
    pub fn finish(self: *Runs) !void {
        if (self.failed) return error.CudaEnqueueFailed;
        errdefer self.failed = true;
        if (self.pending) |run| {
            self.pending = null; // submission failure is terminal, never retried
            if (self.copy(self.ctx, @ptrFromInt(run.dst), @ptrFromInt(run.src), run.bytes) != 0) return error.CudaEnqueueFailed;
        }
    }
};
const Fake = struct {
    var copies: usize = 0;
    var validations: usize = 0;
    var status: c_int = 0;
    var copy_status: c_int = 0;
    var destination_status: c_int = 0;
    var bytes: usize = 0;
    fn copy(_: *anyopaque, _: *anyopaque, _: *const anyopaque, n: usize) callconv(.c) c_int {
        copies += 1;
        bytes += n;
        return copy_status;
    }
    fn validate(_: *anyopaque, p: *const anyopaque, _: usize) callconv(.c) c_int {
        validations += 1;
        return if (@intFromPtr(p) == 0x1000) destination_status else status;
    }
    fn init(available: bool) Runs {
        copies = 0;
        validations = 0;
        status = 0;
        copy_status = 0;
        destination_status = 0;
        bytes = 0;
        return .{ .ctx = @ptrFromInt(1), .copy = copy, .validate = if (available) validate else null };
    }
};
test "column copy runs merge only authenticated contiguous spans" {
    var r = Fake.init(true);
    try r.push(@ptrFromInt(0x1000), @ptrFromInt(0x2000), 4);
    try r.push(@ptrFromInt(0x1010), @ptrFromInt(0x2010), 8);
    try r.finish();
    try std.testing.expectEqual(@as(usize, 1), Fake.copies);
    try std.testing.expectEqual(@as(usize, 2), Fake.validations);
    try std.testing.expectEqual(@as(usize, 48), Fake.bytes);
}
test "column copy runs retain gaps reordered columns and absent capability" {
    for ([_]bool{ false, true }) |available| {
        var r = Fake.init(available);
        try r.push(@ptrFromInt(0x1000), @ptrFromInt(0x3000), 4);
        try r.push(@ptrFromInt(0x1020), @ptrFromInt(0x3010), 4);
        try r.push(@ptrFromInt(0x1030), @ptrFromInt(0x2000), 4);
        try r.finish();
        try std.testing.expectEqual(@as(usize, 3), Fake.copies);
    }
    var r = Fake.init(false);
    try r.push(@ptrFromInt(0x1000), @ptrFromInt(0x2000), 4);
    try r.push(@ptrFromInt(0x1010), @ptrFromInt(0x2010), 4);
    try r.finish();
    try std.testing.expectEqual(@as(usize, 2), Fake.copies);
}
test "column copy runs refuse adjacent foreign allocations and overlapping unions" {
    var r = Fake.init(true);
    Fake.status = 17; // existing validate_allocation: no single owning allocation
    try r.push(@ptrFromInt(0x1000), @ptrFromInt(0x2000), 4);
    try r.push(@ptrFromInt(0x1010), @ptrFromInt(0x2010), 4);
    try r.finish();
    try std.testing.expectEqual(@as(usize, 2), Fake.copies);
    r = Fake.init(true);
    Fake.destination_status = 17;
    try r.push(@ptrFromInt(0x1000), @ptrFromInt(0x2000), 4);
    try r.push(@ptrFromInt(0x1010), @ptrFromInt(0x2010), 4);
    try r.finish();
    try std.testing.expectEqual(@as(usize, 2), Fake.copies);
    r = Fake.init(true);
    try r.push(@ptrFromInt(0x1000), @ptrFromInt(0x1010), 4);
    try r.push(@ptrFromInt(0x1010), @ptrFromInt(0x1020), 4);
    try r.finish();
    try std.testing.expectEqual(@as(usize, 2), Fake.copies);
    try std.testing.expectEqual(@as(usize, 0), Fake.validations);
}
test "column copy runs fail terminally on overflow validator and copy errors" {
    var r = Fake.init(true);
    try std.testing.expectError(error.Overflow, r.push(@ptrFromInt(0x1000), @ptrFromInt(0x2000), std.math.maxInt(usize)));
    try std.testing.expectError(error.CudaEnqueueFailed, r.finish());
    r = Fake.init(true);
    try std.testing.expectError(error.Overflow, r.push(@ptrFromInt(std.math.maxInt(usize) - 3), @ptrFromInt(0x2000), 4));
    r = Fake.init(true);
    try r.push(@ptrFromInt(0x1000), @ptrFromInt(0x2000), 4);
    Fake.status = 1;
    try std.testing.expectError(error.CudaEnqueueFailed, r.push(@ptrFromInt(0x1010), @ptrFromInt(0x2010), 4));
    try std.testing.expectError(error.CudaEnqueueFailed, r.finish());
    try std.testing.expectEqual(@as(usize, 0), Fake.copies);
    r = Fake.init(true);
    try r.push(@ptrFromInt(0x1000), @ptrFromInt(0x2000), 4);
    Fake.copy_status = 1;
    try std.testing.expectError(error.CudaEnqueueFailed, r.finish());
    try std.testing.expectError(error.CudaEnqueueFailed, r.finish());
    try std.testing.expectEqual(@as(usize, 1), Fake.copies);
}

test "authenticated run copies real column bytes exactly once" {
    const Host = struct {
        src: []const u32,
        dst: []u32,
        calls: usize = 0,
        fn validate(raw: *anyopaque, ptr: *const anyopaque, bytes: usize) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(raw));
            const at = @intFromPtr(ptr);
            for ([_][]const u32{ self.src, self.dst }) |span| {
                const base = @intFromPtr(span.ptr);
                if (at >= base and at - base <= span.len * 4 and bytes <= span.len * 4 - (at - base)) return 0;
            }
            return 17;
        }
        fn copy(raw: *anyopaque, dst: *anyopaque, src: *const anyopaque, bytes: usize) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.calls += 1;
            const d: [*]u8 = @ptrCast(dst);
            const s: [*]const u8 = @ptrCast(src);
            @memcpy(d[0..bytes], s[0..bytes]);
            return 0;
        }
    };
    const input = [_]u32{ 0, 1, 0xffffffff, 3, 4, 5, 6, 7 };
    var output: [8]u32 = @splat(42);
    var host = Host{ .src = &input, .dst = &output };
    var r = Runs{ .ctx = &host, .copy = Host.copy, .validate = Host.validate };
    try r.push(&output, &input, 3);
    try r.push(output[3..].ptr, input[3..].ptr, 5);
    try r.finish();
    try std.testing.expectEqualSlices(u32, &input, &output);
    try std.testing.expectEqual(@as(usize, 1), host.calls);
}
