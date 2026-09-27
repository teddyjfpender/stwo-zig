//! One owned artifact buffer. Limits are checked before every capacity growth;
//! proof serializers write into the final envelope without a staging copy.
const std = @import("std");
pub const Writer = struct {
    allocator: std.mem.Allocator,
    limit: usize,
    bytes: std.ArrayList(u8) = .empty,

    pub fn init(a: std.mem.Allocator, limit: usize) Writer {
        return .{ .allocator = a, .limit = limit };
    }
    pub fn deinit(self: *Writer) void {
        self.bytes.deinit(self.allocator);
        self.bytes = .empty;
    }
    pub fn writeByte(self: *Writer, value: u8) !void {
        try self.writeAll(&.{value});
    }
    pub fn writeClaim(self: *Writer, value: @import("stwo_core").fields.qm31.QM31) !void {
        var raw: [16]u8 = undefined;
        for (value.toM31Array(), 0..) |coordinate, index| {
            if (coordinate.v >= @import("stwo_core").fields.m31.Modulus) return error.InvalidInteractionClaim;
            std.mem.writeInt(u32, raw[index * 4 ..][0..4], coordinate.v, .little);
        }
        try self.writeAll(&raw);
    }
    pub fn writeAll(self: *Writer, values: []const u8) !void {
        const needed = try std.math.add(usize, self.bytes.items.len, values.len);
        if (needed > self.limit) return error.ArtifactTooLarge;
        if (needed > self.bytes.capacity) {
            const doubled = std.math.mul(usize, self.bytes.capacity, 2) catch self.limit;
            const target = @min(self.limit, @max(needed, @max(@as(usize, 256), doubled)));
            try self.bytes.ensureTotalCapacityPrecise(self.allocator, target);
        }
        self.bytes.appendSliceAssumeCapacity(values);
    }
    pub fn toOwnedSlice(self: *Writer) ![]u8 {
        return self.bytes.toOwnedSlice(self.allocator);
    }
};
