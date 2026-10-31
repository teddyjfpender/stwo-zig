//! Explicit concrete M31 main ownership. Borrowing never substitutes an allocator.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
pub const Buffer = union(enum) {
    owned: std.mem.Allocator,
    borrowed: []M,
    pub fn validate(self: Buffer, cells: usize) !void {
        _ = try std.math.mul(usize, cells, @sizeOf(M));
        if (self == .borrowed and self.borrowed.len != cells) return error.InvalidCryptoMainBuffers;
    }
    pub fn acquire(self: Buffer, cells: usize) ![]M {
        try self.validate(cells);
        return switch (self) {
            .owned => |a| a.alloc(M, cells),
            .borrowed => |values| values,
        };
    }
    pub fn release(self: Buffer, values: []M) void {
        if (self == .owned) self.owned.free(values);
    }
    pub fn allocator(self: Buffer) ?std.mem.Allocator {
        return switch (self) {
            .owned => |a| a,
            .borrowed => null,
        };
    }
};
pub const Slice = struct { values: []M, cells: usize };
/// Check the complete role set before any constructor allocates or writes.
pub fn validate(slices: []const Slice) !void {
    for (slices, 0..) |slice, i| {
        try (Buffer{ .borrowed = slice.values }).validate(slice.cells);
        for (slices[0..i]) |prior| if (overlaps(std.mem.sliceAsBytes(slice.values), std.mem.sliceAsBytes(prior.values))) return error.OverlappingCryptoMainBuffers;
    }
}
pub fn exclude(slices: []const Slice, bytes: []const u8) !void {
    for (slices) |slice| if (overlaps(std.mem.sliceAsBytes(slice.values), bytes)) return error.OverlappingCryptoMainBuffers;
}
fn overlaps(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;
    // Allocator/slice validity ensures these ends are representable; checked
    // length arithmetic above prevents constructed role geometry overflowing.
    return @intFromPtr(a.ptr) < @intFromPtr(b.ptr) + b.len and @intFromPtr(b.ptr) < @intFromPtr(a.ptr) + a.len;
}
