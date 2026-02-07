const std = @import("std");

/// Byte-level equality for VCS hash values.
pub fn eql(a: anytype, b: @TypeOf(a)) bool {
    return std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b));
}

/// Minimal compile-time contract for hash value types used in VCS modules.
pub fn assertHashType(comptime Hash: type) void {
    comptime {
        _ = std.mem.zeroes(Hash);
        if (@typeInfo(Hash) == .Pointer) {
            @compileError("VCS hash type must be a value type, not a pointer.");
        }
    }
}

test "hash: eql matches byte equality" {
    const a = [_]u8{1} ** 32;
    const b = [_]u8{1} ** 32;
    const c = [_]u8{2} ** 32;
    try std.testing.expect(eql(a, b));
    try std.testing.expect(!eql(a, c));
}
