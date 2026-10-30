//! Explicit resource policy propagation only. The enclosing shared allocator
//! remains the hard aggregate cap; this does not alter verifier geometry.
const std = @import("std");
pub fn clamp(outer: usize, requested: ?usize) !?usize {
    if (outer == 0) return error.InvalidFamilyResourceLimit;
    if (requested) |value| {
        if (value == 0) return error.InvalidFamilyResourceLimit;
        return @min(outer, value);
    }
    return null;
}
pub fn forSetup(comptime T: type, outer: usize, requested: ?usize) !T {
    var result: T = .{};
    if (try clamp(outer, requested)) |limit| {
        result.max_bytes = limit;
        if (@hasField(T, "native")) result.native.max_bytes = limit;
    }
    return result;
}
test "explicit family byte limits clamp to outer authority and preserve defaults" {
    const T = struct { max_bytes: usize = 4, native: struct { max_bytes: usize = 2, geometry: usize = 17 } = .{} };
    try std.testing.expectEqualDeep(T{}, try forSetup(T, 12, null));
    const result = try forSetup(T, 12, 20);
    try std.testing.expectEqual(@as(usize, 12), result.max_bytes);
    try std.testing.expectEqual(@as(usize, 12), result.native.max_bytes);
    try std.testing.expectEqual(@as(usize, 17), result.native.geometry);
    try std.testing.expectError(error.InvalidFamilyResourceLimit, forSetup(T, 12, 0));
}
