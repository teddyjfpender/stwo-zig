//! Compile-time helpers shared by backend capability contracts.

pub fn assertErrorUnionPayload(
    comptime Actual: type,
    comptime Expected: type,
    comptime message: []const u8,
) void {
    const info = @typeInfo(Actual);
    if (info != .error_union or info.error_union.payload != Expected) {
        @compileError(message);
    }
}
