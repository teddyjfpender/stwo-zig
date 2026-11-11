//! Runtime view of the generated Native Metal product identity.

const native_identity = @import("native_product_identity");
const std = @import("std");

pub const value = native_identity.value;

test "generated Native Metal identity binds exact source-JIT semantics" {
    const actual = value();
    try actual.validate();
    try std.testing.expectEqualStrings("stwo-native-metal", actual.name);
    try std.testing.expectEqualStrings("metal", actual.backend);
    try std.testing.expect(std.mem.startsWith(
        u8,
        actual.runtime_manifest,
        "metal-runtime-v2:mode=source-jit;",
    ));
    try std.testing.expect(std.mem.startsWith(u8, actual.sdk_manifest, "apple-metal-sdk-v2:"));
    try std.testing.expectEqualStrings("none", actual.aot_manifest);
}
