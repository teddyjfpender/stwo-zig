//! Runtime view of the generated product identity.

const native_identity = @import("native_product_identity");
const std = @import("std");

pub const value = native_identity.value;

test "generated Native CPU identity is internally consistent" {
    const actual = value();
    try actual.validate();
    try std.testing.expectEqualStrings("stwo-native-cpu", actual.name);
    try std.testing.expectEqualStrings("cpu", actual.backend);
    try std.testing.expectEqualStrings("none", actual.runtime_manifest);
}
