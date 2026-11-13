const std = @import("std");

test "logup-gkr: capture refuses retired physical columns instead of silently reinterpreting debt" {
    const Main = @import("main.zig");
    const Historic = struct {
        pub const U16 = [_]usize{0} ** 12;
        pub const U8 = [_]usize{0} ** 4;
    };
    const Missing = struct {
        pub const U16 = [_]usize{0} ** 12;
    };
    const Narrow = struct {
        pub const U16 = [_]usize{0} ** 4;
        pub const U8 = [_]usize{0} ** 4;
    };
    try std.testing.expect(Main.captureSupported(Historic));
    try std.testing.expect(!Main.captureSupported(Missing));
    try std.testing.expect(!Main.captureSupported(Narrow));
}
