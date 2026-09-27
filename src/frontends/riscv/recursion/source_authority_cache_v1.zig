//! Cache an infallible identity of immutable, compiled source recipes once per
//! process. The builder must be deterministic and must not read job/proof data
//! or re-enter its own cache. Runtime policy/key verification is never cached.
const std = @import("std");
pub fn For(comptime build: fn () [32]u8) type {
    return struct {
        var value: [32]u8 = undefined;
        var once = std.once(initialize);
        fn initialize() void {
            value = build();
        }
        pub fn get() [32]u8 {
            once.call();
            return value;
        }
    };
}
