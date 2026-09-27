//! Normalize heterogeneous quotient degrees before canonical composition lifting.
//! Degree extensions interpolate the smaller quotient; repeating its evaluations
//! would change the polynomial sampled by the independently constructed verifier.
const std = @import("std");
const typed = @import("universal_typed_geometry.zig");
pub fn ForAirs(comptime Airs: anytype) type {
    return struct {
        pub const quotient_log_blowup: u8 = blk: {
            var largest: u8 = 1;
            for (Airs) |Air| largest = @max(largest, blowup(Air));
            break :blk largest;
        };
        pub fn component(comptime Air: type, handle: anytype) !@TypeOf(handle) {
            return normalize(blowup(Air), handle);
        }
        pub fn table(handle: anytype) !@TypeOf(handle) {
            return normalize(1, handle);
        }
        fn normalize(comptime intrinsic: u8, handle: anytype) !@TypeOf(handle) {
            if (comptime quotient_log_blowup == 1) return handle;
            return handle.withCompositionGeometryOverrideV1(.{
                .max_constraint_log_degree_bound_delta = quotient_log_blowup - intrinsic,
                .composition_log_split = quotient_log_blowup,
            });
        }
    };
}
fn blowup(comptime Air: type) u8 {
    return @intCast(@max(1, std.math.log2_int_ceil(u32, typed.protocolMaximumConstraintDegree(Air) - 1)));
}
