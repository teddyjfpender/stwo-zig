//! Qualified finite pair layout over the shared exact component placement.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
pub const NATIVE_MAP = [4]usize{ 0, 1, 2, 5 };
pub const CALLER_MAP = [5]usize{ 0, 3, 4, 6, 7 };
pub const TRACE_TREES = 8;
pub fn Owner(comptime proving: bool) type {
    const Inner = @import("block_v7_heterogeneous_components_v1.zig").For(.{ NATIVE_MAP, CALLER_MAP }, TRACE_TREES, proving);
    const H = if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component;
    return struct {
        inner: Inner,
        handles: []H,
        pub fn init(a: std.mem.Allocator, native: []const H, caller: H, native_fixed: usize, caller_fixed: usize) !@This() {
            const inner = try Inner.init(a, .{ native, &.{caller} }, .{ native_fixed, caller_fixed });
            return .{ .inner = inner, .handles = inner.handles };
        }
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            self.inner.deinit(a);
            self.* = undefined;
        }
    };
}
