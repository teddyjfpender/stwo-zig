//! M8 GPU-native recursion (stream: recursion). Contract: gpu_native.zig
//! RecursionFactory; design: rv64-m8-gpu-native.md §3.3, §6.
//!
//! STUB (contract landing): every entry fails closed. The recursion stream
//! replaces it with: per-class node plans (assignment tasks/levels, stream
//! plans, PCS framing, FIXED tree) built in `warm`; per node a device seed
//! fill from the children's encoded slab regions, whole-node CUDA graph
//! replay (<= 50 launches/node), device lookupSum / OODS checks and device
//! encoding; TruthJob (truth_job.zig) for truth/service proofs.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");

pub const Recursion = struct {
    pub fn factory(self: *Recursion) G.RecursionFactory {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable = G.RecursionFactory.VTable{ .warm = warm, .class_of = classOf, .truth = truth, .node = node };
    fn warm(_: *anyopaque, _: *G.ClassCache) anyerror!void {
        return error.M8GpuNativeRecursionNotLanded;
    }
    fn classOf(_: *anyopaque, _: G.ProofId) anyerror!G.ClassKey {
        return error.M8GpuNativeRecursionNotLanded;
    }
    fn truth(_: *anyopaque, _: *const G.RequestContext, _: u32, _: u32) anyerror!api.Job {
        return error.M8GpuNativeRecursionNotLanded;
    }
    fn node(_: *anyopaque, _: *const G.RequestContext, _: G.ProofId, _: []const G.ProofId, _: u32) anyerror!api.Job {
        return error.M8GpuNativeRecursionNotLanded;
    }
};

test "recursion factory stub fails closed" {
    var r = Recursion{};
    const f = r.factory();
    try std.testing.expectError(error.M8GpuNativeRecursionNotLanded, f.vtable.class_of(f.ctx, .{ .kind = .leaf, .ordinal = 0 }));
}
