//! Actual B5CT recursive producer/receiver/cache bodies. Retain addresses only;
//! no function is invoked, no guest/device/commitment/STARK/proof is created.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Native = @import("prover/block_v5_native_capacity_proof_v1.zig");
const Prepared = @import("prover/block_v5_native_capacity_recursive_admission_v1.zig").Prepared;
const Bus = @import("recursion/block_v5_capacity_recursive_public_bus_v1.zig");
const Protocol = @import("recursion/block_v5_reusable_capacity_parent_protocol_v1.zig");
const StageModule = @import("prover/block_v5_native_capacity_recursive_stage_v1.zig");
const Stage = StageModule.ForBackend(Cpu);
const Leaf = @import("recursion/block_v5_capacity_recursive_leaf_v1.zig");
const Frames = @import("recursion/block_v5_open_child_frames_v2.zig");
fn publish(a: std.mem.Allocator, proof: *const Native.Proof, policy: *const Prepared, options: Stage.Options, sink: StageModule.Sink) anyerror!void {
    try Stage.publish(a, proof, policy, options, sink);
}
fn prepare(a: std.mem.Allocator, policy: *const Prepared, capture: *const Native.VerifiedCapture) anyerror!Bus.Prepared {
    return Bus.prepare(a, policy, capture, 2);
}
fn receive(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, key_id: [32]u8, schedule: []const Bus.Wire, policy: *const Prepared, expected: Native.OpenReceipt) anyerror!Leaf.OpenEquation {
    return Leaf.verify(a, bytes, key, key_id, schedule, policy, expected);
}
fn normalize(a: std.mem.Allocator, key: Protocol.Key, key_id: [32]u8, schedule: []const Bus.Wire, policy: *const Prepared, expected: Native.OpenReceipt) anyerror!Frames.Child {
    return Frames.fromCapacity(a, policy, expected, key, key_id, schedule);
}
fn cached(cache: *Stage.SetupCache, columns: *Bus.Prepared) anyerror!Stage.SetupCache.Proved {
    return cache.provePreparedConsuming(columns);
}
export fn stwo_capacity_recursive_body_gate() void {
    inline for (.{ &publish, &prepare, &receive, &normalize, &cached, &Stage.SetupCache.deinit }) |function| std.mem.doNotOptimizeAway(function);
}
