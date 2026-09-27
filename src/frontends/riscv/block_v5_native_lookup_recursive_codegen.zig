//! Genuine original six-table capture, complete parent and fresh recursive
//! receiver bodies retained without invoking any verifier/proof/setup here.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Native = @import("prover/block_v5_native_lookup_proof_v1.zig");
const Policy = @import("prover/block_v5_native_lookup_recursive_admission_v1.zig").Prepared;
const Capture = @import("prover/block_v5_native_lookup_recursive_capture_v1.zig");
const Bus = @import("recursion/block_v5_native_lookup_recursive_public_bus_v1.zig");
const Protocol = @import("recursion/block_v5_reusable_native_lookup_parent_protocol_v1.zig");
const Stage = @import("prover/block_v5_native_lookup_recursive_stage_v1.zig");
const Leaf = @import("recursion/block_v5_native_lookup_recursive_leaf_v1.zig");
fn capture(a: std.mem.Allocator, proof: *const Native.Proof, admitted: *const Policy) anyerror!Capture.VerifiedCapture {
    return Capture.ForBackend(Cpu).verifyBorrowed(a, proof, admitted);
}
fn ownedCapture(a: std.mem.Allocator, proof: Native.Proof, admitted: *const Policy) anyerror!Capture.VerifiedCapture {
    return Capture.ForBackend(Cpu).verifyOwned(a, proof, admitted);
}
fn nativeOwnedCapture(a: std.mem.Allocator, proof: Native.Proof, admitted: *const Policy) anyerror!Native.ForBackend(Cpu).Captured {
    return Native.ForBackend(Cpu).verifyCaptureOwned(a, proof, admitted.plan, admitted.roots, admitted.sealed, admitted.pins, admitted.entries);
}
fn prepare(a: std.mem.Allocator, admitted: *const Policy, proof: *const Capture.VerifiedCapture) anyerror!Bus.Prepared {
    return Bus.prepare(a, admitted, proof, 2);
}
fn publish(a: std.mem.Allocator, proof: *const Native.Proof, admitted: *const Policy, options: Stage.ForBackend(Cpu).Options, sink: Stage.Sink) anyerror!void {
    return Stage.ForBackend(Cpu).publish(a, proof, admitted, options, sink);
}
fn receive(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, id: [32]u8, schedule: []const Bus.Wire, admitted: *const Policy, expected: Native.OpenReceipt) anyerror!Leaf.OpenEquation {
    return Leaf.verify(a, bytes, key, id, schedule, admitted, expected);
}
export fn stwo_native_lookup_recursive_body_gate() void {
    inline for (.{ &capture, &ownedCapture, &nativeOwnedCapture, &prepare, &publish, &receive, &Bus.Prepared.deinit, &Capture.VerifiedCapture.deinit }) |function| std.mem.doNotOptimizeAway(function);
}
