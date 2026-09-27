//! Actual fresh caller arithmetic capture, all symbolic verifier cohorts, publication and
//! independent recursive receipt bodies retained without any invocation.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Native = @import("prover/block_v5_precompile_family_proof_v1.zig");
const Policy = @import("prover/block_v5_caller_arithmetic_recursive_admission_v1.zig").Prepared;
const Capture = @import("prover/block_v5_caller_arithmetic_recursive_capture_v1.zig");
const Bus = @import("recursion/block_v5_caller_arithmetic_recursive_public_bus_v1.zig");
const Protocol = @import("recursion/block_v5_reusable_caller_arithmetic_parent_protocol_v1.zig");
const Stage = @import("prover/block_v5_caller_arithmetic_recursive_stage_v1.zig");
const Leaf = @import("recursion/block_v5_caller_arithmetic_recursive_leaf_v1.zig");
fn capture(a: std.mem.Allocator, proof: *const Native.Proof, admitted: *const Policy) anyerror!Capture.VerifiedCapture {
    return Capture.ForBackend(Cpu).verifyBorrowed(a, proof, admitted);
}
fn prepare(a: std.mem.Allocator, admitted: *const Policy, proof: *const Capture.VerifiedCapture) anyerror!Bus.Prepared {
    return Bus.prepare(a, admitted, proof, 2);
}
fn publish(a: std.mem.Allocator, proof: *const Native.Proof, admitted: *const Policy, options: Stage.ForBackend(Cpu).Options, sink: Stage.Sink) anyerror!void {
    try Stage.ForBackend(Cpu).publish(a, proof, admitted, options, sink);
}
fn receive(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, id: [32]u8, schedule: []const Bus.Wire, admitted: *const Policy, expected: Native.OpenReceipt, claims: @import("prover/blake3_ethereum_sha_profile.zig").ExtensionClaim) anyerror!Leaf.OpenEquation {
    return Leaf.verify(a, bytes, key, id, schedule, admitted, expected, claims);
}
pub export fn stwo_caller_arithmetic_recursive_body_gate() void {
    inline for (.{ &capture, &prepare, &publish, &receive, &Bus.Prepared.deinit, &Capture.VerifiedCapture.deinit }) |function| std.mem.doNotOptimizeAway(function);
}
