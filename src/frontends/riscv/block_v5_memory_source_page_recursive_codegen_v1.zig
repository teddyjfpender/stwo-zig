//! Retain genuine original capture and complete new recursive producer/fresh
//! receiver bodies. The marker never invokes them or generates a proof.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Semantic = @import("prover/block_v5_memory_source_page_semantic_columns_v1.zig");
fn Bodies(comptime kind: Semantic.Kind) type {
    const Original = @import("prover/block_v5_memory_source_unified_page_proof_v1.zig").ForKind(kind);
    const Admission = @import("prover/block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(kind);
    const Capture = @import("prover/block_v5_memory_source_page_recursive_capture_v1.zig").ForKind(kind);
    const Stage = @import("prover/block_v5_memory_source_page_recursive_stage_v1.zig").ForKind(kind);
    const Bus = @import("recursion/block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
    const Protocol = @import("recursion/block_v5_reusable_memory_source_page_parent_protocol_v1.zig").ForKind(kind);
    const Leaf = @import("recursion/block_v5_memory_source_page_recursive_leaf_v1.zig").ForKind(kind);
    return struct {
        fn captureBorrowed(a: std.mem.Allocator, proof: *const Original.Proof, admitted: *const Admission.Prepared) anyerror!Capture.VerifiedCapture {
            return Capture.verifyBorrowed(a, proof, admitted);
        }
        fn captureOwned(a: std.mem.Allocator, proof: Original.Proof, admitted: *const Admission.Prepared) anyerror!Capture.VerifiedCapture {
            return Capture.verifyOwned(a, proof, admitted);
        }
        fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture) anyerror!Bus.Prepared {
            return Bus.prepare(a, admitted, capture, 2);
        }
        fn publish(a: std.mem.Allocator, proof: *const Original.Proof, admitted: *const Admission.Prepared, options: Stage.ForBackend(Cpu).Options, sink: Stage.Sink) anyerror!void {
            try Stage.ForBackend(Cpu).publish(a, proof, admitted, options, sink);
        }
        fn receive(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, id: [32]u8, wires: []const Bus.Wire, admitted: *const Admission.Prepared, proposed: Bus.Claims) anyerror!Leaf.OpenEquation {
            return Leaf.verify(a, bytes, key, id, wires, admitted, proposed);
        }
        fn keep() void {
            inline for (.{ &captureBorrowed, &captureOwned, &prepare, &publish, &receive, &Capture.VerifiedCapture.deinit, &Bus.Prepared.deinit, &Leaf.OpenEquation.deinit }) |body| std.mem.doNotOptimizeAway(body);
        }
    };
}
pub export fn stwo_source_page_recursive_body_gate() void {
    Bodies(.raw).keep();
    Bodies(.fold).keep();
}
