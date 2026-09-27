//! Actual original proof/capture/verifier-row/producer/fresh-loader bodies are
//! retained only. No export is invoked by these nonproving fixtures.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Native = @import("block_v5_readonly_input_provider_proof_v2.zig");
const Admission = @import("block_v5_readonly_provider_recursive_admission_v2.zig");
const Capture = @import("block_v5_readonly_provider_recursive_capture_v2.zig");
const Stage = @import("block_v5_readonly_provider_recursive_stage_v2.zig");
const Bus = @import("../recursion/block_v5_readonly_provider_recursive_public_bus_v2.zig");
const Protocol = @import("../recursion/block_v5_reusable_readonly_provider_parent_protocol_v2.zig");
const Leaf = @import("../recursion/block_v5_readonly_provider_recursive_leaf_v2.zig");
export fn readonly_provider_v2_actual_capture(a: *std.mem.Allocator, proof: *const Native.Proof, admitted: *const Admission.Prepared, output: *Capture.VerifiedCapture) bool {
    output.* = Capture.ForBackend(Cpu).verifyBorrowed(a.*, proof, admitted) catch return false;
    return true;
}
export fn readonly_provider_v2_actual_rows(a: *std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, capacity: u32, output: *Bus.Prepared) bool {
    output.* = Bus.prepare(a.*, admitted, capture, capacity) catch return false;
    return true;
}
export fn readonly_provider_v2_actual_publication(a: *std.mem.Allocator, proof: *const Native.Proof, admitted: *const Admission.Prepared, options: *const Stage.ForBackend(Cpu).Options, sink: *const Stage.Sink) bool {
    Stage.ForBackend(Cpu).publish(a.*, proof, admitted, options.*, sink.*) catch return false;
    return true;
}
export fn readonly_provider_v2_actual_fresh_leaf(a: *std.mem.Allocator, bytes: [*]const u8, len: usize, key: *const Protocol.Key, id: *const [32]u8, schedule: [*]const Bus.Wire, count: usize, admitted: *const Admission.Prepared, claim: *const @import("block_v5_readonly_input_provider_component_v2.zig").Claim, output: *Leaf.OpenEquation) bool {
    output.* = Leaf.verify(a.*, bytes[0..len], key.*, id.*, schedule[0..count], admitted, claim.*) catch return false;
    return true;
}
test "readonly provider recursive v2: actual physical capture complete verifier publication and fresh body retention" {
    _ = &readonly_provider_v2_actual_capture;
    _ = &readonly_provider_v2_actual_rows;
    _ = &readonly_provider_v2_actual_publication;
    _ = &readonly_provider_v2_actual_fresh_leaf;
}
test "readonly provider recursive v2: invalid publication capacity fails before capture or allocation" {
    var admitted: Admission.Prepared = undefined;
    admitted.config = @import("../recursion/blake3_execution_parent_proof.zig").protocol.Profile.csp_q70_pow26.config();
    var denied = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const options = Stage.ForBackend(Cpu).Options{ .expected = undefined, .profile = .csp_q70_pow26, .transcript_capacity = 0 };
    try std.testing.expectError(error.ProviderReadonlyV2RecursiveSecurityMismatch, Stage.ForBackend(Cpu).publish(denied.allocator(), undefined, &admitted, options, undefined));
    try std.testing.expectEqual(@as(usize, 0), denied.alloc_index);
}
