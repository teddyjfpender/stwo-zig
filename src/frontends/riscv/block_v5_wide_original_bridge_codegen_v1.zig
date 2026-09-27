//! Actual typed original fresh receiver, symbolic verifier and NEW public
//! equations/protocol retention. No function invokes proving or a device.
const std = @import("std");
const core = @import("stwo_core");
const W = @import("recursion/block_v5_wide_original_child_source_v1.zig");
const P = @import("recursion/block_v5_wide_native_public_values_v1.zig");
const Protocol = @import("recursion/block_v5_reusable_wide_native_public_protocol_v1.zig");
const G = @import("recursion/air/block_v5_wide_native_public_graph_v1.zig");
const C = @import("prover/block_v5_recursive_coverage_plan_v1.zig");
fn prepareGraph(a: std.mem.Allocator, values: *const P.ForSubtype(.capacity_v1).Values) !G.Prepared {
    return G.prepare(a, values);
}
fn prepareOldGraph(a: std.mem.Allocator, values: *const P.ForSubtype(.native_v3).Values) !G.Prepared {
    return G.prepare(a, values);
}
fn mix(admission: *const Protocol.ForSubtype(.capacity_v1).Admission, channel: *core.channel.blake3.Channel) !void {
    try admission.mix(channel);
}
fn mixOld(admission: *const Protocol.ForSubtype(.native_v3).Admission, channel: *core.channel.blake3.Channel) !void {
    try admission.mix(channel);
}
pub export fn stwo_wide_original_bridge_body_gate() void {
    inline for (.{ C.Subtype.native_v3, C.Subtype.capacity_v1, C.Subtype.capacity_fused_v1, C.Subtype.caller_family11_v1, C.Subtype.caller_fused_v1 }) |subtype| {
        const Stack = W.ForSubtype(subtype);
        inline for (.{ &Stack.verify, &Stack.Source.init, &Stack.Source.validate, &Stack.Source.cell, &Stack.Source.deinit, &Stack.Fresh.validate, &Stack.Fresh.deinit, &Stack.planOriginal }) |body| std.mem.doNotOptimizeAway(body);
    }
    inline for (.{ C.Subtype.native_v3, C.Subtype.capacity_v1 }) |subtype| {
        const Public = P.ForSubtype(subtype);
        const B = Protocol.ForSubtype(subtype);
        inline for (.{ &Public.Values.init, &Public.Values.validate, &Public.Values.deinit, &Public.Values.firstCycle, &Public.Values.lastCycle, &Public.Values.cell, &B.Key.fromGeometry, &B.Admission.init, &B.Admission.validateClaimsForRelations }) |body| std.mem.doNotOptimizeAway(body);
        const Rows = @import("recursion/block_v5_wide_native_public_preparation_v1.zig").ForSubtype(subtype);
        const Receiver = @import("recursion/block_v5_wide_native_public_receiver_v1.zig").ForSubtype(subtype);
        const Stage = @import("prover/block_v5_wide_native_public_stage_v1.zig").ForSubtype(@import("stwo_cpu_backend").CpuBackend, subtype);
        inline for (.{ &Rows.prepare, &Receiver.verify, &Receiver.Fresh.validate, &Receiver.Fresh.deinit, &Stage.publish, &Stage.Artifact.deinit }) |body| std.mem.doNotOptimizeAway(body);
    }
    inline for (.{ &prepareGraph, &prepareOldGraph, &mix, &mixOld }) |body| std.mem.doNotOptimizeAway(body);
}
