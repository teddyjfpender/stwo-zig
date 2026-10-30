//! Real joined-original DEEP, FRI and root/nonce witness preparation. This is
//! one part of a recursive verifier: composition and public/global closure are
//! deliberately not represented as completed by these arithmetic witnesses.
const std = @import("std");
const Multi = @import("../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Profile = @import("block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Deep = @import("air/blake3_native_deep.zig");
const Fri = @import("air/blake3_native_fri.zig");
const Roots = @import("air/blake3_execution_roots.zig");
const Transcript = @import("air/blake3_native_transcript.zig");
pub const Prepared = struct {
    deep: Deep.Prepared,
    fri: Fri.Prepared,
    roots: @import("air/blake3_native_root_nonce.zig").Prepared,
    pub const complete_recursive_verifier = false;
    pub fn deinit(self: *Prepared) void {
        self.roots.deinit();
        self.fri.deinit();
        self.deep.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture, transcript: *const Transcript.Planned) !Prepared {
    try profile.validateAgainst(&capture.claims);
    return prepareInternal(a, profile, capture, transcript, null, null);
}
pub fn prepareFromCapsule(a: std.mem.Allocator, capsule: *const @import("block_v7_union_compiler_capsule_v1.zig").Capsule, capture: *const Multi.VerifiedCapture, transcript: *const Transcript.Planned) !Prepared {
    try capsule.requireCapture(a, capture);
    return prepareInternal(a, capsule.profile(), capture, transcript, &capsule.compiler().deep, &capsule.compiler().fri);
}
fn prepareInternal(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture, transcript: *const Transcript.Planned, compiled_deep: ?*const @import("air/pcs_deep_circuit.zig").Circuit, compiled_fri: ?*const @import("air/fri_verifier_circuit.zig").Circuit) !Prepared {
    if (capture.proof.commitments.len != profile.trace_count + 1 or !std.meta.eql(capture.proof.commitments[0], profile.fixed_root) or !std.meta.eql(transcript.end, capture.final_channel)) return error.UntrustedUnionPcsPreparation;
    var inputs = try @import("pcs_arithmetic_capture.zig").Owned.init(a, profile.shape.deepProfile(), &capture.proof);
    errdefer inputs.deinit();
    var graph = if (compiled_deep) |g| try @import("air/compiled_pcs_graph_clone_v1.zig").deep(a, g) else try @import("air/pcs_deep_circuit.zig").build(a, profile.shape.deepProfile());
    errdefer graph.deinit();
    var evaluation = try graph.evaluate(a, inputs.inputs);
    errdefer evaluation.deinit();
    const deep = Deep.Prepared{ .inputs = inputs, .graph = graph, .evaluation = evaluation };
    var fri = if (compiled_fri) |g| try Fri.prepareCapturedWithGraph(a, &capture.proof, profile.statement.input.epoch.config, &deep, 1502, 1504, g) else try Fri.prepareCaptured(a, &capture.proof, profile.statement.input.epoch.config, &deep, 1502, 1504);
    errdefer fri.deinit();
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    var reads: std.ArrayList(@TypeOf(transcript.plan.fixed.root_reads[0])) = .empty;
    for (transcript.plan.fixed.root_reads) |read| if (read.source.circuit == @import("air/blake3_root_sources.zig").CIRCUIT) try reads.append(scratch.allocator(), read);
    var pcs = transcript.*;
    pcs.plan.fixed.root_reads = reads.items;
    var roots = try Roots.prepareCapturedExternalBounded(a, &capture.proof, profile.fixed_root, profile.statement.input.epoch.config, &pcs, try @import("air/block_v7_union_transcript_v1.zig").firstInteraction(profile), profile.trace_count + 1);
    roots.external_key = true;
    roots.external_main = true;
    return .{ .deep = deep, .fri = fri, .roots = roots };
}
