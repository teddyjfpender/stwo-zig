//! Original first/claim encoders recorded verbatim, with public dynamic roots,
//! frame bytes, full claim counts and fields routed into the same public bus.
const std = @import("std");
const Admission = @import("../../prover/block_v5_caller_fused_recursive_admission_v1.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_011;
pub const Statement = Frames.Statement;
pub const Step = Frames.Step;
pub fn initClaims(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Admission.Fused.ClaimFrames) !Statement {
    var b = Frames.Builder{ .allocator = a, .max_felts = admitted.limits.max_public_claims };
    defer b.deinit();
    Admission.Fused.mixFirst(&b, admitted.binding, admitted.witness_root, admitted.frame, admitted.sealed.register_custody_mode, &admitted.schedule);
    try b.check();
    if (b.root_count < 6) return error.InvalidCallerFusedStatement;
    const roots: [3]u32 = b.root_offsets[3..6].*;
    const first = try b.steps.toOwnedSlice(a);
    errdefer a.free(first);
    const sealed_offset = try b.digestWords(admitted.sealed.digest);
    b.mixRoot(Admission.Fused.instanceId(admitted.binding, admitted.witness_root, admitted.frame, admitted.sealed.register_custody_mode, &admitted.schedule));
    try Admission.Fused.mixClaims(&b, admitted.binding, &admitted.schedule, claims.program_claims, claims.state_claims, claims.table_claims, claims.memory_claims);
    try b.check();
    const claim_steps = try b.steps.toOwnedSlice(a);
    errdefer a.free(claim_steps);
    const words = try b.data.toOwnedSlice(a);
    errdefer a.free(words);
    const felts = try b.fields.toOwnedSlice(a);
    return .{ .allocator = a, .words = words, .felts = felts, .first = first, .claims = claim_steps, .sealed_offset = sealed_offset, .roots_offset = roots };
}
