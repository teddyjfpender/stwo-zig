//! Original first/claim encoders recorded verbatim, with public dynamic roots,
//! frame bytes, full claim counts and fields routed into the same public bus.
const std = @import("std");
const Admission = @import("../../prover/block_v5_caller_readonly_global_recursive_admission_v2.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_031;
pub const Statement = Frames.Statement;
pub const Step = Frames.Step;
pub fn initClaims(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Admission.Fused.ClaimFrames) !Statement {
    var b = Frames.Builder{ .allocator = a, .max_felts = admitted.limits.max_public_claims };
    defer b.deinit();
    Admission.Fused.mixFirst(&b, admitted.binding, admitted.witness_root, admitted.frame, admitted.sealed.register_custody_mode, &admitted.schedule, admitted.readonly);
    try b.check();
    if (b.root_count < 6) return error.InvalidCallerReadonlyStatement;
    const roots: [3]u32 = b.root_offsets[3..6].*;
    const first = try b.steps.toOwnedSlice(a);
    errdefer a.free(first);
    const sealed_offset = try b.digestWords(admitted.sealed.digest);
    const epoch = admitted.readonly.roster.epoch();
    const Global = @import("../../prover/block_v5_readonly_input_global_protocol_v2.zig");
    // Shared54 original draws use the actual admitted global suffix, then the
    // distinct B5IC2 second channel retains every repeated genuine Word draw.
    Global.mixSuffix(&b, epoch.plan_digest, epoch.roster_digest);
    b.mixU32s(&.{ Admission.Fused.TAG, Admission.Fused.VERSION, 3, admitted.readonly.ordinal, admitted.readonly.group_id });
    b.mixRoot(admitted.sealed.digest);
    b.mixRoot(epoch.plan_digest);
    b.mixRoot(epoch.roster_digest);
    b.mixRoot(try Admission.Fused.instanceId(admitted.binding, admitted.witness_root, admitted.frame, 1, &admitted.schedule, admitted.readonly));
    const classification = try Admission.Fused.classification(a, admitted.sealed, admitted.plan, admitted.binding, admitted.witness_root, admitted.frame, &admitted.schedule, admitted.readonly);
    try Admission.Fused.mixClaims(&b, admitted.binding, &admitted.schedule, &claims, admitted.plan, &classification, admitted.readonly);
    try b.check();
    const claim_steps = try b.steps.toOwnedSlice(a);
    errdefer a.free(claim_steps);
    const words = try b.data.toOwnedSlice(a);
    errdefer a.free(words);
    const felts = try b.fields.toOwnedSlice(a);
    return .{ .allocator = a, .words = words, .felts = felts, .first = first, .claims = claim_steps, .sealed_offset = sealed_offset, .roots_offset = roots };
}
