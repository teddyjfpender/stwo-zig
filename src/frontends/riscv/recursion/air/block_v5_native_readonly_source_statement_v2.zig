//! Exact original versioned source framing; no host sum or frame is proof authority.
const std = @import("std");
const Admission = @import("../../prover/block_v5_native_readonly_source_recursive_admission_v2.zig");
const Native = @import("../../prover/block_v5_native_readonly_source_proof_v2.zig");
const Global = @import("../../prover/block_v5_readonly_input_global_protocol_v2.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_032;
pub const Statement = Frames.Statement;
pub const Step = Frames.Step;
pub const Claims = @import("../../prover/block_v5_readonly_input_protocol_v1.zig").Claim;
pub fn initClaims(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Claims) !Statement {
    try admitted.validateAuthority();
    return record(a, admitted.pin, admitted.sealed.digest, admitted.authority.epoch(), claims);
}
/// Framing-only constructor shared by the genuine admission path and scalar
/// oracle fixtures. This function grants no source, key or epoch authority.
pub fn record(a: std.mem.Allocator, pin: Native.Pin, sealed: [32]u8, epoch: Global.Epoch, claims: Claims) !Statement {
    var b = Frames.Builder{ .allocator = a };
    defer b.deinit();
    Native.mixFirst(&b, pin);
    try b.check();
    const first = try b.steps.toOwnedSlice(a);
    errdefer a.free(first);
    const sealed_offset = try b.digestWords(sealed);
    Global.mixSuffix(&b, epoch.plan_digest, epoch.roster_digest);
    // The suffix appends source identity and then the two original committed
    // classifier roots. Root offsets are selected from the original encoder.
    const prior_roots = b.root_count;
    try Native.mixPcsSuffix(&b, pin, claims);
    try b.check();
    if (b.root_count != prior_roots + 3) return error.InvalidNativeReadonlyV2Statement;
    const roots: [3]u32 = .{ b.root_offsets[prior_roots + 1], b.root_offsets[prior_roots + 2], 0 };
    const claim_steps = try b.steps.toOwnedSlice(a);
    errdefer a.free(claim_steps);
    const words = try b.data.toOwnedSlice(a);
    errdefer a.free(words);
    const felts = try b.fields.toOwnedSlice(a);
    return .{ .allocator = a, .words = words, .felts = felts, .first = first, .claims = claim_steps, .sealed_offset = sealed_offset, .roots_offset = roots };
}
