//! Full-width execution prefix feeding the shared native BLAKE3 PCS replay.
//! No scalar-root statement projection or legacy relation draw is admitted.
const std = @import("std");
const core = @import("stwo_core");
const protocol = @import("../../prover/blake3_execution_protocol.zig");
const capture_mod = @import("../../prover/blake3_execution_capture.zig");
const shared = @import("blake3_native_transcript.zig");
const recorder = @import("blake3_native_recorder.zig");
const universal = @import("universal_challenges.zig");
pub fn planReplay(a: std.mem.Allocator, prepared: anytype, capture: *const capture_mod.Verified, expected: [32]u8, capacity: u32) !shared.Planned {
    try capture.validate(prepared, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidExecutionCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var r = recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    try protocol.mix(&r, prepared.config, &prepared.shape, prepared.admission());
    r.mixRoot(capture.proof.commitments[0]);
    r.mixRoot(capture.proof.commitments[1]);
    const relations = try universal.UniversalRelations.draw(arena.allocator(), &r);
    if (!std.meta.eql(relations, capture.relations)) return error.InvalidExecutionCapture;
    r.private_felts = true;
    try protocol.mixClaims(&r, &prepared.shape, capture.native_claims, &capture.hash_claims);
    r.mixRoot(capture.proof.commitments[2]);
    try r.check();
    if (r.root_count != 3 or r.relation_count != universal.RELATION_COUNT or r.nonce_pending != null) return error.InvalidExecutionCapture;
    var result = try shared.finishReplay(a, &arena, &r, &capture.proof, prepared.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.mem.eql(u8, &result.end.digestBytes(), &capture.final_channel.digestBytes()) or result.end.n_draws != capture.final_channel.n_draws) return error.InvalidExecutionCapture;
    return result;
}
