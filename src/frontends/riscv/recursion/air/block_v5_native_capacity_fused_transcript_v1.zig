//! Original first commitments then authenticated restart to B5SS/Word52/B5CF.
//! All first-root and claim metadata bytes remain dynamically public routed.
const std = @import("std");
const Admission = @import("../../prover/block_v5_native_capacity_fused_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_native_capacity_fused_recursive_capture_v1.zig");
const Fused = @import("../../prover/block_v5_native_capacity_fused_proof_v1.zig");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const Statement = @import("block_v5_native_capacity_fused_statement_v1.zig");
const Recorder = @import("blake3_native_recorder.zig");
const Shared = @import("blake3_native_transcript.zig");
pub fn prefix(a: std.mem.Allocator, r: *Recorder.Recorder, admitted: *const Admission.Prepared, statement: *const Statement.Statement) !Word.Challenges {
    try statement.record(r, statement.first);
    try r.skipCommittedRoots(admitted.tree_count - 1);
    try r.restartChannel();
    const universal = @import("../../prover/block_v5_universal_channel_v1.zig");
    r.mixU32s(&.{ universal.TAG, universal.VERSION });
    r.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, admitted.native.sealed.digest);
    const challenges = try Word.Challenges.drawFromChannel(a, r);
    r.mixU32s(&.{ Fused.TAG, Fused.VERSION, 3 });
    try statement.record(r, statement.claims);
    try r.check();
    return challenges;
}
pub fn planReplay(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8, capacity: u32) !Shared.Planned {
    try capture.validate(admitted, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidCapacityFusedRecursiveCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var statement = try Statement.Statement.init(arena.allocator(), admitted, capture);
    defer statement.deinit();
    var r = Recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    if (!std.meta.eql(try prefix(arena.allocator(), &r, admitted, &statement), capture.word_challenges)) return error.InvalidCapacityFusedRecursiveChallenges;
    r.mixRoot(capture.proof.commitments[admitted.tree_count - 1]);
    try r.check();
    if (r.root_count != admitted.tree_count or r.relation_count != @import("block_v5_native_capacity_fused_composition_v1.zig").RELATION_COUNT or r.nonce_pending != null) return error.InvalidCapacityFusedRecursiveCapture;
    var result = try Shared.finishReplay(a, &arena, &r, &capture.proof, admitted.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidCapacityFusedRecursiveCapture;
    return result;
}
