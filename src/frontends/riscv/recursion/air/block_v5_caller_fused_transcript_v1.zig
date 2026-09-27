//! Three initial commitments followed by the original B5SS47/Word5 restart,
//! full B5CF claims, interaction root and unchanged PCS/FRI/Merkle/PoW replay.
const std = @import("std");
const Admission = @import("../../prover/block_v5_caller_fused_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_caller_fused_recursive_capture_v1.zig");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const Statement = @import("block_v5_caller_fused_statement_v1.zig");
const Recorder = @import("blake3_native_recorder.zig");
const Shared = @import("blake3_native_transcript.zig");
pub fn prefix(a: std.mem.Allocator, r: *Recorder.Recorder, admitted: *const Admission.Prepared, statement: *const Statement.Statement) !Word.Challenges {
    try statement.recordAt(r, statement.first, Statement.PUBLIC_CIRCUIT);
    try r.skipCommittedRoots(3);
    try r.restartChannel();
    const universal = @import("../../prover/block_v5_universal_channel_v1.zig");
    r.mixU32s(&.{ universal.TAG, universal.VERSION });
    r.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, admitted.sealed.digest);
    const challenges = try Word.Challenges.drawFromChannel(a, r);
    r.mixU32s(&.{ Admission.Fused.TAG, Admission.Fused.VERSION, 3 });
    r.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, admitted.sealed.digest);
    try statement.recordAt(r, statement.claims, Statement.PUBLIC_CIRCUIT);
    try r.check();
    return challenges;
}
pub fn planReplay(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8, capacity: u32) !Shared.Planned {
    try capture.validate(admitted, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidCallerFusedRecursiveCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var statement = try Statement.initClaims(arena.allocator(), admitted, capture.original.claims);
    defer statement.deinit();
    var r = Recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    if (!std.meta.eql(try prefix(arena.allocator(), &r, admitted, &statement), capture.word_challenges)) return error.InvalidCallerFusedRecursiveChallenges;
    r.mixRoot(capture.proof.commitments[3]);
    try r.check();
    if (r.root_count != 4 or r.relation_count != @import("block_v5_caller_fused_composition_v1.zig").RELATION_COUNT or r.nonce_pending != null) return error.InvalidCallerFusedRecursiveCapture;
    var result = try Shared.finishReplay(a, &arena, &r, &capture.proof, admitted.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidCallerFusedRecursiveCapture;
    return result;
}
