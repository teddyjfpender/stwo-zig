//! Original full B5IN2 transcript with shared54 unshifted exports, followed by
//! unchanged classifier composition/DEEP/FRI/Merkle/PoW verification.
const std = @import("std");
const Admission = @import("../../prover/block_v5_native_readonly_source_recursive_admission_v2.zig");
const Capture = @import("../../prover/block_v5_native_readonly_source_recursive_capture_v2.zig");
const Global = @import("../../prover/block_v5_readonly_input_global_protocol_v2.zig");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const Statement = @import("block_v5_native_readonly_source_statement_v2.zig");
const Recorder = @import("blake3_native_recorder.zig");
const Shared = @import("blake3_native_transcript.zig");
pub fn prefix(a: std.mem.Allocator, recorder: *Recorder.Recorder, admitted: *const Admission.Prepared, statement: *const Statement.Statement) !Global.Challenges {
    try statement.recordAt(recorder, statement.first, Statement.PUBLIC_CIRCUIT);
    try recorder.skipCommittedRoots(2);
    try recorder.restartChannel();
    const universal = @import("../../prover/block_v5_universal_channel_v1.zig");
    recorder.mixU32s(&.{ universal.TAG, universal.VERSION });
    recorder.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, admitted.sealed.digest);
    const word = try Word.Challenges.drawFromChannel(a, recorder);
    if (statement.claims.len < 4) return error.InvalidNativeReadonlyV2Statement;
    try statement.recordAt(recorder, statement.claims[0..4], Statement.PUBLIC_CIRCUIT);
    const values = try recorder.drawSecureFelts(a, 4);
    defer a.free(values);
    const challenges = Global.Challenges{ .word = word, .classification = .init(values[0], values[1]), .read = .init(values[2], values[3]) };
    if (!std.meta.eql(challenges, try Global.draw(a, admitted.sealed, admitted.authority.epoch()))) return error.InvalidNativeReadonlyV2RecursiveChallenges;
    try statement.recordAt(recorder, statement.claims[4..], Statement.PUBLIC_CIRCUIT);
    try recorder.check();
    return challenges;
}
pub fn planReplay(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8, capacity: u32) !Shared.Planned {
    try capture.validate(admitted, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidNativeReadonlyV2RecursiveCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var statement = try Statement.initClaims(arena.allocator(), admitted, capture.receipt.claim);
    defer statement.deinit();
    var recorder = Recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    if (!std.meta.eql(try prefix(arena.allocator(), &recorder, admitted, &statement), capture.challenges)) return error.InvalidNativeReadonlyV2RecursiveChallenges;
    recorder.mixRoot(capture.proof.commitments[2]);
    try recorder.check();
    if (recorder.root_count != 3 or recorder.relation_count != @import("block_v5_native_readonly_source_composition_v2.zig").RELATION_COUNT or recorder.nonce_pending != null) return error.InvalidNativeReadonlyV2RecursiveCapture;
    var result = try Shared.finishReplay(a, &arena, &recorder, &capture.proof, admitted.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidNativeReadonlyV2RecursiveCapture;
    return result;
}
