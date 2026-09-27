//! Three initial commitments followed by the original B5SS47/Word5 restart,
//! full B5IC claims, interaction root and unchanged PCS/FRI/Merkle/PoW replay.
const std = @import("std");
const Admission = @import("../../prover/block_v5_caller_readonly_global_recursive_admission_v2.zig");
const Capture = @import("../../prover/block_v5_caller_readonly_global_recursive_capture_v2.zig");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const Statement = @import("block_v5_caller_readonly_global_statement_v2.zig");
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
    if (statement.claims.len < 9) return error.InvalidCallerReadonlyRecursiveClaims;
    try statement.recordAt(r, statement.claims[0..4], Statement.PUBLIC_CIRCUIT);
    const values = try r.drawSecureFelts(a, 4);
    defer a.free(values);
    const OriginalChallenges = @import("../../prover/block_v5_caller_readonly_protocol_v1.zig").Challenges;
    const classification = OriginalChallenges{ .word = challenges, .classification = .init(values[0], values[1]), .read = .init(values[2], values[3]) };
    const expected = try @import("../../prover/block_v5_readonly_input_global_protocol_v2.zig").draw(a, admitted.sealed, admitted.readonly.roster.epoch());
    if (!std.meta.eql(classification, expected)) return error.InvalidCallerReadonlyRecursiveChallenges;
    // Repeat every original Word draw on the second real channel, retaining
    // prior52+2 exports rather than replacing their domain/slot identities.
    try r.restartChannel();
    r.mixU32s(&.{ universal.TAG, universal.VERSION });
    r.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, admitted.sealed.digest);
    var repeated = Repeated{ .recorder = r };
    if (!std.meta.eql(try Word.Challenges.drawFromChannel(a, &repeated), challenges)) return error.InvalidCallerReadonlyRecursiveChallenges;
    try statement.recordAt(r, statement.claims[4..], Statement.PUBLIC_CIRCUIT);
    try r.check();
    return challenges;
}
pub fn planReplay(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8, capacity: u32) !Shared.Planned {
    try capture.validate(admitted, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidCallerReadonlyRecursiveCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var statement = try Statement.initClaims(arena.allocator(), admitted, capture.original.claims);
    defer statement.deinit();
    var r = Recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    if (!std.meta.eql(try prefix(arena.allocator(), &r, admitted, &statement), capture.word_challenges)) return error.InvalidCallerReadonlyRecursiveChallenges;
    r.mixRoot(capture.proof.commitments[3]);
    try r.check();
    if (r.root_count != 4 or r.relation_count != @import("block_v5_caller_readonly_global_composition_v2.zig").RELATION_COUNT or r.nonce_pending != null) return error.InvalidCallerReadonlyRecursiveCapture;
    var result = try Shared.finishReplay(a, &arena, &r, &capture.proof, admitted.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidCallerReadonlyRecursiveCapture;
    return result;
}

const Repeated = struct {
    recorder: *Recorder.Recorder,
    pub fn mixU32s(self: *Repeated, words: []const u32) void {
        self.recorder.mixU32s(words);
    }
    pub fn drawSecureFelts(self: *Repeated, a: std.mem.Allocator, count: usize) ![]@import("stwo_core").fields.qm31.QM31 {
        return self.recorder.drawSecureFeltsUnexported(a, count);
    }
};
