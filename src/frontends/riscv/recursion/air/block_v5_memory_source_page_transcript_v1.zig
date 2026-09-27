//! No original PAGE channel restart: exact six premix roots, semantic roots,
//! page-local Universal47, original claim frames, interaction8, then PCS.
const std = @import("std");
const Semantic = @import("../../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Admission = @import("../../prover/block_v5_memory_source_page_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_memory_source_page_recursive_capture_v1.zig");
const Statement = @import("block_v5_memory_source_page_statement_v1.zig");
const Recorder = @import("blake3_native_recorder.zig");
const Shared = @import("blake3_native_transcript.zig");
const Universal = @import("universal_challenges.zig");
pub fn planReplay(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8, capacity: u32) !Shared.Planned {
    const kind = comptime kindOf(@TypeOf(capture.*));
    try capture.validate(admitted, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidSourcePageRecursiveCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var statement = try Statement.ForKind(kind).init(arena.allocator(), admitted, capture.original.frame.semantic, capture.original.frame.claims);
    defer statement.deinit();
    var recorder = Recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    try statement.frame.recordAt(&recorder, statement.frame.first, Statement.publicCircuit(kind));
    try recorder.skipCommittedRootsFor(8);
    const relations = try Universal.UniversalRelations.draw(arena.allocator(), &recorder);
    if (!std.meta.eql(relations, capture.relations) or !std.meta.eql(statement.relations, capture.relations)) return error.InvalidSourcePageRecursiveChallenges;
    try statement.frame.recordAt(&recorder, statement.frame.claims, Statement.publicCircuit(kind));
    try recorder.check();
    if (!std.meta.eql(recorder.native, statement.proof_start)) return error.InvalidSourcePageRecursiveTranscript;
    recorder.mixRoot(capture.proof.commitments[8]);
    try recorder.check();
    if (!std.meta.eql(recorder.native, capture.original.proof_start)) return error.InvalidSourcePageRecursiveTranscript;
    if (recorder.root_count != 9 or recorder.relation_count != Universal.RELATION_COUNT or recorder.nonce_pending != null) return error.InvalidSourcePageRecursiveTranscript;
    var result = try Shared.finishReplayForCommitments(10, a, &arena, &recorder, &capture.proof, admitted.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidSourcePageRecursiveTranscript;
    return result;
}
pub fn kindOf(comptime T: type) Semantic.Kind {
    if (T == Capture.ForKind(.raw).VerifiedCapture) return .raw;
    if (T == Capture.ForKind(.fold).VerifiedCapture) return .fold;
    @compileError("PAGE adapter requires an exact original fresh PAGE capture type");
}
