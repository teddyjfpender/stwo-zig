//! Two original challenge branches, one six-commitment proof transcript.
//! Universal47 is shared. Arithmetic14 and Word5 retain their own domain
//! separation; no Word challenge is fabricated from the arithmetic branch.
const std = @import("std");
const core = @import("stwo_core");
const Admission = @import("../../prover/block_v6_caller_joint_admission_v1.zig");
const Capture = @import("../../prover/block_v6_caller_joint_capture_v1.zig");
const Joint = @import("../../prover/block_v6_caller_joint_proof_v1.zig");
const Protocol = @import("../../prover/block_v5_precompile_protocol_v1.zig");
const Profile = @import("../../prover/blake3_ethereum_sha_profile.zig");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const Universal = @import("universal_challenges.zig");
const Statement = @import("block_v6_caller_joint_statement_v1.zig");
const Recorder = @import("blake3_native_recorder.zig");
const Shared = @import("blake3_native_transcript.zig");
pub const Draws = struct { arithmetic: Profile.Relations, word: Word.Challenges };
pub fn prefix(a: std.mem.Allocator, r: *Recorder.Recorder, admitted: *const Admission.Prepared, statement: *const Statement.Statement) !Draws {
    if (r.root_count != 0 or r.relation_count != 0 or !r.universal_relations) return error.InvalidJointCallerTranscript;
    return emitPrefix(a, r, admitted, statement, LiveDraw);
}
pub fn prefixFixed(a: std.mem.Allocator, r: *@import("blake3_fixed_operation_recorder_v1.zig").Recorder, admitted: *const Admission.Prepared, statement: *const Statement.Statement) !void {
    return emitPrefix(a, r, admitted, statement, FixedDraw);
}
fn emitPrefix(a: std.mem.Allocator, r: anytype, admitted: *const Admission.Prepared, statement: *const Statement.Statement, comptime Draw: type) !Draw.Output {
    const channel = @import("../../prover/block_v5_universal_channel_v1.zig");
    r.mixU32s(&.{ channel.TAG, channel.VERSION });
    r.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, admitted.arithmetic.sealed.digest);
    try r.skipCommittedRoots(3);
    const word = try Draw.word(a, r);
    // Start the actual PCS branch. Repeated Universal47 draws are checked but
    // do not overwrite their existing exported values. Fill only the reserved
    // arithmetic14 slots; each of the 66 outputs has exactly one producer.
    try r.restartChannel();
    r.mixU32s(&.{ channel.TAG, channel.VERSION });
    r.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, admitted.arithmetic.sealed.digest);
    const universal = try Draw.repeatUniversal(a, r, word);
    r.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, @intFromEnum(Protocol.circuit_profile) });
    const result = try Draw.arithmetic(a, r, universal, word);
    try statement.recordAt(r, statement.claims, Statement.PUBLIC_CIRCUIT);
    try r.check();
    return result;
}
const LiveDraw = struct {
    pub const Output = Draws;
    pub fn word(a: std.mem.Allocator, r: *Recorder.Recorder) !Word.Challenges {
        const result = try Word.Challenges.drawWith(a, r, WordDraw);
        if (r.relation_count != 66) return error.InvalidJointCallerTranscript;
        return result;
    }
    pub fn repeatUniversal(a: std.mem.Allocator, r: *Recorder.Recorder, words: Word.Challenges) !Universal.UniversalRelations {
        var repeated = Repeated{ .r = r };
        const universal = try Universal.UniversalRelations.draw(a, &repeated);
        if (!std.meta.eql(universal, words.universal_prefix)) return error.InvalidJointCallerTranscript;
        r.relation_count = 47;
        return universal;
    }
    pub fn arithmetic(a: std.mem.Allocator, r: *Recorder.Recorder, universal: Universal.UniversalRelations, words: Word.Challenges) !Draws {
        const result = try Profile.Relations.drawAfterVm(a, r, universal);
        if (r.relation_count != 61) return error.InvalidJointCallerTranscript;
        r.relation_count = 66;
        return .{ .arithmetic = result, .word = words };
    }
};
const FixedDraw = struct {
    pub const Output = void;
    pub fn word(a: std.mem.Allocator, r: anytype) !void {
        try Word.Challenges.drawWith(a, r, FixedWord);
    }
    pub fn repeatUniversal(_: std.mem.Allocator, r: anytype, _: void) !void {
        for (0..Universal.RELATION_COUNT) |_| r.append(.{ .secure = .{ .output = null, .discard_output = true, .attempts = 0, .consumption = .two, .values = @splat(core.fields.m31.M31.zero()) } });
        try r.check();
    }
    pub fn arithmetic(_: std.mem.Allocator, r: anytype, _: void, _: void) !void {
        try r.universalPairs(47, 13);
        r.mixU32s(&.{ 0x53484157, 1 });
        try r.universalPairs(60, 1);
    }
};
const FixedWord = struct {
    pub const Output = void;
    pub fn universal(_: std.mem.Allocator, r: anytype) !void {
        try Universal.requireDrawSchema();
        try r.universalPairs(0, Universal.RELATION_COUNT);
    }
    pub fn extra(_: std.mem.Allocator, r: anytype, _: void) !void {
        try r.universalPairs(61, 5);
    }
};
const WordDraw = struct {
    pub const Output = Word.Challenges;
    pub fn universal(a: std.mem.Allocator, r: *Recorder.Recorder) !Universal.UniversalRelations {
        return Universal.UniversalRelations.draw(a, r);
    }
    pub fn extra(a: std.mem.Allocator, r: *Recorder.Recorder, initial: Universal.UniversalRelations) !Word.Challenges {
        if (r.relation_count != 47) return error.InvalidJointCallerTranscript;
        r.relation_count = 61;
        const values = try r.drawSecureFelts(a, 10);
        defer a.free(values);
        return .{ .transition = .init(values[0], values[1]), .link = .init(values[2], values[3]), .initial = .init(values[4], values[5]), .endpoint = .init(values[6], values[7]), .range16 = .init(values[8], values[9]), .universal_prefix = initial };
    }
};
const Repeated = struct {
    r: *Recorder.Recorder,
    pub fn drawSecureFelts(self: *Repeated, a: std.mem.Allocator, n: usize) ![]core.fields.qm31.QM31 {
        return self.r.drawSecureFeltsDiscarded(a, n);
    }
};
pub fn planReplay(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8, capacity: u32) !Shared.Planned {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    const temp = arena.allocator();
    var statement = try Statement.init(temp, admitted, &capture.original.arithmetic, &capture.original.claims);
    defer statement.deinit();
    var r = Recorder.Recorder{ .a = temp, .universal_relations = true };
    const draws = try prefix(temp, &r, admitted, &statement);
    if (!std.meta.eql(draws.arithmetic, try Protocol.drawRelations(temp, admitted.arithmetic.sealed)) or
        !std.meta.eql(draws.word, try Word.Challenges.draw(temp, admitted.arithmetic.sealed))) return error.InvalidJointCallerTranscript;
    const channel = try Joint.proofChannel(temp, admitted.policy(), &admitted.relations.schedule, &capture.original.arithmetic, &capture.original.claims);
    if (!std.meta.eql(channel, r.native)) return error.InvalidJointCallerTranscript;
    r.mixRoot(capture.original.proof.commitments[3]);
    r.mixRoot(capture.original.proof.commitments[4]);
    try r.check();
    if (r.root_count != 5 or r.relation_count != 66 or r.nonce_pending != null) return error.InvalidJointCallerTranscript;
    var result = try Shared.finishReplayForCommitments(6, a, &arena, &r, &capture.original.proof, admitted.arithmetic.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.original.final_channel)) return error.InvalidJointCallerTranscript;
    return result;
}
