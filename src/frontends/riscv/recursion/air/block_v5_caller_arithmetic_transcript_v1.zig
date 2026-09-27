//! Exact empty initial PCS channel, restart, B5SS47 and ETH13/SHA1 suffix,
//! then original complete claim frames and STARK/PCS/PoW replay.
const std = @import("std");
const Admission = @import("../../prover/block_v5_caller_arithmetic_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_caller_arithmetic_recursive_capture_v1.zig");
const Bus = @import("../block_v5_caller_arithmetic_recursive_public_bus_v1.zig");
const recorder = @import("blake3_native_recorder.zig");
const universal = @import("universal_challenges.zig");
const shared = @import("blake3_native_transcript.zig");
const Q = @import("stwo_core").fields.qm31.QM31;
pub const ClaimsChannel = struct {
    recorder: *recorder.Recorder,
    cursor: u32 = Bus.CLAIM_WORD_BASE,
    pub fn mixU32s(self: *ClaimsChannel, words: []const u32) void {
        self.recorder.mixU32s(words);
    }
    pub fn mixFelts(self: *ClaimsChannel, values: []const Q) void {
        self.recorder.mixPublicFelts(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = self.cursor }, values);
        self.cursor += @intCast(values.len * 4);
    }
};
pub fn prefix(a: std.mem.Allocator, r: *recorder.Recorder, admitted: *const Admission.Prepared, claims: *const Admission.Profile.ExtensionClaim) !Admission.Profile.Relations {
    try admitted.validate(admitted.template_id);
    try claims.validate(&admitted.statement);
    r.mixRoot(admitted.roots[0]);
    r.mixRoot(admitted.roots[1]);
    try r.restartChannel();
    const channel = @import("../../prover/block_v5_universal_channel_v1.zig");
    r.mixU32s(&.{ channel.TAG, channel.VERSION });
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 0 }, admitted.sealed.digest);
    const vm = try universal.UniversalRelations.draw(a, r);
    const Protocol = Admission.Protocol;
    r.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, @intFromEnum(Protocol.circuit_profile) });
    const relations = try Admission.Profile.Relations.drawAfterVm(a, r, vm);
    r.mixPublicWords(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = Bus.INDEX_WORD_BASE }, &.{ Protocol.TAG, Protocol.VERSION, admitted.binding.execution_index });
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 8 }, admitted.binding.execution_instance_id);
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 16 }, admitted.binding.caller_key_id);
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 24 }, admitted.binding.caller_instance_id);
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 32 }, admitted.roots[0]);
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 40 }, admitted.roots[1]);
    var routed = ClaimsChannel{ .recorder = r };
    claims.mixInto(&routed);
    try r.check();
    return relations;
}
pub fn planReplay(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8, capacity: u32) !shared.Planned {
    try capture.validate(admitted, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidCallerRecursiveCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var r = recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    if (!std.meta.eql(try prefix(arena.allocator(), &r, admitted, &capture.original.claims), capture.original.relations)) return error.InvalidCallerRecursiveCapture;
    r.mixRoot(capture.proof.commitments[2]);
    try r.check();
    if (r.root_count != 3 or r.relation_count != @import("block_v5_caller_arithmetic_composition_v1.zig").RELATION_COUNT or r.nonce_pending != null) return error.InvalidCallerRecursiveCapture;
    var result = try shared.finishReplay(a, &arena, &r, &capture.proof, admitted.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidCallerRecursiveCapture;
    return result;
}
