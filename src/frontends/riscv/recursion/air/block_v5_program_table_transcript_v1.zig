//! Both original channels, with an authenticated restart at their true boundary.
const std = @import("std");
const Admission = @import("../../prover/block_v5_program_table_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_program_table_recursive_capture_v1.zig");
const Native = @import("../../prover/block_v5_program_table_proof_v1.zig");
const Source = @import("../../prover/block_v5_program_table_v1.zig");
const Bus = @import("../block_v5_program_table_recursive_public_bus_v1.zig");
const universal = @import("universal_challenges.zig");
const recorder = @import("blake3_native_recorder.zig");
const shared = @import("blake3_native_transcript.zig");
pub fn prefix(a: std.mem.Allocator, r: *recorder.Recorder, admitted: *const Admission.Prepared, claim: @import("stwo_core").fields.qm31.QM31) !universal.UniversalRelations {
    const channel = @import("../../prover/block_v5_universal_channel_v1.zig");
    r.mixU32s(&.{ channel.TAG, channel.VERSION });
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 0 }, admitted.sealed.digest);
    const relations = try universal.UniversalRelations.draw(a, r);
    try r.restartChannel();
    r.mixU32s(&.{ Native.TAG, Source.VERSION });
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 0 }, admitted.sealed.digest);
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 8 }, admitted.sealed.native_roster_digest);
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 16 }, admitted.sealed.program_plan_digest);
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 24 }, admitted.plan.program_root.bytes);
    r.mixRoot(admitted.roots[0]);
    r.mixRoot(admitted.roots[1]);
    r.mixPublicFelts(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 32 }, &.{claim});
    try r.check();
    return relations;
}
pub fn planReplay(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8, capacity: u32) !shared.Planned {
    try capture.validate(admitted, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidProgramRecursiveCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var r = recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    if (!std.meta.eql(try prefix(arena.allocator(), &r, admitted, capture.receipt.claim), capture.relations)) return error.InvalidProgramRecursiveCapture;
    r.mixRoot(capture.proof.commitments[2]);
    try r.check();
    if (r.root_count != 3 or r.relation_count != universal.RELATION_COUNT or r.nonce_pending != null) return error.InvalidProgramRecursiveCapture;
    var result = try shared.finishReplay(a, &arena, &r, &capture.proof, admitted.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidProgramRecursiveCapture;
    return result;
}
