//! Original B5SS universal prefix and B5LT channel, with six public claims.
//! First fixed/main roots are absorbed at their original PCS indices; no restart.
const std = @import("std");
const Admission = @import("../../prover/block_v5_native_lookup_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_native_lookup_recursive_capture_v1.zig");
const Native = @import("../../prover/block_v5_native_lookup_proof_v1.zig");
const Bus = @import("../block_v5_native_lookup_recursive_public_bus_v1.zig");
const universal = @import("universal_challenges.zig");
const recorder = @import("blake3_native_recorder.zig");
const shared = @import("blake3_native_transcript.zig");
pub fn prefix(a: std.mem.Allocator, r: *recorder.Recorder, admitted: *const Admission.Prepared, claims: [6]@import("stwo_core").fields.qm31.QM31) !universal.UniversalRelations {
    const channel = @import("../../prover/block_v5_universal_channel_v1.zig");
    r.mixU32s(&.{ channel.TAG, channel.VERSION });
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 0 }, admitted.sealed.digest);
    const relations = try universal.UniversalRelations.draw(a, r);
    r.mixU32s(&.{ 0x42354c54, 1 });
    r.mixPublicRoot(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = 8 }, try admitted.plan.identity());
    for (admitted.roots) |root| r.mixRoot(root);
    for (claims, 0..) |claim, index| {
        if (!@import("universal_provider_relations.zig").secureIsCanonical(&claim)) return error.InvalidBlockV5NativeLookupClaim;
        r.mixPublicFelts(.{ .circuit = Bus.PUBLIC_CIRCUIT, .first_wire = @intCast(16 + 4 * index) }, &.{claim});
    }
    try r.check();
    return relations;
}
pub fn planReplay(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8, capacity: u32) !shared.Planned {
    try capture.validate(admitted, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidLookupRecursiveCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var r = recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    if (!std.meta.eql(try prefix(arena.allocator(), &r, admitted, capture.receipt.claims), capture.relations)) return error.InvalidLookupRecursiveCapture;
    r.mixRoot(capture.proof.commitments[2]);
    try r.check();
    if (r.root_count != 3 or r.relation_count != universal.RELATION_COUNT or r.nonce_pending != null) return error.InvalidLookupRecursiveCapture;
    var result = try shared.finishReplay(a, &arena, &r, &capture.proof, admitted.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidLookupRecursiveCapture;
    return result;
}
