//! Linear native-template v2 transcript replay from the pinned B5SS seed.
const std = @import("std");
const admission = @import("../../prover/block_v5_native_recursive_admission_v1.zig");
const capture_mod = @import("../../prover/block_v5_native_execution_proof_v1.zig");
const template = @import("../../prover/block_v5_native_template_protocol.zig");
const universal_channel = @import("../../prover/block_v5_universal_channel_v1.zig");
const universal = @import("universal_challenges.zig");
const recorder = @import("blake3_native_recorder.zig");
const shared = @import("blake3_native_transcript.zig");

pub fn planReplay(a: std.mem.Allocator, prepared: *const admission.Prepared, capture: *const capture_mod.VerifiedCapture, expected: [32]u8, capacity: u32) !shared.Planned {
    try capture.validate(prepared, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidNativeV5RecursiveCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var r = recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    r.mixU32s(&.{ universal_channel.TAG, universal_channel.VERSION });
    if (prepared.reusable_public_inputs)
        r.mixPublicRoot(.{ .circuit = 4_200_001, .first_wire = 0 }, prepared.sealed.digest)
    else
        r.mixStaticRoot(prepared.sealed.digest);
    const relations = try universal.UniversalRelations.draw(arena.allocator(), &r);
    if (!std.meta.eql(relations, capture.relations)) return error.InvalidNativeV5RecursiveCapture;
    if (prepared.reusable_public_inputs) {
        r.mixPublicWords(.{ .circuit = 4_200_001, .first_wire = 24 }, &.{ template.TAG, template.VERSION, prepared.index });
        r.mixPublicRoot(.{ .circuit = 4_200_001, .first_wire = 8 }, expected);
        r.mixPublicRoot(.{ .circuit = 4_200_001, .first_wire = 16 }, capture.receipt.instance_id);
    } else {
        r.mixU32s(&.{ template.TAG, template.VERSION, prepared.index });
        r.mixStaticRoot(expected);
        r.mixStaticRoot(capture.receipt.instance_id);
    }
    r.mixRoot(capture.proof.commitments[0]);
    r.mixRoot(capture.proof.commitments[1]);
    r.private_felts = true;
    try template.mixClaims(&r, prepared.shape, capture.native_claims);
    r.mixRoot(capture.proof.commitments[2]);
    try r.check();
    if (r.root_count != 3 or r.relation_count != universal.RELATION_COUNT or r.nonce_pending != null)
        return error.InvalidNativeV5RecursiveCapture;
    var result = try shared.finishReplay(a, &arena, &r, &capture.proof, prepared.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidNativeV5RecursiveCapture;
    return result;
}
