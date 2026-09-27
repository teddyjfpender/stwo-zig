//! Original B5SS47+word5, lane domain/pin/claim framing then full PCS replay.
const std = @import("std");
const Admission = @import("../../prover/block_v5_ram_lanes_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_ram_lanes_recursive_capture_v1.zig");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const shared = @import("blake3_native_transcript.zig");
const recorder = @import("blake3_native_recorder.zig");
pub fn prefix(a: std.mem.Allocator, r: *recorder.Recorder, admitted: *const Admission.Prepared, sums: @import("../../prover/block_v5_ram_lanes_interaction_v1.zig").Claim) !Word.Challenges {
    _ = try @import("../../prover/block_v5_ram_lanes_interaction_v1.zig").normalize(sums, admitted.pin.claim);
    const Prefix = @import("block_v5_word_transcript_prefix_v1.zig");
    return Prefix.emit(.ram_lanes, a, r, Prefix.LiveValues(.ram_lanes){ .admitted = admitted, .sums = sums }, Prefix.LiveDraw);
}

pub fn planReplay(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8, capacity: u32) !shared.Planned {
    try capture.validate(admitted, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidRamRecursiveCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var r = recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    const challenges = try prefix(arena.allocator(), &r, admitted, capture.receipt.sums);
    if (!std.meta.eql(challenges, capture.challenges)) return error.InvalidRamRecursiveCapture;
    r.mixRoot(capture.proof.commitments[2]);
    try r.check();
    if (r.root_count != 3 or r.relation_count != @import("block_v5_ram_lanes_composition_v1.zig").RELATION_COUNT or r.nonce_pending != null) return error.InvalidRamRecursiveCapture;
    var result = try shared.finishReplay(a, &arena, &r, &capture.proof, admitted.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidRamRecursiveCapture;
    return result;
}
