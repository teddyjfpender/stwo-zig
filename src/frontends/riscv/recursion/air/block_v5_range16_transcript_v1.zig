//! Exact B5SS + 47 universal + five packed-word pairs + range/PCS transcript.
//! Routing changes ownership only, never framing, bytes, draws or hash flags.
const std = @import("std");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const shared = @import("blake3_native_transcript.zig");
const recorder = @import("blake3_native_recorder.zig");
pub fn prefix(a: std.mem.Allocator, r: *recorder.Recorder, admitted: anytype, sums: @import("../../prover/block_v5_range16_component_v1.zig").Claim) !Word.Challenges {
    const Prefix = @import("block_v5_word_transcript_prefix_v1.zig");
    return Prefix.emit(.range16, a, r, Prefix.LiveValuesFor(.range16, @TypeOf(admitted)){ .admitted = admitted, .sums = sums }, Prefix.LiveDraw);
}

pub fn planReplay(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8, capacity: u32) !shared.Planned {
    try capture.validate(admitted, expected);
    if (capture.proof.fri.layers.len == 0) return error.InvalidRangeRecursiveCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var r = recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    const challenges = try prefix(arena.allocator(), &r, admitted, capture.receipt.claim);
    if (!std.meta.eql(challenges, capture.challenges)) return error.InvalidRangeRecursiveCapture;
    r.mixRoot(capture.proof.commitments[2]);
    try r.check();
    if (r.root_count != 3 or r.relation_count != @import("block_v5_range16_composition_v1.zig").RELATION_COUNT or r.nonce_pending != null) return error.InvalidRangeRecursiveCapture;
    var result = try shared.finishReplay(a, &arena, &r, &capture.proof, admitted.config, capacity);
    owns_arena = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidRangeRecursiveCapture;
    return result;
}
