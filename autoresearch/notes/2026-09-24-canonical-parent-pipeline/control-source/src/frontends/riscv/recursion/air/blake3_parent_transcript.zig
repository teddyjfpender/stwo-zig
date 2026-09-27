//! Replay an admitted parent proof through the same bounded BLAKE3 transcript
//! witness path, preserving its protocol domain and claims framing.
const std = @import("std");
const Verified = @import("../blake3_native_parent_verifier.zig").Verified;
const shared = @import("blake3_native_transcript.zig");
const recorder = @import("blake3_native_recorder.zig");
const universal = @import("universal_challenges.zig");
pub fn planReplay(a: std.mem.Allocator, admission: anytype, capture: *const Verified, capacity: u32) !shared.Planned {
    try capture.validate(admission, admission.expected_id);
    var arena = std.heap.ArenaAllocator.init(a);
    var owns_arena = true;
    defer if (owns_arena) arena.deinit();
    var r = recorder.Recorder{ .a = arena.allocator(), .universal_relations = true };
    try admission.mix(&r);
    r.mixRoot(capture.capture.commitments[0]);
    r.mixRoot(capture.capture.commitments[1]);
    const relations = try universal.UniversalRelations.draw(arena.allocator(), &r);
    if (!std.meta.eql(relations, capture.relations)) return error.InvalidBlake3ParentCapture;
    r.private_felts = true;
    try admission.mixClaims(&r, &capture.claims);
    r.mixRoot(capture.capture.commitments[2]);
    try r.check();
    if (r.root_count != 3 or r.relation_count != universal.RELATION_COUNT or r.nonce_pending != null) return error.InvalidBlake3ParentCapture;
    var planned = try shared.finishReplay(a, &arena, &r, &capture.capture, try admission.config(), capacity);
    owns_arena = false;
    errdefer planned.deinit();
    if (!std.mem.eql(u8, &planned.end.digestBytes(), &capture.channel.digestBytes()) or planned.end.n_draws != capture.channel.n_draws) return error.InvalidBlake3ParentCapture;
    return planned;
}
