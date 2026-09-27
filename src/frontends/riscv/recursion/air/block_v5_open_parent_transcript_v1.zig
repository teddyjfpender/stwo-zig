//! V5 open-parent verifier transcript. Dynamic admission frames use external
//! public routing and never consume canonical PCS commitment indices.
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
    const child_protocol = @import("../block_v5_reusable_native_parent_protocol_v1.zig");
    const public = @import("../block_v5_open_parent_public_bus_v1.zig");
    // Replay the child protocol exactly, retaining native operation boundaries.
    r.mixU32s(&.{ 0x42355250, child_protocol.VERSION, @intFromEnum(admission.key.profile) });
    admission.key.config.mixInto(&r);
    r.mixStaticRoot(admission.expected_id); // invariant child setup identity
    r.mixPublicWords(.{ .circuit = public.PUBLIC_CIRCUIT, .first_wire = 0 }, &.{ 0x42355049, 1, admission.values.index });
    for ([_][32]u8{ admission.values.sealed, admission.values.template, admission.values.instance, admission.values.roots[0], admission.values.roots[1], admission.values.statement_digest }, 0..) |digest, index|
        r.mixPublicRoot(.{ .circuit = public.PUBLIC_CIRCUIT, .first_wire = 8 + 8 * @as(u32, @intCast(index)) }, digest);
    r.mixPublicFelts(.{ .circuit = public.PUBLIC_CIRCUIT, .first_wire = 56 }, &.{ admission.values.compensation, admission.values.open_sum });
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
