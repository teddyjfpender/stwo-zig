//! Exact child Join transcript. Public prefix and both initial commitments are
//! externally routed; every native-parent physical claim remains private AIR.
const std = @import("std");
const Profile = @import("../block_v8_window_root_profile_v1.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
const Cold = @import("blake3_fixed_operation_recorder_v1.zig");
const Live = @import("blake3_native_recorder.zig");
const Shared = @import("blake3_native_transcript.zig");
const Roots = @import("blake3_root_sources.zig");
const Schema = @import("blake3_pcs_operation_schema_v1.zig");
pub const PUBLIC_CIRCUIT = 4_800_001;
pub fn statement(a: std.mem.Allocator, p: *const Profile.Owned) !Frames.Statement {
    try p.validate();
    var b = Frames.Builder{ .allocator = a, .track_root_offsets = false, .max_words = 1 << 22, .max_felts = 1 << 20 };
    defer b.deinit();
    try p.admission.mix(&b);
    const first = try b.steps.toOwnedSlice(a);
    errdefer a.free(first);
    // Both roots occupy the final sixteen words, as required by the generic
    // exact per-tree public bus. Their actual mix follows admission framing.
    const r0 = try b.digestWords(p.fixed_root);
    const r1 = try b.digestWords(p.main_root);
    try b.check();
    return .{ .allocator = a, .words = try b.data.toOwnedSlice(a), .felts = try b.fields.toOwnedSlice(a), .first = first, .claims = &.{}, .sealed_offset = 0, .roots_offset = .{ r0, r1, 0 } };
}
fn begin(r: anytype, frame: *const Frames.Statement) !void {
    try frame.recordAt(r, frame.first, PUBLIC_CIRCUIT);
    for (0..2) |tree| r.mixPublicRoot(.{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.roots_offset[tree] }, try frame.digest(frame.roots_offset[tree]));
    try r.skipCommittedRoots(2);
}
pub fn fixed(a: std.mem.Allocator, p: *const Profile.Owned, capacity: u32, limits: Cold.Limits) !@import("blake3_transcript_plan.zig").Plan {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    var frame = try statement(t, p);
    defer frame.deinit();
    var r = Cold.Recorder{ .a = t, .limits = limits };
    try begin(&r, &frame);
    try r.universalPairs(0, Profile.RELATION_PAIRS);
    try r.suffix(.{ .claim_frame = .{ .tag = .{ p.admission.claim_tag, 1, @import("../blake3_native_parent_artifact.zig").CLAIM_COUNT }, .count = @import("../blake3_native_parent_artifact.zig").CLAIM_COUNT, .source = .{ .circuit = Live.CLAIM_CIRCUIT, .first_wire = 0 } } });
    try r.suffix(.{ .commitment = .{ .slot = 2, .source = try Roots.caller(2) } });
    var suffix: std.ArrayList(Schema.Operation) = .empty;
    try Schema.appendPcsSuffixBounded(t, &suffix, p.shape.config, p.shape.deepProfile(), p.shape.friProfile(), 4);
    for (suffix.items) |operation| try r.suffix(operation);
    try r.check();
    return @import("blake3_transcript_plan.zig").Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items);
}
pub fn replay(a: std.mem.Allocator, p: *const Profile.Owned, c: *const Profile.Capture, capacity: u32) !Shared.Planned {
    try p.requireCapture(c);
    var arena = std.heap.ArenaAllocator.init(a);
    var transferred = false;
    defer if (!transferred) arena.deinit();
    const t = arena.allocator();
    var frame = try statement(t, p);
    var r = Live.Recorder{ .a = t, .universal_relations = true };
    try begin(&r, &frame);
    const relations = try @import("universal_challenges.zig").UniversalRelations.draw(t, &r);
    if (!std.meta.eql(relations, c.parent.relations)) return error.InvalidB8WindowRootTranscript;
    r.private_felts = true;
    try p.admission.mixClaims(&r, &c.parent.claims);
    r.mixRoot(c.proof.commitments[2]);
    try r.check();
    var result = try Shared.finishReplayForBoundedCommitments(a, &arena, &r, &c.proof, p.shape.config, capacity, 4);
    transferred = true;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, c.final_channel)) return error.InvalidB8WindowRootTranscript;
    return result;
}
