//! Exact Mixed original transcript, with dynamically bounded first roots and
//! every physical claim. Original Scope/Context supply the shared framing.
const std = @import("std");
const core = @import("stwo_core");
const Whole = @import("../../prover/block_v8_endpoint_mixed_proof_v1.zig");
const Profile = @import("../block_v8_endpoint_mixed_profile_v1.zig");
const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
const Epoch = @import("block_v7_epoch_transcript_v1.zig");
const Cold = @import("blake3_fixed_operation_recorder_v1.zig");
const Live = @import("blake3_native_recorder.zig");
const Shared = @import("blake3_native_transcript.zig");
const Schema = @import("blake3_pcs_operation_schema_v1.zig");
const Roots = @import("blake3_root_sources.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_089;
pub fn statement(a: std.mem.Allocator, profile: *const Profile.Owned) !Frames.Statement {
    try profile.validate();
    var b = Frames.Builder{ .allocator = a, .track_root_offsets = false, .max_felts = 1 << 18 };
    defer b.deinit();
    const epoch = try b.digestWords(profile.scope.epoch.digest);
    profile.scope.recordAfterDraws(&b);
    b.mixU32s(&.{ 0x42384d58, 1 });
    try b.check();
    const first = try b.steps.toOwnedSlice(a);
    errdefer a.free(first);
    try profile.context.recordPhysicalClaims(&b);
    try b.check();
    var roots_offset: [3]u32 = @splat(0);
    const roots = try firstRoots(a, profile);
    defer a.free(roots);
    for (roots, 0..) |root, index| {
        const offset = try b.digestWords(root);
        if (index < 3) roots_offset[index] = offset;
    }
    const steps = try b.steps.toOwnedSlice(a);
    errdefer a.free(steps);
    const words = try b.data.toOwnedSlice(a);
    errdefer a.free(words);
    const felts = try b.fields.toOwnedSlice(a);
    return .{ .allocator = a, .words = words, .felts = felts, .first = first, .claims = steps, .sealed_offset = epoch, .roots_offset = roots_offset };
}
fn firstRoots(a: std.mem.Allocator, p: *const Profile.Owned) ![][32]u8 {
    const i = p.statement.input;
    return a.dupe([32]u8, &.{ i.native_roots[0], i.native_roots[1], i.native_roots[2], i.native_roots[3], i.program_roots[1], i.lookup_roots[1], i.caller_roots[1] });
}

fn begin(r: anytype, profile: *const Profile.Owned, frame: *const Frames.Statement) !void {
    r.mixU32s(&.{ profile.scope.epoch.sharedTag(), E.VERSION, 2 });
    r.mixPublicRoot(.{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.sealed_offset }, profile.scope.epoch.digest);
    try r.skipCommittedRootsBounded(7, 14 + 1);
}
pub fn fixed(a: std.mem.Allocator, profile: *const Profile.Owned, capacity: u32, limits: Cold.Limits) !@import("blake3_transcript_plan.zig").Plan {
    var schedule = try opSchedule(a, profile, capacity, limits);
    defer schedule.deinit();
    return schedule.compileNative(a);
}
/// Original grammar before NativeParent AIR row materialization. No capture/receipt.
pub fn opSchedule(a: std.mem.Allocator, profile: *const Profile.Owned, capacity: u32, limits: Cold.Limits) !@import("blake3_original_op_schedule_v1.zig").Owned {
    try profile.validate();
    if (capacity == 0) return error.InvalidEndpointTranscriptCapacity;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    var frame = try statement(t, profile);
    defer frame.deinit();
    var r = Cold.Recorder{ .a = t, .limits = limits };
    try begin(&r, profile, &frame);
    try Epoch.fixed(t, &r);
    try frame.recordAt(&r, frame.first, PUBLIC_CIRCUIT);
    try r.universalPairs(53, 13);
    r.mixU32s(&.{ 0x53484157, 1 });
    try r.universalPairs(66, 1);
    try frame.recordAt(&r, frame.claims, PUBLIC_CIRCUIT);
    for (7..14) |tree| try r.suffix(.{ .commitment = .{ .slot = @intCast(tree), .source = try Roots.caller(tree) } });
    var suffix: std.ArrayList(Schema.Operation) = .empty;
    try Schema.appendPcsSuffixBounded(t, &suffix, profile.scope.epoch.config, profile.shape.deepProfile(), profile.shape.friProfile(), 14 + 1);
    for (suffix.items) |operation| try r.suffix(operation);
    try r.check();
    return @import("blake3_original_op_schedule_v1.zig").Owned.capture(a, &frame, &r, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, PUBLIC_CIRCUIT, profile.seal);
}
pub fn replay(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Whole.VerifiedCapture, capacity: u32) !Shared.Planned {
    try profile.requireCapture(capture);
    if (capacity == 0) return error.InvalidEndpointTranscriptCapacity;
    var arena = std.heap.ArenaAllocator.init(a);
    var transferred = false;
    defer if (!transferred) arena.deinit();
    const t = arena.allocator();
    var frame = try statement(t, profile);
    var r = Live.Recorder{ .a = t, .universal_relations = true };
    try begin(&r, profile, &frame);
    try Epoch.live(t, &r);
    try frame.recordAt(&r, frame.first, PUBLIC_CIRCUIT);
    // Relations.drawAfterVm uses the recorder's current index, preserving
    // all53 epoch relations before the14 source-local extension relations.
    _ = try @import("../../prover/blake3_ethereum_sha_profile.zig").Relations.drawAfterVm(t, &r, profile.context.drawn.word.universal_prefix);
    try frame.recordAt(&r, frame.claims, PUBLIC_CIRCUIT);
    const expected = try profile.context.channel();
    if (r.relation_count != Profile.RELATION_PAIRS or !std.meta.eql(expected, r.native)) return error.InvalidEndpointTranscriptPrefix;
    for (7..14) |tree| r.mixRoot(capture.proof.commitments[tree]);
    try r.check();
    var result = try Shared.finishReplayForBoundedCommitments(a, &arena, &r, &capture.proof, profile.scope.epoch.config, capacity, 14 + 1);
    transferred = true;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidEndpointTranscriptCapture;
    return result;
}
