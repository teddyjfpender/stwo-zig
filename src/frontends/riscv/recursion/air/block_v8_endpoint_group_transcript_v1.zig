//! Exact Group original transcript, with dynamically bounded first roots and
//! every physical claim. Original Scope/Context supply the shared framing.
const std = @import("std");
const core = @import("stwo_core");
const Whole = @import("../../prover/block_v8_endpoint_group_proof_v1.zig");
const Profile = @import("../block_v8_endpoint_group_profile_v1.zig");
const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
const Epoch = @import("block_v7_epoch_transcript_v1.zig");
const Cold = @import("blake3_fixed_operation_recorder_v1.zig");
const Live = @import("blake3_native_recorder.zig");
const Shared = @import("blake3_native_transcript.zig");
const Schema = @import("blake3_pcs_operation_schema_v1.zig");
const Roots = @import("blake3_root_sources.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_087;
pub fn statement(a: std.mem.Allocator, profile: *const Profile.Owned) !Frames.Statement {
    try profile.validate();
    var b = Frames.Builder{ .allocator = a, .track_root_offsets = false, .max_felts = 1 << 18 };
    defer b.deinit();
    const epoch = try b.digestWords(profile.scope.epoch.digest);
    profile.scope.recordAfterDraws(&b);
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
    return .{ .allocator = a, .words = words, .felts = felts, .first = &.{}, .claims = steps, .sealed_offset = epoch, .roots_offset = roots_offset };
}
fn firstRoots(a: std.mem.Allocator, p: *const Profile.Owned) ![][32]u8 {
    const roots = try a.alloc([32]u8, p.layout.firstRoots());
    roots[0] = p.statement.input.fixed_root;
    for (p.statement.input.members, 0..) |member, i| {
        roots[p.layout.native(i)[1]] = member.native_main_root;
        roots[p.layout.endpoint(i)[1]] = member.endpoint_main_root;
    }
    roots[p.layout.range()[1]] = p.statement.input.range_main_root;
    roots[p.layout.program()[1]] = p.statement.input.program_roots[1];
    roots[p.layout.lookup()[1]] = p.statement.input.lookup_roots[1];
    return roots;
}
fn begin(r: anytype, profile: *const Profile.Owned, frame: *const Frames.Statement) !void {
    r.mixU32s(&.{ profile.scope.epoch.sharedTag(), E.VERSION, 2 });
    r.mixPublicRoot(.{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.sealed_offset }, profile.scope.epoch.digest);
    try r.skipCommittedRootsBounded(profile.layout.firstRoots(), profile.layout.traces() + 1);
}
pub fn fixed(a: std.mem.Allocator, profile: *const Profile.Owned, capacity: u32, limits: Cold.Limits) !@import("blake3_transcript_plan.zig").Plan {
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
    try frame.recordAt(&r, frame.claims, PUBLIC_CIRCUIT);
    for (profile.layout.firstRoots()..profile.layout.traces()) |tree| try r.suffix(.{ .commitment = .{ .slot = @intCast(tree), .source = try Roots.caller(tree) } });
    var suffix: std.ArrayList(Schema.Operation) = .empty;
    try Schema.appendPcsSuffixBounded(t, &suffix, profile.scope.epoch.config, profile.shape.deepProfile(), profile.shape.friProfile(), profile.layout.traces() + 1);
    for (suffix.items) |operation| try r.suffix(operation);
    try r.check();
    return @import("blake3_transcript_plan.zig").Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items);
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
    try frame.recordAt(&r, frame.claims, PUBLIC_CIRCUIT);
    const expected = try profile.context.channel();
    if (r.relation_count != Profile.RELATION_PAIRS or !std.meta.eql(expected, r.native)) return error.InvalidEndpointTranscriptPrefix;
    for (profile.layout.firstRoots()..profile.layout.traces()) |tree| r.mixRoot(capture.proof.commitments[tree]);
    try r.check();
    var result = try Shared.finishReplayForBoundedCommitments(a, &arena, &r, &capture.proof, profile.scope.epoch.config, capacity, profile.layout.traces() + 1);
    transferred = true;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidEndpointTranscriptCapture;
    return result;
}
