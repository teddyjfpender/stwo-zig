// Exact B8 endpoint original transcript: continue the shared epoch channel
// after all 53 relation pairs, then bind every physical source/provider claim.
const std = @import("std");
const core = @import("stwo_core");
const Whole = @import("../../prover/block_v8_compact_ram_proof_v1.zig");
const Profile = @import("../block_v8_compact_ram_profile_v1.zig");
const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
const Epoch = @import("block_v7_epoch_transcript_v1.zig");
const Cold = @import("blake3_fixed_operation_recorder_v1.zig");
const Live = @import("blake3_native_recorder.zig");
const Shared = @import("blake3_native_transcript.zig");
const Schema = @import("blake3_pcs_operation_schema_v1.zig");
const Roots = @import("blake3_root_sources.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_086;
pub fn statement(a: std.mem.Allocator, profile: *const Profile.Owned) !Frames.Statement {
    try profile.validate();
    var b = Frames.Builder{ .allocator = a, .track_root_offsets = false, .max_felts = 1 << 18 };
    defer b.deinit();
    const epoch = try b.digestWords(profile.statement.input.epoch.digest);
    try @import("../../prover/block_v8_compact_ram_scope_v1.zig").recordClaims(&b, profile.statement.input.epoch, profile.statement.input.roots, profile.claims.ram, profile.claims.boundary, profile.claims.ranges);
    try b.check();
    var roots_offset: [3]u32 = @splat(0);
    for (0..4) |index| {
        const root = profile.statement.input.roots[index];
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
fn begin(r: anytype, profile: *const Profile.Owned, frame: *const Frames.Statement) !void {
    r.mixU32s(&.{ profile.statement.input.epoch.sharedTag(), E.VERSION, 2 });
    r.mixPublicRoot(.{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.sealed_offset }, profile.statement.input.epoch.digest);
    try r.skipCommittedRootsBounded(4, profile.shape.columns.len);
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
    try frame.recordAt(&r, frame.claims, PUBLIC_CIRCUIT);
    for (4..7) |tree| try r.suffix(.{ .commitment = .{ .slot = @intCast(tree), .source = try Roots.caller(tree) } });
    var suffix: std.ArrayList(Schema.Operation) = .empty;
    try Schema.appendPcsSuffixBounded(t, &suffix, profile.statement.input.epoch.config, profile.shape.deepProfile(), profile.shape.friProfile(), profile.shape.columns.len);
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
    try frame.recordAt(&r, frame.claims, PUBLIC_CIRCUIT);
    var expected = (try profile.statement.input.epoch.draw(t)).channel;
    try @import("../../prover/block_v8_compact_ram_scope_v1.zig").recordClaims(&expected, profile.statement.input.epoch, profile.statement.input.roots, profile.claims.ram, profile.claims.boundary, profile.claims.ranges);
    if (r.relation_count != Profile.RELATION_PAIRS or !std.meta.eql(expected, r.native)) return error.InvalidEndpointTranscriptPrefix;
    for (4..7) |tree| r.mixRoot(capture.proof.commitments[tree]);
    try r.check();
    var result = try Shared.finishReplayForBoundedCommitments(a, &arena, &r, &capture.proof, profile.statement.input.epoch.config, capacity, profile.shape.columns.len);
    transferred = true;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidEndpointTranscriptCapture;
    return result;
}
