//! Exact two-stream union grammar: epoch challenge generation, then an
//! explicit constrained channel reset before the union STARK prefix. All
//! physical claim frames are public operands, never captured constants.
const std = @import("std");
const core = @import("stwo_core");
const Multi = @import("../../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Profile = @import("../block_v7_union_fixed_profile_v1.zig").ForMode(true);
const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
const Epoch = @import("block_v7_epoch_transcript_v1.zig");
const Cold = @import("blake3_fixed_operation_recorder_v1.zig");
const Live = @import("blake3_native_recorder.zig");
const Shared = @import("blake3_native_transcript.zig");
const Schema = @import("blake3_pcs_operation_schema_v1.zig");
const Roots = @import("blake3_root_sources.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_037;
pub fn firstInteraction(profile: *const Profile.Owned) !usize {
    var first: usize = 1;
    for (profile.statement.input.entries) |entry| {
        if (entry.root_count < 2 or entry.root_count > 3) return error.InvalidUnionTranscriptRoots;
        first = try std.math.add(usize, first, entry.root_count - 1);
    }
    if (first >= profile.trace_count) return error.InvalidUnionTranscriptRoots;
    return first;
}
pub fn statement(a: std.mem.Allocator, profile: *const Profile.Owned, claims: *const Multi.Claims) !Frames.Statement {
    var components = try Multi.AdmittedComponents.init(a, profile.statement.trusted, profile.statement.input, claims, profile.limits.original);
    defer components.deinit();
    return statementFromComponents(a, profile, &components);
}
/// Structural frame recording from the independently admitted source owner.
pub fn statementFromComponents(a: std.mem.Allocator, profile: *const Profile.Owned, components: *const Multi.AdmittedComponents) !Frames.Statement {
    var b = Frames.Builder{ .allocator = a, .track_root_offsets = false, .max_felts = 1 << 18 };
    defer b.deinit();
    const epoch = try b.digestWords(profile.statement.input.epoch.digest);
    try components.recordPrefix(&b, profile.fixed_root);
    try b.check();
    const first = try firstInteraction(profile);
    const root_values = try a.alloc([32]u8, first);
    defer a.free(root_values);
    @memset(root_values, @splat(0));
    root_values[0] = profile.fixed_root;
    for (components.scope.sources, components.scope.placement.parts) |source, part| for (1..source.entry.root_count) |index| {
        if (part.map[index] >= first) return error.InvalidUnionTranscriptRoots;
        root_values[part.map[index]] = source.entry.roots[index];
    };
    // Public-only tail: these roots are not absorbed again. Their exact
    // independent placement binds the Merkle path boundary suppliers.
    var roots_offset: [3]u32 = undefined;
    for (root_values, 0..) |root, index| {
        const offset = try b.digestWords(root);
        if (index < roots_offset.len) roots_offset[index] = offset;
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
    try r.skipCommittedRootsBounded(try firstInteraction(profile), profile.trace_count + 1);
}
pub fn fixed(a: std.mem.Allocator, profile: *const Profile.Owned, claims: *const Multi.Claims, capacity: u32, limits: Cold.Limits) !@import("blake3_transcript_plan.zig").Plan {
    try profile.validateAgainst(claims);
    if (capacity == 0) return error.InvalidUnionTranscriptCapacity;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    var frame = try statement(t, profile, claims);
    defer frame.deinit();
    return fixedFromFrame(a, profile, &frame, capacity, limits);
}
pub fn fixedFromFrame(a: std.mem.Allocator, profile: *const Profile.Owned, frame: *const Frames.Statement, capacity: u32, limits: Cold.Limits) !@import("blake3_transcript_plan.zig").Plan {
    if (capacity == 0) return error.InvalidUnionTranscriptCapacity;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    var r = Cold.Recorder{ .a = t, .limits = limits };
    try begin(&r, profile, frame);
    try Epoch.fixed(t, &r);
    try @import("block_v7_union_caller_draws_v1.zig").appendFixed(t, &r, profile, .{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.sealed_offset });
    try r.restartChannel();
    try frame.recordAt(&r, frame.claims, PUBLIC_CIRCUIT);
    for (try firstInteraction(profile)..profile.trace_count) |tree| try r.suffix(.{ .commitment = .{ .slot = @intCast(tree), .source = try Roots.caller(tree) } });
    var suffix: std.ArrayList(Schema.Operation) = .empty;
    try Schema.appendPcsSuffixBounded(t, &suffix, profile.statement.input.epoch.config, profile.shape.deepProfile(), profile.shape.friProfile(), profile.trace_count + 1);
    for (suffix.items) |operation| try r.suffix(operation);
    try r.check();
    return @import("blake3_transcript_plan.zig").Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items);
}
pub fn replay(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture, capacity: u32) !Shared.Planned {
    try profile.validateAgainst(&capture.claims);
    if (capacity == 0 or capture.proof.commitments.len != profile.trace_count + 1 or !std.meta.eql(capture.proof.commitments[0], profile.fixed_root)) return error.InvalidUnionTranscriptCapture;
    var components = try Multi.AdmittedComponents.init(a, profile.statement.trusted, profile.statement.input, &capture.claims, profile.limits.original);
    defer components.deinit();
    var frame = try statementFromComponents(a, profile, &components);
    defer frame.deinit();
    return replayFromFrame(a, profile, capture, &frame, capacity);
}
/// The immutable compiler owns the admitted frame; witness operations borrow
/// its values only during this call and retain their own operation storage.
pub fn replayFromFrame(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture, frame: *const Frames.Statement, capacity: u32) !Shared.Planned {
    if (capacity == 0 or capture.proof.commitments.len != profile.trace_count + 1 or !std.meta.eql(capture.proof.commitments[0], profile.fixed_root)) return error.InvalidUnionTranscriptCapture;
    var arena = std.heap.ArenaAllocator.init(a);
    var transferred = false;
    defer if (!transferred) arena.deinit();
    const t = arena.allocator();
    const owned_frame = try frame.clone(t);
    var r = Live.Recorder{ .a = t, .universal_relations = true };
    begin(&r, profile, &owned_frame) catch |err| return if (err == error.InvalidNativeBlake3Transcript) error.InvalidUnionTranscriptRootInventory else err;
    Epoch.live(t, &r) catch |err| return if (err == error.InvalidNativeBlake3Transcript) error.InvalidUnionTranscriptEpochDraw else err;
    try @import("block_v7_union_caller_draws_v1.zig").appendLive(t, &r, profile, .{ .circuit = PUBLIC_CIRCUIT, .first_wire = owned_frame.sealed_offset });
    try r.restartChannel();
    try owned_frame.recordAt(&r, owned_frame.claims, PUBLIC_CIRCUIT);
    var expected = core.proof_suites.Blake3.Channel{};
    try owned_frame.replay(&expected, owned_frame.claims);
    if (r.relation_count != try @import("block_v7_union_caller_draws_v1.zig").pairCount(profile.statement.input.callers.len) or !std.meta.eql(expected, r.native)) return error.InvalidUnionTranscriptPrefix;
    for (try firstInteraction(profile)..profile.trace_count) |tree| r.mixRoot(capture.proof.commitments[tree]);
    try r.check();
    var result = Shared.finishReplayForBoundedCommitments(a, &arena, &r, &capture.proof, profile.statement.input.epoch.config, capacity, profile.trace_count + 1) catch |err| return if (err == error.InvalidNativeBlake3Transcript) error.InvalidUnionTranscriptPcsSuffix else err;
    transferred = true;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidUnionTranscriptCapture;
    return result;
}
