//! V7 original native transcript with shared exact epoch draw grammar.
const std = @import("std");
const Profile = @import("../block_v7_native_fixed_profile_v1.zig");
const Native = @import("../../prover/block_v7_native_proof_v1.zig");
const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
const Statement = @import("block_v7_native_statement_v1.zig");
const Epoch = @import("block_v7_epoch_transcript_v1.zig");
const Live = @import("blake3_native_recorder.zig");
const Cold = @import("blake3_fixed_operation_recorder_v1.zig");
const Shared = @import("blake3_native_transcript.zig");
fn begin(r: anytype, profile: *const Profile.Owned, statement: *const Statement.Statement) !void {
    r.mixU32s(&.{ profile.epoch.sharedTag(), E.VERSION, 2 });
    r.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, profile.epoch.digest);
    try r.skipCommittedRoots(profile.trace_count - 1);
}
pub fn prefixFixed(a: std.mem.Allocator, r: *Cold.Recorder, profile: *const Profile.Owned, statement: *const Statement.Statement) !void {
    try begin(r, profile, statement);
    try Epoch.fixed(a, r);
    try statement.recordAt(r, statement.claims, Statement.PUBLIC_CIRCUIT);
}
pub fn planReplay(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Native.VerifiedCapture, capacity: u32) !Shared.Planned {
    try profile.validate();
    if (capacity == 0 or capture.proof.commitments.len != profile.trace_count + 1) return error.InvalidNativeTranscript;
    var arena = std.heap.ArenaAllocator.init(a);
    var owns = true;
    defer if (owns) arena.deinit();
    const temp = arena.allocator();
    var statement = try Statement.init(temp, profile, capture.claims, capture.memory_claims);
    // The completed replay owns this arena, including statement storage.
    defer if (owns) statement.deinit();
    var r = Live.Recorder{ .a = temp, .universal_relations = true };
    try begin(&r, profile, &statement);
    try Epoch.live(temp, &r);
    try statement.recordAt(&r, statement.claims, Statement.PUBLIC_CIRCUIT);
    const drawn = try profile.epoch.draw(temp);
    const expected = try Native.channel(&drawn, profile.pin, try profile.pin.entry(temp), profile.projections, profile.slots, capture.claims, capture.memory_claims);
    if (!std.meta.eql(expected, r.native) or r.relation_count != 53) return error.InvalidNativeTranscript;
    r.mixRoot(capture.proof.commitments[profile.trace_count - 1]);
    try r.check();
    var result = try Shared.finishReplay(a, &arena, &r, &capture.proof, profile.epoch.config, capacity);
    owns = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidNativeTranscript;
    return result;
}
