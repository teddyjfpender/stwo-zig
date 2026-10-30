//! Exact v7 shared epoch draw and joint-original transcript. Only its actual
//! Word52 + interval pair is traversed; compatibility byte draws are a separate
//! native channel and never influence the original proof channel.
const std = @import("std");
const core = @import("stwo_core");
const Profile = @import("../block_v7_program_fixed_profile_v1.zig");
const Program = @import("../../prover/block_v7_program_provider_v1.zig");
const Protocol = Program;
const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
const Statement = @import("block_v7_program_statement_v1.zig");
const Recorder = @import("blake3_native_recorder.zig");
const Sink = @import("blake3_fixed_operation_recorder_v1.zig");
const Shared = @import("blake3_native_transcript.zig");
pub const RELATION_PAIRS: usize = 53;
fn begin(r: anytype, profile: *const Profile.Owned, statement: *const Statement.Statement) !void {
    r.mixU32s(&.{ profile.input.policy.epoch.sharedTag(), E.VERSION, 2 });
    r.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, profile.input.policy.epoch.digest);
    try r.skipCommittedRoots(2);
}
pub fn prefixFixed(a: std.mem.Allocator, r: *Sink.Recorder, profile: *const Profile.Owned, statement: *const Statement.Statement) !void {
    try begin(r, profile, statement);
    try @import("block_v7_epoch_transcript_v1.zig").fixed(a, r);
    try statement.recordAt(r, statement.claims, Statement.PUBLIC_CIRCUIT);
}
pub fn prefix(a: std.mem.Allocator, r: *Recorder.Recorder, profile: *const Profile.Owned, statement: *const Statement.Statement) !void {
    if (!r.universal_relations or r.root_count != 0 or r.relation_count != 0) return error.InvalidProgramTranscript;
    try begin(r, profile, statement);
    try @import("block_v7_epoch_transcript_v1.zig").live(a, r);
    try statement.recordAt(r, statement.claims, Statement.PUBLIC_CIRCUIT);
    try r.check();
    if (r.relation_count != RELATION_PAIRS or r.root_count != 2) return error.InvalidProgramTranscript;
    const drawn = try profile.input.policy.epoch.draw(a);
    const expected = try Protocol.channel(profile.input.policy, drawn, profile.input.claim);
    if (!std.meta.eql(expected, r.native)) return error.InvalidProgramTranscript;
}
pub fn planReplay(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Program.VerifiedCapture, capacity: u32) !Shared.Planned {
    if (capacity == 0 or capture.proof.commitments.len != 4 or
        !std.meta.eql(capture.receipt.roots, profile.input.policy.roots) or
        !std.meta.eql(capture.receipt.epoch, profile.input.policy.epoch.digest) or
        !std.meta.eql(capture.receipt.plan, try profile.input.policy.plan.digest()) or
        !capture.receipt.claim.eql(profile.input.claim) or capture.receipt.fetch_count != profile.input.policy.plan.expected_fetches) return error.InvalidProgramTranscript;
    var arena = std.heap.ArenaAllocator.init(a);
    var owned = true;
    defer if (owned) arena.deinit();
    const temp = arena.allocator();
    var statement = try Statement.init(temp, profile);
    // The completed replay owns this arena, including statement storage.
    defer if (owned) statement.deinit();
    var r = Recorder.Recorder{ .a = temp, .universal_relations = true };
    try prefix(temp, &r, profile, &statement);
    r.mixRoot(capture.proof.commitments[2]);
    try r.check();
    var result = try Shared.finishReplay(a, &arena, &r, &capture.proof, profile.config, capacity);
    owned = false;
    errdefer result.deinit();
    if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidProgramTranscript;
    return result;
}
