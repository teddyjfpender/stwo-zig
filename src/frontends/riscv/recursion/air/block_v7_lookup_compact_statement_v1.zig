//! Canonical public words and felts from the exact original v7 compact lookup transcript.
const std = @import("std");
const Profile = @import("../block_v7_lookup_compact_fixed_profile_v1.zig");
const Native = @import("../../prover/block_v7_lookup_compact_proof_v1.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_052;
pub const Statement = Frames.Statement;
pub fn init(a: std.mem.Allocator, profile: *const Profile.Owned) !Statement {
    var b = Frames.Builder{ .allocator = a, .max_felts = 6 };
    defer b.deinit();
    const epoch = try b.digestWords(profile.input.policy.epoch.digest);
    try Native.recordAfterChallenges(&b, profile.input.policy, profile.input.claims);
    try b.check();
    if (b.root_count != 3) return error.InvalidCompactLookupStatement;
    const roots = [3]u32{ b.root_offsets[1], b.root_offsets[2], 0 };
    const steps = try b.steps.toOwnedSlice(a);
    errdefer a.free(steps);
    const words = try b.data.toOwnedSlice(a);
    errdefer a.free(words);
    const felts = try b.fields.toOwnedSlice(a);
    return .{ .allocator = a, .words = words, .felts = felts, .first = &.{}, .claims = steps, .sealed_offset = epoch, .roots_offset = roots };
}
