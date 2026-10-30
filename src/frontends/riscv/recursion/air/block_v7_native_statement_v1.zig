//! Exact original v7 native public framing. Not proof authority.
const std = @import("std");
const Profile = @import("../block_v7_native_fixed_profile_v1.zig");
const Native = @import("../../prover/block_v7_native_proof_v1.zig");
const Fused = @import("../../prover/block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("../../prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_032;
pub const Statement = Frames.Statement;
pub fn init(a: std.mem.Allocator, profile: *const Profile.Owned, claims: []const Fused.Claim, memory: []const Memory.Claim) !Statement {
    var b = Frames.Builder{ .allocator = a };
    defer b.deinit();
    const epoch = try b.digestWords(profile.epoch.digest);
    const entry = try profile.pin.entry(a);
    try Native.recordAfterChallenges(&b, profile.pin, entry, profile.projections, profile.slots, claims, memory);
    try b.check();
    // Entry identity precedes the two/three first roots; then template and
    // native identities and the access roster's template are repeated exactly.
    if (b.root_count != entry.root_count + 4) return error.InvalidNativeStatement;
    const roots = [3]u32{ b.root_offsets[1], b.root_offsets[2], if (entry.root_count == 3) b.root_offsets[3] else 0 };
    const steps = try b.steps.toOwnedSlice(a);
    errdefer a.free(steps);
    const words = try b.data.toOwnedSlice(a);
    errdefer a.free(words);
    const felts = try b.fields.toOwnedSlice(a);
    return .{ .allocator = a, .words = words, .felts = felts, .first = &.{}, .claims = steps, .sealed_offset = epoch, .roots_offset = roots };
}
