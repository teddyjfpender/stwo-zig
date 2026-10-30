//! Canonical public transcript frame; rebuilt from independently selected
//! metadata and proposed physical claims, never trusted serialized offsets.
//! Finite protocol variants share implementation; window mode is a distinct key.
pub fn ForMode(comptime window: bool) type {
    return struct {
        const std = @import("std");
        const Profile = @import("../block_v7_memory_joint_fixed_profile_v1.zig").ForMode(window);
        const Protocol = if (window) @import("../../prover/block_v7_window_memory_joint_protocol_v1.zig") else @import("../../prover/block_v7_memory_joint_protocol_v1.zig");
        const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
        pub const PUBLIC_CIRCUIT: u32 = if (window) 4_200_032 else 4_200_031;
        pub const Statement = Frames.Statement;
        pub fn init(a: std.mem.Allocator, profile: *const Profile.Owned) !Statement {
            var b = Frames.Builder{ .allocator = a, .max_felts = profile.limits.layout.max_claims };
            defer b.deinit();
            const epoch = try b.digestWords(profile.input.epoch.digest);
            const pin = try Protocol.entry(profile.input.policy, &profile.layout, profile.input.roots);
            try Protocol.recordAfterChallenges(&b, pin, &profile.layout, profile.input.claims);
            try b.check();
            // The first recorded root is entry identity, followed by its two actual
            // first-round roots. Exact reconstruction pins every metadata word too.
            if (b.root_count != 3) return error.InvalidJointMemoryStatement;
            const roots = [3]u32{ b.root_offsets[1], b.root_offsets[2], 0 };
            const claims = try b.steps.toOwnedSlice(a);
            errdefer a.free(claims);
            const words = try b.data.toOwnedSlice(a);
            errdefer a.free(words);
            const felts = try b.fields.toOwnedSlice(a);
            return .{ .allocator = a, .words = words, .felts = felts, .first = &.{}, .claims = claims, .sealed_offset = epoch, .roots_offset = roots };
        }
    };
}
