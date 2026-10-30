//! Exact actual v7 entry/physical-claim public frame, independently reconstructed.
//! Shared implementation: default and finite active caller families.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const Admission = Policy.Admission;
        const Source = Policy.Source;
        const Profile = @import("../../prover/blake3_ethereum_sha_profile.zig");
        const Fused = @import("../../prover/block_v5_caller_fused_proof_v1.zig");
        const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
        pub const PUBLIC_CIRCUIT: u32 = Policy.public_circuit;
        pub const Statement = Frames.Statement;
        pub fn init(a: std.mem.Allocator, admitted: *const Admission.Prepared, arithmetic: *const Profile.ExtensionClaim, relations: *const Fused.ClaimFrames) !Statement {
            var b = Frames.Builder{ .allocator = a, .max_felts = admitted.limits.max_claims };
            defer b.deinit();
            const epoch = try b.digestWords(admitted.epoch.digest);
            const entry = try admitted.pin().require(a, admitted.epoch, admitted.entries);
            b.mixU32s(&.{ Source.TAG, Source.VERSION, 1 });
            entry.mix(&b);
            try b.check();
            if (b.root_count != 4) return error.InvalidV7CallerStatement;
            const roots = [3]u32{ b.root_offsets[1], b.root_offsets[2], b.root_offsets[3] };
            const first = try b.steps.toOwnedSlice(a);
            errdefer a.free(first);
            try Source.recordAfterChallenges(&b, admitted.pin(), entry, &admitted.relations.schedule, arithmetic, relations);
            try b.check();
            const claims = try b.steps.toOwnedSlice(a);
            errdefer a.free(claims);
            const words = try b.data.toOwnedSlice(a);
            errdefer a.free(words);
            const felts = try b.fields.toOwnedSlice(a);
            return .{ .allocator = a, .words = words, .felts = felts, .first = first, .claims = claims, .sealed_offset = epoch, .roots_offset = roots };
        }
    };
}
