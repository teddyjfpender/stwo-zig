//! Shared four-tree, 53-relation original-verifier plumbing. Finite typed
//! definitions supply equations/framing; no captured metadata selects code.
pub fn For(comptime D: type) type {
    return struct {
        //! Shape-only transcript plan, without proof nonce, samples, roots or claims
        //! becoming circuit constants. Those operands use canonical public routes.
        const std = @import("std");
        const Profile = D.Profile;
        const Statement = D.Statement;
        const Prefix = D.Transcript;
        const Sink = @import("air/blake3_fixed_operation_recorder_v1.zig");
        const Schema = @import("air/blake3_pcs_operation_schema_v1.zig");
        pub fn derive(a: std.mem.Allocator, profile: *const Profile.Owned, capacity: u32, limits: Sink.Limits) !@import("air/blake3_transcript_plan.zig").Plan {
            return deriveWithShared(a, profile, capacity, limits, false);
        }
        pub fn deriveWithShared(a: std.mem.Allocator, profile: *const Profile.Owned, capacity: u32, limits: Sink.Limits, shared_epoch: bool) !@import("air/blake3_transcript_plan.zig").Plan {
            if (capacity == 0 or limits.max_operations == 0 or limits.max_routed_words == 0) return error.InvalidJointMemoryTranscript;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const temp = arena.allocator();
            var statement = try Statement.init(temp, profile);
            defer statement.deinit();
            var r = Sink.Recorder{ .a = temp, .limits = limits };
            try Prefix.prefixFixed(temp, &r, profile, &statement);
            if (r.skipped_roots != 2) return error.InvalidJointMemoryTranscript;
            try r.suffix(.{ .commitment = .{ .slot = 2, .source = try @import("air/blake3_root_sources.zig").caller(2) } });
            var suffix: std.ArrayList(Schema.Operation) = .empty;
            try Schema.appendPcsSuffix(temp, &suffix, profile.config, profile.deepProfile(), profile.friProfile(), 4);
            for (suffix.items) |operation| try r.suffix(operation);
            try r.check();
            if (shared_epoch) return @import("air/block_v7_shared_epoch_transcript_v1.zig").derive(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items, false);
            return @import("air/blake3_transcript_plan.zig").Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items);
        }
    };
}
