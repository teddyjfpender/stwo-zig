//! Metadata-only V7CJ1 transcript plan. No captured channel, nonce, samples,
//! query positions or proposed key is used. Claims are exact public operands.
//! Shared implementation: default and finite active caller families.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const Admission = Policy.Admission;
        const Profile = @import("../prover/blake3_ethereum_sha_profile.zig");
        const Fused = @import("../prover/block_v5_caller_fused_proof_v1.zig");
        const Statement = Policy.Statement;
        const Prefix = Policy.Transcript;
        const Sink = @import("air/blake3_fixed_operation_recorder_v1.zig");
        const Schema = @import("air/blake3_pcs_operation_schema_v1.zig");
        const Roots = @import("air/blake3_root_sources.zig");
        pub fn derive(a: std.mem.Allocator, admitted: *const Admission.Prepared, arithmetic: *const Profile.ExtensionClaim, relations: *const Fused.ClaimFrames, capacity: u32, limits: Sink.Limits) !@import("air/blake3_transcript_plan.zig").Plan {
            return deriveWithShared(a, admitted, arithmetic, relations, capacity, limits, false);
        }
        pub fn deriveWithShared(a: std.mem.Allocator, admitted: *const Admission.Prepared, arithmetic: *const Profile.ExtensionClaim, relations: *const Fused.ClaimFrames, capacity: u32, limits: Sink.Limits, shared_epoch: bool) !@import("air/blake3_transcript_plan.zig").Plan {
            if (capacity == 0 or limits.max_operations == 0 or limits.max_routed_words == 0) return error.InvalidJointCallerTranscript;
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const temp = arena.allocator();
            var shape = try Policy.Shape.derive(temp, admitted);
            defer shape.deinit();
            var statement = try Statement.init(temp, admitted, arithmetic, relations);
            defer statement.deinit();
            var recorder = Sink.Recorder{ .a = temp, .limits = limits };
            try Prefix.prefixFixed(temp, &recorder, admitted, &statement);
            if (recorder.skipped_roots != 3) return error.InvalidJointCallerTranscript;
            for (3..5) |slot| try recorder.suffix(.{ .commitment = .{ .slot = slot, .source = try Roots.caller(slot) } });
            var suffix: std.ArrayList(Schema.Operation) = .empty;
            try Schema.appendPcsSuffix(temp, &suffix, admitted.arithmetic.config, shape.deepProfile(), shape.friProfile(), 6);
            for (suffix.items) |operation| try recorder.suffix(operation);
            try recorder.check();
            if (shared_epoch) return @import("air/block_v7_shared_epoch_transcript_v1.zig").derive(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, recorder.operations.items, true);
            return @import("air/blake3_transcript_plan.zig").Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, recorder.operations.items);
        }
    };
}
