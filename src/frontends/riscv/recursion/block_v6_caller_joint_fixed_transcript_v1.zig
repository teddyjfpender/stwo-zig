//! Metadata-only B6CJ1 transcript plan. No captured channel, nonce, samples,
//! query positions or proposed key is used. Claims are exact public operands.
const std = @import("std");
const Admission = @import("../prover/block_v6_caller_joint_admission_v1.zig");
const Profile = @import("../prover/blake3_ethereum_sha_profile.zig");
const Fused = @import("../prover/block_v5_caller_fused_proof_v1.zig");
const Statement = @import("air/block_v6_caller_joint_statement_v1.zig");
const Prefix = @import("air/block_v6_caller_joint_transcript_v1.zig");
const Sink = @import("air/blake3_fixed_operation_recorder_v1.zig");
const Schema = @import("air/blake3_pcs_operation_schema_v1.zig");
const Roots = @import("air/blake3_root_sources.zig");
pub fn derive(a: std.mem.Allocator, admitted: *const Admission.Prepared, arithmetic: *const Profile.ExtensionClaim, relations: *const Fused.ClaimFrames, capacity: u32, limits: Sink.Limits) !@import("air/blake3_transcript_plan.zig").Plan {
    if (capacity == 0 or limits.max_operations == 0 or limits.max_routed_words == 0) return error.InvalidJointCallerTranscript;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var shape = try @import("block_v6_caller_joint_pcs_shape_v1.zig").derive(temp, admitted);
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
    return @import("air/blake3_transcript_plan.zig").Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, recorder.operations.items);
}
