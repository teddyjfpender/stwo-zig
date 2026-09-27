//! Exact independently reconstructed typed transport geometry, never authority.
const std = @import("std");
const core = @import("stwo_core");
const Codec = @import("block_v5_cpu_stark_codec_v1.zig");
const Classification = @import("block_v5_readonly_input_proof_v1.zig");
const Spec = @import("block_v5_readonly_input_component_v1.zig").Spec;
pub fn native(pin: Classification.Pin, index: u32, intervals: usize, seal: [32]u8) !Codec.Expected {
    try pin.validate();
    if (intervals == 0 or intervals > pin.limits.max_intervals) return error.ReadonlyInputProofResourceLimit;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ @intFromEnum(Codec.Family.native_readonly), index, pin.events, pin.row_log });
    channel.mixRoot(seal);
    channel.mixRoot(pin.plan_digest);
    channel.mixRoot(pin.source_identity);
    for (pin.roots) |root| channel.mixRoot(root);
    channel.mixU64(intervals);
    channel.mixU64(pin.limits.max_matrix_bytes);
    channel.mixU64(pin.limits.max_events);
    channel.mixU64(pin.limits.max_log);
    channel.mixU64(pin.limits.max_intervals);
    pin.config.mixInto(&channel);
    return .{ .family = .native_readonly, .index = index, .policy_digest = channel.digestBytes(), .config = pin.config, .roots = .{ pin.roots[0], pin.roots[1], @splat(0) }, .geometry = .{ .tree_count = 4, .tree_columns = .{ Spec.FIXED_COUNT, Spec.MAIN_COUNT, Spec.INTERACTION_COUNT, @intCast(core.verifier_types.compositionColumnCount(Spec.EXPANSION_BITS, core.fields.qm31.SECURE_EXTENSION_DEGREE).?), 0 }, .max_column_log = pin.row_log, .max_merkle_log = pin.row_log }, .claim_count = 1, .readonly_interval_count = std.math.cast(u32, intervals) orelse return error.Overflow };
}
fn caller(a: std.mem.Allocator, pin: @import("block_v5_caller_readonly_receiver_v1.zig").Pin, config: core.pcs.PcsConfig, seal: [32]u8) !Codec.Expected {
    var plan = try pin.readonly.admit(a);
    defer plan.deinit();
    const Protocol = @import("block_v5_precompile_protocol_v1.zig");
    try Protocol.validate(pin.statement, pin.total_steps, config);
    if (pin.frame.clock_frame != .leaf_local or pin.frame.cycle_count != pin.total_steps or !std.meta.eql(pin.expected_key_id, try Protocol.keyId(pin.statement, pin.total_steps, config, pin.roots[0]))) return error.UntrustedV5CallerReadonlyTransport;
    var schedule = try @import("block_v5_caller_fused_schedule_v1.zig").Schedule.init(a, pin.statement, pin.total_steps, pin.frame, 1);
    defer schedule.deinit();
    const Proof = @import("block_v5_caller_readonly_proof_v1.zig");
    try Proof.preflightCounts(&schedule, plan.intervals.len, .{ schedule.program.len, schedule.program.len, schedule.tables.len, schedule.memory.len, schedule.memory.len }, pin.readonly.limits);
    if (schedule.rw_events != pin.expected_rw_events) return error.UntrustedV5CallerReadonlyTransport;
    const interactions = try Proof.interactionLogs(a, &schedule);
    defer a.free(interactions);
    const witness = try Proof.witnessLogs(a, &schedule);
    defer a.free(witness);
    const log = @max(@max(maximum(schedule.fixed), maximum(schedule.main)), @max(maximum(interactions), maximum(witness)));
    // The caller instance already binds the sparse execution ordinal. Policy
    // construction supplies it explicitly through callerAt, below.
    return .{ .family = .caller_readonly, .index = 0, .policy_digest = seal, .config = config, .roots = .{ pin.roots[0], pin.roots[1], pin.witness_root }, .root_count = 3, .geometry = .{ .tree_count = 5, .tree_columns = .{ @intCast(schedule.fixed.len), @intCast(schedule.main.len), @intCast(witness.len), @intCast(interactions.len), @intCast(core.verifier_types.compositionColumnCount(schedule.split, core.fields.qm31.SECURE_EXTENSION_DEGREE).?) }, .max_column_log = log, .max_merkle_log = log, .sample_width_limits = .{ 2, 6, 1, 2, 1 } }, .claim_count = @intCast(schedule.program.len), .state_claim_count = @intCast(schedule.program.len), .table_claim_count = @intCast(schedule.tables.len), .memory_claim_count = @intCast(schedule.memory.len), .readonly_interval_count = @intCast(plan.intervals.len) };
}
pub fn callerAt(a: std.mem.Allocator, index: u32, pin: @import("block_v5_caller_readonly_receiver_v1.zig").Pin, config: core.pcs.PcsConfig, seal: [32]u8) !Codec.Expected {
    const Protocol = @import("block_v5_precompile_protocol_v1.zig");
    if (!std.meta.eql(pin.expected_caller_instance_id, Protocol.instanceId(pin.expected_key_id, pin.execution_instance_id, index, pin.roots))) return error.UntrustedV5CallerReadonlyTransport;
    var result = try caller(a, pin, config, seal);
    result.index = index;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ @intFromEnum(Codec.Family.caller_readonly), index, result.claim_count, result.state_claim_count, result.table_claim_count, result.memory_claim_count, result.readonly_interval_count });
    channel.mixRoot(seal);
    channel.mixRoot(pin.expected_key_id);
    channel.mixRoot(pin.expected_caller_instance_id);
    channel.mixRoot(pin.execution_instance_id);
    for (result.roots) |root| channel.mixRoot(root);
    channel.mixRoot(pin.readonly.selection.expected_digest);
    channel.mixRoot(pin.readonly.plan.expected_digest);
    channel.mixRoot(@import("block_v5_caller_readonly_protocol_v1.zig").abiId());
    inline for (std.meta.fields(@TypeOf(pin.readonly.limits))) |field| channel.mixU64(@field(pin.readonly.limits, field.name));
    config.mixInto(&channel);
    result.policy_digest = channel.digestBytes();
    try result.validate();
    return result;
}
fn maximum(logs: []const u32) u32 {
    var result: u32 = 0;
    for (logs) |log| result = @max(result, log);
    return result;
}
