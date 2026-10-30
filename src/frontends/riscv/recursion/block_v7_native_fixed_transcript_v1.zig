//! Capture-free original native transcript plan. Values stay public operands.
const std = @import("std");
const Profile = @import("block_v7_native_fixed_profile_v1.zig");
const Fused = @import("../prover/block_v5_native_projection_fused_proof_v2.zig");
const Memory = @import("../prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
const Statement = @import("air/block_v7_native_statement_v1.zig");
const Prefix = @import("air/block_v7_native_transcript_v1.zig");
const Sink = @import("air/blake3_fixed_operation_recorder_v1.zig");
const Schema = @import("air/blake3_pcs_operation_schema_v1.zig");
pub fn derive(a: std.mem.Allocator, profile: *const Profile.Owned, claims: []const Fused.Claim, memory: []const Memory.Claim, capacity: u32, limits: Sink.Limits) !@import("air/blake3_transcript_plan.zig").Plan {
    return deriveWithShared(a, profile, claims, memory, capacity, limits, false);
}
pub fn deriveWithShared(a: std.mem.Allocator, profile: *const Profile.Owned, claims: []const Fused.Claim, memory: []const Memory.Claim, capacity: u32, limits: Sink.Limits, shared_epoch: bool) !@import("air/blake3_transcript_plan.zig").Plan {
    try profile.validate();
    if (capacity == 0) return error.InvalidNativeTranscript;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var statement = try Statement.init(temp, profile, claims, memory);
    defer statement.deinit();
    var r = Sink.Recorder{ .a = temp, .limits = limits };
    try Prefix.prefixFixed(temp, &r, profile, &statement);
    const interaction = profile.trace_count - 1;
    if (r.skipped_roots != interaction) return error.InvalidNativeTranscript;
    try r.suffix(.{ .commitment = .{ .slot = @intCast(interaction), .source = try @import("air/blake3_root_sources.zig").caller(interaction) } });
    var suffix: std.ArrayList(Schema.Operation) = .empty;
    try Schema.appendPcsSuffix(temp, &suffix, profile.epoch.config, profile.shape.deepProfile(), profile.shape.friProfile(), profile.trace_count + 1);
    for (suffix.items) |operation| try r.suffix(operation);
    try r.check();
    if (shared_epoch) return @import("air/block_v7_shared_epoch_transcript_v1.zig").derive(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items, false);
    return @import("air/blake3_transcript_plan.zig").Plan.initCompact(a, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, r.operations.items);
}
