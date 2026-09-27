//! Allocator-aware B3ES protocol and pinned prepared-key identity.
const std = @import("std");
const core = @import("stwo_core");
const base = @import("blake3_execution_protocol.zig");
const admission = @import("blake3_ethereum_sha_statement.zig");
const Native = @import("../air/statement.zig").Blake3ExecutionStatement;
const Pin = @import("blake3_commitment_plan.zig").Admission;
pub fn mixWithAllocator(a: std.mem.Allocator, channel: anytype, config: core.pcs.PcsConfig, native: *const Native, extension: *const admission.Statement, pin: Pin, logs: admission.HashLogs) !void {
    try extension.mix(a, channel, config, native, pin, logs);
}
pub fn identityWithAllocator(a: std.mem.Allocator, config: core.pcs.PcsConfig, native: *const Native, extension: *const admission.Statement, pin: Pin, logs: admission.HashLogs, root: [32]u8) ![32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x4233534b, 1 }); // B3SK
    try mixWithAllocator(a, &channel, config, native, extension, pin, logs);
    inline for (@import("blake3_commitment_components.zig").Airs, 0..) |Air, i| {
        base.mixDigest(&channel, Air.SEMANTIC_DIGEST);
        channel.mixU32s(&.{ logs[i], Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT, Air.DIRECT_CONSTRAINT_COUNT });
    }
    base.mixDigest(&channel, root);
    return channel.digestBytes();
}

pub fn mixValidated(channel: anytype, config: core.pcs.PcsConfig, native: *const Native, extension: *const admission.Statement, pin: Pin, _: admission.HashLogs) !void {
    try extension.mixValidated(channel, config, native, pin);
}
