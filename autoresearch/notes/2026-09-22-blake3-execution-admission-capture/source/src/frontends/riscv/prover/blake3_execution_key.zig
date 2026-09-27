//! Complete execution key identity. Expected IDs belong to verifier admission.
//! This key is specialized to the admitted public statement and schedules.
const std = @import("std");
const core = @import("stwo_core");
const protocol = @import("blake3_execution_protocol.zig");
const Statement = @import("../air/statement.zig").Blake3ExecutionStatement;
const Admission = @import("blake3_commitment_plan.zig").Admission;
const Airs = @import("blake3_commitment_components.zig").Airs;
pub const Key = struct {
    version: u32 = 1,
    preprocessed_root: [32]u8,
    hash_logs: [Airs.len]u32,
    pub fn identity(self: Key, shape: *const Statement, plan: Admission, config: core.pcs.PcsConfig) ![32]u8 {
        if (self.version != 1) return error.InvalidExecutionKeyVersion;
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x4233454b, self.version }); // B3EK
        try protocol.mix(&channel, config, shape, plan);
        inline for (Airs, 0..) |Air, i| {
            if (self.hash_logs[i] == 0 or self.hash_logs[i] > 24) return error.InvalidExecutionKeyGeometry;
            protocol.mixDigest(&channel, Air.SEMANTIC_DIGEST);
            channel.mixU32s(&.{ self.hash_logs[i], Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT, Air.DIRECT_CONSTRAINT_COUNT });
        }
        protocol.mixDigest(&channel, self.preprocessed_root);
        return channel.digestBytes();
    }
    pub fn admit(self: Key, shape: *const Statement, plan: Admission, config: core.pcs.PcsConfig, expected: [32]u8) !void {
        if (!std.mem.eql(u8, &try self.identity(shape, plan, config), &expected)) return error.UntrustedExecutionKey;
    }
};
