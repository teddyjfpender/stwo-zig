//! Explicit full-width guest Poseidon profile; disjoint from base B3EX and legacy ETH1.
const std = @import("std");
const core = @import("stwo_core");
const base = @import("blake3_execution_protocol.zig");
const admission = @import("blake3_poseidon_statement.zig");
const Native = @import("../air/statement.zig").Blake3ExecutionStatement;
const Pin = @import("blake3_commitment_plan.zig").Admission;
const Airs = @import("blake3_commitment_components.zig").Airs;
pub fn mix(channel: anytype, config: core.pcs.PcsConfig, native: *const Native, extension: *const admission.Statement, pin: Pin, logs: admission.HashLogs) !void {
    try base.validateConfig(config);
    try admission.validate(extension, native, pin, logs);
    channel.mixU32s(&.{ 0x42335032, 1 }); // B3P2
    base.mixAdmittedStatement(channel, config, native, pin);
    const wire = @import("guest_precompile/proof_artifact_wire.zig");
    var bytes: [wire.extension_encoded_size]u8 = undefined;
    var stream = std.io.fixedBufferStream(&bytes);
    try wire.encodeExtension(stream.writer(), extension);
    if (stream.pos != bytes.len) return error.InvalidExtensionLength;
    base.mixDigest(channel, core.vcs.blake3_hash.Blake3Hasher.hash(&bytes));
}
pub fn identity(config: core.pcs.PcsConfig, native: *const Native, extension: *const admission.Statement, pin: Pin, logs: admission.HashLogs, root: [32]u8) ![32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x4233504b, 1 }); // B3PK
    try mix(&channel, config, native, extension, pin, logs);
    inline for (Airs, 0..) |Air, i| {
        base.mixDigest(&channel, Air.SEMANTIC_DIGEST);
        channel.mixU32s(&.{ logs[i], Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT, Air.DIRECT_CONSTRAINT_COUNT });
    }
    base.mixDigest(&channel, root);
    return channel.digestBytes();
}
