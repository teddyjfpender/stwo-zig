//! Fixed-size authenticated metadata for the explicit Ethereum/SHA profile.
const std = @import("std");
const wire = @import("proof_artifact_wire.zig");
const ethereum = @import("ethereum_proof_artifact_wire.zig");
const profile = @import("../../isa/execution_profile.zig");
const sha = @import("../../air/guest_precompile/sha256_component_profile.zig");
const Statement = @import("../blake3_ethereum_sha_statement.zig").Statement;
const magic = "B3SHST01";
pub const extension_encoded_size = 56 + ethereum.extension_encoded_size + sha.Airs.len * 64;
pub fn localZeroSemanticDigest() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-sha.statement.local-zero.v1\x00");
    hash.update(&profile.ethereum_sha_semantic_digest);
    hash.update(&@import("../../air/guest_precompile/ethereum_statement.zig").localZeroSemanticDigest());
    hash.update(&@import("../../air/guest_precompile/sha256_caller_local_zero_v1.zig").SEMANTIC_DIGEST);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}
pub fn encodeExtension(writer: anytype, statement: *const Statement) !void {
    return encodeExtensionForRecipe(writer, statement, false);
}
/// The containing independent policy selects the recipe before decoding.
/// Legacy entry points retain their original wire grammar and admission.
pub fn encodeExtensionForRecipe(writer: anytype, statement: *const Statement, local_zero: bool) !void {
    if (statement.ethereum.localZeroCustody() != local_zero) return error.StatementVersionMismatch;
    try statement.sha.validateForRecipe(statement.sha.call_count, local_zero);
    if (local_zero) try statement.ethereum.validateGeometryWithCircuitProfileV1(statement.ethereum.counts.external_retirements, .ethereum_local_zero_v1);
    try writer.writeAll(magic);
    try wire.writeInt(writer, u32, if (local_zero) 2 else 1);
    try wire.writeInt(writer, u32, @intFromEnum(profile.ExecutionProfile.rv32im_zkvm_ethereum_sha_v1));
    try wire.writeInt(writer, u32, if (local_zero) 2 else profile.ethereum_sha_abi_version);
    try writer.writeAll(&(if (local_zero) localZeroSemanticDigest() else profile.ethereum_sha_semantic_digest));
    try wire.writeInt(writer, u32, statement.sha.call_count);
    try ethereum.encodeExtension(writer, &statement.ethereum);
    for (statement.sha.descriptors) |desc| {
        inline for (.{ "live_rows", "log_size", "preprocessed_columns", "main_columns", "interaction_columns", "direct_constraints", "interaction_batches", "maximum_degree" }) |field| try wire.writeInt(writer, u32, @field(desc, field));
        try writer.writeAll(&desc.semantic_digest);
    }
}
pub fn decodeExtension(bytes: []const u8) !Statement {
    return decodeExtensionForRecipe(bytes, false);
}
pub fn decodeExtensionForRecipe(bytes: []const u8, local_zero: bool) !Statement {
    if (bytes.len != extension_encoded_size) return error.InvalidExtensionLength;
    var cursor = wire.Cursor.init(bytes);
    if (!std.mem.eql(u8, try cursor.take(magic.len), magic)) return error.InvalidShaStatementMagic;
    if (try cursor.readInt(u32) != (if (local_zero) @as(u32, 2) else 1)) return error.UnsupportedShaStatementVersion;
    if (try cursor.readInt(u32) != @intFromEnum(profile.ExecutionProfile.rv32im_zkvm_ethereum_sha_v1)) return error.ProfileMismatch;
    if (try cursor.readInt(u32) != (if (local_zero) @as(u32, 2) else profile.ethereum_sha_abi_version)) return error.AbiMismatch;
    if (!std.mem.eql(u8, try cursor.take(32), &(if (local_zero) localZeroSemanticDigest() else profile.ethereum_sha_semantic_digest))) return error.SemanticDigestMismatch;
    const calls = try cursor.readInt(u32);
    var result = Statement{ .ethereum = try ethereum.decodeExtension(try cursor.take(ethereum.extension_encoded_size)), .sha = .{ .call_count = calls, .descriptors = undefined } };
    for (&result.sha.descriptors) |*desc| {
        inline for (.{ "live_rows", "log_size", "preprocessed_columns", "main_columns", "interaction_columns", "direct_constraints", "interaction_batches", "maximum_degree" }) |field| @field(desc, field) = try cursor.readInt(u32);
        try cursor.readExact(&desc.semantic_digest);
    }
    try cursor.requireDone();
    if (result.ethereum.localZeroCustody() != local_zero) return error.StatementVersionMismatch;
    try result.sha.validateForRecipe(calls, local_zero);
    if (local_zero) try result.ethereum.validateGeometryWithCircuitProfileV1(result.ethereum.counts.external_retirements, .ethereum_local_zero_v1);
    return result;
}
