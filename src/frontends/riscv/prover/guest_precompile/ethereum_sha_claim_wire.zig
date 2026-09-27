//! Strict combined claim payload for the shared BLAKE3 artifact codec.
const std = @import("std");
const wire = @import("proof_artifact_wire.zig");
const ethereum = @import("ethereum_proof_artifact_wire.zig");
const types = @import("ethereum_sha_types.zig");
const Statement = @import("../blake3_ethereum_sha_statement.zig").Statement;
const magic = "B3SHCL01";
pub fn encodeExtensionClaim(writer: anytype, statement: *const Statement, claim: *const types.ExtensionClaim) !void {
    try claim.validate(statement);
    try writer.writeAll(magic);
    try wire.writeInt(writer, u32, types.component_count);
    try ethereum.encodeExtensionClaim(writer, &statement.ethereum, &claim.ethereum);
    for (claim.sha) |value| try wire.writeQm31(writer, value);
}
pub fn decodeExtensionClaim(cursor: *wire.Cursor, statement: *const Statement) !types.ExtensionClaim {
    if (!std.mem.eql(u8, try cursor.take(magic.len), magic)) return error.InvalidShaClaimMagic;
    if (try cursor.readInt(u32) != types.component_count) return error.ComponentCountMismatch;
    var result = types.ExtensionClaim{ .ethereum = try ethereum.decodeExtensionClaim(cursor, &statement.ethereum), .sha = undefined };
    for (&result.sha) |*value| value.* = try cursor.readQm31();
    try result.validate(statement);
    return result;
}
