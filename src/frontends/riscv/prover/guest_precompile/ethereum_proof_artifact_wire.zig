//! Canonical metadata codec for the Ethereum `STWGPF01` v2 envelope.
//!
//! The base statement and base interaction claim deliberately reuse the v1
//! codec. The append-only sections bind all fourteen Ethereum components in
//! their fixed order and retain every detailed LogUp sum.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const base_statement = @import("../../air/statement.zig");
const keccak_component = @import("../../air/guest_precompile/keccakf_component.zig");
const secp_bundle = @import("../../air/guest_precompile/secp256k1_component_bundle.zig");
const secp_component = @import("../../air/guest_precompile/secp256k1_component.zig");
const secp_config = @import("../../air/guest_precompile/secp256k1_component_config.zig");
const ethereum_types = @import("ethereum_types.zig");
const base_wire = @import("proof_artifact_wire.zig");

pub const extension_encoded_size: usize = 456;
pub const identity_encoded_size: usize = 84;
pub const claim_schema_version: u16 = 1;
pub const identity_schema_version: u16 = 1;
pub const artifact_format_version: u16 = 2;
pub const identity_magic = [8]u8{ 'S', 'T', 'W', 'G', 'E', 'T', 'H', '2' };

pub const Identity = struct {
    metadata_sha256: [32]u8,

    pub fn canonical(
        statement_bytes: []const u8,
        extension_bytes: []const u8,
    ) Identity {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo.riscv.ethereum-proof-artifact.identity.v1\x00");
        hash.update(statement_bytes);
        hash.update(extension_bytes);
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        return .{ .metadata_sha256 = digest };
    }

    pub fn encode(self: Identity, writer: anytype) !void {
        try writer.writeAll(&identity_magic);
        try base_wire.writeInt(writer, u16, identity_schema_version);
        try base_wire.writeInt(writer, u16, artifact_format_version);
        try base_wire.writeInt(
            writer,
            u16,
            @intFromEnum(ethereum_statement.profile),
        );
        try base_wire.writeInt(writer, u16, execution_profile.ethereum_abi_version);
        try base_wire.writeInt(writer, u16, ethereum_statement.schema_version);
        try base_wire.writeInt(writer, u16, ethereum_statement.component_count);
        try writer.writeAll(&execution_profile.ethereum_semantic_digest);
        try writer.writeAll(&self.metadata_sha256);
    }

    pub fn decode(bytes: []const u8) !Identity {
        if (bytes.len != identity_encoded_size) return error.InvalidIdentityLength;
        var cursor = base_wire.Cursor.init(bytes);
        if (!std.mem.eql(u8, try cursor.take(identity_magic.len), &identity_magic))
            return error.InvalidIdentityMagic;
        if (try cursor.readInt(u16) != identity_schema_version)
            return error.UnsupportedIdentityVersion;
        if (try cursor.readInt(u16) != artifact_format_version)
            return error.IdentityArtifactVersionMismatch;
        if (try cursor.readInt(u16) != @intFromEnum(ethereum_statement.profile))
            return error.ProfileMismatch;
        if (try cursor.readInt(u16) != execution_profile.ethereum_abi_version)
            return error.AbiMismatch;
        if (try cursor.readInt(u16) != ethereum_statement.schema_version)
            return error.StatementVersionMismatch;
        if (try cursor.readInt(u16) != ethereum_statement.component_count)
            return error.ComponentCountMismatch;
        var semantic_digest: [32]u8 = undefined;
        try cursor.readExact(&semantic_digest);
        if (!std.mem.eql(
            u8,
            &semantic_digest,
            &execution_profile.ethereum_semantic_digest,
        )) return error.SemanticDigestMismatch;
        var result: Identity = undefined;
        try cursor.readExact(&result.metadata_sha256);
        try cursor.requireDone();
        return result;
    }

    pub fn validate(
        self: Identity,
        statement_bytes: []const u8,
        extension_bytes: []const u8,
    ) !void {
        const expected = canonical(statement_bytes, extension_bytes);
        if (!std.mem.eql(u8, &self.metadata_sha256, &expected.metadata_sha256))
            return error.IdentityMetadataMismatch;
    }
};

pub fn encodeExtension(
    writer: anytype,
    extension: *const ethereum_statement.Statement,
) !void {
    try base_wire.writeInt(writer, u16, extension.version);
    try base_wire.writeInt(writer, u16, @intFromEnum(extension.profile_id));
    try base_wire.writeInt(writer, u16, extension.abi_version);
    try writer.writeAll(&extension.semantic_digest);
    try base_wire.writeInt(writer, u32, extension.counts.keccak_calls);
    try base_wire.writeInt(writer, u32, extension.counts.signer_calls);
    try base_wire.writeInt(writer, u32, extension.counts.external_retirements);
    for (extension.components) |descriptor| {
        try writer.writeByte(@intFromEnum(descriptor.kind));
        try base_wire.writeInt(writer, u32, descriptor.log_size);
        try base_wire.writeInt(writer, u32, descriptor.n_rows);
        try base_wire.writeInt(writer, u32, descriptor.preprocessed_columns);
        try base_wire.writeInt(writer, u32, descriptor.main_columns);
        try base_wire.writeInt(writer, u32, descriptor.interaction_columns);
    }
    try base_wire.writeInt(writer, u64, extension.admission.extra_memory_terms);
    try base_wire.writeInt(writer, u64, extension.admission.memory_relation_terms);
    for (extension.admission.base_fixed_table_bounds) |value|
        try base_wire.writeInt(writer, u64, value);
    for (extension.admission.extended_fixed_table_bounds) |value|
        try base_wire.writeInt(writer, u64, value);
}

pub fn decodeExtension(bytes: []const u8) !ethereum_statement.Statement {
    if (bytes.len != extension_encoded_size) return error.InvalidExtensionLength;
    var cursor = base_wire.Cursor.init(bytes);
    var result: ethereum_statement.Statement = undefined;
    result.version = try cursor.readInt(u16);
    result.profile_id = try cursor.readKnownEnum(execution_profile.ExecutionProfile);
    result.abi_version = try cursor.readInt(u16);
    try cursor.readExact(&result.semantic_digest);
    result.counts = .{
        .keccak_calls = try cursor.readInt(u32),
        .signer_calls = try cursor.readInt(u32),
        .external_retirements = try cursor.readInt(u32),
    };
    for (&result.components) |*descriptor| descriptor.* = .{
        .kind = try cursor.readKnownEnum(ethereum_statement.Kind),
        .log_size = try cursor.readInt(u32),
        .n_rows = try cursor.readInt(u32),
        .preprocessed_columns = try cursor.readInt(u32),
        .main_columns = try cursor.readInt(u32),
        .interaction_columns = try cursor.readInt(u32),
    };
    result.admission.extra_memory_terms = try cursor.readInt(u64);
    result.admission.memory_relation_terms = try cursor.readInt(u64);
    for (&result.admission.base_fixed_table_bounds) |*value|
        value.* = try cursor.readInt(u64);
    for (&result.admission.extended_fixed_table_bounds) |*value|
        value.* = try cursor.readInt(u64);
    try cursor.requireDone();
    return result;
}

pub const DecodedClaim = struct {
    base: *base_statement.RiscVInteractionClaim,
    extension: ethereum_types.ExtensionClaim,

    pub fn deinit(self: *DecodedClaim, allocator: std.mem.Allocator) void {
        allocator.destroy(self.base);
        self.* = undefined;
    }
};

pub fn encodeClaim(
    writer: anytype,
    statement: *const base_statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    base: *const base_statement.RiscVInteractionClaim,
    claim: *const ethereum_types.ExtensionClaim,
) !void {
    _ = try base.canonical(statement);
    try claim.validate(extension);
    try base_wire.writeInt(writer, u16, claim_schema_version);
    try base_wire.writeInt(writer, u16, ethereum_statement.component_count);
    try base_wire.encodeBaseClaim(writer, statement, base);
    try encodeKeccakClaim(writer, claim.keccak_shard);
    try base_wire.writeQm31(writer, claim.keccak_chi_table);
    try base_wire.writeQm31(writer, claim.keccak_xor5_table);
    inline for (.{
        claim.product_base,
        claim.product_scalar,
        claim.linear_base,
        claim.linear_scalar,
        claim.point,
        claim.split,
        claim.scalar,
        claim.table,
        claim.recovery,
        claim.byte,
        claim.recovery_caller,
    }) |component| try encodeSecpClaim(writer, component);
}

pub fn decodeClaim(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    statement: *const base_statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
) !DecodedClaim {
    var cursor = base_wire.Cursor.init(bytes);
    if (try cursor.readInt(u16) != claim_schema_version)
        return error.UnsupportedClaimVersion;
    if (try cursor.readInt(u16) != ethereum_statement.component_count)
        return error.ComponentCountMismatch;
    const base = try allocator.create(base_statement.RiscVInteractionClaim);
    errdefer allocator.destroy(base);
    try base_wire.decodeBaseClaimInto(&cursor, statement, base);
    const claim = ethereum_types.ExtensionClaim{
        .keccak_shard = try decodeKeccakClaim(&cursor),
        .keccak_chi_table = try cursor.readQm31(),
        .keccak_xor5_table = try cursor.readQm31(),
        .product_base = try decodeSecpClaim(secp_bundle.ProductBase, &cursor),
        .product_scalar = try decodeSecpClaim(secp_bundle.ProductScalar, &cursor),
        .linear_base = try decodeSecpClaim(secp_bundle.LinearBase, &cursor),
        .linear_scalar = try decodeSecpClaim(secp_bundle.LinearScalar, &cursor),
        .point = try decodeSecpClaim(secp_config.Point, &cursor),
        .split = try decodeSecpClaim(secp_config.Split, &cursor),
        .scalar = try decodeSecpClaim(secp_config.ScalarProgram, &cursor),
        .table = try decodeSecpClaim(secp_config.Table, &cursor),
        .recovery = try decodeSecpClaim(secp_config.Recovery, &cursor),
        .byte = try decodeSecpClaim(secp_config.ByteTable, &cursor),
        .recovery_caller = try decodeSecpClaim(secp_config.RecoveryCaller, &cursor),
    };
    try cursor.requireDone();
    try claim.validate(extension);
    return .{ .base = base, .extension = claim };
}

fn encodeKeccakClaim(writer: anytype, claim: keccak_component.Claim) !void {
    try base_wire.writeInt(writer, u32, claim.log_size);
    try base_wire.writeInt(writer, u32, claim.n_rows);
    try base_wire.writeInt(writer, u32, claim.first_call_index);
    try base_wire.writeInt(writer, u32, claim.call_count);
    try writeCount(writer, claim.batch_sums.len);
    for (claim.batch_sums) |sum| try base_wire.writeQm31(writer, sum);
    try base_wire.writeQm31(writer, claim.component_sum);
}

fn decodeKeccakClaim(cursor: *base_wire.Cursor) !keccak_component.Claim {
    var result: keccak_component.Claim = undefined;
    result.log_size = try cursor.readInt(u32);
    result.n_rows = try cursor.readInt(u32);
    result.first_call_index = try cursor.readInt(u32);
    result.call_count = try cursor.readInt(u32);
    if (try cursor.readInt(u16) != result.batch_sums.len)
        return error.InvalidClaimCount;
    for (&result.batch_sums) |*sum| sum.* = try cursor.readQm31();
    result.component_sum = try cursor.readQm31();
    return result;
}

fn encodeSecpClaim(writer: anytype, claim: anytype) !void {
    try base_wire.writeInt(writer, u32, claim.log_size);
    try base_wire.writeInt(writer, u32, claim.n_rows);
    try writeCount(writer, claim.batch_sums.len);
    for (claim.batch_sums) |sum| try base_wire.writeQm31(writer, sum);
    try base_wire.writeQm31(writer, claim.component_sum);
}

fn decodeSecpClaim(
    comptime Config: type,
    cursor: *base_wire.Cursor,
) !secp_component.Claim(Config) {
    var result: secp_component.Claim(Config) = undefined;
    result.log_size = try cursor.readInt(u32);
    result.n_rows = try cursor.readInt(u32);
    if (try cursor.readInt(u16) != result.batch_sums.len)
        return error.InvalidClaimCount;
    for (&result.batch_sums) |*sum| sum.* = try cursor.readQm31();
    result.component_sum = try cursor.readQm31();
    return result;
}

fn writeCount(writer: anytype, value: usize) !void {
    try base_wire.writeInt(
        writer,
        u16,
        std.math.cast(u16, value) orelse return error.CountOverflow,
    );
}

comptime {
    const descriptor_size = @sizeOf(u8) + 5 * @sizeOf(u32);
    const admission_size = 2 * @sizeOf(u64) +
        2 * ethereum_statement.fixed_table_count * @sizeOf(u64);
    const expected_extension = 3 * @sizeOf(u16) + 32 +
        3 * @sizeOf(u32) +
        ethereum_statement.component_count * descriptor_size + admission_size;
    if (expected_extension != extension_encoded_size or
        identity_magic.len + 6 * @sizeOf(u16) + 64 != identity_encoded_size)
    {
        @compileError("Ethereum proof-artifact metadata layout drifted");
    }
}
