//! Identity codec for append-only Poseidon2-M31 Ethereum SegmentV3 proofs.
//!
//! The native Blake2s v3 wire remains immutable. This v4 identity additionally
//! seals the verifier-selected PCS and production-security authorities; exact
//! per-leaf recursive program/VK descriptors are minted only after verification
//! and therefore never come from this prover-authored envelope.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const global_v3 = @import("../../recursion/segment_leaf_local_authority_v3.zig");
const base_wire = @import("proof_artifact_wire.zig");
const native_wire = @import("ethereum_segment_proof_artifact_wire.zig");

pub const artifact_format_version: u16 = 4;
pub const identity_schema_version: u16 = 1;
pub const identity_magic = [8]u8{ 'S', 'T', 'W', 'G', 'E', 'P', '2', '4' };
pub const identity_encoded_size: usize = 384;

pub const Identity = struct {
    security_identity_sha256: [32]u8,
    pcs_sha256: [32]u8,
    execution_semantics_sha256: [32]u8,
    lookup_manifest_id: [32]u8,
    lookup_activation_id: [32]u8,
    global_metadata_id: [32]u8,
    geometry: native_wire.Geometry,
    metadata_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn canonical(
        allocator: std.mem.Allocator,
        config: pcs.PcsConfig,
        security_identity_sha256: [32]u8,
        statement: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        global: *const global_v3.MetadataV3,
        statement_bytes: []const u8,
        extension_bytes: []const u8,
    ) !Identity {
        try statement.validate();
        try extension.validateV2(statement);
        try global.validate();
        if (std.mem.allEqual(u8, &security_identity_sha256, 0))
            return error.InvalidSecurityIdentity;
        var manifest = lookup_physical_v2.Manifest.native();
        const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
            &statement.core,
            &manifest,
        );
        var result = Identity{
            .security_identity_sha256 = security_identity_sha256,
            .pcs_sha256 = pcsHash(config),
            // This digest binds execution/ISA+precompile semantics only. The
            // fresh verifier's typed descriptor separately binds AIR/compiler
            // formulas after the proof has succeeded.
            .execution_semantics_sha256 = execution_profile.ethereum_semantic_digest,
            .lookup_manifest_id = manifest.identity,
            .lookup_activation_id = authenticated.activation_identity,
            .global_metadata_id = digestWords(try global.identity()),
            .geometry = try native_wire.Geometry.canonical(
                allocator,
                statement,
                extension,
                &manifest,
                &authenticated,
            ),
            .metadata_sha256 = metadataHash(statement_bytes, extension_bytes),
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = result.identityHash();
        return result;
    }

    pub fn validateAgainst(
        self: Identity,
        allocator: std.mem.Allocator,
        config: pcs.PcsConfig,
        expected_security_identity_sha256: [32]u8,
        statement: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        global: *const global_v3.MetadataV3,
        statement_bytes: []const u8,
        extension_bytes: []const u8,
    ) !void {
        const expected = try canonical(
            allocator,
            config,
            expected_security_identity_sha256,
            statement,
            extension,
            global,
            statement_bytes,
            extension_bytes,
        );
        if (!std.meta.eql(self, expected)) return error.IdentityMismatch;
    }

    pub fn encode(self: Identity, writer: anytype) !void {
        try writer.writeAll(&identity_magic);
        try base_wire.writeInt(writer, u16, identity_schema_version);
        try base_wire.writeInt(writer, u16, artifact_format_version);
        try base_wire.writeInt(writer, u16, @intFromEnum(ethereum_statement.profile));
        try base_wire.writeInt(writer, u16, execution_profile.ethereum_abi_version);
        try base_wire.writeInt(writer, u16, ethereum_statement.schema_version);
        try base_wire.writeInt(writer, u16, ethereum_statement.component_count);
        try writer.writeAll(&self.security_identity_sha256);
        try writer.writeAll(&self.pcs_sha256);
        try writer.writeAll(&self.execution_semantics_sha256);
        try writer.writeAll(&self.lookup_manifest_id);
        try writer.writeAll(&self.lookup_activation_id);
        try writer.writeAll(&self.global_metadata_id);
        try base_wire.writeInt(writer, u32, self.geometry.tree0_columns);
        try base_wire.writeInt(writer, u32, self.geometry.tree1_columns);
        try base_wire.writeInt(writer, u32, self.geometry.tree2_columns);
        try writer.writeAll(&self.geometry.tree0_sha256);
        try writer.writeAll(&self.geometry.tree1_sha256);
        try writer.writeAll(&self.geometry.tree2_sha256);
        try writer.writeAll(&self.metadata_sha256);
        try writer.writeAll(&self.identity_sha256);
    }

    pub fn decode(bytes: []const u8) !Identity {
        if (bytes.len != identity_encoded_size) return error.InvalidIdentityLength;
        var cursor = base_wire.Cursor.init(bytes);
        if (!std.mem.eql(u8, try cursor.take(identity_magic.len), &identity_magic))
            return error.InvalidIdentityMagic;
        if (try cursor.readInt(u16) != identity_schema_version or
            try cursor.readInt(u16) != artifact_format_version)
        {
            return error.UnsupportedIdentityVersion;
        }
        if (try cursor.readInt(u16) != @intFromEnum(ethereum_statement.profile) or
            try cursor.readInt(u16) != execution_profile.ethereum_abi_version or
            try cursor.readInt(u16) != ethereum_statement.schema_version or
            try cursor.readInt(u16) != ethereum_statement.component_count)
        {
            return error.IdentityAuthorityMismatch;
        }
        var result: Identity = undefined;
        try cursor.readExact(&result.security_identity_sha256);
        try cursor.readExact(&result.pcs_sha256);
        try cursor.readExact(&result.execution_semantics_sha256);
        try cursor.readExact(&result.lookup_manifest_id);
        try cursor.readExact(&result.lookup_activation_id);
        try cursor.readExact(&result.global_metadata_id);
        result.geometry.tree0_columns = try cursor.readInt(u32);
        result.geometry.tree1_columns = try cursor.readInt(u32);
        result.geometry.tree2_columns = try cursor.readInt(u32);
        try cursor.readExact(&result.geometry.tree0_sha256);
        try cursor.readExact(&result.geometry.tree1_sha256);
        try cursor.readExact(&result.geometry.tree2_sha256);
        try cursor.readExact(&result.metadata_sha256);
        try cursor.readExact(&result.identity_sha256);
        try cursor.requireDone();
        if (!std.mem.eql(u8, &result.identity_sha256, &result.identityHash()))
            return error.IdentityMismatch;
        return result;
    }

    fn identityHash(self: Identity) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo.riscv.ethereum-segment-poseidon2-proof.identity.v1\x00");
        hash.update(&self.security_identity_sha256);
        hash.update(&self.pcs_sha256);
        hash.update(&self.execution_semantics_sha256);
        hash.update(&self.lookup_manifest_id);
        hash.update(&self.lookup_activation_id);
        hash.update(&self.global_metadata_id);
        hashInt(&hash, u32, self.geometry.tree0_columns);
        hashInt(&hash, u32, self.geometry.tree1_columns);
        hashInt(&hash, u32, self.geometry.tree2_columns);
        hash.update(&self.geometry.tree0_sha256);
        hash.update(&self.geometry.tree1_sha256);
        hash.update(&self.geometry.tree2_sha256);
        hash.update(&self.metadata_sha256);
        return hash.finalResult();
    }
};

pub fn pcsHash(config: pcs.PcsConfig) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-segment-poseidon2-proof.pcs.v1\x00");
    hashInt(&hash, u32, config.pow_bits);
    hashInt(&hash, u32, config.fri_config.log_blowup_factor);
    hashInt(&hash, u64, config.fri_config.n_queries);
    hashInt(&hash, u32, config.fri_config.log_last_layer_degree_bound);
    hashInt(&hash, u32, config.fri_config.fold_step);
    hashInt(&hash, u8, @intFromBool(config.lifting_log_size != null));
    hashInt(&hash, u32, config.lifting_log_size orelse 0);
    return hash.finalResult();
}

fn metadataHash(statement_bytes: []const u8, extension_bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-segment-poseidon2-proof.metadata.v1\x00");
    hashInt(&hash, u64, statement_bytes.len);
    hash.update(statement_bytes);
    hashInt(&hash, u64, extension_bytes.len);
    hash.update(extension_bytes);
    return hash.finalResult();
}

fn digestWords(words: [8]u32) [32]u8 {
    var result: [32]u8 = undefined;
    for (words, 0..) |word, index|
        std.mem.writeInt(u32, result[4 * index ..][0..4], word, .little);
    return result;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (artifact_format_version != 4 or identity_encoded_size != 384)
        @compileError("Poseidon2 Ethereum SegmentV3 identity authority drifted");
}
