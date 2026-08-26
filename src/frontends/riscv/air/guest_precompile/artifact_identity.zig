//! Canonical proof-artifact envelope for the guest extension statement.

const std = @import("std");
const execution_profile = @import("../../isa/execution_profile.zig");
const components = @import("component_registry.zig");
const hashing = @import("identity_hash.zig");
const manifest = @import("manifest.zig");
const statement_mod = @import("statement.zig");

pub const Digest = hashing.Digest;
pub const magic = [8]u8{ 'S', 'T', 'W', 'G', 'P', 'A', 'V', '1' };
pub const encoded_size: usize = 152;

pub const Identity = struct {
    format_version: u16,
    profile_id: u16,
    abi_version: u16,
    statement_version: u16,
    base_components: u16,
    total_components: u16,
    base_relations: u16,
    total_relations: u16,
    manifest_digest: Digest,
    semantic_digest: Digest,
    provider_layout_digest: Digest,
    statement_digest: Digest,

    pub fn canonical(
        core: anytype,
        statement: *const statement_mod.ExtensionStatement,
    ) Error!Identity {
        try statement.validate(core);
        return .{
            .format_version = manifest.artifact_format_version,
            .profile_id = @intFromEnum(execution_profile.ExecutionProfile.rv32im_zkvm_poseidon2_v1),
            .abi_version = execution_profile.poseidon2_abi_version,
            .statement_version = manifest.statement_schema_version,
            .base_components = components.base_component_count,
            .total_components = components.component_count,
            .base_relations = manifest.base_relation_count,
            .total_relations = manifest.relation_count,
            .manifest_digest = manifest.canonicalDigest(),
            .semantic_digest = execution_profile.poseidon2_semantic_digest,
            .provider_layout_digest = manifest.Identity.canonical().provider_layout_digest,
            .statement_digest = try statement.digest(core),
        };
    }

    pub fn validate(
        self: Identity,
        core: anytype,
        statement: *const statement_mod.ExtensionStatement,
    ) Error!void {
        const expected = try Identity.canonical(core, statement);
        if (self.format_version != expected.format_version)
            return error.ArtifactFormatMismatch;
        if (self.profile_id != expected.profile_id) return error.ProfileMismatch;
        if (self.abi_version != expected.abi_version)
            return error.AbiMismatch;
        if (self.statement_version != expected.statement_version)
            return error.StatementVersionMismatch;
        if (self.base_components != expected.base_components or
            self.total_components != expected.total_components or
            self.base_relations != expected.base_relations or
            self.total_relations != expected.total_relations)
        {
            return error.RegistryGeometryMismatch;
        }
        if (!std.mem.eql(u8, &self.manifest_digest, &expected.manifest_digest))
            return error.ManifestDigestMismatch;
        if (!std.mem.eql(u8, &self.semantic_digest, &expected.semantic_digest))
            return error.SemanticDigestMismatch;
        if (!std.mem.eql(
            u8,
            &self.provider_layout_digest,
            &expected.provider_layout_digest,
        )) return error.ProviderLayoutMismatch;
        if (!std.mem.eql(u8, &self.statement_digest, &expected.statement_digest))
            return error.StatementDigestMismatch;
    }

    pub fn encode(self: Identity) [encoded_size]u8 {
        var result: [encoded_size]u8 = undefined;
        result[0..magic.len].* = magic;
        var cursor: usize = magic.len;
        putInt(&result, &cursor, u16, self.format_version);
        putInt(&result, &cursor, u16, self.profile_id);
        putInt(&result, &cursor, u16, self.abi_version);
        putInt(&result, &cursor, u16, self.statement_version);
        putInt(&result, &cursor, u16, self.base_components);
        putInt(&result, &cursor, u16, self.total_components);
        putInt(&result, &cursor, u16, self.base_relations);
        putInt(&result, &cursor, u16, self.total_relations);
        putDigest(&result, &cursor, self.manifest_digest);
        putDigest(&result, &cursor, self.semantic_digest);
        putDigest(&result, &cursor, self.provider_layout_digest);
        putDigest(&result, &cursor, self.statement_digest);
        std.debug.assert(cursor == result.len);
        return result;
    }

    pub fn decode(bytes: []const u8) DecodeError!Identity {
        if (bytes.len != encoded_size) return error.InvalidArtifactLength;
        if (!std.mem.eql(u8, bytes[0..magic.len], &magic))
            return error.InvalidArtifactMagic;
        var cursor: usize = magic.len;
        const result = Identity{
            .format_version = takeInt(bytes, &cursor, u16),
            .profile_id = takeInt(bytes, &cursor, u16),
            .abi_version = takeInt(bytes, &cursor, u16),
            .statement_version = takeInt(bytes, &cursor, u16),
            .base_components = takeInt(bytes, &cursor, u16),
            .total_components = takeInt(bytes, &cursor, u16),
            .base_relations = takeInt(bytes, &cursor, u16),
            .total_relations = takeInt(bytes, &cursor, u16),
            .manifest_digest = takeDigest(bytes, &cursor),
            .semantic_digest = takeDigest(bytes, &cursor),
            .provider_layout_digest = takeDigest(bytes, &cursor),
            .statement_digest = takeDigest(bytes, &cursor),
        };
        std.debug.assert(cursor == bytes.len);
        return result;
    }
};

pub const Error = statement_mod.Error || error{
    AbiMismatch,
    ArtifactFormatMismatch,
    ManifestDigestMismatch,
    ProfileMismatch,
    ProviderLayoutMismatch,
    RegistryGeometryMismatch,
    SemanticDigestMismatch,
    StatementDigestMismatch,
    StatementVersionMismatch,
};

pub const DecodeError = error{
    InvalidArtifactLength,
    InvalidArtifactMagic,
};

fn putInt(
    destination: *[encoded_size]u8,
    cursor: *usize,
    comptime T: type,
    value: T,
) void {
    std.mem.writeInt(
        T,
        destination[cursor.*..][0..@sizeOf(T)],
        value,
        .little,
    );
    cursor.* += @sizeOf(T);
}

fn takeInt(bytes: []const u8, cursor: *usize, comptime T: type) T {
    const result = std.mem.readInt(T, bytes[cursor.*..][0..@sizeOf(T)], .little);
    cursor.* += @sizeOf(T);
    return result;
}

fn putDigest(
    destination: *[encoded_size]u8,
    cursor: *usize,
    digest: Digest,
) void {
    const end = cursor.* + digest.len;
    @memcpy(destination[cursor.*..end], &digest);
    cursor.* = end;
}

fn takeDigest(bytes: []const u8, cursor: *usize) Digest {
    var result: Digest = undefined;
    const end = cursor.* + result.len;
    @memcpy(&result, bytes[cursor.*..end]);
    cursor.* = end;
    return result;
}

comptime {
    if (encoded_size != magic.len + 8 * @sizeOf(u16) + 4 * @sizeOf(Digest))
        @compileError("guest artifact encoding size drifted");
}
