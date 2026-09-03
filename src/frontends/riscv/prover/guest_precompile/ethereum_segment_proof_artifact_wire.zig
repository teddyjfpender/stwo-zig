//! Metadata/identity codec for append-only `STWGPF01` Ethereum SegmentV3.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const global_v3 = @import("../../recursion/segment_leaf_local_authority_v3.zig");
const base_wire = @import("proof_artifact_wire.zig");
const ethereum_wire = @import("ethereum_proof_artifact_wire.zig");
const metadata_wire = @import("ethereum_segment_artifact_metadata_wire.zig");
const ethereum_interaction = @import("ethereum_interaction.zig");
const ethereum_main = @import("ethereum_main.zig");
const ethereum_preprocessed = @import("ethereum_preprocessed.zig");

pub const artifact_format_version: u16 = 3;
pub const extension_schema_version: u16 = 1;
pub const identity_schema_version: u16 = 1;
pub const identity_magic = [8]u8{ 'S', 'T', 'W', 'G', 'E', 'T', 'H', '3' };
pub const extension_encoded_size: usize = 2 + 2 * @sizeOf(u32) +
    ethereum_wire.extension_encoded_size + metadata_wire.encoded_size;
pub const identity_encoded_size: usize = 320;

pub const Extension = struct {
    ethereum: ethereum_statement.Statement,
    global: global_v3.MetadataV3,
};

pub fn encodeExtension(writer: anytype, value: Extension) !void {
    try value.global.validate();
    try base_wire.writeInt(writer, u16, extension_schema_version);
    try base_wire.writeInt(
        writer,
        u32,
        ethereum_wire.extension_encoded_size,
    );
    try ethereum_wire.encodeExtension(writer, &value.ethereum);
    try base_wire.writeInt(writer, u32, metadata_wire.encoded_size);
    try metadata_wire.encode(writer, &value.global);
}

pub fn decodeExtension(bytes: []const u8) !Extension {
    if (bytes.len != extension_encoded_size) return error.InvalidExtensionLength;
    var cursor = base_wire.Cursor.init(bytes);
    if (try cursor.readInt(u16) != extension_schema_version)
        return error.UnsupportedExtensionVersion;
    if (try cursor.readInt(u32) != ethereum_wire.extension_encoded_size)
        return error.InvalidEthereumExtensionLength;
    const ethereum = try ethereum_wire.decodeExtension(
        try cursor.take(ethereum_wire.extension_encoded_size),
    );
    if (try cursor.readInt(u32) != metadata_wire.encoded_size)
        return error.InvalidMetadataLength;
    const global = try metadata_wire.decode(
        try cursor.take(metadata_wire.encoded_size),
    );
    try cursor.requireDone();
    return .{ .ethereum = ethereum, .global = global };
}

pub const Geometry = struct {
    tree0_columns: u32,
    tree1_columns: u32,
    tree2_columns: u32,
    tree0_sha256: [32]u8,
    tree1_sha256: [32]u8,
    tree2_sha256: [32]u8,

    pub fn canonical(
        allocator: std.mem.Allocator,
        statement: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        manifest: *const lookup_physical_v2.Manifest,
        authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    ) !Geometry {
        const tree0 = try ethereum_preprocessed.logSizes(
            allocator,
            &statement.core,
            extension,
        );
        defer allocator.free(tree0);
        const tree1 = try ethereum_main.logSizes(
            allocator,
            &statement.core,
            extension,
        );
        defer allocator.free(tree1);
        const tree2 = try ethereum_interaction.logSizesAuthenticatedLookupV2(
            allocator,
            &statement.core,
            extension,
            manifest,
            authenticated,
        );
        defer allocator.free(tree2);
        return .{
            .tree0_columns = try count(tree0.len),
            .tree1_columns = try count(tree1.len),
            .tree2_columns = try count(tree2.len),
            .tree0_sha256 = hashLogSizes(.tree0, tree0),
            .tree1_sha256 = hashLogSizes(.tree1, tree1),
            .tree2_sha256 = hashLogSizes(.tree2, tree2),
        };
    }
};

pub const Identity = struct {
    profile_semantic_digest: [32]u8,
    lookup_manifest_id: [32]u8,
    lookup_activation_id: [32]u8,
    global_metadata_id: [32]u8,
    geometry: Geometry,
    metadata_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn canonical(
        allocator: std.mem.Allocator,
        statement: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        global: *const global_v3.MetadataV3,
        statement_bytes: []const u8,
        extension_bytes: []const u8,
    ) !Identity {
        try statement.validate();
        try extension.validateV2(statement);
        try global.validate();
        var manifest = lookup_physical_v2.Manifest.native();
        const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
            &statement.core,
            &manifest,
        );
        var result = Identity{
            .profile_semantic_digest = execution_profile.ethereum_semantic_digest,
            .lookup_manifest_id = manifest.identity,
            .lookup_activation_id = authenticated.activation_identity,
            .global_metadata_id = digestWords(try global.identity()),
            .geometry = try Geometry.canonical(
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
        statement: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        global: *const global_v3.MetadataV3,
        statement_bytes: []const u8,
        extension_bytes: []const u8,
    ) !void {
        const expected = try canonical(
            allocator,
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
        try writer.writeAll(&self.profile_semantic_digest);
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
        try cursor.readExact(&result.profile_semantic_digest);
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
        if (!std.meta.eql(result.identity_sha256, result.identityHash()))
            return error.IdentityMismatch;
        return result;
    }

    fn identityHash(self: Identity) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo.riscv.ethereum-segment-proof.identity.v1\x00");
        hash.update(&self.profile_semantic_digest);
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

fn metadataHash(statement_bytes: []const u8, extension_bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-segment-proof.metadata.v1\x00");
    hash.update(statement_bytes);
    hash.update(extension_bytes);
    return hash.finalResult();
}

const Tree = enum(u8) { tree0 = 0, tree1 = 1, tree2 = 2 };

fn hashLogSizes(tree: Tree, values: []const u32) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-segment-proof.geometry.v1\x00");
    hashInt(&hash, u8, @intFromEnum(tree));
    hashInt(&hash, u32, @intCast(values.len));
    for (values) |value| hashInt(&hash, u32, value);
    return hash.finalResult();
}

fn digestWords(words: [8]u32) [32]u8 {
    var result: [32]u8 = undefined;
    for (words, 0..) |word, index|
        std.mem.writeInt(u32, result[4 * index ..][0..4], word, .little);
    return result;
}

fn count(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.GeometryOverflow;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (m31.Modulus != 0x7fff_ffff or
        extension_encoded_size != 2577 or identity_encoded_size != 320)
    {
        @compileError("Ethereum SegmentV3 wire authority drifted");
    }
}
