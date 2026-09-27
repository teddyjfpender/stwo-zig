//! Fixed, proof-independent authority for one streamed Ethereum leaf.
//!
//! The controller hashes this whole `STWESG31` file as the segment source.
//! The payload binds the canonical global-position metadata that must emerge
//! from reexecution and the admitted execution-journal record that forecast
//! the same leaf. It contains no witness or proof material.

const std = @import("std");
const execution_profile = @import("../../isa/execution_profile.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const global_v3 = @import("../../recursion/segment_leaf_local_authority_v3.zig");
const base_wire = @import("proof_artifact_wire.zig");
const metadata_wire = @import("ethereum_segment_artifact_metadata_wire.zig");

pub const magic = [8]u8{ 'S', 'T', 'W', 'E', 'S', 'G', '3', '1' };
pub const format_version: u16 = 1;
pub const flags: u16 = 0;
pub const encoded_size: usize = magic.len + 2 * @sizeOf(u16) +
    @sizeOf(u32) + @sizeOf([32]u8) + metadata_wire.encoded_size;

pub const Source = struct {
    journal_record_sha256: [32]u8,
    metadata: global_v3.MetadataV3,

    pub fn validate(self: *const Source) !void {
        try self.metadata.validate();
        if (allZero(&self.journal_record_sha256))
            return error.InvalidJournalRecordIdentity;
    }

    pub fn statementSha256(self: *const Source) ![32]u8 {
        try self.validate();
        return publicStatementSha256(&self.metadata);
    }
};

pub fn publicStatementSha256(
    metadata: *const global_v3.MetadataV3,
) ![32]u8 {
    try metadata.validate();
    var metadata_bytes: [metadata_wire.encoded_size]u8 = undefined;
    var stream = std.io.fixedBufferStream(&metadata_bytes);
    try metadata_wire.encode(stream.writer(), metadata);
    if (stream.getWritten().len != metadata_bytes.len)
        return error.InvalidMetadataLength;
    var manifest = lookup_physical_v2.Manifest.native();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-segment-public-statement.v1\x00");
    hash.update(&execution_profile.ethereum_semantic_digest);
    hashInt(&hash, u16, @intFromEnum(
        execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1,
    ));
    hashInt(&hash, u16, execution_profile.ethereum_abi_version);
    hash.update(&manifest.identity);
    hash.update(&metadata_bytes);
    return hash.finalResult();
}

pub fn encode(writer: anytype, source: *const Source) !void {
    try source.validate();
    try writer.writeAll(&magic);
    try base_wire.writeInt(writer, u16, format_version);
    try base_wire.writeInt(writer, u16, flags);
    try base_wire.writeInt(writer, u32, metadata_wire.encoded_size);
    try writer.writeAll(&source.journal_record_sha256);
    try metadata_wire.encode(writer, &source.metadata);
}

pub fn encodeValue(source: *const Source) ![encoded_size]u8 {
    var result: [encoded_size]u8 = undefined;
    var stream = std.io.fixedBufferStream(&result);
    try encode(stream.writer(), source);
    if (stream.getWritten().len != result.len) return error.InvalidSourceLength;
    return result;
}

pub fn decode(bytes: []const u8) !Source {
    if (bytes.len != encoded_size) return error.InvalidSourceLength;
    var cursor = base_wire.Cursor.init(bytes);
    if (!std.mem.eql(u8, try cursor.take(magic.len), &magic))
        return error.InvalidSourceMagic;
    if (try cursor.readInt(u16) != format_version or
        try cursor.readInt(u16) != flags)
    {
        return error.UnsupportedSourceVersion;
    }
    if (try cursor.readInt(u32) != metadata_wire.encoded_size)
        return error.InvalidMetadataLength;
    var result: Source = undefined;
    try cursor.readExact(&result.journal_record_sha256);
    result.metadata = try metadata_wire.decode(
        try cursor.take(metadata_wire.encoded_size),
    );
    try cursor.requireDone();
    try result.validate();
    return result;
}

fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (encoded_size != 2159 or global_v3.PRODUCTION_PROOF_ACTIVATION)
        @compileError("Ethereum streamed-leaf source authority drifted");
}
