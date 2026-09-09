//! Shared fixed-width header for append-only `STWGPF01` envelopes.
//!
//! Profile formats own their five payload sections; this module owns only the
//! allocation-free outer framing and product-selected PCS configuration.

const std = @import("std");
const fri = @import("stwo_core").fri;
const pcs = @import("stwo_core").pcs;
const wire = @import("proof_artifact_wire.zig");

pub const Limits = wire.Limits;
pub const magic = [8]u8{ 'S', 'T', 'W', 'G', 'P', 'F', '0', '1' };
pub const header_size: usize = 80;
pub const postcard_proof_encoding_v1: u16 = 1;
pub const blake2s_merkle_hasher_v1: u16 = 1;
pub const poseidon2_m31_merkle_hasher_v1: u16 = 2;

const ProofHasher = enum(u16) {
    blake2s = blake2s_merkle_hasher_v1,
    poseidon2_m31 = poseidon2_m31_merkle_hasher_v1,
};

pub const Offset = struct {
    pub const version: usize = 8;
    pub const declared_header_size: usize = 10;
    pub const flags: usize = 12;
    pub const total_bytes: usize = 16;
    pub const proof_encoding: usize = 24;
    pub const hasher: usize = 26;
    pub const pow_bits: usize = 28;
    pub const log_blowup_factor: usize = 32;
    pub const n_queries: usize = 36;
    pub const log_last_layer_degree_bound: usize = 44;
    pub const fold_step: usize = 48;
    pub const lifting_tag: usize = 52;
    pub const lifting_value: usize = 56;
    pub const statement_length: usize = 60;
    pub const extension_length: usize = 64;
    pub const identity_length: usize = 68;
    pub const claim_length: usize = 72;
    pub const proof_length: usize = 76;
};

pub const Header = struct {
    format_version: u16,
    total_bytes: u64,
    pcs_config: pcs.PcsConfig,
    statement_length: u32,
    extension_length: u32,
    identity_length: u32,
    claim_length: u32,
    proof_length: u32,

    pub fn encode(self: Header, writer: anytype) !void {
        if (self.format_version == 0) return error.UnsupportedArtifactVersion;
        const proof_hasher = try proofHasherForVersion(self.format_version);
        try writer.writeAll(&magic);
        try wire.writeInt(writer, u16, self.format_version);
        try wire.writeInt(writer, u16, header_size);
        try wire.writeInt(writer, u32, 0);
        try wire.writeInt(writer, u64, self.total_bytes);
        try wire.writeInt(writer, u16, postcard_proof_encoding_v1);
        try wire.writeInt(writer, u16, @intFromEnum(proof_hasher));
        try wire.writeInt(writer, u32, self.pcs_config.pow_bits);
        try wire.writeInt(
            writer,
            u32,
            self.pcs_config.fri_config.log_blowup_factor,
        );
        try wire.writeInt(writer, u64, self.pcs_config.fri_config.n_queries);
        try wire.writeInt(
            writer,
            u32,
            self.pcs_config.fri_config.log_last_layer_degree_bound,
        );
        try wire.writeInt(writer, u32, self.pcs_config.fri_config.fold_step);
        if (self.pcs_config.lifting_log_size) |value| {
            try writer.writeByte(1);
            try writer.writeAll(&.{ 0, 0, 0 });
            try wire.writeInt(writer, u32, value);
        } else {
            try writer.writeByte(0);
            try writer.writeAll(&.{ 0, 0, 0 });
            try wire.writeInt(writer, u32, 0);
        }
        try wire.writeInt(writer, u32, self.statement_length);
        try wire.writeInt(writer, u32, self.extension_length);
        try wire.writeInt(writer, u32, self.identity_length);
        try wire.writeInt(writer, u32, self.claim_length);
        try wire.writeInt(writer, u32, self.proof_length);
    }

    pub fn decodeForVersion(
        bytes: []const u8,
        expected_version: u16,
        limits: Limits,
    ) !Header {
        if (expected_version == 0) return error.UnsupportedArtifactVersion;
        if (bytes.len < header_size) return error.EndOfStream;
        var cursor = wire.Cursor.init(bytes[0..header_size]);
        if (!std.mem.eql(u8, try cursor.take(magic.len), &magic))
            return error.InvalidArtifactMagic;
        const version = try cursor.readInt(u16);
        if (version != expected_version) return error.UnsupportedArtifactVersion;
        const proof_hasher = try proofHasherForVersion(expected_version);
        if (try cursor.readInt(u16) != header_size)
            return error.InvalidHeaderLength;
        if (try cursor.readInt(u32) != 0) return error.UnsupportedArtifactFlags;
        const total_bytes = try cursor.readInt(u64);
        if (try cursor.readInt(u16) != postcard_proof_encoding_v1)
            return error.UnsupportedProofEncoding;
        if (try cursor.readInt(u16) != @intFromEnum(proof_hasher))
            return error.UnsupportedProofHasher;

        const pow_bits = try cursor.readInt(u32);
        const log_blowup_factor = try cursor.readInt(u32);
        const n_queries_u64 = try cursor.readInt(u64);
        if (n_queries_u64 == 0 or n_queries_u64 > limits.max_queries or
            n_queries_u64 > std.math.maxInt(usize))
        {
            return error.ProofResourceLimitExceeded;
        }
        const log_last_layer_degree_bound = try cursor.readInt(u32);
        const fold_step = try cursor.readInt(u32);
        const lifting_tag = try cursor.readByte();
        for (0..3) |_| if (try cursor.readByte() != 0)
            return error.NonCanonicalHeader;
        const lifting_value = try cursor.readInt(u32);
        const lifting_log_size: ?u32 = switch (lifting_tag) {
            0 => if (lifting_value == 0) null else return error.NonCanonicalHeader,
            1 => lifting_value,
            else => return error.InvalidOptionTag,
        };
        var fri_config = try fri.FriConfig.init(
            log_last_layer_degree_bound,
            log_blowup_factor,
            @intCast(n_queries_u64),
        );
        fri_config.fold_step = fold_step;
        const config = pcs.PcsConfig{
            .pow_bits = pow_bits,
            .fri_config = fri_config,
            .lifting_log_size = lifting_log_size,
        };
        try validatePcsConfig(config, limits);
        const result = Header{
            .format_version = version,
            .total_bytes = total_bytes,
            .pcs_config = config,
            .statement_length = try cursor.readInt(u32),
            .extension_length = try cursor.readInt(u32),
            .identity_length = try cursor.readInt(u32),
            .claim_length = try cursor.readInt(u32),
            .proof_length = try cursor.readInt(u32),
        };
        try cursor.requireDone();
        return result;
    }
};

/// The artifact version is selected by the verifier entrypoint. Untrusted
/// bytes never select a hasher suite: versions 1--3 are the immutable Blake2s
/// products and append-only version 4 is Poseidon2-M31.
fn proofHasherForVersion(version: u16) !ProofHasher {
    return switch (version) {
        1...3 => .blake2s,
        4 => .poseidon2_m31,
        else => error.UnsupportedArtifactVersion,
    };
}

pub fn validatePcsConfig(config: pcs.PcsConfig, limits: Limits) !void {
    if (config.pow_bits > limits.max_pow_bits or
        config.fri_config.n_queries == 0 or
        config.fri_config.n_queries > limits.max_queries or
        config.fri_config.fold_step == 0 or
        config.fri_config.fold_step > 16 or
        (config.lifting_log_size != null and config.lifting_log_size.? > 30))
    {
        return error.InvalidPcsConfig;
    }
    _ = try fri.FriConfig.init(
        config.fri_config.log_last_layer_degree_bound,
        config.fri_config.log_blowup_factor,
        config.fri_config.n_queries,
    );
}

pub fn pcsConfigsEqual(expected: pcs.PcsConfig, actual: pcs.PcsConfig) bool {
    return expected.pow_bits == actual.pow_bits and
        expected.fri_config.log_blowup_factor == actual.fri_config.log_blowup_factor and
        expected.fri_config.log_last_layer_degree_bound == actual.fri_config.log_last_layer_degree_bound and
        expected.fri_config.n_queries == actual.fri_config.n_queries and
        expected.fri_config.fold_step == actual.fri_config.fold_step and
        expected.lifting_log_size == actual.lifting_log_size;
}

comptime {
    if (Offset.proof_length + @sizeOf(u32) != header_size)
        @compileError("guest proof-artifact header layout drifted");
}

test "legacy v3 header bytes remain exact and v4 suite is verifier-selected" {
    const config = pcs.PcsConfig{
        .pow_bits = 26,
        .fri_config = .{
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 70,
            .fold_step = 1,
        },
        .lifting_log_size = null,
    };
    const header = Header{
        .format_version = 3,
        .total_bytes = 0x0102_0304_0506_0708,
        .pcs_config = config,
        .statement_length = 11,
        .extension_length = 22,
        .identity_length = 33,
        .claim_length = 44,
        .proof_length = 55,
    };
    var encoded: [header_size]u8 = undefined;
    var stream = std.io.fixedBufferStream(&encoded);
    try header.encode(stream.writer());
    const expected = [_]u8{
        'S', 'T', 'W', 'G', 'P', 'F', '0', '1',
        3,   0,   80,  0,   0,   0,   0,   0,
        8,   7,   6,   5,   4,   3,   2,   1,
        1,   0,   1,   0,   26,  0,   0,   0,
        1,   0,   0,   0,   70,  0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,
        1,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   11,  0,   0,   0,
        22,  0,   0,   0,   33,  0,   0,   0,
        44,  0,   0,   0,   55,  0,   0,   0,
    };
    try std.testing.expectEqualSlices(u8, &expected, &encoded);
    _ = try Header.decodeForVersion(&encoded, 3, .{});

    var v4 = header;
    v4.format_version = 4;
    stream = std.io.fixedBufferStream(&encoded);
    try v4.encode(stream.writer());
    try std.testing.expectEqual(
        poseidon2_m31_merkle_hasher_v1,
        std.mem.readInt(u16, encoded[Offset.hasher..][0..2], .little),
    );
    _ = try Header.decodeForVersion(&encoded, 4, .{});
    try std.testing.expectError(
        error.UnsupportedArtifactVersion,
        Header.decodeForVersion(&encoded, 3, .{}),
    );
    encoded[Offset.version] = 3;
    try std.testing.expectError(
        error.UnsupportedProofHasher,
        Header.decodeForVersion(&encoded, 3, .{}),
    );
}
