//! Fixed Poseidon program receipt encoding, independent of witness construction.
const std = @import("std");
const semantic = @import("digest.zig");
const golden = @import("typed_poseidon2_identity_golden.zig");
const layout = @import("../memory_commitment/poseidon2_layout.zig");
pub const IdentityError = error{ InvalidIdentityEncoding, ProgramIdentityMismatch, UnsupportedIdentityEncoding };
pub const Digest = semantic.Digest;

pub const LAYOUT_DIGEST_FORMAT_VERSION: u16 = 1;
pub const LAYOUT_DIGEST_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/poseidon2-layout/v1";

pub const PROGRAM_IDENTITY_FORMAT_VERSION: u16 = 1;
pub const PROGRAM_IDENTITY_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/poseidon2-program-identity/v1";
pub const PROGRAM_COMPONENT_ID = "stwo.riscv.poseidon2-m31";
pub const PROGRAM_IDENTITY_MAGIC = "STWAIRP\x00";
pub const CANONICAL_SEMANTIC_DIGEST: Digest = golden.semantic;
pub const CANONICAL_LAYOUT_DIGEST: Digest = golden.layout;
pub const CANONICAL_EXECUTOR_DIGEST: Digest = golden.executor;
pub const CANONICAL_RELATION_DIGEST: Digest = golden.relation;
pub const CANONICAL_COMBINED_DIGEST: Digest = golden.combined;
pub const CANONICAL_RECEIPT_SHA256: Digest = golden.receipt_sha256;

pub const CANONICAL_PREIMAGE_LEN: usize =
    PROGRAM_IDENTITY_MAGIC.len +
    @sizeOf(u16) +
    @sizeOf(u16) + PROGRAM_COMPONENT_ID.len +
    4 * (@sizeOf(u8) + @sizeOf(u16) + @sizeOf(Digest)) +
    3 * @sizeOf(u16);
pub const RECEIPT_BYTES_LEN: usize = CANONICAL_PREIMAGE_LEN + @sizeOf(Digest);

pub const EXECUTION_DIGEST_FORMAT_VERSION: u16 = 1;
pub const RELATION_DIGEST_FORMAT_VERSION: u16 = 1;

pub const ProgramIdentity = struct {
    const Shared = Methods(@This());
    semantic_digest: Digest,
    layout_digest: Digest,
    executor_digest: Digest,
    relation_digest: Digest,
    combined_digest: Digest,
    pub const canonical = Shared.canonical;
    pub const isCanonical = Shared.isCanonical;
    pub const sealDigests = Shared.sealDigests;
    pub const validate = Shared.validate;
    pub const preimageBytes = Shared.preimageBytes;
    pub const receiptBytes = Shared.receiptBytes;
    pub const fromReceiptBytes = Shared.fromReceiptBytes;
};

pub fn Methods(comptime Self: type) type {
    return struct {
        pub fn canonical() Self {
            return .{
                .semantic_digest = CANONICAL_SEMANTIC_DIGEST,
                .layout_digest = CANONICAL_LAYOUT_DIGEST,
                .executor_digest = CANONICAL_EXECUTOR_DIGEST,
                .relation_digest = CANONICAL_RELATION_DIGEST,
                .combined_digest = CANONICAL_COMBINED_DIGEST,
            };
        }

        pub fn isCanonical(self: Self) bool {
            return std.meta.eql(self, canonical());
        }

        pub fn sealDigests(
            semantic_digest: Digest,
            layout_digest: Digest,
            executor_digest: Digest,
            relation_digest: Digest,
        ) Self {
            var result = Self{
                .semantic_digest = semantic_digest,
                .layout_digest = layout_digest,
                .executor_digest = executor_digest,
                .relation_digest = relation_digest,
                .combined_digest = undefined,
            };
            result.combined_digest = computeCombinedDigest(result);
            return result;
        }

        pub fn validate(self: Self) IdentityError!void {
            const expected = computeCombinedDigest(self);
            if (!std.mem.eql(u8, &self.combined_digest, &expected))
                return error.ProgramIdentityMismatch;
        }

        pub fn preimageBytes(
            self: Self,
        ) IdentityError![CANONICAL_PREIMAGE_LEN]u8 {
            try self.validate();
            return preimageBytesUnchecked(self);
        }

        pub fn receiptBytes(self: Self) IdentityError![RECEIPT_BYTES_LEN]u8 {
            try self.validate();
            var result: [RECEIPT_BYTES_LEN]u8 = undefined;
            const preimage = preimageBytesUnchecked(self);
            @memcpy(result[0..CANONICAL_PREIMAGE_LEN], &preimage);
            @memcpy(result[CANONICAL_PREIMAGE_LEN..], &self.combined_digest);
            return result;
        }

        pub fn fromReceiptBytes(
            bytes: *const [RECEIPT_BYTES_LEN]u8,
        ) IdentityError!Self {
            var decoder = Decoder{ .bytes = bytes };
            try decoder.expectBytes(PROGRAM_IDENTITY_MAGIC);
            if (try decoder.takeInt(u16) != PROGRAM_IDENTITY_FORMAT_VERSION)
                return error.UnsupportedIdentityEncoding;
            if (try decoder.takeInt(u16) != @as(u16, @intCast(PROGRAM_COMPONENT_ID.len)))
                return error.InvalidIdentityEncoding;
            try decoder.expectBytes(PROGRAM_COMPONENT_ID);

            const semantic_digest = try decoder.takeChild(1, semantic.format_version);
            const layout_digest = try decoder.takeChild(2, LAYOUT_DIGEST_FORMAT_VERSION);
            const executor_digest = try decoder.takeChild(
                3,
                EXECUTION_DIGEST_FORMAT_VERSION,
            );
            const relation_digest = try decoder.takeChild(
                4,
                RELATION_DIGEST_FORMAT_VERSION,
            );
            if (try decoder.takeInt(u16) != @as(u16, @intCast(layout.N_MAIN_COLUMNS)) or
                try decoder.takeInt(u16) !=
                    @as(u16, @intCast(layout.N_INTERACTION_COLUMNS)) or
                try decoder.takeInt(u16) != @as(u16, @intCast(layout.N_SUMS)))
            {
                return error.InvalidIdentityEncoding;
            }
            const combined_digest = try decoder.takeDigest();
            if (decoder.cursor != bytes.len) return error.InvalidIdentityEncoding;

            const result = Self{
                .semantic_digest = semantic_digest,
                .layout_digest = layout_digest,
                .executor_digest = executor_digest,
                .relation_digest = relation_digest,
                .combined_digest = combined_digest,
            };
            try result.validate();
            return result;
        }

        fn computeCombinedDigest(self: Self) Digest {
            const preimage = preimageBytesUnchecked(self);
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(PROGRAM_IDENTITY_DOMAIN_SEPARATOR);
            hashInt(&hash, u16, PROGRAM_IDENTITY_FORMAT_VERSION);
            hash.update(&preimage);
            return hash.finalResult();
        }

        fn preimageBytesUnchecked(self: Self) [CANONICAL_PREIMAGE_LEN]u8 {
            var result: [CANONICAL_PREIMAGE_LEN]u8 = undefined;
            var encoder = Encoder{ .bytes = &result };
            encoder.putBytes(PROGRAM_IDENTITY_MAGIC);
            encoder.putInt(u16, PROGRAM_IDENTITY_FORMAT_VERSION);
            encoder.putInt(u16, @intCast(PROGRAM_COMPONENT_ID.len));
            encoder.putBytes(PROGRAM_COMPONENT_ID);
            encoder.putChild(1, semantic.format_version, self.semantic_digest);
            encoder.putChild(2, LAYOUT_DIGEST_FORMAT_VERSION, self.layout_digest);
            encoder.putChild(
                3,
                EXECUTION_DIGEST_FORMAT_VERSION,
                self.executor_digest,
            );
            encoder.putChild(
                4,
                RELATION_DIGEST_FORMAT_VERSION,
                self.relation_digest,
            );
            encoder.putInt(u16, @intCast(layout.N_MAIN_COLUMNS));
            encoder.putInt(u16, @intCast(layout.N_INTERACTION_COLUMNS));
            encoder.putInt(u16, @intCast(layout.N_SUMS));
            std.debug.assert(encoder.cursor == result.len);
            return result;
        }
    };
}

const Encoder = struct {
    bytes: []u8,
    cursor: usize = 0,

    fn putBytes(self: *Encoder, value: []const u8) void {
        @memcpy(self.bytes[self.cursor..][0..value.len], value);
        self.cursor += value.len;
    }

    fn putInt(self: *Encoder, comptime T: type, value: T) void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, value, .little);
        self.putBytes(&encoded);
    }

    fn putChild(self: *Encoder, tag: u8, version: u16, value: Digest) void {
        self.putInt(u8, tag);
        self.putInt(u16, version);
        self.putBytes(&value);
    }
};

const Decoder = struct {
    bytes: []const u8,
    cursor: usize = 0,

    fn expectBytes(self: *Decoder, expected: []const u8) IdentityError!void {
        const actual = try self.take(expected.len);
        if (!std.mem.eql(u8, actual, expected))
            return error.InvalidIdentityEncoding;
    }

    fn take(self: *Decoder, len: usize) IdentityError![]const u8 {
        const end = std.math.add(usize, self.cursor, len) catch
            return error.InvalidIdentityEncoding;
        if (end > self.bytes.len) return error.InvalidIdentityEncoding;
        defer self.cursor = end;
        return self.bytes[self.cursor..end];
    }

    fn takeInt(self: *Decoder, comptime T: type) IdentityError!T {
        var encoded: [@sizeOf(T)]u8 = undefined;
        @memcpy(&encoded, try self.take(encoded.len));
        return std.mem.readInt(T, &encoded, .little);
    }

    fn takeDigest(self: *Decoder) IdentityError!Digest {
        var result: Digest = undefined;
        @memcpy(&result, try self.take(result.len));
        return result;
    }

    fn takeChild(
        self: *Decoder,
        expected_tag: u8,
        expected_version: u16,
    ) IdentityError!Digest {
        if (try self.takeInt(u8) != expected_tag or
            try self.takeInt(u16) != expected_version)
        {
            return error.UnsupportedIdentityEncoding;
        }
        return self.takeDigest();
    }
};

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

comptime {
    if (CANONICAL_PREIMAGE_LEN != 182 or RECEIPT_BYTES_LEN != 214)
        @compileError("Poseidon2 program-identity v1 byte encoding drifted");
}

test "retained Poseidon codec matches canonical receipt and rejects changed digests" {
    const canonical = ProgramIdentity.canonical();
    const receipt = try canonical.receiptBytes();
    var receipt_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&receipt, &receipt_hash, .{});
    try std.testing.expectEqualDeep(CANONICAL_RECEIPT_SHA256, receipt_hash);
    try std.testing.expectEqualDeep(canonical, try ProgramIdentity.fromReceiptBytes(&receipt));
    var changed = canonical;
    changed.executor_digest[0] ^= 1;
    try std.testing.expectError(error.ProgramIdentityMismatch, changed.validate());
    var malformed = receipt;
    malformed[0] ^= 1;
    try std.testing.expectError(error.InvalidIdentityEncoding, ProgramIdentity.fromReceiptBytes(&malformed));
}
