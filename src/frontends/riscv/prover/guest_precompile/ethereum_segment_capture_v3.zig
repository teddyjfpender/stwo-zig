//! Transactional verifier capture for a full Ethereum SegmentV3 leaf.

const std = @import("std");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const global_v3 = @import("../../recursion/segment_leaf_local_authority_v3.zig");
const verified_link_v3 = @import("../../recursion/segment_leaf_local_verified_link_v3.zig");
const ethereum_context = @import("../../recursion/ethereum_leaf_context_v1.zig");
const base_geometry_v2 =
    @import("../../recursion/vm_composition_base_geometry_v2.zig");
const extension_geometry_v2 =
    @import("../../recursion/ethereum_composition_extension_geometry_v2.zig");
const base_types = @import("../types.zig");
const base_verifier = @import("../verifier.zig");
const proof_capture_sha256 = @import("../proof_capture_sha256.zig");
const ethereum_types = @import("ethereum_types.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
const CAPTURE_DOMAIN =
    "stwo-zig/riscv/ethereum-segment-v3-verified-capture/v1\x00";

pub fn VerifiedEthereumSegmentV3CaptureForEngine(
    comptime Engine: type,
) type {
    return struct {
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        base: base_verifier.VerifiedSegmentV2CaptureForEngine(Engine),
        core_statement: statement_v2.RiscVStatementV2,
        extension_statement: ethereum_statement.Statement,
        extension_claim: ethereum_types.ExtensionClaim,
        extension_context: ethereum_context.ContextV1,
        global_metadata: global_v3.MetadataV3,
        verified_link: verified_link_v3.VerifiedLinkV3,
        proof_capture_sha256: [32]u8,
        identity_digest: [32]u8,

        const Self = @This();

        pub fn initVerified(
            base: base_verifier.VerifiedSegmentV2CaptureForEngine(Engine),
            core: base_types.RiscVStatement,
            extension: ethereum_statement.Statement,
            extension_claim: ethereum_types.ExtensionClaim,
            extension_context: ethereum_context.ContextV1,
            global: global_v3.MetadataV3,
        ) !Self {
            const link = try verified_link_v3.VerifiedLinkV3.init(
                &global,
                &base.public_data.data,
                &base.receipt,
            );
            const owned_statement = try statement_v2.RiscVStatementV2.init(
                core,
                base.public_data.data,
            );
            var result = Self{
                .base = base,
                .core_statement = owned_statement,
                .extension_statement = extension,
                .extension_claim = extension_claim,
                .extension_context = extension_context,
                .global_metadata = global,
                .verified_link = link,
                .proof_capture_sha256 = proofCaptureSha256(&base.proof),
                .identity_digest = undefined,
            };
            result.identity_digest = try result.captureIdentity();
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.base.deinit(allocator);
            self.* = undefined;
        }

        pub fn validate(self: *const Self) !void {
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION)
            {
                return error.InvalidEthereumVerifiedCapture;
            }
            try self.base.validate();
            try self.core_statement.validate();
            if (self.core_statement.public_data.words().ptr !=
                self.base.public_data.data.words().ptr or
                self.core_statement.public_data.words().len !=
                    self.base.public_data.data.words().len)
            {
                return error.InvalidEthereumVerifiedCapture;
            }
            const receipt = try self.core_statement.verifiedReceipt();
            if (!std.meta.eql(receipt, self.base.receipt))
                return error.InvalidEthereumVerifiedCapture;
            try self.extension_context.validateAgainstVmContextV2(
                &self.core_statement,
                &self.extension_statement,
                &self.extension_claim,
                &self.base.vm_air,
            );
            var base_geometry = try base_geometry_v2.GeometryV2.init(
                self.base.vm_air.allocator,
                &self.base.vm_air.profile,
            );
            defer base_geometry.deinit();
            var extension_geometry = try extension_geometry_v2.GeometryV2.init(
                self.base.vm_air.allocator,
                &self.base.vm_air.profile,
                &self.core_statement.core,
                &self.extension_statement,
            );
            defer extension_geometry.deinit();
            const expected_full_sampled_value_count = std.math.add(
                u32,
                base_geometry.sampled_value_count,
                extension_geometry.sampled_value_count,
            ) catch return error.InvalidEthereumVerifiedCapture;
            if (self.base.vm_air.base_sampled_value_count !=
                base_geometry.sampled_value_count or
                self.base.vm_air.full_proof_capture_sampled_value_count !=
                    expected_full_sampled_value_count or
                self.base.proof.sampled_values.len !=
                    @as(usize, expected_full_sampled_value_count))
            {
                return error.InvalidEthereumVerifiedCapture;
            }
            try self.global_metadata.validate();
            try self.verified_link.validateAgainst(
                &self.global_metadata,
                &self.base.public_data.data,
                &self.base.receipt,
            );
            const expected_proof_sha256 = proofCaptureSha256(&self.base.proof);
            const expected_identity = try self.captureIdentity();
            if (!std.mem.eql(
                u8,
                &self.proof_capture_sha256,
                &expected_proof_sha256,
            ) or !std.mem.eql(
                u8,
                &self.identity_digest,
                &expected_identity,
            )) return error.InvalidEthereumVerifiedCapture;
        }

        fn captureIdentity(self: *const Self) ![32]u8 {
            const metadata_id = try self.global_metadata.identity();
            var hash = Sha256.init(.{});
            hash.update(CAPTURE_DOMAIN);
            hashInt(&hash, u16, self.format_version);
            hashInt(&hash, u16, self.schema_version);
            hash.update(&self.proof_capture_sha256);
            hash.update(&self.base.vm_air.identity_digest);
            hashDigest(&hash, self.base.receipt.authority_id);
            hashDigest(&hash, self.base.receipt.wire_id);
            hashDigest(&hash, self.base.receipt.identity);
            hashDigest(&hash, self.base.native_public_sums.identity);
            hash.update(&self.extension_context.statement_sha256);
            hash.update(&self.extension_context.claim_sha256);
            hash.update(&self.extension_context.identity_digest);
            hashDigest(&hash, metadata_id);
            hashDigest(&hash, self.verified_link.identity);
            return hash.finalResult();
        }
    };
}

pub fn proofCaptureSha256(capture: anytype) [32]u8 {
    return proof_capture_sha256.compute(capture);
}

fn hashDigest(hash: *Sha256, value: [8]u32) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 3 or SCHEMA_VERSION != 1)
        @compileError("Ethereum SegmentV3 verified capture authority drifted");
}
