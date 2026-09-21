//! Live cold-open input for the real omitted-provider common leaf wrapper.
//!
//! This module does not prove the common wrapper. It closes the first sound
//! ownership boundary: canonical omitted-bundle bytes are decoded and every
//! native proof is freshly verified before the descriptor, incremental
//! provider authority, fixed NodePublic, or wrapper witness view is exposed.
//! A digest cannot mint this type and no live verifier capability is encoded.

const std = @import("std");

const artifact_mod = @import("recursive_node_artifact_v1.zig");
const bundle_mod = @import("ethereum_provider_omitted_leaf_bundle_v1.zig");
const leaf_descriptor =
    @import("recursive_temporal_ethereum_leaf_descriptor_v1.zig");
const node_authority_mod =
    @import("recursive_temporal_node_public_authority_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const WRAPPER_PROOF_AVAILABLE = false;
pub const WRAPPER_TRANSPORT_AVAILABLE = false;
pub const WRAPPER_COLD_GEOMETRY_AVAILABLE = false;

const CAPABILITY_DOMAIN =
    "stwo-zig/recursive-common-real-omitted-leaf-input/v1\x00";

pub const MissingAuthorityV1 = enum(u8) {
    common_wrapper_one_leaf_cohort = 1,
    omitted_42_claim_air_owner = 2,
    fixed_node_public_hash_air_owner = 3,
    universal_36_padding_owner = 4,
    canonical_wrapper_proof_transport = 5,
    common_wrapper_cold_verifier = 6,
    cold_geometry_lease_mint = 7,
};

pub const CurrentStatusV1 = struct {
    native_bundle_cold_verify_available: bool = true,
    ordinary_h1_capture_custody_available: bool = true,
    descriptor_derived_from_fresh_verifier: bool = true,
    provider_authority_derived_from_fresh_verifier: bool = true,
    fixed_node_public_derived: bool = true,
    wrapper_proof_available: bool = WRAPPER_PROOF_AVAILABLE,
    wrapper_transport_available: bool = WRAPPER_TRANSPORT_AVAILABLE,
    wrapper_cold_geometry_available: bool = WRAPPER_COLD_GEOMETRY_AVAILABLE,
    production_activation: bool = PRODUCTION_ACTIVATION,
    first_missing: MissingAuthorityV1 = .common_wrapper_one_leaf_cohort,

    pub fn validate(self: CurrentStatusV1) !void {
        if (!std.meta.eql(self, currentStatus()))
            return error.InvalidRealOmittedLeafWrapperStatus;
    }
};

pub fn currentStatus() CurrentStatusV1 {
    return .{};
}

/// Borrowed view consumed by a future one-leaf common-wrapper cohort. The
/// owner and its native verifier captures must outlive this value.
pub fn LiveViewV1(comptime Engine: type) type {
    return struct {
        ordinary_h1: bundle_mod.OrdinaryH1ViewV1(Engine),
        node_authority: *const node_authority_mod.EthereumLeafAuthorityV2,
        node_public: *const artifact_mod.NodePublicV1,
        capability_identity_sha256: [32]u8,
    };
}

/// Owned, non-serializable verifier capability. `coldOpen` is its only mint.
/// Revalidation always needs the same canonical bundle bytes and native
/// verifier authority; stored SHA-256 fields are custody diagnostics only.
pub fn FreshInputV1(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        fresh: bundle_mod.FreshVerifiedOmittedLeafV1(Engine),
        node_authority: node_authority_mod.EthereumLeafAuthorityV2,
        node_public: artifact_mod.NodePublicV1,
        bundle_byte_count: u64,
        bundle_sha256: [32]u8,
        capability_identity_sha256: [32]u8,

        const Self = @This();

        pub fn coldOpen(
            allocator: std.mem.Allocator,
            bundle_bytes: []const u8,
            authority: bundle_mod.Authority(Engine),
            limits: bundle_mod.Limits,
        ) !Self {
            var fresh = try bundle_mod.coldVerify(
                Engine,
                allocator,
                bundle_bytes,
                authority,
                limits,
            );
            errdefer fresh.deinit();
            try fresh.validateAgainstArtifact(authority, bundle_bytes);
            const node_authority = try deriveNodeAuthority(
                Engine,
                &fresh,
                authority,
            );
            const node_public = try nodePublicFromAuthority(&node_authority);
            var result = Self{
                .allocator = allocator,
                .fresh = fresh,
                .node_authority = node_authority,
                .node_public = node_public,
                .bundle_byte_count = @intCast(bundle_bytes.len),
                .bundle_sha256 = sha256(bundle_bytes),
                .capability_identity_sha256 = undefined,
            };
            result.capability_identity_sha256 = capabilityIdentity(
                Engine,
                &result,
            );
            try result.validate(authority, bundle_bytes);
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.fresh.deinit();
            self.* = undefined;
        }

        pub fn validate(
            self: *const Self,
            authority: bundle_mod.Authority(Engine),
            bundle_bytes: []const u8,
        ) !void {
            try self.fresh.validateAgainstArtifact(authority, bundle_bytes);
            const ordinary = self.fresh.ordinaryH1View();
            try ordinary.validateCaptureCustody(authority);
            const expected_authority = try deriveNodeAuthority(
                Engine,
                &self.fresh,
                authority,
            );
            const expected_public = try nodePublicFromAuthority(
                &expected_authority,
            );
            const expected_bundle_sha256 = sha256(bundle_bytes);
            if (self.bundle_byte_count !=
                @as(u64, @intCast(bundle_bytes.len)) or
                !std.mem.eql(
                    u8,
                    &self.bundle_sha256,
                    &expected_bundle_sha256,
                ) or
                !std.meta.eql(self.node_authority, expected_authority) or
                !std.meta.eql(self.node_public, expected_public) or
                !std.mem.eql(
                    u8,
                    &self.capability_identity_sha256,
                    &capabilityIdentity(Engine, self),
                ))
            {
                return error.InvalidRealOmittedLeafWrapperInput;
            }
        }

        pub fn liveView(self: *const Self) LiveViewV1(Engine) {
            return .{
                .ordinary_h1 = self.fresh.ordinaryH1View(),
                .node_authority = &self.node_authority,
                .node_public = &self.node_public,
                .capability_identity_sha256 = self.capability_identity_sha256,
            };
        }
    };
}

fn deriveNodeAuthority(
    comptime Engine: type,
    fresh: *const bundle_mod.FreshVerifiedOmittedLeafV1(Engine),
    authority: bundle_mod.Authority(Engine),
) !node_authority_mod.EthereumLeafAuthorityV2 {
    try fresh.validate(authority);
    const view = fresh.ordinaryH1View();
    try view.validateCaptureCustody(authority);
    const descriptor = try leaf_descriptor.initFromFreshVerifier(
        try view.descriptorMintInputColdDerived(authority.source),
    );
    const provider_input = try view.providerCompilerInput(authority);
    return node_authority_mod.EthereumLeafAuthorityV2.initFromFreshVerifier(
        descriptor,
        fresh.global,
        provider_input,
    );
}

/// Exact fixed public ABI projection. Its values are derived from the live
/// verifier edge above. The future role AIR must independently constrain this
/// same conversion; this host helper is not wrapper-proof authority.
pub fn nodePublicFromAuthority(
    authority: *const node_authority_mod.EthereumLeafAuthorityV2,
) !artifact_mod.NodePublicV1 {
    try authority.validate();
    const reference = try authority.reference();
    var statement_words: [artifact_mod.STATEMENT_WORD_COUNT]u32 = undefined;
    for (reference.statement_words, &statement_words) |source, *destination|
        destination.* = source.toU32();
    return artifact_mod.NodePublicV1.seal(.{
        .statement_words = statement_words,
        .statement_identity_sha256 = authority.descriptor.recursive_statement_sha256,
        .node_authority_sha256 = reference.authority_sha256,
        .subtree_sha256 = reference.subtree_sha256,
        .subtree_digest = reference.subtree_digest,
        .output_identity_sha256 = undefined,
    });
}

fn capabilityIdentity(
    comptime Engine: type,
    value: *const FreshInputV1(Engine),
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CAPABILITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u64, value.bundle_byte_count);
    hash.update(&value.bundle_sha256);
    hash.update(&value.fresh.identity);
    hash.update(&value.fresh.authority_identity);
    hash.update(&value.fresh.proof_artifact_sha256);
    hash.update(&value.fresh.proof_root_sha256);
    hash.update(&value.fresh.transcript_state_sha256);
    hash.update(&value.fresh.core_capture.identity);
    hash.update(&value.fresh.tree0.identity);
    hashInt(&hash, u64, value.fresh.provider_captures.len);
    for (value.fresh.provider_captures) |capture| {
        hash.update(&capture.identity);
        hash.update(&capture.proof_root_sha256);
        hash.update(&capture.proof_capture_sha256);
    }
    hash.update(&value.node_authority.authority_sha256);
    hash.update(&value.node_public.output_identity_sha256);
    return hash.finalResult();
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (PRODUCTION_ACTIVATION or WRAPPER_PROOF_AVAILABLE or
        WRAPPER_TRANSPORT_AVAILABLE or WRAPPER_COLD_GEOMETRY_AVAILABLE or
        artifact_mod.STATEMENT_WORD_COUNT != 412)
    {
        @compileError("real omitted common-wrapper input drifted");
    }
}
