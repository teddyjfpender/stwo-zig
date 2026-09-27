//! Verifier-owned capture for an Ethereum proof whose physical native
//! Poseidon provider is proved by ordered external shards.

const std = @import("std");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement =
    @import("../../air/guest_precompile/ethereum_statement.zig");
const ethereum_context =
    @import("../../recursion/ethereum_leaf_context_v1.zig");
const lookup_physical_v2 =
    @import("../../air/lang/lookup_physical_manifest_v2.zig");
const poseidon2_air =
    @import("../../air/memory_commitment/poseidon2_air.zig");
const base_verifier = @import("../verifier.zig");
const provider_authority =
    @import("../memory_provider_shards/authority.zig");
const native_omit =
    @import("../memory_provider_shards/native_provider_omit_v1.zig");
const omit_protocol =
    @import("../memory_provider_shards/ethereum_omit_protocol_v1.zig");
const proof_authority =
    @import("../memory_provider_shards/joint_proof_authority.zig");
const ethereum_types = @import("ethereum_types.zig");

pub const format_version: u16 = 1;
pub const schema_version: u16 = 1;
pub const production_active = false;
pub const recursive_admissible = false;

const capture_domain =
    "stwo-zig/riscv/ethereum-omitted-provider-fresh-capture/v1\x00";

pub fn CaptureV1(comptime Engine: type) type {
    return struct {
        format: u16 = format_version,
        schema: u16 = schema_version,
        projected_base: base_verifier.VerifiedSegmentV2CaptureForEngine(Engine),
        full_statement: statement_v2.RiscVStatementV2,
        projection: native_omit.ProjectionV1,
        extension_statement: ethereum_statement.Statement,
        extension_claim: ethereum_types.ExtensionClaim,
        ethereum_context: ethereum_context.ContextV1,
        shared: omit_protocol.SharedRelationAuthorityV1(Engine),
        fresh_core: omit_protocol.FreshCoreResidualV1,
        proof_commitments: [4]Engine.Hasher.Hash,
        identity: [32]u8,

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.projected_base.deinit(allocator);
            self.* = undefined;
        }

        pub fn validate(
            self: *const Self,
            plan: *const provider_authority.ProviderShardPlanV1,
            calls: []const poseidon2_air.Call,
            provider_stage_a: *const omit_protocol
                .ProviderStageAManifestV1(Engine),
        ) !void {
            if (self.format != format_version or self.schema != schema_version)
                return error.InvalidOmittedProviderFreshCapture;
            try self.projected_base.validate();
            try self.full_statement.validate();
            try self.extension_statement.validateV2(&self.full_statement);
            try self.extension_claim.validate(&self.extension_statement);
            try provider_stage_a.validate(plan, calls);
            var manifest = lookup_physical_v2.Manifest.native();
            const authenticated = try lookup_physical_v2.AuthenticatedStatement
                .init(&self.full_statement.core, &manifest);
            try self.projection.validateAgainst(
                &self.full_statement,
                &self.extension_statement,
                .proof,
                &manifest,
                &authenticated,
                plan,
                calls,
                try native_omit.deriveFullGeometry(&self.full_statement),
            );
            try self.shared.validate(plan, provider_stage_a, &self.projection);
            try self.fresh_core.validate();
            const reconstructed = try self.projected_base.vm_air
                .reconstructStatement(&self.projected_base.public_data.data);
            if (self.full_statement.public_data.words().ptr !=
                self.projected_base.public_data.data.words().ptr or
                self.projection.projected_native.public_data.words().ptr !=
                    self.projected_base.public_data.data.words().ptr or
                !std.meta.eql(
                    self.projection.projected_native.core,
                    reconstructed.core,
                ) or self.projected_base.proof.commitments.len != 4)
                return error.InvalidOmittedProviderFreshCapture;
            for (
                self.proof_commitments,
                self.projected_base.proof.commitments,
            ) |expected, actual| if (!std.meta.eql(expected, actual))
                return error.InvalidOmittedProviderFreshCapture;
            if (!std.mem.eql(
                u8,
                &self.fresh_core.proof_commitments_identity,
                &proof_authority.commitmentsIdentity(
                    Engine,
                    &self.proof_commitments,
                ),
            )) return error.InvalidOmittedProviderFreshCapture;
            try self.ethereum_context.validateAgainstVmContextV2(
                &self.projection.projected_native,
                &self.extension_statement,
                &self.extension_claim,
                &self.projected_base.vm_air,
            );
            if (!std.mem.eql(u8, &self.identity, &captureIdentity(Engine, self)))
                return error.InvalidOmittedProviderFreshCapture;
        }
    };
}

pub fn seal(comptime Engine: type, capture: *const CaptureV1(Engine)) [32]u8 {
    return captureIdentity(Engine, capture);
}

fn captureIdentity(
    comptime Engine: type,
    capture: *const CaptureV1(Engine),
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(capture_domain);
    hashInt(&hash, u16, capture.format);
    hashInt(&hash, u16, capture.schema);
    hash.update(&capture.projected_base.vm_air.proof_capture_sha256);
    hash.update(&capture.projected_base.vm_air.identity_digest);
    hash.update(&capture.ethereum_context.identity_digest);
    hash.update(&capture.projection.identity);
    hash.update(&capture.shared.identity);
    hash.update(&capture.fresh_core.identity);
    for (capture.proof_commitments) |root|
        hash.update(std.mem.asBytes(&root));
    return hash.finalResult();
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
