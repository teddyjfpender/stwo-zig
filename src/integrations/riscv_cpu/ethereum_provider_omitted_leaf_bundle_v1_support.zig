//! Private validation and identity helpers for the ordinary omitted-provider
//! leaf bundle. Kept separate so the public custody module stays compact.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const guest = frontend.prover_mod.guest_precompile;
const d5 = frontend.testing
    .narrow_memory_provider_degree5_ethereum_omit_proof_v1;
const native_omit = guest.native_provider_omit_v1;
const source_wire = guest.ethereum_segment_source_wire;
const ethereum_types = guest.ethereum_types;
const lookup_physical_v2 = frontend.air.lookup_physical_manifest_v2;
const statement_v2 = frontend.air.statement_v2;
const transcript_claims = frontend.air.transcript;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const proof_authority = frontend.prover_mod
    .memory_provider_shard_joint_proof_authority;

const QM31 = core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;

const bundle_identity_domain =
    "stwo-zig/riscv/ethereum-omitted-leaf-bundle-authority/v1\x00";
const tree0_identity_domain =
    "stwo-zig/riscv/ethereum-omitted-leaf-tree0/v1\x00";
const proof_root_domain =
    "stwo-zig/riscv/ethereum-omitted-leaf-proof-roots/v1\x00";
const transcript_state_domain =
    "stwo-zig/riscv/ethereum-omitted-leaf-transcript/v1\x00";
const capture_identity_domain =
    "stwo-zig/riscv/ethereum-omitted-leaf-fresh-capture/v1\x00";

pub fn validateCoreMetadata(
    comptime Engine: type,
    full: *const statement_v2.RiscVStatementV2,
    projected: anytype,
    authority: anytype,
) !void {
    try full.validate();
    try projected.statement.validate();
    try projected.extension.validateV2(full);
    try guest.ethereum_segment_proof_artifact.validateGlobalMetadataMapping(
        full,
        &projected.global,
    );
    if (!std.meta.eql(projected.global, authority.source.metadata) or
        !m31SlicesEqual(
            full.public_data.words(),
            projected.statement.public_data.words(),
        ) or !std.meta.eql(
        authority.calls.public_data_wire_id,
        full.public_data.wireId(),
    )) return error.OmittedLeafCoreMetadataMismatch;
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &full.core,
        &manifest,
    );
    const projection = try native_omit.ProjectionV1.init(
        full,
        &projected.extension,
        .proof,
        &manifest,
        &authenticated,
        authority.plan,
        authority.calls.calls,
        try native_omit.deriveFullGeometry(full),
    );
    if (!std.meta.eql(
        projection.projected_native.core,
        projected.statement.core,
    )) return error.OmittedLeafProjectedStatementMismatch;
    try authority.shared.validate(
        authority.plan,
        authority.provider_stage_a,
        &projection,
    );
    _ = Engine;
}

pub fn claimedSums(
    projected: [transcript_claims.COMPONENT_COUNT]QM31,
    providers: []const d5.FreshDegree5ProviderClaimV1,
    extension: *const ethereum_statement.Statement,
    extension_claim: *const ethereum_types.ExtensionClaim,
) ![transcript_claims.COMPONENT_COUNT + ethereum_statement.component_count]QM31 {
    if (providers.len == 0) return error.MissingOmittedLeafProviderClaims;
    var result: [
        transcript_claims.COMPONENT_COUNT +
            ethereum_statement.component_count
    ]QM31 = undefined;
    @memcpy(result[0..transcript_claims.COMPONENT_COUNT], &projected);
    const poseidon_index = @intFromEnum(transcript_claims.Component.poseidon2);
    if (!result[poseidon_index].isZero())
        return error.NonZeroProjectedPoseidonClaim;
    for (providers) |provider| {
        try provider.validate();
        for (provider.provider.native_claim.claims.sums) |sum|
            result[poseidon_index] = result[poseidon_index].add(sum);
    }
    try extension_claim.validate(extension);
    const claims = extensionClaimSums(extension_claim);
    @memcpy(result[transcript_claims.COMPONENT_COUNT..], &claims);
    return result;
}

pub fn tree0Identity(comptime Engine: type, value: anytype) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(tree0_identity_domain);
    hash.update(std.mem.asBytes(&value.projected_core_root));
    hash.update(&value.projection_identity);
    hash.update(&value.provider_manifest_identity);
    hashInt(&hash, u32, value.omitted_infra_index);
    hashInt(&hash, u32, @intFromEnum(value.omitted_descriptor.kind));
    hashInt(&hash, u32, value.omitted_descriptor.log_size);
    hashInt(&hash, u32, value.omitted_descriptor.n_rows);
    hashInt(&hash, u32, value.omitted_descriptor.n_columns);
    hashInt(&hash, u32, @intCast(value.provider_preprocessed_roots.len));
    for (value.provider_preprocessed_roots) |root|
        hash.update(std.mem.asBytes(&root));
    _ = Engine;
    return hash.finalResult();
}

pub fn proofRootIdentity(comptime Engine: type, value: anytype) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(proof_root_domain);
    hash.update(&proof_authority.commitmentsIdentity(
        Engine,
        &value.core_commitments,
    ));
    hash.update(&value.core_capture.projected_base.vm_air.proof_capture_sha256);
    hash.update(&value.tree0.identity);
    hashInt(&hash, u32, @intCast(value.provider_claims.len));
    for (value.provider_claims, value.provider_captures) |provider, capture| {
        hash.update(&provider.provider.proof_commitments_identity);
        hash.update(&capture.proof_root_sha256);
        hash.update(&capture.proof_capture_sha256);
        hash.update(&capture.identity);
    }
    return hash.finalResult();
}

pub fn transcriptStateIdentity(comptime Engine: type, value: anytype) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(transcript_state_domain);
    hash.update(&value.shared.identity);
    hash.update(&value.fresh_core.identity);
    hash.update(&value.closure.identity);
    hash.update(&value.program_descriptor.descriptor_sha256);
    hash.update(&value.provider_custody.compiler.compiler_authority_sha256);
    for (value.provider_claims) |provider| hash.update(&provider.identity);
    for (value.transcript_claimed_sums) |sum| hashQm31(&hash, sum);
    _ = Engine;
    return hash.finalResult();
}

pub fn freshCaptureIdentity(comptime Engine: type, value: anytype) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(capture_identity_domain);
    hash.update(&value.authority_identity);
    hash.update(&value.proof_artifact_sha256);
    hash.update(&value.proof_root_sha256);
    hash.update(&value.transcript_state_sha256);
    hash.update(&value.tree0.identity);
    for (value.verified_link.identity) |limb|
        hashInt(&hash, u32, limb);
    hash.update(&value.closure.identity);
    _ = Engine;
    return hash.finalResult();
}

pub fn authorityIdentity(authority: anytype) ![32]u8 {
    const source_bytes = try source_wire.encodeValue(authority.source);
    var hash = Sha256.init(.{});
    hash.update(bundle_identity_domain);
    hash.update(&authority.expected_program.air_program_identity);
    hash.update(&authority.execution_profile.identity);
    hash.update(&authority.plan.identity);
    hash.update(&authority.provider_stage_a.identity);
    hash.update(&authority.shared.identity);
    hash.update(&authority.omitted_core.identity);
    hash.update(&authority.plan_admission.identity);
    hash.update(&authority.core_security_identity_sha256);
    hash.update(&source_bytes);
    return hash.finalResult();
}

pub fn sha256(bytes: []const u8) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(bytes);
    return hash.finalResult();
}

fn m31SlicesEqual(
    lhs: []const core.fields.m31.M31,
    rhs: []const core.fields.m31.M31,
) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |left, right|
        if (left.toU32() != right.toU32()) return false;
    return true;
}

fn extensionClaimSums(
    claim: *const ethereum_types.ExtensionClaim,
) [ethereum_statement.component_count]QM31 {
    return .{
        claim.keccak_shard.component_sum,
        claim.keccak_chi_table,
        claim.keccak_xor5_table,
        claim.product_base.component_sum,
        claim.product_scalar.component_sum,
        claim.linear_base.component_sum,
        claim.linear_scalar.component_sum,
        claim.point.component_sum,
        claim.split.component_sum,
        claim.scalar.component_sum,
        claim.table.component_sum,
        claim.recovery.component_sum,
        claim.byte.component_sum,
        claim.recovery_caller.component_sum,
    };
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
