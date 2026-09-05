//! Degree-five provider adapter for the combined candidate Ethereum leaf.
//!
//! The 239-column provider AIR and retained `.always` execution profile are
//! unchanged. Only the shared transcript source and typed authority envelopes
//! differ: every proof replays the candidate Profile+Admission and the four
//! appended call-relation draws. Ordinary provider proofs cannot be relabelled
//! into this route, and this route remains ineligible for production.

const std = @import("std");
const core_pcs = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const aggregation_hash = @import("../../aggregation/hash.zig");
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const candidate_admission = @import("../guest_precompile/ethereum_candidate_leaf_admission_v1.zig");
const candidate_integration = @import("../guest_precompile/ethereum_candidate_leaf_integration_v1.zig");
const candidate_profile = @import("../guest_precompile/ethereum_candidate_leaf_profile_v1.zig");
const provider_authority = @import("authority.zig");
const candidate_protocol = @import("ethereum_candidate_omit_protocol_v1.zig");
const ordinary_protocol = @import("ethereum_omit_protocol_v1.zig");
const ordinary_provider = @import("degree5_ethereum_omit_provider_proof_v1.zig");
const ordinary_source = @import("ethereum_omit_provider_proof_v1.zig");
const omission = @import("native_provider_omit_v1.zig");
const provider_order = @import("provider_order_component.zig");

pub const format_version: u32 = 1;
pub const production_active = false;
pub const Digest = aggregation_hash.Digest;
pub const VerifierProgramAuthorityV2 = ordinary_provider.VerifierProgramAuthorityV2;
pub const ExecutionProfileV1 = ordinary_provider.ExecutionProfileV1;
pub const ExecutionProfileV2 = ordinary_provider.ExecutionProfileV2;
pub const ProviderStatement = ordinary_provider.ProviderStatementV1;
pub const FreshProviderClaim = ordinary_provider.FreshDegree5ProviderClaimV1;
pub const commitStageAV1 = ordinary_provider.commitStageAV1;

pub fn PreparedStageATransactionV1(comptime Engine: type) type {
    return ordinary_provider.PreparedStageATransactionV1(Engine);
}

pub fn Source(comptime Engine: type) type {
    return struct {
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        lookup_manifest: *const lookup_physical_v2.Manifest,
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        projection: *const omission.ProjectionV1,
        profile: *const candidate_profile.Profile,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        provider_stage_a: *const ordinary_protocol.ProviderStageAManifestV1(Engine),
        shared: candidate_protocol.SharedRelationAuthorityV1(Engine),

        const Self = @This();

        pub fn validate(self: Self) !void {
            try self.provider_stage_a.validate(self.plan, self.calls);
            const base_columns = std.math.cast(
                u32,
                try self.authenticated_lookup.totalInteractionColumns(
                    &self.projection.projected_native.core,
                    self.lookup_manifest,
                ),
            ) orelse return error.EthereumCandidateLeafGeometryOverflow;
            const admission = try candidate_admission.validateProjectedV2(
                self.native,
                &self.projection.projected_native.core,
                self.extension,
                base_columns,
                self.profile,
                .proof,
            );
            try self.projection.validateAgainstWithRetirementSupplementV2(
                self.native,
                self.extension,
                .proof,
                admission.retirementSupplementV2(),
                self.lookup_manifest,
                self.authenticated_lookup,
                self.plan,
                self.calls,
                try omission.deriveFullGeometry(self.native),
            );
            try self.shared.validate(
                self.native,
                self.extension,
                base_columns,
                self.profile,
                self.plan,
                self.provider_stage_a,
                self.projection,
            );
            if (!std.meta.eql(admission, self.shared.admission))
                return error.EthereumCandidateAdmissionAuthorityMismatch;
        }

        pub fn ordinary(self: Self) ordinary_source.Source(Engine) {
            return .{
                .native = self.native,
                .extension = self.extension,
                .lookup_manifest = self.lookup_manifest,
                .authenticated_lookup = self.authenticated_lookup,
                .projection = self.projection,
                .plan = self.plan,
                .calls = self.calls,
                .provider_stage_a = self.provider_stage_a,
                .shared = self.shared.ordinary,
                .retirement_supplement = self.shared.admission
                    .retirementSupplementV2(),
            };
        }
    };
}

pub const CandidateProviderStatementV1 = struct {
    format: u32 = format_version,
    candidate_shared_authority_identity: Digest,
    profile_identity: Digest,
    admission: candidate_admission.Admission,
    provider: ProviderStatement,
    identity: Digest,

    pub fn validateAgainst(
        self: CandidateProviderStatementV1,
        source: anytype,
    ) !void {
        try source.validate();
        if (self.format != format_version or
            !aggregation_hash.eql(
                self.candidate_shared_authority_identity,
                source.shared.identity,
            ) or !aggregation_hash.eql(
            self.profile_identity,
            source.profile.identity,
        ) or !std.meta.eql(self.admission, source.shared.admission) or
            !aggregation_hash.eql(
                self.identity,
                candidateProviderStatementIdentity(
                    source.shared.identity,
                    source.profile.identity,
                    source.shared.admission,
                    self.provider,
                ),
            ))
        {
            return error.InvalidDegree5EthereumCandidateProviderStatement;
        }
    }
};

pub fn ProviderProofOutputV1(comptime Engine: type) type {
    return struct {
        statement: CandidateProviderStatementV1,
        execution_profile_identity: Digest,
        proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    };
}

pub const FreshCandidateProviderClaimV1 = struct {
    format: u32 = format_version,
    candidate_statement_identity: Digest,
    candidate_shared_authority_identity: Digest,
    profile_identity: Digest,
    provider: FreshProviderClaim,
    identity: Digest,

    pub fn validateAgainst(
        self: FreshCandidateProviderClaimV1,
        source: anytype,
    ) !void {
        try source.validate();
        try self.provider.validate();
        if (self.format != format_version or
            !aggregation_hash.eql(
                self.candidate_shared_authority_identity,
                source.shared.identity,
            ) or !aggregation_hash.eql(
            self.profile_identity,
            source.profile.identity,
        ) or !aggregation_hash.eql(
            self.identity,
            freshCandidateProviderClaimIdentity(self),
        )) {
            return error.InvalidFreshDegree5EthereumCandidateProviderClaim;
        }
    }
};

/// Minted only by the fresh candidate leaf verifier after ordinary projected
/// STARK verification, all four appended AIRs, and their internal call buses
/// have closed. The constructor is deliberately named for that call site; it
/// is not an alternative verifier.
pub const FreshCandidateCoreResidualV1 = struct {
    format: u32 = format_version,
    candidate_shared_authority_identity: Digest,
    profile_identity: Digest,
    admission: candidate_admission.Admission,
    candidate_claims: candidate_integration.Claims,
    ordinary: ordinary_protocol.FreshCoreResidualV1,
    candidate_components_freshly_verified: bool,
    candidate_internal_call_buses_closed: bool,
    production_eligible: bool = false,
    identity: Digest,

    pub fn captureAfterFreshCandidateVerification(
        source: anytype,
        ordinary_residual: ordinary_protocol.FreshCoreResidualV1,
        claims: candidate_integration.Claims,
    ) !FreshCandidateCoreResidualV1 {
        try source.validate();
        try ordinary_residual.validate();
        try claims.validate(source.profile);
        if (!candidate_integration.bulkCallRelationSum(claims).isZero() or
            !candidate_integration.swapCallRelationSum(claims).isZero())
        {
            return error.EthereumCandidateInternalCallBusNotClosed;
        }
        var result = FreshCandidateCoreResidualV1{
            .candidate_shared_authority_identity = source.shared.identity,
            .profile_identity = source.profile.identity,
            .admission = source.shared.admission,
            .candidate_claims = claims,
            .ordinary = ordinary_residual,
            .candidate_components_freshly_verified = true,
            .candidate_internal_call_buses_closed = true,
            .identity = undefined,
        };
        result.identity = freshCandidateCoreIdentity(result);
        try result.validateAgainst(source);
        return result;
    }

    pub fn validateAgainst(
        self: FreshCandidateCoreResidualV1,
        source: anytype,
    ) !void {
        try source.validate();
        try self.ordinary.validate();
        try self.candidate_claims.validate(source.profile);
        if (self.format != format_version or
            !self.candidate_components_freshly_verified or
            !self.candidate_internal_call_buses_closed or
            self.production_eligible or
            !candidate_integration.bulkCallRelationSum(
                self.candidate_claims,
            ).isZero() or !candidate_integration.swapCallRelationSum(
            self.candidate_claims,
        ).isZero() or !aggregation_hash.eql(
            self.candidate_shared_authority_identity,
            source.shared.identity,
        ) or !aggregation_hash.eql(
            self.profile_identity,
            source.profile.identity,
        ) or !std.meta.eql(self.admission, source.shared.admission) or
            !aggregation_hash.eql(self.identity, freshCandidateCoreIdentity(self)))
        {
            return error.InvalidFreshEthereumCandidateCoreResidual;
        }
    }
};

pub const VerifiedJointClosureV1 = struct {
    format: u32 = format_version,
    candidate_shared_authority_identity: Digest,
    profile_identity: Digest,
    admission: candidate_admission.Admission,
    fresh_core_identity: Digest,
    candidate_provider_claims_identity: Digest,
    ordinary: ordinary_protocol.VerifiedJointClosureV1,
    candidate_components_freshly_verified: bool,
    candidate_internal_call_buses_closed: bool,
    production_eligible: bool = false,
    recursive_admissible: bool = false,
    identity: Digest,

    pub fn validateAgainst(
        self: VerifiedJointClosureV1,
        source: anytype,
        core: FreshCandidateCoreResidualV1,
        providers: []const FreshCandidateProviderClaimV1,
    ) !void {
        try source.validate();
        try core.validateAgainst(source);
        try self.ordinary.validate();
        for (providers) |provider| try provider.validateAgainst(source);
        if (self.format != format_version or
            !self.candidate_components_freshly_verified or
            !self.candidate_internal_call_buses_closed or
            self.production_eligible or self.recursive_admissible or
            !aggregation_hash.eql(
                self.candidate_shared_authority_identity,
                source.shared.identity,
            ) or !aggregation_hash.eql(
            self.profile_identity,
            source.profile.identity,
        ) or !std.meta.eql(self.admission, source.shared.admission) or
            !aggregation_hash.eql(self.fresh_core_identity, core.identity) or
            !aggregation_hash.eql(
                self.candidate_provider_claims_identity,
                candidateProviderClaimsIdentity(providers),
            ) or !aggregation_hash.eql(
            self.identity,
            verifiedJointClosureIdentity(self),
        )) {
            return error.InvalidEthereumCandidateJointClosure;
        }
    }
};

pub const FreshStrategyV1 = struct {
    format: u32 = format_version,
    candidate_shared_authority_identity: Digest,
    profile_identity: Digest,
    closure_identity: Digest,
    ordinary: ordinary_provider.FreshStrategyV1,
    production_eligible: bool = false,
    identity: Digest,

    pub fn validateAgainst(
        self: FreshStrategyV1,
        source: anytype,
        closure: VerifiedJointClosureV1,
    ) !void {
        try source.validate();
        try self.ordinary.validate();
        if (self.format != format_version or self.production_eligible or
            !aggregation_hash.eql(
                self.candidate_shared_authority_identity,
                source.shared.identity,
            ) or !aggregation_hash.eql(
            self.profile_identity,
            source.profile.identity,
        ) or !aggregation_hash.eql(self.closure_identity, closure.identity) or
            !aggregation_hash.eql(self.identity, strategyIdentity(self)))
        {
            return error.InvalidFreshDegree5EthereumCandidateStrategy;
        }
    }
};

pub const ClosedStrategyV1 = struct {
    closure: VerifiedJointClosureV1,
    strategy: FreshStrategyV1,
};

pub fn proveProviderV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV1,
    source: Source(Engine),
    shard_index: u32,
) !ProviderProofOutputV1(Engine) {
    const output = try ordinary_provider.proveProviderWithTranscriptV1(
        Engine,
        CandidateTranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        source,
        shard_index,
    );
    return .{
        .statement = makeCandidateStatement(source, output.statement),
        .execution_profile_identity = output.execution_profile_identity,
        .proof = output.proof,
    };
}

pub fn proveProviderPreparedV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV1,
    source: Source(Engine),
    shard_index: u32,
    prepared: *PreparedStageATransactionV1(Engine),
) !ProviderProofOutputV1(Engine) {
    const output = try ordinary_provider.proveProviderPreparedWithTranscriptV1(
        Engine,
        CandidateTranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        source,
        shard_index,
        prepared,
    );
    return .{
        .statement = makeCandidateStatement(source, output.statement),
        .execution_profile_identity = output.execution_profile_identity,
        .proof = output.proof,
    };
}

pub fn proveProviderV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV2,
    source: Source(Engine),
    shard_index: u32,
) !ProviderProofOutputV1(Engine) {
    const output = try ordinary_provider.proveProviderWithTranscriptV2(
        Engine,
        CandidateTranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        source,
        shard_index,
    );
    return .{
        .statement = makeCandidateStatement(source, output.statement),
        .execution_profile_identity = output.execution_profile_identity,
        .proof = output.proof,
    };
}

pub fn proveProviderPreparedV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV2,
    source: Source(Engine),
    shard_index: u32,
    prepared: *PreparedStageATransactionV1(Engine),
) !ProviderProofOutputV1(Engine) {
    const output = try ordinary_provider.proveProviderPreparedWithTranscriptV2(
        Engine,
        CandidateTranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        execution_profile,
        source,
        shard_index,
        prepared,
    );
    return .{
        .statement = makeCandidateStatement(source, output.statement),
        .execution_profile_identity = output.execution_profile_identity,
        .proof = output.proof,
    };
}

pub fn verifyProviderFreshV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    expected_execution_profile: ExecutionProfileV1,
    source: Source(Engine),
    statement: CandidateProviderStatementV1,
    proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshCandidateProviderClaimV1 {
    try statement.validateAgainst(source);
    const provider = try ordinary_provider.verifyProviderFreshWithTranscriptV1(
        Engine,
        CandidateTranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        expected_execution_profile,
        source,
        statement.provider,
        proof,
    );
    var result = FreshCandidateProviderClaimV1{
        .candidate_statement_identity = statement.identity,
        .candidate_shared_authority_identity = source.shared.identity,
        .profile_identity = source.profile.identity,
        .provider = provider,
        .identity = undefined,
    };
    result.identity = freshCandidateProviderClaimIdentity(result);
    try result.validateAgainst(source);
    return result;
}

pub fn verifyProviderFreshV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: core_pcs.PcsConfig,
    expected_program: VerifierProgramAuthorityV2,
    expected_execution_profile: ExecutionProfileV2,
    source: Source(Engine),
    statement: CandidateProviderStatementV1,
    proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
) !FreshCandidateProviderClaimV1 {
    try statement.validateAgainst(source);
    const provider = try ordinary_provider.verifyProviderFreshWithTranscriptV2(
        Engine,
        CandidateTranscriptAdapter,
        allocator,
        pcs_config,
        expected_program,
        expected_execution_profile,
        source,
        statement.provider,
        proof,
    );
    var result = FreshCandidateProviderClaimV1{
        .candidate_statement_identity = statement.identity,
        .candidate_shared_authority_identity = source.shared.identity,
        .profile_identity = source.profile.identity,
        .provider = provider,
        .identity = undefined,
    };
    result.identity = freshCandidateProviderClaimIdentity(result);
    try result.validateAgainst(source);
    return result;
}

pub fn closeFreshClaimsV1(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV1,
    source: Source(Engine),
    core: FreshCandidateCoreResidualV1,
    providers: []const FreshCandidateProviderClaimV1,
) !ClosedStrategyV1 {
    return closeFreshClaimsInternal(
        Engine,
        allocator,
        expected_program,
        execution_profile,
        source,
        core,
        providers,
    );
}

pub fn closeFreshClaimsV2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: ExecutionProfileV2,
    source: Source(Engine),
    core: FreshCandidateCoreResidualV1,
    providers: []const FreshCandidateProviderClaimV1,
) !ClosedStrategyV1 {
    return closeFreshClaimsInternal(
        Engine,
        allocator,
        expected_program,
        execution_profile,
        source,
        core,
        providers,
    );
}

fn closeFreshClaimsInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    expected_program: VerifierProgramAuthorityV2,
    execution_profile: anytype,
    source: Source(Engine),
    core: FreshCandidateCoreResidualV1,
    providers: []const FreshCandidateProviderClaimV1,
) !ClosedStrategyV1 {
    try source.validate();
    try core.validateAgainst(source);
    if (providers.len != source.plan.shards.len)
        return error.InvalidDegree5EthereumCandidateProviderClaimCount;
    const ordinary_claims = try allocator.alloc(FreshProviderClaim, providers.len);
    defer allocator.free(ordinary_claims);
    for (providers, ordinary_claims, 0..) |provider, *destination, index| {
        try provider.validateAgainst(source);
        if (provider.provider.provider.native_claim.shard_index != index)
            return error.NonCanonicalDegree5EthereumCandidateProviderClaim;
        destination.* = provider.provider;
    }
    const closed = if (comptime @TypeOf(execution_profile) == ExecutionProfileV1)
        try ordinary_provider.closeFreshClaimsV1(
            Engine,
            allocator,
            expected_program,
            execution_profile,
            source.ordinary(),
            core.ordinary,
            ordinary_claims,
        )
    else if (comptime @TypeOf(execution_profile) == ExecutionProfileV2)
        try ordinary_provider.closeFreshClaimsV2(
            Engine,
            allocator,
            expected_program,
            execution_profile,
            source.ordinary(),
            core.ordinary,
            ordinary_claims,
        )
    else
        @compileError("unsupported degree-five execution profile");
    var closure = VerifiedJointClosureV1{
        .candidate_shared_authority_identity = source.shared.identity,
        .profile_identity = source.profile.identity,
        .admission = source.shared.admission,
        .fresh_core_identity = core.identity,
        .candidate_provider_claims_identity = candidateProviderClaimsIdentity(
            providers,
        ),
        .ordinary = closed.closure,
        .candidate_components_freshly_verified = true,
        .candidate_internal_call_buses_closed = true,
        .identity = undefined,
    };
    closure.identity = verifiedJointClosureIdentity(closure);
    try closure.validateAgainst(source, core, providers);
    var strategy = FreshStrategyV1{
        .candidate_shared_authority_identity = source.shared.identity,
        .profile_identity = source.profile.identity,
        .closure_identity = closure.identity,
        .ordinary = closed.strategy,
        .identity = undefined,
    };
    strategy.identity = strategyIdentity(strategy);
    try strategy.validateAgainst(source, closure);
    return .{ .closure = closure, .strategy = strategy };
}

const CandidateTranscriptAdapter = struct {
    pub fn replayShared(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: core_pcs.PcsConfig,
        source: Source(Engine),
    ) !candidate_protocol.Replay(Engine) {
        return candidate_protocol.replaySharedTranscript(
            Engine,
            allocator,
            pcs_config,
            source.native,
            source.extension,
            source.lookup_manifest,
            source.authenticated_lookup,
            source.projection,
            source.profile,
            source.plan,
            source.calls,
            source.provider_stage_a,
            source.shared,
        );
    }

    pub fn providerLocalPrefix(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: core_pcs.PcsConfig,
        source: Source(Engine),
        claim: provider_authority.ProviderShardClaimV1,
        ordered: provider_order.ClaimV1,
    ) !Engine.Channel {
        var channel = try candidate_protocol.providerLocalPrefixV2(
            Engine,
            allocator,
            pcs_config,
            source.native,
            source.extension,
            source.lookup_manifest,
            source.authenticated_lookup,
            source.projection,
            source.profile,
            source.plan,
            source.calls,
            source.provider_stage_a,
            source.shared,
            claim,
            ordered,
        );
        channel.mixU32s(&candidate_provider_local_domain);
        mixDigest(&channel, source.shared.identity);
        mixDigest(&channel, source.profile.identity);
        source.shared.admission.mixInto(&channel);
        return channel;
    }
};

fn makeCandidateStatement(
    source: anytype,
    provider: ProviderStatement,
) CandidateProviderStatementV1 {
    var result = CandidateProviderStatementV1{
        .candidate_shared_authority_identity = source.shared.identity,
        .profile_identity = source.profile.identity,
        .admission = source.shared.admission,
        .provider = provider,
        .identity = undefined,
    };
    result.identity = candidateProviderStatementIdentity(
        source.shared.identity,
        source.profile.identity,
        source.shared.admission,
        provider,
    );
    return result;
}

fn candidateProviderStatementIdentity(
    shared_identity: Digest,
    profile_identity: Digest,
    admission: candidate_admission.Admission,
    provider: ProviderStatement,
) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-candidate-d5-provider-statement/v1\x00",
    );
    sink.writeAll(&shared_identity) catch unreachable;
    sink.writeAll(&profile_identity) catch unreachable;
    writeAdmission(&sink, admission);
    sink.writeAll(&provider.identity) catch unreachable;
    return sink.finalize();
}

fn freshCandidateProviderClaimIdentity(
    value: FreshCandidateProviderClaimV1,
) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-candidate-d5-provider-fresh/v1\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.candidate_statement_identity) catch unreachable;
    sink.writeAll(&value.candidate_shared_authority_identity) catch unreachable;
    sink.writeAll(&value.profile_identity) catch unreachable;
    sink.writeAll(&value.provider.identity) catch unreachable;
    return sink.finalize();
}

fn freshCandidateCoreIdentity(value: FreshCandidateCoreResidualV1) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-candidate-fresh-core/v1\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.candidate_shared_authority_identity) catch unreachable;
    sink.writeAll(&value.profile_identity) catch unreachable;
    writeAdmission(&sink, value.admission);
    writeCandidateClaims(&sink, value.candidate_claims);
    sink.writeAll(&value.ordinary.identity) catch unreachable;
    sink.writeAll(&.{
        @intFromBool(value.candidate_components_freshly_verified),
        @intFromBool(value.candidate_internal_call_buses_closed),
        @intFromBool(value.production_eligible),
    }) catch unreachable;
    return sink.finalize();
}

fn candidateProviderClaimsIdentity(
    values: []const FreshCandidateProviderClaimV1,
) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-candidate-d5-provider-claims/v1\x00",
    );
    aggregation_hash.writeU32(&sink, @intCast(values.len)) catch unreachable;
    for (values) |value| sink.writeAll(&value.identity) catch unreachable;
    return sink.finalize();
}

fn verifiedJointClosureIdentity(value: VerifiedJointClosureV1) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-candidate-joint-closure/v1\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.candidate_shared_authority_identity) catch unreachable;
    sink.writeAll(&value.profile_identity) catch unreachable;
    writeAdmission(&sink, value.admission);
    sink.writeAll(&value.fresh_core_identity) catch unreachable;
    sink.writeAll(&value.candidate_provider_claims_identity) catch unreachable;
    sink.writeAll(&value.ordinary.identity) catch unreachable;
    sink.writeAll(&.{
        @intFromBool(value.candidate_components_freshly_verified),
        @intFromBool(value.candidate_internal_call_buses_closed),
        @intFromBool(value.production_eligible),
        @intFromBool(value.recursive_admissible),
    }) catch unreachable;
    return sink.finalize();
}

fn strategyIdentity(value: FreshStrategyV1) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-candidate-d5-provider-strategy/v1\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.candidate_shared_authority_identity) catch unreachable;
    sink.writeAll(&value.profile_identity) catch unreachable;
    sink.writeAll(&value.closure_identity) catch unreachable;
    sink.writeAll(&value.ordinary.identity) catch unreachable;
    sink.writeAll(&.{@intFromBool(value.production_eligible)}) catch unreachable;
    return sink.finalize();
}

fn writeAdmission(sink: anytype, value: candidate_admission.Admission) void {
    aggregation_hash.writeU16(sink, value.format) catch unreachable;
    aggregation_hash.writeU32(sink, value.candidate_retirements) catch unreachable;
    aggregation_hash.writeU32(sink, value.total_external_retirements) catch unreachable;
    aggregation_hash.writeU64(sink, value.candidate_extra_memory_terms) catch unreachable;
    aggregation_hash.writeU64(sink, value.total_extra_memory_terms) catch unreachable;
    aggregation_hash.writeU64(sink, value.expected_memory_relation_terms) catch unreachable;
    for (value.extended_fixed_table_bounds) |bound|
        aggregation_hash.writeU64(sink, bound) catch unreachable;
    sink.writeAll(&.{@intFromBool(value.production_eligible)}) catch unreachable;
}

fn writeCandidateClaims(sink: anytype, claims: candidate_integration.Claims) void {
    inline for (.{
        claims.bulk_memcpy_caller,
        claims.bulk_memcpy_words,
        claims.stack_swap_caller,
        claims.stack_swap_words,
    }) |claim| {
        aggregation_hash.writeU32(sink, claim.log_size) catch unreachable;
        aggregation_hash.writeU32(sink, claim.n_rows) catch unreachable;
        for (claim.batch_sums) |sum| writeQm31(sink, sum);
        writeQm31(sink, claim.component_sum);
    }
}

fn writeQm31(sink: anytype, value: QM31) void {
    for (value.toM31Array()) |limb|
        aggregation_hash.writeU32(sink, limb.v) catch unreachable;
}

fn mixDigest(channel: anytype, value: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

const candidate_provider_local_domain = [5]u32{
    0x5354_5742, // STWB
    0x3143_3545, // E5C1
    format_version,
    @intFromBool(production_active),
    4,
};

comptime {
    if (production_active or ordinary_provider.ACTIVATES_PRODUCTION_PROOF or
        candidate_protocol.production_active or
        candidate_profile.production_active or
        candidate_admission.production_active or
        candidate_integration.production_active)
    {
        @compileError("candidate degree-five provider became active");
    }
}
