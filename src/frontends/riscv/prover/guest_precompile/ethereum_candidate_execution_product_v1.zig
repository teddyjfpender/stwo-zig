//! Nonproduction product authority for a candidate Ethereum execution journal.
//!
//! This product is not a STARK proof and cannot be published. It binds the
//! transaction-minted executable capability, the complete execution journal,
//! and an explicit provider-strategy slot. The provider slot is unresolved for
//! the current SWAP fixture, allowing a later degree-5, canonical, or sharded
//! provider authority without changing journal or product fields.

const std = @import("std");

const registry_mod =
    @import("../../isa/ethereum_candidate_private_registry_v1.zig");
const capability_mod = @import(
    "../../runner/guest_precompile/ethereum_candidate_execution_capability_v1.zig",
);
const journal_mod = @import(
    "../../runner/guest_precompile/ethereum_candidate_execution_journal_v1.zig",
);
const full_provider_protocol =
    @import("../memory_provider_shards/full_core_joint_protocol.zig");
const degree5_ethereum_strategy = @import(
    "../memory_provider_shards/degree5_ethereum_omit_provider_authority_v1.zig",
);
const ethereum_omit_protocol =
    @import("../memory_provider_shards/ethereum_omit_protocol_v1.zig");

pub const Digest = [32]u8;
pub const production_active = false;
pub const publication_enabled = false;
pub const format_version: u16 = 1;
pub const schema_version: u16 = 1;

/// Extensible numeric tags belong to this ABI; they are not host enum ordinals.
pub const ProviderStrategyTag = struct {
    pub const unresolved: u16 = 0;
    pub const canonical_native: u16 = 1;
    pub const degree5_retained: u16 = 2;
    pub const provider_shards: u16 = 3;
};

pub const ProviderAuthority = struct {
    format: u16 = format_version,
    schema: u16 = schema_version,
    resolved: bool,
    fresh_verification_minted: bool,
    strategy_tag: u16,
    registry_identity: Digest,
    strategy_identity: Digest,
    verifier_program_identity: Digest,
    preprocessed_commitment_identity: Digest,
    provider_plan_identity: Digest,
    provider_manifest_identity: Digest,
    provider_relation_context_identity: Digest,
    provider_closure_identity: Digest,
    ordered_provider_claims_identity: Digest,
    provider_shard_count: u32,
    identity: Digest,

    pub fn unresolved(registry: registry_mod.Registry) !ProviderAuthority {
        try registry.validate();
        var result = ProviderAuthority{
            .resolved = false,
            .fresh_verification_minted = false,
            .strategy_tag = ProviderStrategyTag.unresolved,
            .registry_identity = registry.identity,
            .strategy_identity = zero_digest,
            .verifier_program_identity = zero_digest,
            .preprocessed_commitment_identity = zero_digest,
            .provider_plan_identity = zero_digest,
            .provider_manifest_identity = zero_digest,
            .provider_relation_context_identity = zero_digest,
            .provider_closure_identity = zero_digest,
            .ordered_provider_claims_identity = zero_digest,
            .provider_shard_count = 0,
            .identity = undefined,
        };
        result.identity = providerIdentity(result);
        try result.validateAgainst(registry);
        return result;
    }

    /// Construct only from the genuine full-core + ordered-provider closure
    /// emitted by one shared-transcript verifier transaction. A standalone d5
    /// component receipt has a different type and cannot enter this boundary.
    /// The two program digests are proof-independent cold-verifier custody;
    /// transport SHA values alone are insufficient.
    pub fn initFromFullFreshProviderClosure(
        registry: registry_mod.Registry,
        closure: full_provider_protocol.VerifiedFullCoreJointClosureV1,
        verifier_program_identity: Digest,
        preprocessed_commitment_identity: Digest,
    ) !ProviderAuthority {
        try registry.validate();
        try closure.validate();
        if (isZero(verifier_program_identity) or
            isZero(preprocessed_commitment_identity))
        {
            return error.InvalidEthereumCandidateProviderAuthority;
        }
        var result = ProviderAuthority{
            .resolved = true,
            .fresh_verification_minted = true,
            .strategy_tag = ProviderStrategyTag.provider_shards,
            .registry_identity = registry.identity,
            .strategy_identity = closure.identity,
            .verifier_program_identity = verifier_program_identity,
            .preprocessed_commitment_identity = preprocessed_commitment_identity,
            .provider_plan_identity = closure.plan_identity,
            .provider_manifest_identity = closure.manifest_identity,
            .provider_relation_context_identity = closure.relation_context_identity,
            .provider_closure_identity = closure.identity,
            .ordered_provider_claims_identity = closure.ordered_provider_claims_identity,
            .provider_shard_count = closure.shard_count,
            .identity = undefined,
        };
        result.identity = providerIdentity(result);
        try result.validateAgainst(registry);
        return result;
    }

    /// Accept root's d5 strategy only beside the exact full Ethereum
    /// core-plus-N closure it names. The standalone d5 proof/receipt type is
    /// intentionally absent from this API.
    pub fn initFromDegree5EthereumOmitClosure(
        registry: registry_mod.Registry,
        strategy: degree5_ethereum_strategy.FreshStrategyV1,
        closure: ethereum_omit_protocol.VerifiedJointClosureV1,
    ) !ProviderAuthority {
        try registry.validate();
        try strategy.validate();
        try closure.validate();
        if (isZero(strategy.air_program_identity) or
            isZero(strategy.execution_profile_identity) or
            isZero(strategy.plan_identity) or
            isZero(strategy.manifest_identity) or
            isZero(strategy.preprocessed_commitment_identity) or
            isZero(strategy.relation_context_identity) or
            isZero(strategy.closure_identity) or
            isZero(strategy.ordered_provider_claims_identity) or
            !std.mem.eql(u8, &strategy.plan_identity, &closure.plan_identity) or
            !std.mem.eql(u8, &strategy.manifest_identity, &closure.manifest_identity) or
            !std.mem.eql(
                u8,
                &strategy.relation_context_identity,
                &closure.relation_context_identity,
            ) or !std.mem.eql(
            u8,
            &strategy.closure_identity,
            &closure.identity,
        ) or !std.mem.eql(
            u8,
            &strategy.ordered_provider_claims_identity,
            &closure.ordered_provider_claims_identity,
        ) or strategy.shard_count != closure.shard_count) {
            return error.Degree5EthereumProviderClosureMismatch;
        }
        var result = ProviderAuthority{
            .resolved = true,
            .fresh_verification_minted = true,
            .strategy_tag = ProviderStrategyTag.degree5_retained,
            .registry_identity = registry.identity,
            .strategy_identity = strategy.identity,
            .verifier_program_identity = strategy.air_program_identity,
            .preprocessed_commitment_identity = strategy.preprocessed_commitment_identity,
            .provider_plan_identity = strategy.plan_identity,
            .provider_manifest_identity = strategy.manifest_identity,
            .provider_relation_context_identity = strategy.relation_context_identity,
            .provider_closure_identity = closure.identity,
            .ordered_provider_claims_identity = strategy.ordered_provider_claims_identity,
            .provider_shard_count = strategy.shard_count,
            .identity = undefined,
        };
        result.identity = providerIdentity(result);
        try result.validateAgainst(registry);
        return result;
    }

    pub fn validateAgainst(
        self: ProviderAuthority,
        registry: registry_mod.Registry,
    ) !void {
        try registry.validate();
        if (self.format != format_version or self.schema != schema_version or
            !std.mem.eql(u8, &self.registry_identity, &registry.identity))
        {
            return error.InvalidEthereumCandidateProviderAuthority;
        }
        if (self.resolved) {
            if (!self.fresh_verification_minted or
                (self.strategy_tag != ProviderStrategyTag.provider_shards and
                    self.strategy_tag != ProviderStrategyTag.degree5_retained) or
                isZero(self.strategy_identity) or
                isZero(self.verifier_program_identity) or
                isZero(self.preprocessed_commitment_identity) or
                isZero(self.provider_plan_identity) or
                isZero(self.provider_manifest_identity) or
                isZero(self.provider_relation_context_identity) or
                isZero(self.provider_closure_identity) or
                isZero(self.ordered_provider_claims_identity) or
                self.provider_shard_count == 0)
            {
                return error.InvalidEthereumCandidateProviderAuthority;
            }
        } else if (self.fresh_verification_minted or
            self.strategy_tag != ProviderStrategyTag.unresolved or
            !isZero(self.strategy_identity) or
            !isZero(self.verifier_program_identity) or
            !isZero(self.preprocessed_commitment_identity) or
            !isZero(self.provider_plan_identity) or
            !isZero(self.provider_manifest_identity) or
            !isZero(self.provider_relation_context_identity) or
            !isZero(self.provider_closure_identity) or
            !isZero(self.ordered_provider_claims_identity) or
            self.provider_shard_count != 0)
        {
            return error.InvalidEthereumCandidateProviderAuthority;
        }
        if (!std.mem.eql(u8, &self.identity, &providerIdentity(self)))
            return error.InvalidEthereumCandidateProviderAuthorityIdentity;
    }
};

pub const Product = struct {
    format: u16 = format_version,
    schema: u16 = schema_version,
    capability_identity: Digest,
    registry_identity: Digest,
    guest_elf_sha256: Digest,
    program_commitment_identity: Digest,
    program_root: u32,
    journal_identity: Digest,
    segment_count: u32,
    total_cycles: u64,
    final_cpu_identity: Digest,
    final_memory_identity: Digest,
    terminal_output_present: bool,
    terminal_output_identity: Digest,
    provider: ProviderAuthority,
    final_candidate_executable: bool,
    execution_proof_freshly_verified: bool,
    publication_enabled: bool,
    identity: Digest,

    pub fn create(
        capability: capability_mod.Capability,
        journal: journal_mod.JournalView,
        provider: ProviderAuthority,
    ) !Product {
        try capability.validate();
        try journal.validateAgainst(capability);
        try journal.requireCanonicalBulkArtifactCustody(capability);
        try provider.validateAgainst(capability.registry);
        const journal_identity = try journal.identity(capability);
        var result = Product{
            .capability_identity = capability.identity,
            .registry_identity = capability.registry.identity,
            .guest_elf_sha256 = capability.guest_elf_sha256,
            .program_commitment_identity = capability.program_commitment_identity,
            .program_root = capability.program_root,
            .journal_identity = journal_identity,
            .segment_count = journal.summary.segment_count,
            .total_cycles = journal.summary.total_cycles,
            .final_cpu_identity = journal.summary.final_cpu_identity,
            .final_memory_identity = journal.summary.final_memory_identity,
            .terminal_output_present = journal.summary.terminal_output_present,
            .terminal_output_identity = journal.summary.terminal_output_identity,
            .provider = provider,
            .final_candidate_executable = capability.final_candidate_executable,
            // Provider verification alone never verifies the complete VM.
            .execution_proof_freshly_verified = false,
            .publication_enabled = false,
            .identity = undefined,
        };
        result.identity = productIdentity(result);
        try result.validateAgainst(capability, journal);
        return result;
    }

    /// Typed convenience edge for the shared-context d5 provider strategy.
    /// It still leaves complete-VM proof verification and publication false.
    pub fn createWithDegree5EthereumOmitProvider(
        capability: capability_mod.Capability,
        journal: journal_mod.JournalView,
        strategy: degree5_ethereum_strategy.FreshStrategyV1,
        closure: ethereum_omit_protocol.VerifiedJointClosureV1,
    ) !Product {
        const provider = try ProviderAuthority.initFromDegree5EthereumOmitClosure(
            capability.registry,
            strategy,
            closure,
        );
        return create(capability, journal, provider);
    }

    pub fn validateAgainst(
        self: Product,
        capability: capability_mod.Capability,
        journal: journal_mod.JournalView,
    ) !void {
        try capability.validate();
        try journal.validateAgainst(capability);
        try self.provider.validateAgainst(capability.registry);
        const expected_journal_identity = try journal.identity(capability);
        if (production_active or publication_enabled or
            self.format != format_version or self.schema != schema_version or
            !std.mem.eql(u8, &self.capability_identity, &capability.identity) or
            !std.mem.eql(u8, &self.registry_identity, &capability.registry.identity) or
            !std.mem.eql(u8, &self.guest_elf_sha256, &capability.guest_elf_sha256) or
            !std.mem.eql(
                u8,
                &self.program_commitment_identity,
                &capability.program_commitment_identity,
            ) or self.program_root != capability.program_root or
            !std.mem.eql(u8, &self.journal_identity, &expected_journal_identity) or
            self.segment_count != journal.summary.segment_count or
            self.total_cycles != journal.summary.total_cycles or
            !std.mem.eql(
                u8,
                &self.final_cpu_identity,
                &journal.summary.final_cpu_identity,
            ) or !std.mem.eql(
            u8,
            &self.final_memory_identity,
            &journal.summary.final_memory_identity,
        ) or self.terminal_output_present !=
            journal.summary.terminal_output_present or
            !std.mem.eql(
                u8,
                &self.terminal_output_identity,
                &journal.summary.terminal_output_identity,
            ) or self.final_candidate_executable !=
            capability.final_candidate_executable or
            self.execution_proof_freshly_verified or self.publication_enabled or
            !std.mem.eql(u8, &self.identity, &productIdentity(self)))
        {
            return error.InvalidEthereumCandidateExecutionProduct;
        }
    }
};

fn providerIdentity(value: ProviderAuthority) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-provider-authority.v1\x00");
    putInt(&hash, u16, value.format);
    putInt(&hash, u16, value.schema);
    hash.update(&.{
        @intFromBool(value.resolved),
        @intFromBool(value.fresh_verification_minted),
    });
    putInt(&hash, u16, value.strategy_tag);
    hash.update(&value.registry_identity);
    hash.update(&value.strategy_identity);
    hash.update(&value.verifier_program_identity);
    hash.update(&value.preprocessed_commitment_identity);
    hash.update(&value.provider_plan_identity);
    hash.update(&value.provider_manifest_identity);
    hash.update(&value.provider_relation_context_identity);
    hash.update(&value.provider_closure_identity);
    hash.update(&value.ordered_provider_claims_identity);
    putInt(&hash, u32, value.provider_shard_count);
    return hash.finalResult();
}

fn productIdentity(value: Product) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-execution-product.v1\x00");
    putInt(&hash, u16, value.format);
    putInt(&hash, u16, value.schema);
    hash.update(&value.capability_identity);
    hash.update(&value.registry_identity);
    hash.update(&value.guest_elf_sha256);
    hash.update(&value.program_commitment_identity);
    putInt(&hash, u32, value.program_root);
    hash.update(&value.journal_identity);
    putInt(&hash, u32, value.segment_count);
    putInt(&hash, u64, value.total_cycles);
    hash.update(&value.final_cpu_identity);
    hash.update(&value.final_memory_identity);
    hash.update(&.{@intFromBool(value.terminal_output_present)});
    hash.update(&value.terminal_output_identity);
    hash.update(&value.provider.identity);
    hash.update(&.{
        @intFromBool(value.final_candidate_executable),
        @intFromBool(value.execution_proof_freshly_verified),
        @intFromBool(value.publication_enabled),
    });
    return hash.finalResult();
}

fn putInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn isZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

const zero_digest = [_]u8{0} ** 32;

comptime {
    if (production_active or publication_enabled or format_version != 1 or
        schema_version != 1 or registry_mod.production_active or
        capability_mod.production_active or journal_mod.production_active or
        capability_mod.proof_or_fresh_verification or
        journal_mod.proof_or_fresh_verification)
    {
        @compileError("Ethereum candidate execution product became active");
    }
}

test "combined candidate contract v1: provider slot is explicit and mutation closed" {
    const registry = try registry_mod.Registry.canonical();
    const unresolved_authority = try ProviderAuthority.unresolved(registry);
    try unresolved_authority.validateAgainst(registry);

    var relabelled = unresolved_authority;
    relabelled.strategy_tag = ProviderStrategyTag.degree5_retained;
    try std.testing.expectError(
        error.InvalidEthereumCandidateProviderAuthority,
        relabelled.validateAgainst(registry),
    );

    var closure = full_provider_protocol.VerifiedFullCoreJointClosureV1{
        .format = 2,
        .plan_identity = patternedDigest(1),
        .manifest_identity = patternedDigest(2),
        .relation_context_identity = patternedDigest(3),
        .core_claim_identity = patternedDigest(4),
        .ordered_provider_claims_identity = patternedDigest(5),
        .shard_count = 2,
        .core_claim = .zero(),
        .provider_claim = .zero(),
        .closed_sum = .zero(),
        .full_core_freshly_verified = true,
        .every_provider_freshly_verified = true,
        .every_ordered_call_air_verified = true,
        .complete_ordered_coverage = true,
        .one_shared_relation_context = true,
        .native_provider_retained = true,
        .omit_recompute_owner_verified = false,
        .production_eligible = false,
        .identity = undefined,
    };
    closure.identity = full_provider_protocol.fullClosureIdentity(closure);
    var resolved = try ProviderAuthority.initFromFullFreshProviderClosure(
        registry,
        closure,
        patternedDigest(6),
        patternedDigest(7),
    );
    try resolved.validateAgainst(registry);
    resolved.preprocessed_commitment_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumCandidateProviderAuthorityIdentity,
        resolved.validateAgainst(registry),
    );

    var partial = closure;
    partial.every_provider_freshly_verified = false;
    partial.identity = full_provider_protocol.fullClosureIdentity(partial);
    try std.testing.expectError(
        error.InvalidVerifiedFullCoreJointClosure,
        ProviderAuthority.initFromFullFreshProviderClosure(
            registry,
            partial,
            patternedDigest(6),
            patternedDigest(7),
        ),
    );

    var omit_closure = ethereum_omit_protocol.VerifiedJointClosureV1{
        .format = 2,
        .plan_identity = patternedDigest(20),
        .manifest_identity = patternedDigest(21),
        .relation_context_identity = patternedDigest(22),
        .core_claim_identity = patternedDigest(23),
        .ordered_provider_claims_identity = patternedDigest(24),
        .shard_count = 3,
        .core_claim = .zero(),
        .provider_claim = .zero(),
        .closed_sum = .zero(),
        .core_freshly_verified = true,
        .every_provider_freshly_verified = true,
        .every_ordered_call_air_verified = true,
        .complete_ordered_coverage = true,
        .one_shared_relation_context = true,
        .omit_recompute_owner_verified = true,
        .production_eligible = false,
        .recursive_admissible = false,
        .identity = undefined,
    };
    omit_closure.identity = ethereum_omit_protocol.closureIdentity(omit_closure);
    var d5_strategy = degree5_ethereum_strategy.FreshStrategyV1{
        .format = degree5_ethereum_strategy.format_version,
        .air_program_identity = patternedDigest(25),
        .execution_profile_identity = patternedDigest(26),
        .plan_identity = omit_closure.plan_identity,
        .manifest_identity = omit_closure.manifest_identity,
        .preprocessed_commitment_identity = patternedDigest(27),
        .relation_context_identity = omit_closure.relation_context_identity,
        .closure_identity = omit_closure.identity,
        .ordered_provider_claims_identity = omit_closure.ordered_provider_claims_identity,
        .shard_count = omit_closure.shard_count,
        .every_provider_degree5_fresh_verified = true,
        .shared_core_zero_sum_verified = true,
        .production_eligible = false,
        .identity = undefined,
    };
    d5_strategy.identity = degree5_ethereum_strategy.strategyIdentity(d5_strategy);
    const d5_provider = try ProviderAuthority.initFromDegree5EthereumOmitClosure(
        registry,
        d5_strategy,
        omit_closure,
    );
    try std.testing.expectEqual(
        ProviderStrategyTag.degree5_retained,
        d5_provider.strategy_tag,
    );
    var mismatched_closure = omit_closure;
    mismatched_closure.relation_context_identity[0] ^= 1;
    mismatched_closure.identity =
        ethereum_omit_protocol.closureIdentity(mismatched_closure);
    try std.testing.expectError(
        error.Degree5EthereumProviderClosureMismatch,
        ProviderAuthority.initFromDegree5EthereumOmitClosure(
            registry,
            d5_strategy,
            mismatched_closure,
        ),
    );
}

fn patternedDigest(seed: u8) Digest {
    var result: Digest = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @truncate(index));
    return result;
}
