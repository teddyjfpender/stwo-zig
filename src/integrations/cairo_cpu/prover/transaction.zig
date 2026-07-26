//! Complete official Cairo proving transaction through the CPU/SIMD backend.
//!
//! The current entrypoint remains profile-gated by an authenticated AIR bundle.
//! Component presence and row geometry are derived from the live input.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const cairo = @import("../../../frontends/cairo/mod.zig");
const cpu_air = @import("../air/mod.zig");
const CpuBackend = @import("../../../backends/cpu_scalar/mod.zig").CpuBackend;
const geometry = @import("../../../frontends/cairo/witness/resident_geometry.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const VerifierComponent = core.air.components.Component;
const ComponentProver = prover.air.component_prover.ComponentProver;

pub const Hasher = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
pub const MerkleChannel =
    core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleChannel;
pub const Channel = core.channel.blake2s.Blake2sChannel;
pub const ExtendedProof = core.proof.ExtendedStarkProof(Hasher);
pub const Scheme = prover.pcs.CommitmentSchemeProver(
    CpuBackend,
    Hasher,
    MerkleChannel,
);

pub const official_pcs_config = core.pcs.PcsConfig{
    .pow_bits = 26,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 70,
        .fold_step = 1,
    },
    .lifting_log_size = 0,
};

pub const Fixture = struct {
    input: *const cairo.adapter.ProverInput,
    programs: *const cairo.witness.bundle.Bundle,
    topology: cairo.witness.feed_topology.Loaded,
    fixed: *const cairo.witness.fixed_table_bundle.Bundle,
    relations: *const cairo.witness.relation_bundle.Bundle,
    expected_base: []const cairo.conformance.checkpoint.Component,
    composition: *cairo.witness.composition_bundle.Bundle,
};

pub const Result = struct {
    allocator: std.mem.Allocator,
    proof: ExtendedProof,
    statement: cairo.statement_bootstrap.OwnedStatementBootstrap,
    claimed_sums: []QM31,
    interaction_pow: u64,
    preprocessed_variant: cairo.preprocessed.trace.Variant,
    proof_owned: bool = true,

    pub fn deinit(self: *Result) void {
        if (self.proof_owned) self.proof.deinit(self.allocator);
        self.statement.deinit();
        self.allocator.free(self.claimed_sums);
        self.* = undefined;
    }
};

pub fn proveFixture(
    allocator: std.mem.Allocator,
    fixture: Fixture,
    variant: cairo.preprocessed.trace.Variant,
) !Result {
    var canonical = try cairo.preprocessed.trace.Spec.init(
        allocator,
        .canonical,
    );
    defer canonical.deinit();
    var target = try cairo.preprocessed.trace.Spec.init(allocator, variant);
    defer target.deinit();
    try projectPreprocessedIndices(allocator, fixture.composition, canonical, target);
    const preprocessed_logs = try target.logs(allocator);
    defer allocator.free(preprocessed_logs);

    var base = try cairo.proving.base_trace.build(
        allocator,
        fixture.input,
        fixture.programs,
        fixture.topology,
        fixture.fixed,
        claimVariant(variant),
    );
    defer base.deinit();
    try validateComposition(fixture.composition, base.geometry);

    var flat = try base.geometry.flatten();
    defer flat.deinit();
    var statement = try cairo.statement_bootstrap.init(allocator, .{
        .channel_salt = 0,
        .pcs = .{
            .pow_bits = official_pcs_config.pow_bits,
            .log_blowup_factor = official_pcs_config.fri_config.log_blowup_factor,
            .n_queries = @intCast(official_pcs_config.fri_config.n_queries),
            .log_last_layer_degree_bound = official_pcs_config.fri_config.log_last_layer_degree_bound,
            .fold_step = official_pcs_config.fri_config.fold_step,
            .lifting_log_size = official_pcs_config.lifting_log_size,
        },
        .component_enable_bits = flat.component_enable_bits,
        .component_log_sizes = flat.component_log_sizes,
        .prover_input = fixture.input,
    });
    errdefer statement.deinit();

    var channel = Channel{};
    cairo.proving.transcript.mixChannelSalt(&channel, 0);
    official_pcs_config.mixInto(&channel);
    var scheme = try Scheme.init(allocator, official_pcs_config);
    var scheme_owned = true;
    errdefer if (scheme_owned) scheme.deinit(allocator);

    const preprocessed_columns = try target.materialize(allocator);
    try scheme.commitOwned(allocator, preprocessed_columns, &channel);
    try cairo.proving.transcript.mixClaim(allocator, &channel, &statement);

    try scheme.commitOwned(allocator, base.takeColumns(), &channel);

    const interaction_pow =
        cairo.proving.transcript.grindInteraction(&channel);
    const lookup = try cairo.proving.transcript.drawLookupElements(
        allocator,
        &channel,
    );

    var pedersen: cairo.preprocessed.pedersen_table.Table = undefined;
    var pedersen_initialized = false;
    defer if (pedersen_initialized) pedersen.deinit();
    switch (variant) {
        .canonical_without_pedersen => {},
        .canonical => {
            pedersen = try cairo.preprocessed.pedersen_table.Table.init(
                allocator,
                .standard,
            );
            pedersen_initialized = true;
        },
        .canonical_small => {
            pedersen = try cairo.preprocessed.pedersen_table.Table.init(
                allocator,
                .small,
            );
            pedersen_initialized = true;
        },
    }
    var interaction = try cairo.proving.interaction_trace.build(
        allocator,
        fixture.input,
        fixture.topology,
        fixture.fixed,
        fixture.relations,
        &base,
        fixture.expected_base,
        lookup.z,
        lookup.alpha,
        if (pedersen_initialized) &pedersen else null,
    );
    defer interaction.deinit();
    const public_sum = try cairo.statement.public_logup.sum(
        allocator,
        fixture.input,
        lookup.z,
        lookup.alpha,
    );
    if (!public_sum.add(interaction.component_sum).eql(QM31.zero()))
        return error.InvalidGlobalLookupSum;
    cairo.proving.transcript.mixInteractionClaim(
        &channel,
        interaction.claimed_sums,
    );
    try scheme.commitOwned(allocator, interaction.takeColumns(), &channel);

    const runtime_components = try allocator.alloc(
        cpu_air.component.Component,
        fixture.composition.components.len,
    );
    defer allocator.free(runtime_components);
    const components = try allocator.alloc(
        ComponentProver,
        runtime_components.len,
    );
    defer allocator.free(components);
    for (
        fixture.composition.components,
        runtime_components,
        components,
        interaction.claimed_sums,
    ) |*captured, *runtime, *component, claimed_sum| {
        runtime.* = cpu_air.component.Component.init(
            allocator,
            captured,
            preprocessed_logs,
            fixture.composition.max_evaluation_log_size,
            lookup.z,
            lookup.alpha,
            claimed_sum,
        );
        component.* = runtime.asProverComponent();
    }

    scheme_owned = false;
    const proof = try prover.prove.proveEx(
        CpuBackend,
        Hasher,
        MerkleChannel,
        allocator,
        components,
        &channel,
        scheme,
        false,
    );
    return .{
        .allocator = allocator,
        .proof = proof,
        .statement = statement,
        .claimed_sums = interaction.takeClaimedSums(),
        .interaction_pow = interaction_pow,
        .preprocessed_variant = variant,
    };
}

/// Replays the official Cairo transcript and consumes the in-memory proof.
///
/// Callers that need proof bytes must serialize them before this function.
/// Success means the Zig AIR, PCS, FRI, interaction PoW, and public LogUp
/// statement have all accepted the proof.
pub fn verifyAndConsume(
    input: *const cairo.adapter.ProverInput,
    composition: *const cairo.witness.composition_bundle.Bundle,
    result: *Result,
) !void {
    if (!result.proof_owned) return error.ProofAlreadyConsumed;
    const allocator = result.allocator;
    const stark_proof = &result.proof.proof;
    if (stark_proof.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidProofShape;
    if (!std.meta.eql(
        stark_proof.commitment_scheme_proof.config,
        official_pcs_config,
    )) return error.InvalidProtocolConfiguration;
    if (composition.components.len != result.claimed_sums.len)
        return error.InvalidComponentShape;

    var preprocessed = try cairo.preprocessed.trace.Spec.init(
        allocator,
        result.preprocessed_variant,
    );
    defer preprocessed.deinit();
    const preprocessed_logs = try preprocessed.logs(allocator);
    defer allocator.free(preprocessed_logs);
    const base_logs = try componentTreeLogs(allocator, composition, 1);
    defer allocator.free(base_logs);
    const interaction_logs = try componentTreeLogs(allocator, composition, 2);
    defer allocator.free(interaction_logs);

    var channel = Channel{};
    cairo.proving.transcript.mixChannelSalt(&channel, 0);
    official_pcs_config.mixInto(&channel);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(
        Hasher,
        MerkleChannel,
    ).init(allocator, official_pcs_config);
    defer scheme.deinit(allocator);

    const commitments = stark_proof.commitment_scheme_proof.commitments.items;
    try scheme.commit(allocator, commitments[0], preprocessed_logs, &channel);
    try cairo.proving.transcript.mixClaim(
        allocator,
        &channel,
        &result.statement,
    );
    try scheme.commit(allocator, commitments[1], base_logs, &channel);
    if (!channel.verifyPowNonce(
        cairo.proving.transcript.interaction_pow_bits,
        result.interaction_pow,
    )) return error.ProofOfWork;
    channel.mixU64(result.interaction_pow);
    const lookup = try cairo.proving.transcript.drawLookupElements(
        allocator,
        &channel,
    );

    var global_sum = try cairo.statement.public_logup.sum(
        allocator,
        input,
        lookup.z,
        lookup.alpha,
    );
    for (result.claimed_sums) |claimed_sum|
        global_sum = global_sum.add(claimed_sum);
    if (!global_sum.eql(QM31.zero())) return error.InvalidGlobalLookupSum;
    cairo.proving.transcript.mixInteractionClaim(
        &channel,
        result.claimed_sums,
    );
    try scheme.commit(
        allocator,
        commitments[2],
        interaction_logs,
        &channel,
    );

    const runtime_components = try allocator.alloc(
        cpu_air.component.Component,
        composition.components.len,
    );
    defer allocator.free(runtime_components);
    const verifier_components = try allocator.alloc(
        VerifierComponent,
        runtime_components.len,
    );
    defer allocator.free(verifier_components);
    for (
        composition.components,
        runtime_components,
        verifier_components,
        result.claimed_sums,
    ) |*captured, *runtime, *component, claimed_sum| {
        runtime.* = cpu_air.component.Component.init(
            allocator,
            captured,
            preprocessed_logs,
            composition.max_evaluation_log_size,
            lookup.z,
            lookup.alpha,
            claimed_sum,
        );
        component.* = runtime.asVerifierComponent();
    }

    result.proof.aux.deinit(allocator);
    const proof = result.proof.proof;
    result.proof_owned = false;
    try core.verifier.verify(
        Hasher,
        MerkleChannel,
        allocator,
        verifier_components,
        &channel,
        &scheme,
        proof,
    );
}

fn componentTreeLogs(
    allocator: std.mem.Allocator,
    composition: *const cairo.witness.composition_bundle.Bundle,
    tree: u32,
) ![]u32 {
    var column_count: usize = 0;
    for (composition.components) |component| {
        const span = try geometry.componentSpan(
            component,
            tree,
        );
        if (span.start != column_count) return error.InvalidComponentShape;
        column_count = span.end;
    }
    const logs = try allocator.alloc(u32, column_count);
    errdefer allocator.free(logs);
    for (composition.components) |component| {
        const span = try geometry.componentSpan(
            component,
            tree,
        );
        @memset(logs[span.start..span.end], component.trace_log_size);
    }
    return logs;
}

fn validateComposition(
    composition: *const cairo.witness.composition_bundle.Bundle,
    live: cairo.claim_generator.OwnedClaimGeometry,
) !void {
    if (composition.components.len != live.components.len)
        return error.InvalidCompositionGeometry;
    for (composition.components, live.components) |component, actual| {
        const log_size = switch (actual.log_size) {
            .known => |value| value,
            .deferred => return error.InvalidCompositionGeometry,
        };
        if (component.instance != actual.instance or
            !compositionLabelMatches(component.label, actual) or
            component.trace_log_size != log_size)
            return error.InvalidCompositionGeometry;
    }
}

fn compositionLabelMatches(
    label: []const u8,
    component: cairo.claim_generator.ComponentGeometry,
) bool {
    if (!std.mem.eql(u8, component.name, "memory_id_to_big"))
        return std.mem.eql(u8, label, component.name);
    var buffer: [64]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &buffer,
        "memory_id_to_big[{}]",
        .{component.instance},
    ) catch return false;
    return std.mem.eql(u8, label, expected);
}

fn claimVariant(
    variant: cairo.preprocessed.trace.Variant,
) cairo.claim_generator.PreprocessedVariant {
    return switch (variant) {
        .canonical => .canonical,
        .canonical_without_pedersen => .canonical_without_pedersen,
        .canonical_small => .canonical_small,
    };
}

fn projectPreprocessedIndices(
    allocator: std.mem.Allocator,
    composition: *cairo.witness.composition_bundle.Bundle,
    canonical: cairo.preprocessed.trace.Spec,
    target: cairo.preprocessed.trace.Spec,
) !void {
    for (composition.components) |*component| {
        const projected = try canonical.projectIndices(
            allocator,
            target,
            component.preprocessed_indices,
        );
        allocator.free(component.preprocessed_indices);
        component.preprocessed_indices = projected;
    }
}

test "official Cairo CPU transaction configuration is upstream-compatible" {
    try std.testing.expectEqual(@as(u32, 26), official_pcs_config.pow_bits);
    try std.testing.expectEqual(
        @as(u32, 1),
        official_pcs_config.fri_config.log_blowup_factor,
    );
    try std.testing.expectEqual(
        @as(usize, 70),
        official_pcs_config.fri_config.n_queries,
    );
    try std.testing.expectEqual(
        @as(u32, 24),
        cairo.proving.transcript.interaction_pow_bits,
    );
    try std.testing.expectEqual(@as(?u32, 0), official_pcs_config.lifting_log_size);
}
