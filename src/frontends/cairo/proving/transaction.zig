//! Complete backend-neutral official Cairo proving transaction.
//!
//! The current entrypoint remains profile-gated by an authenticated AIR bundle.
//! Component presence and row geometry are derived from the live input.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const adapter = @import("../adapter/mod.zig");
const cairo_air = @import("../air/mod.zig");
const claim_generator = @import("../claim_generator.zig");
const preprocessed = @import("../preprocessed/mod.zig");
const statement = @import("../statement/mod.zig");
const statement_bootstrap = @import("../statement_bootstrap.zig");
const witness = @import("../witness/mod.zig");
const proving_air = @import("air/mod.zig");
const base_trace = @import("base_trace.zig");
const interaction_trace = @import("interaction_trace.zig");
const transcript = @import("transcript.zig");
const geometry = @import("../witness/resident_geometry.zig");

const QM31 = core.fields.qm31.QM31;
const VerifierComponent = core.air.components.Component;
const ComponentProver = prover.air.component_prover.ComponentProver;

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
    input: *const adapter.ProverInput,
    programs: *const witness.bundle.Bundle,
    topology: witness.feed_topology.Loaded,
    fixed: *const witness.fixed_table_bundle.Bundle,
    relations: *const witness.relation_bundle.Bundle,
    air_templates: *const cairo_air.template_library.Library,
};

pub fn Result(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        proof: Engine.ExtendedProof,
        statement: statement_bootstrap.OwnedStatementBootstrap,
        composition: witness.composition_bundle.Bundle,
        claimed_sums: []QM31,
        interaction_pow: u64,
        preprocessed_variant: preprocessed.trace.Variant,
        proof_owned: bool = true,

        pub fn deinit(self: *@This()) void {
            if (self.proof_owned) self.proof.deinit(self.allocator);
            self.statement.deinit();
            self.composition.deinit();
            self.allocator.free(self.claimed_sums);
            self.* = undefined;
        }
    };
}

pub fn proveFixture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    fixture: Fixture,
    variant: preprocessed.trace.Variant,
) !Result(Engine) {
    comptime prover.engine.assertProverEngine(Engine);
    var target = try preprocessed.trace.Spec.init(allocator, variant);
    defer target.deinit();
    const preprocessed_logs = try target.logs(allocator);
    defer allocator.free(preprocessed_logs);

    var base = try base_trace.build(
        allocator,
        fixture.input,
        fixture.programs,
        fixture.topology,
        fixture.fixed,
        claimVariant(variant),
    );
    defer base.deinit();
    var composition = try fixture.air_templates.instantiate(
        allocator,
        &base.geometry,
        variant,
        fixture.input.builtin_segments,
    );
    errdefer composition.deinit();
    try validateComposition(&composition, base.geometry);

    var flat = try base.geometry.flatten();
    defer flat.deinit();
    var owned_statement = try statement_bootstrap.init(allocator, .{
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
    errdefer owned_statement.deinit();

    var channel = Engine.Channel{};
    transcript.mixChannelSalt(&channel, 0);
    official_pcs_config.mixInto(&channel);
    var scheme = try Engine.init(allocator, official_pcs_config);
    var scheme_owned = true;
    errdefer if (scheme_owned) Engine.deinit(&scheme, allocator);

    const preprocessed_columns = try target.materialize(allocator);
    try Engine.commit(&scheme, allocator, preprocessed_columns, null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);
    try transcript.mixClaim(allocator, &channel, &owned_statement);

    try Engine.commit(&scheme, allocator, base.takeColumns(), null, &channel);
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    const interaction_pow =
        transcript.grindInteraction(&channel);
    const lookup = try transcript.drawLookupElements(
        allocator,
        &channel,
    );

    var pedersen: preprocessed.pedersen_table.Table = undefined;
    var pedersen_initialized = false;
    defer if (pedersen_initialized) pedersen.deinit();
    switch (variant) {
        .canonical_without_pedersen => {},
        .canonical => {
            pedersen = try preprocessed.pedersen_table.Table.init(
                allocator,
                .standard,
            );
            pedersen_initialized = true;
        },
        .canonical_small => {
            pedersen = try preprocessed.pedersen_table.Table.init(
                allocator,
                .small,
            );
            pedersen_initialized = true;
        },
    }
    var interaction = try interaction_trace.build(
        allocator,
        fixture.input,
        fixture.topology,
        fixture.fixed,
        fixture.relations,
        &base,
        lookup.z,
        lookup.alpha,
        if (pedersen_initialized) &pedersen else null,
    );
    defer interaction.deinit();
    const public_sum = try statement.public_logup.sum(
        allocator,
        fixture.input,
        lookup.z,
        lookup.alpha,
    );
    if (!public_sum.add(interaction.component_sum).eql(QM31.zero()))
        return error.InvalidGlobalLookupSum;
    transcript.mixInteractionClaim(
        &channel,
        interaction.claimed_sums,
    );
    try Engine.commit(
        &scheme,
        allocator,
        interaction.takeColumns(),
        null,
        &channel,
    );
    try Engine.flushPendingCommit(&scheme, allocator, &channel);

    const runtime_components = try allocator.alloc(
        proving_air.component.Component,
        composition.components.len,
    );
    defer allocator.free(runtime_components);
    const components = try allocator.alloc(
        ComponentProver,
        runtime_components.len,
    );
    defer allocator.free(components);
    for (
        composition.components,
        runtime_components,
        components,
        interaction.claimed_sums,
    ) |*captured, *runtime, *component, claimed_sum| {
        runtime.* = proving_air.component.Component.init(
            allocator,
            captured,
            preprocessed_logs,
            composition.max_evaluation_log_size,
            lookup.z,
            lookup.alpha,
            claimed_sum,
        );
        component.* = runtime.asProverComponent();
    }

    scheme_owned = false;
    const proof = try Engine.prove(
        allocator,
        components,
        &channel,
        scheme,
        .{},
    );
    return .{
        .allocator = allocator,
        .proof = proof,
        .statement = owned_statement,
        .composition = composition,
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
    comptime Engine: type,
    input: *const adapter.ProverInput,
    result: *Result(Engine),
) !void {
    comptime prover.engine.assertProverEngine(Engine);
    if (!result.proof_owned) return error.ProofAlreadyConsumed;
    const allocator = result.allocator;
    const composition = &result.composition;
    const stark_proof = &result.proof.proof;
    if (stark_proof.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidProofShape;
    if (!std.meta.eql(
        stark_proof.commitment_scheme_proof.config,
        official_pcs_config,
    )) return error.InvalidProtocolConfiguration;
    if (composition.components.len != result.claimed_sums.len)
        return error.InvalidComponentShape;

    var preprocessed_spec = try preprocessed.trace.Spec.init(
        allocator,
        result.preprocessed_variant,
    );
    defer preprocessed_spec.deinit();
    const preprocessed_logs = try preprocessed_spec.logs(allocator);
    defer allocator.free(preprocessed_logs);
    const base_logs = try componentTreeLogs(allocator, composition, 1);
    defer allocator.free(base_logs);
    const interaction_logs = try componentTreeLogs(allocator, composition, 2);
    defer allocator.free(interaction_logs);

    var channel = Engine.Channel{};
    transcript.mixChannelSalt(&channel, 0);
    official_pcs_config.mixInto(&channel);
    var scheme = try core.pcs.verifier.CommitmentSchemeVerifier(
        Engine.Hasher,
        Engine.MerkleChannel,
    ).init(allocator, official_pcs_config);
    defer scheme.deinit(allocator);

    const commitments = stark_proof.commitment_scheme_proof.commitments.items;
    try scheme.commit(allocator, commitments[0], preprocessed_logs, &channel);
    try transcript.mixClaim(
        allocator,
        &channel,
        &result.statement,
    );
    try scheme.commit(allocator, commitments[1], base_logs, &channel);
    if (!channel.verifyPowNonce(
        transcript.interaction_pow_bits,
        result.interaction_pow,
    )) return error.ProofOfWork;
    channel.mixU64(result.interaction_pow);
    const lookup = try transcript.drawLookupElements(
        allocator,
        &channel,
    );

    var global_sum = try statement.public_logup.sum(
        allocator,
        input,
        lookup.z,
        lookup.alpha,
    );
    for (result.claimed_sums) |claimed_sum|
        global_sum = global_sum.add(claimed_sum);
    if (!global_sum.eql(QM31.zero())) return error.InvalidGlobalLookupSum;
    transcript.mixInteractionClaim(
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
        proving_air.component.Component,
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
        runtime.* = proving_air.component.Component.init(
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
        Engine.Hasher,
        Engine.MerkleChannel,
        allocator,
        verifier_components,
        &channel,
        &scheme,
        proof,
    );
}

fn componentTreeLogs(
    allocator: std.mem.Allocator,
    composition: *const witness.composition_bundle.Bundle,
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
    composition: *const witness.composition_bundle.Bundle,
    live: claim_generator.OwnedClaimGeometry,
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
    component: claim_generator.ComponentGeometry,
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
    variant: preprocessed.trace.Variant,
) claim_generator.PreprocessedVariant {
    return switch (variant) {
        .canonical => .canonical,
        .canonical_without_pedersen => .canonical_without_pedersen,
        .canonical_small => .canonical_small,
    };
}

test "official Cairo transaction configuration is upstream-compatible" {
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
        transcript.interaction_pow_bits,
    );
    try std.testing.expectEqual(@as(?u32, 0), official_pcs_config.lifting_log_size);
}
