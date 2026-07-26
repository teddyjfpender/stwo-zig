//! Complete official Cairo proving transaction through the CPU/SIMD backend.
//!
//! The current entrypoint is deliberately fixture-gated by an authenticated
//! Rust base checkpoint. It must not be exposed as production admission until
//! live claim geometry replaces that authority.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_impl");
const cairo = @import("../../../frontends/cairo/mod.zig");
const cpu_air = @import("../air/mod.zig");
const CpuBackend = @import("../../../backends/cpu_scalar/mod.zig").CpuBackend;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
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

    pub fn deinit(self: *Result) void {
        self.proof.deinit(self.allocator);
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
    try validateComposition(fixture.composition, fixture.expected_base);

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

    var flat = try cairo.statement_bootstrap.deriveFlatClaimGeometry(
        allocator,
        fixture.composition,
    );
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

    var base = try cairo.proving.base_trace.build(
        allocator,
        fixture.input,
        fixture.programs,
        fixture.topology,
        fixture.fixed,
        fixture.expected_base,
    );
    defer base.deinit();
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

fn validateComposition(
    composition: *const cairo.witness.composition_bundle.Bundle,
    expected: []const cairo.conformance.checkpoint.Component,
) !void {
    if (composition.components.len != expected.len)
        return error.InvalidCompositionGeometry;
    for (composition.components, expected) |component, oracle| {
        if (!std.mem.eql(u8, component.label, oracle.label) or
            oracle.columns.len == 0 or
            oracle.columns[0].row_count !=
                @as(u64, 1) << @intCast(component.trace_log_size))
            return error.InvalidCompositionGeometry;
    }
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
